import sqlite3
import os
import json
import logging
import socket
import threading
from datetime import datetime, timezone
from config import LOG_DIR, DATA_DIR, DB_PATH, SANDBOX_NOTIFY_HOST, SANDBOX_NOTIFY_PORT
from geoip import lookup as geo_lookup
import risk_score

_log = logging.getLogger(__name__)

# One reusable UDP socket for nudging the sandbox fetcher — see config.py's
# SANDBOX_NOTIFY_PORT comment. A plain send_to on an unconnected UDP socket
# never blocks and never raises for "nobody's listening," so this is safe to
# call unconditionally from the hot path with no reachability check.
_notify_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
_notify_addr = (SANDBOX_NOTIFY_HOST, SANDBOX_NOTIFY_PORT)


def _notify_fetcher():
    try:
        _notify_sock.sendto(b"1", _notify_addr)
    except Exception:
        pass

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

_jsonl_lock = threading.Lock()
_log_path = os.path.join(LOG_DIR, "honeypot.jsonl")
_log_file = open(_log_path, "a", buffering=1)

_event_callbacks = []


def register_event_callback(fn):
    if fn not in _event_callbacks:
        _event_callbacks.append(fn)


def clear_event_callbacks():
    """Remove all subscribers (used when tests reload modules that re-register)."""
    _event_callbacks.clear()


def _table_columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column_if_missing(conn, table, name, col_type):
    if name not in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_type}")


def _drop_column_if_exists(conn, table, name):
    if name in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} DROP COLUMN {name}")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip        TEXT NOT NULL,
            port      INTEGER NOT NULL,
            service   TEXT NOT NULL,
            event_type TEXT NOT NULL,
            data      TEXT
        )
    """)
    _add_column_if_missing(conn, "events", "country", "TEXT")
    _add_column_if_missing(conn, "events", "city", "TEXT")
    _add_column_if_missing(conn, "events", "lat", "REAL")
    _add_column_if_missing(conn, "events", "lon", "REAL")
    _add_column_if_missing(conn, "events", "abuse_score", "INTEGER")
    _add_column_if_missing(conn, "events", "risk_score", "INTEGER")
    # Groups events from one connection-oriented session together (Redis
    # command sequences first — see redis_honey.py — other stateful traps can
    # opt in the same way later). Deliberately not backfilled for pre-existing
    # rows; only NULL there, which read paths already treat as "ungrouped".
    _add_column_if_missing(conn, "events", "connection_id", "TEXT")
    # Manual triage state — a raw event/alert feed at this volume needs some way
    # to track "already looked at this" across visits, or every session re-scans
    # the same rows from scratch. Per-event/per-alert rather than per-IP: the
    # same IP recurs over weeks with genuinely new activity each time, so a
    # single reviewed flag on the IP wouldn't mean anything durable.
    _add_column_if_missing(conn, "events", "reviewed", "INTEGER NOT NULL DEFAULT 0")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS suricata_alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip    TEXT NOT NULL,
            src_port  INTEGER,
            dst_port  INTEGER,
            proto     TEXT,
            alert_sig TEXT,
            category  TEXT,
            severity  INTEGER,
            raw       TEXT
        )
    """)
    # Migrate existing suricata_alerts tables that predate MITRE ATT&CK tagging
    # (see mitre_map.py — populated at insert time in suricata_logger.py).
    _add_column_if_missing(conn, "suricata_alerts", "mitre_tactic", "TEXT")
    _add_column_if_missing(conn, "suricata_alerts", "mitre_technique", "TEXT")
    _add_column_if_missing(conn, "suricata_alerts", "mitre_technique_name", "TEXT")
    _add_column_if_missing(conn, "suricata_alerts", "mitre_url", "TEXT")
    _add_column_if_missing(conn, "suricata_alerts", "sid", "INTEGER")
    _add_column_if_missing(conn, "suricata_alerts", "reviewed", "INTEGER NOT NULL DEFAULT 0")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payloads (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            event_id    INTEGER,
            ip          TEXT NOT NULL,
            service     TEXT NOT NULL,
            filename    TEXT NOT NULL,
            local_path  TEXT NOT NULL,
            file_size   INTEGER,
            md5         TEXT,
            sha256      TEXT,
            mime_type   TEXT,
            FOREIGN KEY(event_id) REFERENCES events(id)
        )
    """)
    # VirusTotal enrichment was removed (2026-08-28) — no key was ever
    # configured, so vt_score sat permanently NULL/"Pending…" in the UI.
    _drop_column_if_exists(conn, "payloads", "vt_score")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_detections (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            service         TEXT NOT NULL,
            port            INTEGER NOT NULL,
            label           TEXT NOT NULL,
            desc            TEXT,
            event_type      TEXT NOT NULL,
            mitre_id        TEXT,
            mitre_technique TEXT,
            mitre_tactic    TEXT,
            mitre_url       TEXT,
            created_at      TEXT NOT NULL
        )
    """)
    _add_column_if_missing(conn, "custom_detections", "query", "TEXT")
    # Outbound alert queue. A honeypot should make no outbound HTTPS calls of its own
    # (see config.py); alerts/discord.py parks fully-formatted payloads here instead,
    # and something on your trusted network drains them via /api/alerts/pending.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_outbox (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            created TEXT NOT NULL,
            payload TEXT NOT NULL
        )
    """)
    # Suricata rules created through the dashboard's rule builder — see
    # rule_builder.py, which renders the enabled ones out to custom.rules and issues a
    # live Suricata reload.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_suricata_rules (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            sid               INTEGER NOT NULL UNIQUE,
            message           TEXT NOT NULL,
            protocol          TEXT NOT NULL,
            dest_port         TEXT NOT NULL,
            contents          TEXT NOT NULL,
            http_field        TEXT,
            classtype         TEXT NOT NULL,
            threshold_count   INTEGER,
            threshold_seconds INTEGER,
            rule_text         TEXT NOT NULL,
            enabled           INTEGER NOT NULL DEFAULT 1,
            created_at        TEXT NOT NULL
        )
    """)
    _add_column_if_missing(conn, "custom_suricata_rules", "mitre_tactic", "TEXT")
    _add_column_if_missing(conn, "custom_suricata_rules", "mitre_technique", "TEXT")
    _add_column_if_missing(conn, "custom_suricata_rules", "mitre_technique_name", "TEXT")
    _add_column_if_missing(conn, "custom_suricata_rules", "mitre_url", "TEXT")
    # Two tables, not one: sandbox_samples is unique-content inventory (one row
    # per distinct sha256, only created when real bytes were downloaded).
    # sandbox_fetch_attempts is an activity log — one row per URL a trap ever
    # handed to the fetcher, regardless of outcome. See sandbox/db.py for the
    # full rationale (this used to be one conflated table; splitting it is
    # what makes non-success attempts visible at all).
    #
    # Migration duplicated from sandbox/db.py's _migrate_to_attempts_split (not
    # imported — this app and the fetcher are separate images) so that whichever
    # of the two containers happens to start first can self-heal the schema;
    # relying on start order between them would be fragile.
    def _migrate_sandbox_attempts_split():
        # Nested so its early-return (on a migration race, below) only skips
        # this migration — a bare `return` here previously exited init_db()
        # itself, silently skipping every table/index created after this
        # point (custom_suricata_rules indexes, sandbox_samples/
        # sandbox_fetch_attempts, shell_sessions, all the idx_* indexes).
        _sandbox_cols = {row[1] for row in conn.execute("PRAGMA table_info(sandbox_samples)")}
        if not (_sandbox_cols and "fetch_status" in _sandbox_cols):
            return  # table doesn't exist, or already migrated
        _old_rows = conn.execute(
            "SELECT sha256, md5, url, file_size, mime_type, architecture, fetched_at, "
            "source_event_id, source_ip, fetch_status, fetch_error, local_path "
            "FROM sandbox_samples"
        ).fetchall()
        # No locking against sandbox/db.py's copy of this same migration
        # running in the other container — if both ever start against a
        # still-unmigrated DB at once, the loser hits "table already exists"
        # here. Degrade to "the other container is already handling it"
        # rather than crash-looping.
        try:
            conn.execute("ALTER TABLE sandbox_samples RENAME TO sandbox_samples_old")
        except sqlite3.OperationalError as e:
            print(f"[logger] migration race with the fetcher container, skipping: {e}")
            conn.rollback()
            return
        conn.execute("""
            CREATE TABLE sandbox_samples (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256        TEXT NOT NULL UNIQUE,
                md5           TEXT,
                file_size     INTEGER,
                mime_type     TEXT,
                architecture  TEXT,
                first_seen_at TEXT NOT NULL,
                local_path    TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_fetch_attempts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                attempted_at    TEXT NOT NULL,
                url             TEXT NOT NULL,
                source_event_id INTEGER,
                source_ip       TEXT,
                status          TEXT NOT NULL,
                error           TEXT,
                sample_id       INTEGER REFERENCES sandbox_samples(id),
                duration_ms     INTEGER
            )
        """)
        for _r in _old_rows:
            (_sha256, _md5, _url, _file_size, _mime_type, _architecture, _fetched_at,
             _source_event_id, _source_ip, _fetch_status, _fetch_error, _local_path) = _r
            _sample_id = None
            if _sha256 is not None and _local_path is not None:
                _cur = conn.execute(
                    "INSERT INTO sandbox_samples (sha256, md5, file_size, mime_type, "
                    "architecture, first_seen_at, local_path) VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(sha256) DO NOTHING",
                    (_sha256, _md5, _file_size, _mime_type, _architecture, _fetched_at, _local_path),
                )
                _sample_id = _cur.lastrowid or conn.execute(
                    "SELECT id FROM sandbox_samples WHERE sha256 = ?", (_sha256,)
                ).fetchone()[0]
            conn.execute(
                "INSERT INTO sandbox_fetch_attempts "
                "(attempted_at, url, source_event_id, source_ip, status, error, sample_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_fetched_at, _url, _source_event_id, _source_ip, _fetch_status, _fetch_error, _sample_id),
            )
        conn.execute("DROP TABLE sandbox_samples_old")
        print(f"[logger] migrated {len(_old_rows)} row(s) from the old single-table "
              f"sandbox_samples into the new samples/fetch_attempts split")

    _migrate_sandbox_attempts_split()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sandbox_samples (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256        TEXT NOT NULL UNIQUE,
            md5           TEXT,
            file_size     INTEGER,
            mime_type     TEXT,
            architecture  TEXT,
            first_seen_at TEXT NOT NULL,
            local_path    TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sandbox_samples_sha256 ON sandbox_samples(sha256)")
    # VirusTotal enrichment and detonation were both removed (2026-08-28) — see
    # the matching comment in sandbox/db.py's init_sandbox_db for why.
    _drop_column_if_exists(conn, "sandbox_samples", "vt_score")
    conn.execute("DROP TABLE IF EXISTS sandbox_detonations")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sandbox_fetch_attempts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            attempted_at    TEXT NOT NULL,
            url             TEXT NOT NULL,
            source_event_id INTEGER,
            source_ip       TEXT,
            status          TEXT NOT NULL,
            error           TEXT,
            sample_id       INTEGER REFERENCES sandbox_samples(id),
            duration_ms     INTEGER
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sandbox_attempts_url ON sandbox_fetch_attempts(url)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sandbox_attempts_attempted_at ON sandbox_fetch_attempts(attempted_at)")

    # Full-session recordings of interactive fake-shell drop-ins (SSH/Telnet),
    # written by session_recorder.py. cast_path points at an asciinema v2
    # .cast file under data/sessions/ — the raw event stream lives on disk,
    # not in the DB, matching how payloads/sandbox_samples store bytes on
    # disk and only metadata in sqlite.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shell_sessions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            session_uuid  TEXT NOT NULL UNIQUE,
            ip            TEXT NOT NULL,
            port          INTEGER NOT NULL,
            service       TEXT NOT NULL,
            username      TEXT,
            started_at    TEXT NOT NULL,
            duration_s    REAL,
            event_count   INTEGER NOT NULL DEFAULT 0,
            command_count INTEGER NOT NULL DEFAULT 0,
            cast_path     TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_shell_sessions_ip ON shell_sessions(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_shell_sessions_started_at ON shell_sessions(started_at)")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_connection_id ON events(connection_id)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_suricata_timestamp ON suricata_alerts(timestamp)"
    )
    conn.commit()
    conn.close()


def log_event(ip, port, service, event_type, data=None, connection_id=None):
    timestamp = datetime.now(timezone.utc).isoformat()
    data_str = json.dumps(data) if data is not None else None
    geo = geo_lookup(ip)
    country = geo.get("country")
    city = geo.get("city")
    lat = geo.get("lat")
    lon = geo.get("lon")

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO events (timestamp, ip, port, service, event_type, data,
               country, city, lat, lon, connection_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, ip, port, service, event_type, data_str, country, city, lat, lon, connection_id),
        )
        conn.commit()
        rowid = cur.lastrowid
    finally:
        conn.close()

    # Local, no-API-call composite score (event severity + this IP's activity volume/
    # diversity against this honeypot + AbuseIPDB reputation if known yet) — computed
    # for every event, unlike abuse_score which only covers a couple of event types
    # and needs a network round-trip. See risk_score.py.
    risk = risk_score.score_and_store(rowid, ip, event_type)

    event_dict = {
        "rowid": rowid,
        "timestamp": timestamp,
        "ip": ip,
        "port": port,
        "service": service,
        "event_type": event_type,
        "data": data,
        "country": country,
        "city": city,
        "lat": lat,
        "lon": lon,
        "risk_score": risk,
        "connection_id": connection_id,
    }

    line = json.dumps(event_dict, default=str) + "\n"
    with _jsonl_lock:
        _log_file.write(line)

    # Cheap substring gate, not the fetcher's full URL/base64/dev-tcp regex —
    # this runs on every single event (hundreds of thousands/day), so it has
    # to stay near-free. A false negative here just misses the latency
    # shortcut (falls back to the fetcher's own poll); nothing is lost.
    if data_str and ("http://" in data_str or "https://" in data_str):
        _notify_fetcher()

    for cb in _event_callbacks:
        try:
            cb(event_dict)
        except Exception:
            _log.exception("event callback %r failed", cb)

    return event_dict
