"""sandbox_samples / sandbox_fetch_attempts helpers.

Two-table split, not one: sandbox_samples is a unique-content inventory (one
row per distinct sha256, only ever created when real bytes were downloaded —
this is what you'd want to browse/download). sandbox_fetch_attempts is an
activity log — one row for EVERY url a trap's fake shell handed us, regardless
of outcome (fetched new content, matched existing content, recognized-URL skip,
SSRF-blocked, network failure, empty response). Conflating these into one table
(the original design) made every non-"clean success" attempt invisible, which
defeated the entire point of wanting to see what's actually happening.

Connect-per-call, same style as the main app's logger.py/app.py.
"""

import datetime
import sqlite3

import config


def _add_column_if_missing(conn, table, column, coltype):
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def _drop_column_if_exists(conn, table, column):
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column in existing:
        conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _migrate_to_attempts_split(conn):
    """One-time migration from the original single-table design. The old
    sandbox_samples had url/source_event_id/source_ip/fetch_status/fetch_error
    columns that belong on an attempt, not a unique-content row. Existing rows
    (at the time this was written: 4 rows, all fetch_status='failed', all
    sha256=NULL — i.e. attempts with no content at all) move wholesale into
    sandbox_fetch_attempts; sandbox_samples is rebuilt lean."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(sandbox_samples)")}
    if not cols or "fetch_status" not in cols:
        return  # table doesn't exist, or already migrated

    old_rows = conn.execute(
        "SELECT sha256, md5, url, file_size, mime_type, architecture, fetched_at, "
        "source_event_id, source_ip, fetch_status, fetch_error, local_path "
        "FROM sandbox_samples"
    ).fetchall()

    # This runs at startup in BOTH this container and the main honeypot app
    # (logger.py duplicates this migration — separate images, see its own
    # comment on why). No locking between them: if both ever start against a
    # still-unmigrated DB at once, the loser hits "table already exists" on
    # the RENAME/CREATE below. Only ever a race on a fresh, never-yet-migrated
    # DB (checked via the fetch_status column above) — degrade to "someone
    # else is already doing this" rather than crash-looping.
    try:
        conn.execute("ALTER TABLE sandbox_samples RENAME TO sandbox_samples_old")
    except sqlite3.OperationalError as e:
        print(f"[db] migration race with the other container, skipping: {e}")
        conn.rollback()
        return
    conn.execute("""
        CREATE TABLE sandbox_samples (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256       TEXT NOT NULL UNIQUE,
            md5          TEXT,
            file_size    INTEGER,
            mime_type    TEXT,
            architecture TEXT,
            first_seen_at TEXT NOT NULL,
            local_path   TEXT NOT NULL
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

    for r in old_rows:
        (sha256, md5, url, file_size, mime_type, architecture, fetched_at,
         source_event_id, source_ip, fetch_status, fetch_error, local_path) = r

        sample_id = None
        if sha256 is not None and local_path is not None:
            cur = conn.execute(
                "INSERT INTO sandbox_samples (sha256, md5, file_size, mime_type, "
                "architecture, first_seen_at, local_path) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(sha256) DO NOTHING",
                (sha256, md5, file_size, mime_type, architecture, fetched_at, local_path),
            )
            sample_id = cur.lastrowid or conn.execute(
                "SELECT id FROM sandbox_samples WHERE sha256 = ?", (sha256,)
            ).fetchone()[0]

        conn.execute(
            "INSERT INTO sandbox_fetch_attempts "
            "(attempted_at, url, source_event_id, source_ip, status, error, sample_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (fetched_at, url, source_event_id, source_ip, fetch_status, fetch_error, sample_id),
        )

    conn.execute("DROP TABLE sandbox_samples_old")
    conn.commit()
    print(f"[db] migrated {len(old_rows)} row(s) from the old single-table "
          f"sandbox_samples into the new samples/fetch_attempts split")


def init_sandbox_db():
    conn = sqlite3.connect(config.DB_PATH)
    try:
        _migrate_to_attempts_split(conn)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_samples (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256       TEXT NOT NULL UNIQUE,
                md5          TEXT,
                file_size    INTEGER,
                mime_type    TEXT,
                architecture TEXT,
                first_seen_at TEXT NOT NULL,
                local_path   TEXT NOT NULL
            )
        """)
        # VirusTotal enrichment and detonation were both removed (2026-08-28) — no
        # VT key was ever configured and detonation's controller/runtime was never
        # built (the "milestone 2" real-execution work was deliberately descoped
        # early on). Both columns/tables sat permanently empty, showing "Pending…"
        # / "not queued" forever in the UI, which is worse than not having the
        # feature at all. Dropped outright rather than just hidden in the UI.
        _drop_column_if_exists(conn, "sandbox_samples", "vt_score")
        conn.execute("DROP TABLE IF EXISTS sandbox_detonations")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sandbox_samples_sha256 ON sandbox_samples(sha256)")

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
        conn.commit()
    finally:
        conn.close()


def find_sample_id_for_known_url(url):
    """Has this exact URL already led to successfully-stored content? Returns
    the sample_id if so (used to skip a redundant re-download), else None."""
    conn = sqlite3.connect(config.DB_PATH)
    try:
        row = conn.execute(
            "SELECT sample_id FROM sandbox_fetch_attempts "
            "WHERE url = ? AND status IN ('fetched', 'dedup_content') AND sample_id IS NOT NULL "
            "ORDER BY id DESC LIMIT 1",
            (url,),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def get_sample_by_sha256(sha256):
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM sandbox_samples WHERE sha256 = ?", (sha256,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def insert_sample(sha256, md5, file_size, mime_type, architecture, local_path):
    """Insert a new unique-content row, or return the existing one's id on a
    sha256 collision (same bytes seen before, from a different URL/event)."""
    conn = sqlite3.connect(config.DB_PATH)
    try:
        cur = conn.execute(
            "INSERT INTO sandbox_samples (sha256, md5, file_size, mime_type, architecture, first_seen_at, local_path) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(sha256) DO NOTHING",
            (sha256, md5, file_size, mime_type, architecture, _now(), local_path),
        )
        conn.commit()
        if cur.rowcount == 0:
            existing = conn.execute("SELECT id FROM sandbox_samples WHERE sha256 = ?", (sha256,)).fetchone()
            return existing[0]
        return cur.lastrowid
    finally:
        conn.close()


def find_retryable_urls(retryable_statuses, max_attempts, max_age_hours, limit=200):
    """One row per URL whose MOST RECENT attempt landed in retryable_statuses,
    happened within the last max_age_hours, and whose total attempt count so
    far is below max_attempts — a URL that eventually succeeded, was
    dedup'd, or was SSRF-blocked is never a candidate even if an earlier
    attempt failed, since only the latest status per URL is considered. The
    age cutoff keeps this from re-fetching long-stale, likely-never-malware
    URLs indefinitely (see the config.py comment). Backoff timing (which
    retry number this would be, so the caller can pick the right delay) is
    the caller's job — this just finds candidates, oldest-attempted first so
    the most overdue go first."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        placeholders = ",".join("?" * len(retryable_statuses))
        rows = conn.execute(f"""
            SELECT url, source_event_id, source_ip, attempted_at, attempt_count
            FROM (
                SELECT a.url, a.source_event_id, a.source_ip, a.status, a.attempted_at,
                       (SELECT COUNT(*) FROM sandbox_fetch_attempts b WHERE b.url = a.url) AS attempt_count
                FROM sandbox_fetch_attempts a
                WHERE a.id IN (SELECT MAX(id) FROM sandbox_fetch_attempts GROUP BY url)
            )
            WHERE status IN ({placeholders}) AND attempt_count < ?
                  AND attempted_at > strftime('%Y-%m-%dT%H:%M:%S', 'now', ?)
            ORDER BY attempted_at ASC
            LIMIT ?
        """, (*retryable_statuses, max_attempts, f"-{max_age_hours} hours", limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def insert_fetch_attempt(url, source_event_id, source_ip, status, error, sample_id, duration_ms):
    """The record that makes every attempt visible, regardless of outcome —
    this is the whole point of splitting attempts out from samples."""
    conn = sqlite3.connect(config.DB_PATH)
    try:
        conn.execute(
            "INSERT INTO sandbox_fetch_attempts "
            "(attempted_at, url, source_event_id, source_ip, status, error, sample_id, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (_now(), url, source_event_id, source_ip, status, error, sample_id, duration_ms),
        )
        conn.commit()
    finally:
        conn.close()
