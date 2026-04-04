import sqlite3
import os
import json
import logging
import threading
from datetime import datetime, timezone
from config import LOG_DIR, DATA_DIR, DB_PATH
from geoip import lookup as geo_lookup

_log = logging.getLogger(__name__)

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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_suricata_timestamp ON suricata_alerts(timestamp)"
    )
    conn.commit()
    conn.close()


def log_event(ip, port, service, event_type, data=None):
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
               country, city, lat, lon)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, ip, port, service, event_type, data_str, country, city, lat, lon),
        )
        conn.commit()
        rowid = cur.lastrowid
    finally:
        conn.close()

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
    }

    line = json.dumps(event_dict, default=str) + "\n"
    with _jsonl_lock:
        _log_file.write(line)

    for cb in _event_callbacks:
        try:
            cb(event_dict)
        except Exception:
            _log.exception("event callback %r failed", cb)

    return event_dict
