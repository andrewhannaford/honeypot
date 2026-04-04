import sqlite3
import os
import json
import logging
from datetime import datetime, timezone
from config import LOG_DIR, DATA_DIR, DB_PATH

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# File logger
_file_logger = logging.getLogger("honeypot")
_file_logger.setLevel(logging.INFO)
_file_logger.propagate = False  # don't pass events up to the root logger
_handler = logging.FileHandler(os.path.join(LOG_DIR, "honeypot.log"))
_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
_file_logger.addHandler(_handler)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    # WAL mode handles concurrent writes from multiple threads without locking errors
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
    conn.commit()
    conn.close()


# init_db() is called explicitly from main.py after startup


def log_event(ip, port, service, event_type, data=None):
    timestamp = datetime.now(timezone.utc).isoformat()
    data_str = json.dumps(data) if data is not None else None

    _file_logger.info(f"[{service}] {event_type} from {ip}:{port} | {data_str}")

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO events (timestamp, ip, port, service, event_type, data) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, ip, port, service, event_type, data_str),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "timestamp": timestamp,
        "ip": ip,
        "port": port,
        "service": service,
        "event_type": event_type,
        "data": data,
    }
