"""
Logger and DB migration tests. Run from project root:
  python -m pytest tests/test_logger.py -v
"""

import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_ROOT)
sys.path.insert(0, _ROOT)


def _reload_logger(db_path, log_dir, data_dir):
    import importlib

    with patch("config.DB_PATH", db_path), patch("config.LOG_DIR", log_dir), patch(
        "config.DATA_DIR", data_dir
    ):
        import logger

        importlib.reload(logger)
        return logger


class TestLoggerDB(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._db = os.path.join(self._tmp, "t.db")
        self._logs = os.path.join(self._tmp, "logs")
        self._data = os.path.join(self._tmp, "data")
        os.makedirs(self._logs, exist_ok=True)
        os.makedirs(self._data, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        # Reload logger so other test modules see production config paths again.
        import importlib

        import logger

        importlib.reload(logger)

    def test_schema_has_geo_columns(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        conn = sqlite3.connect(self._db)
        try:
            rows = conn.execute("PRAGMA table_info(events)").fetchall()
            names = {r[1] for r in rows}
            for col in ("country", "city", "lat", "lon", "abuse_score"):
                self.assertIn(col, names, f"missing column {col}")
        finally:
            conn.close()

    def test_suricata_table_created(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        conn = sqlite3.connect(self._db)
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='suricata_alerts'"
            ).fetchone()
            self.assertIsNotNone(row)
        finally:
            conn.close()

    def test_indexes_created(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        conn = sqlite3.connect(self._db)
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
            ).fetchall()
            names = {r[0] for r in rows}
            self.assertIn("idx_events_timestamp", names)
            self.assertIn("idx_events_ip", names)
            self.assertIn("idx_suricata_timestamp", names)
        finally:
            conn.close()

    def test_migration_idempotent(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        lg.init_db()
        lg.init_db()

    def test_log_event_returns_rowid(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        out = lg.log_event("1.2.3.4", 22, "SSH", "connect", None)
        self.assertIn("rowid", out)
        self.assertIsInstance(out["rowid"], int)
        self.assertGreater(out["rowid"], 0)

    def test_callback_called(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        seen = []

        def cb(ev):
            seen.append(ev)

        lg.register_event_callback(cb)
        lg.log_event("10.0.0.1", 80, "HTTP", "connect", {"x": 1})
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["ip"], "10.0.0.1")
        self.assertEqual(seen[0]["event_type"], "connect")

    def test_register_callback_dedupes(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        seen = []

        def cb(ev):
            seen.append(ev)

        lg.register_event_callback(cb)
        lg.register_event_callback(cb)
        lg.log_event("10.0.0.1", 80, "HTTP", "connect", None)
        self.assertEqual(len(seen), 1)

    def test_bad_callback_doesnt_crash_log_event(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()

        def bad(_ev):
            raise RuntimeError("boom")

        lg.register_event_callback(bad)
        out = lg.log_event("10.0.0.2", 80, "HTTP", "connect", None)
        self.assertIn("rowid", out)

    def test_bad_callback_emits_log_record(self):
        import logging

        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()

        def bad(_ev):
            raise RuntimeError("boom")

        lg.register_event_callback(bad)
        with self.assertLogs("logger", level="ERROR") as captured:
            lg.log_event("10.0.0.8", 80, "HTTP", "connect", None)
        self.assertTrue(
            any("event callback" in r.getMessage() for r in captured.records),
            msg=captured.output,
        )

    def test_jsonl_written(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        lg.log_event("10.0.0.3", 22, "SSH", "credential", {"u": "a"})
        path = os.path.join(self._logs, "honeypot.jsonl")
        self.assertTrue(os.path.isfile(path))
        with open(path, encoding="utf-8") as f:
            line = f.readline()
        obj = json.loads(line)
        self.assertEqual(obj["ip"], "10.0.0.3")
        self.assertEqual(obj["event_type"], "credential")

    def test_private_ip_geo_null_in_database(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        lg.log_event("10.0.0.99", 22, "SSH", "connect", None)
        conn = sqlite3.connect(self._db)
        try:
            row = conn.execute(
                "SELECT country, city, lat, lon FROM events WHERE ip = ?",
                ("10.0.0.99",),
            ).fetchone()
            self.assertIsNone(row[0])
            self.assertIsNone(row[1])
            self.assertIsNone(row[2])
            self.assertIsNone(row[3])
        finally:
            conn.close()

    def test_jsonl_contains_geo_fields_for_private_ip(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        lg.log_event("10.0.0.50", 80, "HTTP", "connect", None)
        path = os.path.join(self._logs, "honeypot.jsonl")
        with open(path, encoding="utf-8") as f:
            obj = json.loads(f.readline())
        self.assertIn("country", obj)
        self.assertIn("lat", obj)
        self.assertIsNone(obj["country"])
        self.assertIsNone(obj["lat"])

    def test_concurrent_log_lines_are_valid_json(self):
        lg = _reload_logger(self._db, self._logs, self._data)
        lg.init_db()
        errors = []
        threads = []

        def worker(n):
            try:
                for i in range(20):
                    lg.log_event(f"192.0.2.{n}", 22, "SSH", "connect", {"i": i})
            except Exception as e:
                errors.append(e)

        for t in range(8):
            threads.append(threading.Thread(target=worker, args=(t,)))
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=30)
        self.assertEqual(errors, [])
        path = os.path.join(self._logs, "honeypot.jsonl")
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    json.loads(line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
