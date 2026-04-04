import unittest
from unittest.mock import MagicMock, patch
import sqlite3
from threat_intel import enrich_event, _update_db
from config import DB_PATH, ABUSEIPDB_API_KEY
from logger import init_db
import os
import time

class TestThreatIntel(unittest.TestCase):
    def setUp(self):
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()
        self.mock_event = {
            "rowid": 1,
            "ip": "8.8.8.8",
            "event_type": "credential",
            "service": "SSH"
        }

    def test_update_db_updates_score(self):
        # Insert event row
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO events (timestamp, ip, port, service, event_type) VALUES (?,?,?,?,?)",
                     ("2026-04-04T12:00:00", "8.8.8.8", 22, "SSH", "credential"))
        conn.commit()
        rowid = conn.execute("SELECT id FROM events").fetchone()[0]
        conn.close()

        _update_db(rowid, 100)
        
        # Verify
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT abuse_score FROM events WHERE id = ?", (rowid,)).fetchone()
        self.assertEqual(row[0], 100)
        conn.close()

    @patch("threat_intel.ABUSEIPDB_API_KEY", "fake_key")
    @patch("threat_intel._executor.submit")
    def test_enrich_event_submits_credential_to_executor(self, mock_submit):
        enrich_event(self.mock_event)
        mock_submit.assert_called_once()

    @patch("threat_intel.ABUSEIPDB_API_KEY", "fake_key")
    @patch("threat_intel._executor.submit")
    def test_enrich_event_skips_low_value_events(self, mock_submit):
        low_value_event = self.mock_event.copy()
        low_value_event["event_type"] = "connect"
        enrich_event(low_value_event)
        mock_submit.assert_not_called()

    @patch("threat_intel.ABUSEIPDB_API_KEY", "fake_key")
    @patch("threat_intel._executor.submit")
    def test_enrich_event_skips_private_ips(self, mock_submit):
        private_event = self.mock_event.copy()
        private_event["ip"] = "192.168.1.1"
        enrich_event(private_event)
        mock_submit.assert_not_called()

if __name__ == "__main__":
    unittest.main()
