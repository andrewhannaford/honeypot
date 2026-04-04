import unittest
import json
import io
import csv
from datetime import datetime, timezone
from dashboard.app import app
from logger import init_db, log_event, clear_event_callbacks
from config import DB_PATH
import os

class TestDashboard(unittest.TestCase):
    def setUp(self):
        # Ensure fresh DB for each test
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()
        clear_event_callbacks() # Prevent SSE/ThreatIntel from running in stats tests
        self.client = app.test_client()

    def test_api_timeline_returns_list(self):
        log_event("1.1.1.1", 22, "SSH", "connect")
        res = self.client.get("/api/timeline")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)
        self.assertTrue(len(data) > 0)
        self.assertIn("hour", data[0])
        self.assertIn("count", data[0])

    def test_api_geo_stats_returns_list(self):
        # log_event triggers geo_lookup
        log_event("8.8.8.8", 80, "HTTP", "request")
        res = self.client.get("/api/geo-stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)
        # 8.8.8.8 should have a country in a real run, but geoip2fast might 
        # return None in some environments if not fully loaded.
        # We just check structure here.

    def test_api_events_filtering(self):
        log_event("1.1.1.1", 22, "SSH", "connect")
        log_event("2.2.2.2", 80, "HTTP", "request")
        
        # Filter by service
        res = self.client.get("/api/events?service=SSH")
        data = res.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["service"], "SSH")

        # Filter by IP search
        res = self.client.get("/api/events?search=2.2")
        data = res.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["ip"], "2.2.2.2")

    def test_export_csv_headers_and_content(self):
        log_event("1.2.3.4", 22, "SSH", "connect", {"test": "data"})
        res = self.client.get("/api/events/export.csv")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")
        
        content = res.data.decode()
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "1.2.3.4")
        self.assertEqual(rows[0]["service"], "SSH")

if __name__ == "__main__":
    unittest.main()
