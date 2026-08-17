import unittest
import json
import io
import csv
import sqlite3
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

    def test_api_search_with_query_language(self):
        log_event("1.1.1.1", 22, "SSH", "credential", {"username": "root", "password": "x"})
        log_event("2.2.2.2", 80, "HTTP", "connect")

        res = self.client.get("/api/search?q=" + "service:SSH AND event_type:credential")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["results"][0]["ip"], "1.1.1.1")

    def test_api_search_or_across_services(self):
        log_event("1.1.1.1", 22, "SSH", "connect")
        log_event("2.2.2.2", 23, "TELNET", "connect")
        log_event("3.3.3.3", 80, "HTTP", "connect")

        res = self.client.get("/api/search?q=" + "service:SSH OR service:TELNET")
        data = res.get_json()
        self.assertEqual(data["total"], 2)

    def test_api_search_empty_query_returns_everything(self):
        log_event("1.1.1.1", 22, "SSH", "connect")
        log_event("2.2.2.2", 80, "HTTP", "connect")

        res = self.client.get("/api/search")
        data = res.get_json()
        self.assertEqual(data["total"], 2)

    def test_api_search_bad_query_returns_400_not_500(self):
        res = self.client.get("/api/search?q=" + "nonsense_field:value")
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json())

    def test_api_search_respects_date_range_alongside_query_language(self):
        log_event("1.1.1.1", 22, "SSH", "connect")
        res = self.client.get(
            "/api/search?q=service:SSH&from_date=2099-01-01"
        )
        data = res.get_json()
        self.assertEqual(data["total"], 0)  # event is well before the from_date filter

    def test_api_rules_create_list_toggle_delete(self):
        from unittest.mock import patch
        with patch("rule_builder.reload_suricata", return_value=(True, "ok")):
            res = self.client.post("/api/rules", json={
                "message": "Test rule", "protocol": "tcp", "dest_port": "4444",
                "classtype": "attempted-recon", "contents": ["evil"],
            })
            self.assertEqual(res.status_code, 201)
            rule_id = res.get_json()["id"]

            res = self.client.get("/api/rules")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(len(res.get_json()), 1)

            res = self.client.post(f"/api/rules/{rule_id}/toggle", json={"enabled": False})
            self.assertEqual(res.status_code, 200)
            self.assertFalse(self.client.get("/api/rules").get_json()[0]["enabled"])

            res = self.client.delete(f"/api/rules/{rule_id}")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(self.client.get("/api/rules").get_json(), [])

    def test_api_rules_invalid_fields_returns_400(self):
        res = self.client.post("/api/rules", json={"message": "", "protocol": "tcp"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json())

    def test_api_rules_classtypes_endpoint(self):
        res = self.client.get("/api/rules/classtypes")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("attempted-recon", data["classtypes"])
        self.assertIn("tcp", data["protocols"])

    def test_api_ids_alert_detail_returns_parsed_raw(self):
        raw = json.dumps({"alert": {"signature": "Test sig"}, "src_ip": "9.9.9.9"})
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO suricata_alerts (timestamp, src_ip, src_port, dst_port, proto, "
            "alert_sig, category, severity, raw) VALUES (?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), "9.9.9.9", 4444, 22, "TCP",
             "Test sig", "Attempted Recon", 2, raw),
        )
        conn.commit()
        alert_id = conn.execute("SELECT id FROM suricata_alerts").fetchone()[0]
        conn.close()

        res = self.client.get(f"/api/ids-alerts/{alert_id}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["src_ip"], "9.9.9.9")
        self.assertEqual(data["raw_parsed"]["src_ip"], "9.9.9.9")

    def test_api_ids_alert_detail_404_for_missing_id(self):
        res = self.client.get("/api/ids-alerts/999999")
        self.assertEqual(res.status_code, 404)

    def test_api_ip_profile_aggregates_events_alerts_and_payloads(self):
        log_event("5.5.5.5", 22, "SSH", "credential", {"username": "root", "password": "x"})
        log_event("5.5.5.5", 22, "SSH", "connect")
        log_event("6.6.6.6", 80, "HTTP", "connect")  # different IP, should not appear

        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO suricata_alerts (timestamp, src_ip, src_port, dst_port, proto, "
            "alert_sig, category, severity, raw) VALUES (?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), "5.5.5.5", 1234, 22, "TCP",
             "SSH brute force", "Attempted Admin", 1, "{}"),
        )
        conn.execute(
            "INSERT INTO payloads (timestamp, event_id, ip, service, filename, local_path, "
            "file_size, md5, sha256, mime_type, vt_score) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), None, "5.5.5.5", "HTTP", "x.bin",
             "/tmp/x.bin", 10, "m", "s", "text/plain", None),
        )
        conn.commit()
        conn.close()

        res = self.client.get("/api/ip/5.5.5.5")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["ip"], "5.5.5.5")
        self.assertEqual(data["total_events"], 2)
        self.assertEqual(len(data["events"]), 2)
        self.assertTrue(all(e["ip"] == "5.5.5.5" for e in data["events"]))
        self.assertEqual(len(data["ids_alerts"]), 1)
        self.assertEqual(data["ids_alerts"][0]["alert_sig"], "SSH brute force")
        self.assertEqual(len(data["payloads"]), 1)

    def test_api_ip_profile_unknown_ip_returns_empty_not_error(self):
        res = self.client.get("/api/ip/1.2.3.4")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["total_events"], 0)
        self.assertEqual(data["events"], [])
        self.assertEqual(data["ids_alerts"], [])
        self.assertEqual(data["payloads"], [])

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
