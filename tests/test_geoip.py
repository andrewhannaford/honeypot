"""
GeoIP wrapper tests. Run from project root: python -m pytest tests/test_geoip.py -v
"""

import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_ROOT)
sys.path.insert(0, _ROOT)


class TestGeoipLookup(unittest.TestCase):
    def test_private_ips_return_empty(self):
        import geoip

        for addr in ("192.168.1.1", "127.0.0.1", "10.0.0.1", "fe80::1"):
            self.assertEqual(geoip.lookup(addr), {}, msg=addr)

    def test_bad_input_returns_empty(self):
        import geoip

        self.assertEqual(geoip.lookup(""), {})
        self.assertEqual(geoip.lookup("not-an-ip"), {})
        self.assertEqual(geoip.lookup("   "), {})

    def test_multicast_returns_empty(self):
        import geoip

        self.assertEqual(geoip.lookup("224.0.0.1"), {})

    def test_lookup_respects_is_private_flag_on_detail(self):
        import importlib
        from unittest.mock import patch

        import geoip

        importlib.reload(geoip)

        class FakeDetail:
            def to_dict(self):
                return {"country_code": "XX", "is_private": True}

        with patch.object(geoip, "_engine") as eng:
            eng.return_value.lookup.return_value = FakeDetail()
            self.assertEqual(geoip.lookup("203.0.113.1"), {})

    def test_public_ip_has_country(self):
        import importlib

        import geoip

        importlib.reload(geoip)
        out = geoip.lookup("8.8.8.8")
        self.assertIn("country", out)
        self.assertTrue(out["country"])

    def test_geo_written_to_db_via_logger(self):
        import importlib

        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "g.db")
        logs = os.path.join(tmp, "logs")
        data = os.path.join(tmp, "data")
        os.makedirs(logs, exist_ok=True)
        os.makedirs(data, exist_ok=True)

        with patch("config.DB_PATH", db), patch("config.LOG_DIR", logs), patch(
            "config.DATA_DIR", data
        ):
            import logger

            importlib.reload(logger)

            def fake_geo(ip):
                return {"country": "ZZ", "city": "Testville", "lat": 12.5, "lon": -3.25}

            with patch.object(logger, "geo_lookup", side_effect=fake_geo):
                logger.init_db()
                logger.log_event("198.51.100.1", 22, "SSH", "connect", None)

            conn = sqlite3.connect(db)
            try:
                row = conn.execute(
                    "SELECT country, city, lat, lon FROM events WHERE ip = ?",
                    ("198.51.100.1",),
                ).fetchone()
                self.assertEqual(row[0], "ZZ")
                self.assertEqual(row[1], "Testville")
                self.assertAlmostEqual(row[2], 12.5)
                self.assertAlmostEqual(row[3], -3.25)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
