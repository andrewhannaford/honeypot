"""
Honeypot test suite
Run from the honeypot directory:  python -m pytest tests/ -v
"""

import os
import sys
import json
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

# Ensure imports resolve from project root regardless of where pytest is invoked
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_ROOT)
sys.path.insert(0, _ROOT)

import ratelimit


def setUpModule():
    """Initialise the honeypot DB once before any service-handler test runs.
    Without this, log_event raises inside handlers (table doesn't exist),
    causing the handler to exit before sending a response."""
    from logger import init_db
    init_db()


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _prime_ratelimit(ip="127.0.0.1"):
    """Call check_and_acquire so the handler's release() call is balanced."""
    ratelimit.configure(200, 60, 100)
    ratelimit._active_count = 0
    ratelimit._ip_timestamps.clear()
    ratelimit.check_and_acquire(ip)


def _run_handler(handler_fn, server_sock, addr=("127.0.0.1", 9999)):
    """Run a service handler in a daemon thread; return the thread."""
    t = threading.Thread(target=handler_fn, args=(server_sock, addr), daemon=True)
    t.start()
    return t


# ─────────────────────────────────────────────────────────────────
# 1. Rate limiter
# ─────────────────────────────────────────────────────────────────

class TestRatelimit(unittest.TestCase):

    def setUp(self):
        ratelimit.configure(5, 60, 3)
        ratelimit._active_count = 0
        ratelimit._ip_timestamps.clear()

    def test_allows_connection_under_limit(self):
        self.assertTrue(ratelimit.check_and_acquire("1.2.3.4"))
        ratelimit.release()

    def test_blocks_ip_over_rate(self):
        ip = "5.5.5.5"
        for _ in range(3):
            self.assertTrue(ratelimit.check_and_acquire(ip))
        self.assertFalse(ratelimit.check_and_acquire(ip))
        for _ in range(3):
            ratelimit.release()

    def test_different_ips_are_independent(self):
        ratelimit.configure(10, 60, 3)
        for i in range(3):
            ratelimit.check_and_acquire(f"10.0.0.{i + 1}")
        # A fresh IP should still be allowed even though another IP hit its limit
        self.assertTrue(ratelimit.check_and_acquire("10.0.0.99"))
        for _ in range(4):
            ratelimit.release()

    def test_global_cap_enforced(self):
        ratelimit.configure(2, 60, 10)
        ratelimit._active_count = 0
        self.assertTrue(ratelimit.check_and_acquire("1.1.1.1"))
        self.assertTrue(ratelimit.check_and_acquire("2.2.2.2"))
        self.assertFalse(ratelimit.check_and_acquire("3.3.3.3"))  # cap hit
        ratelimit.release()
        ratelimit.release()

    def test_release_decrements_active_count(self):
        ratelimit.check_and_acquire("9.9.9.9")
        self.assertEqual(ratelimit._active_count, 1)
        ratelimit.release()
        self.assertEqual(ratelimit._active_count, 0)

    def test_connection_allowed_after_release_frees_cap(self):
        ratelimit.configure(1, 60, 10)
        self.assertTrue(ratelimit.check_and_acquire("a"))
        self.assertFalse(ratelimit.check_and_acquire("b"))  # cap hit
        ratelimit.release()
        self.assertTrue(ratelimit.check_and_acquire("b"))  # now free
        ratelimit.release()


# ─────────────────────────────────────────────────────────────────
# 2. Telnet IAC parser
# ─────────────────────────────────────────────────────────────────

from services.telnet_honey import _recv_line as _telnet_recv_line


class TestTelnetIACParser(unittest.TestCase):

    def _make_pair(self):
        server, client = socket.socketpair()
        server.settimeout(2)
        client.settimeout(2)
        return server, client

    def _send_and_recv(self, data):
        server, client = self._make_pair()
        client.sendall(data)
        client.close()
        result = _telnet_recv_line(server)
        server.close()
        return result

    def test_plain_text(self):
        result = self._send_and_recv(b"admin\r\n")
        self.assertEqual(result, "admin")

    def test_plain_text_lf_only(self):
        result = self._send_and_recv(b"root\n")
        self.assertEqual(result, "root")

    def test_strips_3byte_will_sequence(self):
        # IAC WILL ECHO before the username
        data = b"\xff\xfb\x01admin\r\n"
        self.assertEqual(self._send_and_recv(data), "admin")

    def test_strips_3byte_do_sequence(self):
        data = b"\xff\xfd\x03admin\r\n"
        self.assertEqual(self._send_and_recv(data), "admin")

    def test_strips_3byte_wont_sequence(self):
        data = b"\xff\xfc\x01admin\r\n"
        self.assertEqual(self._send_and_recv(data), "admin")

    def test_strips_3byte_dont_sequence(self):
        data = b"\xff\xfe\x01admin\r\n"
        self.assertEqual(self._send_and_recv(data), "admin")

    def test_strips_subnegotiation(self):
        # IAC SB ... IAC SE surrounding the username
        data = b"\xff\xfa\x18\x00VT100\xff\xf0admin\r\n"
        self.assertEqual(self._send_and_recv(data), "admin")

    def test_iac_interspersed_with_text(self):
        # IAC sequence in the middle of the username
        data = b"ad\xff\xfb\x01min\r\n"
        self.assertEqual(self._send_and_recv(data), "admin")

    def test_returns_none_on_closed_socket(self):
        server, client = self._make_pair()
        client.close()
        result = _telnet_recv_line(server)
        server.close()
        self.assertIsNone(result)


# ─────────────────────────────────────────────────────────────────
# 3. Logger
# ─────────────────────────────────────────────────────────────────

class TestLogger(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._db = os.path.join(self._tmp, "test.db")
        # logger uses a local `DB_PATH` copied from config at import time,
        # so we must patch logger.DB_PATH directly.
        import logger as logger_mod
        self._logger_mod = logger_mod
        self._orig_db = logger_mod.DB_PATH
        logger_mod.DB_PATH = self._db

    def tearDown(self):
        self._logger_mod.DB_PATH = self._orig_db

    def test_init_db_creates_table(self):
        import sqlite3
        from logger import init_db
        init_db()
        conn = sqlite3.connect(self._db)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(tables)

    def test_log_event_inserts_row(self):
        import sqlite3
        from logger import init_db, log_event
        init_db()
        log_event("1.2.3.4", 22, "SSH", "credential", {"username": "root", "password": "pass"})
        conn = sqlite3.connect(self._db)
        row = conn.execute("SELECT * FROM events").fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[2], "1.2.3.4")   # ip
        self.assertEqual(row[4], "SSH")         # service
        self.assertEqual(row[5], "credential")  # event_type

    def test_log_event_returns_dict(self):
        from logger import init_db, log_event
        init_db()
        result = log_event("5.5.5.5", 21, "FTP", "connect")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["ip"], "5.5.5.5")
        self.assertEqual(result["service"], "FTP")


# ─────────────────────────────────────────────────────────────────
# 4. Discord alerts
# ─────────────────────────────────────────────────────────────────

class TestDiscordAlerts(unittest.TestCase):

    def test_no_op_when_no_webhook_url(self):
        # discord.py copies DISCORD_WEBHOOK_URL into its own namespace at import,
        # so we must patch the module-level name directly.
        with patch("alerts.discord.DISCORD_WEBHOOK_URL", ""):
            with patch("requests.post") as mock_post:
                from alerts.discord import send_alert
                send_alert("SSH", "1.2.3.4", "test", alert_type="connect")
                time.sleep(0.1)
                mock_post.assert_not_called()

    def test_connect_alert_suppressed_when_disabled(self):
        # Patch module-level names directly — no reload needed or safe here.
        with patch("alerts.discord.DISCORD_WEBHOOK_URL", "https://example.com/webhook"):
            with patch("alerts.discord.ALERT_ON_CONNECT", False):
                with patch("alerts.discord._post") as mock_post:
                    from alerts.discord import send_alert
                    send_alert("SSH", "1.2.3.4", "New connection", alert_type="connect")
                    time.sleep(0.2)
                    mock_post.assert_not_called()

    def test_credential_alert_uses_red_color(self):
        captured = {}

        # Patch _post directly so we don't race against the background thread
        # outliving the requests.post mock context.
        with patch("alerts.discord.DISCORD_WEBHOOK_URL", "https://example.com/hook"):
            with patch("alerts.discord._post", side_effect=lambda p: captured.update({"payload": p})):
                from alerts.discord import send_alert
                send_alert("SSH", "1.2.3.4", "Login attempt", alert_type="credential")
                time.sleep(0.2)

        self.assertIn("payload", captured)
        self.assertEqual(captured["payload"]["embeds"][0]["color"], 0xFF4444)

    def test_connect_alert_uses_orange_color(self):
        captured = {}

        with patch("alerts.discord.DISCORD_WEBHOOK_URL", "https://example.com/hook"):
            with patch("alerts.discord._post", side_effect=lambda p: captured.update({"payload": p})):
                from alerts.discord import send_alert
                send_alert("FTP", "2.3.4.5", "New connection", alert_type="connect")
                time.sleep(0.2)

        self.assertIn("payload", captured)
        self.assertEqual(captured["payload"]["embeds"][0]["color"], 0xFFA500)


# ─────────────────────────────────────────────────────────────────
# 5. HTTP service
# ─────────────────────────────────────────────────────────────────

class TestHTTPService(unittest.TestCase):

    def test_build_response_is_valid_http(self):
        from services.http_honey import _build_response
        resp = _build_response()
        self.assertTrue(resp.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"\r\n\r\n", resp)
        self.assertIn(b"Apache", resp)

    def test_handler_responds_to_get_request(self):
        from services.http_honey import _handle_client
        _prime_ratelimit()
        server, client = socket.socketpair()
        client.settimeout(3)

        with patch("services.http_honey.send_alert"):
            t = _run_handler(_handle_client, server)
            client.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            response = b""
            try:
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            client.close()
            t.join(timeout=3)

        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK"))
        self.assertIn(b"Apache2 Ubuntu Default Page", response)

    def test_handler_handles_split_headers(self):
        """Verify the recv loop reassembles headers split across two sends."""
        from services.http_honey import _handle_client
        _prime_ratelimit()
        server, client = socket.socketpair()
        client.settimeout(3)

        with patch("services.http_honey.send_alert"):
            t = _run_handler(_handle_client, server)
            # Send headers in two chunks with a small delay to simulate TCP splitting
            client.sendall(b"GET / HTTP/1.1\r\nHost: exam")
            time.sleep(0.05)
            client.sendall(b"ple.com\r\n\r\n")

            response = b""
            try:
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            client.close()
            t.join(timeout=3)

        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK"))


# ─────────────────────────────────────────────────────────────────
# 6. FTP service
# ─────────────────────────────────────────────────────────────────

class TestFTPService(unittest.TestCase):

    def test_banner_sent_on_connect(self):
        from services.ftp_honey import _handle_client
        _prime_ratelimit()
        server, client = socket.socketpair()
        client.settimeout(3)

        with patch("services.ftp_honey.send_alert"):
            t = _run_handler(_handle_client, server)
            banner = client.recv(256)
            client.close()
            t.join(timeout=3)

        self.assertIn(b"220", banner)

    def test_captures_credentials(self):
        logged = []

        def fake_log(ip, port, service, event_type, data=None):
            logged.append({"event_type": event_type, "data": data})
            return {}

        from services.ftp_honey import _handle_client
        _prime_ratelimit()
        server, client = socket.socketpair()
        client.settimeout(3)

        with patch("services.ftp_honey.log_event", side_effect=fake_log):
            with patch("services.ftp_honey.send_alert"):
                t = _run_handler(_handle_client, server)
                client.recv(256)  # banner
                client.sendall(b"USER admin\r\n")
                client.recv(256)  # 331
                client.sendall(b"PASS secret123\r\n")
                client.recv(256)  # 530
                client.sendall(b"QUIT\r\n")
                client.close()
                t.join(timeout=3)

        cred_events = [e for e in logged if e["event_type"] == "credential"]
        self.assertEqual(len(cred_events), 1)
        self.assertEqual(cred_events[0]["data"]["username"], "admin")
        self.assertEqual(cred_events[0]["data"]["password"], "secret123")

    def test_rejects_login(self):
        from services.ftp_honey import _handle_client
        _prime_ratelimit()
        server, client = socket.socketpair()
        client.settimeout(3)

        with patch("services.ftp_honey.log_event", return_value={}):
            with patch("services.ftp_honey.send_alert"):
                t = _run_handler(_handle_client, server)
                client.recv(256)               # banner
                client.sendall(b"USER root\r\n")
                client.recv(256)               # 331 — must read this before sending PASS
                client.sendall(b"PASS toor\r\n")
                response = client.recv(512)    # 530
                client.close()
                t.join(timeout=3)

        self.assertIn(b"530", response)


# ─────────────────────────────────────────────────────────────────
# 7. Telnet service (full handler)
# ─────────────────────────────────────────────────────────────────

class TestTelnetService(unittest.TestCase):

    def test_captures_credentials(self):
        logged = []

        def fake_log(ip, port, service, event_type, data=None):
            logged.append({"event_type": event_type, "data": data})
            return {}

        from services.telnet_honey import _handle_client
        _prime_ratelimit()
        server, client = socket.socketpair()
        client.settimeout(3)

        with patch("services.telnet_honey.log_event", side_effect=fake_log):
            with patch("services.telnet_honey.send_alert"):
                t = _run_handler(_handle_client, server)
                client.recv(512)  # negotiation + prompt
                client.sendall(b"admin\r\n")
                client.recv(256)  # "Password: "
                client.sendall(b"hunter2\r\n")
                client.recv(256)  # "Login incorrect"
                client.close()
                t.join(timeout=3)

        cred_events = [e for e in logged if e["event_type"] == "credential"]
        self.assertEqual(len(cred_events), 1)
        self.assertEqual(cred_events[0]["data"]["username"], "admin")
        self.assertEqual(cred_events[0]["data"]["password"], "hunter2")


# ─────────────────────────────────────────────────────────────────
# 8. Dashboard
# ─────────────────────────────────────────────────────────────────

class TestDashboard(unittest.TestCase):

    def setUp(self):
        # Point the dashboard at a fresh temp DB
        self._tmp = tempfile.mkdtemp()
        self._db = os.path.join(self._tmp, "dash_test.db")
        import config
        self._orig_db = config.DB_PATH
        config.DB_PATH = self._db

        # Seed the DB
        import sqlite3
        conn = sqlite3.connect(self._db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data TEXT
            )
        """)
        conn.execute(
            "INSERT INTO events VALUES (NULL,'2024-01-01T00:00:00','1.2.3.4',22,'SSH','credential','{\"username\":\"root\",\"password\":\"pass\"}')"
        )
        conn.execute(
            "INSERT INTO events VALUES (NULL,'2024-01-01T00:00:01','1.2.3.4',80,'HTTP','connect',NULL)"
        )
        conn.commit()
        conn.close()

        # Reload dashboard with the test DB and a known token
        import importlib
        import dashboard.app as dash_mod
        with patch("config.DB_PATH", self._db):
            with patch("config.DASHBOARD_TOKEN", "testtoken"):
                importlib.reload(dash_mod)
        self._app = dash_mod.app
        self._app.config["TESTING"] = True
        self._client = self._app.test_client()
        self._token = "testtoken"

    def tearDown(self):
        import config
        config.DB_PATH = self._orig_db

    def _auth(self):
        import base64
        creds = base64.b64encode(b"user:testtoken").decode()
        return {"Authorization": f"Basic {creds}"}

    def test_index_requires_auth(self):
        resp = self._client.get("/")
        self.assertEqual(resp.status_code, 401)

    def test_api_events_requires_auth(self):
        resp = self._client.get("/api/events")
        self.assertEqual(resp.status_code, 401)

    def test_api_stats_requires_auth(self):
        resp = self._client.get("/api/stats")
        self.assertEqual(resp.status_code, 401)

    def test_index_ok_with_auth(self):
        resp = self._client.get("/", headers=self._auth())
        self.assertEqual(resp.status_code, 200)

    def test_api_events_returns_list(self):
        resp = self._client.get("/api/events", headers=self._auth())
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)

    def test_api_stats_structure(self):
        resp = self._client.get("/api/stats", headers=self._auth())
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("total", data)
        self.assertIn("by_service", data)
        self.assertIn("top_ips", data)
        self.assertIn("credential_count", data)
        self.assertIn("credentials", data)
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["credential_count"], 1)

    def test_wrong_password_rejected(self):
        import base64
        bad_creds = base64.b64encode(b"user:wrongpassword").decode()
        resp = self._client.get("/", headers={"Authorization": f"Basic {bad_creds}"})
        self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
