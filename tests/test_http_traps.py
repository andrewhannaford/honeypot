import unittest
from unittest.mock import MagicMock, patch
from services.http_honey import _handle_client

class TestHTTPTraps(unittest.TestCase):
    def setUp(self):
        self.sock = MagicMock()
        self.addr = ("1.2.3.4", 54321)

    @patch("services.http_honey.log_event")
    def test_wp_login_get(self, mock_log):
        self.sock.recv.side_effect = [b"GET /wp-login.php HTTP/1.1\r\n\r\n", b""]
        _handle_client(self.sock, self.addr)
        
        mock_log.assert_any_call("1.2.3.4", 80, "HTTP", "trap_hit", {"path": "/wp-login.php"})
        # Check if WP login form is sent
        all_sent = b"".join(call.args[0] for call in self.sock.sendall.call_args_list)
        self.assertIn(b"loginform", all_sent)

    @patch("services.http_honey.log_event")
    @patch("services.http_honey.send_alert")
    def test_wp_login_post(self, mock_alert, mock_log):
        self.sock.recv.side_effect = [b"POST /wp-login.php HTTP/1.1\r\nContent-Length: 17\r\n\r\nlog=admin&pwd=pass", b""]
        _handle_client(self.sock, self.addr)
        
        mock_log.assert_any_call("1.2.3.4", 80, "HTTP", "credential", {"username": "admin", "password": "pass", "path": "/wp-login.php"})
        mock_alert.assert_called_with("HTTP", "1.2.3.4", unittest.mock.ANY, alert_type="credential")

    @patch("services.http_honey.log_event")
    def test_dotenv_trap(self, mock_log):
        self.sock.recv.side_effect = [b"GET /.env HTTP/1.1\r\n\r\n", b""]
        _handle_client(self.sock, self.addr)
        
        mock_log.assert_any_call("1.2.3.4", 80, "HTTP", "trap_hit", {"path": "/.env"})
        all_sent = b"".join(call.args[0] for call in self.sock.sendall.call_args_list)
        self.assertIn(b"DB_PASSWORD", all_sent)

    @patch("services.http_honey.log_event")
    def test_wp_admin_redirect(self, mock_log):
        self.sock.recv.side_effect = [b"GET /wp-admin HTTP/1.1\r\n\r\n", b""]
        _handle_client(self.sock, self.addr)
        
        mock_log.assert_any_call("1.2.3.4", 80, "HTTP", "trap_hit", {"path": "/wp-admin"})
        all_sent = b"".join(call.args[0] for call in self.sock.sendall.call_args_list)
        self.assertIn(b"301 Moved Permanently", all_sent)
        self.assertIn(b"Location: /wp-login.php", all_sent)

if __name__ == "__main__":
    unittest.main()
