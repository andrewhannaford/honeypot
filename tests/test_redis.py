import unittest
from unittest.mock import MagicMock, patch
from services.redis_honey import _handle_client

class TestRedisHoney(unittest.TestCase):
    def setUp(self):
        self.sock = MagicMock()
        self.addr = ("1.2.3.4", 12345)
        self.data = b""

    def _set_data(self, data):
        self.data = data
        def side_effect(n):
            chunk = self.data[:n]
            self.data = self.data[n:]
            return chunk
        self.sock.recv.side_effect = side_effect

    @patch("services.redis_honey.log_event")
    @patch("services.redis_honey.send_alert")
    def test_inline_ping(self, mock_alert, mock_log):
        self._set_data(b"PING\r\n")
        _handle_client(self.sock, self.addr)
        self.sock.sendall.assert_any_call(b"+PONG\r\n")

    @patch("services.redis_honey.log_event")
    def test_resp_array_auth(self, mock_log):
        # pass123 is 7 chars
        self._set_data(b"*2\r\n$4\r\nAUTH\r\n$7\r\npass123\r\n")
        _handle_client(self.sock, self.addr)
        
        mock_log.assert_any_call("1.2.3.4", 6379, "REDIS", "credential", {"password": "pass123"})
        self.sock.sendall.assert_any_call(b"+OK\r\n")

    @patch("services.redis_honey.log_event")
    def test_unknown_command_logs(self, mock_log):
        self._set_data(b"FLUSHALL\r\n")
        _handle_client(self.sock, self.addr)
        
        mock_log.assert_any_call("1.2.3.4", 6379, "REDIS", "command", {"cmd": "FLUSHALL"})
        self.sock.sendall.assert_any_call(b"+OK\r\n")

if __name__ == "__main__":
    unittest.main()
