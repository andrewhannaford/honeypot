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

    @patch("services.redis_honey.save_payload")
    @patch("services.redis_honey.log_event")
    def test_unknown_command_logs_and_saves_payload(self, mock_log, mock_save):
        mock_log.return_value = {"rowid": 1}
        self._set_data(b"FLUSHALL\r\n")
        _handle_client(self.sock, self.addr)

        mock_log.assert_any_call("1.2.3.4", 6379, "REDIS", "command", {"cmd": "FLUSHALL"})
        self.sock.sendall.assert_any_call(b"+OK\r\n")
        mock_save.assert_called_once()

    @patch("services.redis_honey.save_payload")
    @patch("services.redis_honey.log_event")
    def test_set_command_saves_payload(self, mock_log, mock_save):
        mock_log.return_value = {"rowid": 2}
        # RESP: SET cron "* * * * * /bin/sh"
        data = b"*3\r\n$3\r\nSET\r\n$4\r\ncron\r\n$18\r\n* * * * * /bin/sh\r\n"
        self._set_data(data)
        _handle_client(self.sock, self.addr)

        mock_log.assert_any_call("1.2.3.4", 6379, "REDIS", "set_attempt", unittest.mock.ANY)
        mock_save.assert_called_once()
        saved_data = mock_save.call_args[0][2]
        self.assertIn(b"* * * * *", saved_data)

    @patch("services.redis_honey.save_payload")
    @patch("services.redis_honey.log_event")
    def test_eval_command_saves_payload(self, mock_log, mock_save):
        mock_log.return_value = {"rowid": 3}
        # Inline EVAL command
        self._set_data(b"EVAL return 1 0\r\n")
        _handle_client(self.sock, self.addr)

        mock_log.assert_any_call("1.2.3.4", 6379, "REDIS", "eval_attempt", unittest.mock.ANY)
        mock_save.assert_called_once()

if __name__ == "__main__":
    unittest.main()
