import unittest
from unittest.mock import MagicMock, patch
import base64
from services.smtp_honey import _handle_client

def socket_bytes(data):
    return [bytes([b]) for b in data]

class TestSMTPHoney(unittest.TestCase):
    def setUp(self):
        self.sock = MagicMock()
        self.addr = ("1.2.3.4", 12345)

    @patch("services.smtp_honey.log_event")
    @patch("services.smtp_honey.send_alert")
    def test_auth_plain_decoded(self, mock_alert, mock_log):
        auth_str = base64.b64encode(b"\x00user123\x00pass456").decode()
        # SMTP recv uses recv(1024), so simple side_effect is fine if it matches the calls
        self.sock.recv.side_effect = [
            f"AUTH PLAIN {auth_str}\r\n".encode(),
            b"QUIT\r\n",
            b""
        ]
        _handle_client(self.sock, self.addr)
        
        mock_log.assert_any_call("1.2.3.4", 25, "SMTP", "credential", 
                                 {"username": "user123", "password": "pass456", "mech": "PLAIN"})

    @patch("services.smtp_honey.save_payload")
    @patch("services.smtp_honey.log_event")
    def test_full_session_logged(self, mock_log, mock_save):
        mock_log.return_value = {"rowid": 1}
        self.sock.recv.side_effect = [
            b"EHLO test\r\n",
            b"MAIL FROM:<test@example.com>\r\n",
            b"RCPT TO:<target@victim.com>\r\n",
            b"DATA\r\n",
            b"Subject: Hello\r\n",
            b"This is a test body\r\n",
            b".\r\n",
            b"QUIT\r\n",
            b""
        ]
        _handle_client(self.sock, self.addr)

        mock_log.assert_any_call("1.2.3.4", 25, "SMTP", "email_attempt", unittest.mock.ANY)
        args = [call.args for call in mock_log.call_args_list if len(call.args) > 3 and call.args[3] == "email_attempt"][0]
        data = args[4]
        self.assertEqual(data["from"], "test@example.com")
        self.assertEqual(data["subject"], "Hello")
        # Payload should be saved with the email body
        mock_save.assert_called_once()
        saved_data = mock_save.call_args[0][2]
        self.assertIn(b"This is a test body", saved_data)

if __name__ == "__main__":
    unittest.main()
