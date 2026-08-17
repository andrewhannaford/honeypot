"""
rule_builder.py tests. Run from project root: python -m pytest tests/test_rule_builder.py -v
"""

import json
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_ROOT)
sys.path.insert(0, _ROOT)

import rule_builder
from rule_builder import validate_fields, build_rule_text, RuleError


class TestValidateFields(unittest.TestCase):
    def _valid(self, **overrides):
        base = {
            "message": "Test rule",
            "protocol": "tcp",
            "dest_port": "4444",
            "classtype": "attempted-recon",
            "contents": ["evil"],
        }
        base.update(overrides)
        return base

    def test_valid_fields_pass(self):
        out = validate_fields(self._valid())
        self.assertEqual(out["message"], "Test rule")

    def test_missing_message_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(message=""))

    def test_message_with_quote_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(message='say "hi"'))

    def test_bad_protocol_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(protocol="icmp"))

    def test_bad_port_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(dest_port="not-a-port"))

    def test_port_out_of_range_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(dest_port="99999"))

    def test_port_any_allowed(self):
        out = validate_fields(self._valid(dest_port="any"))
        self.assertEqual(out["dest_port"], "any")

    def test_bad_classtype_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(classtype="made-up-type"))

    def test_content_with_quote_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(contents=['bad"content']))

    def test_http_field_without_http_protocol_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(http_field="http.uri"))

    def test_http_field_with_http_protocol_ok(self):
        out = validate_fields(self._valid(protocol="http", http_field="http.uri", contents=["/admin"]))
        self.assertEqual(out["http_field"], "http.uri")

    def test_no_content_no_threshold_non_http_rejected(self):
        # Would alert on every single packet to the port — must be refused.
        with self.assertRaises(RuleError):
            validate_fields(self._valid(contents=[]))

    def test_no_content_but_threshold_is_ok(self):
        out = validate_fields(self._valid(contents=[], threshold={"count": 3, "seconds": 60}))
        self.assertEqual(out["threshold"], {"count": 3, "seconds": 60})

    def test_no_content_but_http_protocol_is_ok(self):
        out = validate_fields(self._valid(protocol="http", contents=[]))
        self.assertEqual(out["contents"], [])

    def test_bad_threshold_values_rejected(self):
        with self.assertRaises(RuleError):
            validate_fields(self._valid(threshold={"count": 0, "seconds": 60}))

    def test_empty_contents_after_stripping_whitespace_filtered_out(self):
        out = validate_fields(self._valid(contents=["  ", "real", ""]))
        self.assertEqual(out["contents"], ["real"])


class TestBuildRuleText(unittest.TestCase):
    def test_basic_tcp_rule_with_content(self):
        fields = validate_fields({
            "message": "Reverse shell", "protocol": "tcp", "dest_port": "any",
            "classtype": "shellcode-detect", "contents": ["/dev/tcp/"],
        })
        text = build_rule_text(2000001, fields)
        self.assertTrue(text.startswith("alert tcp any any -> any any ("))
        self.assertIn('msg:"Reverse shell"', text)
        self.assertIn('content:"/dev/tcp/"; nocase', text)
        self.assertIn("classtype:shellcode-detect", text)
        self.assertIn("sid:2000001", text)
        self.assertTrue(text.endswith(";)"))

    def test_multiple_contents_all_included(self):
        fields = validate_fields({
            "message": "Redis attack", "protocol": "tcp", "dest_port": "6379",
            "classtype": "attempted-admin", "contents": ["CONFIG", "SET"],
        })
        text = build_rule_text(2000002, fields)
        self.assertIn('content:"CONFIG"', text)
        self.assertIn('content:"SET"', text)

    def test_http_field_applies_to_each_content(self):
        fields = validate_fields({
            "message": "Admin probe", "protocol": "http", "dest_port": "80",
            "classtype": "web-application-attack", "contents": ["/admin"],
            "http_field": "http.uri",
        })
        text = build_rule_text(2000003, fields)
        self.assertIn('http.uri; content:"/admin"', text)

    def test_threshold_included(self):
        fields = validate_fields({
            "message": "Scan", "protocol": "tcp", "dest_port": "22",
            "classtype": "attempted-recon", "contents": [],
            "threshold": {"count": 5, "seconds": 30},
        })
        text = build_rule_text(2000004, fields)
        self.assertIn("threshold:type both, count 5, seconds 30, track by_src", text)

    def test_http_protocol_no_content_gets_syn_flag(self):
        fields = validate_fields({
            "message": "Any HTTP hit", "protocol": "http", "dest_port": "80",
            "classtype": "attempted-recon", "contents": [],
        })
        text = build_rule_text(2000005, fields)
        self.assertIn("flags:S", text)


class TestRuleLifecycle(unittest.TestCase):
    """Exercises create/list/toggle/delete against a real temp SQLite DB, with
    reload_suricata mocked out (covered separately in TestReloadSuricata)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._db = os.path.join(self._tmp, "rules_test.db")
        self._rules_file = os.path.join(self._tmp, "custom.rules")

        conn = sqlite3.connect(self._db)
        conn.execute("""
            CREATE TABLE custom_suricata_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT, sid INTEGER NOT NULL UNIQUE,
                message TEXT NOT NULL, protocol TEXT NOT NULL, dest_port TEXT NOT NULL,
                contents TEXT NOT NULL, http_field TEXT, classtype TEXT NOT NULL,
                threshold_count INTEGER, threshold_seconds INTEGER,
                rule_text TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

        self._patches = [
            patch("rule_builder.DB_PATH", self._db),
            patch("rule_builder.CUSTOM_RULES_PATH", self._rules_file),
        ]
        for p in self._patches:
            p.start()
        # reload_suricata talks to a real socket — not under test here.
        self._reload_patch = patch("rule_builder.reload_suricata", return_value=(True, "ok"))
        self._reload_patch.start()

    def tearDown(self):
        self._reload_patch.stop()
        for p in self._patches:
            p.stop()

    def test_create_rule_assigns_sid_starting_at_2000000(self):
        rule, ok, msg = rule_builder.create_rule({
            "message": "First", "protocol": "tcp", "dest_port": "4444",
            "classtype": "attempted-recon", "contents": ["x"],
        })
        self.assertEqual(rule["sid"], 2000000)
        self.assertTrue(ok)

    def test_create_rule_increments_sid(self):
        rule_builder.create_rule({
            "message": "First", "protocol": "tcp", "dest_port": "4444",
            "classtype": "attempted-recon", "contents": ["x"],
        })
        rule2, _, _ = rule_builder.create_rule({
            "message": "Second", "protocol": "tcp", "dest_port": "5555",
            "classtype": "attempted-recon", "contents": ["y"],
        })
        self.assertEqual(rule2["sid"], 2000001)

    def test_invalid_rule_raises_before_touching_db(self):
        with self.assertRaises(RuleError):
            rule_builder.create_rule({"message": "", "protocol": "tcp"})
        self.assertEqual(rule_builder.list_rules(), [])

    def test_create_rule_writes_to_rules_file(self):
        rule_builder.create_rule({
            "message": "First", "protocol": "tcp", "dest_port": "4444",
            "classtype": "attempted-recon", "contents": ["x"],
        })
        with open(self._rules_file) as f:
            content = f.read()
        self.assertIn("sid:2000000", content)

    def test_disabled_rule_excluded_from_rules_file(self):
        rule, _, _ = rule_builder.create_rule({
            "message": "First", "protocol": "tcp", "dest_port": "4444",
            "classtype": "attempted-recon", "contents": ["x"],
        })
        rule_builder.set_enabled(rule["id"], False)
        with open(self._rules_file) as f:
            content = f.read()
        self.assertNotIn("sid:2000000", content)

        listed = rule_builder.list_rules()
        self.assertEqual(listed[0]["enabled"], 0)

    def test_re_enabling_restores_it_to_the_rules_file(self):
        rule, _, _ = rule_builder.create_rule({
            "message": "First", "protocol": "tcp", "dest_port": "4444",
            "classtype": "attempted-recon", "contents": ["x"],
        })
        rule_builder.set_enabled(rule["id"], False)
        rule_builder.set_enabled(rule["id"], True)
        with open(self._rules_file) as f:
            content = f.read()
        self.assertIn("sid:2000000", content)

    def test_delete_removes_from_list_and_file(self):
        rule, _, _ = rule_builder.create_rule({
            "message": "First", "protocol": "tcp", "dest_port": "4444",
            "classtype": "attempted-recon", "contents": ["x"],
        })
        rule_builder.delete_rule(rule["id"])
        self.assertEqual(rule_builder.list_rules(), [])
        with open(self._rules_file) as f:
            content = f.read()
        self.assertNotIn("sid:2000000", content)

    def test_list_rules_returns_newest_first(self):
        rule_builder.create_rule({
            "message": "First", "protocol": "tcp", "dest_port": "4444",
            "classtype": "attempted-recon", "contents": ["x"],
        })
        rule_builder.create_rule({
            "message": "Second", "protocol": "tcp", "dest_port": "5555",
            "classtype": "attempted-recon", "contents": ["y"],
        })
        rules = rule_builder.list_rules()
        self.assertEqual(rules[0]["message"], "Second")
        self.assertEqual(rules[1]["message"], "First")


class TestReloadSuricata(unittest.TestCase):
    """Exercises reload_suricata() against a mock unix socket server speaking the same
    version-handshake + JSON-command protocol as Suricata's real unix-command socket,
    confirmed empirically against a live instance (see the commit message)."""

    def test_missing_socket_returns_false_with_helpful_message(self):
        with patch("rule_builder.SURICATA_SOCKET_PATH", "/nonexistent/path.socket"):
            ok, msg = rule_builder.reload_suricata()
        self.assertFalse(ok)
        self.assertIn("restart", msg.lower())

    def test_successful_reload_against_mock_socket(self):
        tmp = tempfile.mkdtemp()
        sock_path = os.path.join(tmp, "test.socket")

        def server():
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            srv.listen(1)
            conn, _ = srv.accept()
            conn.recv(4096)  # version handshake
            conn.sendall(json.dumps({"return": "OK"}).encode() + b"\n")
            conn.recv(4096)  # reload-rules command
            conn.sendall(json.dumps({"return": "OK", "message": "done"}).encode() + b"\n")
            conn.close()
            srv.close()

        t = threading.Thread(target=server, daemon=True)
        t.start()
        import time
        time.sleep(0.1)  # let the server bind before we connect

        with patch("rule_builder.SURICATA_SOCKET_PATH", sock_path):
            ok, msg = rule_builder.reload_suricata(timeout=3)
        t.join(timeout=2)
        self.assertTrue(ok)

    def test_reload_error_response_returns_false(self):
        tmp = tempfile.mkdtemp()
        sock_path = os.path.join(tmp, "test.socket")

        def server():
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            srv.listen(1)
            conn, _ = srv.accept()
            conn.recv(4096)
            conn.sendall(json.dumps({"return": "OK"}).encode() + b"\n")
            conn.recv(4096)
            conn.sendall(json.dumps({"return": "NOK", "message": "bad rule"}).encode() + b"\n")
            conn.close()
            srv.close()

        t = threading.Thread(target=server, daemon=True)
        t.start()
        import time
        time.sleep(0.1)

        with patch("rule_builder.SURICATA_SOCKET_PATH", sock_path):
            ok, msg = rule_builder.reload_suricata(timeout=3)
        t.join(timeout=2)
        self.assertFalse(ok)
        self.assertIn("bad rule", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
