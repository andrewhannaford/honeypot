"""Tests for config env parsing helpers (Phase 1)."""

import os
import sys
import unittest
import uuid
from unittest.mock import patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)


class TestConfigEnvHelpers(unittest.TestCase):
    def test_env_bool_missing_key_uses_default(self):
        from config import _env_bool

        key = "HONEYPOT_UNDEF_" + uuid.uuid4().hex
        self.assertNotIn(key, os.environ)
        self.assertTrue(_env_bool(key, True))
        self.assertFalse(_env_bool(key, False))

    def test_env_bool_explicit_values(self):
        from config import _env_bool

        key = "HONEYPOT_TEST_BOOL_XYZ_UNUSED"
        with patch.dict(os.environ, {key: "1"}):
            self.assertTrue(_env_bool(key, True))
        with patch.dict(os.environ, {key: "true"}):
            self.assertTrue(_env_bool(key, True))
        with patch.dict(os.environ, {key: "0"}):
            self.assertFalse(_env_bool(key, True))
        with patch.dict(os.environ, {key: "false"}):
            self.assertFalse(_env_bool(key, True))
        with patch.dict(os.environ, {key: "no"}):
            self.assertFalse(_env_bool(key, True))
        with patch.dict(os.environ, {key: "off"}):
            self.assertFalse(_env_bool(key, True))

    def test_env_bool_when_default_false_branch(self):
        from config import _env_bool

        key = "HONEYPOT_TEST_BOOL_DEFAULT_OFF"
        with patch.dict(os.environ, {key: "1"}):
            self.assertTrue(_env_bool(key, False))
        with patch.dict(os.environ, {key: "0"}):
            self.assertFalse(_env_bool(key, False))

    def test_positive_int_parses_and_clamps_negative(self):
        from config import _positive_int

        key = "HONEYPOT_TEST_POS_INT"
        with patch.dict(os.environ, {key: "120"}):
            self.assertEqual(_positive_int(key, 60), 120)
        with patch.dict(os.environ, {key: "not-a-number"}):
            self.assertEqual(_positive_int(key, 60), 60)
        with patch.dict(os.environ, {key: "-5"}):
            self.assertEqual(_positive_int(key, 60), 60)

    def test_env_float_invalid_uses_default(self):
        from config import _env_float

        key = "HONEYPOT_TEST_FLOAT"
        with patch.dict(os.environ, {key: "12.5"}):
            self.assertAlmostEqual(_env_float(key, 1.0), 12.5)
        with patch.dict(os.environ, {key: "bad"}):
            self.assertAlmostEqual(_env_float(key, -0.5), -0.5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
