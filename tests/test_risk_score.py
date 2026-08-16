"""
risk_score.py tests. Run from project root: python -m pytest tests/test_risk_score.py -v
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

import risk_score


class TestComputeRiskScore(unittest.TestCase):
    def test_bounds_are_0_to_100(self):
        low = risk_score.compute_risk_score("rate_limited", 1, 1, None)
        high = risk_score.compute_risk_score("eval_attempt", 100000, 20, 100)
        self.assertGreaterEqual(low, 0)
        self.assertLessEqual(high, 100)

    def test_more_severe_event_type_scores_higher_all_else_equal(self):
        low = risk_score.compute_risk_score("connect", 5, 1, None)
        high = risk_score.compute_risk_score("eval_attempt", 5, 1, None)
        self.assertGreater(high, low)

    def test_more_volume_scores_higher_all_else_equal(self):
        low = risk_score.compute_risk_score("credential", 1, 1, None)
        high = risk_score.compute_risk_score("credential", 500, 1, None)
        self.assertGreater(high, low)

    def test_more_service_diversity_scores_higher_all_else_equal(self):
        low = risk_score.compute_risk_score("credential", 5, 1, None)
        high = risk_score.compute_risk_score("credential", 5, 5, None)
        self.assertGreater(high, low)

    def test_known_bad_abuse_score_raises_it(self):
        unknown = risk_score.compute_risk_score("credential", 5, 1, None)
        known_bad = risk_score.compute_risk_score("credential", 5, 1, 100)
        self.assertGreater(known_bad, unknown)

    def test_unknown_event_type_falls_back_to_default_severity(self):
        # Must not raise on an event type not in the severity table.
        score = risk_score.compute_risk_score("something_new", 1, 1, None)
        self.assertIsInstance(score, int)

    def test_returns_int(self):
        self.assertIsInstance(risk_score.compute_risk_score("credential", 5, 1, 50), int)


class TestScoreAndStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._db = os.path.join(self._tmp, "risk_test.db")
        conn = sqlite3.connect(self._db)
        conn.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data TEXT,
                abuse_score INTEGER,
                risk_score INTEGER
            )
        """)
        conn.commit()
        conn.close()

    def _insert(self, ip, service, event_type, abuse_score=None):
        conn = sqlite3.connect(self._db)
        cur = conn.execute(
            "INSERT INTO events (timestamp, ip, port, service, event_type, abuse_score) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("2026-01-01T00:00:00", ip, 22, service, event_type, abuse_score),
        )
        conn.commit()
        rowid = cur.lastrowid
        conn.close()
        return rowid

    def test_writes_risk_score_to_the_row(self):
        rowid = self._insert("1.2.3.4", "SSH", "credential")
        with patch("risk_score.DB_PATH", self._db):
            risk_score.score_and_store(rowid, "1.2.3.4", "credential")

        conn = sqlite3.connect(self._db)
        row = conn.execute("SELECT risk_score FROM events WHERE id = ?", (rowid,)).fetchone()
        conn.close()
        self.assertIsNotNone(row[0])

    def test_picks_up_existing_abuse_score_for_the_ip(self):
        self._insert("5.6.7.8", "SSH", "credential", abuse_score=90)
        rowid = self._insert("5.6.7.8", "HTTP", "request")
        with patch("risk_score.DB_PATH", self._db):
            score_with_abuse = risk_score.score_and_store(rowid, "5.6.7.8", "request")

            rowid2 = self._insert("9.9.9.9", "HTTP", "request")
            score_without_abuse = risk_score.score_and_store(rowid2, "9.9.9.9", "request")

        self.assertGreater(score_with_abuse, score_without_abuse)

    def test_reuses_caller_supplied_connection_without_committing(self):
        rowid = self._insert("1.1.1.1", "SSH", "credential")
        with patch("risk_score.DB_PATH", self._db):
            conn = sqlite3.connect(self._db)
            risk_score.score_and_store(rowid, "1.1.1.1", "credential", conn=conn)
            # Not yet committed by score_and_store itself — still visible on this same
            # connection (SQLite read-your-own-writes within a transaction) but caller
            # is responsible for committing.
            row = conn.execute("SELECT risk_score FROM events WHERE id = ?", (rowid,)).fetchone()
            self.assertIsNotNone(row[0])
            conn.commit()
            conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
