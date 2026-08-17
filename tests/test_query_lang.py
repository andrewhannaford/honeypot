"""
query_lang.py tests. Run from project root: python -m pytest tests/test_query_lang.py -v
"""

import os
import sqlite3
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_ROOT)
sys.path.insert(0, _ROOT)

from query_lang import compile_query, QueryError


class TestCompileQuery(unittest.TestCase):
    def test_empty_query_matches_everything(self):
        sql, params = compile_query("")
        self.assertEqual(sql, "1=1")
        self.assertEqual(params, [])

    def test_whitespace_only_matches_everything(self):
        sql, params = compile_query("   ")
        self.assertEqual(sql, "1=1")
        self.assertEqual(params, [])

    def test_simple_field_equals(self):
        sql, params = compile_query("service:SSH")
        self.assertIn("UPPER(service) = UPPER(?)", sql)
        self.assertEqual(params, ["SSH"])

    def test_field_alias_type_maps_to_event_type_column(self):
        sql, params = compile_query("type:credential")
        self.assertIn("UPPER(event_type) = UPPER(?)", sql)

    def test_ip_wildcard_becomes_like(self):
        sql, params = compile_query("ip:10.0.0.*")
        self.assertIn("ip LIKE ?", sql)
        self.assertEqual(params, ["10.0.0.%"])

    def test_numeric_greater_than(self):
        sql, params = compile_query("risk_score>70")
        self.assertIn("risk_score > ?", sql)
        self.assertEqual(params, [70])

    def test_numeric_greater_equal(self):
        sql, params = compile_query("risk_score>=70")
        self.assertIn("risk_score >= ?", sql)

    def test_numeric_less_than(self):
        sql, params = compile_query("port<1024")
        self.assertIn("port < ?", sql)
        self.assertEqual(params, [1024])

    def test_numeric_field_rejects_non_numeric_value(self):
        with self.assertRaises(QueryError):
            compile_query("risk_score>abc")

    def test_string_field_rejects_comparison_operator(self):
        with self.assertRaises(QueryError):
            compile_query("service>SSH")

    def test_unknown_field_raises_helpful_error(self):
        with self.assertRaises(QueryError) as ctx:
            compile_query("nonsense_field:value")
        self.assertIn("nonsense_field", str(ctx.exception))

    def test_explicit_and(self):
        sql, params = compile_query("service:SSH AND risk_score>70")
        self.assertIn(" AND ", sql)
        self.assertEqual(params, ["SSH", 70])

    def test_implicit_and_same_as_explicit(self):
        sql1, params1 = compile_query("service:SSH AND risk_score>70")
        sql2, params2 = compile_query("service:SSH risk_score>70")
        self.assertEqual(sql1, sql2)
        self.assertEqual(params1, params2)

    def test_or(self):
        sql, params = compile_query("service:SSH OR service:TELNET")
        self.assertIn(" OR ", sql)
        self.assertEqual(params, ["SSH", "TELNET"])

    def test_not_keyword(self):
        sql, params = compile_query("NOT ip:10.0.0.1")
        self.assertIn("NOT", sql)
        self.assertEqual(params, ["10.0.0.1"])

    def test_minus_prefix_same_as_not(self):
        sql1, params1 = compile_query("NOT ip:10.0.0.1")
        sql2, params2 = compile_query("-ip:10.0.0.1")
        self.assertEqual(sql1, sql2)
        self.assertEqual(params1, params2)

    def test_parentheses_grouping_changes_precedence(self):
        sql_grouped, _ = compile_query("(service:SSH OR service:TELNET) AND risk_score>50")
        sql_ungrouped, _ = compile_query("service:SSH OR service:TELNET AND risk_score>50")
        # Different grouping must produce structurally different SQL.
        self.assertNotEqual(sql_grouped, sql_ungrouped)

    def test_unbalanced_parenthesis_raises(self):
        with self.assertRaises(QueryError):
            compile_query("(service:SSH AND risk_score>50")

    def test_unexpected_closing_paren_raises(self):
        with self.assertRaises(QueryError):
            compile_query("service:SSH)")

    def test_free_text_matches_ip_or_data(self):
        sql, params = compile_query("wget")
        self.assertIn("ip LIKE ?", sql)
        self.assertIn("data LIKE ?", sql)
        self.assertEqual(params, ["%wget%", "%wget%"])

    def test_quoted_phrase_with_spaces(self):
        sql, params = compile_query('"bash -i"')
        self.assertEqual(params, ["%bash -i%", "%bash -i%"])

    def test_quoted_field_value_with_spaces(self):
        sql, params = compile_query('data:"cmd="')
        self.assertEqual(params, ["cmd="])

    def test_combined_realistic_query(self):
        sql, params = compile_query(
            '(service:SSH OR service:TELNET) AND event_type:credential AND risk_score>=50 NOT ip:10.0.0.*'
        )
        # Should parse without raising, produce 4 params in order encountered.
        self.assertEqual(params, ["SSH", "TELNET", "credential", 50, "10.0.0.%"])

    def test_malformed_query_never_raises_non_queryerror(self):
        bad_inputs = [
            "service:", "AND", "OR OR", "((service:SSH)", "service:SSH AND",
            ":value", "service::SSH", "NOT",
        ]
        for q in bad_inputs:
            with self.subTest(q=q):
                try:
                    compile_query(q)
                except QueryError:
                    pass  # expected — must be QueryError specifically, not e.g. IndexError

    def test_sql_injection_attempt_is_treated_as_literal_value(self):
        # A classic injection payload as a field value must end up as a bound param,
        # never concatenated into the SQL string itself.
        sql, params = compile_query('ip:"1\' OR \'1\'=\'1"')
        self.assertNotIn("OR '1'='1'", sql)
        self.assertIn("1' OR '1'='1", params)

    def test_field_value_actually_filters_against_real_db(self):
        """End-to-end sanity check against a real (temp) SQLite events table."""
        conn = sqlite3.connect(":memory:")
        conn.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, port INTEGER,
                service TEXT, event_type TEXT, data TEXT, country TEXT, city TEXT,
                lat REAL, lon REAL, abuse_score INTEGER, risk_score INTEGER
            )
        """)
        rows = [
            (1, "t", "1.2.3.4", 22, "SSH", "credential", None, "US", None, None, None, 0, 80),
            (2, "t", "5.6.7.8", 80, "HTTP", "connect", None, "CN", None, None, None, 0, 10),
            (3, "t", "9.9.9.9", 23, "TELNET", "credential", None, "RU", None, None, None, 0, 60),
        ]
        conn.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

        where, params = compile_query("event_type:credential AND risk_score>50")
        result = conn.execute(f"SELECT id FROM events WHERE {where}", params).fetchall()
        self.assertEqual([r[0] for r in result], [1, 3])

        where, params = compile_query("service:SSH OR service:TELNET")
        result = conn.execute(f"SELECT id FROM events WHERE {where}", params).fetchall()
        self.assertEqual(sorted(r[0] for r in result), [1, 3])

        conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
