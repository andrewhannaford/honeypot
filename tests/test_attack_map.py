"""SSE attack stream tests (Phase 3)."""

import json
import os
import queue
import sys
import unittest
from unittest.mock import MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_ROOT)
sys.path.insert(0, _ROOT)


def tearDownModule():
    from logger import clear_event_callbacks

    clear_event_callbacks()


class TestAttackStream(unittest.TestCase):
    def test_sse_response_headers(self):
        import dashboard.app as dash

        fn = dash.app.view_functions.get("attack_stream")
        self.assertIsNotNone(fn)
        with dash.app.test_request_context():
            resp = fn()
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/event-stream", resp.content_type)
        self.assertIn("no-cache", resp.headers.get("Cache-Control", ""))

    def test_sse_generator_emits_keepalive_without_waiting(self):
        """Queue.get would block 30s; mock Empty so the first chunk is immediate."""
        import dashboard.app as dash

        mock_q = MagicMock()
        mock_q.get.side_effect = queue.Empty()
        with patch("dashboard.app.queue.Queue", return_value=mock_q):
            with dash.app.test_request_context():
                resp = dash.attack_stream()
            first = next(resp.response)
        chunk = first if isinstance(first, bytes) else first.encode("utf-8")
        self.assertIn(b"keepalive", chunk)

    def test_publish_payload_is_valid_json_with_expected_keys(self):
        import dashboard.app as dash

        q = queue.Queue(maxsize=10)
        with dash._client_lock:
            dash._client_queues.append(q)
        try:
            dash.publish_attack_event(
                {
                    "lat": -33.86,
                    "lon": 151.2,
                    "service": "SSH",
                    "country": "AU",
                    "ip": "1.0.0.1",
                }
            )
            line = q.get(timeout=2).strip()
            obj = json.loads(line)
            self.assertEqual(obj["src_lat"], -33.86)
            self.assertEqual(obj["country"], "AU")
            self.assertIn("dst_lat", obj)
            self.assertIn("dst_lon", obj)
        finally:
            with dash._client_lock:
                try:
                    dash._client_queues.remove(q)
                except ValueError:
                    pass

    def test_publish_fans_out_to_multiple_clients(self):
        import dashboard.app as dash

        q1 = queue.Queue(maxsize=10)
        q2 = queue.Queue(maxsize=10)
        with dash._client_lock:
            dash._client_queues.append(q1)
            dash._client_queues.append(q2)
        try:
            dash.publish_attack_event(
                {
                    "lat": 1.0,
                    "lon": 2.0,
                    "service": "HTTP",
                    "country": "JP",
                    "ip": "9.9.9.9",
                }
            )
            self.assertIn("9.9.9.9", q1.get(timeout=2))
            self.assertIn("9.9.9.9", q2.get(timeout=2))
        finally:
            with dash._client_lock:
                for q in (q1, q2):
                    try:
                        dash._client_queues.remove(q)
                    except ValueError:
                        pass

    def test_event_with_geo_published(self):
        import dashboard.app as dash

        q = queue.Queue(maxsize=10)
        with dash._client_lock:
            dash._client_queues.append(q)
        try:
            dash.publish_attack_event(
                {
                    "lat": 40.0,
                    "lon": -74.0,
                    "service": "SSH",
                    "country": "US",
                    "ip": "1.2.3.4",
                }
            )
            line = q.get(timeout=2)
            self.assertIn("src_lat", line)
            self.assertIn("40.0", line)
        finally:
            with dash._client_lock:
                try:
                    dash._client_queues.remove(q)
                except ValueError:
                    pass

    def test_event_without_geo_not_published(self):
        import dashboard.app as dash

        q = queue.Queue(maxsize=10)
        with dash._client_lock:
            dash._client_queues.append(q)
        try:
            dash.publish_attack_event(
                {"lat": None, "lon": None, "service": "SSH", "ip": "9.9.9.9"}
            )
            with self.assertRaises(queue.Empty):
                q.get(timeout=0.3)
        finally:
            with dash._client_lock:
                try:
                    dash._client_queues.remove(q)
                except ValueError:
                    pass

    def test_full_queue_does_not_raise(self):
        import dashboard.app as dash

        q = queue.Queue(maxsize=1)
        q.put_nowait("{}\n")
        with dash._client_lock:
            dash._client_queues.append(q)
        try:
            dash.publish_attack_event(
                {
                    "lat": 1.0,
                    "lon": 2.0,
                    "service": "HTTP",
                    "country": "ZZ",
                    "ip": "8.8.8.8",
                }
            )
        finally:
            with dash._client_lock:
                try:
                    dash._client_queues.remove(q)
                except ValueError:
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
