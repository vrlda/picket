"""Self-test: run with `python3 sdk/python/test_picket.py` (stdlib)."""

import http.server
import json
import sys
import threading
import unittest

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import picket


class Handler(http.server.BaseHTTPRequestHandler):
    captured = {}

    def do_POST(self):
        Handler.captured["path"] = self.path
        Handler.captured["auth"] = self.headers.get("Authorization")
        n = int(self.headers.get("Content-Length", 0))
        Handler.captured["body"] = json.loads(self.rfile.read(n))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


class TestSdk(unittest.TestCase):
    def setUp(self):
        Handler.captured = {}
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()

    def test_capture_payload(self):
        c = picket.Client(endpoint="http://127.0.0.1:%d" % self.port,
                              token="tok", host_id="h-1", service="api")
        ok = c.capture("error", "ValueError", "bad input",
                       [("app.py", 42, "validate")])
        self.assertTrue(ok)
        self.assertEqual(Handler.captured["path"], "/v1/errors")
        self.assertEqual(Handler.captured["auth"], "Bearer tok")
        b = Handler.captured["body"]
        self.assertEqual(b["host_id"], "h-1")
        self.assertEqual(b["service"], "api")
        self.assertEqual(b["exception"]["type"], "ValueError")
        self.assertEqual(b["exception"]["frames"][0]["file"], "app.py")
        self.assertEqual(b["exception"]["frames"][0]["line"], 42)

    def test_capture_exception_current(self):
        c = picket.Client(endpoint="http://127.0.0.1:%d" % self.port, token="tok")
        try:
            raise ValueError("boom")
        except ValueError:
            ok = c.capture_exception()
        self.assertTrue(ok)
        b = Handler.captured["body"]
        self.assertEqual(b["exception"]["type"], "ValueError")
        self.assertEqual(b["exception"]["message"], "boom")
        self.assertGreater(len(b["exception"]["frames"]), 0)

    def test_capture_event_payload(self):
        c = picket.Client(endpoint="http://127.0.0.1:%d" % self.port,
                              token="tok", service="payment-api", environment="production")
        ok = c.capture_event("payment.request_failed", "Payment request failed",
                             severity="warning", subject="merchant:mer_1",
                             attributes={"merchant_id": "mer_1", "status_code": 502},
                             measurements={"latency_ms": 812})
        self.assertTrue(ok)
        self.assertEqual(Handler.captured["path"], "/v1/events")
        b = Handler.captured["body"]
        self.assertEqual(b["kind"], "payment.request_failed")
        self.assertEqual(b["source"], "payment-api")
        self.assertEqual(b["environment"], "production")
        self.assertEqual(b["subject"], "merchant:mer_1")
        self.assertEqual(b["attributes"]["status_code"], 502)
        self.assertEqual(b["measurements"]["latency_ms"], 812)
        self.assertNotIn("id", b)

    def test_no_config_no_crash(self):
        c = picket.Client()
        self.assertFalse(c.capture("error", "T", "m"))
        self.assertFalse(c.capture_exception())
        self.assertFalse(c.capture_event("a.b", "x"))


if __name__ == "__main__":
    unittest.main()
