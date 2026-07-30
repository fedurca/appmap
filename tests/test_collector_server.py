"""Tests for the central push server (SEC-046: previously untested).

Covers the authentication matrix (SEC-001/002), malformed and hostile bodies
(SEC-014, SEC-019), and that the server refuses to run unauthenticated.
"""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from commatrix import collector_server
from commatrix.store import Store

TOKEN = "s3cret-token"


class _Server:
    def __init__(self, token=TOKEN):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "central.db")
        Store(self.db).close()
        handler = collector_server.make_handler(self.db, token)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def post(self, body, token=TOKEN, path="/ingest"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=body, method="POST"
        )
        if token is not None:
            req.add_header("X-Commatrix-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TokenComparisonTests(unittest.TestCase):
    def test_missing_expected_token_never_matches(self):
        self.assertFalse(collector_server._token_ok(None, "anything"))
        self.assertFalse(collector_server._token_ok("", "anything"))

    def test_missing_presented_token_is_rejected(self):
        self.assertFalse(collector_server._token_ok(TOKEN, None))

    def test_exact_match_accepted(self):
        self.assertTrue(collector_server._token_ok(TOKEN, TOKEN))

    def test_prefix_is_not_enough(self):
        self.assertFalse(collector_server._token_ok(TOKEN, TOKEN[:-1]))
        self.assertFalse(collector_server._token_ok(TOKEN, TOKEN + "x"))


class AuthMatrixTests(unittest.TestCase):
    def setUp(self):
        self.srv = _Server()
        self.addCleanup(self.srv.close)

    def test_valid_token_accepted(self):
        status, _ = self.srv.post({"hosts": {}, "flows": []})
        self.assertEqual(status, 200)

    def test_wrong_token_rejected(self):
        status, _ = self.srv.post({"hosts": {}, "flows": []}, token="nope")
        self.assertEqual(status, 401)

    def test_absent_token_rejected(self):
        status, _ = self.srv.post({"hosts": {}, "flows": []}, token=None)
        self.assertEqual(status, 401)

    def test_unknown_path_is_404(self):
        status, _ = self.srv.post({}, path="/anything")
        self.assertEqual(status, 404)


class BodyHandlingTests(unittest.TestCase):
    def setUp(self):
        self.srv = _Server()
        self.addCleanup(self.srv.close)

    def test_malformed_json_is_400(self):
        status, _ = self.srv.post("{not json")
        self.assertEqual(status, 400)

    def test_non_object_payload_is_400(self):
        status, _ = self.srv.post([1, 2, 3])
        self.assertEqual(status, 400)

    def test_deeply_nested_json_does_not_kill_the_server(self):
        payload = "[" * 20000 + "]" * 20000
        status, _ = self.srv.post(payload)
        self.assertEqual(status, 400)
        status, _ = self.srv.post({"hosts": {}, "flows": []})
        self.assertEqual(status, 200, "server must survive the nested payload")

    def test_error_body_does_not_leak_internals(self):
        status, body = self.srv.post({"flows": "not-a-list"})
        if status == 500:
            self.assertNotIn(self.srv.db, body)
            self.assertNotIn("Traceback", body)


class ServeGuardTests(unittest.TestCase):
    def test_serve_refuses_without_a_token(self):
        tmp = tempfile.mkdtemp()
        for token in (None, ""):
            with self.assertRaises(ValueError):
                collector_server.serve(os.path.join(tmp, "c.db"), token=token)

    def test_default_bind_is_loopback(self):
        import inspect

        default = inspect.signature(collector_server.serve).parameters["host"].default
        self.assertEqual(default, "127.0.0.1")

    def test_handler_has_a_read_timeout(self):
        self.assertTrue(getattr(collector_server.make_handler("x", "t"), "timeout", None))


if __name__ == "__main__":
    unittest.main()
