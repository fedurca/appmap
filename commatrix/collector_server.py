"""Optional central collector: a tiny stdlib HTTP server that receives JSON
snapshots pushed by agents and merges them into the central database.

This is one of two supported centralisation transports (the other being
file-pull via ssh/rsync of exported snapshots).  It intentionally uses only
:mod:`http.server` from the standard library.

Security note: this server performs an optional shared-token check via the
``X-Commatrix-Token`` header.  It is meant to run on a trusted management
network; put it behind TLS-terminating reverse proxy / firewall for anything
beyond that.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .store import Store

log = logging.getLogger("commatrix.server")

MAX_BODY_BYTES = 64 * 1024 * 1024  # 64 MiB safety cap


def make_handler(db_path: str, token: Optional[str]):
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "commatrix/0.1"
        # SEC-003: without this a slow client holds its worker thread forever
        # (slowloris); ThreadingHTTPServer imposes no thread ceiling.
        timeout = 30

        def _reject(self, code: int, message: str) -> None:
            body = json.dumps({"error": message}).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if self.path == "/health":
                body = json.dumps({"status": "ok"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._reject(404, "not found")

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path != "/ingest":
                self._reject(404, "not found")
                return
            if not _token_ok(token, self.headers.get("X-Commatrix-Token")):
                self._reject(401, "unauthorized")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._reject(400, "invalid content-length")
                return
            if length <= 0 or length > MAX_BODY_BYTES:
                self._reject(400, "invalid body size")
                return

            raw = self.rfile.read(length)
            if len(raw) != length:
                self._reject(400, "truncated body")
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._reject(400, "invalid json")
                return
            except RecursionError:
                # SEC-014: deeply nested JSON raises RecursionError, which is
                # not a subclass of ValueError and would escape do_POST.
                self._reject(400, "json nested too deeply")
                return
            if not isinstance(payload, dict):
                self._reject(400, "payload must be an object")
                return

            try:
                with lock:
                    store = Store(db_path)
                    try:
                        merged = store.import_dict(payload)
                    finally:
                        store.close()
            except Exception:
                # SEC-004: the exception text can carry filesystem paths and
                # SQL fragments. Log it server-side, tell the client nothing.
                log.exception("ingest failed")
                self._reject(500, "ingest failed")
                return

            body = json.dumps({"status": "ok", "merged": merged}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args) -> None:  # quieter default logging
            log.info("%s - %s", self.address_string(), fmt % args)

    return Handler


def _token_ok(expected: Optional[str], presented: Optional[str]) -> bool:
    """Constant-time token check (SEC-001).

    A plain != leaks the length of the matching prefix through timing. Both
    sides are compared as bytes so a missing header cannot short-circuit.
    """

    if not expected:
        return False
    return hmac.compare_digest(
        expected.encode("utf-8"), (presented or "").encode("utf-8")
    )


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8899, token: Optional[str] = None) -> None:
    if not token:
        raise ValueError(
            "serve() requires a token: /ingest is an authoritative write into "
            "the central database and must not be exposed unauthenticated"
        )
    handler = make_handler(db_path, token)
    httpd = ThreadingHTTPServer((host, port), handler)
    log.info("commatrix collector server listening on %s:%d (db=%s)", host, port, db_path)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("collector server shutting down")
    finally:
        httpd.server_close()
