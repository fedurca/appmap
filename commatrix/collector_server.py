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
import signal
import threading
import time
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


# How long shutdown waits for requests that are already being served. Long
# enough for a large snapshot merge, short enough that one wedged request
# cannot stop the unit from stopping.
SHUTDOWN_GRACE_SECONDS = 30.0


class GracefulHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that lets in-flight requests finish on shutdown.

    CODE-006, second half. Handling SIGTERM is not enough on its own:
    ThreadingHTTPServer runs each request on a *daemon* thread, so once
    serve_forever() returns, the interpreter exits and any handler still
    running is killed where it stands. Measured: SIGTERM during an /ingest
    merge left the client with an empty reply and nothing written -- the
    snapshot that agent had just spent a poll interval producing was gone, and
    neither side logged an error.

    Daemon threads stay (a wedged handler must never stop the unit from
    stopping); shutdown just waits for them, with a deadline.
    """

    daemon_threads = True
    shutdown_grace_seconds = SHUTDOWN_GRACE_SECONDS

    def __init__(self, *args, **kwargs):
        self._active_lock = threading.Lock()
        self._active = set()
        super().__init__(*args, **kwargs)

    def process_request_thread(self, request, client_address):  # noqa: D102
        current = threading.current_thread()
        with self._active_lock:
            self._active.add(current)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active.discard(current)

    def inflight(self) -> int:
        with self._active_lock:
            return sum(1 for t in self._active if t.is_alive())

    def wait_for_inflight(self, timeout: Optional[float] = None) -> bool:
        """Block until in-flight handlers finish. True if all of them did."""

        grace = self.shutdown_grace_seconds if timeout is None else timeout
        deadline = time.monotonic() + grace
        announced = False
        while True:
            with self._active_lock:
                pending = [t for t in self._active if t.is_alive()]
            if not pending:
                return True
            if not announced:
                log.info(
                    "waiting up to %.0fs for %d in-flight request(s) to finish",
                    grace, len(pending),
                )
                announced = True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.warning(
                    "%d request(s) still running after %.0fs; exiting anyway. "
                    "Their writes are rolled back by SQLite, so the database "
                    "stays consistent, but those snapshots were not stored.",
                    len(pending), grace,
                )
                return False
            pending[0].join(min(0.2, remaining))


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8899, token: Optional[str] = None) -> None:
    if not token:
        raise ValueError(
            "serve() requires a token: /ingest is an authoritative write into "
            "the central database and must not be exposed unauthenticated"
        )
    handler = make_handler(db_path, token)
    httpd = GracefulHTTPServer((host, port), handler)
    log.info("commatrix collector server listening on %s:%d (db=%s)", host, port, db_path)

    # CODE-006: only KeyboardInterrupt was handled, but systemctl stop and
    # docker stop send SIGTERM, whose default action terminates the process
    # outright. server_close() never ran, in-flight /ingest requests were cut
    # mid-write, and the listening socket was left for the kernel to reap.
    # Convert the signals into an orderly shutdown.
    _install_shutdown_handlers(httpd)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("collector server shutting down")
    finally:
        # Stop accepting first, then let whatever is already being handled
        # finish before the interpreter tears the daemon threads down.
        httpd.wait_for_inflight()
        httpd.server_close()
        log.info("collector server stopped")


def _install_shutdown_handlers(httpd: ThreadingHTTPServer) -> None:
    """Make SIGTERM/SIGHUP stop serve_forever() the same way Ctrl-C does."""

    def _stop(signum, _frame):
        log.info("received signal %s; shutting down the collector server", signum)
        # shutdown() must not run in the handler's own thread: it blocks until
        # serve_forever() returns, and serve_forever() is what we interrupted.
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for signame in ("SIGTERM", "SIGHUP", "SIGINT"):
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            # Not the main thread (test harness, embedded use): leave the
            # default disposition alone.
            log.debug("could not install a %s handler", signame)
