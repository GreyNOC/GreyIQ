"""Regression test: recon.discover must never mine params/fingerprint/JS from a page a
redirect landed on OUT OF SCOPE.

_fetch_raw's redirect guard (_GuardedRedirect) only validates SSRF safety per hop, never
SCOPE -- an in-scope seed page can 302 to a public out-of-scope host. Before the fix,
discover() mined that out-of-scope body's form fields and fingerprinted it anyway,
leaking them into the active prover's surface.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import recon  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


class _RedirectHandler(BaseHTTPRequestHandler):
    port = 0  # set by the test before the server starts handling requests

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", f"http://evil.example.test:{self.port}/oos")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = (
            b"<html><body>"
            b'<form method="post"><input name="leaked_secret_param"></form>'
            b'<script src="/leaked.js"></script>'
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


class ReconScopeBleedTests(unittest.TestCase):
    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self._orig_gai = socket.getaddrinfo
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        _RedirectHandler.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        orig = self._orig_gai
        port = self.server.server_port
        # BOTH the in-scope seed host and the out-of-scope redirect target resolve here.
        socket.getaddrinfo = lambda host, p, *a, **k: orig("127.0.0.1", port, *a, **k)

    def tearDown(self) -> None:
        socket.getaddrinfo = self._orig_gai
        self.server.shutdown()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def test_params_not_mined_from_out_of_scope_redirect_target(self) -> None:
        seed = f"http://app.example.test:{self.server.server_port}/"
        # No callback => only the seed's own host ("app.example.test") is in scope;
        # evil.example.test is NOT.
        result = recon.discover(seed, scope_in=lambda h: False, settings=get_settings())
        self.assertNotIn("leaked_secret_param", result["params"])
        self.assertGreaterEqual(result["dropped_out_of_scope"], 1)
        # And the OOS page's JS asset was never even considered for mining.
        self.assertEqual(result.get("js_secrets"), [])


if __name__ == "__main__":
    unittest.main()
