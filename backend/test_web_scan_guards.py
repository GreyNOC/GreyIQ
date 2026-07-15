"""Direct tests for web_scan_service's SSRF guard core: _guard_url (no prior test called
it directly -- other tests stub it out) and _GuardedRedirect's redirect-bounce
re-validation (the only existing redirect tests, in test_scan_auth.py, patch
_host_is_private off and assert ONLY auth-stripping, never that a bounce to a private
host / disallowed port / cross-protocol target is actually rejected).
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, build_opener

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.scan_auth import AuthContext  # noqa: E402
from bughunter.web_ingest import WebsiteFetchError  # noqa: E402
from bughunter.web_scan_service import _MAX_REDIRECTS, _GuardedRedirect, _guard_url  # noqa: E402

_PORTS = frozenset({80, 443})


class GuardUrlTests(unittest.TestCase):
    def test_rejects_non_http_scheme(self) -> None:
        for url in ("ftp://example.com/", "file:///etc/passwd", "gopher://example.com/", "data:text/html,x"):
            with self.assertRaises(WebsiteFetchError, msg=url):
                _guard_url(url, False, _PORTS)

    def test_rejects_missing_host(self) -> None:
        with self.assertRaises(WebsiteFetchError):
            _guard_url("https:///path", False, _PORTS)

    def test_rejects_backslash_in_netloc(self) -> None:
        with self.assertRaises(WebsiteFetchError):
            _guard_url("https://example.com\\@evil.com/", False, _PORTS)

    def test_rejects_embedded_credentials(self) -> None:
        with self.assertRaises(WebsiteFetchError):
            _guard_url("https://user:pass@example.com/", False, _PORTS)

    def test_rejects_invalid_port(self) -> None:
        with self.assertRaises(WebsiteFetchError):
            _guard_url("https://example.com:notaport/", False, _PORTS)

    def test_rejects_private_host_by_default(self) -> None:
        for host in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "localhost"):
            with self.assertRaises(WebsiteFetchError, msg=host):
                _guard_url(f"https://{host}/", False, _PORTS)

    def test_allows_private_host_when_opted_in(self) -> None:
        self.assertEqual(_guard_url("https://127.0.0.1/", True, _PORTS), "https://127.0.0.1/")

    def test_rejects_disallowed_port_for_public_host(self) -> None:
        with self.assertRaises(WebsiteFetchError):
            _guard_url("https://example.com:9999/", False, _PORTS)

    def test_allows_allowlisted_port_for_public_host(self) -> None:
        self.assertEqual(_guard_url("https://example.com:443/", False, _PORTS), "https://example.com:443/")

    def test_private_urls_allowed_lifts_the_port_restriction(self) -> None:
        # The settings docstring: "when enabled... the port allowlist is also lifted."
        self.assertEqual(_guard_url("https://127.0.0.1:9999/", True, _PORTS), "https://127.0.0.1:9999/")

    def test_returns_ascii_punycoded_host(self) -> None:
        guarded = _guard_url("https://münchen.de/path", False, _PORTS)
        self.assertEqual(guarded, "https://xn--mnchen-3ya.de/path")


class _RedirectChainHandler(BaseHTTPRequestHandler):
    # Class attribute set per-test before the server starts handling requests.
    chain: list[str] = []
    hop = {"n": 0}

    def do_GET(self) -> None:  # noqa: N802
        idx = self.hop["n"]
        self.hop["n"] += 1
        if idx < len(self.chain):
            self.send_response(302)
            self.send_header("Location", self.chain[idx])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"final"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


class GuardedRedirectBounceTests(unittest.TestCase):
    """A real local server issues a 30x bounce; _GuardedRedirect must reject the bounce
    when the target violates the same guard a fresh request would (private host,
    disallowed port), and must cap the hop count.

    _GuardedRedirect takes allow_private/allowed_ports as CONSTRUCTOR arguments (not via
    settings/env), so each test passes them directly rather than touching the environment.
    The test server itself is on 127.0.0.1 (private), so the "legitimate redirect"
    control case opts IN to private hosts for the test server's own same-host hop —
    that's a different axis from whether a BOUNCE TO A DIFFERENT, genuinely-private
    target gets caught."""

    def setUp(self) -> None:
        _RedirectChainHandler.hop = {"n": 0}

    def _serve(self, chain: list[str]) -> ThreadingHTTPServer:
        _RedirectChainHandler.chain = chain
        server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectChainHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def _fetch(self, url: str, *, allow_private: bool, auth=None) -> None:
        opener = build_opener(_GuardedRedirect(allow_private, _PORTS, auth=auth))
        opener.open(Request(url), timeout=5)

    def test_bounce_to_private_host_is_rejected(self) -> None:
        # The INITIAL request to the local test server is never guarded by
        # _GuardedRedirect itself (only _fetch_raw guards the first URL, via a separate
        # explicit call before opener.open() — calling the opener directly, as this test
        # does, bypasses that). allow_private=False here exercises the REAL production
        # default: only the redirect TARGET (a different, genuinely-private host) gets
        # checked, and must be rejected.
        server = self._serve(["http://169.254.169.254/latest/meta-data/"])
        with self.assertRaises(WebsiteFetchError):
            self._fetch(f"http://127.0.0.1:{server.server_port}/", allow_private=False)

    def test_bounce_to_disallowed_port_is_rejected(self) -> None:
        server = self._serve(["http://example.com:9999/"])
        with self.assertRaises(WebsiteFetchError):
            self._fetch(f"http://127.0.0.1:{server.server_port}/", allow_private=False)

    def test_too_many_redirects_is_rejected(self) -> None:
        server = self._serve([f"/hop{i}" for i in range(_MAX_REDIRECTS + 2)])
        # Same-host hops, so allow_private=True here only to isolate the HOP-COUNT limit
        # from the private-host check (already covered by the dedicated test above).
        with self.assertRaises(WebsiteFetchError):
            self._fetch(f"http://127.0.0.1:{server.server_port}/", allow_private=True)

    def test_legitimate_same_host_redirect_chain_succeeds(self) -> None:
        server = self._serve(["/next"])  # one hop, well under the cap
        # Must not raise.
        self._fetch(f"http://127.0.0.1:{server.server_port}/", allow_private=True)


if __name__ == "__main__":
    unittest.main()
