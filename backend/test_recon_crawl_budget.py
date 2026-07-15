"""Tests for recon.discover's three independent kill switches -- the page cap
(max_pages), the global per-campaign request budget (max_requests), the BFS depth
cap (max_depth) -- and the per-host token governor _safe_fetch defers to. None of
these had dedicated coverage before this: test_recon.py only covers pure helpers +
the private-seed short-circuit, never a real multi-page crawl.

Uses a real local HTTP server (matching test_recon_scope_redirect.py's pattern) so
the BFS genuinely walks live responses rather than a mocked fetch.
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
from bughunter.rate_limit import HostRateGovernor  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402

_PASSIVE_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}


def _serve_404(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(404)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def _serve_html(handler: BaseHTTPRequestHandler, body: bytes) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class _FanOutHandler(BaseHTTPRequestHandler):
    """/ links to 20 leaf pages; every leaf page is a dead end."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path in _PASSIVE_PATHS:
            _serve_404(self)
            return
        if self.path == "/":
            links = "".join(f'<a href="/p{i}">p{i}</a>' for i in range(20))
            _serve_html(self, f"<html><body>{links}</body></html>".encode())
            return
        if self.path.startswith("/p"):
            _serve_html(self, b"<html><body>leaf</body></html>")
            return
        _serve_404(self)

    def log_message(self, *args: object) -> None:
        return


class _ChainHandler(BaseHTTPRequestHandler):
    """A linear chain / -> /d1 -> /d2 -> /d3 (dead end), one link per page."""

    _CHAIN = {"/": "/d1", "/d1": "/d2", "/d2": "/d3", "/d3": None}

    def do_GET(self) -> None:  # noqa: N802
        if self.path in _PASSIVE_PATHS:
            _serve_404(self)
            return
        if self.path not in self._CHAIN:
            _serve_404(self)
            return
        nxt = self._CHAIN[self.path]
        body = (f'<html><body><a href="{nxt}">next</a></body></html>' if nxt else "<html><body>end</body></html>")
        _serve_html(self, body.encode())

    def log_message(self, *args: object) -> None:
        return


class _ServerFixture(unittest.TestCase):
    handler_cls: type[BaseHTTPRequestHandler]

    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self._orig_gai = socket.getaddrinfo
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler_cls)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        orig = self._orig_gai
        port = self.server.server_port
        socket.getaddrinfo = lambda host, p, *a, **k: orig("127.0.0.1", port, *a, **k)
        self.seed = f"http://fanout.example.test:{self.server.server_port}/"

    def tearDown(self) -> None:
        socket.getaddrinfo = self._orig_gai
        self.server.shutdown()
        self.server.server_close()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev


class MaxPagesCapTests(_ServerFixture):
    handler_cls = _FanOutHandler

    def test_discovered_urls_never_exceed_max_pages(self) -> None:
        governor = HostRateGovernor(capacity=200, min_interval_s=0.0, refill_per_s=1000.0)
        result = recon.discover(
            self.seed, max_pages=5, max_requests=100, max_depth=2, settings=get_settings(), governor=governor,
        )
        self.assertLessEqual(len(result["urls"]), 5)
        self.assertTrue(any("discovery capped at 5 URLs" in n for n in result["notes"]))


class MaxRequestsCapTests(_ServerFixture):
    handler_cls = _FanOutHandler

    def test_requests_used_never_exceeds_max_requests(self) -> None:
        # Generous governor capacity so the REQUEST budget, not the per-host
        # governor, is the thing that stops the crawl here.
        governor = HostRateGovernor(capacity=200, min_interval_s=0.0, refill_per_s=1000.0)
        result = recon.discover(
            self.seed, max_pages=100, max_requests=3, max_depth=2, settings=get_settings(), governor=governor,
        )
        self.assertLessEqual(result["requests_used"], 3)
        self.assertTrue(any("recon request budget (3) reached" in n for n in result["notes"]))
        # far fewer than the 20 leaf links actually got crawled
        self.assertLess(len(result["urls"]), 20)


class MaxDepthCapTests(_ServerFixture):
    handler_cls = _ChainHandler

    def test_pages_beyond_max_depth_are_listed_but_never_crawled(self) -> None:
        governor = HostRateGovernor(capacity=200, min_interval_s=0.0, refill_per_s=1000.0)
        result = recon.discover(
            self.seed, max_pages=50, max_requests=50, max_depth=1, settings=get_settings(), governor=governor,
        )
        urls = result["urls"]
        d1 = next((u for u in urls if u.endswith("/d1")), None)
        d2 = next((u for u in urls if u.endswith("/d2")), None)
        d3 = next((u for u in urls if u.endswith("/d3")), None)
        self.assertIsNotNone(d1)  # depth 1 -- within max_depth, fully crawled
        # depth 2 was DISCOVERED as a link extracted from d1's body (queued before the
        # depth check runs), but never actually fetched -- so its own out-link (d3) is
        # never reached.
        self.assertIsNotNone(d2)
        self.assertIsNone(d3)


class SafeFetchGovernorThrottleTests(_ServerFixture):
    handler_cls = _FanOutHandler

    def test_exhausted_governor_silently_stops_all_further_fetches(self) -> None:
        # capacity=1, no refill -> exactly one throttle() call for this host ever
        # succeeds; every fetch after that (including the seed's own page load)
        # returns None via _safe_fetch, without raising.
        governor = HostRateGovernor(capacity=1, min_interval_s=0.0, refill_per_s=0.0)
        result = recon.discover(
            self.seed, max_pages=50, max_requests=50, max_depth=2, settings=get_settings(), governor=governor,
        )
        # Only the pre-seeded seed URL is present -- nothing was actually crawled.
        self.assertEqual(result["urls"], [self.seed])
        self.assertEqual(result["sources"], {})
        # budgeted_fetch was still attempted (and counted) multiple times even though
        # every attempt past the first was silently throttled to None.
        self.assertGreaterEqual(result["requests_used"], 1)

    def test_direct_safe_fetch_returns_none_when_throttled(self) -> None:
        governor = HostRateGovernor(capacity=1, min_interval_s=0.0, refill_per_s=0.0)
        host = f"127.0.0.1:{self.server.server_port}"
        url = f"http://{host}/"
        first = recon._safe_fetch(url, get_settings(), governor)
        second = recon._safe_fetch(url, get_settings(), governor)
        self.assertIsNotNone(first)
        self.assertIsNone(second)  # bucket exhausted, no network attempt made


if __name__ == "__main__":
    unittest.main()
