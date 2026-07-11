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
from urllib.parse import parse_qsl, urlparse

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


class _JsRedirectHandler(BaseHTTPRequestHandler):
    """In-scope seed page references an in-scope `<script src>`, but that JS asset 302s to a public
    OUT-OF-SCOPE host whose body carries a mineable param + secret. recon must re-gate the JS's
    post-redirect final_url and never mine the OOS body."""
    port = 0

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            body = b'<html><body><script src="/asset.js"></script></body></html>'
            ctype = "text/html"
        elif self.path == "/asset.js":  # in-scope asset that redirects OFF the seed host
            self.send_response(302)
            self.send_header("Location", f"http://evil.example.test:{self.port}/oos.js")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        else:  # the OOS host's JS body — must never be mined
            body = b'var u = "/api/data?leaked_js_param=1"; var k = "AKIAIOSFODNN7EXAMPLE";'
            ctype = "text/javascript"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


class ReconServedJsScopeBleedTests(unittest.TestCase):
    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self._orig_gai = socket.getaddrinfo
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _JsRedirectHandler)
        _JsRedirectHandler.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        orig = self._orig_gai
        port = self.server.server_port
        socket.getaddrinfo = lambda host, p, *a, **k: orig("127.0.0.1", port, *a, **k)

    def tearDown(self) -> None:
        socket.getaddrinfo = self._orig_gai
        self.server.shutdown()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def test_served_js_redirecting_out_of_scope_is_not_mined(self) -> None:
        seed = f"http://app.example.test:{self.server.server_port}/"
        result = recon.discover(seed, scope_in=lambda h: False, settings=get_settings())
        self.assertNotIn("leaked_js_param", result["params"])
        self.assertEqual(result.get("js_secrets"), [])
        self.assertGreaterEqual(result["dropped_out_of_scope"], 1)


class ReconHtmlEntityTests(unittest.TestCase):
    """Regression: an href/src value in HTML encodes '&' as '&amp;'. Recon must DECODE it to
    the real URL, or the '&amp;' survives into the finding location + curl PoC (breaking a
    triager's copy-paste reproduction) and mis-parses the query into a bogus 'amp;<name>'
    parameter the active prober would then chase."""

    def test_extract_links_decodes_amp_entity(self) -> None:
        body = '<a href="/?lang=en&amp;enter_method=bottom_navigation">x</a>'
        [link] = recon._extract_links(body, "https://support.example.test/")
        self.assertNotIn("&amp;", link)
        params = dict(parse_qsl(urlparse(link).query))
        self.assertEqual(params.get("enter_method"), "bottom_navigation")  # real 2nd param, not 'amp;enter_method'
        self.assertNotIn("amp;enter_method", params)

    def test_extract_scripts_decodes_amp_entity(self) -> None:
        body = '<script src="/bundle.js?v=1&amp;t=2"></script>'
        [src] = recon._extract_scripts(body, "https://support.example.test/")
        self.assertNotIn("&amp;", src)
        self.assertIn("v=1&t=2", src)

    def test_raw_ampersand_is_preserved_not_over_decoded(self) -> None:
        # A raw (unencoded) '&' in an href is invalid HTML but widespread. Decoding must NOT
        # eat '&param' / '&copy' / '&notify' as semicolon-less HTML5 named references (which
        # full html.unescape does), or those query parameters silently vanish from discovery.
        body = '<a href="/p?id=1&param=2&copy=3&notify=4">x</a>'
        [link] = recon._extract_links(body, "https://support.example.test/")
        params = dict(parse_qsl(urlparse(link).query))
        self.assertEqual(set(params), {"id", "param", "copy", "notify"})
        for glyph in ("¶", "©", "§"):
            self.assertNotIn(glyph, link)

    def test_only_semicolon_terminated_entities_are_decoded(self) -> None:
        # '&amp;' (';'-terminated) decodes; the trailing raw '&reg' (no ';') is left intact.
        body = '<a href="/s?a=1&amp;b=2&reg=3">x</a>'
        [link] = recon._extract_links(body, "https://support.example.test/")
        self.assertEqual(set(dict(parse_qsl(urlparse(link).query))), {"a", "b", "reg"})


if __name__ == "__main__":
    unittest.main()
