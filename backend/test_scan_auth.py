"""Unit tests for the authenticated-scan credential boundary.

The whole safety story of authenticated scanning rests on `same_site` /
`auth_headers_for`: the operator's session must reach the target host (and its
subdomains) and NOTHING else. These tests pin that boundary, including the ways
it must REFUSE to widen (substring, sibling subdomain, registrable-domain guess).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import scan_auth as sa  # noqa: E402
from bughunter import web_scan_service as ws  # noqa: E402
from bughunter.scan_auth import AuthContext  # noqa: E402


class SameSiteTests(unittest.TestCase):
    def test_exact_and_subdomain_match(self) -> None:
        self.assertTrue(sa.same_site("example.com", "example.com"))
        self.assertTrue(sa.same_site("app.example.com", "example.com"))
        self.assertTrue(sa.same_site("a.b.example.com", "example.com"))
        self.assertTrue(sa.same_site("EXAMPLE.com", "example.com"))  # case-insensitive

    def test_refuses_to_widen(self) -> None:
        # substring is NOT same-site
        self.assertFalse(sa.same_site("evil-example.com", "example.com"))
        self.assertFalse(sa.same_site("example.com.evil.test", "example.com"))
        # a parent / sibling of the bound host is NOT covered (binding to app.example.com
        # must not leak to api.example.com or example.com)
        self.assertFalse(sa.same_site("api.example.com", "app.example.com"))
        self.assertFalse(sa.same_site("example.com", "app.example.com"))
        # a third-party bucket host is never same-site with the target
        self.assertFalse(sa.same_site("bucket.s3.amazonaws.com", "example.com"))
        # empty inputs fail closed
        self.assertFalse(sa.same_site("", "example.com"))
        self.assertFalse(sa.same_site("example.com", ""))

    def test_ip_hosts_require_exact_match(self) -> None:
        # An IP has no subdomains; the dotted-suffix test must not treat an IP whose
        # label-suffix coincides as same-site.
        self.assertTrue(sa.same_site("203.0.113.5", "203.0.113.5"))
        self.assertFalse(sa.same_site("5.203.0.113.5", "203.0.113.5"))
        self.assertFalse(sa.same_site("203.0.113.5", "0.113.5"))
        self.assertFalse(sa.same_site("evil.203.0.113.5", "203.0.113.5"))


class AuthHeadersForTests(unittest.TestCase):
    AUTH = AuthContext(host="example.com", headers={"Cookie": "session=secret", "Authorization": "Bearer t"})

    def test_attaches_only_same_site(self) -> None:
        self.assertEqual(sa.auth_headers_for("app.example.com", self.AUTH), dict(self.AUTH.headers))
        self.assertEqual(sa.auth_headers_for("example.com", self.AUTH), dict(self.AUTH.headers))

    def test_never_attaches_off_site(self) -> None:
        self.assertEqual(sa.auth_headers_for("bucket.s3.amazonaws.com", self.AUTH), {})
        self.assertEqual(sa.auth_headers_for("evil-example.com", self.AUTH), {})

    def test_none_auth_is_empty(self) -> None:
        self.assertEqual(sa.auth_headers_for("example.com", None), {})
        self.assertEqual(sa.auth_headers_for("example.com", AuthContext(host="example.com", headers={})), {})

    def test_returned_dict_is_a_copy(self) -> None:
        out = sa.auth_headers_for("example.com", self.AUTH)
        out["Cookie"] = "tampered"
        self.assertEqual(self.AUTH.headers["Cookie"], "session=secret")  # source not mutated


class BuildAuthTests(unittest.TestCase):
    def test_cookie_and_headers(self) -> None:
        auth = sa.build_auth("https://app.example.com/dash", cookie="session=abc; csrf=z",
                             headers=["Authorization: Bearer xyz", "X-Api-Key: k"])
        self.assertIsNotNone(auth)
        self.assertEqual(auth.host, "app.example.com")
        self.assertEqual(auth.headers["Cookie"], "session=abc; csrf=z")
        self.assertEqual(auth.headers["Authorization"], "Bearer xyz")
        self.assertEqual(auth.headers["X-Api-Key"], "k")

    def test_forbidden_and_malformed_headers_dropped(self) -> None:
        auth = sa.build_auth("https://example.com/", headers=[
            "Host: evil.test",           # forbidden — transport-controlled
            "Content-Length: 0",         # forbidden
            "no-colon-here",             # malformed
            "Authorization: Bearer ok",  # kept
        ])
        self.assertIsNotNone(auth)
        self.assertNotIn("Host", auth.headers)
        self.assertNotIn("Content-Length", auth.headers)
        self.assertEqual(auth.headers, {"Authorization": "Bearer ok"})

    def test_no_auth_returns_none(self) -> None:
        self.assertIsNone(sa.build_auth("https://example.com/", cookie="", headers=[]))
        self.assertIsNone(sa.build_auth("https://example.com/", headers=["garbage", "Host: x"]))

    def test_no_host_returns_none(self) -> None:
        self.assertIsNone(sa.build_auth("not-a-url", cookie="session=1"))

    def test_pasted_multiline_cookie_is_collapsed(self) -> None:
        auth = sa.build_auth("https://example.com/", cookie="a=1;\n  b=2")
        self.assertNotIn("\n", auth.headers["Cookie"])
        self.assertEqual(auth.headers["Cookie"], "a=1; b=2")

    def test_idn_host_is_bound_in_punycode_not_unicode(self) -> None:
        # web_scan_service sanitizes every request/redirect host through _guard_url ->
        # _ascii_hostname BEFORE comparing it with same_site(). If build_auth bound the
        # UNICODE form here, every request to the legitimate target -- which arrives
        # punycoded -- would mismatch and silently never receive the session.
        auth = sa.build_auth("https://münchen.de/dash", cookie="session=abc")
        self.assertIsNotNone(auth)
        self.assertEqual(auth.host, "xn--mnchen-3ya.de")
        # And the request host (as web_scan_service would present it) now matches.
        self.assertTrue(sa.same_site("xn--mnchen-3ya.de", auth.host))
        self.assertTrue(sa.same_site("api.xn--mnchen-3ya.de", auth.host))


class GuardedRedirectAuthTests(unittest.TestCase):
    """The passive scanner FOLLOWS redirects, so a 30x bounce off the target host
    must drop the session — otherwise a redirect to a login/SSO host leaks it.
    (_host_is_private is patched off so the guard doesn't do real DNS in the test.)"""

    PORTS = frozenset({80, 443})

    @patch("bughunter.web_scan_service._host_is_private", lambda *a, **k: False)
    def test_strips_auth_on_cross_site_redirect(self) -> None:
        # Includes a MULTI-WORD custom header — urllib stores keys capitalized
        # ("X-Api-Key" -> "X-api-key"), so a naive remove_header(original) would miss
        # it and leak the token to the redirect target. The strip must be casing-robust.
        auth = AuthContext(host="example.com", headers={
            "Cookie": "session=s", "Authorization": "Bearer t", "X-Api-Key": "APIKEYSECRET",
        })
        handler = ws._GuardedRedirect(True, self.PORTS, auth=auth)
        req = Request("https://app.example.com/", headers={
            "Cookie": "session=s", "Authorization": "Bearer t", "X-Api-Key": "APIKEYSECRET",
        })
        new = handler.redirect_request(req, None, 302, "Found", {}, "https://login.evil.test/sso")
        self.assertIsNotNone(new)
        remaining = " ".join(f"{k}:{v}" for k, v in new.header_items()).lower()
        self.assertNotIn("apikeysecret", remaining, "custom auth header must not follow a cross-site redirect")
        self.assertNotIn("session=s", remaining, "session cookie must not follow a cross-site redirect")
        self.assertNotIn("bearer t", remaining)

    @patch("bughunter.web_scan_service._host_is_private", lambda *a, **k: False)
    def test_keeps_auth_on_same_site_redirect(self) -> None:
        auth = AuthContext(host="example.com", headers={"Cookie": "session=s"})
        handler = ws._GuardedRedirect(True, self.PORTS, auth=auth)
        req = Request("https://app.example.com/", headers={"Cookie": "session=s"})
        new = handler.redirect_request(req, None, 302, "Found", {}, "https://api.example.com/v2")
        self.assertIsNotNone(new)
        self.assertTrue(new.has_header("Cookie"), "session may follow a same-site redirect")


if __name__ == "__main__":
    unittest.main()
