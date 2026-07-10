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

from bughunter import account_login_service  # noqa: E402
from bughunter import bounty  # noqa: E402
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

    def test_trailing_dot_fqdn_is_unrecognized_fails_closed(self) -> None:
        # PINS the current behavior (a coverage gap, not a security bug): same_site does
        # a raw string compare with no trailing-dot normalization, so the root-zone FQDN
        # form ('example.com.' -- semantically identical to 'example.com') does NOT match
        # unless BOTH sides carry the dot. This only ever causes a session to be withheld
        # (fail-closed), never attached somewhere it shouldn't be -- a correctness/
        # usability gap, not an exploitable widening.
        self.assertFalse(sa.same_site("app.example.com.", "example.com"))
        self.assertFalse(sa.same_site("app.example.com", "example.com."))
        self.assertTrue(sa.same_site("app.example.com.", "example.com."))  # both dotted -> matches

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


class SameRegistrableSiteTests(unittest.TestCase):
    """The wider issuer boundary: a reused research-account session may reach any host on
    the ISSUER's registrable domain (siblings included), and nothing off it."""

    def test_same_registrable_domain_including_siblings(self) -> None:
        self.assertTrue(sa.same_registrable_site("app.acme.com", "login.acme.com"))  # siblings, neither a subdomain
        self.assertTrue(sa.same_registrable_site("acme.com", "login.acme.com"))       # apex, from a subdomain issuer
        self.assertTrue(sa.same_registrable_site("a.b.acme.com", "acme.com"))
        self.assertTrue(sa.same_registrable_site("acme.com", "acme.com"))
        self.assertTrue(sa.same_registrable_site("APP.acme.com", "login.ACME.com"))   # case-insensitive

    def test_refuses_across_registrable_boundary(self) -> None:
        self.assertFalse(sa.same_registrable_site("acme-b.com", "acme-a.com"))
        self.assertFalse(sa.same_registrable_site("evil-acme.com", "acme.com"))        # substring is not same-registrable
        self.assertFalse(sa.same_registrable_site("acme.com.evil.test", "acme.com"))   # suffix-graft attack

    def test_multi_label_etld_is_respected(self) -> None:
        # foo.co.uk and bar.co.uk are DIFFERENT owners under the co.uk public suffix
        self.assertTrue(sa.same_registrable_site("shop.foo.co.uk", "foo.co.uk"))
        self.assertFalse(sa.same_registrable_site("bar.co.uk", "foo.co.uk"))

    def test_shared_hosting_tenants_are_distinct(self) -> None:
        # a session on one PaaS tenant must never be judged same-site with a sibling tenant
        self.assertFalse(sa.same_registrable_site("a.herokuapp.com", "b.herokuapp.com"))
        self.assertTrue(sa.same_registrable_site("myapp.herokuapp.com", "myapp.herokuapp.com"))

    def test_empty_fails_closed(self) -> None:
        self.assertFalse(sa.same_registrable_site("", "acme.com"))
        self.assertFalse(sa.same_registrable_site("acme.com", ""))

    def test_ip_requires_exact_match(self) -> None:
        self.assertTrue(sa.same_registrable_site("203.0.113.5", "203.0.113.5"))
        self.assertFalse(sa.same_registrable_site("203.0.113.6", "203.0.113.5"))
        self.assertFalse(sa.same_registrable_site("app.example.com", "203.0.113.5"))


class IssuerGateBuildAuthTests(unittest.TestCase):
    """build_auth's issuer_host gate: credentials minted at one host are never re-bound to a
    target on a different registrable domain (the reused-session leak)."""

    def test_no_issuer_binds_to_target_as_before(self) -> None:
        auth = sa.build_auth("https://app.example.com/", cookie="session=x")  # no issuer_host supplied
        self.assertIsNotNone(auth)
        self.assertEqual(auth.host, "app.example.com")
        self.assertEqual(auth.headers["Cookie"], "session=x")

    def test_same_registrable_issuer_attaches_and_binds_to_target(self) -> None:
        auth = sa.build_auth("https://api.example.com/", cookie="session=x", issuer_host="login.example.com")
        self.assertIsNotNone(auth)
        self.assertEqual(auth.headers["Cookie"], "session=x")
        # still bound to the TARGET host, so the per-request same_site redirect check is unchanged
        self.assertEqual(auth.host, "api.example.com")

    def test_off_registrable_issuer_withholds_everything(self) -> None:
        self.assertIsNone(sa.build_auth("https://other-brand.com/", cookie="session=x", issuer_host="login.example.com"))
        self.assertIsNone(sa.build_auth("https://app.other-brand.com/", headers=["Authorization: Bearer t"],
                                        issuer_host="example.com"))

    def test_shared_hosting_tenants_are_isolated(self) -> None:
        self.assertIsNone(sa.build_auth("https://attacker.herokuapp.com/", cookie="s=1", issuer_host="victim.herokuapp.com"))
        self.assertIsNotNone(sa.build_auth("https://victim.herokuapp.com/x", cookie="s=1", issuer_host="victim.herokuapp.com"))

    def test_ip_issuer_requires_exact_match(self) -> None:
        self.assertIsNotNone(sa.build_auth("http://203.0.113.5/", cookie="s=1", issuer_host="203.0.113.5"))
        self.assertIsNone(sa.build_auth("http://203.0.113.6/", cookie="s=1", issuer_host="203.0.113.5"))

    def test_idn_target_gate_compares_in_punycode(self) -> None:
        # issuer given in unicode; the target arrives punycoded — the gate must still recognize them as
        # the same registrable domain (and bind the session), not silently withhold it.
        auth = sa.build_auth("https://api.xn--mnchen-3ya.de/", cookie="s=1", issuer_host="münchen.de")
        self.assertIsNotNone(auth)
        self.assertEqual(auth.host, "api.xn--mnchen-3ya.de")


class SpanReuseIssuerGateTests(unittest.TestCase):
    """End-to-end regression for the reported defect: a multi-target span logs into the research
    account ONCE (at host L) and reuses that one session for every in-scope target. The login
    cookie must reach L's own registrable domain but NEVER a target on a different one."""

    def _session(self) -> dict:
        # exactly what account_login_service.login returns for a program whose login lives on
        # registrable domain acme-a.com (pasted-cookie path carries the login_url's host)
        return account_login_service.login(
            {"cookie": "session=SECRET-A", "login_url": "https://login.acme-a.com/signin"},
            scope="acme-a.com")

    def test_login_reports_the_issuing_host(self) -> None:
        s = self._session()
        self.assertTrue(s["ok"])
        self.assertEqual(s["host"], "login.acme-a.com")

    def test_cookie_reaches_same_registrable_domain_targets(self) -> None:
        s = self._session()
        for target in ("https://login.acme-a.com/", "https://app.acme-a.com/",
                       "https://api.acme-a.com/dash", "https://acme-a.com/"):
            auth = sa.build_auth(target, cookie=s["cookie"], issuer_host=s["host"])
            self.assertIsNotNone(auth, target)
            self.assertEqual(auth.headers["Cookie"], "session=SECRET-A")

    def test_domain_A_cookie_is_never_sent_to_domain_B(self) -> None:
        s = self._session()
        for target in ("https://acme-b.com/", "https://app.acme-b.com/",
                       "https://acme-a.com.evil.test/", "https://evil-acme-a.com/"):
            self.assertIsNone(
                sa.build_auth(target, cookie=s["cookie"], issuer_host=s["host"]),
                f"domain-A login cookie must not bind to {target}")


class RunBountyHuntIssuerWiringTests(unittest.TestCase):
    """The exact call site named in the defect (bounty.run_bounty_hunt -> build_auth) must forward
    the session's issuer_host, or the span gate above would be bypassed for the per-URL scan."""

    def test_run_bounty_hunt_forwards_issuer_host_to_build_auth(self) -> None:
        captured: dict = {}

        class _Stop(Exception):
            pass

        def _spy(target_url, *, cookie="", headers=None, issuer_host=""):
            captured["target_url"] = target_url
            captured["cookie"] = cookie
            captured["issuer_host"] = issuer_host
            raise _Stop()  # build_auth is called before any scanner runs — abort early, no network

        orig = bounty.build_auth
        bounty.build_auth = _spy
        try:
            with self.assertRaises(_Stop):
                bounty.run_bounty_hunt(
                    "https://acme-b.com/", "web-app", None, None, "acme-b.com", True, None,
                    default_reports_dir=Path("."),
                    auth={"cookie": "session=SECRET-A", "issuer_host": "acme-a.com"},
                )
        finally:
            bounty.build_auth = orig
        self.assertEqual(captured["issuer_host"], "acme-a.com")
        self.assertEqual(captured["cookie"], "session=SECRET-A")


if __name__ == "__main__":
    unittest.main()
