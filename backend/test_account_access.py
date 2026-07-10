"""Per-program hunting requirements: research-account access (auto-login / pasted cookie) + a mandatory
user-agent suffix. Verifies the credentials are bounded + redacted, the UA tag is header-injection-safe
and rides in-scope requests, and the login service is scope-gated and fails closed."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api  # noqa: E402
from bughunter import account_login_service, campaign, portfolio, web_ingest, web_scan_service  # noqa: E402


class SchemaTests(unittest.TestCase):
    def test_account_access_is_bounded_and_junk_dropped(self) -> None:
        r = portfolio._normalize({"name": "P", "account_access": {
            "email": "me@ywh.example", "password": "pw", "login_url": "https://app.example/login",
            "register_url": "https://app.example/register", "cookie": "sid=abc", "notes": "n", "junk": "x"}})
        acc = r["account_access"]
        self.assertEqual(acc["email"], "me@ywh.example")
        self.assertEqual(acc["password"], "pw")
        self.assertNotIn("junk", acc)                       # only known fields survive
        self.assertEqual(portfolio._normalize({"name": "P"})["account_access"], {})

    def test_ua_suffix_strips_control_chars_keeps_spaces(self) -> None:
        # the required tag often has intentional surrounding spaces; a CR/LF would be header injection
        s = portfolio._normalize({"name": "P", "user_agent_suffix": " -BugBounty-acme-31337 \r\nEVIL"})["user_agent_suffix"]
        self.assertIn(" -BugBounty-acme-31337 ", s)
        self.assertNotIn("\r", s)
        self.assertNotIn("\n", s)


class UserAgentSuffixTests(unittest.TestCase):
    def tearDown(self) -> None:
        web_ingest.set_ua_suffix("")  # never leak the suffix into another test

    def test_suffix_appends_and_resets(self) -> None:
        tok = web_ingest.set_ua_suffix(" -BugBounty-acme-31337 ")
        self.assertEqual(web_ingest.current_user_agent("UA"), "UA -BugBounty-acme-31337 ")
        # the web_scan_service re-export reads the SAME contextvar (so the active prover/scan get it)
        self.assertEqual(web_scan_service.current_user_agent("UA"), "UA -BugBounty-acme-31337 ")
        web_ingest.reset_ua_suffix(tok)
        self.assertEqual(web_ingest.current_user_agent("UA"), "UA")

    def test_crlf_can_never_be_injected(self) -> None:
        web_ingest.set_ua_suffix("a\r\nInjected: header")
        self.assertNotIn("\n", web_ingest.current_user_agent("UA"))


class LoginServiceTests(unittest.TestCase):
    def test_pasted_cookie_is_the_direct_path(self) -> None:
        out = account_login_service.login({"cookie": "sid=abc123"}, scope="app.example")
        self.assertTrue(out["ok"])
        self.assertEqual(out["cookie"], "sid=abc123")

    def test_pasted_cookie_carries_issuing_host_from_login_url(self) -> None:
        # a span reuses this session for every target; the issuing host is what gates the cookie
        # to its own registrable domain downstream (scan_auth.build_auth)
        out = account_login_service.login(
            {"cookie": "sid=abc123", "login_url": "https://login.acme-a.com/signin"}, scope="acme-a.com")
        self.assertTrue(out["ok"])
        self.assertEqual(out["host"], "login.acme-a.com")

    def test_pasted_cookie_without_login_url_has_no_issuing_host(self) -> None:
        # unknown issuer => empty host => no cross-issuer gate (a single-target paste is unaffected)
        out = account_login_service.login({"cookie": "sid=abc123"}, scope="app.example")
        self.assertEqual(out.get("host", ""), "")

    def test_pasted_cookie_with_out_of_scope_login_url_has_no_issuing_host(self) -> None:
        # a third-party/SSO login_url (not in scope) is NOT the cookie's issuer — leaving the host
        # empty means the pasted cookie is NOT wrongly withheld from its in-scope target
        out = account_login_service.login(
            {"cookie": "sid=abc123", "login_url": "https://login.okta-idp.com/app"}, scope="acme-a.com")
        self.assertTrue(out["ok"])
        self.assertEqual(out.get("host", ""), "")

    def test_no_credentials_fails_closed(self) -> None:
        out = account_login_service.login({"email": "me@x.example"}, scope="app.example")  # no password/login_url
        self.assertFalse(out["ok"])
        self.assertEqual(out["cookie"], "")

    def test_out_of_scope_login_url_never_submits_credentials(self) -> None:
        # credentials must go ONLY to an in-scope, guard-approved host; an out-of-scope (or otherwise
        # refused) login URL fails closed BEFORE any browser/login is attempted
        called = []
        orig = account_login_service._playwright_login
        account_login_service._playwright_login = lambda *a, **k: called.append(1) or {"ok": True, "cookie": "x"}
        try:
            out = account_login_service.login(
                {"email": "me@x.example", "password": "pw", "login_url": "https://evil.example/login"},
                scope="app.example")  # login host not in scope
        finally:
            account_login_service._playwright_login = orig
        self.assertFalse(out["ok"])                            # fails closed
        self.assertEqual(out["cookie"], "")
        self.assertEqual(called, [])                           # and NEVER reached the login attempt

    def test_scope_gate_rejects_resolvable_out_of_scope_host(self) -> None:
        # isolate the SCOPE gate specifically: bypass the DNS/SSRF guard, then confirm an in-DNS but
        # out-of-scope login host is still refused before the credentials are submitted
        called = []
        orig_guard = account_login_service._guard_url
        orig_login = account_login_service._playwright_login
        account_login_service._guard_url = lambda url, *a, **k: url  # pretend the URL guard passed
        account_login_service._playwright_login = lambda *a, **k: called.append(1) or {"ok": True, "cookie": "x"}
        try:
            out = account_login_service.login(
                {"email": "me@x.example", "password": "pw", "login_url": "https://out-of-scope.example/login"},
                scope="app.example")  # host resolves-ish but is not in scope
        finally:
            account_login_service._guard_url = orig_guard
            account_login_service._playwright_login = orig_login
        self.assertFalse(out["ok"])
        self.assertEqual(called, [])                           # scope gate stopped it
        self.assertIn("scope", out["note"].lower())


class LoginAuthPlumbingTests(unittest.TestCase):
    """campaign._login_auth is what a span calls ONCE; it must carry the login's issuing host into
    the reused auth dict so every per-target build_auth can gate the cookie to the issuer's domain."""

    def test_login_auth_propagates_issuer_host(self) -> None:
        orig = campaign.account_login_service.login
        campaign.account_login_service.login = lambda *a, **k: {
            "ok": True, "cookie": "session=SECRET-A", "headers": [], "host": "login.acme-a.com", "note": "ok"}
        try:
            auth = campaign._login_auth({"email": "u@x", "password": "p", "login_url": "https://login.acme-a.com/"},
                                        scope="acme-a.com", excluded_hosts=(), emit=None)
        finally:
            campaign.account_login_service.login = orig
        self.assertEqual(auth["cookie"], "session=SECRET-A")
        self.assertEqual(auth["issuer_host"], "login.acme-a.com")

    def test_login_auth_none_when_login_fails_closed(self) -> None:
        orig = campaign.account_login_service.login
        campaign.account_login_service.login = lambda *a, **k: {"ok": False, "cookie": "", "note": "nope"}
        try:
            auth = campaign._login_auth({"email": "u@x"}, scope="acme-a.com", excluded_hosts=(), emit=None)
        finally:
            campaign.account_login_service.login = orig
        self.assertIsNone(auth)


class ApiRedactionTests(unittest.TestCase):
    def test_read_back_redacts_password_and_cookie(self) -> None:
        prog = {"id": "p1", "name": "P", "account_access": {
            "email": "me@ywh.example", "login_url": "https://app.example/login",
            "password": "supersecret", "cookie": "sid=abc"}}
        red = greyiq_api._program_for_read(prog)["account_access"]
        self.assertEqual(red["email"], "me@ywh.example")      # identity/URLs still shown for editing
        self.assertEqual(red["login_url"], "https://app.example/login")
        self.assertNotIn("password", red)                     # the secret itself never leaves the API
        self.assertNotIn("cookie", red)
        self.assertTrue(red["password_set"])                  # only that it IS set
        self.assertTrue(red["cookie_set"])

    def test_read_back_no_account_is_untouched(self) -> None:
        self.assertEqual(greyiq_api._program_for_read({"id": "p", "name": "P"}).get("account_access"), None)


class AdminAccountAccessTests(unittest.TestCase):
    """The SECOND (high-privilege) research account that unlocks dual-account BFLA — same shape,
    bounding, and redaction as the low-privilege account_access."""

    def test_admin_account_access_is_bounded_and_junk_dropped(self) -> None:
        r = portfolio._normalize({"name": "P", "admin_account_access": {
            "email": "admin@ywh.example", "password": "apw", "cookie": "sid=admin", "junk": "x"}})
        acc = r["admin_account_access"]
        self.assertEqual(acc["email"], "admin@ywh.example")
        self.assertEqual(acc["password"], "apw")
        self.assertNotIn("junk", acc)
        self.assertEqual(portfolio._normalize({"name": "P"})["admin_account_access"], {})  # default empty

    def test_read_back_redacts_admin_secrets(self) -> None:
        prog = {"id": "p1", "name": "P", "admin_account_access": {
            "email": "admin@ywh.example", "password": "topsecret", "cookie": "sid=admin"}}
        red = greyiq_api._program_for_read(prog)["admin_account_access"]
        self.assertEqual(red["email"], "admin@ywh.example")
        self.assertNotIn("password", red)                     # admin secret never leaves the API either
        self.assertNotIn("cookie", red)
        self.assertTrue(red["password_set"])
        self.assertTrue(red["cookie_set"])

    def test_read_back_no_admin_account_is_untouched(self) -> None:
        # a program with only the low-priv account must not sprout an empty admin_account_access on read
        self.assertNotIn("admin_account_access",
                         greyiq_api._program_for_read({"id": "p", "name": "P", "account_access": {"email": "u@x"}}))


class IdorPairsTests(unittest.TestCase):
    """Operator-supplied cross-tenant IDOR test pairs — object URLs only (no secrets), bounded/deduped/
    capped, and NEVER auto-derived by the engine (the operator asserts the ownership)."""

    def test_pairs_are_bounded_deduped_and_incomplete_dropped(self) -> None:
        r = portfolio._normalize({"name": "P", "idor_pairs": [
            {"url_a": "https://app/a/1", "url_b": "https://app/b/2", "label": "orders", "junk": "x"},
            {"url_a": "https://app/a/1", "url_b": "https://app/b/2"},   # exact duplicate -> dropped
            {"url_a": "https://app/a/9"},                               # missing url_b -> dropped
            {"url_a": "https://app/same", "url_b": "https://app/same"},  # identical URLs -> dropped
            {"nonsense": True},                                         # not a pair -> dropped
        ]})
        pairs = r["idor_pairs"]
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0], {"url_a": "https://app/a/1", "url_b": "https://app/b/2", "label": "orders"})
        self.assertNotIn("junk", pairs[0])
        self.assertEqual(portfolio._normalize({"name": "P"})["idor_pairs"], [])   # default empty

    def test_pairs_list_is_capped(self) -> None:
        many = [{"url_a": f"https://app/a/{i}", "url_b": f"https://app/b/{i}"} for i in range(50)]
        pairs = portfolio._normalize({"name": "P", "idor_pairs": many})["idor_pairs"]
        self.assertLessEqual(len(pairs), portfolio._MAX_IDOR_PAIRS)

    def test_read_back_passes_pairs_through_unredacted(self) -> None:
        # object URLs aren't secrets — they round-trip verbatim so an edit re-sends them
        prog = {"id": "p1", "name": "P", "idor_pairs": [{"url_a": "https://app/a/1", "url_b": "https://app/b/2"}]}
        self.assertEqual(greyiq_api._program_for_read(prog)["idor_pairs"], prog["idor_pairs"])


if __name__ == "__main__":
    unittest.main()
