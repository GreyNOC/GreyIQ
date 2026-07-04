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
from bughunter import account_login_service, portfolio, web_ingest, web_scan_service  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
