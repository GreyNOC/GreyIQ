"""Tests for the IDOR / BOLA dual-session differential.

A fake two-session HTTP (no network) drives the confirm logic: a real cross-tenant read
confirms; a denied/own-data/static-page/invalid-session case never falsely confirms. The
gating (same host, in-scope, two sessions required) is asserted too.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"  # 127.0.0.1 reachable for the gate
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import access_control_service as ac  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402

URL_A = "http://127.0.0.1/api/object/a"
URL_B = "http://127.0.0.1/api/object/b"
A_DATA = "<html>Account A — order 1001, card ****1111, ship to 1 A St</html>"
B_DATA = "<html>Account B — order 2002, card ****9999, ship to 9 B Ave</html>"
SHARED = "<html>Welcome to the app dashboard. Generic content for everyone here.</html>"


def _settings():
    s = get_settings()
    try:
        object.__setattr__(s, "allow_private_urls", True)
    except Exception:  # frozen-dataclass fallback
        s.allow_private_urls = True  # type: ignore[attr-defined]
    return s


def _fake_http(responses):
    """responses: dict[(who, path_suffix)] -> (status, body). who is 'A'/'B' by cookie."""
    class FakeHttp:
        def __init__(self, settings, governor, max_requests=4, auth=None):
            self.auth = auth
        def fetch(self, url, *, method="GET", extra_headers=None):
            cookie = (self.auth.headers.get("Cookie", "") if self.auth else "")
            who = "A" if "AAA" in cookie else "B"
            suffix = "/a" if url.rstrip("/").endswith("/a") else "/b"
            status, body = responses[(who, suffix)]
            return {"status": status, "headers": {}, "body": body, "cookies": [], "final_url": url, "location": None}
    return FakeHttp


def _run(responses):
    orig = ac._Http
    ac._Http = _fake_http(responses)
    try:
        return ac.run_idor_check(
            URL_A, URL_B,
            account_a={"cookie": "sess=AAA"}, account_b={"cookie": "sess=BBB"},
            scope="127.0.0.1", settings=_settings(),
        )
    finally:
        ac._Http = orig


class IdorDifferentialTests(unittest.TestCase):
    def test_confirms_real_cross_tenant_read(self) -> None:
        # B requesting A's object returns A's data (not B's) -> confirmed IDOR.
        res = _run({
            ("A", "/a"): (200, A_DATA),    # A reads A's object
            ("B", "/b"): (200, B_DATA),    # B reads B's own object (control, valid session)
            ("B", "/a"): (200, A_DATA),    # B reads A's object -> gets A's data (the bug)
        })
        self.assertEqual(res["status"], "confirmed")
        f = res["finding"]
        self.assertEqual(f["class_id"], "access-control")
        self.assertEqual(f["rule_id"], "active.idor")
        # The cross-tenant BODY must never be embedded (it's another user's data).
        self.assertEqual(f["snippet"], "")
        self.assertNotIn("card ****1111", f["proof_evidence"]["matched_value"])
        self.assertEqual(res["attack_plan"]["proof_of_impact"]["status"], "confirmed")

    def test_access_control_enforced_does_not_confirm(self) -> None:
        # B is denied A's object (403) -> access control held, no IDOR.
        res = _run({
            ("A", "/a"): (200, A_DATA),
            ("B", "/b"): (200, B_DATA),
            ("B", "/a"): (403, "<html>Forbidden</html>"),
        })
        self.assertEqual(res["status"], "enforced")
        self.assertNotIn("finding", res)

    def test_b_gets_its_own_data_does_not_confirm(self) -> None:
        # B requesting A's object returns B's OWN data (server scoped to the session) -> not IDOR.
        res = _run({
            ("A", "/a"): (200, A_DATA),
            ("B", "/b"): (200, B_DATA),
            ("B", "/a"): (200, B_DATA),
        })
        self.assertEqual(res["status"], "enforced")

    def test_static_shared_page_is_candidate_not_confirmed(self) -> None:
        # A's and B's objects return identical content -> endpoint isn't object-specific.
        res = _run({
            ("A", "/a"): (200, SHARED),
            ("B", "/b"): (200, SHARED),
            ("B", "/a"): (200, SHARED),
        })
        self.assertEqual(res["status"], "candidate")
        self.assertIn("object-specific", res["reason"])

    def test_page_chrome_dilution_is_candidate_not_silently_enforced(self) -> None:
        # B-on-A returns A's object wrapped in B's page chrome -> resembles A but below the
        # auto-confirm bar; surface as a candidate to inspect, not a silent 'enforced'.
        # Object body larger than the shared chrome -> B-on-A ~0.85 similar to A's raw
        # object (below the 0.95 confirm bar) but far more similar to A than to B's own.
        a_obj = "A" * 120
        b_obj = "B" * 120
        chrome = "C" * 40  # shared page chrome (nav/footer) wrapping B's rendered pages
        res = _run({
            ("A", "/a"): (200, a_obj),                 # A's raw object
            ("B", "/b"): (200, b_obj + chrome),        # B's own object in B's chrome
            ("B", "/a"): (200, a_obj + chrome),        # A's object in B's chrome (the leak)
        })
        self.assertEqual(res["status"], "candidate")
        self.assertIn("page chrome", res["reason"])

    def test_invalid_b_session_is_candidate(self) -> None:
        # B can't read its OWN object (302 to login) -> can't attribute a cross-read.
        res = _run({
            ("A", "/a"): (200, A_DATA),
            ("B", "/b"): (302, ""),
            ("B", "/a"): (200, A_DATA),
        })
        self.assertEqual(res["status"], "candidate")


PRIV_URL = "http://127.0.0.1/admin/users"
ADMIN_DATA = "<html>Admin panel — users alice, bob, carol with role + delete controls</html>"
DENIED = "<html>403 Forbidden — you do not have permission to view this page</html>"


def _fake_bfla_http(by_role):
    """by_role: dict role -> (status, body). role is 'admin'/'user' by cookie, 'anon' when auth is None."""
    class FakeHttp:
        def __init__(self, settings, governor, max_requests=4, auth=None):
            self.auth = auth
        def fetch(self, url, *, method="GET", extra_headers=None):
            if not self.auth:
                role = "anon"
            else:
                cookie = self.auth.headers.get("Cookie", "")
                role = "admin" if "ADM" in cookie else "user"
            status, body = by_role[role]
            return {"status": status, "headers": {}, "body": body, "cookies": [], "final_url": url, "location": None}
    return FakeHttp


def _run_bfla(by_role):
    orig = ac._Http
    ac._Http = _fake_bfla_http(by_role)
    try:
        return ac.run_bfla_check(
            PRIV_URL, admin_account={"cookie": "sess=ADM"}, user_account={"cookie": "sess=USR"},
            scope="127.0.0.1", settings=_settings())
    finally:
        ac._Http = orig


class BflaDifferentialTests(unittest.TestCase):
    def test_confirms_when_low_priv_user_gets_admin_content(self) -> None:
        res = _run_bfla({
            "admin": (200, ADMIN_DATA),   # admin sees the privileged page
            "user": (200, ADMIN_DATA),    # low-priv user ALSO sees it (the bug)
            "anon": (403, DENIED),        # anonymous is denied -> endpoint is protected
        })
        self.assertEqual(res["status"], "confirmed")
        f = res["finding"]
        self.assertEqual(f["rule_id"], "active.bfla")
        self.assertEqual(f["class_id"], "access-control")
        self.assertEqual(f["snippet"], "")  # privileged body never embedded
        self.assertNotIn("alice", f["proof_evidence"]["matched_value"])
        self.assertEqual(res["attack_plan"]["proof_of_impact"]["status"], "confirmed")

    def test_enforced_when_user_is_denied(self) -> None:
        res = _run_bfla({
            "admin": (200, ADMIN_DATA),
            "user": (403, DENIED),
            "anon": (403, DENIED),
        })
        self.assertEqual(res["status"], "enforced")
        self.assertNotIn("finding", res)

    def test_public_endpoint_is_candidate_not_confirmed(self) -> None:
        # Anonymous sees the same content as admin -> the page is PUBLIC, not privilege-gated.
        res = _run_bfla({
            "admin": (200, ADMIN_DATA),
            "user": (200, ADMIN_DATA),
            "anon": (200, ADMIN_DATA),
        })
        self.assertEqual(res["status"], "candidate")
        self.assertIn("public", res["reason"].lower())

    def test_admin_session_not_authorized_is_candidate(self) -> None:
        res = _run_bfla({
            "admin": (302, ""),           # admin session can't read the page either
            "user": (200, ADMIN_DATA),
            "anon": (403, DENIED),
        })
        self.assertEqual(res["status"], "candidate")
        self.assertIn("high-privilege", res["reason"].lower())

    def test_page_chrome_dilution_is_candidate(self) -> None:
        admin_body = "A" * 120
        res = _run_bfla({
            "admin": (200, admin_body),
            "user": (200, admin_body + "C" * 40),   # admin content in the user's chrome (~0.86)
            "anon": (403, "no"),
        })
        self.assertEqual(res["status"], "candidate")
        self.assertIn("page chrome", res["reason"])


class BflaGatingTests(unittest.TestCase):
    def test_requires_two_sessions(self) -> None:
        r = ac.run_bfla_check(PRIV_URL, admin_account={"cookie": "sess=ADM"}, user_account={},
                              scope="127.0.0.1", settings=_settings())
        self.assertFalse(r["ok"])
        self.assertIn("TWO sessions", r["error"])

    def test_out_of_scope_refused(self) -> None:
        r = ac.run_bfla_check("http://1.2.3.4/admin", admin_account={"cookie": "a"}, user_account={"cookie": "b"},
                              scope="example.com")
        self.assertFalse(r["ok"])
        self.assertIn("scope", r["error"].lower())


class IdorGatingTests(unittest.TestCase):
    def test_requires_two_distinct_same_host_urls(self) -> None:
        self.assertFalse(ac.run_idor_check("", "", account_a={}, account_b={}, scope="x")["ok"])
        self.assertIn("identical", ac.run_idor_check(URL_A, URL_A, account_a={"cookie": "a"}, account_b={"cookie": "b"}, scope="127.0.0.1", settings=_settings())["error"])
        r = ac.run_idor_check("http://127.0.0.1/a", "http://other.example/b",
                              account_a={"cookie": "a"}, account_b={"cookie": "b"}, scope="127.0.0.1", settings=_settings())
        self.assertIn("same host", r["error"])

    def test_requires_both_sessions(self) -> None:
        r = ac.run_idor_check(URL_A, URL_B, account_a={"cookie": "sess=AAA"}, account_b={},
                              scope="127.0.0.1", settings=_settings())
        self.assertFalse(r["ok"])
        self.assertIn("TWO sessions", r["error"])

    def test_out_of_scope_host_refused(self) -> None:
        r = ac.run_idor_check("http://1.2.3.4/a", "http://1.2.3.4/b",
                              account_a={"cookie": "a"}, account_b={"cookie": "b"}, scope="example.com")
        self.assertFalse(r["ok"])
        self.assertIn("scope", r["error"].lower())


if __name__ == "__main__":
    unittest.main()
