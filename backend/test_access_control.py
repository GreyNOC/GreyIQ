"""Tests for the IDOR / BOLA dual-session differential.

A fake two-session HTTP (no network) drives the confirm logic: a real cross-tenant read
confirms; a denied/own-data/static-page/invalid-session case never falsely confirms. The
gating (same host, in-scope, two sessions required) is asserted too.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

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
        # A genuinely confirmed dual-session differential is no longer a template CVSS
        # guess — 'estimated' flips false and the justification says why.
        self.assertFalse(res["attack_plan"]["cvss"]["estimated"])
        self.assertIn("confirmed", res["attack_plan"]["cvss"]["justification"].lower())

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
        self.assertFalse(res["attack_plan"]["cvss"]["estimated"])

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


import re as _re

_CHROME = ("<html><head><title>App</title></head><body><nav>Home Orders Account Settings Logout</nav>"
           "<h1>Order detail</h1><div class='card'>")
_OBJECTS = {
    "1001": "Alice ordered 3 widgets, total $42.00, ship to 1 Apple Street, card ending 1111",
    "1002": "Bob ordered 99 sprockets, total $9999.00, ship to 9 Banana Avenue, card ending 2222",
}


def _fake_probe_http(by_url):
    class FakeHttp:
        def __init__(self, settings, governor, max_requests=4, auth=None):
            self.auth = auth
        def fetch(self, url, *, method="GET", extra_headers=None):
            status, body = by_url(url)
            return {"status": status, "headers": {}, "body": body, "cookies": [], "final_url": url, "location": None}
    return FakeHttp


def _run_probe(by_url, url):
    orig = ac._Http
    ac._Http = _fake_probe_http(by_url)
    try:
        return ac.run_idor_probe(url, account={"cookie": "sess=ME"}, scope="127.0.0.1", settings=_settings())
    finally:
        ac._Http = orig


def _by_id_object(url):
    m = _re.search(r"/order/(\d+)", url) or _re.search(r"[?&]id=(\d+)", url)
    if not m:
        return (404, "nope")
    oid = m.group(1)
    detail = _OBJECTS.get(oid, f"object {oid} placeholder content for testing the differential band")
    return (200, _CHROME + f"<p>{detail}</p></div></body></html>")


class IdorProbeTests(unittest.TestCase):
    def test_path_id_mutation_flags_a_candidate(self) -> None:
        res = _run_probe(_by_id_object, "http://127.0.0.1/api/order/1001")
        self.assertEqual(res["status"], "candidate")
        self.assertEqual(res["finding"]["rule_id"], "active.idor-probe")
        self.assertEqual(res["finding"]["snippet"], "")          # neighbour body withheld
        self.assertNotIn("Bob", res["finding"]["proof_evidence"]["matched_value"])
        self.assertEqual(res["attack_plan"]["proof_of_impact"]["status"], "candidate")

    def test_query_id_mutation_flags_a_candidate(self) -> None:
        res = _run_probe(_by_id_object, "http://127.0.0.1/view?id=1001")
        self.assertEqual(res["status"], "candidate")

    def test_identical_neighbour_is_enforced(self) -> None:
        # Every id returns the SAME static page -> not object-specific -> no signal.
        res = _run_probe(lambda url: (200, _CHROME + "<p>generic dashboard for everyone</p></div></body></html>"),
                         "http://127.0.0.1/api/order/1001")
        self.assertEqual(res["status"], "enforced")

    def test_denied_neighbour_is_enforced(self) -> None:
        def by_url(url):
            if "/order/1001" in url:
                return (200, _CHROME + "<p>" + _OBJECTS["1001"] + "</p></div></body></html>")
            return (403, "<html>Forbidden</html>")
        res = _run_probe(by_url, "http://127.0.0.1/api/order/1001")
        self.assertEqual(res["status"], "enforced")

    def test_no_numeric_id_is_reported(self) -> None:
        res = _run_probe(lambda url: (200, _CHROME + "<p>x</p>"), "http://127.0.0.1/account/profile")
        self.assertEqual(res["status"], "no-id")

    def test_requires_a_session(self) -> None:
        r = ac.run_idor_probe("http://127.0.0.1/api/order/1001", account={}, scope="127.0.0.1", settings=_settings())
        self.assertFalse(r["ok"])
        self.assertIn("session", r["error"].lower())

    def test_out_of_scope_refused(self) -> None:
        r = ac.run_idor_probe("http://1.2.3.4/api/order/1", account={"cookie": "a"}, scope="example.com")
        self.assertFalse(r["ok"])
        self.assertIn("scope", r["error"].lower())


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

    def test_guard_url_failure_after_scope_passes(self) -> None:
        # A host can be IN active scope (named verbatim as a token in scope text -- a
        # no-DNS, free-text match) while still failing the SEPARATE SSRF/_guard_url check
        # (e.g. private-host refusal when allow_private_urls is off). Names the host
        # itself in scope text -- host_in_active_scope matches it via the token-equality
        # branch with no DNS lookup -- then _guard_url's own (DNS-resolving) private-host
        # check refuses it, since this settings object has allow_private_urls=False.
        s = get_settings()
        try:
            object.__setattr__(s, "allow_private_urls", False)
        except Exception:  # frozen-dataclass fallback
            s.allow_private_urls = False  # type: ignore[attr-defined]
        r = ac.run_idor_check("http://127.0.0.1/a", "http://127.0.0.1/b",
                              account_a={"cookie": "a"}, account_b={"cookie": "b"}, scope="127.0.0.1", settings=s)
        self.assertFalse(r["ok"])
        self.assertIn("guard", r["error"].lower())

    def test_norm_truncation_means_bodies_identical_only_within_the_cap_are_indistinguishable(self) -> None:
        # PINS a real, intentional (performance-bounding) limitation: _norm caps body
        # comparison at 6000 chars, so two bodies that are byte-identical for the first
        # 6000 chars but DIVERGE only after that are treated as IDENTICAL (ratio 1.0).
        head = "x" * 6000
        a = head + "AAAA_TAIL_DIFFERS_FOR_A"
        b = head + "BBBB_TAIL_DIFFERS_FOR_B_AND_IS_A_DIFFERENT_LENGTH_TOO"
        self.assertEqual(ac._norm(a), ac._norm(b))  # both truncate to the identical head
        self.assertEqual(ac._ratio(a, b), 1.0)       # so the differential sees them as the same object


class IdorProbeTwoIdTests(unittest.TestCase):
    """run_idor_probe's docstring advertises mutating "a URL carrying TWO ids" -- only
    single-id cases had a test before."""

    def test_url_with_two_path_ids_tries_both_positions(self) -> None:
        # /order/<id>/item/<id> -- both numeric segments are candidate mutation points.
        # run_idor_probe returns on the FIRST candidate match, so to prove the SECOND
        # position is genuinely reached (not just present in `positions`), the first
        # id's neighbours must be denied/enforced -- only the second id's neighbour
        # yields the distinct-valid-object signal that ends the search.
        seen_mutations: list[str] = []

        def by_url(url):
            seen_mutations.append(url)
            if "/order/1001/item/55" in url:
                return (200, _CHROME + "<p>" + _OBJECTS["1001"] + "</p></div></body></html>")
            if "/order/1002/item/55" in url or "/order/1000/item/55" in url:
                return (403, "<html>Forbidden</html>")  # order-id neighbours: enforced
            if "/order/1001/item/56" in url or "/order/1001/item/54" in url:
                return (200, _CHROME + "<p>" + _OBJECTS["1002"] + "</p></div></body></html>")  # item-id: distinct object
            return (404, "not found")

        res = _run_probe(by_url, "http://127.0.0.1/api/order/1001/item/55")
        self.assertEqual(res["status"], "candidate")
        # Both id positions were genuinely tried -- the search did not stop after the
        # first (enforced) position; it continued to the second and found the signal there.
        self.assertTrue(any("/order/1002/item/55" in u or "/order/1000/item/55" in u for u in seen_mutations))
        self.assertTrue(any("/order/1001/item/56" in u or "/order/1001/item/54" in u for u in seen_mutations))

    def test_digit_count_changing_mutation_targets_the_correct_url(self) -> None:
        # 9 -> 10 grows the id from 1 to 2 digits, shifting every later path offset.
        # _mutate_id must still build a correctly-formed URL (it always mutates the
        # ORIGINAL su, never a previously-mutated string, so offsets stay valid).
        seen_mutations: list[str] = []

        def by_url(url):
            seen_mutations.append(url)
            if url.rstrip("/").endswith("/order/9"):
                return (200, _CHROME + "<p>" + _OBJECTS["1001"] + "</p></div></body></html>")
            return (200, _CHROME + "<p>" + _OBJECTS["1002"] + "</p></div></body></html>")

        res = _run_probe(by_url, "http://127.0.0.1/api/order/9")
        self.assertEqual(res["status"], "candidate")
        self.assertIn("http://127.0.0.1/api/order/10", seen_mutations)  # the 2-digit neighbour, well-formed


if __name__ == "__main__":
    unittest.main()
