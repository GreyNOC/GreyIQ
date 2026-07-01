"""Tests for hackerone_import (HackerOne program/structured-scope read-only fetch).

All network is injected via ``fetch`` — never a real socket. Covers success, pagination
(``links.next``), and the 401/403/404 graceful-degrade messages the Program tab surfaces.
"""
from __future__ import annotations

import sys
import unittest
import urllib.error
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hackerone_import as h1  # noqa: E402


def _http_error(code: int, reason: str = "error") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url="https://api.hackerone.com/v1/hackers/x", code=code, msg=reason, hdrs=None, fp=None)


class MissingCredsTests(unittest.TestCase):
    def test_empty_handle_refused(self) -> None:
        r = h1.fetch_structured_scope("", "user", "token")
        self.assertFalse(r["ok"])
        self.assertIn("handle", r["error"].lower())

    def test_missing_creds_refused(self) -> None:
        r = h1.fetch_structured_scope("acme", "", "")
        self.assertFalse(r["ok"])
        self.assertIn("api username", r["error"].lower())


class FetchSuccessTests(unittest.TestCase):
    def test_single_page(self) -> None:
        calls = []

        def fake_fetch(url, **kw):
            calls.append(url)
            if url.endswith("/programs/acme"):
                return {"data": {"attributes": {"name": "Acme Corp", "policy": "Be nice.", "offers_bounties": True}}}
            return {
                "data": [
                    {"attributes": {"asset_identifier": "*.acme.com", "asset_type": "URL",
                                     "eligible_for_submission": True, "eligible_for_bounty": True,
                                     "instruction": "Web app", "max_severity": "critical"}},
                    {"attributes": {"asset_identifier": "legacy.acme.com", "asset_type": "URL",
                                     "eligible_for_submission": False, "eligible_for_bounty": False}},
                    {"attributes": {"asset_identifier": ""}},  # no identifier -> dropped
                ],
                "links": {},
            }

        r = h1.fetch_structured_scope("acme", "user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertEqual(r["program_name"], "Acme Corp")
        self.assertTrue(r["offers_bounty"])
        self.assertEqual(len(r["structured_scope"]), 2)
        self.assertEqual(r["structured_scope"][0]["identifier"], "*.acme.com")
        self.assertTrue(r["structured_scope"][0]["eligible_for_bounty"])
        self.assertFalse(r["structured_scope"][1]["eligible_for_submission"])
        self.assertEqual(calls[0], f"{h1._API_BASE}/programs/acme")

    def test_pagination_follows_links_next(self) -> None:
        # links.next is a full absolute URL in HackerOne's real (JSON:API-style) pagination
        # — never a bare relative token — so the fixture must reflect that.
        page2_url = f"{h1._API_BASE}/programs/acme/structured_scopes?page%5Bnumber%5D=2"
        pages = {
            "page1": {"data": [{"attributes": {"asset_identifier": "a.acme.com"}}], "links": {"next": page2_url}},
            "page2": {"data": [{"attributes": {"asset_identifier": "b.acme.com"}}], "links": {}},
        }

        def fake_fetch(url, **kw):
            if url.endswith("/programs/acme"):
                return {"data": {"attributes": {"name": "Acme"}}}
            if url == f"{h1._API_BASE}/programs/acme/structured_scopes":
                return pages["page1"]
            if url == page2_url:
                return pages["page2"]
            raise AssertionError(f"unexpected url {url!r}")

        r = h1.fetch_structured_scope("acme", "user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        identifiers = [e["identifier"] for e in r["structured_scope"]]
        self.assertEqual(identifiers, ["a.acme.com", "b.acme.com"])

    def test_no_scope_entries_warns(self) -> None:
        def fake_fetch(url, **kw):
            if url.endswith("/programs/acme"):
                return {"data": {"attributes": {"name": "Acme"}}}
            return {"data": [], "links": {}}

        r = h1.fetch_structured_scope("acme", "user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertEqual(r["structured_scope"], [])
        self.assertTrue(any("no structured scope" in w.lower() for w in r["warnings"]))


class DegradeTests(unittest.TestCase):
    def test_401_bad_token(self) -> None:
        def fake_fetch(url, **kw):
            raise _http_error(401)

        r = h1.fetch_structured_scope("acme", "user", "badtoken", fetch=fake_fetch)
        self.assertFalse(r["ok"])
        self.assertIn("401", r["error"])
        self.assertIn("token", r["error"].lower())

    def test_403_on_program_lookup_degrades_with_csv_hint(self) -> None:
        def fake_fetch(url, **kw):
            raise _http_error(403)

        r = h1.fetch_structured_scope("private-program", "user", "token", fetch=fake_fetch)
        self.assertFalse(r["ok"])
        self.assertIn("csv", r["error"].lower())

    def test_404_unknown_handle(self) -> None:
        def fake_fetch(url, **kw):
            raise _http_error(404)

        r = h1.fetch_structured_scope("no-such-program", "user", "token", fetch=fake_fetch)
        self.assertFalse(r["ok"])
        self.assertIn("csv", r["error"].lower())

    def test_scope_fetch_403_after_program_ok_keeps_program_info_as_warning(self) -> None:
        def fake_fetch(url, **kw):
            if url.endswith("/programs/acme"):
                return {"data": {"attributes": {"name": "Acme"}}}
            raise _http_error(403)

        r = h1.fetch_structured_scope("acme", "user", "token", fetch=fake_fetch)
        # Program metadata succeeded but scope is inaccessible -> ok with a warning, not a hard error
        # (no entries were ever gathered, so this degrades the whole call per the "not entries" branch).
        self.assertFalse(r["ok"])
        self.assertIn("csv", r["error"].lower())

    def test_network_error(self) -> None:
        import urllib.error as ue

        def fake_fetch(url, **kw):
            raise ue.URLError("no route to host")

        r = h1.fetch_structured_scope("acme", "user", "token", fetch=fake_fetch)
        self.assertFalse(r["ok"])
        self.assertIn("could not reach", r["error"].lower())


class PaginationHostPinningTests(unittest.TestCase):
    """A malicious/compromised HackerOne response must never redirect the Basic-auth
    credentialed request to another host via links.next (SSRF / credential exfiltration)."""

    def test_malicious_links_next_is_refused_not_followed(self) -> None:
        calls = []

        def fake_fetch(url, **kw):
            calls.append(url)
            if url.endswith("/programs/acme"):
                return {"data": {"attributes": {"name": "Acme"}}}
            if url == f"{h1._API_BASE}/programs/acme/structured_scopes":
                return {
                    "data": [{"attributes": {"asset_identifier": "a.acme.com"}}],
                    "links": {"next": "https://evil.attacker.example/steal?creds=1"},
                }
            raise AssertionError(f"must never be called with {url!r}")

        r = h1.fetch_structured_scope("acme", "user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertEqual([e["identifier"] for e in r["structured_scope"]], ["a.acme.com"])
        self.assertNotIn("https://evil.attacker.example/steal?creds=1", calls)
        self.assertTrue(any("outside the api host" in w.lower() for w in r["warnings"]))

    def test_links_next_on_http_scheme_is_also_refused(self) -> None:
        def fake_fetch(url, **kw):
            if url.endswith("/programs/acme"):
                return {"data": {"attributes": {"name": "Acme"}}}
            return {"data": [], "links": {"next": "http://api.hackerone.com/v1/hackers/programs/acme/structured_scopes?page=2"}}

        r = h1.fetch_structured_scope("acme", "user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertTrue(any("outside the api host" in w.lower() for w in r["warnings"]))

    def test_is_hackerone_url_accepts_only_the_real_host(self) -> None:
        self.assertTrue(h1._is_hackerone_url("https://api.hackerone.com/v1/hackers/programs/acme"))
        self.assertFalse(h1._is_hackerone_url("http://api.hackerone.com/v1/hackers/programs/acme"))  # not https
        self.assertFalse(h1._is_hackerone_url("https://evil.example/v1/hackers/programs/acme"))
        self.assertFalse(h1._is_hackerone_url("https://api.hackerone.com.evil.example/x"))  # lookalike host

    def test_fetch_json_refuses_a_non_hackerone_url(self) -> None:
        with self.assertRaises(ValueError):
            h1._fetch_json("https://evil.example/steal", api_username="u", api_token="t", timeout=5.0)

    def test_no_redirect_handler_never_follows(self) -> None:
        handler = h1._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/steal"))


if __name__ == "__main__":
    unittest.main()
