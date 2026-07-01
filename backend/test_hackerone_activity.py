"""Tests for hackerone_activity (HackerOne hacker-activity API: hacktivity, own reports,
report status, earnings, balance).

All network is injected via ``fetch`` — never a real socket, matching
test_hackerone_import.py's pattern. This module reuses hackerone_import's host-pinned
``_fetch_json`` directly rather than reimplementing it, so the host-pinning /
no-redirect guard itself is only tested once, in test_hackerone_import.py.
"""
from __future__ import annotations

import sys
import unittest
import urllib.error
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hackerone_activity as h1a  # noqa: E402


def _http_error(code: int, reason: str = "error") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url="https://api.hackerone.com/v1/hackers/x", code=code, msg=reason, hdrs=None, fp=None)


class MissingCredsTests(unittest.TestCase):
    def test_hacktivity_requires_handle(self) -> None:
        r = h1a.fetch_hacktivity("", "user", "token")
        self.assertFalse(r["ok"])
        self.assertIn("handle", r["error"].lower())

    def test_hacktivity_requires_creds(self) -> None:
        r = h1a.fetch_hacktivity("acme", "", "")
        self.assertFalse(r["ok"])
        self.assertIn("api username", r["error"].lower())

    def test_my_reports_requires_creds(self) -> None:
        r = h1a.fetch_my_reports("", "")
        self.assertFalse(r["ok"])

    def test_report_status_requires_creds(self) -> None:
        r = h1a.fetch_report_status("123", "", "")
        self.assertFalse(r["ok"])

    def test_earnings_requires_creds(self) -> None:
        r = h1a.fetch_earnings("", "")
        self.assertFalse(r["ok"])

    def test_balance_requires_creds(self) -> None:
        r = h1a.fetch_balance("", "")
        self.assertFalse(r["ok"])

    def test_report_status_requires_numeric_id(self) -> None:
        calls = []
        r = h1a.fetch_report_status("not-a-number", "user", "token", fetch=lambda *a, **k: calls.append(1))
        self.assertFalse(r["ok"])
        self.assertIn("numeric", r["error"].lower())
        self.assertEqual(calls, [])  # never even attempted the network call


class HacktivityTests(unittest.TestCase):
    def test_success_shape_and_query(self) -> None:
        seen = {}

        def fake_fetch(url, **kw):
            seen["url"] = url
            return {"data": [{"attributes": {
                "title": "Reflected XSS", "severity_rating": "high", "cwe": "CWE-79",
                "total_awarded_amount": 500, "disclosed_at": "2026-01-01T00:00:00Z", "substate": "resolved",
            }}]}

        r = h1a.fetch_hacktivity("acme", "user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["items"]), 1)
        item = r["items"][0]
        self.assertEqual(item["title"], "Reflected XSS")
        self.assertEqual(item["severity_rating"], "high")
        self.assertEqual(item["total_awarded_amount"], 500)
        self.assertEqual(item["program_handle"], "acme")
        self.assertIn("hacktivity", seen["url"])
        self.assertIn("team%3Aacme", seen["url"])  # queryString=team:acme, urlencoded

    def test_no_items_is_ok_with_empty_list(self) -> None:
        r = h1a.fetch_hacktivity("acme", "user", "token", fetch=lambda url, **k: {"data": []})
        self.assertTrue(r["ok"])
        self.assertEqual(r["items"], [])

    def test_403_degrades_with_hacktivity_wording(self) -> None:
        r = h1a.fetch_hacktivity("acme", "user", "token", fetch=lambda url, **k: (_ for _ in ()).throw(_http_error(403)))
        self.assertFalse(r["ok"])
        self.assertIn("hacktivity", r["error"].lower())


class MyReportsTests(unittest.TestCase):
    def test_success_shape(self) -> None:
        def fake_fetch(url, **kw):
            return {"data": [
                {"id": "42", "attributes": {"title": "SSRF via webhook", "state": "triaged",
                                            "bounty_awarded_at": None, "swag_awarded_at": None,
                                            "last_activity_at": "2026-01-02T00:00:00Z"}},
            ]}

        r = h1a.fetch_my_reports("user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertEqual(r["items"][0]["id"], "42")
        self.assertEqual(r["items"][0]["state"], "triaged")

    def test_401_bad_token(self) -> None:
        r = h1a.fetch_my_reports("user", "badtoken", fetch=lambda url, **k: (_ for _ in ()).throw(_http_error(401)))
        self.assertFalse(r["ok"])
        self.assertIn("401", r["error"])


class ReportStatusTests(unittest.TestCase):
    def test_success_shape(self) -> None:
        seen = {}

        def fake_fetch(url, **kw):
            seen["url"] = url
            return {"data": {"id": "129329", "attributes": {
                "state": "resolved", "title": "Blind SSRF", "bounty_awarded_at": "2026-01-03T00:00:00Z",
                "swag_awarded_at": None, "last_activity_at": "2026-01-03T00:00:00Z",
            }}}

        r = h1a.fetch_report_status("129329", "user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertEqual(r["state"], "resolved")
        self.assertEqual(r["title"], "Blind SSRF")
        self.assertTrue(r["bounty_awarded_at"])
        self.assertTrue(seen["url"].endswith("/reports/129329"))

    def test_404_unknown_report(self) -> None:
        r = h1a.fetch_report_status("999", "user", "token", fetch=lambda url, **k: (_ for _ in ()).throw(_http_error(404)))
        self.assertFalse(r["ok"])
        self.assertIn("report", r["error"].lower())
        self.assertIn("404", r["error"])


class EarningsAndBalanceTests(unittest.TestCase):
    def test_earnings_reads_type_from_attributes(self) -> None:
        def fake_fetch(url, **kw):
            return {"data": [{"id": "1", "attributes": {"type": "earning-bounty-earned", "amount": 500, "created_at": "2026-01-01T00:00:00Z"}}]}

        r = h1a.fetch_earnings("user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertEqual(r["items"][0]["type"], "earning-bounty-earned")
        self.assertEqual(r["items"][0]["amount"], 500)

    def test_earnings_falls_back_to_json_api_resource_type(self) -> None:
        # If HackerOne's JSON:API resource type carries the category instead of a
        # dedicated attribute, the extraction must still find it rather than KeyError.
        def fake_fetch(url, **kw):
            return {"data": [{"id": "1", "type": "earning-bounty-earned", "attributes": {"amount": 500, "created_at": "2026-01-01T00:00:00Z"}}]}

        r = h1a.fetch_earnings("user", "token", fetch=fake_fetch)
        self.assertTrue(r["ok"])
        self.assertEqual(r["items"][0]["type"], "earning-bounty-earned")

    def test_balance_passes_through_raw_attributes(self) -> None:
        r = h1a.fetch_balance("user", "token", fetch=lambda url, **k: {"data": {"attributes": {"amount": 42, "currency": "usd"}}})
        self.assertTrue(r["ok"])
        self.assertEqual(r["balance"], {"amount": 42, "currency": "usd"})

    def test_network_error(self) -> None:
        import urllib.error as ue

        r = h1a.fetch_earnings("user", "token", fetch=lambda url, **k: (_ for _ in ()).throw(ue.URLError("no route to host")))
        self.assertFalse(r["ok"])
        self.assertIn("could not reach", r["error"].lower())


if __name__ == "__main__":
    unittest.main()
