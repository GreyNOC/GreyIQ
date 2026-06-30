"""Tests for subdomain enumeration + takeover confirmation.

No network: the guarded fetch + DNS resolver are stubbed. A dangling-service fingerprint
confirms a takeover; a normal page never does; out-of-scope hosts are never touched.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import takeover_service as ts  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


def _stub_fetch(bodies):
    """bodies: dict host -> (status, body). Patches _guard_url (no DNS) + _fetch_raw."""
    def guard(url, *a, **k):
        return url
    def fetch(url):
        host = urlparse(url).hostname or ""
        if host not in bodies:
            raise ts.WebsiteFetchError("unreachable")
        status, body = bodies[host]
        return {"status": status, "body": body, "headers": {}, "cookies": []}
    return guard, fetch


class FingerprintTests(unittest.TestCase):
    def setUp(self) -> None:
        self._g, self._f = ts._guard_url, ts._fetch_raw

    def tearDown(self) -> None:
        ts._guard_url, ts._fetch_raw = self._g, self._f

    def test_github_pages_takeover_confirms(self) -> None:
        ts._guard_url, ts._fetch_raw = _stub_fetch({
            "ghost.example.com": (404, "<html>There isn't a GitHub Pages site here.</html>")})
        f = ts.check_host_takeover("ghost.example.com")
        self.assertIsNotNone(f)
        self.assertEqual(f["class_id"], "subdomain-takeover")
        self.assertEqual(f["_takeover_service"], "GitHub Pages")
        self.assertEqual(f["severity"], "high")

    def test_normal_page_is_not_a_takeover(self) -> None:
        ts._guard_url, ts._fetch_raw = _stub_fetch({
            "www.example.com": (200, "<html>Welcome to Example, your trusted shop.</html>")})
        self.assertIsNone(ts.check_host_takeover("www.example.com"))

    def test_plain_404_is_not_a_takeover(self) -> None:
        ts._guard_url, ts._fetch_raw = _stub_fetch({
            "x.example.com": (404, "<html><h1>404 Not Found</h1>The page was not found.</html>")})
        self.assertIsNone(ts.check_host_takeover("x.example.com"))

    def test_200_page_quoting_a_fingerprint_is_not_a_takeover(self) -> None:
        # A normal 200 page (status dashboard / blog / aggregator) that merely QUOTES the
        # unclaimed-service text must NOT confirm — a dangling service serves a 4xx/5xx.
        ts._guard_url, ts._fetch_raw = _stub_fetch({
            "status.example.com": (200, "<html>Past incident: 'Fastly error: unknown domain' on our CDN. Resolved.</html>")})
        self.assertIsNone(ts.check_host_takeover("status.example.com"))


class ScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._g, self._f = ts._guard_url, ts._fetch_raw

    def tearDown(self) -> None:
        ts._guard_url, ts._fetch_raw = self._g, self._f

    def test_scan_finds_takeover_among_resolved_in_scope_hosts(self) -> None:
        ts._guard_url, ts._fetch_raw = _stub_fetch({
            "dangling.example.com": (404, "<html>Fastly error: unknown domain dangling.example.com</html>"),
            "www.example.com": (200, "<html>normal site</html>"),
        })
        resolve = {"dangling.example.com", "www.example.com"}
        res = ts.scan_subdomain_takeover(
            "https://example.com/", scope="example.com", settings=get_settings(),
            extra_hosts=["dangling.example.com", "evil.other.com"],
            resolver=lambda h: h in resolve, include_ct=False,
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["apex"], "example.com")
        self.assertEqual(sorted(res["resolved"]), ["dangling.example.com", "www.example.com"])
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["_takeover_service"], "Fastly")

    def test_out_of_scope_host_never_checked(self) -> None:
        # evil.other.com resolves but is out of scope -> never fetched / never a finding.
        touched: list[str] = []
        def guard(url, *a, **k):
            touched.append(urlparse(url).hostname or ""); return url
        def fetch(url):
            return {"status": 404, "body": "Fastly error: unknown domain", "headers": {}, "cookies": []}
        ts._guard_url, ts._fetch_raw = guard, fetch
        res = ts.scan_subdomain_takeover(
            "example.com", scope="example.com", settings=get_settings(),
            extra_hosts=["evil.other.com"], resolver=lambda h: True, include_ct=False,
        )
        self.assertNotIn("evil.other.com", touched)
        self.assertTrue(all(h.endswith("example.com") for h in touched))

    def test_wildcard_dns_skips_wordlist_expansion(self) -> None:
        # Everything resolves (a wildcard A/CNAME) -> don't expand the wordlist (every label
        # would hit the same catch-all); rely on apex + recon-discovered hosts only.
        ts._guard_url, ts._fetch_raw = _stub_fetch({})  # no host matches a fingerprint
        res = ts.scan_subdomain_takeover("example.com", scope="example.com", settings=get_settings(),
                                         extra_hosts=["api.example.com"], resolver=lambda h: True, include_ct=False)
        self.assertTrue(res["ok"])
        self.assertNotIn("www.example.com", res["resolved"])  # wordlist NOT expanded under wildcard
        self.assertIn("example.com", res["resolved"])

    def test_bad_target_errors(self) -> None:
        self.assertFalse(ts.scan_subdomain_takeover("not-a-domain", scope="x")["ok"])


class CertTransparencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._g, self._f = ts._guard_url, ts._fetch_raw

    def tearDown(self) -> None:
        ts._guard_url, ts._fetch_raw = self._g, self._f

    _CRT_JSON = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "dangling.example.com"},
        {"name_value": "mail.example.com\nmail.example.com"},   # duplicate
        {"name_value": "evil.other.com"},                        # different apex -> excluded
        {"name_value": "example.com"},                           # the apex itself
    ]

    def test_parses_dedupes_and_filters_to_apex(self) -> None:
        names = ts.cert_transparency_subdomains("example.com", fetch_json=lambda url, **k: self._CRT_JSON)
        self.assertEqual(names, ["dangling.example.com", "example.com", "mail.example.com", "www.example.com"])
        self.assertNotIn("evil.other.com", names)   # other apex dropped
        self.assertNotIn("*.example.com", names)     # wildcard stripped

    def test_query_targets_the_apex(self) -> None:
        seen = {}
        ts.cert_transparency_subdomains("example.com", fetch_json=lambda url, **k: seen.update(url=url) or [])
        self.assertIn("crt.sh", seen["url"])
        self.assertIn("example.com", seen["url"])

    def test_failure_returns_empty(self) -> None:
        def boom(url, **k):
            raise OSError("crt.sh down")
        self.assertEqual(ts.cert_transparency_subdomains("example.com", fetch_json=boom), [])
        self.assertEqual(ts.cert_transparency_subdomains("not-a-domain"), [])  # no network

    def test_scan_seeds_candidates_from_ct(self) -> None:
        # A CT-discovered dangling host (not in the wordlist) is enumerated + confirmed.
        ts._guard_url, ts._fetch_raw = _stub_fetch({
            "legacy-cdn.example.com": (404, "<html>Fastly error: unknown domain</html>")})
        try:
            res = ts.scan_subdomain_takeover(
                "example.com", scope="example.com", settings=get_settings(),
                resolver=lambda h: h == "legacy-cdn.example.com",
                ct_fetch_json=lambda url, **k: [{"name_value": "legacy-cdn.example.com"}],
            )
        finally:
            ts._guard_url, ts._fetch_raw = self._g, self._f
        self.assertGreaterEqual(res["ct_count"], 1)
        self.assertIn("legacy-cdn.example.com", res["resolved"])
        self.assertEqual(len(res["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
