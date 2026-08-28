"""Tests for the passive multi-source OSINT campaign engine."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import osint  # noqa: E402


def _dns_doc(name: str, rtype: str, *, address: str = "8.8.8.8") -> dict:
    type_id = {"A": 1, "AAAA": 28, "NS": 2, "MX": 15}[rtype]
    values = {
        "A": address,
        "AAAA": "2001:4860:4860::8888",
        "NS": "ns1.example.net.",
        "MX": "10 mail.example.com.",
    }
    return {"Status": 0, "Answer": [{"name": name + ".", "type": type_id, "TTL": 60, "data": values[rtype]}]}


class FakeProviders:
    def __init__(self, *, fail_cloudflare: bool = False) -> None:
        self.fail_cloudflare = fail_cloudflare
        self.urls: list[str] = []

    def __call__(self, url: str, **_kwargs):
        self.urls.append(url)
        host = urllib.parse.urlsplit(url).hostname
        if host == "crt.sh":
            return [{"name_value": "example.com\napi.example.com\nlegacy.example.com\n*.example.com\nevil.test"}]
        if host == "api.certspotter.com":
            return [{"dns_names": ["example.com", "api.example.com", "shop.example.com", "outside.test"]}]
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        name = params["name"][0]
        rtype = params["type"][0]
        if self.fail_cloudflare and host == "cloudflare-dns.com":
            raise urllib.error.URLError("resolver unavailable")
        if name == "legacy.example.com":
            return {"Status": 3}
        if name == "shop.example.com" and host == "cloudflare-dns.com":
            return {"Status": 3}
        return _dns_doc(name, rtype)


class OsintEngineTests(unittest.TestCase):
    def test_domain_normalization_is_strict(self) -> None:
        self.assertEqual(osint.normalize_domain("https://API.Example.com/path"), "api.example.com")
        self.assertEqual(osint.normalize_domain("bücher.example"), "xn--bcher-kva.example")
        for bad in ("", "localhost", "127.0.0.1", "*.example.com", "herokuapp.com", "example.com/path",
                    "ftp://example.com", "https://user:pass@example.com"):
            with self.subTest(bad=bad), self.assertRaises(osint.OsintInputError):
                osint.normalize_domain(bad)

    def test_two_source_agreement_promotes_only_current_dns_assets(self) -> None:
        fake = FakeProviders()
        with tempfile.TemporaryDirectory() as tmp:
            result = osint.run_campaign(
                "example.com", output_dir=tmp, max_hosts=4, fetch_json=fake,
                now="2026-08-28T12:00:00+00:00",
            )
            saved = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
            report = Path(result["report_path"]).read_text(encoding="utf-8")

        self.assertEqual(result["status"], "complete")
        self.assertEqual(saved["campaign_id"], result["campaign_id"])
        self.assertIn("Exact agreement from two independent providers", report)
        by_host = {row["hostname"]: row for row in result["assets"]}
        self.assertEqual(by_host["example.com"]["state"], "dns-verified")
        self.assertTrue(by_host["api.example.com"]["hunt_eligible"])
        self.assertFalse(by_host["shop.example.com"]["hunt_eligible"])
        self.assertEqual(by_host["legacy.example.com"]["state"], "historical-only")
        self.assertEqual(
            set(result["hunt_targets"]),
            {"https://example.com/", "https://api.example.com/"},
        )
        api_ct = next(c for c in result["claims"] if c["kind"] == "ct-hostname" and c["subject"] == "api.example.com")
        legacy_ct = next(c for c in result["claims"] if c["kind"] == "ct-hostname" and c["subject"] == "legacy.example.com")
        self.assertEqual(api_ct["status"], "verified")
        self.assertEqual(legacy_ct["status"], "historical")
        self.assertEqual(len(api_ct["source_ids"]), 2)

    def test_provider_failure_is_partial_and_never_false_verifies_dns(self) -> None:
        fake = FakeProviders(fail_cloudflare=True)
        with tempfile.TemporaryDirectory() as tmp:
            result = osint.run_campaign("example.com", output_dir=tmp, max_hosts=2, fetch_json=fake)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["hunt_targets"], [])
        dns_claims = [claim for claim in result["claims"] if claim["kind"].startswith("dns-")]
        self.assertTrue(dns_claims)
        self.assertTrue(all(claim["status"] == "observed" for claim in dns_claims))
        self.assertTrue(any("no missing answer was treated as a fact" in note for note in result["notes"]))

    def test_total_provider_outage_is_failed_not_partial(self) -> None:
        def offline(*_args, **_kwargs):
            raise urllib.error.URLError("offline")

        with tempfile.TemporaryDirectory() as tmp:
            result = osint.run_campaign("example.com", output_dir=tmp, max_hosts=1, fetch_json=offline)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["summary"]["providers_ok"], 0)
            self.assertEqual(result["hunt_targets"], [])
            self.assertTrue(Path(result["report_path"]).is_file())

    def test_private_dns_answers_are_withheld(self) -> None:
        class PrivateProviders(FakeProviders):
            def __call__(self, url: str, **kwargs):
                doc = super().__call__(url, **kwargs)
                params = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                if params.get("type") == ["A"] and isinstance(doc, dict) and doc.get("Answer"):
                    doc["Answer"][0]["data"] = "127.0.0.1"
                return doc

        with tempfile.TemporaryDirectory() as tmp:
            result = osint.run_campaign("example.com", output_dir=tmp, max_hosts=1,
                                        fetch_json=PrivateProviders())
        self.assertEqual(result["hunt_targets"], [])
        self.assertEqual(result["assets"][0]["blocked_addresses"], ["127.0.0.1"])
        self.assertTrue(any("Private/reserved" in note for note in result["notes"]))

    def test_provider_fetch_rejects_unapproved_hosts_before_network(self) -> None:
        with self.assertRaises(ValueError):
            osint._fetch_json("https://example.com/not-a-provider")


if __name__ == "__main__":
    unittest.main()
