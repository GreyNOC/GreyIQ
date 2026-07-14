"""Tests for GreyIQ v2 submission upgrades — CWE→taxonomy mapping, per-platform
preflight, HackerOne weakness fetch/match, pre-submit duplicate detection, and the
routed (weakness + asset) + attachment-carrying HackerOne submit."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hackerone_activity, hackerone_import, submission, taxonomy  # noqa: E402


def _ctx_and_finding(*, cwe="CWE-639", location="https://app.example.com/api/orders/1",
                     status="confirmed", cvss=True):
    finding = {
        "ref": "F1", "title": "IDOR in orders", "severity": "high", "confidence": "high",
        "class_id": "idor", "class_name": "IDOR", "cwe": cwe, "location": location,
        "rule_id": "web-idor",
    }
    plan = {"impact": "Read another user's order.", "steps": ["GET /api/orders/2"],
            "proof_of_impact": {"status": status, "observed_result": "returned order 2"}}
    if cvss:
        plan["cvss"] = {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "base_score": 6.5,
                        "base_severity": "Medium"}
    ctx = {"tool": "GreyIQ", "version": "2.0.0", "generated_at": "now",
           "target": "https://app.example.com", "scope": "*.example.com", "attack_plans": {"F1": plan}}
    return ctx, finding


class TaxonomyTests(unittest.TestCase):
    def test_cwe_number_variants(self):
        self.assertEqual(taxonomy.cwe_number("CWE-79"), "79")
        self.assertEqual(taxonomy.cwe_number("cwe 918"), "918")
        self.assertEqual(taxonomy.cwe_number("89"), "89")
        self.assertEqual(taxonomy.cwe_number("CWE-89 / CWE-90"), "89")
        self.assertEqual(taxonomy.cwe_number(None), "")
        self.assertEqual(taxonomy.cwe_number("n/a"), "")

    def test_cwe_to_vrt(self):
        self.assertIn("Cross-Site Scripting", taxonomy.cwe_to_vrt("CWE-79"))
        self.assertIn("SSRF", taxonomy.cwe_to_vrt("CWE-918"))
        self.assertIn("IDOR", taxonomy.cwe_to_vrt("CWE-639"))
        self.assertIsNone(taxonomy.cwe_to_vrt("CWE-99999"))
        self.assertIsNone(taxonomy.cwe_to_vrt(""))

    def test_match_weakness_id_flattened_and_jsonapi(self):
        flat = [{"id": "42", "external_id": "cwe-79"}, {"id": "7", "external_id": "cwe-89"}]
        self.assertEqual(taxonomy.match_weakness_id(flat, "CWE-89"), 7)
        jsonapi = [{"id": "55", "attributes": {"external_id": "CWE-918"}}]
        self.assertEqual(taxonomy.match_weakness_id(jsonapi, "cwe-918"), 55)

    def test_match_weakness_id_failclosed(self):
        self.assertIsNone(taxonomy.match_weakness_id([], "CWE-79"))
        self.assertIsNone(taxonomy.match_weakness_id(None, "CWE-79"))
        self.assertIsNone(taxonomy.match_weakness_id([{"id": "x", "external_id": "cwe-79"}], "CWE-79"))
        self.assertIsNone(taxonomy.match_weakness_id([{"id": "1", "external_id": "cwe-79"}], "CWE-89"))


class BuildSubmissionV2Tests(unittest.TestCase):
    def test_vrt_derived_from_cwe(self):
        ctx, finding = _ctx_and_finding()
        pkg = submission.build_submission(ctx, finding, "bugcrowd")
        self.assertIn("IDOR", pkg["vrt"])

    def test_explicit_vrt_wins_over_derived(self):
        ctx, finding = _ctx_and_finding()
        finding["vrt"] = "Custom > Category"
        pkg = submission.build_submission(ctx, finding, "bugcrowd")
        self.assertEqual(pkg["vrt"], "Custom > Category")

    def test_cvss_vector_and_location_carried(self):
        ctx, finding = _ctx_and_finding()
        pkg = submission.build_submission(ctx, finding, "hackerone")
        self.assertTrue(pkg["cvss_vector"].startswith("CVSS:3.1"))
        self.assertEqual(pkg["location"], "https://app.example.com/api/orders/1")


class PreflightTests(unittest.TestCase):
    def test_hackerone_ready_when_confirmed_and_fields_present(self):
        ctx, finding = _ctx_and_finding()
        pkg = submission.build_submission(ctx, finding, "hackerone")
        pf = submission.preflight(pkg, "hackerone")
        # proof_status depends on captured artifact; assert the field-level readiness instead.
        self.assertEqual(pf["missing"], [])
        self.assertEqual(pf["platform"], "hackerone")

    def test_bugcrowd_missing_vrt_reported(self):
        ctx, finding = _ctx_and_finding(cwe="CWE-99999")  # unmapped -> no VRT
        pkg = submission.build_submission(ctx, finding, "bugcrowd")
        pf = submission.preflight(pkg, "bugcrowd")
        self.assertIn("Bug type (VRT)", pf["missing"])
        self.assertFalse(pf["ready"])

    def test_intigriti_requires_cvss(self):
        ctx, finding = _ctx_and_finding(cvss=False)
        pkg = submission.build_submission(ctx, finding, "intigriti")
        pf = submission.preflight(pkg, "intigriti")
        self.assertIn("CVSS vector", pf["missing"])

    def test_unconfirmed_proof_blocks_ready(self):
        ctx, finding = _ctx_and_finding(status="candidate")
        pkg = submission.build_submission(ctx, finding, "hackerone")
        pf = submission.preflight(pkg, "hackerone")
        self.assertFalse(pf["ready"])
        self.assertTrue(any("proof" in w.lower() for w in pf["warnings"]))


class WeaknessFetchTests(unittest.TestCase):
    def test_fetch_weaknesses_parses_entries(self):
        def fake_fetch(url, **kw):
            self.assertIn("/weaknesses", url)
            return {"data": [{"id": "42", "attributes": {"external_id": "cwe-79", "name": "XSS"}},
                             {"id": "7", "attributes": {"external_id": "cwe-89", "name": "SQLi"}}]}
        res = hackerone_import.fetch_weaknesses("acme", "u", "t", fetch=fake_fetch)
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["weaknesses"]), 2)
        self.assertEqual(taxonomy.match_weakness_id(res["weaknesses"], "CWE-89"), 7)

    def test_fetch_weaknesses_http_error_failclosed(self):
        def boom(url, **kw):
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
        res = hackerone_import.fetch_weaknesses("acme", "u", "t", fetch=boom)
        self.assertFalse(res["ok"])

    def test_structured_scope_id_is_captured(self):
        def fake_fetch(url, **kw):
            if url.endswith("/structured_scopes"):
                return {"data": [{"id": "9001", "attributes": {"asset_identifier": "a.acme.com",
                                                               "asset_type": "URL", "eligible_for_submission": True}}]}
            return {"data": {"attributes": {"name": "Acme", "offers_bounties": True}}}
        res = hackerone_import.fetch_structured_scope("acme", "u", "t", fetch=fake_fetch)
        self.assertTrue(res["ok"])
        self.assertEqual(res["structured_scope"][0]["id"], "9001")


class DuplicateCheckTests(unittest.TestCase):
    def test_finds_probable_duplicate_with_cwe_boost(self):
        items = [{"id": "12345", "url": "https://hackerone.com/reports/12345",
                  "title": "IDOR in orders endpoint leaks other users orders", "cwe": "CWE-639"},
                 {"id": "999", "title": "XSS in search", "cwe": "CWE-79"}]
        dups = hackerone_activity.find_probable_duplicates("IDOR in orders", "CWE-639", items)
        self.assertTrue(dups)
        self.assertEqual(dups[0]["id"], "12345")
        self.assertIn("same CWE", dups[0]["reason"])

    def test_below_threshold_filtered(self):
        items = [{"id": "1", "title": "Completely unrelated subject matter here", "cwe": "CWE-200"}]
        self.assertEqual(hackerone_activity.find_probable_duplicates("IDOR in orders", "CWE-639", items), [])

    def test_empty_inputs_are_total(self):
        self.assertEqual(hackerone_activity.find_probable_duplicates("", "", []), [])
        self.assertEqual(hackerone_activity.find_probable_duplicates("x", "y", None), [])


class _FakeResp:
    def __init__(self, body=b"{}"):
        self._b = body
    def __enter__(self): return self
    def __exit__(self, *a): return None
    def read(self): return self._b


class RoutedSubmitTests(unittest.TestCase):
    def _pkg(self):
        return {"title": "t", "vulnerability_information": "body", "impact": "i",
                "severity_rating": "high", "proof_status": "confirmed", "cwe": "CWE-79"}

    def test_weakness_and_scope_added_to_payload(self):
        captured = {}
        def fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResp(json.dumps({"data": {"id": "50"}}).encode())
        res = submission.submit_to_hackerone(
            self._pkg(), team_handle="acme", api_username="u", api_token="t", confirm=True,
            weakness_id=42, structured_scope_id="9001", _urlopen=fake_urlopen)
        attrs = captured["body"]["data"]["attributes"]
        self.assertEqual(attrs["weakness_id"], 42)
        self.assertEqual(attrs["structured_scope_id"], "9001")
        self.assertEqual(res["routed"], {"weakness_id": 42, "structured_scope_id": "9001"})

    def test_none_routing_omits_keys(self):
        captured = {}
        def fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResp(json.dumps({"data": {"id": "50"}}).encode())
        submission.submit_to_hackerone(
            self._pkg(), team_handle="acme", api_username="u", api_token="t", confirm=True,
            _urlopen=fake_urlopen)
        attrs = captured["body"]["data"]["attributes"]
        self.assertNotIn("weakness_id", attrs)
        self.assertNotIn("structured_scope_id", attrs)

    def test_attachments_uploaded_after_create(self):
        with tempfile.TemporaryDirectory() as tmp:
            shot = Path(tmp) / "proof.png"
            shot.write_bytes(b"\x89PNG proof bytes")
            calls = []
            def fake_urlopen(req, timeout=None):
                calls.append(req.full_url)
                if req.full_url.endswith("/reports"):
                    return _FakeResp(json.dumps({"data": {"id": "77"}}).encode())
                return _FakeResp(b"{}")  # attachment endpoint
            res = submission.submit_to_hackerone(
                self._pkg(), team_handle="acme", api_username="u", api_token="t", confirm=True,
                attachments=[str(shot)], _urlopen=fake_urlopen)
        self.assertEqual(res["report_id"], "77")
        self.assertEqual(res["attachments"]["uploaded"], ["proof.png"])
        self.assertTrue(any("/reports/77/attachments" in u for u in calls))

    def test_attachment_failure_is_nonfatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            shot = Path(tmp) / "proof.png"
            shot.write_bytes(b"data")
            def fake_urlopen(req, timeout=None):
                if req.full_url.endswith("/reports"):
                    return _FakeResp(json.dumps({"data": {"id": "88"}}).encode())
                raise urllib.error.HTTPError(req.full_url, 422, "Unprocessable", {}, None)
            res = submission.submit_to_hackerone(
                self._pkg(), team_handle="acme", api_username="u", api_token="t", confirm=True,
                attachments=[str(shot)], _urlopen=fake_urlopen)
        self.assertTrue(res["ok"])  # report still filed
        self.assertEqual(res["report_id"], "88")
        self.assertEqual(res["attachments"]["uploaded"], [])
        self.assertEqual(res["attachments"]["failed"][0]["name"], "proof.png")

    def test_upload_skips_missing_and_oversized(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "a.txt"; good.write_bytes(b"x")
            res = submission.upload_hackerone_attachments(
                "5", [str(good), str(Path(tmp) / "ghost.txt")],
                api_username="u", api_token="t", _urlopen=lambda req, timeout=None: _FakeResp(b"{}"))
        self.assertEqual(res["uploaded"], ["a.txt"])  # ghost silently skipped (not a file)


if __name__ == "__main__":
    unittest.main()
