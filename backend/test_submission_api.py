"""Tests for the after-testing / submission API: canonical package build, the
hard-gated HackerOne submit (no network), and the creds store (token never echoed)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402


def _run_result() -> dict:
    return {
        "ok": True,
        "findings": [
            {"ref": "F1", "title": "Reflected XSS", "severity": "high", "class_id": "xss",
             "class_name": "Cross-site scripting", "cwe": "CWE-79", "location": "https://app.example.com/?q=",
             "rule_id": "active.reflected-xss"},
            {"ref": "F2", "title": "Missing header", "severity": "low", "class_id": "headers",
             "class_name": "Headers", "cwe": "CWE-693", "location": "https://app.example.com/",
             "rule_id": "web.missing-header.csp"},
        ],
        "attack_plans": {
            "F1": {"steps": ["Send GET with marker payload", "Observe unescaped reflection"],
                   "impact": "Run script in the victim session",
                   "proof_of_impact": {"status": "confirmed", "observed_result": "payload reflected unescaped",
                                       "control_result": "plain marker reflected too", "evidence": "raw <svg/onload>"},
                   "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "base_score": 6.1, "base_severity": "medium"}},
            "F2": {"steps": ["curl -I"], "impact": "minor", "proof_of_impact": {"status": "missing"}},
        },
    }


class SubmissionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        # Isolate the secrets store so the test never reads/writes the real one.
        self._orig_secrets = g.SECRETS_PATH
        g.SECRETS_PATH = Path(self._tmp.name) / "secrets.json"
        result = _run_result()
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="app.example.com", program="acme")
        self.run_id = result["run_id"]

    def tearDown(self) -> None:
        g.SECRETS_PATH = self._orig_secrets
        self._tmp.cleanup()

    def test_canonical_package_built_for_confirmed(self) -> None:
        res = self.rt.build_submission_package(g.SubmissionPackageRequest(run_id=self.run_id, ref="F1"))
        self.assertTrue(res["ok"])
        pkg = res["package"]
        self.assertEqual(pkg["proof_status"], "confirmed")
        self.assertEqual(pkg["severity_rating"], "medium")  # from CVSS base_severity
        self.assertEqual(pkg["weakness"], "79")
        self.assertIn("Steps", pkg["vulnerability_information"])  # canonical build_finding_markdown

    def test_unknown_run_or_ref_errors_gracefully(self) -> None:
        self.assertFalse(self.rt.build_submission_package(g.SubmissionPackageRequest(run_id="nope", ref="F1"))["ok"])
        self.assertFalse(self.rt.build_submission_package(g.SubmissionPackageRequest(run_id=self.run_id, ref="ZZ"))["ok"])

    def test_submit_gate_is_server_authoritative(self) -> None:
        # No creds -> refuse.
        self.assertIn("refused", self.rt.submit_finding(g.SubmitRequest(run_id=self.run_id, ref="F1", confirm=True))["error"])
        # Add creds, then: a MISSING-proof finding must still refuse (proof recomputed server-side),
        # and confirm=False must refuse — the client can't bypass either gate.
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_username="me@x.com", api_token="TOK"))
        self.assertIn("CONFIRMED", self.rt.submit_finding(g.SubmitRequest(run_id=self.run_id, ref="F2", confirm=True))["error"])
        self.assertIn("confirmation", self.rt.submit_finding(g.SubmitRequest(run_id=self.run_id, ref="F1", confirm=False))["error"])

    def test_non_hackerone_platform_refused(self) -> None:
        res = self.rt.submit_finding(g.SubmitRequest(run_id=self.run_id, ref="F1", confirm=True, platform="bugcrowd"))
        self.assertFalse(res["ok"])
        self.assertIn("Only the HackerOne", res["error"])

    def test_creds_status_never_leaks_token(self) -> None:
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_username="me@x.com", api_token="SUPERSECRET"))
        status = self.rt.hackerone_creds_status()
        self.assertEqual(status["team_handle"], "acme")
        self.assertTrue(status["has_token"])
        self.assertNotIn("SUPERSECRET", str(status))

    def test_run_cache_is_bounded(self) -> None:
        for _ in range(20):
            r = _run_result()
            self.rt._cache_bounty_run(r, target="https://t", scope="t", program=None)
        self.assertLessEqual(len(self.rt.bounty_runs), 16)


if __name__ == "__main__":
    unittest.main()
