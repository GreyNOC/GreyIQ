"""Tests for the after-testing / submission API: canonical package build, the
hard-gated HackerOne submit (no network), and the creds store (token never echoed)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402
from bughunter import ledger as bounty_ledger  # noqa: E402


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
        # Isolate the secrets store AND the runtime dir (ledger/learning stores live
        # there) so a successful-submit test never reads/writes the real ones.
        self._orig_secrets = g.SECRETS_PATH
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.SECRETS_PATH = Path(self._tmp.name) / "secrets.json"
        g.RUNTIME_DIR = Path(self._tmp.name)
        result = _run_result()
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="app.example.com", program="acme")
        self.run_id = result["run_id"]

    def tearDown(self) -> None:
        g.SECRETS_PATH = self._orig_secrets
        g.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def test_canonical_package_built_for_confirmed(self) -> None:
        res = self.rt.build_submission_package(g.SubmissionPackageRequest(run_id=self.run_id, ref="F1"))
        self.assertTrue(res["ok"])
        pkg = res["package"]
        self.assertEqual(pkg["proof_status"], "confirmed")
        self.assertEqual(pkg["severity_rating"], "medium")  # from CVSS base_severity
        self.assertEqual(pkg["weakness"], "79")
        self.assertIn("**Proof of Concept**", pkg["vulnerability_information"])
        self.assertIn("1. Send GET with marker payload", pkg["vulnerability_information"])

    def test_unknown_run_or_ref_errors_gracefully(self) -> None:
        self.assertFalse(self.rt.build_submission_package(g.SubmissionPackageRequest(run_id="nope", ref="F1"))["ok"])
        self.assertFalse(self.rt.build_submission_package(g.SubmissionPackageRequest(run_id=self.run_id, ref="ZZ"))["ok"])

    def test_source_api_key_test_writes_bundle_artifact_without_leaking_key(self) -> None:
        raw = "sk-proj-" + ("G" * 32)
        result = {
            "ok": True,
            "findings": [{
                "ref": "F1", "title": "OpenAI API key", "severity": "high", "class_id": "secrets",
                "class_name": "Secrets / exposed credentials", "cwe": "CWE-798", "location": "src/settings.py",
                "rule_id": "secret.openai-key", "secret_value": raw,
                "snippet": 'OPENAI_API_KEY = "[REDACTED_SECRET]"',
            }],
            "attack_plans": {"F1": {"steps": ["Inspect source"], "proof_of_impact": {"status": "candidate"}}},
        }
        self.rt._cache_bounty_run(result, target="src", scope="source", program="acme")
        old_get_full = g.bounty_credential_validation._get_full
        try:
            g.bounty_credential_validation._get_full = lambda url, extra_headers=None: (
                200, {}, '{"data":[{"id":"gpt-4o"}]}'
            )
            res = self.rt.test_source_credential(g.CredentialTestRequest(
                run_id=result["run_id"], ref="F1", authorized=True))
        finally:
            g.bounty_credential_validation._get_full = old_get_full

        self.assertTrue(res["ok"], res)
        self.assertEqual(res["status"], "confirmed")
        self.assertIn("gpt-4o", res["artifact_text"])
        self.assertNotIn(raw, json.dumps(res))
        self.assertTrue(Path(res["path"]).is_file())

        bundle = self.rt.export_bundle(g.BundleRequest(run_id=result["run_id"]))
        self.assertTrue(bundle["ok"], bundle)
        with zipfile.ZipFile(bundle["path"]) as zf:
            names = zf.namelist()
            txt_name = next(name for name in names if name.endswith("api-key-access.txt"))
            body = zf.read(txt_name).decode("utf-8")
        self.assertIn("API response returned by issuer", body)
        self.assertIn("gpt-4o", body)
        self.assertNotIn(raw, body)

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

    def test_api_credential_splits_identifier_and_token(self) -> None:
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_credential="my-ident:SECRETTOK"))
        _, username, token = self.rt._hackerone_creds()
        self.assertEqual(username, "my-ident")
        self.assertEqual(token, "SECRETTOK")

    def test_api_credential_splits_on_first_colon_only(self) -> None:
        # A token that itself contains a colon must not be truncated — partition on the
        # FIRST colon (the Basic-auth userinfo boundary), everything after is the token.
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_credential="ident:tok:en:more"))
        _, username, token = self.rt._hackerone_creds()
        self.assertEqual(username, "ident")
        self.assertEqual(token, "tok:en:more")

    def test_bare_token_credential_keeps_existing_identifier(self) -> None:
        # First save a full pair, then rotate with a bare token — the identifier must
        # survive (a token rotation shouldn't wipe a known-good username).
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_credential="keep-me:OLDTOK"))
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_credential="NEWTOK"))
        _, username, token = self.rt._hackerone_creds()
        self.assertEqual(username, "keep-me")
        self.assertEqual(token, "NEWTOK")

    def test_legacy_separate_fields_still_supported(self) -> None:
        # api_username/api_token (no api_credential) is the pre-existing shape the CLI and
        # older clients use — must keep working unchanged.
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_username="me@x.com", api_token="TOK"))
        _, username, token = self.rt._hackerone_creds()
        self.assertEqual(username, "me@x.com")
        self.assertEqual(token, "TOK")

    def test_test_creds_reports_missing_token(self) -> None:
        res = self.rt.test_hackerone_creds()
        self.assertFalse(res["ok"])
        self.assertIn("token", res["error"].lower())

    def test_creds_status_never_leaks_token(self) -> None:
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_username="me@x.com", api_token="SUPERSECRET"))
        status = self.rt.hackerone_creds_status()
        self.assertEqual(status["team_handle"], "acme")
        self.assertTrue(status["has_token"])
        self.assertNotIn("SUPERSECRET", str(status))

    def test_successful_submit_registers_the_finding_in_the_ledger(self) -> None:
        # F1 here was never registered via ledger.upsert_findings at discovery time (this
        # cached run mimics a single-hunt/confirm-route result, which — unlike a campaign
        # run — never touches the ledger before a submit). A successful submit must still
        # end up trackable for report-status sync: it lazily creates the ledger record.
        self.rt.save_hackerone_creds(g.HackerOneCredsRequest(team_handle="acme", api_username="me@x.com", api_token="TOK"))
        orig_submit = g.bounty_submission.submit_to_hackerone
        g.bounty_submission.submit_to_hackerone = lambda package, **kw: {"ok": True, "report_id": "999", "url": "https://hackerone.com/reports/999"}
        try:
            res = self.rt.submit_finding(g.SubmitRequest(run_id=self.run_id, ref="F1", confirm=True))
        finally:
            g.bounty_submission.submit_to_hackerone = orig_submit
        self.assertTrue(res["ok"], res)
        records = bounty_ledger.submitted_records(g.RUNTIME_DIR)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["h1_report_id"], "999")

    def test_run_cache_is_bounded(self) -> None:
        for _ in range(20):
            r = _run_result()
            self.rt._cache_bounty_run(r, target="https://t", scope="t", program=None)
        self.assertLessEqual(len(self.rt.bounty_runs), 16)

    def test_bundle_keeps_same_basename_evidence_from_multiple_findings(self) -> None:
        run = self.rt.bounty_runs[self.run_id]
        first = Path(self._tmp.name) / "one" / "proof.png"
        second = Path(self._tmp.name) / "two" / "proof.png"
        first.parent.mkdir()
        second.parent.mkdir()
        first.write_bytes(b"first-proof")
        second.write_bytes(b"second-proof")
        run["screenshots"] = {"F1": [str(first)], "F2": [str(second)]}

        bundle = self.rt.export_bundle(g.BundleRequest(run_id=self.run_id))
        self.assertTrue(bundle["ok"], bundle)
        with zipfile.ZipFile(bundle["path"]) as zf:
            names = set(zf.namelist())
            self.assertIn("screenshots/F1-01-proof.png", names)
            self.assertIn("screenshots/F2-01-proof.png", names)
            self.assertEqual(zf.read("screenshots/F1-01-proof.png"), b"first-proof")
            self.assertEqual(zf.read("screenshots/F2-01-proof.png"), b"second-proof")


if __name__ == "__main__":
    unittest.main()
