"""Offline checks for the concise operator body and the detailed evidence sidecar."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report, report_formats, submission  # noqa: E402


def _case(*, confirmed: bool = True) -> tuple[dict, dict]:
    token = "opaqueBearerToken1234567890"
    finding = {
        "ref": "F1", "title": "Cross-account record read", "severity": "high",
        "description": "Account A received a record assigned to account B.",
        "location": "https://app.example.test/records/42", "cwe": "CWE-639",
        "proof_evidence": {
            "request_line": "POST /records/42 HTTP/1.1",
            "request_header": f"Authorization: Bearer {token}",
            "response_status": "HTTP 200",
            "read_data": '{"record":"sample","token":"' + token + '","tail":"' + "x" * 1600 + 'END"}',
        },
    }
    proof = {
        "status": "confirmed" if confirmed else "candidate",
        "observed_result": "Account A received record 42 (HTTP 200).",
        "control_result": "Account A received HTTP 403 for record 43.",
        "limitations": "Only the two test records were checked.",
    }
    ctx = {
        "target": "https://app.example.test", "scope": "app.example.test",
        "attack_plans": {"F1": {
            "steps": ["Log in as account A.", "Request record 42."],
            "poc": f"curl -H 'Authorization: Bearer {token}' https://app.example.test/records/42",
            "impact": "Account A can read the tested record assigned to account B.",
            "proof_of_impact": proof,
            "remediation": "Check record ownership on the server.",
        }},
    }
    return ctx, finding


class SubmissionBodyStyleTests(unittest.TestCase):
    def test_final_redaction_handles_known_and_other_bearer_tokens_once(self) -> None:
        known = "knownBearerSecret12345"
        other = "otherOpaqueBearer4567890"
        text = f"Authorization: Bearer {known}\nAuthorization: Bearer {other}"
        rendered = report_formats._safe_report_text(text, {"secret_value": known})
        self.assertIn("Authorization: Bearer <redacted>", rendered)
        self.assertNotIn(known, rendered)
        self.assertNotIn(other, rendered)
        self.assertEqual(rendered.count("[REDACTED_SECRET:"), 1)

    def test_final_redaction_handles_five_character_known_secret(self) -> None:
        rendered = report_formats._safe_report_text(
            "Recovered signing secret abcde. Authorization: Bearer abcde",
            {"secret_value": "abcde"},
        )
        self.assertNotIn("abcde", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("[REDACTED_SECRET:[REDACTED_SECRET:", rendered)

    def test_secret_specific_redaction_does_not_skip_other_credentials(self) -> None:
        ctx, finding = _case()
        finding["secret_value"] = "exact-secret-not-in-capture"
        finding["description"] = (
            "Token exact-secret-not-in-capture appeared beside "
            "Authorization: Bearer opaqueBearerToken1234567890"
        )
        for rendered in (
            report_formats.render_submission_body(ctx, finding),
            report_formats.render_finding(ctx, finding),
        ):
            self.assertNotIn("exact-secret-not-in-capture", rendered)
            self.assertNotIn("opaqueBearerToken1234567890", rendered)

    def test_confirmed_body_is_plain_and_keeps_capture_and_control(self) -> None:
        ctx, finding = _case()
        body = report_formats.render_submission_body(ctx, finding, "hackerone")
        self.assertTrue(body.startswith("**Summary**\n"))
        self.assertIn("**Proof of Concept**", body)
        self.assertIn("1. Log in as account A.", body)
        self.assertIn("POST /records/42 HTTP/1.1", body)
        self.assertIn("HTTP 200", body)
        self.assertIn("END", body)  # captured output is not cut at 1,500 characters
        self.assertIn("Confirmed result:", body)
        self.assertIn("Control result:", body)
        self.assertIn("## Impact\n\nAssessed impact: Account A can read the tested record", body)
        self.assertNotIn("opaqueBearerToken1234567890", body)
        self.assertNotIn("[REDACTED_SECRET:[REDACTED_SECRET:", body)
        self.assertNotIn("| **Severity", body)
        self.assertNotIn("Retest after fix", body)
        self.assertNotIn("## Remediation", body)

    def test_candidate_does_not_paste_speculative_impact(self) -> None:
        ctx, finding = _case(confirmed=False)
        ctx["attack_plans"]["F1"]["proof_of_impact"].pop("control_result")
        body = report_formats.render_submission_body(ctx, finding)
        self.assertIn("This location was flagged for review.", body)
        self.assertNotIn("Account A received a record assigned to account B.", body)
        self.assertIn("Observed result (unconfirmed):", body)
        self.assertIn("Impact has not been confirmed", body)
        self.assertNotIn("Account A can read the tested record", body)
        self.assertIn("does not yet establish security impact", body)
        self.assertIn("No negative-control result was captured.", body)

    def test_missing_reproduction_artifact_is_explicit(self) -> None:
        ctx, finding = _case(confirmed=False)
        ctx["attack_plans"]["F1"].pop("poc")
        finding.pop("proof_evidence")
        body = report_formats.render_submission_body(ctx, finding)
        self.assertIn("No request or runnable command was captured in this report.", body)

    def test_program_can_require_remediation_and_automation_disclosure(self) -> None:
        ctx, finding = _case()
        ctx.update({"required_report_sections": ["remediation"], "disclose_automation": True,
                    "tool": "GreyIQ", "version": "1.2.3"})
        body = report_formats.render_submission_body(ctx, finding, "hackerone")
        self.assertIn("## Remediation", body)
        self.assertIn("Check record ownership on the server.", body)
        self.assertIn("Automated testing assistance: GreyIQ v1.2.3.", body)

    def test_package_writes_paste_body_and_full_review_sidecar(self) -> None:
        ctx, finding = _case()
        with tempfile.TemporaryDirectory() as temp:
            package = submission.write_submission_package(ctx, finding, Path(temp), "finding", "hackerone")
            self.assertIsNotNone(package)
            assert package is not None
            body = Path(package["markdown_path"]).read_text(encoding="utf-8")
            details = Path(package["details_path"]).read_text(encoding="utf-8")
            sidecar = json.loads(Path(package["json_path"]).read_text(encoding="utf-8"))
            self.assertEqual(body, package["vulnerability_information"])
            self.assertTrue(body.startswith("**Summary**"))
            self.assertIn("| **Severity** |", details)
            self.assertEqual(sidecar["analyst_report"], details)
            self.assertEqual(sidecar["cwe"], "CWE-639")
            self.assertEqual(sidecar["proof_status"], "confirmed")
            self.assertNotIn("opaqueBearerToken1234567890", details)

    def test_detailed_evidence_caption_does_not_invent_a_get_or_leak_token(self) -> None:
        _ctx, finding = _case()
        out: list[str] = []
        report._append_proof_evidence(out, finding)
        text = "\n".join(out)
        self.assertIn("POST /records/42 HTTP/1.1", text)
        self.assertIn("Captured evidence (redacted)", text)
        self.assertNotIn("benign GET probe", text)
        self.assertNotIn("passive", text.lower())
        self.assertNotIn("opaqueBearerToken1234567890", text)

    def test_proof_prose_and_version_are_redacted_at_paste_boundary(self) -> None:
        ctx, finding = _case()
        token = "opaqueBearerToken1234567890"
        ctx["attack_plans"]["F1"]["proof_of_impact"].update({
            "observed_result": f"Authorization: Bearer {token} returned HTTP 200",
            "control_result": f"Authorization: Bearer {token} returned HTTP 403 on control",
            "limitations": f"token={token} was used only for the test records",
        })
        ctx.update({"disclose_automation": True, "version": f"token={token}"})
        body = report_formats.render_submission_body(ctx, finding)
        self.assertNotIn(token, body)
        self.assertIn("Confirmed result:", body)
        self.assertIn("Control result:", body)

    def test_failed_sidecar_write_removes_new_paste_and_details_files(self) -> None:
        ctx, finding = _case()
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            real_write = submission.fsutil.write_text_safe
            calls = 0

            def _fail_second(path: Path, content: str) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("disk full")
                real_write(path, content)

            with mock.patch.object(submission.fsutil, "write_text_safe", side_effect=_fail_second):
                self.assertIsNone(submission.write_submission_package(ctx, finding, out, "finding"))
            self.assertFalse((out / "finding.md").exists())
            self.assertFalse((out / "finding.details.md").exists())
            self.assertFalse((out / "finding.json").exists())

    def test_credential_validation_text_is_redacted_in_both_outputs(self) -> None:
        token = "opaqueBearerToken1234567890"
        finding = {
            "ref": "F1", "title": "Leaked server token", "severity": "high",
            "rule_id": "secret.github-pat", "secret_classification": "confirmed_secret",
            "secret_value": token, "location": "src/config.py:12",
            "secret_evidence": {"redacted_secret": token,
                                "request_evidence": f"Authorization: Bearer {token}"},
            "_credential_proof": {"live": True, "checked": True, "http_status": 200,
                                  "detail": f"Authorization: Bearer {token} returned HTTP 200",
                                  "poc": f"curl -H 'Authorization: Bearer {token}' https://issuer.example.test/me"},
        }
        ctx = {"target": "src/config.py", "attack_plans": {"F1": {"steps": ["Review the captured validation."]}}}
        body = report_formats.render_submission_body(ctx, finding)
        details = report_formats.render_finding(ctx, finding)
        self.assertIn("Confirmed result:", body)
        self.assertNotIn(token, body)
        self.assertNotIn(token, details)


if __name__ == "__main__":
    unittest.main()
