"""End-to-end plumbing guarantee: a confirmed finding's Proof-of-Concept (reproduction steps + a
runnable command), its Proof-of-Impact (confirmed status + the impact), AND the 'pure evidence of
sent and return code' (the exact request line sent + the HTTP status it returned) must all reach
EVERY report surface — the campaign report, the per-finding file, the per-platform submission, and
the JSON sidecar. Locks the wiring the user depends on."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as R  # noqa: E402
from bughunter import report_formats as RF  # noqa: E402

_FINDING = {
    "ref": "F1", "severity": "critical", "confidence": "high",
    "class_id": "rce", "class_name": "OS command injection",
    "title": "OS command injection via 'cmd' parameter",
    "location": "https://example.test/run?cmd=1", "rule_id": "active.rce-command-injection",
    "cwe": "CWE-78", "description": "The 'cmd' parameter reaches a server-side shell.",
    "snippet": "out: 222",
    # The captured 'pure evidence' — the exact request SENT and the RETURN CODE it produced.
    "proof_evidence": {
        "request_line": "GET https://example.test/run?cmd=$(expr 111 + 111)",
        "response_status": "HTTP 200",
        "matched_value": "shell command substitution evaluated to 222 (OS command injection)",
        "read_data": "out: 222",
    },
}
_PLAN = {
    "steps": ["Send GET /run?cmd=$(expr 111 + 111).", "Observe 222 in the response body."],
    "poc": "curl -s 'https://example.test/run?cmd=$(expr%20111%20%2B%20111)'",
    "impact": "Arbitrary OS command execution on the application server.",
    "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_score": 9.8, "base_severity": "critical"},
    "proof_of_impact": {
        "status": "confirmed", "method": "GET with a benign $(expr 111 + 111) shell substitution",
        "actor": "an unauthenticated attacker", "affected_asset": "the application server",
        "observed_result": "the shell evaluated the substitution to 222 (HTTP 200)",
        "control_result": "a literal 'expr 111 + 111' control did not yield 222",
        "evidence": "the marker followed by 222 appears in the response",
    },
}


def _ctx() -> dict:
    return {
        "tool": "GreyIQ BugHunter", "version": "test", "generated_at": "2026-07-03 12:00 UTC",
        "target": "https://example.test", "profile": {"id": "web-app", "name": "Web application", "description": ""},
        "vuln_class": None, "scope": "example.test in scope", "authorized": True,
        "scanners_run": ["active"], "risk": "critical", "score": 0.98,
        "findings": [dict(_FINDING)], "attack_plans": {"F1": dict(_PLAN)},
        "manual_checklist": [], "recommended_tools": [], "brain": {"used": False},
    }


class PocPoiPlumbingTests(unittest.TestCase):
    def _assert_all_present(self, text: str, surface: str) -> None:
        # POC: the runnable command + a reproduction step
        self.assertIn("curl -s 'https://example.test/run", text, f"{surface}: POC command missing")
        self.assertIn("Observe 222 in the response", text, f"{surface}: reproduction steps missing")
        # PURE EVIDENCE: the exact request SENT + the RETURN CODE
        self.assertIn("run?cmd=$(expr 111 + 111)", text, f"{surface}: request-sent evidence missing")
        self.assertIn("HTTP 200", text, f"{surface}: return-code evidence missing")
        # POI: the impact + a Confirmed proof-of-impact
        self.assertIn("Arbitrary OS command execution", text, f"{surface}: impact missing")
        self.assertRegex(text, r"(?i)status:\*\*\s*Confirmed")  # POI renders as confirmed

    def test_campaign_report_carries_poc_poi_and_evidence(self) -> None:
        self._assert_all_present(R.build_markdown(_ctx()), "build_markdown")

    def test_per_finding_report_carries_poc_poi_and_evidence(self) -> None:
        self._assert_all_present(R.build_finding_markdown(_ctx(), dict(_FINDING)), "build_finding_markdown")

    def test_per_platform_report_carries_poc_poi_and_evidence(self) -> None:
        for platform in ("hackerone", "bugcrowd", "yeswehack", "intigriti"):
            self._assert_all_present(RF.render_finding(_ctx(), dict(_FINDING), platform), f"render_finding/{platform}")

    def test_json_sidecar_carries_poc_and_confirmed_poi(self) -> None:
        doc = R.build_json(_ctx())
        self.assertEqual(doc["proof_of_impact"]["F1"]["status"], "confirmed")     # POI in the machine-readable sidecar
        self.assertEqual(doc["attack_plans"]["F1"]["poc"], _PLAN["poc"])          # POC command in the sidecar
        # the request-sent + return-code evidence rides on the finding dict itself
        self.assertEqual(doc["findings"][0]["proof_evidence"]["response_status"], "HTTP 200")
        self.assertIn("run?cmd=", doc["findings"][0]["proof_evidence"]["request_line"])


if __name__ == "__main__":
    unittest.main()
