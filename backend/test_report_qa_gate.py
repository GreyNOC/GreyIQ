"""Pre-export QA gate (report.qa_validate_report): the final evidence-vs-claim check GreyIQ runs
before exporting a report. It must apply conservative, DOWNGRADE-ONLY corrections so a CORS/disclosure
finding can never claim more than the captured evidence proves, and must leave a well-evidenced High
alone."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as report_lib  # noqa: E402

_HIGH_CORS_VECTOR = "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"


def _cors_finding(ref: str, status: str, *, labels: str = "", read_data: str = "",
                  cross_origin: bool = False) -> tuple[dict, dict]:
    pe = {"request_line": "GET /api/me HTTP/1.1", "response_status": status,
          "matched_value": "Access-Control-Allow-Origin: https://evil.example; Access-Control-Allow-Credentials: true"}
    if labels:
        pe["sensitive_data_labels"] = labels
    if read_data:
        pe["read_data"] = read_data
    finding = {"ref": ref, "class_id": "cors", "rule_id": "active.cors-reflection",
               "severity": "high", "proof_evidence": pe}
    if cross_origin:
        finding["cross_origin_read_confirmed"] = True
    # A plan CVSS that (wrongly) asserts High — the gate must correct it unless evidence backs it.
    plan = {"cvss": {"vector": _HIGH_CORS_VECTOR, "base_score": 8.3, "base_severity": "High",
                     "estimated": False, "justification": "seed"},
            "proof_of_impact": {"status": "confirmed", "observed_result": "ACAO reflected with creds"}}
    return finding, plan


class QaGateTests(unittest.TestCase):
    def test_high_cors_on_404_with_no_data_is_capped_to_low(self) -> None:
        f, p = _cors_finding("F1", "HTTP 404")
        res = report_lib.qa_validate_report([f], {"F1": p})
        self.assertEqual(report_lib.resolve_severity(f, p), "low")
        self.assertNotIn("/C:H", p["cvss"]["vector"])          # Confidentiality:High stripped (not AC:H)
        self.assertIn("C:L", p["cvss"]["vector"])
        self.assertTrue(any(i.get("action") for i in res["issues"]))
        self.assertFalse(res["ok"])                             # corrections were applied

    def test_high_cors_with_sensitive_read_but_no_browser_poc_caps_to_medium(self) -> None:
        # Sensitive data present + 200, but same-site only (no browser PoC) -> Medium, never High.
        f, p = _cors_finding("F1", "HTTP 200", labels="a JWT (session/bearer token)",
                             read_data='{"token":"eyJ..."}')
        report_lib.qa_validate_report([f], {"F1": p})
        self.assertEqual(report_lib.resolve_severity(f, p), "medium")
        self.assertNotIn("C:H", p["cvss"]["vector"])

    def test_high_cors_with_confirmed_browser_cross_origin_read_stays_high(self) -> None:
        # The one path to High: a browser PoC on an attacker origin actually read sensitive data.
        f, p = _cors_finding("F1", "HTTP 200", labels="a JWT (session/bearer token)",
                             read_data='{"token":"eyJ..."}', cross_origin=True)
        res = report_lib.qa_validate_report([f], {"F1": p})
        self.assertEqual(report_lib.resolve_severity(f, p), "high")
        self.assertIn("C:H", p["cvss"]["vector"])              # High is justified — untouched
        self.assertTrue(res["ok"])                             # nothing corrected

    def test_gate_never_raises_severity(self) -> None:
        # A Low finding with a modest vector must not be bumped up by the gate.
        f, p = _cors_finding("F1", "HTTP 404")
        f["severity"] = "low"
        p["cvss"] = {"vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "base_score": 3.1,
                     "base_severity": "Low", "estimated": False, "justification": "seed"}
        report_lib.qa_validate_report([f], {"F1": p})
        self.assertEqual(report_lib.resolve_severity(f, p), "low")


if __name__ == "__main__":
    unittest.main()
