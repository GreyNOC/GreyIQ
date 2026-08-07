"""Contract tests for the shared evidence-grounded investigation cortex."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import investigator, report  # noqa: E402


class InvestigationCortexTests(unittest.TestCase):
    def test_static_match_remains_a_candidate(self) -> None:
        graph = investigator.build_investigation([{
            "ref": "F1", "rule_id": "code.sql-string-format", "title": "SQL query built from input",
            "class_id": "sqli", "severity": "high", "confidence": "high",
            "file_path": "app.py", "snippet": "query = 'SELECT ' + value",
        }])
        item = graph["hypotheses"][0]
        self.assertEqual(item["status"], "candidate")
        self.assertEqual(item["decision"], "gather-proof")
        self.assertFalse(item["report_ready"])
        self.assertIn("differential", item["next_action"])

    def test_typed_differential_can_be_report_ready(self) -> None:
        finding = {
            "ref": "F1", "rule_id": "active.sqli", "title": "SQL injection differential",
            "class_id": "sqli", "severity": "high", "confidence": "high",
            "location": "https://app.example/api/search",
        }
        plans = {"F1": {"proof_of_impact": {
            "status": "confirmed", "method": "GET parameter differential",
            "observed_result": "true condition returned 17 rows",
            "control_result": "false condition returned 0 rows",
        }}}
        graph = investigator.build_investigation([finding], plans)
        item = graph["hypotheses"][0]
        self.assertEqual(item["status"], "confirmed")
        self.assertIn("observed-control-differential", item["artifacts"])
        self.assertTrue(item["report_ready"])
        self.assertEqual(graph["metrics"]["report_ready"], 1)

    def test_confirmation_prose_without_artifact_is_blocked(self) -> None:
        finding = {
            "ref": "F1", "rule_id": "web.cors", "title": "CORS",
            "class_id": "cors", "severity": "high", "confidence": "high",
            "location": "https://app.example/api/me",
        }
        plans = {"F1": {"proof_of_impact": {
            "status": "confirmed", "evidence": "The model says an attacker can read all records.",
        }}}
        graph = investigator.build_investigation([finding], plans)
        item = graph["hypotheses"][0]
        self.assertEqual(item["status"], "contradicted")
        self.assertEqual(item["decision"], "resolve-contradiction")
        self.assertFalse(item["report_ready"])
        self.assertEqual(graph["contradictions"][0]["code"], "confirmation-without-artifact")

    def test_identical_control_is_not_a_differential(self) -> None:
        finding = {"ref": "F1", "class_id": "xss", "severity": "medium", "confidence": "high"}
        plans = {"F1": {"proof_of_impact": {
            "status": "confirmed", "observed_result": "HTTP 200 marker absent",
            "control_result": "HTTP   200 marker absent",
        }}}
        graph = investigator.build_investigation([finding], plans)
        self.assertEqual(graph["hypotheses"][0]["status"], "contradicted")
        self.assertTrue(any(row["code"] == "non-differential-control" for row in graph["contradictions"]))

    def test_secret_classification_conflict_is_explicit(self) -> None:
        graph = investigator.build_investigation([{
            "ref": "F1", "rule_id": "secret.google-api-key", "category": "secret",
            "title": "Browser API key", "severity": "high", "confidence": "high",
            "secret_classification": "public_client_key", "file_path": "public/app.js",
        }])
        self.assertTrue(any(row["code"] == "secret-severity-conflict" for row in graph["contradictions"]))
        self.assertEqual(graph["hypotheses"][0]["status"], "contradicted")

    def test_attack_chain_correlates_real_refs(self) -> None:
        findings = [
            {"ref": "F1", "class_id": "disclosure", "severity": "medium", "confidence": "high",
             "title": "Leaked object ids", "location": "https://app.example/api/debug"},
            {"ref": "F2", "class_id": "access-control", "severity": "high", "confidence": "medium",
             "title": "Object authorization lead", "location": "https://app.example/api/orders/1"},
        ]
        graph = investigator.build_investigation(findings)
        self.assertEqual(graph["metrics"]["attack_chains"], 1)
        chain = graph["attack_chains"][0]
        self.assertEqual(set(chain["refs"]), {"F1", "F2"})
        self.assertIn("object", chain["title"].lower())
        self.assertTrue(all(item["chain_candidate"] for item in graph["hypotheses"]))

    def test_probe_plan_becomes_explicit_evidence_queue(self) -> None:
        plan = {"probe_priority": [{
            "endpoint": "https://app.example/download?file=x",
            "classes": ["path-traversal", "xss"], "why": "file parameter", "score": 120,
        }]}
        first = investigator.build_probe_hypotheses(plan)
        self.assertEqual(first, investigator.build_probe_hypotheses(plan))
        self.assertEqual(first[0]["endpoint"], plan["probe_priority"][0]["endpoint"])
        self.assertEqual(first[0]["status"], "untested")
        self.assertTrue(first[0]["evidence_required"])
        self.assertGreater(first[0]["likelihood_score"], first[1]["likelihood_score"])

    def test_malformed_input_is_bounded_and_safe(self) -> None:
        graph = investigator.build_investigation([None, "bad", {"severity": {"x": 1}}], {"H3": 7})
        self.assertEqual(graph["algorithm"], investigator.ALGORITHM_VERSION)
        self.assertLessEqual(len(graph["hypotheses"]), investigator._MAX_HYPOTHESES)


class InvestigationReportTests(unittest.TestCase):
    def test_report_and_json_carry_the_same_investigation(self) -> None:
        finding = {
            "ref": "F1", "rule_id": "active.sqli", "title": "SQL injection",
            "class_id": "sqli", "class_name": "SQL injection", "severity": "high",
            "confidence": "high", "location": "https://app.example/search",
        }
        plans = {"F1": {"steps": ["Send a benign true/false differential."], "proof_of_impact": {
            "status": "confirmed", "method": "differential",
            "observed_result": "true condition changed row count",
            "control_result": "false condition did not change row count",
        }}}
        investigation = investigator.build_investigation([finding], plans)
        ctx = {
            "tool": "GreyIQ BugHunter", "version": "test", "target": "https://app.example",
            "profile": {"name": "Test"}, "risk": "high", "score": 0.8,
            "findings": [finding], "attack_plans": plans, "scanners_run": ["active"],
            "authorized": True, "brain": {}, "investigation": investigation,
            "next_steps": [], "coverage": {},
        }
        markdown = report.build_markdown(ctx)
        sidecar = report.build_json(ctx)
        self.assertIn("## Investigation intelligence", markdown)
        self.assertIn("Ranked hypothesis queue", markdown)
        self.assertEqual(sidecar["investigation"], investigation)

    def test_malformed_advisory_metrics_do_not_break_report(self) -> None:
        ctx = {
            "profile": {"name": "Test"}, "findings": [], "attack_plans": {},
            "scanners_run": [], "brain": {}, "next_steps": [], "coverage": {},
            "investigation": {
                "verdict": {"bad": True},
                "metrics": {"confirmed": "many", "average_confidence": {"bad": True}},
                "hypotheses": [], "attack_chains": [], "contradictions": [],
            },
        }
        markdown = report.build_markdown(ctx)
        self.assertIn("0 confirmed", markdown)
        self.assertIn("confidence 0/100", markdown)


if __name__ == "__main__":
    unittest.main()
