"""Tests for the guided next-step planner (bughunter.next_steps).

Severity-resolution consistency: next_steps.build_next_steps must agree with the report/
H1 rating on the SAME finding (both route through report.resolve_severity), so a finding
whose raw scanner label disagrees with its plan's CVSS base_severity is ranked, grouped,
and counted by the CVSS-resolved severity everywhere — not just in the report.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import next_steps  # noqa: E402


def _finding(ref: str, raw_severity: str, *, confidence: str = "high", class_id: str = "ssrf") -> dict:
    return {"ref": ref, "severity": raw_severity, "confidence": confidence, "class_id": class_id,
            "class_name": class_id.upper(), "title": f"{class_id} finding {ref}", "location": "https://x/"}


class SeverityResolutionTests(unittest.TestCase):
    def test_submission_counts_use_cvss_resolved_severity_not_raw_label(self) -> None:
        # Raw label says 'medium'; the plan's CVSS says 'high' (the exact disagreement
        # test_severity_consistency.py pins for the report/H1 surfaces). next_steps'
        # submission-phase counts must agree -- not silently undercount it as medium.
        finding = _finding("F1", "medium")
        plan = {"cvss": {"base_score": 9.1, "base_severity": "high"}}
        ctx = {"findings": [finding], "attack_plans": {"F1": plan}, "scanners_run": ["web"], "kind": "url"}
        steps = next_steps.build_next_steps(ctx)
        submit_step = next((s for s in steps if s["phase"] == "Prepare submission"), None)
        self.assertIsNotNone(submit_step)
        self.assertEqual(submit_step["action"], "Write up and submit the high-impact finding(s) first")
        self.assertEqual(submit_step["ref"], "F1")  # the CVSS-high finding is the lead, not skipped

    def test_confirm_step_priority_uses_cvss_resolved_severity(self) -> None:
        finding = _finding("F1", "medium")
        plan = {"cvss": {"base_score": 9.1, "base_severity": "high"}}
        ctx = {"findings": [finding], "attack_plans": {"F1": plan}, "scanners_run": ["web"], "kind": "url"}
        steps = next_steps.build_next_steps(ctx)
        confirm_step = next(s for s in steps if s["phase"] == "Confirm findings" and s["ref"] == "F1")
        self.assertEqual(confirm_step["priority"], "high")  # not 'medium' -- the raw label

    def test_ranking_order_follows_cvss_resolved_severity(self) -> None:
        # F1's raw label (low) would normally rank BELOW F2 (medium), but F1's CVSS lifts
        # it to critical -- the confirm-step order must reflect the resolved severity.
        low_raw_critical_cvss = _finding("F1", "low")
        plain_medium = _finding("F2", "medium")
        plans = {"F1": {"cvss": {"base_score": 9.8, "base_severity": "critical"}}}
        ctx = {"findings": [low_raw_critical_cvss, plain_medium], "attack_plans": plans,
               "scanners_run": ["web"], "kind": "url"}
        steps = next_steps.build_next_steps(ctx)
        confirm_refs = [s["ref"] for s in steps if s["phase"] == "Confirm findings" and s["ref"]]
        self.assertEqual(confirm_refs[0], "F1")  # the CVSS-critical finding leads, despite the raw 'low' label

    def test_no_plan_falls_back_to_raw_severity(self) -> None:
        finding = _finding("F1", "medium")
        ctx = {"findings": [finding], "attack_plans": {}, "scanners_run": ["web"], "kind": "url"}
        steps = next_steps.build_next_steps(ctx)
        confirm_step = next(s for s in steps if s["phase"] == "Confirm findings" and s["ref"] == "F1")
        self.assertEqual(confirm_step["priority"], "medium")  # no CVSS override available -> raw label stands

    def test_confirmed_source_secret_step_reviews_captured_proof(self) -> None:
        finding = _finding("F1", "high", class_id="secrets")
        finding.update({"class_name": "Secrets / exposed credentials", "location": "src/settings.py"})
        plan = {
            "proof_of_impact": {
                "status": "confirmed",
                "authenticated_read_request": "curl -H 'Authorization: Bearer [REDACTED_SECRET]' https://api.openai.com/v1/models",
                "authenticated_read_response": '{"data":[{"id":"gpt-4o"}]}',
                "blast_radius": "OpenAI API key; scopes: gpt-4o",
            }
        }
        ctx = {"findings": [finding], "attack_plans": {"F1": plan}, "scanners_run": ["code"], "kind": "path"}
        steps = next_steps.build_next_steps(ctx)
        confirm_step = next(s for s in steps if s["phase"] == "Confirm findings" and s["ref"] == "F1")

        self.assertIn("Review confirmed proof for F1", confirm_step["action"])
        self.assertIn("already captured", confirm_step["detail"])
        self.assertIn("redacted authenticated-read request", confirm_step["detail"])
        self.assertIn("issuer success response", confirm_step["detail"])
        self.assertIn("blast radius", confirm_step["detail"])
        self.assertNotIn("Capture the exact request/response", confirm_step["detail"])


class ChainPhaseTests(unittest.TestCase):
    """The chain phase reads ctx["investigation"], which makes its wiring easy to break
    silently — and it was: the plan used to be built before that key existed."""

    def _ctx(self, **over: object) -> dict:
        finding = _finding("F1", "high", class_id="xss")
        ctx = {"findings": [finding], "attack_plans": {}, "scanners_run": ["web"], "kind": "url",
               "investigation": {"attack_chains": [{
                   "id": "C1", "title": "Unauthenticated attacker -> account takeover",
                   "refs": ["F1"], "status": "supported", "projected_impact": "Account takeover",
                   "step_count": 3, "proven_steps": 1, "next_action": "close it",
                   "steps": [
                       {"n": 1, "title": "XSS executes", "proven": True, "next_action": ""},
                       {"n": 2, "title": "Read session cookie", "proven": False,
                        "next_action": "Read document.cookie in a test account."},
                   ]}], "chain_probes": []}}
        ctx.update(over)
        return ctx

    def test_plan_is_not_corrupted_by_the_chain_phase(self) -> None:
        """The loop must not rebind the plan accumulator: doing so appended every later step
        into the chain's own step list and dropped Phases 1-3 from the returned plan."""
        ctx = self._ctx()
        chain = ctx["investigation"]["attack_chains"][0]
        steps = next_steps.build_next_steps(ctx)

        self.assertIsNot(steps, chain["steps"], "returned the chain's step list, not the plan")
        self.assertEqual(len(chain["steps"]), 2, "the chain's own steps were mutated")
        self.assertTrue(any(s["phase"] == "Confirm findings" for s in steps),
                        "earlier phases were silently discarded")
        self.assertTrue(all(isinstance(s.get("phase"), str) and s.get("action") for s in steps))

    def test_chain_step_names_the_blocking_step(self) -> None:
        steps = next_steps.build_next_steps(self._ctx())
        chain_step = next(s for s in steps if s["phase"] == "Chain & escalate")
        self.assertIn("C1", chain_step["action"])
        self.assertIn("Blocking step 2", chain_step["detail"])
        self.assertIn("document.cookie", chain_step["detail"])

    def test_blocked_chain_is_not_described_as_submittable(self) -> None:
        ctx = self._ctx()
        chain = ctx["investigation"]["attack_chains"][0]
        chain["status"] = "blocked"
        chain["steps"] = [{"n": 1, "title": "step", "proven": True, "next_action": ""}]
        chain_step = next(s for s in next_steps.build_next_steps(ctx)
                          if s["phase"] == "Chain & escalate")
        detail = chain_step["detail"].lower()
        self.assertIn("contradiction", detail)
        self.assertIn("do not package", detail)
        # The fully-proven wording ("Package the whole chain as ONE report") must not appear:
        # every step here IS proven, which is exactly how the blocked case used to reach it.
        self.assertNotIn("package the whole chain", detail)

    def test_a_speculative_probe_does_not_suppress_class_pair_advice(self) -> None:
        """A signal-only probe is not a chain; it must not silence the generic advice that
        two chainable findings should be combined."""
        ctx = {"findings": [_finding("F1", "medium", class_id="disclosure"),
                            _finding("F2", "high", class_id="access-control")],
               "attack_plans": {}, "scanners_run": ["web"], "kind": "url",
               "investigation": {"attack_chains": [], "chain_probes": [
                   {"id": "CP1", "title": "mass assignment", "hypothesis": "an is_admin field",
                    "next_action": "submit it and watch the echo"}]}}
        chain_steps = [s for s in next_steps.build_next_steps(ctx) if s["phase"] == "Chain & escalate"]
        self.assertTrue(any("CP1" in s["action"] for s in chain_steps))
        self.assertTrue(any("leaked ids" in s["detail"].lower() for s in chain_steps),
                        f"class-pair advice was suppressed: {[s['detail'][:60] for s in chain_steps]}")


if __name__ == "__main__":
    unittest.main()
