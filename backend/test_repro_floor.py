"""A captured reproduction is an artifact. The brain must not be able to replace one.

``_deterministic_attack_plan`` builds each finding's plan, and where the captured evidence supports it
``_concrete_repro`` supplies a real crafted request and a runnable PoC. The hunt body then merges the
coding brain's plan over the top with a plain dict merge, and that merge already carried explicit
floors for two fields: the proof obligation inside ``proof_of_impact`` (so the report never loses its
"capture this to prove impact" guidance) and ``cvss`` (so a submitted severity is never an
attacker-influenceable brain-supplied vector).

It did not floor the two fields that carry the reproduction itself. Measured on a CONFIRMED CORS
finding: the deterministic plan's 782-character runnable PoC page — the artifact a triager opens to
watch the cross-origin read happen — was replaced by whatever the brain returned, in the reproducing
case the three characters ``"N/A"``, and its five concrete reproduction steps by ``"Read the
report."``.

A wrong PoC is worse than none. The triager runs it, nothing happens, and a real finding looks false.
The brain is a text model reachable over the network and prompted with target-derived content, so this
is also the one field where "the brain wins" is the wrong default.

The floor is deliberately narrow: it applies only where a concrete reproduction EXISTS. A candidate
whose plan is a generic class checklist is still enriched freely, which is what the brain is for.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty  # noqa: E402

BOUNTY_SOURCE = (BACKEND_DIR / "bughunter" / "bounty.py").read_text(encoding="utf-8")
REPORT_SOURCE = (BACKEND_DIR / "bughunter" / "report.py").read_text(encoding="utf-8")

#: A confirmed CORS finding — the case measured above, and the one class whose deterministic PoC is a
#: full runnable HTML page rather than a curl line.
CONFIRMED_CORS = {
    "ref": "F1", "class_id": "cors", "rule_id": "active.cors-wildcard-credentials",
    "title": "Cross-origin read with credentials", "severity": "high",
    "location": "https://t.example/api/me", "proof_status": "confirmed",
    "proof_evidence": {
        "request_header": "Origin: https://evil.example",
        "response_header": ("Access-Control-Allow-Origin: https://evil.example\n"
                            "Access-Control-Allow-Credentials: true"),
    },
    "proof_of_impact": {"status": "confirmed", "observed_result": "read", "control_result": "blocked"},
}
#: What a brain plausibly returns when it has nothing useful to add — and used to win.
LOSSY_BRAIN_PLAN = {"steps": ["Read the report."], "poc": "N/A"}


def _merge(finding: dict, brain_plan: dict) -> dict:
    """Replay the hunt body's merge for one finding, exactly as _run_bounty_hunt_body does."""
    class_id = str(finding.get("class_id") or "")
    base = bounty._deterministic_attack_plan(finding, class_id)
    merged = {**base, **{k: v for k, v in brain_plan.items() if v}}
    concrete_steps, concrete_poc = bounty._concrete_repro(finding, class_id)
    if concrete_poc:
        merged["poc"] = concrete_poc
    if concrete_steps:
        brain_steps = [str(x) for x in (brain_plan.get("steps") or []) if str(x or "").strip()]
        merged["steps"] = list(concrete_steps) + [x for x in brain_steps if x not in concrete_steps]
    return merged


class ThePremiseHoldsTests(unittest.TestCase):
    """Anti-vacuity: without a real concrete reproduction there is nothing here to protect."""

    def test_the_confirmed_cors_finding_really_does_get_a_runnable_poc(self) -> None:
        steps, poc = bounty._concrete_repro(CONFIRMED_CORS, "cors")
        self.assertTrue(poc, "the CORS prover no longer produces a concrete PoC — re-check this test")
        self.assertGreater(len(poc), 200, "the PoC is no longer a full page; the measurement is stale")
        self.assertIn("<!doctype html>", poc.lower())
        self.assertTrue(steps, "the CORS prover no longer produces concrete steps")

    def test_the_brain_plan_used_here_would_genuinely_have_won_the_plain_merge(self) -> None:
        base = bounty._deterministic_attack_plan(CONFIRMED_CORS, "cors")
        naive = {**base, **{k: v for k, v in LOSSY_BRAIN_PLAN.items() if v}}
        self.assertEqual(naive["poc"], "N/A",
                         "the plain merge no longer loses the PoC, so this suite guards nothing")
        self.assertNotEqual(naive["steps"], base["steps"])


class TheFloorPreservesTheArtifactTests(unittest.TestCase):
    def test_a_runnable_poc_survives_a_brain_that_would_replace_it(self) -> None:
        _steps, concrete_poc = bounty._concrete_repro(CONFIRMED_CORS, "cors")
        merged = _merge(CONFIRMED_CORS, LOSSY_BRAIN_PLAN)
        self.assertEqual(merged["poc"], concrete_poc,
                         "the brain replaced a runnable PoC on a confirmed finding")

    def test_the_concrete_steps_lead_and_are_not_substituted(self) -> None:
        concrete_steps, _poc = bounty._concrete_repro(CONFIRMED_CORS, "cors")
        merged = _merge(CONFIRMED_CORS, LOSSY_BRAIN_PLAN)
        self.assertEqual(merged["steps"][:len(concrete_steps)], list(concrete_steps),
                         "the captured reproduction no longer leads the steps")

    def test_the_brains_own_steps_are_appended_rather_than_discarded(self) -> None:
        # The floor protects the artifact; it should not throw away genuine enrichment.
        merged = _merge(CONFIRMED_CORS, {"steps": ["Also check the preflight cache."], "poc": ""})
        self.assertIn("Also check the preflight cache.", merged["steps"])

    def test_a_duplicated_brain_step_is_not_repeated(self) -> None:
        concrete_steps, _poc = bounty._concrete_repro(CONFIRMED_CORS, "cors")
        merged = _merge(CONFIRMED_CORS, {"steps": list(concrete_steps), "poc": ""})
        self.assertEqual(merged["steps"], list(concrete_steps))

    def test_the_existing_floors_are_still_in_force(self) -> None:
        # The two this change was modelled on must not have regressed.
        base = bounty._deterministic_attack_plan(CONFIRMED_CORS, "cors")
        merged = _merge(CONFIRMED_CORS, LOSSY_BRAIN_PLAN)
        self.assertEqual(merged["cvss"], base["cvss"])
        self.assertEqual(merged["proof_of_impact"].get("proof_obligation"),
                         base["proof_of_impact"].get("proof_obligation"))


class EnrichmentStillWorksWhereThereIsNothingToProtectTests(unittest.TestCase):
    """The floor must not turn the brain off for the findings it genuinely helps."""

    CANDIDATE = {
        "ref": "F2", "class_id": "auth", "rule_id": "passive.weak-session",
        "title": "Session cookie without Secure", "severity": "medium",
        "location": "https://t.example/login", "proof_status": "candidate", "proof_evidence": {},
    }

    def test_a_candidate_with_no_concrete_reproduction_is_enriched_freely(self) -> None:
        steps, poc = bounty._concrete_repro(self.CANDIDATE, "auth")
        self.assertFalse(steps, "precondition: this finding should have no concrete reproduction")
        self.assertFalse(poc)
        merged = _merge(self.CANDIDATE, {"steps": ["Log in and inspect Set-Cookie."], "poc": "curl -i ..."})
        self.assertEqual(merged["steps"], ["Log in and inspect Set-Cookie."])
        self.assertEqual(merged["poc"], "curl -i ...")

    def test_a_brain_poc_still_fills_an_empty_slot(self) -> None:
        merged = _merge(self.CANDIDATE, {"steps": [], "poc": "python3 exploit.py"})
        self.assertEqual(merged["poc"], "python3 exploit.py")


class TheFloorIsWiredIntoTheHuntBodyTests(unittest.TestCase):
    """The merge above is a replay; assert the real code does the same thing."""

    def test_the_hunt_body_recomputes_the_concrete_reproduction_at_merge_time(self) -> None:
        import inspect

        source = inspect.getsource(bounty._run_bounty_hunt_body)
        self.assertIn("_concrete_repro(_finding", source,
                      "the hunt body no longer consults the concrete reproduction when merging")
        self.assertIn("_finding_by_ref", source, "the ref -> finding lookup is gone")
        # Both fields must be restored, not just one.
        self.assertIn('merged["poc"] = _concrete_poc', source)
        self.assertIn('merged["steps"] = list(_concrete_steps)', source)

    def test_no_dead_field_was_invented_to_carry_the_discarded_prose(self) -> None:
        # An earlier draft kept the brain's poc as `poc_notes`. report.py reads only plan["poc"], so
        # that would have been a field nothing renders — the exact class of bug this branch fixes
        # elsewhere. The prose is discarded outright instead, and that choice is documented in place.
        self.assertNotIn("poc_notes", BOUNTY_SOURCE)
        self.assertIn('plan.get("poc")', REPORT_SOURCE,
                      "report.py no longer reads plan['poc']; re-check what the floor should protect")


if __name__ == "__main__":
    unittest.main()
