"""The outer theorize -> act wave.

The hunt pipeline runs its phases once, in order, and nothing revisited an earlier phase when later
knowledge arrived — so the engine would work out exactly which (endpoint, class) was still unresolved
and then print that conclusion in a report instead of acting on it. These lock the safety properties
that make acting on it acceptable: it is opt-in, bounded, focused, gated by the same prover, and it
confirms nothing on its own.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import active_verify_service, bounty, investigator  # noqa: E402
from bughunter.settings import ScannerSettings  # noqa: E402


# Two findings that leave a chain blocked on a CORS step — the shape the wave exists to chase.
FINDINGS = [
    {"ref": "F1", "class_id": "cors", "severity": "medium", "confidence": "medium",
     "title": "Permissive CORS", "location": "https://app.example/api/me"},
    {"ref": "F2", "class_id": "xss", "severity": "medium", "confidence": "medium",
     "title": "Reflected input", "location": "https://app.example/search"},
]
SURFACE = {"endpoints": ["https://app.example/"], "params": []}


class ReplanWaveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = active_verify_service.verify_active
        self.addCleanup(lambda: setattr(active_verify_service, "verify_active", self._orig))
        self.calls: list[dict] = []

    def _settings(self) -> ScannerSettings:
        return ScannerSettings(active_max_requests_per_host=20, active_min_interval_ms=0)

    def _stub(self, *, confirmed: bool = False, used: int = 2, boom: bool = False,
              rate_limited: bool = False) -> None:
        def fake(target, findings, *, requests_budget=12, class_priority=None, only_classes=None,
                 governor=None, **kw):
            self.calls.append({"target": target, "budget": requests_budget,
                               "only_classes": list(only_classes or []),
                               "class_priority": list(class_priority or []),
                               "governor": governor})
            if boom:
                raise RuntimeError("prover exploded")
            status = "confirmed" if confirmed else "candidate"
            found = [{"_active_class_hint": "cors", "rule_id": "active.cors",
                      "location": target, "_active_proof": {"status": status,
                                                            "observed_result": "o",
                                                            "control_result": "c"}}]
            # Honour the allotment, exactly as the real prover's _Http does — the wave's own
            # accounting is what decides how much is offered, and that is asserted separately.
            return found, {"in_scope": True, "host": "app.example",
                           "requests_used": min(used, requests_budget),
                           "rate_limited": rate_limited, "verified_classes": []}
        active_verify_service.verify_active = fake

    def _run(self, findings=None):
        return bounty._replan_wave(
            "https://app.example/", findings if findings is not None else FINDINGS,
            scope="app.example", settings=self._settings(), auth=None,
            extra_params=[], surface=SURFACE)

    # --- it acts on the cortex's own conclusion ---------------------------------------

    def test_it_probes_the_lead_the_cortex_ranked_highest(self) -> None:
        self._stub()
        out, info = self._run()
        self.assertTrue(info["ran"])
        self.assertTrue(self.calls)
        self.assertEqual(self.calls[0]["target"], "https://app.example/api/me")
        self.assertIn("cors", self.calls[0]["only_classes"])
        self.assertTrue(out)

    def test_it_probes_focused_not_the_whole_suite(self) -> None:
        """The wave exists to close ONE gap. Re-running all ~25 checks would make it a second hunt."""
        self._stub()
        self._run()
        for call in self.calls:
            self.assertTrue(call["only_classes"], "every wave probe must be class-restricted")
            self.assertLessEqual(len(call["only_classes"]), bounty._REPLAN_MAX_CLASSES)

    def test_it_shares_the_per_host_governor(self) -> None:
        """It must compete for the existing per-host allowance, not open a second one."""
        self._stub()
        self._run()
        self.assertIsNotNone(self.calls[0]["governor"])

    def test_confirmations_are_counted_but_never_asserted_by_the_wave(self) -> None:
        """The wave reports what the prover's own proof status says. It has no opinion of its own —
        report._has_captured_artifact still decides what is confirmed."""
        self._stub(confirmed=True)
        _out, info = self._run()
        self.assertEqual(info["confirmed"], info["targets"])
        self._stub(confirmed=False)
        self.calls.clear()
        _out2, info2 = self._run()
        self.assertEqual(info2["confirmed"], 0)

    # --- bounds -----------------------------------------------------------------------

    def test_it_never_exceeds_its_request_budget(self) -> None:
        self._stub(used=5)
        _out, info = self._run()
        self.assertLessEqual(info["requests_used"], bounty._REPLAN_BUDGET)

    def test_it_never_allots_more_than_the_wave_has_left(self) -> None:
        """The part the wave itself owns: whatever the prover then does with the allotment, the
        wave must never OFFER more than its remaining budget, or the cap is decorative."""
        self._stub(used=3)
        self._run()
        remaining = bounty._REPLAN_BUDGET
        for call in self.calls:
            self.assertLessEqual(call["budget"], remaining)
            remaining -= 3
        self.assertGreaterEqual(len(self.calls), 1)

    def test_it_never_probes_more_than_its_target_cap(self) -> None:
        many = [{"ref": f"F{i}", "class_id": "xss", "severity": "medium", "confidence": "medium",
                 "title": "Reflected input", "location": f"https://app.example/s/{i}"}
                for i in range(20)]
        self._stub(used=1)
        _out, info = self._run(many)
        self.assertLessEqual(info["targets"], bounty._REPLAN_MAX_TARGETS)
        self.assertLessEqual(len(self.calls), bounty._REPLAN_MAX_TARGETS)

    def test_a_rate_limited_target_stops_the_wave(self) -> None:
        self._stub(rate_limited=True, used=1)
        _out, info = self._run()
        self.assertEqual(info["targets"], 1)

    def test_nothing_to_chase_is_a_no_op(self) -> None:
        """A graph with no probeable unproven lead must cost zero requests."""
        self._stub()
        out, info = self._run([])
        self.assertEqual(out, [])
        self.assertFalse(self.calls)
        self.assertEqual(info["requests_used"], 0)

    def test_a_source_only_graph_is_a_no_op(self) -> None:
        """There is nothing for an ACTIVE prober to point at in a source file."""
        self._stub()
        out, _info = self._run([
            {"ref": "F1", "class_id": "sqli", "severity": "high", "confidence": "low",
             "title": "String-built query", "file_path": "app.py", "snippet": "q = 'SELECT ' + v"}])
        self.assertEqual(out, [])
        self.assertFalse(self.calls)

    # --- failure behaviour ------------------------------------------------------------

    def test_an_exploding_prover_never_breaks_the_hunt(self) -> None:
        self._stub(boom=True)
        out, info = self._run()
        self.assertEqual(out, [])
        self.assertFalse(info["ran"])

    def test_a_malformed_finding_set_is_survivable(self) -> None:
        self._stub()
        for bad in ([None], ["nope"], [{}], [{"class_id": {"x": 1}}]):
            with self.subTest(findings=bad):
                out, _info = bounty._replan_wave(
                    "https://app.example/", bad, scope="app.example", settings=self._settings(),
                    auth=None, extra_params=[], surface=SURFACE)
                self.assertIsInstance(out, list)

    # --- the opt-in gate --------------------------------------------------------------

    def test_the_wave_is_off_by_default(self) -> None:
        """It spends real requests against someone's target, so it must be a deliberate choice."""
        self.assertFalse(ScannerSettings().hunt_replan_enabled)

    def test_the_plan_it_consumes_only_names_confirmable_classes(self) -> None:
        """A class the prover cannot confirm would spend budget for a guaranteed non-result."""
        graph = investigator.build_investigation(FINDINGS, surface=SURFACE)
        for row in investigator.build_probe_plan(graph):
            self.assertIn(row["class_id"], active_verify_service.ACTIVE_PROVER_CLASSES)


if __name__ == "__main__":
    unittest.main()
