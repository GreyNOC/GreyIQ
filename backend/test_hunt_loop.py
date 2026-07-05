"""The AI-driven iterative hunt loop is a BOUNDED scheduler over verify_active. These lock the safety-
critical invariants: total requests across all turns never exceed a single hunt's budget, it stops on
done / no-progress / rate-limit / max-iters, and it fails closed to a single pass without a brain."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
from bughunter import active_verify_service, hunt_loop  # noqa: E402
from bughunter.settings import ScannerSettings  # noqa: E402


class HuntLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = (active_verify_service.verify_active, coder.coder_enabled, coder.coder_config, coder.generate)
        self.addCleanup(lambda: self._restore())
        self.budgets_seen: list[int] = []
        self.turn = 0
        coder.coder_enabled = lambda cfg: bool(cfg)
        coder.coder_config = lambda cfg: {"provider": "x"}

    def _restore(self) -> None:
        active_verify_service.verify_active, coder.coder_enabled, coder.coder_config, coder.generate = self._orig

    def _settings(self, max_iters: int = 5) -> ScannerSettings:
        return ScannerSettings(hunt_loop_enabled=True, hunt_loop_max_iters=max_iters, active_max_requests_per_host=20)

    def _stub_verify(self, used_per_turn: int) -> None:
        def fake(target, findings, *, requests_budget=12, **kw):
            self.budgets_seen.append(requests_budget)
            self.turn += 1
            f = {"class_id": "xss", "rule_id": "active.reflected-xss", "location": f"https://t/?q={self.turn}",
                 "_active_proof": {"status": "candidate", "observed_result": "reflected"}}
            return [f], {"in_scope": True, "host": "t", "requests_used": used_per_turn,
                         "rate_limited": False, "verified_classes": ["xss"]}
        active_verify_service.verify_active = fake

    def _brain(self, *, done: bool, new_each_turn: bool = True) -> None:
        n = {"i": 0}
        def gen(messages, cfg):
            n["i"] += 1
            param = f'"newparam{n["i"]}"' if new_each_turn else '"same"'
            return {"text": '{"param_hypotheses": [' + param + '], "probe_priority": [], "xss_params": [], '
                            '"done": ' + ("true" if done else "false") + "}"}
        coder.generate = gen

    def test_total_requests_never_exceed_the_single_hunt_budget(self) -> None:
        # each turn uses 3; the loop keeps re-planning, but the SUM across turns must stay <= budget (12)
        self._stub_verify(used_per_turn=3)
        self._brain(done=False)
        used = {"n": 0}
        orig_fake = active_verify_service.verify_active
        def counting(*a, **k):
            r, m = orig_fake(*a, **k)
            used["n"] += m["requests_used"]
            return r, m
        active_verify_service.verify_active = counting
        _, meta = hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=12,
                                                 settings=self._settings(max_iters=99), coder_cfg={"provider": "x"})
        self.assertLessEqual(used["n"], 12)                       # NEVER exceeds a single hunt's budget
        self.assertTrue(all(b <= 12 for b in self.budgets_seen))  # each turn's allotment is bounded too

    def test_respects_max_iters(self) -> None:
        self._stub_verify(used_per_turn=1)                        # cheap turns -> budget won't stop it
        self._brain(done=False)
        hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=100,
                                       settings=self._settings(max_iters=3), coder_cfg={"provider": "x"})
        self.assertLessEqual(self.turn, 3)                        # hard iteration cap

    def test_brain_done_stops_after_first_turn(self) -> None:
        self._stub_verify(used_per_turn=1)
        self._brain(done=True)
        hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=100,
                                       settings=self._settings(max_iters=9), coder_cfg={"provider": "x"})
        self.assertEqual(self.turn, 1)                            # one probe, brain says done -> stop

    def test_no_progress_stops(self) -> None:
        self._stub_verify(used_per_turn=1)
        self._brain(done=False, new_each_turn=False)             # brain repeats the same param -> no new surface
        hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=100,
                                       settings=self._settings(max_iters=9), coder_cfg={"provider": "x"},
                                       extra_params=["same"])
        self.assertEqual(self.turn, 1)

    def test_disabled_brain_is_a_single_pass(self) -> None:
        self._stub_verify(used_per_turn=1)
        coder.coder_enabled = lambda cfg: False
        results, _ = hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=12,
                                                    settings=self._settings(), coder_cfg=None)
        self.assertEqual(self.turn, 1)                            # exactly one verify_active (today's behaviour)
        self.assertTrue(results)

    def test_findings_deduped_across_turns(self) -> None:
        # every turn returns the SAME normalized finding (location differs only by the numeric marker)
        def fake(target, findings, *, requests_budget=12, **kw):
            self.turn += 1
            return ([{"class_id": "xss", "rule_id": "r", "location": f"https://t/?q={self.turn}",
                      "_active_proof": {"status": "candidate"}}],
                    {"in_scope": True, "requests_used": 2, "rate_limited": False, "verified_classes": []})
        active_verify_service.verify_active = fake
        self._brain(done=False)
        results, _ = hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=12,
                                                    settings=self._settings(max_iters=9), coder_cfg={"provider": "x"})
        self.assertEqual(len(results), 1)                        # numeric-id-normalized dedup collapses them

    def test_iterative_enabled_gate(self) -> None:
        self.assertFalse(hunt_loop.iterative_enabled({"provider": "x"}, ScannerSettings(hunt_loop_enabled=False)))
        coder.coder_enabled = lambda cfg: False
        self.assertFalse(hunt_loop.iterative_enabled(None, ScannerSettings(hunt_loop_enabled=True)))

    def test_observations_digest_surfaces_response_structure_to_the_brain(self) -> None:
        # The re-plan brain must READ the real response structure (the digest), not just an excerpt —
        # this is the "stop starving the brain" wiring. It stays trust-wrapped (UNTRUSTED data).
        meta = {"verified_classes": ["xss"], "requests_used": 3,
                "digest": {"interesting_names": ["owner_id", "is_admin"], "error_family": "sql", "jwt": {"alg": "HS256"}}}
        blob = hunt_loop._observations_digest([], meta)
        self.assertIn("owner_id", blob)                          # the brain sees the real key names
        self.assertIn("is_admin", blob)
        self.assertIn("sql", blob)                               # ...and the error family
        self.assertIn("response_structure", blob)
        # a missing/empty digest degrades cleanly (no crash, empty structure)
        self.assertIn("response_structure", hunt_loop._observations_digest([], {"verified_classes": []}))


if __name__ == "__main__":
    unittest.main()
