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
from bughunter import active_verify_service, hunt_loop, investigator  # noqa: E402
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

    # --- the loop's own endpoint allowlist ------------------------------------------------------

    def _stub_verify_capturing(self, used_per_turn: int = 1) -> list[list[str] | None]:
        """Record the class_priority handed to each verify_active call."""
        seen: list[list[str] | None] = []

        def fake(target, findings, *, requests_budget=12, class_priority=None, **kw):
            seen.append(list(class_priority) if class_priority else None)
            self.turn += 1
            return [], {"in_scope": True, "host": "t", "requests_used": used_per_turn,
                        "rate_limited": False, "verified_classes": []}
        active_verify_service.verify_active = fake
        return seen

    def _plan_brain(self, payload: str) -> None:
        coder.generate = lambda messages, cfg: {"text": payload}

    def test_class_steering_survives_a_surface_that_dropped_the_seed(self) -> None:
        # bounty ranks the discovered URLs and can drop the seed from the surface it passes, while the
        # loop still probes ONLY the seed. If the loop validated against that surface, every
        # probe_priority row for target_url was dropped and class steering never reached the prober.
        seen = self._stub_verify_capturing()
        self._plan_brain('{"param_hypotheses": [], "probe_priority": '
                         '[{"endpoint": "https://t/", "classes": ["sqli"]}], '
                         '"xss_params": [], "done": false}')
        hunt_loop.run_iterative_verify(
            "https://t/", [], scope="t", requests_budget=100,
            settings=self._settings(max_iters=5), coder_cfg={"provider": "x"},
            surface={"endpoints": ["https://t/api?id=1", "https://t/search?q=1"], "params": []})
        self.assertGreaterEqual(len(seen), 2)      # the plan was accepted -> the loop kept going
        self.assertEqual(seen[1], ["sqli"])        # ...and the brain's class order reached the prober

    def test_target_url_is_pinned_first_and_the_caller_surface_is_preserved(self) -> None:
        captured: dict[str, object] = {}
        self._stub_verify_capturing()
        def gen(messages, cfg):
            captured["prompt"] = messages[0]["content"]
            return {"text": '{"param_hypotheses": [], "probe_priority": [], "xss_params": [], "done": true}'}
        coder.generate = gen
        hunt_loop.run_iterative_verify(
            "https://t/", [], scope="t", requests_budget=100,
            settings=self._settings(max_iters=2), coder_cfg={"provider": "x"},
            surface={"endpoints": ["https://t/api?id=1"], "params": []})
        self.assertIn("https://t/api?id=1", str(captured["prompt"]))   # caller's ranking still shown

    # --- chain steering -------------------------------------------------------------------------

    def test_chain_focus_surfaces_an_open_chain_behind_proven_ones(self) -> None:
        # _build_chains sorts proven chains to the front, so slicing the top 3 BEFORE dropping the
        # fully-proven ones hid the very chain this steering exists for. A blocked chain (its cited
        # finding was contradicted) must stay out even though it has an unproven step.
        proven = {"title": "proven", "status": "confirmed",
                  "steps": [{"title": "s", "proven": True}], "projected_impact": "x"}
        graph = {"attack_chains": [
            {"title": "blocked", "status": "blocked", "projected_impact": "x",
             "steps": [{"title": "contradicted step", "proven": False, "next_action": "resolve"}]},
            dict(proven), dict(proven), dict(proven),
            {"title": "open", "status": "supported", "projected_impact": "account takeover",
             "steps": [{"title": "s1", "proven": True},
                       {"title": "steal token", "proven": False, "next_action": "capture cookie"}]},
        ]}
        orig = investigator.build_investigation
        investigator.build_investigation = lambda *a, **k: graph
        self.addCleanup(lambda: setattr(investigator, "build_investigation", orig))
        focus = hunt_loop._chain_focus([], {"endpoints": []}, {})
        self.assertEqual([row["chain"] for row in focus], ["open"])
        self.assertEqual(focus[0]["blocked_on"], "steal token")

    # --- no-progress guard ----------------------------------------------------------------------

    def test_identical_plan_every_turn_stops_after_one_repeat(self) -> None:
        # The old guard only asked whether priority/xss were non-empty, so a brain repeating itself
        # re-ran byte-identical probes until max_iters and drained the shared per-host bucket.
        self._stub_verify_capturing()
        self._plan_brain('{"param_hypotheses": [], "probe_priority": '
                         '[{"endpoint": "https://t/", "classes": ["sqli"]}], '
                         '"xss_params": ["q"], "done": false}')
        hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=100,
                                       settings=self._settings(max_iters=9), coder_cfg={"provider": "x"})
        self.assertEqual(self.turn, 2)             # one probe, one steered probe, then no new surface

    def test_empty_plan_with_caller_class_priority_still_stops_immediately(self) -> None:
        # Guards the measured regression: comparing new_priority to cur_priority directly would treat
        # an EMPTY plan as a change (the real update rule keeps cur_priority when the plan is empty).
        self._stub_verify_capturing()
        self._plan_brain('{"param_hypotheses": [], "probe_priority": [], "xss_params": [], "done": false}')
        hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=100,
                                       settings=self._settings(max_iters=9), coder_cfg={"provider": "x"},
                                       class_priority=["xss"], xss_params=["q"])
        self.assertEqual(self.turn, 1)

    # --- coverage accounting --------------------------------------------------------------------

    def test_requests_used_is_the_sum_across_turns(self) -> None:
        # bounty feeds this meta into the authoritative graph as scan_meta, so reporting only the LAST
        # turn's count understated the loop's spend — and disagreed with the non-loop path, which sums.
        counts = iter([3, 5])
        def fake(target, findings, *, requests_budget=12, **kw):
            self.turn += 1
            return [], {"in_scope": True, "host": "t", "requests_used": next(counts, 1),
                        "rate_limited": False, "verified_classes": []}
        active_verify_service.verify_active = fake
        self._plan_brain('{"param_hypotheses": ["a"], "probe_priority": [], "xss_params": [], "done": false}')
        _, meta = hunt_loop.run_iterative_verify("https://t/", [], scope="t", requests_budget=100,
                                                 settings=self._settings(max_iters=2),
                                                 coder_cfg={"provider": "x"})
        self.assertEqual(self.turn, 2)
        self.assertEqual(meta["requests_used"], 8)                 # 3 + 5, not the last turn's 5
        # ...and the loop's own snapshot is built AFTER the override, so it carries the same number
        self.assertEqual(meta["investigation"]["coverage"]["requests_used"], 8)


if __name__ == "__main__":
    unittest.main()
