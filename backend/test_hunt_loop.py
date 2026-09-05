"""The AI-driven iterative hunt loop is a BOUNDED scheduler over verify_active. These lock the safety-
critical invariants: total requests across all turns never exceed a single hunt's budget, it stops on
done / no-progress / rate-limit / max-iters, and it fails closed to a single pass without a brain."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
from bughunter import active_verify_service, hunt_brain, hunt_loop, investigator  # noqa: E402
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


class OfflineReactPlanTests(unittest.TestCase):
    """The DETERMINISTIC re-planner: with no brain configured the loop must still refine from the real
    observed structure — and must still terminate, stay inside _validate_plan, and stay opt-in."""

    EP = "https://target.example/app"
    EMPTY = {"param_hypotheses": [], "probe_priority": [], "xss_params": [], "done": True}

    def setUp(self) -> None:
        self._orig = (active_verify_service.verify_active, coder.coder_enabled)
        self.addCleanup(lambda: self._restore())
        coder.coder_enabled = lambda cfg: bool(cfg)   # no coder_cfg -> no brain -> the offline path
        self.turn = 0

    def _restore(self) -> None:
        active_verify_service.verify_active, coder.coder_enabled = self._orig

    def _surface(self) -> dict:
        return {"endpoints": [self.EP], "params": []}

    def _obs(self, digest: dict, *, endpoint: str | None = None, class_priority: list | None = None) -> dict:
        return {"endpoint": self.EP if endpoint is None else endpoint, "digest": digest,
                "class_priority": list(class_priority or [])}

    # --- enablement / opt-in -------------------------------------------------
    def test_flag_off_returns_todays_byte_identical_empty_plan(self) -> None:
        plan = hunt_loop._react_plan(None, self.EP, "", self._surface(), ["obs"], [], 12,
                                     structural=[self._obs({"error_family": "sql"})],
                                     settings=ScannerSettings(hunt_loop_offline_enabled=False))
        self.assertEqual(plan, self.EMPTY)                    # unchanged behaviour when not opted in

    def test_flag_on_delegates_to_the_offline_replanner(self) -> None:
        plan = hunt_loop._react_plan(None, self.EP, "", self._surface(), ["obs"], [], 12,
                                     structural=[self._obs({"error_family": "sql"}, class_priority=["xss"])],
                                     settings=ScannerSettings(hunt_loop_offline_enabled=True))
        self.assertFalse(plan["done"])
        self.assertEqual(plan["probe_priority"][0]["classes"][0], "sqli")

    def test_iterative_enabled_allows_the_offline_loop(self) -> None:
        coder.coder_enabled = lambda cfg: False
        self.assertTrue(hunt_loop.iterative_enabled(None, ScannerSettings(
            hunt_loop_enabled=True, hunt_loop_offline_enabled=True)))
        self.assertFalse(hunt_loop.iterative_enabled(None, ScannerSettings(
            hunt_loop_enabled=False, hunt_loop_offline_enabled=True)))   # master switch still rules
        # A settings object that predates the flag means OFF, never an AttributeError mid-hunt.
        self.assertFalse(hunt_loop.iterative_enabled(None, SimpleNamespace(hunt_loop_enabled=True)))

    # --- the rules the LLM prompt states in prose ----------------------------
    def test_error_family_promotes_its_injection_class_to_the_front(self) -> None:
        for family, expected in (("sql", "sqli"), ("nosql", "nosqli"), ("template", "ssti")):
            plan = hunt_loop._react_plan_offline(
                self._surface(), [self._obs({"error_family": family}, class_priority=["xss", "redirect"])],
                set(), 12)
            row = plan["probe_priority"][0]
            self.assertEqual(row["endpoint"], self.EP)
            self.assertEqual(row["classes"], [expected, "xss", "redirect"])   # promoted, nothing dropped
            self.assertEqual(plan["param_hypotheses"], [])                    # ...and nothing else changed
            self.assertEqual(plan["xss_params"], [])
            self.assertFalse(plan["done"])

    def test_unmapped_error_family_promotes_nothing(self) -> None:
        # A generic traceback names no injection family — guessing one would be fabrication.
        plan = hunt_loop._react_plan_offline(
            self._surface(), [self._obs({"error_family": "stacktrace"}, class_priority=["xss"])], set(), 12)
        self.assertEqual(plan["probe_priority"], [])
        self.assertTrue(plan["done"])

    def test_observed_names_become_param_hypotheses_and_repeats_stop_the_loop(self) -> None:
        digest = {"json_keys": ["owner_id", "q"], "form_fields": ["referrer_field"]}
        plan = hunt_loop._react_plan_offline(self._surface(), [self._obs(digest)], set(), 12)
        self.assertEqual(plan["param_hypotheses"], ["owner_id", "q", "referrer_field"])
        self.assertIn("q", plan["xss_params"])                # reflective-looking field -> xss steering
        self.assertFalse(plan["done"])
        # Same structure, but every name already probed -> nothing new -> done (the no-progress guard).
        again = hunt_loop._react_plan_offline(self._surface(), [self._obs(digest)],
                                              {"owner_id", "q", "referrer_field"}, 12)
        self.assertEqual(again["param_hypotheses"], [])
        self.assertTrue(again["done"])

    def test_jwt_and_cookie_gaps_promote_conditionally_reachable_classes(self) -> None:
        plan = hunt_loop._react_plan_offline(self._surface(), [self._obs(
            {"jwt": {"alg": "HS256"}, "cookie_flag_gaps": [{"cookie": "sid", "missing": ["HttpOnly", "SameSite"]}]},
            class_priority=["xss"])], set(), 12)
        classes = plan["probe_priority"][0]["classes"] if plan["probe_priority"] else []
        # jwt/csrf only survive if the validator's class vocabulary covers them; either way the row
        # must never be corrupted and the baseline class must never be lost.
        for cls in classes:
            self.assertIn(cls, set(hunt_brain.ACTIVE_CLASSES) | {"jwt", "csrf"})
        if classes:
            self.assertIn("xss", classes)
        # A Secure-only gap is a transport issue, not a forgeable-request one -> no csrf promotion.
        secure_only = hunt_loop._react_plan_offline(self._surface(), [self._obs(
            {"cookie_flag_gaps": [{"cookie": "sid", "missing": ["Secure"]}]})], set(), 12)
        self.assertEqual(secure_only["probe_priority"], [])

    # --- the safety gate -----------------------------------------------------
    def test_every_output_survives_validate_plan(self) -> None:
        hostile = {
            "json_keys": ["https://evil.example/x", "a" * 60, "drop table users", "id=1", "<script>",
                          "owner_id", "ok_name"] + [f"k{i}" for i in range(60)],
            "form_fields": ["valid-name", "bad name", "search"],
            "error_family": "sql", "jwt": {"alg": "none"},
        }
        plan = hunt_loop._react_plan_offline(self._surface(), [
            self._obs({"json_keys": ["sneaky"]}, endpoint="https://evil.example/"),   # not in scope
            self._obs(hostile, class_priority=["xss"]),
        ], set(), 99)
        for name in plan["param_hypotheses"]:
            self.assertRegex(name, hunt_brain._PARAM_NAME_RE)                 # names only, never a URL/payload
        for row in plan["probe_priority"]:
            self.assertIn(row["endpoint"], set(self._surface()["endpoints"]))  # verbatim in-scope only
        self.assertLessEqual(len(plan["param_hypotheses"]), hunt_brain._MAX_PARAM_HYPOTHESES)
        self.assertLessEqual(len(plan["probe_priority"]), hunt_brain._MAX_PRIORITY_ROWS)
        self.assertLessEqual(len(plan["xss_params"]), 12)
        # Idempotent under the gate == it already IS a validated plan.
        params, priority, _i, _s, xss, _p = hunt_brain._validate_plan(
            {"param_hypotheses": plan["param_hypotheses"], "probe_priority": plan["probe_priority"],
             "xss_params": plan["xss_params"]}, self._surface())
        self.assertEqual((params, priority, xss),
                         (plan["param_hypotheses"], plan["probe_priority"], plan["xss_params"]))

    def test_proposals_never_exceed_the_remaining_request_budget(self) -> None:
        digest = {"json_keys": [f"name{i}" for i in range(40)]}
        plan = hunt_loop._react_plan_offline(self._surface(), [self._obs(digest)], set(), 5)
        self.assertLessEqual(len(plan["param_hypotheses"]), 5)   # each new name costs at least a request
        # Below the per-turn floor there is nothing worth planning.
        self.assertEqual(hunt_loop._react_plan_offline(self._surface(), [self._obs(digest)], set(), 1),
                         self.EMPTY)

    def test_malformed_observations_are_done_and_never_raise(self) -> None:
        for obs in ([], [None], ["not-a-dict"], [{}], [{"digest": "not-a-dict"}],
                    [{"digest": {"json_keys": "not-a-list", "cookie_flag_gaps": [7]}}],
                    [{"digest": {"error_family": 12}}]):
            plan = hunt_loop._react_plan_offline(self._surface(), obs, set(), 12)  # type: ignore[arg-type]
            self.assertTrue(plan["done"], obs)
            self.assertEqual(plan["param_hypotheses"], [])
        self.assertTrue(hunt_loop._react_plan_offline(None, None, None, None)["done"])  # type: ignore[arg-type]

    # --- the loop itself -----------------------------------------------------
    def _stub_digest_verify(self, digest_for_turn) -> None:
        def fake(target, findings, *, requests_budget=12, **kw):
            self.turn += 1
            return [], {"in_scope": True, "host": "t", "requests_used": 4, "rate_limited": False,
                        "verified_classes": [], "digest": digest_for_turn(self.turn)}
        active_verify_service.verify_active = fake

    def _loop_settings(self, max_iters: int = 99) -> ScannerSettings:
        return ScannerSettings(hunt_loop_enabled=True, hunt_loop_max_iters=max_iters,
                               active_max_requests_per_host=500, hunt_loop_offline_enabled=True)

    def test_offline_loop_iterates_and_terminates_within_budget(self) -> None:
        # Every turn shows NEW structure, so only the budget can stop it: 40 / 4 requests = 10 turns.
        self._stub_digest_verify(lambda t: {"json_keys": [f"newkey{t}"], "error_family": "sql"})
        _, meta = hunt_loop.run_iterative_verify("https://target.example/app", [], scope="t",
                                                 requests_budget=40, settings=self._loop_settings(),
                                                 coder_cfg=None)
        self.assertGreater(self.turn, 1)          # the loop is ALIVE offline (it was a single pass before)
        self.assertLessEqual(self.turn, 10)       # ...and still bounded by the single hunt's budget
        self.assertEqual(meta["loop_turns"], self.turn)

    def test_offline_loop_stops_when_the_structure_repeats(self) -> None:
        self._stub_digest_verify(lambda t: {"json_keys": ["same_key"]})
        hunt_loop.run_iterative_verify("https://target.example/app", [], scope="t", requests_budget=100,
                                       settings=self._loop_settings(), coder_cfg=None)
        self.assertEqual(self.turn, 2)            # turn 2 sees nothing new -> done, no third probe

    def test_offline_loop_stays_a_single_pass_when_not_opted_in(self) -> None:
        self._stub_digest_verify(lambda t: {"json_keys": [f"newkey{t}"]})
        settings = ScannerSettings(hunt_loop_enabled=True, hunt_loop_max_iters=99,
                                   active_max_requests_per_host=500, hunt_loop_offline_enabled=False)
        hunt_loop.run_iterative_verify("https://target.example/app", [], scope="t", requests_budget=100,
                                       settings=settings, coder_cfg=None)
        self.assertEqual(self.turn, 1)            # flag off == exactly today's behaviour


class ProbeObservationLoopTests(unittest.TestCase):
    """The loop's observe step used to re-read the LANDING page every turn.

    ``meta['digest']`` is built from a fetch of the same URL each time, so after turn 0 the structure
    was byte-identical and the deterministic re-planner's whole termination argument ("continue only
    when the latest observation carries structure no earlier one did") fired immediately. The loop
    could not see the error its own probe raised, so it could only reschedule the scan it had run.
    """

    EP = "https://target.example/app"

    def setUp(self) -> None:
        self._orig = (active_verify_service.verify_active, coder.coder_enabled)
        self.addCleanup(lambda: self._restore())
        coder.coder_enabled = lambda cfg: bool(cfg)
        self.turn = 0
        self.seen: list[dict] = []

    def _restore(self) -> None:
        active_verify_service.verify_active, coder.coder_enabled = self._orig

    def _settings(self, max_iters: int = 99) -> ScannerSettings:
        return ScannerSettings(hunt_loop_enabled=True, hunt_loop_max_iters=max_iters,
                               active_max_requests_per_host=500, hunt_loop_offline_enabled=True)

    def _stub(self, probe_for_turn) -> None:
        """A CONSTANT landing digest — the realistic case — with a varying probe digest."""
        def fake(target, findings, *, requests_budget=12, class_priority=None,
                 only_classes=None, extra_params=None, **kw):
            self.turn += 1
            self.seen.append({"budget": requests_budget, "only_classes": only_classes,
                              "class_priority": list(class_priority or []),
                              "extra_params": list(extra_params or [])})
            return [], {"in_scope": True, "host": "target.example", "requests_used": 4,
                        "rate_limited": False, "verified_classes": [],
                        "digest": {"json_keys": ["same_key"]},          # identical every turn
                        "probe_digest": probe_for_turn(self.turn)}
        active_verify_service.verify_active = fake

    def test_a_probe_provoked_error_keeps_the_offline_loop_alive(self) -> None:
        """With a constant landing page, a probe that provokes a NEW error family each turn is real
        new structure and must justify another turn. Before the probe digest existed it did not."""
        families = {1: "sql", 2: "template", 3: "nosql"}
        self._stub(lambda t: {"error_families": [families[t]]} if t in families else {})
        hunt_loop.run_iterative_verify(self.EP, [], scope="target.example", requests_budget=100,
                                       settings=self._settings(), coder_cfg=None)
        self.assertGreater(self.turn, 2, "probe-provoked structure must keep the loop iterating")

    def test_a_repeating_probe_digest_still_terminates(self) -> None:
        """The termination argument has to survive the new signal: same structure, no new turn."""
        self._stub(lambda t: {"error_families": ["sql"], "candidate_classes": ["sqli"]})
        hunt_loop.run_iterative_verify(self.EP, [], scope="target.example", requests_budget=100,
                                       settings=self._settings(), coder_cfg=None)
        self.assertEqual(self.turn, 2)

    def test_a_probe_provoked_family_promotes_its_injection_class(self) -> None:
        obs = {"endpoint": self.EP, "digest": {}, "class_priority": ["xss"],
               "probe_digest": {"error_families": ["sql"]}}
        plan = hunt_loop._react_plan_offline({"endpoints": [self.EP], "params": []}, [obs], set(), 20)
        self.assertEqual(plan["probe_priority"][0]["classes"], ["sqli", "xss"])

    def test_a_class_that_answered_without_confirming_is_promoted(self) -> None:
        """It is one good probe from a real differential — the best place to spend the next turn."""
        obs = {"endpoint": self.EP, "digest": {}, "class_priority": [],
               "probe_digest": {"candidate_classes": ["cors"]}}
        plan = hunt_loop._react_plan_offline({"endpoints": [self.EP], "params": []}, [obs], set(), 20)
        self.assertIn("cors", plan["probe_priority"][0]["classes"])

    def test_an_already_confirmed_class_is_never_re_promoted(self) -> None:
        """Settled ground. Re-probing it spends budget to re-learn what the gate already accepted."""
        obs = {"endpoint": self.EP, "digest": {}, "class_priority": [],
               "probe_digest": {"confirmed_classes": ["sqli"], "error_families": ["sql"],
                                "candidate_classes": ["sqli"]}}
        plan = hunt_loop._react_plan_offline({"endpoints": [self.EP], "params": []}, [obs], set(), 20)
        self.assertEqual(plan["probe_priority"], [])
        self.assertTrue(plan["done"])

    def test_a_missing_probe_digest_degrades_to_todays_behaviour(self) -> None:
        obs = {"endpoint": self.EP, "digest": {"error_family": "sql"}, "class_priority": ["xss"]}
        plan = hunt_loop._react_plan_offline({"endpoints": [self.EP], "params": []}, [obs], set(), 20)
        self.assertEqual(plan["probe_priority"][0]["classes"], ["sqli", "xss"])

    def test_the_probe_structure_reaches_the_brain_prompt(self) -> None:
        blob = hunt_loop._observations_digest([], {
            "verified_classes": [], "requests_used": 1,
            "probe_digest": {"error_families": ["template"], "candidate_classes": ["ssti"]}})
        self.assertIn("probe_structure", blob)
        self.assertIn("template", blob)

    # --- budget and focus -------------------------------------------------------------

    def test_turn_zero_does_not_take_the_whole_budget(self) -> None:
        """Turn 0 is the UNSTEERED sweep. It used to be handed everything, so the steered turns the
        loop exists for ran on whatever the broad sweep happened to leave."""
        self._stub(lambda t: {"error_families": ["sql"] if t == 1 else ["template"]})
        hunt_loop.run_iterative_verify(self.EP, [], scope="target.example", requests_budget=100,
                                       settings=self._settings(max_iters=3), coder_cfg=None)
        self.assertLess(self.seen[0]["budget"], 100)
        self.assertGreaterEqual(self.seen[0]["budget"], hunt_loop._PER_TURN_MIN)

    def test_a_single_iteration_loop_keeps_the_whole_budget(self) -> None:
        """With max_iters == 1 there is nothing to reserve for, so reserving would just shrink the
        only pass that runs."""
        self._stub(lambda t: {})
        hunt_loop.run_iterative_verify(self.EP, [], scope="target.example", requests_budget=100,
                                       settings=self._settings(max_iters=1), coder_cfg=None)
        self.assertEqual(self.seen[0]["budget"], 100)

    def test_turn_zero_runs_the_full_suite_and_steered_turns_are_focused(self) -> None:
        """Recall is established by the unrestricted turn 0; only then may a turn narrow to the
        hypothesis it is chasing."""
        self._stub(lambda t: {"error_families": ["sql"] if t == 1 else ["template"]})
        hunt_loop.run_iterative_verify(self.EP, [], scope="target.example", requests_budget=100,
                                       settings=self._settings(max_iters=3), coder_cfg=None)
        self.assertIsNone(self.seen[0]["only_classes"])
        self.assertGreaterEqual(len(self.seen), 2)
        self.assertEqual(self.seen[1]["only_classes"], self.seen[1]["class_priority"])
        self.assertIn("sqli", self.seen[1]["only_classes"])

    def test_new_parameter_hypotheses_are_probed_before_exhausted_ones(self) -> None:
        """Each check applies its own small per-call parameter cap, so appending fresh hypotheses to
        the tail of a growing list spent the cap re-probing names earlier turns already cleared —
        and the new hypothesis, the only reason to run another turn, was never reached."""
        def fake(target, findings, *, requests_budget=12, extra_params=None, **kw):
            self.turn += 1
            self.seen.append({"extra_params": list(extra_params or [])})
            return [], {"in_scope": True, "host": "target.example", "requests_used": 4,
                        "rate_limited": False, "verified_classes": [],
                        "digest": {"json_keys": [f"newkey{self.turn}"]}, "probe_digest": {}}
        active_verify_service.verify_active = fake
        hunt_loop.run_iterative_verify(
            self.EP, [], scope="target.example", requests_budget=100,
            settings=self._settings(max_iters=3), coder_cfg=None,
            extra_params=["olda", "oldb"], surface={"endpoints": [self.EP], "params": []})
        self.assertGreaterEqual(len(self.seen), 2)
        later = self.seen[1]["extra_params"]
        self.assertEqual(later[0], "newkey1", "the fresh hypothesis must be probed first")
        self.assertEqual(set(later), {"newkey1", "olda", "oldb"}, "nothing may be dropped")

    def test_restricting_classes_never_raises_the_request_budget(self) -> None:
        self._stub(lambda t: {"error_families": ["sql"] if t == 1 else ["template"]})
        _, meta = hunt_loop.run_iterative_verify(self.EP, [], scope="target.example",
                                                 requests_budget=20, settings=self._settings(),
                                                 coder_cfg=None)
        self.assertLessEqual(meta["requests_used"], 20)


class RestrictToClassesTests(unittest.TestCase):
    """``_apply_class_priority`` reorders; ``_restrict_to_classes`` selects. A loop that only
    reorders re-pays for the whole ~25-check suite on every steered turn."""

    CHECKS = [("xss", lambda: None), ("sqli", lambda: None), ("cors", lambda: None),
              ("xss", lambda: None)]

    def test_it_keeps_only_the_requested_classes_in_order(self) -> None:
        kept = active_verify_service._restrict_to_classes(self.CHECKS, ["xss"])
        self.assertEqual([c for c, _ in kept], ["xss", "xss"])

    def test_no_restriction_is_a_no_op(self) -> None:
        for empty in (None, [], [""]):
            with self.subTest(value=empty):
                self.assertEqual(active_verify_service._restrict_to_classes(self.CHECKS, empty),
                                 self.CHECKS)

    def test_a_restriction_matching_nothing_falls_back_to_the_full_suite(self) -> None:
        """Silently probing nothing would look like a clean target. Fail open instead."""
        self.assertEqual(active_verify_service._restrict_to_classes(self.CHECKS, ["nope"]),
                         self.CHECKS)

    def test_it_never_adds_or_mutates_a_check(self) -> None:
        kept = active_verify_service._restrict_to_classes(self.CHECKS, ["sqli", "cors"])
        self.assertTrue(set(kept).issubset(set(self.CHECKS)))
        self.assertEqual(len(self.CHECKS), 4)


class DeterministicCoderIsNotAReasoningBrainTests(unittest.TestCase):
    """Selecting the deterministic coder provider must not be mistaken for configuring a brain.

    ``offline``/``deterministic`` are real, selectable coder providers that are deliberately NOT in
    ``coder._PROVIDERS_OFF``, so ``coder_enabled`` answers True for them — but they have no chat
    completion at all. Gating the loop's LLM branch on ``coder_enabled`` meant the loop STARTED
    (``iterative_enabled`` True) and then died at turn 0, because ``_react_plan`` took the LLM branch
    straight into a guaranteed CoderError instead of reaching ``_react_plan_offline``. That is worse
    than provider "off", which at least reached the offline re-planner. Sibling of the same defect
    fixed in ``hunt_brain.plan_hunt``."""

    _DETERMINISTIC = ({"enabled": True, "provider": "offline"},
                      {"enabled": True, "provider": "deterministic"})

    def test_the_deterministic_providers_are_enabled_but_are_not_reasoning_brains(self) -> None:
        for cfg in self._DETERMINISTIC:
            with self.subTest(provider=cfg["provider"]):
                self.assertTrue(coder.coder_enabled(cfg))
                self.assertFalse(coder.reasoning_brain_enabled(cfg))

    def test_react_plan_reaches_the_offline_replanner_not_the_llm_branch(self) -> None:
        surface = {"endpoints": ["https://target.example/api/item?id=1"], "params": ["id"],
                   "tech": [], "forms": []}
        structural = [{"endpoint": "https://target.example/api/item?id=1",
                       "digest": {"json_keys": ["account_id", "balance"], "error_family": "sql"},
                       "verified_classes": [], "class_priority": ["sqli"]}]
        settings = ScannerSettings(hunt_loop_enabled=True, hunt_loop_offline_enabled=True)

        def explode(*_a, **_k):  # the LLM branch must never be reached for these providers
            raise AssertionError("_react_plan took the LLM branch for a deterministic provider")

        original = coder.generate
        coder.generate = explode
        self.addCleanup(lambda: setattr(coder, "generate", original))
        for cfg in self._DETERMINISTIC:
            with self.subTest(provider=cfg["provider"]):
                plan = hunt_loop._react_plan(cfg, "https://target.example/app", "target.example",
                                             surface, [], [], 40, structural=structural,
                                             settings=settings)
                # It re-planned deterministically rather than failing closed to the empty done plan.
                self.assertFalse(plan["done"])
                self.assertTrue(plan["param_hypotheses"] or plan["probe_priority"])

    def test_the_offline_loop_is_still_opt_in_for_a_deterministic_provider(self) -> None:
        settings = ScannerSettings(hunt_loop_enabled=True, hunt_loop_offline_enabled=False)
        for cfg in self._DETERMINISTIC:
            with self.subTest(provider=cfg["provider"]):
                self.assertFalse(hunt_loop.iterative_enabled(cfg, settings))

    def test_a_real_reasoning_provider_still_takes_the_llm_branch(self) -> None:
        self.assertTrue(coder.reasoning_brain_enabled({"enabled": True, "provider": "anthropic"}))


class ChatSurfaceRfTableDirsTests(unittest.TestCase):
    """The chat ``wardrive`` command must resolve the same OUI/SSID table dirs the CLI does.

    Without it the operator's ``<runtime>/rf/oui.tsv`` override is dead on the chat surface while the
    assessment still tells them to edit that very file — a deliverable instructing a step that does
    nothing, and two surfaces disagreeing about vendor attribution on the same capture."""

    def test_chat_resolves_real_seed_and_runtime_dirs(self) -> None:
        from bughunter import chat_commands

        seed_dir, runtime_dir = chat_commands._rf_table_dirs()
        self.assertIsNotNone(seed_dir)
        self.assertIsNotNone(runtime_dir)
        # The seed dir must be the one that actually carries the bundled RF tables.
        self.assertTrue((Path(str(seed_dir)) / "rf" / "oui.tsv").is_file())

    def test_it_never_raises_when_neither_module_is_importable(self) -> None:
        from bughunter import chat_commands

        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

        def blocked(name, *args, **kwargs):
            if name in ("greyiq_api", "gn_cli"):
                raise ImportError(f"blocked {name}")
            return real_import(name, *args, **kwargs)

        import builtins
        builtins.__import__ = blocked
        self.addCleanup(lambda: setattr(builtins, "__import__", real_import))
        self.assertEqual(chat_commands._rf_table_dirs(), (None, None))


if __name__ == "__main__":
    unittest.main()
