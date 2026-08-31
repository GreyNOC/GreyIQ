"""hunt_brain: the LLM reasoning layer that boosts recall by proposing WHERE to probe, while the
deterministic prover keeps precision. Tests lock the safety contract: brain output is param-names-
only, scope-safe (can't introduce a URL), fail-closed, and every target-derived input is trust-
wrapped before the model sees it (prompt-injection hardening)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import trust  # noqa: E402
from bughunter import hunt_brain  # noqa: E402
from bughunter.prover_classes import PROVER_CLASSES  # noqa: E402

SURFACE = {
    "endpoints": ["https://app.example.com/login", "https://app.example.com/api/orders",
                  "https://app.example.com/download"],
    "params": ["q", "id"],
    "tech": ["nginx", "React"],
    "forms": [{"action": "https://app.example.com/login", "method": "POST", "params": ["user", "pass"]}],
}


class _StubResult:
    def __init__(self, text):
        self.text = text


class HuntBrainTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = (coder.coder_enabled, coder.coder_config, coder.generate)
        self.addCleanup(lambda: self._restore())
        coder.coder_enabled = lambda cfg: True
        coder.coder_config = lambda cfg: {"provider": "anthropic"}

    def _restore(self) -> None:
        coder.coder_enabled, coder.coder_config, coder.generate = self._orig

    def _brain_returns(self, text: str) -> None:
        coder.generate = lambda messages, cfg: {"text": text, "provider": "anthropic", "model": "claude"}

    def test_disabled_brain_falls_back_to_the_offline_engine(self) -> None:
        # No LLM configured -> the offline knowledge-rule engine steers the hunt (was: empty plan).
        coder.coder_enabled = lambda cfg: False
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertEqual(plan["provider"], "offline")
        for row in plan["probe_priority"]:                     # every endpoint is verbatim in-scope
            self.assertIn(row["endpoint"], set(SURFACE.get("endpoints") or []))

    def test_disabled_brain_empty_surface_is_still_an_empty_plan(self) -> None:
        coder.coder_enabled = lambda cfg: False
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", {"endpoints": [], "params": []})
        self.assertFalse(plan["used"])
        self.assertEqual(plan["probe_priority"], [])

    def test_valid_output_yields_new_params_and_scoped_priority(self) -> None:
        self._brain_returns(
            '{"param_hypotheses": ["returnUrl", "callback", "tpl", "file", "id"],'  # "id" already known -> dropped
            ' "probe_priority": [{"endpoint": "https://app.example.com/download", "classes": ["path-traversal","lfi"], "why": "download param"},'
            '                     {"endpoint": "https://evil.com/x", "classes": ["xss"], "why": "invented"}],'
            ' "notes": "login looks redirect-y"}')
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertTrue(plan["used"])
        self.assertIn("returnUrl", plan["param_hypotheses"])
        self.assertIn("tpl", plan["param_hypotheses"])
        self.assertNotIn("id", plan["param_hypotheses"])          # already-known param not re-added
        self.assertEqual(len(plan["probe_priority"]), 1)          # invented-host row dropped (scope-safe)
        row = plan["probe_priority"][0]
        self.assertEqual(row["endpoint"], "https://app.example.com/download")
        self.assertEqual(row["classes"], ["path-traversal"])      # 'lfi' folds onto 'path-traversal', deduped

    def test_idor_candidates_only_keep_verbatim_in_scope_endpoints(self) -> None:
        self._brain_returns(
            '{"param_hypotheses": [], "probe_priority": [],'
            ' "idor_candidates": ["https://app.example.com/api/orders",'   # verbatim in-scope -> kept
            '                     "https://evil.com/order/1",'             # invented host -> dropped
            '                     "https://app.example.com/api/orders"]}')  # duplicate -> deduped
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertEqual(plan["idor_candidates"], ["https://app.example.com/api/orders"])  # only the real in-scope one

    def test_privileged_endpoints_only_keep_verbatim_in_scope_endpoints(self) -> None:
        self._brain_returns(
            '{"param_hypotheses": [], "probe_priority": [],'
            ' "privileged_endpoints": ["https://app.example.com/download",'   # verbatim in-scope -> kept
            '                          "https://evil.com/admin",'             # invented host -> dropped
            '                          "https://app.example.com/download"]}')  # duplicate -> deduped
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertEqual(plan["privileged_endpoints"], ["https://app.example.com/download"])  # only the real in-scope one

    def test_payloads_and_urls_are_rejected_as_param_names(self) -> None:
        self._brain_returns(
            '{"param_hypotheses": ["<script>alarm(1)</script>", "https://evil.com/x", "q=1&a=2",'
            '  "../../etc/passwd", "valid_name", "also-ok"], "probe_priority": []}')
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertEqual(set(plan["param_hypotheses"]), {"valid_name", "also-ok"})  # only real names survive

    def test_garbage_output_is_fail_closed(self) -> None:
        self._brain_returns("I could not analyze this target, sorry!")
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertTrue(plan["used"])                 # the call happened
        self.assertEqual(plan["param_hypotheses"], [])  # but nothing usable -> empty, no crash

    def test_coder_error_is_fail_closed(self) -> None:
        def boom(messages, cfg):
            raise coder.CoderError("brain offline")
        coder.generate = boom
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertFalse(plan["used"])
        self.assertEqual(plan["param_hypotheses"], [])

    def test_hijacked_nonlist_fields_are_fail_closed(self) -> None:
        # vet finding: a hijacked page could make the model return well-formed JSON whose fields are
        # truthy non-lists ({"param_hypotheses": 5}). `x or []` doesn't rescue those — must not raise.
        for payload in ('{"param_hypotheses": 5, "probe_priority": []}',
                        '{"param_hypotheses": true, "probe_priority": 7}',
                        '{"param_hypotheses": "returnUrl", "probe_priority": {"a": 1}}'):
            self._brain_returns(payload)
            plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
            self.assertEqual(plan["param_hypotheses"], [])   # no crash, empty plan
            self.assertEqual(plan["probe_priority"], [])

    def test_malformed_row_classes_do_not_discard_later_valid_rows(self) -> None:
        self._brain_returns(
            '{"param_hypotheses": [], "probe_priority": ['
            '{"endpoint": "https://app.example.com/login", "classes": 7},'
            '{"endpoint": "https://app.example.com/download", "classes": ["path-traversal"]}'
            ']}'
        )
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertEqual(
            plan["probe_priority"],
            [{"endpoint": "https://app.example.com/download", "classes": ["path-traversal"], "why": ""}],
        )

    def test_param_hypotheses_are_capped(self) -> None:
        many = ", ".join(f'"p{i}"' for i in range(100))
        self._brain_returns(f'{{"param_hypotheses": [{many}], "probe_priority": []}}')
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertLessEqual(len(plan["param_hypotheses"]), hunt_brain._MAX_PARAM_HYPOTHESES)

    def test_target_surface_is_trust_wrapped_before_the_model(self) -> None:
        # Prove no target-derived data reaches the model un-wrapped: tag the wrapper and assert the
        # tag surrounds the surface in the prompt the model is handed.
        orig_wrap = trust.wrap_for_model
        self.addCleanup(lambda: setattr(trust, "wrap_for_model", orig_wrap))
        trust.wrap_for_model = lambda text, path="": f"<<UNTRUSTED::{path}>>\n{text}\n<<END>>"
        captured = {}

        def capture(messages, cfg):
            captured["prompt"] = messages[0]["content"]
            return {"text": '{"param_hypotheses": [], "probe_priority": []}', "provider": "x", "model": "y"}
        coder.generate = capture
        hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertIn("<<UNTRUSTED::", captured["prompt"])            # wrapper applied
        self.assertIn("https://app.example.com/login", captured["prompt"])
        # the endpoint must appear INSIDE the untrusted block, never as bare instruction text
        block = captured["prompt"].split("<<UNTRUSTED::", 1)[1]
        self.assertIn("https://app.example.com/login", block)


class ProverClassGateTests(unittest.TestCase):
    """_validate_plan's class gate now uses the prover's REAL vocabulary instead of a hand-listed
    subset. A class the prover has a check for survives; one it cannot confirm is still dropped."""

    def setUp(self) -> None:
        self._orig = (coder.coder_enabled, coder.coder_config, coder.generate)
        self.addCleanup(lambda: self._restore())
        coder.coder_enabled = lambda cfg: True
        coder.coder_config = lambda cfg: {"provider": "anthropic"}

    def _restore(self) -> None:
        coder.coder_enabled, coder.coder_config, coder.generate = self._orig

    def _classes_for(self, raw_classes: str) -> list[str]:
        coder.generate = lambda messages, cfg: {
            "text": ('{"param_hypotheses": [], "probe_priority": [{"endpoint": '
                     f'"https://app.example.com/login", "classes": {raw_classes}}}]}}'),
            "provider": "anthropic", "model": "claude"}
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        rows = plan["probe_priority"]
        return rows[0]["classes"] if rows else []

    def test_newly_reachable_prover_classes_survive_validation(self) -> None:
        # These were dropped by the old hand-listed gate even though the prover proves all of them.
        self.assertEqual(self._classes_for('["jwt", "graphql", "debug"]'), ["jwt", "graphql", "debug"])
        self.assertEqual(self._classes_for('["websocket", "sensitive", "cloud-exposure"]'),
                         ["websocket", "sensitive", "cloud-exposure"])
        self.assertEqual(self._classes_for('["csrf", "clickjacking"]'), ["csrf", "clickjacking"])

    def test_classes_the_prover_cannot_confirm_are_still_dropped(self) -> None:
        # Widening the vocabulary must not become "accept anything" -- an unconfirmable class would
        # only ever steer budget at a lead the prover can never promote past 'candidate'.
        self.assertEqual(self._classes_for('["xxe", "idor", "ssrf", "deserialization"]'), [])
        self.assertEqual(self._classes_for('["xxe", "jwt"]'), ["jwt"])   # partial row keeps the real one

    def test_aliases_still_fold_onto_the_canonical_tag(self) -> None:
        self.assertEqual(self._classes_for('["lfi", "cswsh", "OS Command_Injection"]'),
                         ["path-traversal", "websocket", "rce"])
        self.assertEqual(self._classes_for('["open-redirect", "redirect"]'), ["redirect"])  # deduped

    def test_the_exported_vocabulary_covers_the_prover_plus_its_aliases(self) -> None:
        self.assertTrue(set(hunt_brain.ACTIVE_CLASSES) >= set(PROVER_CLASSES))
        self.assertIn("lfi", hunt_brain.ACTIVE_CLASSES)                 # aliases stay accepted


class OfflineRankerHookTests(unittest.TestCase):
    """plan_hunt's optional seed_dir/runtime_dir hook for the learned offline ranker. Absent module,
    absent weight file, or the kill switch must all mean 'exactly the pre-existing rule behaviour'."""

    def setUp(self) -> None:
        self._orig = coder.coder_enabled
        self.addCleanup(lambda: setattr(coder, "coder_enabled", self._orig))
        coder.coder_enabled = lambda cfg: False        # force the offline path

    def test_still_callable_with_four_positional_args(self) -> None:
        # every existing caller passes 4 positional args (+ priors kwarg); none may break.
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        self.assertEqual(plan["provider"], "offline")
        self.assertTrue(plan["probe_priority"])
        self.assertEqual(plan, hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com",
                                                    SURFACE, None))

    def test_empty_model_dirs_are_byte_identical_to_no_dirs_at_all(self) -> None:
        base = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        with tempfile.TemporaryDirectory() as seed, tempfile.TemporaryDirectory() as runtime:
            hooked = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE,
                                          seed_dir=Path(seed), runtime_dir=Path(runtime))
        self.assertEqual(hooked, base)                 # no weight file -> the rules, unchanged
        self.assertNotIn("+ranker", hooked["notes"])

    def test_load_ranker_returns_none_without_a_weight_file(self) -> None:
        # No weight file on disk, and no dirs at all, both mean "use the rules".
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(hunt_brain._load_ranker(Path(tmp), Path(tmp)))
        self.assertIsNone(hunt_brain._load_ranker(None, None))

    def test_load_ranker_returns_none_when_the_optional_module_is_absent(self) -> None:
        # hunt_model is an OPTIONAL module -- a frozen build may ship without it, and importing it
        # must not be a precondition for hunting. Simulate the absent build via a blocked import.
        import builtins
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "bughunter" and args and args[2] and "hunt_model" in args[2]:
                raise ImportError("no module named bughunter.hunt_model")
            return real_import(name, *args, **kwargs)
        self.addCleanup(lambda: setattr(builtins, "__import__", real_import))
        builtins.__import__ = blocked
        self.assertIsNone(hunt_brain._load_ranker(None, None))

    def test_the_kill_switch_forces_the_rules_even_with_a_ranker_present(self) -> None:
        # GREYIQ_OFFLINE_RANKER=0 is the operator's escape hatch (e.g. reproducing an older run).
        import os
        from bughunter import settings as bh_settings
        orig = os.environ.get("GREYIQ_OFFLINE_RANKER")
        self.addCleanup(lambda: os.environ.pop("GREYIQ_OFFLINE_RANKER", None)
                        if orig is None else os.environ.__setitem__("GREYIQ_OFFLINE_RANKER", orig))
        os.environ["GREYIQ_OFFLINE_RANKER"] = "0"
        self.assertFalse(bh_settings.get_settings().offline_ranker_enabled)
        self.assertIsNone(hunt_brain._load_ranker(Path("."), Path(".")))

    def test_a_raising_ranker_loader_still_yields_the_rules_plan(self) -> None:
        # fail-closed: the offline planner must never break a hunt, whatever the model layer does.
        orig = hunt_brain._load_ranker
        self.addCleanup(lambda: setattr(hunt_brain, "_load_ranker", orig))
        base = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)

        def boom(seed_dir, runtime_dir):
            raise RuntimeError("weight file is a directory")
        hunt_brain._load_ranker = boom
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE,
                                    seed_dir=Path("."), runtime_dir=Path("."))
        self.assertEqual(plan, hunt_brain._empty_plan())   # fail-closed, never a crash
        self.assertTrue(base["probe_priority"])            # (and the un-hooked path still works)

    def test_offline_plan_stays_scope_safe_and_within_the_prover_vocabulary(self) -> None:
        plan = hunt_brain.plan_hunt({}, "https://app.example.com/", "app.example.com", SURFACE)
        allowed = set(SURFACE["endpoints"])
        for row in plan["probe_priority"]:
            self.assertIn(row["endpoint"], allowed)              # verbatim in-scope, never invented
            self.assertLessEqual(set(row["classes"]), set(PROVER_CLASSES))
            self.assertLessEqual(len(row["classes"]), 6)


class ReasoningBrainGateTests(unittest.TestCase):
    """plan_hunt must gate on whether a REASONING brain is available, not on whether SOME coder is
    selected. The deterministic ("offline"/"deterministic") coder is a real, selectable provider that
    ``coder_enabled`` answers True for, but it has no chat completion at all — ``coder.generate``
    raises CoderError for it by design. Gating on ``coder_enabled`` sent that configuration down the
    LLM branch, where the raise fail-closed to an EMPTY plan: the hunt flew blind, strictly worse
    than provider "off". These use the REAL coder gates (no monkeypatching) on purpose."""

    _OFFLINE_KEYS = ("param_hypotheses", "probe_priority", "idor_candidates", "ssrf_params",
                     "xss_params", "privileged_endpoints")

    def _plan(self, cfg):
        return hunt_brain.plan_hunt(cfg, "https://app.example.com/", "app.example.com", SURFACE)

    def test_the_deterministic_coder_is_enabled_but_is_not_a_reasoning_brain(self) -> None:
        for provider in sorted(coder.PROVIDERS_DETERMINISTIC):
            cfg = {"enabled": True, "provider": provider}
            self.assertTrue(coder.coder_enabled(cfg), provider)              # a real coding capability
            self.assertFalse(coder.reasoning_brain_enabled(cfg), provider)   # but it cannot answer a prompt
            with self.assertRaises(coder.CoderError):                        # ...proven by generate itself
                coder.generate([{"role": "user", "content": "hi"}], cfg)

    def test_selecting_the_deterministic_coder_keeps_the_offline_hunt_plan(self) -> None:
        # The defect: with provider "offline" the hunt got {'used': False, 'probe_priority': [], ...}.
        baseline = self._plan({"enabled": False, "provider": "off"})
        self.assertTrue(baseline["probe_priority"])                          # the offline brain works
        for provider in sorted(coder.PROVIDERS_DETERMINISTIC):
            plan = self._plan({"enabled": True, "provider": provider})
            self.assertEqual(plan["provider"], "offline", provider)
            self.assertTrue(plan["used"], provider)
            for key in self._OFFLINE_KEYS:
                self.assertEqual(plan[key], baseline[key], f"{provider}:{key}")

    def test_a_real_reasoning_provider_still_takes_the_llm_branch(self) -> None:
        # The fix must not turn a configured LLM into an offline hunt.
        orig = coder.generate
        self.addCleanup(lambda: setattr(coder, "generate", orig))
        coder.generate = lambda messages, cfg: {
            "text": '{"param_hypotheses": ["returnUrl"], "probe_priority": []}',
            "provider": "anthropic", "model": "claude"}
        for provider in ("anthropic", "local", "openai"):
            self.assertTrue(coder.reasoning_brain_enabled({"enabled": True, "provider": provider}))
            plan = self._plan({"enabled": True, "provider": provider})
            self.assertEqual(plan["param_hypotheses"], ["returnUrl"], provider)
            self.assertEqual(plan["provider"], "anthropic", provider)

    def test_reasoning_is_off_whenever_the_coder_is_off(self) -> None:
        # reasoning_brain_enabled delegates to coder_enabled, so every "off" spelling and the
        # disabled flag are honoured in exactly one place.
        for cfg in (None, {}, {"enabled": False, "provider": "anthropic"},
                    {"enabled": True, "provider": "off"}, {"enabled": True, "provider": "none"},
                    {"enabled": True, "provider": "disabled"}, {"enabled": True, "provider": ""}):
            self.assertFalse(coder.reasoning_brain_enabled(cfg), cfg)


class DeterministicVeteranPlannerTests(unittest.TestCase):
    def _classes(self, endpoint: str, *, tech=None, forms=None) -> list[str]:
        plan = hunt_brain.heuristic_plan({"endpoints": [endpoint], "tech": tech or [], "forms": forms or []})
        self.assertTrue(plan["used"])
        self.assertEqual(plan["probe_priority"][0]["endpoint"], endpoint)
        return plan["probe_priority"][0]["classes"]

    def test_file_download_spends_budget_on_traversal_first(self) -> None:
        classes = self._classes("https://app.example.com/api/download?file=report.pdf")
        self.assertEqual(classes[0], "path-traversal")
        self.assertIn("crlf", classes)

    def test_command_and_template_routes_get_high_impact_priority(self) -> None:
        self.assertEqual(self._classes("https://app.example.com/api/ping?host=example.com")[0], "rce")
        self.assertEqual(self._classes("https://app.example.com/render?template=invoice")[0], "ssti")

    def test_search_api_ranks_injection_and_cross_origin_checks(self) -> None:
        classes = self._classes("https://app.example.com/api/search?q=boots", tech=["Node/Express"])
        self.assertEqual(classes[0], "nosqli")
        self.assertIn("sqli", classes)
        self.assertIn("xss", classes)
        self.assertIn("cors", classes)

    def test_auth_callback_ranks_redirect_jwt_and_host_header(self) -> None:
        classes = self._classes("https://app.example.com/oauth/callback?returnUrl=%2Fhome")
        self.assertEqual(classes[0], "redirect")
        self.assertIn("jwt", classes)
        self.assertIn("host-header", classes)

    def test_graphql_semantics_promote_the_self_gated_graphql_check(self) -> None:
        classes = self._classes("https://app.example.com/graphql")
        self.assertEqual(classes[0], "graphql")
        self.assertIn("cors", classes)

    def test_post_state_change_form_promotes_csrf_without_inventing_surface(self) -> None:
        endpoint = "https://app.example.com/account/delete"
        classes = self._classes(endpoint, forms=[{"action": endpoint, "method": "POST", "params": ["accountId"]}])
        self.assertIn("csrf", classes)
        plan = hunt_brain.heuristic_plan({"endpoints": [endpoint], "forms": []})
        self.assertTrue(all(row["endpoint"] == endpoint for row in plan["probe_priority"]))
        self.assertEqual(plan["param_hypotheses"], [])

    def test_generic_and_malformed_surfaces_fail_quietly(self) -> None:
        self.assertFalse(hunt_brain.heuristic_plan({"endpoints": ["https://app.example.com/"]})["used"])
        self.assertFalse(hunt_brain.heuristic_plan({"endpoints": 7, "forms": "bad", "tech": True})["used"])
        self.assertFalse(hunt_brain.heuristic_plan({"endpoints": ["not-a-url", None]})["used"])

    def test_rows_and_classes_are_hard_capped_and_deterministic(self) -> None:
        endpoints = [f"https://app.example.com/api/download/{i}?file=x" for i in range(100)]
        surface = {"endpoints": endpoints, "tech": [], "forms": []}
        first = hunt_brain.heuristic_plan(surface)
        second = hunt_brain.heuristic_plan(surface)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first["probe_priority"]), hunt_brain._MAX_PRIORITY_ROWS)
        self.assertTrue(all(len(row["classes"]) <= 6 for row in first["probe_priority"]))


if __name__ == "__main__":
    unittest.main()
