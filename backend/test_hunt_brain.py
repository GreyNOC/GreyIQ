"""hunt_brain: the LLM reasoning layer that boosts recall by proposing WHERE to probe, while the
deterministic prover keeps precision. Tests lock the safety contract: brain output is param-names-
only, scope-safe (can't introduce a URL), fail-closed, and every target-derived input is trust-
wrapped before the model sees it (prompt-injection hardening)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import trust  # noqa: E402
from bughunter import hunt_brain  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
