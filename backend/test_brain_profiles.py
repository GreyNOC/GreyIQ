"""Per-brain reasoning profiles: each brain gets an effort/token budget that fits its job.

The load-bearing rule is that a profile is a DEFAULT, not an override — an operator who has set
effort or max_tokens explicitly must keep those values. Spending more of someone else's API quota
than they configured, silently, is the failure mode these tests exist to prevent.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import brain_profiles  # noqa: E402
import coder  # noqa: E402


class ProfileContentTests(unittest.TestCase):
    def test_every_profile_is_valid(self) -> None:
        for name, p in brain_profiles.PROFILES.items():
            with self.subTest(brain=name):
                self.assertIn(p["effort"], brain_profiles.EFFORT_LEVELS)
                self.assertIsInstance(p["max_tokens"], int)
                self.assertGreater(p["max_tokens"], 0)

    def test_deep_brains_think_harder_than_hot_path_brains(self) -> None:
        rank = {e: i for i, e in enumerate(brain_profiles.EFFORT_LEVELS)}
        plan = brain_profiles.PROFILES["hunt_plan"]
        narrate = brain_profiles.PROFILES["narrate"]
        # The planner decides where a whole engagement probes; the narrator writes one clause per
        # finding on the hot path. The first must outrank the second on both axes or the profiles
        # are not doing their job.
        self.assertGreater(rank[plan["effort"]], rank[narrate["effort"]])
        self.assertGreater(plan["max_tokens"], narrate["max_tokens"])

    def test_agentic_brains_use_xhigh(self) -> None:
        # xhigh is the recommended setting for coding/agentic work.
        for name in ("hunt_plan", "strategy", "code_agent"):
            with self.subTest(brain=name):
                self.assertEqual(brain_profiles.PROFILES[name]["effort"], "xhigh")


class ApplyTests(unittest.TestCase):
    def _fresh(self) -> dict:
        return coder.coder_config({"provider": "anthropic", "anthropic": {"api_key": "k"}})

    def test_profile_fills_shipped_defaults(self) -> None:
        cfg = self._fresh()
        self.assertEqual(cfg["max_tokens"], brain_profiles._SHIPPED_MAX_TOKENS)
        self.assertEqual(cfg["anthropic"]["effort"], "high")
        brain_profiles.apply(cfg, "hunt_plan")
        self.assertEqual(cfg["anthropic"]["effort"], "xhigh")
        self.assertEqual(cfg["max_tokens"], brain_profiles.PROFILES["hunt_plan"]["max_tokens"])
        self.assertEqual(cfg["brain_profile"], "hunt_plan")

    def test_the_shipped_default_matches_coder(self) -> None:
        # brain_profiles decides "did the operator choose this?" by comparing against the shipped
        # value. If coder's default drifts, every profile silently stops applying.
        self.assertEqual(brain_profiles._SHIPPED_MAX_TOKENS, coder.CODER_DEFAULTS["max_tokens"])
        self.assertEqual(brain_profiles._SHIPPED_EFFORT, coder.CODER_DEFAULTS["anthropic"]["effort"])

    def test_a_cheap_profile_lowers_the_budget(self) -> None:
        cfg = self._fresh()
        brain_profiles.apply(cfg, "narrate")
        self.assertLess(cfg["max_tokens"], brain_profiles._SHIPPED_MAX_TOKENS)

    def test_an_explicit_operator_effort_wins(self) -> None:
        cfg = self._fresh()
        cfg["anthropic"]["effort"] = "low"  # operator chose cheap on purpose
        brain_profiles.apply(cfg, "hunt_plan")
        self.assertEqual(cfg["anthropic"]["effort"], "low")

    def test_an_explicit_operator_max_tokens_wins(self) -> None:
        cfg = self._fresh()
        cfg["max_tokens"] = 4096
        brain_profiles.apply(cfg, "hunt_plan")
        self.assertEqual(cfg["max_tokens"], 4096)

    def test_unknown_brain_is_a_no_op(self) -> None:
        cfg = self._fresh()
        before = dict(cfg)
        brain_profiles.apply(cfg, "no-such-brain")
        self.assertEqual(cfg["max_tokens"], before["max_tokens"])
        self.assertEqual(cfg["anthropic"]["effort"], before["anthropic"]["effort"])
        self.assertNotIn("brain_profile", cfg)

    def test_apply_never_touches_the_stored_config_or_defaults(self) -> None:
        stored = {"provider": "anthropic", "anthropic": {"api_key": "k"}}
        cfg = coder.coder_config(stored)
        brain_profiles.apply(cfg, "code_agent")
        self.assertNotIn("effort", stored["anthropic"])       # caller's dict untouched
        self.assertEqual(coder.CODER_DEFAULTS["max_tokens"], brain_profiles._SHIPPED_MAX_TOKENS)
        self.assertEqual(coder.CODER_DEFAULTS["anthropic"]["effort"], "high")

    def test_two_brains_do_not_leak_into_each_other(self) -> None:
        a = brain_profiles.apply(self._fresh(), "hunt_plan")
        b = brain_profiles.apply(self._fresh(), "narrate")
        self.assertEqual(a["anthropic"]["effort"], "xhigh")
        self.assertEqual(b["anthropic"]["effort"], "low")
        self.assertNotEqual(a["max_tokens"], b["max_tokens"])

    def test_apply_survives_a_malformed_config(self) -> None:
        # A profile must never be the thing that breaks a hunt.
        self.assertEqual(brain_profiles.apply({}, "hunt_plan")["max_tokens"], 16000)
        brain_profiles.apply({"max_tokens": "not-a-number", "anthropic": None}, "hunt_plan")
        brain_profiles.apply(None, "hunt_plan")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
