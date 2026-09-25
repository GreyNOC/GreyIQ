"""Tests for the active-layer per-host request governor."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import rate_limit  # noqa: E402
from bughunter.rate_limit import HostRateGovernor  # noqa: E402


class RateGovernorTests(unittest.TestCase):
    def test_caps_at_capacity(self) -> None:
        g = HostRateGovernor(capacity=4, min_interval_s=0.0, refill_per_s=0.0)
        results = [g.throttle("h") for _ in range(6)]
        self.assertEqual(results, [True, True, True, True, False, False])

    def test_per_host_budgets_are_independent(self) -> None:
        g = HostRateGovernor(capacity=1, min_interval_s=0.0, refill_per_s=0.0)
        self.assertTrue(g.throttle("a"))
        self.assertFalse(g.throttle("a"))
        self.assertTrue(g.throttle("b"))  # b has its own budget

    def test_min_interval_enforced(self) -> None:
        import time
        g = HostRateGovernor(capacity=10, min_interval_s=0.05, refill_per_s=0.0)
        start = time.monotonic()
        for _ in range(3):
            self.assertTrue(g.throttle("h"))
        # 3 sends with a 50ms floor between them => at least ~100ms total.
        self.assertGreaterEqual(time.monotonic() - start, 0.08)

    def test_remaining_reports_budget(self) -> None:
        g = HostRateGovernor(capacity=3, min_interval_s=0.0, refill_per_s=0.0)
        g.throttle("h")
        self.assertEqual(g.remaining("h"), 2)
        self.assertEqual(g.remaining("never-touched"), 3)

    def test_refills_over_real_elapsed_time(self) -> None:
        import time
        g = HostRateGovernor(capacity=2, min_interval_s=0.0, refill_per_s=20.0)  # fast refill for a quick test
        self.assertTrue(g.throttle("h"))
        self.assertTrue(g.throttle("h"))
        self.assertFalse(g.throttle("h"))  # bucket empty
        time.sleep(0.1)  # 0.1s * 20/s = ~2 tokens refilled
        self.assertTrue(g.throttle("h"))  # the real elapsed time replenished the bucket

    def test_refill_never_exceeds_capacity(self) -> None:
        import time
        g = HostRateGovernor(capacity=2, min_interval_s=0.0, refill_per_s=1000.0)
        g.throttle("h")
        time.sleep(0.05)  # would refill far past capacity at this rate if uncapped
        self.assertLessEqual(g.remaining("h"), 2)

    def test_host_key_normalization_case_and_whitespace(self) -> None:
        g = HostRateGovernor(capacity=1, min_interval_s=0.0, refill_per_s=0.0)
        self.assertTrue(g.throttle("Example.COM"))
        # The SAME host in a different case / with surrounding whitespace shares the
        # one bucket already spent above -- not a fresh budget.
        self.assertFalse(g.throttle("example.com"))
        self.assertFalse(g.throttle("  EXAMPLE.COM  "))

    def test_empty_and_whitespace_only_host_share_one_bucket(self) -> None:
        g = HostRateGovernor(capacity=1, min_interval_s=0.0, refill_per_s=0.0)
        self.assertTrue(g.throttle(""))
        self.assertFalse(g.throttle("   "))  # normalizes to the same "" key
        self.assertFalse(g.throttle(None))

    def test_unicode_host_normalized_consistently(self) -> None:
        g = HostRateGovernor(capacity=1, min_interval_s=0.0, refill_per_s=0.0)
        self.assertTrue(g.throttle("MÜNCHEN.de"))
        self.assertFalse(g.throttle("münchen.de"))  # same bucket, lowercased


class SharedGovernorResetTests(unittest.TestCase):
    """``reset_shared_governors`` is the process-boundary seam the suite depends on.

    The governors are process-lifetime singletons on purpose, so ~150 test modules sharing one
    interpreter all draw on the single 127.0.0.1 bucket. Measured: five modules spend 1012 tokens
    against a capacity of 700, which used to leave the later ones probing NOTHING — a vacuous pass,
    not a loud failure. Each of those modules now resets at its module boundary; these tests keep the
    seam working and keep the process-wide sharing it must not break.
    """

    def tearDown(self) -> None:
        # Never leave this test's own bookkeeping behind for the modules that follow.
        rate_limit.reset_shared_governors()

    def test_reset_hands_back_a_fresh_bucket(self) -> None:
        rate_limit.reset_shared_governors()
        gov = rate_limit.shared_governor(capacity=3, min_interval_s=0.0, refill_per_s=0.0)
        for _ in range(3):
            self.assertTrue(gov.throttle("app.example.com"))
        self.assertFalse(gov.throttle("app.example.com"))  # drained

        rate_limit.reset_shared_governors()
        fresh = rate_limit.shared_governor(capacity=3, min_interval_s=0.0, refill_per_s=0.0)
        self.assertIsNot(fresh, gov)
        self.assertEqual(fresh.remaining("app.example.com"), 3)
        self.assertTrue(fresh.throttle("app.example.com"))

    def test_without_a_reset_the_bucket_is_still_shared_process_wide(self) -> None:
        # The invariant the reset must NOT break: two callers with the same config share one bucket,
        # so concurrent hunts cannot multiply a host's budget by the worker count.
        rate_limit.reset_shared_governors()
        a = rate_limit.shared_governor(capacity=2, min_interval_s=0.0, refill_per_s=0.0)
        b = rate_limit.shared_governor(capacity=2, min_interval_s=0.0, refill_per_s=0.0)
        self.assertIs(a, b)
        self.assertTrue(a.throttle("shared.example.com"))
        self.assertTrue(b.throttle("shared.example.com"))
        self.assertFalse(a.throttle("shared.example.com"))  # b spent the second token

    def test_reset_clears_every_pool_and_config(self) -> None:
        rate_limit.reset_shared_governors()
        active = rate_limit.shared_governor(capacity=1, min_interval_s=0.0, refill_per_s=0.0)
        recon = rate_limit.shared_governor(capacity=1, min_interval_s=0.0, refill_per_s=0.0, pool="recon")
        self.assertIsNot(active, recon)  # separate pools, as shared_governor documents
        active.throttle("h")
        recon.throttle("h")
        rate_limit.reset_shared_governors()
        self.assertEqual(rate_limit.shared_governor(capacity=1, min_interval_s=0.0, refill_per_s=0.0).remaining("h"), 1)
        self.assertEqual(
            rate_limit.shared_governor(capacity=1, min_interval_s=0.0, refill_per_s=0.0, pool="recon").remaining("h"), 1)

    def test_active_layer_test_modules_reset_at_their_module_boundary(self) -> None:
        """The modules that spend this budget must each declare a setUpModule reset.

        Enforced mechanically because the failure mode is invisible: a module that forgets it does
        not fail, it silently stops sending probes. If a new module starts driving the active layer
        against a loopback fixture, add the reset (and add it here).
        """
        import ast

        spenders = (
            "test_active_verify_service.py",
            "test_bounty_progress.py",
            "test_campaign_active_honesty.py",
            "test_cvss_confirmation.py",
            "test_web_scan_service.py",
        )
        for name in spenders:
            with self.subTest(module=name):
                tree = ast.parse((BACKEND_DIR / name).read_text(encoding="utf-8"))
                setup = next(
                    (node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name == "setUpModule"),
                    None,
                )
                self.assertIsNotNone(setup, f"{name} drives the active layer but has no setUpModule")
                calls = [
                    n.func.attr for n in ast.walk(setup)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                ]
                self.assertIn("reset_shared_governors", calls,
                              f"{name}'s setUpModule must call rate_limit.reset_shared_governors()")


if __name__ == "__main__":
    unittest.main()
