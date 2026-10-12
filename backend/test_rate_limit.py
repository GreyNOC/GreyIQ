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


class GovernorSnapshotTests(unittest.TestCase):
    """``governor_snapshot`` is the only read path onto the live per-host buckets.

    It feeds an operator display, so two properties matter more than the numbers: it must RESERVE
    NOTHING (a panel refresh that spends or credits tokens would make the process-wide cap a
    function of how fast someone is watching), and it must never raise (the readout sits in front of
    a running hunt).
    """

    def setUp(self) -> None:
        rate_limit.reset_shared_governors()

    def tearDown(self) -> None:
        # The governors are process-lifetime singletons shared by the whole suite -- never leave
        # this module's synthetic pools behind. See reset_shared_governors().
        rate_limit.reset_shared_governors()

    def test_reports_each_live_bucket_with_its_pool_and_capacity(self) -> None:
        gov = rate_limit.shared_governor(capacity=5, min_interval_s=0.0, refill_per_s=0.0)
        gov.throttle("a.example.com")
        gov.throttle("a.example.com")
        gov.throttle("b.example.com")
        rows = rate_limit.governor_snapshot()
        self.assertEqual(rows, [
            {"pool": "", "host": "a.example.com", "tokens": 3, "capacity": 5},
            {"pool": "", "host": "b.example.com", "tokens": 4, "capacity": 5},
        ])

    def test_pools_are_reported_separately(self) -> None:
        # The recon crawl and the active prover are sized independently and must not be summed into
        # one misleading "this host has N left" figure on a panel.
        active = rate_limit.shared_governor(capacity=2, min_interval_s=0.0, refill_per_s=0.0)
        recon = rate_limit.shared_governor(capacity=9, min_interval_s=0.0, refill_per_s=0.0, pool="recon")
        active.throttle("shared.example.com")
        recon.throttle("shared.example.com")
        rows = {(r["pool"], r["host"]): r for r in rate_limit.governor_snapshot()}
        self.assertEqual(rows[("", "shared.example.com")]["capacity"], 2)
        self.assertEqual(rows[("recon", "shared.example.com")]["capacity"], 9)

    def test_empty_before_any_host_is_touched(self) -> None:
        # A governor exists but has no buckets yet: a host with a full, untouched budget has no row,
        # because the bucket is only created on first contact. Reporting it would be inventing a
        # host the process has never spoken to.
        rate_limit.shared_governor(capacity=4, min_interval_s=0.0, refill_per_s=0.0)
        self.assertEqual(rate_limit.governor_snapshot(), [])

    def test_agrees_with_remaining_for_the_same_host(self) -> None:
        # It reuses remaining()'s refill math rather than restating it; this is what pins that.
        gov = rate_limit.shared_governor(capacity=700, min_interval_s=0.0, refill_per_s=0.0)
        for _ in range(11):
            gov.throttle("agree.example.com")
        row = next(r for r in rate_limit.governor_snapshot() if r["host"] == "agree.example.com")
        self.assertEqual(row["tokens"], gov.remaining("agree.example.com"))

    def test_reserves_nothing_and_writes_nothing_back(self) -> None:
        gov = rate_limit.shared_governor(capacity=3, min_interval_s=0.0, refill_per_s=100.0)
        gov.throttle("h.example.com")
        before = dict(gov._buckets["h.example.com"])
        for _ in range(20):
            rate_limit.governor_snapshot()
        # The accrued refill is COMPUTED for the readout, never persisted: polling faster must not
        # hand the host tokens it has not waited for.
        self.assertEqual(dict(gov._buckets["h.example.com"]), before)
        # And nothing was spent either -- the two remaining sends are still there.
        self.assertTrue(gov.throttle("h.example.com"))

    def test_a_drained_bucket_reads_zero_not_a_negative_or_a_lie(self) -> None:
        gov = rate_limit.shared_governor(capacity=1, min_interval_s=0.0, refill_per_s=0.0)
        self.assertTrue(gov.throttle("drained.example.com"))
        self.assertFalse(gov.throttle("drained.example.com"))
        row = next(r for r in rate_limit.governor_snapshot() if r["host"] == "drained.example.com")
        self.assertEqual(row["tokens"], 0)

    def test_the_reported_tokens_grow_with_the_real_refill(self) -> None:
        import time
        gov = rate_limit.shared_governor(capacity=4, min_interval_s=0.0, refill_per_s=50.0)
        for _ in range(4):
            gov.throttle("refill.example.com")
        self.assertEqual(next(r for r in rate_limit.governor_snapshot()
                              if r["host"] == "refill.example.com")["tokens"], 0)
        time.sleep(0.06)  # 0.06s * 50/s = ~3 tokens
        self.assertGreater(next(r for r in rate_limit.governor_snapshot()
                                if r["host"] == "refill.example.com")["tokens"], 0)

    def test_never_exceeds_capacity_however_long_the_bucket_sat(self) -> None:
        gov = rate_limit.shared_governor(capacity=2, min_interval_s=0.0, refill_per_s=1000.0)
        gov.throttle("capped.example.com")
        # Backdate the bucket instead of sleeping: the uncapped sum would be enormous.
        with gov._lock:
            gov._buckets["capped.example.com"]["last_refill"] -= 60.0
        row = next(r for r in rate_limit.governor_snapshot() if r["host"] == "capped.example.com")
        self.assertEqual(row["tokens"], 2)

    def test_a_broken_governor_yields_a_short_list_not_an_exception(self) -> None:
        """Totality. The readout runs beside a live hunt, so it returns what it has and stops."""
        good = rate_limit.shared_governor(capacity=2, min_interval_s=0.0, refill_per_s=0.0)
        good.throttle("good.example.com")

        class _Exploding:
            capacity = 1
            refill_per_s = 0.0

            @property
            def _lock(self):
                raise RuntimeError("a governor that cannot be read must not kill the panel")

        with rate_limit._shared_lock:
            rate_limit._shared_governors[("broken", 1, 0.0, 0.0)] = _Exploding()  # type: ignore[assignment]
        rows = rate_limit.governor_snapshot()  # must not raise
        self.assertEqual([r["host"] for r in rows], ["good.example.com"])


if __name__ == "__main__":
    unittest.main()
