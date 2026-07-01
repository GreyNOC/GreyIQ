"""Tests for the active-layer per-host request governor."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

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


if __name__ == "__main__":
    unittest.main()
