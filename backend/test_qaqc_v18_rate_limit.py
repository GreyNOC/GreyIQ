"""Regression tests for QA/QC v1.8 rate-limit findings.

Covers the HostRateGovernor burst-under-concurrency defect (rate_limit.py:61):
the throttle used to sleep min(wait, min_interval_s), which capped every
caller's wait at ONE interval no matter how far its reserved slot was in the
future, so concurrent callers on the same host all woke together and burst.
"""

import sys
import threading
import time
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from bughunter.rate_limit import HostRateGovernor


class HostRateGovernorConcurrencyTest(unittest.TestCase):
    def test_concurrent_callers_same_host_stay_spaced(self):
        """N threads hammering ONE host must have their sends spaced by at least
        min_interval_s (minus a small scheduling slack) — not all bunch up after
        a single interval. Fails pre-fix (sleep capped at one interval)."""
        min_interval = 0.2
        n = 5
        gov = HostRateGovernor(capacity=100, min_interval_s=min_interval, refill_per_s=0.0)

        send_times: list[float] = []
        times_lock = threading.Lock()
        start_barrier = threading.Barrier(n)

        def worker() -> None:
            # Release all threads together so they contend on the same host key.
            start_barrier.wait()
            ok = gov.throttle("target.example")
            t = time.monotonic()
            if ok:
                with times_lock:
                    send_times.append(t)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(len(send_times), n, "all reserved slots should have sent")
        send_times.sort()
        # Consecutive sends must respect the per-host floor. Allow a modest slack
        # for scheduler jitter, but far below a full interval so the pre-fix
        # collapse (gaps ~0) is caught.
        slack = min_interval * 0.5
        for earlier, later in zip(send_times, send_times[1:]):
            gap = later - earlier
            self.assertGreaterEqual(
                gap,
                min_interval - slack,
                f"consecutive sends spaced only {gap:.4f}s apart; "
                f"expected >= {min_interval - slack:.4f}s (burst collapse)",
            )

    def test_single_caller_not_delayed(self):
        """A lone caller never accrues >1 interval of reserved wait, so the first
        send should be effectively immediate even with the full-remainder sleep."""
        gov = HostRateGovernor(capacity=10, min_interval_s=0.2, refill_per_s=0.0)
        t0 = time.monotonic()
        self.assertTrue(gov.throttle("solo.example"))
        self.assertLess(time.monotonic() - t0, 0.2)


if __name__ == "__main__":
    unittest.main()
