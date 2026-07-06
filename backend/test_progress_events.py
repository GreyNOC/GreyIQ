"""Tests for the app-wide (cross-run) live event stream in bughunter.progress.

Covers the global ring's cursor semantics (a client's absolute ``after`` cursor only ever
returns events it hasn't seen, and never desyncs once the ring wraps) and that
``add_findings`` emits a ``finding_confirmed`` event only for confirmed findings.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import progress  # noqa: E402


class GlobalEventStreamTests(unittest.TestCase):
    def setUp(self) -> None:
        # Reset the module-global ring so tests are order-independent.
        with progress._lock:
            progress._global_events.clear()
            progress._global_base_seq = 0

    def test_tail_cursor_returns_only_new_events(self) -> None:
        progress.global_log("report_ready", {"a": 1})
        first = progress.global_tail(0)
        self.assertEqual(first["count"], 1)
        self.assertEqual(len(first["events"]), 1)
        self.assertEqual(first["events"][0]["kind"], "report_ready")
        # A cursor at the current count returns nothing new.
        self.assertEqual(progress.global_tail(first["count"])["events"], [])
        progress.global_log("submitted", {"b": 2})
        nxt = progress.global_tail(first["count"])
        self.assertEqual(len(nxt["events"]), 1)
        self.assertEqual(nxt["events"][0]["kind"], "submitted")
        self.assertEqual(nxt["count"], 2)

    def test_ring_trims_but_cursor_stays_stable(self) -> None:
        cap = progress._MAX_GLOBAL_EVENTS
        for i in range(cap + 10):
            progress.global_log("finding_confirmed", {"i": i})
        tail = progress.global_tail(0)
        # Ring is capped; count reflects the true monotonic total, not the buffer length.
        self.assertEqual(len(tail["events"]), cap)
        self.assertEqual(tail["count"], cap + 10)
        # A stale cursor (before the trim point) still yields the retained tail and the true count.
        self.assertEqual(progress.global_tail(5)["count"], cap + 10)
        self.assertEqual(len(progress.global_tail(5)["events"]), cap)

    def test_bad_after_cursor_is_tolerated(self) -> None:
        progress.global_log("report_ready", {})
        # A non-integer cursor must not raise — it falls back to "from the start".
        self.assertEqual(progress.global_tail("junk")["count"], 1)

    def test_add_findings_emits_only_confirmed(self) -> None:
        run_id = "test-run-events"
        progress.start_run(run_id)
        progress.set_targets(run_id, ["https://example.com"])
        before = progress.global_tail(0)["count"]
        progress.add_findings(run_id, "https://example.com", [
            {"ref": "R1", "title": "Reflected XSS", "severity": "high", "class_id": "xss",
             "proof_status": "confirmed", "location": "https://example.com/?q=1"},
            {"ref": "R2", "title": "Missing header", "severity": "low", "class_id": "headers",
             "proof_status": "candidate"},
        ])
        after = progress.global_tail(before)
        self.assertEqual(len(after["events"]), 1)  # only the confirmed finding
        ev = after["events"][0]
        self.assertEqual(ev["kind"], "finding_confirmed")
        self.assertEqual(ev["payload"]["ref"], "R1")
        self.assertEqual(ev["payload"]["run_id"], run_id)
        self.assertEqual(ev["payload"]["severity"], "high")

    def test_add_findings_without_confirmed_emits_nothing(self) -> None:
        run_id = "test-run-events-2"
        progress.start_run(run_id)
        before = progress.global_tail(0)["count"]
        progress.add_findings(run_id, "t", [
            {"ref": "R1", "severity": "medium", "proof_status": "candidate"},
        ])
        self.assertEqual(progress.global_tail(before)["events"], [])


if __name__ == "__main__":
    unittest.main()
