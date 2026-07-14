"""Tests for the v2 hunt reproduction-stability check on reverify_finding: re-running the
same scope-gated probe N times and reporting how consistently each finding re-confirms
(a flaky WAF/timing false-positive won't confirm every pass). Operator-triggered, benign
(idempotent GETs), bounded — verify_active is mocked so no network is touched."""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


class _Stub:
    _active_scope_for = api.GreyIQRuntime._active_scope_for
    _compact_active = staticmethod(api.GreyIQRuntime._compact_active)
    reverify_finding = api.GreyIQRuntime.reverify_finding

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.bounty_runs: dict = {}


def _result(status: str):
    return {"title": "Reflected XSS", "severity": "high", "rule_id": "active.xss",
            "_active_class_hint": "xss", "proof_evidence": {},
            "_active_proof": {"status": status, "observed_result": "reflected", "control_result": "plain too"}}


def _pass(status: str, requests_used: int = 4):
    return ([_result(status)], {"in_scope": True, "host": "in-scope.example", "requests_used": requests_used})


class StabilityTests(unittest.TestCase):
    def _reverify(self, side_effect, passes):
        with mock.patch.object(api.bounty_active_verify, "verify_active", side_effect=side_effect):
            return _Stub().reverify_finding(api.ReverifyRequest(
                url="https://in-scope.example/x?q=1", scope="in-scope.example",
                authorized=True, stability_passes=passes))

    def test_stable_finding_confirms_every_pass(self):
        out = self._reverify([_pass("confirmed"), _pass("confirmed"), _pass("confirmed")], passes=3)
        self.assertTrue(out["ok"])
        self.assertEqual(out["stability_passes"], 3)
        st = out["findings"][0]["stability"]
        self.assertEqual((st["passes"], st["of"], st["stable"]), (3, 3, True))
        self.assertEqual(out["requests_used"], 12)  # summed across all passes

    def test_flaky_finding_is_flagged_unstable(self):
        # Confirms on pass 1 and 3 but not 2 -> 2/3, not stable.
        out = self._reverify([_pass("confirmed"), _pass("candidate"), _pass("confirmed")], passes=3)
        st = out["findings"][0]["stability"]
        self.assertEqual((st["passes"], st["of"], st["stable"]), (2, 3, False))

    def test_single_pass_adds_no_stability_field(self):
        out = self._reverify([_pass("confirmed")], passes=1)
        self.assertTrue(out["ok"])
        self.assertNotIn("stability", out["findings"][0])

    def test_extra_pass_exception_is_nonfatal(self):
        # First pass confirms; the second pass raises — the base result must still return.
        def side(*a, **k):
            if not hasattr(side, "n"):
                side.n = 0
            side.n += 1
            if side.n == 1:
                return _pass("confirmed")
            raise RuntimeError("network blip")
        out = self._reverify(side, passes=3)
        self.assertTrue(out["ok"])
        st = out["findings"][0]["stability"]
        # Only the first pass counted before the blip aborted the extra passes.
        self.assertEqual(st["passes"], 1)


if __name__ == "__main__":
    unittest.main()
