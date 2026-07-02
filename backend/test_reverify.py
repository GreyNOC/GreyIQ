"""Tests for the dashboard's on-demand re-probe (GreyIQRuntime.reverify_finding).

The wrapper's own guarantees are what's new here (verify_active itself is covered by
test_active_verify_service): it fails closed without authorization, refuses an
out-of-scope URL (via the fail-closed host_in_active_scope gate, which does NO network),
and compacts verify_active's results into the shape the drawer renders. reverify_finding
touches no instance state, so it's exercised as an unbound call on a dummy self."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


def _call(**kw):
    request = api.ReverifyRequest(**kw)
    return api.GreyIQRuntime.reverify_finding(object(), request)


class ReverifyGateTests(unittest.TestCase):
    def test_refuses_when_not_authorized(self) -> None:
        out = _call(url="https://in-scope.example/x", scope="in-scope.example", authorized=False)
        self.assertFalse(out["ok"])
        self.assertIn("authorized", out["error"].lower())

    def test_out_of_scope_url_is_refused_without_network(self) -> None:
        # host_in_active_scope is checked FIRST (no DNS), so an out-of-scope host returns
        # in_scope=False before any request is made — safe to assert in CI with no network.
        out = _call(url="https://attacker.invalid/x", scope="in-scope.example", authorized=True)
        self.assertFalse(out["ok"])
        self.assertFalse(out["in_scope"])

    def test_empty_url_refused(self) -> None:
        out = _call(url="   ", scope="in-scope.example", authorized=True)
        self.assertFalse(out["ok"])


class ReverifyCompactTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = api.bounty_active_verify.verify_active

    def tearDown(self) -> None:
        api.bounty_active_verify.verify_active = self._orig

    def test_compacts_active_findings(self) -> None:
        # Stub verify_active so no network runs; assert the wrapper flattens _active_proof
        # into the drawer's flat shape and counts confirmed correctly.
        def fake(url, findings, **kw):
            results = [
                {"title": "Reflected XSS", "severity": "high", "rule_id": "xss-reflected",
                 "_active_class_hint": "xss",
                 "_active_proof": {"status": "confirmed", "method": "GET",
                                   "observed_result": "marker reflected", "control_result": "no marker",
                                   "evidence": "<marker>", "limitations": ""}},
                {"title": "CORS", "severity": "low", "rule_id": "cors", "_active_class_hint": "cors",
                 "_active_proof": {"status": "candidate", "method": "GET", "observed_result": "acao *"}},
            ]
            meta = {"in_scope": True, "host": "in-scope.example", "requests_used": 7, "rate_limited": False, "verified_classes": ["xss"]}
            return results, meta

        api.bounty_active_verify.verify_active = fake
        out = _call(url="https://in-scope.example/x", scope="in-scope.example", authorized=True)
        self.assertTrue(out["ok"])
        self.assertTrue(out["in_scope"])
        self.assertEqual(out["host"], "in-scope.example")
        self.assertEqual(out["requests_used"], 7)
        self.assertEqual(out["confirmed"], 1)
        self.assertEqual(len(out["findings"]), 2)
        first = out["findings"][0]
        self.assertEqual(first["status"], "confirmed")
        self.assertEqual(first["observed"], "marker reflected")
        self.assertEqual(first["control"], "no marker")
        self.assertEqual(first["class_hint"], "xss")

    def test_out_of_scope_meta_surfaces_reason(self) -> None:
        def fake(url, findings, **kw):
            return [], {"in_scope": False, "host": "x", "requests_used": 0, "rate_limited": False,
                        "skipped_reason": "'x' was not named in the hunt scope"}

        api.bounty_active_verify.verify_active = fake
        out = _call(url="https://x/y", scope="x", authorized=True)
        self.assertFalse(out["ok"])
        self.assertFalse(out["in_scope"])
        self.assertIn("scope", out["error"].lower())


if __name__ == "__main__":
    unittest.main()
