"""AI steering for XSS + SSRF: the brain names the params it judges reflect input (XSS) or take a URL
the server fetches (SSRF); those are tried FIRST by the respective checks within their small cap. The
brain supplies NAMES ONLY (a name can't carry a payload) — the deterministic checks supply the payload
and own every confirmation."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hunt_brain  # noqa: E402
from bughunter.active_verify_service import _candidate_params  # noqa: E402


class CandidatePriorityTests(unittest.TestCase):
    def test_priority_names_are_tried_first_within_the_cap(self) -> None:
        out = _candidate_params("https://t/?a=1", ["b", "c"], ("q",), 3, priority=["webhook", "image_url"])
        self.assertEqual(out, ["webhook", "image_url", "a"])   # priority first, then the live URL param, capped at 3

    def test_no_priority_is_unchanged(self) -> None:
        self.assertEqual(_candidate_params("https://t/?a=1", ["b"], ("q",), 3), ["a", "b"])

    def test_priority_deduped_against_url_and_extra(self) -> None:
        out = _candidate_params("https://t/?url=x", ["url"], (), 4, priority=["url", "webhook"])
        self.assertEqual(out, ["url", "webhook"])              # 'url' appears once despite being in all three


class BrainParamSelectionTests(unittest.TestCase):
    def _validate(self, parsed: dict) -> tuple:
        return hunt_brain._validate_plan(parsed, {"endpoints": ["https://t/x"], "params": []})

    def test_ssrf_and_xss_params_are_names_only(self) -> None:
        _, _, _, ssrf, xss = self._validate({
            "ssrf_params": ["image_url", "webhook", "https://evil.com/x", "<script>alert(1)</script>", "a b"],
            "xss_params": ["search", "q", "http://x", "'; DROP"]})
        self.assertEqual(ssrf, ["image_url", "webhook"])       # the URL, payload, and spaced value are rejected
        self.assertEqual(xss, ["search", "q"])

    def test_non_list_values_coerced_safely(self) -> None:
        # a hijacked model returning a scalar must not crash or leak
        _, _, _, ssrf, xss = self._validate({"ssrf_params": 5, "xss_params": True})
        self.assertEqual((ssrf, xss), ([], []))

    def test_empty_plan_has_the_fields(self) -> None:
        plan = hunt_brain._empty_plan()
        self.assertEqual(plan["ssrf_params"], [])
        self.assertEqual(plan["xss_params"], [])

    def test_names_capped(self) -> None:
        _, _, _, ssrf, _ = self._validate({"ssrf_params": [f"p{i}" for i in range(40)]})
        self.assertLessEqual(len(ssrf), 12)


class CheckSignaturesAcceptPriorityTests(unittest.TestCase):
    def test_xss_and_ssrf_checks_accept_priority_without_crashing(self) -> None:
        # the priority kwarg is threaded end-to-end; a param-less URL with a priority name is a clean
        # no-op path (no network here — we only assert the signatures accept it)
        import inspect
        from bughunter import active_verify_service as avs, oob_service
        for fn in (avs._check_reflected_xss, avs._check_reflected_xss_context):
            self.assertIn("priority", inspect.signature(fn).parameters)
        self.assertIn("priority", inspect.signature(oob_service.confirm_blind_ssrf).parameters)
        self.assertIn("xss_params", inspect.signature(avs.verify_active).parameters)


if __name__ == "__main__":
    unittest.main()
