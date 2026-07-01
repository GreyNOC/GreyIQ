"""Tests for bughunter.scan_service's error branches (no existing dedicated test file
covered these -- only exercised indirectly, via happy-path, by test_jwt_exposure.py /
test_secret_rules.py). run_code_scan's documented contract is {"ok": False, "error": ...}
on bad input or a scan failure, never a raised exception.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import scan_service  # noqa: E402


class RunCodeScanErrorBranchTests(unittest.TestCase):
    def test_empty_target_returns_clean_error(self) -> None:
        res = scan_service.run_code_scan("")
        self.assertFalse(res["ok"])
        self.assertIn("error", res)

    def test_unknown_target_type_returns_clean_error_naming_valid_choices(self) -> None:
        res = scan_service.run_code_scan("/some/path", target_type="not-a-real-type")
        self.assertFalse(res["ok"])
        self.assertIn("not-a-real-type", res["error"])
        # The error must name at least one real, usable target_type so the caller can
        # self-correct (the message format is "Use one of: <sorted list>").
        self.assertIn("Use one of:", res["error"])

    def test_scan_target_exception_is_caught_not_raised(self) -> None:
        # A scanner-internal exception (corrupt repo, permission error mid-walk, a bug in
        # a rule) must surface as the documented {"ok": False, "error": ...} envelope,
        # never escape run_code_scan as a raised exception.
        orig = scan_service.scan_target

        def boom(request):
            raise RuntimeError("simulated scanner crash")
        scan_service.scan_target = boom
        try:
            res = scan_service.run_code_scan("/some/path")
        finally:
            scan_service.scan_target = orig
        self.assertFalse(res["ok"])
        self.assertIn("RuntimeError", res["error"])
        self.assertIn("simulated scanner crash", res["error"])
        self.assertEqual(res["target"], "/some/path")

    def test_real_scan_of_empty_directory_succeeds(self) -> None:
        # A genuine (not monkeypatched) scan_target call through an empty dir -- proves
        # the happy path still returns the documented {"ok": True, ...} shape.
        with tempfile.TemporaryDirectory() as tmp:
            res = scan_service.run_code_scan(tmp, target_type="path")
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["scan_type"], "code")
        self.assertEqual(res["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
