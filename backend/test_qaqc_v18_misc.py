"""QA/QC v1.8 regression tests — misc-backend group.

Covers three verified defects, one per module:
  - hunt_trace.record_trace: top-level ``target`` field was stored raw, bypassing
    the module's URL redaction and leaking secrets into the append-only corpus.
  - code_scanner.scanner.scan_target: the code_scan_base_path containment lockdown
    only gated target_type == PATH, so a git_local target escaped to arbitrary paths.
  - hunt_loop._observations_digest / _dedup_key: read the nonexistent class_id/
    class_name keys, so the class the brain sees was always blank.

Every test is offline + deterministic and uses tempfile.TemporaryDirectory for any
runtime dir. Each FAILS before its fix and PASSES after.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hunt_trace, hunt_loop  # noqa: E402
from bughunter.code_scanner import scanner  # noqa: E402
from bughunter.code_scanner.model import ScanRequest, ScanTargetType  # noqa: E402


class TestHuntTraceTargetRedaction(unittest.TestCase):
    """hunt_trace.py:235 — the top-level target URL must be secret-redacted like every
    other URL in the record, not stored verbatim."""

    def test_target_query_secret_is_redacted(self):
        secret = "AAAA1234BBBB5678CCCC9012"
        target = f"https://app.acme.com/reset?access_token={secret}"
        with tempfile.TemporaryDirectory() as rt:
            ok = hunt_trace.record_trace(
                rt,
                program="acme",
                target=target,
                surface=None,
                plan=None,
                outcomes=[],
            )
            self.assertTrue(ok)
            line = (Path(rt) / "hunt_traces.jsonl").read_text(encoding="utf-8").strip()
            rec = json.loads(line)
            # The raw secret must NOT appear anywhere in the stored record.
            self.assertNotIn(secret, line)
            # The URL structure is preserved (host + param name kept, value stripped) —
            # confirming it was redacted, not simply dropped.
            self.assertIn("app.acme.com", rec["target"])
            self.assertNotIn(secret, rec["target"])


class TestScannerGitLocalContainment(unittest.TestCase):
    """scanner.py:42 — code_scan_base_path containment must also apply to git_local
    (an in-place local source), not only to target_type == PATH."""

    def _make_git_checkout(self, parent: Path, name: str) -> Path:
        repo = parent / name
        repo.mkdir(parents=True, exist_ok=True)
        (repo / ".git").mkdir()  # LocalGitSource only requires a .git entry to exist
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        return repo

    def test_git_local_outside_base_is_forbidden(self):
        with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as outside:
            base_path = Path(base).resolve()
            outside_repo = self._make_git_checkout(Path(outside).resolve(), "private-repo")
            prev = os.environ.get("GREYIQ_CODE_SCAN_BASE_PATH")
            os.environ["GREYIQ_CODE_SCAN_BASE_PATH"] = str(base_path)
            try:
                req = ScanRequest(target=str(outside_repo), target_type=ScanTargetType.GIT_LOCAL)
                # Before the fix this walked the out-of-base repo and returned a
                # ScanResult; now it must refuse.
                with self.assertRaises(scanner.ScanTargetForbidden):
                    scanner.scan_target(req)
            finally:
                if prev is None:
                    os.environ.pop("GREYIQ_CODE_SCAN_BASE_PATH", None)
                else:
                    os.environ["GREYIQ_CODE_SCAN_BASE_PATH"] = prev

    def test_git_local_inside_base_is_allowed(self):
        # Positive control: a git_local repo INSIDE the base path must still scan.
        with tempfile.TemporaryDirectory() as base:
            base_path = Path(base).resolve()
            inside_repo = self._make_git_checkout(base_path, "allowed-repo")
            prev = os.environ.get("GREYIQ_CODE_SCAN_BASE_PATH")
            os.environ["GREYIQ_CODE_SCAN_BASE_PATH"] = str(base_path)
            try:
                req = ScanRequest(target=str(inside_repo), target_type=ScanTargetType.GIT_LOCAL)
                result = scanner.scan_target(req)  # must not raise
                self.assertEqual(result.target_type, ScanTargetType.GIT_LOCAL)
            finally:
                if prev is None:
                    os.environ.pop("GREYIQ_CODE_SCAN_BASE_PATH", None)
                else:
                    os.environ["GREYIQ_CODE_SCAN_BASE_PATH"] = prev


class TestHuntLoopClassKeys(unittest.TestCase):
    """hunt_loop.py:65/55 — the digest and dedup key must read the real class keys
    (_active_class_hint / category), not the nonexistent class_id/class_name."""

    def _finding(self):
        # Shaped like active_verify_service._finding output: class lives on
        # _active_class_hint + category; there is NO class_id / class_name.
        return {
            "rule_id": "active.idor",
            "category": "idor",
            "_active_class_hint": "idor",
            "file_path": "https://api.acme.com/users/1",
            "_active_proof": {"status": "confirmed", "observed_result": "leaked"},
        }

    def test_digest_carries_real_class(self):
        digest = hunt_loop._observations_digest([self._finding()], {})
        # The class the brain sees must be the real hint, not a blank string.
        self.assertIn("idor", digest)

    def test_dedup_key_uses_real_class(self):
        key = hunt_loop._dedup_key(self._finding())
        # digit-normalized location; class component must be the real hint.
        self.assertTrue(key.startswith("idor|"))
        self.assertNotIn("None|", key)


if __name__ == "__main__":
    unittest.main()
