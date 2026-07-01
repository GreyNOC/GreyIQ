"""Tests for bounty._resolve_output_dir's containment (shared by agent_redteam.py too).

Regression coverage for a confirmed medium-severity finding: a client-supplied
output_dir accepted ANY absolute path with no containment check and auto-created a
brand-new, multi-level directory tree there via mkdir(parents=True) -- letting an
authenticated caller make the server create directories (and drop server-named
report files into them) anywhere the process has write access, e.g. a startup or
scheduled-task directory that doesn't exist yet.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.agent_redteam import _resolve_output_dir as redteam_resolve_output_dir  # noqa: E402
from bughunter.bounty import _resolve_output_dir  # noqa: E402


class ResolveOutputDirTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.default_reports_dir = self.root / "reports"
        self.default_reports_dir.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_no_output_dir_uses_the_default(self) -> None:
        self.assertEqual(_resolve_output_dir(None, self.default_reports_dir), self.default_reports_dir.resolve())
        self.assertEqual(_resolve_output_dir("", self.default_reports_dir), self.default_reports_dir.resolve())
        self.assertEqual(_resolve_output_dir("   ", self.default_reports_dir), self.default_reports_dir.resolve())

    def test_existing_directory_is_used_as_is(self) -> None:
        existing = self.root / "my-existing-folder"
        existing.mkdir()
        self.assertEqual(_resolve_output_dir(str(existing), self.default_reports_dir), existing.resolve())

    def test_new_leaf_folder_inside_an_existing_parent_is_created(self) -> None:
        # The legitimate "put my reports in a new subfolder of somewhere I already
        # have" UX must keep working -- only ONE new level is being created here.
        new_leaf = self.root / "brand-new-subfolder"
        self.assertFalse(new_leaf.exists())
        result = _resolve_output_dir(str(new_leaf), self.default_reports_dir)
        self.assertEqual(result, new_leaf.resolve())
        self.assertTrue(new_leaf.is_dir())

    def test_multi_level_new_tree_falls_back_to_default_instead_of_being_created(self) -> None:
        # The actual fix: a path whose PARENT also doesn't exist yet must never be
        # auto-vivified (mkdir(parents=True)) -- that's the write-anywhere-including-
        # never-existed-before-paths primitive the finding flagged (e.g. planting a
        # brand-new Startup/scheduled-task directory tree).
        deeply_nested = self.root / "does-not-exist-1" / "does-not-exist-2" / "does-not-exist-3"
        result = _resolve_output_dir(str(deeply_nested), self.default_reports_dir)
        self.assertEqual(result, self.default_reports_dir.resolve())
        self.assertFalse(deeply_nested.parent.exists())
        self.assertFalse((self.root / "does-not-exist-1").exists())

    def test_agent_redteam_reuses_the_same_containment(self) -> None:
        deeply_nested = self.root / "nope-1" / "nope-2"
        result = redteam_resolve_output_dir(str(deeply_nested), self.default_reports_dir)
        self.assertEqual(result, self.default_reports_dir.resolve())
        self.assertFalse((self.root / "nope-1").exists())


if __name__ == "__main__":
    unittest.main()
