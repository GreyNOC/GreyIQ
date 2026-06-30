"""Tests for the engagement .zip bundle (download-everything)."""
from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bundle  # noqa: E402


class BundleFilesTests(unittest.TestCase):
    def test_bundles_explicit_files_with_arcnames(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "a.md").write_text("report", encoding="utf-8")
            (tdp / "b.json").write_text("{}", encoding="utf-8")
            (tdp / "shot.png").write_bytes(b"PNG")
            out = tdp / "out.zip"
            res = bundle.bundle_files(
                [("a.md", tdp / "a.md"), ("b.json", tdp / "b.json"), ("screenshots/shot.png", tdp / "shot.png")], out)
            self.assertTrue(res["ok"])
            self.assertEqual(res["file_count"], 3)
            with zipfile.ZipFile(out) as zf:
                self.assertEqual(set(zf.namelist()), {"a.md", "b.json", "screenshots/shot.png"})

    def test_missing_files_are_skipped_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "a.md").write_text("x", encoding="utf-8")
            out = tdp / "out.zip"
            res = bundle.bundle_files([("a.md", tdp / "a.md"), ("gone.md", tdp / "nope.md")], out)
            self.assertTrue(res["ok"])
            self.assertEqual(res["file_count"], 1)
            self.assertIn("gone.md", res["skipped"])

    def test_empty_bundle_is_not_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.zip"
            res = bundle.bundle_files([("gone", Path(td) / "nope")], out)
            self.assertFalse(res["ok"])
            self.assertFalse(out.exists())  # no empty zip left behind


class BundleDirectoryTests(unittest.TestCase):
    def test_bundles_a_tree_relative_to_folder_and_skips_caches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "campaign-acme"
            (src / "targets").mkdir(parents=True)
            (src / "CAMPAIGN.md").write_text("index", encoding="utf-8")
            (src / "targets" / "t1.md").write_text("t1", encoding="utf-8")
            (src / "__pycache__").mkdir()
            (src / "__pycache__" / "junk.pyc").write_bytes(b"junk")
            out = Path(td) / "camp.zip"
            res = bundle.bundle_directory(src, out)
            self.assertTrue(res["ok"])
            with zipfile.ZipFile(out) as zf:
                names = set(zf.namelist())
            self.assertIn("campaign-acme/CAMPAIGN.md", names)        # arcname rooted at the folder
            self.assertIn("campaign-acme/targets/t1.md", names)
            self.assertFalse(any("__pycache__" in n for n in names))  # cache dir excluded

    def test_not_a_directory_errors(self) -> None:
        res = bundle.bundle_directory("/definitely/not/here", "/tmp/x.zip")
        self.assertFalse(res["ok"])


if __name__ == "__main__":
    unittest.main()
