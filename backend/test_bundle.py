"""Tests for the engagement .zip bundle (download-everything)."""
from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

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


class AddSizeCapTests(unittest.TestCase):
    """Direct unit tests of bundle._add's two size-cap branches and the per-file
    OSError swallow -- previously only reachable by writing real 50MB/200MB files,
    so never exercised. Patches the module-level caps down to a few bytes instead."""

    def test_file_larger_than_max_file_bytes_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "big.bin"
            big.write_bytes(b"x" * 20)
            out = Path(td) / "out.zip"
            state = {"total": 0, "count": 0}
            skipped: list[str] = []
            with mock.patch.object(bundle, "_MAX_FILE_BYTES", 10):
                with zipfile.ZipFile(out, "w") as zf:
                    bundle._add(zf, "big.bin", big, state, skipped)
            self.assertEqual(state, {"total": 0, "count": 0})
            self.assertEqual(len(skipped), 1)
            self.assertIn("too large", skipped[0])
            self.assertIn("20 bytes", skipped[0])
            with zipfile.ZipFile(out) as zf:
                self.assertEqual(zf.namelist(), [])

    def test_total_cap_stops_admitting_further_files_but_keeps_earlier_ones(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f1 = Path(td) / "f1.bin"
            f1.write_bytes(b"a" * 8)
            f2 = Path(td) / "f2.bin"
            f2.write_bytes(b"b" * 5)
            out = Path(td) / "out.zip"
            state = {"total": 0, "count": 0}
            skipped: list[str] = []
            with mock.patch.object(bundle, "_MAX_TOTAL_BYTES", 10):
                with zipfile.ZipFile(out, "w") as zf:
                    bundle._add(zf, "f1.bin", f1, state, skipped)  # 0 + 8 <= 10 -> admitted
                    bundle._add(zf, "f2.bin", f2, state, skipped)  # 8 + 5 > 10 -> capped
            self.assertEqual(state, {"total": 8, "count": 1})
            self.assertEqual(len(skipped), 1)
            self.assertIn("archive size cap reached", skipped[0])
            with zipfile.ZipFile(out) as zf:
                self.assertEqual(zf.namelist(), ["f1.bin"])

    def test_stat_oserror_is_skipped_not_raised(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.zip"
            state = {"total": 0, "count": 0}
            skipped: list[str] = []
            ghost = Path(td) / "ghost.bin"  # never created -> .stat() raises OSError
            with zipfile.ZipFile(out, "w") as zf:
                bundle._add(zf, "ghost.bin", ghost, state, skipped)
            self.assertEqual(state, {"total": 0, "count": 0})
            self.assertEqual(skipped, ["ghost.bin"])

    def test_zf_write_oserror_is_skipped_state_not_advanced(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f1 = Path(td) / "f1.bin"
            f1.write_bytes(b"data")
            out = Path(td) / "out.zip"
            state = {"total": 0, "count": 0}
            skipped: list[str] = []
            with zipfile.ZipFile(out, "w") as zf:
                with mock.patch.object(zf, "write", side_effect=OSError("locked")):
                    bundle._add(zf, "f1.bin", f1, state, skipped)
            self.assertEqual(state, {"total": 0, "count": 0})
            self.assertEqual(skipped, ["f1.bin"])

    def test_bundle_files_end_to_end_respects_patched_total_cap(self) -> None:
        # Integration check: the cap genuinely plumbs through bundle_files, not just
        # the isolated _add unit tests above.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            f1 = tdp / "f1.bin"
            f1.write_bytes(b"a" * 8)
            f2 = tdp / "f2.bin"
            f2.write_bytes(b"b" * 5)
            out = tdp / "out.zip"
            with mock.patch.object(bundle, "_MAX_TOTAL_BYTES", 10):
                res = bundle.bundle_files([("f1.bin", f1), ("f2.bin", f2)], out)
            self.assertTrue(res["ok"])
            self.assertEqual(res["file_count"], 1)
            self.assertTrue(any("archive size cap reached" in s for s in res["skipped"]))


if __name__ == "__main__":
    unittest.main()
