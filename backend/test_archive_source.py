"""Targeted tests for the archive zip-slip / tar-slip guard (ArchiveSource._safe_join).

An archive source ingests an UNTRUSTED uploaded archive; a hostile member name that
escapes the destination (traversal, absolute, drive, null byte) must be rejected before
anything is written. Tested directly, no real archive needed.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.code_scanner.sources.archive import ArchiveSource  # noqa: E402


class SafeJoinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.src = ArchiveSource("dummy.zip")  # construction doesn't open the file
        self._td = tempfile.TemporaryDirectory()
        self.dest = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_normal_member_resolves_under_dest(self) -> None:
        p = self.src._safe_join(self.dest, "src/app/main.py")
        self.assertTrue(p.is_relative_to(self.dest.resolve()))

    def test_traversal_members_refused(self) -> None:
        for m in ("../../etc/passwd", "../sibling", "a/../../escape", "deep/../../../out"):
            with self.assertRaises(ValueError):
                self.src._safe_join(self.dest, m)

    def test_absolute_members_refused(self) -> None:
        for m in ("/etc/passwd", "\\\\server\\share\\x", "/"):
            with self.assertRaises(ValueError):
                self.src._safe_join(self.dest, m)

    def test_empty_or_null_byte_members_refused(self) -> None:
        for m in ("", "bad\x00name", "\x00"):
            with self.assertRaises(ValueError):
                self.src._safe_join(self.dest, m)


if __name__ == "__main__":
    unittest.main()
