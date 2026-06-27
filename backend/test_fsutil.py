"""Tests for the long-path-safe filesystem helpers."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import fsutil  # noqa: E402


class FsUtilTests(unittest.TestCase):
    def test_round_trip_creates_parents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a" / "b" / "c.txt"
            fsutil.write_text_safe(target, "hello")
            self.assertEqual(fsutil.read_text_safe(target), "hello")

    def test_unicode_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "u.txt"
            fsutil.write_text_safe(target, "arrow -> → done")
            self.assertIn("→", fsutil.read_text_safe(target))

    @unittest.skipUnless(os.name == "nt", "MAX_PATH only applies on Windows")
    def test_long_path_round_trip(self) -> None:
        # A short directory + a very long filename pushes the file path past
        # MAX_PATH (260) while keeping the dir short enough for stdlib cleanup.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "d" / ("file" + "y" * 215 + ".txt")
            self.assertGreater(len(str(target)), 260)
            fsutil.write_text_safe(target, "long-path payload")
            try:
                self.assertEqual(fsutil.read_text_safe(target), "long-path payload")
            finally:
                # stdlib rmtree can't delete the >260 file; remove it via the
                # extended prefix so the TemporaryDirectory cleanup succeeds.
                os.remove(fsutil._extended_path(target))


if __name__ == "__main__":
    unittest.main()
