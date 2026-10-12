"""Debian desktop/CLI runtime path and OCR command discovery checks."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import document_ingest  # noqa: E402
import gn_cli  # noqa: E402
import greyiq_api  # noqa: E402


class FrozenLinuxRuntimeDirTests(unittest.TestCase):
    def test_frozen_linux_uses_xdg_data_home_for_cli_and_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xdg_home = root / "user-data"
            expected = xdg_home / "greyiq" / "runtime"
            with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(xdg_home)}, clear=True), \
                    mock.patch.object(sys, "platform", "linux"), \
                    mock.patch.object(sys, "frozen", True, create=True):
                for module in (gn_cli, greyiq_api):
                    with self.subTest(module=module.__name__):
                        self.assertEqual(module._resolve_runtime_dir(root / "read-only-bundle"), expected)

    def test_frozen_linux_defaults_to_home_data_and_ignores_relative_xdg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            expected = home / ".local" / "share" / "greyiq" / "runtime"
            with mock.patch.dict(os.environ, {"XDG_DATA_HOME": "relative-data"}, clear=True), \
                    mock.patch.object(Path, "home", return_value=home), \
                    mock.patch.object(sys, "platform", "linux"), \
                    mock.patch.object(sys, "frozen", True, create=True):
                for module in (gn_cli, greyiq_api):
                    with self.subTest(module=module.__name__):
                        self.assertEqual(module._resolve_runtime_dir(Path(tmp) / "bundle"), expected)

    def test_explicit_runtime_dir_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            explicit = root / "operator-runtime"
            with mock.patch.dict(os.environ, {
                "GREYIQ_RUNTIME_DIR": str(explicit),
                "XDG_DATA_HOME": str(root / "user-data"),
            }, clear=True), mock.patch.object(sys, "platform", "linux"), \
                    mock.patch.object(sys, "frozen", True, create=True):
                for module in (gn_cli, greyiq_api):
                    with self.subTest(module=module.__name__):
                        self.assertEqual(module._resolve_runtime_dir(root / "bundle"), explicit)

    def test_source_and_non_linux_frozen_keep_project_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            expected = project / "runtime"
            with mock.patch.dict(os.environ, {}, clear=True):
                for platform, frozen in (("linux", False), ("win32", True)):
                    with mock.patch.object(sys, "platform", platform), \
                            mock.patch.object(sys, "frozen", frozen, create=True):
                        for module in (gn_cli, greyiq_api):
                            with self.subTest(platform=platform, frozen=frozen, module=module.__name__):
                                self.assertEqual(module._resolve_runtime_dir(project), expected)


class TesseractDiscoveryTests(unittest.TestCase):
    def test_finds_tesseract_on_path_without_override(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(document_ingest.shutil, "which", return_value="/usr/bin/tesseract"):
            self.assertEqual(document_ingest._find_tesseract_cmd(), "/usr/bin/tesseract")

    def test_explicit_command_on_path_takes_precedence(self) -> None:
        def which(command: str) -> str | None:
            return {"custom-tesseract": "/opt/ocr/bin/custom-tesseract", "tesseract": "/usr/bin/tesseract"}.get(command)

        with mock.patch.dict(os.environ, {"TESSERACT_CMD": "custom-tesseract"}, clear=True), \
                mock.patch.object(document_ingest.shutil, "which", side_effect=which):
            self.assertEqual(document_ingest._find_tesseract_cmd(), "/opt/ocr/bin/custom-tesseract")

    def test_missing_tesseract_remains_unavailable(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(document_ingest.shutil, "which", return_value=None), \
                mock.patch.object(document_ingest, "WINDOWS_TESSERACT_CANDIDATES", ()):
            self.assertIsNone(document_ingest._find_tesseract_cmd())


if __name__ == "__main__":
    unittest.main()
