"""Local scan inputs must not silently turn into network or linked paths."""

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

from bughunter.code_scanner import walker  # noqa: E402
from bughunter.code_scanner import scanner  # noqa: E402
from bughunter.code_scanner.model import ScanRequest, ScanTargetType  # noqa: E402
from bughunter.code_scanner.sources import local_guard  # noqa: E402
from bughunter.code_scanner.sources.archive import ArchiveSource  # noqa: E402
from bughunter.code_scanner.sources.git_local import LocalGitSource  # noqa: E402
from bughunter.code_scanner.sources.local import LocalPathSource  # noqa: E402


class LocalScanPathGuardTests(unittest.TestCase):
    def test_network_and_device_syntax_refused_before_filesystem_access(self) -> None:
        paths = (
            r"\\server\share\code",
            "//server/share/code",
            r"\\?\UNC\server\share\code",
            r"\\?\C:\code",
            r"\\.\C:\code",
            r"\??\UNC\server\share\code",
            "file://server/share/code",
        )
        for path in paths:
            with self.subTest(path=path):
                with (
                    mock.patch.object(local_guard.os, "lstat", side_effect=AssertionError("filesystem touched")),
                    mock.patch.object(Path, "resolve", side_effect=AssertionError("path resolved")),
                ):
                    with self.assertRaisesRegex(ValueError, "network and device paths"):
                        local_guard.resolve_local_scan_path(path)

    def test_all_local_sources_share_network_input_guard(self) -> None:
        for source in (LocalPathSource, LocalGitSource, ArchiveSource):
            with self.subTest(source=source.__name__):
                with mock.patch.object(local_guard.os, "lstat", side_effect=AssertionError("filesystem touched")):
                    with self.assertRaisesRegex(ValueError, "network and device paths"):
                        source(r"\\server\share\target")._prepare()

    @unittest.skipUnless(os.name == "nt", "Windows mapped drives only")
    def test_mapped_drive_refused_before_path_lookup(self) -> None:
        with (
            mock.patch.object(local_guard, "_windows_drive_type", return_value=4) as drive_type,
            mock.patch.object(local_guard.os, "lstat", side_effect=AssertionError("filesystem touched")),
        ):
            with self.assertRaisesRegex(ValueError, "mapped network drives"):
                local_guard.resolve_local_scan_path(r"Q:\code")
        drive_type.assert_called_once_with("Q:\\")

    def test_reparse_component_refused_before_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            linked = root / "linked"
            linked.mkdir()
            target = linked / "file.py"
            target.write_text("safe", encoding="utf-8")
            real_check = local_guard.is_link_or_reparse

            def fake_check(path: Path) -> bool:
                return path == linked or real_check(path)

            with (
                mock.patch.object(local_guard, "is_link_or_reparse", side_effect=fake_check),
                mock.patch.object(Path, "resolve", side_effect=AssertionError("path resolved")),
            ):
                with self.assertRaisesRegex(ValueError, "symlink or junction"):
                    local_guard.resolve_local_scan_path(target)

    def test_local_git_refuses_linked_git_directory_before_git_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".git").mkdir()
            real_check = local_guard.is_link_or_reparse

            def fake_check(path: Path) -> bool:
                return path == root / ".git" or real_check(path)

            with (
                mock.patch("bughunter.code_scanner.sources.git_local.is_link_or_reparse", side_effect=fake_check),
                mock.patch("subprocess.run") as git_process,
            ):
                with self.assertRaisesRegex(ValueError, "in-tree .git"):
                    LocalGitSource(str(root))._prepare()
            git_process.assert_not_called()

    def test_local_git_refuses_gitfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".git").write_text("gitdir: \\\\server\\share\\objects", encoding="utf-8")
            with mock.patch("subprocess.run") as git_process:
                with self.assertRaisesRegex(ValueError, "in-tree .git"):
                    LocalGitSource(str(root))._prepare()
            git_process.assert_not_called()

    def test_local_git_scans_without_launching_git(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".git").mkdir()
            (root / "app.py").write_text("safe = True\n", encoding="utf-8")
            with mock.patch("subprocess.run") as git_process:
                source = LocalGitSource(str(root))
                self.assertEqual(source.root, root.resolve())
                self.assertEqual(source.git_metadata, {})
            git_process.assert_not_called()

    def test_configured_unc_base_refused_before_network_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "safe.py").write_text("safe = True\n", encoding="utf-8")
            original_lstat = os.lstat
            original_resolve = Path.resolve

            def checked_lstat(path, *args, **kwargs):
                self.assertFalse(str(path).startswith(r"\\server"), "UNC path queried")
                return original_lstat(path, *args, **kwargs)

            def checked_resolve(path, *args, **kwargs):
                self.assertFalse(str(path).startswith(r"\\server"), "UNC path resolved")
                return original_resolve(path, *args, **kwargs)

            settings = mock.Mock(code_scan_base_path=r"\\server\share\base")
            with (
                mock.patch.object(scanner, "get_settings", return_value=settings),
                mock.patch.object(local_guard.os, "lstat", side_effect=checked_lstat),
                mock.patch.object(Path, "resolve", checked_resolve),
            ):
                with self.assertRaisesRegex(ValueError, "network and device paths"):
                    scanner.scan_target(ScanRequest(target=str(root), target_type=ScanTargetType.PATH))

    def test_walker_skips_reparse_directories_and_file_links(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "safe.py").write_text("safe = True\n", encoding="utf-8")
            (root / "linked.py").write_text("outside = True\n", encoding="utf-8")
            (root / "linked_dir").mkdir()
            (root / "linked_dir" / "outside.py").write_text("outside = True\n", encoding="utf-8")
            real_check = local_guard.is_link_or_reparse
            blocked = {root / "linked.py", root / "linked_dir"}

            def fake_check(path: Path) -> bool:
                return path in blocked or real_check(path)

            with mock.patch.object(walker, "is_link_or_reparse", side_effect=fake_check):
                files, stats = walker.walk_collect(
                    root, max_bytes_per_file=1024, max_total_bytes=4096, max_files=10
                )
            self.assertEqual([item.relative_path for item in files], ["safe.py"])
            self.assertEqual(stats.files_skipped, 2)
            self.assertTrue(all("symlink or junction" in example for example in stats.skipped_examples))

    def test_actual_file_symlink_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside.txt"
            outside.write_text("secret = 'outside'\n", encoding="utf-8")
            scan_root = root / "scan"
            scan_root.mkdir()
            linked = scan_root / "linked.py"
            try:
                linked.symlink_to(outside)
            except OSError:
                self.skipTest("Creating symlinks is unavailable on this host")
            with self.assertRaisesRegex(ValueError, "symlink or junction"):
                LocalPathSource(str(linked))._prepare()
            files, stats = walker.walk_collect(
                scan_root, max_bytes_per_file=1024, max_total_bytes=4096, max_files=10
            )
            self.assertEqual(files, [])
            self.assertEqual(stats.files_skipped, 1)


if __name__ == "__main__":
    unittest.main()
