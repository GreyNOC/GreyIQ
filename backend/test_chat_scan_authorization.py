"""Chat scan commands must establish authorization and exact network scope."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import chat_commands  # noqa: E402


class ChatScanAuthorizationTests(unittest.TestCase):
    def test_non_scan_text_does_not_dispatch(self) -> None:
        with patch.object(chat_commands, "run_scan") as scan:
            self.assertIsNone(chat_commands.dispatch_authorized_scan_command("How does a scan work?"))
            scan.assert_not_called()

    def test_existing_scan_command_parser_is_unchanged(self) -> None:
        self.assertEqual(
            chat_commands.detect_scan_command("scan web https://example.com"),
            ("web", "https://example.com"),
        )

    def test_local_code_path_needs_no_network_grant(self) -> None:
        with patch.object(chat_commands, "run_code_scan", return_value={"ok": True}) as scan:
            self.assertEqual(
                chat_commands.dispatch_authorized_scan_command("scan code C:/work/src"),
                {"ok": True},
            )
            scan.assert_called_once_with("C:/work/src", "path")

    def test_local_git_suffix_is_still_a_local_path(self) -> None:
        with patch.object(chat_commands, "run_code_scan", return_value={"ok": True}) as scan:
            result = chat_commands.dispatch_authorized_scan_command("scan code C:/work/project.git")
        self.assertTrue(result["ok"])
        scan.assert_called_once_with("C:/work/project.git", "path")

    def test_network_scan_without_authorization_never_calls_scanner(self) -> None:
        for command in (
            "scan web https://app.example.com",
            "scan live https://app.example.com",
            "scan repo https://github.com/org/repo",
        ):
            with self.subTest(command=command), patch.object(chat_commands, "run_scan") as scan:
                result = chat_commands.dispatch_authorized_scan_command(command)
                self.assertFalse(result["ok"])
                self.assertIn("authorization", result["error"])
                scan.assert_not_called()

    def test_network_scan_without_exact_scope_never_calls_scanner(self) -> None:
        for command in (
            "scan web -y https://app.example.com",
            "scan web -y --scope https://app.example.com https://app.example.com",
            "scan web -y --scope *.example.com https://app.example.com",
            "scan live -y --scope app.example.com https://other.example.com",
            "scan web -y --scope example.com https://sub.example.com",
            "scan web -y --scope app.example.com --scope other.example.com https://app.example.com",
            "scan repo -y --scope github.com git@github.com:org/repo.git",
            "scan repo -y --scope github.com https://github.com/org/repo",
            "scan repo -y --scope https://github.com/org/other https://github.com/org/repo",
        ):
            with self.subTest(command=command), patch.object(chat_commands, "run_scan") as scan:
                result = chat_commands.dispatch_authorized_scan_command(command)
                self.assertFalse(result["ok"])
                scan.assert_not_called()

    def test_authorized_web_scan_forwards_exact_scope_to_service(self) -> None:
        with patch.object(chat_commands, "run_web_scan", return_value={"ok": True}) as scan:
            result = chat_commands.dispatch_authorized_scan_command(
                "scan web -y --scope app.example.com https://app.example.com/path?q=1"
            )
            self.assertTrue(result["ok"])
            scan.assert_called_once_with("https://app.example.com/path?q=1", scope_host="app.example.com")

    def test_authorized_live_scan_forwards_exact_scope_to_service(self) -> None:
        with patch.object(chat_commands, "run_live_scan", return_value={"ok": True}) as scan:
            result = chat_commands.dispatch_authorized_scan_command(
                "scan live --authorized --scope=app.example.com https://app.example.com/"
            )
            self.assertTrue(result["ok"])
            scan.assert_called_once_with("https://app.example.com/", scope_host="app.example.com")

    def test_remote_repository_requires_matching_repository_root(self) -> None:
        with patch.object(chat_commands, "run_code_scan", return_value={"ok": True}) as scan:
            result = chat_commands.dispatch_authorized_scan_command(
                "scan repo -y --scope https://github.com/org/repo https://github.com/org/repo"
            )
            self.assertTrue(result["ok"])
            scan.assert_called_once_with("https://github.com/org/repo", "git_remote")

    def test_chat_api_refuses_unscoped_network_scan_without_a_request(self) -> None:
        import greyiq_api  # noqa: PLC0415 - integration path imported only for this test

        runtime = greyiq_api.GreyIQRuntime()
        with patch.object(chat_commands, "run_web_scan") as scan:
            reply = runtime.chat(greyiq_api.ChatRequest(message="scan web https://app.example.com/"))
        scan.assert_not_called()
        self.assertEqual(reply["model_name"], "bughunter")
        self.assertFalse(reply["scan"]["ok"])
        self.assertIn("authorization", reply["message"].lower())


if __name__ == "__main__":
    unittest.main()
