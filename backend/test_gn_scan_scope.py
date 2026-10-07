"""The quick CLI scan must gate every network target before dispatch."""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_cli  # noqa: E402


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = gn_cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class ScanScopeCliTests(unittest.TestCase):
    def test_web_and_repo_denials_do_not_call_either_scanner(self) -> None:
        cases = (
            ["scan", "https://app.example.com/"],
            ["scan", "https://app.example.com/", "-y"],
            ["scan", "https://app.example.com/", "-y", "--scope", "example.com"],
            ["scan", "https://app.example.com/", "-y", "--scope", "*.example.com"],
            ["scan", "https://app.example.com/", "-y", "--scope", "app.example.com.evil"],
            ["scan", "https://github.com/acme/widget"],
            ["scan", "https://github.com/acme/widget", "-y"],
            ["scan", "https://github.com/acme/widget", "-y", "--scope", "acme.github.com"],
            ["scan", "https://github.com/acme/widget", "-y", "--scope", "github.com"],
            ["scan", "https://github.com/acme/widget", "-y", "--scope", "https://github.com/acme/other"],
            ["scan", "git@github.com:acme/widget.git", "-y", "--scope", "github.com"],
        )
        with patch("bughunter.web_scan_service.run_web_scan") as web:
            with patch("bughunter.scan_service.run_code_scan") as code:
                for argv in cases:
                    with self.subTest(argv=argv):
                        status, _out, error = _run(argv)
                        self.assertEqual(status, 2)
                        self.assertIn("gn:", error)
                web.assert_not_called()
                code.assert_not_called()

    def test_authorized_web_scan_receives_exact_scope_host(self) -> None:
        with patch("bughunter.web_scan_service.run_web_scan", return_value={"ok": True, "findings": []}) as web:
            with patch("bughunter.scan_service.run_code_scan") as code:
                status, out, error = _run([
                    "scan", "https://App.Example.Com/path", "-y", "--scope", "app.example.com", "--json",
                ])
        self.assertEqual(status, 0, error)
        self.assertIn('"ok": true', out)
        web.assert_called_once_with("https://App.Example.Com/path", scope_host="app.example.com")
        code.assert_not_called()

    def test_authorized_repository_scan_uses_remote_code_scanner(self) -> None:
        with patch("bughunter.scan_service.run_code_scan", return_value={"ok": True, "findings": []}) as code:
            with patch("bughunter.web_scan_service.run_web_scan") as web:
                status, _out, error = _run([
                    "scan", "https://github.com/acme/widget", "-y", "--scope", "https://github.com/acme/widget", "--json",
                ])
        self.assertEqual(status, 0, error)
        code.assert_called_once_with("https://github.com/acme/widget", "git_remote")
        web.assert_not_called()

    def test_local_path_scan_needs_no_network_grant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bughunter.scan_service.run_code_scan", return_value={"ok": True, "findings": []}) as code:
                with patch("bughunter.web_scan_service.run_web_scan") as web:
                    status, _out, error = _run(["scan", tmp, "--json"])
            self.assertEqual(status, 0, error)
            code.assert_called_once_with(tmp, "path")
            web.assert_not_called()

    def test_json_scan_failure_uses_nonzero_exit(self) -> None:
        with patch("bughunter.scan_service.run_code_scan", return_value={"ok": False, "error": "refused"}):
            status, output, _error = _run(["scan", "C:/work/src", "--json"])
        self.assertEqual(status, 1)
        self.assertIn('"error": "refused"', output)

    def test_help_states_the_network_grant(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as exit_status:
                gn_cli.build_parser().parse_args(["scan", "--help"])
        self.assertEqual(exit_status.exception.code, 0)
        self.assertIn("--scope", output.getvalue())
        self.assertIn("--authorize", output.getvalue())
        self.assertIn("exact", output.getvalue())


if __name__ == "__main__":
    unittest.main()
