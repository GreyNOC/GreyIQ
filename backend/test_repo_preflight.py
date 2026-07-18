"""Repo preflight catches typo'd/private/missing repos up front with a clean message,
and the clone path never leaks the local temp path or raw git plumbing to the operator."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
from bughunter.code_scanner.sources import git_remote  # noqa: E402

_REPO = "https://github.com/acme/webapp"


def _completed(returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=returncode, stdout=stdout, stderr=stderr)


class CategorizeGitErrorTests(unittest.TestCase):
    def test_not_found_and_private_collapse_to_actionable_messages(self) -> None:
        status, msg = git_remote._categorize_git_error("remote: Repository not found.\nfatal: repository '...' not found")
        self.assertEqual(status, "not_found")
        self.assertIn("public", msg.lower())
        status, msg = git_remote._categorize_git_error("fatal: Authentication failed for 'https://...'")
        self.assertEqual(status, "private")

    def test_message_never_leaks_the_local_temp_path(self) -> None:
        # The real failure that reached the user: git prints "Cloning into '<tempdir>'" first.
        stderr = ("Cloning into 'C:\\Users\\bsoul\\AppData\\Local\\Temp\\gn-scan-72i0iu2n\\repo'...\n"
                  "remote: Repository not found.\nfatal: repository 'https://github.com/x/y' not found")
        _status, msg = git_remote._categorize_git_error(stderr)
        self.assertNotIn("gn-scan", msg)
        self.assertNotIn("Temp", msg)
        self.assertNotIn("Cloning into", msg)

    def test_network_failure_is_categorized(self) -> None:
        status, _msg = git_remote._categorize_git_error("fatal: unable to access '...': Could not resolve host: github.com")
        self.assertEqual(status, "unreachable")


class PreflightTests(unittest.TestCase):
    def test_invalid_url_is_rejected_without_running_git(self) -> None:
        with mock.patch.object(git_remote.subprocess, "run") as run:
            out = git_remote.preflight("https://github.com/acme/webapp/issues/1")
        self.assertFalse(out["ok"])
        self.assertEqual(out["status"], "invalid")
        run.assert_not_called()

    def test_reachable_repo_parses_default_branch(self) -> None:
        stdout = b"ref: refs/heads/main\tHEAD\n0123456789abcdef0123456789abcdef01234567\tHEAD\n"
        with mock.patch.object(git_remote.shutil, "which", return_value="git"), \
             mock.patch.object(git_remote.subprocess, "run", return_value=_completed(0, stdout=stdout)):
            out = git_remote.preflight(_REPO)
        self.assertTrue(out["ok"])
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["default_branch"], "main")

    def test_missing_repo_is_not_found(self) -> None:
        stderr = b"remote: Repository not found.\nfatal: repository 'https://github.com/acme/webapp/' not found\n"
        with mock.patch.object(git_remote.shutil, "which", return_value="git"), \
             mock.patch.object(git_remote.subprocess, "run", return_value=_completed(128, stderr=stderr)):
            out = git_remote.preflight(_REPO)
        self.assertFalse(out["ok"])
        self.assertEqual(out["status"], "not_found")

    def test_timeout_is_reported(self) -> None:
        with mock.patch.object(git_remote.shutil, "which", return_value="git"), \
             mock.patch.object(git_remote.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired(cmd="git", timeout=12)):
            out = git_remote.preflight(_REPO)
        self.assertEqual(out["status"], "timeout")
        self.assertFalse(out["ok"])

    def test_missing_git_binary_is_reported(self) -> None:
        with mock.patch.object(git_remote.shutil, "which", return_value=None):
            out = git_remote.preflight(_REPO)
        self.assertEqual(out["status"], "no_git")


class CloneErrorSurfaceTests(unittest.TestCase):
    def test_clone_failure_raises_clean_message(self) -> None:
        src = git_remote.RemoteGitSource(_REPO)
        stderr = b"Cloning into 'C:\\Temp\\gn-scan-abcd\\repo'...\nremote: Repository not found.\n"
        err = subprocess.CalledProcessError(returncode=128, cmd=["git", "clone"], stderr=stderr)
        with mock.patch.object(git_remote.shutil, "which", return_value="git"), \
             mock.patch.object(git_remote.subprocess, "run", side_effect=err):
            with self.assertRaises(RuntimeError) as ctx:
                src._prepare()
        message = str(ctx.exception)
        self.assertNotIn("gn-scan", message)
        self.assertNotIn("Cloning into", message)
        self.assertIn("not found", message.lower())


class PreflightRouteTests(unittest.TestCase):
    def test_route_validates_and_dispatches(self) -> None:
        captured: dict = {}

        async def receive():
            return {"type": "http.request", "body": json.dumps({"url": _REPO}).encode(), "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                captured["status"] = msg["status"]
            elif msg["type"] == "http.response.body":
                captured["body"] = captured.get("body", b"") + msg.get("body", b"")

        scope = {"method": "POST", "path": "/api/repos/preflight", "scheme": "http", "query_string": b"",
                 "headers": [(b"host", b"127.0.0.1:8766"), (b"content-type", b"application/json"),
                             (b"x-greyiq-token", api.SESSION_TOKEN.encode("ascii"))]}
        with mock.patch.object(api.bounty_git_remote, "preflight",
                               return_value={"ok": True, "status": "ok", "message": "ok", "default_branch": "main"}):
            asyncio.run(api.route_http(scope, receive, send))
        self.assertEqual(captured["status"], 200)
        self.assertTrue(json.loads(captured["body"])["ok"])


if __name__ == "__main__":
    unittest.main()
