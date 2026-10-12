"""Remote repository checks refuse transport that cannot enforce exact scope."""

from __future__ import annotations

import asyncio
import json
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


class PreflightTests(unittest.TestCase):
    def test_invalid_url_is_rejected_without_running_git(self) -> None:
        with mock.patch("subprocess.run") as run:
            out = git_remote.preflight("https://github.com/acme/webapp/issues/1")
        self.assertFalse(out["ok"])
        self.assertEqual(out["status"], "invalid")
        run.assert_not_called()

    def test_valid_repo_is_unavailable_without_dns_or_git(self) -> None:
        with mock.patch("socket.getaddrinfo") as dns, mock.patch("subprocess.run") as run:
            out = git_remote.preflight(_REPO)
        self.assertFalse(out["ok"])
        self.assertEqual(out["status"], "unavailable")
        self.assertIn("operator-supplied local clone", out["message"])
        dns.assert_not_called()
        run.assert_not_called()


class CloneFailClosedTests(unittest.TestCase):
    def test_clone_refuses_without_dns_or_git(self) -> None:
        src = git_remote.RemoteGitSource(_REPO)
        with mock.patch("socket.getaddrinfo") as dns, mock.patch("subprocess.run") as run:
            with self.assertRaises(RuntimeError) as ctx:
                src._prepare()
        self.assertIn("operator-supplied local clone", str(ctx.exception))
        dns.assert_not_called()
        run.assert_not_called()


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
