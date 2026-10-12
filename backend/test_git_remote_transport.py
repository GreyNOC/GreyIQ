"""Remote Git scans must keep their repository identity and transport boundary."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.code_scanner.sources import git_remote  # noqa: E402


class CanonicalRepoRootTests(unittest.TestCase):
    def test_safe_aliases_share_one_repository_root(self) -> None:
        for url in (
            "https://GITHUB.com/Org/Repo",
            "https://github.com/Org/Repo/",
            "https://github.com/Org/Repo.git",
            "https://github.com/Org/Repo.git/",
        ):
            with self.subTest(url=url):
                self.assertEqual(git_remote.canonical_repo_root(url), "https://github.com/Org/Repo")
        self.assertEqual(
            git_remote.canonical_repo_root("https://gitlab.com/team/subgroup/repo.git"),
            "https://gitlab.com/team/subgroup/repo",
        )

    def test_ambiguous_or_non_repository_urls_are_rejected(self) -> None:
        rejected = (
            "http://github.com/Org/Repo",
            "https://github.com:443/Org/Repo",
            "https://user:pass@github.com/Org/Repo",
            "https://@github.com/Org/Repo",
            "https://github.com/Org/Repo?token=abc",
            "https://github.com/Org/Repo?",
            "https://github.com/Org/Repo#",
            "https://github.com/Org%2fOther/Repo",
            "https://github.com/Org/Repo%5cOther",
            "https://github.com/Org/Repo//",
            "https://github.com/Org/../Repo",
            "https://github.com/Org/Repo.git.git",
            "https://github.com/Org/Repo/issues/1",
            "https://example.test/Org/Repo",
            " https://github.com/Org/Repo",
            "https://github.com/Org/Repo\n",
        )
        for url in rejected:
            with self.subTest(url=url):
                self.assertEqual(git_remote.canonical_repo_root(url), "")
                self.assertFalse(git_remote.is_supported_remote_git_url(url))


class FailClosedRemoteTransportTests(unittest.TestCase):
    def test_ambient_git_config_and_proxy_cannot_trigger_any_subprocess(self) -> None:
        poisoned = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "url.https://outside.test/.insteadOf",
            "GIT_CONFIG_VALUE_0": "https://github.com/",
            "GIT_CONFIG_GLOBAL": "C:/poisoned/.gitconfig",
            "GIT_SSL_NO_VERIFY": "1",
            "HTTPS_PROXY": "http://outside.test:8080",
            "http_proxy": "http://outside.test:8080",
            "ALL_PROXY": "socks5://outside.test:1080",
            "SSH_ASKPASS": "C:/poisoned/askpass.exe",
        }
        with mock.patch.dict(os.environ, poisoned), mock.patch("subprocess.run") as run, mock.patch(
            "subprocess.Popen"
        ) as popen, mock.patch("socket.getaddrinfo") as dns:
            preflight = git_remote.preflight("https://GITHUB.com/Org/Repo.git/")
            self.assertEqual(preflight["status"], "unavailable")
            source = git_remote.RemoteGitSource("https://GITHUB.com/Org/Repo.git/")
            with self.assertRaisesRegex(RuntimeError, "operator-supplied local clone"):
                source._prepare()
        run.assert_not_called()
        popen.assert_not_called()
        dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()
