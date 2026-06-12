"""Local git repository source.

Points at a path that is already a git checkout. We walk the worktree
in place (so the scan sees the developer's current state), and shell
out to ``git`` to collect a small set of metadata: HEAD ref, branch,
last commit author/date, and the number of commits in the last 30
days. Findings can reference this context to flag e.g. a freshly
authored backdoor.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from bughunter.code_scanner.sources.base import ScanSource


def _run_git(repo: Path, *args: str) -> str:
    cmd = ["git", "-C", str(repo), *args]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0:
            return ""
        return completed.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


class LocalGitSource(ScanSource):
    def _prepare(self) -> Path:
        path = Path(self.target).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Scan target does not exist: {self.target}")
        if not (path / ".git").exists():
            raise ValueError(f"Path is not a git checkout: {self.target}")
        if shutil.which("git") is None:
            # We still scan the worktree, but metadata stays empty so
            # the dashboard makes the missing-git situation explicit.
            self.git_metadata = {"git_cli": "not_found"}
            return path
        # Best-effort: every metadata fetch tolerates failure so a
        # detached HEAD / non-git command in the tree doesn't kill the
        # scan.
        self.git_metadata = {
            "head_sha": _run_git(path, "rev-parse", "HEAD"),
            "branch": _run_git(path, "rev-parse", "--abbrev-ref", "HEAD"),
            "remote_origin": _run_git(path, "config", "--get", "remote.origin.url"),
            "last_commit_author": _run_git(path, "log", "-1", "--pretty=%an"),
            "last_commit_date": _run_git(path, "log", "-1", "--pretty=%ci"),
            "commits_30d": _run_git(path, "rev-list", "--count", "--since=30.days", "HEAD"),
        }
        # Drop empty entries so the API payload stays tight.
        self.git_metadata = {k: v for k, v in self.git_metadata.items() if v}
        return path
