"""Local git repository source.

Points at a path that is already a git checkout. We walk the worktree
in place so the scan sees the developer's current state. Git metadata
commands are omitted because repository config includes and object
alternates can make even read-only Git commands access network paths.
"""

from __future__ import annotations

from pathlib import Path

from bughunter.code_scanner.sources.base import ScanSource
from bughunter.code_scanner.sources.local_guard import (
    is_link_or_reparse,
    resolve_local_scan_path,
)


class LocalGitSource(ScanSource):
    def _prepare(self) -> Path:
        path = resolve_local_scan_path(self.target)
        if not path.exists():
            raise FileNotFoundError(f"Scan target does not exist: {self.target}")
        git_dir = path / ".git"
        try:
            linked_git_dir = is_link_or_reparse(git_dir)
        except FileNotFoundError:
            raise ValueError(f"Path is not a git checkout: {self.target}")
        if linked_git_dir or not git_dir.is_dir():
            raise ValueError("Local Git scan requires an in-tree .git directory without links.")
        return path
