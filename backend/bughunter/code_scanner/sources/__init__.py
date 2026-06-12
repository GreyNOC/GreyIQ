"""Scan source adapters.

Each adapter knows how to take a user-supplied target (path, git URL,
archive bytes) and produce a real on-disk directory the walker can
traverse. Adapters also report any git metadata they have access to,
and clean up temporary state.
"""

from __future__ import annotations

from bughunter.code_scanner.model import ScanRequest, ScanTargetType
from bughunter.code_scanner.sources.archive import ArchiveSource
from bughunter.code_scanner.sources.base import ScanSource
from bughunter.code_scanner.sources.git_local import LocalGitSource
from bughunter.code_scanner.sources.git_remote import RemoteGitSource
from bughunter.code_scanner.sources.local import LocalPathSource


def resolve_source(request: ScanRequest) -> ScanSource:
    if request.target_type == ScanTargetType.PATH:
        return LocalPathSource(request.target)
    if request.target_type == ScanTargetType.GIT_LOCAL:
        return LocalGitSource(request.target)
    if request.target_type == ScanTargetType.GIT_REMOTE:
        return RemoteGitSource(request.target)
    if request.target_type == ScanTargetType.ARCHIVE:
        return ArchiveSource(request.target)
    raise ValueError(f"Unknown scan target type: {request.target_type}")


__all__ = [
    "ArchiveSource",
    "LocalGitSource",
    "LocalPathSource",
    "RemoteGitSource",
    "ScanSource",
    "resolve_source",
]
