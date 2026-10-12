"""Local path source — point at a folder or a single file, scan it in-place."""

from __future__ import annotations

from pathlib import Path

from bughunter.code_scanner.sources.base import ScanSource
from bughunter.code_scanner.sources.local_guard import resolve_local_scan_path


class LocalPathSource(ScanSource):
    """Scan a local path.

    If the target is a *file*, ``single_file_relative`` is set so the
    orchestrator can constrain the walker to that one file rather than
    pulling in everything else in the parent directory. The ``root``
    still points at the parent dir because the walker takes a dir, but
    the constraint short-circuits accidental scanning of siblings.
    """

    def __init__(self, target: str) -> None:
        super().__init__(target)
        self.single_file_relative: str | None = None

    def _prepare(self) -> Path:
        path = resolve_local_scan_path(self.target)
        if not path.exists():
            raise FileNotFoundError(f"Scan target does not exist: {self.target}")
        if path.is_file():
            self.single_file_relative = path.name
            return path.parent
        if not path.is_dir():
            raise NotADirectoryError(f"Scan target is not a directory: {self.target}")
        return path
