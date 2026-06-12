"""Source adapter base class."""

from __future__ import annotations

from pathlib import Path


class ScanSource:
    """Adapter that turns a user-supplied target into an on-disk root."""

    def __init__(self, target: str) -> None:
        self.target = target
        self._root: Path | None = None
        self.git_metadata: dict[str, str] = {}
        # Set by LocalPathSource when a single-file target is detected.
        # The orchestrator uses it to constrain include_globs so a
        # file-shaped target doesn't pull in the rest of its directory.
        self.single_file_relative: str | None = None

    @property
    def root(self) -> Path:
        if self._root is None:
            self._root = self._prepare()
        return self._root

    def _prepare(self) -> Path:
        raise NotImplementedError

    def cleanup(self) -> None:
        """Release any temporary resources the adapter holds.

        The default implementation is a no-op; remote / archive sources
        override to delete their temp dirs.
        """
        return None
