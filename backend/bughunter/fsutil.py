"""GreyIQ BugHunter — filesystem helpers.

Windows caps paths at 260 chars (``MAX_PATH``) unless an app opts in. A deep
install dir + the campaign's nested ``campaign-…/targets/`` layout + a long
target slug can blow past that, surfacing as a misleading ``FileNotFoundError``
on write. ``write_text_safe`` writes normally and, only when a long-path error
hits on Windows, retries through the ``\\?\`` extended-length prefix so reports
still land. No-op everywhere else. Pure / frozen-safe.
"""

from __future__ import annotations

import os
from pathlib import Path


def _extended_path(path: Path) -> str:
    """The ``\\?\`` extended-length form of an absolute Windows path (UNC-aware)."""
    resolved = os.path.abspath(str(path))
    if resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\"):  # UNC share -> \\?\UNC\server\share
        return "\\\\?\\UNC\\" + resolved.lstrip("\\")
    return "\\\\?\\" + resolved


def write_text_safe(path: Path, text: str, *, encoding: str = "utf-8") -> Path:
    """Write ``text`` to ``path``, creating parents. On Windows, transparently
    retry over the long-path prefix if the first attempt trips ``MAX_PATH``.
    Returns the path actually written. Raises the original OSError if the retry
    is not applicable (non-Windows) or also fails."""
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        if os.name != "nt":
            raise
        Path(_extended_path(path.parent)).mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(text, encoding=encoding)
        return path
    except OSError:
        if os.name != "nt":
            raise
        extended = _extended_path(path)
        with open(extended, "w", encoding=encoding) as handle:
            handle.write(text)
        return path


def read_text_safe(path: Path, *, encoding: str = "utf-8") -> str:
    """Read ``path``, retrying over the Windows long-path prefix if a normal read
    trips ``MAX_PATH``. Raises the original OSError if the retry can't apply."""
    path = Path(path)
    try:
        return path.read_text(encoding=encoding)
    except OSError:
        if os.name != "nt":
            raise
        with open(_extended_path(path), encoding=encoding) as handle:
            return handle.read()
