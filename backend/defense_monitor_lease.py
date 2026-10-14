"""Cross-process lease for one defense log collector per GreyIQ runtime.

This module uses only the standard library so the source CLI remains usable
without installing the desktop or database dependency set.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO


class MonitorLeaseBusy(OSError):
    """Another process owns the defense monitor for this runtime."""


class MonitorLease:
    """An exclusive, nonblocking process lock held until ``release``.

    The desktop API should hold this for its collector's lifetime. A headless
    CLI watch holds it for the command's lifetime; one-shot local writes hold
    it until their state is committed. Processes must use the same runtime dir.
    """

    def __init__(self, runtime_dir: str | os.PathLike[str]) -> None:
        self.path = Path(runtime_dir) / "data" / "defense_monitor.lock"
        self._handle: BinaryIO | None = None

    def acquire(self) -> "MonitorLease":
        if self._handle is not None:
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise MonitorLeaseBusy("Another defense log monitor is using this runtime.") from exc
        self._handle = handle
        return self

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def __enter__(self) -> "MonitorLease":
        return self.acquire()

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.release()
