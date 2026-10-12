"""Keep local code scans on local files without following filesystem links."""

from __future__ import annotations

import os
import stat
from pathlib import Path


_DRIVE_REMOTE = 4
_DRIVE_UNKNOWN = 0
_DRIVE_NO_ROOT_DIR = 1


def _reject_network_syntax(value: str) -> None:
    # Do this before any filesystem operation: even a seemingly harmless
    # exists()/resolve() on a UNC path can contact a remote SMB server.
    windows_form = value.replace("/", "\\")
    if (
        windows_form.startswith("\\\\")
        or windows_form.startswith("\\??\\")
        or value.lower().startswith("file:")
    ):
        raise ValueError("Local scans require a local filesystem path; network and device paths are refused.")


def _windows_drive_type(root: str) -> int:
    import ctypes

    get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
    get_drive_type.argtypes = [ctypes.c_wchar_p]
    get_drive_type.restype = ctypes.c_uint
    return int(get_drive_type(root))


def _reject_remote_drive(path: Path) -> None:
    if os.name != "nt":
        return
    drive = path.drive
    if not drive:
        raise ValueError("Cannot verify that the scan path is on a local drive.")
    drive_type = _windows_drive_type(drive.rstrip("\\/") + "\\")
    if drive_type in (_DRIVE_REMOTE, _DRIVE_UNKNOWN, _DRIVE_NO_ROOT_DIR):
        raise ValueError("Local scans require a local drive; mapped network drives are refused.")


def is_link_or_reparse(path: Path) -> bool:
    """Inspect the entry itself, without following a symlink or junction."""
    entry = os.lstat(path)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(entry.st_mode) or bool(
        getattr(entry, "st_file_attributes", 0) & reparse_flag
    )


def resolve_local_scan_path(value: str | os.PathLike[str]) -> Path:
    """Validate a local target before resolving or opening any of its entries."""
    raw = os.fspath(value)
    _reject_network_syntax(raw)
    expanded = Path(raw).expanduser()
    _reject_network_syntax(str(expanded))
    # abspath removes lexical '..' segments without following links. Inspect
    # every existing component before resolve() can traverse a reparse point.
    path = Path(os.path.abspath(expanded))
    _reject_network_syntax(str(path))
    _reject_remote_drive(path)
    for component in (*reversed(path.parents), path):
        try:
            if is_link_or_reparse(component):
                raise ValueError(f"Local scan path contains a symlink or junction: {component}")
        except FileNotFoundError:
            break
        except OSError as exc:
            raise ValueError(f"Cannot verify local scan path component: {component}") from exc
    return path.resolve()


__all__ = ["is_link_or_reparse", "resolve_local_scan_path"]
