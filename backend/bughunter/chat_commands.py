"""Detect and dispatch BugHunter scan commands typed in chat.

Lets a user drive the scanners conversationally, e.g.:
    scan code C:/path/to/repo
    scan repo https://github.com/org/project
    scan web https://example.com
    scan https://example.com          (type inferred: URL -> web)
    bughunt ./src                     (type inferred: path -> code)

Returns a (kind, target) pair or None so non-scan messages fall through to the
normal chat engine untouched.
"""

from __future__ import annotations

import re
from typing import Any

from bughunter.live_scan_service import run_live_scan
from bughunter.scan_service import run_code_scan
from bughunter.web_scan_service import run_web_scan

_TRIGGER = re.compile(r"^\s*(?:/?scan|bughunt)\b[:\s]+(?P<rest>.+)$", re.IGNORECASE | re.DOTALL)

_SUBTYPES: dict[str, str] = {
    "code": "code", "repo": "code", "path": "code", "codebase": "code", "folder": "code",
    "web": "web", "site": "web", "url": "web", "website": "web", "page": "web",
    "live": "live", "app": "live", "dynamic": "live", "runtime": "live", "browser": "live",
}


def _looks_like_url(target: str) -> bool:
    lowered = target.lower()
    if lowered.startswith(("http://", "https://")):
        return True
    if lowered.startswith(("git@", "ssh://")):
        return False
    return " " not in target and bool(re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/.*)?$", lowered))


def _looks_like_path(target: str) -> bool:
    return bool(re.search(r"[\\/]", target)) or bool(re.match(r"^[A-Za-z]:", target)) or target in {".", "./"}


def _code_target_type(target: str) -> str:
    lowered = target.lower()
    if (
        lowered.endswith(".git")
        or lowered.startswith(("http://", "https://", "git@", "ssh://"))
        or "github.com/" in lowered
        or "gitlab.com/" in lowered
    ):
        return "git_remote"
    return "path"


def detect_scan_command(message: str) -> tuple[str, str] | None:
    if not message:
        return None
    match = _TRIGGER.match(message)
    if not match:
        return None
    rest = match.group("rest").strip()
    parts = rest.split(None, 1)

    kind: str | None = None
    target = rest
    if parts and parts[0].lower() in _SUBTYPES:
        kind = _SUBTYPES[parts[0].lower()]
        target = parts[1].strip() if len(parts) > 1 else ""

    target = target.strip().strip("`\"'<>").strip()
    if not target:
        return None

    if kind is None:
        if _looks_like_url(target):
            kind = "web"
        elif _looks_like_path(target):
            kind = "code"
        else:
            # Ambiguous free text after "scan" - let normal chat handle it.
            return None
    return kind, target


def run_scan(kind: str, target: str) -> dict[str, Any]:
    if kind == "web":
        return run_web_scan(target)
    if kind == "live":
        return run_live_scan(target)
    return run_code_scan(target, _code_target_type(target))
