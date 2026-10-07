"""Validate public forge repository roots; remote Git transport is fail-closed.

Git can resolve DNS independently and fetch dumb-HTTP alternate object URLs.
Neither a parsed URL nor disabled redirects proves that every Git request
stays on the authorized host, so the scanner requires an operator-supplied
local clone until a fully constrained transport is available.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from bughunter.code_scanner.sources.base import ScanSource

_HOST_ALLOWLIST = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "git.sr.ht",
    }
)
_REPO_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
_REMOTE_UNAVAILABLE = (
    "Remote Git preflight and clone are unavailable because Git cannot yet enforce "
    "the exact authorized repository and network destination for every request. "
    "Use an operator-supplied local clone and scan its path instead."
)

# Forge paths that identify a page *inside* a repository rather than the repository
# itself. Passing one of these to ``git clone`` produces a confusing transport error;
# reject it as a non-repository link before any subprocess is started.
_NON_REPOSITORY_SEGMENTS = frozenset({
    "blob", "commit", "commits", "compare", "issues", "merge_requests", "pull",
    "pulls", "releases", "src", "tree", "wiki", "-",
})


def canonical_repo_root(url: str) -> str:
    """Return a supported public HTTPS repository root, or ``''`` if ambiguous.

    Host case, one trailing slash, and the optional Git transport ``.git``
    suffix normalize to one repository identity. Percent escapes, dot segments,
    repeated separators, ports, userinfo, and query/fragment delimiters are
    refused rather than interpreted differently by the scope gate and Git.
    """
    raw = str(url or "")
    if not raw.lower().startswith("https://") or any(ord(ch) <= 32 or ord(ch) == 127 for ch in raw):
        return ""
    if any(ch in raw for ch in ("\\", "?", "#")):
        return ""
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return ""
    if (parsed.scheme.lower() != "https" or host not in _HOST_ALLOWLIST or port is not None
            or "@" in parsed.netloc or parsed.netloc.endswith(":") or parsed.query or parsed.fragment):
        return ""
    path = parsed.path.removesuffix("/")
    if not path.startswith("/") or "//" in path or "%" in path:
        return ""
    parts = path[1:].split("/")
    if any(part in {"", ".", ".."} or not _REPO_SEGMENT_RE.fullmatch(part) for part in parts):
        return ""
    if any(part.lower() in _NON_REPOSITORY_SEGMENTS for part in parts[2:]):
        return ""
    if host == "gitlab.com":
        valid = len(parts) >= 2 and "-" not in parts
    elif host == "git.sr.ht":
        valid = len(parts) == 2 and parts[0].startswith("~")
    else:
        valid = len(parts) == 2
    if not valid or parts[-1].lower().endswith(".git.git"):
        return ""
    if parts[-1].lower().endswith(".git"):
        parts[-1] = parts[-1][:-4]
    if not parts[-1] or parts[-1] in {".", ".."}:
        return ""
    return f"https://{host}/{'/'.join(parts)}"


def is_supported_remote_git_url(url: str) -> bool:
    """Return whether *url* is a canonicalizable public HTTPS repo root."""
    return bool(canonical_repo_root(url))


def _validate_url(url: str) -> str:
    root = canonical_repo_root(url)
    if not root:
        raise ValueError("Remote Git URL must be an unambiguous public HTTPS repository root on a supported forge.")
    return root


def preflight(url: str, *, timeout: float = 12.0) -> dict[str, object]:
    """Validate syntax only; never start Git or another network transport."""
    del timeout  # retained for callers of the former network preflight API
    if not canonical_repo_root(url):
        return {"ok": False, "status": "invalid",
                "message": "Enter a public HTTPS repository-root URL from a supported forge (GitHub, "
                           "GitLab, Bitbucket, Codeberg, or SourceHut) — not an issue, blob, tree, or "
                           "pull-request page.",
                "default_branch": ""}
    return {"ok": False, "status": "unavailable", "message": _REMOTE_UNAVAILABLE,
            "default_branch": ""}


class RemoteGitSource(ScanSource):
    def _prepare(self) -> Path:
        _validate_url(self.target)
        raise RuntimeError(_REMOTE_UNAVAILABLE)
