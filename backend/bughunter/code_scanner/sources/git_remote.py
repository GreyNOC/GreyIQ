"""Remote git source — shallow-clone a public URL into a tempdir, scan, clean up.

Only HTTPS URLs are accepted, and a strict allowlist of hosts is
enforced. Cloning is shallow (depth=1) and bandwidth-capped to the
configured max-total-bytes setting. Authentication is intentionally
not supported in v1 — pass a local clone via ``git_local`` if you need
private-repo scanning.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

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
_URL_RE = re.compile(r"^https://[^\s]+$", re.IGNORECASE)

# Forge paths that identify a page *inside* a repository rather than the repository
# itself. Passing one of these to ``git clone`` produces a confusing transport error;
# reject it as a non-repository link before any subprocess is started.
_NON_REPOSITORY_SEGMENTS = frozenset({
    "blob", "commit", "commits", "compare", "issues", "merge_requests", "pull",
    "pulls", "releases", "src", "tree", "wiki", "-",
})


def is_supported_remote_git_url(url: str) -> bool:
    """Return whether *url* is a public HTTPS repository root GreyIQ can clone.

    This is deliberately stricter than "URL hosted on a forge": issue, pull-request,
    blob, and tree pages are web targets, not clone targets. GitLab permits nested
    groups, while the other supported forges use a two-component owner/repository
    shape.
    """
    raw = str(url or "").strip()
    if not _URL_RE.match(raw):
        return False
    try:
        parsed = urlparse(raw)
    except ValueError:
        return False
    if (parsed.scheme.lower() != "https" or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        return False
    host = (parsed.hostname or "").lower()
    if host not in _HOST_ALLOWLIST:
        return False
    parts = [part for part in parsed.path.split("/") if part]
    if any(part.lower() in _NON_REPOSITORY_SEGMENTS for part in parts[2:]):
        return False
    if host == "gitlab.com":
        return len(parts) >= 2 and "-" not in parts
    if host == "git.sr.ht":
        return len(parts) == 2 and parts[0].startswith("~")
    return len(parts) == 2


def _validate_url(url: str) -> str:
    url = url.strip()
    if not _URL_RE.match(url):
        raise ValueError("Remote git URL must use https.")
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Remote git URL must use https.")
    host = (parsed.hostname or "").lower()
    if host not in _HOST_ALLOWLIST:
        raise ValueError(
            f"Remote git host '{host}' is not in the allowlist. Add support explicitly "
            f"or scan a local clone instead."
        )
    # Drop userinfo to avoid sneaking creds into the URL.
    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in URLs are not supported.")
    if not is_supported_remote_git_url(url):
        raise ValueError("Remote git URL must point to a repository root, not a forge page inside a repository.")
    return url


def _categorize_git_error(stderr: str) -> tuple[str, str]:
    """Map raw git transport stderr to a (status, operator-facing message) pair.

    The message is deliberately actionable and NEVER echoes the local temp path git
    prints (``Cloning into 'C:\\...\\gn-scan-xxxx\\repo'``) or other plumbing. GitHub (and
    most forges) return "not found" for BOTH a missing repo and a private one — to avoid
    leaking existence — so those collapse to one honest message.
    """
    low = (stderr or "").lower()
    if any(s in low for s in ("not found", "repository does not exist", "does not appear to be a git")):
        return ("not_found", "Repository not found. Check the URL for typos, or confirm the repo is "
                             "public — GreyIQ only clones public repositories, and a private repo reads "
                             "as not-found here.")
    if any(s in low for s in ("authentication failed", "could not read username", "could not read password",
                              "terminal prompts disabled", "invalid username or password", "permission denied")):
        return ("private", "This repository requires authentication, so it looks private. GreyIQ only "
                          "clones public repositories.")
    if any(s in low for s in ("could not resolve host", "failed to connect", "unable to access",
                              "connection timed out", "network is unreachable", "temporary failure")):
        return ("unreachable", "Couldn't reach the forge to read the repository. Check your network "
                             "connection and try again.")
    # Unknown git failure: surface only the first non-"Cloning into" line, never the temp path.
    detail = ""
    for line in (stderr or "").splitlines():
        line = line.strip()
        if line and not line.lower().startswith("cloning into"):
            detail = line[:160]
            break
    return ("error", "Couldn't read the repository" + (f" — {detail}" if detail else "") + ".")


def preflight(url: str, *, timeout: float = 12.0) -> dict[str, object]:
    """Cheaply verify a public repo root is reachable and cloneable WITHOUT cloning it.

    Uses ``git ls-remote`` (the same smart-HTTP transport a clone uses, so it tests the real
    thing) against the already-allowlisted forge host. Returns
    ``{"ok": bool, "status": str, "message": str, "default_branch": str}`` — status is one of
    ``ok`` / ``not_found`` / ``private`` / ``unreachable`` / ``invalid`` / ``no_git`` / ``timeout`` /
    ``error``. Never raises; every failure is a categorized, operator-facing message.
    """
    raw = str(url or "").strip().rstrip("/")
    if not is_supported_remote_git_url(raw):
        return {"ok": False, "status": "invalid",
                "message": "Enter a public HTTPS repository-root URL from a supported forge (GitHub, "
                           "GitLab, Bitbucket, Codeberg, or SourceHut) — not an issue, blob, tree, or "
                           "pull-request page.",
                "default_branch": ""}
    if shutil.which("git") is None:
        return {"ok": False, "status": "no_git",
                "message": "git isn't installed on this machine, so GreyIQ can't check or clone "
                           "repositories. Install git and try again.",
                "default_branch": ""}
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}
    try:
        proc = subprocess.run(
            ["git", "ls-remote", "--symref", raw, "HEAD"],
            capture_output=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "status": "timeout",
                "message": "The forge took too long to respond. Check your connection and try again.",
                "default_branch": ""}
    except (OSError, ValueError):
        return {"ok": False, "status": "error",
                "message": "Couldn't run the repository check. Try again.", "default_branch": ""}
    if proc.returncode == 0:
        default_branch = ""
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            if line.startswith("ref:") and "\tHEAD" in line:
                default_branch = line[4:].split("\t", 1)[0].strip().removeprefix("refs/heads/")
                break
        return {"ok": True, "status": "ok",
                "message": "Reachable public repository — ready to clone and scan.",
                "default_branch": default_branch or "HEAD"}
    status, message = _categorize_git_error(proc.stderr.decode("utf-8", "replace"))
    return {"ok": False, "status": status, "message": message, "default_branch": ""}


class RemoteGitSource(ScanSource):
    def __init__(self, target: str) -> None:
        super().__init__(target)
        self._tempdir: tempfile.TemporaryDirectory[str] | None = None

    def _prepare(self) -> Path:
        url = _validate_url(self.target)
        if shutil.which("git") is None:
            raise RuntimeError(
                "git binary is required for remote-URL scans. Install git or scan a local clone."
            )
        self._tempdir = tempfile.TemporaryDirectory(prefix="gn-scan-")
        dest = Path(self._tempdir.name) / "repo"
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    "--no-tags",
                    url,
                    str(dest),
                ],
                check=True,
                capture_output=True,
                timeout=120,
                env=env,
            )
        except FileNotFoundError as error:
            self._tempdir.cleanup()
            self._tempdir = None
            raise RuntimeError("git binary not found on PATH.") from error
        except subprocess.TimeoutExpired as error:
            self._tempdir.cleanup()
            self._tempdir = None
            raise RuntimeError("git clone timed out.") from error
        except subprocess.CalledProcessError as error:
            self._tempdir.cleanup()
            self._tempdir = None
            _status, message = _categorize_git_error((error.stderr or b"").decode("utf-8", errors="replace"))
            raise RuntimeError(message) from error

        self.git_metadata = {
            "remote_url": url,
            "clone_depth": "1",
        }
        return dest

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None
