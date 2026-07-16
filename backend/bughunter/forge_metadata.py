"""Best-effort public forge metadata for repo-link program onboarding.

This module is deliberately narrow: it performs at most one unauthenticated, read-only
GET per supported repository, only when the caller explicitly asks for enrichment.  API
destinations are constructed from already validated repository roots, pinned to the two
documented forge API hosts, never redirected, bounded, and never retried.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
import urllib.request
from typing import Any, Callable

from bughunter.code_scanner.sources.git_remote import is_supported_remote_git_url

_API_HOSTS = frozenset({"api.github.com", "gitlab.com"})
_MAX_RESPONSE_BYTES = 1_000_000
_MAX_DESCRIPTION_CHARS = 500
_USER_AGENT = "GreyIQ-BugHunter/repo-onboarding"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never let a forge API response redirect the fixed-host metadata request."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, N802
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _api_endpoint(repository_url: str) -> str | None:
    """Return the single documented metadata endpoint for a supported repo root."""
    if not is_supported_remote_git_url(repository_url):
        return None
    parsed = urllib.parse.urlparse(repository_url)
    host = (parsed.hostname or "").lower()
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if not parts:
        return None
    parts[-1] = re.sub(r"\.git$", "", parts[-1], flags=re.IGNORECASE)
    if host == "github.com" and len(parts) == 2:
        owner = urllib.parse.quote(parts[0], safe="")
        repo = urllib.parse.quote(parts[1], safe="")
        return f"https://api.github.com/repos/{owner}/{repo}"
    if host == "gitlab.com" and len(parts) >= 2:
        project = urllib.parse.quote("/".join(parts), safe="")
        return f"https://gitlab.com/api/v4/projects/{project}"
    return None


def _is_pinned_api_url(url: str) -> bool:
    """Defense in depth for the only function that opens a network connection."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.port not in (None, 443):
            return False
    except ValueError:
        return False
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or parsed.query or parsed.fragment or (parsed.hostname or "").lower() not in _API_HOSTS):
        return False
    path = parsed.path
    host = (parsed.hostname or "").lower()
    return ((host == "api.github.com" and path.startswith("/repos/"))
            or (host == "gitlab.com" and path.startswith("/api/v4/projects/")))


def _fetch_json(url: str, *, timeout: float = 10.0) -> Any:
    if not _is_pinned_api_url(url):
        raise ValueError("refusing forge metadata request outside the documented API allowlist")
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
    )
    with _OPENER.open(request, timeout=timeout) as response:  # noqa: S310 - URL is pinned above; redirects are disabled
        body = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ValueError("forge metadata response exceeded the size limit")
    return json.loads(body.decode("utf-8", "replace"))


def _clean_description(value: Any) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()[:_MAX_DESCRIPTION_CHARS]


def _candidate_host(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urllib.parse.urlparse(raw)
        if parsed.port not in (None, 80, 443):
            return ""
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        return ""
    host = (parsed.hostname or "").strip(".").lower()
    if "." not in host:
        return ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return ""


def enrich_repositories(
    repository_urls: list[str],
    *,
    fetch: Callable[..., Any] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Fetch bounded public metadata once per GitHub/GitLab repository.

    Unsupported forges and every fetch/parse failure are skipped. Candidate hosts are
    returned as inert strings; this module never writes or authorizes scope.
    """
    fetch = fetch or _fetch_json
    descriptions: list[dict[str, str]] = []
    candidate_hosts: list[str] = []
    seen_hosts: set[str] = set()
    for repository_url in repository_urls:
        endpoint = _api_endpoint(repository_url)
        if not endpoint:
            continue
        try:
            payload = fetch(endpoint, timeout=timeout)
        except Exception:  # noqa: BLE001 - enrichment is explicitly best-effort and never fatal
            continue
        if not isinstance(payload, dict):
            continue
        description = _clean_description(payload.get("description"))
        if description:
            descriptions.append({"repository_url": repository_url, "description": description})
        for field in ("homepage", "web_url"):
            host = _candidate_host(payload.get(field))
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                candidate_hosts.append(host)
    return {"descriptions": descriptions, "candidate_hosts": candidate_hosts}
