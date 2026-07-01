"""GreyIQ BugHunter — HackerOne hacker-activity API (reconnaissance + own-account status).

Read-only, operator-triggered calls against HackerOne's own Hacker API v1 — same posture
as hackerone_import.py (manually triggered only, never automatic/background), reusing the
SAME API username/token already stored for scope import and submission (no new secret, no
new trust boundary). Every call here reuses hackerone_import's host-pinned fetch
(``_fetch_json``) rather than re-implementing it, so the redirect/host-pinning guard that
prevents credential exfiltration only has to be right in one place.

Endpoints (HTTP Basic auth, api_username as username / api_token as password):
  GET https://api.hackerone.com/v1/hackers/hacktivity
  GET https://api.hackerone.com/v1/hackers/me/reports
  GET https://api.hackerone.com/v1/hackers/reports/{id}
  GET https://api.hackerone.com/v1/hackers/payments/earnings
  GET https://api.hackerone.com/v1/hackers/payments/balance

Hacktivity/my-reports/earnings are each a single bounded page (a recent-activity glance,
not an exhaustive archive) — no pagination loop, so there's nothing here that can run away
against HackerOne's rate limits (report-page reads are capped at 300/min).

Best-effort / never raises to the caller: every network/parse failure returns
``{"ok": False, "error": "..."}``.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
from typing import Any, Callable

from bughunter.hackerone_import import _API_BASE, _fetch_json

_MAX_PAGE_SIZE = 100
_DEFAULT_PAGE_SIZE = 25


def _clamp_page_size(size: int) -> int:
    return max(1, min(int(size or _DEFAULT_PAGE_SIZE), _MAX_PAGE_SIZE))


def _missing_creds(api_username: str, api_token: str) -> dict[str, Any] | None:
    if not (api_username and api_token):
        return {"ok": False, "error": "Save your HackerOne API username + token in the Submissions tab first."}
    return None


def _error_for(exc: urllib.error.HTTPError, *, noun: str) -> str:
    if exc.code == 401:
        return "HackerOne rejected the API credentials (401) — check your API username/token in the Submissions tab."
    if exc.code == 403:
        return f"HackerOne returned 403 — your account doesn't have API access to this {noun}."
    if exc.code == 404:
        return f"HackerOne returned 404 — {noun} not found (or not visible to your account)."
    return f"HackerOne API HTTP {exc.code}: {exc.reason}"


def _get(url: str, *, api_username: str, api_token: str, timeout: float,
         fetch: Callable[..., Any] | None, noun: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Shared GET + error-mapping tail. Returns (page, error_response) — exactly one is None."""
    fetch = fetch or _fetch_json
    try:
        page = fetch(url, api_username=api_username, api_token=api_token, timeout=timeout)
    except urllib.error.HTTPError as exc:
        return None, {"ok": False, "error": _error_for(exc, noun=noun)}
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return None, {"ok": False, "error": f"Could not reach HackerOne: {exc}"}
    return (page if isinstance(page, dict) else {}), None


def fetch_hacktivity(
    team_handle: str,
    api_username: str,
    api_token: str,
    *,
    limit: int = _DEFAULT_PAGE_SIZE,
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Recent disclosed reports for one program — a reconnaissance glance at what's
    actually getting paid there (severity/CWE/bounty), not an exhaustive archive.
    Returns {"ok", "handle", "items": [...]} or {"ok": False, "error"}."""
    handle = str(team_handle or "").strip()
    if not handle:
        return {"ok": False, "error": "A HackerOne program handle is required."}
    missing = _missing_creds(api_username, api_token)
    if missing:
        return missing
    query = urllib.parse.urlencode({
        "queryString": f"team:{handle}",
        "sort": "-disclosed_at",
        "page[size]": _clamp_page_size(limit),
    })
    page, err = _get(f"{_API_BASE}/hacktivity?{query}", api_username=api_username, api_token=api_token,
                     timeout=timeout, fetch=fetch, noun="hacktivity")
    if err:
        return err
    items: list[dict[str, Any]] = []
    for row in page.get("data") or []:
        attrs = (row or {}).get("attributes") or {}
        items.append({
            "title": str(attrs.get("title") or ""),
            "severity_rating": str(attrs.get("severity_rating") or ""),
            "cwe": str(attrs.get("cwe") or ""),
            "total_awarded_amount": attrs.get("total_awarded_amount"),
            "disclosed_at": str(attrs.get("disclosed_at") or ""),
            "substate": str(attrs.get("substate") or ""),
            "program_handle": handle,  # already filtered server-side to this program
        })
    return {"ok": True, "handle": handle, "items": items}


def fetch_my_reports(
    api_username: str,
    api_token: str,
    *,
    page: int = 1,
    page_size: int = _DEFAULT_PAGE_SIZE,
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """The operator's own submitted reports across every program. Returns
    {"ok", "page", "items": [...]} or {"ok": False, "error"}."""
    missing = _missing_creds(api_username, api_token)
    if missing:
        return missing
    query = urllib.parse.urlencode({"page[number]": max(1, int(page or 1)), "page[size]": _clamp_page_size(page_size)})
    result, err = _get(f"{_API_BASE}/me/reports?{query}", api_username=api_username, api_token=api_token,
                       timeout=timeout, fetch=fetch, noun="reports")
    if err:
        return err
    items: list[dict[str, Any]] = []
    for row in result.get("data") or []:
        attrs = (row or {}).get("attributes") or {}
        items.append({
            "id": str((row or {}).get("id") or ""),
            "title": str(attrs.get("title") or ""),
            "state": str(attrs.get("state") or ""),
            "bounty_awarded_at": attrs.get("bounty_awarded_at"),
            "swag_awarded_at": attrs.get("swag_awarded_at"),
            "last_activity_at": attrs.get("last_activity_at"),
        })
    return {"ok": True, "page": max(1, int(page or 1)), "items": items}


def fetch_report_status(
    report_id: str,
    api_username: str,
    api_token: str,
    *,
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """The current state of one report GreyIQ (or the operator) submitted. Returns
    {"ok", "id", "state", "title", "bounty_awarded_at", "swag_awarded_at",
    "last_activity_at"} or {"ok": False, "error"}."""
    try:
        clean_id = str(int(str(report_id).strip()))
    except (TypeError, ValueError):
        return {"ok": False, "error": "A numeric HackerOne report id is required."}
    missing = _missing_creds(api_username, api_token)
    if missing:
        return missing
    result, err = _get(f"{_API_BASE}/reports/{clean_id}", api_username=api_username, api_token=api_token,
                       timeout=timeout, fetch=fetch, noun="report")
    if err:
        return err
    data = result.get("data") or {}
    attrs = (data or {}).get("attributes") or {}
    return {
        "ok": True,
        "id": clean_id,
        "state": str(attrs.get("state") or ""),
        "title": str(attrs.get("title") or ""),
        "bounty_awarded_at": attrs.get("bounty_awarded_at"),
        "swag_awarded_at": attrs.get("swag_awarded_at"),
        "last_activity_at": attrs.get("last_activity_at"),
    }


def fetch_earnings(
    api_username: str,
    api_token: str,
    *,
    page: int = 1,
    page_size: int = _DEFAULT_PAGE_SIZE,
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """The operator's own bounty/reward payment history. Returns
    {"ok", "page", "items": [...]} or {"ok": False, "error"}."""
    missing = _missing_creds(api_username, api_token)
    if missing:
        return missing
    query = urllib.parse.urlencode({"page[number]": max(1, int(page or 1)), "page[size]": _clamp_page_size(page_size)})
    result, err = _get(f"{_API_BASE}/payments/earnings?{query}", api_username=api_username, api_token=api_token,
                       timeout=timeout, fetch=fetch, noun="earnings")
    if err:
        return err
    items: list[dict[str, Any]] = []
    for row in result.get("data") or []:
        attrs = (row or {}).get("attributes") or {}
        items.append({
            "id": str((row or {}).get("id") or ""),
            # HackerOne's JSON:API 'type' can appear as the resource type itself
            # (e.g. 'earning-bounty-earned') or as an attribute — check both rather
            # than assume one, so a shape difference degrades to '' instead of KeyError.
            "type": str(attrs.get("type") or (row or {}).get("type") or ""),
            "amount": attrs.get("amount"),
            "created_at": str(attrs.get("created_at") or ""),
        })
    return {"ok": True, "page": max(1, int(page or 1)), "items": items}


def fetch_balance(
    api_username: str,
    api_token: str,
    *,
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """The operator's current HackerOne account balance. Returns {"ok", "balance": {...}}
    (raw attributes, passed through as-is rather than guessing field names) or
    {"ok": False, "error"}."""
    missing = _missing_creds(api_username, api_token)
    if missing:
        return missing
    result, err = _get(f"{_API_BASE}/payments/balance", api_username=api_username, api_token=api_token,
                       timeout=timeout, fetch=fetch, noun="balance")
    if err:
        return err
    data = result.get("data") or {}
    return {"ok": True, "balance": (data or {}).get("attributes") or {}}
