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

import re
import urllib.error
import urllib.parse
from typing import Any, Callable

from bughunter import taxonomy

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
        rid = str((row or {}).get("id") or "").strip()
        items.append({
            "id": rid,
            "url": f"https://hackerone.com/reports/{rid}" if rid.isdigit() else "",
            "title": str(attrs.get("title") or ""),
            "severity_rating": str(attrs.get("severity_rating") or ""),
            "cwe": str(attrs.get("cwe") or ""),
            "total_awarded_amount": attrs.get("total_awarded_amount"),
            "disclosed_at": str(attrs.get("disclosed_at") or ""),
            "substate": str(attrs.get("substate") or ""),
            "program_handle": handle,  # already filtered server-side to this program
        })
    return {"ok": True, "handle": handle, "items": items}


# ---------------------------------------------------------------------------
# Pre-submit duplicate detection (against a program's disclosed reports)
# ---------------------------------------------------------------------------
# Duplicate is the #1 bug-bounty rejection reason. fetch_hacktivity already pulls a
# program's disclosed reports; this compares a pending finding against them so the
# operator gets a "this looks like #12345" warning BEFORE filing. Deterministic /
# offline — pure string + CWE overlap, no network, no model.
_DUP_STOPWORDS = frozenset({
    "the", "a", "an", "in", "on", "at", "of", "to", "and", "or", "for", "with", "via",
    "is", "are", "was", "by", "from", "vulnerability", "issue", "bug", "security",
})


def _dup_tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", str(text or "").lower())
    return {w for w in words if len(w) > 2 and w not in _DUP_STOPWORDS}


def find_probable_duplicates(
    title: str, cwe: str, items: list[dict[str, Any]], *, threshold: float = 0.4, limit: int = 5,
) -> list[dict[str, Any]]:
    """Score a pending finding's (title, cwe) against disclosed reports; return the most
    similar above ``threshold``, most-similar first.

    Score = Jaccard token overlap of titles, boosted when the CWE matches. Pure, total,
    never raises — an empty/garbage input just yields []. This is an advisory signal, never
    a gate: it warns, it does not block a submit.
    """
    my_tokens = _dup_tokens(title)
    my_cwe = taxonomy.cwe_number(cwe) if title or cwe else ""
    if not my_tokens:
        return []
    scored: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        their_tokens = _dup_tokens(item.get("title"))
        if not their_tokens:
            continue
        overlap = my_tokens & their_tokens
        union = my_tokens | their_tokens
        jaccard = len(overlap) / len(union) if union else 0.0
        cwe_match = bool(my_cwe) and taxonomy.cwe_number(item.get("cwe")) == my_cwe
        score = min(1.0, jaccard + (0.25 if cwe_match else 0.0))
        if score < threshold:
            continue
        reasons = []
        if cwe_match:
            reasons.append(f"same CWE ({my_cwe})")
        if overlap:
            reasons.append("shared terms: " + ", ".join(sorted(overlap)[:6]))
        scored.append({
            "title": str(item.get("title") or ""),
            "url": str(item.get("url") or ""),
            "id": str(item.get("id") or ""),
            "cwe": str(item.get("cwe") or ""),
            "severity_rating": str(item.get("severity_rating") or ""),
            "disclosed_at": str(item.get("disclosed_at") or ""),
            "score": round(score, 3),
            "reason": "; ".join(reasons) or "similar title",
        })
    scored.sort(key=lambda row: row["score"], reverse=True)
    return scored[:limit]


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
    data = result.get("data")
    # Guard data's type before .get(): an unexpected response shape for this
    # single-resource endpoint (data as a non-dict truthy value) would otherwise
    # raise AttributeError, breaking this module's documented never-raises contract.
    attrs = data.get("attributes") or {} if isinstance(data, dict) else {}
    return {
        "ok": True,
        "id": clean_id,
        "state": str(attrs.get("state") or ""),
        "title": str(attrs.get("title") or ""),
        "bounty_awarded_at": attrs.get("bounty_awarded_at"),
        "swag_awarded_at": attrs.get("swag_awarded_at"),
        # The cumulative bounty paid on this report — so the sync can record the REAL amount into the
        # ledger (feeds the 'paid' EV boost) instead of leaving bounty at 0.0.
        "total_awarded_amount": attrs.get("total_awarded_amount"),
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
    """The operator's current HackerOne account balance. Returns {"ok", "balance": <amount>}
    or {"ok": False, "error"}. Per HackerOne's documented response
    (https://api.hackerone.com/hacker-resources/#get-balance) the amount is
    ``data.balance`` directly (not wrapped in the usual JSON:API 'attributes' envelope
    every other resource here uses) — read that field, with a defensive fallback to
    'attributes.balance' in case HackerOne ever normalizes the shape."""
    missing = _missing_creds(api_username, api_token)
    if missing:
        return missing
    result, err = _get(f"{_API_BASE}/payments/balance", api_username=api_username, api_token=api_token,
                       timeout=timeout, fetch=fetch, noun="balance")
    if err:
        return err
    data = result.get("data") or {}
    if "balance" in data:
        balance = data["balance"]
    else:
        attrs = data.get("attributes")
        balance = attrs.get("balance") if isinstance(attrs, dict) else None
    return {"ok": True, "balance": balance}
