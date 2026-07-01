"""GreyIQ BugHunter — HackerOne program/scope import.

Pulls a program's name/policy + its structured scope from HackerOne's OWN hacker API,
using the same API username/token GreyIQ already stores for submission (no new secret).
This is a **read-only, operator-triggered** call — never automatic/background — and is
the first outbound call in this engine that goes to a fixed, non-target host purely to
read data (the same posture as the crt.sh cert-transparency lookup in takeover_service.py).

Endpoints (HTTP Basic auth, api_username as username / api_token as password):
  GET https://api.hackerone.com/v1/hackers/programs/{handle}
  GET https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes

Many programs restrict structured-scope visibility to invited/paid researchers, so a
403/404 here is common and NOT an error in the app's sense — it degrades to a clear
message pointing at the CSV/paste import fallback (target_ingest.parse_hackerone_scope_csv).

Best-effort / never raises to the caller: every network/parse failure returns
``{"ok": False, "error": "..."}``.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

_API_HOST = "api.hackerone.com"
_API_BASE = f"https://{_API_HOST}/v1/hackers"
_UA = "GreyIQ-BugHunter/hackerone-import"
_MAX_ENTRIES = 500
_MAX_PAGES = 10  # 500 entries / 10 pages = 50/page, matches H1's default page size
# A bounded retry for connection-level failures AND transient/rate-limit HTTP
# statuses (429/5xx) -- but NEVER 401/403/404, which are deterministic auth/
# permission/not-found outcomes this module's own docstring already treats as
# expected, not errors. Honors a 429's Retry-After header, capped so a large
# value can't stall an operator-triggered UI action for long.
_MAX_FETCH_ATTEMPTS = 3
_RETRY_BACKOFF_S = 0.5
_RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
_MAX_RETRY_AFTER_S = 5.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Capture, never follow: a 3xx is surfaced as HTTPError instead of urllib's default
    behavior of silently re-sending the Basic-auth Authorization header to whatever host
    the Location header names (see active_verify_service.py's identical pattern)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, N802
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _is_hackerone_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.hostname == _API_HOST


def _fetch_json(url: str, *, api_username: str, api_token: str, timeout: float) -> Any:
    if not _is_hackerone_url(url):
        # Defense in depth: this function is the only thing that ever attaches the
        # Basic-auth credentials, so it must refuse to send them anywhere but the fixed
        # HackerOne API host, no matter what URL a caller (or a paginated response's
        # links.next) hands it.
        raise ValueError(f"refusing to send HackerOne API credentials to a non-HackerOne URL ({url!r})")
    auth = base64.b64encode(f"{api_username}:{api_token}".encode()).decode()
    req = urllib.request.Request(
        url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json", "User-Agent": _UA}
    )
    # Every retry reuses this SAME already-validated request/URL -- _is_hackerone_url
    # was already checked above and _NoRedirect never follows a hop, so a retry can
    # never end up sending credentials anywhere but the pinned API host.
    for attempt in range(1, _MAX_FETCH_ATTEMPTS + 1):
        try:
            with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310 - _is_hackerone_url pins the host; _NoRedirect blocks off-host hops
                return json.loads(resp.read(8_000_000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code not in _RETRYABLE_HTTP_CODES or attempt >= _MAX_FETCH_ATTEMPTS:
                raise
            wait = _RETRY_BACKOFF_S * attempt
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            if retry_after:
                try:
                    # max(0.0, ...) -- a malformed/hostile negative Retry-After must never
                    # reach time.sleep(), which raises ValueError on a negative duration.
                    wait = max(0.0, min(float(retry_after), _MAX_RETRY_AFTER_S))
                except ValueError:
                    pass
            time.sleep(wait)
        except (urllib.error.URLError, OSError, TimeoutError):
            if attempt >= _MAX_FETCH_ATTEMPTS:
                raise
            time.sleep(_RETRY_BACKOFF_S * attempt)


def _clean_entry(attrs: dict[str, Any]) -> dict[str, Any] | None:
    identifier = str(attrs.get("asset_identifier") or "").strip()
    if not identifier:
        return None
    return {
        "identifier": identifier,
        "asset_type": str(attrs.get("asset_type") or ""),
        "eligible_for_submission": bool(attrs.get("eligible_for_submission", True)),
        "eligible_for_bounty": bool(attrs.get("eligible_for_bounty", False)),
        "instruction": str(attrs.get("instruction") or ""),
        "max_severity": str(attrs.get("max_severity") or ""),
    }


def _error_for(exc: urllib.error.HTTPError) -> str:
    if exc.code == 401:
        return "HackerOne rejected the API credentials (401) — check your API username/token in the Submissions tab."
    if exc.code in (403, 404):
        return (
            f"HackerOne returned {exc.code} for this program's scope — this is common: many programs "
            "don't expose structured scope via the API to every researcher. Use CSV or paste import instead."
        )
    return f"HackerOne API HTTP {exc.code}: {exc.reason}"


def fetch_structured_scope(
    handle: str,
    api_username: str,
    api_token: str,
    *,
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
    max_entries: int = _MAX_ENTRIES,
) -> dict[str, Any]:
    """Fetch a program's name/policy + its structured scope from the HackerOne hacker API.

    ``fetch`` is injectable for offline testing: ``fetch(url, api_username=, api_token=,
    timeout=) -> parsed JSON`` (raises on HTTP error, matching urllib semantics). Returns
    ``{"ok", "handle", "program_name", "policy_excerpt", "offers_bounty", "program_stats",
    "structured_scope", "warnings", "error"}`` — never raises."""
    handle = str(handle or "").strip()
    if not handle:
        return {"ok": False, "error": "A HackerOne program handle is required."}
    if not (api_username and api_token):
        return {"ok": False, "error": "Save your HackerOne API username + token in the Submissions tab first."}
    fetch = fetch or _fetch_json
    safe_handle = urllib.parse.quote(handle, safe="")

    program_name, policy_excerpt, offers_bounty = handle, "", False
    program_stats: dict[str, Any] = {}
    try:
        program = fetch(f"{_API_BASE}/programs/{safe_handle}", api_username=api_username, api_token=api_token, timeout=timeout)
        # Guard BOTH levels: an unexpected response shape (a proxy/WAF error page
        # shaped like JSON:API, an API version change) could make "data" itself a
        # non-dict truthy value (e.g. a list) -- .get("attributes") on that raises
        # AttributeError, breaking this function's documented never-raises contract.
        program_data = program.get("data") if isinstance(program, dict) else None
        attrs = program_data.get("attributes") or {} if isinstance(program_data, dict) else {}
        program_name = str(attrs.get("name") or handle)
        policy_excerpt = str(attrs.get("policy") or "")[:4000]
        offers_bounty = bool(attrs.get("offers_bounties"))
        # Real signals the program resource carries (verified against HackerOne's docs —
        # there is NO structured per-severity bounty table anywhere in the API, only this
        # handful of flags plus the free-text policy above). Coerced to fixed known types
        # so a caller never receives an unbounded blob from the API.
        program_stats = {
            "offers_bounties": offers_bounty,
            "submission_state": str(attrs.get("submission_state") or ""),
            "currency": str(attrs.get("currency") or ""),
            "open_scope": bool(attrs.get("open_scope")),
            "fast_payments": bool(attrs.get("fast_payments")),
            "gold_standard_safe_harbor": bool(attrs.get("gold_standard_safe_harbor")),
            "allows_bounty_splitting": bool(attrs.get("allows_bounty_splitting")),
            "number_of_reports_for_user": int(attrs.get("number_of_reports_for_user") or 0),
            "number_of_valid_reports_for_user": int(attrs.get("number_of_valid_reports_for_user") or 0),
            "bounty_earned_for_user": float(attrs.get("bounty_earned_for_user") or 0.0),
            "state": str(attrs.get("state") or ""),
            "started_accepting_at": str(attrs.get("started_accepting_at") or ""),
        }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": _error_for(exc)}
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return {"ok": False, "error": f"Could not reach HackerOne: {exc}"}

    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    url: str | None = f"{_API_BASE}/programs/{safe_handle}/structured_scopes"
    pages = 0
    try:
        while url and pages < _MAX_PAGES and len(entries) < max_entries:
            page = fetch(url, api_username=api_username, api_token=api_token, timeout=timeout)
            pages += 1
            if not isinstance(page, dict):
                break
            for row in page.get("data") or []:
                cleaned = _clean_entry((row or {}).get("attributes") or {})
                if cleaned:
                    entries.append(cleaned)
                if len(entries) >= max_entries:
                    warnings.append(f"Capped to the first {max_entries} scope entries.")
                    break
            next_url = ((page.get("links") or {}).get("next")) or None
            # Pin pagination to the HackerOne API host at the ORCHESTRATION level too (not
            # just inside _fetch_json) so this holds regardless of which `fetch` a caller
            # injects: a compromised/malicious response must never redirect the next
            # Basic-auth-credentialed request to an attacker-controlled host.
            if next_url is not None and not _is_hackerone_url(next_url):
                warnings.append("HackerOne returned a scope-pagination link outside the API host — stopped early for safety.")
                next_url = None
            url = next_url
    except urllib.error.HTTPError as exc:
        if not entries:
            return {"ok": False, "error": _error_for(exc)}
        warnings.append(f"Stopped early: {_error_for(exc)}")
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        if not entries:
            return {"ok": False, "error": f"Could not reach HackerOne: {exc}"}
        warnings.append(f"Stopped early: could not reach HackerOne ({exc}).")

    if not entries:
        warnings.append(
            "No structured scope entries were returned — either this program has none configured, "
            "or your account doesn't have API scope visibility. Use CSV or paste import instead."
        )
    return {
        "ok": True,
        "handle": handle,
        "program_name": program_name,
        "policy_excerpt": policy_excerpt,
        "offers_bounty": offers_bounty,
        "program_stats": program_stats,
        "structured_scope": entries,
        "warnings": warnings,
    }
