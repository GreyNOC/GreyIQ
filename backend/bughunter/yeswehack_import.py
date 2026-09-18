"""GreyIQ BugHunter — YesWeHack program/scope import.

Pulls a program's title, rules of engagement, structured scope, out-of-scope list and
— the part that actually matters for hunting — the program's REQUIRED per-program
user-agent MARKER from YesWeHack's OWN API. That marker is how a program recognizes
your traffic as authorized research; YesWeHack's own Burp extension appends it to every
request's User-Agent, and GreyIQ's ``portfolio.user_agent_suffix`` /
``web_ingest.set_ua_suffix`` do the same thing, so an imported program arrives already
wired to hunt in-policy.

This is a **read-only, operator-triggered** call — never automatic/background — to a
fixed, non-target host, the same posture as hackerone_import.py and the crt.sh
cert-transparency lookup in takeover_service.py.

Endpoints (verified against YesWeHack's own clients and live responses):
  POST https://api.yeswehack.com/login            {"email","password"} -> {"token"} | {"totp_token"}
  POST https://api.yeswehack.com/account/totp     {"token","code"}     -> {"token"}
  GET  https://api.yeswehack.com/programs?page=N  -> {"pagination", "items":[{title,slug,...}]}
  GET  https://api.yeswehack.com/programs/{slug}  -> the full program resource

Four auth modes, in the order an operator is most likely to want them:
  * anonymous  — no credential at all. YesWeHack serves its PUBLIC programs' full scope,
                 rules and marker unauthenticated (verified live), so the common case
                 needs no secret. This is the default.
  * jwt        — ``Authorization: Bearer <jwt>``; needed for private/invited programs.
  * pat        — ``X-AUTH-TOKEN: <pat>``; YesWeHack Personal Access Tokens are issued to
                 program-manager/business-unit roles, not hunter accounts.
  * login      — exchange email+password (+TOTP) for a JWT via POST /login. The password
                 is used for that one exchange and NEVER stored or returned; only the
                 resulting JWT is handed back for the caller to persist.

Best-effort / never raises to the caller: every network/parse failure returns
``{"ok": False, "error": "..."}``.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

_API_HOST = "api.yeswehack.com"
_API_BASE = f"https://{_API_HOST}"
_UA = "GreyIQ-BugHunter/yeswehack-import"
_MAX_ENTRIES = 500
_MAX_PAGES = 20
_MAX_LIST_ENTRIES = 600
# Same bounded retry policy as hackerone_import: connection-level failures AND
# transient/rate-limit statuses (429/5xx), but NEVER 401/403/404, which are deterministic
# auth/permission/not-found outcomes. Honors a 429's Retry-After, capped so a hostile or
# large value can't stall an operator-triggered UI action.
_MAX_FETCH_ATTEMPTS = 3
_RETRY_BACKOFF_S = 0.5
_RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
_MAX_RETRY_AFTER_S = 5.0

# portfolio.notes is bounded at 4000 chars, so the rules digest is built to fit.
_MAX_NOTES = 4000
_MAX_RULES_EXCERPT = 4000

# A YesWeHack out-of-scope list is free prose ("All content which is not listed as
# Scopes...") mixed with real host patterns, often annotated ("staging.acme.example (do
# not test)") or written as a URL. Only lines that reduce to a bare host token may become
# enforced out-of-scope hosts; the rest stays readable in the notes digest instead of
# polluting the host matcher with sentences.
_HOST_ONLY_RE = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,63}$")
_IP_SHAPED_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")

# YesWeHack scope_type -> the asset-type vocabulary the rest of GreyIQ already displays
# (HackerOne's, which target_ingest/vdp_policy/the scope table all speak). Unknown types
# fall through to the raw YesWeHack value rather than being invented into something else.
_SCOPE_TYPE_TO_ASSET_TYPE = {
    "web-application": "URL",
    "api": "URL",
    "ip-address": "CIDR",
    "mobile-application-android": "GOOGLE_PLAY_APP_ID",
    "mobile-application-ios": "APPLE_STORE_APP_ID",
    "application": "OTHER",
    "executable": "DOWNLOADABLE_EXECUTABLES",
    "open-source": "SOURCE_CODE",
    "other": "OTHER",
}

# scope.asset_value names which reward grid applies to that asset.
_ASSET_VALUE_TO_GRID = {
    "VERY_LOW": "reward_grid_very_low",
    "LOW": "reward_grid_low",
    "MEDIUM": "reward_grid_medium",
    "HIGH": "reward_grid_high",
    "CRITICAL": "reward_grid_critical",
}
_GRID_TIERS = ("bounty_low", "bounty_medium", "bounty_high", "bounty_critical")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Capture, never follow: a 3xx is surfaced as HTTPError instead of urllib's default
    behavior of silently re-sending the Authorization/X-AUTH-TOKEN header to whatever host
    the Location header names (same pattern as hackerone_import.py)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, N802
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _is_yeswehack_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.hostname == _API_HOST


def _auth_headers(token: str, token_kind: str) -> dict[str, str]:
    """The one place a YesWeHack credential becomes a header. An empty token is the
    anonymous mode — no auth header at all, which is a fully supported way to read a
    public program."""
    token = str(token or "").strip()
    if not token:
        return {}
    if str(token_kind or "").strip().lower() == "pat":
        return {"X-AUTH-TOKEN": token}
    return {"Authorization": f"Bearer {token}"}


def _fetch_json(
    url: str,
    *,
    token: str = "",
    token_kind: str = "",
    timeout: float = 30.0,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> Any:
    if not _is_yeswehack_url(url):
        # Defense in depth: this function is the only thing that ever attaches the
        # credential, so it must refuse to send it anywhere but the fixed YesWeHack API
        # host, no matter what URL a caller hands it.
        raise ValueError(f"refusing to send YesWeHack API credentials to a non-YesWeHack URL ({url!r})")
    headers = {"Accept": "application/json", "User-Agent": _UA, **_auth_headers(token, token_kind)}
    body: bytes | None = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    # Every retry reuses this SAME already-validated request/URL -- _is_yeswehack_url was
    # checked above and _NoRedirect never follows a hop, so a retry can never end up
    # sending the credential anywhere but the pinned API host.
    for attempt in range(1, _MAX_FETCH_ATTEMPTS + 1):
        try:
            with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310 - _is_yeswehack_url pins the host; _NoRedirect blocks off-host hops
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


def _error_for(exc: urllib.error.HTTPError, *, noun: str = "this program") -> str:
    if exc.code == 401:
        return (
            "YesWeHack rejected the credential (401) — it may have expired. A YesWeHack JWT is "
            "short-lived; sign in again in the Submissions tab, or leave the credential blank to "
            "read public programs anonymously."
        )
    if exc.code == 403:
        return (
            f"YesWeHack returned 403 for {noun} — this is a private program your account isn't "
            "invited to, or your credential lacks access. Public programs need no credential at all."
        )
    if exc.code == 404:
        return (
            f"YesWeHack has no program with that slug (404). The slug is the last path segment of "
            "the program URL — yeswehack.com/programs/<slug>."
        )
    return f"YesWeHack API HTTP {exc.code}: {exc.reason}"


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _iter_strings(value: Any, limit: int = 200) -> list[str]:
    """Every list-shaped field read from the API goes through here.

    A third-party response is not a contract: ``scopes`` or ``out_of_scope`` coming back as
    an int, a string or null must not make an iteration raise, because this module documents
    that it never raises and the API layer turns an escaped exception into an opaque 500
    instead of the ``{"ok": False, "error": ...}`` the UI knows how to show."""
    if not isinstance(value, list):
        return []
    return [str(v) for v in value[:limit] if v is not None and not isinstance(v, (dict, list))]


def _text(value: Any, limit: int) -> str:
    """Bounded, control-character-free text from a third-party field. Applied to the
    PREVIEW as well as to storage — portfolio's cleaners bound what is persisted, but the
    preview response goes straight to the browser and was otherwise unbounded."""
    raw = str(value or "")
    return "".join(c for c in raw if c == " " or 0x20 < ord(c) < 0x7f or ord(c) > 0x7f)[:limit]


def _host_token(value: str) -> str:
    """Reduce one out-of-scope line to the bare host token the scope matchers honor ("" if
    it is prose).

    This normalization is load-bearing, not cosmetic. Both exclusion matchers —
    ``campaign._target_host_excluded`` and ``active_verify_service``'s scope check — parse
    the CANDIDATE host but compare the exclusion token verbatim:

        if host == token or host.endswith("." + token) or reg == token

    So an exclusion stored as ``https://shop.acme.example/checkout`` or
    ``api.acme.example:8443`` never matches anything and is silently inert — the host stays
    huntable while the UI claims it was excluded. Reducing to the host HERE, where the data
    arrives, is what makes a YesWeHack exclusion actually bind.

    An annotated line ("staging.acme.example (do not test)") keeps its first token; a line
    whose first token is not a host is prose and returns "". A CIDR is kept verbatim: it is
    the honest representation, and the positive side cannot put a CIDR host in scope either,
    so nothing is exposed by it not matching."""
    text = value.strip().rstrip(".,;")
    if not text or len(text) > 300:
        return ""
    if _IP_SHAPED_RE.match(text):
        return text
    first = text.split()[0].rstrip(".,;") if text.split() else ""
    if not first:
        return ""
    if "://" in first:
        host = urllib.parse.urlparse(first).hostname or ""
    else:
        host = first.split("/", 1)[0]
        # host:port — but never an IPv6 literal, which is full of colons.
        if host.count(":") == 1:
            host = host.split(":", 1)[0]
    host = host.strip().strip("[]").lower()
    if not host:
        return ""
    return host if (_IP_SHAPED_RE.match(host) or _HOST_ONLY_RE.match(host)) else ""


def _grid_for(program: dict[str, Any], asset_value: str) -> dict[str, Any]:
    """The reward grid that applies to an asset of this value tier, falling back to the
    program default — YesWeHack leaves the per-tier grids all-null when a program prices
    every asset the same."""
    grid_key = _ASSET_VALUE_TO_GRID.get(str(asset_value or "").strip().upper(), "")
    grid = program.get(grid_key) if grid_key else None
    if isinstance(grid, dict) and any(grid.get(t) is not None for t in _GRID_TIERS):
        return grid
    default = program.get("reward_grid_default")
    return default if isinstance(default, dict) else {}


def _bounty_summary(grid: dict[str, Any], currency: str) -> str:
    amounts = [_as_int(grid.get(t)) for t in _GRID_TIERS if grid.get(t) is not None]
    amounts = [a for a in amounts if a > 0]
    if not amounts:
        return ""
    unit = f" {currency}" if currency else ""
    low, high = min(amounts), max(amounts)
    return f"{low}–{high}{unit}" if low != high else f"{low}{unit}"


def _clean_entry(raw: Any, program: dict[str, Any], currency: str) -> dict[str, Any] | None:
    """One YesWeHack scope row -> the structured-scope shape the rest of GreyIQ speaks
    (portfolio._clean_scope_entry / target_ingest._finalize_scope)."""
    if not isinstance(raw, dict):
        return None
    identifier = _text(raw.get("scope"), 500).strip()
    if not identifier:
        return None
    scope_type = _text(raw.get("scope_type"), 60).strip()
    type_name = _text(raw.get("scope_type_name"), 60).strip()
    asset_value = _text(raw.get("asset_value"), 20).strip().upper()
    grid = _grid_for(program, asset_value)
    bounty = _bounty_summary(grid, currency)
    # Human-readable context for the scope table: what kind of asset it is, how the
    # program values it, and what that tier actually pays. All of it comes straight from
    # the API — nothing is estimated.
    bits = [b for b in (type_name or scope_type, f"asset value {asset_value}" if asset_value else "",
                        f"bounty {bounty}" if bounty else "") if b]
    return {
        "identifier": identifier,
        # YesWeHack's scope rows carry no per-asset id (unlike HackerOne's
        # structured_scope_id), so there is nothing to route a submission to. Left empty
        # rather than invented.
        "id": "",
        "asset_type": _SCOPE_TYPE_TO_ASSET_TYPE.get(scope_type, scope_type),
        "eligible_for_submission": True,
        "eligible_for_bounty": bool(program.get("bounty")) and bool(bounty),
        "instruction": " · ".join(bits)[:2000],
        # YesWeHack's asset_value is the asset's value tier (it selects the reward grid),
        # which is the same "how much does this asset matter" signal GreyIQ shows in the
        # max_severity column for HackerOne imports.
        "max_severity": asset_value.lower(),
    }


def _out_of_scope_entries(program: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], int]:
    """Split the out_of_scope list into enforceable host patterns and readable prose.

    Host-shaped lines become structured-scope rows with eligible_for_submission=False,
    which is what portfolio._normalize turns into out_of_scope_hosts (an exclusion the
    hunt actually honors). Everything else is returned as prose for the notes digest.

    Third element: how many raw lines were past the read cap and never classified — the
    caller must warn about those rather than let a forbidden host vanish quietly."""
    entries: list[dict[str, Any]] = []
    prose: list[str] = []
    seen: set[str] = set()
    raw = program.get("out_of_scope")
    raw_count = len(raw) if isinstance(raw, list) else 0
    # _iter_strings' 200 default is a guard for display lists; applying it HERE silently
    # dropped exclusion 201 and beyond before the 500-entry budget below ever ran, so a
    # forbidden host in a long list just vanished. Read up to the real entry cap, and the
    # caller reports anything past it rather than letting it disappear.
    for item in _iter_strings(raw, limit=_MAX_ENTRIES):
        text = item.strip()
        if not text:
            continue
        token = _host_token(text)
        if not token:
            prose.append(text)
            continue
        if token in seen:
            continue
        seen.add(token)
        entries.append({
            "identifier": token,
            "id": "",
            "asset_type": "",
            "eligible_for_submission": False,
            "eligible_for_bounty": False,
            # Keep the program's own wording, since the stored identifier is a reduction
            # of it — the operator can still see what the program actually wrote.
            "instruction": f"Out of scope (YesWeHack program): {text}"[:2000],
            "max_severity": "",
        })
    return entries, prose, max(0, raw_count - _MAX_ENTRIES)


def _marker_suffix(marker: str) -> str:
    """The program's user-agent marker, shaped for verbatim append.

    GreyIQ appends ``user_agent_suffix`` to the User-Agent with NO separator inserted
    (web_ingest.set_ua_suffix), while YesWeHack's own Burp extension appends the marker
    after a space ("User-Agent: $1 <marker>"). So a leading space is added here when the
    program's own value doesn't already carry one — matching YesWeHack's tooling exactly."""
    # Bounded to 120 to match ProgramUpsertRequest.user_agent_suffix / portfolio's own
    # cap: a longer value would prefill the form with something the Save endpoint then
    # rejects with a 422, failing the WHOLE program save over one oversized marker.
    marker = _text(marker, 120)
    stripped = marker.strip()
    if not stripped:
        return ""
    return marker if marker[:1].isspace() else f" {stripped}"[:120]


def _bullets(title: str, items: list[str], limit: int = 20) -> list[str]:
    rows = [r for r in (_text(i, 500).strip() for i in items) if r]
    if not rows:
        return []
    out = [f"## {title}"]
    out.extend(f"- {r}" for r in rows[:limit])
    if len(rows) > limit:
        out.append(f"- …and {len(rows) - limit} more (see the program page).")
    return out


def _notes_digest(program: dict[str, Any], oos_prose: list[str], currency: str,
                  unenforceable: list[str] | None = None) -> str:
    """A compact, operator-readable digest for the program's notes field.

    Ordered by what will get you removed from a program first: the hard operational
    constraints, then what's excluded, then what does and doesn't qualify, then as much
    of the rules text as fits. Bounded to portfolio.notes' 4000-char limit."""
    blocks: list[list[str]] = []

    constraints: list[str] = []
    marker = _text(program.get("user_agent"), 120).strip()
    if marker:
        constraints.append(f"- REQUIRED user-agent marker: `{marker}` (appended to every request).")
    if program.get("vpn_active"):
        vpn_ips = [i for i in (_text(x, 60).strip() for x in _iter_strings(program.get("vpn_ips"))) if i]
        constraints.append("- YesWeHack VPN is REQUIRED for this program."
                           + (f" VPN IPs: {', '.join(vpn_ips[:10])}." if vpn_ips else ""))
    restricted = [i for i in (_text(x, 60).strip() for x in _iter_strings(program.get("restricted_ips"))) if i]
    if restricted:
        constraints.append(f"- Testing restricted to these source IPs: {', '.join(restricted[:10])}.")
    account_access = _text(program.get("account_access"), 400).strip()
    if account_access:
        constraints.append(f"- Test accounts: {account_access}")
    if program.get("disabled"):
        constraints.append(f"- PROGRAM DISABLED: {_text(program.get('disable_message'), 300).strip()}")
    # Prose exclusions bind the operator but CANNOT be enforced by the host matcher, so
    # they belong with the other things that will get you removed from a program.
    if unenforceable:
        constraints.append(
            f"- {len(unenforceable)} out-of-scope rule(s) below are prose, not host patterns — "
            "GreyIQ cannot enforce them automatically. Read them before you hunt."
        )
    if constraints:
        blocks.append(["## Rules of engagement (YesWeHack)", *constraints])

    grid = program.get("reward_grid_default")
    if isinstance(grid, dict) and any(grid.get(t) is not None for t in _GRID_TIERS):
        unit = f" {currency}" if currency else ""
        row = ", ".join(
            f"{t.replace('bounty_', '')} {_as_int(grid.get(t))}{unit}"
            for t in _GRID_TIERS if grid.get(t) is not None
        )
        blocks.append(["## Default reward grid", f"- {row}"])

    blocks.append(_bullets("Out of scope (not host-matchable — read these)", oos_prose))
    blocks.append(_bullets("Qualifying vulnerabilities", _iter_strings(program.get("qualifying_vulnerability"))))
    blocks.append(_bullets("Non-qualifying vulnerabilities", _iter_strings(program.get("non_qualifying_vulnerability"))))

    text = "\n".join("\n".join(b) for b in blocks if b)
    rules = _text(program.get("rules"), _MAX_RULES_EXCERPT).strip()
    if rules:
        header = "\n## Program rules\n"
        cut_note = "\n…(truncated — full rules on the program page)"
        # Budget for the truncation marker, not just the header. Without this the marker
        # was appended AFTER the budget was spent and the final clamp chopped it straight
        # back off — so a clipped rules section ended mid-sentence saying nothing about
        # having been clipped, but only when the rules had no newline in the clip window.
        room = _MAX_NOTES - len(text) - len(header) - len(cut_note) - 1
        if room > 200:
            if len(rules) > room:
                clipped = rules[:room]
                # Prefer a line boundary, but only if there is one -- rsplit returns the
                # whole string when there is not.
                head, sep, _ = clipped.rpartition("\n")
                clipped = (head if sep else clipped) + cut_note
            else:
                clipped = rules
            text = f"{text}{header}{clipped}" if text else f"## Program rules\n{clipped}"
        else:
            # The constraints alone filled the digest. Say the rules were left out rather
            # than letting the operator assume Notes is the whole story.
            note = "\n## Program rules\n…(the rules did not fit — read them on the program page)"
            text = (text[:_MAX_NOTES - len(note)] + note) if len(text) + len(note) > _MAX_NOTES else text + note
    return text[:_MAX_NOTES]


def _program_stats(program: dict[str, Any], currency: str) -> dict[str, Any]:
    """The program-level signals worth showing next to a saved program, coerced to fixed
    known types so a caller never receives an unbounded blob from the API."""
    stats = program.get("stats") if isinstance(program.get("stats"), dict) else {}
    return {
        "public": bool(program.get("public")),
        "vdp": bool(program.get("vdp")),
        "program_type": _text(program.get("type"), 40),
        "status": _text(program.get("status"), 40),
        "disabled": bool(program.get("disabled")),
        "offers_bounty": bool(program.get("bounty")),
        "offers_gift": bool(program.get("gift")),
        "currency": currency,
        "bounty_reward_min": _as_int(program.get("bounty_reward_min")),
        "bounty_reward_max": _as_int(program.get("bounty_reward_max")),
        "reports_count": _as_int(program.get("reports_count")),
        "average_reward": _as_int(stats.get("average_reward")),
        "max_reward": _as_int(stats.get("max_reward")),
        "average_first_response_days": _as_int(stats.get("average_first_time_response")),
        "vpn_required": bool(program.get("vpn_active")),
        "ip_restricted": bool(program.get("restricted_ips")),
        "hall_of_fame": bool(program.get("hall_of_fame")),
        "business_unit": _text((program.get("business_unit") or {}).get("name"), 120)
        if isinstance(program.get("business_unit"), dict) else "",
        "user_agent_marker": _text(program.get("user_agent"), 120),
    }


def login(
    email: str,
    password: str,
    *,
    totp_code: str = "",
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Exchange email + password (+ TOTP) for a YesWeHack JWT.

    The password is used for this one exchange and is NEVER stored, logged or returned —
    only the resulting JWT comes back, for the caller to persist in the secrets store.

    When the account has 2FA on, YesWeHack answers the first POST with a short-lived
    ``totp_token`` instead of a JWT. That exchange token is deliberately NOT returned to
    the caller; this function reports ``totp_required`` and the operator resubmits with a
    code, which is exactly how YesWeHack's own client handles it. Never raises."""
    email = str(email or "").strip()
    password = str(password or "")
    if not (email and password):
        return {"ok": False, "error": "Enter your YesWeHack email and password to sign in."}
    fetch = fetch or _fetch_json
    try:
        resp = fetch(f"{_API_BASE}/login", timeout=timeout, method="POST",
                     payload={"email": email, "password": password})
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"ok": False, "status": 401, "error": "YesWeHack rejected that email/password."}
        return {"ok": False, "status": exc.code, "error": _error_for(exc, noun="this account")}
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return {"ok": False, "error": f"Could not reach YesWeHack: {exc}"}

    if not isinstance(resp, dict):
        return {"ok": False, "error": "YesWeHack returned an unexpected sign-in response."}
    token = str(resp.get("token") or "").strip()
    if token:
        return {"ok": True, "token": token, "token_kind": "jwt",
                "message": f"Signed in to YesWeHack as {email}."}

    totp_token = str(resp.get("totp_token") or "").strip()
    if not totp_token:
        return {"ok": False, "error": "YesWeHack did not return a session token."}
    if not str(totp_code or "").strip():
        return {"ok": False, "totp_required": True,
                "error": "This account has 2FA enabled — re-enter the password with your 6-digit code."}
    try:
        second = fetch(f"{_API_BASE}/account/totp", timeout=timeout, method="POST",
                       payload={"token": totp_token, "code": str(totp_code).strip()})
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 401, 403):
            return {"ok": False, "status": exc.code, "totp_required": True,
                    "error": "YesWeHack rejected that 2FA code — codes expire fast, try the current one."}
        return {"ok": False, "status": exc.code, "error": _error_for(exc, noun="this account")}
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return {"ok": False, "error": f"Could not reach YesWeHack: {exc}"}

    token = str((second or {}).get("token") or "").strip() if isinstance(second, dict) else ""
    if not token:
        return {"ok": False, "totp_required": True, "error": "YesWeHack did not return a session token after 2FA."}
    return {"ok": True, "token": token, "token_kind": "jwt",
            "message": f"Signed in to YesWeHack as {email} (2FA accepted)."}


def verify_credentials(
    token: str,
    token_kind: str = "",
    *,
    fetch: Callable[..., Any] | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Probe the stored credential against a real endpoint (GET /programs?page=1) so the
    operator gets a server-authoritative yes/no instead of guessing.

    Unlike HackerOne's, an EMPTY credential is a valid, useful state here: YesWeHack
    serves public programs anonymously, so this reports that the anonymous path works
    rather than refusing. Never raises."""
    fetch = fetch or _fetch_json
    token = str(token or "").strip()
    try:
        page = fetch(f"{_API_BASE}/programs?page=1", token=token, token_kind=token_kind, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"ok": False, "status": 401, "error": (
                "YesWeHack rejected this credential (401). A YesWeHack JWT is short-lived — sign in "
                "again to mint a fresh one, or clear it to read public programs anonymously.")}
        return {"ok": False, "status": exc.code, "error": _error_for(exc, noun="the programs list")}
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return {"ok": False, "error": f"Could not reach YesWeHack: {exc}"}

    count = 0
    if isinstance(page, dict):
        pagination = page.get("pagination") if isinstance(page.get("pagination"), dict) else {}
        items = page.get("items")
        count = _as_int(pagination.get("nb_results")) or (len(items) if isinstance(items, list) else 0)
    if not token:
        return {"ok": True, "anonymous": True, "program_count": count,
                "message": f"YesWeHack reachable anonymously — {count} public program(s) visible. "
                           "Sign in only if you need a private/invited program."}
    return {"ok": True, "anonymous": False, "program_count": count,
            "message": f"YesWeHack accepted this credential — {count} program(s) visible."}


def list_programs(
    *,
    token: str = "",
    token_kind: str = "",
    query: str = "",
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
    max_entries: int = _MAX_LIST_ENTRIES,
) -> dict[str, Any]:
    """List the programs this credential can see (anonymous = the public catalogue), so
    the operator can find a program without already knowing its slug.

    Filtering is done locally on title/slug rather than by a server-side search parameter,
    because the documented list endpoint takes only ``page``. Never raises."""
    fetch = fetch or _fetch_json
    needle = str(query or "").strip().lower()
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    pages = 0
    page_num = 1
    total_pages = 1
    try:
        while page_num <= total_pages and pages < _MAX_PAGES and len(items) < max_entries:
            # The URL is built here from a pinned base and an integer page, so — unlike a
            # server-supplied "next" link — there is no path by which a hostile response
            # could redirect the next credentialed request off-host.
            page = fetch(f"{_API_BASE}/programs?page={int(page_num)}",
                         token=token, token_kind=token_kind, timeout=timeout)
            pages += 1
            if not isinstance(page, dict):
                break
            pagination = page.get("pagination") if isinstance(page.get("pagination"), dict) else {}
            total_pages = max(1, _as_int(pagination.get("nb_pages")) or 1)
            rows = page.get("items")
            for row in (rows if isinstance(rows, list) else []):
                if not isinstance(row, dict):
                    continue
                slug = _text(row.get("slug"), 200).strip()
                title = _text(row.get("title"), 200).strip()
                if not slug:
                    continue
                if needle and needle not in slug.lower() and needle not in title.lower():
                    continue
                items.append({
                    "slug": slug,
                    "title": title or slug,
                    "public": bool(row.get("public")),
                    "vdp": bool(row.get("vdp")),
                    "disabled": bool(row.get("disabled")),
                    "offers_bounty": bool(row.get("bounty")),
                    "bounty_reward_min": _as_int(row.get("bounty_reward_min")),
                    "bounty_reward_max": _as_int(row.get("bounty_reward_max")),
                    "scopes_count": _as_int(row.get("scopes_count")),
                    "reports_count": _as_int(row.get("reports_count")),
                    "average_first_response_days": _as_int(row.get("average_first_response_time")),
                    "activity_area": _text(row.get("activity_area"), 80),
                    "program_type": _text(row.get("type"), 40),
                })
                if len(items) >= max_entries:
                    warnings.append(f"Capped to the first {max_entries} programs.")
                    break
            page_num += 1
        if page_num <= total_pages and len(items) < max_entries:
            # The page cap stopped the walk early. Without this the wizard would render
            # "No program matched X" for a program that simply sat on an unvisited page —
            # a false negative presented as a definitive answer.
            warnings.append(
                f"Stopped after {pages} of {total_pages} pages of the YesWeHack catalogue — "
                "narrow the search, or paste the program slug directly."
            )
    except urllib.error.HTTPError as exc:
        if not items:
            return {"ok": False, "error": _error_for(exc, noun="the programs list")}
        warnings.append(f"Stopped early: {_error_for(exc, noun='the programs list')}")
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        if not items:
            return {"ok": False, "error": f"Could not reach YesWeHack: {exc}"}
        warnings.append(f"Stopped early: could not reach YesWeHack ({exc}).")
    return {"ok": True, "programs": items, "count": len(items), "warnings": warnings}


def fetch_program_scope(
    slug: str,
    *,
    token: str = "",
    token_kind: str = "",
    fetch: Callable[..., Any] | None = None,
    timeout: float = 30.0,
    max_entries: int = _MAX_ENTRIES,
) -> dict[str, Any]:
    """Fetch everything needed to hunt a YesWeHack program: scope, out-of-scope, rules,
    the required user-agent marker, reward grids and testing constraints.

    ``fetch`` is injectable for offline testing: ``fetch(url, token=, token_kind=,
    timeout=) -> parsed JSON`` (raises on HTTP error, matching urllib semantics).

    Returns ``{"ok", "slug", "handle", "program_name", "policy_excerpt", "offers_bounty",
    "program_stats", "structured_scope", "out_of_scope", "user_agent_marker",
    "user_agent_suffix", "notes_digest", "warnings", "error"}`` — never raises.

    The key names deliberately match hackerone_import.fetch_structured_scope where the
    meaning is the same, so the Program form consumes either import identically."""
    slug = str(slug or "").strip().strip("/")
    if not slug:
        return {"ok": False, "error": "A YesWeHack program slug is required."}
    if "/" in slug:
        # Accept a pasted program URL as a convenience — the slug is the last segment.
        slug = slug.rsplit("/", 1)[-1].strip()
        if not slug:
            return {"ok": False, "error": "A YesWeHack program slug is required."}
    fetch = fetch or _fetch_json
    safe_slug = urllib.parse.quote(slug, safe="")

    try:
        program = fetch(f"{_API_BASE}/programs/{safe_slug}",
                        token=token, token_kind=token_kind, timeout=timeout)
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": _error_for(exc)}
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return {"ok": False, "error": f"Could not reach YesWeHack: {exc}"}

    if not isinstance(program, dict):
        # An unexpected response shape (a proxy/WAF error page shaped like JSON, an API
        # version change) must not break this function's documented never-raises contract.
        return {"ok": False, "error": "YesWeHack returned an unexpected response for this program."}

    business_unit = program.get("business_unit")
    currency = str((business_unit or {}).get("currency") or "") if isinstance(business_unit, dict) else ""

    warnings: list[str] = []

    # EXCLUSIONS ARE BUDGETED FIRST, deliberately. If the cap has to drop something, losing
    # an in-scope row costs an opportunity; losing an out-of-scope row would leave a host
    # the program forbade looking merely un-listed, and the hunt would go at it. The safe
    # direction is the one that hunts less.
    oos_entries, oos_prose, oos_unread = _out_of_scope_entries(program)
    entries: list[dict[str, Any]] = oos_entries[:max_entries]
    if len(oos_entries) > len(entries):
        warnings.append(
            f"Only the first {len(entries)} of {len(oos_entries)} out-of-scope entries fit — "
            "add the rest to out-of-scope hosts by hand before hunting."
        )
    if oos_unread:
        warnings.append(
            f"{oos_unread} out-of-scope line(s) past the first {_MAX_ENTRIES} were not read at all — "
            "check the program page and add any hosts among them by hand before hunting."
        )

    raw_scopes = [s for s in (program.get("scopes") or []) if isinstance(s, dict)] \
        if isinstance(program.get("scopes"), list) else []
    dropped_in_scope = 0
    for index, raw in enumerate(raw_scopes):
        if len(entries) >= max_entries:
            dropped_in_scope = len(raw_scopes) - index
            break
        cleaned = _clean_entry(raw, program, currency)
        if cleaned:
            entries.append(cleaned)
    if dropped_in_scope:
        warnings.append(
            f"Capped at {max_entries} scope entries — {dropped_in_scope} in-scope "
            f"entr{'y' if dropped_in_scope == 1 else 'ies'} did not fit."
        )
    if oos_prose:
        # These bind the operator but the host matcher cannot enforce them. Never let that
        # pass silently: the fetch result is where it gets read.
        warnings.append(
            f"{len(oos_prose)} out-of-scope rule(s) are prose, not host patterns — GreyIQ "
            "cannot enforce them automatically; they are in Notes, read them before hunting."
        )

    marker = _text(program.get("user_agent"), 120).strip()
    if program.get("disabled"):
        warnings.append("This program is currently DISABLED on YesWeHack — do not test it.")
    if program.get("vpn_active"):
        warnings.append("This program REQUIRES the YesWeHack VPN — connect it before hunting.")
    if program.get("restricted_ips"):
        warnings.append("This program restricts testing to specific source IPs — check the rules before hunting.")
    if marker:
        warnings.append(f"Required user-agent marker '{marker}' has been set as this program's UA suffix.")
    else:
        warnings.append("This program publishes no user-agent marker — nothing to append.")
    if not entries:
        warnings.append(
            "No scope entries were returned — either this program has none configured, or it is "
            "private and your credential doesn't cover it. Add scope by hand, or sign in."
        )

    return {
        "ok": True,
        "slug": slug,
        # Alias so a caller written against the HackerOne import ("handle") works unchanged.
        "handle": slug,
        # 200 matches ProgramUpsertRequest.name, so a long title can't 422 the whole save.
        "program_name": _text(program.get("title"), 200) or slug,
        "policy_excerpt": _text(program.get("rules"), _MAX_RULES_EXCERPT),
        "offers_bounty": bool(program.get("bounty")),
        "program_stats": _program_stats(program, currency),
        "structured_scope": entries,
        "out_of_scope": [_text(p, 500) for p in oos_prose[:100]],
        "qualifying_vulnerability": [_text(x, 300) for x in _iter_strings(program.get("qualifying_vulnerability"), 100)],
        "non_qualifying_vulnerability": [_text(x, 300) for x in _iter_strings(program.get("non_qualifying_vulnerability"), 100)],
        "user_agent_marker": marker,
        "user_agent_suffix": _marker_suffix(marker),
        "notes_digest": _notes_digest(program, oos_prose, currency, oos_prose),
        "warnings": warnings,
    }
