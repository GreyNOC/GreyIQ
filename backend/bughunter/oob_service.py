"""GreyIQ BugHunter — out-of-band (OOB) confirmation via an operator collaborator.

Confirms BLIND vulnerabilities that never reflect anything in the target's own response —
blind SSRF above all — by injecting a unique callback URL that points at the OPERATOR's
own OOB collaborator (the greynoc-chat ``/oob`` endpoint), sending a benign GET probe to
the in-scope target, then polling the collaborator's authenticated ``/api/oob/<token>``
for an inbound hit. A recorded hit PROVES the target reached out of band.

Config (operator-supplied, kept in GreyIQ's secrets store — never hardcoded): the
collaborator BASE URL (your phone's public tunnel, e.g. ``https://chat.example``) and the
``OOB_SECRET`` bearer. The target probe is scope-bound + SSRF-guarded exactly like the
rest of the active prover; the collaborator poll is a separate authenticated call to YOUR
OWN host. Also usable standalone: mint a token, paste the callback URL into a manual XXE /
blind-XSS payload, and poll for the hit.

GET-only target probes, marker-token correlation, bounded polling. Pure/frozen-safe
(stdlib urllib + the existing guarded active HTTP).
"""

from __future__ import annotations

import json
import secrets as _secrets
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from bughunter.active_verify_service import (
    _ActiveError,
    _Http,
    _candidate_params,
    _with_query,
    host_in_active_scope,
)
from bughunter.rate_limit import HostRateGovernor
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _USER_AGENT, _guard_url


def mint_token() -> str:
    """A unique, unguessable correlation token for one OOB probe."""
    return _secrets.token_hex(16)  # 32 hex chars; matches the collaborator's [A-Za-z0-9]{6,64}


def callback_url(base: str, token: str) -> str:
    """The callback URL the target is asked to reach: <collaborator>/oob/<token>."""
    return f"{str(base or '').rstrip('/')}/oob/{token}"


def poll_collaborator(base: str, secret: str, token: str, *, timeout: float = 8.0) -> dict[str, Any]:
    """GET the collaborator's authed poll endpoint for a token's interactions. Hits the
    OPERATOR's own host (not the target). Returns {ok, count, hits} or {ok: False, error}."""
    base = str(base or "").strip().rstrip("/")
    if not base or not secret:
        return {"ok": False, "error": "OOB collaborator URL + secret are not configured."}
    if not token:
        return {"ok": False, "error": "No token to poll."}
    url = f"{base}/api/oob/{token}"
    request = urllib.request.Request(url, method="GET", headers={
        "Authorization": f"Bearer {secret}", "User-Agent": _USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            data = json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"ok": False, "error": "collaborator poll unauthorized — check the OOB secret."}
        return {"ok": False, "error": f"collaborator poll HTTP {exc.code}"}
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"collaborator poll failed: {exc}"}
    hits = data.get("hits") if isinstance(data, dict) else None
    return {"ok": True, "count": int((data or {}).get("count") or 0), "hits": hits or []}


def _build_ssrf_finding(target_url: str, param: str, token: str, base: str, hit: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": "active.blind-ssrf-oob",
        "title": f"Blind SSRF via '{param}' (out-of-band confirmed)",
        "severity": "high",
        "confidence": "high",
        "category": "ssrf",
        "location": target_url,
        "file_path": target_url,
        "line_start": 1, "line_end": 1,
        "class_id": "ssrf",
        "class_name": "Server-side request forgery (SSRF)",
        "cwe": "CWE-918",
        "owasp": "A10:2021 Server-Side Request Forgery (SSRF)",
        "references": [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://portswigger.net/web-security/ssrf",
        ],
        "remediation": ("Validate and allow-list the outbound destination; resolve and pin it, reject internal/"
                        "metadata ranges, and disable unused URL schemes/redirfollowing."),
        "snippet": "",  # the proof is the OOB callback, not target data
        "proof_evidence": {
            "request_line": f"GET {_with_query(target_url, {param: callback_url(base, token)})}",
            "response_status": f"collaborator hit: {hit.get('method', 'GET')} {hit.get('path', '/oob/' + token)}",
            "matched_value": (f"the target server made an out-of-band {hit.get('method', 'GET')} request to the "
                              f"collaborator token {token} (source {hit.get('ip', '?')}) after '{param}' was set to "
                              f"the callback URL — blind SSRF confirmed"),
        },
    }


def _ssrf_plan(target_url: str, param: str, token: str, base: str, hit: dict[str, Any]) -> dict[str, Any]:
    cb = callback_url(base, token)
    return {
        "steps": [
            f"Set the '{param}' parameter to a callback URL on a collaborator you control: {cb}",
            f"Send: GET {_with_query(target_url, {param: cb})}",
            f"Observe an inbound {hit.get('method', 'GET')} hit on the collaborator for token {token} "
            f"(from {hit.get('ip', 'the target')}) — the server fetched the attacker-supplied URL.",
            "Re-point the parameter at an internal/metadata URL (in scope) to assess reachability and impact.",
        ],
        "poc": f"GET {_with_query(target_url, {param: cb})}\n# -> out-of-band callback recorded at {base}/oob/{token}",
        "impact": ("The server can be made to issue requests to attacker-chosen hosts — internal services, cloud "
                   "metadata (credential theft), and otherwise-unreachable infrastructure behind the firewall."),
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", "base_score": 8.5, "base_severity": "high", "estimated": True},
        "remediation": "Allow-list outbound destinations; block internal/metadata ranges; pin the resolved IP.",
        "proof_of_impact": {
            "status": "confirmed",
            "method": "out-of-band callback (collaborator) — GET-only probe, no data exfiltrated into the report",
            "affected_asset": "internal services and cloud metadata reachable from the server",
            "observed_result": (f"setting '{param}' to the collaborator URL caused the target to make an out-of-band "
                                f"{hit.get('method', 'GET')} request to token {token}"),
            "control_result": "without the injected callback the collaborator records nothing for this fresh token",
            "evidence": f"collaborator interaction for token {token} ({hit.get('method', 'GET')} {hit.get('path', '')})",
        },
    }


def confirm_blind_ssrf(
    target_url: str,
    *,
    base: str,
    secret: str,
    scope: str = "",
    settings: Any = None,
    extra_params: list[str] | None = None,
    governor: HostRateGovernor | None = None,
    http: _Http | None = None,
    poll_attempts: int = 4,
    poll_delay_s: float = 2.0,
) -> dict[str, Any]:
    """Inject a fresh collaborator callback URL into each candidate param of an in-scope
    target, send a GET probe, and poll the collaborator for a hit. Returns
    ``{ok, status, finding?, attack_plan?, detail}``; status is ``confirmed`` (a hit
    landed) or ``no-callback`` (none did)."""
    settings = settings or get_settings()
    if not str(base or "").strip() or not str(secret or "").strip():
        return {"ok": False, "error": "Configure the OOB collaborator URL + secret first."}
    try:
        normalized = normalize_website_url(target_url)
    except WebsiteFetchError as exc:
        return {"ok": False, "error": str(exc)}
    host = urlparse(normalized).hostname or ""
    if not host_in_active_scope(host, scope, settings):
        return {"ok": False, "error": f"'{host}' is not named in your scope — OOB probing is fail-closed."}
    try:
        sanitized = _guard_url(normalized, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return {"ok": False, "error": f"target refused by the URL guard: {exc}"}

    governor = governor or HostRateGovernor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http = http or _Http(settings, governor, max_requests=8)
    params = _candidate_params(sanitized, extra_params, ("url", "next", "dest", "uri", "callback", "u"), 3)
    tried: list[str] = []
    for param in params:
        token = mint_token()
        probe_url = _with_query(sanitized, {param: callback_url(base, token)})
        try:
            http.fetch(probe_url)  # the target makes the OOB call if vulnerable
        except _ActiveError:
            continue
        tried.append(param)
        for _ in range(max(1, poll_attempts)):
            time.sleep(max(0.0, poll_delay_s))
            res = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
            if res.get("ok") and res.get("count"):
                hit = (res.get("hits") or [{}])[0]
                finding = _build_ssrf_finding(sanitized, param, token, base, hit)
                finding["ref"] = "F1"
                return {"ok": True, "status": "confirmed", "param": param, "token": token,
                        "finding": finding, "attack_plan": _ssrf_plan(sanitized, param, token, base, hit),
                        "detail": {"hit": hit}}
            if not res.get("ok"):
                return {"ok": False, "error": res.get("error", "collaborator poll failed")}
    return {"ok": True, "status": "no-callback", "params_tried": tried,
            "reason": "no out-of-band callback was observed for these parameters (no blind SSRF proven here)."}
