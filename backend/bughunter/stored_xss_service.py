"""GreyIQ BugHunter — stored (persistent) XSS confirmation.

Confirms a marker payload SUBMITTED on one request and RENDERED UNESCAPED on a DIFFERENT
'view' page — true stored XSS, distinct from the reflected check (same response). Honest +
GET-by-default:

  * **Assisted (default, GET-only):** GreyIQ mints a unique marker payload; you submit it via
    your own form/tooling, then GreyIQ GETs the view URL and confirms whether the raw
    executable tag rendered.
  * **Auto (opt-in ``send``):** GreyIQ POSTs the marker into the form field itself — a guarded,
    scope-bound, no-redirect form POST (the engine's second non-GET egress, like the XXE
    ``--send``) — then GETs the view URL.

A confirmed match is OUR OWN unique marker payload appearing RAW in the view page, so the
proof embeds only our marker, never another user's data. View + inject URLs are scope-bound
+ SSRF-guarded; the operator's session (cookie/headers) is attached to both if supplied.
"""

from __future__ import annotations

import html as _html
import secrets as _secrets
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlencode, urlparse

from bughunter.active_verify_service import _ActiveError, _Http, _NoRedirect, host_in_active_scope
from bughunter.rate_limit import HostRateGovernor
from bughunter.scan_auth import auth_headers_for, build_auth
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _USER_AGENT, _guard_url


def mint_marker() -> str:
    """A unique, unguessable marker so a raw-payload match on the view page is attributable."""
    return "gqsx" + _secrets.token_hex(8)


def build_payloads(marker: str) -> dict[str, str]:
    """Stored-XSS payload variants, each carrying the unique marker. If one renders RAW on the
    view page, the executable tag fires — that's the confirmation."""
    return {
        "svg": f"<svg/onload=alert(1)>{marker}</svg>",
        "img": f"<img src=x onerror=alert(1)>{marker}",
        "script": f"<script>/*{marker}*/alert(1)</script>",
        "breakout": f'"><svg/onload=alert(1)>{marker}',
    }


def _fetch_view(url: str, *, auth: Any, settings: Any) -> dict[str, Any]:
    governor = HostRateGovernor(capacity=settings.active_max_requests_per_host,
                                min_interval_s=settings.active_min_interval_ms / 1000.0)
    return _Http(settings, governor, max_requests=2, auth=auth).fetch(url)


def _post_form(url: str, data: dict[str, str], *, auth: Any, timeout: float) -> dict[str, Any]:
    """POST a form body to an ALREADY scope-checked + SSRF-guarded URL, no redirect followed.
    The operator's session is attached if present. Reached only via the opt-in ``send``."""
    headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": _USER_AGENT, "Accept": "*/*"}
    # Attach the operator session ONLY when the POST host is same-site as the host the
    # credentials were bound to — same invariant the GET path (_Http.fetch) enforces. The
    # inject URL is scope-checked independently and may be a DIFFERENT in-scope host, so a
    # raw header copy would leak the session off-target on the strictest (non-GET) egress.
    headers.update(auth_headers_for(urlparse(url).hostname or "", auth))
    request = urllib.request.Request(url, data=urlencode(data).encode("utf-8"), method="POST", headers=headers)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as resp:
            return {"ok": True, "status": getattr(resp, "status", 0)}
    except urllib.error.HTTPError as exc:
        return {"ok": True, "status": exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "error": f"form POST failed: {exc}"}


def _build_finding(view_url: str, inject_url: str, field: str, kind: str, marker: str) -> tuple[dict[str, Any], dict[str, Any]]:
    path = urlparse(view_url).path or "/"
    matched = (f"the injected {kind} payload (unique marker {marker}) rendered UNESCAPED on the view page — the "
               f"executable tag is served raw, so it runs in every viewer's browser")
    finding = {
        "rule_id": "active.stored-xss",
        "title": f"Stored XSS rendered at {path}",
        "severity": "high",
        "confidence": "high",
        "category": "client_sink",
        "location": view_url,
        "file_path": view_url,
        "line_start": 1, "line_end": 1,
        "class_id": "xss", "class_name": "Stored / persistent XSS",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "vrt": "",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://portswigger.net/web-security/cross-site-scripting/stored",
        ],
        "remediation": ("Context-encode all stored user input on output (HTML-entity-encode), prefer a safe templating "
                        "auto-escape, sanitize rich HTML server-side (allow-list), and apply a strict CSP."),
        # The marker payload is OURS (not another user's data) — safe to name as proof.
        "snippet": "",
        "proof_evidence": {
            "request_line": (f"POST {inject_url} ({field}=<payload>)  then  GET {view_url}" if inject_url
                             else f"GET {view_url}  (payload submitted out-of-band)"),
            "response_status": "200 with the raw payload rendered",
            "matched_value": matched,
        },
    }
    plan = {
        "steps": [
            (f"Submit the payload into the '{field}' field at {inject_url}." if inject_url
             else "Submit the marker payload into the target field via the app."),
            f"Load the view page where that content is shown: GET {view_url}",
            f"Observe the raw {kind} payload (marker {marker}) in the page source — it executes for every viewer (stored XSS).",
            "Assess the blast radius: who views this content (other users / admins) and what a session-stealing payload reaches.",
        ],
        "poc": f"# After submitting the payload, the view page returns it raw:\n# GET {view_url}\n# -> ...{build_payloads(marker)[kind]}...",
        "impact": ("Stored XSS executes attacker JavaScript in the browser of everyone who views the content — session "
                   "theft, account takeover, and actions performed as the victim, with no per-victim interaction needed."),
        "cvss": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N", "base_score": 8.0, "base_severity": "high",
            "estimated": False,
            "justification": (
                f"Actively confirmed: a unique marker payload ({marker}) was submitted and observed rendering "
                "UNESCAPED on a separate view — not a template estimate."
            ),
        },
        "remediation": finding["remediation"],
        "proof_of_impact": {
            "status": "confirmed",
            "method": "marker payload submitted, then rendered RAW on a different view page (GET) — our own marker, no other user's data",
            "actor": "any user who can submit this content",
            "affected_asset": "every user (and admin) who views the stored content",
            "observed_result": matched,
            "control_result": "an escaped/encoded output would show the marker as inert text (&lt;svg…), not a live tag",
            "evidence": f"the raw {kind} payload bearing marker {marker} is present in the view page source",
        },
    }
    return finding, plan


def _verdict(body: str, payloads: dict[str, str], marker: str, view_url: str,
             inject_url: str, field: str) -> dict[str, Any]:
    body = body or ""
    for kind, payload in payloads.items():
        if payload in body:   # the RAW executable payload rendered -> stored XSS
            finding, plan = _build_finding(view_url, inject_url, field, kind, marker)
            finding["ref"] = "F1"
            return {"ok": True, "status": "confirmed", "marker": marker, "finding": finding,
                    "attack_plan": plan, "detail": {"view_url": view_url, "inject_url": inject_url,
                                                     "field": field, "payload_kind": kind}}
    if marker in body or _html.escape(marker) in body:
        return {"ok": True, "status": "escaped", "marker": marker,
                "reason": "the marker is stored but HTML-escaped on the view page — not exploitable as XSS here."}
    return {"ok": True, "status": "not-stored", "marker": marker,
            "reason": "the marker did not appear on the view page — it wasn't stored, or it renders on a different page."}


def confirm_stored_xss(
    *,
    view_url: str,
    inject_url: str = "",
    field: str = "",
    scope: str = "",
    send: bool = False,
    marker: str | None = None,
    cookie: str = "",
    headers: list[str] | None = None,
    settings: Any = None,
) -> dict[str, Any]:
    """Confirm stored XSS. Assisted by default (mint a marker payload, hand it back to submit,
    then re-call with the marker to check the view URL). ``send=True`` opts in to GreyIQ POSTing
    the payload into ``field`` at ``inject_url`` itself, then checking the view URL."""
    settings = settings or get_settings()
    if not str(view_url or "").strip():
        return {"ok": False, "error": "Provide the view URL where the stored content is displayed."}
    try:
        nview = normalize_website_url(view_url)
    except WebsiteFetchError as exc:
        return {"ok": False, "error": str(exc)}
    vhost = urlparse(nview).hostname or ""
    if not host_in_active_scope(vhost, scope, settings):
        return {"ok": False, "error": f"'{vhost}' is not named in your scope — stored-XSS testing is fail-closed."}
    try:
        sview = _guard_url(nview, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return {"ok": False, "error": f"view URL refused by the guard: {exc}"}
    auth = build_auth(sview, cookie=cookie or "", headers=headers or [])

    fresh = not str(marker or "").strip()
    marker = str(marker or "").strip() or mint_marker()
    payloads = build_payloads(marker)

    if send:
        if not str(inject_url or "").strip() or not str(field or "").strip():
            return {"ok": False, "error": "Auto-send needs both the inject_url (the form endpoint) and the field name."}
        try:
            ninj = normalize_website_url(inject_url)
            ihost = urlparse(ninj).hostname or ""
            if not host_in_active_scope(ihost, scope, settings):
                return {"ok": False, "error": f"'{ihost}' (inject URL) is not in scope — fail-closed."}
            sinj = _guard_url(ninj, settings.allow_private_urls, settings.web_allowed_ports)
        except WebsiteFetchError as exc:
            return {"ok": False, "error": f"inject URL refused by the guard: {exc}"}
        try:
            pre = _fetch_view(sview, auth=auth, settings=settings)
        except _ActiveError as exc:
            return {"ok": False, "error": f"view fetch failed: {exc}"}
        if marker in (pre.get("body") or ""):
            return {"ok": False, "error": "the fresh marker already appears on the view page — mint another and retry."}
        post = _post_form(sinj, {field: payloads["svg"]}, auth=auth, timeout=settings.web_fetch_timeout_seconds)
        if not post.get("ok"):
            return {"ok": True, "status": "send-failed", "marker": marker, "payloads": payloads, "error": post.get("error")}
        try:
            res = _fetch_view(sview, auth=auth, settings=settings)
        except _ActiveError as exc:
            return {"ok": False, "error": f"view fetch failed: {exc}"}
        return _verdict(res.get("body") or "", {"svg": payloads["svg"]}, marker, sview, sinj, field)

    # Assisted mode.
    if fresh:
        return {"ok": True, "status": "ready", "marker": marker, "payloads": payloads,
                "view_url": sview, "inject_url": inject_url, "field": field,
                "reason": (f"Submit one of these payloads into the target field (each carries the marker {marker}), then "
                           f"re-run with marker={marker} to check whether it rendered unescaped at {sview}.")}
    try:
        res = _fetch_view(sview, auth=auth, settings=settings)
    except _ActiveError as exc:
        return {"ok": False, "error": f"view fetch failed: {exc}"}
    return _verdict(res.get("body") or "", payloads, marker, sview, inject_url, field)
