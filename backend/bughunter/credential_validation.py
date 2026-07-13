"""Benign liveness validation for a credential found in source code.

HackerOne rejects a "leaked API key" report that doesn't PROVE the key is live and name what it
grants. This module makes that proof for a Firebase / Google API key (the ``AIza…`` shape) by
sending ONE benign, read-only GET to the credential's OWN issuer (Google) — never to the target —
and reading back whether the key authenticates and which Firebase project it belongs to.

Safety envelope (mirrors the active-verify posture, but for the credential's issuer rather than the
scan target):
  * The request goes ONLY to a hardcoded allowlist of Google API hosts. Nothing else is contactable.
  * GET only. The endpoint (`getProjectConfig`) is read-only: it reads the project's public config,
    creates nothing, changes nothing, touches no user data.
  * The only secret transmitted is the found key itself, to its own issuer — the same thing a
    browser running the app already does.
  * The caller gates this behind the operator's ``authorized`` flag (see run_bounty_hunt).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlencode, urlparse

# Only a credential ISSUER's own infrastructure is ever contacted — a fixed host allowlist (+ the
# *.firebaseio.com RTDB suffix). Each dynamic host (Firebase project id) is derived from the issuer's
# OWN response, so it can only ever be the issuer's infra — never a target- or attacker-controlled host.
_ALLOWED_HOSTS = frozenset({
    "www.googleapis.com", "identitytoolkit.googleapis.com",
    "firestore.googleapis.com", "firebasestorage.googleapis.com",
    "api.github.com", "slack.com",  # issuers for GitHub PAT / Slack token liveness checks
    "api.openai.com", "api.anthropic.com", "api.stripe.com",  # OpenAI / Anthropic / Stripe key liveness
    "gitlab.com", "registry.npmjs.org",  # GitLab PAT / npm token liveness
    "api.sendgrid.com", "api.digitalocean.com",  # SendGrid / DigitalOcean token liveness
    "sts.amazonaws.com",  # AWS key liveness — sts:GetCallerIdentity (reads only the caller's own ARN)
    "oauth2.googleapis.com",  # GCP service-account key liveness — JWT token exchange (proves auth, reads nothing)
})
_ALLOWED_SUFFIXES = (".firebaseio.com",)
_TIMEOUT_S = 8
_MAX_BYTES = 65536
_UA = "GreyIQ-CredentialCheck/1.0"
_GOOGLE_KEY_RE = re.compile(r"\AAIza[0-9A-Za-z_\-]{35}\Z")
_PROJECT_RE = re.compile(r"\A[a-z0-9][a-z0-9\-]{3,58}[a-z0-9]\Z")  # a Firebase project id shape
# The legacy Identity Toolkit endpoint that returns a project's config for a Firebase Web API key.
_PROJECT_CONFIG_URL = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={key}"


def _host_allowed(host: str) -> bool:
    host = (host or "").lower()
    return host in _ALLOWED_HOSTS or host.endswith(_ALLOWED_SUFFIXES)


def _poc_curl(key: str) -> str:
    """The exact, copy-pasteable command a triager runs to reproduce liveness — one benign,
    read-only GET to the key's OWN issuer (Google), never the target. Carries the real key so the
    reproduction is literal; the caller renders it in the already-'sensitive' credential block."""
    return ("curl -s 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/"
            f"getProjectConfig?key={key}'")


def is_google_api_key(value: str) -> bool:
    return bool(_GOOGLE_KEY_RE.match(str(value or "").strip()))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow ANY redirect during credential validation. stdlib urllib re-sends the
    Authorization/x-api-key header across a cross-host redirect; the allowlist is checked only on the
    initial URL, so following a 3xx could replay the found token to a non-allowlisted host. Blocking
    redirects keeps the token strictly on its own (allowlisted) issuer — matching every other guarded
    HTTP call site in this codebase (_NoRedirect / _GuardedRedirect)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None  # do not follow -> urllib surfaces the 3xx as an HTTPError, token never re-sent


_OPENER = urllib.request.build_opener(_NoRedirect())


def _get_full(url: str, extra_headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
    """GET a URL on the issuer allowlist and return (status, response_headers, body). Never raises.
    ``extra_headers`` carries the credential to its OWN issuer (e.g. an Authorization header) — the
    only place a found token is ever transmitted, exactly as the leaking app already does. Redirects
    are NOT followed, so the token can never be replayed to a redirect target off the allowlist."""
    if not _host_allowed(urlparse(url).hostname or ""):  # only allowlisted issuer infra is contactable
        return 0, {}, "host not allowlisted"
    hdrs = {"User-Agent": _UA, "Accept": "application/json"}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, method="GET", headers=hdrs)
    try:
        with _OPENER.open(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310 - fixed https host, GET only, no redirects
            return int(getattr(resp, "status", 0) or 200), dict(resp.headers or {}), resp.read(_MAX_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(_MAX_BYTES).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        return int(exc.code or 0), dict(getattr(exc, "headers", {}) or {}), body
    except Exception as exc:  # noqa: BLE001 - network/DNS/timeout -> inconclusive, never fatal
        return 0, {}, f"{type(exc).__name__}: {exc}"


def _get(url: str) -> tuple[int, str]:
    """GET a URL on the issuer allowlist and return (status, body). Never raises."""
    status, _headers, body = _get_full(url)
    return status, body


_DEAD_MARKERS = ("api key not valid", "api_key_invalid", "keyinvalid", "invalid api key")
# The key is REAL but that particular API is disabled / restricted — still proves the key is live.
_LIVE_BUT_RESTRICTED = ("permission_denied", "has not been used", "is disabled", "requests to this api",
                        "api_key_service_blocked", "requests from referer")


def validate_firebase_key(key: str) -> dict[str, Any]:
    """Validate a Firebase/Google API key is live and identify its project. Returns a structured
    result: ``{checked, live, project_id, authorized_domains, detail, http_status, endpoint}``.
    ``live`` is True/False/None (None = inconclusive, e.g. no network)."""
    key = str(key or "").strip()
    result: dict[str, Any] = {
        "checked": False, "live": None, "project_id": "", "authorized_domains": [],
        "detail": "", "http_status": 0, "endpoint": "identitytoolkit getProjectConfig",
        # A copy-pasteable reproduction command + the ACTUAL issuer response, so the report proves
        # liveness with a runnable PoC and a captured artifact — not prose alone.
        "poc": "", "response_excerpt": "",
    }
    if not is_google_api_key(key):
        result["detail"] = "Not a Google/Firebase API key format (AIza…) — no validation attempted."
        return result
    result["poc"] = _poc_curl(key)  # always present for a well-formed key, whatever the liveness verdict
    status, body = _get(_PROJECT_CONFIG_URL.format(key=quote(key, safe="")))
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:900]  # the issuer's real response — the concrete proof artifact
    low = body.lower()
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            data = {}
        project = str(data.get("projectId") or data.get("projectNumber") or "").strip()
        domains = [str(d) for d in (data.get("authorizedDomains") or []) if str(d).strip()][:20]
        result.update(live=True, project_id=project, authorized_domains=domains, unrestricted=True)
        result["detail"] = (
            f"LIVE — the key authenticates to Firebase project '{project or '(unnamed)'}'"
            + (f"; authorized domains: {', '.join(domains)}" if domains else "")
            + ". It can reach that project's Firebase services (Identity Toolkit sign-in/sign-up and, "
              "subject to security rules, Firestore / Realtime Database / Storage). The key is also "
              "UNRESTRICTED: this validation came from a server with no HTTP referrer and an arbitrary "
              "IP, so it has no HTTP-referrer / IP application restriction and is usable from anywhere "
              "(API-abuse / quota-theft exposure on its own)."
        )
        return result
    if any(m in low for m in _DEAD_MARKERS):
        result.update(live=False)
        result["detail"] = f"NOT live — the issuer rejected the key as invalid/revoked (HTTP {status})."
        return result
    if any(m in low for m in _LIVE_BUT_RESTRICTED):
        result.update(live=True)
        # Try to surface a project NUMBER the error sometimes names ("project 123456789012"). Store it
        # in a distinct field, NOT project_id: project_id is a SLUG (RTDB hosts key off the slug), so a
        # numeric project number there yields a futile <number>.firebaseio.com probe and a misleading
        # "Firebase project <number>" label. Leaving project_id empty also gates probe_firebase_exposure.
        m = re.search(r"project[^0-9]{0,12}(\d{6,})", low)
        if m:
            result["project_number"] = m.group(1)
        result["detail"] = (
            f"LIVE — the key is accepted (HTTP {status}) but the Identity Toolkit API is disabled/"
            "restricted for it. The credential is real; enumerate the other Google/Firebase APIs it "
            "is authorized for to demonstrate access."
        )
        return result
    result["detail"] = (
        f"Inconclusive (HTTP {status or 'no response'}). Could not confirm the key is live via this "
        "benign endpoint — validate manually within scope."
    )
    return result


def probe_firebase_exposure(project: str, key: str = "") -> list[dict[str, Any]]:
    """Given a Firebase project id (from ``validate_firebase_key``), probe its data stores for
    UNAUTHENTICATED read exposure — the high-value, VRP-eligible misconfiguration. Benign + GET-only:
    the Realtime Database check uses ``?shallow=true`` so it reads only top-level KEY NAMES, never the
    stored values. Returns a list of exposure dicts (``[]`` when locked / unreachable / bad project)."""
    project = str(project or "").strip().lower()
    findings: list[dict[str, Any]] = []
    if not _PROJECT_RE.match(project):
        return findings
    # --- Realtime Database: a shallow read (top-level keys only) proves anon read w/o exfiltration.
    for host in (f"https://{project}.firebaseio.com", f"https://{project}-default-rtdb.firebaseio.com"):
        status, body = _get(host + "/.json?shallow=true")
        stripped = body.strip()
        if status == 200 and stripped and stripped.lower() != "null":
            keys: list[str] = []
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    keys = [str(k) for k in list(data.keys())[:40]]
            except ValueError:
                pass
            findings.append({
                "service": "Firebase Realtime Database", "endpoint": f"{host}/.json",
                "severity": "high",  # unauthenticated READ (C:H) = High by CVSS; escalate in-report if it also holds PII
                "detail": (f"The Realtime Database at {host} is readable UNAUTHENTICATED (HTTP 200 to "
                           "/.json?shallow=true — a shallow read that returns top-level keys only, no values). "
                           + (f"Top-level keys exposed: {', '.join(keys)}." if keys else "Data is present and readable.")),
                "evidence": ("top-level keys: " + ", ".join(keys)) if keys else "shallow read returned data (not null)",
                "repro": f"curl -s '{host}/.json?shallow=true'",
            })
            break  # one reachable RTDB host is enough
    # --- Cloud Storage: a public default bucket lists its objects to an unauthenticated GET.
    # A small maxResults keeps it minimal while returning REAL object/prefix names as proof.
    status, body = _get(f"https://firebasestorage.googleapis.com/v0/b/{quote(project, safe='')}.appspot.com/o?maxResults=10")
    low = body.lower()
    if status == 200 and ('"items"' in low or '"prefixes"' in low):
        # Parse the actual object/prefix NAMES (mirrors the RTDB branch) so the report shows the
        # concrete files an attacker can enumerate — not a prose "listing returned". Names/metadata
        # only; nothing is downloaded. Falls back to prose when the body doesn't parse.
        names: list[str] = []
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                names = [str(i.get("name")) for i in (data.get("items") or []) if isinstance(i, dict) and i.get("name")][:40]
                names += [str(p) for p in (data.get("prefixes") or []) if str(p or "").strip()][:40]
        except ValueError:
            pass
        findings.append({
            "service": "Firebase Cloud Storage", "endpoint": f"gs://{project}.appspot.com",
            "severity": "high",
            "detail": (f"The default Firebase Storage bucket {project}.appspot.com lists objects to an "
                       "unauthenticated request (HTTP 200) — stored files are enumerable/readable. "
                       + (f"Objects/prefixes exposed: {', '.join(names)}." if names else "Object listing is present.")),
            "evidence": ("objects/prefixes: " + ", ".join(names)) if names else "object listing returned (items/prefixes present)",
            "repro": f"curl -s 'https://firebasestorage.googleapis.com/v0/b/{project}.appspot.com/o'",
        })
    return findings


def _credential_result(endpoint: str) -> dict[str, Any]:
    """The shared shape every issuer-liveness check returns (parallels validate_firebase_key)."""
    return {"checked": False, "live": None, "principal": "", "scopes": "", "detail": "",
            "http_status": 0, "endpoint": endpoint, "poc": "", "response_excerpt": ""}


def validate_github_token(token: str) -> dict[str, Any]:
    """Validate a leaked GitHub token is live by identifying its own account — ONE benign, read-only
    GET to api.github.com/user (the token's issuer, never the target). A 200 + a login proves it is
    live and names the account; the ``X-OAuth-Scopes`` header names what it grants. 401/403 = dead."""
    token = str(token or "").strip()
    result = _credential_result("GitHub api.github.com/user")
    if not token:
        return result
    result["poc"] = f"curl -s -H 'Authorization: Bearer {token}' https://api.github.com/user"
    status, headers, body = _get_full("https://api.github.com/user",
                                      {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:700]
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            data = {}
        login = str(data.get("login") or "").strip()
        scopes = str(headers.get("X-OAuth-Scopes") or headers.get("x-oauth-scopes") or "").strip()
        result.update(live=True, principal=login, scopes=scopes)
        result["detail"] = (
            f"LIVE — the token authenticates to GitHub account '{login or '(unknown)'}'"
            + (f" with scopes: {scopes}" if scopes else "")
            + ". It can act on every repository and resource those scopes grant (read/write code, "
              "secrets, and org resources depending on scope) as that account."
        )
        return result
    if status in (401, 403):
        result.update(live=False)
        result["detail"] = f"NOT live — GitHub rejected the token (HTTP {status})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


def validate_slack_token(token: str) -> dict[str, Any]:
    """Validate a leaked Slack token is live via auth.test — ONE benign, read-only GET to slack.com
    (the token's issuer, never the target). ``ok:true`` + a team/user proves it is live and names the
    workspace it belongs to; ``invalid_auth``/``token_revoked`` = dead."""
    token = str(token or "").strip()
    result = _credential_result("Slack auth.test")
    if not token:
        return result
    result["poc"] = f"curl -s -H 'Authorization: Bearer {token}' https://slack.com/api/auth.test"
    status, _headers, body = _get_full("https://slack.com/api/auth.test", {"Authorization": f"Bearer {token}"})
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:700]
    try:
        data = json.loads(body)
    except ValueError:
        data = {}
    if status == 200 and isinstance(data, dict) and data.get("ok") is True:
        team, user = str(data.get("team") or "").strip(), str(data.get("user") or "").strip()
        result.update(live=True, principal=(f"{user} @ {team}".strip(" @") or "(unknown)"))
        result["detail"] = (
            f"LIVE — the token authenticates to Slack workspace '{team or '(unknown)'}' as '{user or '(unknown)'}'. "
            "It can act on everything the token's scopes grant (read messages/files, post, etc.)."
        )
        return result
    err = str((data or {}).get("error") or "").strip()
    if err in ("invalid_auth", "not_authed", "account_inactive", "token_revoked", "token_expired"):
        result.update(live=False)
        result["detail"] = f"NOT live — Slack rejected the token ({err})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status}; {err or 'no ok field'}) — validate manually within scope."
    return result


def validate_openai_key(token: str) -> dict[str, Any]:
    """Validate a leaked OpenAI key via GET /v1/models — ONE benign, read-only request to the key's
    OWN issuer (never the target). 200 + a model list proves it is live; 401/403 = dead. The model
    catalog is public (not account data), so nothing sensitive is read."""
    token = str(token or "").strip()
    result = _credential_result("OpenAI api.openai.com/v1/models")
    result["no_data_read"] = True  # only the public model catalog is read — never account data
    if not token or token.startswith("sk-ant-"):  # sk-ant- is an Anthropic key — never send it to OpenAI
        return result
    result["poc"] = f"curl -s -H 'Authorization: Bearer {token}' https://api.openai.com/v1/models"
    status, _h, body = _get_full("https://api.openai.com/v1/models", {"Authorization": f"Bearer {token}"})
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:500]
    if status == 200:
        try:
            models = [str(m.get("id")) for m in (json.loads(body).get("data") or []) if isinstance(m, dict) and m.get("id")][:8]
        except ValueError:
            models = []
        result.update(live=True, principal="OpenAI API key", scopes=", ".join(models))
        result["detail"] = ("LIVE — the key authenticates to the OpenAI API"
                            + (f"; models available: {', '.join(models)}" if models else "")
                            + ". It can spend the account's API credits / quota (billing abuse) and use every enabled model.")
        return result
    if status in (401, 403):
        result.update(live=False)
        result["detail"] = f"NOT live — OpenAI rejected the key (HTTP {status})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


def validate_anthropic_key(token: str) -> dict[str, Any]:
    """Validate a leaked Anthropic key via GET /v1/models — ONE benign, read-only request to the
    key's OWN issuer (never the target). 200 + a model list proves it is live; 401 = dead. The model
    catalog is public (not account data)."""
    token = str(token or "").strip()
    result = _credential_result("Anthropic api.anthropic.com/v1/models")
    result["no_data_read"] = True  # only the public model catalog is read — never account data
    if not token:
        return result
    result["poc"] = f"curl -s -H 'x-api-key: {token}' -H 'anthropic-version: 2023-06-01' https://api.anthropic.com/v1/models"
    status, _h, body = _get_full("https://api.anthropic.com/v1/models",
                                 {"x-api-key": token, "anthropic-version": "2023-06-01"})
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:500]
    if status == 200:
        try:
            models = [str(m.get("id")) for m in (json.loads(body).get("data") or []) if isinstance(m, dict) and m.get("id")][:8]
        except ValueError:
            models = []
        result.update(live=True, principal="Anthropic API key", scopes=", ".join(models))
        result["detail"] = ("LIVE — the key authenticates to the Anthropic API"
                            + (f"; models available: {', '.join(models)}" if models else "")
                            + ". It can spend the account's API credits (billing abuse).")
        return result
    if status in (401, 403):
        result.update(live=False)
        result["detail"] = f"NOT live — Anthropic rejected the key (HTTP {status})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


def validate_stripe_key(token: str) -> dict[str, Any]:
    """Validate a leaked Stripe secret key WITHOUT reading any account data: probe a deliberately
    NON-EXISTENT resource so a VALID key returns 404 ("No such customer") and an INVALID key returns
    401 — liveness from the status code alone, no charges/balance/customers ever read. ONE benign,
    read-only GET to the key's OWN issuer (never the target)."""
    token = str(token or "").strip()
    result = _credential_result("Stripe api.stripe.com/v1/customers/<nonexistent>")
    result["no_data_read"] = True  # probes a non-existent resource — no account data is ever returned
    if not token:
        return result
    probe_url = "https://api.stripe.com/v1/customers/cus_00000000000000"  # a resource that cannot exist
    result["poc"] = f"curl -s -H 'Authorization: Bearer {token}' {probe_url}"
    status, _h, body = _get_full(probe_url, {"Authorization": f"Bearer {token}"})
    result["checked"] = True
    result["http_status"] = status
    err_type = ""
    try:  # capture ONLY the error type, never account data (the resource doesn't exist, so there is none)
        err_type = str((json.loads(body).get("error") or {}).get("type") or "")
    except ValueError:
        pass
    result["response_excerpt"] = f"error.type={err_type}" if err_type else body[:150]
    if status == 401:
        result.update(live=False)
        result["detail"] = "NOT live — Stripe rejected the key (HTTP 401, invalid API key)."
        return result
    # Only a status that unambiguously means "the key AUTHENTICATED but the resource/permission
    # failed" confirms live: 404 (our non-existent customer), 403 (valid but restricted key), 402.
    # A 5xx / 429 / 3xx is transient/ambiguous, NOT proof of a live key -> inconclusive.
    if status in (402, 403, 404):
        mode = "live" if token.startswith("sk_live") else "test" if token.startswith("sk_test") else ""
        result.update(live=True, principal=(f"Stripe {mode}-mode secret key" if mode else "Stripe secret key"))
        result["detail"] = (
            f"LIVE — the key authenticated (HTTP {status} for a non-existent resource, not 401). "
            + ("This is a LIVE-mode key — it can move real money and read customer/payment data."
               if mode == "live" else "This is a test-mode key." if mode == "test"
               else "It authenticates to the Stripe API.")
            + " Validated against a non-existent resource, so NO account data was read."
        )
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


def validate_gitlab_token(token: str) -> dict[str, Any]:
    """Validate a leaked GitLab token (``glpat-…``) is live by identifying its own account — ONE
    benign, read-only GET to gitlab.com/api/v4/user (the token's issuer, never the target). 200 +
    a username proves it is live and names the account; 401 = dead."""
    token = str(token or "").strip()
    result = _credential_result("GitLab gitlab.com/api/v4/user")
    if not token:
        return result
    result["poc"] = f"curl -s -H 'PRIVATE-TOKEN: {token}' https://gitlab.com/api/v4/user"
    status, _h, body = _get_full("https://gitlab.com/api/v4/user", {"PRIVATE-TOKEN": token})
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:300]
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            data = {}
        username = str((data or {}).get("username") or "").strip()
        result.update(live=True, principal=username or "(unknown)")
        result["detail"] = (
            f"LIVE — the token authenticates to GitLab account '{username or '(unknown)'}'. It can act on "
            "every project and resource that account/token scope grants (read/write code, CI, registry)."
        )
        return result
    if status in (401, 403):
        result.update(live=False)
        result["detail"] = f"NOT live — GitLab rejected the token (HTTP {status})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


def validate_npm_token(token: str) -> dict[str, Any]:
    """Validate a leaked npm token (``npm_…``) is live by identifying its own account — ONE benign,
    read-only GET to registry.npmjs.org/-/npm/v1/user (the token's issuer, never the target). 200 +
    a username proves it is live; 401 = dead."""
    token = str(token or "").strip()
    result = _credential_result("npm registry.npmjs.org/-/npm/v1/user")
    if not token:
        return result
    result["poc"] = f"curl -s -H 'Authorization: Bearer {token}' https://registry.npmjs.org/-/npm/v1/user"
    status, _h, body = _get_full("https://registry.npmjs.org/-/npm/v1/user", {"Authorization": f"Bearer {token}"})
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:300]
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            data = {}
        name = str((data or {}).get("name") or "").strip()
        result.update(live=True, principal=name or "(unknown)")
        result["detail"] = (
            f"LIVE — the token authenticates to npm account '{name or '(unknown)'}'. It can publish/yank "
            "packages and read private packages that account can access (supply-chain risk)."
        )
        return result
    if status in (401, 403):
        result.update(live=False)
        result["detail"] = f"NOT live — npm rejected the token (HTTP {status})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


def validate_sendgrid_key(token: str) -> dict[str, Any]:
    """Validate a leaked SendGrid key (``SG.…``) is live via GET /v3/scopes — ONE benign, read-only
    request to the key's OWN issuer (never the target). 200 + a scope list proves it is live and
    names what it grants; the scope list is capability metadata, not account/recipient data. 401 = dead."""
    token = str(token or "").strip()
    result = _credential_result("SendGrid api.sendgrid.com/v3/scopes")
    result["no_data_read"] = True  # only the key's own permission scopes are read — never mail/recipient data
    if not token:
        return result
    result["poc"] = f"curl -s -H 'Authorization: Bearer {token}' https://api.sendgrid.com/v3/scopes"
    status, _h, body = _get_full("https://api.sendgrid.com/v3/scopes", {"Authorization": f"Bearer {token}"})
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:400]
    if status == 200:
        try:
            scopes = [str(s) for s in (json.loads(body).get("scopes") or []) if s][:12]
        except ValueError:
            scopes = []
        result.update(live=True, principal="SendGrid API key", scopes=", ".join(scopes))
        result["detail"] = ("LIVE — the key authenticates to the SendGrid API"
                            + (f"; scopes include: {', '.join(scopes)}" if scopes else "")
                            + ". It can send mail as the account (phishing/spoofing) and read its templates/settings.")
        return result
    if status in (401, 403):
        result.update(live=False)
        result["detail"] = f"NOT live — SendGrid rejected the key (HTTP {status})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


def validate_digitalocean_token(token: str) -> dict[str, Any]:
    """Validate a leaked DigitalOcean token (``dop_v1_…``) is live via GET /v2/account — ONE benign,
    read-only request to the token's OWN issuer (never the target). 200 proves it is live and names
    the account it controls; 401 = dead."""
    token = str(token or "").strip()
    result = _credential_result("DigitalOcean api.digitalocean.com/v2/account")
    if not token:
        return result
    result["poc"] = f"curl -s -H 'Authorization: Bearer {token}' https://api.digitalocean.com/v2/account"
    status, _h, body = _get_full("https://api.digitalocean.com/v2/account", {"Authorization": f"Bearer {token}"})
    result["checked"] = True
    result["http_status"] = status
    result["response_excerpt"] = body[:300]
    if status == 200:
        try:
            acct = (json.loads(body) or {}).get("account") or {}
        except ValueError:
            acct = {}
        principal = str(acct.get("email") or acct.get("uuid") or "").strip()
        result.update(live=True, principal=principal or "(unknown)")
        result["detail"] = (
            f"LIVE — the token authenticates to DigitalOcean account '{principal or '(unknown)'}'. It can "
            "read and control that account's droplets, DNS, databases, and spaces (full infrastructure takeover)."
        )
        return result
    if status in (401, 403):
        result.update(live=False)
        result["detail"] = f"NOT live — DigitalOcean rejected the token (HTTP {status})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


def _post_form(url: str, data: dict[str, str], extra_headers: dict[str, str] | None = None) -> tuple[int, str]:
    """POST a form-encoded body to a URL on the issuer allowlist and return (status, body). Never
    raises. Used ONLY for a credential's own issuer token exchange (GCP). Redirects are not followed.
    The host is re-checked against the allowlist so a POST can never reach a non-issuer host."""
    if not _host_allowed(urlparse(url).hostname or ""):
        return 0, "host not allowlisted"
    body = urlencode(data).encode("utf-8")
    hdrs = {"User-Agent": _UA, "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, method="POST", data=body, headers=hdrs)
    try:
        with _OPENER.open(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310 - fixed https issuer host, no redirects
            return int(getattr(resp, "status", 0) or 200), resp.read(_MAX_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body_s = ""
        try:
            body_s = exc.read(_MAX_BYTES).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        return int(exc.code or 0), body_s
    except Exception as exc:  # noqa: BLE001 - network/DNS/timeout -> inconclusive, never fatal
        return 0, f"{type(exc).__name__}: {exc}"


# --- AWS access key liveness via SigV4-signed sts:GetCallerIdentity --------------------------------
# GetCallerIdentity returns ONLY the caller's own ARN / account / user id — it reads no resource and
# changes nothing, so it is the canonical benign "is this key live and whose is it?" probe. SigV4 uses
# HMAC-SHA256 (stdlib), so no crypto dependency. The request goes only to sts.amazonaws.com.
_AWS_REGION = "us-east-1"
_AWS_SERVICE = "sts"
_STS_HOST = "sts.amazonaws.com"
_STS_QUERY = "Action=GetCallerIdentity&Version=2011-06-15"
_AKID_RE = re.compile(r"\A(?:AKIA|ASIA)[0-9A-Z]{16}\Z")


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sigv4_headers(access_key_id: str, secret_access_key: str, amzdate: str, datestamp: str) -> dict[str, str]:
    """Build the SigV4 Authorization + X-Amz-Date headers for a GET sts:GetCallerIdentity call. Signed
    headers are host;x-amz-date; the body is empty (GET). Pure HMAC-SHA256 per the AWS SigV4 spec."""
    canonical_headers = f"host:{_STS_HOST}\nx-amz-date:{amzdate}\n"
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join(["GET", "/", _STS_QUERY, canonical_headers, signed_headers, payload_hash])
    credential_scope = f"{datestamp}/{_AWS_REGION}/{_AWS_SERVICE}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amzdate, credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    k_date = _sign(("AWS4" + secret_access_key).encode("utf-8"), datestamp)
    k_region = _sign(k_date, _AWS_REGION)
    k_service = _sign(k_region, _AWS_SERVICE)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (f"AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, "
                     f"SignedHeaders={signed_headers}, Signature={signature}")
    return {"X-Amz-Date": amzdate, "Authorization": authorization}


# STS <Code> values that genuinely prove the key pair is invalid/inactive (=> dead). A 403/401 with
# ANY OTHER code (or none) — notably RequestTimeTooSkewed (host clock drift) or Throttling — does NOT
# prove the key is dead: the signature was accepted, only the timestamp/rate was rejected. Mark those
# inconclusive rather than under-report a genuinely live (possibly admin) key.
_AWS_DEAD_CODES = frozenset({
    "SignatureDoesNotMatch", "InvalidClientTokenId", "InvalidAccessKeyId", "AccessDenied",
    "UnrecognizedClientException", "InvalidSignatureException", "ExpiredToken",
    "TokenRefreshRequired", "InvalidToken",
})


def validate_aws_key(access_key_id: str, secret_access_key: str) -> dict[str, Any]:
    """Validate a leaked AWS access key + secret via SigV4-signed ``sts:GetCallerIdentity`` — ONE
    benign, read-only GET to the key's OWN issuer (AWS STS, never the target). A 200 returns the
    caller's ARN/account (the key is live and identified); a 403 with a genuine invalid-credential
    <Code> (SignatureDoesNotMatch / InvalidClientTokenId / …) means the pair is invalid/inactive,
    while a 403 from clock skew (RequestTimeTooSkewed) or throttling is inconclusive, not dead. NO
    resource is read — GetCallerIdentity returns only the caller's own identity."""
    access_key_id = str(access_key_id or "").strip()
    secret_access_key = str(secret_access_key or "").strip()
    result = _credential_result("AWS sts:GetCallerIdentity")
    result["no_data_read"] = True  # returns only the caller's OWN identity — no resource is ever read
    if not _AKID_RE.match(access_key_id) or len(secret_access_key) < 40:
        return result  # not a well-formed AWS pair -> unchecked (never sign junk)
    if access_key_id.startswith("ASIA"):
        # ASIA = a TEMPORARY credential; sts:GetCallerIdentity also requires its X-Amz-Security-Token
        # (session token), which a leaked access-key-id + secret pair does not carry. Signing without it
        # ALWAYS 403s, which would falsely mark a genuinely LIVE temp credential dead/revoked (and
        # downgrade the finding). Leave it inconclusive (unchecked) rather than under-reporting; the
        # paired secret access key is still reported separately.
        result["detail"] = ("Temporary AWS credential (ASIA…): liveness needs the paired session token "
                            "(X-Amz-Security-Token), which is not part of the leaked key pair, so liveness "
                            "cannot be determined here — inconclusive, not dead.")
        return result
    url = f"https://{_STS_HOST}/?{_STS_QUERY}"
    result["poc"] = ("# with the paired key configured (aws configure):\n"
                     "aws sts get-caller-identity")
    now = datetime.now(UTC)
    headers = _sigv4_headers(access_key_id, secret_access_key, now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d"))
    status, _h, body = _get_full(url, headers)
    result["checked"] = True
    result["http_status"] = status
    if status == 200:
        arn = (re.search(r"<Arn>([^<]+)</Arn>", body) or [None, ""])[1]
        account = (re.search(r"<Account>([^<]+)</Account>", body) or [None, ""])[1]
        result.update(live=True, principal=arn or account or "(unknown)")
        result["response_excerpt"] = f"Arn={arn}; Account={account}"
        result["detail"] = (
            f"LIVE — the key authenticates to AWS as '{arn or account or '(unknown)'}'. It can act on every "
            "AWS resource that principal's IAM policy grants (potentially full account access). Validated "
            "with GetCallerIdentity, which reads only the caller's own identity — NO resource was accessed."
        )
        return result
    err = (re.search(r"<Code>([^<]+)</Code>", body) or [None, ""])[1]
    if status in (403, 401):
        result["response_excerpt"] = f"error={err}" if err else body[:150]
        if err in _AWS_DEAD_CODES:
            result.update(live=False)
            result["detail"] = f"NOT live — AWS STS rejected the key (HTTP {status}; {err})."
            return result
        # 403/401 with a non-credential code (e.g. RequestTimeTooSkewed from a skewed host clock on a
        # VM/container/CI runner/frozen .exe, or Throttling) does NOT prove the key is dead — the
        # signature verified, only the timestamp/rate failed. Same guard as the ASIA path above:
        # prefer inconclusive over marking a genuinely LIVE (possibly admin) key dead.
        result["detail"] = (
            f"Inconclusive — AWS STS returned HTTP {status}{f'; {err}' if err else ''}, which does not "
            "prove the key is invalid (e.g. RequestTimeTooSkewed from host clock drift, or Throttling). "
            "Check the host clock and re-validate manually within scope."
        )
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result


# --- GCP service-account key liveness via a JWT token exchange --------------------------------------
_GCP_TOKEN_URL = "https://oauth2.googleapis.com/token"  # HARDCODED issuer — never the JSON's token_uri (SSRF-safe)
_GCP_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"  # read-only, though the token is never used to read


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def validate_gcp_service_account(sa_json: str) -> dict[str, Any]:
    """Validate a leaked GCP service-account key (the JSON with ``private_key`` + ``client_email``) by
    minting a short-lived RS256 JWT signed with the key and exchanging it at Google's OWN token
    endpoint — ONE benign POST to oauth2.googleapis.com (never the target, and NEVER the JSON's own
    ``token_uri``, which is ignored to stay SSRF-safe). A 200 returning an access_token proves the key
    is live and names the service account; a 400/401 means it is revoked/disabled. Getting the token
    proves authentication — it is never used to read any resource."""
    result = _credential_result("GCP oauth2.googleapis.com/token")
    result["no_data_read"] = True  # only proves the key can mint a token — the token is never used
    try:
        data = json.loads(sa_json) if isinstance(sa_json, str) else (sa_json or {})
    except (ValueError, TypeError):
        return result
    if not isinstance(data, dict) or str(data.get("type") or "") != "service_account":
        return result
    client_email = str(data.get("client_email") or "").strip()
    private_key = str(data.get("private_key") or "").strip()
    if not client_email or "BEGIN" not in private_key:
        return result
    result["poc"] = ("# save the key JSON, then:\n"
                     "gcloud auth activate-service-account --key-file=key.json && gcloud auth print-access-token")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        result["detail"] = "Inconclusive — RSA signing (cryptography) is unavailable in this build; validate manually within scope."
        return result
    now = int(datetime.now(UTC).timestamp())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode("utf-8"))
    claims = _b64url(json.dumps({
        "iss": client_email, "scope": _GCP_SCOPE, "aud": _GCP_TOKEN_URL, "iat": now, "exp": now + 300,
    }).encode("utf-8"))
    signing_input = f"{header}.{claims}".encode("ascii")
    try:
        key = serialization.load_pem_private_key(private_key.encode("utf-8"), password=None)
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:  # noqa: BLE001 - malformed key -> inconclusive, never fatal
        result["detail"] = f"Inconclusive — could not load/sign with the private key ({type(exc).__name__})."
        return result
    assertion = f"{header}.{claims}.{_b64url(signature)}"
    status, body = _post_form(_GCP_TOKEN_URL, {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion,
    })
    result["checked"] = True
    result["http_status"] = status
    if status == 200 and '"access_token"' in body:
        result.update(live=True, principal=client_email)
        result["response_excerpt"] = "access_token issued (value withheld)"  # never store the minted token
        result["detail"] = (
            f"LIVE — the service-account key '{client_email}' minted a Google access token. It can act on "
            "every GCP resource that service account's IAM roles grant. Proven by a token exchange only — "
            "the token was NOT used to read any resource."
        )
        return result
    if status in (400, 401, 403):
        err = (re.search(r'"error"\s*:\s*"([^"]+)"', body) or [None, ""])[1]
        result.update(live=False)
        result["response_excerpt"] = f"error={err}" if err else body[:150]
        result["detail"] = f"NOT live — Google rejected the key (HTTP {status}{f'; {err}' if err else ''})."
        return result
    result["detail"] = f"Inconclusive (HTTP {status or 'no response'}) — validate manually within scope."
    return result
