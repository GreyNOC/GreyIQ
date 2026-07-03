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

import json
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote, urlparse

# Only Google/Firebase infrastructure is ever contacted — a fixed host allowlist + the *.firebaseio.com
# Realtime-Database suffix. The project id is derived from Google's OWN getProjectConfig response, so
# even that dynamic host can only ever be Google's RTDB — never a target- or attacker-controlled host.
_ALLOWED_HOSTS = frozenset({
    "www.googleapis.com", "identitytoolkit.googleapis.com",
    "firestore.googleapis.com", "firebasestorage.googleapis.com",
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


def _get(url: str) -> tuple[int, str]:
    """GET a URL on the Google/Firebase allowlist and return (status, body). Never raises."""
    if not _host_allowed(urlparse(url).hostname or ""):  # only Google/Firebase infra is contactable
        return 0, "host not allowlisted"
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310 - fixed https host, GET only
            return int(getattr(resp, "status", 0) or 200), resp.read(_MAX_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(_MAX_BYTES).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        return int(exc.code or 0), body
    except Exception as exc:  # noqa: BLE001 - network/DNS/timeout -> inconclusive, never fatal
        return 0, f"{type(exc).__name__}: {exc}"


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
        # Try to surface a project number the error sometimes names ("project 123456789012").
        m = re.search(r"project[^0-9]{0,12}(\d{6,})", low)
        if m:
            result["project_id"] = m.group(1)
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
