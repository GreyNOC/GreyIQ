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

# Only the credential's own issuer is ever contacted — a fixed allowlist, no target-derived host.
_ALLOWED_HOSTS = frozenset({"www.googleapis.com", "identitytoolkit.googleapis.com"})
_TIMEOUT_S = 8
_MAX_BYTES = 65536
_UA = "GreyIQ-CredentialCheck/1.0"
_GOOGLE_KEY_RE = re.compile(r"\AAIza[0-9A-Za-z_\-]{35}\Z")
# The legacy Identity Toolkit endpoint that returns a project's config for a Firebase Web API key.
_PROJECT_CONFIG_URL = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={key}"


def is_google_api_key(value: str) -> bool:
    return bool(_GOOGLE_KEY_RE.match(str(value or "").strip()))


def _get(url: str) -> tuple[int, str]:
    """GET a URL on the allowlist and return (status, body). Never raises."""
    host = (urlparse(url).hostname or "").lower()
    if host not in _ALLOWED_HOSTS:  # belt-and-suspenders — the URL is built from a constant host
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
    }
    if not is_google_api_key(key):
        result["detail"] = "Not a Google/Firebase API key format (AIza…) — no validation attempted."
        return result
    status, body = _get(_PROJECT_CONFIG_URL.format(key=quote(key, safe="")))
    result["checked"] = True
    result["http_status"] = status
    low = body.lower()
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            data = {}
        project = str(data.get("projectId") or data.get("projectNumber") or "").strip()
        domains = [str(d) for d in (data.get("authorizedDomains") or []) if str(d).strip()][:20]
        result.update(live=True, project_id=project, authorized_domains=domains)
        result["detail"] = (
            f"LIVE — the key authenticates to Firebase project '{project or '(unnamed)'}'"
            + (f"; authorized domains: {', '.join(domains)}" if domains else "")
            + ". It can reach that project's Firebase services (Identity Toolkit sign-in/sign-up and, "
              "subject to security rules, Firestore / Realtime Database / Storage)."
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
