"""GreyIQ BugHunter — served-JS surface miner.

Modern apps ship their whole API map, parameter names, and sometimes secrets inside
bundled JavaScript that a landing-page HTML crawl never sees. ``mine_js`` is a PURE,
text-in / data-out extractor (no network — the caller fetches, this only parses) that
pulls in-scope endpoints, query-param names, same-apex hosts, and (already-redacted)
leaked secrets out of a JS/HTML body. Those endpoints + params are exactly what the
active prover (XSS/SQLi/redirect/CRLF checks) needs to bite on.

Frozen-safe: stdlib ``re`` + the existing SECRET_RULES + redact_text. Unit-testable
with no I/O. SAFETY: secrets are redacted HERE before they ever leave this module, and
every discovered host is pre-filtered through the caller's scope gate so the caller
only ever fetches in-scope targets.
"""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

from bughunter.code_scanner.redaction import redact_text
from bughunter.code_scanner.rules import SECRET_RULES
from bughunter.registrable_domain import registrable_domain

# Leading-slash endpoint paths in string literals (api/graphql/rest/version-y looking).
_ENDPOINT_RE = re.compile(r"""["'`](/[A-Za-z0-9_][A-Za-z0-9_./{}\-]{1,120})["'`]""")
# fetch/axios/XHR call targets.
_CALL_URL_RE = re.compile(r"""(?:fetch|axios(?:\.\s*\w+)?|\.open)\s*\(\s*["'`]([^"'`]{2,200})["'`]""")
# Query-param names from URL strings and explicit param assignments.
_PARAM_RE = re.compile(r"""[?&]([A-Za-z_][A-Za-z0-9_]{1,39})=""")
# Absolute hostnames (for same-apex asset discovery).
_HOST_RE = re.compile(r"""https?://([A-Za-z0-9][A-Za-z0-9.\-]{1,250}\.[A-Za-z]{2,24})""")

_ENDPOINT_HINTS = ("api", "graphql", "/v1", "/v2", "/v3", "rest", "/query", "/admin", "/internal")
_CAP_ENDPOINTS, _CAP_PARAMS, _CAP_HOSTS, _CAP_SECRETS = 80, 60, 40, 20


def _registrable_apex(host: str) -> str:
    return registrable_domain(host)


def mine_js(js_text: str, base_url: str, *, host_filter: Callable[[str], bool] | None = None) -> dict[str, Any]:
    """Extract {endpoints, params, hosts, secret_findings} from one JS/HTML body.

    ``host_filter(host) -> bool`` (if given) keeps only in-scope endpoint URLs + hosts;
    without it, only same-origin endpoints (relative to base_url) are kept. Returns
    deduped, capped lists. Secrets are already redacted."""
    text = js_text or ""
    base_host = (urlparse(base_url).hostname or "").lower()
    base_apex = _registrable_apex(base_host)

    def keep_host(h: str) -> bool:
        h = (h or "").lower()
        if not h:
            return False
        if callable(host_filter):
            return bool(host_filter(h))
        return h == base_host  # default: same-origin only

    endpoints: list[str] = []
    seen_ep: set[str] = set()
    raw_paths = _ENDPOINT_RE.findall(text)[:1500] + _CALL_URL_RE.findall(text)[:500]
    for raw in raw_paths:
        if not (raw.startswith("/") or raw.startswith(("http://", "https://"))):
            continue
        if not any(h in raw.lower() for h in _ENDPOINT_HINTS):
            continue
        try:
            absolute = urljoin(base_url, raw)
        except ValueError:
            continue
        if not absolute.startswith(("http://", "https://")):
            continue
        if not keep_host(urlparse(absolute).hostname or ""):
            continue
        if absolute not in seen_ep:
            seen_ep.add(absolute)
            endpoints.append(absolute)
        if len(endpoints) >= _CAP_ENDPOINTS:
            break

    params = sorted({p for p in _PARAM_RE.findall(text)})[:_CAP_PARAMS]

    hosts: list[str] = []
    seen_h: set[str] = set()
    for h in _HOST_RE.findall(text):
        h = h.lower().rstrip(".")
        if h == base_host or h in seen_h:
            continue
        # Same-apex only by default (an unrelated CDN host isn't the program's asset),
        # plus whatever the scope gate explicitly allows.
        if _registrable_apex(h) == base_apex or (callable(host_filter) and host_filter(h)):
            seen_h.add(h)
            hosts.append(h)
        if len(hosts) >= _CAP_HOSTS:
            break

    secret_findings: list[dict[str, Any]] = []
    for rule in SECRET_RULES:
        for hit in rule.scan(path=base_url, text=text):
            safe_snippet, _ = redact_text(getattr(hit, "snippet", "") or "")  # REDACT here, always
            secret_findings.append({
                "rule_id": getattr(hit, "rule_id", "web.exposed.secret"),
                "title": f"Secret in served JS: {getattr(hit, 'title', 'exposed secret')}",
                "severity": getattr(getattr(hit, "severity", None), "value", "medium"),
                "confidence": getattr(getattr(hit, "confidence", None), "value", "medium"),
                "category": "secret_exposed",
                "file_path": base_url, "line_start": getattr(hit, "line_start", 1), "line_end": getattr(hit, "line_start", 1),
                "snippet": safe_snippet, "redacted": True, "remediation": "Remove the secret from client-shipped JS and rotate it.",
            })
            if len(secret_findings) >= _CAP_SECRETS:
                break
        if len(secret_findings) >= _CAP_SECRETS:
            break

    return {"endpoints": endpoints, "params": params, "hosts": hosts, "secret_findings": secret_findings}
