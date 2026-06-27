"""Server-side request forgery (SSRF) sink primitives.

These flag a server-side HTTP fetch whose target URL is a variable / expression
rather than a fixed https:// literal — the shape of an SSRF sink the moment the
URL is attacker-influenced (a proxy, a webhook, an image-from-URL, a URL preview).
Like the command-injection pack we flag the SINK, not a proven data flow, and the
first argument is often a benign constant, so these are HIGH severity but LOW
confidence: real leads to investigate, not confirmed bugs. A fixed
requests.get("https://api.example.com/...") literal does not match.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    # ---------- Python ----------
    (
        "py.requests-variable-url",
        "Python requests/httpx fetch of a non-literal URL",
        "requests/httpx .get/.post/.request given a variable or f-string URL (not a fixed https:// literal) is an SSRF sink if the URL is attacker-influenced.",
        Severity.HIGH,
        Confidence.LOW,
        "ssrf",
        "Validate the URL against an allowlist of hosts/schemes before fetching; block private/link-local IPs and redirects.",
        ("python",),
        r"(?:requests|httpx|session|client)\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\(\s*(?!['\"]https?://)[\w(]",
    ),
    (
        "py.urlopen-variable-url",
        "Python urllib urlopen of a non-literal URL",
        "urllib.request.urlopen / urlopen given a variable URL fetches whatever host the value resolves to — an SSRF sink.",
        Severity.HIGH,
        Confidence.LOW,
        "ssrf",
        "Resolve and allowlist the host before opening; reject private ranges and non-http(s) schemes.",
        ("python",),
        r"\burlopen\s*\(\s*(?!['\"]https?://)[\w(]",
    ),
    # ---------- JavaScript / TypeScript ----------
    (
        "js.axios-variable-url",
        "Node axios fetch of a non-literal URL",
        "axios.get/.post/.request (or axios(config)) with a variable URL is an SSRF sink when the URL comes from a request.",
        Severity.HIGH,
        Confidence.LOW,
        "ssrf",
        "Allowlist the destination host/scheme; block redirects to private IPs (axios maxRedirects + a custom validator).",
        ("javascript", "typescript"),
        r"\baxios\s*(?:\.\s*(?:get|post|put|patch|delete|request)\s*)?\(\s*(?!['\"]https?://)[\w`{]",
    ),
    (
        "js.fetch-variable-url",
        "Node fetch() of a non-literal URL",
        "fetch(variable) / fetch(`...${x}`) on the server side reaches whatever host the value names — an SSRF sink.",
        Severity.HIGH,
        Confidence.LOW,
        "ssrf",
        "Validate the URL host against an allowlist before fetching; reject private/link-local addresses.",
        ("javascript", "typescript"),
        r"(?<!\.)\bfetch\s*\(\s*(?!['\"]https?://)[\w`{]",
    ),
    # ---------- Go ----------
    (
        "go.http-get-variable-url",
        "Go http.Get/Post of a non-literal URL",
        "http.Get(url) / http.Post(url, ...) with a variable URL is an SSRF sink when url is request-derived.",
        Severity.HIGH,
        Confidence.LOW,
        "ssrf",
        "Parse the URL and allowlist host+scheme before the request; use a custom http.Client that blocks private IPs.",
        ("go",),
        r"\bhttp\.(?:Get|Post|Head)\s*\(\s*(?!\"https?://)[\w]",
    ),
    # ---------- PHP ----------
    (
        "php.fetch-superglobal-url",
        "PHP file_get_contents/curl of a request-supplied URL",
        "file_get_contents($_GET[...]) or curl_setopt(..., CURLOPT_URL, $_GET[...]) fetches an attacker-named URL — SSRF.",
        Severity.HIGH,
        Confidence.LOW,
        "ssrf",
        "Allowlist the host/scheme; disable following redirects and block internal addresses.",
        ("php",),
        r"(?:file_get_contents|curl_setopt)\s*\([^)]*\$_(?:GET|POST|REQUEST)\b",
    ),
]


RULES = tuple(
    RegexRule(
        rule_id=rid,
        title=title,
        description=desc,
        severity=sev,
        confidence=conf,
        category=cat,
        remediation=remed,
        languages=langs,
        pattern=pat,
        flags=re.MULTILINE,
    )
    for rid, title, desc, sev, conf, cat, remed, langs, pat in _RULES_RAW
)
