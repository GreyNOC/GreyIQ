"""GreyIQ BugHunter — passive tech fingerprinting.

A pure function over response data the scanner ALREADY fetched (headers/cookies/body)
— no extra requests. It names the stack and emits advisory ``hints`` (class_id ->
why) the campaign uses to REORDER/weight which already-gated active checks to try
first (e.g. a Django app -> emphasize SSTI/SQLi). Hints are ADVISORY ONLY: they never
enable a check that scope/budget would gate, never invent params/payloads, never relax
the negative-control rule. Fail-open to empty on anything unexpected. Frozen-safe.
"""

from __future__ import annotations

from typing import Any

# (substring to look for, where, tech label, hinted class_id)
_HEADER_SIGNS = [
    ("x-powered-by", "php", "PHP", "rce"),
    ("x-aspnet-version", "", "ASP.NET", "rce"),
    ("x-aspnetmvc-version", "", "ASP.NET MVC", "rce"),
    ("server", "apache", "Apache", ""),
    ("server", "nginx", "nginx", ""),
    ("server", "express", "Express", "ssti"),
    ("server", "werkzeug", "Flask/Werkzeug", "ssti"),
    ("server", "gunicorn", "Python (gunicorn)", "ssti"),
]
_COOKIE_SIGNS = [
    ("phpsessid", "PHP", "rce"),
    ("jsessionid", "Java", "deserialization"),
    ("laravel_session", "Laravel (PHP)", "rce"),
    ("asp.net", "ASP.NET", "rce"),
    ("django", "Django", "ssti"),
    ("connect.sid", "Node/Express", "ssti"),
]
_BODY_SIGNS = [
    ("wp-content", "WordPress", "rce"),
    ("__next_data__", "Next.js", "ssti"),
    ("/_nuxt/", "Nuxt.js", "ssti"),
    ("csrfmiddlewaretoken", "Django", "ssti"),
    ("ng-version", "Angular", "xss"),
    ("__graphql", "GraphQL", "graphql"),
    ("/graphql", "GraphQL", "graphql"),
    ("drupal", "Drupal", "rce"),
]


def fingerprint(headers: dict[str, Any] | None, body: str | None, cookies: Any = None) -> dict[str, Any]:
    """Return {tech: [labels], hints: {class_id: reason}} from already-fetched data."""
    try:
        h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
        cookie_text = " ".join(str(c).lower() for c in (cookies or []))
        body_low = (body or "")[:200_000].lower()
        tech: list[str] = []
        hints: dict[str, str] = {}

        def add(label: str, cid: str, reason: str) -> None:
            if label not in tech:
                tech.append(label)
            if cid and cid not in hints:
                hints[cid] = reason

        for header, needle, label, cid in _HEADER_SIGNS:
            val = h.get(header, "")
            if val and (not needle or needle in val):
                add(label, cid, f"{header}: {val[:40]}")
        for needle, label, cid in _COOKIE_SIGNS:
            if needle in cookie_text:
                add(label, cid, f"{needle} cookie")
        for needle, label, cid in _BODY_SIGNS:
            if needle in body_low:
                add(label, cid, f"'{needle}' in body")
        return {"tech": tech[:12], "hints": hints}
    except Exception:  # noqa: BLE001 - fingerprinting is advisory; never break the scan
        return {"tech": [], "hints": {}}
