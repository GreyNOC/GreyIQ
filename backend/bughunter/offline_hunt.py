"""Offline hunt intelligence — the no-LLM hunt brain.

TinyGPT (the 0.8M-param char-level model) is far too small to reason about vulnerability classes or
emit the structured guidance the hunt needs, so the OFFLINE path (no Claude/Ollama configured) used to
get an EMPTY plan — it hunted blind. ``offline_plan`` fills that: it produces the SAME plan shape
``hunt_brain.plan_hunt`` does (param_hypotheses / probe_priority / ssrf_params / xss_params /
idor_candidates), derived from curated bug-bounty KNOWLEDGE RULES over the recon surface and SHARPENED
by what the program has actually confirmed before (``learning.learned_priors``). No model, no network.

SAFETY: identical to the LLM brain's contract — it only ever emits parameter NAMES, verbatim in-scope
endpoint selections, and class orderings. Every one is re-validated by hunt_brain._validate_plan and
executed by the deterministic, scope+SSRF-gated prover, which owns every confirmation. It can raise
recall, never precision.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

# param-name substring -> the vuln class it most likely feeds. Ordered by specificity in _classify.
_SSRF_HINTS = ("url", "uri", "dest", "target", "callback", "webhook", "image", "avatar", "photo", "feed",
               "rss", "proxy", "fetch", "load", "site", "link", "source", "remote", "xml", "endpoint",
               "redirect_uri", "return_to", "continue", "domain", "host", "server", "upload")
_XSS_HINTS = ("q", "s", "query", "search", "keyword", "term", "name", "title", "message", "comment",
              "text", "body", "content", "desc", "subject", "error", "msg", "lang", "return", "ref")
_REDIRECT_HINTS = ("redirect", "next", "return", "url", "goto", "dest", "continue", "target", "back", "callback")
_RCE_HINTS = ("cmd", "exec", "command", "ping", "host", "ip", "run", "shell", "exe", "system", "func")
_TRAVERSAL_HINTS = ("file", "path", "page", "include", "doc", "document", "download", "attachment", "dir",
                    "folder", "load", "read", "view", "template", "img")
_SSTI_HINTS = ("template", "tpl", "render", "theme", "view", "layout", "format", "pattern")
_SQLI_HINTS = ("id", "user", "uid", "order", "sort", "filter", "category", "cat", "product", "item",
               "search", "query", "num", "page", "select", "where", "column", "field")
_IDOR_PARAM_HINTS = ("id", "user_id", "userid", "uid", "account", "account_id", "order", "order_id",
                     "invoice", "customer", "profile", "doc_id", "file_id", "record", "object")

# tech fingerprint -> classes to boost (a rendering/interpreter stack implies its injection surface).
_TECH_CLASS = {
    "flask": ("ssti",), "django": ("ssti",), "jinja": ("ssti",), "twig": ("ssti",), "php": ("rce", "sqli"),
    "wordpress": ("sqli", "xss"), "express": ("nosqli",), "node": ("nosqli",), "mongo": ("nosqli",),
    "asp.net": ("host-header",), "rails": ("ssti",), "graphql": ("nosqli",), "spring": ("ssti", "path-traversal"),
}

_NUMERIC_SEG_RE = re.compile(r"/\d+(?:/|$)")
_UUID_SEG_RE = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:/|$)")
# path substrings that mark an ADMIN / privileged FUNCTION worth a dual-session BFLA check (is the
# privileged action reachable by a low-privilege session?). Distinct from IDOR — this is function-level.
_PRIV_PATH_HINTS = ("/admin", "/internal", "/manage", "/moderat", "/staff", "/superuser", "/root/",
                    "/console", "/dashboard/admin", "/settings", "/config", "/audit", "/approve",
                    "/promote", "/grant", "/role", "/permission", "/impersonat", "/billing", "/payout")
_ACTIVE_CLASSES = ("xss", "sqli", "redirect", "ssti", "rce", "crlf", "path-traversal", "cors", "nosqli", "host-header")
_CAP = 24


def _hit(name: str, hints: tuple[str, ...]) -> bool:
    low = name.lower()
    return any(h in low for h in hints)


def _endpoint_params(url: str) -> list[str]:
    try:
        return [k for k, _ in parse_qsl(urlparse(url).query) if k]
    except ValueError:
        return []


def _classes_for_endpoint(url: str, names: list[str], tech_boost: tuple[str, ...]) -> list[str]:
    """The vuln classes worth prioritising on ONE endpoint, most-likely first — from its path shape,
    its parameter names, and the observed tech stack."""
    path = urlparse(url).path.lower()
    classes: list[str] = []

    def add(c: str) -> None:
        if c in _ACTIVE_CLASSES and c not in classes:
            classes.append(c)

    # path-shape cues (high signal)
    if any(k in path for k in ("redirect", "login", "logout", "sso", "oauth", "auth", "callback")):
        add("redirect")
    if any(k in path for k in ("download", "file", "attachment", "export", "include", "template", "view")):
        add("path-traversal")
    if any(k in path for k in ("search", "query", "find", "lookup")):
        add("xss"); add("sqli")
    if any(k in path for k in ("admin", "internal", "exec", "run", "cmd", "ping", "convert", "import")):
        add("rce")
    if "/api" in path or "graphql" in path or path.endswith(".json"):
        add("cors")
    # parameter-name cues
    for n in names:
        if _hit(n, _RCE_HINTS): add("rce")
        if _hit(n, _TRAVERSAL_HINTS): add("path-traversal")
        if _hit(n, _SSTI_HINTS): add("ssti")
        if _hit(n, _REDIRECT_HINTS): add("redirect")
        if _hit(n, _SQLI_HINTS): add("sqli")
        if _hit(n, _XSS_HINTS): add("xss")
        if _hit(n, _SSRF_HINTS): add("redirect")  # ssrf isn't a verify_active class; its url-params also feed redirect
    for c in tech_boost:
        add(c)
    return classes[:6]


def _reorder_by_priors(classes: list[str], priors: dict[str, float] | None) -> list[str]:
    """Stable-sort a class list so the classes the program has REWARDED before come first — the
    learning signal. Ties keep the knowledge order."""
    if not priors:
        return classes
    return sorted(classes, key=lambda c: -float(priors.get(c, 0.0)))


def offline_plan(surface: dict[str, Any], priors: dict[str, float] | None = None) -> dict[str, Any]:
    """Produce a hunt plan (same shape as hunt_brain.plan_hunt) from knowledge rules + learned priors.
    ``surface`` = {endpoints, params, tech, forms}; ``priors`` = learning.learned_priors (class->weight)."""
    endpoints = [str(u).strip() for u in (surface.get("endpoints") or []) if str(u or "").strip()]
    recon_params = {str(p).strip().lower() for p in (surface.get("params") or []) if str(p or "").strip()}
    tech = " ".join(str(t) for t in (surface.get("tech") or [])).lower()
    tech_boost = tuple({c for key, cs in _TECH_CLASS.items() if key in tech for c in cs})

    ssrf_params: list[str] = []
    xss_params: list[str] = []
    param_hypotheses: list[str] = []
    idor_candidates: list[str] = []
    privileged_endpoints: list[str] = []
    priority: list[dict[str, Any]] = []
    seen_pri: set[str] = set()

    # A curated set of high-yield param names to TRY even when recon didn't surface them — the offline
    # analogue of the LLM proposing param_hypotheses. Only NEW names (not already discovered) are added.
    _SUGGEST = {"url", "redirect", "next", "callback", "file", "path", "id", "q", "search", "template",
                "image_url", "webhook", "return", "dest", "user_id", "order_id", "cmd", "page"}

    for url in endpoints[:60]:
        names = _endpoint_params(url) or []
        alln = names + sorted(recon_params)
        classes = _reorder_by_priors(_classes_for_endpoint(url, alln, tech_boost), priors)
        if classes and url not in seen_pri:
            seen_pri.add(url)
            priority.append({"endpoint": url, "classes": classes})
        # object-scoped endpoint -> IDOR candidate
        if _NUMERIC_SEG_RE.search(url) or _UUID_SEG_RE.search(url) or any(_hit(n, _IDOR_PARAM_HINTS) for n in names):
            if url not in idor_candidates:
                idor_candidates.append(url)
        # admin / privileged FUNCTION path -> BFLA candidate (function-level, not object-level)
        low_path = urlparse(url).path.lower()
        if any(h in low_path for h in _PRIV_PATH_HINTS) and url not in privileged_endpoints:
            privileged_endpoints.append(url)
        for n in names + list(recon_params):
            if _hit(n, _SSRF_HINTS) and n not in ssrf_params:
                ssrf_params.append(n)
            if _hit(n, _XSS_HINTS) and n not in xss_params:
                xss_params.append(n)

    for n in _SUGGEST:
        if n.lower() not in recon_params and n not in param_hypotheses:
            param_hypotheses.append(n)

    return {
        "used": bool(endpoints), "provider": "offline", "model": "greyiq-offline-hunt",
        "param_hypotheses": param_hypotheses[:_CAP],
        "probe_priority": priority[:20],
        "ssrf_params": ssrf_params[:12],
        "xss_params": xss_params[:12],
        "idor_candidates": idor_candidates[:6],
        "privileged_endpoints": privileged_endpoints[:6],
        "notes": (f"offline knowledge-rule plan over {len(endpoints)} endpoint(s)"
                  + (" (sharpened by learned priors)" if priors else "")),
    }
