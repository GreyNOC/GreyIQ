"""GreyIQ BugHunter — bounded recon / discovery.

A campaign starts by mapping the surface: a depth- and page-capped crawl, passive
recon (robots.txt, sitemap.xml, /.well-known/security.txt), served-JS endpoint/secret
mining, and tech fingerprinting — to find far more input points than the single
landing page. Every fetch goes through the passive scanner's SSRF/private-host/port
guard (reused verbatim), is GET-only, and is bounded three ways: the per-host token
governor, a global per-campaign request budget (the kill switch for host fan-out under
a wildcard scope), and the page cap.

SCOPE: by default discovery never leaves the seed origin. When the caller passes a
``scope_in(host) -> bool`` gate (the campaign binds it to the SAME fail-closed
host_in_active_scope used for active probing), discovery may follow in-scope hosts —
and ONLY those; every new host is checked BEFORE it is fetched, and out-of-scope hosts
are counted, never fetched. Pure / frozen-safe.
"""

from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse

from bughunter import api_discovery_service
from bughunter.fingerprint import fingerprint
from bughunter.rate_limit import HostRateGovernor
from bughunter.recon_js import mine_js
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _fetch_raw, _guard_url

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#\s]+)["']""", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+\.m?js[^"']*)["']""", re.IGNORECASE)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
# Form-field names — the param names a page's own inputs submit. These are exactly the
# parameters the active prover should bite on, even when no link carries them in a query
# string. ``name=`` may appear before or after other attributes on the tag.
_FORM_NAME_RE = re.compile(
    r"""<(?:input|textarea|select|button)\b[^>]*?\bname\s*=\s*["']([A-Za-z_][A-Za-z0-9_\-\[\]\.]{0,39})["']""",
    re.IGNORECASE,
)
_SKIP_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
             ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webm", ".mp3", ".map")
_MAX_JS = 8  # served-JS bundles mined per campaign (bounded)

# Decode ONLY well-formed, ';'-terminated HTML/XML entities in an extracted URL (so a
# properly-encoded '&amp;' becomes '&'), while leaving a RAW '&' untouched. Full
# html.unescape() is the wrong tool here: it greedily resolves *semicolon-less* HTML5 named
# references, so a raw query string like '?a=1&param=2' (invalid HTML but widespread) would
# have '&param' eaten as '¶m' — silently dropping the 'param' parameter from the discovered
# attack surface. This regex only matches the unambiguous ';'-terminated form.
_URL_ENTITY_RE = re.compile(r"&(?:#[0-9]+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);")


def _unescape_url(value: str) -> str:
    return _URL_ENTITY_RE.sub(lambda m: html.unescape(m.group(0)), value)


def _same_origin(url: str, host: str) -> bool:
    return (urlparse(url).hostname or "").lower() == host.lower()


def _clean(url: str) -> str:
    return urldefrag(url)[0]


def _extract_links(body: str, base_url: str) -> list[str]:
    """All in-page http(s) links (NOT scope-filtered — the caller applies the scope
    gate so out-of-scope hosts can be counted)."""
    out: list[str] = []
    for raw in _LINK_RE.findall(body or "")[:600]:
        if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        # An href/src value in HTML encodes '&' as '&amp;' (and may carry other entities).
        # Use the DECODED value as the real URL, or the '&amp;' survives into the finding
        # location + curl PoC (breaking reproduction) and mis-parses the query into a bogus
        # 'amp;<name>' parameter the active prober would then chase.
        raw = _unescape_url(raw)
        try:
            absolute = _clean(urljoin(base_url, raw))
        except ValueError:
            continue
        if absolute.lower().endswith(_SKIP_EXT):
            continue
        if absolute.startswith(("http://", "https://")):
            out.append(absolute)
    return out


def _extract_scripts(body: str, base_url: str) -> list[str]:
    out: list[str] = []
    for raw in _SCRIPT_SRC_RE.findall(body or "")[:60]:
        raw = _unescape_url(raw)  # decode ';'-terminated entities — the src is a real URL, not display HTML
        try:
            absolute = _clean(urljoin(base_url, raw))
        except ValueError:
            continue
        if absolute.startswith(("http://", "https://")):
            out.append(absolute)
    return out


def _html_param_names(body: str) -> set[str]:
    """Parameter names from a page's own form fields (input/select/textarea/button)."""
    return set(_FORM_NAME_RE.findall(body or "")[:200])


def _qs_param_names(url: str) -> set[str]:
    """Query-string parameter names embedded in a URL — so a param seen on one endpoint
    can be tried against a param-less sibling."""
    try:
        return {k for k, _ in parse_qsl(urlparse(url).query) if k}
    except ValueError:
        return set()


def _safe_fetch(url: str, settings: Any, governor: HostRateGovernor) -> dict[str, Any] | None:
    host = urlparse(url).hostname or ""
    if not governor.throttle(host):
        return None
    try:
        return _fetch_raw(url)  # full SSRF/redirect guard; GET only
    except (WebsiteFetchError, OSError, ValueError):
        return None


def discover(
    seed_url: str,
    *,
    scope_in: Any = None,
    max_pages: int = 15,
    max_depth: int = 2,
    max_requests: int = 40,
    settings: Any = None,
    governor: HostRateGovernor | None = None,
) -> dict[str, Any]:
    """Map the seed's surface (bounded). Returns {urls, host, sources, notes,
    endpoints, params, js_secrets, tech, hints, dropped_out_of_scope, requests_used}.
    ``scope_in(host) -> bool`` gates which hosts may be fetched (default: same-origin)."""
    settings = settings or get_settings()
    try:
        sanitized = _guard_url(normalize_website_url(seed_url), settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return {"urls": [seed_url], "host": "", "sources": {}, "notes": [f"recon skipped: {exc}"],
                "endpoints": [], "params": [], "js_secrets": [], "tech": [], "hints": {}, "dropped_out_of_scope": 0, "requests_used": 0}
    host = (urlparse(sanitized).hostname or "").lower()
    governor = governor or HostRateGovernor(
        capacity=max(settings.active_max_requests_per_host, max_pages + 6),
        min_interval_s=settings.active_min_interval_ms / 1000.0,
    )
    used = {"n": 0}

    def budgeted_fetch(url: str) -> dict[str, Any] | None:
        if used["n"] >= max_requests:
            return None  # global per-campaign budget — the host-fan-out kill switch
        used["n"] += 1
        return _safe_fetch(url, settings, governor)

    def host_ok(h: str) -> bool:
        h = (h or "").lower()
        if not h:
            return False
        if h == host:
            return True
        return bool(scope_in(h)) if callable(scope_in) else False

    def in_scope(u: str) -> bool:
        return host_ok(urlparse(u).hostname or "")

    discovered: list[str] = [sanitized]
    seen = {sanitized}
    sources: dict[str, int] = {}
    notes: list[str] = []
    params: set[str] = set()
    js_secrets: list[dict[str, Any]] = []
    tech: list[str] = []
    hints: dict[str, str] = {}
    dropped_oos = 0
    js_done: set[str] = set()

    # --- Passive recon: robots, sitemap, security.txt seed extra paths. ---
    base = f"{urlparse(sanitized).scheme}://{urlparse(sanitized).netloc}"
    for path, kind in (("/robots.txt", "robots"), ("/sitemap.xml", "sitemap"), ("/.well-known/security.txt", "security.txt")):
        fetched = budgeted_fetch(base + path)
        if not fetched or fetched.get("status", 0) >= 400:
            continue
        body = fetched.get("body") or ""
        found = 0
        if kind == "robots":
            for m in re.findall(r"(?:Disallow|Allow|Sitemap)\s*:\s*(\S+)", body, re.IGNORECASE)[:100]:
                # robots.txt is served BY the target -- a malformed directive value
                # (e.g. an incomplete IPv6-bracket URL) makes urljoin() raise
                # ValueError, same hazard _extract_links/_extract_scripts already
                # guard against; unguarded here it escaped discover() (and its only
                # caller, run_campaign, which has no try/except of its own either).
                try:
                    url = _clean(urljoin(base + "/", m))
                except ValueError:
                    continue
                if url.startswith(("http://", "https://")) and in_scope(url) and url not in seen:
                    seen.add(url); discovered.append(url); found += 1
        elif kind == "sitemap":
            for loc in _SITEMAP_LOC_RE.findall(body)[:200]:
                # <loc> is XML — '&' is encoded as '&amp;'. Decode to the real URL (robots.txt
                # below is plain text and is intentionally NOT unescaped).
                url = _clean(_unescape_url(loc.strip()))
                if url.startswith(("http://", "https://")) and in_scope(url) and url not in seen:
                    seen.add(url); discovered.append(url); found += 1
        else:
            notes.append("security.txt present (program contact / policy).")
        if found:
            sources[kind] = found

    # --- Bounded BFS crawl + served-JS mine + fingerprint. ---
    queue: list[tuple[str, int]] = [(sanitized, 0)]
    crawled = 0
    while queue and len(discovered) < max_pages and used["n"] < max_requests and crawled < max_pages:
        url, depth = queue.pop(0)
        if depth > max_depth:
            continue
        fetched = budgeted_fetch(url)
        crawled += 1
        if not fetched:
            continue
        body = fetched.get("body") or ""
        final = fetched.get("final_url") or url
        # The QUEUED url was scope-checked before being crawled, but _fetch_raw's redirect
        # guard only validates SSRF safety per-hop, never SCOPE -- an in-scope page can
        # still 302 to a public out-of-scope host. Mining params/fingerprinting/links from
        # that OOS body would leak it into the active prover's surface and the report's
        # tech fingerprint, so skip ALL body processing for this fetch once it has landed
        # somewhere out of scope (each extracted link is still independently scope-checked
        # before being queued, but we must never even look at an OOS page's content).
        if not in_scope(final):
            dropped_oos += 1
            continue
        params.update(_html_param_names(body))  # the page's own form-field names

        if not tech:  # fingerprint once, from the first reachable page
            fp = fingerprint(fetched.get("headers"), body, fetched.get("cookies"))
            tech, hints = fp.get("tech") or [], fp.get("hints") or {}

        for link in _extract_links(body, final):
            if link in seen:
                continue
            if not in_scope(link):
                dropped_oos += 1
                continue
            seen.add(link)
            discovered.append(link)
            sources["crawl"] = sources.get("crawl", 0) + 1
            if len(discovered) < max_pages:
                queue.append((link, depth + 1))
            if len(discovered) >= max_pages:
                break

        # Mine served JS for endpoints / params / secrets.
        for js_url in _extract_scripts(body, final):
            if js_url in js_done or len(js_done) >= _MAX_JS or used["n"] >= max_requests:
                continue
            if not in_scope(js_url):
                dropped_oos += 1
                continue
            js_done.add(js_url)
            jf = budgeted_fetch(js_url)
            if not jf:
                continue
            mined = mine_js(jf.get("body") or "", jf.get("final_url") or js_url, host_filter=host_ok)
            params.update(mined.get("params") or [])
            js_secrets.extend(mined.get("secret_findings") or [])
            for ep in (mined.get("endpoints") or []):
                if ep not in seen and in_scope(ep) and len(discovered) < max_pages:
                    seen.add(ep); discovered.append(ep)
                    sources["js-endpoint"] = sources.get("js-endpoint", 0) + 1

    # --- API surface discovery: OpenAPI/Swagger spec + GraphQL introspection (GET-only,
    # scope-gated, budget-shared). Expands the prover's surface with the spec's endpoints +
    # params, and flags GraphQL introspection if it's enabled. ---
    api_findings: list[dict[str, Any]] = []
    api_surface = api_discovery_service.discover_api_surface(sanitized, fetch=budgeted_fetch, in_scope=in_scope)
    for ep in api_surface.get("endpoints") or []:
        if ep not in seen and in_scope(ep) and len(discovered) < max_pages:
            seen.add(ep); discovered.append(ep)
            sources["api-spec"] = sources.get("api-spec", 0) + 1
    params.update(api_surface.get("params") or [])
    api_findings = api_surface.get("findings") or []
    notes.extend(api_surface.get("notes") or [])

    # Query-string param names from every discovered URL — a param seen on one endpoint
    # becomes a candidate for a param-less sibling (the active prover dedupes per-URL).
    for disc_url in discovered:
        params.update(_qs_param_names(disc_url))

    if len(discovered) >= max_pages:
        notes.append(f"discovery capped at {max_pages} URLs.")
    if used["n"] >= max_requests:
        notes.append(f"recon request budget ({max_requests}) reached — surface may be partial.")
    if dropped_oos:
        notes.append(f"{dropped_oos} discovered link(s) skipped as out-of-scope.")
    if js_secrets:
        notes.append(f"{len(js_secrets)} secret(s) found in served JS (redacted).")
    if params:
        notes.append(f"{len(params)} input parameter name(s) discovered (forms/JS/links) — probed by the active checks.")

    return {
        "urls": discovered[:max_pages], "host": host, "sources": sources, "notes": notes,
        "endpoints": [u for u in discovered if u != sanitized][:max_pages],
        "params": sorted(params)[:60], "js_secrets": js_secrets, "tech": tech, "hints": hints,
        "api_findings": api_findings,
        "dropped_out_of_scope": dropped_oos, "requests_used": used["n"],
    }
