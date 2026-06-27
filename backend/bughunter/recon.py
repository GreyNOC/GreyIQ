"""GreyIQ BugHunter — bounded recon / discovery.

A campaign starts by mapping the surface: a small, same-origin, depth- and
page-capped crawl plus passive recon (robots.txt, sitemap.xml,
/.well-known/security.txt) to find more input points than the single landing
page. Every fetch goes through the passive scanner's SSRF/private-host/port guard
(reused verbatim), is GET-only, rate-limited by the shared per-host governor, and
NEVER leaves the seed origin. Pure / frozen-safe.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

from bughunter.rate_limit import HostRateGovernor
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _fetch_raw, _guard_url

# Pull hrefs / form actions / script srcs out of HTML (cheap, no parser dep).
_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#\s]+)["']""", re.IGNORECASE)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
# Non-page assets we don't bother queuing as crawl targets.
_SKIP_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
             ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webm", ".mp3", ".map")


def _same_origin(url: str, host: str) -> bool:
    return (urlparse(url).hostname or "").lower() == host.lower()


def _clean(url: str) -> str:
    return urldefrag(url)[0]


def _extract_links(body: str, base_url: str, host: str) -> list[str]:
    out: list[str] = []
    for raw in _LINK_RE.findall(body or "")[:600]:
        if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        try:
            absolute = _clean(urljoin(base_url, raw))
        except ValueError:
            continue
        if absolute.lower().endswith(_SKIP_EXT):
            continue
        if absolute.startswith(("http://", "https://")) and _same_origin(absolute, host):
            out.append(absolute)
    return out


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
    settings: Any = None,
    governor: HostRateGovernor | None = None,
) -> dict[str, Any]:
    """Crawl the seed origin (bounded) + passive recon. Returns
    {urls, host, sources, notes} where urls is a deduped, in-origin, capped list
    (seed first). ``scope_in(host) -> bool`` optionally gates which hosts may be
    fetched (defaults to same-origin only)."""
    settings = settings or get_settings()
    try:
        sanitized = _guard_url(normalize_website_url(seed_url), settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return {"urls": [seed_url], "host": "", "sources": {}, "notes": [f"recon skipped: {exc}"]}
    host = (urlparse(sanitized).hostname or "").lower()
    governor = governor or HostRateGovernor(
        capacity=max(settings.active_max_requests_per_host, max_pages + 6),
        min_interval_s=settings.active_min_interval_ms / 1000.0,
    )

    def in_scope(u: str) -> bool:
        if not _same_origin(u, host):
            return False
        return bool(scope_in(urlparse(u).hostname or "")) if callable(scope_in) else True

    discovered: list[str] = [sanitized]
    seen = {sanitized}
    sources: dict[str, int] = {}
    notes: list[str] = []

    # --- Passive recon: robots, sitemap, security.txt seed extra paths. ---
    base = f"{urlparse(sanitized).scheme}://{urlparse(sanitized).netloc}"
    for path, kind in (("/robots.txt", "robots"), ("/sitemap.xml", "sitemap"), ("/.well-known/security.txt", "security.txt")):
        fetched = _safe_fetch(base + path, settings, governor)
        if not fetched or fetched.get("status", 0) >= 400:
            continue
        body = fetched.get("body") or ""
        found = 0
        if kind == "robots":
            for m in re.findall(r"(?:Disallow|Allow|Sitemap)\s*:\s*(\S+)", body, re.IGNORECASE)[:100]:
                url = _clean(urljoin(base + "/", m))
                if url.startswith(("http://", "https://")) and in_scope(url) and url not in seen:
                    seen.add(url); discovered.append(url); found += 1
        elif kind == "sitemap":
            for loc in _SITEMAP_LOC_RE.findall(body)[:200]:
                url = _clean(loc.strip())
                if url.startswith(("http://", "https://")) and in_scope(url) and url not in seen:
                    seen.add(url); discovered.append(url); found += 1
        else:  # security.txt presence is itself a (good) signal
            notes.append("security.txt present (program contact / policy).")
        if found:
            sources[kind] = found

    # --- Bounded BFS crawl from the seed. ---
    queue: list[tuple[str, int]] = [(sanitized, 0)]
    crawled = 0
    while queue and len(discovered) < max_pages and crawled < max_pages:
        url, depth = queue.pop(0)
        if depth > max_depth:
            continue
        fetched = _safe_fetch(url, settings, governor)
        crawled += 1
        if not fetched:
            continue
        for link in _extract_links(fetched.get("body") or "", fetched.get("final_url") or url, host):
            if link in seen or not in_scope(link):
                continue
            seen.add(link)
            discovered.append(link)
            sources["crawl"] = sources.get("crawl", 0) + 1
            if len(discovered) < max_pages:
                queue.append((link, depth + 1))
            if len(discovered) >= max_pages:
                break

    if len(discovered) >= max_pages:
        notes.append(f"discovery capped at {max_pages} URLs.")
    return {"urls": discovered[:max_pages], "host": host, "sources": sources, "notes": notes}
