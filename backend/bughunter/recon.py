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
import json
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
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
# A bare URL or leading-slash path inside a comment body (no host/scope matching here — every
# candidate is urljoin'd + in_scope()-gated at the call site before it's ever fetched).
_BARE_URL_RE = re.compile(r"""(?:https?://[^\s"'<>()]+|(?<![\w/])/[A-Za-z0-9_][A-Za-z0-9_./%\-]{1,120})""")
# Form-field names — the param names a page's own inputs submit. These are exactly the
# parameters the active prover should bite on, even when no link carries them in a query
# string. ``name=`` may appear before or after other attributes on the tag.
_FORM_NAME_RE = re.compile(
    r"""<(?:input|textarea|select|button)\b[^>]*?\bname\s*=\s*["']([A-Za-z_][A-Za-z0-9_\-\[\]\.]{0,39})["']""",
    re.IGNORECASE,
)
# A whole <form> block: its action target + method + the fields it submits. The action is a
# real endpoint that RECEIVES those params, so it belongs on the crawl/probe surface even when
# no <a href> points at it. Non-greedy body match handles the common (non-nested) case.
_FORM_BLOCK_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_ATTR_ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_ATTR_METHOD_RE = re.compile(r"""\bmethod\s*=\s*["']([A-Za-z]+)["']""", re.IGNORECASE)
# /.well-known/ OIDC & OAuth discovery documents — JSON that enumerates the real
# authorization/token/userinfo/jwks endpoints (prime auth surface a crawl never reaches).
# Bounded, one GET each, scope-gated, budget-shared; extracted endpoints are in_scope-gated too.
_WELL_KNOWN_JSON = ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")
# The URL-valued keys in an OIDC/OAuth discovery document — each is a concrete endpoint.
_OIDC_ENDPOINT_KEYS = ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
                       "registration_endpoint", "end_session_endpoint", "revocation_endpoint",
                       "introspection_endpoint", "device_authorization_endpoint")
_SKIP_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
             ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webm", ".mp3", ".map")
_MAX_JS = 8  # served-JS bundles mined per campaign (bounded)
_MAX_SITEMAPS = 6         # child/robots-declared sitemap files fetched per campaign (bounded)
_MAX_SITEMAP_DEPTH = 2    # sitemap-index recursion depth cap

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


def _extract_forms(body: str, base_url: str) -> list[dict[str, Any]]:
    """Each <form> as {action, method, params}. ``action`` is absolute (empty/self-submit ->
    the page URL); ``params`` are that form's own field names. NOT scope-filtered here — the
    caller scope-gates every action before queuing it."""
    out: list[dict[str, Any]] = []
    for attrs, inner in _FORM_BLOCK_RE.findall(body or "")[:40]:
        am = _ATTR_ACTION_RE.search(attrs)
        raw_action = _unescape_url(am.group(1).strip()) if am else ""
        if raw_action.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        try:
            action = _clean(urljoin(base_url, raw_action) if raw_action else base_url)
        except ValueError:
            continue
        if not action.startswith(("http://", "https://")):
            continue
        mm = _ATTR_METHOD_RE.search(attrs)
        method = (mm.group(1).upper() if mm else "GET") or "GET"
        out.append({"action": action, "method": method,
                    "params": sorted(set(_FORM_NAME_RE.findall(inner)[:200]))})
    return out


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
    forms_out: list[dict[str, Any]] = []  # structured in-scope forms (action/method/fields) for the reasoning layer
    dropped_oos = 0
    js_done: set[str] = set()

    # --- Passive recon: robots + security.txt seed extra paths; sitemaps handled by the recursive
    # worklist below (which follows sitemap-index children + robots-declared Sitemap: files). ---
    base = f"{urlparse(sanitized).scheme}://{urlparse(sanitized).netloc}"
    sitemap_worklist: list[tuple[str, int]] = [(base + "/sitemap.xml", 0)]  # (url, depth)
    for path, kind in (("/robots.txt", "robots"), ("/.well-known/security.txt", "security.txt")):
        fetched = budgeted_fetch(base + path)
        if not fetched or fetched.get("status", 0) >= 400:
            continue
        body = fetched.get("body") or ""
        found = 0
        if kind == "robots":
            for label, m in re.findall(r"(Disallow|Allow|Sitemap)\s*:\s*(\S+)", body, re.IGNORECASE)[:100]:
                # robots.txt is served BY the target -- a malformed directive value (e.g. an
                # incomplete IPv6-bracket URL) makes urljoin() raise ValueError; guard it.
                try:
                    url = _clean(urljoin(base + "/", m))
                except ValueError:
                    continue
                if not url.startswith(("http://", "https://")):
                    continue
                if label.lower() == "sitemap":
                    if in_scope(url):  # a robots-declared Sitemap: -> recurse (gated again when popped)
                        sitemap_worklist.append((url, 0))
                    else:
                        dropped_oos += 1  # robots.txt can point Sitemap: at an OOS host
                    continue
                if in_scope(url) and url not in seen:
                    seen.add(url); discovered.append(url); found += 1
        else:
            notes.append("security.txt present (program contact / policy).")
        if found:
            sources[kind] = found

    # Recurse sitemap INDEXES + robots-declared Sitemap: files into their child sitemaps — captures
    # the full published URL inventory large sites split across dozens of child sitemaps. TWO guards:
    # (1) GATE-BEFORE-FETCH each sitemap URL, (2) RE-GATE the final_url AFTER fetch (an in-scope
    # sitemap can 302 to an OOS host; the fetch redirect guard is SSRF-only). Bounded by depth,
    # child count, and the shared request budget.
    sm_seen: set[str] = set()
    sm_children = 0
    sm_found = 0
    while sitemap_worklist and used["n"] < max_requests and sm_children < _MAX_SITEMAPS:
        sm_url, sm_depth = sitemap_worklist.pop(0)
        if sm_url in sm_seen or sm_depth > _MAX_SITEMAP_DEPTH or not in_scope(sm_url):
            continue
        sm_seen.add(sm_url)
        sm_children += 1
        fetched = budgeted_fetch(sm_url)
        if not fetched or fetched.get("status", 0) >= 400:
            continue
        if not in_scope(fetched.get("final_url") or sm_url):  # re-gate: the sitemap could 302 out of scope
            dropped_oos += 1
            continue
        smbody = fetched.get("body") or ""
        is_index = "<sitemapindex" in smbody.lower()
        for loc in _SITEMAP_LOC_RE.findall(smbody)[:400]:
            url = _clean(_unescape_url(loc.strip()))  # <loc> is XML — decode &amp; to the real URL
            if not url.startswith(("http://", "https://")) or not in_scope(url):
                continue
            if is_index:
                sitemap_worklist.append((url, sm_depth + 1))  # child sitemap -> gated when popped
            elif url not in seen and len(discovered) < max_pages:
                seen.add(url); discovered.append(url); sm_found += 1
    if sm_found:
        sources["sitemap"] = sm_found

    # --- OIDC / OAuth discovery documents. A self-hosted auth server publishes its real
    # authorization/token/userinfo/jwks endpoints here — endpoints the HTML crawl never sees.
    # GATE-BEFORE-FETCH the descriptor, RE-GATE its final_url, and in_scope-gate every endpoint
    # it names (an external IdP's endpoints are out of scope and dropped, never added). ---
    wk_found = 0
    for wk in _WELL_KNOWN_JSON:
        if used["n"] >= max_requests:
            break
        fetched = budgeted_fetch(base + wk)
        if not fetched or fetched.get("status", 0) >= 400:
            continue
        if not in_scope(fetched.get("final_url") or (base + wk)):  # descriptor could 302 out of scope
            dropped_oos += 1
            continue
        try:
            doc = json.loads(fetched.get("body") or "")
        except (ValueError, TypeError):
            continue
        if not isinstance(doc, dict):
            continue
        for key in _OIDC_ENDPOINT_KEYS:
            val = doc.get(key)
            if not isinstance(val, str) or not val.startswith(("http://", "https://")):
                continue
            ep = _clean(val)
            if ep in seen or len(discovered) >= max_pages:
                continue
            if not in_scope(ep):  # a federated endpoint on an external IdP host — drop it
                dropped_oos += 1
                continue
            seen.add(ep); discovered.append(ep); wk_found += 1
        issuer = doc.get("issuer")
        if isinstance(issuer, str) and issuer:
            notes.append(f"OIDC/OAuth discovery at {wk} (issuer {issuer[:80]}).")
    if wk_found:
        sources["well-known"] = wk_found

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

        # A <form>'s action target is a real endpoint that RECEIVES the form's params — surface
        # the active prover would otherwise miss (no <a href> points at a POST action). Queue each
        # in-scope action + union its field names; the action URL is scope-gated before queuing.
        for form in _extract_forms(body, final):
            params.update(form["params"])
            action = form["action"]
            if not in_scope(action):
                dropped_oos += 1
                continue
            # Record the in-scope form (action + method + fields) for the reasoning layer, even if
            # its action URL was already discovered — the brain reasons about the form's shape.
            if len(forms_out) < 30 and not any(f["action"] == action for f in forms_out):
                forms_out.append({"action": action, "method": form["method"], "params": form["params"]})
            if action in seen:
                continue
            seen.add(action); discovered.append(action)
            sources["form"] = sources.get("form", 0) + 1
            if len(discovered) < max_pages:
                queue.append((action, depth + 1))
            if len(discovered) >= max_pages:
                break

        # Mine the landing HTML body ITSELF (zero extra fetches) — reaches endpoints/params living in
        # inline <script>, __NEXT_DATA__/__STATE__ blobs, and inline config. Union params/secrets +
        # in_scope-gated endpoints only (never hosts, never queued) — exactly like the served-JS branch.
        inline = mine_js(body, final, host_filter=host_ok)
        params.update(inline.get("params") or [])
        js_secrets.extend(inline.get("secret_findings") or [])
        for ep in (inline.get("endpoints") or []):
            if ep not in seen and in_scope(ep) and len(discovered) < max_pages:
                seen.add(ep); discovered.append(ep)
                sources["js-inline"] = sources.get("js-inline", 0) + 1

        # Parse HTML comments for commented-out endpoints / dev-staging URLs / disabled links. The
        # bare-URL regex only EXTRACTS candidate strings; each is urljoin'd absolute and passes the
        # SAME in_scope() gate every crawled link does before it's queued (an OOS candidate is dropped).
        for comment in _HTML_COMMENT_RE.findall(body)[:40]:
            cands = _extract_links(comment, final) + [
                (_clean(urljoin(final + "/", m)) if not m.startswith(("http://", "https://")) else _clean(m))
                for m in _BARE_URL_RE.findall(comment)[:60]
            ]
            for cand in cands:
                if not cand.startswith(("http://", "https://")) or cand in seen:
                    continue
                if not in_scope(cand):
                    dropped_oos += 1
                    continue
                seen.add(cand); discovered.append(cand)
                sources["comment"] = sources.get("comment", 0) + 1
                if len(discovered) < max_pages:
                    queue.append((cand, depth + 1))
                if len(discovered) >= max_pages:
                    break

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
            # A mined host can be an in-scope SIBLING (api.example.com) that no HTML link exposes.
            # RE-GATE each with host_ok (mine_js's own filter is a looser same-apex match that ignores
            # active scope + excluded_hosts) before seeding its root as a crawl target.
            for mh in (mined.get("hosts") or []):
                root = f"https://{(mh or '').lower()}/"
                if host_ok(mh) and root not in seen and len(discovered) < max_pages:
                    seen.add(root); discovered.append(root)
                    sources["js-host"] = sources.get("js-host", 0) + 1
                    queue.append((root, depth + 1))
            for ep in (mined.get("endpoints") or []):
                if ep not in seen and in_scope(ep) and len(discovered) < max_pages:
                    seen.add(ep); discovered.append(ep)
                    sources["js-endpoint"] = sources.get("js-endpoint", 0) + 1
                    queue.append((ep, depth + 1))  # actually CRAWL it (its body/sublinks/forms/JS), not just inventory

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
        "forms": forms_out, "api_findings": api_findings,
        "dropped_out_of_scope": dropped_oos, "requests_used": used["n"],
    }
