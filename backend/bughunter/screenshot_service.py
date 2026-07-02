"""GreyIQ BugHunter — visual evidence capture (Playwright screenshot).

Captures a PNG of a finding's proof-of-concept URL in a real headless browser, so a bug
report can carry a screenshot a triager can actually see. Opt-in and gated exactly like
the active prover: it only drives a host the operator NAMED in scope (fail-closed) and
reuses the passive scanner's SSRF / private-host / port guard before navigating.
Playwright is an optional, heavy dependency (it downloads a browser); when it is absent
this degrades cleanly to a structured "not installed" result instead of raising.

SAFETY — a screenshot is an IMAGE and CANNOT be auto-redacted the way text artifacts are.
A captured page can show the very secret the finding is about, a session cookie in view,
or another user's data. So screenshots are: OPT-IN, stored LOCALLY only, NEVER auto-
attached to an API submission, and always surfaced with a "review before you submit"
warning. Confirming the image is safe to share is the operator's call, not the tool's.

Enable:
    pip install playwright && python -m playwright install chromium
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bughunter.active_verify_service import host_in_active_scope
from bughunter.playwright_env import ensure_bundled_browsers_path
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _guard_url, playwright_request_allowed

_VIEWPORT = {"width": 1280, "height": 900}
_URL_IN_TEXT = re.compile(r"https?://\S+")
# The image is unredactable; every successful capture carries this so the UI/report can
# never present a screenshot without the caveat.
REDACTION_WARNING = "This image is NOT auto-redacted — review it for secrets, session tokens, or other users' data before attaching it to a report."

# Injected into the target page (headless, throwaway) right before capture so the screenshot
# CARRIES the finding context — a rendered page often shows nothing about the bug (a secret in
# page source, a missing header). All fields are text-escaped, so page-controlled title/evidence
# can't inject markup. position:fixed keeps the banner at the viewport top on any scroll.
_ANNOTATE_JS = r"""(a) => {
  try {
    var esc = function (s) { var d = document.createElement('div'); d.textContent = String(s == null ? '' : s); return d.innerHTML; };
    var prev = document.querySelector('[data-greyiq-evidence]'); if (prev) prev.remove();
    var b = document.createElement('div');
    b.setAttribute('data-greyiq-evidence', '1');
    b.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#0b1020;color:#e6edf3;'
      + 'font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:10px 14px;'
      + 'border-bottom:3px solid #f0a500;box-shadow:0 2px 10px rgba(0,0,0,.5);white-space:pre-wrap;word-break:break-word;';
    var lines = ['<b style="color:#f0a500">GreyIQ — proof of impact</b>'];
    if (a.title) lines.push('<b>Finding:</b> ' + esc(a.title));
    if (a.location) lines.push('<b>Location:</b> ' + esc(a.location));
    if (a.matched) lines.push('<b>Evidence:</b> ' + esc(String(a.matched).slice(0, 300)));
    b.innerHTML = lines.join('<br>');
    document.documentElement.appendChild(b);
    var h = b.offsetHeight + 8;
    if (document.body) document.body.style.paddingTop = h + 'px';
  } catch (e) {}
}"""

# Best-effort: outline + scroll to the first element whose text contains the matched value, so
# the shot points at WHERE the evidence is. Returns true when a target was highlighted.
_HIGHLIGHT_JS = r"""(needle) => {
  try {
    needle = String(needle || '').trim(); if (!needle) return false;
    var probe = needle.slice(0, 80);
    var w = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, null);
    var n;
    while ((n = w.nextNode())) {
      if (n.nodeValue && n.nodeValue.indexOf(probe) !== -1) {
        var el = n.parentElement; if (!el) continue;
        el.style.outline = '3px solid #ff3b30';
        el.style.outlineOffset = '2px';
        el.style.backgroundColor = 'rgba(255,59,48,0.18)';
        try { el.scrollIntoView({ block: 'center', inline: 'nearest' }); } catch (e) {}
        return true;
      }
    }
    return false;
  } catch (e) { return false; }
}"""


def poc_url_for_finding(finding: dict[str, Any], ctx: dict[str, Any] | None = None) -> str:
    """Best-effort proof-of-concept URL to screenshot: the captured active-probe request
    line first (it already encodes the exact crafted request), then the finding location,
    then the hunt target. Returns '' when nothing looks like an http(s) URL."""
    if isinstance(finding, dict):
        pe = finding.get("proof_evidence")
        if isinstance(pe, dict):
            match = _URL_IN_TEXT.search(str(pe.get("request_line") or ""))
            if match:
                return match.group(0).rstrip("`\"'")
        for key in ("location", "file_path"):
            val = str(finding.get(key) or "").strip()
            if val.startswith(("http://", "https://")):
                return val
    target = str((ctx or {}).get("target") or "").strip()
    return target if target.startswith(("http://", "https://")) else ""


_PROOF_BODY_CAP = 200_000  # cap the rendered source body so a huge page can't blow up the shot


def _fmt_headers(headers: Any, limit: int = 60) -> str:
    """Render a real HTTP header set as ``name: value`` lines (escaped), preserving what the
    developer/triager sees on the wire; '(none captured)' when empty."""
    items = list(headers.items())[:limit] if isinstance(headers, dict) else []
    return html.escape("\n".join(f"{k}: {v}" for k, v in items)) or "(none captured)"


def _build_proof_sheet(*, url: str, request_line: str = "", method: str = "GET",
                       req_headers: Any = None, status: int, resp_headers: Any,
                       body: str, matched: str, title: str) -> str:
    """A self-contained HTML 'proof sheet' rendered (via set_content, no navigation) and
    screenshotted as the PoC. It reproduces the REAL HTTP exchange a developer/triager sees —
    the request line + request headers actually sent, the response status + ALL response
    headers, and the raw served response body — with the matched value highlighted. That is
    where a secret-in-source / disclosure / security-header finding actually lives; a
    screenshot of the rendered page shows none of it. All fields are HTML-escaped (no
    injection, no subresources)."""
    esc = html.escape
    body_text = str(body or "")[:_PROOF_BODY_CAP]
    truncated = len(str(body or "")) > _PROOF_BODY_CAP
    body_esc = esc(body_text)
    needle = esc(str(matched or "")[:200].strip())
    if needle and needle in body_esc:
        body_esc = body_esc.replace(needle, f"<mark>{needle}</mark>")  # highlight every occurrence
    req_line = esc(request_line or f"{method or 'GET'} {url}")
    req_hdrs = _fmt_headers(req_headers)
    resp_hdrs = _fmt_headers(resp_headers)
    ev = f'<div class="sec"><span class="k">Matched evidence:</span> <mark>{needle}</mark></div>' if needle else ""
    tail = "\n\n… (truncated)" if truncated else ""
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><style>"
        "body{margin:0;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0b1020;color:#e6edf3}"
        ".hd{background:#111a2e;border-bottom:3px solid #f0a500;padding:12px 16px}"
        ".hd b{color:#f0a500}.sec{padding:9px 16px;border-bottom:1px solid #1e2a44}"
        ".k{color:#8aa0c6;font-weight:bold}mark{background:#ffd54a;color:#111;padding:0 2px;border-radius:2px}"
        "pre{white-space:pre-wrap;word-break:break-word;margin:6px 0 0}"
        "</style></head><body>"
        f'<div class="hd"><b>GreyIQ — proof of concept</b><br>{esc(title or "")}</div>'
        f'<div class="sec"><span class="k">Request:</span> {req_line}<pre>{req_hdrs}</pre></div>'
        f'<div class="sec"><span class="k">Response:</span> HTTP {int(status) if status else "?"}<pre>{resp_hdrs}</pre></div>'
        f"{ev}"
        f'<div class="sec"><span class="k">Response body (served source — the proof):</span><pre>{body_esc}{esc(tail)}</pre></div>'
        "</body></html>"
    )


def _not_installed(url: str) -> dict[str, Any]:
    return {
        "ok": False,
        "available": False,
        "url": url,
        "error": "Playwright (Python) is not installed; screenshot capture is unavailable.",
        "install": "pip install playwright && python -m playwright install chromium",
    }


def capture_screenshot(
    url: str,
    out_path: str | Path,
    *,
    scope: str = "",
    authorized: bool = False,
    settings: Any = None,
    wait_seconds: float = 3.0,
    full_page: bool = False,
    annotate: dict[str, Any] | None = None,
    highlight: str = "",
    extra_full_page: bool = False,
) -> dict[str, Any]:
    """Capture a PNG of ``url`` to ``out_path`` in a headless browser.

    Double-gated (authorized + the host named in scope), SSRF-guarded, Playwright-lazy.
    Returns ``{ok, path, shots, url, final_url, title, bytes, warning, highlighted}`` on
    success or ``{ok: False, error, ...}`` — it never raises for the common failure modes
    (not authorized, out of scope, refused by the guard, Playwright missing, navigation
    error). The capture is VIEWPORT-sized by default (focused, smaller, less incidental
    data); pass ``full_page=True`` for the whole page.

    ``annotate`` (``{title, location, matched}``) overlays a proof banner so the image
    carries the finding context even when the bug isn't visible on the rendered page (a
    secret in source, a missing header). ``highlight`` outlines + scrolls to the first
    element containing that text. ``extra_full_page`` additionally writes a whole-page shot
    beside the primary one; ``shots`` lists every image written (``path``/``kind``)."""
    settings = settings or get_settings()
    target = str(url or "").strip()
    if not target:
        return {"ok": False, "error": "No URL to screenshot."}
    if not authorized:
        return {"ok": False, "error": "Confirm you're authorized and in scope before capturing a screenshot.", "url": target}
    try:
        normalized = normalize_website_url(target)
    except WebsiteFetchError as exc:
        return {"ok": False, "error": str(exc), "url": target}
    host = urlparse(normalized).hostname or ""
    # Scope binding FIRST (fail-closed, no DNS): only a NAMED host may be driven.
    if not host_in_active_scope(host, scope, settings):
        return {"ok": False, "error": f"'{host}' is not named in your scope — screenshot skipped (fail-closed). Add it to Scope to capture.", "url": target}
    # Then the same SSRF / private-host / port guard the scanners use.
    try:
        sanitized = _guard_url(normalized, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return {"ok": False, "error": f"target refused by the URL guard: {exc}", "url": target}

    # In a frozen release, point Playwright at the Chromium we bundled before importing it.
    ensure_bundled_browsers_path()
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 - optional dependency
        return _not_installed(target)

    out = Path(out_path)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": f"could not create the output directory: {exc}", "url": target}

    def _guard_route(route: Any) -> None:
        if playwright_request_allowed(route.request.url, settings.allow_private_urls, settings.web_allowed_ports):
            route.continue_()
        else:
            route.abort()

    wait_ms = int(max(0.0, wait_seconds) * 1000)
    highlighted = False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True, viewport=_VIEWPORT)
            context.route("**/*", _guard_route)
            page = context.new_page()
            resp = page.goto(sanitized, wait_until="load", timeout=wait_ms + 15000)
            page.wait_for_timeout(wait_ms)
            final_url = page.url
            # A redirect may have left the named host; capturing an out-of-scope / private
            # page is exactly what the scope gate exists to prevent — fail closed, no file.
            final_host = urlparse(final_url).hostname or ""
            if not host_in_active_scope(final_host, scope, settings):
                browser.close()
                return {"ok": False, "error": f"navigation left scope (ended at '{final_host}') — screenshot discarded.", "url": target}
            title = page.title()
            # Grab the REAL HTTP exchange NOW, before we repaint the page for the proof sheet:
            # the request method + headers actually sent, the response status + ALL response
            # headers (all_headers gives the complete wire set, not the combined subset), and the
            # served body. This is the actual evidence a developer/triager wants for a
            # source/header/disclosure finding — the rendered page shows none of it.
            resp_status, resp_headers, resp_body = 0, {}, ""
            req_method, req_headers = "GET", {}
            if resp is not None:
                try:
                    resp_status = resp.status
                except Exception:  # noqa: BLE001
                    pass
                try:
                    resp_headers = resp.all_headers()
                except Exception:  # noqa: BLE001
                    try:
                        resp_headers = dict(resp.headers)
                    except Exception:  # noqa: BLE001
                        pass
                try:
                    req = resp.request
                    req_method = req.method
                    req_headers = req.all_headers()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    resp_body = resp.text()
                except Exception:  # noqa: BLE001 - non-text/binary response -> fall back to the DOM
                    try:
                        resp_body = page.content()
                    except Exception:  # noqa: BLE001
                        resp_body = ""
            # Point the rendered shot at the evidence too (helps when the value IS visible, e.g.
            # reflected content). Best-effort — a page-script failure must never lose the capture.
            if highlight:
                try:
                    highlighted = bool(page.evaluate(_HIGHLIGHT_JS, str(highlight)))
                except Exception:  # noqa: BLE001
                    highlighted = False
            if annotate:
                try:
                    page.evaluate(_ANNOTATE_JS, {k: ("" if v is None else str(v)) for k, v in annotate.items()})
                except Exception:  # noqa: BLE001
                    pass
            shots: list[dict[str, Any]] = []
            page.screenshot(path=str(out), full_page=full_page)
            shots.append({"path": str(out), "kind": "full-page" if full_page else "rendered"})
            if extra_full_page and not full_page:
                full_out = out.with_name(f"{out.stem}-full{out.suffix}")
                try:
                    page.screenshot(path=str(full_out), full_page=True)
                    shots.append({"path": str(full_out), "kind": "full-page"})
                except Exception:  # noqa: BLE001 - the extra shot is optional
                    pass
            # PROOF SHEET (the PoC): render the served request / response / source with the match
            # highlighted and screenshot it. Made the FIRST shot so the evidence leads. set_content
            # loads a self-contained page (no navigation, no subresources -> guard untouched).
            if resp is not None:
                source_out = out.with_name(f"{out.stem}-source{out.suffix}")
                try:
                    sheet = _build_proof_sheet(
                        url=final_url or target, request_line=str((annotate or {}).get("request_line") or ""),
                        method=req_method, req_headers=req_headers,
                        status=resp_status, resp_headers=resp_headers, body=resp_body,
                        matched=str(highlight or ""), title=str((annotate or {}).get("title") or title),
                    )
                    page.set_content(sheet, wait_until="load")
                    try:
                        page.evaluate("() => { var m = document.querySelector('mark'); if (m) m.scrollIntoView({block:'center'}); }")
                    except Exception:  # noqa: BLE001
                        pass
                    page.screenshot(path=str(source_out), full_page=True)
                    shots.insert(0, {"path": str(source_out), "kind": "source"})
                    if "<mark>" in sheet:
                        highlighted = True
                except Exception:  # noqa: BLE001 - proof sheet is best-effort; the page shots still stand
                    pass
            browser.close()
    except Exception as exc:  # noqa: BLE001 - navigation/runtime errors -> data, never raise
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "url": target}

    for shot in shots:
        try:
            shot["bytes"] = Path(shot["path"]).stat().st_size
        except OSError:
            shot["bytes"] = 0
    # The legacy top-level `path` is the PRIMARY shot — now the source proof sheet (shots[0])
    # when we produced one. Callers that predate `shots` (campaign auto-attach, the prove-flow
    # preview) read `path` directly, so this makes them embed the PoC, not the rendered page.
    primary = shots[0]["path"] if shots else str(out)
    return {
        "ok": True,
        "path": primary,
        "shots": shots,
        "url": target,
        "final_url": final_url,
        "title": title,
        "bytes": shots[0].get("bytes", 0) if shots else 0,
        "warning": REDACTION_WARNING,
        "highlighted": highlighted,
    }
