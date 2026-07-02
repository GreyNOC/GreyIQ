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
) -> dict[str, Any]:
    """Capture a PNG of ``url`` to ``out_path`` in a headless browser.

    Double-gated (authorized + the host named in scope), SSRF-guarded, Playwright-lazy.
    Returns ``{ok, path, url, final_url, title, bytes, warning}`` on success or
    ``{ok: False, error, ...}`` — it never raises for the common failure modes
    (not authorized, out of scope, refused by the guard, Playwright missing, navigation
    error). The capture is VIEWPORT-sized by default (focused, smaller, less incidental
    data); pass ``full_page=True`` for the whole page."""
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
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True, viewport=_VIEWPORT)
            context.route("**/*", _guard_route)
            page = context.new_page()
            page.goto(sanitized, wait_until="load", timeout=wait_ms + 15000)
            page.wait_for_timeout(wait_ms)
            final_url = page.url
            # A redirect may have left the named host; capturing an out-of-scope / private
            # page is exactly what the scope gate exists to prevent — fail closed, no file.
            final_host = urlparse(final_url).hostname or ""
            if not host_in_active_scope(final_host, scope, settings):
                browser.close()
                return {"ok": False, "error": f"navigation left scope (ended at '{final_host}') — screenshot discarded.", "url": target}
            title = page.title()
            page.screenshot(path=str(out), full_page=full_page)
            browser.close()
    except Exception as exc:  # noqa: BLE001 - navigation/runtime errors -> data, never raise
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "url": target}

    try:
        size = out.stat().st_size
    except OSError:
        size = 0
    return {
        "ok": True,
        "path": str(out),
        "url": target,
        "final_url": final_url,
        "title": title,
        "bytes": size,
        "warning": REDACTION_WARNING,
    }
