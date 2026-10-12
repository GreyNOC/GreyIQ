"""Authorized-research-account login for a program.

Given the operator's OWN credentials for a program's authorized research account, obtain a session
the hunt can use — by driving the program's own login page exactly as a human researcher does. This
is a BENIGN, AUTHORIZED action against the operator's own account, not an attack: the credentials are
sent ONLY to the program's own (scope-gated, SSRF-guarded) login URL, the login submit is the single
state-changing request, and the resulting session is then used read-only by the hunt.

Order of preference:
1. A pasted session cookie / auth headers (the direct path, and the fallback when auto-login can't
   drive a JS-heavy or CAPTCHA-guarded form).
2. Playwright auto-login: fill the email + password fields on the real login page, submit, and export
   the session cookies (reuses the bundled-Chromium + route scope-guard plumbing screenshot_service
   uses).

Fails CLOSED — any error, an out-of-scope/guarded login URL, or a login that yields no session
returns {ok: False, cookie: ""} and the hunt simply runs unauthenticated. The password and cookie
are NEVER logged or returned in a note.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from bughunter.active_verify_service import host_in_active_scope
from bughunter.playwright_env import ensure_bundled_browsers_path
from bughunter.scan_auth import same_registrable_site
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, current_user_agent, normalize_website_url
from bughunter.web_scan_service import _guard_url, playwright_request_allowed

# Candidate selectors for the username/email field, most-specific first. The password field is always
# input[type=password]. A benign login form on the program's own page — no scraping of anything else.
_EMAIL_SELECTORS = (
    "input[type=email]",
    "input[name*=email i]", "input[id*=email i]",
    "input[autocomplete=username]", "input[name*=user i]", "input[id*=user i]",
    "input[name*=login i]",
    "input[type=text]",  # last resort: the first free-text field
)
_SUBMIT_SELECTORS = (
    "button[type=submit]", "input[type=submit]",
    "button[name*=login i]", "button[id*=login i]", "button[id*=signin i]",
)
_NAV_WAIT_MS = 3000


def _first_selector(page: Any, selectors: tuple[str, ...]) -> str:
    """First selector that matches a visible element on the page (or '')."""
    for sel in selectors:
        try:
            el = page.query_selector(sel)
            if el is not None and el.is_visible():
                return sel
        except Exception:  # noqa: BLE001 - selector engine hiccup: try the next candidate
            continue
    return ""


def _cookie_header_for_host(cookies: list[dict[str, Any]], host: str) -> str:
    """Build a `name=value; ...` Cookie header from the cookies that apply to ``host`` (the login may
    set cookies on the apex; a leading-dot domain covers subdomains)."""
    host = (host or "").lower()
    parts: list[str] = []
    for c in cookies or []:
        raw_domain = str(c.get("domain") or "").lower()
        dom = raw_domain.lstrip(".")
        name = str(c.get("name") or "")
        if not name or not dom:
            continue
        # Playwright retains the leading dot for a domain cookie. Without it,
        # this is host-only; a sibling or child host must not inherit it. The
        # reverse suffix test previously copied child-host cookies to the login
        # host, then replayed them to scan targets.
        if host == dom or (raw_domain.startswith(".") and host.endswith("." + dom)):
            parts.append(f"{name}={c.get('value', '')}")
    return "; ".join(parts)


def _login_request_allowed(url: str, issuer_host: str, scope: str, settings: Any) -> bool:
    """Constrain every browser request, including redirects and form actions.

    The generic Playwright guard checks SSRF and ports. Login also needs the
    program's scope and the issuer's domain boundary before any credentials
    can leave the browser. Local browser-only schemes cause no network egress.
    """
    if not playwright_request_allowed(url, settings.allow_private_urls, settings.web_allowed_ports):
        return False
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return True
    request_host = parsed.hostname or ""
    return (host_in_active_scope(request_host, scope, settings)
            and same_registrable_site(request_host, issuer_host))


def _playwright_login(url: str, host: str, email: str, password: str, scope: str, settings: Any) -> dict[str, Any]:
    ensure_bundled_browsers_path()
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 - optional dependency
        return {"ok": False, "cookie": "", "headers": [], "note": "Playwright not available — paste a session cookie instead."}

    def _guard_route(route: Any) -> None:
        if _login_request_allowed(route.request.url, host, scope, settings):
            route.continue_()
        else:
            route.abort()  # no off-scope/issuer request, redirect, or form submission

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            # Carry the app signature + the program's mandatory marker (see screenshot_service).
            context = browser.new_context(ignore_https_errors=True, user_agent=current_user_agent())
            context.route("**/*", _guard_route)
            page = context.new_page()
            try:
                page.goto(url, wait_until="load", timeout=30000)
                email_sel = _first_selector(page, _EMAIL_SELECTORS)
                pw_sel = _first_selector(page, ("input[type=password]",))
                if not email_sel or not pw_sel:
                    return {"ok": False, "cookie": "", "headers": [], "note": "could not find the login form's email/password fields — paste a session cookie instead."}
                page.fill(email_sel, email)
                page.fill(pw_sel, password)
                submit_sel = _first_selector(page, _SUBMIT_SELECTORS)
                if submit_sel:
                    page.click(submit_sel)
                else:
                    page.press(pw_sel, "Enter")  # no obvious submit button — submit the form via Enter
                page.wait_for_timeout(_NAV_WAIT_MS)
                final_host = urlparse(page.url).hostname or ""
                # Re-gate after the login navigation: a login can 302 to an SSO/other host. Only accept
                # a session that ended on an in-scope host.
                if final_host and not host_in_active_scope(final_host, scope, settings):
                    return {"ok": False, "cookie": "", "headers": [], "note": f"login navigation left scope (ended at '{final_host}') — not using it."}
                cookie_str = _cookie_header_for_host(context.cookies(), host)
                still_login = page.query_selector("input[type=password]") is not None
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 - login is best-effort; never break the hunt
        return {"ok": False, "cookie": "", "headers": [], "note": f"auto-login failed ({type(exc).__name__}) — paste a session cookie instead."}

    if not cookie_str:
        return {"ok": False, "cookie": "", "headers": [], "note": "login submitted but no session cookie was set — check the credentials, or paste a cookie."}
    note = "auto-login succeeded" if not still_login else "auto-login submitted (login form still present — verify the session)"
    # ``host`` is the ISSUING host — the (in-scope, sanitized) login URL host the cookies were
    # collected for. Carried so a span reusing this session never replays it to a target on a
    # different registrable domain than the one that issued it (scan_auth.build_auth gate).
    return {"ok": True, "cookie": cookie_str, "headers": [], "host": host, "note": note}


def login(account_access: dict[str, Any] | None, scope: str, settings: Any = None) -> dict[str, Any]:
    """Resolve a program's research-account session. Returns {ok, cookie, headers, note}; fails
    closed (ok=False, empty cookie) so the caller hunts unauthenticated on any problem.

    ``account_access`` is the program record's block (email/password/login_url/cookie). A pasted
    ``cookie`` wins; otherwise email+password+login_url drives an auto-login. ``scope`` is the
    program's scope string — the login URL host must be in it."""
    settings = settings or get_settings()
    acc = account_access if isinstance(account_access, dict) else {}
    pasted = str(acc.get("cookie") or "").strip()
    if pasted:  # the direct path and the auto-login fallback
        # Best-effort ISSUING host so a pasted session reused across a multi-target span is
        # gated to its own registrable domain (scan_auth.build_auth). The paste carries no
        # host of its own, so take the configured login URL's host — but ONLY when it's IN
        # SCOPE, exactly as the auto-login path guarantees: an in-scope login page is a real
        # program host for this session, whereas an out-of-scope or third-party (SSO)
        # login_url is NOT the cookie's issuer. Off-scope/absent leaves the issuer empty, so
        # no cross-issuer gate applies and the paste binds to its target as before.
        paste_host = ""
        raw_login = str(acc.get("login_url") or "").strip()
        if raw_login:
            try:
                cand = (urlparse(normalize_website_url(raw_login)).hostname or "").lower()
            except (WebsiteFetchError, ValueError):
                cand = (urlparse(raw_login).hostname or "").lower()
            if cand and host_in_active_scope(cand, scope, settings):
                paste_host = cand
        return {"ok": True, "cookie": pasted, "headers": [], "host": paste_host,
                "note": "using the operator-provided session cookie."}
    email = str(acc.get("email") or "").strip()
    password = str(acc.get("password") or "").strip()
    login_url = str(acc.get("login_url") or "").strip()
    if not (email and password and login_url):
        return {"ok": False, "cookie": "", "headers": [], "note": "no research-account credentials configured."}
    try:
        sanitized = _guard_url(normalize_website_url(login_url), settings.allow_private_urls, settings.web_allowed_ports)
    except (WebsiteFetchError, ValueError) as exc:
        return {"ok": False, "cookie": "", "headers": [], "note": f"login URL refused by the URL guard: {exc}"}
    host = (urlparse(sanitized).hostname or "").lower()
    if not host_in_active_scope(host, scope, settings):
        # credentials must go ONLY to an authorized host — never auto-login to an out-of-scope URL
        return {"ok": False, "cookie": "", "headers": [], "note": f"login URL host '{host}' is not in this program's scope — not logging in."}
    return _playwright_login(sanitized, host, email, password, scope, settings)
