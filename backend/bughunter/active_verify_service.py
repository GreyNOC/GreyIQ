"""GreyIQ BugHunter — opt-in ACTIVE proof-capture verification.

The static/passive scanners produce *leads* that cap at proof status "candidate"
(a static tool can't exploit). This layer closes the loop for the subset of
classes that are provable with a single benign request: it fires at most one
crafted, **non-destructive** GET/HEAD/OPTIONS per check, captures the exact proof
artifact the impact model's ``proof_obligation`` names, validates it against a
same-run **negative control**, and returns a ``status:'confirmed'`` proof dict
(with the captured request/response) for the orchestrator to merge — so the
report renders "Confirmed" with no report.py change.

SAFETY (this is the one place a bounty tool could become a weapon):
  - Double-gated: only runs when the caller passes ``active=True`` AND the hunt is
    ``authorized=True`` AND the target is a URL. A default hunt sends ZERO crafted
    requests.
  - Scope-bound, fail-closed: only probes a host the operator NAMED in the hunt
    scope (or an env allowlist, or — for your own infra — a private host with
    GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1). Any other host is downgraded to passive-only.
  - No new egress path: every request reuses web_scan_service._guard_url + the same
    settings, so SSRF/private-host/metadata/port/IDN guards apply identically.
    Redirects are NEVER followed off-host — the first 30x Location is *captured*.
  - Methods are GET/HEAD/OPTIONS only with benign idempotent markers (a single
    quote to elicit a SQL error, an `AND '1'='1` vs `AND '1'='2` boolean differential
    that reads ONE bit and extracts no data, a `{{7*7}}` arithmetic expression to
    detect a template engine, a `<svg/onload>` reflection probe, an encoded-CRLF +
    custom-header marker to detect header injection — all inspected, never executed by
    us); never a state-changing verb/parameter, never a file-read/RCE payload, never
    fuzzing/wordlists.
  - OPT-IN time-based blind SQLi (``time_based=True``) is the one exception to the
    "never executed" rule: it injects a single FIXED, bounded ``SLEEP(4)`` (well under
    the fetch timeout, no amplification), reads ZERO data (one timing bit), excludes the
    governor throttle from its measurement, and confirms only on a stable multi-trial
    differential against a fast ``SLEEP(0)`` negative control. Off by default.
  - Open-bucket exposure only GET-probes a cloud bucket whose HOST is itself in the
    hunt scope; a referenced third-party bucket is reported as a candidate, never probed.
  - A per-host token-bucket governor + a per-hunt request budget bound the load.
  - Every captured string is redacted before it lands in a proof artifact.
  - Fail-closed proof: 'confirmed' needs a positive observation AND a control
    differential; otherwise it degrades to 'candidate'.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from bughunter.code_scanner.redaction import redact_text
from bughunter.rate_limit import HostRateGovernor
from bughunter.scan_auth import AuthContext, auth_headers_for
from bughunter.settings import get_settings
from bughunter.web_ingest import (
    WebsiteFetchError,
    _ascii_hostname,
    _host_is_private,
    normalize_website_url,
)
from bughunter.web_scan_service import (
    _ERROR_PATTERNS,
    _USER_AGENT,
    _consume,
    _guard_url,
)

# A reserved, non-resolving marker host (RFC 2606 example.* is reserved and will
# never point at a victim). Used as the off-origin target for redirect / CORS /
# host-header proofs so nothing is ever actually sent to it.
_MARKER_HOST = "greyiq-marker.example"
_MARKER_ORIGIN = f"https://{_MARKER_HOST}"
_REDIRECT_PARAMS = ("next", "returnurl", "return_url", "redirect", "redirect_uri", "redirecturl", "url", "continue", "dest", "destination", "returnto", "return_to")
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# SQL-specific error signatures only — a generic stack trace is not SQL injection.
_SQL_ERROR_RE = re.compile(
    r"SQLSTATE\[|\bORA-\d{5}\b|SQL syntax.{0,40}near|\bpsql:|PostgreSQL.{0,30}ERROR|"
    r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark|"
    r"You have an error in your SQL syntax|SQLite3?::|sqlite3.OperationalError",
    re.IGNORECASE,
)
# A stable marker token (no Math.random needed): unique enough across one host's
# response surface, deterministic for tests.
_MARK = "gq7x4q2v"


class _ActiveError(Exception):
    """Internal: a single active request failed (network/guard) — skip that check."""


class _RateLimited(Exception):
    """The per-host request budget is exhausted. Deliberately NOT an _ActiveError so
    the per-check ``except _ActiveError`` doesn't swallow it — it must propagate up to
    verify_active and stop the whole active pass (fail closed, no bursting)."""


class _NoRedirect(HTTPRedirectHandler):
    """Capture, never follow: returning None makes urllib raise HTTPError for a
    3xx so we can read the Location without an off-host hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, N802
        return None


def _registrable(host: str) -> str:
    """Best-effort eTLD+1 (last two labels). Good enough for a scope-naming check;
    the operator names example.com or the full host."""
    labels = (host or "").strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else (host or "")


def _scope_hosts(scope: str) -> set[str]:
    """Extract dotted host tokens from free-text scope, normalizing pasted URLs and
    `*.`-wildcards to bare hosts. Used for EXACT / proper-suffix matching — never a
    substring test (so 'example.com' can't match scope text 'notexample.com')."""
    hosts: set[str] = set()
    for raw in re.split(r"[\s,;]+", (scope or "").lower()):
        token = raw.strip().strip("()<>[]\"'")
        if not token:
            continue
        token = (urlparse(token).hostname or "") if "://" in token else token.split("/", 1)[0]
        token = token.lstrip("*").lstrip(".")
        if token and "." in token:  # require a dotted host, not a bare word
            hosts.add(token)
    return hosts


def host_in_active_scope(host: str, scope: str, settings: Any) -> bool:
    """Fail-closed scope binding: a host is eligible for ACTIVE probing only if the
    operator named it (its registrable domain or full host appears in the scope
    text), or it matches the env allowlist, or it's your own private/loopback infra
    with private URLs explicitly allowed."""
    cleaned = (host or "").strip().lower().strip("[]")
    if not cleaned:
        return False
    # No-DNS checks first: the operator named the host. Match host TOKENS exactly or
    # by proper dotted suffix — not a substring of the free text (which would let
    # 'example.com' match scope 'notexample.com' and probe an out-of-scope host).
    reg = _registrable(cleaned)
    for token in _scope_hosts(scope):
        if cleaned == token or cleaned.endswith("." + token) or reg == token:
            return True
    for suffix in getattr(settings, "active_scan_allowlist", ()):  # host-suffix allowlist
        if cleaned == suffix or cleaned.endswith("." + suffix):
            return True
    # Own infra: a private/loopback host is in scope only when private URLs are
    # explicitly allowed. This resolves DNS, so do it last and tolerate failure.
    if getattr(settings, "allow_private_urls", False):
        try:
            if _host_is_private(_ascii_hostname(cleaned)):
                return True
        except WebsiteFetchError:
            return False
    return False


def _with_query(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
    existing.update(params)
    return urlunparse(parsed._replace(query=urlencode(existing)))


# A valid query-parameter token (incl. PHP/Rails-style `user[id]` / `filter.name`).
# Operator- and recon-supplied param names are validated against this before they ever
# become a probe key — a malformed token is dropped rather than injected.
_PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\[\]\.]{0,39}$")
_MAX_DISCOVERED_PARAMS = 40
# Param NAMES that signal a redirect/forward target (used to pick which discovered
# params the redirect/CRLF checks bite on, without fuzzing every unrelated param).
_REDIRECT_HINTS = ("redirect", "return", "next", "dest", "continue", "callback", "forward", "goto", "url")


def _clean_param_names(names: Any) -> list[str]:
    """Sanitize + bound caller-supplied (recon/operator) param names before they become
    probe keys: keep only well-formed tokens, dedupe case-insensitively, cap the count.
    These are names DISCOVERED from the target's own JS/HTML (evidence the param exists),
    not a blind wordlist."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in names or []:
        name = str(raw or "").strip()
        if not _PARAM_NAME_RE.match(name):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
        if len(out) >= _MAX_DISCOVERED_PARAMS:
            break
    return out


def _candidate_params(url: str, extra: list[str] | None, default: tuple[str, ...], limit: int) -> list[str]:
    """Ordered, deduped parameter names a param-keyed check should probe: params already
    present in the URL FIRST (most likely live), then recon-discovered names, then a small
    built-in default — capped at ``limit`` (the SAME small per-check cap as before, so an
    already-parametered URL costs the same number of requests; only param-poor endpoints,
    which previously tested nothing, gain coverage). Pass ``default=()`` for the SQLi checks
    so a param-less endpoint with no discovered name still bails — they never invent an
    injection point."""
    out: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        clean = (name or "").strip()
        key = clean.lower()
        if clean and key not in seen:
            seen.add(key)
            out.append(clean)

    for key, _ in parse_qsl(urlparse(url).query):
        _add(key)
    for name in extra or []:
        _add(name)
    if not out:
        for name in default:
            _add(name)
    return out[:limit]


def _redirect_candidates(url: str, extra: list[str] | None, default: tuple[str, ...], limit: int) -> list[str]:
    """Redirect/CRLF candidates: redirect-NAMED params already in the URL first, then
    recon-discovered params whose NAME looks like a redirect/forward target, then the
    built-in defaults — so a custom-named redirect param the app actually uses gets tested
    without firing at every unrelated param."""
    existing = {k.lower() for k, _ in parse_qsl(urlparse(url).query)}
    out: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        clean = (name or "").strip()
        key = clean.lower()
        if clean and key not in seen:
            seen.add(key)
            out.append(clean)

    for param in _REDIRECT_PARAMS:
        if param in existing:
            _add(param)
    for name in extra or []:
        if any(hint in (name or "").lower() for hint in _REDIRECT_HINTS):
            _add(name)
    if not out:
        for name in default:
            _add(name)
    return out[:limit]


class _Http:
    """Bounded, SSRF-guarded, non-redirect-following HTTP for active checks. Two
    independent ceilings: a per-hunt request budget (``max_requests``, counted here)
    and a process-wide per-host token bucket (the governor)."""

    def __init__(self, settings: Any, governor: HostRateGovernor, max_requests: int = 12,
                 auth: AuthContext | None = None) -> None:
        self.settings = settings
        self.governor = governor
        self.max_requests = max(1, int(max_requests))
        self.auth = auth  # operator session, attached SAME-SITE only (never to a foreign bucket)
        self.sent = 0
        self.opener = build_opener(_NoRedirect())

    def fetch(self, url: str, *, method: str = "GET", extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        method = method.upper()
        if method not in _SAFE_METHODS:  # belt-and-suspenders; callers never pass others
            raise _ActiveError(f"refused non-idempotent method {method}")
        if self.sent >= self.max_requests:  # per-hunt budget, independent of the host bucket
            raise _RateLimited()
        sanitized = _guard_url(normalize_website_url(url), self.settings.allow_private_urls, self.settings.web_allowed_ports)
        host = urlparse(sanitized).hostname or ""
        if not self.governor.throttle(host):
            raise _RateLimited()
        self.sent += 1
        headers = {"User-Agent": _USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"}
        # Operator auth is attached ONLY when this request's host is same-site as the
        # bound host — so the open-bucket check's foreign-host fetch (and any other
        # off-target host) never receives the session.
        headers.update(auth_headers_for(host, self.auth))
        if extra_headers:
            headers.update(extra_headers)
        request = Request(sanitized, headers=headers, method=method)
        # Time ONLY the request (not the governor throttle above), so a time-based
        # check measures the server, not our own rate-limit sleep.
        started = time.monotonic()
        try:
            with self.opener.open(request, timeout=self.settings.web_fetch_timeout_seconds) as resp:
                consumed = _consume(resp, self.settings)
                consumed["final_url"] = resp.geturl()
                consumed["location"] = resp.headers.get("Location") if resp.headers else None
                consumed["elapsed"] = time.monotonic() - started
                return consumed
        except HTTPError as exc:
            # A 3xx (captured, not followed) or 4xx/5xx is a valid observation.
            consumed = _consume(exc, self.settings)
            consumed["final_url"] = sanitized
            consumed["location"] = exc.headers.get("Location") if exc.headers else None
            consumed["elapsed"] = time.monotonic() - started
            return consumed
        except (URLError, TimeoutError, OSError) as exc:
            raise _ActiveError(str(exc)) from exc


def _redact(value: str) -> str:
    return redact_text(str(value or ""))[0]


def _proof(status: str, **fields: Any) -> dict[str, Any]:
    base = {
        "status": status, "method": "", "actor": "unauthenticated", "affected_asset": "",
        "observed_result": "", "control_result": "", "evidence": "", "limitations": "",
    }
    base.update({k: _redact(v) if isinstance(v, str) else v for k, v in fields.items()})
    return base


def _finding(rule_id: str, title: str, severity: str, category: str, class_hint: str, url: str,
             proof: dict[str, Any], proof_evidence: dict[str, str], cvss: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "rule_id": rule_id, "title": title, "severity": severity, "confidence": "high",
        "category": category, "file_path": url, "line_start": 1, "line_end": 1,
        "snippet": _redact(proof.get("observed_result") or "")[:240],
        "remediation": "", "redacted": True,
        "proof_evidence": {k: _redact(v) for k, v in proof_evidence.items() if str(v or "").strip()},
        "_active_proof": proof,
        "_active_cvss": cvss,
        "_active_class_hint": class_hint,
    }


# ----------------------------- individual checks -----------------------------
# Each returns a finding dict (confirmed/candidate) or None. Conservative: a
# 'confirmed' status requires a positive observation AND a control differential.

def _check_cors(http: _Http, url: str) -> dict[str, Any] | None:
    try:
        probe = http.fetch(url, extra_headers={"Origin": _MARKER_ORIGIN})
        control = http.fetch(url, extra_headers={"Origin": f"https://{urlparse(url).hostname}"})
    except _ActiveError:
        return None
    acao = (probe["headers"].get("access-control-allow-origin") or "").strip()
    acac = (probe["headers"].get("access-control-allow-credentials") or "").strip().lower()
    ctrl_acao = (control["headers"].get("access-control-allow-origin") or "").strip()
    reflects_marker = acao == _MARKER_ORIGIN
    credentialed = acac == "true"
    # Confirmed: the response reflects the ATTACKER origin (not a static value/wildcard)
    # and allows credentials — a real cross-origin credentialed read. The control
    # (a different origin) reflecting differently proves it's Origin-driven.
    if reflects_marker and credentialed and ctrl_acao != acao:
        proof = _proof(
            "confirmed", method="GET with Origin: " + _MARKER_ORIGIN, affected_asset="authenticated cross-origin API responses",
            observed_result=f"Access-Control-Allow-Origin reflected the attacker origin ({acao}) with Allow-Credentials: true",
            control_result=f"a different Origin was reflected as {ctrl_acao} — reflection is attacker-controlled, not static",
            evidence=f"ACAO={acao}; ACAC={acac}",
        )
        ev = {"request_line": f"GET {url}", "request_header": f"Origin: {_MARKER_ORIGIN}",
              "response_status": f"HTTP {probe['status']}", "matched_value": f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}"}
        return _finding("active.cors-reflection", "CORS reflects attacker Origin with credentials", "high",
                        "cors", "cors", url, proof, ev)
    if reflects_marker and not credentialed:
        proof = _proof("candidate", method="GET with attacker Origin",
                       observed_result=f"ACAO reflected {acao} but Allow-Credentials was not true",
                       limitations="Without Allow-Credentials, a credentialed cross-origin read is not proven.")
        ev = {"request_line": f"GET {url}", "request_header": f"Origin: {_MARKER_ORIGIN}", "response_status": f"HTTP {probe['status']}", "matched_value": f"ACAO: {acao}"}
        return _finding("active.cors-reflection", "CORS reflects arbitrary Origin (no credentials)", "low", "cors", "cors", url, proof, ev)

    # Variant 2 — Origin: null trusted with credentials (reachable from a sandboxed
    # iframe/data-URI). Confirm only when a DIFFERENT benign Origin does NOT also yield
    # null, so 'null' is genuinely attacker-reachable, not a static value.
    try:
        null_probe = http.fetch(url, extra_headers={"Origin": "null"})
    except _ActiveError:
        null_probe = None
    if null_probe is not None:
        n_acao = (null_probe["headers"].get("access-control-allow-origin") or "").strip()
        n_acac = (null_probe["headers"].get("access-control-allow-credentials") or "").strip().lower()
        if n_acao == "null" and n_acac == "true" and ctrl_acao != "null":
            proof = _proof(
                "confirmed", method="GET with Origin: null", affected_asset="authenticated API responses (readable from a sandboxed iframe / data: URI)",
                observed_result="Access-Control-Allow-Origin: null was returned with Allow-Credentials: true",
                control_result=f"a normal Origin was reflected as {ctrl_acao or '(none)'} — 'null' is specially trusted",
                evidence=f"ACAO=null; ACAC={n_acac}",
            )
            ev = {"request_line": f"GET {url}", "request_header": "Origin: null", "response_status": f"HTTP {null_probe['status']}",
                  "matched_value": "Access-Control-Allow-Origin: null; Access-Control-Allow-Credentials: true"}
            return _finding("active.cors-reflection", "CORS trusts Origin: null with credentials", "high", "cors", "cors", url, proof, ev)

    # Variant 3 — attacker-controlled subdomain of the in-scope host reflected with
    # credentials (a takeover/XSS on any sibling subdomain then reads this API).
    host = urlparse(url).hostname or ""
    if host:
        sub_origin = f"https://{_MARK}.{host}"
        try:
            sub_probe = http.fetch(url, extra_headers={"Origin": sub_origin})
        except _ActiveError:
            sub_probe = None
        if sub_probe is not None:
            s_acao = (sub_probe["headers"].get("access-control-allow-origin") or "").strip()
            s_acac = (sub_probe["headers"].get("access-control-allow-credentials") or "").strip().lower()
            if s_acao == sub_origin and s_acac == "true" and ctrl_acao != sub_origin:
                proof = _proof(
                    "confirmed", method=f"GET with Origin: {sub_origin}", affected_asset="authenticated API responses readable from any subdomain of the target",
                    observed_result=f"an arbitrary subdomain Origin ({sub_origin}) was reflected with Allow-Credentials: true",
                    control_result=f"a different Origin was reflected as {ctrl_acao or '(none)'} — any subdomain is trusted",
                    evidence=f"ACAO={sub_origin}; ACAC={s_acac}",
                )
                ev = {"request_line": f"GET {url}", "request_header": f"Origin: {sub_origin}", "response_status": f"HTTP {sub_probe['status']}",
                      "matched_value": f"Access-Control-Allow-Origin: {sub_origin}; Access-Control-Allow-Credentials: true"}
                return _finding("active.cors-reflection", "CORS trusts arbitrary subdomain Origin with credentials", "high", "cors", "cors", url, proof, ev)
    return None


def _check_open_redirect(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    candidates = _redirect_candidates(url, extra_params, ("next", "redirect", "url"), 3)
    for param in candidates:
        try:
            probe = http.fetch(_with_query(url, {param: _MARKER_ORIGIN + "/"}))
        except _ActiveError:
            continue
        location = (probe.get("location") or "").strip()
        if not location:
            continue
        loc_host = urlparse(location if "://" in location else "http://x" + location).hostname or ""
        if loc_host == _MARKER_HOST or location.startswith(_MARKER_ORIGIN):
            try:
                control = http.fetch(_with_query(url, {param: "/greyiq-control"}))
            except _ActiveError:
                control = {"location": ""}
            ctrl_loc = (control.get("location") or "").strip()
            if _MARKER_HOST not in ctrl_loc:
                proof = _proof(
                    "confirmed", method=f"GET with {param}={_MARKER_ORIGIN}/", affected_asset="users following the link; tokens passed through the redirect",
                    observed_result=f"the server issued a {probe['status']} redirect to the external host via the '{param}' parameter (Location: {location})",
                    control_result=f"a same-origin '{param}' value redirected to {ctrl_loc or '(same origin)'} — the external host is attacker-supplied",
                    evidence=f"Location: {location}",
                )
                ev = {"request_line": f"GET {_with_query(url, {param: _MARKER_ORIGIN + '/'})}", "response_status": f"HTTP {probe['status']}", "matched_value": f"Location: {location}"}
                return _finding("active.open-redirect", f"Open redirect via '{param}' parameter", "medium", "redirect", "redirect", url, proof, ev)
    return None


def _check_clickjacking(http: _Http, url: str, fetched: dict[str, Any] | None) -> dict[str, Any] | None:
    try:
        resp = fetched or http.fetch(url)
    except _ActiveError:
        return None
    headers = resp["headers"]
    xfo = headers.get("x-frame-options")
    csp = (headers.get("content-security-policy") or "").lower()
    framable = not xfo and "frame-ancestors" not in csp
    if not framable:
        return None
    # A header inspection proves the page is FRAMABLE, but not that a working
    # clickjacking attack exists (frame-busting JS / no sensitive action). With no
    # same-run differential to capture, this is an honest 'candidate', not confirmed.
    proof = _proof(
        "candidate", method="GET (response headers inspected)", affected_asset="users of the page (UI redress / clickjacking)",
        observed_result="the response sets neither X-Frame-Options nor a CSP frame-ancestors directive, so the page is framable",
        limitations="Framability is shown from headers; a working clickjacking attack is not yet proven.",
        proof_obligation="Build a minimal HTML page that frames the target and show a sensitive action is clickable through the overlay.",
        evidence="X-Frame-Options: (absent); CSP frame-ancestors: (absent)",
    )
    ev = {"request_line": f"GET {url}", "response_status": f"HTTP {resp['status']}", "matched_value": "no X-Frame-Options, no CSP frame-ancestors"}
    return _finding("active.clickjacking", "Page is framable (clickjacking candidate)", "low", "headers", "headers", url, proof, ev)


def _check_host_header(http: _Http, url: str) -> dict[str, Any] | None:
    try:
        probe = http.fetch(url, extra_headers={"Host": _MARKER_HOST})
    except _ActiveError:
        return None
    location = (probe.get("location") or "")
    body = probe.get("body") or ""
    echoed = _MARKER_HOST in location or _MARKER_HOST in body
    if not echoed:
        return None
    try:
        control = http.fetch(url)
    except _ActiveError:
        control = {"location": "", "body": ""}
    if _MARKER_HOST in (control.get("location") or "") or _MARKER_HOST in (control.get("body") or ""):
        return None  # marker present without our header → not host-driven
    where = "Location header" if _MARKER_HOST in location else "response body"
    proof = _proof(
        "confirmed", method=f"GET with Host: {_MARKER_HOST}", affected_asset="absolute links / redirects (password-reset poisoning, cache poisoning)",
        observed_result=f"the attacker-supplied Host header was reflected into the {where}",
        control_result="the real Host did not produce the marker — the value is attacker-controlled",
        evidence=f"marker host echoed in {where}",
    )
    ev = {"request_line": f"GET {url}", "request_header": f"Host: {_MARKER_HOST}", "response_status": f"HTTP {probe['status']}", "matched_value": f"{_MARKER_HOST} in {where}"}
    return _finding("active.host-header-injection", "Host header reflected (host-header injection)", "medium", "redirect", "redirect", url, proof, ev)


def _check_reflected_xss(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    params = _candidate_params(url, extra_params, ("q",), 2)
    marker_payload = f"{_MARK}<svg/onload=1>"
    for param in params:
        try:
            probe = http.fetch(_with_query(url, {param: marker_payload}))
            control = http.fetch(_with_query(url, {param: _MARK}))
        except _ActiveError:
            continue
        body, ctrl_body = probe.get("body") or "", control.get("body") or ""
        ctype = (probe["headers"].get("content-type") or "").lower()
        html_context = (not ctype) or "html" in ctype or "xml" in ctype
        # Confirmed: the special-char payload reflects UNESCAPED (a real injection
        # point), the plain marker reflects in the control (the param is echoed, ruling
        # out a coincidental match), AND the response is HTML-renderable — a verbatim
        # reflection into application/json or text/plain is not browser-executable.
        # We INSPECT the string; nothing executes.
        if marker_payload in body and _MARK in ctrl_body and f"{_MARK}&lt;" not in body and html_context:
            proof = _proof(
                "confirmed", method=f"GET with {param}={marker_payload}", affected_asset="victim sessions/cookies and any action the victim can take",
                observed_result=f"the '{param}' parameter reflected the payload UNESCAPED into the response (the `<svg/onload>` markup was not HTML-encoded)",
                control_result=f"a plain marker reflected too, confirming '{param}' is echoed — the difference is the unescaped special characters",
                evidence="reflected payload appears raw (not entity-encoded) in the response body",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: marker_payload})}", "response_status": f"HTTP {probe['status']}", "matched_value": "unescaped reflection of <svg/onload=...>"}
            return _finding("active.reflected-xss", f"Reflected XSS via '{param}' parameter", "high", "client_sink", "xss", url, proof, ev)
    return None


def _check_ssti(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    params = _candidate_params(url, extra_params, ("q",), 2)
    probe_payload = f"{_MARK}{{{{7*7}}}}"  # marker + {{7*7}} (a benign arithmetic expression)
    control_payload = f"{_MARK}7*7"        # marker + the literal string '7*7'
    evaluated = f"{_MARK}49"               # what an engine that EVALUATES {{7*7}} emits
    for param in params:
        try:
            probe = http.fetch(_with_query(url, {param: probe_payload}))
            control = http.fetch(_with_query(url, {param: control_payload}))
        except _ActiveError:
            continue
        body, ctrl_body = probe.get("body") or "", control.get("body") or ""
        # Confirmed: the template expression {{7*7}} was EVALUATED to 49 immediately
        # after our unique marker (server-side engine execution), and the literal-
        # arithmetic control did NOT yield marker+49 (rules out a coincidental '49').
        # We only INSPECT strings; the arithmetic is evaluated by the target's own
        # engine — no file read, no code, no RCE payload.
        if evaluated in body and evaluated not in ctrl_body:
            proof = _proof(
                "confirmed", method=f"GET with {param}={probe_payload}",
                affected_asset="the server-side template/rendering context (a path to RCE on many engines)",
                observed_result=f"the '{param}' parameter's {{{{7*7}}}} expression was evaluated to 49 by the server-side template engine",
                control_result="a literal '7*7' control did NOT produce 49 — proving the engine evaluated the expression rather than echoing it",
                evidence=f"the marker immediately followed by the evaluated result ({evaluated}) appears in the response body",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: probe_payload})}", "response_status": f"HTTP {probe['status']}",
                  "matched_value": f"{{{{7*7}}}} evaluated to 49 ({evaluated})"}
            return _finding("active.ssti", f"Server-side template injection via '{param}' parameter", "high", "injection", "ssti", url, proof, ev)
    return None


def _check_error_sqli(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    parsed = urlparse(url)
    params = _candidate_params(url, extra_params, (), 2)
    if not params:
        return None  # need a URL or recon-discovered param to perturb; never invent one blindly
    for param in params:
        original = dict(parse_qsl(parsed.query)).get(param, "1")
        try:
            probe = http.fetch(_with_query(url, {param: original + "'"}))
            control = http.fetch(_with_query(url, {param: original}))
        except _ActiveError:
            continue
        body, ctrl_body = probe.get("body") or "", control.get("body") or ""
        # SQL-ONLY signature: a generic Python/PHP/Java stack trace from a broken
        # quote is NOT SQL injection. Only a real database error banner confirms.
        matched = bool(_SQL_ERROR_RE.search(body))
        ctrl_matched = bool(_SQL_ERROR_RE.search(ctrl_body))
        if matched and not ctrl_matched:
            proof = _proof(
                "confirmed", method=f"GET with {param}={original}' (a single quote)", affected_asset="the database reachable by the query's role",
                observed_result=f"appending a single quote to '{param}' produced a SQL database error in the response",
                control_result="the unmodified parameter returned no SQL error — the quote broke the query",
                evidence="a SQL error banner (SQLSTATE/ORA-/SQL syntax) surfaced after the injected quote",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: original + chr(39)})}", "response_status": f"HTTP {probe['status']}", "matched_value": f"{matched} error banner"}
            return _finding("active.sqli-error", f"SQL error elicited via '{param}' (probable SQL injection)", "high", "disclosure", "sqli", url, proof, ev)
    return None


def _norm_len(body: str) -> int:
    """Length of the body with volatile whitespace collapsed, so a stable page
    compares stably across reads (CSRF tokens / timestamps still flap — handled by
    the baseline-stability gate, not here)."""
    return len(re.sub(r"\s+", " ", body or ""))


def _check_bool_sqli(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    """Boolean-based blind SQLi, GET-only, no timing/SLEEP, no data extraction — just
    one boolean bit. Confirms ONLY when the page is stable across two baselines AND a
    TRUE tautology tracks the baseline while a FALSE contradiction diverges materially.
    The two matching baselines ARE the negative control: a page that flaps on its own
    can't be differentiated, so it degrades to candidate rather than over-claiming."""
    parsed = urlparse(url)
    params = _candidate_params(url, extra_params, (), 2)
    if not params:
        return None  # need a URL or recon-discovered param; never invent injection points
    for param in params:
        original = dict(parse_qsl(parsed.query)).get(param, "1")
        try:
            base1 = http.fetch(_with_query(url, {param: original}))
            base2 = http.fetch(_with_query(url, {param: original}))
            t_resp = http.fetch(_with_query(url, {param: original + "' AND '1'='1"}))
            f_resp = http.fetch(_with_query(url, {param: original + "' AND '1'='2"}))
        except _ActiveError:
            continue
        b1, b2 = _norm_len(base1.get("body") or ""), _norm_len(base2.get("body") or "")
        tl, fl = _norm_len(t_resp.get("body") or ""), _norm_len(f_resp.get("body") or "")
        ref = max(b1, 1)
        # Page must be STABLE (two unmodified reads near-identical) to be differentiable.
        if abs(b1 - b2) > max(8, ref * 0.02):
            continue  # dynamic page — not safely confirmable here
        true_tracks = abs(tl - b1) <= max(8, ref * 0.02)
        false_diverges = abs(fl - b1) > max(24, ref * 0.05)
        if true_tracks and false_diverges:
            proof = _proof(
                "confirmed", method=f"GET with {param}=...' AND '1'='1 vs ...' AND '1'='2",
                affected_asset="the database reachable by the query's role (boolean-inferable)",
                observed_result=f"the TRUE condition returned a page matching the stable baseline (~{b1} chars) while the FALSE condition diverged (~{fl} chars)",
                control_result=f"two unmodified requests returned near-identical pages (~{b1}/{b2} chars), so the page is stable and the TRUE/FALSE difference tracks the injected boolean",
                evidence=f"normalized lengths baseline={b1}/{b2}, TRUE={tl}, FALSE={fl}",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: original + chr(39) + ' AND ' + chr(39) + '1' + chr(39) + '=' + chr(39) + '2'})}",
                  "response_status": f"HTTP {f_resp['status']}", "matched_value": f"FALSE page diverged by {abs(fl - b1)} chars from a stable baseline"}
            return _finding("active.sqli-boolean", f"Boolean-based blind SQL injection via '{param}'", "high", "disclosure", "sqli", url, proof, ev)
    return None


def _check_crlf(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    """CRLF / response-header injection, GET-only. Injects an encoded CRLF + a benign
    custom-header marker into a param; confirms ONLY when the server SPLITS it into a
    real response header equal to the marker AND a control without the CRLF does not —
    proving the value crossed into the header block. Benign marker header only; nothing
    that affects other users' traffic (contrast request smuggling)."""
    candidates = _redirect_candidates(url, extra_params, ("next", "redirect", "url", "page"), 3)
    # RAW CR/LF — _with_query's urlencode encodes it ONCE to %0D%0A (pre-encoding here
    # would double-encode to %250D%250A and never inject a real newline).
    marker_value = f"\r\nX-Greyiq-Crlf:{_MARK}"
    for param in candidates:
        try:
            probe = http.fetch(_with_query(url, {param: marker_value}))
            control = http.fetch(_with_query(url, {param: f"X-Greyiq-Crlf-{_MARK}"}))
        except _ActiveError:
            continue
        injected = (probe["headers"].get("x-greyiq-crlf") or "").strip()
        ctrl_injected = (control["headers"].get("x-greyiq-crlf") or "").strip()
        if injected == _MARK and ctrl_injected != _MARK:
            proof = _proof(
                "confirmed", method=f"GET with {param} carrying an encoded CRLF + marker header",
                affected_asset="response headers (header injection, cache poisoning, cookie setting, XSS via header)",
                observed_result=f"the server split the '{param}' value into a real 'X-Greyiq-Crlf: {_MARK}' response header — the CRLF was honored",
                control_result="the same marker WITHOUT a CRLF did not produce the header, proving the newline was the cause",
                evidence=f"X-Greyiq-Crlf: {_MARK} present in the response headers",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: marker_value})}", "response_status": f"HTTP {probe['status']}",
                  "matched_value": f"injected response header X-Greyiq-Crlf: {_MARK}"}
            return _finding("active.crlf", f"CRLF / response-header injection via '{param}'", "high", "disclosure", "redirect", url, proof, ev)
    return None


# Time-based blind SQLi sends a small, FIXED, bounded SLEEP — the one check that emits
# an executing payload, so it is OPT-IN (off by default) and held to a strict envelope:
# a constant delay we control (no amplification), well under the fetch timeout, request-
# only timing (excludes the governor throttle), and a multi-trial differential with a
# fast SLEEP(0) negative control. No data is ever read or extracted — one timing bit.
# The delay/margin default to 4s/3s and are tunable via settings (jittery targets).
_TIME_DELAY_S = 4          # the injected sleep (fixed; < web_fetch_timeout_seconds, default 8)
_TIME_MARGIN_S = 3.0       # a confirmed probe must be at least this much slower than the fast controls


def _check_time_sqli(http: _Http, url: str, settings: Any = None, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    settings = settings or get_settings()
    parsed = urlparse(url)
    params = _candidate_params(url, extra_params, (), 1)
    if not params:
        return None  # need a URL or recon-discovered param; never invent injection points
    d = getattr(settings, "active_time_sqli_delay_seconds", _TIME_DELAY_S) or _TIME_DELAY_S
    margin = getattr(settings, "active_time_sqli_margin_seconds", _TIME_MARGIN_S) or _TIME_MARGIN_S
    # Keep the injected delay strictly under the fetch timeout so a confirmed probe never
    # trips the timeout (which would read as an error, not a delay).
    d = min(float(d), max(1.0, float(settings.web_fetch_timeout_seconds) - 1.0))
    # MySQL/MariaDB SLEEP is the most common; a single fixed payload keeps requests bounded.
    d_str = str(int(d)) if float(d).is_integer() else f"{d:.1f}"  # SLEEP(4), not SLEEP(4.0)
    slow = f"' AND SLEEP({d_str})-- -"
    fast = "' AND SLEEP(0)-- -"
    for param in params:  # one param — the timing pass is request-heavy
        original = dict(parse_qsl(parsed.query)).get(param, "1")
        try:
            base = http.fetch(_with_query(url, {param: original}))
            ctrl = http.fetch(_with_query(url, {param: original + fast}))   # injected, but SLEEP(0) -> fast (negative control)
            p1 = http.fetch(_with_query(url, {param: original + slow}))
            p2 = http.fetch(_with_query(url, {param: original + slow}))     # second trial to rule out jitter
        except _ActiveError:
            continue
        fast_max = max(float(base.get("elapsed") or 0.0), float(ctrl.get("elapsed") or 0.0))
        e1, e2 = float(p1.get("elapsed") or 0.0), float(p2.get("elapsed") or 0.0)
        # Confirm ONLY when both SLEEP(D) probes are >= D-margin slower than BOTH fast
        # controls (the unmodified baseline AND the injected-but-SLEEP(0) request). The
        # SLEEP(0) control proves the delay tracks the injected value, not a slow page.
        if e1 - fast_max >= margin and e2 - fast_max >= margin:
            proof = _proof(
                "confirmed", method=f"GET with {param}=...' AND SLEEP({d_str}) (bounded, no data read)",
                affected_asset="the database reachable by the query's role (time-inferable blind SQLi)",
                observed_result=f"injecting SLEEP({d_str}) delayed the response to ~{e1:.1f}s/{e2:.1f}s across two trials",
                control_result=f"the unmodified request and a SLEEP(0) injection both returned in ~{fast_max:.1f}s — the delay tracks the injected sleep",
                evidence=f"request-only timing: baseline/SLEEP(0)≈{fast_max:.1f}s, SLEEP({d_str})≈{e1:.1f}s and {e2:.1f}s",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: original + slow})}", "response_status": f"HTTP {p1['status']}",
                  "matched_value": f"SLEEP({d_str}) caused a ~{e1:.1f}s delay vs ~{fast_max:.1f}s control"}
            return _finding("active.sqli-time", f"Time-based blind SQL injection via '{param}'", "high", "disclosure", "sqli", url, proof, ev)
    return None


_BUCKET_RE = re.compile(
    r"https?://(?:"
    r"([a-z0-9][a-z0-9.\-]{1,200}\.s3[.\-][a-z0-9.\-]*amazonaws\.com)"          # S3 virtual-hosted
    r"|(storage\.googleapis\.com/[a-z0-9._\-]{3,200})"                            # GCS
    r"|([a-z0-9][a-z0-9.\-]{1,200}\.blob\.core\.windows\.net/[a-z0-9._\-]{1,200})"  # Azure
    r")", re.IGNORECASE)


def _check_open_bucket(http: _Http, landing: dict[str, Any] | None, scope: str, settings: Any) -> dict[str, Any] | None:
    """Open cloud-bucket exposure for buckets the PAGE references. Strictly scope-gated:
    a bucket host MUST pass host_in_active_scope (a third-party bucket is not auto-in-
    scope — those degrade to a candidate note). GET-only list endpoint; confirms only on
    an anonymous directory listing; 403/AccessDenied is the negative control -> candidate."""
    body = (landing or {}).get("body") or ""
    if not body:
        return None
    candidates: list[str] = []
    for m in _BUCKET_RE.finditer(body):
        u = m.group(0).rstrip("/\"'")
        if u not in candidates:
            candidates.append(u)
        if len(candidates) >= 8:
            break
    referenced_out_of_scope = 0
    for bucket_url in candidates[:6]:
        host = urlparse(bucket_url).hostname or ""
        if not host_in_active_scope(host, scope, settings):
            referenced_out_of_scope += 1
            continue  # never probe a bucket host the operator didn't put in scope
        list_url = bucket_url + ("?list-type=2" if "amazonaws.com" in host else "")
        try:
            resp = http.fetch(list_url)
        except (_ActiveError, WebsiteFetchError):
            # This check fetches a FOREIGN host (the bucket), so unlike the other
            # checks it can hit the SSRF/port guard (e.g. a bucket whose host resolves
            # to a private IP when private URLs are off). Skip it — never abort the pass.
            continue
        rbody = (resp.get("body") or "")[:4000]
        status = int(resp.get("status") or 0)
        # Anonymous listing (body may be truncated by the fetch cap — match the opening).
        is_listing = status == 200 and ("<ListBucketResult" in rbody and ("<Key>" in rbody or "<Contents>" in rbody))
        denied = "AccessDenied" in rbody or status in (401, 403)
        if is_listing:
            proof = _proof(
                "confirmed", method=f"GET {list_url}", affected_asset="every object in the referenced cloud bucket",
                observed_result="the bucket returned an anonymous directory listing (public read)",
                control_result="a locked bucket returns 403/AccessDenied — this one listed its contents to an unauthenticated request",
                evidence="anonymous ListBucketResult with object keys",
            )
            ev = {"request_line": f"GET {list_url}", "response_status": f"HTTP {status}", "matched_value": "public ListBucketResult (object keys redacted)"}
            return _finding("active.open-bucket", "Public cloud bucket (anonymous listing)", "high", "disclosure", "cloud-exposure", bucket_url, proof, ev)
        if denied:
            proof = _proof("candidate", method=f"GET {list_url}",
                           observed_result="the referenced bucket exists but denied anonymous listing (403/AccessDenied)",
                           limitations="The bucket is not publicly listable; individual objects or write access may still be testable.",
                           proof_obligation="Probe specific object keys / test write access within scope to assess impact.")
            ev = {"request_line": f"GET {list_url}", "response_status": f"HTTP {status}", "matched_value": "AccessDenied (bucket exists, not public)"}
            return _finding("active.open-bucket", "Cloud bucket referenced (access denied — candidate)", "low", "disclosure", "cloud-exposure", bucket_url, proof, ev)
    if referenced_out_of_scope:
        proof = _proof("candidate", method="page reference (not probed)",
                       observed_result=f"the page references {referenced_out_of_scope} cloud bucket(s) whose host is not in your scope",
                       limitations="Bucket hosts outside the program scope are never probed.",
                       proof_obligation="If the bucket is in scope, add its host to Scope and re-run to verify public access.")
        ev = {"request_line": "(page reference)", "matched_value": f"{referenced_out_of_scope} referenced bucket(s) out of scope"}
        return _finding("active.open-bucket", "Cloud bucket referenced (out of scope — add to verify)", "info", "disclosure", "cloud-exposure", "", proof, ev)
    return None


def verify_active(
    target_url: str,
    findings: list[dict[str, Any]],
    *,
    scope: str = "",
    requests_budget: int = 12,
    settings: Any = None,
    governor: HostRateGovernor | None = None,
    http: _Http | None = None,
    time_based: bool = False,
    auth: AuthContext | None = None,
    extra_params: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the active checks against an in-scope target. Returns
    ``(active_findings, meta)``. ``active_findings`` are confirmed/candidate finding
    dicts carrying a ``_active_proof`` for the orchestrator to merge; ``meta`` records
    the authorization/scope/budget outcome for the report.

    ``extra_params`` are parameter NAMES recon discovered for this host (mined from the
    target's own JS/HTML). The param-keyed checks probe URL params UNION these, so an
    endpoint that carries no query string itself still gets its real parameters tested —
    the surface recon found but the prover previously ignored."""
    settings = settings or get_settings()
    discovered_params = _clean_param_names(extra_params)
    try:
        normalized = normalize_website_url(target_url)
    except WebsiteFetchError as exc:
        return [], {"in_scope": False, "skipped_reason": str(exc), "host": "", "requests_used": 0, "rate_limited": False, "verified_classes": []}
    host = urlparse(normalized).hostname or ""

    # Scope binding FIRST (no DNS, fail-closed): an unnamed host never gets probed.
    if not host_in_active_scope(host, scope, settings):
        return [], {
            "in_scope": False, "host": host, "requests_used": 0, "rate_limited": False, "verified_classes": [],
            "skipped_reason": f"'{host}' was not named in the hunt scope, so active verification was skipped (passive only). "
                              "Name the host in Scope, set GREYIQ_ACTIVE_SCAN_ALLOWLIST, or scan your own infra with GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1.",
        }
    # Then the same SSRF/private/port guard the passive scanner uses (this resolves DNS).
    try:
        sanitized = _guard_url(normalized, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return [], {"in_scope": True, "host": host, "requests_used": 0, "rate_limited": False, "verified_classes": [], "skipped_reason": f"target refused by the URL guard: {exc}"}
    host = urlparse(sanitized).hostname or host

    governor = governor or HostRateGovernor(
        capacity=settings.active_max_requests_per_host,
        min_interval_s=settings.active_min_interval_ms / 1000.0,
    )
    http = http or _Http(settings, governor, max_requests=requests_budget, auth=auth)

    # Fetch the landing page once so header-only checks (clickjacking) reuse it.
    landing: dict[str, Any] | None = None
    rate_limited = False
    try:
        landing = http.fetch(sanitized)
    except _RateLimited:
        rate_limited = True
    except _ActiveError:
        landing = None

    results: list[dict[str, Any]] = []
    # Order: header-only first (cheap), then the request-heavier probes. Each check
    # is wrapped so a budget exhaustion stops cleanly without raising.
    checks: list[Callable[[], dict[str, Any] | None]] = [
        lambda: _check_clickjacking(http, sanitized, landing),
        lambda: _check_cors(http, sanitized),
        lambda: _check_open_redirect(http, sanitized, discovered_params),
        lambda: _check_host_header(http, sanitized),
        lambda: _check_reflected_xss(http, sanitized, discovered_params),
        lambda: _check_ssti(http, sanitized, discovered_params),
        lambda: _check_error_sqli(http, sanitized, discovered_params),
        lambda: _check_bool_sqli(http, sanitized, discovered_params),
        lambda: _check_crlf(http, sanitized, discovered_params),
        # Open-bucket is GET-only and scope-gated; safe in the default pass.
        lambda: _check_open_bucket(http, landing, scope, settings),
    ]
    # Time-based blind SQLi is the only check that emits an executing payload (a bounded
    # SLEEP), so it is OPT-IN — appended only when the operator explicitly enables it.
    if time_based:
        checks.append(lambda: _check_time_sqli(http, sanitized, settings, discovered_params))
    for check in checks:
        if rate_limited:
            break
        try:
            result = check()
        except _RateLimited:
            rate_limited = True
            break
        except _ActiveError:
            result = None
        if result:
            results.append(result)

    verified = sorted({r["_active_class_hint"] for r in results if r.get("_active_proof", {}).get("status") == "confirmed"})
    meta = {
        "in_scope": True, "host": host, "requests_used": getattr(http, "sent", 0),
        "rate_limited": rate_limited, "verified_classes": verified,
        "discovered_params_used": len(discovered_params),
        "skipped_reason": "",
    }
    return results, meta
