"""GreyIQ BugHunter — passive live-site security scan.

Safely fetches a single URL, reusing the hardened SSRF/URL guard from
``web_ingest`` but keeping the *raw* HTML and response headers (the readable
extractor strips scripts and headers, which is exactly where web security
signal lives). It then runs passive checks: missing/weak security headers,
software-version disclosure, mixed content, secrets leaked in inline scripts,
dangerous client-side sinks, and error/stack disclosure. Session-cookie flag
gaps are NOT findings here — they are emitted as ``attack_chain`` escalation
signals (see ``docs/attack-chains.md``).

PASSIVE means: one GET, no auth, no fuzzing, no state-changing requests. Point
it only at sites you own or are explicitly authorized to test. Private,
loopback, and reserved hosts are refused unless
``GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1``.
"""

from __future__ import annotations

import http.client
import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from bughunter import attack_chain, secret_classification
from bughunter.code_scanner.redaction import redact_text
from bughunter.code_scanner.rules import SECRET_RULES
from bughunter.rate_limit import HostRateGovernor
from bughunter.scan_auth import AuthContext, auth_headers_for, same_site
from bughunter.settings import get_settings
from bughunter.web_ingest import (
    GREYIQ_UA,
    WebsiteFetchError,
    _ascii_hostname,
    _host_is_private,
    guarded_dns_scope,
    normalize_website_url,
)

# One source of truth for the app's signature on authorized traffic (web_ingest.GREYIQ_UA, derived
# from _version). This previously hardcoded "/0.1" and had drifted six minor versions behind the app.
_USER_AGENT = GREYIQ_UA
_MAX_FINDINGS_RETURNED = 300

# The per-program required-UA machinery lives in web_ingest (the lowest-level fetcher, imported here);
# re-exported so this module and its importers (active_verify/oob/stored_xss) can build a UA carrying
# the active program's mandatory suffix without a circular import.
from bughunter.web_ingest import current_user_agent, reset_ua_suffix, set_ua_suffix  # noqa: E402,F401

# Security response headers expected on a modern site -> (severity, advice).
_EXPECTED_HEADERS: dict[str, tuple[str, str]] = {
    "content-security-policy": (
        "medium",
        "Add a Content-Security-Policy to constrain script and resource origins.",
    ),
    "x-content-type-options": (
        "low",
        "Add 'X-Content-Type-Options: nosniff' to stop MIME sniffing.",
    ),
    "x-frame-options": (
        "low",
        "Add 'X-Frame-Options: DENY' or a CSP frame-ancestors directive to prevent clickjacking.",
    ),
    "referrer-policy": (
        "low",
        "Add a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
    ),
}

_SINK_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    ("web.js-eval", r"\beval\s*\(", "Client-side eval() call", "low"),
    ("web.js-innerhtml", r"\.innerHTML\s*=", "Direct innerHTML assignment (XSS sink)", "low"),
    ("web.js-document-write", r"document\.write\s*\(", "document.write() call (XSS sink)", "low"),
    ("web.js-react-dangerous", r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML (XSS sink)", "low"),
)

_ERROR_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"(?:Fatal error|Warning|Notice):.{0,80}on line \d+", "PHP error"),
    (r"java\.lang\.[A-Za-z.]+(?:Exception|Error)", "Java exception"),
    (r"SQLSTATE\[|ORA-\d{5}|SQL syntax.{0,40}near", "SQL error"),
)

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 0.5,
    "high": 0.32,
    "medium": 0.18,
    "low": 0.06,
    "info": 0.02,
}
_SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    confidence: str,
    category: str,
    url: str,
    *,
    snippet: str = "",
    remediation: str = "",
    line_start: int = 1,
    proof_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    safe_snippet, redacted = redact_text(snippet)
    finding: dict[str, Any] = {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "file_path": url,
        "line_start": line_start,
        "line_end": line_start,
        "snippet": safe_snippet,
        "remediation": remediation,
        "redacted": redacted,
    }
    # Carry the passive proof artifacts (the exact request + offending response
    # element) so the report can prove the finding without exploitation. Every
    # value is redacted — a Set-Cookie or header can carry a token.
    if proof_evidence:
        cleaned = {
            key: redact_text(str(value))[0]
            for key, value in proof_evidence.items()
            if str(value or "").strip()
        }
        if cleaned:
            finding["proof_evidence"] = cleaned
    return finding


def _snippet(body: str, match: re.Match[str], ctx: int = 60) -> str:
    start = max(0, match.start() - ctx)
    end = min(len(body), match.end() + ctx)
    return re.sub(r"\s+", " ", body[start:end]).strip()[:200]


def _consume(response: Any, settings: Any, *, read_body: bool = True) -> dict[str, Any]:
    """Read status, headers, cookies, and a byte-capped body from a response
    or an HTTPError (so error pages are still analyzed).

    ``read_body=False`` returns status + headers WITHOUT reading the body — for a
    ``101 Switching Protocols`` WebSocket handshake, the server may hold the connection
    open after the headers, so reading the body would block until timeout. Only the
    status + ``Sec-WebSocket-Accept`` header are needed there; the body is skipped."""
    headers = {key.lower(): value for key, value in response.headers.items()}
    cookies = response.headers.get_all("Set-Cookie") or []
    if read_body:
        raw = response.read(settings.web_fetch_max_bytes + 1)
        truncated = len(raw) > settings.web_fetch_max_bytes
        raw = raw[: settings.web_fetch_max_bytes]
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            body = raw.decode(charset, errors="replace")
        except LookupError:
            body = raw.decode("utf-8", errors="replace")
    else:
        body, truncated = "", False
    status = getattr(response, "status", None) or getattr(response, "code", 0)
    return {
        "status": int(status or 0),
        "headers": headers,
        "cookies": list(cookies),
        "body": body,
        "truncated": truncated,
    }


_MAX_REDIRECTS = 5


def _guard_url(url: str, allow_private: bool, allowed_ports: frozenset[int]) -> str:
    """SSRF/policy guard: enforce scheme, reject embedded credentials, block
    private/loopback/reserved hosts (unless opted in), and restrict ports for
    public hosts. Returns the URL with an ASCII (punycoded) host so the actual
    connection target matches exactly what was validated."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise WebsiteFetchError("Only http and https URLs can be scanned.")
    if not parsed.netloc or not parsed.hostname:
        raise WebsiteFetchError("URL is missing a host.")
    if "\\" in parsed.netloc:
        raise WebsiteFetchError("URL host cannot contain backslashes.")
    if parsed.username or parsed.password:
        raise WebsiteFetchError("URLs with embedded credentials are not supported.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise WebsiteFetchError("URL contains an invalid port.") from exc

    ascii_host = _ascii_hostname(parsed.hostname)
    if _host_is_private(ascii_host) and not allow_private:
        raise WebsiteFetchError(
            "Private, local, and reserved hosts are refused. "
            "Set GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1 to scan your own local apps."
        )
    if port is not None and not allow_private and port not in allowed_ports:
        allowed = ", ".join(str(p) for p in sorted(allowed_ports))
        raise WebsiteFetchError(f"Port {port} is not allowed for public hosts. Allowed: {allowed}.")

    # An IPv6 literal -- urlparse().hostname strips the [brackets], so ascii_host is
    # bracket-less here. Without re-adding them, the rebuilt URL is malformed:
    # http.client splits host:port on the LAST colon, misreading it as an entirely
    # different, invalid host than the one just validated as public/safe.
    host_for_netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    netloc = host_for_netloc if port is None else f"{host_for_netloc}:{port}"
    return urlunparse(parsed._replace(netloc=netloc))


def playwright_request_allowed(url: str, allow_private: bool, allowed_ports: frozenset[int]) -> bool:
    """True if a Playwright page's request to ``url`` should be allowed through. Shared by
    every module that drives a real browser (screenshot_service, live_scan_service): bind
    this as a ``context.route("**/*", ...)`` handler so the SSRF/private-host/port guard is
    re-applied to EVERY request the page makes — the document navigation (including
    redirects) and every sub-resource — not just the initial URL. Without this, a redirect
    or an embedded resource could drive the browser to a private/internal host the initial
    guard already blocked (the guard would otherwise only ever see the URL passed to
    ``page.goto``). Non-http(s) schemes (data:/blob:/about:) are not network egress and are
    always allowed through; this function never raises."""
    if not url.startswith(("http://", "https://")):
        return True
    try:
        _guard_url(url, allow_private, allowed_ports)
        return True
    except WebsiteFetchError:
        return False


class _GuardedRedirect(HTTPRedirectHandler):
    """Re-validate every redirect target through the same guard so a 30x bounce
    cannot escape the policy (DNS rebinding, cross-protocol, internal hop). When an
    operator session is attached, it is ALSO stripped from the redirected request
    if the bounce leaves the same-site boundary — so a redirect to a login/SSO host
    can never carry the session off-target."""

    def __init__(self, allow_private: bool, allowed_ports: frozenset[int],
                 auth: AuthContext | None = None) -> None:
        self.allow_private = allow_private
        self.allowed_ports = allowed_ports
        self.auth = auth
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, N802
        self.count += 1
        if self.count > _MAX_REDIRECTS:
            raise WebsiteFetchError("Website redirected too many times.")
        target = _guard_url(urljoin(req.full_url, newurl), self.allow_private, self.allowed_ports)
        new = super().redirect_request(req, fp, code, msg, headers, target)
        if new is not None and self.auth is not None:
            target_host = urlparse(target).hostname or ""
            if not same_site(target_host, self.auth.host):
                # Drop the session on a cross-site bounce. Match by LOWERCASED name:
                # urllib stores header keys capitalized ("X-Api-Key" -> "X-api-key"),
                # so remove_header(original_name) would silently miss multi-word headers
                # and leak them to the redirect target.
                drop = {name.lower() for name in self.auth.headers}
                new.headers = {k: v for k, v in new.headers.items() if k.lower() not in drop}
                new.unredirected_hdrs = {k: v for k, v in new.unredirected_hdrs.items() if k.lower() not in drop}
        return new


def _fetch_raw(url: str, *, auth: AuthContext | None = None) -> dict[str, Any]:
    settings = get_settings()
    normalized = normalize_website_url(url)
    # guarded_dns_scope() covers the whole guarded fetch (initial URL through every
    # redirect hop _GuardedRedirect follows) so the DNS pin each _guard_url() call
    # installs for its hop's hostname is still in effect when the real connection to
    # that hop is made a moment later — see web_ingest.py for why this matters.
    with guarded_dns_scope():
        sanitized = _guard_url(normalized, settings.allow_private_urls, settings.web_allowed_ports)
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "User-Agent": current_user_agent(_USER_AGENT),
        }
        # Operator session attached SAME-SITE only; a cross-site redirect strips it again
        # (see _GuardedRedirect), so it never leaves the target's host.
        headers.update(auth_headers_for(urlparse(sanitized).hostname or "", auth))
        request = Request(sanitized, headers=headers, method="GET")
        opener = build_opener(_GuardedRedirect(settings.allow_private_urls, settings.web_allowed_ports, auth=auth))
        try:
            with opener.open(request, timeout=settings.web_fetch_timeout_seconds) as response:
                final_url = response.geturl()
                _guard_url(final_url, settings.allow_private_urls, settings.web_allowed_ports)
                consumed = _consume(response, settings)
        except HTTPError as error:
            # An error response is still worth analyzing (stack traces, headers). Unlike the
            # success path (a `with` block), HTTPError isn't auto-closed -- close it in
            # finally or every 404/500 leaks the underlying socket/file descriptor.
            try:
                final_url = getattr(error, "url", None) or sanitized
                # Re-validate the FINAL url too (defence-in-depth, mirrors the success path):
                # a redirect chain ending in an error response could still terminate at a
                # malformed/private host even though each hop was guarded along the way.
                _guard_url(final_url, settings.allow_private_urls, settings.web_allowed_ports)
                consumed = _consume(error, settings)
            finally:
                error.close()
        except http.client.HTTPException as exc:
            # A truncated/short-closed body (e.g. Content-Length lies, or the connection drops
            # mid-read -> http.client.IncompleteRead) is neither a URLError nor an HTTPError.
            # Re-raise as the ONE error type every caller of _fetch_raw already catches, instead
            # of letting it escape as a raw http.client exception none of them expect.
            raise WebsiteFetchError(f"the response body was truncated or malformed: {exc}") from exc
    consumed["final_url"] = final_url
    consumed["requested_url"] = normalized
    return consumed


def _analyze(fetched: dict[str, Any]) -> list[dict[str, Any]]:
    headers = fetched["headers"]
    body = fetched["body"]
    final_url = fetched["final_url"]
    is_https = final_url.lower().startswith("https://")
    # The exact passive request + response status are the proof context every
    # finding shares — the report shows them so the operator sees what produced it.
    request_line = f"GET {final_url}"
    response_status = f"HTTP {fetched.get('status')}" if fetched.get("status") else ""
    base_proof = {"request_line": request_line, "response_status": response_status}
    findings: list[dict[str, Any]] = []

    # 1. Missing security headers.
    for header, (severity, advice) in _EXPECTED_HEADERS.items():
        if header not in headers:
            findings.append(
                _finding(
                    f"web.missing-header.{header}",
                    f"Missing security header: {header}",
                    severity,
                    "high",
                    "headers",
                    final_url,
                    remediation=advice,
                    proof_evidence={**base_proof, "matched_value": f"{header} header absent from the response"},
                )
            )
    if is_https and "strict-transport-security" not in headers:
        findings.append(
            _finding(
                "web.missing-header.hsts",
                "Missing Strict-Transport-Security (HSTS)",
                "low",
                "high",
                "headers",
                final_url,
                remediation="Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains'.",
                proof_evidence={**base_proof, "matched_value": "strict-transport-security header absent from the response"},
            )
        )

    # 2. Software/version disclosure headers.
    for header in ("server", "x-powered-by"):
        value = headers.get(header, "")
        if value and re.search(r"\d", value):
            findings.append(
                _finding(
                    f"web.info-header.{header}",
                    f"{header} header discloses software/version",
                    "info",
                    "medium",
                    "disclosure",
                    final_url,
                    snippet=value[:120],
                    remediation=f"Remove or obscure the {header} response header.",
                    proof_evidence={**base_proof, "response_header": f"{header}: {value[:120]}"},
                )
            )

    # 3. Cookie flags are NOT findings. See ``attack_chain.cookie_signals``.
    #
    # A missing HttpOnly/SameSite/Secure flag describes no attacker capability on its own —
    # there is nothing to reproduce and nothing to impact. Reported standalone it is the
    # single largest source of auto-closed "informational" noise in a bounty queue, and it
    # crowds out the findings that matter. What the flag actually changes is the SEVERITY OF
    # SOMETHING ELSE: no HttpOnly is the difference between "XSS pops an alert" and "XSS takes
    # the account"; no SameSite is what makes a CSRF request arrive with the session attached;
    # no Secure only matters to a network-adjacent attacker with a reachable plaintext endpoint.
    #
    # So the flags are emitted as escalation SIGNALS and consumed by the attack-chain engine,
    # which reports them as the escalation step of a real chain — attached to the finding they
    # escalate, with that finding's proof — or not at all.

    # 4. Mixed content on an HTTPS page.
    if is_https:
        mixed = re.findall(r"""(?:src|href|action)\s*=\s*["']http://[^"']+""", body, re.IGNORECASE)
        if mixed:
            findings.append(
                _finding(
                    "web.mixed-content",
                    f"{len(mixed)} insecure http:// resource reference(s) on an HTTPS page",
                    "medium",
                    "high",
                    "mixed_content",
                    final_url,
                    snippet=mixed[0][:160],
                    remediation="Load every sub-resource over HTTPS.",
                    proof_evidence={**base_proof, "matched_value": mixed[0][:200]},
                )
            )

    # 5. Secrets leaked in the served HTML/JS (reuse the code-scanner rules).
    for rule in SECRET_RULES:
        try:
            for hit in rule.scan(path=final_url, text=body):
                findings.append(
                    _finding(
                        f"web.exposed.{hit.rule_id}",
                        f"Secret exposed in page source: {hit.title}",
                        hit.severity.value,
                        hit.confidence.value,
                        "secret_exposed",
                        final_url,
                        snippet=hit.snippet,
                        remediation="Never ship secrets to the client; rotate this credential.",
                        line_start=hit.line_start,
                        proof_evidence={**base_proof, "matched_value": hit.snippet},
                    )
                )
        except Exception:  # noqa: BLE001 - one bad rule must not abort the scan
            continue

    # 6. Dangerous client-side sinks.
    for rule_id, pattern, title, severity in _SINK_PATTERNS:
        match = re.search(pattern, body)
        if match:
            findings.append(
                _finding(
                    rule_id,
                    title,
                    severity,
                    "low",
                    "client_sink",
                    final_url,
                    snippet=_snippet(body, match),
                )
            )

    # 7. Source map exposure.
    sm_match = re.search(r"(?i)sourceMappingURL\s*=\s*\S+", body)  # match the ORIGINAL body so the excerpt keeps the real URL
    if sm_match:
        findings.append(
            _finding(
                "web.source-map-exposed",
                "Source map reference exposed (sourceMappingURL)",
                "info",
                "medium",
                "disclosure",
                final_url,
                snippet=_snippet(body, sm_match),
                remediation="Do not ship source maps to production, or restrict access to them.",
                proof_evidence={**base_proof, "matched_value": _snippet(body, sm_match)},
            )
        )

    # 8. Error / stack disclosure.
    for pattern, label in _ERROR_PATTERNS:
        match = re.search(pattern, body)
        if match:
            findings.append(
                _finding(
                    "web.error-disclosure",
                    f"Possible error/stack disclosure ({label})",
                    "low",
                    "medium",
                    "disclosure",
                    final_url,
                    snippet=_snippet(body, match),
                    proof_evidence={**base_proof, "matched_value": _snippet(body, match)},
                )
            )
            break

    return findings


def _risk(findings: list[dict[str, Any]]) -> tuple[str, float]:
    score = round(min(1.0, sum(_SEVERITY_WEIGHT.get(f["severity"], 0.0) for f in findings)), 3)
    severities = {f["severity"] for f in findings}
    if severities & {"critical", "high"} or score >= 0.5:
        return "high", score
    if "medium" in severities or score >= 0.2:
        return "moderate", score
    if findings:
        return "low", score
    return "clean", score


_RISK_ADVICE = {
    "high": "Serious web exposure detected. Review the high/critical findings before this stays live.",
    "moderate": "Hardening gaps detected. Address the medium findings to reduce attack surface.",
    "low": "Minor hardening findings only. Triage as routine.",
    "clean": "No passive web security issues detected at this depth.",
}


# A short, CONSTANT wordlist of well-known sensitive paths — never recursion or
# fuzzing, so this stays passive recon, not a scanner-evasion tool. Each entry is
# (path, severity, validator-kind); the validator content-checks the body so an SPA
# that 200s every path with its HTML shell never produces a false finding.
_SENSITIVE_PATHS = (
    ("/.git/config", "high", "git_config"),
    ("/.git/HEAD", "high", "git_head"),
    ("/.env", "high", "dotenv"),
    ("/.svn/entries", "high", "svn"),
    ("/server-status", "medium", "apache_status"),
    ("/actuator/health", "medium", "actuator"),
    ("/swagger.json", "low", "openapi"),
    ("/openapi.json", "low", "openapi"),
    ("/api-docs", "low", "openapi"),
    ("/.DS_Store", "low", "dsstore"),
)


def _sensitive_path_matches(kind: str, body: str, headers: dict[str, Any], status: int) -> bool:
    """Content-validate a candidate exposed path. NEVER flag on a 200 alone — SPAs
    return their HTML shell (200) for unknown paths, which would be all false
    positives. Each kind checks for the file's real signature."""
    head = (body or "")[:4096]
    low = head.lower()
    if "<html" in low or "<!doctype html" in low:
        return False  # an HTML shell is the SPA fallback, not the real artifact
    if kind == "git_config":
        return "[core]" in head
    if kind == "git_head":
        return head.lstrip().startswith("ref:")
    if kind == "dotenv":
        return bool(re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", head))
    if kind == "svn":
        return bool(re.match(r"^\d+\s", (body or "").lstrip())) or "svn:" in head
    if kind == "apache_status":
        return "Apache Server Status" in head
    if kind == "actuator":
        try:
            data = json.loads(body or "")
        except (ValueError, TypeError):
            return False
        return isinstance(data, dict) and "status" in data
    if kind == "openapi":
        try:
            data = json.loads(body or "")
        except (ValueError, TypeError):
            return False
        return isinstance(data, dict) and any(k in data for k in ("swagger", "openapi", "paths"))
    if kind == "dsstore":
        return "Bud1" in head
    return False


def _probe_sensitive_paths(base_url: str, governor: HostRateGovernor, *, auth: AuthContext | None = None) -> list[dict[str, Any]]:
    """Probe the small constant wordlist on the target's own origin, content-validate
    each 200, and emit a redacted disclosure finding for real hits. Same-origin,
    GET-only via _fetch_raw (so the SSRF/redirect/port guards apply identically),
    governor-throttled, and bounded — best-effort, never raises."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname or ""
    out: list[dict[str, Any]] = []
    for path, severity, kind in _SENSITIVE_PATHS:
        if not governor.throttle(host):
            break  # per-host budget exhausted -> stop (fail closed, no bursting)
        url = base + path
        try:
            fetched = _fetch_raw(url, auth=auth)
        except (WebsiteFetchError, URLError, TimeoutError, ValueError, OSError):
            continue
        if int(fetched.get("status") or 0) != 200:
            continue
        if not _sensitive_path_matches(kind, fetched.get("body") or "", fetched.get("headers") or {}, 200):
            continue
        name = re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")
        out.append(
            _finding(
                f"web.exposed-path.{name}",
                f"Sensitive path exposed: {path}",
                severity,
                "high",
                "disclosure",
                url,
                remediation=f"Block public access to {path} at the web server / reverse proxy; it should never be served.",
                proof_evidence={
                    "request_line": f"GET {url}",
                    "response_status": "HTTP 200",
                    "matched_value": (fetched.get("body") or "")[:200],
                },
            )
        )
    return out


def run_web_scan(
    url: str, max_findings: int = _MAX_FINDINGS_RETURNED, *, probe_paths: bool = False,
    auth: AuthContext | None = None,
) -> dict[str, Any]:
    """Passively scan a single URL. Returns a JSON-serializable result, or
    ``{"ok": False, "error": ...}`` on a fetch failure instead of raising.

    ``probe_paths`` adds the bounded, content-validated sensitive-path probe (used by
    the bounty engine for hunts + campaigns); the bare passive scan leaves it off so
    a quick scan stays a single GET."""
    target = str(url or "").strip()
    if not target:
        return {"ok": False, "scan_type": "web", "error": "No URL provided."}

    try:
        fetched = _fetch_raw(target, auth=auth)
    except WebsiteFetchError as exc:
        return {"ok": False, "scan_type": "web", "target": target, "error": str(exc)}
    # http.client.HTTPException (incl. IncompleteRead -> a truncated/short-closed response
    # body) and OSError (incl. ConnectionError / RemoteDisconnected -> the server dropping
    # the connection mid-read) are neither URLError nor ValueError, so they must be caught
    # explicitly here too or this "never raises" contract breaks on a truncating server.
    except (URLError, TimeoutError, ValueError, http.client.HTTPException, OSError) as exc:
        return {
            "ok": False,
            "scan_type": "web",
            "target": target,
            "error": f"{type(exc).__name__}: {exc}",
        }

    findings = _analyze(fetched)
    if probe_paths:
        # Best-effort: a probe failure must never sink the whole scan.
        try:
            settings = get_settings()
            governor = HostRateGovernor(
                capacity=len(_SENSITIVE_PATHS) + 2,
                min_interval_s=settings.active_min_interval_ms / 1000.0,
            )
            findings.extend(_probe_sensitive_paths(fetched["final_url"], governor, auth=auth))
        except Exception:  # noqa: BLE001 - probing is additive, never fatal
            pass
    # Strict secret classification for the standalone web scan too: a page-source Google/Firebase key,
    # OAuth client id, or analytics/CDN config is a PUBLIC client key by default — classified, downgraded
    # to Info, and marked not-reportable, never a scary High from a page-source match. (The hunt path does
    # this inside run_bounty_hunt; this covers the direct /api/bounty/web-scan route identically.)
    secret_classification.apply_secret_classification(findings)
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 0), reverse=True)
    risk, score = _risk(findings)
    # Sub-finding escalation clues (session-cookie flag gaps and friends). These are NOT
    # findings and deliberately do not affect risk/score — they exist so the attack-chain
    # engine can turn "XSS executes" into "XSS takes the account". Fail-open: a signal
    # error must never sink a scan that already succeeded.
    try:
        signals = attack_chain.cookie_signals(fetched.get("cookies"), fetched["final_url"])
    except Exception:  # noqa: BLE001 - advisory enrichment only
        signals = []
    return {
        "ok": True,
        "scan_type": "web",
        "target": target,
        "final_url": fetched["final_url"],
        "signals": signals,
        "status": fetched["status"],
        "risk": risk,
        "score": score,
        "recommendation": _RISK_ADVICE[risk],
        "finding_count": len(findings),
        "findings": findings[:max_findings],
        "findings_truncated": len(findings) > max_findings,
        "response_truncated": fetched["truncated"],
        "security_headers_present": sorted(
            h for h in _EXPECTED_HEADERS if h in fetched["headers"]
        ),
    }
