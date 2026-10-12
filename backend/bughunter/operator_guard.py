"""Fail-closed authority and request controls for unattended BugHunter cycles.

The operator grants are deliberately process-local. Restarting the application
requires the human operator to arm it again. A grant binds one saved program's
exact executable configuration, a documented authorization reference, a recently
checked policy source, an expiry, and a bounded number of cycles. It never grants
the model permission to add targets, methods, or reporting actions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import posixpath
import re
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote, unquote_plus, urlparse, urlunparse

from bughunter import portfolio
from bughunter.code_scanner.sources.git_remote import is_supported_remote_git_url
from bughunter.registrable_domain import is_bare_public_suffix
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, _ascii_hostname, normalize_website_url

MAX_GRANT_DAYS = 7
MAX_CYCLES = 100
MAX_REQUESTS_PER_CYCLE = 1000
_CHALLENGE_MARKERS = (
    "captcha", "cf-chl", "cf-mitigated", "verify you are human",
    "checking your browser", "automated traffic", "bot challenge",
)
_UNAMBIGUOUS_CHALLENGE_MARKERS = (
    "cf-chl", "verify you are human", "checking your browser", "bot challenge",
)
_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_HOST_TOKEN = re.compile(r"(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z0-9-]+", re.IGNORECASE)
_CURRENT: ContextVar[RunGuard | None] = ContextVar("greyiq_operator_guard", default=None)
_LOGIN_SUBMISSION = threading.local()
_AUDIT_LOCK = threading.Lock()
_AUDIT_FILE = "operator_authorization_audit.jsonl"
_MAX_AUDIT_BYTES = 16 * 1024 * 1024
_LEASE_FILE = "operator.lock"


class GuardHalt(RuntimeError):
    """An unattended campaign must stop before it sends another request."""


def acquire_operator_lease(runtime_dir: str) -> int:
    """Hold a runtime-wide nonblocking OS file lock until the loop exits."""
    path = Path(runtime_dir) / _LEASE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise ValueError("Another unattended operator already owns this runtime directory") from exc
    return fd


def release_operator_lease(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def audit_event(runtime_dir: str, event: str, *, grant: ProgramGrant,
                session_id: str = "", cycles_used: int = 0, requests_used: int = 0,
                stop_reason: str = "", detail: dict[str, Any] | None = None) -> None:
    """Persist a narrow, non-executable authorization trail before/after work.

    The log intentionally has no saved scope, cookies, grant object, raw response,
    or recovered credential. Process-local grants still require re-arming after
    restart. A failed write is an operational failure, never a silent success.
    """
    row: dict[str, Any] = {
        "at": datetime.now(UTC).isoformat(),
        "event": str(event)[:60],
        "session_id": str(session_id)[:80],
        "program_id": grant.program_id,
        "program_fingerprint": grant.fingerprint,
        "authorization_ref": grant.authorization_ref,
        "policy_source": grant.policy_source,
        "policy_checked_at": grant.policy_checked_at.isoformat(),
        "expires_at": grant.expires_at.isoformat(),
        "max_cycles": grant.max_cycles,
        "max_requests_per_cycle": grant.max_requests_per_cycle,
        "allow_account_access": grant.allow_account_access,
        "cycles_used": max(0, int(cycles_used)),
        "requests_used": max(0, int(requests_used)),
        "stop_reason": str(stop_reason)[:240],
    }
    if detail:
        # Callers may add only pre-sanitized, non-secret scalar evidence. Do not
        # accept arbitrary finding/response dictionaries into this durable log.
        for key in ("response_host", "response_status", "body_sha256", "sensitive_labels"):
            if key in detail:
                row[key] = detail[key]
    payload = (json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    path = Path(runtime_dir) / _AUDIT_FILE
    with _AUDIT_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size + len(payload) > _MAX_AUDIT_BYTES:
            raise OSError("operator audit limit reached; archive the local log before re-arming")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            if os.write(fd, payload) != len(payload):
                raise OSError("short operator audit write")
            os.fsync(fd)
        finally:
            os.close(fd)


def _timestamp(value: Any, field_name: str) -> datetime:
    try:
        stamp = datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp with a timezone") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return stamp.astimezone(UTC)


def _reference(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if len(text) < 4 or len(text) > 500 or any(ord(char) < 0x20 for char in text):
        raise ValueError(f"{field_name} must be a short documented reference")
    # These strings are copied into the local audit trail. Require an ordinary
    # document/ticket reference, never a credential-bearing URL or key/value.
    parsed = urlparse(text)
    if (parsed.scheme in {"http", "https"} and
            (parsed.username or parsed.password or parsed.query or parsed.fragment)):
        raise ValueError(f"{field_name} must not contain URL credentials, query, or fragment")
    if re.search(r"(?i)\b(?:token|api[_-]?key|secret|password)\s*=", text):
        raise ValueError(f"{field_name} must not contain credentials")
    from bughunter import sensitive_data

    if any(label != "email address(es)" for label in sensitive_data.classify(text)):
        raise ValueError(f"{field_name} must not contain credentials")
    return text


def _bounded_int(value: Any, field_name: str, *, default: int, maximum: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer from 1 to {maximum}")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer from 1 to {maximum}") from exc
    if not 1 <= number <= maximum:
        raise ValueError(f"{field_name} must be an integer from 1 to {maximum}")
    return number


def _web_scope_patterns(program: dict[str, Any]) -> tuple[tuple[str, bool], ...]:
    """Read only explicit host or strict ``*.`` subdomain tokens.

    URL/path/port/scheme tokens cannot be reduced to a host by an unattended
    crawler, which probes root paths and may fall back across schemes. Reject
    them instead of silently widening a path- or scheme-limited policy.
    """
    patterns: list[tuple[str, bool]] = []
    for token in re.split(r"[\s,;]+", str(program.get("scope_text") or "")):
        if not token:
            continue
        if is_supported_remote_git_url(token):
            continue  # a repository link never authorizes its forge as a web host
        if not _HOST_TOKEN.fullmatch(token):
            raise ValueError("unattended scope requires host-only tokens without scheme, path, query, or port")
        wildcard = token.startswith("*.")
        host = token[2:].lower() if wildcard else token.lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("unattended scope requires a named public host, not an IP literal")
        if is_bare_public_suffix(host):
            raise ValueError("unattended scope cannot name a shared public suffix")
        patterns.append((host, wildcard))
    return tuple(patterns)


def _host_matches_patterns(host: str, patterns: tuple[tuple[str, bool], ...]) -> bool:
    cleaned = str(host or "").strip().lower().strip("[]")
    return any((cleaned.endswith("." + base) and cleaned != base) if wildcard else cleaned == base
               for base, wildcard in patterns)


def _positive_scope_constraints(program: dict[str, Any]) -> tuple[tuple[tuple[str, bool], ...], ...]:
    """Keep saved asset lists as intersections, never broaden scope_text.

    A URL/path/port-limited imported asset cannot be represented by the host-only
    unattended crawler. Refuse it instead of treating its hostname as all paths.
    """
    groups: list[tuple[tuple[str, bool], ...]] = []
    for values in (
        program.get("in_scope_hosts") or [],
        [row.get("identifier") for row in (program.get("structured_scope") or [])
         if isinstance(row, dict) and row.get("eligible_for_submission", True)],
    ):
        tokens = [str(value).strip() for value in values if str(value or "").strip()
                  and not is_supported_remote_git_url(str(value).strip())]
        if tokens:
            patterns = _web_scope_patterns({"scope_text": " ".join(tokens)})
            if patterns:
                groups.append(patterns)
    return tuple(groups)


def _excluded_hosts(program: dict[str, Any]) -> tuple[str, ...]:
    """Union explicit exclusions with ineligible structured-scope assets.

    A hand-written scope_text prevents portfolio._normalize from deriving
    out_of_scope_hosts. Ineligible rows still narrow the unattended web grant;
    path-specific rows conservatively exclude their whole host.
    """
    hosts = [str(host) for host in (program.get("out_of_scope_hosts") or [])]
    for row in program.get("structured_scope") or []:
        if not isinstance(row, dict) or row.get("eligible_for_submission", True):
            continue
        raw = str(row.get("identifier") or "").strip()
        if not raw:
            continue
        try:
            parsed = urlparse(raw if "://" in raw else "//" + raw.lstrip("*"))
            host = (parsed.hostname or "").strip().lower()
        except ValueError:
            host = ""
        if host and "." in host:
            hosts.append(host)
    return tuple(dict.fromkeys(hosts))


def web_url_allowed(program: dict[str, Any], url: str) -> bool:
    """Require a concrete web host named by this program, ignoring env allowlists."""
    try:
        normalized = normalize_website_url(str(url or ""))
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        # A URL that names a cloneable repository is a source target, not a
        # shortcut to turn github.com/gitlab.com into a web-crawl scope.
        if is_supported_remote_git_url(normalized):
            return False
        patterns = _web_scope_patterns(program)
        if not _host_matches_patterns(parsed.hostname, patterns):
            return False
        if any(not _host_matches_patterns(parsed.hostname, group)
               for group in _positive_scope_constraints(program)):
            return False
        from bughunter.active_verify_service import host_in_active_scope
        from bughunter import vdp_policy

        profile = vdp_policy.get_profile(program.get("policy_profile"))
        if profile:
            profile_hosts = tuple((str(host).lower(), False) for host in (profile.get("scope_hosts") or ()))
            # Profiles intentionally include all subdomains of their listed
            # registered hosts; that is an additional restriction on the saved
            # program scope, never a source of new authority.
            if not any(parsed.hostname.lower() == base or parsed.hostname.lower().endswith("." + base)
                       for base, _ in profile_hosts):
                return False
            exclusions = tuple(str(part).lower() for part in (profile.get("excluded_path_substrings") or ()))
            if exclusions:
                decoded_path = parsed.path
                # A server may decode an encoded path before routing. Check
                # each representation, including normalized dot segments, and
                # reject residual encodings after a bounded decode depth.
                for _ in range(5):
                    path_view = posixpath.normpath(decoded_path.replace("\\", "/")).lower()
                    if any(part in path_view or part in decoded_path.lower() for part in exclusions):
                        return False
                    next_path = unquote(decoded_path)
                    if next_path == decoded_path:
                        break
                    decoded_path = next_path
                if re.search(r"%[0-9a-f]{2}", decoded_path, re.IGNORECASE):
                    return False

        settings = replace(
            get_settings(), active_scan_allowlist=(), allow_private_urls=False,
            excluded_hosts=_excluded_hosts(program),
        )
        return bool(host_in_active_scope(parsed.hostname, " ".join(base for base, _ in patterns), settings))
    except (ValueError, WebsiteFetchError):
        return False


def target_allowed(program: dict[str, Any], target: str) -> bool:
    """Authorize one concrete saved web or selected public-repository target."""
    raw = str(target or "").strip().rstrip("/")
    if is_supported_remote_git_url(raw):
        selected = {str(url).strip().rstrip("/") for url in (program.get("repository_urls") or [])}
        # An imported structured-scope repository may be implicitly selected by
        # portfolio._normalize only after the operator opts into cloning.
        return bool(program.get("clone_repositories") and raw in selected and not program.get("repo_draft_pending"))
    return web_url_allowed(program, raw)


def _exact_https_login_url(value: Any) -> str:
    """Canonicalize only a plain HTTPS login URL; never return credential text.

    A query, fragment, unusual port, or ambiguous path would make a broad or
    unstable POST grant. The saved URL and each attempted POST use this same
    representation, so a different action path fails closed.
    """
    raw = str(value or "").strip()
    if not raw.startswith("https://"):
        raise ValueError("saved account access requires an explicit HTTPS login URL")
    try:
        parsed = urlparse(normalize_website_url(raw))
        host = _ascii_hostname(parsed.hostname or "")
        port = parsed.port
    except (WebsiteFetchError, ValueError) as exc:
        raise ValueError("saved account login URL is invalid") from exc
    path = parsed.path or "/"
    if (not host or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.params or port not in (None, 443) or "//" in path
            or "%" in path or any(part in {".", ".."} for part in path.split("/"))):
        raise ValueError("saved account login URL must be a plain HTTPS URL without credentials, query, or fragment")
    return urlunparse(("https", host, path, "", "", ""))


def _saved_account_login_url(program: dict[str, Any]) -> str:
    account = program.get("account_access")
    if not isinstance(account, dict):
        raise ValueError("saved research account access is required")
    if not str(account.get("cookie") or "").strip() and not (
        str(account.get("email") or "").strip() and str(account.get("password") or "").strip()
    ):
        raise ValueError("saved research account needs a cookie or email and password")
    raw_login_url = str(account.get("login_url") or "").strip()
    if not raw_login_url:
        raise ValueError("saved research account needs an exact HTTPS login URL to identify the issuer")
    login_url = _exact_https_login_url(raw_login_url)
    if not web_url_allowed(program, login_url):
        raise ValueError("saved account login URL is outside the exact authorized scope")
    return login_url


@dataclass(frozen=True, slots=True)
class ProgramGrant:
    program_id: str
    fingerprint: str
    authorization_ref: str
    policy_source: str
    policy_checked_at: datetime
    expires_at: datetime
    max_cycles: int
    max_requests_per_cycle: int
    allow_account_access: bool = False
    allow_login_post: bool = False
    account_login_url: str = ""

    def current_reason(self, program: dict[str, Any] | None, *, now: datetime | None = None) -> str:
        now = now or datetime.now(UTC)
        if now >= self.expires_at:
            return "authorization expired"
        if program is None or not program.get("enabled"):
            return "program removed or disabled"
        if portfolio.execution_fingerprint(program) != self.fingerprint:
            return "program scope, policy, or testing settings changed; re-arm required"
        return ""


def create_grants(programs: list[dict[str, Any]], specs: list[dict[str, Any]] | None,
                  *, now: datetime | None = None) -> dict[str, ProgramGrant]:
    """Validate the complete enabled-program set before starting the scheduler."""
    now = now or datetime.now(UTC)
    if not isinstance(specs, list):
        raise ValueError("Provide explicit authorization grants for enabled programs")
    enabled = {str(program.get("id") or ""): program for program in programs if program.get("enabled")}
    if not enabled:
        raise ValueError("Enable at least one saved program before starting the operator")
    supplied: dict[str, dict[str, Any]] = {}
    for spec in specs:
        if not isinstance(spec, dict):
            raise ValueError("Each authorization grant must be an object")
        pid = str(spec.get("program_id") or "").strip()
        if not pid or pid in supplied or pid not in enabled:
            raise ValueError("Authorization grants must name each enabled saved program exactly once")
        supplied[pid] = spec
    if set(supplied) != set(enabled):
        missing = sorted(set(enabled) - set(supplied))
        raise ValueError("Missing authorization grants for: " + ", ".join(missing))

    grants: dict[str, ProgramGrant] = {}
    for pid, program in enabled.items():
        spec = supplied[pid]
        try:
            _web_scope_patterns(program)
            _positive_scope_constraints(program)
        except ValueError as exc:
            raise ValueError(f"{pid}: {exc}") from exc
        checked = _timestamp(spec.get("policy_checked_at"), "policy_checked_at")
        expires = _timestamp(spec.get("expires_at"), "expires_at")
        if checked > now + timedelta(minutes=5) or checked < now - timedelta(days=MAX_GRANT_DAYS):
            raise ValueError(f"{pid}: policy check must be recent (within {MAX_GRANT_DAYS} days)")
        if expires <= now or expires > now + timedelta(days=MAX_GRANT_DAYS):
            raise ValueError(f"{pid}: grant expiry must be in the next {MAX_GRANT_DAYS} days")
        if expires > checked + timedelta(days=MAX_GRANT_DAYS):
            raise ValueError(f"{pid}: grant cannot outlive the checked policy by more than {MAX_GRANT_DAYS} days")
        # The git transport runs in a subprocess and cannot observe the HTTP
        # guard's scope, stop, challenge, or cycle-budget state. Keep repository
        # scanning manual until that transport has equivalent controls.
        if program.get("clone_repositories"):
            raise ValueError(f"{pid}: repository cloning requires a manual run")
        from bughunter import campaign

        targets = campaign.program_campaign_targets(program)
        if not targets:
            raise ValueError(f"{pid}: no concrete hunt targets are configured")
        refused = [target for target in targets if not target_allowed(program, target)]
        if refused:
            raise ValueError(f"{pid}: target outside the saved scope or repository selection: {refused[0][:200]}")
        # Browser research-account login is a narrow exception to the normal
        # GET/HEAD/OPTIONS posture. Its saved credentials and exact HTTPS login
        # URL require a separate grant flag; admin accounts and ownership pairs
        # remain manual because they permit higher-impact access checks.
        if program.get("live") or program.get("deep"):
            raise ValueError(f"{pid}: live browser and deep/time-based testing require a manual run")
        if program.get("admin_account_access") or program.get("idor_pairs"):
            raise ValueError(f"{pid}: admin account sessions and IDOR pairs require a manual run")
        opt_in = spec.get("allow_account_access", False)
        if type(opt_in) is not bool:
            raise ValueError(f"{pid}: allow_account_access must be true or false")
        saved_account = bool(program.get("account_access"))
        if saved_account and not opt_in:
            raise ValueError(f"{pid}: stored account access needs allow_account_access=true; otherwise use a manual run")
        if opt_in and not saved_account:
            raise ValueError(f"{pid}: allow_account_access requires a saved research account")
        login_url = _saved_account_login_url(program) if opt_in else ""
        account = program.get("account_access") or {}
        allow_login_post = bool(opt_in and str(account.get("email") or "").strip()
                                and str(account.get("password") or "").strip())
        if opt_in:
            for target in targets:
                if urlparse(target).scheme.lower() != "https":
                    raise ValueError(f"{pid}: account access requires HTTPS seed targets")
        grants[pid] = ProgramGrant(
            program_id=pid,
            fingerprint=portfolio.execution_fingerprint(program),
            authorization_ref=_reference(spec.get("authorization_ref"), "authorization_ref"),
            policy_source=_reference(spec.get("policy_source"), "policy_source"),
            policy_checked_at=checked,
            expires_at=expires,
            max_cycles=_bounded_int(spec.get("max_cycles"), "max_cycles", default=7, maximum=MAX_CYCLES),
            max_requests_per_cycle=_bounded_int(
                spec.get("max_requests_per_cycle"), "max_requests_per_cycle", default=200,
                maximum=MAX_REQUESTS_PER_CYCLE,
            ),
            allow_account_access=opt_in,
            allow_login_post=allow_login_post,
            account_login_url=login_url,
        )
    return grants


@dataclass(slots=True)
class RunGuard:
    runtime_dir: str
    grant: ProgramGrant
    stop_event: threading.Event
    session_id: str = ""
    requests_used: int = 0
    login_posts_used: int = 0
    consecutive_403: int = 0
    halt_reason: str = ""
    research_auth: Any = field(default=None, repr=False)
    research_auth_resolved: bool = False
    research_auth_program: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def halt(self, reason: str) -> None:
        with self._lock:
            if not self.halt_reason:
                self.halt_reason = str(reason)[:240]
            message = self.halt_reason
        self.stop_event.set()
        raise GuardHalt(message)

    def check_current(self) -> dict[str, Any]:
        if self.halt_reason:
            raise GuardHalt(self.halt_reason)
        if self.stop_event.is_set():
            self.halt("operator stop requested")
        current = portfolio.get_program(self.runtime_dir, self.grant.program_id)
        reason = self.grant.current_reason(current)
        if reason:
            self.halt(reason)
        return current or {}

    def check_target(self, target: str) -> None:
        program = self.check_current()
        if not target_allowed(program, target):
            self.halt("target no longer belongs to the authorized saved scope")

    def before_request(self, url: str, *, method: str = "GET", reserve: bool = True) -> None:
        program = self.check_current()
        request_method = str(method or "").upper()
        if request_method == "GET" and self.grant.allow_login_post:
            try:
                query = urlparse(url).query
            except ValueError:
                query = ""
            if query:
                decoded = unquote_plus(unquote_plus(query))
                account = program.get("account_access") or {}
                email = str(account.get("email") or "").strip()
                password = str(account.get("password") or "").strip()
                if ((email and email.casefold() in decoded.casefold())
                        or (password and password in decoded)):
                    self.halt("saved research account credential appeared in a request URL")
        login_post = False
        if request_method not in _HTTP_METHODS:
            if (request_method == "POST" and self.grant.allow_login_post
                    and getattr(_LOGIN_SUBMISSION, "guard", None) is self):
                try:
                    login_post = _exact_https_login_url(url) == self.grant.account_login_url
                except ValueError:
                    pass
            if not login_post:
                self.halt("unattended request used a method outside GET/HEAD/OPTIONS or the exact approved login POST")
        if not web_url_allowed(program, url):
            self.halt("request or redirect left the authorized program scope")
        if reserve or login_post:
            with self._lock:
                if login_post and self.login_posts_used >= 1:
                    self.halt_reason = "saved research login POST already submitted in this cycle"
                    self.stop_event.set()
                    raise GuardHalt(self.halt_reason)
                if self.requests_used >= self.grant.max_requests_per_cycle:
                    self.halt_reason = "cycle request budget exhausted"
                    self.stop_event.set()
                    raise GuardHalt(self.halt_reason)
                if reserve:
                    self.requests_used += 1
                    if login_post:
                        self.login_posts_used += 1

    def check_saved_login_form(self, method: str, action: str) -> None:
        """Check the form before credentials are filled into an unattended browser."""
        self.check_current()
        if not self.grant.allow_login_post or str(method or "").upper() != "POST":
            self.halt("saved research login form must submit by POST")
        try:
            exact_action = _exact_https_login_url(action)
        except ValueError:
            self.halt("saved research login form action is not the exact approved HTTPS URL")
        if exact_action != self.grant.account_login_url:
            self.halt("saved research login form action is not the exact approved HTTPS URL")

    def note_sensitive_response(self, response: dict[str, Any], labels: list[str]) -> None:
        """Pause after retaining only non-secret provenance for operator review."""
        if self.halt_reason:
            return
        body = str(response.get("body") or "")
        url = str(response.get("final_url") or response.get("requested_url") or "")
        try:
            host = (urlparse(url).hostname or "")[:253]
        except ValueError:
            host = ""
        try:
            status = int(response.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        try:
            audit_event(
                self.runtime_dir, "sensitive_exposure", grant=self.grant,
                session_id=self.session_id, requests_used=self.requests_used,
                stop_reason="sensitive information exposed; operator review required",
                detail={"response_host": host, "response_status": status,
                        "body_sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
                        "sensitive_labels": labels[:8]},
            )
        except OSError as exc:
            self.halt(f"authorization audit unavailable: {exc}")
        with self._lock:
            if not self.halt_reason:
                self.halt_reason = "sensitive information exposed; operator review required"
        self.stop_event.set()

    def observe_response(self, response: dict[str, Any], *, stage: str = "complete") -> None:
        """Check headers before a body read; inspect body later without recounting 403."""
        try:
            status = int(response.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        headers = response.get("headers") or {}
        body = str(response.get("body") or "")
        text = body.lower()
        header_text = " ".join(f"{key}: {value}" for key, value in headers.items()).lower() if isinstance(headers, dict) else ""
        if stage in {"headers", "complete"}:
            if status == 401:
                self.halt("target reached an authentication boundary (HTTP 401); automated testing paused")
            if status == 429:
                self.halt("target returned HTTP 429; automated testing paused")
            if ("cf-mitigated: challenge" in header_text
                    or any(marker in header_text for marker in _UNAMBIGUOUS_CHALLENGE_MARKERS)
                    or (status in {403, 503} and any(marker in header_text for marker in _CHALLENGE_MARKERS))):
                self.halt("target presented a bot or access challenge; automated testing paused")
            with self._lock:
                self.consecutive_403 = self.consecutive_403 + 1 if status == 403 else 0
                repeated = self.consecutive_403 >= 5
            if repeated:
                self.halt("target repeatedly returned HTTP 403; automated testing paused")
        if stage in {"body", "complete"} and (
            any(marker in text for marker in _UNAMBIGUOUS_CHALLENGE_MARKERS)
            or (status in {403, 503} and any(marker in text for marker in _CHALLENGE_MARKERS))
        ):
            self.halt("target presented a bot or access challenge; automated testing paused")
        # Preserve the response-derived finding in the normal scan path, but
        # prohibit the *next* network request. Public client keys and ordinary
        # contact emails do not trigger this stop.
        if stage in {"body", "complete"} and body:
            from bughunter import sensitive_data

            labels = [label for label in sensitive_data.classify(body)
                      if label not in {"email address(es)", "a CSRF/anti-forgery token"}]
            if labels:
                self.note_sensitive_response(response, labels)


@contextmanager
def bind(guard: RunGuard) -> Iterator[None]:
    token = _CURRENT.set(guard)
    try:
        yield
    finally:
        _CURRENT.reset(token)


@contextmanager
def saved_login_submission() -> Iterator[None]:
    """Permit one exact saved-account form POST from the login service thread."""
    guard = current()
    previous = getattr(_LOGIN_SUBMISSION, "guard", None)
    _LOGIN_SUBMISSION.guard = guard
    try:
        yield
    finally:
        _LOGIN_SUBMISSION.guard = previous


def current() -> RunGuard | None:
    return _CURRENT.get()


def before_request(url: str, *, method: str = "GET", reserve: bool = True) -> None:
    guard = current()
    if guard is not None:
        guard.before_request(url, method=method, reserve=reserve)


def observe_response(response: dict[str, Any], *, stage: str = "complete") -> None:
    guard = current()
    if guard is not None:
        guard.observe_response(response, stage=stage)


def observe_playwright_response(response: Any, *, guard: RunGuard | None = None) -> None:
    """Retain a browser header stop even if Playwright swallows event exceptions."""
    guard = guard or current()
    if guard is None:
        return
    try:
        guard.observe_response({"status": response.status, "headers": response.headers}, stage="headers")
    except GuardHalt:
        pass
    except Exception:  # noqa: BLE001 - an uninspectable response is not safe to ignore
        try:
            guard.halt("unable to inspect browser response")
        except GuardHalt:
            pass


def inspect_playwright_page(page: Any, *, status: int = 0,
                            guard: RunGuard | None = None) -> None:
    """Inspect a bounded primary browser page for body-only challenges in memory."""
    guard = guard or current()
    if guard is None:
        return
    guard.check_current()
    try:
        body = page.evaluate("document.documentElement.outerHTML.slice(0, 65536)")
    except Exception:  # noqa: BLE001 - unreadable page cannot validate safe continuation
        guard.halt("unable to inspect browser page")
    guard.observe_response({"status": status, "headers": {}, "body": body}, stage="body")
    guard.check_current()
