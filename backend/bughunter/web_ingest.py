from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import re
import socket
import threading
import time
from typing import Any, Final
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request

from _version import VERSION as _APP_VERSION
from bughunter.settings import get_settings

MAX_URL_LENGTH: Final = 2048

# --- Per-program required user-agent suffix ---
# A bug-bounty program can REQUIRE a tag appended to the User-Agent of every request it receives (so
# it can identify authorized researcher traffic — common on HackerOne/YesWeHack). The active
# program's suffix is held in a contextvar set for the duration of that program's hunt; it is
# per-context/thread, so parallel program hunts never cross-contaminate. Every hunt-path fetcher
# builds its UA via ``current_user_agent()`` so the tag rides on recon, the web scan, and the active
# prover alike. Off-target requests (credential issuers, CT logs, the HackerOne API) don't use it.
_UA_SUFFIX_VAR: contextvars.ContextVar[str] = contextvars.ContextVar("greyiq_ua_suffix", default="")

# --- Global operator (researcher) marker ---
# The per-program suffix above only exists while a saved program's hunt is running, and
# ``campaign.run_campaign`` is its ONLY setter — so an ad-hoc hunt, a re-verify, a screenshot, or a
# prover run launched outside a program carried no researcher identity at all. Most platforms ask a
# researcher to make their traffic attributable at all times ("include your handle in the UA"), so
# this is an install-wide marker (e.g. "h1-greynoc") that rides EVERY in-scope request, program or
# not. It is a plain module global rather than a contextvar on purpose: a contextvar ``.set`` on the
# main thread is invisible to the worker threads campaigns/hunts run in, so a startup-loaded default
# would silently never reach the fetchers. A str rebind is atomic under the GIL, and the value is
# operator-supplied config, never scan-derived.
_UA_MARKER: str = ""

# How many characters of an operator-supplied UA fragment survive. Shared by the program suffix and
# the global marker so neither can be used to smuggle a long/odd header value.
_UA_FRAGMENT_MAX: Final = 120

# The product+version GreyIQ identifies itself as. This is the string a program's triage team sees in
# their logs, so it is the app's signature on authorized traffic and must be accurate: until v2.7.0 it
# read "GreyNOC-Slop-Detection/0.1", which is a DIFFERENT GreyNOC tool entirely, so every in-scope
# request was misattributed. Derived from the single version source (``_version``, the same string
# stamped into delivered reports) so a release can never ship a stale marker again.
GREYIQ_UA: Final = f"GreyIQ-BugHunter/{_APP_VERSION} (+authorized-scan)"
_DEFAULT_UA: Final = GREYIQ_UA


def sanitize_ua_fragment(value: Any) -> str:
    """Strip control characters from an operator-supplied UA fragment and cap its length.

    Printable ASCII plus the space survives; everything else (CR, LF, tab, NUL, and any
    non-ASCII byte) is dropped, so a fragment can never inject a header. This is the single
    definition shared by the per-program suffix and the global researcher marker — they must
    not be able to drift apart, because either one alone would reopen header injection."""
    return "".join(c for c in str(value or "") if c == " " or 0x20 < ord(c) < 0x7f)[:_UA_FRAGMENT_MAX]


def set_ua_suffix(suffix: str) -> contextvars.Token:
    """Set the current program's required UA suffix for this context/thread; returns a restore token.
    Control chars are dropped so the suffix can never inject a CR/LF into the header.

    Appended VERBATIM (no separator is inserted): a program dictates the exact tag, including its
    own leading/trailing spacing, so GreyIQ must not reshape it."""
    return _UA_SUFFIX_VAR.set(sanitize_ua_fragment(suffix))


def reset_ua_suffix(token: contextvars.Token) -> None:
    try:
        _UA_SUFFIX_VAR.reset(token)
    except (ValueError, LookupError):  # token minted in another context — clear instead
        _UA_SUFFIX_VAR.set("")


def set_ua_marker(marker: str) -> str:
    """Set (or clear, with "") the install-wide researcher marker; returns the stored value.

    Unlike the program suffix this is process-global and thread-wide by design — it identifies the
    OPERATOR, not a program, so it must survive into every worker thread a hunt spawns. Sanitized
    with the same rules as the suffix, then trimmed: the operator types a handle, not spacing, and
    ``current_user_agent`` supplies the single separating space."""
    global _UA_MARKER
    _UA_MARKER = sanitize_ua_fragment(marker).strip()
    return _UA_MARKER


def current_ua_marker() -> str:
    """The install-wide researcher marker currently in effect ("" when unset)."""
    return _UA_MARKER


def current_user_agent(base: str = _DEFAULT_UA) -> str:
    """The UA sent on in-scope requests: base + global researcher marker + program suffix.

    The marker is space-separated (it is a token GreyIQ owns the formatting of); the program suffix
    is appended verbatim (the program owns its formatting). With neither set this is just ``base``."""
    marker = _UA_MARKER
    suffix = _UA_SUFFIX_VAR.get()
    agent = f"{base} {marker}" if marker else base
    return f"{agent}{suffix}" if suffix else agent
ALLOWED_PORTS: Final = {80, 443}
CONTROL_OR_SPACE_RE: Final = re.compile(r"[\x00-\x20\x7f]")
# A bounded retry for CONNECTION-LEVEL transient failures only (reset TCP, a DNS
# hiccup, a timeout) -- never for an HTTPError (a real server answer). See
# _connect_with_retry() below.
_MAX_FETCH_ATTEMPTS: Final = 2
_FETCH_RETRY_BACKOFF_S: Final = 0.4


class WebsiteFetchError(ValueError):
    """Raised when a website cannot be fetched or converted into text."""


def normalize_website_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        raise WebsiteFetchError("URL is required.")
    if CONTROL_OR_SPACE_RE.search(cleaned):
        raise WebsiteFetchError("URL cannot contain spaces or control characters.")
    if "\\" in cleaned:
        raise WebsiteFetchError("URL cannot contain backslashes.")
    if len(cleaned) > MAX_URL_LENGTH:
        raise WebsiteFetchError("URL is too long.")

    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    return cleaned


def _connect_with_retry(opener: Any, request: Request, timeout: float) -> Any:
    """opener.open(request), retried once for a CONNECTION-LEVEL transient failure
    (reset/timeout/DNS hiccup) only -- an HTTPError (a real server answer, e.g. a
    404/500) is never retried and propagates on the first attempt, exactly as
    before this helper existed. Retrying here (rather than wrapping the whole body-
    processing block below) keeps the retry scoped to the network connect step
    only -- a content-type/length validation failure on a successfully-connected
    response must never trigger a wasted second real request."""
    for attempt in range(1, _MAX_FETCH_ATTEMPTS + 1):
        try:
            return opener.open(request, timeout=timeout)
        except HTTPError:
            raise
        except (URLError, TimeoutError, OSError):
            if attempt >= _MAX_FETCH_ATTEMPTS:
                raise
            time.sleep(_FETCH_RETRY_BACKOFF_S * attempt)


def _enforce_url_policy(url: str, allow_private_urls: bool) -> str:
    """Validate URL safety and return a sanitized form with the host punycoded.

    Returning a sanitized URL forces every later step (request, redirect) to
    use the same hostname we just validated, removing a class of bypasses that
    rely on differences between the URL we checked and the URL we connected to.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise WebsiteFetchError("Only http and https URLs can be analyzed.")
    if not parsed.netloc or not parsed.hostname:
        raise WebsiteFetchError("URL is missing a host.")
    if "\\" in parsed.netloc:
        raise WebsiteFetchError("URL host cannot contain backslashes.")
    if parsed.username or parsed.password:
        raise WebsiteFetchError("URLs with embedded usernames or passwords are not supported.")
    if parsed.netloc.endswith(":"):
        raise WebsiteFetchError("URL contains an invalid port.")
    try:
        port = parsed.port
    except ValueError as error:
        raise WebsiteFetchError("URL contains an invalid port.") from error
    if port is not None and port not in ALLOWED_PORTS:
        raise WebsiteFetchError("Only standard website ports 80 and 443 are supported.")

    hostname = parsed.hostname
    ascii_hostname = _ascii_hostname(hostname)
    if not allow_private_urls and _host_is_private(ascii_hostname):
        raise WebsiteFetchError("Private, local, and reserved network URLs are not enabled.")

    # Rebuild netloc with the ASCII hostname so the connection target matches
    # exactly what we validated. This blocks IDN-homograph payloads from
    # silently re-resolving to a different host during the actual fetch.
    netloc = ascii_hostname
    if ":" in ascii_hostname:
        # An IPv6 literal -- urlparse().hostname strips the [brackets], so
        # ascii_hostname is bracket-less here. Without re-adding them, the
        # rebuilt URL (e.g. "http://2606:4700:4700::1111/") is malformed:
        # http.client splits host:port on the LAST colon, misreading it as
        # host="2606:4700:4700:" port=1111 -- an entirely different, invalid
        # host than the one just validated as public/safe.
        netloc = f"[{ascii_hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    sanitized = parsed._replace(netloc=netloc)
    return urlunparse(sanitized)


def _ascii_hostname(hostname: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise WebsiteFetchError("URL host is invalid or contains unsupported characters.") from error


# --- DNS-rebinding TOCTOU mitigation -------------------------------------------
# _host_is_private() resolves a hostname purely to decide pass/fail. Without this,
# the actual HTTP connection made afterwards (urllib -> http.client -> socket.
# create_connection) performs its OWN, completely independent getaddrinfo() call at
# connect time -- so an attacker's authoritative DNS server can answer with a public
# IP for the guard's lookup and a private/cloud-metadata IP moments later for the
# real connection, defeating the guard entirely (classic check-then-connect / DNS
# rebinding). Every caller here (web_ingest, web_scan_service, active_verify_service
# all share this one function) resolves through it, so pinning HERE closes the gap
# everywhere at once, with no custom socket/connection class needed in each module.
#
# Mechanism: the module installs ONE process-wide wrapper around socket.getaddrinfo.
# _host_is_private() records its OWN resolution as "the pinned answer for hostname X
# on thread N"; the wrapper serves that exact answer back to any nested getaddrinfo()
# call for the SAME hostname on the SAME thread (which is exactly what the real HTTP
# connect step performs a few lines later) instead of re-resolving DNS. Any lookup
# for a different host, or on a thread with no active pin, passes straight through
# to the real resolver untouched -- this only affects the narrow window of a single
# guarded fetch. guarded_dns_scope() wraps one logical request (all its redirect
# hops included) and guarantees the pin is cleared afterward either way.
_real_getaddrinfo = socket.getaddrinfo
_dns_pin_lock = threading.Lock()
_dns_pins: dict[int, tuple[str, list[tuple]]] = {}


def _rewrite_sockaddr_port(sockaddr: tuple, port) -> tuple | None:
    """A pin caches resolved IPs, not a specific port — _host_is_private() pins with
    port=None (it only needs the address to classify), but the real connect a moment
    later asks for the real port. Returns sockaddr with `port` substituted in, or None
    if `port` can't be coerced to an int (caller should fall back to a real lookup)."""
    try:
        new_port = int(port) if port is not None else 0
    except (TypeError, ValueError):
        return None
    if len(sockaddr) == 2:  # AF_INET: (host, port)
        return (sockaddr[0], new_port)
    if len(sockaddr) == 4:  # AF_INET6: (host, port, flowinfo, scopeid)
        return (sockaddr[0], new_port, sockaddr[2], sockaddr[3])
    return None


def _pinned_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002 - matches socket.getaddrinfo's own signature
    if isinstance(host, str):
        with _dns_pin_lock:
            pin = _dns_pins.get(threading.get_ident())
        if pin is not None and host.strip().lower() == pin[0]:
            rewritten = []
            for entry_family, entry_type, entry_proto, canonname, sockaddr in pin[1]:
                new_sockaddr = _rewrite_sockaddr_port(sockaddr, port)
                if new_sockaddr is None:
                    rewritten = None
                    break
                rewritten.append((entry_family, entry_type, entry_proto, canonname, new_sockaddr))
            if rewritten is not None:
                return rewritten
    return _real_getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = _pinned_getaddrinfo


@contextlib.contextmanager
def guarded_dns_scope():
    """Wrap ONE logical outbound request (including any redirect hops) so every
    _host_is_private() call inside it pins its resolution for the current thread —
    and the pin is always cleared afterward, success or failure. Every fetch helper
    that calls _host_is_private()/_guard_url() and then opens the connection must
    run inside this context manager for the pin to actually protect anything."""
    ident = threading.get_ident()
    try:
        yield
    finally:
        with _dns_pin_lock:
            _dns_pins.pop(ident, None)


def resolve_and_pin(hostname: str) -> list[str]:
    """Resolve ``hostname`` and PIN that exact answer for the current thread (inside a
    ``guarded_dns_scope``), so a connect that follows can't re-resolve to a different IP — closing
    the DNS-rebinding TOCTOU. Returns the resolved IP strings; raises ``WebsiteFetchError`` if the
    host can't be resolved. Used by guards that apply their OWN IP policy on the pinned addresses
    (e.g. net_probe allows RFC1918 but blocks link-local/metadata) while still getting the pin."""
    try:
        ipaddress.ip_address(hostname.strip().strip("[]"))
        return [hostname.strip().strip("[]")]  # a literal IP -> no DNS, nothing to rebind
    except ValueError:
        pass
    try:
        # The dynamic module attribute (our _pinned_getaddrinfo wrapper / a test shim), not the
        # frozen _real_getaddrinfo captured at import before any patch is installed.
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise WebsiteFetchError(f"Could not resolve host: {hostname}") from error
    with _dns_pin_lock:
        _dns_pins[threading.get_ident()] = (hostname.strip().lower(), results)
    return [str(result[4][0]).split("%")[0] for result in results]


def _host_is_private(hostname: str) -> bool:
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        addresses = [ipaddress.ip_address(ip) for ip in resolve_and_pin(hostname)]
    return any(_address_is_private(address) for address in addresses)


# RFC 6598 Carrier-Grade NAT. Python's is_private only added this in 3.13; the shipped
# runtime is 3.11, and CGNAT space routes to internal load balancers / metadata front-ends
# in many clouds, k8s node/pod networks, Tailscale, and ISP infra — exactly what the guard
# must block. Kept as an explicit network so the classification holds on every Python.
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def _address_is_private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # An IPv6 address that embeds an IPv4 one — ::ffff:a.b.c.d (mapped) or 2002:: (6to4) — is
    # only as safe as the IPv4 it points at, so unwrap and re-check. Without this the guard is
    # bypassed by expressing an internal IPv4 in IPv6 form.
    if isinstance(address, ipaddress.IPv6Address):
        embedded = address.ipv4_mapped or address.sixtofour
        if embedded is not None and _address_is_private(embedded):
            return True
    if isinstance(address, ipaddress.IPv4Address) and address in _CGNAT_NET:
        return True
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


# Backwards-compat alias for callers that imported the underscore-prefixed
# validator from the previous version.
_validate_public_url = _enforce_url_policy
