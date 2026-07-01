"""Operator-supplied authentication for scanning behind a login.

The operator pastes a session cookie and/or auth headers; the engine attaches
them ONLY to requests whose host is *same-site* as the host the credentials were
bound to (the target host, or a subdomain of it). A request to ANY other host —
a third-party CDN, an OAuth/SSO provider reached on a redirect, or a referenced
cloud bucket (e.g. ``*.amazonaws.com`` probed by the open-bucket check) — never
receives the credentials.

That same-site boundary is the one invariant that keeps an authenticated scan
from leaking the operator's session off-target. It is deliberately strict:
exact host or proper subdomain only — never a substring or a registrable-domain
guess (which would mis-handle multi-part eTLDs like ``co.uk``).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from bughunter.web_ingest import WebsiteFetchError, _ascii_hostname

# Header names an operator may not inject — hop-by-hop / framing headers whose
# value the transport must control. Auth headers (Cookie, Authorization, X-*) are fine.
_FORBIDDEN_HEADER_NAMES = frozenset(
    {"host", "content-length", "connection", "transfer-encoding", "expect", "te", "upgrade"}
)


@dataclass(frozen=True)
class AuthContext:
    """Credentials bound to a single host. ``headers`` are sent verbatim, but only
    to same-site requests (see :func:`auth_headers_for`)."""

    host: str  # lowercased host the credentials are bound to
    headers: dict[str, str] = field(default_factory=dict)


def _host(value: str) -> str:
    return (value or "").strip().lower().strip("[]")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def same_site(request_host: str, auth_host: str) -> bool:
    """True only when ``request_host`` IS ``auth_host`` or a proper subdomain of it.

    Never a substring and never a registrable-domain guess, so a cookie bound to
    ``app.example.com`` is never sent to ``evil-example.com`` (substring) nor to a
    third-party bucket — and a cookie bound to ``example.com`` covers
    ``api.example.com`` only because that is a real subdomain. An IP-literal host on
    either side requires an EXACT match (an IP has no subdomains, and the dotted
    suffix test would otherwise treat ``5.203.0.113.5`` as "under" ``203.0.113.5``).
    """
    rh, ah = _host(request_host), _host(auth_host)
    if not rh or not ah:
        return False
    if rh == ah:
        return True
    if _is_ip(rh) or _is_ip(ah):
        return False
    return rh.endswith("." + ah)


def auth_headers_for(request_host: str, auth: AuthContext | None) -> dict[str, str]:
    """The auth headers to attach to a request to ``request_host`` — the bound
    headers if (and only if) the host is same-site as the credentials, else none."""
    if auth is None or not auth.headers:
        return {}
    return dict(auth.headers) if same_site(request_host, auth.host) else {}


def _parse_header_line(line: str) -> tuple[str, str] | None:
    if ":" not in line:
        return None
    name, _, value = line.partition(":")
    name, value = name.strip(), value.strip()
    if not name or not value or any(c in name for c in "\r\n") or any(c in value for c in "\r\n"):
        return None
    return name, value


def build_auth(target_url: str, *, cookie: str = "", headers: Any = None) -> AuthContext | None:
    """Build an :class:`AuthContext` bound to ``target_url``'s host from an operator
    cookie string and/or a list of ``"Name: value"`` header lines. Returns ``None``
    when no usable auth was supplied or the target has no host."""
    host = urlparse(str(target_url or "")).hostname or ""
    if not host:
        return None
    try:
        # Normalize to the SAME punycoded, lowercased form same_site() compares the
        # request/redirect host against (web_scan_service sanitizes via _guard_url before
        # every fetch). Without this, an IDN target binds auth to its unicode hostname
        # ('münchen.de'), the actual requests go out to the punycoded form
        # ('xn--mnchen-3ya.de'), same_site() does an exact/suffix STRING compare between
        # the two forms, and the session is silently never attached -- even to the
        # legitimate same-site target.
        host = _ascii_hostname(host)
    except WebsiteFetchError:
        pass  # an unencodable host falls back to the raw (lowercased) form below
    built: dict[str, str] = {}
    cookie = str(cookie or "").strip()
    if cookie:
        # A Cookie header is a single physical line — collapse any pasted newlines.
        built["Cookie"] = " ".join(cookie.split())
    for raw in headers or []:
        parsed = _parse_header_line(str(raw))
        if parsed and parsed[0].lower() not in _FORBIDDEN_HEADER_NAMES:
            built[parsed[0]] = parsed[1]
    if not built:
        return None
    return AuthContext(host=_host(host), headers=built)
