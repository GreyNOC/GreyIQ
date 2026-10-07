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

There is a second, coarser boundary for REUSED sessions. A multi-target span logs
in to a program's research account ONCE (at host ``L``) and reuses the resulting
session for every in-scope target ``T``. Binding that session to ``T`` makes
``same_site(T, T)`` trivially true, so without a further check ``L``'s token would
be replayed to targets on unrelated registrable domains. :func:`build_auth` takes
the login's ISSUING host and attaches the session to ``T`` only when ``T`` shares
the issuer's registrable domain (:func:`same_registrable_site`) — off the issuer's
domain, ``T`` is hunted unauthenticated. This issuer gate is registrable-domain
wide (a login at ``login.acme.com`` still covers sibling ``app.acme.com``) while the
same-site gate above stays strict; the two compose, and the tighter one always wins.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from bughunter.registrable_domain import is_bare_public_suffix, registrable_domain
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


def same_registrable_site(request_host: str, issuer_host: str) -> bool:
    """True when ``request_host`` may receive a session that was ISSUED at ``issuer_host`` —
    i.e. the two hosts share a registrable domain (or one is a subdomain of the other).

    This is deliberately WIDER than :func:`same_site`: a research-account login minted at
    ``login.acme.com`` legitimately covers sibling in-scope hosts like ``app.acme.com`` and
    ``api.acme.com`` (same registrable domain ``acme.com``), which are NOT subdomains of the
    login host. It stays STRICT across a registrable-domain boundary and across the
    multi-tenant shared-hosting suffixes ``registrable_domain`` knows about: a session from
    ``victim.herokuapp.com`` is never reused on ``attacker.herokuapp.com``, and a login at
    ``brand-a.com`` is never replayed to an unrelated in-scope host ``brand-b.com``. An IP
    host on either side requires an EXACT match (an IP has no registrable domain to share).
    """
    rh, ih = _host(request_host), _host(issuer_host)
    if not rh or not ih:
        return False
    # A provider/public suffix is not an issuer-owned site. The parent/child
    # short-circuit below must not allow a tenant cookie onto the provider root
    # (or from the root to every tenant).
    if is_bare_public_suffix(rh) or is_bare_public_suffix(ih):
        return False
    if same_site(rh, ih) or same_site(ih, rh):  # exact, subdomain either way, or IP-exact
        return True
    if _is_ip(rh) or _is_ip(ih):
        return False
    reg = registrable_domain(rh)
    return bool(reg) and reg == registrable_domain(ih)


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


def build_auth(target_url: str, *, cookie: str = "", headers: Any = None, issuer_host: str = "") -> AuthContext | None:
    """Build an :class:`AuthContext` bound to ``target_url``'s host from an operator
    cookie string and/or a list of ``"Name: value"`` header lines. Returns ``None``
    when no usable auth was supplied or the target has no host.

    ``issuer_host`` (optional): the host that ISSUED these credentials — e.g. the login
    URL host of a research-account session that a multi-target span logs in ONCE and reuses
    across every in-scope target. When set, the credentials are attached to ``target_url``
    ONLY if the target shares the issuer's registrable domain (see
    :func:`same_registrable_site`); off the issuer's domain this returns ``None`` and the
    target is hunted unauthenticated. Without this gate, ``same_site(T, T)`` is trivially
    true, so a session minted at host L would be re-bound to EVERY target — replaying it off
    its own issuer. Empty ``issuer_host`` = no cross-issuer gate (a single-target paste binds
    to its own target host, unchanged)."""
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
    issuer = str(issuer_host or "").strip()
    if issuer:
        try:
            issuer = _ascii_hostname(issuer)  # compare in the same punycoded form as the target host
        except WebsiteFetchError:
            pass
        if not same_registrable_site(host, issuer):
            return None  # credentials minted elsewhere: never replay off the issuer's own domain
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
