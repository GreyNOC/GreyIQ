from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import re
import socket
import threading
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Final
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from bughunter.settings import get_settings

TEXT_CONTENT_TYPES: Final = {
    "text/html",
    "text/plain",
    "application/xhtml+xml",
}
MAX_URL_LENGTH: Final = 2048
MAX_REDIRECTS: Final = 5
ALLOWED_PORTS: Final = {80, 443}
ALLOWED_CONTENT_ENCODINGS: Final = {"", "identity"}
CONTROL_OR_SPACE_RE: Final = re.compile(r"[\x00-\x20\x7f]")


class WebsiteFetchError(ValueError):
    """Raised when a website cannot be fetched or converted into text."""


@dataclass(frozen=True)
class FetchedWebsite:
    requested_url: str
    final_url: str
    title: str | None
    text: str
    status_code: int
    content_type: str
    byte_count: int
    redirect_count: int = 0
    redirect_chain: tuple[str, ...] = field(default_factory=tuple)
    extraction_text_length: int = 0
    content_hash: str | None = None
    meta_description: str | None = None
    open_graph_title: str | None = None
    open_graph_description: str | None = None


class SafeRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allow_private_urls: bool) -> None:
        self.allow_private_urls = allow_private_urls
        self.redirect_count = 0
        self.redirect_chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, N802
        self.redirect_count += 1
        if self.redirect_count > MAX_REDIRECTS:
            raise WebsiteFetchError("Website redirected too many times.")

        safe_url = urljoin(req.full_url, newurl)
        # Re-run full validation on every redirect target so DNS rebinding or
        # cross-protocol bounces are rejected at the same gate as the original URL.
        safe_url = _enforce_url_policy(safe_url, self.allow_private_urls)
        self.redirect_chain.append(safe_url)
        return super().redirect_request(req, fp, code, msg, headers, safe_url)


class ReadableHTMLParser(HTMLParser):
    # Tags whose text content we keep, weighted into the readable
    # extraction. Body text from these is more useful than scattered
    # nav/menu chrome.
    _CONTENT_TAGS = {
        "p", "div", "section", "article", "main", "header", "footer",
        "li", "br", "h1", "h2", "h3", "h4", "h5", "h6",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._in_title = False
        self._chunks: list[str] = []
        self._title_chunks: list[str] = []
        self.meta_description: str | None = None
        self.open_graph_title: str | None = None
        self.open_graph_description: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg", "canvas"}:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            attr_map = {key.lower(): (value or "") for key, value in attrs}
            content = attr_map.get("content", "").strip()
            if not content:
                return
            name = attr_map.get("name", "").lower()
            prop = attr_map.get("property", "").lower()
            if name == "description" and not self.meta_description:
                self.meta_description = content[:600]
            elif prop == "og:title" and not self.open_graph_title:
                self.open_graph_title = content[:240]
            elif prop == "og:description" and not self.open_graph_description:
                self.open_graph_description = content[:600]
            return
        if tag in self._CONTENT_TAGS:
            self._chunks.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg", "canvas"} and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False
        if tag in self._CONTENT_TAGS:
            self._chunks.append(" ")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self._title_chunks.append(data)
        self._chunks.append(data)

    @property
    def title(self) -> str | None:
        title = _clean_text(" ".join(self._title_chunks))
        return title or None

    @property
    def text(self) -> str:
        return _clean_text(" ".join(self._chunks))


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


def fetch_website_text(url: str) -> FetchedWebsite:
    settings = get_settings()
    normalized_url = normalize_website_url(url)

    request_headers = {
        "Accept": "text/html,text/plain,application/xhtml+xml;q=0.9,*/*;q=0.5",
        # Refuse compressed responses so a tiny gzipped payload cannot expand
        # past the configured byte cap during decoding.
        "Accept-Encoding": "identity",
        "User-Agent": "GreyNOC-Slop-Detection/0.1",
    }
    redirect_handler = SafeRedirectHandler(settings.allow_private_urls)
    opener = build_opener(redirect_handler)

    # guarded_dns_scope() covers the ENTIRE guarded fetch (initial URL through
    # every redirect hop the handler follows) so the DNS pin _enforce_url_policy
    # installs for each hop's hostname is guaranteed to still be in effect when
    # the real connection to that hop is made a moment later.
    with guarded_dns_scope():
        sanitized_url = _enforce_url_policy(normalized_url, settings.allow_private_urls)
        request = Request(sanitized_url, headers=request_headers, method="GET")
        try:
            with opener.open(request, timeout=settings.web_fetch_timeout_seconds) as response:
                final_url = response.geturl()
                # Validate the post-redirect URL one last time before consuming the
                # response body — defence in depth against any redirect we missed.
                _enforce_url_policy(final_url, settings.allow_private_urls)

                content_type = response.headers.get_content_type()
                if content_type not in TEXT_CONTENT_TYPES:
                    raise WebsiteFetchError(f"Unsupported content type: {content_type}")

                content_encoding = (response.headers.get("Content-Encoding") or "").strip().lower()
                if content_encoding and content_encoding not in ALLOWED_CONTENT_ENCODINGS:
                    raise WebsiteFetchError(
                        f"Unsupported content encoding: {content_encoding}"
                    )

                announced_length = response.headers.get("Content-Length")
                if announced_length is not None:
                    try:
                        announced = int(announced_length)
                    except ValueError as error:
                        raise WebsiteFetchError("Server returned an invalid Content-Length.") from error
                    if announced > settings.web_fetch_max_bytes:
                        raise WebsiteFetchError(
                            "Website response exceeded the configured analysis limit."
                        )

                charset = response.headers.get_content_charset() or "utf-8"
                raw = response.read(settings.web_fetch_max_bytes + 1)
                if len(raw) > settings.web_fetch_max_bytes:
                    raise WebsiteFetchError("Website response exceeded the configured analysis limit.")

                try:
                    body = raw.decode(charset, errors="replace")
                except LookupError as error:
                    # Unknown charset names land here; fall back to utf-8 to keep
                    # the analysis useful instead of aborting the whole request.
                    body = raw.decode("utf-8", errors="replace")
                    del error
                status_code = response.status
        except WebsiteFetchError:
            raise
        except HTTPError as error:
            raise WebsiteFetchError(f"Website returned HTTP {error.code}.") from error
        except URLError as error:
            reason = getattr(error, "reason", error)
            raise WebsiteFetchError(f"Could not fetch website: {reason}") from error
        except TimeoutError as error:
            raise WebsiteFetchError("Website fetch timed out.") from error

    meta_description: str | None = None
    open_graph_title: str | None = None
    open_graph_description: str | None = None
    if content_type in {"text/html", "application/xhtml+xml"}:
        parser = ReadableHTMLParser()
        parser.feed(body)
        text = parser.text
        title = parser.title
        meta_description = parser.meta_description
        open_graph_title = parser.open_graph_title
        open_graph_description = parser.open_graph_description
        # If the body text was thin and we got meaningful OG / meta
        # text, splice it into the extraction so the downstream detector
        # has more signal to work with.
        extras: list[str] = []
        if open_graph_title and open_graph_title not in text:
            extras.append(open_graph_title)
        if open_graph_description and open_graph_description not in text:
            extras.append(open_graph_description)
        if meta_description and meta_description not in text:
            extras.append(meta_description)
        if extras:
            text = (" ".join(extras) + " " + text).strip()
    else:
        text = _clean_text(body)
        title = None

    if not text:
        raise WebsiteFetchError("No readable text was found on the website.")

    return FetchedWebsite(
        requested_url=normalized_url,
        final_url=final_url,
        title=title,
        text=text,
        status_code=status_code,
        content_type=content_type,
        byte_count=len(raw),
        redirect_count=redirect_handler.redirect_count,
        redirect_chain=tuple(redirect_handler.redirect_chain),
        extraction_text_length=len(text),
        content_hash=hashlib.sha256(raw).hexdigest(),
        meta_description=meta_description,
        open_graph_title=open_graph_title,
        open_graph_description=open_graph_description,
    )


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


def _pinned_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002 - matches socket.getaddrinfo's own signature
    if isinstance(host, str):
        with _dns_pin_lock:
            pin = _dns_pins.get(threading.get_ident())
        if pin is not None and host.strip().lower() == pin[0]:
            return pin[1]
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


def _host_is_private(hostname: str) -> bool:
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            # Call socket.getaddrinfo (the dynamic module attribute, NOT the frozen
            # _real_getaddrinfo) so this still goes through whatever resolver is
            # currently installed -- our own _pinned_getaddrinfo wrapper in normal
            # operation, but also any test's own getaddrinfo monkeypatch. Calling
            # _real_getaddrinfo directly here would silently bypass such a shim,
            # since it was captured once at import time before any patch (ours or a
            # test's) is ever installed.
            results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as error:
            raise WebsiteFetchError(f"Could not resolve host: {hostname}") from error
        addresses = [ipaddress.ip_address(result[4][0]) for result in results]
        # Pin THIS exact resolution for the current thread so the real HTTP connect
        # that follows (inside the same guarded_dns_scope) is guaranteed to see the
        # identical answer instead of re-resolving DNS independently.
        with _dns_pin_lock:
            _dns_pins[threading.get_ident()] = (hostname.strip().lower(), results)

    return any(_address_is_private(address) for address in addresses)


def _address_is_private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# Backwards-compat alias for callers that imported the underscore-prefixed
# validator from the previous version.
_validate_public_url = _enforce_url_policy
