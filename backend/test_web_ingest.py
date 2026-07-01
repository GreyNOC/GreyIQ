"""Targeted tests for the SSRF / URL-safety policy (web_ingest._enforce_url_policy).

This is the single most safety-critical function in the engine — every active probe,
passive scan, recon fetch, and live scan routes through it. Tested directly with IP
LITERALS + scheme/format cases so no DNS/network is needed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import email.message  # noqa: E402
import io  # noqa: E402
import urllib.error  # noqa: E402

from bughunter.web_ingest import (  # noqa: E402
    _MAX_FETCH_ATTEMPTS,
    WebsiteFetchError,
    _connect_with_retry,
    _enforce_url_policy,
    _host_is_private,
    normalize_website_url,
)


class UrlPolicyTests(unittest.TestCase):
    def _refused(self, url: str, allow_private: bool = False) -> None:
        with self.assertRaises(WebsiteFetchError):
            _enforce_url_policy(url, allow_private)

    def test_non_http_schemes_refused(self) -> None:
        for u in ("file:///etc/passwd", "ftp://8.8.8.8/", "gopher://8.8.8.8/9", "dict://8.8.8.8/"):
            self._refused(u)

    def test_embedded_credentials_refused(self) -> None:
        self._refused("http://user:pass@8.8.8.8/")  # SSRF-via-userinfo bypass

    def test_nonstandard_ports_refused(self) -> None:
        self._refused("http://8.8.8.8:8080/")
        self._refused("http://8.8.8.8:22/")

    def test_private_reserved_and_metadata_ips_refused(self) -> None:
        # The cloud-metadata IP (169.254.169.254) and all RFC1918/loopback/link-local
        # literals must be refused when private URLs are off.
        for ip in ("127.0.0.1", "[::1]", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254"):
            self._refused(f"http://{ip}/")

    def test_public_ip_passes_and_is_sanitized(self) -> None:
        out = _enforce_url_policy("http://8.8.8.8/path", False)
        self.assertTrue(out.startswith("http://8.8.8.8"))

    def test_public_ipv6_literal_keeps_its_brackets_after_sanitizing(self) -> None:
        # Regression: the netloc rebuild used the bracket-less ascii_hostname
        # (urlparse().hostname strips [brackets] for IPv6) directly, producing a
        # malformed URL like "http://2606:4700:4700::1111/path". Re-parsing that
        # string reads a WRONG host ("2606:4700:4700:" per http.client's own
        # last-colon host:port split) than the one just validated as public --
        # every public IPv6-literal target was unscannable as a result.
        from urllib.parse import urlparse as _urlparse

        out = _enforce_url_policy("http://[2606:4700:4700::1111]/path", False)
        self.assertEqual(out, "http://[2606:4700:4700::1111]/path")
        # The sanitized URL must re-parse back to the SAME hostname that was
        # actually validated -- the whole point of returning a sanitized URL.
        self.assertEqual(_urlparse(out).hostname, "2606:4700:4700::1111")

    def test_public_ipv6_literal_with_explicit_port_stays_well_formed(self) -> None:
        from urllib.parse import urlparse as _urlparse

        out = _enforce_url_policy("http://[2606:4700:4700::1111]:80/path", False)
        self.assertEqual(_urlparse(out).hostname, "2606:4700:4700::1111")
        self.assertEqual(_urlparse(out).port, 80)

    def test_allow_private_lets_loopback_through(self) -> None:
        self.assertTrue(_enforce_url_policy("http://127.0.0.1/", True).startswith("http://127.0.0.1"))

    def test_host_is_private_classification(self) -> None:
        for ip in ("127.0.0.1", "169.254.169.254", "::1", "10.255.255.255", "192.168.0.1"):
            self.assertTrue(_host_is_private(ip), ip)
        self.assertFalse(_host_is_private("8.8.8.8"))

    def test_normalize_rejects_spaces_backslashes_and_empty(self) -> None:
        for bad in ("", "http://ex ample.com/", "http://e\\vil/"):
            with self.assertRaises(WebsiteFetchError):
                normalize_website_url(bad)


class ConnectWithRetryTests(unittest.TestCase):
    """_connect_with_retry() retries a CONNECTION-LEVEL transient failure once, but
    never an HTTPError (a real server answer) -- and only wraps the connect step
    itself, not the caller's own response-processing (content-type/length checks)."""

    class _FakeOpener:
        def __init__(self, behaviors: list) -> None:
            self._behaviors = list(behaviors)
            self.calls = 0

        def open(self, request, timeout=None):
            self.calls += 1
            behavior = self._behaviors.pop(0)
            if isinstance(behavior, Exception):
                raise behavior
            return behavior

    def test_one_transient_failure_is_retried_and_succeeds(self) -> None:
        sentinel = object()
        opener = self._FakeOpener([urllib.error.URLError("simulated connection reset"), sentinel])
        result = _connect_with_retry(opener, object(), 5.0)
        self.assertIs(result, sentinel)
        self.assertEqual(opener.calls, 2)

    def test_retries_are_exhausted_then_raise(self) -> None:
        opener = self._FakeOpener([urllib.error.URLError("down")] * (_MAX_FETCH_ATTEMPTS + 1))
        with self.assertRaises(urllib.error.URLError):
            _connect_with_retry(opener, object(), 5.0)
        self.assertEqual(opener.calls, _MAX_FETCH_ATTEMPTS)

    def test_http_error_is_never_retried(self) -> None:
        hdrs = email.message.Message()
        http_error = urllib.error.HTTPError("http://x/", 503, "Service Unavailable", hdrs, io.BytesIO(b""))
        opener = self._FakeOpener([http_error])
        with self.assertRaises(urllib.error.HTTPError):
            _connect_with_retry(opener, object(), 5.0)
        self.assertEqual(opener.calls, 1, "an HTTPError must never trigger a retry")


if __name__ == "__main__":
    unittest.main()
