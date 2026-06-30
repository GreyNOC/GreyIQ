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

from bughunter.web_ingest import (  # noqa: E402
    WebsiteFetchError,
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


if __name__ == "__main__":
    unittest.main()
