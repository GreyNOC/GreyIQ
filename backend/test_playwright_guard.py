"""Tests for web_scan_service.playwright_request_allowed — the shared route-guard used by
both screenshot_service and live_scan_service to re-check EVERY request a real browser
makes (navigation redirects + sub-resources), not just the initial URL. Pure / no browser
needed: it wraps the same _guard_url the passive scanner uses.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.web_scan_service import playwright_request_allowed  # noqa: E402

_PORTS = frozenset({80, 443, 8080, 8443})


class PlaywrightRequestAllowedTests(unittest.TestCase):
    def test_public_https_allowed(self) -> None:
        self.assertTrue(playwright_request_allowed("https://example.com/a", False, _PORTS))

    def test_private_host_blocked(self) -> None:
        # A redirect or sub-resource pointing at loopback/private must be blocked unless
        # private URLs are explicitly allowed — same as the initial-URL guard.
        self.assertFalse(playwright_request_allowed("http://127.0.0.1/admin", False, _PORTS))
        self.assertFalse(playwright_request_allowed("http://169.254.169.254/latest/meta-data/", False, _PORTS))

    def test_private_host_allowed_when_opted_in(self) -> None:
        self.assertTrue(playwright_request_allowed("http://127.0.0.1:8080/", True, _PORTS))

    def test_disallowed_port_blocked(self) -> None:
        self.assertFalse(playwright_request_allowed("https://example.com:9999/", False, _PORTS))

    def test_non_http_scheme_always_allowed(self) -> None:
        # data:/blob:/about: are not network egress — never the SSRF guard's concern.
        for url in ("data:image/png;base64,AAAA", "blob:https://example.com/uuid", "about:blank"):
            self.assertTrue(playwright_request_allowed(url, False, _PORTS), url)

    def test_malformed_url_blocked_not_raised(self) -> None:
        self.assertFalse(playwright_request_allowed("http://", False, _PORTS))
        self.assertFalse(playwright_request_allowed("https://user:pass@example.com/", False, _PORTS))


if __name__ == "__main__":
    unittest.main()
