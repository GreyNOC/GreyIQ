"""Exact chat-scan scope must bind each network request, not just the first URL."""

from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import live_scan_service, web_scan_service  # noqa: E402
from bughunter.web_ingest import WebsiteFetchError  # noqa: E402


class ScopedWebScanTests(unittest.TestCase):
    def test_initial_host_mismatch_refuses_before_fetch(self) -> None:
        with patch.object(web_scan_service, "_guard_url") as guard, patch.object(
            web_scan_service, "build_opener"
        ) as opener:
            result = web_scan_service.run_web_scan(
                "https://outside.example.test/", scope_host="app.example.test"
            )
        self.assertFalse(result["ok"])
        self.assertIn("outside the exact authorized scope", result["error"])
        guard.assert_not_called()
        opener.assert_not_called()

    def test_cross_host_redirect_refuses_before_guard_or_followup_request(self) -> None:
        redirect = web_scan_service._GuardedRedirect(
            False, frozenset({80, 443}), scope_host="app.example.test"
        )
        initial = Request("https://app.example.test/start")
        with patch.object(web_scan_service, "_guard_url") as guard:
            with self.assertRaisesRegex(WebsiteFetchError, "outside the exact authorized scope"):
                redirect.redirect_request(
                    initial, None, 302, "Found", {}, "https://outside.example.test/final"
                )
        guard.assert_not_called()

    def test_same_host_redirect_is_allowed(self) -> None:
        redirect = web_scan_service._GuardedRedirect(
            False, frozenset({80, 443}), scope_host="app.example.test"
        )
        initial = Request("https://app.example.test/start")
        with patch.object(web_scan_service, "_guard_url", side_effect=lambda url, *_: url) as guard:
            next_request = redirect.redirect_request(initial, None, 302, "Found", {}, "/next")
        self.assertIsNotNone(next_request)
        self.assertEqual(next_request.full_url, "https://app.example.test/next")
        guard.assert_called_once()


class ScopedLiveScanTests(unittest.TestCase):
    def _run_without_egress(self, target: str) -> dict[str, object]:
        with patch.object(socket, "getaddrinfo") as dns, patch.object(
            live_scan_service, "_guard_url"
        ) as guard, patch.object(
            live_scan_service, "ensure_bundled_browsers_path"
        ) as browser_setup, patch.object(
            live_scan_service, "get_settings"
        ) as settings:
            result = live_scan_service.run_live_scan(target, scope_host="app.example.test")
        dns.assert_not_called()
        guard.assert_not_called()
        browser_setup.assert_not_called()
        settings.assert_not_called()
        return result

    def test_initial_host_mismatch_refuses_before_dns_or_browser_launch(self) -> None:
        result = self._run_without_egress("https://outside.example.test/")
        self.assertFalse(result["ok"])
        self.assertIn("outside the exact authorized scope", result["error"])

    def test_exact_host_refuses_before_dns_or_browser_launch(self) -> None:
        result = self._run_without_egress("https://app.example.test/")
        self.assertFalse(result["ok"])
        self.assertIn("Scoped live scanning is unavailable", result["error"])
        self.assertIn("scoped web scanning or active verification", result["error"])

    def test_bad_scheme_refuses_before_dns_or_browser_launch(self) -> None:
        result = self._run_without_egress("ftp://app.example.test/")
        self.assertFalse(result["ok"])
        self.assertIn("Only http and https", result["error"])

    def test_malformed_port_refuses_before_dns_or_browser_launch(self) -> None:
        result = self._run_without_egress("https://app.example.test:99999/")
        self.assertFalse(result["ok"])
        self.assertIn("invalid port", result["error"])


if __name__ == "__main__":
    unittest.main()
