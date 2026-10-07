"""A chat-bound active verifier cannot send any request off its exact host."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import active_verify_service as av  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


class _Governor:
    def __init__(self) -> None:
        self.hosts: list[str] = []

    def throttle(self, host: str) -> bool:
        self.hosts.append(host)
        return True


class _Response:
    status = 200
    headers: dict[str, str] = {}

    def __init__(self, url: str) -> None:
        self.url = url

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def geturl(self) -> str:
        return self.url


class ActiveExactScopeTests(unittest.TestCase):
    def test_initial_url_mismatch_returns_without_network(self) -> None:
        with patch.object(av, "_guard_url") as guard, patch.object(av, "_Http") as transport:
            findings, meta = av.verify_active(
                "https://outside.example.test/", [], scope="outside.example.test",
                scope_host="app.example.test"
            )
        self.assertEqual(findings, [])
        self.assertFalse(meta["in_scope"])
        self.assertEqual(meta["requests_used"], 0)
        guard.assert_not_called()
        transport.assert_not_called()

    def test_generated_off_host_request_refuses_before_guard_governor_or_socket(self) -> None:
        governor = _Governor()
        http = av._Http(get_settings(), governor, scope_host="app.example.test")
        for url in ("https://outside.example.test/", "https://sub.app.example.test/"):
            with self.subTest(url=url), patch.object(av, "_guard_url") as guard, patch.object(
                http.opener, "open"
            ) as opened:
                with self.assertRaises(av._ActiveError):
                    http.fetch(url)
                guard.assert_not_called()
                opened.assert_not_called()
        self.assertEqual(http.sent, 0)
        self.assertEqual(governor.hosts, [])

    def test_same_host_request_uses_existing_transport(self) -> None:
        governor = _Governor()
        http = av._Http(get_settings(), governor, scope_host="app.example.test")
        self.assertFalse(any(isinstance(handler, ProxyHandler)
                             for handler in http.opener.handlers))
        url = "https://app.example.test/path"
        with patch.object(av, "_guard_url", side_effect=lambda value, *_: value), patch.object(
            av, "_consume", return_value={"status": 200, "headers": {}, "body": ""}
        ), patch.object(http.opener, "open", return_value=_Response(url)) as opened:
            result = http.fetch(url)
        self.assertEqual(result["status"], 200)
        self.assertEqual(http.sent, 1)
        self.assertEqual(governor.hosts, ["app.example.test"])
        opened.assert_called_once()

    def test_scoped_chat_request_has_no_unbudgeted_retry(self) -> None:
        http = av._Http(get_settings(), _Governor(), scope_host="app.example.test")
        url = "https://app.example.test/path"
        with patch.object(av, "_guard_url", side_effect=lambda value, *_: value), patch.object(
            http.opener, "open", side_effect=URLError("simulated disconnect")
        ) as opened, patch.object(av.time, "sleep") as slept:
            with self.assertRaises(av._ActiveError):
                http.fetch(url)
        opened.assert_called_once()
        slept.assert_not_called()
        self.assertEqual(http.sent, 1)

    def test_scoped_transport_refuses_virtual_host_headers_before_socket(self) -> None:
        http = av._Http(get_settings(), _Governor(), scope_host="app.example.test")
        for header in ("Host", "X-Forwarded-Host", "Forwarded"):
            with self.subTest(header=header), patch.object(av, "_guard_url") as guard, patch.object(
                http.opener, "open"
            ) as opened:
                with self.assertRaises(av._ActiveError):
                    http.fetch("https://app.example.test/", extra_headers={header: "other.example.test"})
                guard.assert_not_called()
                opened.assert_not_called()
        self.assertEqual(http.sent, 0)

    def test_scoped_verifier_omits_host_header_probe(self) -> None:
        url = "https://app.example.test/"
        with patch.object(av, "_guard_url", side_effect=lambda value, *_: value), patch.object(
            av, "_check_host_header"
        ) as host_check, patch.object(av, "_consume", return_value={"status": 200, "headers": {}, "body": ""}), patch.object(
            av._Http, "fetch", return_value={"status": 200, "headers": {}, "body": "", "final_url": url}
        ):
            av.verify_active(url, [], scope="app.example.test", scope_host="app.example.test",
                             requests_budget=1)
        host_check.assert_not_called()

    def test_scoped_transport_stops_after_rate_limit(self) -> None:
        url = "https://app.example.test/"
        http = av._Http(get_settings(), _Governor(), scope_host="app.example.test")
        with patch.object(av, "_guard_url", side_effect=lambda value, *_: value), patch.object(
            av, "_consume", return_value={"status": 429, "headers": {}, "body": "slow down"}
        ), patch.object(http.opener, "open", return_value=_Response(url)) as opened:
            http.fetch(url)
            with self.assertRaises(av._RateLimited):
                http.fetch(url)
        opened.assert_called_once()
        self.assertEqual(http.sent, 1)
        self.assertIn("rate limited", http.halt_reason)

    def test_scoped_transport_stops_after_explicit_challenge(self) -> None:
        url = "https://app.example.test/"
        http = av._Http(get_settings(), _Governor(), scope_host="app.example.test")
        with patch.object(av, "_guard_url", side_effect=lambda value, *_: value), patch.object(
            av, "_consume", return_value={"status": 403, "headers": {"cf-mitigated": "challenge"}, "body": ""}
        ), patch.object(http.opener, "open", return_value=_Response(url)) as opened:
            http.fetch(url)
            with self.assertRaises(av._RateLimited):
                http.fetch(url)
        opened.assert_called_once()
        self.assertIn("challenge", http.halt_reason)

    def test_default_transport_still_has_no_exact_host_restriction(self) -> None:
        governor = _Governor()
        http = av._Http(get_settings(), governor)
        url = "https://other.example.test/path"
        with patch.object(av, "_guard_url", side_effect=lambda value, *_: value), patch.object(
            av, "_consume", return_value={"status": 200, "headers": {}, "body": ""}
        ), patch.object(http.opener, "open", return_value=_Response(url)):
            result = http.fetch(url)
        self.assertEqual(result["status"], 200)
        self.assertEqual(governor.hosts, ["other.example.test"])

    def test_scoped_verifier_refuses_untrusted_injected_transport(self) -> None:
        class FakeHttp:
            sent = 0

            def fetch(self, _url: str) -> None:
                raise AssertionError("fake transport must not fetch")

        with patch.object(av, "_guard_url", side_effect=lambda value, *_: value):
            findings, meta = av.verify_active(
                "https://app.example.test/", [], scope="app.example.test",
                scope_host="app.example.test", http=FakeHttp()
            )
        self.assertEqual(findings, [])
        self.assertFalse(meta["in_scope"])
        self.assertIn("guarded HTTP transport", meta["skipped_reason"])


if __name__ == "__main__":
    unittest.main()
