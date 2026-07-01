"""Tests for greyiq_api's local-process auth gate, CORS origin handling, and the
static-file path-traversal guard -- a security boundary with no prior dedicated test.
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402


def _scope(*, method="GET", path="/", headers=None, scheme="http"):
    hdrs = [(k.lower().encode("ascii"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    return {"method": method, "path": path, "headers": hdrs, "scheme": scheme, "query_string": b""}


class NormalizeOriginTests(unittest.TestCase):
    def test_valid_https_origin(self) -> None:
        self.assertEqual(g._normalize_origin("https://example.com"), "https://example.com")

    def test_lowercases_scheme_and_host(self) -> None:
        self.assertEqual(g._normalize_origin("HTTPS://Example.COM"), "https://example.com")

    def test_null_origin_rejected(self) -> None:
        self.assertEqual(g._normalize_origin("null"), "")

    def test_empty_rejected(self) -> None:
        self.assertEqual(g._normalize_origin(""), "")

    def test_non_http_scheme_rejected(self) -> None:
        self.assertEqual(g._normalize_origin("ftp://example.com"), "")
        self.assertEqual(g._normalize_origin("file:///etc/passwd"), "")

    def test_missing_host_rejected(self) -> None:
        self.assertEqual(g._normalize_origin("https:///path"), "")

    def test_userinfo_rejected(self) -> None:
        # An Origin header carrying embedded credentials is never legitimate -- refuse it
        # rather than silently stripping the userinfo and matching on the host alone.
        self.assertEqual(g._normalize_origin("https://user:pass@example.com"), "")

    def test_idna_host_normalized_to_punycode(self) -> None:
        self.assertEqual(g._normalize_origin("https://münchen.de"), "https://xn--mnchen-3ya.de")

    def test_explicit_default_port_is_kept_not_stripped(self) -> None:
        # PINS the current behavior: urlparse(...).port is None for an implicit default
        # port, so a bare "https://example.com" and an explicit "https://example.com:443"
        # normalize to DIFFERENT strings. A client (or proxy) sending the explicit form
        # would fail to origin-match a same-origin/allowlist entry written in bare form.
        self.assertEqual(g._normalize_origin("https://example.com:443"), "https://example.com:443")
        self.assertNotEqual(g._normalize_origin("https://example.com:443"), g._normalize_origin("https://example.com"))

    def test_non_default_port_kept(self) -> None:
        self.assertEqual(g._normalize_origin("http://example.com:8080"), "http://example.com:8080")

    def test_malformed_origin_does_not_raise(self) -> None:
        self.assertEqual(g._normalize_origin("https://[::1"), "")  # unterminated IPv6 literal


class RequestOriginAllowedTests(unittest.TestCase):
    def test_no_origin_header_is_allowed(self) -> None:
        # Non-browser / same-origin requests (curl, the desktop app's own fetch) often
        # carry no Origin header at all -- must not be refused.
        self.assertTrue(g._request_origin_allowed(_scope(headers={"Host": "127.0.0.1:8791"})))

    def test_origin_matching_request_host_is_allowed(self) -> None:
        scope = _scope(headers={"Host": "127.0.0.1:8791", "Origin": "http://127.0.0.1:8791"})
        self.assertTrue(g._request_origin_allowed(scope))

    def test_cross_origin_not_in_allowlist_is_refused(self) -> None:
        scope = _scope(headers={"Host": "127.0.0.1:8791", "Origin": "https://evil.example"})
        self.assertFalse(g._request_origin_allowed(scope))

    def test_malformed_origin_is_refused(self) -> None:
        scope = _scope(headers={"Host": "127.0.0.1:8791", "Origin": "not a url"})
        self.assertFalse(g._request_origin_allowed(scope))

    def test_configured_allowlisted_origin_is_allowed(self) -> None:
        orig = g.os.environ.get("GREYIQ_ALLOWED_ORIGINS")
        g.os.environ["GREYIQ_ALLOWED_ORIGINS"] = "https://allowed.example"
        try:
            scope = _scope(headers={"Host": "127.0.0.1:8791", "Origin": "https://allowed.example"})
            self.assertTrue(g._request_origin_allowed(scope))
        finally:
            if orig is None:
                g.os.environ.pop("GREYIQ_ALLOWED_ORIGINS", None)
            else:
                g.os.environ["GREYIQ_ALLOWED_ORIGINS"] = orig


class CorsHeadersTests(unittest.TestCase):
    def test_no_origin_emits_no_cors_headers(self) -> None:
        self.assertEqual(g._cors_headers(_scope(headers={"Host": "x"})), [])

    def test_disallowed_origin_emits_no_cors_headers(self) -> None:
        scope = _scope(headers={"Host": "127.0.0.1:8791", "Origin": "https://evil.example"})
        self.assertEqual(g._cors_headers(scope), [])

    def test_allowed_origin_emits_acao_and_vary(self) -> None:
        scope = _scope(headers={"Host": "127.0.0.1:8791", "Origin": "http://127.0.0.1:8791"})
        headers = dict(g._cors_headers(scope))
        self.assertEqual(headers.get(b"access-control-allow-origin"), b"http://127.0.0.1:8791")
        self.assertEqual(headers.get(b"vary"), b"Origin")


class SessionAuthorizedTests(unittest.TestCase):
    def test_correct_token_authorizes(self) -> None:
        scope = _scope(headers={"X-GreyIQ-Token": g.SESSION_TOKEN})
        self.assertTrue(g._session_authorized(scope))

    def test_wrong_token_refused(self) -> None:
        scope = _scope(headers={"X-GreyIQ-Token": "wrong-token"})
        self.assertFalse(g._session_authorized(scope))

    def test_missing_token_refused(self) -> None:
        self.assertFalse(g._session_authorized(_scope()))

    def test_allowlisted_origin_exempts_the_token(self) -> None:
        orig = g.os.environ.get("GREYIQ_ALLOWED_ORIGINS")
        g.os.environ["GREYIQ_ALLOWED_ORIGINS"] = "https://allowed.example"
        try:
            scope = _scope(headers={"Origin": "https://allowed.example"})  # no token at all
            self.assertTrue(g._session_authorized(scope))
        finally:
            if orig is None:
                g.os.environ.pop("GREYIQ_ALLOWED_ORIGINS", None)
            else:
                g.os.environ["GREYIQ_ALLOWED_ORIGINS"] = orig


class _Capture:
    def __init__(self) -> None:
        self.status: int | None = None
        self.headers: list[tuple[bytes, bytes]] = []
        self.body = b""

    async def send(self, message: dict) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
            self.headers = message.get("headers", [])
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")

    @staticmethod
    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}


def _run_route(method: str, path: str, headers: dict | None = None) -> _Capture:
    cap = _Capture()
    scope = _scope(method=method, path=path, headers=headers or {"Host": "127.0.0.1:8791"})
    asyncio.run(g.route_http(scope, cap.receive, cap.send))
    return cap


class RouteHttpAsgiTests(unittest.TestCase):
    """End-to-end through the real ASGI entry point (a minimal in-process harness --
    no socket), covering the session-token gate, OPTIONS bypass, and the static-file
    path-traversal guard, none of which had any prior test."""

    def test_api_health_exempt_from_token_requirement(self) -> None:
        cap = _run_route("GET", "/api/health")
        self.assertEqual(cap.status, 200)

    def test_protected_api_path_without_token_is_refused(self) -> None:
        cap = _run_route("GET", "/api/status")
        self.assertEqual(cap.status, 403)

    def test_protected_api_path_with_correct_token_succeeds(self) -> None:
        cap = _run_route("GET", "/api/status", headers={"Host": "127.0.0.1:8791", "X-GreyIQ-Token": g.SESSION_TOKEN})
        self.assertEqual(cap.status, 200)

    def test_unknown_api_path_returns_404_not_500(self) -> None:
        cap = _run_route("GET", "/api/this-route-does-not-exist", headers={"Host": "127.0.0.1:8791", "X-GreyIQ-Token": g.SESSION_TOKEN})
        self.assertEqual(cap.status, 404)

    def test_options_preflight_bypasses_token_but_not_origin(self) -> None:
        cap = _run_route("OPTIONS", "/api/status", headers={"Host": "127.0.0.1:8791", "Origin": "https://evil.example"})
        self.assertEqual(cap.status, 403)  # disallowed origin still refused
        cap2 = _run_route("OPTIONS", "/api/status")  # no Origin -> allowed, no token needed
        self.assertEqual(cap2.status, 204)

    def test_path_traversal_with_dotdot_is_refused(self) -> None:
        cap = _run_route("GET", "/../../../../etc/passwd")
        self.assertIn(cap.status, (404,))  # never serves the file, never 500s

    def test_url_encoded_path_traversal_is_refused(self) -> None:
        cap = _run_route("GET", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
        self.assertIn(cap.status, (404,))

    def test_deliberate_http_error_returns_structured_detail(self) -> None:
        # A handler-level deliberate error (e.g. validate_payload) -> {"detail": ...}
        # with the HTTPError's own status code, never a generic 500.
        orig = g.validate_payload
        g.validate_payload = lambda *a, **k: (_ for _ in ()).throw(g.HTTPError(422, "deliberate test detail"))
        try:
            cap = _run_route("POST", "/api/chat", headers={"Host": "127.0.0.1:8791", "X-GreyIQ-Token": g.SESSION_TOKEN})
        finally:
            g.validate_payload = orig
        self.assertEqual(cap.status, 422)
        self.assertIn(b"deliberate test detail", cap.body)

    def test_unexpected_exception_returns_generic_500_no_raw_text_leak(self) -> None:
        # An UNEXPECTED internal exception must never reflect its message/traceback to
        # the client -- only the generic 'internal server error'.
        orig = g.runtime.status
        g.runtime.status = lambda: (_ for _ in ()).throw(RuntimeError("SECRET_INTERNAL_DETAIL_12345"))
        try:
            cap = _run_route("GET", "/api/status", headers={"Host": "127.0.0.1:8791", "X-GreyIQ-Token": g.SESSION_TOKEN})
        finally:
            g.runtime.status = orig
        self.assertEqual(cap.status, 500)
        self.assertNotIn(b"SECRET_INTERNAL_DETAIL_12345", cap.body)
        self.assertIn(b"internal server error", cap.body)


if __name__ == "__main__":
    unittest.main()
