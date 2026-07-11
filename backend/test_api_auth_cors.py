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

    def test_api_health_does_not_leak_version_to_unauthenticated_callers(self) -> None:
        # /api/health is the one /api/* path reachable with no credentials at all (it's
        # the liveness check Electron polls before a session exists) -- it must never
        # hand a scanner the exact app/version string to fingerprint.
        cap = _run_route("GET", "/api/health")
        self.assertEqual(cap.status, 200)
        body = g.json.loads(cap.body)
        self.assertEqual(body, {"status": "ok"})
        self.assertNotIn("version", body)
        self.assertNotIn("app", body)

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


class IsLoopbackBindTests(unittest.TestCase):
    def test_loopback_hosts(self) -> None:
        self.assertTrue(g._is_loopback_bind("127.0.0.1"))
        self.assertTrue(g._is_loopback_bind("localhost"))
        self.assertTrue(g._is_loopback_bind("::1"))
        self.assertTrue(g._is_loopback_bind("LOCALHOST"))  # case-insensitive

    def test_non_loopback_hosts(self) -> None:
        # 0.0.0.0 means "all interfaces" -- the opposite of loopback-only, must NOT
        # be treated as safe.
        self.assertFalse(g._is_loopback_bind("0.0.0.0"))
        self.assertFalse(g._is_loopback_bind("10.0.0.5"))
        self.assertFalse(g._is_loopback_bind("example.com"))
        self.assertFalse(g._is_loopback_bind(""))


class AccessKeyGateTests(unittest.TestCase):
    """GREYIQ_ACCESS_KEY (opt-in) gates EVERY request -- including the unauthenticated
    index page that embeds SESSION_TOKEN -- ahead of the origin/session-token logic.
    Regression coverage for the confirmed critical finding: an unauthenticated GET to
    '/' (or any unmatched path) with no Origin header returns SESSION_TOKEN in the
    HTML, which can then be replayed via X-GreyIQ-Token against every /api/* route."""

    def setUp(self) -> None:
        self._orig_key = g.GREYIQ_ACCESS_KEY

    def tearDown(self) -> None:
        g.GREYIQ_ACCESS_KEY = self._orig_key

    def _basic(self, password: str, user: str = "op") -> dict:
        token = g.base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Host": "127.0.0.1:8791", "Authorization": f"Basic {token}"}

    def test_default_unset_key_preserves_existing_behavior(self) -> None:
        # Backward compatibility: the default (no key configured) local/Electron case
        # must be completely unaffected -- '/' still serves index.html with no auth.
        g.GREYIQ_ACCESS_KEY = ""
        cap = _run_route("GET", "/")
        self.assertEqual(cap.status, 200)

    def test_index_leaks_token_when_no_key_configured_documents_the_pre_fix_behavior(self) -> None:
        # This PINS the known, documented, accepted-by-design behavior for the default
        # (unconfigured) case: local/Electron use never sets GREYIQ_ACCESS_KEY, so the
        # token is still served this way for that trusted, same-machine scenario. The
        # actual fix is that GREYIQ_ACCESS_KEY, once set, closes this off entirely
        # (see the tests below) -- this test exists so a future change to send_index
        # can't silently reintroduce the leak without a visible test failure either way.
        g.GREYIQ_ACCESS_KEY = ""
        cap = _run_route("GET", "/")
        self.assertIn(g.SESSION_TOKEN.encode(), cap.body)

    def test_no_credentials_is_rejected_when_key_configured(self) -> None:
        g.GREYIQ_ACCESS_KEY = "supersecretkey"
        cap = _run_route("GET", "/")
        self.assertEqual(cap.status, 401)
        self.assertNotIn(g.SESSION_TOKEN.encode(), cap.body)  # the token is never leaked pre-auth
        header_names = {k.lower() for k, _ in cap.headers}
        self.assertIn(b"www-authenticate", header_names)

    def test_wrong_password_is_rejected(self) -> None:
        g.GREYIQ_ACCESS_KEY = "supersecretkey"
        cap = _run_route("GET", "/", headers=self._basic("wrong-password"))
        self.assertEqual(cap.status, 401)

    def test_correct_password_any_username_is_accepted(self) -> None:
        g.GREYIQ_ACCESS_KEY = "supersecretkey"
        cap = _run_route("GET", "/", headers=self._basic("supersecretkey", user="anyone"))
        self.assertEqual(cap.status, 200)
        self.assertIn(g.SESSION_TOKEN.encode(), cap.body)

    def test_gate_covers_api_health_too(self) -> None:
        # /api/health is normally exempt from the session-token gate (line 3029), but
        # the access-key gate runs BEFORE that logic and must still apply to it --
        # otherwise an attacker could still fingerprint/reach it unauthenticated.
        g.GREYIQ_ACCESS_KEY = "supersecretkey"
        cap = _run_route("GET", "/api/health")
        self.assertEqual(cap.status, 401)
        cap2 = _run_route("GET", "/api/health", headers=self._basic("supersecretkey"))
        self.assertEqual(cap2.status, 200)

    def test_gate_covers_the_static_catch_all_too(self) -> None:
        g.GREYIQ_ACCESS_KEY = "supersecretkey"
        cap = _run_route("GET", "/app.js")
        self.assertEqual(cap.status, 401)

    def test_gate_covers_protected_api_paths_even_with_a_valid_session_token(self) -> None:
        # A stolen/leaked SESSION_TOKEN alone must not be enough once an access key is
        # configured -- both credentials are required.
        g.GREYIQ_ACCESS_KEY = "supersecretkey"
        cap = _run_route("GET", "/api/status", headers={"Host": "127.0.0.1:8791", "X-GreyIQ-Token": g.SESSION_TOKEN})
        self.assertEqual(cap.status, 401)

    def test_malformed_authorization_header_does_not_crash(self) -> None:
        g.GREYIQ_ACCESS_KEY = "supersecretkey"
        for bad in ["Basic", "Basic not-valid-base64!!!", "Bearer sometoken", ""]:
            headers = {"Host": "127.0.0.1:8791"}
            if bad:
                headers["Authorization"] = bad
            cap = _run_route("GET", "/", headers=headers)
            self.assertEqual(cap.status, 401, bad)

    def test_options_preflight_succeeds_under_access_key_for_allowed_origin(self) -> None:
        # A CORS preflight (OPTIONS) NEVER carries credentials (Fetch spec). With an access key set it
        # must still return 204 for an allowlisted origin so the browser can then send the real
        # credentialed request -- otherwise every preflighted cross-origin /api/* call 401s and the
        # documented GREYIQ_ALLOWED_ORIGINS + access-key deployment is unusable.
        g.GREYIQ_ACCESS_KEY = "supersecretkey"
        orig = g.os.environ.get("GREYIQ_ALLOWED_ORIGINS")
        g.os.environ["GREYIQ_ALLOWED_ORIGINS"] = "https://allowed.example"
        try:
            cap = _run_route("OPTIONS", "/api/bounty/scan",
                             headers={"Host": "127.0.0.1:8791", "Origin": "https://allowed.example"})
            self.assertEqual(cap.status, 204)  # preflight succeeds without Basic auth
            # A disallowed origin's preflight is still refused -- OPTIONS bypasses the key, NOT the origin check.
            cap2 = _run_route("OPTIONS", "/api/bounty/scan",
                              headers={"Host": "127.0.0.1:8791", "Origin": "https://evil.example"})
            self.assertEqual(cap2.status, 403)
        finally:
            if orig is None:
                g.os.environ.pop("GREYIQ_ALLOWED_ORIGINS", None)
            else:
                g.os.environ["GREYIQ_ALLOWED_ORIGINS"] = orig


if __name__ == "__main__":
    unittest.main()
