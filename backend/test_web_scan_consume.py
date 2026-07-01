"""Direct tests for web_scan_service._consume (byte-cap, cookies, charset fallback,
status extraction) and the remaining _probe_sensitive_paths validators (only the
git-config-vs-SPA case had a test before).
"""
from __future__ import annotations

import io
import sys
import unittest
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.web_scan_service import _consume, _probe_sensitive_paths, _sensitive_path_matches  # noqa: E402


class _FakeResponse:
    def __init__(self, *, headers: dict | None = None, body: bytes = b"", status: int = 200,
                 code: int | None = None, cookies: list[str] | None = None, has_status_attr: bool = True):
        msg = Message()
        for k, v in (headers or {}).items():
            msg[k] = v
        for c in cookies or []:
            msg.add_header("Set-Cookie", c)
        self.headers = msg
        self._body = io.BytesIO(body)
        if has_status_attr:
            self.status = status
        if code is not None:
            self.code = code

    def read(self, amt=None):
        return self._body.read(amt)


def _settings(max_bytes: int) -> SimpleNamespace:
    return SimpleNamespace(web_fetch_max_bytes=max_bytes)


class ConsumeByteCapTests(unittest.TestCase):
    def test_body_under_cap_is_not_truncated(self) -> None:
        resp = _FakeResponse(body=b"short")
        out = _consume(resp, _settings(100))
        self.assertEqual(out["body"], "short")
        self.assertFalse(out["truncated"])

    def test_body_exactly_at_cap_is_not_truncated(self) -> None:
        resp = _FakeResponse(body=b"x" * 10)
        out = _consume(resp, _settings(10))
        self.assertEqual(len(out["body"]), 10)
        self.assertFalse(out["truncated"])

    def test_body_over_cap_is_truncated_to_exactly_the_cap(self) -> None:
        resp = _FakeResponse(body=b"x" * 11)
        out = _consume(resp, _settings(10))
        self.assertEqual(len(out["body"]), 10)
        self.assertTrue(out["truncated"])


class ConsumeCookiesTests(unittest.TestCase):
    def test_multiple_set_cookie_headers_all_captured(self) -> None:
        resp = _FakeResponse(body=b"", cookies=["a=1; Path=/", "b=2; HttpOnly"])
        out = _consume(resp, _settings(1000))
        self.assertEqual(len(out["cookies"]), 2)
        self.assertIn("a=1; Path=/", out["cookies"])
        self.assertIn("b=2; HttpOnly", out["cookies"])

    def test_no_cookies_returns_empty_list(self) -> None:
        resp = _FakeResponse(body=b"")
        out = _consume(resp, _settings(1000))
        self.assertEqual(out["cookies"], [])


class ConsumeCharsetTests(unittest.TestCase):
    def test_unknown_charset_falls_back_to_utf8(self) -> None:
        resp = _FakeResponse(headers={"Content-Type": "text/html; charset=bogus-charset-xyz"}, body="héllo".encode("utf-8"))
        out = _consume(resp, _settings(1000))
        self.assertEqual(out["body"], "héllo")  # LookupError on the bogus charset -> utf-8 fallback

    def test_explicit_valid_charset_is_honored(self) -> None:
        resp = _FakeResponse(headers={"Content-Type": "text/html; charset=latin-1"}, body="café".encode("latin-1"))
        out = _consume(resp, _settings(1000))
        self.assertEqual(out["body"], "café")

    def test_no_content_type_defaults_to_utf8(self) -> None:
        resp = _FakeResponse(body="ünïcödé".encode("utf-8"))
        out = _consume(resp, _settings(1000))
        self.assertEqual(out["body"], "ünïcödé")


class ConsumeStatusTests(unittest.TestCase):
    def test_status_attribute_used_when_present(self) -> None:
        resp = _FakeResponse(status=204)
        out = _consume(resp, _settings(1000))
        self.assertEqual(out["status"], 204)

    def test_falls_back_to_code_when_status_is_falsy_or_absent(self) -> None:
        # urllib.error.HTTPError exposes .code, not .status.
        resp = _FakeResponse(has_status_attr=False, code=404)
        out = _consume(resp, _settings(1000))
        self.assertEqual(out["status"], 404)

    def test_neither_attribute_defaults_to_zero(self) -> None:
        resp = _FakeResponse(has_status_attr=False)
        out = _consume(resp, _settings(1000))
        self.assertEqual(out["status"], 0)


class SensitivePathValidatorTests(unittest.TestCase):
    """_sensitive_path_matches(kind, body, headers, status) per-kind content validators
    beyond the existing git-config-vs-SPA case (test_web_scan_service.py::
    SensitivePathProbeTests). NOTE: the function does not itself gate on `status` (its
    only caller, _probe_sensitive_paths, already filters to 200 before calling it) and
    the HTML-shell guard (an SPA's 200 fallback page) applies BEFORE any kind-specific
    check, for every kind."""

    def test_dotenv_with_real_assignment_matches(self) -> None:
        self.assertTrue(_sensitive_path_matches("dotenv", "DB_PASSWORD=hunter2\nAPI_KEY=sk-abc123\n", {}, 200))

    def test_dotenv_html_shell_does_not_match(self) -> None:
        self.assertFalse(_sensitive_path_matches("dotenv", "<!doctype html><html>app</html>", {}, 200))

    def test_dotenv_lowercase_or_short_keys_do_not_match(self) -> None:
        self.assertFalse(_sensitive_path_matches("dotenv", "just some prose, no assignment here", {}, 200))

    def test_git_head_matches_real_ref(self) -> None:
        self.assertTrue(_sensitive_path_matches("git_head", "ref: refs/heads/main\n", {}, 200))

    def test_git_head_spa_shell_does_not_match(self) -> None:
        self.assertFalse(_sensitive_path_matches("git_head", "<html><body>app</body></html>", {}, 200))

    def test_svn_entries_digit_prefix_matches(self) -> None:
        self.assertTrue(_sensitive_path_matches("svn", "12\ndir\n123\nhttps://svn.example.com/repo\n", {}, 200))

    def test_svn_marker_text_matches(self) -> None:
        self.assertTrue(_sensitive_path_matches("svn", "some preamble svn: revision data", {}, 200))

    def test_apache_status_matches(self) -> None:
        self.assertTrue(_sensitive_path_matches(
            "apache_status", "Apache Server Status for example.com\nTotal Accesses: 500", {}, 200))

    def test_apache_status_unrelated_text_does_not_match(self) -> None:
        self.assertFalse(_sensitive_path_matches("apache_status", "Server is running fine.", {}, 200))

    def test_actuator_requires_status_key_in_json_dict(self) -> None:
        self.assertTrue(_sensitive_path_matches("actuator", '{"status": "UP"}', {}, 200))

    def test_actuator_json_without_status_key_does_not_match(self) -> None:
        self.assertFalse(_sensitive_path_matches("actuator", '{"propertySources": []}', {}, 200))

    def test_actuator_non_json_body_does_not_match(self) -> None:
        self.assertFalse(_sensitive_path_matches("actuator", "not json at all", {}, 200))

    def test_openapi_requires_swagger_openapi_or_paths_key(self) -> None:
        self.assertTrue(_sensitive_path_matches("openapi", '{"openapi": "3.0.0", "paths": {}}', {}, 200))
        self.assertTrue(_sensitive_path_matches("openapi", '{"swagger": "2.0"}', {}, 200))

    def test_openapi_unrelated_json_does_not_match(self) -> None:
        self.assertFalse(_sensitive_path_matches("openapi", '{"hello": "world"}', {}, 200))

    def test_dsstore_binary_signature_matches(self) -> None:
        self.assertTrue(_sensitive_path_matches("dsstore", "\x00\x00\x00\x01Bud1\x00\x00", {}, 200))

    def test_dsstore_without_signature_does_not_match(self) -> None:
        self.assertFalse(_sensitive_path_matches("dsstore", "just some random bytes", {}, 200))

    def test_unknown_kind_never_matches(self) -> None:
        self.assertFalse(_sensitive_path_matches("not-a-real-kind", "[core]\nanything", {}, 200))


class _ExhaustedGovernor:
    """A fake governor whose bucket is always empty — exercises the fail-closed
    'budget exhausted -> stop, no bursting' break in _probe_sensitive_paths without
    needing to actually drain a real HostRateGovernor's token bucket."""

    def throttle(self, host: str) -> bool:
        return False


class ProbeSensitivePathsGovernorTests(unittest.TestCase):
    def test_exhausted_governor_returns_immediately_with_no_findings(self) -> None:
        # Never even attempts a fetch -- the very first throttle() call returns False,
        # so the loop breaks before any request, fail-closed (no bursting past budget).
        findings = _probe_sensitive_paths("https://app.example.com/", _ExhaustedGovernor())
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
