"""Tests for bughunter.settings's env-var parsers — no dedicated test file existed.

Every scanner/active-prover safety knob (private-URL allowance, port allowlist, byte/
timeout caps) is sourced through these; a parser that silently swallows a malformed env
value into the wrong default would change the gate's behavior with no signal.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import settings as S  # noqa: E402

_ENV_KEYS = (
    "GREYIQ_CODE_SCAN_BASE_PATH", "GREYIQ_SCAN_ALLOW_PRIVATE_URLS", "GREYIQ_WEB_ALLOWED_PORTS",
    "GREYIQ_WEB_FETCH_TIMEOUT", "GREYIQ_WEB_FETCH_MAX_BYTES", "GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST",
    "GREYIQ_ACTIVE_MIN_INTERVAL_MS", "GREYIQ_ACTIVE_SCAN_ALLOWLIST",
    "GREYIQ_ACTIVE_TIME_SQLI_DELAY_S", "GREYIQ_ACTIVE_TIME_SQLI_MARGIN_S",
)


class _EnvIsolated(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class BoolEnvTests(_EnvIsolated):
    def test_unset_uses_default(self) -> None:
        self.assertFalse(S._bool_env("GREYIQ_SCAN_ALLOW_PRIVATE_URLS"))

    def test_truthy_variants(self) -> None:
        for val in ("1", "true", "True", "yes", "on", " 1 "):
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = val
            self.assertTrue(S._bool_env("GREYIQ_SCAN_ALLOW_PRIVATE_URLS"), val)

    def test_falsy_variants(self) -> None:
        for val in ("0", "false", "no", "off", "garbage", ""):
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = val
            self.assertFalse(S._bool_env("GREYIQ_SCAN_ALLOW_PRIVATE_URLS"), val)


class FloatIntEnvTests(_EnvIsolated):
    def test_float_env_parses_and_defaults(self) -> None:
        self.assertEqual(S._float_env("GREYIQ_WEB_FETCH_TIMEOUT", 8.0), 8.0)
        os.environ["GREYIQ_WEB_FETCH_TIMEOUT"] = "12.5"
        self.assertEqual(S._float_env("GREYIQ_WEB_FETCH_TIMEOUT", 8.0), 12.5)

    def test_float_env_malformed_falls_back_to_default(self) -> None:
        os.environ["GREYIQ_WEB_FETCH_TIMEOUT"] = "not-a-number"
        self.assertEqual(S._float_env("GREYIQ_WEB_FETCH_TIMEOUT", 8.0), 8.0)

    def test_int_env_parses_and_defaults(self) -> None:
        self.assertEqual(S._int_env("GREYIQ_WEB_FETCH_MAX_BYTES", 3_000_000), 3_000_000)
        os.environ["GREYIQ_WEB_FETCH_MAX_BYTES"] = "500"
        self.assertEqual(S._int_env("GREYIQ_WEB_FETCH_MAX_BYTES", 3_000_000), 500)

    def test_int_env_malformed_falls_back_to_default(self) -> None:
        os.environ["GREYIQ_WEB_FETCH_MAX_BYTES"] = "abc"
        self.assertEqual(S._int_env("GREYIQ_WEB_FETCH_MAX_BYTES", 3_000_000), 3_000_000)

    def test_int_env_negative_value_is_accepted_as_is(self) -> None:
        # _int_env itself doesn't clamp -- callers (e.g. max_files = max(1, int(...))) own
        # that. Pin the current (permissive) parsing behavior so a future change is visible.
        os.environ["GREYIQ_WEB_FETCH_MAX_BYTES"] = "-5"
        self.assertEqual(S._int_env("GREYIQ_WEB_FETCH_MAX_BYTES", 3_000_000), -5)


class PortsEnvTests(_EnvIsolated):
    def test_unset_uses_default(self) -> None:
        self.assertEqual(S._ports_env("GREYIQ_WEB_ALLOWED_PORTS", S._DEFAULT_PORTS), S._DEFAULT_PORTS)

    def test_parses_comma_separated_ports(self) -> None:
        os.environ["GREYIQ_WEB_ALLOWED_PORTS"] = "80,443,8443"
        self.assertEqual(S._ports_env("GREYIQ_WEB_ALLOWED_PORTS", S._DEFAULT_PORTS), frozenset({80, 443, 8443}))

    def test_non_digit_entries_are_silently_dropped(self) -> None:
        os.environ["GREYIQ_WEB_ALLOWED_PORTS"] = "80,abc,443"
        self.assertEqual(S._ports_env("GREYIQ_WEB_ALLOWED_PORTS", S._DEFAULT_PORTS), frozenset({80, 443}))

    def test_all_garbage_falls_back_to_default(self) -> None:
        os.environ["GREYIQ_WEB_ALLOWED_PORTS"] = "abc,def"
        self.assertEqual(S._ports_env("GREYIQ_WEB_ALLOWED_PORTS", S._DEFAULT_PORTS), S._DEFAULT_PORTS)

    def test_empty_string_falls_back_to_default(self) -> None:
        os.environ["GREYIQ_WEB_ALLOWED_PORTS"] = ""
        self.assertEqual(S._ports_env("GREYIQ_WEB_ALLOWED_PORTS", S._DEFAULT_PORTS), S._DEFAULT_PORTS)


class SuffixesEnvTests(_EnvIsolated):
    def test_unset_is_empty_tuple(self) -> None:
        self.assertEqual(S._suffixes_env("GREYIQ_ACTIVE_SCAN_ALLOWLIST"), ())

    def test_parses_lowercases_and_strips_leading_dots(self) -> None:
        os.environ["GREYIQ_ACTIVE_SCAN_ALLOWLIST"] = "Example.COM, .internal.test , corp.local"
        self.assertEqual(
            S._suffixes_env("GREYIQ_ACTIVE_SCAN_ALLOWLIST"),
            ("example.com", "internal.test", "corp.local"),
        )

    def test_blank_entries_are_dropped(self) -> None:
        os.environ["GREYIQ_ACTIVE_SCAN_ALLOWLIST"] = "a.com,,  ,b.com"
        self.assertEqual(S._suffixes_env("GREYIQ_ACTIVE_SCAN_ALLOWLIST"), ("a.com", "b.com"))


class GetSettingsIntegrationTests(_EnvIsolated):
    def test_defaults_with_no_env(self) -> None:
        s = S.get_settings()
        self.assertFalse(s.allow_private_urls)
        self.assertEqual(s.web_allowed_ports, S._DEFAULT_PORTS)
        self.assertEqual(s.web_fetch_timeout_seconds, 8.0)
        self.assertEqual(s.active_scan_allowlist, ())

    def test_private_urls_allowed_does_not_auto_lift_port_allowlist_field(self) -> None:
        # The DOCSTRING says "when enabled... the port allowlist is also lifted" -- that
        # lifting happens at the call site (_guard_url skips the port check entirely when
        # allow_private_urls is True), NOT by mutating web_allowed_ports itself. Pin that
        # get_settings() still reports the configured/default port set verbatim.
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        s = S.get_settings()
        self.assertTrue(s.allow_private_urls)
        self.assertEqual(s.web_allowed_ports, S._DEFAULT_PORTS)

    def test_full_env_override(self) -> None:
        os.environ.update({
            "GREYIQ_CODE_SCAN_BASE_PATH": "/srv/code",
            "GREYIQ_SCAN_ALLOW_PRIVATE_URLS": "true",
            "GREYIQ_WEB_ALLOWED_PORTS": "8080",
            "GREYIQ_WEB_FETCH_TIMEOUT": "15",
            "GREYIQ_WEB_FETCH_MAX_BYTES": "1000",
            "GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST": "5",
            "GREYIQ_ACTIVE_MIN_INTERVAL_MS": "100",
            "GREYIQ_ACTIVE_SCAN_ALLOWLIST": "trusted.example",
            "GREYIQ_ACTIVE_TIME_SQLI_DELAY_S": "2",
            "GREYIQ_ACTIVE_TIME_SQLI_MARGIN_S": "1",
        })
        s = S.get_settings()
        self.assertEqual(s.code_scan_base_path, "/srv/code")
        self.assertTrue(s.allow_private_urls)
        self.assertEqual(s.web_allowed_ports, frozenset({8080}))
        self.assertEqual(s.web_fetch_timeout_seconds, 15.0)
        self.assertEqual(s.web_fetch_max_bytes, 1000)
        self.assertEqual(s.active_max_requests_per_host, 5)
        self.assertEqual(s.active_min_interval_ms, 100)
        self.assertEqual(s.active_scan_allowlist, ("trusted.example",))
        self.assertEqual(s.active_time_sqli_delay_seconds, 2.0)
        self.assertEqual(s.active_time_sqli_margin_seconds, 1.0)


if __name__ == "__main__":
    unittest.main()
