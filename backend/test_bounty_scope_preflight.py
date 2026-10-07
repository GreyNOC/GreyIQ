"""URL hunt scope must be established before network-capable scanners run."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty  # noqa: E402


class UrlScopePreflightTests(unittest.TestCase):
    def test_missing_ambiguous_and_unrelated_scope_never_reaches_a_scanner(self) -> None:
        cases = (
            ("", "https://app.example.com/"),
            ("we own app.example.com", "https://app.example.com/"),
            ("https://app.example.com/", "https://app.example.com/"),
            ("app.example.com/path", "https://app.example.com/"),
            ("app.example.com:443", "https://app.example.com/"),
            ("https://github.com/acme/widget", "https://app.example.com/"),
            ("https://app.example.com/ app.example.com", "https://app.example.com/"),
            ("example.com", "https://app.example.com/"),
            ("notapp.example.com", "https://app.example.com/"),
            ("app.example.com.evil", "https://app.example.com/"),
            ("*.other.com", "https://app.example.com/"),
            ("*.example.com", "https://example.com/"),
            ("*.com", "https://app.example.com/"),
            ("*.herokuapp.com", "https://tenant.herokuapp.com/"),
            ("app.example.com", "https://[broken"),
            ("app.example.com", "https://app.example.com/ evil.com"),
            ("app.example.com", "https://app.example.com\\@evil.com"),
            ("app.example.com", "https://@app.example.com/"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=AssertionError("scanner ran")) as scanners:
                for scope, target in cases:
                    with self.subTest(scope=scope, target=target):
                        result = bounty.run_bounty_hunt(
                            target, "web-app", None, None, scope, True, {},
                            default_reports_dir=Path(tmp),
                        )
                        self.assertFalse(result["ok"], result)
                scanners.assert_not_called()

    def test_authorization_and_program_exclusion_precede_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=AssertionError("scanner ran")) as scanners:
                unauthorized = bounty.run_bounty_hunt(
                    "https://app.example.com/", "web-app", None, None,
                    "app.example.com", False, {}, default_reports_dir=Path(tmp),
                )
                excluded = bounty.run_bounty_hunt(
                    "https://blocked.example.com/", "web-app", None, None,
                    "*.example.com", True, {}, default_reports_dir=Path(tmp),
                    settings=SimpleNamespace(excluded_hosts=("blocked.example.com",)),
                )
                self.assertFalse(unauthorized["ok"])
                self.assertIn("authorized", unauthorized["error"].lower())
                self.assertFalse(excluded["ok"])
                self.assertIn("excluded", excluded["error"].lower())
                scanners.assert_not_called()

    def test_exact_and_wildcard_grants_pass_the_exact_target_host(self) -> None:
        class StopBeforeNetwork(BaseException):
            pass

        captured: list[str] = []

        def scanner_spy(*_args: object, **kwargs: object) -> None:
            captured.append(str(kwargs.get("scope_host")))
            raise StopBeforeNetwork

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=scanner_spy):
                for scope in (
                    "app.example.com", "*.example.com",
                    "https://github.com/acme/widget app.example.com",
                ):
                    with self.subTest(scope=scope):
                        with self.assertRaises(StopBeforeNetwork):
                            bounty.run_bounty_hunt(
                                "https://App.Example.Com/path", "web-app", None, None,
                                scope, True, {}, default_reports_dir=Path(tmp),
                            )
        self.assertEqual(captured, ["app.example.com"] * 3)

    def test_scanner_dispatch_binds_web_and_live_to_the_preflight_host(self) -> None:
        web_result = {"ok": True, "findings": [], "risk": "low", "score": 0,
                      "status": 200, "finding_count": 0}
        live_result = {"ok": True, "findings": [], "risk": "low", "score": 0,
                       "finding_count": 0}
        with patch.object(bounty, "run_web_scan", return_value=web_result) as web:
            with patch.object(bounty, "run_live_scan", return_value=live_result) as live:
                bounty._run_scanners(
                    bounty.BOUNTY_PROFILES["web-app"], "url",
                    "https://app.example.com/", 100, True,
                    scope_host="app.example.com",
                )
        self.assertEqual(web.call_args.kwargs["scope_host"], "app.example.com")
        self.assertEqual(live.call_args.kwargs["scope_host"], "app.example.com")


class RepositoryScopePreflightTests(unittest.TestCase):
    def test_remote_clone_rejects_missing_unrelated_and_ambiguous_scope_before_scan(self) -> None:
        target = "https://github.com/acme/widget"
        cases = (
            (target, ""),
            (target, "github.com"),
            (target, "*.github.com"),
            (target, "https://github.com/acme/other"),
            (target, "https://github.com/acme/widget/tree/main"),
            (target, "we own https://github.com/acme/widget"),
            (target, "https://github.com/acme/widget https://example.com/allowed"),
            ("https://github.com:8443/acme/widget", target),
            ("https://gitlab.com/acme/widget/branch/main", "https://gitlab.com/acme/widget"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=AssertionError("clone started")) as scanners:
                for repository, scope in cases:
                    with self.subTest(repository=repository, scope=scope):
                        result = bounty.run_bounty_hunt(
                            repository, "source-code", None, None, scope, True, {},
                            default_reports_dir=Path(tmp),
                        )
                        self.assertFalse(result["ok"], result)
                scanners.assert_not_called()

    def test_matching_root_in_mixed_saved_scope_reaches_scanner(self) -> None:
        class StopBeforeNetwork(BaseException):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=StopBeforeNetwork) as scanners:
                for target in (
                    "https://GitHub.Com/acme/widget/",
                    "https://github.com/acme/widget.git",
                ):
                    with self.subTest(target=target):
                        with self.assertRaises(StopBeforeNetwork):
                            bounty.run_bounty_hunt(
                                target, "source-code", None, None,
                                "app.example.com\nhttps://github.com/acme/widget", True, {},
                                default_reports_dir=Path(tmp),
                            )
                self.assertEqual(scanners.call_count, 2)
                self.assertTrue(all(call.args[1] == "git" for call in scanners.call_args_list))

    def test_exclusion_overrides_exact_repository_grant(self) -> None:
        target = "https://github.com/acme/widget"
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=AssertionError("clone started")) as scanners:
                result = bounty.run_bounty_hunt(
                    target, "source-code", None, None, target, True, {},
                    settings=SimpleNamespace(excluded_hosts=("github.com",)),
                    default_reports_dir=Path(tmp),
                )
                self.assertFalse(result["ok"])
                self.assertIn("excluded", result["error"].lower())
                scanners.assert_not_called()

    def test_local_path_hunt_still_uses_local_scanner(self) -> None:
        class StopBeforeNetwork(BaseException):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=StopBeforeNetwork) as scanners:
                with self.assertRaises(StopBeforeNetwork):
                    bounty.run_bounty_hunt(
                        tmp, "source-code", None, None, "local QA fixture", True, {},
                        default_reports_dir=Path(tmp),
                    )
                scanners.assert_called_once()
                self.assertEqual(scanners.call_args.args[1], "path")


if __name__ == "__main__":
    unittest.main()
