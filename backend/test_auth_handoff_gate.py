"""The first protected response pauses URL hunts before active requests or exports."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty, operator_guard, web_scan_service  # noqa: E402
from bughunter.scan_auth import AuthContext  # noqa: E402


TARGET = "https://app.example.com/private?return_token=keep-private"
CONTEXT = {"reason": "http_401", "status": 401,
           "target_host": "app.example.com", "login_host": "app.example.com"}
WALL = {"ok": False, "scan_type": "web", "needs_operator": True,
        "operator_action": "authentication_required", "auth_context": CONTEXT,
        "error": "Authentication is required to continue this hunt."}
SUCCESS = {"ok": True, "scan_type": "web", "findings": [], "signals": [],
           "risk": "low", "score": 0, "status": 200,
           "final_url": "https://app.example.com/private", "finding_count": 0}


class AuthWallDetectorTests(unittest.TestCase):
    def test_credible_walls_and_false_positive_controls(self) -> None:
        samples = [
            ({"status": 401, "final_url": TARGET}, "http_401"),
            ({"status": 403, "headers": {"WWW-Authenticate": "Bearer"}, "final_url": TARGET},
             "http_403_challenge"),
            ({"status": 200, "final_url": "https://app.example.com/account/sign-in?state=hidden"},
             "login_redirect"),
            ({"status": 200, "final_url": TARGET,
              "body": '<form><input name="email"><input type="password"></form>'},
             "login_form"),
        ]
        for fetched, expected in samples:
            with self.subTest(expected=expected):
                context = web_scan_service.auth_wall_context(fetched, TARGET)
                self.assertEqual(context["reason"], expected)
                self.assertEqual(set(context), {"reason", "status", "target_host", "login_host"})
                self.assertNotIn("keep-private", json.dumps(context))

        self.assertIsNone(web_scan_service.auth_wall_context(
            {"status": 403, "final_url": TARGET}, TARGET))
        self.assertIsNone(web_scan_service.auth_wall_context(
            {"status": 200, "final_url": "https://app.example.com/private?next=/login"}, TARGET))
        self.assertEqual(web_scan_service.auth_wall_context(
            {"status": 401, "final_url": "https://app.example.com/login"},
            "https://app.example.com/login")["reason"], "http_401")
        self.assertIsNone(web_scan_service.auth_wall_context(
            {"status": 200, "final_url": "https://app.example.com/login",
             "body": '<form><input name="email"><input type="password"></form>'},
            "https://app.example.com/login"))
        self.assertIsNone(web_scan_service.auth_wall_context(
            {"status": 200, "final_url": TARGET,
             "body": '<form><input name="email"><input type="password"></form>'},
            TARGET, allow_form=False))
        self.assertIsNone(web_scan_service.auth_wall_context(
            {"status": 200, "final_url": TARGET,
             "body": ('<title>Product overview</title><main><h1>Public documentation</h1>'
                      '<p>Learn about features and browse the documentation.</p>'
                      '<a href="/docs">Docs</a><form><input name="email">'
                      '<input type="password"></form></main>')}, TARGET))
        self.assertEqual(web_scan_service.auth_wall_context(
            {"status": 200, "final_url": TARGET,
             "body": ('<title>Sign in</title><h1>Welcome back</h1><form>'
                      '<input name="email"><input type="password"></form>'
                      '<footer><a href="/terms">Terms</a><a href="/privacy">Privacy</a></footer>')},
            TARGET)["reason"], "login_form")
        self.assertIsNone(web_scan_service.auth_wall_context(
            {"status": 200, "final_url": TARGET,
             "body": ('<title>Acme products</title><h1>Products</h1><p>Browse products.</p>'
                      '<h2>Sign in</h2><form><input name="email">'
                      '<input type="password"></form>')}, TARGET))

    def test_wall_has_no_findings_or_sensitive_path_requests(self) -> None:
        fetched = {"status": 401, "final_url": TARGET, "headers": {"set-cookie": "session=secret"},
                   "body": "secret page body", "cookies": ["session=secret"], "truncated": False}
        with patch.object(web_scan_service, "_fetch_raw", return_value=fetched) as fetch, \
             patch.object(web_scan_service, "_probe_sensitive_paths") as paths, \
             patch.object(web_scan_service, "_analyze") as analyze:
            result = web_scan_service.run_web_scan(TARGET, probe_paths=True)
        self.assertFalse(result["ok"])
        self.assertTrue(result["needs_operator"])
        self.assertEqual(fetch.call_count, 1)
        paths.assert_not_called()
        analyze.assert_not_called()
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("keep-private", json.dumps(result))

    def test_authenticated_page_form_does_not_reprompt(self) -> None:
        fetched = {"status": 200, "final_url": TARGET, "headers": {},
                   "body": '<form><input name="email"><input type="password"></form>',
                   "cookies": [], "truncated": False}
        with patch.object(web_scan_service, "_fetch_raw", return_value=fetched):
            anonymous = web_scan_service.run_web_scan(TARGET)
            authenticated = web_scan_service.run_web_scan(
                TARGET, auth=AuthContext("app.example.com", {"Cookie": "session=valid"}))
        self.assertTrue(anonymous["needs_operator"])
        self.assertTrue(authenticated["ok"])


class HuntAuthHandoffTests(unittest.TestCase):
    def test_callback_binds_auth_and_retries_once(self) -> None:
        seen: list[AuthContext | None] = []
        prompted: list[dict] = []

        def scan(_url: str, **kwargs: object) -> dict:
            seen.append(kwargs.get("auth"))
            return WALL if len(seen) == 1 else SUCCESS

        def ask(context: dict) -> dict:
            prompted.append(context)
            return {"cookie": "session=operator-only-secret-123", "issuer_host": "login.example.com"}

        auth_state: dict = {"context": None}
        with patch.object(bounty, "run_web_scan", side_effect=scan):
            _raw, ran, meta, _risk, _score, _signals = bounty._run_scanners(
                bounty.BOUNTY_PROFILES["web-app"], "url", TARGET, 100, False,
                scope_host="app.example.com", on_auth_needed=ask, auth_state=auth_state)
        self.assertEqual(ran, ["web"])
        self.assertEqual(prompted, [CONTEXT])
        self.assertIsNone(seen[0])
        self.assertEqual(seen[1].headers["Cookie"], "session=operator-only-secret-123")
        self.assertIs(auth_state["context"], seen[1])
        self.assertNotIn("operator-only-secret-123", json.dumps(meta))

    def test_saved_login_retry_can_fall_back_to_one_operator_session(self) -> None:
        supplied = iter([
            {"cookie": "session=auto-ineffective", "issuer_host": "app.example.com",
             "_allow_operator_fallback": True},
            {"cookie": "session=operator-effective", "issuer_host": "app.example.com"},
        ])
        ask = Mock(side_effect=lambda _context: next(supplied))
        state: dict = {"context": None}
        with patch.object(bounty, "run_web_scan", side_effect=[WALL, WALL, SUCCESS]) as web:
            _raw, _ran, meta, _risk, _score, _signals = bounty._run_scanners(
                bounty.BOUNTY_PROFILES["web-app"], "url", TARGET, 100, False,
                scope_host="app.example.com", on_auth_needed=ask, auth_state=state)

        self.assertEqual(ask.call_count, 2)
        self.assertEqual(web.call_count, 3)
        self.assertNotIn("needs_operator", meta["web"])
        self.assertEqual(state["context"].headers["Cookie"], "session=operator-effective")
        self.assertNotIn("auto-ineffective", json.dumps(meta))
        self.assertNotIn("operator-effective", json.dumps(meta))

    def test_decline_and_bad_session_fail_closed_without_live_scan(self) -> None:
        for supplied in (None, {"cookie": "session=invalid"}):
            with self.subTest(supplied=supplied is not None):
                state: dict = {"context": None}
                with patch.object(bounty, "run_web_scan", return_value=WALL) as web, \
                     patch.object(bounty, "run_live_scan") as live:
                    _raw, ran, meta, _risk, _score, _signals = bounty._run_scanners(
                        bounty.BOUNTY_PROFILES["web-app"], "url", TARGET, 100, True,
                        scope_host="app.example.com", on_auth_needed=lambda _context: supplied,
                        auth_state=state)
                self.assertEqual(ran, ["web"])
                self.assertTrue(meta["web"]["needs_operator"])
                self.assertIsNone(state["context"])
                self.assertEqual(web.call_count, 1 if supplied is None else 2)
                live.assert_not_called()

    def test_ineffective_existing_auth_can_be_replaced_once(self) -> None:
        old = AuthContext("app.example.com", {"Cookie": "session=old"})
        state: dict = {"context": old}
        with patch.object(bounty, "run_web_scan", side_effect=[WALL, SUCCESS]) as web, \
             patch.object(bounty, "run_live_scan") as live:
            _raw, _ran, meta, _risk, _score, _signals = bounty._run_scanners(
                bounty.BOUNTY_PROFILES["web-app"], "url", TARGET, 100, True, old,
                scope_host="app.example.com", auth_state=state,
                on_auth_needed=lambda _context: {"cookie": "session=replacement"})
        self.assertNotIn("needs_operator", meta["web"])
        self.assertEqual(web.call_count, 2)
        self.assertEqual(web.call_args.kwargs["auth"].headers["Cookie"], "session=replacement")
        self.assertEqual(state["context"].headers["Cookie"], "session=replacement")
        live.assert_called_once()

    def test_expired_explicit_cookie_does_not_turn_login_form_into_active_coverage(self) -> None:
        fetched = {"status": 200, "final_url": TARGET, "headers": {},
                   "body": '<form><input name="email"><input type="password"></form>',
                   "cookies": [], "truncated": False}
        old = AuthContext("app.example.com", {"Cookie": "session=expired"})
        prompts: list[dict] = []
        with patch.object(web_scan_service, "_fetch_raw", return_value=fetched), \
             patch.object(web_scan_service, "_probe_sensitive_paths") as paths, \
             patch.object(bounty, "run_live_scan") as live:
            _raw, _ran, meta, _risk, _score, _signals = bounty._run_scanners(
                bounty.BOUNTY_PROFILES["web-app"], "url", TARGET, 100, True, old,
                scope_host="app.example.com", on_auth_needed=lambda context: prompts.append(context))
        self.assertTrue(meta["web"]["needs_operator"])
        self.assertEqual(len(prompts), 1)
        paths.assert_not_called()
        live.assert_not_called()

    def test_http_wall_never_requests_or_sends_interactive_session(self) -> None:
        http_target = "http://app.example.com/private"
        with patch.object(bounty, "run_web_scan", return_value=WALL) as web:
            _raw, _ran, meta, _risk, _score, _signals = bounty._run_scanners(
                bounty.BOUNTY_PROFILES["web-app"], "url", http_target, 100, False,
                scope_host="app.example.com",
                on_auth_needed=lambda _context: self.fail("HTTP must not prompt for a session"))
        self.assertEqual(web.call_count, 1)
        self.assertTrue(meta["web"]["needs_operator"])
        self.assertTrue(meta["web"]["secure_transport_required"])

    def test_stop_during_prompt_prevents_credential_retry(self) -> None:
        stopped = False

        def ask(_context: dict) -> dict:
            nonlocal stopped
            stopped = True
            return {"cookie": "session=unused"}

        with patch.object(bounty, "run_web_scan", return_value=WALL) as web:
            _raw, _ran, meta, _risk, _score, _signals = bounty._run_scanners(
                bounty.BOUNTY_PROFILES["web-app"], "url", TARGET, 100, False,
                scope_host="app.example.com", on_auth_needed=ask,
                should_stop=lambda: stopped)
        self.assertTrue(meta["web"]["needs_operator"])
        self.assertEqual(web.call_count, 1)

    def test_bad_cookie_cannot_turn_same_login_form_into_success(self) -> None:
        fetched = {"status": 200, "final_url": TARGET, "headers": {},
                   "body": '<form><input name="email"><input type="password"></form>',
                   "cookies": [], "truncated": False}
        state: dict = {"context": None}
        with patch.object(web_scan_service, "_fetch_raw", return_value=fetched) as fetch, \
             patch.object(web_scan_service, "_probe_sensitive_paths") as paths:
            _raw, _ran, meta, _risk, _score, _signals = bounty._run_scanners(
                bounty.BOUNTY_PROFILES["web-app"], "url", TARGET, 100, False,
                scope_host="app.example.com", auth_state=state,
                on_auth_needed=lambda _context: {"cookie": "session=bad"})
        self.assertTrue(meta["web"]["needs_operator"])
        self.assertIsNone(state["context"])
        self.assertEqual(fetch.call_count, 2)
        paths.assert_not_called()

    def test_hunt_exits_before_recon_active_and_report_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(bounty, "run_web_scan", return_value=WALL), \
             patch.object(bounty, "run_live_scan") as live, \
             patch.object(bounty.recon, "discover") as recon, \
             patch.object(bounty.active_verify_service, "verify_active") as active:
            result = bounty.run_bounty_hunt(
                TARGET, "web-app", None, tmp, "app.example.com", True, {},
                default_reports_dir=Path(tmp), active=True, run_live=True,
            )
            self.assertEqual(list(Path(tmp).iterdir()), [])
        self.assertEqual(result["operator_action"], "authentication_required")
        self.assertTrue(result["needs_operator"])
        self.assertNotIn("keep-private", json.dumps(result))
        live.assert_not_called()
        recon.assert_not_called()
        active.assert_not_called()

    def test_direct_hunt_recon_uses_prompted_session_and_stops_if_it_expires(self) -> None:
        session_cookie = "session=operator-only-secret-123"
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(bounty, "run_web_scan", side_effect=[WALL, SUCCESS]) as web, \
             patch.object(bounty.recon, "discover", return_value={"auth_wall": CONTEXT}) as discover, \
             patch.object(bounty.active_verify_service, "verify_active") as active:
            result = bounty.run_bounty_hunt(
                TARGET, "web-app", None, tmp, "app.example.com", True, {},
                default_reports_dir=Path(tmp), active=True,
                on_auth_needed=lambda _context: {"cookie": session_cookie},
            )
            self.assertEqual(list(Path(tmp).iterdir()), [])

        self.assertEqual(web.call_count, 2)
        self.assertTrue(result["needs_operator"])
        self.assertEqual(result["auth_context"], CONTEXT)
        self.assertNotIn(session_cookie, json.dumps(result))
        bound = discover.call_args.kwargs["auth"]
        self.assertIsInstance(bound, AuthContext)
        self.assertEqual(bound.headers["Cookie"], session_cookie)
        self.assertTrue(bound.https_only)
        self.assertTrue(discover.call_args.kwargs["https_only_auth"])
        self.assertTrue(discover.call_args.kwargs["detect_auth_wall"])
        self.assertTrue(discover.call_args.kwargs["verify_login_form"])
        active.assert_not_called()

    def test_direct_hunt_stops_when_recon_cannot_verify_the_session(self) -> None:
        for recon_result in ({"auth_seed_unverified": True}, operator_guard.GuardHalt("halted")):
            with self.subTest(guard_halt=isinstance(recon_result, Exception)), \
                 tempfile.TemporaryDirectory() as tmp, \
                 patch.object(bounty, "run_web_scan", return_value=SUCCESS), \
                 patch.object(bounty.recon, "discover",
                              side_effect=recon_result if isinstance(recon_result, Exception) else None,
                              return_value=recon_result if isinstance(recon_result, dict) else None), \
                 patch.object(bounty.active_verify_service, "verify_active") as active:
                if isinstance(recon_result, Exception):
                    with self.assertRaises(operator_guard.GuardHalt):
                        bounty.run_bounty_hunt(
                            TARGET, "web-app", None, tmp, "app.example.com", True, {},
                            default_reports_dir=Path(tmp), active=True,
                            auth={"cookie": "sid=secret", "https_only": True})
                else:
                    result = bounty.run_bounty_hunt(
                        TARGET, "web-app", None, tmp, "app.example.com", True, {},
                        default_reports_dir=Path(tmp), active=True,
                        auth={"cookie": "sid=secret", "https_only": True})
                    self.assertTrue(result["auth_seed_unverified"])
                    self.assertNotIn("sid=secret", json.dumps(result))
                self.assertEqual(list(Path(tmp).iterdir()), [])
                active.assert_not_called()


if __name__ == "__main__":
    unittest.main()
