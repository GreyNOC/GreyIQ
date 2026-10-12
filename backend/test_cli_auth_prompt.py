"""Operator authentication questions in the CLI stay scoped and out of output."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
import warnings
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_cli  # noqa: E402


WALL = {"reason": "http_401", "status": 401,
        "target_host": "app.example.com", "login_host": "app.example.com"}
NEEDS_AUTH = {"ok": False, "needs_operator": True,
              "operator_action": "authentication_required", "auth_context": WALL,
              "error": "Authentication is required to continue this hunt."}


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = gn_cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliAuthPromptTests(unittest.TestCase):
    def test_cookie_is_read_without_echo_and_bound_to_target(self) -> None:
        args = gn_cli.build_parser().parse_args([
            "hunt", "https://app.example.com/private", "--scope", "app.example.com", "-y",
        ])
        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
             mock.patch.object(gn_cli, "_can_ask_for_auth", return_value=True), \
             mock.patch.object(gn_cli, "_operator_line", return_value="c"), \
             mock.patch.object(gn_cli.getpass, "getpass", return_value="session=hidden-value") as hidden:
            auth = gn_cli._ask_for_hunt_auth(args, WALL)
        self.assertEqual(auth, {"cookie": "session=hidden-value", "headers": [],
                                "issuer_host": "app.example.com", "https_only": True})
        hidden.assert_called_once()
        self.assertNotIn("hidden-value", err.getvalue())

    def test_off_scope_login_url_is_rejected_before_password_prompt(self) -> None:
        args = gn_cli.build_parser().parse_args([
            "hunt", "https://app.example.com/private", "--scope", "*.example.com", "-y",
        ])
        with contextlib.redirect_stderr(io.StringIO()), \
             mock.patch.object(gn_cli, "_can_ask_for_auth", return_value=True), \
             mock.patch.object(gn_cli, "_operator_line", side_effect=["l", "https://outside.test/login"]), \
             mock.patch.object(gn_cli, "_operator_secret") as hidden:
            self.assertIsNone(gn_cli._ask_for_hunt_auth(args, WALL))
        hidden.assert_not_called()

    def test_hidden_input_does_not_fall_back_to_plaintext(self) -> None:
        def cannot_hide(*_args, **_kwargs):
            warnings.warn("no echo control", gn_cli.getpass.GetPassWarning)
            raise AssertionError("getpass must not continue to plaintext input")

        with contextlib.redirect_stderr(io.StringIO()), \
             mock.patch.object(gn_cli.getpass, "getpass", side_effect=cannot_hide):
            self.assertEqual(gn_cli._operator_secret("Token: "), "")

    def test_http_target_does_not_ask_for_secrets(self) -> None:
        args = gn_cli.build_parser().parse_args([
            "hunt", "http://app.example.com/private", "--scope", "app.example.com", "-y",
        ])
        with contextlib.redirect_stderr(io.StringIO()), \
             mock.patch.object(gn_cli, "_can_ask_for_auth", return_value=True), \
             mock.patch.object(gn_cli, "_operator_line") as question, \
             mock.patch.object(gn_cli, "_operator_secret") as hidden:
            self.assertIsNone(gn_cli._ask_for_hunt_auth(args, WALL))
        question.assert_not_called()
        hidden.assert_not_called()

    def test_hunt_uses_engine_request_once_after_authorization(self) -> None:
        secret = "session=memory-only"

        def engine(*_args, **kwargs):
            self.assertEqual(kwargs["auth"], {"cookie": "", "headers": []})
            self.assertEqual(kwargs["on_auth_needed"](WALL)["cookie"], secret)
            return {"ok": True, "target": "https://app.example.com/private"}

        with mock.patch("bughunter.bounty.run_bounty_hunt", side_effect=engine) as run, \
             mock.patch.object(gn_cli, "_can_ask_for_auth", return_value=True), \
             mock.patch.object(gn_cli, "_ask_for_hunt_auth", return_value={
                 "cookie": secret, "headers": [], "issuer_host": "app.example.com",
             }) as ask:
            code, out, err = run_cli([
                "hunt", "https://app.example.com/private", "--scope", "app.example.com",
                "-y", "--no-fx",
            ])
        self.assertEqual(code, 0, err)
        run.assert_called_once()
        ask.assert_called_once()
        self.assertNotIn(secret, out + err)

    def test_json_returns_operator_request_without_reading_stdin(self) -> None:
        with mock.patch("bughunter.bounty.run_bounty_hunt", return_value=NEEDS_AUTH) as run, \
             mock.patch.object(gn_cli, "_ask_for_hunt_auth") as ask:
            code, out, err = run_cli([
                "hunt", "https://app.example.com/private", "--scope", "app.example.com",
                "-y", "--json",
            ])
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(out)["needs_operator"])
        self.assertIsNone(run.call_args.kwargs["on_auth_needed"])
        self.assertIn("Authentication is required", err)
        ask.assert_not_called()

    def test_unauthorized_hunt_cannot_prompt(self) -> None:
        with mock.patch("bughunter.bounty.run_bounty_hunt") as run, \
             mock.patch.object(gn_cli, "_ask_for_hunt_auth") as ask:
            code, _, err = run_cli([
                "hunt", "https://app.example.com/private", "--scope", "app.example.com",
            ])
        self.assertEqual(code, 2)
        self.assertIn("authorize", err)
        run.assert_not_called()
        ask.assert_not_called()

    def test_campaign_forwards_callback_without_disabling_account_access(self) -> None:
        with mock.patch("bughunter.campaign.run_campaign", return_value={"ok": True}) as run, \
             mock.patch.object(gn_cli, "_can_ask_for_auth", return_value=True):
            code, _, err = run_cli([
                "campaign", "https://app.example.com/private", "--scope", "app.example.com",
                "-y", "--no-fx",
            ])
        self.assertEqual(code, 0, err)
        self.assertIsNone(run.call_args.kwargs["auth"])
        self.assertTrue(callable(run.call_args.kwargs["on_auth_needed"]))

    def test_dash_asks_only_after_restoring_screen_and_retries_once(self) -> None:
        import gn_dash
        import gn_tui

        calls: list[dict] = []

        def fake_hunt(args, _run_id, into):
            calls.append(gn_cli._hunt_auth(args))
            into["result"] = NEEDS_AUTH if len(calls) == 1 else {"ok": True}
            return 2 if len(calls) == 1 else 0

        def fake_run(_source, **kwargs):
            return kwargs["launch"]()

        with mock.patch.object(gn_tui, "refusal", return_value=""), \
             mock.patch.object(gn_tui, "terminal_size", return_value=(80, 24)), \
             mock.patch.object(gn_dash, "size_refusal", return_value=""), \
             mock.patch.object(gn_dash, "run", side_effect=fake_run), \
             mock.patch.object(gn_cli, "_dash_hunt", side_effect=fake_hunt), \
             mock.patch.object(gn_cli, "_can_ask_for_auth", return_value=True), \
             mock.patch.object(gn_cli, "_ask_for_hunt_auth", return_value={
                 "cookie": "session=hidden", "headers": [], "issuer_host": "app.example.com",
             }) as ask, \
             mock.patch.object(gn_cli, "_print_hunt_summary"):
            code, _, err = run_cli([
                "dash", "https://app.example.com/private", "--scope", "app.example.com", "-y",
            ])
        self.assertEqual(code, 0, err)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1]["cookie"], "session=hidden")
        ask.assert_called_once()

    def test_dash_http_wall_does_not_open_secret_prompt(self) -> None:
        import gn_dash
        import gn_tui

        wall = {**NEEDS_AUTH, "secure_transport_required": True,
                "error": "An HTTPS target is required before an operator session can be requested."}

        def fake_hunt(_args, _run_id, into):
            into["result"] = wall
            return 2

        with mock.patch.object(gn_tui, "refusal", return_value=""), \
             mock.patch.object(gn_tui, "terminal_size", return_value=(80, 24)), \
             mock.patch.object(gn_dash, "size_refusal", return_value=""), \
             mock.patch.object(gn_dash, "run", side_effect=lambda _source, **kw: kw["launch"]()), \
             mock.patch.object(gn_cli, "_dash_hunt", side_effect=fake_hunt), \
             mock.patch.object(gn_cli, "_can_ask_for_auth", return_value=True), \
             mock.patch.object(gn_cli, "_ask_for_hunt_auth") as ask:
            code, _, err = run_cli([
                "dash", "http://app.example.com/private", "--scope", "app.example.com", "-y",
            ])
        self.assertEqual(code, 2)
        self.assertIn("HTTPS", err)
        ask.assert_not_called()


if __name__ == "__main__":
    unittest.main()
