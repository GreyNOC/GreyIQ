"""Authorization, cancellation, and defensive-stop tests for unattended hunts."""

from __future__ import annotations

import sys
import json
import os
import http.client
import tempfile
import threading
import types
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError
from urllib.request import ProxyHandler

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import account_login_service, active_verify_service, bounty, campaign, operator_guard, portfolio, progress, recon, web_scan_service  # noqa: E402
from bughunter.operator import OperatorLoop, run_program_cycle  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


def _spec(pid: str, **overrides) -> dict:
    now = datetime.now(UTC)
    return {
        "program_id": pid,
        "authorization_ref": "GreyNOC engagement record GN-TEST",
        "policy_source": "https://example.com/security-policy",
        "policy_checked_at": now.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "max_cycles": 2,
        "max_requests_per_cycle": 5,
        **overrides,
    }


class OperatorGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.rt = self.tmp.name
        self.program = portfolio.upsert_program(self.rt, {
            "id": "example", "name": "Example", "scope_text": "example.com",
            "seed_targets": ["https://example.com"], "active": True,
        })

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _grant(self, **spec_overrides):
        [grant] = operator_guard.create_grants(
            portfolio.list_programs(self.rt), [_spec("example", **spec_overrides)]
        ).values()
        return grant

    def test_start_requires_complete_documented_grants(self) -> None:
        loop = OperatorLoop(self.rt, run_campaign_fn=lambda *args, **kwargs: {})
        with self.assertRaisesRegex(ValueError, "explicit authorization grants"):
            loop.start()
        with self.assertRaisesRegex(ValueError, "authorization_ref"):
            loop.start(grants=[_spec("example", authorization_ref="")])
        with self.assertRaisesRegex(ValueError, "policy_source"):
            loop.start(grants=[_spec("example", policy_source="")])
        with self.assertRaisesRegex(ValueError, "URL credentials, query"):
            loop.start(grants=[_spec("example", policy_source="https://example.com/policy?token=hidden")])
        with self.assertRaisesRegex(ValueError, "grant expiry"):
            loop.start(grants=[_spec("example", expires_at=(datetime.now(UTC) + timedelta(days=8)).isoformat())])
        self.assertFalse(loop.running)

    def test_added_enabled_program_requires_its_own_grant(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "other", "name": "Other", "scope_text": "other.com",
                                           "seed_targets": ["https://other.com"]})
        with self.assertRaisesRegex(ValueError, "Missing authorization grants"):
            operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])

    def test_out_of_scope_seed_is_rejected_before_campaign(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": "example.com",
                                           "seed_targets": ["https://other.com"], "active": True})
        called = []
        loop = OperatorLoop(self.rt, run_campaign_fn=lambda *args, **kwargs: called.append(args))
        with self.assertRaisesRegex(ValueError, "outside the saved scope"):
            loop.start(grants=[_spec("example")])
        self.assertEqual(called, [])

    def test_ineligible_structured_host_narrows_handwritten_scope(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": "example.com",
                                           "seed_targets": ["https://admin.example.com"],
                                           "structured_scope": [{"identifier": "admin.example.com",
                                                                 "eligible_for_submission": False}],
                                           "out_of_scope_hosts": []})
        current = portfolio.get_program(self.rt, "example")
        self.assertEqual(current["out_of_scope_hosts"], [])
        self.assertFalse(operator_guard.web_url_allowed(current, "https://admin.example.com"))
        with self.assertRaisesRegex(ValueError, "outside the saved scope"):
            operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])

    def test_eligible_asset_list_cannot_be_widened_by_handwritten_scope(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": "example.com",
                                           "seed_targets": ["https://other.example.com"],
                                           "in_scope_hosts": ["app.example.com"],
                                           "structured_scope": [{"identifier": "app.example.com",
                                                                 "eligible_for_submission": True}]})
        current = portfolio.get_program(self.rt, "example")
        self.assertFalse(operator_guard.web_url_allowed(current, "https://other.example.com"))
        with self.assertRaisesRegex(ValueError, "outside the saved scope"):
            operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": "example.com",
                                           "seed_targets": ["https://app.example.com"],
                                           "in_scope_hosts": [],
                                           "structured_scope": [{"identifier": "https://app.example.com/app/",
                                                                 "eligible_for_submission": True}]})
        with self.assertRaisesRegex(ValueError, "host-only tokens"):
            operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])

    def test_repo_scope_does_not_authorize_forge_web_crawl_or_auto_clone(self) -> None:
        repo = "https://github.com/acme/private-test"
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": repo,
                                           "seed_targets": ["https://github.com/other"], "active": True})
        current = portfolio.get_program(self.rt, "example")
        self.assertFalse(operator_guard.web_url_allowed(current, "https://github.com/other"))
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": repo,
                                           "seed_targets": [], "repository_urls": [repo], "clone_repositories": True})
        with self.assertRaisesRegex(ValueError, "repository cloning requires a manual run"):
            operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])

    def test_auto_scope_rejects_path_scheme_port_and_query_restrictions(self) -> None:
        for scope in ("https://example.com/", "https://example.com/app/", "example.com:8443",
                      "example.com/app", "example.com?view=public"):
            with self.subTest(scope=scope):
                portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": scope,
                                                   "seed_targets": ["https://example.com"]})
                with self.assertRaisesRegex(ValueError, "host-only tokens"):
                    operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example",
                                           "scope_text": "127.0.0.1", "seed_targets": ["http://127.0.0.1"]})
        with self.assertRaisesRegex(ValueError, "IP literal"):
            operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])

    def test_wildcard_does_not_authorize_apex(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": "*.example.com",
                                           "seed_targets": ["https://example.com"]})
        with self.assertRaisesRegex(ValueError, "outside the saved scope"):
            operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": "*.example.com",
                                           "seed_targets": ["https://app.example.com"]})
        current = portfolio.get_program(self.rt, "example")
        self.assertFalse(operator_guard.web_url_allowed(current, "https://example.com"))
        self.assertTrue(operator_guard.web_url_allowed(current, "https://app.example.com"))

    def test_policy_profile_narrows_hosts_and_paths(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example",
                                           "scope_text": "nasa.gov other.example.com",
                                           "seed_targets": ["https://other.example.com"],
                                           "policy_profile": "nasa"})
        current = portfolio.get_program(self.rt, "example")
        self.assertFalse(operator_guard.web_url_allowed(current, "https://other.example.com"))
        self.assertTrue(operator_guard.web_url_allowed(current, "https://nasa.gov"))
        self.assertFalse(operator_guard.web_url_allowed(current, "https://nasa.gov/xmlrpc.php"))
        self.assertFalse(operator_guard.web_url_allowed(current, "https://nasa.gov/%77p-json/wp/v2/users"))
        self.assertFalse(operator_guard.web_url_allowed(current, "https://nasa.gov/%2577p-json/wp/v2/users"))
        self.assertFalse(operator_guard.web_url_allowed(current, "https://nasa.gov/a/../wp-json/wp/v2/users"))
        with self.assertRaisesRegex(ValueError, "outside the saved scope"):
            operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])

    def test_live_deep_and_account_sessions_stay_manual(self) -> None:
        for extra in ({"live": True}, {"deep": True}, {"account_access": {"cookie": "session=x"}}):
            with self.subTest(extra=extra):
                portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": "example.com",
                                                   "seed_targets": ["https://example.com"], "active": True,
                                                   "live": False, "deep": False, "account_access": {}, **extra})
                with self.assertRaisesRegex(ValueError, "manual run"):
                    operator_guard.create_grants(portfolio.list_programs(self.rt), [_spec("example")])

    def test_saved_research_account_requires_explicit_grant_and_https_login(self) -> None:
        account = {"cookie": "session=operator-owned", "login_url": "https://example.com/login"}
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": account})
        with self.assertRaisesRegex(ValueError, "allow_account_access=true"):
            self._grant()
        grant = self._grant(allow_account_access=True)
        self.assertTrue(grant.allow_account_access)
        self.assertFalse(grant.allow_login_post)
        self.assertEqual(grant.account_login_url, "https://example.com/login")
        self.assertNotIn(account["cookie"], repr(grant))
        ephemeral = operator_guard.RunGuard(self.rt, grant, threading.Event())
        ephemeral.research_auth = {"cookie": account["cookie"]}
        self.assertNotIn(account["cookie"], repr(ephemeral))
        cookie_only = operator_guard.RunGuard(self.rt, grant, threading.Event())
        with operator_guard.bind(cookie_only), operator_guard.saved_login_submission():
            with self.assertRaisesRegex(operator_guard.GuardHalt, "exact approved login POST"):
                cookie_only.before_request("https://example.com/login", method="POST")
        self.assertEqual(cookie_only.requests_used, 0)
        with self.assertRaisesRegex(ValueError, "true or false"):
            self._grant(allow_account_access="true")

    def test_two_target_operator_cycle_reuses_one_guarded_research_session(self) -> None:
        access = {"cookie": "session=stale", "email": "researcher@example.com",
                  "password": "stored-secret", "login_url": "https://app.example.com/login"}
        portfolio.upsert_program(self.rt, {
            "id": "example", "scope_text": "*.example.com",
            "seed_targets": ["https://app.example.com/one", "https://api.example.com/two"],
            "account_access": access,
        })
        program = portfolio.get_program(self.rt, "example")
        guard = operator_guard.RunGuard(
            self.rt, self._grant(allow_account_access=True), threading.Event())
        session = {"cookie": "session=fresh-one", "issuer_host": "app.example.com", "https_only": True}
        next_session = {"cookie": "session=fresh-two", "issuer_host": "app.example.com", "https_only": True}
        seen: list[tuple[str, dict]] = []

        def campaign_fn(target: str, **kwargs):
            return campaign.run_campaign(
                target, scope=kwargs["scope"], authorized=True, coder_cfg={},
                default_reports_dir=Path(self.rt), program=kwargs["program"],
                account_access=access,
            )

        def body(target: str, **kwargs):
            seen.append((target, kwargs["auth"]))
            return {"ok": True, "findings": [], "proof_of_impact": {}}

        with patch.object(campaign, "_login_auth", side_effect=[session, next_session]) as login, \
             patch.object(campaign, "_run_campaign_body", side_effect=body):
            summary = run_program_cycle(
                self.rt, program, run_campaign_fn=campaign_fn, guard=guard)
            next_guard = operator_guard.RunGuard(
                self.rt, guard.grant, threading.Event())
            next_summary = run_program_cycle(
                self.rt, program, run_campaign_fn=campaign_fn, guard=next_guard)

        self.assertEqual(summary["targets_run"], 2)
        self.assertEqual(next_summary["targets_run"], 2)
        self.assertEqual(login.call_count, 2, "each new cycle must resolve its own session")
        self.assertTrue(all(call.args[0]["cookie"] == "" for call in login.call_args_list))
        self.assertEqual([target for target, _ in seen],
                         ["https://app.example.com/one", "https://api.example.com/two"] * 2)
        self.assertIs(seen[0][1], session)
        self.assertIs(seen[1][1], session)
        self.assertIs(seen[2][1], next_session)
        self.assertIs(seen[3][1], next_session)
        self.assertIs(guard.research_auth, session)
        self.assertTrue(guard.research_auth_resolved)
        self.assertEqual(guard.research_auth_program, "example")
        self.assertIs(next_guard.research_auth, next_session)
        self.assertEqual(access["cookie"], "session=stale")

    def test_account_grant_refuses_ambiguous_or_out_of_scope_login(self) -> None:
        for login_url in (
            "http://example.com/login", "https://user:password@example.com/login",
            "https://example.com/login?next=/private", "https://example.com/login#state",
            "https://other.example.com/login", "https://example.com:8443/login",
            "https://example.com/a/../login", "https://example.com/log%69n",
        ):
            with self.subTest(login_url=login_url):
                portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
                    "cookie": "session=operator-owned", "login_url": login_url,
                }})
                with self.assertRaises(ValueError):
                    self._grant(allow_account_access=True)

    def test_account_grant_requires_saved_credentials_and_https_seeds(self) -> None:
        with self.assertRaisesRegex(ValueError, "saved research account"):
            self._grant(allow_account_access=True)
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "email": "researcher@example.com", "login_url": "https://example.com/login",
        }})
        with self.assertRaisesRegex(ValueError, "cookie or email and password"):
            self._grant(allow_account_access=True)
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "cookie": "session=operator-owned",
        }})
        with self.assertRaisesRegex(ValueError, "identify the issuer"):
            self._grant(allow_account_access=True)
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "cookie": "session=operator-owned", "login_url": "https://example.com/login",
        }, "seed_targets": ["http://example.com/"]})
        with self.assertRaisesRegex(ValueError, "HTTPS seed"):
            self._grant(allow_account_access=True)

    def test_account_grant_allows_only_exact_login_post(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "email": "researcher@example.com", "password": "operator-owned-password",
            "login_url": "https://example.com/login",
        }})
        grant = self._grant(allow_account_access=True)
        guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
        with self.assertRaisesRegex(operator_guard.GuardHalt, "exact approved login POST"):
            guard.before_request("https://example.com/login", method="POST", reserve=True)
        self.assertEqual(guard.requests_used, 0)
        guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
        with operator_guard.bind(guard), operator_guard.saved_login_submission():
            guard.before_request("https://example.com/login", method="POST", reserve=True)
            with self.assertRaisesRegex(operator_guard.GuardHalt, "already submitted"):
                guard.before_request("https://example.com/login", method="POST", reserve=True)
        self.assertEqual(guard.requests_used, 1)
        self.assertEqual(guard.login_posts_used, 1)
        for target, method in (
            ("https://example.com/private", "POST"),
            ("https://example.com/login/", "POST"),
            ("https://example.com/login?token=1", "POST"),
            ("http://example.com/login", "POST"),
            ("https://example.com/login", "PUT"),
        ):
            with self.subTest(target=target, method=method):
                blocked = operator_guard.RunGuard(self.rt, grant, threading.Event())
                with operator_guard.bind(blocked), operator_guard.saved_login_submission():
                    with self.assertRaises(operator_guard.GuardHalt):
                        blocked.before_request(target, method=method, reserve=True)
                self.assertEqual(blocked.requests_used, 0)
                self.assertTrue(blocked.stop_event.is_set())

    def test_playwright_route_method_reaches_unattended_guard(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "email": "researcher@example.com", "password": "operator-owned-password",
            "login_url": "https://example.com/login",
        }})
        grant = self._grant(allow_account_access=True)
        guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
        with operator_guard.bind(guard), \
             operator_guard.saved_login_submission(), \
             patch.object(web_scan_service, "_guard_url", side_effect=lambda url, *_args: url):
            self.assertTrue(web_scan_service.playwright_request_allowed(
                "https://example.com/login", False, frozenset({443}), method="POST"))
        self.assertEqual(guard.requests_used, 1)
        blocked = operator_guard.RunGuard(self.rt, grant, threading.Event())
        with operator_guard.bind(blocked), \
             operator_guard.saved_login_submission(), \
             patch.object(web_scan_service, "_guard_url", side_effect=lambda url, *_args: url):
            self.assertFalse(web_scan_service.playwright_request_allowed(
                "https://example.com/private", False, frozenset({443}), method="POST"))
        self.assertEqual(blocked.requests_used, 0)
        self.assertTrue(blocked.stop_event.is_set())

    def test_saved_login_form_requires_post_to_exact_approved_action(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "email": "researcher@example.com", "password": "operator-owned-password",
            "login_url": "https://example.com/login",
        }})
        grant = self._grant(allow_account_access=True)
        approved = operator_guard.RunGuard(self.rt, grant, threading.Event())
        approved.check_saved_login_form("post", "https://example.com/login")
        self.assertEqual(approved.requests_used, 0)
        for method, action in (("GET", "https://example.com/login"),
                               ("POST", "https://example.com/other"),
                               ("POST", "https://example.com/login?next=private"),
                               ("POST", "http://example.com/login")):
            with self.subTest(method=method, action=action):
                guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
                with self.assertRaises(operator_guard.GuardHalt):
                    guard.check_saved_login_form(method, action)
                self.assertTrue(guard.stop_event.is_set())

    def test_unattended_get_never_carries_saved_credentials_in_query(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "email": "researcher@example.com", "password": "operator-owned-password",
            "login_url": "https://example.com/login",
        }})
        grant = self._grant(allow_account_access=True)
        for url in ("https://example.com/?email=researcher%40example.com",
                    "https://example.com/?password=operator-owned-password"):
            with self.subTest(url=url):
                guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
                with self.assertRaisesRegex(operator_guard.GuardHalt, "credential appeared"):
                    guard.before_request(url)
                self.assertEqual(guard.requests_used, 0)
                self.assertNotIn("operator-owned-password", guard.halt_reason)

    def _run_mocked_saved_login(self, page: MagicMock, guard: operator_guard.RunGuard,
                               context: MagicMock | None = None) -> dict:
        context = context or MagicMock()
        context.new_page.return_value = page
        browser = MagicMock()
        browser.new_context.return_value = context
        playwright = MagicMock()
        playwright.chromium.launch.return_value = browser
        manager = MagicMock()
        manager.__enter__.return_value = playwright
        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = lambda: manager  # type: ignore[attr-defined]
        package = types.ModuleType("playwright")
        package.sync_api = api  # type: ignore[attr-defined]
        with operator_guard.bind(guard), \
             patch.object(account_login_service, "ensure_bundled_browsers_path"), \
             patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}):
            return account_login_service._playwright_login(
                "https://example.com/login", "example.com", "researcher@example.com",
                "operator-owned-password", "example.com", get_settings())

    def test_unattended_browser_rejects_get_form_before_filling_credentials(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "email": "researcher@example.com", "password": "operator-owned-password",
            "login_url": "https://example.com/login",
        }})
        grant = self._grant(allow_account_access=True)
        for form, reason in (
            ({"method": "GET", "action": "https://example.com/login"}, "must submit by POST"),
            ({"unsafe_submit": True}, "submit override"),
        ):
            with self.subTest(form=form):
                guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
                page = MagicMock()
                page.evaluate.return_value = ""
                page.query_selector.return_value.is_visible.return_value = True
                page.eval_on_selector.return_value = form
                with self.assertRaisesRegex(operator_guard.GuardHalt, reason):
                    self._run_mocked_saved_login(page, guard)
                page.fill.assert_not_called()
                page.click.assert_not_called()
                self.assertEqual(guard.requests_used, 0)

    def test_unattended_browser_stops_429_and_body_challenge_before_credentials(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "email": "researcher@example.com", "password": "operator-owned-password",
            "login_url": "https://example.com/login",
        }})
        grant = self._grant(allow_account_access=True)
        for scenario, body, status, expected in (
            ("rate limit", "", 429, "429"),
            ("body challenge", "<html>checking your browser</html>", 200, "challenge"),
        ):
            with self.subTest(scenario=scenario):
                guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
                page = MagicMock()
                context = MagicMock()
                page.evaluate.return_value = body
                callbacks: dict[str, object] = {}
                context.on.side_effect = lambda event, callback: callbacks.__setitem__(event, callback)
                response = types.SimpleNamespace(
                    status=status, headers={},
                    request=types.SimpleNamespace(resource_type="document"),
                )
                page.goto.side_effect = lambda *_args, **_kwargs: callbacks["response"](response)
                with self.assertRaisesRegex(operator_guard.GuardHalt, expected):
                    self._run_mocked_saved_login(page, guard, context)
                page.fill.assert_not_called()
                page.click.assert_not_called()
                self.assertTrue(guard.stop_event.is_set())

    def test_unattended_browser_requires_visible_submit_instead_of_enter(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "email": "researcher@example.com", "password": "operator-owned-password",
            "login_url": "https://example.com/login",
        }})
        guard = operator_guard.RunGuard(self.rt, self._grant(allow_account_access=True), threading.Event())
        page = MagicMock()
        page.evaluate.return_value = ""
        visible = MagicMock()
        visible.is_visible.return_value = True
        page.query_selector.side_effect = lambda selector: (
            visible if selector in {"input[type=email]", "input[type=password]"} else None)
        with self.assertRaisesRegex(operator_guard.GuardHalt, "visible submit control"):
            self._run_mocked_saved_login(page, guard)
        page.fill.assert_not_called()
        page.press.assert_not_called()
        self.assertEqual(guard.requests_used, 0)

    def test_browser_response_headers_halt_without_secret_output(self) -> None:
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        class Response:
            status = 429
            headers = {"set-cookie": "session=secret", "cf-mitigated": "challenge"}
        operator_guard.observe_playwright_response(Response(), guard=guard)
        self.assertTrue(guard.stop_event.is_set())
        self.assertNotIn("secret", guard.halt_reason)
        with self.assertRaises(operator_guard.GuardHalt):
            guard.check_current()

    def test_account_grant_revokes_on_credential_change_and_still_halts_on_401(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "cookie": "session=first", "login_url": "https://example.com/login",
        }})
        grant = self._grant(allow_account_access=True)
        guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
        with self.assertRaisesRegex(operator_guard.GuardHalt, "authentication boundary"):
            guard.observe_response({"status": 401, "headers": {}, "body": ""}, stage="headers")
        portfolio.upsert_program(self.rt, {"id": "example", "account_access": {
            "cookie": "session=second", "login_url": "https://example.com/login",
        }})
        changed = operator_guard.RunGuard(self.rt, grant, threading.Event())
        with self.assertRaisesRegex(operator_guard.GuardHalt, "changed"):
            changed.before_request("https://example.com/login", method="POST")

    def test_grant_is_revoked_by_scope_or_settings_change(self) -> None:
        grant = self._grant()
        guard = operator_guard.RunGuard(self.rt, grant, threading.Event())
        self.assertEqual(guard.check_current()["id"], "example")
        portfolio.upsert_program(self.rt, {"id": "example", "name": "Example", "scope_text": "example.com",
                                           "seed_targets": ["https://example.com"], "active": False})
        with self.assertRaisesRegex(operator_guard.GuardHalt, "changed"):
            guard.before_request("https://example.com")
        self.assertTrue(guard.stop_event.is_set())

    def test_run_timestamps_do_not_revoke_grant(self) -> None:
        grant = self._grant()
        portfolio.touch_run(self.rt, "example", next_run_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat())
        self.assertEqual(grant.current_reason(portfolio.get_program(self.rt, "example")), "")

    def test_request_scope_method_and_cycle_budget_fail_closed(self) -> None:
        guard = operator_guard.RunGuard(self.rt, self._grant(max_requests_per_cycle=1), threading.Event())
        guard.before_request("https://example.com", reserve=True)
        with self.assertRaisesRegex(operator_guard.GuardHalt, "budget"):
            guard.before_request("https://example.com/second", reserve=True)
        guard2 = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with self.assertRaisesRegex(operator_guard.GuardHalt, "method"):
            guard2.before_request("https://example.com", method="POST")
        guard3 = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with self.assertRaisesRegex(operator_guard.GuardHalt, "scope"):
            guard3.before_request("https://other.com")

    def test_defensive_responses_halt_and_preserve_reason(self) -> None:
        cases = [
            ({"status": 401, "headers": {}, "body": ""}, "authentication boundary"),
            ({"status": 429, "headers": {}, "body": ""}, "429"),
            ({"status": 403, "headers": {"cf-mitigated": "challenge"}, "body": ""}, "challenge"),
            ({"status": 200, "headers": {"cf-mitigated": "challenge"}, "body": ""}, "challenge"),
            ({"status": 302, "headers": {}, "body": "verify you are human"}, "challenge"),
            ({"status": 200, "headers": {}, "body": "x" * 5000 + "verify you are human"}, "challenge"),
        ]
        for response, reason in cases:
            with self.subTest(response=response):
                guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
                with self.assertRaisesRegex(operator_guard.GuardHalt, reason):
                    guard.observe_response(response)
                self.assertTrue(guard.stop_event.is_set())
                self.assertIn(reason, guard.halt_reason)
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        for _ in range(4):
            guard.observe_response({"status": 403, "headers": {}, "body": "denied"})
        with self.assertRaisesRegex(operator_guard.GuardHalt, "repeatedly"):
            guard.observe_response({"status": 403, "headers": {}, "body": "denied"})
        split = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        split.observe_response({"status": 403, "headers": {}, "body": ""}, stage="headers")
        split.observe_response({"status": 403, "headers": {}, "body": "denied"}, stage="body")
        self.assertEqual(split.consecutive_403, 1)

    def test_sensitive_response_pauses_and_audit_contains_no_secret(self) -> None:
        key = "sk-" + "A" * 32
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event(), session_id="test-session")
        guard.observe_response({"status": 200, "headers": {}, "body": f"token = {key}",
                                "final_url": "https://example.com/public?token=must-not-log"})
        self.assertTrue(guard.stop_event.is_set())
        with self.assertRaisesRegex(operator_guard.GuardHalt, "sensitive information"):
            guard.before_request("https://example.com/next")
        log = (Path(self.rt) / "operator_authorization_audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(key, log)
        self.assertNotIn("must-not-log", log)
        row = json.loads(log.splitlines()[0])
        self.assertEqual(row["event"], "sensitive_exposure")
        self.assertEqual(row["response_host"], "example.com")
        self.assertEqual(len(row["body_sha256"]), 64)

    def test_sensitive_response_after_first_128kb_still_pauses(self) -> None:
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        guard.observe_response({"status": 200, "headers": {},
                                "body": "x" * 140000 + " token = sk-" + "C" * 32,
                                "final_url": "https://example.com/"})
        self.assertTrue(guard.stop_event.is_set())
        self.assertIn("sensitive information", guard.halt_reason)

    def test_validated_env_probe_stops_before_another_path(self) -> None:
        class Governor:
            def throttle(self, host): return True
        calls = []
        def fake_fetch(url, **kwargs):
            calls.append(url)
            body = "PRIVATE_CONFIG=abcdefgh" if url.endswith("/.env") else "not found"
            return {"status": 200 if url.endswith("/.env") else 404, "headers": {},
                    "body": body, "final_url": url}
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with operator_guard.bind(guard), patch.object(web_scan_service, "_fetch_raw", side_effect=fake_fetch):
            found = web_scan_service._probe_sensitive_paths("https://example.com", Governor())
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["rule_id"], "web.exposed-path.env")
        self.assertEqual(len(calls), 3)
        self.assertTrue(guard.stop_event.is_set())

    def test_web_scan_keeps_sensitive_finding_without_further_probes(self) -> None:
        key = "sk-" + "B" * 32
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        fetched = {"status": 200, "headers": {}, "cookies": [], "body": f"token = {key}",
                   "final_url": "https://example.com", "requested_url": "https://example.com",
                   "truncated": False}
        def fake_fetch(url, **kwargs):
            guard.observe_response(fetched)
            return fetched
        with operator_guard.bind(guard), \
             patch.object(web_scan_service, "_fetch_raw", side_effect=fake_fetch), \
             patch.object(web_scan_service, "_probe_sensitive_paths") as more:
            result = web_scan_service.run_web_scan("https://example.com", probe_paths=True)
        self.assertTrue(result["ok"])
        self.assertTrue(guard.stop_event.is_set())
        self.assertTrue(any(f["rule_id"].startswith("web.exposed.") for f in result["findings"]))
        more.assert_not_called()

    def test_unattended_hunt_never_calls_credential_issuers_or_oob(self) -> None:
        class ReachedClassification(Exception):
            pass
        finding = {"rule_id": "secret.github-pat", "secret_value": "ghp_" + "x" * 36,
                   "file_path": "https://example.com"}
        issuer_calls: list[str] = []
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with operator_guard.bind(guard), \
             patch.object(bounty, "_run_scanners", return_value=([finding], ["web"], {"web": {}}, "low", 0.1, [])), \
             patch.object(bounty.hunt_loop, "iterative_enabled", return_value=False), \
             patch.object(bounty.active_verify_service, "verify_active", return_value=([], {"in_scope": True})), \
             patch.object(bounty.oob_service, "confirm_blind_ssrf") as ssrf, \
             patch.object(bounty.oob_service, "confirm_blind_xxe") as xxe, \
             patch.object(bounty.oob_service, "confirm_blind_rce") as rce, \
             patch.object(bounty.oob_service, "confirm_jwt_key_injection") as jwt_key, \
             patch.dict(bounty._TOKEN_ISSUER_VALIDATORS, {"secret.github-pat": lambda key: issuer_calls.append(key)}), \
             patch.object(bounty.credential_validation, "validate_aws_key") as aws, \
             patch.object(bounty.credential_validation, "validate_firebase_key") as firebase, \
             patch.object(bounty.credential_validation, "probe_firebase_exposure") as exposure, \
             patch.object(bounty.secret_classification, "apply_secret_classification", side_effect=ReachedClassification):
            with self.assertRaises(ReachedClassification):
                bounty._run_bounty_hunt_body(
                    "https://example.com", "web-app", None, None, "example.com", True, None,
                    default_reports_dir=Path(self.rt), active=True, extra_params=[], class_priority=[],
                    validate_credential_issuers=True,
                    oob_base="https://collaborator.example", oob_secret="configured",
                )
            ssrf.assert_not_called()
            xxe.assert_not_called()
            rce.assert_not_called()
            jwt_key.assert_not_called()
            self.assertEqual(issuer_calls, [])
            aws.assert_not_called()
            firebase.assert_not_called()
            exposure.assert_not_called()

    def test_audit_failure_prevents_start(self) -> None:
        loop = OperatorLoop(self.rt, run_campaign_fn=lambda *args, **kwargs: self.fail("campaign ran"))
        with patch.object(operator_guard, "audit_event", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                loop.start(grants=[_spec("example")])
        self.assertFalse(loop.running)

    def test_two_operator_instances_cannot_double_spend_same_runtime(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        def run_fn(target, **kwargs):
            entered.set()
            release.wait(timeout=5)
            return {"ok": True, "findings": [], "proof_of_impact": {}}
        first = OperatorLoop(self.rt, run_campaign_fn=run_fn)
        second = OperatorLoop(self.rt, run_campaign_fn=run_fn)
        self.assertTrue(first.start(grants=[_spec("example")]))
        try:
            self.assertTrue(entered.wait(timeout=5))
            with self.assertRaisesRegex(ValueError, "already owns"):
                second.start(grants=[_spec("example")])
            self.assertFalse(second.running)
        finally:
            first.stop()
            release.set()
            first._thread.join(timeout=5)
        self.assertFalse(first._thread.is_alive())
        self.assertTrue(second.start(grants=[_spec("example")]))
        second.stop()
        second._thread.join(timeout=5)
        self.assertFalse(second._thread.is_alive())

    def test_recon_refuses_out_of_scope_seed_without_fetch(self) -> None:
        with patch.object(recon, "_guard_url", return_value="https://other.com"), \
             patch.object(recon, "_fetch_raw", side_effect=AssertionError("network fetch")):
            result = recon.discover("https://other.com", scope_in=lambda host: host == "example.com")
        self.assertEqual(result["requests_used"], 0)
        self.assertEqual(result["urls"], [])

    def test_passive_fetch_hook_stops_on_real_429_response(self) -> None:
        class Response:
            status = 429
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def geturl(self): return "https://example.com/"
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                return Response()
        opener = Opener()
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with operator_guard.bind(guard), \
             patch.object(web_scan_service, "_guard_url", side_effect=lambda url, *_: url), \
             patch.object(web_scan_service, "build_opener", return_value=opener) as opener_factory, \
             patch.object(web_scan_service, "_consume", return_value={"status": 429, "headers": {}, "body": "", "cookies": []}):
            with self.assertRaisesRegex(operator_guard.GuardHalt, "429"):
                web_scan_service._fetch_raw("https://example.com/")
        self.assertEqual(opener.calls, 1)
        self.assertEqual(guard.requests_used, 1)
        self.assertTrue(any(isinstance(handler, ProxyHandler) and handler.proxies == {}
                            for handler in opener_factory.call_args.args))

    def test_429_headers_halt_before_malformed_body_read(self) -> None:
        class BrokenResponse:
            status = 429
            headers = {}
            read_called = False
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def geturl(self): return "https://example.com/"
            def read(self, *args):
                self.read_called = True
                raise http.client.IncompleteRead(b"broken", 100)
        class Opener:
            def open(self, request, timeout): return response
        response = BrokenResponse()
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with operator_guard.bind(guard), \
             patch.object(web_scan_service, "_guard_url", side_effect=lambda url, *_: url), \
             patch.object(web_scan_service, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(operator_guard.GuardHalt, "429"):
                web_scan_service._fetch_raw("https://example.com/")
        self.assertFalse(response.read_called)
        self.assertTrue(guard.stop_event.is_set())

        class Governor:
            def throttle(self, host): return True
        active_response = BrokenResponse()
        active_guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with operator_guard.bind(active_guard), \
             patch.object(active_verify_service, "_guard_url", side_effect=lambda url, *_: url):
            http = active_verify_service._Http(get_settings(), Governor(), max_requests=5)
            http.opener = Opener()
            response = active_response
            with self.assertRaisesRegex(operator_guard.GuardHalt, "429"):
                http.fetch("https://example.com/")
        self.assertFalse(active_response.read_called)
        self.assertTrue(active_guard.stop_event.is_set())

    def test_manual_private_url_switch_cannot_widen_unattended_fetches(self) -> None:
        class Governor:
            def throttle(self, host): return True
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        manual_settings = replace(get_settings(), allow_private_urls=True)
        with operator_guard.bind(guard), \
             patch.object(web_scan_service, "_host_is_private", return_value=True), \
             patch.object(web_scan_service, "get_settings", return_value=manual_settings), \
             patch.object(web_scan_service, "build_opener") as passive_socket:
            with self.assertRaisesRegex(web_scan_service.WebsiteFetchError, "Private"):
                web_scan_service._fetch_raw("https://example.com/")
            passive_socket.assert_not_called()
            http = active_verify_service._Http(manual_settings, Governor(), max_requests=5)
            with patch.object(http.opener, "open") as active_socket:
                with self.assertRaisesRegex(web_scan_service.WebsiteFetchError, "Private"):
                    http.fetch("https://example.com/")
                active_socket.assert_not_called()

    def test_redirect_challenge_stops_before_following_hop(self) -> None:
        from urllib.request import Request
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        handler = web_scan_service._GuardedRedirect(False, frozenset({80, 443}))
        with operator_guard.bind(guard):
            with self.assertRaisesRegex(operator_guard.GuardHalt, "challenge"):
                handler.redirect_request(Request("https://example.com/"), None, 302, "Found",
                                         {"cf-mitigated": "challenge"}, "https://example.com/login")
        self.assertEqual(guard.requests_used, 0)

    def test_active_transport_failure_is_not_retried_unattended(self) -> None:
        class Governor:
            def throttle(self, host): return True
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                raise URLError("temporary disconnect")
        opener = Opener()
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with operator_guard.bind(guard), patch.object(active_verify_service, "_guard_url", side_effect=lambda url, *_: url):
            http = active_verify_service._Http(get_settings(), Governor(), max_requests=5)
            http.opener = opener
            with self.assertRaises(active_verify_service._ActiveError):
                http.fetch("https://example.com/")
        self.assertEqual(opener.calls, 1)
        self.assertEqual(guard.requests_used, 1)

    def test_active_unattended_opener_ignores_environment_proxy(self) -> None:
        class Governor:
            def throttle(self, host): return True
        guard = operator_guard.RunGuard(self.rt, self._grant(), threading.Event())
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:3128", "NO_PROXY": ""}), \
             operator_guard.bind(guard):
            http = active_verify_service._Http(get_settings(), Governor(), max_requests=5)
            proxy_handlers = [handler for handler in http.opener.handlers if isinstance(handler, ProxyHandler)]
            # urllib omits an empty ProxyHandler from OpenerDirector.handlers,
            # while suppressing its usual environment-derived proxy handler.
            self.assertEqual(proxy_handlers, [])

    def test_stop_cancels_current_run_and_context_is_bound(self) -> None:
        started = threading.Event()
        release = threading.Event()
        observed: dict[str, object] = {}
        calls: list[str] = []

        def run_fn(target, **kwargs):
            calls.append(target)
            observed["guard_bound"] = operator_guard.current() is not None
            observed["run_id"] = kwargs.get("run_id")
            started.set()
            release.wait(timeout=5)
            operator_guard.before_request("https://example.com/another")
            return {"ok": True, "findings": [], "proof_of_impact": {}}

        loop = OperatorLoop(self.rt, run_campaign_fn=run_fn)
        self.assertTrue(loop.start(grants=[_spec("example")]))
        self.assertTrue(started.wait(timeout=5))
        loop.stop()
        release.set()
        loop._thread.join(timeout=5)
        self.assertFalse(loop._thread.is_alive())
        self.assertTrue(observed["guard_bound"])
        self.assertTrue(progress.is_stopped(str(observed["run_id"])))
        self.assertEqual(calls, ["https://example.com"])
        self.assertTrue(any("cycle halted" in e["message"] for e in loop.event_tail()["events"]))
        rows = [json.loads(line) for line in (Path(self.rt) / "operator_authorization_audit.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["event"] for row in rows], ["armed", "cycle_started", "cycle_finished", "stopped"])
        self.assertEqual(rows[-1]["authorization_ref"], _spec("example")["authorization_ref"])
        self.assertEqual(rows[-1]["cycles_used"], 1)


if __name__ == "__main__":
    unittest.main()
