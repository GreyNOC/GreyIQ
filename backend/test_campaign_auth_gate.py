"""On-demand campaign authentication is bounded, scope-gated, and ephemeral."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import campaign, recon  # noqa: E402
from bughunter.scan_auth import AuthContext  # noqa: E402
from bughunter.web_ingest import WebsiteFetchError  # noqa: E402


TARGET = "https://app.example.com/private"
WALL = {"reason": "http_401", "status": 401,
        "target_host": "app.example.com", "login_host": "app.example.com"}


class _Governor:
    def throttle(self, _host: str) -> bool:
        return True


class ReconAuthGateTests(unittest.TestCase):
    def test_https_session_downgrade_is_a_blocked_marker(self) -> None:
        session = AuthContext(host="app.example.com", headers={"Cookie": "sid=secret-value"},
                              https_only=True)
        with patch.object(recon, "_guard_url", return_value=TARGET), \
                patch.object(recon, "_fetch_raw", side_effect=WebsiteFetchError(
                    "Operator session requires HTTPS; refusing an HTTP redirect.")) as fetch:
            result = recon.discover(TARGET, scope_in=lambda host: host == "app.example.com",
                                    max_pages=3, governor=_Governor(), detect_auth_wall=True,
                                    auth=session)

        self.assertTrue(result["auth_transport_blocked"])
        self.assertEqual(fetch.call_count, 1)
        self.assertNotIn("secret-value", json.dumps(result))

    def test_auth_wall_uses_only_seed_fetch_and_returns_no_response_content(self) -> None:
        calls: list[str] = []

        def fetched(url, _settings, _governor):
            calls.append(url)
            return {"status": 401, "headers": {"WWW-Authenticate": "Bearer secret-value"},
                    "body": "secret response body", "final_url": url}

        with patch.object(recon, "_guard_url", return_value=TARGET), \
                patch.object(recon, "_safe_fetch", side_effect=fetched):
            result = recon.discover(TARGET, scope_in=lambda host: host == "app.example.com",
                                    max_pages=3, governor=_Governor(), detect_auth_wall=True)

        self.assertEqual(calls, [TARGET])
        self.assertEqual(result["auth_wall"], WALL)
        self.assertEqual(result["requests_used"], 1)
        self.assertNotIn("secret response body", json.dumps(result))
        self.assertNotIn("Bearer secret-value", json.dumps(result))

    def test_public_seed_is_reused_in_crawl_and_auth_is_attached_to_each_recon_fetch(self) -> None:
        calls: list[tuple[str, AuthContext | None]] = []
        session = AuthContext(host="app.example.com", headers={"Cookie": "sid=secret"})

        def fetched(url, _settings, _governor, auth=None):
            calls.append((url, auth))
            status = 200 if url == TARGET else 404
            return {"status": status, "headers": {}, "body": "plain page", "final_url": url}

        with patch.object(recon, "_guard_url", return_value=TARGET), \
                patch.object(recon, "_safe_fetch", side_effect=fetched):
            result = recon.discover(TARGET, scope_in=lambda host: host == "app.example.com",
                                    max_pages=3, max_requests=20, governor=_Governor(),
                                    detect_auth_wall=True, auth=session)

        self.assertIsNone(result["auth_wall"])
        self.assertEqual(sum(url == TARGET for url, _ in calls), 1)
        self.assertTrue(all(auth is session for _, auth in calls))

    def test_supplied_bad_session_receiving_200_login_form_is_still_a_wall(self) -> None:
        session = AuthContext(host="app.example.com", headers={"Cookie": "sid=bad"})
        login_page = ('<title>Sign in</title><form action="/login"><input type="email" name="email">'
                      '<input type="password" name="password"></form>')
        response = {"status": 200, "headers": {}, "body": login_page, "final_url": TARGET}
        with patch.object(recon, "_guard_url", return_value=TARGET), \
                patch.object(recon, "_safe_fetch", return_value=response) as fetch:
            result = recon.discover(TARGET, scope_in=lambda host: host == "app.example.com",
                                    max_pages=3, governor=_Governor(), detect_auth_wall=True,
                                    auth=session, verify_login_form=True)

        self.assertEqual(result["auth_wall"]["reason"], "login_form")
        self.assertEqual(fetch.call_count, 1)

    def test_public_page_with_sign_in_widget_does_not_pause(self) -> None:
        widget_page = ('<title>Product news</title><h1>Updates</h1>'
                       '<form action="/login"><input type="email" name="email">'
                       '<input type="password" name="password"></form>')

        def fetched(url, _settings, _governor):
            return {"status": 200 if url == TARGET else 404, "headers": {},
                    "body": widget_page if url == TARGET else "", "final_url": url}

        with patch.object(recon, "_guard_url", return_value=TARGET), \
                patch.object(recon, "_safe_fetch", side_effect=fetched) as fetch:
            result = recon.discover(TARGET, scope_in=lambda host: host == "app.example.com",
                                    max_pages=3, max_requests=20, governor=_Governor(),
                                    detect_auth_wall=True, verify_login_form=True)

        self.assertIsNone(result["auth_wall"])
        self.assertEqual(sum(call.args[0] == TARGET for call in fetch.call_args_list), 1)

    def test_prompted_session_is_not_attached_to_discovered_http_link(self) -> None:
        http_link = "http://app.example.com/public"
        session = AuthContext(host="app.example.com", headers={"Cookie": "sid=secret-value"})
        calls: list[tuple[str, AuthContext | None]] = []

        def fetched(url, _settings, _governor, auth=None):
            calls.append((url, auth))
            body = f'<a href="{http_link}">public</a>' if url == TARGET else ""
            return {"status": 200 if url == TARGET else 404, "headers": {},
                    "body": body, "final_url": url}

        with patch.object(recon, "_guard_url", return_value=TARGET), \
                patch.object(recon, "_safe_fetch", side_effect=fetched):
            recon.discover(TARGET, scope_in=lambda host: host == "app.example.com",
                           max_pages=4, max_requests=20, governor=_Governor(),
                           detect_auth_wall=True, auth=session, https_only_auth=True)

        self.assertTrue(any(url == http_link for url, _ in calls))
        self.assertTrue(all(auth is None for url, auth in calls if url.startswith("http://")))
        self.assertTrue(all(auth is session for url, auth in calls if url.startswith("https://")))


class CampaignAuthGateTests(unittest.TestCase):
    def _run(self, root: Path, **extra):
        return campaign.run_campaign(TARGET, scope="app.example.com", authorized=True,
                                     coder_cfg={}, default_reports_dir=root, **extra)

    def test_recon_wall_without_operator_stops_before_planning_or_active_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", return_value={"auth_wall": WALL}) as discover, \
                patch.object(campaign.hunt_brain, "heuristic_plan") as plan, \
                patch.object(campaign, "run_bounty_hunt") as hunt:
            result = self._run(Path(tmp))
            self.assertEqual(list(Path(tmp).glob("campaign-*")), [])

        self.assertTrue(result["needs_operator"])
        self.assertEqual(result["operator_action"], "authentication_required")
        self.assertEqual(result["auth_context"], WALL)
        self.assertTrue(discover.call_args.kwargs["detect_auth_wall"])
        plan.assert_not_called()
        hunt.assert_not_called()

    def test_recon_https_downgrade_stops_campaign_before_planning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", return_value={
                    "auth_transport_blocked": True}) as discover, \
                patch.object(campaign.hunt_brain, "heuristic_plan") as plan:
            result = self._run(Path(tmp), auth={"cookie": "sid=secret-value", "https_only": True})

        self.assertFalse(result["ok"])
        self.assertTrue(result["auth_transport_blocked"])
        self.assertTrue(result["authentication_requires_https"])
        self.assertTrue(discover.call_args.kwargs["https_only_auth"])
        plan.assert_not_called()
        self.assertNotIn("secret-value", json.dumps(result))

    def test_operator_session_is_verified_by_a_second_credentialed_recon(self) -> None:
        class _ReachedPlanner(Exception):
            pass

        discover = Mock(side_effect=[{"auth_wall": WALL},
                                     {"auth_wall": None, "urls": [TARGET], "notes": [],
                                      "sources": {}, "params": [], "tech": [], "forms": []}])
        ask = Mock(return_value={"cookie": "sid=secret-value", "headers": []})
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", discover), \
                patch.object(campaign.hunt_brain, "heuristic_plan", side_effect=_ReachedPlanner):
            with self.assertRaises(_ReachedPlanner):
                self._run(Path(tmp), on_auth_needed=ask)

        ask.assert_called_once_with(WALL)
        self.assertEqual(discover.call_count, 2)
        self.assertIsNone(discover.call_args_list[0].kwargs["auth"])
        bound = discover.call_args_list[1].kwargs["auth"]
        self.assertIsInstance(bound, AuthContext)
        self.assertEqual(bound.headers["Cookie"], "sid=secret-value")
        self.assertEqual(bound.host, "app.example.com")

    def test_ineffective_supplied_session_without_callback_is_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", return_value={"auth_wall": WALL}) as discover:
            result = self._run(Path(tmp), auth={"cookie": "sid=bad"})

        self.assertTrue(result["needs_operator"])
        self.assertEqual(discover.call_count, 1)
        self.assertIsInstance(discover.call_args.kwargs["auth"], AuthContext)

    def test_operator_can_replace_stale_supplied_session_once(self) -> None:
        class _ReachedPlanner(Exception):
            pass

        discover = Mock(side_effect=[{"auth_wall": WALL},
                                     {"auth_wall": None, "urls": [TARGET], "notes": [],
                                      "sources": {}, "params": [], "tech": [], "forms": []}])
        ask = Mock(return_value={"cookie": "sid=fresh-value"})
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", discover), \
                patch.object(campaign.hunt_brain, "heuristic_plan", side_effect=_ReachedPlanner):
            with self.assertRaises(_ReachedPlanner):
                self._run(Path(tmp), auth={"cookie": "sid=stale-value"}, on_auth_needed=ask)

        ask.assert_called_once_with(WALL)
        self.assertEqual(discover.call_count, 2)
        self.assertEqual(discover.call_args_list[0].kwargs["auth"].headers["Cookie"], "sid=stale-value")
        self.assertEqual(discover.call_args_list[1].kwargs["auth"].headers["Cookie"], "sid=fresh-value")

    def test_campaign_rejects_bad_supplied_session_on_200_login_form(self) -> None:
        login_page = ('<title>Sign in</title><form action="/login"><input type="email" name="email">'
                      '<input type="password" name="password"></form>')
        response = {"status": 200, "headers": {}, "body": login_page, "final_url": TARGET}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "_guard_url", return_value=TARGET), \
                patch.object(campaign.recon, "_safe_fetch", return_value=response) as fetch:
            result = self._run(Path(tmp), auth={"cookie": "sid=bad"})

        self.assertTrue(result["needs_operator"])
        self.assertEqual(result["auth_context"]["reason"], "login_form")
        self.assertEqual(fetch.call_count, 1)

    def test_second_wall_stops_without_persisting_supplied_cookie(self) -> None:
        ask = Mock(return_value={"cookie": "sid=secret-value", "headers": []})
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", return_value={"auth_wall": WALL}) as discover:
            result = self._run(Path(tmp), on_auth_needed=ask)
            self.assertEqual(list(Path(tmp).glob("campaign-*")), [])

        self.assertTrue(result["needs_operator"])
        self.assertEqual(discover.call_count, 2)
        ask.assert_called_once()
        self.assertNotIn("secret-value", json.dumps(result))

    def test_invalid_scope_never_collects_credentials_or_fetches(self) -> None:
        ask = Mock()
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover") as discover:
            result = campaign.run_campaign(TARGET, scope="elsewhere.example", authorized=True,
                                           coder_cfg={}, default_reports_dir=Path(tmp), on_auth_needed=ask)

        self.assertFalse(result["ok"])
        self.assertNotIn("needs_operator", result)
        discover.assert_not_called()
        ask.assert_not_called()

    def test_http_seed_wall_never_requests_a_new_session(self) -> None:
        http_target = "http://app.example.com/private"
        ask = Mock(return_value={"cookie": "sid=secret-value"})
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", return_value={"auth_wall": WALL}) as discover:
            result = campaign.run_campaign(
                http_target, scope="app.example.com", authorized=True,
                coder_cfg={}, default_reports_dir=Path(tmp), on_auth_needed=ask,
            )

        self.assertTrue(result["needs_operator"])
        self.assertTrue(result["authentication_requires_https"])
        self.assertTrue(result["secure_transport_required"])
        self.assertIn("HTTPS", result["error"])
        self.assertEqual(discover.call_count, 1)
        ask.assert_not_called()
        self.assertNotIn("secret-value", json.dumps(result))

    def test_discovered_http_wall_never_requests_a_new_session(self) -> None:
        http_target = "http://app.example.com/private"
        surface = {"auth_wall": None, "urls": [http_target], "notes": [],
                   "sources": {}, "params": [], "tech": [], "forms": []}
        ask = Mock(return_value={"cookie": "sid=secret-value"})

        def fake_hunt(_target, *_args, **kwargs):
            self.assertIsNone(kwargs["on_auth_needed"](WALL))
            return {"ok": False, "needs_operator": True, "auth_context": WALL}

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", return_value=surface), \
                patch.object(campaign.cve_service, "scan_known_cves", return_value={"findings": []}), \
                patch.object(campaign, "run_bounty_hunt", side_effect=fake_hunt) as hunt:
            result = self._run(Path(tmp), on_auth_needed=ask)

        self.assertTrue(result["needs_operator"])
        self.assertTrue(result["authentication_requires_https"])
        self.assertEqual(hunt.call_count, 1)
        ask.assert_not_called()
        self.assertNotIn("secret-value", json.dumps(result))

    def test_prompted_https_session_is_not_forwarded_to_discovered_http_hunt(self) -> None:
        http_target = "http://app.example.com/private"
        surface = {"auth_wall": None, "urls": [http_target], "notes": [],
                   "sources": {}, "params": [], "tech": [], "forms": []}
        discover = Mock(side_effect=[{"auth_wall": WALL}, surface])
        ask = Mock(return_value={"cookie": "sid=secret-value"})

        def fake_hunt(_target, *_args, **kwargs):
            self.assertIsNone(kwargs["auth"])
            self.assertIsNone(kwargs["on_auth_needed"](WALL))
            return {"ok": False, "needs_operator": True, "auth_context": WALL}

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", discover), \
                patch.object(campaign.cve_service, "scan_known_cves", return_value={"findings": []}), \
                patch.object(campaign, "run_bounty_hunt", side_effect=fake_hunt) as hunt:
            result = self._run(Path(tmp), on_auth_needed=ask)

        self.assertTrue(result["needs_operator"])
        self.assertTrue(result["authentication_requires_https"])
        self.assertEqual(discover.call_count, 2)
        self.assertTrue(discover.call_args.kwargs["https_only_auth"])
        self.assertEqual(hunt.call_count, 1)
        ask.assert_called_once_with(WALL)
        self.assertNotIn("secret-value", json.dumps(result))

    def test_previously_prompted_session_is_not_forwarded_to_http_hunt(self) -> None:
        http_target = "http://app.example.com/private"
        surface = {"auth_wall": None, "urls": [http_target], "notes": [],
                   "sources": {}, "params": [], "tech": [], "forms": []}

        def fake_hunt(_target, *_args, **kwargs):
            self.assertIsNone(kwargs["auth"])
            return {"ok": False, "needs_operator": True, "auth_context": WALL}

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", return_value=surface) as discover, \
                patch.object(campaign.cve_service, "scan_known_cves", return_value={"findings": []}), \
                patch.object(campaign, "run_bounty_hunt", side_effect=fake_hunt):
            result = self._run(Path(tmp), auth={"cookie": "sid=secret-value", "https_only": True})

        self.assertTrue(result["needs_operator"])
        self.assertTrue(discover.call_args.kwargs["https_only_auth"])
        self.assertNotIn("secret-value", json.dumps(result))

    def test_per_url_hunt_wall_stops_before_the_next_url(self) -> None:
        second = "https://app.example.com/second"
        surface = {"auth_wall": None, "urls": [TARGET, second], "notes": [],
                   "sources": {}, "params": [], "tech": [], "forms": []}
        hunt_result = {"ok": False, "needs_operator": True,
                       "auth_context": {**WALL, "target_host": "app.example.com"}}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign.recon, "discover", return_value=surface), \
                patch.object(campaign.cve_service, "scan_known_cves", return_value={"findings": []}), \
                patch.object(campaign, "run_bounty_hunt", return_value=hunt_result) as hunt:
            result = self._run(Path(tmp), active=True)

        self.assertTrue(result["needs_operator"])
        self.assertEqual(result["urls_discovered"], 2)
        self.assertEqual(hunt.call_count, 1)


class SpanAuthGateTests(unittest.TestCase):
    def test_http_only_span_preserves_https_requirement(self) -> None:
        target = "http://a.example.com/private"
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign, "run_campaign",
                             return_value=campaign._auth_required_result(WALL, target)):
            result = campaign.run_campaign_over_targets(
                [target], scope="a.example.com", authorized=True, coder_cfg={},
                default_reports_dir=Path(tmp))

        self.assertFalse(result["ok"])
        self.assertTrue(result["needs_operator"])
        self.assertTrue(result["secure_transport_required"])
        self.assertIn("HTTPS", result["error"])

    def test_prompts_from_parallel_targets_are_serialized(self) -> None:
        targets = ["https://a.example.com/", "https://b.example.com/"]
        state = {"active": 0, "peak": 0}
        state_lock = threading.Lock()

        def ask(_context):
            with state_lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            time.sleep(0.02)
            with state_lock:
                state["active"] -= 1
            return {"cookie": "sid=secret-value"}

        def fake_campaign(target, **kwargs):
            callback = kwargs["on_auth_needed"]
            callback({**WALL, "target_host": target.split("/")[2]})
            return {"ok": False, "needs_operator": True, "auth_context": {
                **WALL, "target_host": target.split("/")[2], "login_host": target.split("/")[2]}}

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign, "run_campaign", side_effect=fake_campaign):
            result = campaign.run_campaign_over_targets(
                targets, scope="*.example.com", authorized=True, coder_cfg={},
                default_reports_dir=Path(tmp), on_auth_needed=ask)

        self.assertEqual(state["peak"], 1)
        self.assertTrue(result["needs_operator"])
        self.assertEqual(len(result["auth_contexts"]), 2)
        self.assertEqual(result["targets_hunted"], 0)
        self.assertNotIn("secret-value", json.dumps(result))

    def test_partial_span_retains_auth_request_and_completed_report(self) -> None:
        targets = ["https://a.example.com/", "https://b.example.com/"]

        def fake_campaign(target, **_kwargs):
            if target == targets[0]:
                return {"ok": True, "findings": [], "proof_of_impact": {}, "cvss": {},
                        "attack_plans": {}, "surface": {"urls": [target], "sources": {},
                                                       "notes": [], "tech": []}}
            return {"ok": False, "needs_operator": True, "auth_context": {
                **WALL, "target_host": "b.example.com", "login_host": "b.example.com"},
                    "error": "Authentication is required."}

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(campaign, "run_campaign", side_effect=fake_campaign):
            result = campaign.run_campaign_over_targets(
                targets, scope="*.example.com", authorized=True, coder_cfg={},
                default_reports_dir=Path(tmp))
            artifact = Path(result["json_path"]).read_text(encoding="utf-8")

        self.assertFalse(result["ok"])
        self.assertTrue(result["needs_operator"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["targets_hunted"], 1)
        self.assertEqual(result["auth_context"]["target_host"], "b.example.com")
        self.assertIn("needs_operator", artifact)


if __name__ == "__main__":
    unittest.main()
