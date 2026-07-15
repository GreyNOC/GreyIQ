"""Tests for stored (persistent) XSS confirmation — offline (view fetch + form POST stubbed).

A raw marker payload on the view page confirms; an HTML-escaped marker is reported escaped;
an absent marker is not-stored. Assisted mode hands back the kit without sending; the opt-in
send POSTs once. Scope is fail-closed.
"""
from __future__ import annotations

import html
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import stored_xss_service as sx  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


class StoredXssTests(unittest.TestCase):
    def setUp(self) -> None:
        self._guard = sx._guard_url
        self._fetch = sx._fetch_view
        self._post = sx._post_form
        sx._guard_url = lambda u, *a, **k: u
        self.cfg = {"scope": "app.example.com", "settings": get_settings()}

    def tearDown(self) -> None:
        sx._guard_url = self._guard
        sx._fetch_view = self._fetch
        sx._post_form = self._post

    def test_payloads_carry_the_marker(self) -> None:
        p = sx.build_payloads("MARK123")
        self.assertIn("MARK123", p["svg"])
        self.assertIn("<svg/onload=", p["svg"])

    def test_assisted_ready_returns_kit_without_fetching(self) -> None:
        fetched = []
        sx._fetch_view = lambda url, **k: fetched.append(url) or {"status": 200, "body": ""}
        res = sx.confirm_stored_xss(view_url="https://app.example.com/profile", **self.cfg)
        self.assertEqual(res["status"], "ready")
        self.assertIn("svg", res["payloads"])
        self.assertTrue(res["marker"])
        self.assertEqual(fetched, [])  # nothing fetched, nothing sent

    def test_assisted_recheck_confirms_raw_payload(self) -> None:
        marker = "gqsxdeadbeef"
        payload = sx.build_payloads(marker)["svg"]
        sx._fetch_view = lambda url, **k: {"status": 200, "body": f"<html><div class=bio>{payload}</div></html>"}
        res = sx.confirm_stored_xss(view_url="https://app.example.com/profile", marker=marker, **self.cfg)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["finding"]["rule_id"], "active.stored-xss")
        self.assertEqual(res["finding"]["class_id"], "xss")
        self.assertEqual(res["attack_plan"]["proof_of_impact"]["status"], "confirmed")
        self.assertFalse(res["attack_plan"]["cvss"]["estimated"])
        self.assertIn("confirmed", res["attack_plan"]["cvss"]["justification"].lower())

    def test_escaped_marker_is_not_confirmed(self) -> None:
        marker = "gqsxcafef00d"
        payload = sx.build_payloads(marker)["svg"]
        sx._fetch_view = lambda url, **k: {"status": 200, "body": f"<html>{html.escape(payload)}</html>"}
        res = sx.confirm_stored_xss(view_url="https://app.example.com/profile", marker=marker, **self.cfg)
        self.assertEqual(res["status"], "escaped")

    def test_absent_marker_is_not_stored(self) -> None:
        sx._fetch_view = lambda url, **k: {"status": 200, "body": "<html>nothing here</html>"}
        res = sx.confirm_stored_xss(view_url="https://app.example.com/profile", marker="gqsxnope", **self.cfg)
        self.assertEqual(res["status"], "not-stored")

    def test_auto_send_posts_then_confirms(self) -> None:
        marker = "gqsxsend0001"
        payload = sx.build_payloads(marker)["svg"]
        posted = []
        sx._post_form = lambda url, data, **k: posted.append((url, data)) or {"ok": True, "status": 200}
        calls = {"n": 0}
        def fetch(url, **k):
            calls["n"] += 1
            # pre-check empty, post-submit shows the raw payload
            return {"status": 200, "body": "" if calls["n"] == 1 else f"<div>{payload}</div>"}
        sx._fetch_view = fetch
        res = sx.confirm_stored_xss(view_url="https://app.example.com/profile",
                                    inject_url="https://app.example.com/bio", field="bio",
                                    send=True, marker=marker, **self.cfg)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0][1], {"bio": payload})  # exactly one form POST with the payload

    def test_auto_send_aborts_if_marker_preexists(self) -> None:
        marker = "gqsxdup00002"
        payload = sx.build_payloads(marker)["svg"]
        sx._fetch_view = lambda url, **k: {"status": 200, "body": f"<div>{payload}</div>"}  # already present
        posted = []
        sx._post_form = lambda url, data, **k: posted.append(url) or {"ok": True, "status": 200}
        res = sx.confirm_stored_xss(view_url="https://app.example.com/profile",
                                    inject_url="https://app.example.com/bio", field="bio",
                                    send=True, marker=marker, **self.cfg)
        self.assertFalse(res["ok"])
        self.assertEqual(posted, [])  # never POSTed — can't attribute a pre-existing marker

    def test_auto_send_requires_inject_url_and_field(self) -> None:
        res = sx.confirm_stored_xss(view_url="https://app.example.com/profile", send=True, **self.cfg)
        self.assertFalse(res["ok"])
        self.assertIn("inject_url", res["error"])

    def test_out_of_scope_view_refused(self) -> None:
        res = sx.confirm_stored_xss(view_url="https://evil.example/p", scope="app.example.com", settings=get_settings())
        self.assertFalse(res["ok"])
        self.assertIn("scope", res["error"].lower())


class PostFormSameSiteTests(unittest.TestCase):
    """The REAL _post_form (not stubbed) against a local server: the operator's session
    must attach only when the POST host is same-site as the auth's bound host — the same
    invariant scan_auth.same_site enforces on the GET path."""

    def setUp(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        captured = self.captured = []

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                captured.append({k: v for k, v in self.headers.items()})
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_session_attached_when_post_host_is_same_site_as_auth(self) -> None:
        from bughunter.scan_auth import build_auth
        url = f"http://127.0.0.1:{self.port}/submit"
        auth = build_auth(url, cookie="session=secret123")  # bound to 127.0.0.1
        res = sx._post_form(url, {"f": "x"}, auth=auth, timeout=5.0)
        self.assertTrue(res["ok"])
        self.assertIn("Cookie", self.captured[0])
        self.assertIn("secret123", self.captured[0]["Cookie"])

    def test_session_withheld_when_post_host_differs_from_auth(self) -> None:
        from bughunter.scan_auth import build_auth
        url = f"http://127.0.0.1:{self.port}/submit"
        # Bound to a DIFFERENT host than the one we're about to POST to — the inject URL
        # can legitimately be a different in-scope host than the view URL the session was
        # built against (confirm_stored_xss builds auth from the VIEW url).
        auth = build_auth("https://app.example.com/", cookie="session=secret123")
        res = sx._post_form(url, {"f": "x"}, auth=auth, timeout=5.0)
        self.assertTrue(res["ok"])
        self.assertNotIn("Cookie", self.captured[0])  # session must NOT leak to a different host


class StoredXssBeaconTests(unittest.TestCase):
    """OOB-beacon stored XSS: inject an <img src=collaborator> beacon, render the view in a browser,
    and a callback for the fresh (pre-injection empty) token proves the stored markup executes on
    render. Browser + collaborator are stubbed; no real network/browser is used."""

    def setUp(self) -> None:
        self._save = (sx._guard_url, sx._render_beacon, sx._post_form, sx.poll_collaborator)
        sx._guard_url = lambda u, *a, **k: u
        sx._render_beacon = lambda url, **k: {"ok": True, "final_url": url}       # no real browser
        sx._post_form = lambda url, data, **k: {"ok": True, "status": 200}        # no real POST
        self.cfg = {"base": "https://collab.example", "secret": "s" * 16, "scope": "app.example.com",
                    "settings": get_settings(), "poll_delay_s": 0.0, "poll_attempts": 1}
        self.V = {"view_url": "https://app.example.com/profile", "inject_url": "https://app.example.com/bio", "field": "bio"}

    def tearDown(self) -> None:
        sx._guard_url, sx._render_beacon, sx._post_form, sx.poll_collaborator = self._save

    def _poll_seq(self, second):
        state = {"n": 0}
        def poll(base, secret, token, **k):
            state["n"] += 1
            return {"ok": True, "count": 0} if state["n"] == 1 else second(token)
        return poll

    def test_beacon_payloads_embed_the_callback(self) -> None:
        p = sx._beacon_payloads("https://collab.example/oob/tok", "tok")
        self.assertIn("https://collab.example/oob/tok", p["img"])
        self.assertIn("<img", p["img"])

    def test_auto_send_render_hit_confirms_and_carries_active_proof(self) -> None:
        from bughunter import report
        sx.poll_collaborator = self._poll_seq(lambda t: {"ok": True, "count": 1, "hits": [
            {"method": "GET", "path": "/oob/" + t, "ip": "203.0.113.9", "headers": {"user-agent": "HeadlessChrome/120"}}]})
        res = sx.confirm_stored_xss_beacon(send=True, **self.V, **self.cfg)
        self.assertEqual(res["status"], "confirmed")
        f = res["finding"]
        self.assertEqual(f["rule_id"], "active.stored-xss-beacon")
        self.assertEqual(f["_active_class_hint"], "xss")                          # renders confirmed in a hunt/report
        poi = f["_active_proof"]
        self.assertTrue(report._has_captured_artifact(f, poi, poi.get("observed_result", "")))
        self.assertIn("control_result", poi)                                     # fresh-token negative control

    def test_no_callback_is_not_confirmed(self) -> None:
        sx.poll_collaborator = lambda *a, **k: {"ok": True, "count": 0}
        res = sx.confirm_stored_xss_beacon(send=True, **self.V, **self.cfg)
        self.assertEqual(res["status"], "no-callback")

    def test_preexisting_token_hit_aborts_negative_control(self) -> None:
        sx.poll_collaborator = lambda *a, **k: {"ok": True, "count": 5}
        res = sx.confirm_stored_xss_beacon(send=True, **self.V, **self.cfg)
        self.assertFalse(res["ok"])
        self.assertIn("already has hits", res["error"])

    def test_crawler_ua_callback_downgrades_to_candidate(self) -> None:
        sx.poll_collaborator = self._poll_seq(lambda t: {"ok": True, "count": 1, "hits": [
            {"method": "GET", "path": "/x", "ip": "1.2.3.4", "headers": {"user-agent": "Slackbot-LinkExpanding 1.0"}}]})
        res = sx.confirm_stored_xss_beacon(send=True, **self.V, **self.cfg)
        self.assertEqual(res["status"], "candidate")
        self.assertEqual(res["finding"]["_active_proof"]["status"], "candidate")

    def test_assisted_ready_hands_back_beacon_kit_without_rendering(self) -> None:
        rendered = []
        sx._render_beacon = lambda url, **k: rendered.append(url) or {"ok": True, "final_url": url}
        res = sx.confirm_stored_xss_beacon(view_url="https://app.example.com/profile", **self.cfg)
        self.assertEqual(res["status"], "ready")
        self.assertIn("collab.example", res["payloads"]["img"])
        self.assertTrue(res["token"])
        self.assertEqual(rendered, [])                                           # nothing rendered, nothing sent

    def test_requires_collaborator_and_scope(self) -> None:
        self.assertFalse(sx.confirm_stored_xss_beacon(view_url="https://app.example.com/p", base="", secret="",
                                                      scope="app.example.com", settings=get_settings())["ok"])
        # out-of-scope view is refused
        self.assertFalse(sx.confirm_stored_xss_beacon(view_url="https://evil.example/p", base="https://c", secret="s",
                                                      scope="app.example.com", settings=get_settings())["ok"])

    def test_auto_send_requires_inject_url_and_field(self) -> None:
        res = sx.confirm_stored_xss_beacon(view_url="https://app.example.com/profile", send=True, **self.cfg)
        self.assertFalse(res["ok"])
        self.assertIn("inject_url", res["error"])

    def test_render_session_never_rides_an_off_site_request(self) -> None:
        # SECURITY: the render must attach the operator session ONLY to same-site requests. A cross-origin
        # sub-resource the (attacker-controlled) stored markup references must receive NO credentials, or a
        # header-based session (Authorization) would leak off-target. Regression for the QAQC P0.
        from bughunter.scan_auth import build_auth
        auth = build_auth("https://app.example.com/profile", cookie="session=SECRET",
                          headers=["Authorization: Bearer OP_TOKEN"])
        # same-site (the view host + subdomains) -> session attached
        same = sx._beacon_route_headers("https://app.example.com/api/me", {"accept": "*/*"}, auth)
        self.assertIsNotNone(same)
        self.assertEqual(same.get("authorization"), "Bearer OP_TOKEN")
        self.assertIn("session=SECRET", same.get("cookie", ""))
        # off-site attacker host (the beacon-referenced <img> host / a public CDN) -> NO credentials
        for evil in ("https://attacker.example/steal", "https://cdn.evil.net/x", "https://collab.example/oob/tok"):
            self.assertIsNone(sx._beacon_route_headers(evil, {"accept": "*/*"}, auth), evil)


if __name__ == "__main__":
    unittest.main()
