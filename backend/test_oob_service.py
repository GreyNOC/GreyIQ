"""Tests for the OOB (out-of-band) blind-SSRF confirm via an operator collaborator.

No network: the target HTTP and the collaborator poll are stubbed. A recorded callback
confirms blind SSRF; no callback never confirms; the scope gate is fail-closed.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import oob_service as oob  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


class FakeHttp:
    def __init__(self):
        self.fetched: list[str] = []

    def fetch(self, url, **kwargs):
        self.fetched.append(url)
        return {"status": 200, "headers": {}, "body": "", "cookies": [], "final_url": url, "location": None}


class HelperTests(unittest.TestCase):
    def test_mint_token_is_unique_hex(self) -> None:
        a, b = oob.mint_token(), oob.mint_token()
        self.assertRegex(a, r"^[0-9a-f]{32}$")
        self.assertNotEqual(a, b)

    def test_callback_url(self) -> None:
        self.assertEqual(oob.callback_url("https://c.example/", "abc123"), "https://c.example/oob/abc123")
        self.assertEqual(oob.callback_url("https://c.example", "abc123"), "https://c.example/oob/abc123")

    def test_poll_requires_config(self) -> None:
        self.assertFalse(oob.poll_collaborator("", "secret", "tok")["ok"])

    def test_ssrf_finding_carries_confirmed_active_proof(self) -> None:
        # A hunt appends this finding to raw_findings, so it MUST carry the active-proof carriers or
        # it renders as a deterministic 'candidate' instead of the confirmed OOB SSRF it is.
        hit = {"method": "GET", "ip": "10.0.0.5", "path": "/oob/tok", "headers": {"user-agent": "curl"}}
        f = oob._build_ssrf_finding("https://app.example.com/?url=x", "url", "tok", "https://c.example", hit, True)
        self.assertEqual(f["_active_class_hint"], "ssrf")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("control_result", f["_active_proof"])   # fresh-token negative control
        # Derived from the vector via impact_model.cvss_block, so it is the canonical capitalized band
        # cvss_base_score returns (the same form cvss_for_class and report.py:220 already produce).
        self.assertEqual(f["_active_cvss"]["base_severity"], "High")
        self.assertEqual(f["_active_cvss"]["base_score"], 7.7)   # the vector's real score (was hardcoded 8.5)

    def test_candidate_ssrf_finding_is_not_confirmed(self) -> None:
        hit = {"method": "GET", "ip": "1.2.3.4", "headers": {"user-agent": "bot"}}
        f = oob._build_ssrf_finding("https://app.example.com/?url=x", "url", "tok", "https://c.example", hit, False)
        self.assertEqual(f["_active_proof"]["status"], "candidate")
        self.assertFalse(oob.poll_collaborator("https://c.example", "", "tok")["ok"])
        self.assertFalse(oob.poll_collaborator("https://c.example", "secret", "")["ok"])


class ConfirmTests(unittest.TestCase):
    def setUp(self) -> None:
        self._guard = oob._guard_url
        self._poll = oob.poll_collaborator
        oob._guard_url = lambda u, *a, **k: u  # bypass DNS/SSRF guard in tests

    def tearDown(self) -> None:
        oob._guard_url = self._guard
        oob.poll_collaborator = self._poll

    def _staged_poll(self, hit):
        """A fake poll: empty on the first call per token (the pre-probe control), then the hit."""
        calls = {}
        def fake_poll(base, secret, token, **k):
            calls[token] = calls.get(token, 0) + 1
            if calls[token] == 1:
                return {"ok": True, "count": 0, "hits": []}
            return {"ok": True, "count": 1, "hits": [{**hit, "path": f"/oob/{token}"}]}
        return fake_poll

    def test_confirms_blind_ssrf_on_a_callback_hit(self) -> None:
        seen = {}
        base_fake = self._staged_poll({"method": "GET", "ip": "9.9.9.9", "headers": {"user-agent": "Go-http-client/1.1"}})
        def fake_poll(base, secret, token, **k):
            seen["token"] = token
            return base_fake(base, secret, token, **k)
        oob.poll_collaborator = fake_poll
        http = FakeHttp()
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=http, poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["finding"]["class_id"], "ssrf")
        self.assertEqual(res["finding"]["rule_id"], "active.blind-ssrf-oob")
        self.assertEqual(res["attack_plan"]["proof_of_impact"]["status"], "confirmed")
        # A real collaborator hit is no longer a template CVSS guess.
        self.assertFalse(res["attack_plan"]["cvss"]["estimated"])
        # the probe injected the unique callback token into the target's 'url' param
        # (the callback URL is urlencoded, so the surrounding /oob/ becomes %2Foob%2F).
        self.assertTrue(any(seen["token"] in u for u in http.fetched))
        # no target data is embedded — the proof is the OOB callback
        self.assertEqual(res["finding"]["snippet"], "")

    def test_crawler_callback_is_candidate_not_confirmed(self) -> None:
        # A hit from a social unfurler / search crawler is NOT the target's own SSRF fetch.
        oob.poll_collaborator = self._staged_poll({"method": "GET", "ip": "1.1.1.1", "headers": {"user-agent": "Slackbot-LinkExpanding 1.0"}})
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=FakeHttp(), poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "candidate")
        self.assertEqual(res["attack_plan"]["proof_of_impact"]["status"], "candidate")
        self.assertTrue(res["attack_plan"]["cvss"]["estimated"])  # unverified source stays a template estimate

    def test_no_callback_does_not_confirm(self) -> None:
        oob.poll_collaborator = lambda base, secret, token, **k: {"ok": True, "count": 0, "hits": []}
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=FakeHttp(), poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "no-callback")
        self.assertNotIn("finding", res)

    def test_stale_token_with_preexisting_hits_is_skipped(self) -> None:
        # If the fresh token already has hits (the negative control fails), don't confirm.
        oob.poll_collaborator = lambda base, secret, token, **k: {"ok": True, "count": 5, "hits": [{"method": "GET", "ip": "2.2.2.2", "headers": {}}]}
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=FakeHttp(), poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "no-callback")

    def test_out_of_scope_target_refused(self) -> None:
        res = oob.confirm_blind_ssrf(
            "https://evil.example/?url=x", base="https://collab.example", secret="s" * 16,
            scope="other.example", settings=get_settings(), http=FakeHttp(), poll_delay_s=0.0)
        self.assertFalse(res["ok"])
        self.assertIn("scope", res["error"].lower())

    def test_unconfigured_collaborator_errors(self) -> None:
        res = oob.confirm_blind_ssrf("https://app.example.com/?url=x", base="", secret="",
                                     scope="app.example.com", settings=get_settings())
        self.assertFalse(res["ok"])
        self.assertIn("collaborator", res["error"].lower())

    def test_all_pre_probe_polls_failing_returns_an_error_not_no_callback(self) -> None:
        # Every param's PRE-PROBE poll (the negative-control check) fails -- no param is
        # ever actually tried, so this must surface as a real error (ok=False), not the
        # misleadingly-clean 'no-callback' status (which would imply the probe RAN and
        # genuinely saw nothing).
        oob.poll_collaborator = lambda base, secret, token, **k: {"ok": False, "error": "collaborator unreachable"}
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=FakeHttp(), poll_attempts=1, poll_delay_s=0.0)
        self.assertFalse(res["ok"])
        self.assertIn("collaborator unreachable", res["error"])

    def test_transient_poll_failure_on_one_param_does_not_abort_the_sweep(self) -> None:
        # A transient poll failure for ONE param's in-loop attempt must `break` to the
        # NEXT param (continuing the sweep), not abort the whole probe -- the next
        # candidate param still gets a fair shot and can still confirm.
        calls = {"n": 0}

        def fake_poll(base, secret, token, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"ok": True, "count": 0, "hits": []}      # param 1 pre-probe: clean
            if calls["n"] == 2:
                return {"ok": False, "error": "transient timeout"}  # param 1 poll-attempt: fails -> break
            if calls["n"] == 3:
                return {"ok": True, "count": 0, "hits": []}      # param 2 pre-probe: clean
            return {"ok": True, "count": 1, "hits": [{"method": "GET", "ip": "9.9.9.9",
                    "headers": {"user-agent": "Go-http-client/1.1"}}]}  # param 2 poll-attempt: HIT
        oob.poll_collaborator = fake_poll
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x&next=y", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=FakeHttp(), poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["param"], "next")  # confirmed via the SECOND param, after param 1's transient failure

    def test_websitefetcherror_on_one_params_probe_does_not_abort_the_sweep(self) -> None:
        # Regression: only _ActiveError was caught around http.fetch() in the
        # per-param probe loop, but _Http.fetch() can also raise WebsiteFetchError (a
        # ValueError subclass) -- e.g. this param's probe URL grew past
        # MAX_URL_LENGTH, or the target's DNS answer changed to private mid-sweep.
        # That used to propagate out of confirm_blind_ssrf entirely, aborting every
        # param ordered after the one that raised.
        class RaisingThenOkHttp:
            def __init__(self) -> None:
                self.calls = 0

            def fetch(self, url, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise oob.WebsiteFetchError("simulated: URL too long")
                return {"status": 200, "headers": {}, "body": "", "cookies": [], "final_url": url, "location": None}

        oob.poll_collaborator = self._staged_poll({"method": "GET", "ip": "9.9.9.9",
                                                    "headers": {"user-agent": "Go-http-client/1.1"}})
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x&next=y", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=RaisingThenOkHttp(), poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["param"], "next")  # confirmed via the SECOND param, after param 1's WebsiteFetchError


class XxeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._guard = oob._guard_url
        self._poll = oob.poll_collaborator
        self._post = oob._post_xml
        oob._guard_url = lambda u, *a, **k: u
        self.cfg = {"base": "https://collab.example", "secret": "s" * 16,
                    "scope": "app.example.com", "settings": get_settings()}

    def tearDown(self) -> None:
        oob._guard_url = self._guard
        oob.poll_collaborator = self._poll
        oob._post_xml = self._post

    def test_xxe_finding_carries_confirmed_active_proof(self) -> None:
        # The autonomous XXE pass appends this finding to raw_findings; like the SSRF sibling it MUST
        # carry the active-proof carriers, or a genuinely OOB-proven XXE renders as 'missing' (class
        # 'xxe' is not a deterministic-artifact category) instead of confirmed. Regression guard.
        from bughunter import report
        hit = {"method": "GET", "ip": "203.0.113.9", "path": "/oob/tok", "headers": {"user-agent": "curl/8.0"}}
        f = oob._xxe_finding_from_hit("https://app.example.com/import", "tok", "https://collab.example", hit)["finding"]
        self.assertEqual(f["_active_class_hint"], "xxe")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("control_result", f["_active_proof"])          # fresh-token negative control
        self.assertEqual(f["_active_cvss"]["base_severity"], "High")
        # XXE's vector is PR:N/S:C (8.6) — its score was already right; only the band's case changed when
        # the block moved to impact_model.cvss_block.
        self.assertEqual(f["_active_cvss"]["base_score"], 8.6)
        # end-to-end: the carriers make it a CAPTURED ARTIFACT, so the report renders it confirmed
        poi = f["_active_proof"]
        self.assertTrue(report._has_captured_artifact(f, poi, poi.get("observed_result", "")))

    def test_crawler_ua_xxe_hit_is_candidate_not_confirmed(self) -> None:
        hit = {"method": "GET", "ip": "1.2.3.4", "path": "/oob/tok", "headers": {"user-agent": "Slackbot-LinkExpanding 1.0"}}
        res = oob._xxe_finding_from_hit("https://app.example.com/import", "tok", "https://collab.example", hit)
        self.assertEqual(res["status"], "candidate")
        self.assertEqual(res["finding"]["_active_proof"]["status"], "candidate")

    def test_payloads_embed_the_callback_as_an_external_entity(self) -> None:
        p = oob.build_xxe_payloads("https://collab.example", "deadbeef")
        cb = "https://collab.example/oob/deadbeef"
        self.assertIn(cb, p["classic"])
        self.assertIn("<!ENTITY xxe SYSTEM", p["classic"])
        for variant in ("classic", "parameter_entity", "svg", "soap"):
            self.assertIn("deadbeef", p[variant])

    def test_assisted_mode_returns_ready_kit_without_sending(self) -> None:
        # Fresh assisted call: hand back payloads + token, send NOTHING (GET-only preserved).
        posted = []
        oob._post_xml = lambda url, xml, **k: posted.append(url) or {"ok": True, "status": 200}
        res = oob.confirm_blind_xxe("https://app.example.com/import", **self.cfg)
        self.assertEqual(res["status"], "ready")
        self.assertIn("classic", res["payloads"])
        self.assertTrue(res["token"])
        self.assertEqual(posted, [])  # nothing was POSTed in assisted mode

    def test_assisted_repoll_confirms_on_a_hit(self) -> None:
        hit = {"method": "GET", "ip": "9.9.9.9", "headers": {"user-agent": "Java/1.8.0"}}
        oob.poll_collaborator = lambda base, secret, token, **k: {"ok": True, "count": 1, "hits": [{**hit, "path": f"/oob/{token}"}]}
        res = oob.confirm_blind_xxe("https://app.example.com/import", token="abc123token", **self.cfg)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["finding"]["class_id"], "xxe")
        self.assertEqual(res["finding"]["rule_id"], "active.blind-xxe-oob")
        self.assertEqual(res["finding"]["snippet"], "")  # no file exfiltrated
        self.assertEqual(res["attack_plan"]["proof_of_impact"]["status"], "confirmed")
        self.assertFalse(res["attack_plan"]["cvss"]["estimated"])

    def test_auto_send_posts_then_confirms(self) -> None:
        sent = []
        oob._post_xml = lambda url, xml, **k: sent.append((url, xml)) or {"ok": True, "status": 200}
        # staged poll: empty first (negative control), hit after.
        calls = {}
        def staged(base, secret, token, **k):
            calls[token] = calls.get(token, 0) + 1
            if calls[token] == 1:
                return {"ok": True, "count": 0, "hits": []}
            return {"ok": True, "count": 1, "hits": [{"method": "GET", "ip": "9.9.9.9", "headers": {"user-agent": "Go-http-client/1.1"}, "path": f"/oob/{token}"}]}
        oob.poll_collaborator = staged
        res = oob.confirm_blind_xxe("https://app.example.com/import", send=True, poll_attempts=1, poll_delay_s=0.0, **self.cfg)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(len(sent), 1)              # exactly one POST
        self.assertIn("<!ENTITY xxe SYSTEM", sent[0][1])  # the classic XXE payload body

    def test_auto_send_crawler_hit_is_candidate(self) -> None:
        oob._post_xml = lambda url, xml, **k: {"ok": True, "status": 200}
        calls = {}
        def staged(base, secret, token, **k):
            calls[token] = calls.get(token, 0) + 1
            if calls[token] == 1:
                return {"ok": True, "count": 0, "hits": []}
            return {"ok": True, "count": 1, "hits": [{"method": "GET", "ip": "1.1.1.1", "headers": {"user-agent": "Twitterbot/1.0"}, "path": f"/oob/{token}"}]}
        oob.poll_collaborator = staged
        res = oob.confirm_blind_xxe("https://app.example.com/import", send=True, poll_attempts=1, poll_delay_s=0.0, **self.cfg)
        self.assertEqual(res["status"], "candidate")

    def test_auto_send_negative_control_blocks_a_dirty_token(self) -> None:
        # Token already has hits before the POST -> can't attribute -> refuse.
        oob._post_xml = lambda url, xml, **k: {"ok": True, "status": 200}
        oob.poll_collaborator = lambda base, secret, token, **k: {"ok": True, "count": 3, "hits": [{}]}
        res = oob.confirm_blind_xxe("https://app.example.com/import", send=True, poll_delay_s=0.0, **self.cfg)
        self.assertFalse(res["ok"])
        self.assertIn("already has hits", res["error"])

    def test_auto_send_post_failure_is_reported(self) -> None:
        oob._post_xml = lambda url, xml, **k: {"ok": False, "error": "connection refused"}
        oob.poll_collaborator = lambda base, secret, token, **k: {"ok": True, "count": 0, "hits": []}
        res = oob.confirm_blind_xxe("https://app.example.com/import", send=True, poll_delay_s=0.0, **self.cfg)
        self.assertEqual(res["status"], "send-failed")

    def test_out_of_scope_target_refused(self) -> None:
        res = oob.confirm_blind_xxe("https://evil.example/import", base="https://collab.example",
                                    secret="s" * 16, scope="other.example", settings=get_settings())
        self.assertFalse(res["ok"])
        self.assertIn("scope", res["error"].lower())


class PollCollaboratorRealResponseTests(unittest.TestCase):
    """The REAL poll_collaborator (not stubbed) against a local server: a misconfigured
    tunnel/proxy, a load-balancer error page rendered as JSON, or a buggy collaborator can
    return a non-object JSON body (array/string/number) -- the poll must degrade cleanly,
    never raise."""

    def _serve(self, body: bytes) -> int:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_port

    def test_normal_object_body_parses(self) -> None:
        port = self._serve(b'{"count": 2, "hits": [{"ip": "1.1.1.1"}]}')
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 2)
        self.assertEqual(len(res["hits"]), 1)

    def test_json_array_body_does_not_crash(self) -> None:
        port = self._serve(b'[{"ip": "1.1.1.1"}]')
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 0)
        self.assertEqual(res["hits"], [])

    def test_json_string_body_does_not_crash(self) -> None:
        port = self._serve(b'"ok"')
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 0)

    def test_json_number_body_does_not_crash(self) -> None:
        port = self._serve(b"5")
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 0)


if __name__ == "__main__":
    unittest.main()
