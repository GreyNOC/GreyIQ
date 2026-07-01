"""Tests for the opt-in ACTIVE proof-capture verifier.

Unit tests drive the per-check logic through a recording stub (no network);
end-to-end tests run the real verifier (and a full bounty hunt) against a local
HTTP server with GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1 so 127.0.0.1 is reachable.
Safety is asserted directly: only GET/HEAD/OPTIONS are ever issued, an
out-of-scope host triggers zero requests, and 'confirmed' requires a control
differential.
"""
from __future__ import annotations

import os
import re
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import active_verify_service as av  # noqa: E402
from bughunter import web_ingest  # noqa: E402
from bughunter.rate_limit import HostRateGovernor  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


class _Stub:
    """Records methods and returns canned responses keyed off the crafted request."""

    def __init__(self, *, cors_credentialed: bool = True, reflect_control_origin: bool = True) -> None:
        self.methods: list[str] = []
        self.cors_credentialed = cors_credentialed
        self.reflect_control_origin = reflect_control_origin

    def fetch(self, url: str, *, method: str = "GET", extra_headers=None) -> dict:
        self.methods.append(method)
        h = {k.lower(): v for k, v in (extra_headers or {}).items()}
        headers: dict[str, str] = {}
        status, location, body = 200, None, ""
        origin = h.get("origin")
        if origin == av._MARKER_ORIGIN:
            headers["access-control-allow-origin"] = origin
            if self.cors_credentialed:
                headers["access-control-allow-credentials"] = "true"
        elif origin and self.reflect_control_origin:
            headers["access-control-allow-origin"] = origin
        q = parse_qs(urlparse(url).query, keep_blank_values=True)
        nxt = (q.get("next") or [""])[0]
        if av._MARKER_HOST in nxt:
            status, location = 302, av._MARKER_ORIGIN + "/"
        reflected = " ".join(v for vals in q.values() for v in vals)
        body = f"<html>echo {reflected}</html>"
        if h.get("host") == av._MARKER_HOST:
            location = f"http://{av._MARKER_HOST}/x"
        return {"status": status, "headers": headers, "cookies": [], "body": body, "truncated": False, "final_url": url, "location": location}


class ActiveCheckTests(unittest.TestCase):
    URL = "https://app.example.com/?q=x&next=/home"

    def test_cors_credentialed_reflection_confirms(self) -> None:
        f = av._check_cors(_Stub(), self.URL)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("Access-Control-Allow-Origin", f["proof_evidence"]["matched_value"])

    def test_cors_without_credentials_is_candidate_not_confirmed(self) -> None:
        f = av._check_cors(_Stub(cors_credentialed=False), self.URL)
        self.assertEqual(f["_active_proof"]["status"], "candidate")

    def test_reflected_xss_unescaped_confirms_with_control(self) -> None:
        f = av._check_reflected_xss(_Stub(), self.URL)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["_active_class_hint"], "xss")

    def test_open_redirect_confirms_and_is_not_followed(self) -> None:
        f = av._check_open_redirect(_Stub(), self.URL)
        self.assertEqual(f["rule_id"], "active.open-redirect")
        self.assertIn(av._MARKER_HOST, f["proof_evidence"]["matched_value"])

    def test_open_redirect_confirms_on_protocol_relative_location(self) -> None:
        # 'Location: //evil/' (no scheme) is one of the most common, fully browser-
        # exploitable open-redirect shapes -- a naive 'http://x' + location parse mis-reads
        # its host as 'x' instead of the real target. Must still confirm.
        class ProtocolRelativeStub(_Stub):
            def fetch(self, url, *, method="GET", extra_headers=None):
                r = super().fetch(url, method=method, extra_headers=extra_headers)
                if r.get("location") == av._MARKER_ORIGIN + "/":
                    r["location"] = "//" + av._MARKER_HOST + "/"  # strip the scheme
                    r["status"] = 302
                return r
        f = av._check_open_redirect(ProtocolRelativeStub(), self.URL)
        self.assertIsNotNone(f)
        self.assertEqual(f["rule_id"], "active.open-redirect")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_only_safe_methods_are_ever_issued(self) -> None:
        stub = _Stub()
        for check in (av._check_cors, av._check_open_redirect, av._check_reflected_xss, av._check_host_header,
                      av._check_ssti, av._check_error_sqli, av._check_bool_sqli, av._check_crlf):
            check(stub, self.URL)
        av._check_clickjacking(stub, self.URL, None)
        self.assertTrue(set(stub.methods) <= {"GET", "HEAD", "OPTIONS"}, stub.methods)

    def test_clickjacking_is_candidate_not_confirmed(self) -> None:
        resp = {"status": 200, "headers": {}, "body": "", "cookies": [], "location": None}
        f = av._check_clickjacking(_Stub(), self.URL, resp)
        self.assertEqual(f["_active_proof"]["status"], "candidate")
        self.assertTrue(f["_active_proof"]["proof_obligation"])  # tells the operator how to prove it

    def test_xss_non_html_content_type_is_not_confirmed(self) -> None:
        class JsonStub(_Stub):
            def fetch(self, url, *, method="GET", extra_headers=None):
                r = super().fetch(url, method=method, extra_headers=extra_headers)
                r["headers"]["content-type"] = "application/json"
                return r
        # A verbatim reflection into application/json is not browser-executable XSS.
        self.assertIsNone(av._check_reflected_xss(JsonStub(), self.URL))

    def test_sqli_does_not_confirm_on_non_sql_error(self) -> None:
        class TracebackStub:  # the injected quote (%27) breaks a NON-SQL path
            def fetch(self, url, *, method="GET", extra_headers=None):
                body = "Traceback (most recent call last): KeyError" if "%27" in url else "ok"
                return {"status": 500, "headers": {}, "body": body, "cookies": [], "location": None}
        self.assertIsNone(av._check_error_sqli(TracebackStub(), "https://app.example.com/?id=1"))

    def test_sqli_confirms_on_real_sql_error(self) -> None:
        class SqlStub:  # the injected quote (%27) produces a real DB error banner
            def fetch(self, url, *, method="GET", extra_headers=None):
                body = "You have an error in your SQL syntax near" if "%27" in url else "ok"
                return {"status": 500, "headers": {}, "body": body, "cookies": [], "location": None}
        f = av._check_error_sqli(SqlStub(), "https://app.example.com/?id=1")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_csrf_candidate_on_tokenless_post_form(self) -> None:
        landing = {"body": '<form method="POST" action="/transfer"><input name="amount"></form>',
                   "cookies": [], "final_url": "https://app.example.com/pay"}
        f = av._check_csrf(landing, "https://app.example.com/pay")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "candidate")
        self.assertEqual(f["_active_class_hint"], "csrf")
        self.assertEqual(f["severity"], "low")

    def test_csrf_skips_form_with_token(self) -> None:
        landing = {"body": '<form method="post"><input type="hidden" name="csrf_token" value="x"><input name="amount"></form>',
                   "cookies": [], "final_url": "u"}
        self.assertIsNone(av._check_csrf(landing, "https://app.example.com/pay"))

    def test_csrf_skips_when_meta_csrf_token_present(self) -> None:
        landing = {"body": '<head><meta name="csrf-token" content="abc"></head><form method="post"><input name="x"></form>',
                   "cookies": [], "final_url": "u"}
        self.assertIsNone(av._check_csrf(landing, "https://app.example.com/pay"))

    def test_csrf_skips_when_cookie_is_samesite_lax(self) -> None:
        landing = {"body": '<form method="post"><input name="amount"></form>',
                   "cookies": ["sid=abc; Path=/; HttpOnly; SameSite=Lax"], "final_url": "u"}
        self.assertIsNone(av._check_csrf(landing, "https://app.example.com/pay"))

    def test_csrf_medium_when_cookie_is_samesite_none(self) -> None:
        landing = {"body": '<form method="post"><input name="amount"></form>',
                   "cookies": ["sid=abc; Path=/; Secure; SameSite=None"], "final_url": "u"}
        f = av._check_csrf(landing, "https://app.example.com/pay")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "medium")

    def test_csrf_ignores_get_forms(self) -> None:
        landing = {"body": '<form method="get" action="/search"><input name="q"></form>', "cookies": [], "final_url": "u"}
        self.assertIsNone(av._check_csrf(landing, "https://app.example.com/"))

    def test_nosqli_confirms_on_operator_object_error(self) -> None:
        # The param sent as {$ne: ...} (encoded %24ne) breaks a typed Mongoose field -> CastError.
        class MongoStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                body = "CastError: Cast to ObjectId failed for value" if "%24ne" in url else "ok"
                return {"status": 500 if "%24ne" in url else 200, "headers": {}, "body": body, "cookies": [], "location": None}
        f = av._check_nosqli(MongoStub(), "https://app.example.com/?id=1")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["_active_class_hint"], "nosqli")
        self.assertEqual(f["rule_id"], "active.nosqli-error")

    def test_nosqli_does_not_confirm_on_generic_error(self) -> None:
        # A generic stack trace from the operator object is NOT a NoSQL backend error.
        class TracebackStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                body = "Traceback (most recent call last): TypeError" if "%24ne" in url else "ok"
                return {"status": 500, "headers": {}, "body": body, "cookies": [], "location": None}
        self.assertIsNone(av._check_nosqli(TracebackStub(), "https://app.example.com/?id=1"))

    def test_nosqli_does_not_confirm_when_banner_is_always_present(self) -> None:
        # A page that always shows a Mongo banner (e.g. a debug console) fails the control.
        class AlwaysStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "body": "MongoServerError: something", "cookies": [], "location": None}
        self.assertIsNone(av._check_nosqli(AlwaysStub(), "https://app.example.com/?id=1"))

    def test_nosqli_needs_a_param(self) -> None:
        class Stub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "body": "MongoError", "cookies": [], "location": None}
        self.assertIsNone(av._check_nosqli(Stub(), "https://app.example.com/"))  # no param to perturb

    def test_ssti_confirms_when_expression_is_evaluated(self) -> None:
        class TemplateStub:  # a real template engine evaluates {{7*7}} -> 49
            def fetch(self, url, *, method="GET", extra_headers=None):
                val = (parse_qs(urlparse(url).query, keep_blank_values=True).get("q") or [""])[0]
                rendered = val.replace("{{7*7}}", "49")
                return {"status": 200, "headers": {"content-type": "text/html"}, "cookies": [],
                        "body": f"<html>{rendered}</html>", "final_url": url, "location": None}
        f = av._check_ssti(TemplateStub(), self.URL)
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["_active_class_hint"], "ssti")
        self.assertEqual(f["rule_id"], "active.ssti")

    def test_ssti_does_not_confirm_on_verbatim_reflection(self) -> None:
        class LiteralStub:  # no template engine — reflects {{7*7}} verbatim
            def fetch(self, url, *, method="GET", extra_headers=None):
                val = (parse_qs(urlparse(url).query, keep_blank_values=True).get("q") or [""])[0]
                return {"status": 200, "headers": {"content-type": "text/html"}, "cookies": [],
                        "body": f"<html>{val}</html>", "final_url": url, "location": None}
        self.assertIsNone(av._check_ssti(LiteralStub(), self.URL))

    def test_bool_sqli_confirms_on_stable_differential(self) -> None:
        class BoolStub:  # stable page; FALSE condition returns a much shorter page
            def fetch(self, url, *, method="GET", extra_headers=None):
                body = "x" * 800
                if "1'='2" in url or "1%27%3D%272" in url:
                    body = "x" * 200  # FALSE branch diverges materially
                return {"status": 200, "headers": {}, "body": body, "cookies": [], "final_url": url, "location": None}
        f = av._check_bool_sqli(BoolStub(), "https://app.example.com/?id=1")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["rule_id"], "active.sqli-boolean")

    def test_bool_sqli_does_not_confirm_on_dynamic_page(self) -> None:
        import itertools
        class FlapStub:  # the page flaps on its own — not safely differentiable
            def __init__(self): self._n = itertools.count()
            def fetch(self, url, *, method="GET", extra_headers=None):
                body = "x" * (300 + (next(self._n) % 2) * 500)  # alternates 300/800
                return {"status": 200, "headers": {}, "body": body, "cookies": [], "final_url": url, "location": None}
        self.assertIsNone(av._check_bool_sqli(FlapStub(), "https://app.example.com/?id=1"))

    def test_bool_sqli_does_not_confirm_when_param_ignored(self) -> None:
        class IgnoreStub:  # every response identical — the param has no effect
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "body": "x" * 500, "cookies": [], "final_url": url, "location": None}
        self.assertIsNone(av._check_bool_sqli(IgnoreStub(), "https://app.example.com/?id=1"))

    def test_bool_sqli_does_not_confirm_on_waf_block_page(self) -> None:
        # The FALSE payload is blocked by a WAF (403, different length). That length
        # differential is infrastructure, not a DB boolean — must NOT confirm.
        class WafStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                if "1'='2" in url or "1%27%3D%272" in url:
                    return {"status": 403, "headers": {}, "body": "Request blocked by WAF. " + "z" * 300, "cookies": [], "final_url": url, "location": None}
                return {"status": 200, "headers": {}, "body": "x" * 800, "cookies": [], "final_url": url, "location": None}
        self.assertIsNone(av._check_bool_sqli(WafStub(), "https://app.example.com/?id=1"))

    def test_host_header_body_only_reflection_is_candidate(self) -> None:
        # Host reflected only into the BODY (common, usually harmless) -> candidate, not confirmed.
        class BodyEchoStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                h = {k.lower(): v for k, v in (extra_headers or {}).items()}
                body = f"<html>host={h.get('host', '')}</html>" if "host" in h else "<html>host=real</html>"
                return {"status": 200, "headers": {}, "cookies": [], "body": body, "final_url": url, "location": None}
        f = av._check_host_header(BodyEchoStub(), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "candidate")

    def test_host_header_location_reflection_is_confirmed(self) -> None:
        # Host reflected into a redirect Location (password-reset/cache poisoning) is
        # genuinely actionable -> CONFIRMED, medium severity, distinct from the
        # body-only candidate case above. No coverage of this branch before this.
        class LocationEchoStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                h = {k.lower(): v for k, v in (extra_headers or {}).items()}
                if h.get("host") == av._MARKER_HOST:
                    return {"status": 302, "headers": {}, "cookies": [], "body": "",
                            "final_url": url, "location": f"https://{av._MARKER_HOST}/reset?token=abc"}
                return {"status": 200, "headers": {}, "cookies": [], "body": "<html>ok</html>",
                        "final_url": url, "location": None}
        f = av._check_host_header(LocationEchoStub(), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["rule_id"], "active.host-header-injection")
        self.assertIn("Location header", f["proof_evidence"]["matched_value"])

    def test_host_header_marker_present_in_unmodified_control_is_not_host_driven(self) -> None:
        # The marker host shows up EVEN WITHOUT our injected Host header (e.g. it's
        # coincidentally part of the real site's own content) -> not attacker-controlled,
        # must not report anything at all.
        class AlwaysPresentStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 302, "headers": {}, "cookies": [], "body": "",
                        "final_url": url, "location": f"https://{av._MARKER_HOST}/always"}
        self.assertIsNone(av._check_host_header(AlwaysPresentStub(), "https://app.example.com/"))

    def test_crlf_confirms_when_header_is_split_out(self) -> None:
        class CrlfStub:  # server reflects the CRLF-injected value as a real header
            def fetch(self, url, *, method="GET", extra_headers=None):
                headers = {}
                if "%0d%0a" in url.lower():
                    headers["x-greyiq-crlf"] = av._MARK
                return {"status": 200, "headers": headers, "body": "", "cookies": [], "final_url": url, "location": None}
        f = av._check_crlf(CrlfStub(), "https://app.example.com/?next=/home")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["rule_id"], "active.crlf")

    def test_crlf_does_not_confirm_without_split(self) -> None:
        class NoSplitStub:  # value reflected in body but NOT split into a header
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "body": "echo", "cookies": [], "final_url": url, "location": None}
        self.assertIsNone(av._check_crlf(NoSplitStub(), "https://app.example.com/?next=/home"))

    def test_cors_null_origin_confirms(self) -> None:
        class NullCorsStub:  # trusts ONLY Origin: null (so variant 1 fails, variant 2 confirms)
            def fetch(self, url, *, method="GET", extra_headers=None):
                origin = {k.lower(): v for k, v in (extra_headers or {}).items()}.get("origin")
                headers = {}
                if origin == "null":
                    headers["access-control-allow-origin"] = "null"
                    headers["access-control-allow-credentials"] = "true"
                return {"status": 200, "headers": headers, "cookies": [], "body": "", "final_url": url, "location": None}
        f = av._check_cors(NullCorsStub(), "https://app.example.com/?q=x")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("null", f["proof_evidence"]["matched_value"])

    def test_cors_subdomain_origin_confirms(self) -> None:
        class SubCorsStub:  # reflects any subdomain of the host with credentials
            def fetch(self, url, *, method="GET", extra_headers=None):
                origin = {k.lower(): v for k, v in (extra_headers or {}).items()}.get("origin") or ""
                headers = {}
                host = urlparse(url).hostname or ""
                if origin.endswith("." + host) and origin != f"https://{host}":
                    headers["access-control-allow-origin"] = origin
                    headers["access-control-allow-credentials"] = "true"
                return {"status": 200, "headers": headers, "cookies": [], "body": "", "final_url": url, "location": None}
        f = av._check_cors(SubCorsStub(), "https://app.example.com/?q=x")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn(av._MARK, f["proof_evidence"]["matched_value"])

    def test_ssti_does_not_confirm_on_coincidental_49(self) -> None:
        class Coincidental49Stub:  # the page contains '49' but never evaluates the marker
            def fetch(self, url, *, method="GET", extra_headers=None):
                val = (parse_qs(urlparse(url).query, keep_blank_values=True).get("q") or [""])[0]
                return {"status": 200, "headers": {"content-type": "text/html"}, "cookies": [],
                        "body": f"<html>49 results for {val}</html>", "final_url": url, "location": None}
        self.assertIsNone(av._check_ssti(Coincidental49Stub(), self.URL))

    # ---- time-based blind SQLi (opt-in; the one executing payload) -----------------
    def test_time_sqli_confirms_on_stable_delay_differential(self) -> None:
        class TimeStub:  # only SLEEP(4) is slow; baseline and SLEEP(0) are fast
            def fetch(self, url, *, method="GET", extra_headers=None):
                val = (parse_qs(urlparse(url).query, keep_blank_values=True).get("id") or [""])[0]
                elapsed = 4.4 if "SLEEP(4)" in val else 0.05
                return {"status": 200, "headers": {}, "cookies": [], "body": "ok",
                        "final_url": url, "location": None, "elapsed": elapsed}
        f = av._check_time_sqli(TimeStub(), "https://app.example.com/?id=1")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["rule_id"], "active.sqli-time")
        self.assertEqual(f["_active_class_hint"], "sqli")

    def test_time_sqli_does_not_confirm_on_uniformly_slow_page(self) -> None:
        class SlowStub:  # the page is slow for EVERY request — no differential
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "cookies": [], "body": "ok",
                        "final_url": url, "location": None, "elapsed": 4.5}
        self.assertIsNone(av._check_time_sqli(SlowStub(), "https://app.example.com/?id=1"))

    def test_time_sqli_requires_both_trials_slow(self) -> None:
        # base, SLEEP(0) control, then the two SLEEP(4) trials — only the FIRST is slow.
        seq = iter([0.05, 0.05, 4.4, 0.05])
        class JitterStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "cookies": [], "body": "ok",
                        "final_url": url, "location": None, "elapsed": next(seq)}
        self.assertIsNone(av._check_time_sqli(JitterStub(), "https://app.example.com/?id=1"))

    def test_time_sqli_skips_when_no_param(self) -> None:
        self.assertIsNone(av._check_time_sqli(_Stub(), "https://app.example.com/"))

    def test_time_sqli_off_by_default_in_verify_active_checks(self) -> None:
        # The opt-in probe must NOT be in the default check set (only added when time_based=True).
        import inspect
        src = inspect.getsource(av.verify_active)
        self.assertIn("if time_based:", src)
        self.assertIn("_check_time_sqli", src)

    # ---- open cloud-bucket exposure (GET-only, scope-gated) ------------------------
    def test_open_bucket_confirms_on_public_listing(self) -> None:
        s = get_settings()
        bucket = "https://acme-uploads.s3.amazonaws.com/"
        landing = {"body": f'<img src="{bucket}logo.png">', "status": 200, "headers": {}}
        class ListingStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                self_url = url
                return {"status": 200, "headers": {}, "cookies": [], "final_url": self_url, "location": None,
                        "body": '<?xml version="1.0"?><ListBucketResult><Contents><Key>db-backup.sql</Key></Contents></ListBucketResult>'}
        f = av._check_open_bucket(ListingStub(), landing, "acme-uploads.s3.amazonaws.com", s)
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["rule_id"], "active.open-bucket")
        self.assertEqual(f["_active_class_hint"], "cloud-exposure")
        self.assertNotIn("db-backup.sql", str(f))  # object keys are never echoed

    def test_open_bucket_access_denied_is_candidate(self) -> None:
        s = get_settings()
        bucket = "https://acme-locked.s3.amazonaws.com/"
        landing = {"body": f'config: {bucket}private', "status": 200, "headers": {}}
        class DeniedStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 403, "headers": {}, "cookies": [], "final_url": url, "location": None,
                        "body": '<Error><Code>AccessDenied</Code></Error>'}
        f = av._check_open_bucket(DeniedStub(), landing, "acme-locked.s3.amazonaws.com", s)
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "candidate")
        self.assertEqual(f["rule_id"], "active.open-bucket")

    def test_open_bucket_out_of_scope_host_is_never_probed(self) -> None:
        s = get_settings()
        bucket = "https://thirdparty.s3.amazonaws.com/"
        landing = {"body": f'cdn {bucket}asset.js', "status": 200, "headers": {}}
        class NeverStub:
            def __init__(self): self.called = False
            def fetch(self, url, *, method="GET", extra_headers=None):
                self.called = True
                return {"status": 200, "headers": {}, "cookies": [], "body": "", "final_url": url, "location": None}
        stub = NeverStub()
        # Scope names the app host, NOT the bucket host → the bucket must never be fetched.
        f = av._check_open_bucket(stub, landing, "app.example.com", s)
        self.assertFalse(stub.called)
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "candidate")
        self.assertEqual(f["severity"], "info")

    def test_open_bucket_returns_none_when_no_buckets_referenced(self) -> None:
        s = get_settings()
        f = av._check_open_bucket(_Stub(), {"body": "<html>nothing to see</html>"}, "app.example.com", s)
        self.assertIsNone(f)

    def test_gcs_bucket_confirms_on_public_listing(self) -> None:
        # GCS's XML API returns the SAME ListBucketResult shape as S3 -- a bare GET to the
        # bucket root (no special query needed) already lists when public-read is granted.
        s = get_settings()
        bucket = "https://storage.googleapis.com/acme-public-bucket/logo.png"
        landing = {"body": f'<img src="{bucket}">', "status": 200, "headers": {}}
        seen = {}
        class GcsListingStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                seen["url"] = url
                return {"status": 200, "headers": {}, "cookies": [], "final_url": url, "location": None,
                        "body": '<?xml version="1.0"?><ListBucketResult><Contents><Key>data.csv</Key></Contents></ListBucketResult>'}
        f = av._check_open_bucket(GcsListingStub(), landing, "storage.googleapis.com", s)
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        # Listed against the BUCKET ROOT (acme-public-bucket), not the deep object path.
        self.assertEqual(seen["url"], "https://storage.googleapis.com/acme-public-bucket")

    def test_azure_container_confirms_on_public_listing(self) -> None:
        # Azure's listing endpoint needs an explicit restype=container&comp=list on the
        # CONTAINER root -- a bare GET (even to the root) does not return a listing.
        s = get_settings()
        bucket = "https://acmestorage.blob.core.windows.net/public-container/file.txt"
        landing = {"body": f'<script src="{bucket}"></script>', "status": 200, "headers": {}}
        seen = {}
        class AzureListingStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                seen["url"] = url
                return {"status": 200, "headers": {}, "cookies": [], "final_url": url, "location": None,
                        "body": '<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>secrets.json</Name></Blob></Blobs></EnumerationResults>'}
        f = av._check_open_bucket(AzureListingStub(), landing, "acmestorage.blob.core.windows.net", s)
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(seen["url"], "https://acmestorage.blob.core.windows.net/public-container?restype=container&comp=list")

    def test_azure_does_not_confirm_on_an_s3_gcs_shaped_body(self) -> None:
        # Cross-provider negative: an Azure container must NOT confirm on the S3/GCS body
        # shape (it never legitimately appears from Azure) -- providers are matched
        # against their OWN real response format, not a shared heuristic. A 200 response
        # that matches NEITHER the listing shape NOR an access-denied shape is genuinely
        # ambiguous, so no finding (confirmed or candidate) is emitted for it at all.
        s = get_settings()
        bucket = "https://acmestorage.blob.core.windows.net/container/file.txt"
        landing = {"body": f'<script src="{bucket}"></script>', "status": 200, "headers": {}}
        class WrongShapeStub:
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "cookies": [], "final_url": url, "location": None,
                        "body": '<?xml version="1.0"?><ListBucketResult><Contents><Key>x</Key></Contents></ListBucketResult>'}
        f = av._check_open_bucket(WrongShapeStub(), landing, "acmestorage.blob.core.windows.net", s)
        self.assertIsNone(f)


class WithOperatorTests(unittest.TestCase):
    """_with_operator's URL transformation (param -> param[$ne]=value, plain param
    dropped) -- only ever exercised indirectly through _check_nosqli before this."""

    def test_replaces_scalar_param_with_operator_object_key(self) -> None:
        out = av._with_operator("https://x/y?id=1&other=2", "id", "1")
        parsed = urlparse(out)
        q = dict(parse_qs(parsed.query))
        self.assertNotIn("id", q)                 # plain scalar param removed
        self.assertIn("id[$ne]", q)
        self.assertEqual(q["id[$ne]"], ["1"])
        self.assertEqual(q["other"], ["2"])        # unrelated params preserved

    def test_param_not_present_still_adds_operator_key(self) -> None:
        out = av._with_operator("https://x/y", "id", "1")
        self.assertIn("id%5B%24ne%5D=1", out)  # URL-encoded param[$ne]=1

    def test_path_and_host_are_untouched(self) -> None:
        out = av._with_operator("https://app.example.com/search?id=1", "id", "1")
        parsed = urlparse(out)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "app.example.com")
        self.assertEqual(parsed.path, "/search")


class NormLenTests(unittest.TestCase):
    """_norm_len collapses volatile whitespace so a stable page compares stably --
    only ever exercised indirectly through _check_bool_sqli before this."""

    def test_collapses_runs_of_whitespace_to_a_single_space(self) -> None:
        self.assertEqual(av._norm_len("a\n\n  b\t\tc"), len("a b c"))

    def test_identical_content_different_whitespace_normalizes_equal(self) -> None:
        self.assertEqual(av._norm_len("a\nb\nc"), av._norm_len("a   b   c"))

    def test_empty_and_none_are_zero(self) -> None:
        self.assertEqual(av._norm_len(""), 0)
        self.assertEqual(av._norm_len(None), 0)

    def test_leading_and_trailing_whitespace_still_counts_as_one_space(self) -> None:
        # re.sub collapses the run but does not strip() -- pinning current behavior.
        self.assertEqual(av._norm_len("  x  "), len(" x "))


class HttpPerHuntBudgetTests(unittest.TestCase):
    """_Http's per-hunt request budget (max_requests) is a SEPARATE ceiling from the
    per-host governor -- exhausting it must raise _RateLimited without ever touching
    the governor or the network for the request that trips it."""

    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"

    def tearDown(self) -> None:
        self.server.shutdown()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def test_budget_exhaustion_raises_rate_limited_after_the_nth_request(self) -> None:
        # Governor capacity is generous (20) so the GOVERNOR never trips here -- only
        # the per-hunt budget (max_requests=2) should.
        http = av._Http(get_settings(), HostRateGovernor(capacity=20, min_interval_s=0.0), max_requests=2)
        http.fetch(self.url)
        http.fetch(self.url)
        self.assertEqual(http.sent, 2)
        with self.assertRaises(av._RateLimited):
            http.fetch(self.url)
        self.assertEqual(http.sent, 2)  # the trip itself does not consume a slot

    def test_rate_limited_is_not_an_active_error_and_is_not_swallowed_by_per_check_handling(self) -> None:
        # _RateLimited is deliberately NOT an _ActiveError subclass so a per-check
        # `except _ActiveError` can't accidentally eat it and keep the pass going.
        self.assertFalse(issubclass(av._RateLimited, av._ActiveError))
        http = av._Http(get_settings(), HostRateGovernor(capacity=20, min_interval_s=0.0), max_requests=1)
        http.fetch(self.url)
        with self.assertRaises(av._RateLimited):
            try:
                http.fetch(self.url)
            except av._ActiveError:
                self.fail("_RateLimited must not be caught by an `except _ActiveError` handler")


class ParamDiscoveryTests(unittest.TestCase):
    """Recon-discovered parameter names let the param-keyed checks bite on endpoints
    that carry no query string of their own — the surface recon found but the prover
    previously ignored. The per-check request budget is unchanged: URL params come
    first, discovered names only fill the slots the URL didn't."""

    def test_candidate_params_url_first_then_discovered_deduped(self) -> None:
        # URL param first, then discovered (case-insensitive dedupe drops the dup 'A').
        out = av._candidate_params("https://h/x?a=1", ["A", "b", "c"], ("z",), 3)
        self.assertEqual(out, ["a", "b", "c"])

    def test_candidate_params_default_only_when_no_url_or_discovered(self) -> None:
        self.assertEqual(av._candidate_params("https://h/x", [], ("q",), 2), ["q"])
        self.assertEqual(av._candidate_params("https://h/x", ["p"], ("q",), 2), ["p"])  # discovered beats default

    def test_candidate_params_empty_default_bails(self) -> None:
        # SQLi checks pass default=() so a param-less URL with no discovered name yields
        # nothing — they never invent an injection point.
        self.assertEqual(av._candidate_params("https://h/x", [], (), 2), [])

    def test_clean_param_names_drops_malformed_dedupes_and_caps(self) -> None:
        cleaned = av._clean_param_names(["good", "al_so-ok", "user[id]", "bad name", "x" * 60, "9lead", "", "GOOD"])
        self.assertIn("good", cleaned)
        self.assertIn("user[id]", cleaned)            # PHP/Rails-style names are valid
        self.assertNotIn("bad name", cleaned)          # space → dropped
        self.assertNotIn("9lead", cleaned)             # must start with a letter/underscore
        self.assertEqual(sum(1 for n in cleaned if n.lower() == "good"), 1)  # case-insensitive dedupe
        capped = av._clean_param_names([f"p{i}" for i in range(100)])
        self.assertLessEqual(len(capped), av._MAX_DISCOVERED_PARAMS)

    def test_reflected_xss_fires_on_discovered_param_for_paramless_url(self) -> None:
        class OnlyKwStub:  # reflects ONLY the 'kw' param, unescaped, as HTML
            def fetch(self, url, *, method="GET", extra_headers=None):
                kw = (parse_qs(urlparse(url).query, keep_blank_values=True).get("kw") or [""])[0]
                return {"status": 200, "headers": {"content-type": "text/html"}, "cookies": [],
                        "body": f"<html>{kw}</html>", "final_url": url, "location": None}
        url = "https://app.example.com/profile"  # no query string of its own
        # Without the discovered name, the check guesses 'q'; the server ignores it → miss.
        self.assertIsNone(av._check_reflected_xss(OnlyKwStub(), url))
        # Recon found 'kw' (a form field / JS param) → the check now bites and confirms.
        f = av._check_reflected_xss(OnlyKwStub(), url, ["kw"])
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("kw", f["title"])

    def test_error_sqli_fires_on_discovered_param_for_paramless_url(self) -> None:
        class KwSqlStub:  # a quote in 'kw' yields a DB error banner; no 'kw' → clean
            def fetch(self, url, *, method="GET", extra_headers=None):
                kw = (parse_qs(urlparse(url).query, keep_blank_values=True).get("kw") or [""])[0]
                body = "You have an error in your SQL syntax near" if "'" in kw else "ok"
                return {"status": 200, "headers": {}, "body": body, "cookies": [], "final_url": url, "location": None}
        url = "https://app.example.com/list"
        self.assertIsNone(av._check_error_sqli(KwSqlStub(), url))      # no param → never invents one
        f = av._check_error_sqli(KwSqlStub(), url, ["kw"])             # discovered 'kw' → confirmed
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_redirect_candidates_pick_up_discovered_redirectish_param_only(self) -> None:
        cands = av._redirect_candidates("https://h/login", ["returnTo", "q", "csrf"], ("next",), 3)
        self.assertIn("returnTo", cands)     # redirect-ish discovered name is tried
        self.assertNotIn("q", cands)         # unrelated discovered names are not fuzzed
        self.assertNotIn("csrf", cands)

    def test_verify_active_sanitizes_extra_params_before_use(self) -> None:
        # An out-of-scope host returns before any probe, but the call must accept the
        # extra_params kwarg and not raise on malformed names.
        _, meta = av.verify_active("https://not-in-scope.example/", [], scope="other.example",
                                   extra_params=["ok_name", "bad name", "user[id]"])
        self.assertFalse(meta["in_scope"])


class ScopeBindingTests(unittest.TestCase):
    def test_named_host_in_scope(self) -> None:
        s = get_settings()
        self.assertTrue(av.host_in_active_scope("app.example.com", "program: *.example.com in scope", s))
        self.assertTrue(av.host_in_active_scope("example.com", "example.com", s))

    def test_unnamed_host_out_of_scope(self) -> None:
        s = get_settings()
        self.assertFalse(av.host_in_active_scope("evil.test", "example.com only", s))
        self.assertFalse(av.host_in_active_scope("evil.test", "", s))

    def test_substring_does_not_widen_scope(self) -> None:
        s = get_settings()
        # 'example.com' must NOT match a scope that only names 'notexample.com'.
        self.assertFalse(av.host_in_active_scope("example.com", "in scope: notexample.com", s))
        self.assertFalse(av.host_in_active_scope("evilexample.com", "example.com", s))
        # Proper subdomain / wildcard matching still works.
        self.assertTrue(av.host_in_active_scope("app.example.com", "*.example.com", s))
        self.assertTrue(av.host_in_active_scope("example.com", "https://example.com/login in scope", s))

    def test_bare_public_suffix_in_scope_text_does_not_authorize_the_whole_platform(self) -> None:
        # A scope token that is ITSELF a known multi-label public suffix (a shared PaaS
        # host) must never be treated as someone's own apex -- naming 'herokuapp.com' in
        # scope text (e.g. copied from a program description mentioning the platform, not
        # a specific app) must NOT authorize every unrelated tenant's *.herokuapp.com.
        s = get_settings()
        self.assertFalse(av.host_in_active_scope("victim-unrelated.herokuapp.com", "herokuapp.com", s))
        self.assertFalse(av.host_in_active_scope("herokuapp.com", "herokuapp.com", s))
        self.assertFalse(av.host_in_active_scope("someone-elses-blog.github.io", "scope: github.io", s))
        # A REAL owned app under that platform still works when the operator names the
        # FULL host they actually own (not the bare platform suffix).
        self.assertTrue(av.host_in_active_scope("myapp.herokuapp.com", "myapp.herokuapp.com", s))
        self.assertTrue(av.host_in_active_scope("api.myapp.herokuapp.com", "myapp.herokuapp.com", s))
        self.assertFalse(av.host_in_active_scope("other-app.herokuapp.com", "myapp.herokuapp.com", s))
        # Same protection for multi-label ccSLDs (co.uk): the bare suffix can't authorize
        # an unrelated co.uk site, but a real owned co.uk apex still works normally.
        self.assertFalse(av.host_in_active_scope("victim.co.uk", "co.uk", s))
        self.assertTrue(av.host_in_active_scope("shop.example.co.uk", "example.co.uk", s))

    def test_out_of_scope_target_makes_zero_requests(self) -> None:
        # No DNS, no network: scope is checked before the URL guard.
        findings, meta = av.verify_active("https://evil.test/", [], scope="example.com")
        self.assertEqual(findings, [])
        self.assertFalse(meta["in_scope"])
        self.assertIn("not named", meta["skipped_reason"])


class _SiteHandler(BaseHTTPRequestHandler):
    seen_methods: list[str] = []

    def _respond(self, status: int, headers: dict, body: bytes) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        _SiteHandler.seen_methods.append(self.command)
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        headers = {"Content-Type": "text/html"}  # intentionally NO X-Frame-Options (clickjacking)
        origin = self.headers.get("Origin")
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        nxt = (q.get("next") or [""])[0]
        if "greyiq-marker.example" in nxt:
            self._respond(302, {"Location": nxt}, b"")
            return
        reflected = " ".join(v for vals in q.values() for v in vals)  # raw reflection (XSS)
        self._respond(200, headers, f"<html>echo {reflected}</html>".encode())

    do_HEAD = do_GET

    def log_message(self, *args: object) -> None:
        return


class ActiveE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        _SiteHandler.seen_methods = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"

    def tearDown(self) -> None:
        self.server.shutdown()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def test_verify_active_confirms_classes_against_local_site(self) -> None:
        url = f"http://127.0.0.1:{self.port}/?q=x&next=/home"
        findings, meta = av.verify_active(url, [], scope="127.0.0.1")
        self.assertTrue(meta["in_scope"])
        status = {f["_active_class_hint"]: f["_active_proof"]["status"] for f in findings}
        # CORS / reflected-XSS (html) / open-redirect have real control differentials -> confirmed.
        self.assertEqual(status.get("cors"), "confirmed")
        self.assertEqual(status.get("xss"), "confirmed")
        self.assertEqual(status.get("redirect"), "confirmed")
        # Clickjacking is header-only (no differential) -> honestly a candidate, not confirmed.
        self.assertEqual(status.get("headers"), "candidate")
        self.assertTrue(set(_SiteHandler.seen_methods) <= {"GET", "HEAD", "OPTIONS"})

    def test_governor_exhaustion_returns_partial_not_raise(self) -> None:
        url = f"http://127.0.0.1:{self.port}/?q=x&next=/home"
        gov = HostRateGovernor(capacity=1, min_interval_s=0.0)
        findings, meta = av.verify_active(url, [], scope="127.0.0.1", governor=gov)
        self.assertTrue(meta["rate_limited"])

    def test_per_hunt_budget_exhaustion_stops_the_pass_independent_of_the_governor(self) -> None:
        # A GENEROUS governor (won't trip) but a tight per-hunt requests_budget --
        # proves the _Http.max_requests ceiling (independent of the host governor)
        # also cleanly ends the pass via _RateLimited propagation, not a raise.
        url = f"http://127.0.0.1:{self.port}/?q=x&next=/home"
        gov = HostRateGovernor(capacity=100, min_interval_s=0.0)
        findings, meta = av.verify_active(url, [], scope="127.0.0.1", governor=gov, requests_budget=1)
        self.assertTrue(meta["rate_limited"])
        self.assertEqual(meta["requests_used"], 1)
        # No finding needing a SECOND fetch (cors/xss/redirect/etc.) could possibly
        # have run once the sole request slot was spent on the landing page.
        classes = {f["_active_class_hint"] for f in findings}
        self.assertFalse(classes & {"cors", "xss", "redirect", "sqli", "nosqli"})

    def test_bounty_hunt_active_renders_confirmed(self) -> None:
        from bughunter.bounty import run_bounty_hunt
        import tempfile
        url = f"http://127.0.0.1:{self.port}/?q=x&next=/home"
        with tempfile.TemporaryDirectory() as tmp:
            res = run_bounty_hunt(
                url, "web-app", None, tmp, "127.0.0.1", True, {},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", runtime_dir=None,
                version="t", active=True,
            )
            self.assertTrue(res["ok"])
            markdown = Path(res["report_path"]).read_text(encoding="utf-8")
            self.assertIn("active.", markdown)            # an active finding is present
            self.assertIn("Status:** Confirmed", markdown)  # rendered as confirmed proof
            self.assertIn("Active verification", markdown)   # authorization note

    def test_bounty_hunt_without_active_has_no_active_findings(self) -> None:
        from bughunter.bounty import run_bounty_hunt
        import tempfile
        url = f"http://127.0.0.1:{self.port}/?q=x"
        with tempfile.TemporaryDirectory() as tmp:
            res = run_bounty_hunt(
                url, "web-app", None, tmp, "127.0.0.1", True, {},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", runtime_dir=None,
                version="t", active=False,
            )
            self.assertTrue(res["ok"])
            self.assertNotIn("active.", Path(res["report_path"]).read_text(encoding="utf-8"))


# ============================================================================
# END-TO-END: drive the real engine (real sockets, real _Http.fetch + governor +
# timing) against local servers I control. These prove the two advanced checks
# actually FIRE against a vulnerable backend AND stay silent against a clean one —
# the timing path in particular cannot be validated by the no-network stubs above.
# All run on 127.0.0.1 with GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1 (authorized own-infra).
# ============================================================================
class _BaseTimeHandler(BaseHTTPRequestHandler):
    """A backend whose query is time-injectable: when 'vulnerable', it actually
    runs the injected SLEEP(n) (sleeps n seconds) — exactly what a real blind-SQLi
    backend does. The clean subclass ignores the payload."""
    vulnerable = True
    seen_methods: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).seen_methods.append(self.command)
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        injected = " ".join(v for vals in q.values() for v in vals)
        m = re.search(r"sleep\((\d+(?:\.\d+)?)\)", injected, re.IGNORECASE)
        if type(self).vulnerable and m:
            time.sleep(float(m.group(1)))  # the DB executes the injected delay
        body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_HEAD = do_GET

    def log_message(self, *args: object) -> None:
        return


class _VulnTimeHandler(_BaseTimeHandler):
    vulnerable = True


class _CleanTimeHandler(_BaseTimeHandler):
    vulnerable = False


class TimeSqliE2ETests(unittest.TestCase):
    # Small, REAL delay so the differential is genuine but the test stays fast + robust:
    # the injected SLEEP dominates (>= 0.6s); the fast controls are sub-ms localhost hops.
    ENV = {
        "GREYIQ_SCAN_ALLOW_PRIVATE_URLS": "1",
        "GREYIQ_ACTIVE_MIN_INTERVAL_MS": "0",
        "GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST": "60",
        "GREYIQ_ACTIVE_TIME_SQLI_DELAY_S": "0.8",
        "GREYIQ_ACTIVE_TIME_SQLI_MARGIN_S": "0.3",  # 0.5s headroom — robust under CI scheduler jitter
    }

    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in self.ENV}
        os.environ.update(self.ENV)
        self.server = None

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if self.server is not None:
            self.server.shutdown()

    def _serve(self, handler_cls: type) -> int:
        handler_cls.seen_methods = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self.server.server_port

    def _http(self):
        return av._Http(get_settings(), HostRateGovernor(capacity=60, min_interval_s=0.0), max_requests=30)

    def test_confirms_against_time_vulnerable_backend(self) -> None:
        port = self._serve(_VulnTimeHandler)
        url = f"http://127.0.0.1:{port}/?id=1"
        f = av._check_time_sqli(self._http(), url, get_settings())
        self.assertIsNotNone(f, "time-based SQLi must confirm when the backend runs the injected SLEEP")
        self.assertEqual(f["rule_id"], "active.sqli-time")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["_active_class_hint"], "sqli")

    def test_no_false_positive_against_clean_backend(self) -> None:
        port = self._serve(_CleanTimeHandler)
        url = f"http://127.0.0.1:{port}/?id=1"
        f = av._check_time_sqli(self._http(), url, get_settings())
        self.assertIsNone(f, "a backend that ignores the SLEEP payload must NOT be reported")
        # Prove the None is a real negative (server WAS probed, just never delayed) —
        # not a silent connection failure: exactly the four timing requests reached the
        # server (baseline + SLEEP(0) control + two SLEEP(D) trials), and no more.
        self.assertEqual(len(_CleanTimeHandler.seen_methods), 4)

    def test_full_verify_active_fires_time_check_only_when_opted_in(self) -> None:
        port = self._serve(_VulnTimeHandler)
        url = f"http://127.0.0.1:{port}/?id=1"
        # Opt-in ON: the executing SLEEP probe runs and confirms.
        findings, meta = av.verify_active(url, [], scope="127.0.0.1", time_based=True, requests_budget=40)
        self.assertTrue(meta["in_scope"])
        self.assertIn("active.sqli-time", {f["rule_id"] for f in findings})
        # Opt-in OFF (default): no executing SLEEP probe, even against the vulnerable backend.
        findings_off, _ = av.verify_active(url, [], scope="127.0.0.1", requests_budget=40)
        self.assertNotIn("active.sqli-time", {f["rule_id"] for f in findings_off})
        # And we only ever issued idempotent methods.
        self.assertTrue(set(_VulnTimeHandler.seen_methods) <= {"GET", "HEAD", "OPTIONS"})


class _BucketHandler(BaseHTTPRequestHandler):
    """Stands in for an S3 bucket endpoint over a real socket. Class attrs set per
    test: a public bucket returns an anonymous ListBucketResult; a locked one 403s."""
    status = 200
    body = b""
    hits = 0
    last_headers: dict = {}

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits += 1
        type(self).last_headers = {k.lower(): v for k, v in self.headers.items()}
        body = type(self).body
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET

    def log_message(self, *args: object) -> None:
        return


class OpenBucketE2ETests(unittest.TestCase):
    """Real _Http.fetch over a socket. A getaddrinfo shim points the (regex-matched)
    S3 hostname at the local server, so the FULL path runs — regex, scope gate,
    _guard_url, real fetch, listing detection — without external egress."""

    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self._orig_gai = socket.getaddrinfo
        self.server = None

    def tearDown(self) -> None:
        socket.getaddrinfo = self._orig_gai
        if self.server is not None:
            self.server.shutdown()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def _serve(self, status: int, body: bytes) -> None:
        _BucketHandler.status = status
        _BucketHandler.body = body
        _BucketHandler.hits = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _BucketHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        port = self.server.server_port
        orig = self._orig_gai
        # Any host now resolves to the local listener (controls IP AND port via sockaddr).
        socket.getaddrinfo = lambda host, p, *a, **k: orig("127.0.0.1", port, *a, **k)

    def _http(self, auth=None):
        return av._Http(get_settings(), HostRateGovernor(capacity=20, min_interval_s=0.0), max_requests=12, auth=auth)

    def test_confirms_public_listing_over_real_socket(self) -> None:
        self._serve(200, (b'<?xml version="1.0" encoding="UTF-8"?>'
                          b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                          b'<Name>testbucket</Name><Contents><Key>secret/db-backup.sql</Key></Contents>'
                          b'</ListBucketResult>'))
        bucket = "http://testbucket.s3.amazonaws.com/"
        landing = {"body": f'<a href="{bucket}logo.png">x</a>', "status": 200, "headers": {}}
        f = av._check_open_bucket(self._http(), landing, "testbucket.s3.amazonaws.com", get_settings())
        self.assertIsNotNone(f, "an anonymous public listing must confirm over a real fetch")
        self.assertEqual(f["rule_id"], "active.open-bucket")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertNotIn("db-backup.sql", str(f))  # object keys are never echoed

    def test_locked_bucket_is_candidate_not_confirmed(self) -> None:
        self._serve(403, b'<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>')
        bucket = "http://locked-bucket.s3.amazonaws.com/"
        landing = {"body": f'cfg {bucket}private', "status": 200, "headers": {}}
        f = av._check_open_bucket(self._http(), landing, "locked-bucket.s3.amazonaws.com", get_settings())
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "candidate")  # no false "public" positive

    def test_private_resolving_bucket_is_refused_when_private_urls_off(self) -> None:
        # SSRF / DNS-rebind defense: with private URLs DISABLED, a public-looking S3 host
        # that resolves (here, via the shim) to a private/loopback IP must be REFUSED by
        # the guard — never fetched, never reported — even though it is named in scope.
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "0"
        self._serve(200, (b'<?xml version="1.0"?><ListBucketResult>'
                          b'<Contents><Key>x</Key></Contents></ListBucketResult>'))
        bucket = "http://evil-rebind.s3.amazonaws.com/"
        landing = {"body": f'<img src="{bucket}p.png">', "status": 200, "headers": {}}
        f = av._check_open_bucket(self._http(), landing, "evil-rebind.s3.amazonaws.com", get_settings())
        self.assertIsNone(f, "a bucket host resolving to a private IP must be refused, not reported")
        self.assertEqual(_BucketHandler.hits, 0, "the guard must block before any socket reaches the listener")

    def test_true_dns_rebinding_the_guard_passes_then_dns_changes_is_still_pinned(self) -> None:
        # This is the scenario test_private_resolving_bucket_is_refused_when_private_urls_off
        # (above) CANNOT exercise: that test's shim returns the SAME answer for every call,
        # so it only proves the guard works when DNS is consistent. Here the underlying
        # resolver (web_ingest._real_getaddrinfo -- the fallback _pinned_getaddrinfo calls
        # when nothing is pinned yet) answers DIFFERENTLY on the second lookup for the exact
        # same hostname -- exactly what a real DNS-rebinding attacker does between the
        # guard's check and the real HTTP connect a moment later. socket.getaddrinfo itself
        # is left as _pinned_getaddrinfo throughout (never replaced) -- deliberately NOT using
        # self._serve() here, since that helper replaces socket.getaddrinfo with a lambda that
        # collapses EVERY hostname to "127.0.0.1" before _pinned_getaddrinfo ever sees the
        # original hostname, which would defeat the pin-matching this test exercises. So this
        # exercises the REAL production code path end to end: without the fix, _Http.fetch's
        # real connect would re-resolve and reach the SECOND (attacker) answer instead of the
        # one the guard actually validated.
        _BucketHandler.status = 200
        _BucketHandler.body = (b'<?xml version="1.0"?><ListBucketResult>'
                               b'<Contents><Key>x</Key></Contents></ListBucketResult>')
        _BucketHandler.hits = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _BucketHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        real_port = self.server.server_port
        calls = {"n": 0}
        orig_real = web_ingest._real_getaddrinfo

        def rebinding_resolver(host, p, *a, **k):
            calls["n"] += 1
            # First lookup (the guard's _host_is_private check, made through
            # socket.getaddrinfo == _pinned_getaddrinfo, which falls through to this
            # function since nothing is pinned yet): the real, expected server.
            # Every lookup after that: a different port with NOTHING listening -- if
            # the real HTTP connect re-resolved independently (the pre-fix behavior,
            # i.e. if _pinned_getaddrinfo's pin didn't match), it would try to reach
            # this dead port instead and the fetch would fail, never reaching
            # _BucketHandler at all.
            target_port = real_port if calls["n"] == 1 else 1
            return orig_real("127.0.0.1", target_port, *a, **k)

        web_ingest._real_getaddrinfo = rebinding_resolver
        try:
            bucket = "http://rebind-test.s3.amazonaws.com/"
            landing = {"body": f'<img src="{bucket}p.png">', "status": 200, "headers": {}}
            f = av._check_open_bucket(self._http(), landing, "rebind-test.s3.amazonaws.com", get_settings())
        finally:
            web_ingest._real_getaddrinfo = orig_real
            with web_ingest._dns_pin_lock:
                web_ingest._dns_pins.clear()
        self.assertIsNotNone(f, "the pinned (first, guard-validated) resolution must be what the real connect uses")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(_BucketHandler.hits, 1, "the real connect must reach the SAME server the guard validated")
        self.assertGreaterEqual(calls["n"], 1)

    def test_operator_session_never_leaks_to_a_foreign_bucket(self) -> None:
        # The CRITICAL invariant: an authenticated scan binds the operator's cookie to
        # the TARGET host. The open-bucket check fetches a FOREIGN host (the bucket), so
        # that fetch must carry NO Cookie even though auth is active for the hunt.
        from bughunter.scan_auth import build_auth
        self._serve(200, (b'<?xml version="1.0"?><ListBucketResult>'
                          b'<Contents><Key>k</Key></Contents></ListBucketResult>'))
        auth = build_auth("https://app.example.com/", cookie="session=TOP-SECRET")  # bound to the TARGET
        bucket = "http://assets.s3.amazonaws.com/"
        landing = {"body": f'<img src="{bucket}p.png">', "status": 200, "headers": {}}
        f = av._check_open_bucket(self._http(auth=auth), landing, "assets.s3.amazonaws.com", get_settings())
        self.assertIsNotNone(f)  # the bucket is still probed + confirmed
        self.assertNotIn("cookie", _BucketHandler.last_headers, "the session must NEVER reach a foreign bucket host")
        self.assertNotIn("TOP-SECRET", str(_BucketHandler.last_headers))


class _CookieGatedHandler(BaseHTTPRequestHandler):
    """A behind-login app: it reflects the `q` param UNESCAPED (a real XSS) only when a
    valid session cookie is present; unauthenticated requests get a benign login page.
    So the bug is reachable ONLY by an authenticated scan."""

    def do_GET(self) -> None:  # noqa: N802
        cookie = self.headers.get("Cookie") or ""
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        reflected = " ".join(v for vals in q.values() for v in vals)
        if "session=" in cookie:
            body = f"<html>echo {reflected}</html>".encode()          # authed -> vulnerable reflection
        else:
            body = b"<html>Please log in to continue.</html>"          # anon -> nothing to find
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_HEAD = do_GET

    def log_message(self, *args: object) -> None:
        return


class AuthScanE2ETests(unittest.TestCase):
    """End-to-end: a reflected-XSS that only exists behind login is found WITH a
    session and missed WITHOUT one — over real sockets."""

    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _CookieGatedHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port

    def tearDown(self) -> None:
        self.server.shutdown()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def _xss(self, findings) -> bool:
        return any(f.get("_active_class_hint") == "xss" and f["_active_proof"]["status"] == "confirmed" for f in findings)

    def test_behind_login_xss_found_only_with_session(self) -> None:
        from bughunter.scan_auth import build_auth
        url = f"http://127.0.0.1:{self.port}/?q=x"
        auth = build_auth(f"http://127.0.0.1:{self.port}/", cookie="session=abc123")
        # WITH the session -> the authed reflection is reachable -> XSS confirmed.
        findings, meta = av.verify_active(url, [], scope="127.0.0.1", auth=auth)
        self.assertTrue(meta["in_scope"])
        self.assertTrue(self._xss(findings), "authenticated scan must reach the behind-login XSS")
        # WITHOUT it -> only the login page is seen -> nothing to confirm.
        findings_anon, _ = av.verify_active(url, [], scope="127.0.0.1")
        self.assertFalse(self._xss(findings_anon), "without a session the bug is not reachable")


if __name__ == "__main__":
    unittest.main()
