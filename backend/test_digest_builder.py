"""Deterministic Response Digest — the structural view the reasoning brain reads instead of a 200-char
excerpt. Verifies it extracts the security-relevant STRUCTURE (JSON keys, form fields, header gaps,
cookie flags, JWT header, error family) while NEVER leaking a value, and fails open on junk."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import digest_builder as db  # noqa: E402


class BuildDigestTests(unittest.TestCase):
    def test_extracts_json_key_names_and_interesting_subset(self) -> None:
        body = json.dumps({"id": 42, "owner_id": 7, "is_admin": False, "email": "victim@x.com",
                           "order": {"price": 9.99, "items": [{"sku": "x"}]}})
        d = db.build_digest({"status": 200, "headers": {"Content-Type": "application/json"}, "cookies": [], "body": body})
        self.assertIn("owner_id", d["json_keys"])
        self.assertIn("is_admin", d["json_keys"])
        self.assertIn("price", d["json_keys"])            # nested keys collected
        self.assertIn("owner_id", d["interesting_names"])  # the reasoning hint
        self.assertIn("is_admin", d["interesting_names"])

    def test_never_leaks_a_value(self) -> None:
        body = json.dumps({"email": "victim@secret.com", "balance": 133700, "api_key": "sk-LEAKED-VALUE-123"})
        d = db.build_digest({"status": 200, "headers": {}, "cookies": [], "body": body})
        blob = json.dumps(d)
        for value in ("victim@secret.com", "133700", "sk-LEAKED-VALUE-123"):
            self.assertNotIn(value, blob)                 # NAMES only — never the value
        self.assertIn("email", d["json_keys"])            # ...but the key name is there

    def test_jwt_header_only_never_payload(self) -> None:
        # header {"alg":"HS256","typ":"JWT"} . payload {"user":"admin","secret":"S"} . sig
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJzZWNyZXQiOiJTIn0.sIgNaTuRe"
        d = db.build_digest({"status": 200, "headers": {"Authorization": f"Bearer {jwt}"}, "cookies": [], "body": "{}"})
        self.assertEqual(d["jwt"]["alg"], "HS256")
        self.assertEqual(d["jwt"]["typ"], "JWT")
        self.assertNotIn("admin", json.dumps(d))          # the payload is NEVER decoded

    @staticmethod
    def _gaps(cookies: list[str], final_url: str = "https://app.test/") -> dict[str, list[str]]:
        d = db.build_digest({"status": 200, "headers": {}, "cookies": cookies, "body": "{}",
                             "final_url": final_url})
        return {g["cookie"]: g["missing"] for g in d.get("cookie_flag_gaps") or []}

    def test_auth_cookie_flag_gaps_and_cors(self) -> None:
        d = db.build_digest({"status": 200,
                             "headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
                             "cookies": ["sessionid=abc; Path=/", "theme=dark; Path=/"], "body": "{}",
                             "final_url": "https://app.test/"})
        gaps = {g["cookie"]: g["missing"] for g in d["cookie_flag_gaps"]}
        self.assertIn("sessionid", gaps)                  # auth cookie flagged
        self.assertNotIn("theme", gaps)                   # a non-auth cookie is NOT flagged
        self.assertEqual(set(gaps["sessionid"]), {"Secure", "HttpOnly", "SameSite"})
        self.assertEqual(d["cors_acao"], "*")
        self.assertTrue(d["cors_allow_credentials"])       # the dangerous *+credentials combo

    def test_cookie_value_containing_flag_words_does_not_suppress_the_gap(self) -> None:
        # The VALUE is app/attacker-influenceable (a base64 blob contains most things). Scanning the
        # whole Set-Cookie header for "httponly"/"secure" let a cookie hide its own flag gap — the
        # digest fed that miss into the same chain graph as attack_chain.cookie_signals.
        gaps = self._gaps(["sessionid=aHR0cG9ubHktc2VjdXJl_httponly_secure_samesite; Path=/"])
        self.assertEqual(set(gaps["sessionid"]), {"Secure", "HttpOnly", "SameSite"})
        # and the real attributes are still read off the attribute list, not the value
        gaps = self._gaps(["sessionid=httponly; Path=/; HttpOnly; Secure; SameSite=Lax"])
        self.assertEqual(gaps, {})

    def test_samesite_none_counts_as_missing_samesite(self) -> None:
        # SameSite=None is the explicit opt-IN to cross-site sending — the CSRF precondition, not
        # protection. Reading its mere presence as "has SameSite" inverted the one value that matters.
        self.assertEqual(self._gaps(["sessionid=a; Path=/; HttpOnly; Secure; SameSite=None"]),
                         {"sessionid": ["SameSite"]})
        self.assertEqual(self._gaps(["sessionid=a; Path=/; HttpOnly; Secure; samesite = none"]),
                         {"sessionid": ["SameSite"]})
        self.assertEqual(self._gaps(["sessionid=a; Path=/; HttpOnly; Secure; SameSite=Lax"]), {})

    def test_secure_gap_is_https_gated_like_cookie_signals(self) -> None:
        # cookie_signals only reports a missing Secure on an https page; the digest reported it
        # unconditionally, so an http target grew a `cookie.session-no-secure` chain signal the
        # chain engine itself would never have raised.
        cookie = ["sessionid=a; Path=/; HttpOnly; SameSite=Lax"]
        self.assertEqual(self._gaps(cookie, "https://app.test/"), {"sessionid": ["Secure"]})
        self.assertEqual(self._gaps(cookie, "http://app.test/"), {})
        self.assertEqual(self._gaps(cookie, ""), {})          # unknown scheme == not https
        # an explicit url argument wins over the response's own final_url
        d = db.build_digest({"status": 200, "headers": {}, "cookies": cookie, "body": "{}",
                             "final_url": "http://app.test/"}, "https://app.test/")
        self.assertEqual(d["cookie_flag_gaps"], [{"cookie": "sessionid", "missing": ["Secure"]}])

    def test_cookie_gaps_never_carry_the_cookie_value(self) -> None:
        d = db.build_digest({"status": 200, "headers": {}, "body": "{}", "final_url": "https://app.test/",
                             "cookies": ["session_token=SUPER-SECRET-SESSION-VALUE; Path=/"]})
        self.assertNotIn("SUPER-SECRET-SESSION-VALUE", json.dumps(d))   # NAME + flag facts only
        self.assertIn("session_token", json.dumps(d))

    def test_form_fields_include_hidden_and_error_family(self) -> None:
        body = ('<form><input name="user"><input type=hidden name="is_admin" value="0"></form>'
                "You have an error in your SQL syntax; check the manual")
        d = db.build_digest({"status": 500, "headers": {}, "cookies": [], "body": body})
        self.assertIn("is_admin", d["form_fields"])        # hidden field surfaced (mass-assignment hint)
        self.assertIn("is_admin", d["interesting_names"])
        self.assertEqual(d["error_family"], "sql")

    def test_missing_security_headers(self) -> None:
        d = db.build_digest({"status": 200, "headers": {"content-security-policy": "default-src 'self'"},
                             "cookies": [], "body": "{}"})
        self.assertNotIn("csp", d["missing_security_headers"])   # present -> not flagged
        self.assertIn("hsts", d["missing_security_headers"])     # absent -> flagged

    def test_fails_open_on_junk(self) -> None:
        for junk in (None, "a string", 42, [], {"body": None, "headers": None, "cookies": None, "status": None}):
            self.assertIsInstance(db.build_digest(junk), dict)   # never raises
        self.assertEqual(db.build_digest(None), {})

    def test_hostile_body_never_hangs_redos_regression(self) -> None:
        # The response body is attacker-controlled. A 200KB body of `<input name=` near-matches once
        # backtracked the form-field regex for ~22s (O(n^2)); the bounded gap keeps it well under 1s.
        import time
        hostile = [
            "<input name=" * 20000,          # form-field backtrack bait
            "eyJ" + "A" * 200000,            # JWT near-match
            "SQL synta" * 22000,             # error-family near-match
            '{"' + "_" * 100000 + '":1}',    # interesting-name bait
        ]
        for body in hostile:
            start = time.perf_counter()
            db.build_digest({"status": 200, "headers": {}, "cookies": [], "body": body})
            self.assertLess(time.perf_counter() - start, 1.0, "build_digest must stay cheap on hostile input")
        # large attacker-controlled HEADERS must also be bounded (the JWT haystack join) — 400 x 200KB
        # headers allocated ~400MB before the bounded-join fix.
        start = time.perf_counter()
        db.build_digest({"status": 200, "headers": {f"x-h{i}": "V" * 200000 for i in range(400)}, "cookies": [], "body": ""})
        self.assertLess(time.perf_counter() - start, 1.0, "large headers must stay bounded")

    def test_non_json_html_has_no_json_keys(self) -> None:
        d = db.build_digest({"status": 200, "headers": {}, "cookies": [], "body": "<html><body>hi</body></html>"})
        self.assertNotIn("json_keys", d)
        self.assertEqual(d["status"], 200)


if __name__ == "__main__":
    unittest.main()
