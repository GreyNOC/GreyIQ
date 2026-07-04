"""Firebase / Google API-key credential validation and reporting.

Covers the four things HackerOne demanded for a leaked-key report: exact location + variable name,
that the key is validated LIVE, the specific project/data it grants, and the ACTUAL key shown
(un-redacted) — while the surrounding snippet stays redacted and non-key rules never retain a raw
value. The validator's network layer is mocked; no real request is ever made in the tests.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import credential_validation as cv  # noqa: E402
from bughunter import report as report_lib  # noqa: E402
from bughunter import report_formats as RF  # noqa: E402
from bughunter.bounty import _deterministic_attack_plan  # noqa: E402
from bughunter.code_scanner.redaction import redact_finding_snippets  # noqa: E402
from bughunter.code_scanner.rules.secrets import RULES  # noqa: E402
from bughunter.scan_service import _finding_to_dict  # noqa: E402

_KEY = "AIza" + "B" * 35
_GOOGLE_RULE = next(r for r in RULES if getattr(r, "rule_id", "") == "secret.google-api-key")


class ValidatorInterpretationTests(unittest.TestCase):
    def tearDown(self) -> None:
        import importlib
        importlib.reload(cv)  # restore the real _get after monkeypatching

    def _mock(self, status, body):
        cv._get = lambda url: (status, body)

    def test_live_key_reports_project_and_domains(self) -> None:
        self._mock(200, '{"projectId":"acme-prod","authorizedDomains":["acme.com","acme.firebaseapp.com"]}')
        r = cv.validate_firebase_key(_KEY)
        self.assertIs(r["live"], True)
        self.assertEqual(r["project_id"], "acme-prod")
        self.assertIn("acme.firebaseapp.com", r["authorized_domains"])

    def test_invalid_key_is_not_live(self) -> None:
        self._mock(400, '{"error":{"message":"API key not valid. Please pass a valid API key."}}')
        self.assertIs(cv.validate_firebase_key(_KEY)["live"], False)

    def test_live_key_captures_runnable_poc_and_issuer_response(self) -> None:
        self._mock(200, '{"projectId":"acme-prod","authorizedDomains":["acme.com"]}')
        r = cv.validate_firebase_key(_KEY)
        self.assertIn(_KEY, r["poc"])                        # the PoC is a literal, runnable reproduction
        self.assertIn("getProjectConfig", r["poc"])
        self.assertIn("acme-prod", r["response_excerpt"])    # the ACTUAL issuer response is captured as proof

    def test_poc_present_even_when_inconclusive(self) -> None:
        self._mock(0, "Timeout")  # offline / no verdict — the operator still gets the command to run
        r = cv.validate_firebase_key(_KEY)
        self.assertIsNone(r["live"])
        self.assertIn(_KEY, r["poc"])

    def test_storage_exposure_captures_real_object_names(self) -> None:
        cv._get = lambda url: ((200, '{"items":[{"name":"users/secret.json"},{"name":"backups/db.sql"}],"prefixes":["private/"]}')
                               if "firebasestorage" in url else (200, "null"))  # RTDB locked, Storage open
        exps = cv.probe_firebase_exposure("acme-prod")
        storage = next(e for e in exps if e["service"] == "Firebase Cloud Storage")
        self.assertIn("users/secret.json", storage["evidence"])   # concrete object name, not prose
        self.assertIn("private/", storage["detail"])

    def test_live_but_restricted_still_live_and_extracts_project(self) -> None:
        self._mock(403, '{"error":{"message":"Identity Toolkit API has not been used in project 123456789012 before or it is disabled."}}')
        r = cv.validate_firebase_key(_KEY)
        self.assertIs(r["live"], True)
        self.assertEqual(r["project_id"], "123456789012")

    def test_non_key_is_not_checked(self) -> None:
        r = cv.validate_firebase_key("not-a-google-key")
        self.assertFalse(r["checked"])
        self.assertIsNone(r["live"])

    def test_host_allowlist_blocks_non_google_hosts(self) -> None:
        # The real _get refuses any host not on the Google allowlist.
        self.assertEqual(cv._get("https://evil.example.com/x?key=1")[0], 0)


class TokenLivenessTests(unittest.TestCase):
    def tearDown(self) -> None:
        import importlib
        importlib.reload(cv)  # restore the real _get_full after monkeypatching

    def test_github_token_live_names_account_and_scopes(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {"X-OAuth-Scopes": "repo, read:org"}, '{"login":"octocat"}')
        r = cv.validate_github_token("ghp_" + "A" * 36)
        self.assertIs(r["live"], True)
        self.assertEqual(r["principal"], "octocat")           # the account it controls
        self.assertIn("repo", r["scopes"])                    # what it grants
        self.assertIn("api.github.com/user", r["poc"])        # runnable PoC to the issuer

    def test_github_token_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (401, {}, '{"message":"Bad credentials"}')
        self.assertIs(cv.validate_github_token("ghp_bad")["live"], False)

    def test_slack_token_live_names_workspace(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"ok":true,"team":"acme-corp","user":"deploybot"}')
        r = cv.validate_slack_token("xoxb-1-1")
        self.assertIs(r["live"], True)
        self.assertIn("acme-corp", r["principal"])

    def test_slack_token_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"ok":false,"error":"invalid_auth"}')
        self.assertIs(cv.validate_slack_token("xoxb-bad")["live"], False)

    def test_openai_key_live_lists_models(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"data":[{"id":"gpt-4o"},{"id":"o1"}]}')
        r = cv.validate_openai_key("sk-proj-abc")
        self.assertIs(r["live"], True)
        self.assertIn("gpt-4o", r["scopes"])
        self.assertIn("api.openai.com/v1/models", r["poc"])

    def test_openai_key_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (401, {}, '{"error":{"message":"Incorrect API key"}}')
        self.assertIs(cv.validate_openai_key("sk-bad")["live"], False)

    def test_anthropic_key_never_validated_against_openai(self) -> None:
        # defensive: even if an sk-ant- key reached the OpenAI validator, it must NOT be sent there
        sent = []
        cv._get_full = lambda url, extra_headers=None: (sent.append(url), (200, {}, "{}"))[1]
        r = cv.validate_openai_key("sk-ant-api03-" + "A" * 30)
        self.assertEqual(sent, [])                 # no request was made to OpenAI
        self.assertNotEqual(r.get("live"), True)   # and no live OpenAI finding is produced

    def test_anthropic_key_live_lists_models(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"data":[{"id":"claude-sonnet-4"}]}')
        r = cv.validate_anthropic_key("sk-ant-abc")
        self.assertIs(r["live"], True)
        self.assertIn("claude-sonnet-4", r["scopes"])

    def test_stripe_key_live_via_nonexistent_resource(self) -> None:
        # a VALID key returns 404 "No such customer" for the non-existent probe; NO account data read
        cv._get_full = lambda url, extra_headers=None: (404, {}, '{"error":{"type":"invalid_request_error","message":"No such customer"}}')
        r = cv.validate_stripe_key("sk_live_abc")
        self.assertIs(r["live"], True)
        self.assertIn("live-mode", r["principal"])
        self.assertIn("move real money", r["detail"])          # live-mode impact called out
        self.assertNotIn("No such customer", r["response_excerpt"])  # only the error TYPE captured, no data

    def test_stripe_key_dead_on_401(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (401, {}, '{"error":{"type":"invalid_request_error","message":"Invalid API Key"}}')
        self.assertIs(cv.validate_stripe_key("sk_live_bad")["live"], False)

    def test_stripe_transient_5xx_is_inconclusive_not_live(self) -> None:
        # a 500/429 is transient/ambiguous — it must NOT be misread as a live key
        cv._get_full = lambda url, extra_headers=None: (500, {}, '{"error":{"type":"api_error"}}')
        self.assertIsNone(cv.validate_stripe_key("sk_live_x")["live"])

    def test_gitlab_token_live_names_account(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"id":42,"username":"deploybot"}')
        r = cv.validate_gitlab_token("glpat-" + "A" * 20)
        self.assertIs(r["live"], True)
        self.assertEqual(r["principal"], "deploybot")
        self.assertIn("gitlab.com/api/v4/user", r["poc"])

    def test_gitlab_token_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (401, {}, '{"message":"401 Unauthorized"}')
        self.assertIs(cv.validate_gitlab_token("glpat-bad")["live"], False)

    def test_npm_token_live_names_account(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"name":"acme-ci"}')
        r = cv.validate_npm_token("npm_" + "a" * 36)
        self.assertIs(r["live"], True)
        self.assertEqual(r["principal"], "acme-ci")
        self.assertIn("registry.npmjs.org/-/npm/v1/user", r["poc"])

    def test_npm_token_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (401, {}, '{"error":"Unauthorized"}')
        self.assertIs(cv.validate_npm_token("npm_bad")["live"], False)

    def test_sendgrid_key_live_lists_scopes_no_data_read(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"scopes":["mail.send","templates.read"]}')
        r = cv.validate_sendgrid_key("SG." + "a" * 22 + "." + "b" * 43)
        self.assertIs(r["live"], True)
        self.assertIn("mail.send", r["scopes"])        # capability, not recipient data
        self.assertTrue(r["no_data_read"])
        self.assertIn("api.sendgrid.com/v3/scopes", r["poc"])

    def test_sendgrid_key_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (401, {}, '{"errors":[{"message":"authorization required"}]}')
        self.assertIs(cv.validate_sendgrid_key("SG.bad")["live"], False)

    def test_digitalocean_token_live_names_account(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"account":{"email":"ops@acme.example","status":"active"}}')
        r = cv.validate_digitalocean_token("dop_v1_" + "0" * 64)
        self.assertIs(r["live"], True)
        self.assertEqual(r["principal"], "ops@acme.example")
        self.assertIn("api.digitalocean.com/v2/account", r["poc"])

    def test_digitalocean_token_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (401, {}, '{"id":"unauthorized"}')
        self.assertIs(cv.validate_digitalocean_token("dop_v1_bad")["live"], False)

    def test_aws_sigv4_matches_the_published_get_vanilla_vector(self) -> None:
        # correctness of the SigV4 signing primitive against AWS's canonical published test case
        import hashlib
        import hmac
        secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        amzdate, datestamp, region, service = "20150830T123600Z", "20150830", "us-east-1", "service"
        ch = f"host:example.amazonaws.com\nx-amz-date:{amzdate}\n"
        cr = "\n".join(["GET", "/", "", ch, "host;x-amz-date", hashlib.sha256(b"").hexdigest()])
        sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, f"{datestamp}/{region}/{service}/aws4_request",
                         hashlib.sha256(cr.encode()).hexdigest()])
        kd = cv._sign(("AWS4" + secret).encode(), datestamp)
        ksign = cv._sign(cv._sign(cv._sign(kd, region), service), "aws4_request")
        sig = hmac.new(ksign, sts.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(sig, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")

    def test_aws_key_live_names_the_caller_identity(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, "<GetCallerIdentityResponse><GetCallerIdentityResult>"
            "<Arn>arn:aws:iam::123456789012:user/leaked</Arn><Account>123456789012</Account>"
            "</GetCallerIdentityResult></GetCallerIdentityResponse>")
        r = cv.validate_aws_key("AKIA" + "A" * 16, "w" * 40)
        self.assertIs(r["live"], True)
        self.assertIn("arn:aws:iam::123456789012:user/leaked", r["principal"])
        self.assertTrue(r["no_data_read"])                       # GetCallerIdentity reads only the caller's own identity
        self.assertIn("get-caller-identity", r["poc"])

    def test_aws_key_dead_on_403(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (403, {}, "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>")
        self.assertIs(cv.validate_aws_key("AKIA" + "B" * 16, "x" * 40)["live"], False)

    def test_aws_junk_pair_is_never_signed(self) -> None:
        sent = []
        cv._get_full = lambda url, extra_headers=None: (sent.append(url), (200, {}, ""))[1]
        r = cv.validate_aws_key("not-an-akid", "short")
        self.assertFalse(r["checked"])                           # malformed pair -> never contacts AWS
        self.assertEqual(sent, [])

    def test_gcp_service_account_live_and_ssrf_safe(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        sa = json.dumps({"type": "service_account", "client_email": "svc@proj.iam.gserviceaccount.com",
                         "private_key": pem, "token_uri": "https://evil.example/token"})   # attacker token_uri
        posted = {}
        cv._post_form = lambda url, data, extra_headers=None: (posted.update(url=url), (200, '{"access_token":"ya29.SECRET"}'))[1]
        r = cv.validate_gcp_service_account(sa)
        self.assertIs(r["live"], True)
        self.assertEqual(r["principal"], "svc@proj.iam.gserviceaccount.com")
        self.assertEqual(posted["url"], "https://oauth2.googleapis.com/token")   # HARDCODED issuer, NOT the JSON's evil token_uri
        self.assertNotIn("ya29.SECRET", r["response_excerpt"])                    # the minted token is never stored

    def test_gcp_dead_key_and_non_service_account_json(self) -> None:
        cv._post_form = lambda url, data, extra_headers=None: (401, '{"error":"invalid_grant"}')
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        dead = json.dumps({"type": "service_account", "client_email": "x@y.iam", "private_key": pem})
        self.assertIs(cv.validate_gcp_service_account(dead)["live"], False)
        # a JSON that is not a service-account key is never checked (never signs/sends)
        self.assertFalse(cv.validate_gcp_service_account('{"type":"authorized_user"}')["checked"])

    def test_new_validators_are_registered_for_their_detection_rules(self) -> None:
        # compare by name, not identity: this class's tearDown reload of cv swaps function objects while
        # bounty still holds the originals — same function, different id.
        from bughunter import bounty
        for rid, name in (("secret.gitlab-pat", "validate_gitlab_token"),
                          ("secret.npm-token", "validate_npm_token"),
                          ("secret.sendgrid-key", "validate_sendgrid_key"),
                          ("secret.digitalocean-token", "validate_digitalocean_token")):
            fn = bounty._TOKEN_ISSUER_VALIDATORS.get(rid)
            self.assertTrue(callable(fn), rid)
            self.assertEqual(getattr(fn, "__name__", ""), name, rid)

    def test_redirects_are_never_followed(self) -> None:
        # the token is never replayed to a redirect target: the handler refuses to follow any 3xx
        self.assertIsNone(cv._NoRedirect().redirect_request(None, None, 302, "moved", {}, "https://evil.example.com/steal"))

    def test_anthropic_key_does_not_double_match_openai_rule(self) -> None:
        # an sk-ant- key must fire ONLY secret.anthropic-key — never secret.openai-key, or it would be
        # validated against the wrong issuer (the P1 own-issuer violation)
        from bughunter.code_scanner.rules import SECRET_RULES

        def rule_ids(text: str) -> set[str]:
            ids: set[str] = set()
            for rule in SECRET_RULES:
                for hit in rule.scan(path="app.js", text=text):
                    ids.add(getattr(hit, "rule_id", ""))
            return ids

        ant = rule_ids('const k = "sk-ant-api03-' + "A" * 40 + '";')
        self.assertIn("secret.anthropic-key", ant)
        self.assertNotIn("secret.openai-key", ant)              # the fix: no double-detection
        # a genuine OpenAI key still fires the OpenAI rule
        self.assertIn("secret.openai-key", rule_ids('const k = "sk-proj-' + "B" * 40 + '";'))

    def test_new_issuer_hosts_allowlisted_others_blocked(self) -> None:
        for h in ("api.github.com", "slack.com", "api.openai.com", "api.anthropic.com", "api.stripe.com",
                  "gitlab.com", "registry.npmjs.org", "api.sendgrid.com", "api.digitalocean.com",
                  "sts.amazonaws.com", "oauth2.googleapis.com"):
            self.assertTrue(cv._host_allowed(h), h)
        self.assertFalse(cv._host_allowed("evil.example.com"))
        # a token is only ever sent to its allowlisted issuer — never an arbitrary host
        self.assertEqual(cv._get_full("https://evil.example.com/steal")[0], 0)


class AwsPairingIntegrationTests(unittest.TestCase):
    """AWS keys are detected as two SEPARATE findings (id + secret); the hunt must pair the two from the
    same file and hand the SigV4 validator BOTH, since a single value cannot sign a request."""

    def test_hunt_pairs_the_access_key_id_with_its_file_secret(self) -> None:
        import tempfile
        from bughunter import bounty
        from bughunter.bounty import run_bounty_hunt

        captured: list = []
        orig = bounty.credential_validation.validate_aws_key
        bounty.credential_validation.validate_aws_key = lambda akid, secret: (
            captured.append((akid, secret)),
            {"checked": True, "live": True, "principal": "arn:aws:iam::1:user/x", "http_status": 200,
             "endpoint": "AWS sts:GetCallerIdentity", "no_data_read": True, "detail": "LIVE", "poc": "aws sts get-caller-identity",
             "scopes": "", "project_id": "", "authorized_domains": [], "response_excerpt": "Arn=..."})[1]
        try:
            with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
                (Path(src) / "creds.env").write_text(
                    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\n", encoding="utf-8")
                report = run_bounty_hunt(src, "source-code", None, out, "local", True, {},
                                         default_reports_dir=Path(out), seed_dir=BACKEND_DIR / "seed")
        finally:
            bounty.credential_validation.validate_aws_key = orig

        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertEqual(len(captured), 1, "the AWS validator ran exactly once for the paired key")
        akid, secret = captured[0]
        self.assertEqual(akid, "AKIAIOSFODNN7EXAMPLE")                       # the access-key-id verbatim
        self.assertEqual(secret, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")  # the paired 40-char secret, extracted


class SecretCaptureTests(unittest.TestCase):
    def test_variable_name_and_raw_value_captured(self) -> None:
        f = list(_GOOGLE_RULE.scan(path="src/fb.js", text=f'const apiKey = "{_KEY}";'))[0]
        self.assertEqual(f.variable_name, "apiKey")
        self.assertEqual(f.secret_value, _KEY)

    def test_raw_value_survives_redaction_but_snippet_is_redacted(self) -> None:
        findings = list(_GOOGLE_RULE.scan(path="src/fb.js", text=f'apiKey = "{_KEY}"'))
        redacted, rmap = redact_finding_snippets(findings)
        d = _finding_to_dict(redacted[0], redacted=True)
        self.assertIn("REDACTED", d["snippet"])       # the snippet never leaks the key
        self.assertEqual(d.get("secret_value"), _KEY)  # but the raw value is kept for the credential section
        self.assertEqual(d.get("variable_name"), "apiKey")

    def test_non_secret_rule_retains_no_raw_value(self) -> None:
        from bughunter.code_scanner.model import Confidence, Severity
        from bughunter.code_scanner.rules.base import RegexRule
        rule = RegexRule(rule_id="x.t", title="t", description="d", severity=Severity.LOW,
                         confidence=Confidence.LOW, category="headers", pattern=r"AIza\w+")
        f = list(rule.scan(path="c.js", text=f'k="{_KEY}"'))[0]
        self.assertEqual(f.secret_value, "")
        self.assertEqual(f.variable_name, "")


class CredentialReportTests(unittest.TestCase):
    def _render(self, proof):
        finding = {
            "ref": "F1", "title": "Google API key", "severity": "high", "class_id": "secrets",
            "location": "src/firebase.js", "line_start": 12, "rule_id": "secret.google-api-key",
            "cwe": "CWE-798", "description": "A Google Cloud API key is hardcoded.",
            "snippet": 'const apiKey = "AIza...[REDACTED_SECRET:sha256:x]";',
            "variable_name": "apiKey", "secret_value": _KEY, "_credential_proof": proof,
        }
        plan = _deterministic_attack_plan(finding, "secrets")
        ctx = {"tool": "g", "version": "t", "generated_at": "now", "target": "src/firebase.js",
               "scope": "", "attack_plans": {"F1": plan}}
        return RF.render_finding(ctx, finding, "hackerone")

    def test_report_has_all_four_h1_requirements(self) -> None:
        body = self._render({"checked": True, "live": True, "project_id": "acme-prod-42",
                             "authorized_domains": ["acme.com", "acme.firebaseapp.com"],
                             "detail": "LIVE — authenticates to Firebase project acme-prod-42", "http_status": 200})
        self.assertIn("src/firebase.js:12", body)                 # exact location
        self.assertIn("variable `apiKey`", body)                  # variable name
        self.assertIn(_KEY, body)                                 # actual, un-redacted key
        self.assertIn("LIVE", body)                               # validated live
        self.assertIn("acme-prod-42", body)                       # specific project
        self.assertIn("acme.firebaseapp.com", body)               # data/domains it grants
        self.assertIn("UN-REDACTED", body)                        # review-before-sharing warning

    def test_report_includes_runnable_poc_and_captured_response(self) -> None:
        poc = f"curl -s 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={_KEY}'"
        body = self._render({"checked": True, "live": True, "project_id": "acme-prod-42",
                             "authorized_domains": ["acme.com"], "detail": "LIVE", "http_status": 200,
                             "poc": poc, "response_excerpt": '{"projectId":"acme-prod-42","authorizedDomains":["acme.com"]}'})
        self.assertIn("Proof of concept", body)                       # a PoC section is present
        self.assertIn(f"getProjectConfig?key={_KEY}", body)           # the runnable command, with the real key
        self.assertIn("Issuer response", body)                        # the captured artifact heading
        self.assertIn("acme-prod-42", body)                           # the actual issuer response content

    def _render_plan_proof(self, poi: dict) -> str:
        # A secret finding whose proof-of-impact is supplied directly (no _credential_proof branch),
        # so we exercise the general confirmed/candidate obligation logic exactly as a hunt does.
        finding = {"ref": "F1", "title": "Google API key", "severity": "high", "class_id": "secrets",
                   "location": "src/firebase.js", "line_start": 12, "rule_id": "secret.google-api-key",
                   "cwe": "CWE-798", "secret_value": _KEY, "variable_name": "apiKey"}
        plan = _deterministic_attack_plan(finding, "secrets")
        plan["proof_of_impact"] = {**(plan.get("proof_of_impact") or {}), **poi}
        ctx = {"tool": "g", "version": "t", "generated_at": "now", "target": "src/firebase.js",
               "scope": "", "attack_plans": {"F1": plan}}
        return RF.render_finding(ctx, finding, "hackerone")

    def test_confirmed_finding_never_shows_the_capture_this_obligation(self) -> None:
        # THE reported bug: a finding CONFIRMED by a captured authenticated-read differential must not
        # ALSO carry "Proof obligation (capture this to prove impact)" — the proof is already in the
        # report; asking the operator to prove what the engine proved is the contradiction.
        body = self._render_plan_proof({
            "status": "confirmed",
            "observed_result": "the leaked key authenticated (HTTP 200) to Firebase project acme-prod",
            "control_result": "an invalid/revoked key is rejected by the same endpoint — the key is genuinely live",
            "authenticated_read_request": "GET https://www.googleapis.com/.../getProjectConfig?key=[REDACTED_SECRET]",
            "authenticated_read_response": '{"projectId":"acme-prod"}'})
        self.assertNotIn("Proof obligation (capture this to prove impact)", body)  # suppressed on a proven finding
        self.assertNotIn("Treat this as a lead", body)                             # nor the lead "Gap"
        self.assertIn("Authenticated read request", body)                          # the ALREADY-captured proof IS shown
        self.assertIn("Authenticated read success response", body)

    def test_unconfirmed_finding_still_shows_the_obligation(self) -> None:
        # a genuine lead (nothing captured) still tells the operator exactly what to grab
        body = self._render_plan_proof({})  # deterministic plan only -> not captured
        self.assertIn("Proof obligation (capture this to prove impact)", body)

    def test_report_shows_explicit_request_sent_and_return_code(self) -> None:
        body = self._render({"checked": True, "live": True, "principal": "OpenAI API key",
                             "detail": "LIVE — OpenAI API", "http_status": 200, "no_data_read": True,
                             "endpoint": "OpenAI api.openai.com/v1/models",
                             "poc": "curl -s -H 'Authorization: Bearer sk-XXX' https://api.openai.com/v1/models"})
        self.assertIn("**Request sent:**", body)                # the exact request is stated
        self.assertIn("**Return code:** HTTP 200", body)        # the pure return-code evidence
        self.assertIn("api.openai.com/v1/models", body)         # the issuer it was sent to
        self.assertIn("No account data was read", body)         # accurate: OpenAI reads only the public catalog

    def test_no_data_read_claim_omitted_when_issuer_metadata_was_read(self) -> None:
        # a GitHub/Slack/Firebase validator reads + shows the account, so it must NOT claim no-data-read
        body = self._render({"checked": True, "live": True, "principal": "octocat",
                             "detail": "LIVE — GitHub", "http_status": 200,
                             "endpoint": "GitHub api.github.com/user", "scopes": "repo, read:org",
                             "poc": "curl -s -H 'Authorization: Bearer ghp_XXX' https://api.github.com/user"})
        self.assertIn("Account / workspace", body)              # the account IS shown
        self.assertNotIn("No account data was read", body)      # so the contradictory claim is suppressed

    def test_live_credential_reads_as_confirmed(self) -> None:
        body = self._render({"checked": True, "live": True, "project_id": "p", "detail": "LIVE", "http_status": 200})
        self.assertRegex(body, r"(?i)status:\*\*\s*Confirmed")

    def test_report_renders_github_token_account_scopes_and_confirmed(self) -> None:
        body = self._render({"checked": True, "live": True, "principal": "octocat", "scopes": "repo, read:org",
                             "detail": "LIVE — GitHub account octocat", "http_status": 200,
                             "endpoint": "GitHub api.github.com/user",
                             "poc": "curl -s -H 'Authorization: Bearer ghp_XXX' https://api.github.com/user",
                             "response_excerpt": '{"login":"octocat"}'})
        self.assertIn("octocat", body)                          # the account the token controls
        self.assertIn("repo, read:org", body)                  # granted scopes
        self.assertIn("api.github.com/user", body)             # runnable PoC + generic issuer wording
        self.assertRegex(body, r"(?i)status:\*\*\s*Confirmed")  # a live token is a confirmed finding

    def test_dead_credential_is_shown_but_not_confirmed(self) -> None:
        body = self._render({"checked": True, "live": False, "detail": "NOT live", "http_status": 400})
        self.assertIn(_KEY, body)                                 # still shows the key + location
        self.assertNotRegex(body, r"(?i)status:\*\*\s*Confirmed")  # but a dead key is not a confirmed finding

    def test_source_api_credential_plan_carries_redacted_read_proof(self) -> None:
        raw = "sk-proj-" + ("C" * 32)
        finding = {
            "ref": "F1", "title": "OpenAI API key", "severity": "high", "confidence": "high",
            "class_id": "secrets", "category": "secret", "location": "src/settings.py",
            "rule_id": "secret.openai-key", "description": "An OpenAI API key is hardcoded.",
            "snippet": 'OPENAI_API_KEY = "sk-p...[REDACTED_SECRET:sha256:x]"',
            "variable_name": "OPENAI_API_KEY", "secret_value": raw,
            "_credential_proof": {
                "checked": True, "live": True, "principal": "OpenAI API key",
                "scopes": "gpt-4o", "detail": "LIVE - OpenAI API; models available: gpt-4o",
                "http_status": 200, "no_data_read": True,
                "endpoint": "OpenAI api.openai.com/v1/models",
                "poc": f"curl -s -H 'Authorization: Bearer {raw}' https://api.openai.com/v1/models",
                "response_excerpt": '{"data":[{"id":"gpt-4o"}]}',
            },
        }
        plan = _deterministic_attack_plan(finding, "secrets")
        proof = plan["proof_of_impact"]
        detail = report_lib._proof_of_impact_detail(finding, plan)

        self.assertNotIn(raw, json.dumps(plan))
        self.assertIn("[REDACTED_SECRET", proof["authenticated_read_request"])
        self.assertIn("api.openai.com/v1/models", proof["authenticated_read_request"])
        self.assertIn("gpt-4o", proof["authenticated_read_response"])
        self.assertIn("OpenAI API key", proof["blast_radius"])
        self.assertEqual(detail["status"], "confirmed")
        self.assertTrue(detail["ready"])

        ctx = {"tool": "g", "version": "t", "generated_at": "now", "target": "src/settings.py",
               "scope": "", "attack_plans": {"F1": plan}}
        body = RF.render_finding(ctx, finding, "hackerone")
        self.assertIn("Authenticated read request", body)
        self.assertIn("Authenticated read success response", body)
        self.assertIn("Blast radius", body)
        self.assertIn("[REDACTED_SECRET", body)

    def test_inconclusive_source_api_credential_stays_candidate_with_poc(self) -> None:
        raw = "sk-proj-" + ("D" * 32)
        finding = {
            "ref": "F1", "title": "OpenAI API key", "severity": "high", "confidence": "high",
            "class_id": "secrets", "category": "secret", "location": "src/settings.py",
            "rule_id": "secret.openai-key", "description": "An OpenAI API key is hardcoded.",
            "snippet": 'OPENAI_API_KEY = "sk-p...[REDACTED_SECRET:sha256:x]"',
            "variable_name": "OPENAI_API_KEY", "secret_value": raw,
            "_credential_proof": {
                "checked": True, "live": None, "detail": "Inconclusive timeout", "http_status": 0,
                "endpoint": "OpenAI api.openai.com/v1/models",
                "poc": f"curl -s -H 'Authorization: Bearer {raw}' https://api.openai.com/v1/models",
                "response_excerpt": "Timeout",
            },
        }
        plan = _deterministic_attack_plan(finding, "secrets")
        detail = report_lib._proof_of_impact_detail(finding, plan)

        self.assertNotIn(raw, json.dumps(plan))
        self.assertEqual(plan["proof_of_impact"]["status"], "candidate")
        self.assertEqual(detail["status"], "candidate")
        self.assertFalse(detail["ready"])
        self.assertIn("Benign source-credential validation PoC", plan["poc"])
        self.assertIn("[REDACTED_SECRET", plan["poc"])


if __name__ == "__main__":
    unittest.main()
