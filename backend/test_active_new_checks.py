"""Tests for the new active checks: JWT weak-secret crack, path traversal / LFI, and GraphQL
introspection. Each drives the per-check logic through a recording stub (no network) and asserts
the confirmed path fires only on the real signal and stays quiet otherwise (fail-closed)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sys
import types
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import active_verify_service as av  # noqa: E402


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_jwt(secret: str, alg: str = "HS256", payload: dict | None = None) -> str:
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    h = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = _b64(json.dumps(payload or {"sub": "1", "role": "user"}).encode())
    sig = _b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), digest).digest())
    return f"{h}.{p}.{sig}"


class _JwtHttp:
    def __init__(self, token: str, *, accept: bool = True) -> None:
        self.auth = types.SimpleNamespace(headers={"Authorization": f"Bearer {token}"})
        self.accept = accept
        self.forged_headers: list[dict] = []

    def fetch(self, url, *, method="GET", extra_headers=None):
        if extra_headers:
            self.forged_headers.append(extra_headers)
        return {"status": 200 if self.accept else 401, "headers": {}, "body": "", "location": None}


class JwtWeakSecretTests(unittest.TestCase):
    def test_weak_secret_recovered_and_confirmed(self) -> None:
        f = av._check_jwt_weak_secret(_JwtHttp(_make_jwt("secret")), "https://t/api/me")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["rule_id"], "active.jwt-weak-secret")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_strong_secret_is_not_flagged(self) -> None:
        strong = _make_jwt("9f8a3c-Zx!Lm2-very-long-random-signing-key-000")
        self.assertIsNone(av._check_jwt_weak_secret(_JwtHttp(strong), "https://t/api/me"))

    def test_offline_crack_confirms_even_if_server_unreachable(self) -> None:
        class _Dead(_JwtHttp):
            def fetch(self, url, *, method="GET", extra_headers=None):
                raise av._ActiveError("no route")
        f = av._check_jwt_weak_secret(_Dead(_make_jwt("changeme")), "https://t/api/me")
        self.assertIsNotNone(f)  # the crypto is self-certifying; a dead server doesn't lose it
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_no_jwt_no_finding(self) -> None:
        http = types.SimpleNamespace(auth=None, fetch=lambda *a, **k: None)
        self.assertIsNone(av._check_jwt_weak_secret(http, "https://t/"))


class _LfiHttp:
    def __init__(self, vuln_param: str | None = "file") -> None:
        self.vuln_param = vuln_param

    def fetch(self, url, *, method="GET", extra_headers=None):
        q = parse_qs(urlparse(url).query, keep_blank_values=True)
        val = (q.get(self.vuln_param) or [""])[0] if self.vuln_param else ""
        low = val.lower()
        body = "<html>normal page</html>"
        if self.vuln_param and ("etc/passwd" in low or "etc%2fpasswd" in low):
            body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        return {"status": 200, "headers": {}, "body": body, "location": None}


class PathTraversalTests(unittest.TestCase):
    def test_lfi_confirmed_on_passwd_signature(self) -> None:
        f = av._check_path_traversal(_LfiHttp("file"), "https://t/download?file=a.pdf")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["rule_id"], "active.path-traversal")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_no_traversal_no_finding(self) -> None:
        self.assertIsNone(av._check_path_traversal(_LfiHttp(None), "https://t/download?file=a.pdf"))


class DefaultAliasCoverageTests(unittest.TestCase):
    class _SearchReflect:
        auth = None

        def fetch(self, url, *, method="GET", extra_headers=None):
            val = (parse_qs(urlparse(url).query, keep_blank_values=True).get("search") or [""])[0]
            return {
                "status": 200,
                "headers": {"content-type": "text/html"},
                "cookies": [],
                "body": f"<html>{val}</html>",
                "location": None,
                "final_url": url,
            }

    def test_xss_default_aliases_include_search_on_paramless_endpoint(self) -> None:
        finding = av._check_reflected_xss(self._SearchReflect(), "https://app.example.com/search")
        self.assertIsNotNone(finding)
        self.assertIn("search", finding["title"])

    def test_path_traversal_default_aliases_include_filename(self) -> None:
        finding = av._check_path_traversal(_LfiHttp("filename"), "https://t/download")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["rule_id"], "active.path-traversal")


class _GqlHttp:
    def __init__(self, introspects: bool = True) -> None:
        self.introspects = introspects

    def fetch(self, url, *, method="GET", extra_headers=None):
        q = parse_qs(urlparse(url).query, keep_blank_values=True)
        if self.introspects and "__schema" in (q.get("query") or [""])[0]:
            return {"status": 200, "headers": {"content-type": "application/json"},
                    "body": '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}', "location": None}
        return {"status": 200, "headers": {"content-type": "text/html"}, "body": "<html></html>", "location": None}


class GraphqlIntrospectionTests(unittest.TestCase):
    def test_introspection_confirmed(self) -> None:
        f = av._check_graphql_introspection(_GqlHttp(True), "https://t/graphql")
        self.assertIsNotNone(f)
        self.assertEqual(f["rule_id"], "active.graphql-introspection")

    def test_non_graphql_path_skipped(self) -> None:
        # gated to graphql-shaped paths so it costs nothing elsewhere
        self.assertIsNone(av._check_graphql_introspection(_GqlHttp(True), "https://t/api/users"))

    def test_introspection_disabled_no_finding(self) -> None:
        self.assertIsNone(av._check_graphql_introspection(_GqlHttp(False), "https://t/graphql"))


class _GqlSuggestHttp:
    """A GraphQL endpoint whose validation errors leak the schema via 'Did you mean' suggestions,
    EVEN with introspection off. `mode` picks the failure shape."""
    def __init__(self, mode: str = "suggests") -> None:
        self.mode = mode

    def fetch(self, url, *, method="GET", extra_headers=None):
        q = parse_qs(urlparse(url).query, keep_blank_values=True)[("query")]
        query = (q or [""])[0]
        if self.mode == "suggests" and av._GRAPHQL_BOGUS_FIELD in query:
            # graphql-js phrasing: suggests a REAL field ('user') for our nonexistent one
            return {"status": 400, "headers": {"content-type": "application/json"},
                    "body": '{"errors":[{"message":"Cannot query field \\"' + av._GRAPHQL_BOGUS_FIELD + '\\" on type \\"Query\\". Did you mean \\"user\\"?"}]}', "location": None}
        if self.mode == "no_suggest":
            return {"status": 400, "headers": {"content-type": "application/json"},
                    "body": '{"errors":[{"message":"Cannot query field on type Query."}]}', "location": None}
        if self.mode == "html_didyoumean":  # a search page saying "did you mean" — NOT a graphql leak
            return {"status": 200, "headers": {"content-type": "text/html"}, "body": "<html>Did you mean user?</html>", "location": None}
        if self.mode == "echo_only":  # only echoes our own bogus field back — not a real schema field
            return {"status": 400, "headers": {"content-type": "application/json"},
                    "body": '{"errors":[{"message":"Did you mean \\"' + av._GRAPHQL_BOGUS_FIELD + '\\"?"}]}', "location": None}
        if self.mode == "prose_gateway":  # a NON-graphql JSON error whose prose says "did you mean" — no probe echo
            return {"status": 400, "headers": {"content-type": "application/json"},
                    "body": '{"error":"Unknown operation. Did you mean to POST?"}', "location": None}
        if self.mode == "prose_queryroot":  # "Did you mean the query root?" — no probe echo, generic prose
            return {"status": 400, "headers": {"content-type": "application/json"},
                    "body": '{"errors":[{"message":"Did you mean the query root?"}]}', "location": None}
        if self.mode == "type_suggest":  # echoes our probe AND suggests a real TYPE — still a schema leak
            return {"status": 400, "headers": {"content-type": "application/json"},
                    "body": '{"errors":[{"message":"Cannot query field \\"' + av._GRAPHQL_BOGUS_FIELD + '\\" on type \\"Query\\". Did you mean \\"User\\"?"}]}', "location": None}
        return {"status": 200, "headers": {"content-type": "application/json"}, "body": '{"data":{}}', "location": None}


class GraphqlFieldSuggestionTests(unittest.TestCase):
    def test_suggestion_leak_is_confirmed(self) -> None:
        f = av._check_graphql_field_suggestions(_GqlSuggestHttp("suggests"), "https://t/graphql")
        self.assertIsNotNone(f)
        self.assertEqual(f["rule_id"], "active.graphql-field-suggestions")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("user", f["proof_evidence"]["matched_value"])

    def test_non_graphql_path_skipped(self) -> None:
        self.assertIsNone(av._check_graphql_field_suggestions(_GqlSuggestHttp("suggests"), "https://t/api/users"))

    def test_no_suggestion_is_not_flagged(self) -> None:
        self.assertIsNone(av._check_graphql_field_suggestions(_GqlSuggestHttp("no_suggest"), "https://t/graphql"))

    def test_html_did_you_mean_page_is_not_flagged(self) -> None:
        # a non-JSON "did you mean" (a search page) must not false-positive as a GraphQL leak
        self.assertIsNone(av._check_graphql_field_suggestions(_GqlSuggestHttp("html_didyoumean"), "https://t/graphql"))

    def test_echo_of_our_own_bogus_field_is_not_flagged(self) -> None:
        # a suggestion that only names the unguessable field WE sent is not a real schema leak
        self.assertIsNone(av._check_graphql_field_suggestions(_GqlSuggestHttp("echo_only"), "https://t/graphql"))

    def test_generic_did_you_mean_prose_without_probe_echo_is_not_flagged(self) -> None:
        # QAQC regression: arbitrary JSON prose on a graphql-ish path ("Did you mean to POST?" /
        # "Did you mean the query root?") must NOT confirm — a real leak echoes OUR probe field.
        self.assertIsNone(av._check_graphql_field_suggestions(_GqlSuggestHttp("prose_gateway"), "https://t/graphql"))
        self.assertIsNone(av._check_graphql_field_suggestions(_GqlSuggestHttp("prose_queryroot"), "https://t/graphql"))

    def test_type_name_suggestion_is_a_valid_disclosure(self) -> None:
        # a suggested TYPE (not field) is still a schema disclosure — confirmed, and the proof text says
        # "schema name" (not "field") so it's honest about what leaked.
        f = av._check_graphql_field_suggestions(_GqlSuggestHttp("type_suggest"), "https://t/graphql")
        self.assertIsNotNone(f)
        self.assertIn("User", f["proof_evidence"]["matched_value"])
        self.assertIn("schema name", f["_active_proof"]["observed_result"])


class _FileHttp:
    def __init__(self, expose: bool = True, catchall: bool = False) -> None:
        self.expose, self.catchall = expose, catchall

    def fetch(self, url, *, method="GET", extra_headers=None):
        path = urlparse(url).path
        if self.catchall:  # an SPA that 200s everything with the same index page
            return {"status": 200, "headers": {}, "body": "<html>app</html>", "location": None}
        if self.expose and path == "/.git/config":
            return {"status": 200, "headers": {}, "body": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n", "location": None}
        return {"status": 404, "headers": {}, "body": "Not Found", "location": None}


class SensitiveFileTests(unittest.TestCase):
    def test_git_config_exposed_confirmed(self) -> None:
        f = av._check_sensitive_paths(_FileHttp(expose=True), "https://t/")
        self.assertIsNotNone(f)
        self.assertEqual(f["rule_id"], "active.exposed-file")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_spa_catchall_is_not_flagged(self) -> None:
        # A site that returns index.html (200) for every path must NOT false-positive.
        self.assertIsNone(av._check_sensitive_paths(_FileHttp(catchall=True), "https://t/"))

    def test_only_probes_at_site_root(self) -> None:
        # Gated to the root so it probes each host once, not per discovered URL.
        self.assertIsNone(av._check_sensitive_paths(_FileHttp(expose=True), "https://t/some/page"))


class _ServesOne:
    """Serves ONE path (path+query) with a given body, 404s everything else (incl. the control)."""
    def __init__(self, served_path: str, body: str) -> None:
        self.served_path, self.body = served_path, body

    def fetch(self, url, *, method="GET", extra_headers=None):
        p = urlparse(url)
        pq = p.path + (("?" + p.query) if p.query else "")
        if pq == self.served_path:
            return {"status": 200, "headers": {}, "body": self.body, "location": None}
        return {"status": 404, "headers": {}, "body": "Not Found", "location": None}


class NewSignatureTableTests(unittest.TestCase):
    def test_aws_credentials_file_exposed_confirmed(self) -> None:
        body = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalr...\n"
        f = av._check_sensitive_paths(_ServesOne("/.aws/credentials", body), "https://t/")
        self.assertIsNotNone(f)
        self.assertEqual(f["rule_id"], "active.exposed-file")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_npmrc_auth_token_exposed_confirmed(self) -> None:
        # port- AND path-qualified PRIVATE registries (the high-value case) must match, not just npmjs.org
        for line in ("//registry.npmjs.org/:_authToken=npm_abc123\n",
                     "//registry.internal:8443/:_authToken=abc\n",
                     "//company.jfrog.io/artifactory/api/npm/npm-local/:_authToken=abc\n"):
            f = av._check_sensitive_paths(_ServesOne("/.npmrc", line), "https://t/")
            self.assertIsNotNone(f, line)
            self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_sql_dump_exposed_confirmed(self) -> None:
        body = "-- MySQL dump 10.13  Distrib 8.0.32\n--\nDROP TABLE IF EXISTS `users`;\nCREATE TABLE `users` (...);\nINSERT INTO `users` VALUES (1,'a');\n"
        f = av._check_sensitive_paths(_ServesOne("/backup.sql", body), "https://t/")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_env_backup_variant_exposed_confirmed(self) -> None:
        f = av._check_sensitive_paths(_ServesOne("/.env.bak", "DB_PASSWORD=hunter2\nSTRIPE_KEY=sk_live_x\n"), "https://t/")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_wp_config_backup_exposed_confirmed(self) -> None:
        body = "<?php\ndefine('DB_NAME', 'wp');\ndefine('DB_USER', 'root');\ndefine('DB_PASSWORD', 's3cr3t');\n"
        f = av._check_sensitive_paths(_ServesOne("/wp-config.php.bak", body), "https://t/")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")

    def test_backup_signatures_do_not_flag_prose(self) -> None:
        # a docs/blog page that MENTIONS these strings must not false-positive (anchored signatures)
        docs = _ServesOne("/backup.sql", "Our tutorial explains how to CREATE TABLE and INSERT INTO rows in SQL.")
        self.assertIsNone(av._check_sensitive_paths(docs, "https://t/"))
        env_docs = _ServesOne("/.env.bak", "Set your DB_PASSWORD environment variable before running.")
        self.assertIsNone(av._check_sensitive_paths(env_docs, "https://t/"))

    def test_elasticsearch_cat_indices_exposed_confirmed(self) -> None:
        body = "health status index          uuid   pri rep docs.count\ngreen  open   logs-2024-01 aBcD   1   1   1200\n"
        f = av._check_debug_endpoints(_ServesOne("/_cat/indices?v", body), "https://t/")
        self.assertIsNotNone(f)
        self.assertEqual(f["rule_id"], "active.debug-endpoint")
        self.assertEqual(f["severity"], "high")

    def test_wordpress_user_enumeration_confirmed(self) -> None:
        # REAL WP core field order (name/link BEFORE slug) on a SINGLE-author site — the highest-value
        # case an earlier too-strict "slug before name/link" regex silently missed.
        body = ('[{"id":1,"name":"admin","url":"","description":"","link":"https://t/author/admin/",'
                '"slug":"admin","avatar_urls":{"24":"https://s/a"},"meta":[],"_links":{}}]')
        f = av._check_debug_endpoints(_ServesOne("/wp-json/wp/v2/users", body), "https://t/")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        # an arbitrary slug-bearing JSON array without WP's avatar_urls must NOT match (no false positive)
        self.assertIsNone(av._check_debug_endpoints(
            _ServesOne("/wp-json/wp/v2/users", '[{"slug":"x","name":"y"}]'), "https://t/"))

    def test_new_signatures_do_not_flag_a_catchall_or_benign_body(self) -> None:
        # a site that 200s a benign page for the sensitive paths must NOT be flagged (no false positive)
        benign = _FileHttp(catchall=True)
        self.assertIsNone(av._check_sensitive_paths(benign, "https://t/"))
        self.assertIsNone(av._check_debug_endpoints(benign, "https://t/"))
        # and a docs page merely MENTIONING the strings mid-body doesn't match the anchored signatures
        docs = _ServesOne("/.aws/credentials", "See the docs: set aws_access_key_id in your [profile] block.")
        self.assertIsNone(av._check_sensitive_paths(docs, "https://t/"))


class _XfhHttp:
    """Host is PINNED (ignored); only X-Forwarded-Host is trusted into the Location — the
    dominant reverse-proxy shape a raw-Host probe misses."""
    def fetch(self, url, *, method="GET", extra_headers=None):
        h = {k.lower(): v for k, v in (extra_headers or {}).items()}
        if h.get("x-forwarded-host") == av._MARKER_HOST:
            return {"status": 302, "headers": {}, "body": "", "location": f"https://{av._MARKER_HOST}/reset?token=abc"}
        return {"status": 200, "headers": {}, "body": "<html>ok</html>", "location": None}


class HostHeaderXfhTests(unittest.TestCase):
    def test_x_forwarded_host_reflected_into_location_confirms(self) -> None:
        f = av._check_host_header(_XfhHttp(), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["severity"], "medium")
        self.assertIn("X-Forwarded-Host", f["proof_evidence"]["request_header"])


class _DollarSstiStub:
    """Only the ${7*7} (Freemarker/JSP-EL) engine evaluates — proves the multi-engine probe
    catches an engine the old {{7*7}}-only probe missed."""
    def fetch(self, url, *, method="GET", extra_headers=None):
        val = (parse_qs(urlparse(url).query, keep_blank_values=True).get("q") or [""])[0]
        rendered = val.replace("${7*7}", "49")
        return {"status": 200, "headers": {"content-type": "text/html"}, "body": f"<html>{rendered}</html>", "location": None}


class SstiMultiEngineTests(unittest.TestCase):
    def test_dollar_expression_engine_confirmed(self) -> None:
        f = av._check_ssti(_DollarSstiStub(), "https://app.example.com/?q=x")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("Freemarker/JSP-EL", f["proof_evidence"]["matched_value"])


class _PrefixCorsStub:
    """An ACL that trusts any Origin STARTING WITH a fixed origin prefix (no boundary check) — the
    substring/prefix-trust bug that CORS variants 1-3 (exact marker, null, subdomain) don't catch,
    so it exercises variant 4 specifically."""
    def __init__(self, prefix: str = "https://app.example.com") -> None:
        self.prefix = prefix

    def fetch(self, url, *, method="GET", extra_headers=None):
        origin = {k.lower(): v for k, v in (extra_headers or {}).items()}.get("origin")
        headers = {}
        if origin and origin.startswith(self.prefix):
            headers["access-control-allow-origin"] = origin
            headers["access-control-allow-credentials"] = "true"
        return {"status": 200, "headers": headers, "cookies": [], "body": "", "location": None}


class CorsSubstringTrustTests(unittest.TestCase):
    def test_prefix_trust_origin_confirms(self) -> None:
        f = av._check_cors(_PrefixCorsStub(), "https://app.example.com/?q=x")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("app.example.com." + av._MARKER_HOST, f["proof_evidence"]["matched_value"])

    def test_http_target_prefix_trust_confirms(self) -> None:
        # On an http:// target the control/substring origins must be built from the URL's real
        # scheme, or a middleware trusting http://<host>-prefixed origins is never probed.
        f = av._check_cors(_PrefixCorsStub("http://app.example.com"), "http://app.example.com/?q=x")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("http://app.example.com." + av._MARKER_HOST, f["proof_evidence"]["matched_value"])

    def test_strict_acl_not_flagged(self) -> None:
        class _StrictCorsStub:  # only the exact site origin is trusted -> nothing to confirm
            def fetch(self, url, *, method="GET", extra_headers=None):
                origin = {k.lower(): v for k, v in (extra_headers or {}).items()}.get("origin")
                headers = {}
                if origin == "https://app.example.com":
                    headers["access-control-allow-origin"] = origin
                    headers["access-control-allow-credentials"] = "true"
                return {"status": 200, "headers": headers, "cookies": [], "body": "", "location": None}
        self.assertIsNone(av._check_cors(_StrictCorsStub(), "https://app.example.com/?q=x"))


class _AuthedReflectCorsStub:
    """Reflects an ARBITRARY attacker Origin with credentials AND returns an authenticated
    response body — models a logged-in scan (``auth`` set) where the reflected ACAO + creds
    let a foreign origin read real data. The control (site origin) reflects statically with no
    creds so the differential still confirms."""
    auth = object()  # truthy: an authenticated scan; fetch() would attach the operator session

    def __init__(self, body: str = '{"email":"victim@example.com","token":"tok_live_xyz"}') -> None:
        self.body = body

    def fetch(self, url, *, method="GET", extra_headers=None):
        origin = {k.lower(): v for k, v in (extra_headers or {}).items()}.get("origin")
        host = urlparse(url).hostname or ""
        headers, body = {}, ""
        if origin and origin != f"https://{host}" and origin != "null":
            headers = {"access-control-allow-origin": origin, "access-control-allow-credentials": "true"}
            body = self.body
        elif origin == f"https://{host}":
            headers = {"access-control-allow-origin": origin}  # control: static, no creds
        return {"status": 200, "headers": headers, "cookies": [], "body": body, "location": None, "final_url": url}


class CorsAuthenticatedReadTests(unittest.TestCase):
    def test_authenticated_scan_captures_cross_origin_read(self) -> None:
        # An authenticated scan CAPTURES the authenticated body (read_data) and NAMES the sensitive
        # data — but the read is SAME-SITE (curl-equivalent), so severity is Medium (not High) and the
        # observation is honest that a browser cross-origin read is not yet proven (no overclaimed theft).
        f = av._check_cors(_AuthedReflectCorsStub(), "https://api.example.com/user/me")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")   # the MISCONFIGURATION is confirmed
        self.assertEqual(f["severity"], "medium")                     # not High — no browser PoC
        self.assertNotIn("/C:H", f["_active_cvss"]["vector"])          # Confidentiality:High not asserted
        self.assertIn("read_data", f["proof_evidence"])
        self.assertIn("victim@example.com", f["proof_evidence"]["read_data"])
        self.assertIn("email address(es)", f["proof_evidence"]["sensitive_data_labels"])
        self.assertIn("same-site", f["_active_proof"]["observed_result"])
        self.assertIn("not yet been proven", f["_active_proof"]["observed_result"])
        # read_data is redacted exactly once — no nested "[REDACTED_SECRET:[REDACTED_SECRET" markers.
        self.assertNotIn("[REDACTED_SECRET:[REDACTED_SECRET", f["proof_evidence"]["read_data"])

    def test_unauthenticated_scan_reports_misconfig_without_read(self) -> None:
        # No auth attribute -> _cors_read_impact grades Low: the misconfiguration is still
        # confirmed, but nothing is claimed to have been read (fail-closed on the read claim).
        class _Anon(_AuthedReflectCorsStub):
            auth = None
        f = av._check_cors(_Anon(), "https://api.example.com/user/me")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertNotIn("read_data", f["proof_evidence"])
        self.assertNotIn("READ", f["_active_proof"]["observed_result"])

    def test_report_shows_concrete_cors_repro_and_headers(self) -> None:
        # The offline attack plan builds a class-specific concrete reproduction (a real
        # curl -H 'Origin:' request) and a runnable credentialed-fetch PoC from the finding's
        # captured evidence — the concrete steps + headers a triager demands.
        from bughunter.bounty import _deterministic_attack_plan
        from bughunter import report_formats as RF
        f = av._check_cors(_AuthedReflectCorsStub(), "https://api.example.com/user/me")
        finding = {
            "ref": "F1", "title": f["title"], "severity": "high", "class_id": "cors",
            "class_name": "CORS misconfiguration", "location": "https://api.example.com/user/me",
            "cwe": "CWE-284", "category": "cors", "proof_evidence": f["proof_evidence"],
            "rule_id": f["rule_id"], "snippet": f.get("snippet", ""),
        }
        plan = _deterministic_attack_plan(finding, "cors")
        plan["proof_of_impact"] = f["_active_proof"]
        ctx = {"tool": "GreyIQ", "version": "t", "generated_at": "now", "target": "",
               "scope": "", "attack_plans": {"F1": plan}}
        body = RF.render_finding(ctx, finding, "hackerone")
        self.assertIn("curl -i -H 'Origin:", body)                     # concrete repro request
        self.assertIn("credentials: \"include\"", body)                # runnable credentialed PoC
        self.assertIn("same-site read", body)                          # the captured read is shown honestly
        self.assertIn("victim@example.com", body)                      # the actual sensitive data
        self.assertRegex(body, r"(?m)^Access-Control-Allow-Credentials: true$")  # ACAC on its own line


class ConcreteReproAllClassesTests(unittest.TestCase):
    """The generalized proof-of-concept engine: every ACTIVE-confirmed class gets the exact
    crafted request rebuilt as a copy-paste curl, the confirming evidence, an escalation step,
    and — where browser-exploitable — a runnable PoC. A PASSIVE finding does not."""

    def _repro(self, class_id, rule_id, request_line, matched, request_header="",
               url="https://app.example.com/?q=x"):
        from bughunter.bounty import _concrete_repro
        pe = {"request_line": request_line, "matched_value": matched, "response_status": "HTTP 200"}
        if request_header:
            pe["request_header"] = request_header
        return _concrete_repro(
            {"title": "t", "location": url, "class_id": class_id, "rule_id": rule_id, "proof_evidence": pe},
            class_id)

    def test_every_active_class_gets_a_concrete_curl(self) -> None:
        cases = [
            ("xss", "active.reflected-xss", "GET https://app.example.com/?q=<svg/onload=1>", "unescaped reflection"),
            ("redirect", "active.open-redirect", "GET https://app.example.com/?next=//evil/", "Location: //evil/"),
            ("ssti", "active.ssti", "GET https://app.example.com/?q={{7*7}}", "evaluated to 49 (jinja2)"),
            ("sqli", "active.sqli-error", "GET https://app.example.com/?id=1'", "MySQL error banner"),
            ("path-traversal", "active.path-traversal", "GET https://app.example.com/?f=../etc/passwd", "passwd disclosed"),
            ("graphql", "active.graphql-introspection", "GET https://app.example.com/graphql?query=x", "__schema returned"),
            ("disclosure", "active.exposed-file", "GET https://app.example.com/.git/config", ".git/config exposed"),
        ]
        for cls, rid, rl, mv in cases:
            steps, _poc = self._repro(cls, rid, rl, mv)
            self.assertTrue(any("curl -i" in s for s in steps), cls)
            self.assertTrue(any(mv.split()[0] in s for s in steps), f"{cls} missing confirming evidence")

    def test_browser_classes_get_runnable_poc(self) -> None:
        for cls, rid in [("xss", "active.reflected-xss"), ("redirect", "active.open-redirect"),
                         ("csrf", "active.csrf-missing-token"), ("headers", "active.clickjacking")]:
            _steps, poc = self._repro(cls, rid, "GET https://app.example.com/", "signal")
            self.assertIn("<", poc, f"{cls} should emit an HTML PoC")

    def test_jwt_forge_poc_uses_recovered_secret(self) -> None:
        _steps, poc = self._repro(
            "jwt", "active.jwt-weak-secret", "GET https://app.example.com/",
            "weak HMAC-HS384 signing secret recovered: 'hunter2'",
            request_header="Authorization: <token forged with the recovered secret>")
        self.assertIn("hunter2", poc)
        self.assertIn("HS384", poc)

    def test_placeholder_header_not_leaked_into_curl(self) -> None:
        # A "<forged token>" placeholder header must never appear in the copy-paste curl.
        steps, _poc = self._repro(
            "jwt", "active.jwt-weak-secret", "GET https://app.example.com/",
            "weak HMAC-HS256 signing secret recovered: 's'",
            request_header="Authorization: <forged>")
        curl = next(s for s in steps if "curl -i" in s)
        self.assertNotIn("<forged>", curl)

    def test_host_header_and_crlf_get_no_misleading_browser_poc(self) -> None:
        # Class "redirect" covers open-redirect (browser PoC) but ALSO host-header/CRLF, whose
        # crafted part is a header the browser can't set — those must not emit an open-URL PoC.
        _s, poc_hh = self._repro("redirect", "active.host-header-injection", "GET https://app.example.com/",
                                 "marker in Location", request_header="X-Forwarded-Host: greyiq-marker.example")
        _s2, poc_crlf = self._repro("redirect", "active.crlf", "GET https://app.example.com/?q=%0d%0aX",
                                    "injected response header")
        self.assertEqual(poc_hh, "")
        self.assertEqual(poc_crlf, "")

    def test_passive_finding_keeps_generic_checklist(self) -> None:
        # A passive finding (web.*) is not reproduced via a crafted request -> generic checklist,
        # not the "send the exact request" concrete repro.
        steps, _poc = self._repro("headers", "web.missing-header.csp", "GET https://app.example.com/", "no CSP")
        self.assertEqual(steps, [])  # _concrete_repro declines -> caller uses the generic steps


class DisclosureDemonstratedImpactTests(unittest.TestCase):
    """The disclosure/read checks capture an excerpt of the retrieved content as demonstrated
    impact (like CORS read_data), so the report shows the actual data, not just 'contents
    disclosed'. The report renders it under a generic 'Demonstrated impact' heading."""

    def test_path_traversal_captures_disclosed_file(self) -> None:
        class LfiStub:
            auth = None
            def fetch(self, url, *, method="GET", extra_headers=None):
                body = "root:x:0:0:root:/root:/bin/bash\n" if "passwd" in url else "not found"
                return {"status": 200, "headers": {}, "cookies": [], "body": body, "location": None, "final_url": url}
        f = av._check_path_traversal(LfiStub(), "https://app.example.com/?file=x")
        self.assertIsNotNone(f)
        self.assertIn("read_data", f["proof_evidence"])
        self.assertIn("root:x:0:0", f["proof_evidence"]["read_data"])

    def test_exposed_file_captures_served_content(self) -> None:
        class FileStub:
            auth = None
            def fetch(self, url, *, method="GET", extra_headers=None):
                if url.endswith("/.env"):
                    body = "SECRET_KEY=abcdef123456\nDB_PASSWORD=hunter2\n"
                elif "nonexistent" in url:
                    body = "404"
                else:
                    body = "404"
                return {"status": 200, "headers": {}, "cookies": [], "body": body, "location": None, "final_url": url}
        f = av._check_sensitive_paths(FileStub(), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertIn("read_data", f["proof_evidence"])
        # The secret VALUE is redacted, but the disclosed structure is proof of exposure.
        self.assertIn("SECRET_KEY", f["proof_evidence"]["read_data"])

    def test_disclosure_report_uses_generic_impact_heading(self) -> None:
        from bughunter.bounty import _deterministic_attack_plan
        from bughunter import report_formats as RF
        finding = {
            "ref": "F1", "title": "Path traversal", "severity": "high", "class_id": "disclosure",
            "location": "https://app.example.com/?file=x", "cwe": "CWE-22", "rule_id": "active.path-traversal",
            "proof_evidence": {"request_line": "GET https://app.example.com/?file=../etc/passwd",
                               "response_status": "HTTP 200", "matched_value": "/etc/passwd disclosed",
                               "read_data": "root:x:0:0:root:/root:/bin/bash"},
        }
        plan = _deterministic_attack_plan(finding, "path-traversal")
        ctx = {"tool": "g", "version": "t", "generated_at": "now", "target": "", "scope": "",
               "attack_plans": {"F1": plan}}
        body = RF.render_finding(ctx, finding, "hackerone")
        self.assertIn("Demonstrated impact", body)
        self.assertNotIn("cross-origin", body.lower())  # generic heading, not the CORS one
        self.assertIn("root:x:0:0", body)


class RceCommandInjectionTests(unittest.TestCase):
    """The active RCE check confirms OS command injection with a BENIGN $(expr) shell-substitution
    probe (arithmetic only), and stays quiet on an app that merely echoes the literal input."""

    class _ShellStub:
        auth = None
        def fetch(self, url, *, method="GET", extra_headers=None):
            val = dict(parse_qs(urlparse(url).query)).get("cmd", [""])[0]
            # A real shell evaluates $(expr 111 + 111) / `expr 111 + 111` to 222.
            out = re.sub(r"\$\(expr 111 \+ 111\)|`expr 111 \+ 111`", "222", val)
            return {"status": 200, "headers": {}, "cookies": [], "body": "out: " + out, "location": None, "final_url": url}

    def test_command_substitution_evaluated_confirms(self) -> None:
        f = av._check_rce_command_injection(self._ShellStub(), "https://app.example.com/run?cmd=x")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["rule_id"], "active.rce-command-injection")
        self.assertEqual(f["_active_class_hint"], "rce")
        self.assertEqual(f["severity"], "critical")

    def test_literal_echo_is_not_flagged(self) -> None:
        class _EchoStub(self._ShellStub):  # echoes input verbatim, no shell -> must NOT confirm
            def fetch(self, url, *, method="GET", extra_headers=None):
                val = dict(parse_qs(urlparse(url).query)).get("cmd", [""])[0]
                return {"status": 200, "headers": {}, "cookies": [], "body": "echo: " + val, "location": None, "final_url": url}
        self.assertIsNone(av._check_rce_command_injection(_EchoStub(), "https://app.example.com/run?cmd=x"))


class DebugEndpointExposureTests(unittest.TestCase):
    """Spring actuator heapdump/env + Jolokia exposure — critical secret-exfil / RCE, confirmed by
    an unmistakable product signature AND a catch-all control, so a 200s-everything app can't FP."""

    def _stub(self, path_body):
        class _S:
            auth = None
            def fetch(self, url, *, method="GET", extra_headers=None):
                for suffix, body in path_body.items():
                    if url.endswith(suffix):
                        return {"status": 200, "headers": {}, "cookies": [], "body": body, "location": None, "final_url": url}
                return {"status": 404, "headers": {}, "cookies": [], "body": "Whitelabel Error Page", "location": None, "final_url": url}
        return _S()

    def test_heapdump_is_critical(self) -> None:
        f = av._check_debug_endpoints(self._stub({"/actuator/heapdump": "JAVA PROFILE 1.0.2\x00binary"}), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["rule_id"], "active.debug-endpoint")

    def test_jolokia_maps_to_rce_class(self) -> None:
        body = '{"request":{"type":"list"},"value":{"java.lang":{"type=Memory":{}}},"status":200}'
        f = av._check_debug_endpoints(self._stub({"/jolokia/list": body}), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["_active_class_hint"], "rce")

    def test_phpinfo_exposure_is_high(self) -> None:
        body = (
            "<html><head><title>phpinfo()</title></head><body>"
            "<h1>PHP Version 8.2.12</h1><tr><td>Configuration File (php.ini) Path</td></tr>"
            "</body></html>"
        )
        f = av._check_debug_endpoints(self._stub({"/phpinfo.php": body}), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "high")
        self.assertIn("phpinfo", f["title"])

    def test_go_expvar_exposure_is_high(self) -> None:
        body = '{"cmdline":["/srv/api"],"memstats":{"Alloc":12345},"app_secret_status":"configured"}'
        f = av._check_debug_endpoints(self._stub({"/debug/vars": body}), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "high")
        self.assertIn("Go expvar", f["title"])

    def test_go_pprof_exposure_is_high(self) -> None:
        body = "goroutine 17 [running]:\nmain.handler()\n\t/app/server.go:42\nruntime.goexit()\n"
        f = av._check_debug_endpoints(self._stub({"/debug/pprof/goroutine?debug=1": body}), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "high")
        self.assertIn("pprof", f["title"])

    def test_docker_registry_catalog_exposure_is_high(self) -> None:
        body = '{"repositories":["backend-api","prod/payment-worker"]}'
        f = av._check_debug_endpoints(self._stub({"/v2/_catalog": body}), "https://registry.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "high")
        self.assertIn("Docker Registry", f["title"])

    def test_kubernetes_namespace_list_exposure_is_high(self) -> None:
        body = '{"kind":"NamespaceList","apiVersion":"v1","items":[{"metadata":{"name":"prod"}}]}'
        f = av._check_debug_endpoints(self._stub({"/api/v1/namespaces": body}), "https://k8s.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "high")
        self.assertIn("Kubernetes", f["title"])

    def test_apache_server_status_is_medium(self) -> None:
        body = "Total Accesses: 123\nTotal kBytes: 456\nCPULoad: .01\nBusyWorkers: 2\nIdleWorkers: 8\n"
        f = av._check_debug_endpoints(self._stub({"/server-status?auto": body}), "https://www.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "medium")
        self.assertIn("server-status", f["title"])

    def test_catch_all_200_app_is_not_flagged(self) -> None:
        class _All:
            auth = None
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "cookies": [], "body": "<html>app</html>", "location": None, "final_url": url}
        self.assertIsNone(av._check_debug_endpoints(_All(), "https://app.example.com/"))

    def test_catch_all_phpinfo_signature_not_flagged(self) -> None:
        body = (
            "<html><head><title>phpinfo()</title></head><body>"
            "PHP Version 8.1.0 Configuration File (php.ini) Path"
            "</body></html>"
        )

        class _AllPhpinfo:
            auth = None
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "cookies": [], "body": body, "location": None, "final_url": url}

        self.assertIsNone(av._check_debug_endpoints(_AllPhpinfo(), "https://app.example.com/"))

    def test_only_probes_at_root(self) -> None:
        self.assertIsNone(av._check_debug_endpoints(self._stub({"/actuator/heapdump": "JAVA PROFILE 1.0.2"}),
                                                    "https://app.example.com/some/page"))

    def test_docs_page_mentioning_hprof_is_not_flagged(self) -> None:
        # A route-dependent docs/soft-404 page that merely CONTAINS "JAVA PROFILE" mid-body must
        # not match — the HPROF magic is anchored to the START of the response (real heap dump only).
        body = "<html><body><h1>JAVA PROFILE format explained</h1><p>heap dumps...</p></body></html>"
        self.assertIsNone(av._check_debug_endpoints(self._stub({"/actuator/heapdump": body}), "https://app.example.com/"))


class _RceTimingSettings:
    web_fetch_timeout_seconds = 8
    active_time_sqli_delay_seconds = 4
    active_time_sqli_margin_seconds = 3.0


class TimeBasedRceTests(unittest.TestCase):
    """Blind OS command injection confirmed ONLY by a stable two-trial timing differential vs a
    'sleep 0' control — a non-vulnerable app never sleeps, and a uniformly-slow page can't confirm."""

    class _ShellStub:
        auth = None
        def fetch(self, url, *, method="GET", extra_headers=None):
            from urllib.parse import unquote_plus  # a real server decodes + -> space before the shell
            m = re.search(r"sleep (\d+)", unquote_plus(url))
            secs = float(m.group(1)) if m else 0.0
            return {"status": 200, "headers": {}, "cookies": [], "body": "ok", "location": None, "final_url": url, "elapsed": secs + 0.05}

    def test_sleep_differential_confirms_critical(self) -> None:
        f = av._check_time_rce(self._ShellStub(), "https://app.example.com/run?cmd=1", settings=_RceTimingSettings())
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["rule_id"], "active.rce-time")
        self.assertEqual(f["_active_class_hint"], "rce")

    def test_non_vulnerable_app_never_confirms(self) -> None:
        class _NoSleep(self._ShellStub):
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "cookies": [], "body": "ok", "location": None, "final_url": url, "elapsed": 0.05}
        self.assertIsNone(av._check_time_rce(_NoSleep(), "https://app.example.com/run?cmd=1", settings=_RceTimingSettings()))

    def test_uniformly_slow_page_does_not_confirm(self) -> None:
        class _Slow(self._ShellStub):
            def fetch(self, url, *, method="GET", extra_headers=None):
                return {"status": 200, "headers": {}, "cookies": [], "body": "ok", "location": None, "final_url": url, "elapsed": 6.0}
        self.assertIsNone(av._check_time_rce(_Slow(), "https://app.example.com/run?cmd=1", settings=_RceTimingSettings()))

    def test_waf_tarpit_on_metacharacter_does_not_confirm(self) -> None:
        # A WAF/bot-defense that TARPITS on the shell metacharacter ($( or backtick) — regardless of
        # the sleep value — must NOT confirm: the matched 'sleep 0' control carries the same
        # metacharacter and absorbs the same delay, so the differential cancels (no command injection).
        from urllib.parse import unquote_plus
        class _Waf(self._ShellStub):
            def fetch(self, url, *, method="GET", extra_headers=None):
                val = unquote_plus(url)
                secs = 5.0 if ("$(" in val or "`" in val) else 0.05  # penalizes syntax, ignores the sleep arg
                return {"status": 200, "headers": {}, "cookies": [], "body": "ok", "location": None, "final_url": url, "elapsed": secs}
        self.assertIsNone(av._check_time_rce(_Waf(), "https://app.example.com/run?cmd=1", settings=_RceTimingSettings()))


class ContextXssTests(unittest.TestCase):
    """Context-aware reflected XSS: confirms a JS-string </script> breakout or a double-quoted-
    attribute " breakout, but stays SILENT when the breakout char is encoded or the reflection
    isn't in an executable context (no false positives)."""

    def _stub(self, render):
        class S:
            auth = None
            def fetch(self, url, *, method="GET", extra_headers=None):
                val = dict(parse_qs(urlparse(url).query)).get("q", [""])[0]
                return {"status": 200, "headers": {"content-type": "text/html"}, "cookies": [],
                        "body": render(val), "location": None, "final_url": url}
        return S()

    def test_js_context_breakout_confirms(self) -> None:
        f = av._check_reflected_xss_context(self._stub(lambda v: f"<html><script>var x='{v}';</script></html>"),
                                            "https://app.example.com/p?q=x")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("JavaScript-context", f["title"])

    def test_attribute_context_breakout_confirms(self) -> None:
        f = av._check_reflected_xss_context(self._stub(lambda v: f'<html><input value="{v}"></html>'),
                                            "https://app.example.com/p?q=x")
        self.assertIsNotNone(f)
        self.assertIn("attribute-context", f["title"])

    def test_script_close_in_html_body_is_not_confirmed(self) -> None:
        # </script> reflected in a <div>, NOT inside a script element -> not executable -> no FP
        self.assertIsNone(av._check_reflected_xss_context(
            self._stub(lambda v: f"<html><div>{v}</div></html>"), "https://app.example.com/p?q=x"))

    def test_encoded_breakout_is_not_confirmed(self) -> None:
        import html as _h  # app HTML-encodes < and " -> no raw breakout survives -> no FP
        self.assertIsNone(av._check_reflected_xss_context(
            self._stub(lambda v: f"<html><script>var x='{_h.escape(v)}';</script></html>"),
            "https://app.example.com/p?q=x"))

    def test_context_helpers(self) -> None:
        self.assertTrue(av._in_script_context("<script>abc", 9))       # inside an open script
        self.assertFalse(av._in_script_context("<script>a</script>b", 18))  # after the close
        self.assertTrue(av._in_double_quoted_attr('<input value="ab', 15))  # inside a "…" value
        self.assertFalse(av._in_double_quoted_attr("<div>ab", 6))      # not inside a tag


class ClassPriorityReorderTests(unittest.TestCase):
    """The reasoning layer's per-endpoint class priorities steer the active pass — it only reorders
    checks (never adds/removes), so a prioritised class gets request-budget priority."""

    def _checks(self):
        return [("clickjacking", 1), ("csrf", 2), ("jwt", 3), ("cors", 4), ("redirect", 5),
                ("xss", 6), ("rce", 7), ("sqli", 8), ("path-traversal", 9)]

    def test_priority_promotes_and_preserves_order(self) -> None:
        out = av._apply_class_priority(self._checks(), ["path-traversal", "rce"])
        # prioritised classes move to the front; within each partition the default order is kept
        self.assertEqual([c for c, _ in out][:2], ["rce", "path-traversal"])  # rce(7) before traversal(9): default order preserved
        self.assertEqual([c for c, _ in out][2:], ["clickjacking", "csrf", "jwt", "cors", "redirect", "xss", "sqli"])

    def test_reorder_never_adds_or_drops_a_check(self) -> None:
        original = self._checks()
        out = av._apply_class_priority(original, ["xss"])
        self.assertEqual(sorted(out), sorted(original))  # exact same multiset of checks
        self.assertEqual(len(out), len(original))

    def test_empty_or_unknown_priority_is_a_noop(self) -> None:
        original = self._checks()
        self.assertEqual(av._apply_class_priority(original, None), original)
        self.assertEqual(av._apply_class_priority(original, []), original)
        self.assertEqual(av._apply_class_priority(original, ["nonexistent-class"]), original)  # no match -> unchanged order


if __name__ == "__main__":
    unittest.main()
