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
        # An authenticated scan turns a header-only misconfig into a proven cross-origin READ:
        # read_data holds the response body and the observation states the attacker origin READ it.
        f = av._check_cors(_AuthedReflectCorsStub(), "https://api.example.com/user/me")
        self.assertIsNotNone(f)
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertIn("read_data", f["proof_evidence"])
        self.assertIn("victim@example.com", f["proof_evidence"]["read_data"])
        self.assertIn("READ", f["_active_proof"]["observed_result"])
        # read_data is redacted exactly once — no nested "[REDACTED_SECRET:[REDACTED_SECRET" markers.
        self.assertNotIn("[REDACTED_SECRET:[REDACTED_SECRET", f["proof_evidence"]["read_data"])

    def test_unauthenticated_scan_reports_misconfig_without_read(self) -> None:
        # No auth attribute -> _cors_enrich_read is a no-op: the misconfiguration is still
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
        self.assertIn("Demonstrated cross-origin read", body)          # the read is shown
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


if __name__ == "__main__":
    unittest.main()
