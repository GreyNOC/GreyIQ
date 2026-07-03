"""'All-knowing within scope' recon expansion batch 2: form action targets, OIDC/OAuth
discovery docs, and broadened API-spec discovery (YAML, templated-path instantiation,
Swagger-UI spec-URL scraping). Every test asserts BOTH the added reach and the scope drops."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import recon  # noqa: E402
from bughunter.api_discovery_service import (  # noqa: E402
    discover_api_surface, parse_openapi, parse_spec_body,
)


def _resp(body: str, final: str, ctype: str = "text/html") -> dict:
    return {"status": 200, "final_url": final, "headers": {"content-type": ctype}, "cookies": [], "body": body}


# ---------------------------------------------------------------- recon.py: forms + OIDC
class ReconFormAndOidcTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_fetch = recon._safe_fetch
        self.addCleanup(lambda: setattr(recon, "_safe_fetch", self._orig_fetch))

    def _discover(self, pages: dict, scope: set):
        recon._safe_fetch = lambda url, s, g: pages.get(url) or {"status": 404, "final_url": url, "headers": {}, "cookies": [], "body": ""}
        return recon.discover("https://example.com/", scope_in=lambda h: h in scope, max_pages=50, max_requests=60)

    def test_form_action_target_queued_and_params_unioned(self) -> None:
        pages = {"https://example.com/": _resp(
            '<form action="/search" method="get"><input name="q"><input name="lang"></form>'
            '<form action="https://evil.com/collect"><input name="p"></form>',
            "https://example.com/")}
        res = self._discover(pages, {"example.com"})
        urls = set(res["urls"])
        self.assertTrue(any("/search" in u for u in urls))       # in-scope form action becomes surface
        self.assertFalse(any("evil.com" in u for u in urls))     # OOS form action dropped, never fetched
        self.assertIn("q", res["params"])                        # the form's field names on the surface
        self.assertIn("lang", res["params"])

    def test_oidc_discovery_doc_adds_inscope_endpoints_drops_external_idp(self) -> None:
        doc = {"issuer": "https://example.com",
               "authorization_endpoint": "https://example.com/oauth/authorize",
               "token_endpoint": "https://example.com/oauth/token",
               "jwks_uri": "https://idp.external.com/jwks"}  # federated -> out of scope
        pages = {
            "https://example.com/": _resp("<html></html>", "https://example.com/"),
            "https://example.com/.well-known/openid-configuration": _resp(
                json.dumps(doc), "https://example.com/.well-known/openid-configuration", "application/json"),
        }
        urls = set(self._discover(pages, {"example.com"})["urls"])
        self.assertTrue(any("/oauth/authorize" in u for u in urls))   # self-hosted auth endpoints added
        self.assertTrue(any("/oauth/token" in u for u in urls))
        self.assertFalse(any("idp.external.com" in u for u in urls))  # external IdP endpoint dropped


# ---------------------------------------------------------------- api_discovery_service.py
class OpenApiExpansionTests(unittest.TestCase):
    def test_templated_get_path_is_instantiated(self) -> None:
        spec = {"openapi": "3.0.0", "info": {"title": "T"}, "servers": [{"url": "https://api.x.com"}],
                "paths": {"/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
                          "/orgs/{org}/repos/{repo}": {"get": {}},
                          "/health": {"get": {}}}}
        parsed = parse_openapi(spec, "https://api.x.com/openapi.json")
        self.assertIn("https://api.x.com/users/1", parsed["endpoints"])            # {id} -> 1
        self.assertIn("https://api.x.com/orgs/1/repos/1", parsed["endpoints"])     # every segment instantiated
        self.assertIn("https://api.x.com/health", parsed["endpoints"])            # concrete path unchanged
        self.assertEqual(parsed["templated_count"], 2)

    def test_malformed_template_never_surfaces_raw_braces(self) -> None:
        # A nested/malformed/slash-containing template must not reach the surface with literal braces
        # (vet finding: /files/{path/to}, /x/{}, /q/{{weird}} previously leaked '{'/'}' to the prover).
        spec = {"openapi": "3.0.0", "info": {"title": "T"}, "servers": [{"url": "https://api.x.com"}],
                "paths": {"/files/{path/to}": {"get": {}}, "/x/{}": {"get": {}},
                          "/q/{{weird}}": {"get": {}}, "/ok/{id}": {"get": {}}}}
        parsed = parse_openapi(spec, "https://api.x.com/openapi.json")
        for ep in parsed["endpoints"]:
            self.assertNotIn("{", ep, ep)
            self.assertNotIn("}", ep, ep)
        self.assertIn("https://api.x.com/ok/1", parsed["endpoints"])  # the well-formed one still instantiated
        self.assertIn("https://api.x.com/files/1", parsed["endpoints"])  # slash-containing token collapses cleanly

    def test_yaml_spec_is_parsed(self) -> None:
        y = "openapi: 3.0.0\ninfo:\n  title: Y\npaths:\n  /ping:\n    get: {}\n  /items/{id}:\n    get: {}\n"
        doc = parse_spec_body(y, is_yaml_hint=True)
        self.assertIsInstance(doc, dict)
        parsed = parse_openapi(doc, "https://api.x.com/openapi.yaml")
        self.assertIn("https://api.x.com/ping", parsed["endpoints"])
        self.assertIn("https://api.x.com/items/1", parsed["endpoints"])

    def test_discover_prefers_yaml_when_json_absent(self) -> None:
        y = "openapi: 3.0.0\ninfo:\n  title: Y\npaths:\n  /ping:\n    get: {}\n"

        def fetch(url):
            if url.endswith("/openapi.yaml"):
                return _resp(y, url, "application/yaml")
            return {"status": 404, "final_url": url, "headers": {}, "cookies": [], "body": ""}

        out = discover_api_surface("https://api.x.com/", fetch=fetch, in_scope=lambda u: "api.x.com" in u)
        self.assertTrue(any(e.endswith("/ping") for e in out["endpoints"]))
        self.assertIsNotNone(out["openapi"])

    def test_swagger_ui_embedded_spec_url_is_followed(self) -> None:
        spec = {"openapi": "3.0.0", "info": {"title": "UI"}, "servers": [{"url": "https://api.x.com"}],
                "paths": {"/from-ui": {"get": {}}}}

        def fetch(url):
            if url.endswith("/docs"):  # a Swagger-UI page embedding the real (non-standard) spec URL
                return _resp('<script>const ui = SwaggerUIBundle({ url: "/custom/api-spec.json" })</script>', url)
            if url.endswith("/custom/api-spec.json"):
                return _resp(json.dumps(spec), url, "application/json")
            return {"status": 404, "final_url": url, "headers": {}, "cookies": [], "body": ""}

        out = discover_api_surface("https://api.x.com/", fetch=fetch, in_scope=lambda u: "api.x.com" in u)
        self.assertTrue(any(e.endswith("/from-ui") for e in out["endpoints"]))  # spec found via UI scrape
        self.assertEqual(out["openapi"]["spec_url"], "https://api.x.com/custom/api-spec.json")

    def test_swagger_ui_out_of_scope_spec_url_is_dropped(self) -> None:
        def fetch(url):
            if url.endswith("/docs"):
                return _resp('<script>SwaggerUIBundle({ url: "https://evil.com/openapi.json" })</script>', url)
            if "evil.com" in url:
                raise AssertionError("out-of-scope spec URL must never be fetched")
            return {"status": 404, "final_url": url, "headers": {}, "cookies": [], "body": ""}

        out = discover_api_surface("https://api.x.com/", fetch=fetch, in_scope=lambda u: "api.x.com" in u)
        self.assertIsNone(out["openapi"])       # OOS spec URL never followed
        self.assertEqual(out["endpoints"], [])


if __name__ == "__main__":
    unittest.main()
