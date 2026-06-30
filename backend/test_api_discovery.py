"""Tests for API surface discovery (OpenAPI/Swagger + GraphQL). Fully offline — the fetch
callable is injected, so no sockets. Covers spec parsing, GraphQL introspection detection,
the candidate-finding shape, and the scope-gated driver."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import api_discovery_service as api  # noqa: E402

_OPENAPI3 = {
    "openapi": "3.0.1",
    "info": {"title": "Shop API"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/products": {"get": {"parameters": [{"name": "category", "in": "query"}, {"name": "limit", "in": "query"}]}},
        "/products/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},  # templated -> not a concrete endpoint
        "/checkout": {"post": {"parameters": [{"name": "coupon", "in": "query"}]}},  # POST -> not added as a GET endpoint
    },
}

_SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "Legacy API"},
    "host": "ignored.example.com",
    "basePath": "/api",
    "paths": {"/users": {"get": {"parameters": [{"name": "page", "in": "query"}]}}},
}

_INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [{"name": "User"}, {"name": "Order"}, {"name": "__Directive"}],
}}}


class ParseOpenApiTests(unittest.TestCase):
    def test_openapi3_endpoints_and_params(self) -> None:
        p = api.parse_openapi(_OPENAPI3, "https://api.example.com/openapi.json")
        self.assertEqual(p["title"], "Shop API")
        # concrete GET endpoint resolved against servers[].url; templated/POST excluded
        self.assertIn("https://api.example.com/v1/products", p["endpoints"])
        self.assertNotIn("https://api.example.com/v1/products/{id}", p["endpoints"])
        self.assertFalse(any("checkout" in e for e in p["endpoints"]))
        # every declared param name is collected (query + path)
        self.assertEqual(set(p["params"]), {"category", "limit", "id", "coupon"})

    def test_swagger2_basepath_resolution(self) -> None:
        p = api.parse_openapi(_SWAGGER2, "https://legacy.example.com/swagger.json")
        # basePath is resolved against the SPEC's origin, not the spec's `host` field
        self.assertIn("https://legacy.example.com/api/users", p["endpoints"])
        self.assertEqual(set(p["params"]), {"page"})

    def test_non_spec_returns_empty(self) -> None:
        self.assertEqual(api.parse_openapi({"hello": "world"}, "https://x/y"), {})
        self.assertEqual(api.parse_openapi("not a dict", "https://x/y"), {})


class GraphQLTests(unittest.TestCase):
    def test_introspection_parsed(self) -> None:
        info = api.parse_graphql_introspection(_INTROSPECTION)
        self.assertEqual(info["query_type"], "Query")
        self.assertEqual(info["mutation_type"], "Mutation")
        self.assertEqual(info["type_count"], 2)            # __Directive (a __ type) excluded
        self.assertEqual(set(info["types"]), {"User", "Order"})

    def test_non_introspection_returns_none(self) -> None:
        self.assertIsNone(api.parse_graphql_introspection({"data": {"viewer": {}}}))
        self.assertIsNone(api.parse_graphql_introspection({"errors": [{"message": "nope"}]}))

    def test_finding_is_candidate_with_inline_plan(self) -> None:
        f = api._graphql_finding("https://api.example.com/graphql", api.parse_graphql_introspection(_INTROSPECTION))
        self.assertEqual(f["class_id"], "info-disclosure")
        self.assertEqual(f["rule_id"], "passive.graphql-introspection")
        self.assertEqual(f["_plan"]["proof_of_impact"]["status"], "candidate")
        self.assertEqual(f["_plan"]["cvss"]["base_severity"], "low")


class DiscoverDriverTests(unittest.TestCase):
    def _fetch_map(self, mapping):
        def fetch(url):
            return mapping.get(url)
        return fetch

    def test_discovers_openapi_and_graphql_in_scope(self) -> None:
        origin = "https://api.example.com"
        gql_url = f"{origin}/graphql?query={api.quote(api.GRAPHQL_INTROSPECTION_QUERY, safe='')}"
        mapping = {
            f"{origin}/openapi.json": {"status": 200, "body": json.dumps(_OPENAPI3), "final_url": f"{origin}/openapi.json"},
            gql_url: {"status": 200, "body": json.dumps(_INTROSPECTION), "final_url": gql_url},
        }
        out = api.discover_api_surface(f"{origin}/", fetch=self._fetch_map(mapping), in_scope=lambda u: True)
        self.assertIsNotNone(out["openapi"])
        self.assertIn("https://api.example.com/v1/products", out["endpoints"])
        self.assertIn("category", out["params"])
        self.assertIsNotNone(out["graphql"])
        self.assertEqual(len(out["findings"]), 1)
        self.assertEqual(out["findings"][0]["class_id"], "info-disclosure")

    def test_out_of_scope_specs_are_never_fetched(self) -> None:
        fetched: list[str] = []
        def fetch(url):
            fetched.append(url)
            return {"status": 200, "body": "{}"}
        out = api.discover_api_surface("https://api.example.com/", fetch=fetch, in_scope=lambda u: False)
        self.assertEqual(fetched, [])           # in_scope=False -> nothing fetched (fail-closed)
        self.assertEqual(out["findings"], [])

    def test_no_spec_no_graphql_is_clean(self) -> None:
        out = api.discover_api_surface("https://api.example.com/",
                                       fetch=lambda u: {"status": 404, "body": "nope"}, in_scope=lambda u: True)
        self.assertEqual(out["endpoints"], [])
        self.assertEqual(out["findings"], [])
        self.assertIsNone(out["openapi"])


if __name__ == "__main__":
    unittest.main()
