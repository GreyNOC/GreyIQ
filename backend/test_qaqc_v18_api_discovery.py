"""QAQC v1.8 regression tests for api_discovery_service.

Covers three verified defects, each fails before the fix and passes after:
  * GraphQL introspection finding must be re-gated on the post-redirect final_url,
    so an in-scope /graphql that 302s to a public OOS host does NOT yield a false
    finding attributed to the in-scope target (api_discovery_service.py:~398).
  * OpenAPI spec ingest must be re-gated on the post-redirect final_url, so an
    OOS-redirected spec contributes neither params nor a note (~:353).
  * parse_spec_body's last-resort json.loads must catch RecursionError (a
    RuntimeError, NOT a ValueError) so deeply-nested hostile JSON in a stripped
    (no-PyYAML) build degrades to None instead of re-raising (~:95).

Fully offline/deterministic: the fetch callable is injected; no sockets.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import api_discovery_service as api  # noqa: E402

_INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [{"name": "User"}, {"name": "Order"}],
}}}


def _nested_json(depth: int) -> str:
    """A syntactically valid JSON object whose value is `depth` nested arrays — deep
    enough to make CPython's json C scanner raise RecursionError."""
    return '{"a":' + "[" * depth + "]" * depth + "}"


class GraphQLFinalUrlRegateTests(unittest.TestCase):
    def test_graphql_introspection_on_oos_redirect_is_not_credited(self) -> None:
        origin = "https://target.example"
        in_scope = lambda u: u.startswith(origin)  # noqa: E731
        gql_probe = f"{origin}/graphql?query={api.quote(api.GRAPHQL_INTROSPECTION_QUERY, safe='')}"
        # in-scope /graphql 302s to a public OOS host that serves a valid introspection schema
        mapping = {
            gql_probe: {"status": 200, "body": json.dumps(_INTROSPECTION),
                        "final_url": "https://api.thirdparty.example/graphql"},
        }
        out = api.discover_api_surface(f"{origin}/", fetch=lambda u: mapping.get(u), in_scope=in_scope)
        # Pre-fix: a passive.graphql-introspection finding is emitted against the in-scope target.
        self.assertEqual(out["findings"], [])
        self.assertIsNone(out["graphql"])


class OpenApiFinalUrlRegateTests(unittest.TestCase):
    def test_oos_redirected_spec_contributes_no_params_or_endpoints(self) -> None:
        origin = "https://target.example"
        in_scope = lambda u: u.startswith(origin)  # noqa: E731
        oos_spec = {"openapi": "3.0.1", "info": {"title": "Evil"},
                    "servers": [{"url": "https://evil-oos.example"}],
                    "paths": {"/loot": {"get": {"parameters": [{"name": "attacker_param", "in": "query"}]}}}}
        # in-scope /openapi.json 302s to a public OOS host that serves the attacker's spec
        mapping = {
            f"{origin}/openapi.json": {"status": 200, "body": json.dumps(oos_spec),
                                       "final_url": "https://evil-oos.example/spec.json"},
        }
        out = api.discover_api_surface(f"{origin}/", fetch=lambda u: mapping.get(u), in_scope=in_scope)
        # Pre-fix: attacker-chosen param names leak into the prover's surface.
        self.assertEqual(out["params"], [])
        self.assertEqual(out["endpoints"], [])
        self.assertIsNone(out["openapi"])
        self.assertEqual(out["notes"], [])


class ParseSpecBodyRecursionTests(unittest.TestCase):
    def test_last_resort_json_loads_survives_deep_nesting_without_yaml(self) -> None:
        # Simulate a stripped build with PyYAML unavailable so the YAML block is skipped
        # and execution falls through to the last-resort json.loads.
        saved_yaml = api._yaml
        api._yaml = None
        try:
            # is_yaml_hint=True forces the first JSON block to be skipped, so ONLY the
            # last-resort json.loads at the bottom parses the nested body.
            result = api.parse_spec_body(_nested_json(4000), is_yaml_hint=True)
        finally:
            api._yaml = saved_yaml
        # Pre-fix: RecursionError (not a ValueError) escapes and breaks the "never raises" contract.
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
