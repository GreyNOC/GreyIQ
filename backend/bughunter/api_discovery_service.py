"""GreyIQ BugHunter — API surface discovery (OpenAPI / Swagger + GraphQL).

Two force-multipliers for the active prover, both GET-only:

  * **OpenAPI / Swagger** — fetch the common spec locations (``/openapi.json``,
    ``/swagger.json``, ``/v3/api-docs`` …), parse the document, and hand back the concrete
    GET endpoints and the declared parameter names so the existing active checks probe a far
    bigger surface than the HTML crawl alone reveals. A public spec is NOT reported as a
    finding (it's frequently intentional) — it is pure surface expansion.
  * **GraphQL introspection** — probe the common GraphQL routes with a GET introspection
    query; if the schema comes back, introspection is enabled (commonly reported as an
    information-disclosure misconfiguration). That IS emitted as a candidate finding, with the
    type/field counts as evidence.

Network is injected (a ``fetch(url) -> dict | None`` callable, e.g. recon's budgeted, SSRF-
guarded fetch) and an ``in_scope(url) -> bool`` gate, so the parsing logic is pure and
fully unit-testable with no sockets. Frozen-safe (stdlib only).
"""

from __future__ import annotations

import json
from typing import Any, Callable
from urllib.parse import quote, urljoin, urlparse

# Common, high-signal spec locations (bounded — one GET each, stops at the first valid spec).
_OPENAPI_PATHS = (
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/api-docs",
    "/api/openapi.json", "/api/swagger.json", "/swagger/v1/swagger.json", "/openapi/v3",
)
_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphql/console")

# A minimal introspection query — enough to prove introspection is on and size the schema.
GRAPHQL_INTROSPECTION_QUERY = (
    "{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}"
)

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


def _resolve_base(origin: str, server: str) -> str:
    """Resolve an OpenAPI ``servers[].url`` / Swagger ``basePath`` to an absolute base."""
    server = str(server or "").strip()
    if server.startswith(("http://", "https://")):
        return server.rstrip("/")
    if server.startswith("/"):
        return origin.rstrip("/") + server.rstrip("/")
    return origin.rstrip("/")


def parse_openapi(spec: Any, spec_url: str) -> dict[str, Any]:
    """Pure parse of an OpenAPI 3.x / Swagger 2.0 document. Returns
    ``{title, version, endpoints, params}`` — endpoints are absolute URLs for *concrete*
    (non-templated) GET operations; params are every declared parameter name. ``{}`` if the
    document isn't a recognisable spec."""
    if not isinstance(spec, dict):
        return {}
    paths = spec.get("paths")
    if not isinstance(paths, dict) or not paths:
        return {}
    origin = _origin(spec_url)
    base = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base = str(servers[0].get("url") or "")
    elif spec.get("basePath"):  # Swagger 2.0
        base = str(spec.get("basePath") or "")
    base_url = _resolve_base(origin, base)

    endpoints: list[str] = []
    params: set[str] = set()
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        # Path-level shared parameters.
        for p in (item.get("parameters") or []):
            if isinstance(p, dict) and p.get("name"):
                params.add(str(p["name"]))
        for method, op in item.items():
            if str(method).lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            for p in (op.get("parameters") or []):
                if isinstance(p, dict) and p.get("name"):
                    params.add(str(p["name"]))
            if str(method).lower() == "get" and "{" not in str(path):
                full = base_url.rstrip("/") + "/" + str(path).lstrip("/")
                endpoints.append(full)
    # de-dupe, preserve order
    seen: set[str] = set()
    uniq = [e for e in endpoints if not (e in seen or seen.add(e))]
    return {
        "title": str((spec.get("info") or {}).get("title") or ""),
        "version": str(spec.get("openapi") or spec.get("swagger") or ""),
        "endpoints": uniq,
        "params": sorted(params),
    }


def parse_graphql_introspection(data: Any) -> dict[str, Any] | None:
    """Pure parse of a GraphQL introspection response. Returns ``{query_type, mutation_type,
    type_count, types}`` when ``data.__schema`` is present, else ``None``."""
    schema = None
    if isinstance(data, dict):
        d = data.get("data")
        if isinstance(d, dict):
            schema = d.get("__schema")
    if not isinstance(schema, dict):
        return None
    types = [str(t.get("name")) for t in (schema.get("types") or [])
             if isinstance(t, dict) and t.get("name") and not str(t.get("name")).startswith("__")]
    return {
        "query_type": str((schema.get("queryType") or {}).get("name") or ""),
        "mutation_type": str((schema.get("mutationType") or {}).get("name") or ""),
        "type_count": len(types),
        "types": types[:50],
    }


def _graphql_finding(gql_url: str, info: dict[str, Any]) -> dict[str, Any]:
    finding = {
        "rule_id": "passive.graphql-introspection",
        "title": "GraphQL introspection enabled",
        "severity": "low",
        "confidence": "high",  # the schema came back — introspection is definitively on
        "category": "info-disclosure",
        "location": gql_url,
        "file_path": gql_url,
        "line_start": 1, "line_end": 1,
        "class_id": "info-disclosure",
        "class_name": "Information disclosure",
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "vrt": "",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
            "https://portswigger.net/web-security/graphql",
        ],
        "remediation": ("Disable introspection in production (e.g. set introspection: false / a "
                        "validation rule), and apply field-level authorization + query depth/cost limits."),
        "snippet": f"__schema returned {info.get('type_count', 0)} types (query: {info.get('query_type') or '?'})",
        "proof_evidence": {
            "request_line": f"GET {gql_url}?query={{__schema...}}",
            "response_status": "200 with data.__schema",
            "matched_value": (f"GraphQL introspection returned the full schema ({info.get('type_count', 0)} types; "
                              f"queryType {info.get('query_type') or '?'}, mutationType {info.get('mutation_type') or '—'})"),
        },
    }
    finding["_plan"] = {
        "steps": [
            f"Send a GraphQL introspection query to {gql_url} (GET ?query={{__schema...}} or POST).",
            "Observe the full schema returned — types, fields, and mutations are disclosed.",
            "Enumerate sensitive queries/mutations from the schema and test them for authorization gaps.",
        ],
        "poc": f"GET {gql_url}?query={quote('{__schema{types{name}}}')}\n# -> data.__schema with {info.get('type_count', 0)} types",
        "impact": ("Introspection hands an attacker the complete API schema — every type, field, and mutation — "
                   "greatly accelerating discovery of sensitive or unauthorized operations."),
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "base_score": 5.3, "base_severity": "low", "estimated": True},
        "remediation": finding["remediation"],
        "proof_of_impact": {
            "status": "candidate",
            "method": "GET introspection query — schema returned (no data mutated)",
            "affected_asset": f"the GraphQL API at {gql_url}",
            "observed_result": f"introspection returned {info.get('type_count', 0)} types",
            "control_result": "a hardened endpoint returns an error / null for __schema in production",
            "evidence": finding["proof_evidence"]["matched_value"],
            "proof_obligation": ("Introspection-enabled is reportable on its own for many programs; to escalate, show a "
                                 "specific sensitive query/mutation reachable without proper authorization."),
        },
    }
    return finding


def _looks_like_json(body: str) -> bool:
    s = (body or "").lstrip()
    return s.startswith("{") or s.startswith("[")


def discover_api_surface(
    target_url: str,
    *,
    fetch: Callable[[str], dict[str, Any] | None],
    in_scope: Callable[[str], bool],
    max_specs: int = 3,
) -> dict[str, Any]:
    """Probe the target's origin for an OpenAPI/Swagger spec and a GraphQL endpoint using the
    injected ``fetch`` (GET-only, already SSRF-guarded by the caller) and ``in_scope`` gate.

    Returns ``{endpoints, params, openapi, graphql, findings, notes}``: ``endpoints``/``params``
    expand the active prover's surface; ``findings`` carries the GraphQL-introspection candidate
    (with an inline ``_plan``). Never raises — a malformed spec just yields nothing."""
    origin = _origin(target_url)
    out: dict[str, Any] = {"endpoints": [], "params": [], "openapi": None, "graphql": None,
                           "findings": [], "notes": []}
    if not origin:
        return out

    # --- OpenAPI / Swagger (first valid spec wins). ---
    tried = 0
    for path in _OPENAPI_PATHS:
        if tried >= max_specs:
            break
        url = origin + path
        if not in_scope(url):
            continue
        tried += 1
        r = fetch(url)
        if not r or int(r.get("status") or 0) != 200:
            continue
        body = r.get("body") or ""
        if not _looks_like_json(body):
            continue
        try:
            spec = json.loads(body)
        except (ValueError, TypeError):
            continue
        parsed = parse_openapi(spec, r.get("final_url") or url)
        if parsed and (parsed.get("endpoints") or parsed.get("params")):
            out["openapi"] = {"spec_url": url, "title": parsed["title"], "version": parsed["version"],
                              "endpoint_count": len(parsed["endpoints"])}
            out["endpoints"] = [e for e in parsed["endpoints"] if in_scope(e)]
            out["params"] = parsed["params"]
            out["notes"].append(
                f"OpenAPI/Swagger spec at {path} ({parsed['title'] or 'untitled'}): "
                f"{len(out['endpoints'])} GET endpoint(s) + {len(parsed['params'])} param(s) added to the surface.")
            break

    # --- GraphQL introspection (first responsive endpoint wins). ---
    enc = quote(GRAPHQL_INTROSPECTION_QUERY, safe="")
    for path in _GRAPHQL_PATHS:
        url = origin + path
        if not in_scope(url):
            continue
        r = fetch(f"{url}?query={enc}")
        if not r or int(r.get("status") or 0) != 200:
            continue
        body = r.get("body") or ""
        if not _looks_like_json(body):
            continue
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            continue
        info = parse_graphql_introspection(data)
        if info:
            out["graphql"] = {"url": url, **info}
            out["findings"].append(_graphql_finding(url, info))
            out["notes"].append(
                f"GraphQL introspection ENABLED at {path} ({info['type_count']} types) — candidate finding added.")
            break
    return out
