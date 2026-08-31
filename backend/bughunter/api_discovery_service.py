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
import re
from typing import Any, Callable
from urllib.parse import quote, urljoin, urlparse

try:  # YAML specs are common (/openapi.yaml). Best-effort: if the parser isn't in this
    import yaml as _yaml  # build we silently skip YAML specs and still handle every JSON one.
except Exception:  # pragma: no cover - only when PyYAML is unavailable in a stripped build
    _yaml = None

# Common, high-signal spec locations (bounded — one GET each, stops at the first valid spec).
# Ordered by prevalence with JSON+YAML variants of the top names interleaved so both are reached
# within the probe budget (max_specs). Every entry here is actually probed — no dead fallbacks.
_OPENAPI_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/v3/api-docs", "/v2/api-docs", "/api-docs", "/api/openapi.json",
    "/swagger/v1/swagger.json", "/apispec_1.json",
)
_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphql/console")

# Swagger-UI / Redoc / RapiDoc HTML pages that EMBED the real spec URL (which may live at a
# non-standard path none of _OPENAPI_PATHS would guess). We fetch a few, scrape the spec URL,
# then fetch+parse it — every scraped URL is scope-gated before it is fetched.
_SWAGGER_UI_PATHS = ("/swagger-ui.html", "/swagger-ui/index.html", "/api/docs", "/docs",
                     "/swagger", "/redoc", "/api-docs/index.html")
# The spec URL as embedded by Swagger-UI (`url: "/v3/api-docs"`), Redoc (`spec-url="..."`),
# or a swagger-config (`configUrl`/`SwaggerUIBundle({url:...})`). Value captured, then vetted
# by _looks_like_spec_url() so we don't chase every string on the page.
_SPEC_URL_RE = re.compile(
    r"""(?:\b(?:url|spec-?url|configUrl)\b)\s*[:=]\s*["']([^"'{}<>\s]{2,300})["']""", re.IGNORECASE)

# A minimal introspection query — enough to prove introspection is on and size the schema.
GRAPHQL_INTROSPECTION_QUERY = (
    "{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}"
)

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

# One inert, obviously-synthetic placeholder per templated path segment. GET-only + read-only,
# so instantiating `/users/{id}` as `/users/1` is a benign probe of the target's own API (the
# active prover then decides whether that concrete endpoint is worth testing). `1` is chosen
# because it most often resolves to a live resource, giving the prover real surface to bite on.
# One {...} token (no nested braces). `[^{}]*` (not `[^}/]+`) so it also collapses an empty
# `{}` and a slash-containing single token; the caller still drops any path that isn't fully
# brace-free after substitution, so a nested/malformed template never reaches the surface.
_TEMPLATE_PARAM_RE = re.compile(r"\{[^{}]*\}")
_TEMPLATE_PLACEHOLDER = "1"


def _instantiate_template(path: str) -> str:
    """`/users/{id}/posts/{postId}` -> `/users/1/posts/1` (inert placeholder per segment)."""
    return _TEMPLATE_PARAM_RE.sub(_TEMPLATE_PLACEHOLDER, path)


def parse_spec_body(body: str, is_yaml_hint: bool = False) -> Any:
    """Parse a spec body as JSON, falling back to YAML (if PyYAML is present). Returns the
    decoded object or ``None``. Pure; never raises."""
    text = body or ""
    s = text.lstrip()
    if not is_yaml_hint and (s.startswith("{") or s.startswith("[")):
        try:
            return json.loads(text)
        except (ValueError, TypeError, RecursionError):
            pass
    if _yaml is not None:
        try:
            loaded = _yaml.safe_load(text)  # safe_load: no arbitrary object construction
            if isinstance(loaded, (dict, list)):
                return loaded
        except Exception:  # pragma: no cover - malformed YAML
            return None
    # last resort: a JSON body that didn't start with {/[ (rare) but is still valid JSON.
    # RecursionError (deeply-nested hostile JSON) is a RuntimeError, not a ValueError, so it
    # must be caught explicitly here too — matching the first-block guard above — otherwise a
    # stripped build (_yaml is None) re-raises it and breaks the "never raises" contract.
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None


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


def _resolve_server_variables(url: str, variables: Any) -> str:
    """Substitute OpenAPI ``servers[].variables`` defaults into a templated server URL
    (``https://{host}/{basePath}`` -> the declared defaults). Any variable without a declared default
    is replaced with a neutral ``1`` so the base never carries a literal ``{...}`` into an assembled
    endpoint URL (which the host-only scope gate would pass and the prover would waste a request on)."""
    if not isinstance(url, str) or "{" not in url:
        return url
    vars_map = variables if isinstance(variables, dict) else {}

    def _sub(match: re.Match[str]) -> str:
        name = match.group(0)[1:-1]  # strip the surrounding { } (the regex has no capture group)
        spec = vars_map.get(name)
        if isinstance(spec, dict) and spec.get("default") is not None:
            return str(spec["default"])
        return _TEMPLATE_PLACEHOLDER

    return _TEMPLATE_PARAM_RE.sub(_sub, url)


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
    server_variables: Any = None
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base = str(servers[0].get("url") or "")
        server_variables = servers[0].get("variables")
    elif spec.get("basePath"):  # Swagger 2.0
        base = str(spec.get("basePath") or "")
    base = _resolve_server_variables(base, server_variables)  # {version} -> its declared default
    base_url = _resolve_base(origin, base)

    endpoints: list[str] = []
    templated = 0
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
            if str(method).lower() != "get":
                continue
            raw_path = str(path)
            # A templated GET path (`/users/{id}`) is a real endpoint the HTML crawl never
            # reaches — instantiate it with an inert placeholder so the active prover gets a
            # concrete, GET-only URL to probe (IDOR/auth surface). Non-templated paths pass through.
            if "{" in raw_path or "}" in raw_path:
                concrete = _instantiate_template(raw_path)
                # A nested/malformed template ({{x}}, unbalanced) can leave a stray brace; never
                # surface a non-concrete URL — the active prover must not receive raw { } junk.
                if "{" in concrete or "}" in concrete:
                    continue
                templated += 1
            else:
                concrete = raw_path
            full = base_url.rstrip("/") + "/" + concrete.lstrip("/")
            if "{" in full or "}" in full:
                continue  # unresolved server-variable/template -> never hand a braced URL to the prover
            endpoints.append(full)
    # de-dupe, preserve order
    seen: set[str] = set()
    uniq = [e for e in endpoints if not (e in seen or seen.add(e))]
    return {
        "title": str((spec.get("info") or {}).get("title") or ""),
        "version": str(spec.get("openapi") or spec.get("swagger") or ""),
        "endpoints": uniq,
        "templated_count": templated,
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
    # The introspection query already fetched `fields{name}` for every type — surface the ROOT
    # query/mutation operation names (the actual read/write API), which the caller can add to the
    # probe surface. No extra request; this only reads what was already returned.
    by_name = {str(t.get("name")): t for t in (schema.get("types") or []) if isinstance(t, dict) and t.get("name")}

    def _field_names(type_name: str) -> list[str]:
        entry = by_name.get(type_name) or {}
        return [str(f.get("name")) for f in (entry.get("fields") or [])
                if isinstance(f, dict) and f.get("name")][:60]

    q_name = str((schema.get("queryType") or {}).get("name") or "")
    m_name = str((schema.get("mutationType") or {}).get("name") or "")
    return {
        "query_type": q_name,
        "mutation_type": m_name,
        "type_count": len(types),
        "types": types[:50],
        "query_fields": _field_names(q_name),      # the read operations exposed
        "mutation_fields": _field_names(m_name),   # the write operations exposed
    }


def _graphql_finding(gql_url: str, info: dict[str, Any]) -> dict[str, Any]:
    finding = {
        "rule_id": "passive.graphql-introspection",
        "title": "GraphQL introspection enabled",
        "severity": "low",
        "confidence": "high",  # the schema came back — introspection is definitively on
        # Vocabulary is load-bearing, so mirror the ACTIVE detector of this same vulnerability exactly
        # (active_verify_service `_finding("active.graphql-introspection", ..., "disclosure", "graphql")`):
        #  - class_id "graphql" is a real chain class; the old "info-disclosure" matched no technique
        #    and no alias, so normalize_class returned it verbatim and the finding chained to nothing.
        #  - category "disclosure" is the key bounty._ARTIFACT_CATEGORIES / _CATEGORY_LABELS actually
        #    hold ("Information disclosure", CWE-200). "graphql" as a CATEGORY would drop the
        #    deterministic proof status to "missing" and degrade _classify to a CWE-less fallback.
        "category": "disclosure",
        "location": gql_url,
        "file_path": gql_url,
        "line_start": 1, "line_end": 1,
        "class_id": "graphql",
        "class_name": "Information disclosure",  # display-only
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
            # The verbatim disclosed schema (the concrete data introspection leaks) — rendered as the
            # demonstrated-disclosure excerpt, not just a count.
            "read_data": (
                f"queryType: {info.get('query_type') or '?'}\n"
                f"mutationType: {info.get('mutation_type') or '—'}\n"
                + (f"Query operations: {', '.join(info.get('query_fields') or [])}\n" if info.get("query_fields") else "")
                + (f"Mutation operations: {', '.join(info.get('mutation_fields') or [])}\n" if info.get("mutation_fields") else "")
                + f"Types ({info.get('type_count', 0)} total, sample of {len(info.get('types') or [])}): "
                + ", ".join(info.get("types") or [])
            ),
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


def _looks_like_spec_url(value: str) -> bool:
    """A scraped Swagger-UI/Redoc URL that plausibly points at an actual spec document."""
    v = (value or "").split("?", 1)[0].split("#", 1)[0].lower()
    if not v or v.startswith(("javascript:", "data:", "mailto:")):
        return False
    return (v.endswith((".json", ".yaml", ".yml"))
            or "api-docs" in v or "openapi" in v or "swagger" in v or "api-spec" in v)


def _ingest_spec(spec_url: str, r: dict[str, Any], in_scope: Callable[[str], bool],
                 out: dict[str, Any]) -> bool:
    """Parse a fetched spec response (JSON or YAML) and, if it's a real spec, populate ``out``
    with its scope-gated endpoints + params. Returns True when a spec was ingested."""
    body = r.get("body") or ""
    final = r.get("final_url") or spec_url
    # Re-gate on the POST-redirect final_url: an in-scope spec URL can 302 to a public OOS host
    # (the injected fetch's redirect guard is SSRF-only, not scope-aware). Without this, the OOS
    # spec's attacker-chosen param names (out["params"]) would leak into the prover's surface.
    if not in_scope(final):
        return False
    is_yaml = final.split("?", 1)[0].lower().endswith((".yaml", ".yml"))
    spec = parse_spec_body(body, is_yaml_hint=is_yaml)
    if not isinstance(spec, dict):
        return False
    parsed = parse_openapi(spec, final)
    if not parsed or not (parsed.get("endpoints") or parsed.get("params")):
        return False
    eps = [e for e in parsed["endpoints"] if in_scope(e)]  # never surface an OOS server[].url endpoint
    out["openapi"] = {"spec_url": spec_url, "title": parsed["title"], "version": parsed["version"],
                      "endpoint_count": len(eps), "templated_count": parsed.get("templated_count", 0)}
    out["endpoints"] = eps
    out["params"] = parsed["params"]
    tmpl = parsed.get("templated_count", 0)
    tmpl_note = f" ({tmpl} templated path(s) instantiated)" if tmpl else ""
    out["notes"].append(
        f"OpenAPI/Swagger spec at {spec_url} ({parsed['title'] or 'untitled'}): "
        f"{len(eps)} GET endpoint(s){tmpl_note} + {len(parsed['params'])} param(s) added to the surface.")
    return True


def discover_api_surface(
    target_url: str,
    *,
    fetch: Callable[[str], dict[str, Any] | None],
    in_scope: Callable[[str], bool],
    max_specs: int = 10,
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

    # --- OpenAPI / Swagger: try the well-known spec locations (JSON + YAML), first valid wins. ---
    tried = 0
    for path in _OPENAPI_PATHS:
        if tried >= max_specs or out["openapi"]:
            break
        url = origin + path
        if not in_scope(url):
            continue
        tried += 1
        r = fetch(url)
        if not r or int(r.get("status") or 0) != 200:
            continue
        _ingest_spec(url, r, in_scope, out)

    # --- Fallback: no spec at a guessed path, so scrape a Swagger-UI/Redoc page for the spec URL
    #     it embeds (the spec often lives at a non-standard path). Bounded; every scraped URL is
    #     scope-gated before fetch, and re-parsed through the same _ingest_spec path. ---
    if not out["openapi"]:
        scraped_seen: set[str] = set()
        for ui_path in _SWAGGER_UI_PATHS:
            if out["openapi"] or tried >= max_specs + len(_SWAGGER_UI_PATHS):
                break
            ui_url = origin + ui_path
            if not in_scope(ui_url):
                continue
            tried += 1  # count each fetched UI page against the combined spec-probe cap (guard above)
            r = fetch(ui_url)
            if not r or int(r.get("status") or 0) != 200:
                continue
            body = r.get("body") or ""
            for raw in _SPEC_URL_RE.findall(body)[:12]:
                if not _looks_like_spec_url(raw):
                    continue
                try:
                    spec_url = urljoin(r.get("final_url") or ui_url, raw)
                except ValueError:
                    continue
                if (not spec_url.startswith(("http://", "https://")) or spec_url in scraped_seen
                        or not in_scope(spec_url)):
                    continue
                scraped_seen.add(spec_url)
                sr = fetch(spec_url)
                if not sr or int(sr.get("status") or 0) != 200:
                    continue
                if _ingest_spec(spec_url, sr, in_scope, out):
                    out["notes"].append(f"spec URL discovered via Swagger-UI page {ui_path}.")
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
        # Re-gate on the post-redirect final_url before crediting introspection to `url`: an
        # in-scope /graphql can 302 to a public OOS host whose schema would otherwise be reported
        # as enabled on the in-scope target (a false finding on the wrong host).
        if not in_scope(r.get("final_url") or url):
            continue
        body = r.get("body") or ""
        if not _looks_like_json(body):
            continue
        try:
            data = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            continue
        info = parse_graphql_introspection(data)
        if info:
            out["graphql"] = {"url": url, **info}
            out["findings"].append(_graphql_finding(url, info))
            # The disclosed query/mutation operation names are real parameter LEADS — add them to the
            # surface so the active prover can probe them (candidate leads only; a name is CONFIRMED
            # solely if a downstream benign differential fires, never here).
            op_names = list(dict.fromkeys((info.get("query_fields") or []) + (info.get("mutation_fields") or [])))
            for name in op_names:
                if name and name not in out["params"]:
                    out["params"].append(name)
            ops_note = f", {len(op_names)} operation(s)" if op_names else ""
            out["notes"].append(
                f"GraphQL introspection ENABLED at {path} ({info['type_count']} types{ops_note}) — candidate finding added.")
            break
    return out
