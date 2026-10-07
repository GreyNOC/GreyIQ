"""Bounded, in-memory MCP advice for an already authorized hunt.

The built-in tool sees only categorical features and list indexes. It cannot send
target traffic, read files, select a new target, or turn a lead into evidence.
The caller retains responsibility for authorization and all request controls.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from bughunter.prover_classes import PROVER_CLASSES


_TOOL_NAME = "review_hunt_snapshot"
_MAX_ENDPOINTS = 24
_MAX_FINDINGS = 40
_MAX_WEB_PRIORITIES = 12
_MAX_FINDING_PRIORITIES = 10
_MAX_SNAPSHOT_BYTES = 8192
_MAX_RESULT_BYTES = 8192
_TIMEOUT_SECONDS = 5.0
_SLOTS = threading.BoundedSemaphore(4)

_WEB_CLASSES: dict[str, tuple[str, ...]] = {
    "graphql": ("graphql",),
    "admin": ("debug", "sensitive"),
    "download": ("path-traversal",),
    "redirect": ("redirect",),
    "search": ("xss", "sqli"),
    "api": ("sqli", "nosqli"),
    "websocket": ("websocket",),
    "upload": ("path-traversal", "xss"),
}
_SOURCE_WEIGHTS = {"secret": 4, "auth": 3, "injection": 3, "dependency": 2, "other": 1}
_SEVERITY_WEIGHTS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _failure(reason: str) -> dict[str, Any]:
    return {"ok": False, "source": "builtin-mcp", "tool": _TOOL_NAME,
            "advisory": True, "reason": reason}


def _endpoint_features(url: Any) -> list[str]:
    """Reduce an endpoint to a fixed vocabulary; no URL or path crosses MCP."""
    if not isinstance(url, str) or len(url) > 2048:
        return []
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return []
        path = parsed.path.lower()[:512]
    except ValueError:
        return []
    features: list[str] = []
    patterns = (
        ("graphql", r"graphql"),
        ("admin", r"(?:^|/)(?:admin|debug|actuator|manage)(?:/|$)"),
        ("download", r"download|export|attachment|/files?(?:/|$)"),
        ("redirect", r"redirect|callback|return"),
        ("search", r"search|query|lookup"),
        ("api", r"(?:^|/)(?:api|v[0-9]+)(?:/|$)"),
        ("websocket", r"websocket|(?:^|/)ws(?:/|$)"),
        ("upload", r"upload|import"),
    )
    for feature, pattern in patterns:
        if re.search(pattern, path):
            features.append(feature)
    return features


def _param_features(raw: Any) -> list[str]:
    if not isinstance(raw, (list, tuple)):
        return []
    names = [str(value).lower()[:64] for value in raw[:40]
             if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value)]
    features: list[str] = []
    if any(re.search(r"(?:redirect|return|callback|next|continue|url)$", name) for name in names):
        features.append("redirect")
    if any(re.search(r"(?:file|path|template|filename|download)$", name) for name in names):
        features.append("download")
    if any(re.search(r"^(?:q|query|search|term|keyword)$", name) for name in names):
        features.append("search")
    return features


def _finding_category(finding: dict[str, Any]) -> str:
    words = " ".join(str(finding.get(key) or "")[:100].lower()
                     for key in ("rule_id", "class_id", "_active_class_hint"))
    if any(word in words for word in ("secret", "credential", "token", "api-key")):
        return "secret"
    if any(word in words for word in ("auth", "idor", "access-control", "permission")):
        return "auth"
    if any(word in words for word in ("inject", "sqli", "xss", "rce", "ssrf", "traversal")):
        return "injection"
    if any(word in words for word in ("depend", "package", "cve", "vulnerable-version")):
        return "dependency"
    return "other"


def _snapshot(kind: str, surface: Any, findings: Any) -> dict[str, Any]:
    surface = surface if isinstance(surface, dict) else {}
    endpoints = surface.get("endpoints")
    endpoints = endpoints if isinstance(endpoints, (list, tuple)) else []
    rows = findings if isinstance(findings, (list, tuple)) else []
    return {
        "kind": kind,
        "endpoints": [
            {"index": index, "features": _endpoint_features(endpoint)}
            for index, endpoint in enumerate(endpoints[:_MAX_ENDPOINTS])
        ] if kind == "url" else [],
        "global_features": _param_features(surface.get("params")) if kind == "url" else [],
        "findings": [
            {"index": index,
             "severity": str(finding.get("severity") or "").lower()
             if str(finding.get("severity") or "").lower() in _SEVERITY_WEIGHTS else "info",
             "category": _finding_category(finding)}
            for index, finding in enumerate(rows[:_MAX_FINDINGS]) if isinstance(finding, dict)
        ],
    }


def _review_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The MCP server's deterministic, pure tool implementation."""
    endpoints = snapshot.get("endpoints") or []
    findings = snapshot.get("findings") or []
    global_features = snapshot.get("global_features") or []
    web_priorities: list[dict[str, Any]] = []
    for endpoint in endpoints:
        features = list(dict.fromkeys([*(endpoint.get("features") or []), *global_features]))
        classes = list(dict.fromkeys(cls for feature in features
                                     for cls in _WEB_CLASSES.get(feature, ())))
        if classes:
            web_priorities.append({
                "endpoint_index": endpoint["index"],
                "classes": classes[:6],
                "reason": "surface feature match",
            })
        if len(web_priorities) >= _MAX_WEB_PRIORITIES:
            break
    ordered = sorted(findings, key=lambda row: (
        -_SEVERITY_WEIGHTS.get(row.get("severity"), 0),
        -_SOURCE_WEIGHTS.get(row.get("category"), 0),
        row["index"],
    ))
    finding_priorities = [
        {"finding_index": row["index"], "reason": "scanner lead review priority"}
        for row in ordered[:_MAX_FINDING_PRIORITIES]
    ]
    return {
        "kind": snapshot["kind"],
        "web_priorities": web_priorities,
        "finding_priorities": finding_priorities,
        "reviewed": {"endpoints": len(endpoints), "findings": len(findings)},
        "note": "Advisory ordering only; no target request or proof was produced.",
    }


async def _call_tool(snapshot: dict[str, Any]) -> dict[str, Any]:
    from mcp.server.fastmcp import FastMCP
    from mcp.shared.memory import create_connected_server_and_client_session

    server = FastMCP("GreyIQ built-in hunt review", log_level="ERROR")

    @server.tool(name=_TOOL_NAME)
    def review_hunt_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
        return _review_snapshot(snapshot)

    async with create_connected_server_and_client_session(
        server, read_timeout_seconds=timedelta(seconds=_TIMEOUT_SECONDS),
    ) as session:
        result = await session.call_tool(_TOOL_NAME, arguments={"snapshot": snapshot})
    if result.isError:
        raise RuntimeError("Built-in MCP tool returned an error")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict) and isinstance(structured.get("result"), dict):
        structured = structured["result"]
    if not isinstance(structured, dict):
        raise ValueError("Built-in MCP tool returned no structured result")
    return structured


def _validated(raw: Any, snapshot: dict[str, Any]) -> dict[str, Any] | None:
    """Allow only advisory indexes and prover class names from the MCP result."""
    if not isinstance(raw, dict) or raw.get("kind") != snapshot["kind"]:
        return None
    try:
        if len(json.dumps(raw, ensure_ascii=True, allow_nan=False).encode("utf-8")) > _MAX_RESULT_BYTES:
            return None
    except (TypeError, ValueError, RecursionError):
        return None
    endpoint_indexes = {row["index"] for row in snapshot["endpoints"]}
    finding_indexes = {row["index"] for row in snapshot["findings"]}
    web: list[dict[str, Any]] = []
    for row in raw.get("web_priorities") or []:
        if not isinstance(row, dict) or type(row.get("endpoint_index")) is not int:
            return None
        index = row["endpoint_index"]
        classes = row.get("classes")
        if (index not in endpoint_indexes or not isinstance(classes, list)
                or not classes or len(classes) > 6
                or any(not isinstance(cls, str) or cls not in PROVER_CLASSES for cls in classes)):
            return None
        web.append({"endpoint_index": index, "classes": list(dict.fromkeys(classes)),
                    "reason": "surface feature match"})
        if len(web) > _MAX_WEB_PRIORITIES:
            return None
    priority: list[dict[str, Any]] = []
    for row in raw.get("finding_priorities") or []:
        if not isinstance(row, dict) or type(row.get("finding_index")) is not int:
            return None
        index = row["finding_index"]
        if index not in finding_indexes:
            return None
        priority.append({"finding_index": index, "reason": "scanner lead review priority"})
        if len(priority) > _MAX_FINDING_PRIORITIES:
            return None
    return {
        "ok": True, "source": "builtin-mcp", "tool": _TOOL_NAME,
        "advisory": True, "kind": snapshot["kind"],
        "web_priorities": web,
        "finding_priorities": priority,
        "reviewed": {"endpoints": len(snapshot["endpoints"]),
                     "findings": len(snapshot["findings"])},
        "note": "Advisory ordering only; no target request or proof was produced.",
    }


def run_builtin_hunt_review(
    kind: str, target: str, scope: str, surface: dict[str, Any] | None,
    findings: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Make one automatic in-memory MCP call over bounded metadata.

    Call only after the hunt's authorization and scope preflight. This function
    performs no target I/O and emits no finding, confirmation, or severity.
    """
    if not isinstance(kind, str) or kind not in {"url", "path", "git"} or not isinstance(target, str) or not target.strip():
        return _failure("A supported hunt target is required.")
    if kind in {"url", "git"} and (not isinstance(scope, str) or not scope.strip()):
        return _failure("Explicit scope is required for this target kind.")
    snapshot = _snapshot(kind, surface, findings)
    try:
        if len(json.dumps(snapshot, ensure_ascii=True, allow_nan=False).encode("utf-8")) > _MAX_SNAPSHOT_BYTES:
            return _failure("The bounded hunt snapshot is too large.")
    except (TypeError, ValueError, RecursionError):
        return _failure("The hunt snapshot could not be encoded.")
    # The synchronous hunt engine runs this from a worker thread. If a caller
    # accidentally invokes it inside an event loop, avoid constructing an
    # unawaited coroutine or trying to nest asyncio.run().
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return _failure("Built-in MCP review requires a synchronous hunt worker.")
    if not _SLOTS.acquire(blocking=False):
        return _failure("Built-in MCP review is busy.")
    try:
        raw = asyncio.run(asyncio.wait_for(_call_tool(snapshot), timeout=_TIMEOUT_SECONDS))
        return _validated(raw, snapshot) or _failure("Built-in MCP review returned invalid advice.")
    except Exception:  # noqa: BLE001 - optional advice must never break a hunt
        return _failure("Built-in MCP review is unavailable.")
    finally:
        _SLOTS.release()
