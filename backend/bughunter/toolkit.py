"""GreyIQ Pentest Toolkit — curated reference catalog.

A structured, queryable index of penetration-testing tools derived from the
`awesome-pentest` list (https://github.com/enaqx/awesome-pentest, CC-BY 4.0) and
mapped onto GreyIQ BugHunter's vuln classes. Pure / dependency-free /
frozen-safe: it only reads a bundled JSON catalog.

This is a REFERENCE index — tool names, one-line descriptions, links, and which
vuln class each tool helps *test* — for authorized security testing, CTF, and
education. It ships no exploit code, payloads, or step-by-step attack
instructions.

The catalog file is resolved from ``<runtime>/toolkit/catalog.json`` first (so a
power user can drop in their own), then the bundled ``<seed>/toolkit/catalog.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Cache keyed by resolved catalog path -> {"_mtime": float, "data": dict}. The
# catalog is static reference data, so this is read once and reused.
_CACHE: dict[str, dict[str, Any]] = {}

_EMPTY: dict[str, Any] = {"version": 0, "source": {}, "categories": [], "tools": []}


def _catalog_file(seed_dir: Path | None, runtime_dir: Path | None) -> Path | None:
    """Runtime override (user-supplied) wins over the bundled seed copy."""
    for base in (runtime_dir, seed_dir):
        if base is None:
            continue
        path = Path(base) / "toolkit" / "catalog.json"
        try:
            if path.is_file():
                return path
        except OSError:
            continue
    return None


def load_catalog(seed_dir: Path | None, runtime_dir: Path | None = None) -> dict[str, Any]:
    """Load and cache the catalog. Returns an empty catalog (never raises) if the
    file is missing or malformed — the toolkit is best-effort, never blocking."""
    path = _catalog_file(seed_dir, runtime_dir)
    if path is None:
        return dict(_EMPTY)
    key = str(path)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return dict(_EMPTY)
    cached = _CACHE.get(key)
    if cached and cached.get("_mtime") == mtime:
        return cached["data"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return dict(_EMPTY)
    if not isinstance(data, dict):
        return dict(_EMPTY)
    data.setdefault("source", {})
    data.setdefault("categories", [])
    data.setdefault("tools", [])
    _CACHE[key] = {"_mtime": mtime, "data": data}
    return data


def catalog_payload(seed_dir: Path | None, runtime_dir: Path | None = None) -> dict[str, Any]:
    """Whole catalog for the UI to render + filter client-side (it's small)."""
    data = load_catalog(seed_dir, runtime_dir)
    tools = data.get("tools", [])
    return {
        "ok": True,
        "source": data.get("source", {}),
        "categories": data.get("categories", []),
        "tools": tools,
        "count": len(tools),
    }


def recommended_tools(
    class_ids: list[str] | None,
    seed_dir: Path | None,
    runtime_dir: Path | None = None,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Tools whose ``maps_to`` intersects the requested vuln classes, ranked by
    how many of those classes they cover (then by name), capped at ``limit``."""
    wanted = {c for c in (class_ids or []) if c}
    if not wanted:
        return []
    scored: list[tuple[int, dict[str, Any]]] = []
    for tool in load_catalog(seed_dir, runtime_dir).get("tools", []):
        overlap = set(tool.get("maps_to") or []) & wanted
        if overlap:
            scored.append((len(overlap), tool))
    # Most relevant first (largest overlap); on a tie prefer the more *specialized*
    # tool (fewer total classes) over a catch-all framework, then by name.
    scored.sort(key=lambda item: (-item[0], len(item[1].get("maps_to") or []), str(item[1].get("name", "")).lower()))
    return [tool for _, tool in scored[:limit]]
