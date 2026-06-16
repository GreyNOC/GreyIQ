"""Safe, read-only workspace introspection for the GreyIQ Workbench.

These helpers power the file explorer and read-only file preview that appear
when Agent mode is on. They are deliberately read-only and strictly confined to
the workspace folder the user picked: every path is resolved and checked to live
inside that root before any disk access, so the frontend can never read outside
the chosen folder. The functions never raise to the caller — they return
structured ``{"ok": False, "error": ...}`` payloads so the UI can show a useful
message instead of a 500.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

# Folders that are large, generated, or irrelevant to a code workspace view.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        "release",
        ".next",
        ".cache",
    }
)

# Only these extensions are previewed as text. Anything else returns a friendly
# "can't preview" message instead of raw bytes.
TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".md",
        ".markdown", ".txt", ".html", ".htm", ".css", ".scss", ".sass", ".less",
        ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties",
        ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".sql", ".xml", ".svg",
        ".csv", ".tsv", ".rs", ".go", ".java", ".kt", ".kts", ".c", ".h",
        ".cpp", ".hpp", ".cc", ".cxx", ".cs", ".rb", ".php", ".swift", ".m",
        ".r", ".lua", ".pl", ".vue", ".svelte", ".gradle", ".tf", ".graphql",
        ".gql", ".proto", ".rst", ".log", ".nsh", ".spec",
    }
)

# Files with no (or a leading-dot) extension that we still treat as text.
TEXT_FILENAMES: frozenset[str] = frozenset(
    {
        "Dockerfile", "Makefile", "LICENSE", "README", "Procfile", "CHANGELOG",
        ".gitignore", ".dockerignore", ".editorconfig", ".env", ".gitattributes",
        ".npmrc", ".prettierrc", ".eslintrc", ".babelrc",
    }
)

DEFAULT_MAX_BYTES = 200_000


class WorkspaceError(Exception):
    """A workspace path was missing, invalid, or escaped the root."""


def resolve_workspace(root: str) -> Path:
    """Resolve and validate the workspace root, raising WorkspaceError if it is
    not an existing folder."""
    raw = str(root or "").strip()
    if not raw:
        raise WorkspaceError("No workspace folder was provided.")
    try:
        resolved = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise WorkspaceError(f"Invalid workspace path: {raw}") from exc
    if not resolved.exists() or not resolved.is_dir():
        raise WorkspaceError(f"Workspace is not a folder: {raw}")
    return resolved


def resolve_inside(root: Path, rel_path: str) -> Path:
    """Resolve ``rel_path`` against ``root`` and guarantee the result stays inside
    the workspace. Raises WorkspaceError on any traversal attempt."""
    base = root.resolve()
    candidate = (base / str(rel_path or ".")).resolve()
    if candidate != base and base not in candidate.parents:
        raise WorkspaceError(f"Path '{rel_path}' is outside the workspace.")
    return candidate


def is_text_file(path: Path) -> bool:
    """True if the file should be previewed as UTF-8 text."""
    if path.name in TEXT_FILENAMES:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def _safe_child(base: Path, child: Path) -> bool:
    """True only if ``child`` is safe to enumerate/read: not a symlink (which
    would let the walk escape the root or loop) and whose real path is still
    inside ``base`` (also rejects Windows junctions pointing outside)."""
    try:
        if child.is_symlink():
            return False
        resolved = child.resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved == base or base in resolved.parents


def list_tree(root: str, max_entries: int = 1000) -> dict[str, Any]:
    """List the workspace as a flat, depth-first (dirs-before-files) entry list.

    Each entry has ``path`` (posix, relative to root), ``name``, ``type``
    ("dir"/"file"), and ``size`` for files. The frontend renders the tree by
    indenting on the number of path segments.
    """
    try:
        base = resolve_workspace(root)
    except WorkspaceError as exc:
        return {"ok": False, "error": str(exc), "root": str(root), "entries": [], "truncated": False}

    cap = max(1, int(max_entries or 1000))
    entries: list[dict[str, Any]] = []
    truncated = False

    def walk(directory: Path) -> None:
        nonlocal truncated
        if truncated:
            return
        try:
            children = sorted(directory.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except OSError:
            return
        for child in children:
            if truncated:
                return
            try:
                if not _safe_child(base, child):
                    continue
                is_dir = child.is_dir()
            except OSError:
                continue
            if is_dir and child.name in SKIP_DIRS:
                continue
            if len(entries) >= cap:
                truncated = True
                return
            rel = child.relative_to(base).as_posix()
            if is_dir:
                entries.append({"path": rel, "name": child.name, "type": "dir"})
                walk(child)
            else:
                try:
                    size = child.stat().st_size
                except OSError:
                    size = 0
                entries.append({"path": rel, "name": child.name, "type": "file", "size": size})

    walk(base)
    return {"ok": True, "root": str(base), "entries": entries, "truncated": truncated}


def read_file(root: str, path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """Read a single text file inside the workspace for preview."""
    try:
        base = resolve_workspace(root)
        target = resolve_inside(base, path)
    except WorkspaceError as exc:
        return {"ok": False, "error": str(exc), "path": str(path)}

    if not target.exists():
        return {"ok": False, "error": f"No such file: {path}", "path": str(path)}
    if target.is_dir():
        return {"ok": False, "error": f"That path is a folder, not a file: {path}", "path": str(path)}
    rel = target.relative_to(base).as_posix()
    if not is_text_file(target):
        return {"ok": False, "error": "This file type can't be previewed as text.", "path": rel, "binary": True}

    try:
        size = target.stat().st_size
    except OSError:
        size = 0
    cap = max(1, int(max_bytes or DEFAULT_MAX_BYTES))
    truncated = size > cap
    try:
        with target.open("rb") as handle:
            data = handle.read(cap) if truncated else handle.read()
    except OSError as exc:
        return {"ok": False, "error": f"Could not read file: {exc}", "path": rel}

    result: dict[str, Any] = {
        "ok": True,
        "path": rel,
        "content": data.decode("utf-8", errors="replace"),
        "size": size,
    }
    if truncated:
        result["truncated"] = True
    return result
