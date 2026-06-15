"""Repo context for the coding agent — a lightweight map + lexical retrieval.

Phase 3. Gives the agent fast orientation in a codebase so a weaker local model
doesn't burn steps (and its small context) blindly grepping:

  - build_repo_map(): a compact, sorted listing of source files with their
    top-level symbols (classes/functions), injected into the agent's prompt.
  - search_repo(): keyword/symbol "RAG" — ranks whole files by relevance to a
    query and returns the best matching snippets. Exposed as the find_code tool.

Pure Python, offline, frozen-safe (no embeddings / no model needed).
"""
from __future__ import annotations

import re
from pathlib import Path

IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build",
    "release", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vscode",
    ".next", ".cache", "site-packages", ".gradle", "target",
}
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go",
    ".rb", ".php", ".cs", ".rs", ".c", ".h", ".cpp", ".hpp", ".swift", ".scala",
    ".sh", ".ps1", ".bat", ".sql", ".html", ".css", ".scss", ".vue", ".svelte",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".md", ".rst", ".txt",
}
_PY = [re.compile(r"^\s*(?:async\s+def|def|class)\s+([A-Za-z_]\w*)")]
_JS = [
    re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*="),
]
_SYMBOLS = {
    ".py": _PY,
    ".js": _JS, ".jsx": _JS, ".ts": _JS, ".tsx": _JS, ".mjs": _JS, ".cjs": _JS,
}
_WORD = re.compile(r"[A-Za-z0-9_]{2,}")


def _iter_text_files(root: Path, max_files: int, max_bytes: int) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if len(files) >= max_files:
            break
        if not path.is_file():
            continue
        if any(part in IGNORE_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        files.append(path)
    return files


def _symbols(path: Path, text: str, limit: int = 8) -> list[str]:
    patterns = _SYMBOLS.get(path.suffix.lower())
    if not patterns:
        return []
    names: list[str] = []
    for line in text.splitlines():
        for pattern in patterns:
            m = pattern.match(line)
            if m and m.group(1) not in names:
                names.append(m.group(1))
                if len(names) >= limit:
                    return names
    return names


def build_repo_map(root: str | Path, max_files: int = 400, max_chars: int = 3000, max_bytes: int = 100_000) -> str:
    base = Path(root)
    files = _iter_text_files(base, max_files=max_files, max_bytes=max_bytes)
    if not files:
        return ""
    lines: list[str] = []
    for path in files:
        rel = path.relative_to(base).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        syms = _symbols(path, text)
        lines.append(f"{rel} — {', '.join(syms)}" if syms else rel)

    header = "Repository map (paths relative to the workspace root):\n"
    body, shown = [], 0
    used = len(header)
    for line in lines:
        if used + len(line) + 1 > max_chars:
            break
        body.append(line)
        used += len(line) + 1
        shown += 1
    if shown < len(lines):
        body.append(f"... (+{len(lines) - shown} more files; use find_code/grep to locate specifics)")
    return header + "\n".join(body)


def search_repo(
    root: str | Path,
    query: str,
    max_results: int = 8,
    max_files: int = 2000,
    max_bytes: int = 100_000,
) -> str:
    base = Path(root)
    tokens = [t.lower() for t in _WORD.findall(query or "")]
    if not tokens:
        return "Provide search terms."
    scored: list[tuple[int, str, list[str]]] = []
    for path in _iter_text_files(base, max_files=max_files, max_bytes=max_bytes):
        rel = path.relative_to(base).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lowered = text.lower()
        path_l = rel.lower()
        symbols = " ".join(_symbols(path, text, limit=20)).lower()
        score = 0
        for token in tokens:
            score += path_l.count(token) * 3 + symbols.count(token) * 2 + lowered.count(token)
        if score <= 0:
            continue
        snippets = []
        for lineno, line in enumerate(text.splitlines(), 1):
            ll = line.lower()
            if any(token in ll for token in tokens):
                snippets.append(f"  {lineno}: {line.strip()[:160]}")
                if len(snippets) >= 3:
                    break
        scored.append((score, rel, snippets))
    if not scored:
        return "(no matches)"
    scored.sort(key=lambda item: item[0], reverse=True)
    out: list[str] = []
    for score, rel, snippets in scored[:max_results]:
        out.append(f"{rel}  (score {score})")
        out.extend(snippets)
    return "\n".join(out)
