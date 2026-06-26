"""Per-project "memory" — the structured facts GreyIQ believes about a workspace.

Stored per workspace under ``RUNTIME_DIR/project_memory/<hash>.json`` as a flat
list of categorized facts. Each fact is ``{id, category, text, source}``:

  - ``source: "auto"`` facts are derived by scanning the workspace — cheap,
    offline heuristics for the tech stack / run commands / key files, plus one
    optional brain call for the one-line purpose.
  - ``source: "user"`` facts are added by the user and survive a re-scan.

The facts power the Workbench "Project" panel (source cards) and are injected
into the agent's system prompt so it starts every task already knowing the
project — less blank-chat-box, more project-aware teammate.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import coder
import repomap

CATEGORIES: tuple[str, ...] = (
    "purpose",
    "stack",
    "run",
    "files",
    "preferences",
    "constraints",
    "tasks",
)
CATEGORY_LABELS: dict[str, str] = {
    "purpose": "Purpose",
    "stack": "Tech stack",
    "run": "Run commands",
    "files": "Key files",
    "preferences": "Preferences",
    "constraints": "Constraints",
    "tasks": "Open tasks",
}

_MAX_FACTS = 200
_MAX_TEXT = 2000

_KEY_FILE_NAMES = [
    "README.md", "README.rst", "README.txt", "package.json", "pyproject.toml",
    "requirements.txt", "setup.py", "go.mod", "Cargo.toml", "Dockerfile",
    "docker-compose.yml", "Makefile", "tsconfig.json", "CHANGELOG.md",
]

_STACK_MARKERS: list[tuple[str, str]] = [
    ("package.json", "Node.js / JavaScript"),
    ("tsconfig.json", "TypeScript"),
    ("pyproject.toml", "Python"),
    ("requirements.txt", "Python"),
    ("setup.py", "Python"),
    ("go.mod", "Go"),
    ("Cargo.toml", "Rust"),
    ("pom.xml", "Java (Maven)"),
    ("build.gradle", "Java/Kotlin (Gradle)"),
    ("Gemfile", "Ruby"),
    ("composer.json", "PHP"),
    ("Dockerfile", "Docker"),
    ("docker-compose.yml", "Docker Compose"),
]


class ProjectMemoryError(Exception):
    """A workspace path was missing or invalid."""


def _resolve(workspace: str) -> Path:
    raw = str(workspace or "").strip()
    if not raw:
        raise ProjectMemoryError("No workspace folder was provided.")
    try:
        root = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProjectMemoryError(f"Invalid workspace path: {raw}") from exc
    if not root.is_dir():
        raise ProjectMemoryError(f"Workspace is not a folder: {workspace}")
    return root


def _path(runtime_dir: str | Path, workspace: str) -> Path:
    raw = Path(str(workspace or "")).expanduser()
    try:
        key = str(raw.resolve())
    except (OSError, RuntimeError, ValueError):
        key = str(raw)
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()
    return Path(runtime_dir) / "project_memory" / f"{digest}.json"


def _fact(category: str, text: str, source: str) -> dict[str, Any]:
    return {"id": uuid4().hex, "category": category, "text": text, "source": source}


def sanitize_facts(raw: Any) -> list[dict[str, Any]]:
    """Coerce an arbitrary facts list to a clean, capped, valid one."""
    facts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in list(raw or [])[: _MAX_FACTS * 2]:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "").strip().lower()
        text = str(item.get("text") or "").strip()[:_MAX_TEXT]
        if category not in CATEGORIES or not text:
            continue
        source = "auto" if str(item.get("source")) == "auto" else "user"
        fid = str(item.get("id") or "").strip() or uuid4().hex
        if fid in seen:
            fid = uuid4().hex
        seen.add(fid)
        facts.append({"id": fid, "category": category, "text": text, "source": source})
        if len(facts) >= _MAX_FACTS:
            break
    return facts


def load(runtime_dir: str | Path, workspace: str) -> dict[str, Any]:
    path = _path(runtime_dir, workspace)
    if not path.is_file():
        return {"facts": [], "updated_at": None}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"facts": [], "updated_at": None}
    return {"facts": sanitize_facts(data.get("facts")), "updated_at": data.get("updated_at")}


def save(runtime_dir: str | Path, workspace: str, facts: Any) -> dict[str, Any]:
    clean = sanitize_facts(facts)
    updated_at = datetime.now(UTC).isoformat()
    path = _path(runtime_dir, workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"workspace": str(workspace), "updated_at": updated_at, "facts": clean}
    # Atomic write: a crash or concurrent writer must never leave a half-written
    # file that `load` then discards (losing every saved fact). Write a sibling temp
    # file and os.replace it into place (atomic on the same filesystem).
    tmp = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
    try:
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return {"facts": clean, "updated_at": updated_at}


def _detect_stack(root: Path) -> list[str]:
    found: list[str] = []
    for fname, label in _STACK_MARKERS:
        if (root / fname).exists() and label not in found:
            found.append(label)
    return found


def _detect_run(root: Path) -> list[str]:
    cmds: list[str] = []
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            scripts = data.get("scripts") if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            scripts = None
        if isinstance(scripts, dict) and scripts:
            cmds.append("npm install")
            for name in list(scripts.keys())[:6]:
                cmds.append(f"npm {name}" if name in ("start", "test") else f"npm run {name}")
    if (root / "requirements.txt").is_file():
        cmds.append("pip install -r requirements.txt")
    elif (root / "pyproject.toml").is_file():
        cmds.append("pip install -e .")
    if (root / "manage.py").is_file():
        cmds.append("python manage.py runserver")
    if (root / "Makefile").is_file():
        cmds.append("make")
    if (root / "Cargo.toml").is_file():
        cmds.append("cargo run")
    if (root / "go.mod").is_file():
        cmds.append("go run .")
    return cmds[:8]


def _key_files(root: Path) -> list[str]:
    return [name for name in _KEY_FILE_NAMES if (root / name).is_file()][:12]


def _derive_purpose(root: Path, cfg: dict[str, Any]) -> str:
    """One-line purpose via the configured brain. Returns "" if no brain or on any
    failure (so a scan still produces the heuristic facts offline)."""
    readme = ""
    for name in ("README.md", "README.rst", "README.txt"):
        path = root / name
        if path.is_file():
            try:
                readme = path.read_text(encoding="utf-8", errors="replace")[:3000]
            except OSError:
                readme = ""
            break
    repo_map = ""
    try:
        repo_map = (repomap.build_repo_map(root) or "")[:2000]
    except Exception:  # noqa: BLE001 - best-effort
        repo_map = ""
    if not readme and not repo_map:
        return ""
    prompt = (
        "In ONE or TWO sentences, say what this software project is and does. "
        "Reply with only the sentence(s) — no preamble, no markdown.\n\n"
        + (f"README:\n{readme}\n\n" if readme else "")
        + (f"FILE MAP:\n{repo_map}\n" if repo_map else "")
    )
    try:
        out = coder.generate([{"role": "user", "content": prompt}], cfg)
    except Exception:  # noqa: BLE001 - brain off / unreachable
        return ""
    text = re.split(r"\n\s*\n", str(out.get("text") or "").strip())[0].strip()
    return text[:_MAX_TEXT]


def scan(runtime_dir: str | Path, workspace: str, cfg: dict[str, Any] | None) -> dict[str, Any]:
    """(Re)derive the 'auto' facts for a workspace, keeping any user facts."""
    root = _resolve(workspace)
    auto: list[dict[str, Any]] = []
    purpose = _derive_purpose(root, cfg or {})
    if purpose:
        auto.append(_fact("purpose", purpose, "auto"))
    auto.extend(_fact("stack", label, "auto") for label in _detect_stack(root))
    auto.extend(_fact("run", cmd, "auto") for cmd in _detect_run(root))
    auto.extend(_fact("files", name, "auto") for name in _key_files(root))

    user_facts = [f for f in load(runtime_dir, workspace)["facts"] if f.get("source") == "user"]
    result = save(runtime_dir, workspace, auto + user_facts)
    result["scanned"] = len(auto)
    result["used_brain"] = bool(purpose)
    return result


def prompt_block(facts: list[dict[str, Any]]) -> str:
    """Compact rendering for injection into the agent's system prompt."""
    if not facts:
        return ""
    by_cat: dict[str, list[str]] = {}
    for fact in facts:
        by_cat.setdefault(str(fact.get("category")), []).append(str(fact.get("text") or ""))
    lines = ["PROJECT MEMORY (what you already know about this project):"]
    for cat in CATEGORIES:
        items = [t for t in by_cat.get(cat, []) if t]
        if not items:
            continue
        label = CATEGORY_LABELS.get(cat, cat)
        if cat == "purpose":
            lines.append(f"- {label}: {items[0]}")
        else:
            lines.append(f"- {label}: " + "; ".join(items[:10]))
    return "\n".join(lines) if len(lines) > 1 else ""
