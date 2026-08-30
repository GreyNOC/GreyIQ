"""Deterministic, no-LLM offline code provider — scaffolds + mechanical edits, verify-gated.

The coding analog of ``bughunter/offline_hunt.py``: a substring-rule planner over the repo that emits
only a small CLOSED SET of edit operations (never free-form text a tiny model would botch). The agent
applies each op through its existing ``ToolBox`` (so every write is snapshotted + undoable) and gates
the result with ``verify``. Honest ceiling: **scaffolds and mechanical edits** — a framework-aware
test stub, a route/Dockerfile/CI file, or a bounded authorized HTTP traffic client from a template.
Anything it can't confidently map returns
``needs_brain=True``: the offline coder never guesses business logic.

Retrieval (strategy move 3): the plan is made **repo-specific** by reading the repo surface — the
dependency manifests decide pytest-vs-unittest and gate stack-specific templates (a Flask route is
only offered in a Flask repo), and ``repomap.search_repo`` locates the target symbol so a test stub's
TODO points at the real file. Templates come from ``seed/snippets/`` (``{{slot}}`` markers filled from
the request + retrieval); a bundled fallback is used if the seed dir is unavailable.

See ``docs/offline-coder-strategy.md``. Phase-1 skeleton (moves 1-3); the verify->repair loop (move 4)
and ``edit_trace.py`` distillation (move 5) build on this same closed-set-of-ops contract.

Pure / dependency-free: stdlib + intra-repo imports only (repomap/skills are optional, best-effort).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"

# Bundled fallbacks — used ONLY when seed/snippets/ is unavailable, so the offline coder still works
# in a stripped environment. The seed templates are the source of truth.
_FALLBACK_UNITTEST = (
    '"""Auto-scaffolded unittest test for {{symbol}}. Fill in real assertions."""\n'
    "from __future__ import annotations\n\nimport unittest\n\n\n"
    "class Test{{cls}}(unittest.TestCase):\n"
    "    def test_{{symbol}}_placeholder(self) -> None:\n"
    "        # TODO: import and exercise {{symbol}} ({{location}}), then assert its real behavior.\n"
    "        self.assertTrue(True)\n\n\n"
    'if __name__ == "__main__":\n    unittest.main()\n'
)


def _class_name(symbol: str) -> str:
    parts = [p for p in re.split(r"[_\W]+", str(symbol or "").strip()) if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) or "Thing"


def _safe_rel(candidate: str) -> str:
    """Normalize a user-named path and reject anything that escapes the workspace (ToolBox._resolve
    re-checks; this is a friendly early gate so a bad path is a clean 'skip', not a raise)."""
    rel = str(candidate or "").strip().strip("`\"'")
    if not rel or rel.startswith(("/", "\\")) or ":" in rel[:3]:
        return ""
    if ".." in Path(rel.replace("\\", "/")).parts:
        return ""
    return rel.replace("\\", "/")


def _fill(template: str, slots: dict[str, str]) -> str:
    """Substitute ``{{slot}}`` markers from ``slots`` (an unknown marker is left as-is)."""
    return re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: str(slots.get(m.group(1), m.group(0))), template)


def _load_snippet(seed_dir: str | Path | None, name: str) -> str | None:
    # Production passes the extracted seed directory explicitly. Falling back to the source-tree
    # seed keeps deterministic scaffolds available to direct/offline callers without copying large
    # templates into this module. Frozen/stripped builds simply return None as before.
    candidates = [Path(seed_dir)] if seed_dir else []
    bundled = Path(__file__).resolve().parent / "seed"
    if bundled not in candidates:
        candidates.append(bundled)
    for base in candidates:
        try:
            p = base / "snippets" / name
            if p.is_file():
                return p.read_text(encoding="utf-8")
        except OSError:
            continue
    return None


# --- Retrieval over the repo surface (what makes an edit repo-specific) ---

_MANIFESTS = ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py", "setup.cfg",
              "Pipfile", "package.json")


def _read_manifests(root: Path) -> str:
    blobs: list[str] = []
    for name in _MANIFESTS:
        p = root / name
        if p.is_file():
            try:
                blobs.append(p.read_text(encoding="utf-8", errors="replace").lower())
            except OSError:
                continue
    return "\n".join(blobs)


def _uses_pytest(root: Path, manifests: str) -> bool:
    return ("pytest" in manifests or (root / "conftest.py").is_file()
            or (root / "pytest.ini").is_file() or (root / "tox.ini").is_file())


def _locate_symbol(root: Path, symbol: str) -> str:
    """Best-effort: use repomap.search_repo to note which file defines ``symbol``, so a scaffold's
    TODO points at the real code. Returns '' if repomap is unavailable or nothing matches."""
    try:
        import repomap
        out = repomap.search_repo(root, f"def {symbol} class {symbol} {symbol}", max_results=1)
    except Exception:  # noqa: BLE001 - retrieval is best-effort, never blocks a plan
        return ""
    m = re.search(r"([\w./\\-]+\.(?:py|js|ts|go|rs)):", str(out or ""))
    return m.group(1) if m else ""


def _guess_module(root: Path) -> str:
    """A best-guess start module for a Dockerfile CMD: the first top-level package (dir with
    __init__.py), else the repo folder name, else 'app'."""
    try:
        for child in sorted(root.iterdir()):
            if child.is_dir() and (child / "__init__.py").is_file():
                return child.name
    except OSError:
        pass
    return re.sub(r"\W+", "_", root.name).strip("_") or "app"


def _skill_hint(message: str, seed_dir: str | Path | None, runtime_dir: str | Path | None,
                root: Path) -> str:
    """The closest matching playbook name (via the SAME deterministic skills matcher the agent uses),
    to make the 'needs a brain' message actionable. Best-effort."""
    if not seed_dir or not runtime_dir:
        return ""
    try:
        import skills as skills_lib
        available = skills_lib.load_skills(Path(runtime_dir), Path(seed_dir), root)
        chosen = skills_lib.select_skills(message, available, limit=1)
        return chosen[0].name if chosen else ""
    except Exception:  # noqa: BLE001
        return ""


def _needs_brain(summary: str = "", skill: str = "") -> dict[str, Any]:
    base = summary or (
        "The offline coder handles scaffolds and mechanical edits (e.g. \"add a test for <function>\", "
        "\"add a flask route <path>\", \"add a dockerfile\", \"build an HTTP traffic client\", "
        "\"create a file <path>\"). This task needs "
        "a configured brain — set up a Local model (Ollama) or Claude in Settings, then re-run."
    )
    if skill:
        base += f" (The `{skill}` playbook covers this once a brain is enabled.)"
    return {"ops": [], "needs_brain": True, "summary": base}


def plan_edits(message: str, root: str | Path, *, seed_dir: str | Path | None = None,
               runtime_dir: str | Path | None = None) -> dict[str, Any]:
    """Map a request to a CLOSED SET of deterministic edit ops, made repo-specific by retrieval.

    Returns ``{"ops": [{"kind","path","content"}], "needs_brain": bool, "summary": str}``. Empty ops +
    ``needs_brain=True`` means the request isn't a templated scaffold — defer to a real brain."""
    text = str(message or "").strip()
    if not text:
        return _needs_brain()
    root = Path(root)
    low = text.lower()
    manifests = _read_manifests(root)

    # Intent: "add/write a [unit] test [stub] for <symbol>" -> a framework-aware test scaffold.
    m = re.search(
        r"\b(?:add|create|write|generate|scaffold|make)\s+(?:a\s+|an\s+)?(?:unit\s+)?test(?:\s+stub)?\s+for\s+"
        r"(?:the\s+)?(?:function|method|class\s+)?[`'\"]?(" + _IDENT + r")",
        low,
    )
    if m:
        symbol = m.group(1)
        use_pytest = _uses_pytest(root, manifests)
        location = _locate_symbol(root, symbol) or "the target module"
        slots = {"symbol": symbol, "cls": _class_name(symbol), "location": location}
        tmpl = (_load_snippet(seed_dir, "pytest_case.py.tmpl") if use_pytest
                else _load_snippet(seed_dir, "unittest_case.py.tmpl")) or _FALLBACK_UNITTEST
        framework = "pytest" if use_pytest else "unittest"
        rel = f"test_{symbol}.py"
        return {
            "ops": [{"kind": "new_file", "path": rel, "content": _fill(tmpl, slots)}],
            "needs_brain": False,
            "summary": f"Scaffolded a {framework} stub `{rel}` for `{symbol}` "
                       f"({'found in ' + location if location != 'the target module' else 'fill in the target'}).",
        }

    # Intent: "add a route/endpoint <path>" -> a Flask route, but ONLY in a Flask repo (retrieval-gated).
    m = re.search(r"\b(?:add|create|make|new)\s+(?:a\s+|an\s+)?(?:route|endpoint)\s+([`'\"]?/\S*)", low)
    if m:
        path = m.group(1).strip("`'\"")
        if "flask" not in manifests:
            return _needs_brain(
                "That looks like a web route, but this repo doesn't declare Flask (the only web "
                "framework the offline coder templates today). Configure a brain to add it for your stack.",
                skill=_skill_hint(text, seed_dir, runtime_dir, root))
        name = re.sub(r"\W+", "_", path.strip("/")).strip("_") or "index"
        slots = {"path": path, "name": name}
        tmpl = _load_snippet(seed_dir, "flask_route.py.tmpl")
        if tmpl:
            return {"ops": [{"kind": "new_file", "path": f"{name}_route.py", "content": _fill(tmpl, slots)}],
                    "needs_brain": False,
                    "summary": f"Scaffolded a Flask route `{path}` in `{name}_route.py` — register {name}_bp on your app."}

    # Intent: "add a dockerfile" -> a Python Dockerfile from the template.
    if re.search(r"\b(?:add|create|make|write|generate)\b[^.?!]{0,30}\bdocker\s*file\b", low):
        tmpl = _load_snippet(seed_dir, "dockerfile.tmpl")
        if tmpl:
            return {"ops": [{"kind": "new_file", "path": "Dockerfile",
                             "content": _fill(tmpl, {"module": _guess_module(root)})}],
                    "needs_brain": False,
                    "summary": "Scaffolded a Dockerfile (adjust the base image + CMD for your app)."}

    # Intent: "add a CI workflow / github action" -> a GitHub Actions workflow.
    if re.search(r"\b(?:add|create|make|set\s*up)\b[^.?!]{0,40}\b(?:ci\s+(?:workflow|pipeline)|github\s+action|workflow)\b", low):
        tmpl = _load_snippet(seed_dir, "github_workflow.yml.tmpl")
        if tmpl:
            test_cmd = "python -m pytest" if _uses_pytest(root, manifests) else "python -m unittest discover"
            return {"ops": [{"kind": "new_file", "path": ".github/workflows/ci.yml",
                             "content": _fill(tmpl, {"test_command": test_cmd})}],
                    "needs_brain": False,
                    "summary": "Scaffolded a GitHub Actions CI workflow at .github/workflows/ci.yml."}

    # Intent: an HTTP/C2 *traffic simulator* -> a bounded, non-tasking client. This deliberately
    # stops at curl-equivalent transport: it can send finite HTTP requests with an attributable
    # User-Agent, a private CA bundle, and an optional mTLS identity, but it never polls for or
    # executes commands, persists, evades, or disables certificate verification.
    traffic_client = bool(
        re.search(
            r"\b(?:create|add|write|generate|scaffold|make|build)\b[^.?!]{0,100}"
            r"\b(?:c2|command(?:\s+and|\s*&\s*)\s+control|https?|network|traffic)\b"
            r"[^.?!]{0,100}\b(?:client|script|sender|request|traffic|simulat\w*)\b",
            low,
        )
        or re.search(
            r"\b(?:create|add|write|generate|scaffold|make|build)\b[^.?!]{0,100}"
            r"\b(?:client|script|sender|simulat\w*)\b[^.?!]{0,100}"
            r"\b(?:send|generate)\s+(?:https?\s+|network\s+)?traffic\b",
            low,
        )
    )
    if traffic_client:
        named = re.search(
            r"\b(?:as|called|named)\s+[`'\"]?([A-Za-z0-9_.\-/]+\.py)\b",
            text,
            re.IGNORECASE,
        )
        rel = _safe_rel(named.group(1)) if named else "authorized_http_client.py"
        tmpl = _load_snippet(seed_dir, "authorized_http_client.py.tmpl")
        if rel and tmpl:
            return {
                "ops": [{"kind": "new_file", "path": rel, "content": tmpl}],
                "needs_brain": False,
                "summary": (
                    f"Scaffolded `{rel}`, a bounded authorized HTTP traffic client with explicit "
                    "User-Agent, CA-bundle, optional mTLS, timeout, and finite-count options. "
                    "It treats responses as data and never executes remote commands."
                ),
            }

    # Intent: "create/add/make a [new] file <path> [with <text>]" -> a new file (won't overwrite).
    m = re.search(r"\b(?:create|add|make|new)\s+(?:a\s+|an\s+)?(?:new\s+)?file\s+(\S+)", text, re.IGNORECASE)
    if m:
        rel = _safe_rel(m.group(1))
        if rel:
            body = re.search(r"\bwith\s+(.+)$", text, re.IGNORECASE | re.DOTALL)
            content = (body.group(1).strip() + "\n") if body else ""
            return {"ops": [{"kind": "new_file", "path": rel, "content": content}],
                    "needs_brain": False, "summary": f"Created `{rel}`."}

    return _needs_brain(skill=_skill_hint(text, seed_dir, runtime_dir, root))
