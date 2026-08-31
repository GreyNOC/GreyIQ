"""Deterministic, no-LLM offline code provider — a RECIPE REGISTRY over the repo surface.

The coding analog of ``bughunter/offline_hunt.py``: a planner that emits only a small CLOSED SET of
edit operations (never free-form text a tiny model would botch). The agent applies each op through
its existing ``ToolBox`` (so every write is snapshotted + undoable) and gates the result with
``verify``. Honest ceiling: **scaffolds and mechanical edits** — a framework-aware test stub, a
router/Dockerfile/CI/unit file from a template, a mechanical import, or a bounded authorized HTTP
traffic client. Anything it can't confidently map returns ``needs_brain=True``: the offline coder
never guesses business logic.

WHY A REGISTRY. The first cut was a five-branch regex if-chain, each branch carrying its own ad-hoc
gating. Coverage therefore grew linearly with reviewer effort, and the one thing the offline coder
must do — cover MORE templated tasks — was the thing the shape made expensive. ``_RECIPES`` turns a
capability into DATA: one row plus one ``seed/snippets/*.tmpl`` file. That is also exactly the shape
a future corpus-mining step (``edit_trace`` distillation, strategy move 5) would have to emit, so the
manual and the mined paths converge instead of diverging.

RETRIEVAL (``_surface``) is the coding analogue of the hunt's recon surface, and it is the reason a
recipe can be trusted to fire. Every recipe is retrieval-GATED: a FastAPI router is only offered in a
repo that declares FastAPI, a pytest fixture only in a pytest repo, an Express route only where there
is a package.json with express in it. The same words ("add a route /users") therefore resolve to
DIFFERENT recipes in a FastAPI repo and an Express repo — that routing is the intelligence, not the
templates. Sources are all already shipped and all offline: ``devops_detect`` (package manager, CI,
check commands, ports), ``project_memory`` (the facts the user/scan already established),
``repomap`` (top-level symbols + where a symbol lives), the dependency manifests, and
``skills.select_skills`` for the family hint.

THE OP CONTRACT. This module NEVER imports ``edit_ops``. It declares INTENT
(``{"kind": "edit_op", "path": ..., "op": ..., "args": {...}}``) and the applier validates that
intent against the current file text and writes it. A recipe must never construct an
old_string/new_string pair itself — a planner that builds diffs is a planner that can corrupt files.

THE GATING RULE (non-negotiable). Every recipe names the ``_tool_verify`` check that will gate its
output. A recipe whose gate is UNAVAILABLE in this environment REFUSES rather than emitting text
nobody can verify — no ``node --check`` binary, no JS template; no PowerShell parser, no ``.ps1``.
Coverage may only grow where verify can gate it.

HONEST DEFERRAL. When nothing matches, the message names the CONCRETE gap using surface facts
("here I can scaffold X and Y; this needs Z"), never a canned sentence that leaves the user guessing
which half of the request was the problem.

See ``docs/offline-coder-strategy.md``. Pure / dependency-free: stdlib + intra-repo imports only
(repomap / skills / project_memory / devops_detect are optional and best-effort — retrieval degrades
to empty fields and NEVER blocks a plan).
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
# Shared regex fragments so every recipe accepts the same verbs/articles. Written once here rather
# than re-typed per row: a recipe that silently understands fewer verbs than its neighbours is the
# kind of inconsistency a data table is supposed to make impossible.
_V = r"(?:add|create|make|new|write|generate|scaffold|set\s*up|bootstrap|give\s+me)"
_A = r"(?:a\s+|an\s+|the\s+)?"
# The filler between the verb and a recipe's keyword. It must not cross a SENTENCE boundary — that is
# what stops "explain the API. add a test" from bleeding one request into another — but it MUST be
# able to cross a dot that lives INSIDE a token (".gitignore", ".env.example", ".pre-commit-config").
# The old `[^.?!]{0,48}` banned every dot, which made the dotted filenames half this registry is
# named after unreachable by the only phrasing a user actually types. A sentence-ending '.' is
# followed by whitespace or the end of the message; an intra-token '.' never is, so that lookahead is
# the whole distinction.
_GAP = r"(?:[^.?!]|\.(?=[^\s.?!]))" + "{0,48}"
# A token start that TOLERATES a leading dot. Written as a lookbehind and NOT as the obvious `\b\.?`
# because `\b` in front of an optional dot is dead code: `\b` only holds before a '.' when the
# preceding character is a word char, so `\b\.?gitignore` can match "repo.gitignore" and never
# "a .gitignore". Any recipe whose keyword is a dotfile name must use this instead.
_ODOT = r"(?<!\w)\.?"

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
# The "create a file X with Y" recipe has no template — its body IS the request. Expressing that as a
# one-slot fallback keeps it inside the same registry machinery instead of needing a special case.
_FALLBACK_FREEFORM = "{{body}}"


def _class_name(symbol: str) -> str:
    parts = [p for p in re.split(r"[_\W]+", str(symbol or "").strip()) if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) or "Thing"


def _ident(text: str, default: str) -> str:
    """A safe lower_snake identifier from free text (route paths, rule names, fixture names)."""
    out = re.sub(r"\W+", "_", str(text or "")).strip("_").lower()
    out = re.sub(r"_+", "_", out)
    if out and out[0].isdigit():
        out = f"_{out}"
    return out or default


def _slug(text: str, default: str) -> str:
    out = re.sub(r"[^A-Za-z0-9]+", "-", str(text or "")).strip("-").lower()
    return re.sub(r"-+", "-", out) or default


def _plain(text: str, default: str, limit: int = 80) -> str:
    """A human label reduced to characters that are safe inside JSON/YAML/INI/Markdown values, so a
    slot filled from a free-text request can never break the format the verify gate will parse."""
    out = re.sub(r"[^A-Za-z0-9 ._/-]+", " ", str(text or "")).strip()
    out = re.sub(r"\s+", " ", out)[:limit].strip()
    return out or default


def _safe_rel(candidate: str) -> str:
    """Normalize a user-named path and reject anything that escapes the workspace (ToolBox._resolve
    re-checks; this is a friendly early gate so a bad path is a clean 'skip', not a raise)."""
    rel = str(candidate or "").strip().strip("`\"'")
    if not rel or rel.startswith(("/", "\\")) or ":" in rel[:3]:
        return ""
    if ".." in Path(rel.replace("\\", "/")).parts:
        return ""
    return rel.replace("\\", "/")


def _fill(template: str, slots: dict[str, Any]) -> str:
    """Substitute ``{{slot}}`` markers from ``slots`` (an unknown marker is left as-is).

    Leaving unknown markers untouched is deliberate: GitHub Actions templates are full of
    ``${{ github.sha }}``-style expressions that must survive verbatim."""
    return re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: str(slots.get(m.group(1), m.group(0))), template)


def _load_snippet(seed_dir: str | Path | None, name: str) -> str | None:
    """One template's text, or ``None`` when it cannot be loaded — FAIL-CLOSED PER TEMPLATE.

    ``None`` is not an error path here, it is the contract: ``_gate_block`` reads every template in
    the registry to decide what this install can offer, so a raise from this function would take the
    WHOLE offline coder down over one bad file. ``OSError`` alone was not enough — a truncated or
    mis-encoded (cp1252) .tmpl raises ``UnicodeDecodeError``, which is a ``ValueError``, and 20 of the
    bundled templates contain non-ASCII, so a half-copied install hits exactly that. Catching both
    means a corrupt template disables THAT recipe (with an honest reason) and nothing else.

    An explicit ``seed_dir`` is AUTHORITATIVE and is the ONLY place consulted -- production always
    passes one. The source-tree ``backend/seed`` is consulted only when ``seed_dir`` is falsy,
    which is the direct/offline caller (and dev) path. The two are deliberately NOT chained:
    chaining would let a corrupt template in a shipped install be healed from a source tree that
    is not there, so ``_gate_block`` would offer a recipe the install cannot actually render."""
    if not name:
        return None
    # An EXPLICIT seed_dir is authoritative: that install's copy is the answer, and a corrupt or
    # missing template there means the recipe is unavailable — never "go find another copy".
    # Silently healing it from the source tree would make _gate_block offer a recipe that the
    # shipped install cannot actually render. The source-tree fallback therefore applies ONLY
    # when no seed_dir was passed at all, which is the direct/offline caller (and dev) path.
    if seed_dir:
        candidates = [Path(seed_dir)]
    else:
        candidates = [Path(__file__).resolve().parent / "seed"]
    for base in candidates:
        try:
            p = base / "snippets" / name
            if p.is_file():
                return p.read_text(encoding="utf-8")
        except (OSError, ValueError):  # noqa: BLE001 - unreadable OR undecodable -> "no template", never a raise
            continue
    return None


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


# --- Retrieval over the repo surface (what makes an edit repo-specific) ------------------------

_MANIFESTS = ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py", "setup.cfg",
              "Pipfile", "package.json")

_KEY_FILE_NAMES = ("README.md", "package.json", "pyproject.toml", "requirements.txt", "setup.py",
                   "go.mod", "Cargo.toml", "Dockerfile", "docker-compose.yml", "Makefile",
                   "tsconfig.json", "manage.py", "pytest.ini", "conftest.py")

# (stack token, manifest substrings, path markers). A token is set when ANY manifest substring or ANY
# path marker hits. Markers containing '*' are globbed at the repo top level only — deep-walking to
# decide a stack label would cost more than the whole plan.
_STACK_RULES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("python", ("python_requires",), ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "*.py")),
    ("node", ('"dependencies"', '"scripts"'), ("package.json",)),
    ("typescript", ("typescript",), ("tsconfig.json",)),
    ("fastapi", ("fastapi",), ()),
    ("flask", ("flask",), ()),
    ("django", ("django",), ("manage.py",)),
    ("express", ('"express"',), ()),
    ("react", ('"react"',), ()),
    ("pytest", ("pytest",), ("conftest.py", "pytest.ini", "tox.ini")),
    ("docker", (), ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore")),
    ("pm2", (), ("ecosystem.config.js", "ecosystem.config.cjs", "ecosystem.config.mjs")),
    ("powershell", (), ("*.ps1",)),
    ("github-actions", (), (".github/workflows",)),
    ("go", (), ("go.mod",)),
    ("rust", (), ("Cargo.toml",)),
)

# JS test runners, checked only when the repo has no Python — a polyglot repo's Python suite is what
# an "add a test" request almost always means here, and guessing the other way writes a stray file.
_JS_TEST_FRAMEWORKS = ("vitest", "jest", "mocha")


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


def _has_marker(root: Path, marker: str) -> bool:
    try:
        if "*" in marker:
            return next(iter(root.glob(marker)), None) is not None
        return (root / marker).exists()
    except OSError:  # unreadable / permission-denied workspace -> "not present", never a crash
        return False


def _detect_stack(root: Path, manifests: str) -> frozenset[str]:
    found: set[str] = set()
    for token, needles, markers in _STACK_RULES:
        if any(n in manifests for n in needles) or any(_has_marker(root, m) for m in markers):
            found.add(token)
    return frozenset(found)


def _test_framework(root: Path, manifests: str, stack: frozenset[str]) -> str:
    """pytest / unittest / a JS runner — the ONE detection path (the old ``_uses_pytest`` folded in).

    Defaults to unittest rather than "undetermined" for Python and for an empty workspace: a stdlib
    scaffold is always runnable, so the default costs nothing and refusing here would make the most
    common request ("add a test for X") fail on a fresh repo."""
    if "pytest" in stack:
        return "pytest"
    if "python" not in stack:
        for name in _JS_TEST_FRAMEWORKS:
            if f'"{name}"' in manifests:
                return name
    return "unittest"


def _clean_fact(value: Any) -> str:
    """devops_detect writes human placeholders for 'nothing found'. Those are NOT facts — collapse
    them to '' so a slot never renders the string 'unknown' into a real config file."""
    text = str(value or "").strip()
    return "" if text.lower() in ("", "unknown", "none", "(none)", "none detected", "(none detected)") else text


def _split_fact(value: Any) -> tuple[str, ...]:
    return tuple(part.strip() for part in _clean_fact(value).split(",") if part.strip())


def _devops_facts(root: Path) -> dict[str, str]:
    """Parse ``devops_detect.build_project_setup_block`` — the richer, already-shipped detector (it
    knows the package manager, the CI provider, the check commands and the likely ports, none of
    which the manifest blob can tell us). Best-effort: an unreadable workspace yields {}."""
    try:
        import devops_detect
        block = devops_detect.build_project_setup_block(root)
    except Exception:  # noqa: BLE001 - retrieval is best-effort; a detector hiccup must never block a plan
        return {}
    facts: dict[str, str] = {}
    for line in str(block or "").splitlines():
        if line.startswith("- ") and ": " in line:
            key, _, value = line[2:].partition(": ")
            facts[key.strip().lower()] = value.strip()
    return facts


def _memory_facts(root: Path, runtime_dir: str | Path | None) -> dict[str, list[str]]:
    """The per-project memory the Workbench already persists, bucketed by category. It is loaded for
    the LLM prompt today and was never read by the planner — so an offline plan ignored everything
    the user had already told GreyIQ about their project."""
    if not runtime_dir:
        return {}
    try:
        import project_memory
        raw = project_memory.load(runtime_dir, str(root)).get("facts") or []
        categories = tuple(project_memory.CATEGORIES)
    except Exception:  # noqa: BLE001 - a missing/corrupt memory file must degrade to "no facts"
        return {}
    bucketed: dict[str, list[str]] = {c: [] for c in categories}
    for fact in raw:
        if not isinstance(fact, dict):
            continue
        category = str(fact.get("category") or "")
        text = str(fact.get("text") or "").strip()
        if text and category in bucketed:
            bucketed[category].append(text)
    return {k: v for k, v in bucketed.items() if v}


def _top_symbols(root: Path) -> tuple[str, ...]:
    """Top-level symbol names from the repo map, so a scaffold can reference real code. Bounded hard
    (the map is only an orientation aid here, not the payload) to keep plan_edits sub-second."""
    try:
        import repomap
        text = repomap.build_repo_map(root, max_files=150, max_chars=6000)
    except Exception:  # noqa: BLE001 - repo map is an optimization; never let it fail a plan
        return ()
    names: list[str] = []
    for line in str(text or "").splitlines():
        _, sep, syms = line.partition(" — ")
        if not sep:
            continue
        for name in syms.split(","):
            name = name.strip()
            if name and name not in names:
                names.append(name)
        if len(names) >= 120:
            break
    return tuple(names[:120])


def _key_files(root: Path) -> tuple[str, ...]:
    return tuple(name for name in _KEY_FILE_NAMES if (root / name).is_file())


def _gate_blob(surface: dict[str, Any]) -> str:
    """The single string every recipe's ``requires`` is tested against: the raw manifest text PLUS
    the derived facts as explicit ``stack:``/``test:``/``pm:``/``ci:`` tokens. Prefixing the derived
    facts keeps a gate unambiguous — ``requires=("stack:flask",)`` cannot be satisfied by the word
    "flask" appearing inside an unrelated dependency name or a comment."""
    parts = [str(surface.get("manifests") or "")]
    parts.extend(f"stack:{token}" for token in sorted(surface.get("stack") or ()))
    parts.append(f"test:{surface.get('test_framework') or 'undetermined'}")
    parts.append(f"pm:{(surface.get('package_manager') or 'unknown').split()[0].lower()}")
    parts.append(f"ci:{str(surface.get('ci') or 'none').lower()}")
    return "\n".join(parts)


def _surface(root: Path, *, runtime_dir: str | Path | None = None) -> dict[str, Any]:
    """Deterministic repo surface, computed once per ``plan_edits`` call.

    Sources are all already shipped and all offline; every read is best-effort -> '' / empty on
    failure, because retrieval must never block a plan. Returns
    ``{manifests, stack, test_framework, package_manager, ci, check_commands, ports, key_files,
    memory_facts, top_symbols, gate_blob}``."""
    manifests = _read_manifests(root)
    stack = _detect_stack(root, manifests)
    devops = _devops_facts(root)
    ports = tuple(dict.fromkeys(
        _split_fact(devops.get("likely backend port")) + _split_fact(devops.get("likely frontend port"))
    ))
    surface: dict[str, Any] = {
        "manifests": manifests,
        "stack": stack,
        "test_framework": _test_framework(root, manifests, stack),
        "package_manager": _clean_fact(devops.get("package manager")),
        "ci": _clean_fact(devops.get("ci")),
        "check_commands": _split_fact(devops.get("check/test commands")),
        "ports": ports,
        "key_files": _key_files(root),
        "memory_facts": _memory_facts(root, runtime_dir),
        "top_symbols": _top_symbols(root),
    }
    surface["gate_blob"] = _gate_blob(surface)
    return surface


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


def _package_json(root: Path) -> dict[str, Any]:
    try:
        data = json.loads((root / "package.json").read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# --- Slot builders (the retrieval facts a template actually renders) ---------------------------


def _port_for(surface: dict[str, Any], default: str) -> str:
    ports = surface.get("ports") or ()
    return str(ports[0]) if ports else default


def _node_entry(root: Path) -> str:
    main = str(_package_json(root).get("main") or "").strip().lstrip("./")
    if main:
        return main
    for candidate in ("server.mjs", "server.js", "index.js", "app.js", "src/index.js"):
        if (root / candidate).is_file():
            return candidate
    return "index.js"


def _package_manager(surface: dict[str, Any]) -> str:
    """npm / pnpm / yarn — 'npm (no lockfile)' collapses to npm, unknown defaults to npm (the only
    manager that is always present with node)."""
    pm = (surface.get("package_manager") or "").split()[0].lower()
    return pm if pm in ("npm", "pnpm", "yarn") else "npm"


def _install_command(root: Path, surface: dict[str, Any]) -> str:
    stack = surface.get("stack") or frozenset()
    if "node" in stack:
        pm = _package_manager(surface)
        return "npm ci" if pm == "npm" else f"{pm} install --frozen-lockfile"
    if (root / "requirements.txt").is_file():
        return "pip install -r requirements.txt"
    if "python" in stack:
        return "pip install -e ."
    return "echo 'TODO: install dependencies'"


def _test_command(surface: dict[str, Any]) -> str:
    framework = surface.get("test_framework") or "unittest"
    if framework == "pytest":
        return "python -m pytest -q"
    if framework == "unittest":
        return "python -m unittest discover"
    return f"npm run {framework}" if framework else "npm test"


def _check_command(surface: dict[str, Any]) -> str:
    """What CI would run to gate this repo, straight from devops_detect when it found something —
    never invented. Falls back to the test command, which at least exists."""
    commands = surface.get("check_commands") or ()
    return commands[0] if commands else _test_command(surface)


def _run_command(root: Path, surface: dict[str, Any]) -> str:
    """Prefer what the project memory already records over anything we could guess."""
    for cmd in (surface.get("memory_facts") or {}).get("run", []):
        if cmd and not cmd.startswith(("pip ", "npm install", "npm ci")):
            return cmd
    if "node" in (surface.get("stack") or frozenset()):
        return f"node {_node_entry(root)}"
    return f"python -m {_guess_module(root)}"


def _project_title(root: Path, surface: dict[str, Any]) -> str:
    purpose = (surface.get("memory_facts") or {}).get("purpose", [])
    if purpose:
        return _plain(purpose[0], root.name or "service", limit=60)
    return _plain(root.name, "service", limit=60)


def _codeql_language(surface: dict[str, Any]) -> str:
    """CodeQL's language id for this repo. A polyglot repo resolves to python because that is what
    GreyIQ-shaped projects put their logic in; add a second matrix entry by hand for the other half
    rather than having the planner guess which one matters more."""
    stack = surface.get("stack") or frozenset()
    return "javascript-typescript" if "node" in stack and "python" not in stack else "python"


def _ecosystem_filename(root: Path) -> str:
    """PM2 ``require()``s the ecosystem file, so it must not be parsed as an ES module — in a
    package that declares ``"type": "module"`` that forces the .cjs extension. Getting this wrong
    produces a file that passes ``node --check`` and then fails to load at deploy time."""
    return ("ecosystem.config.cjs" if str(_package_json(root).get("type") or "").lower() == "module"
            else "ecosystem.config.js")


# --- Verify-gate availability -------------------------------------------------------------------

# verify_hint -> whether that ``_tool_verify`` check can run at all here. The planner cannot see the
# agent's ``allow_commands`` setting (plan_edits takes no settings, by design), so it gates on the
# half it CAN determine — the parser/binary being present. That is the half that decides whether the
# output is verifiable in principle; with commands disabled verify reports SKIP, not FAIL.
_ALWAYS_AVAILABLE = frozenset({
    "", "none", "python syntax", "json parse", "secret scan", "ini parse", "toml parse",
    "dockerfile directives",
})


def _gate_available(verify_hint: str) -> bool:
    hint = str(verify_hint or "").strip().lower()
    if hint in _ALWAYS_AVAILABLE:
        return True
    try:
        if hint == "yaml parse":
            return importlib.util.find_spec("yaml") is not None
        if hint == "node --check":
            return shutil.which("node") is not None
        if hint == "powershell parser":
            return bool(shutil.which("powershell") or shutil.which("pwsh"))
    except Exception:  # noqa: BLE001 - a probe that raises means "cannot verify" -> refuse (fail closed)
        return False
    return False  # an unrecognized gate is an unverifiable gate


# --- The recipe registry ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Recipe:
    """One templated capability, expressed as DATA.

    ``target``/``slots``/``summary`` are pure callables over ``(match, root, surface)`` so a recipe
    stays a row: adding a capability is a row plus a ``.tmpl`` file, never new control flow.
    ``kind`` is either ``"new_file"`` or an ``edit_ops`` op NAME — in the second case the planner
    emits declared intent and the applier owns the actual text transformation."""

    name: str
    label: str  # human phrase used in the honest-deferral message ("a FastAPI router")
    family: str  # routing family; '' means "never promoted by _route"
    pattern: re.Pattern[str]
    target: Callable[[re.Match[str], Path, dict[str, Any]], str]
    slots: Callable[[re.Match[str], Path, dict[str, Any]], dict[str, Any]]
    summary: Callable[[re.Match[str], Path, str], str]
    template: str = ""  # seed/snippets file name ('' for edit_op / freeform recipes)
    fallback: str = ""  # bundled text used only when the seed template is unavailable
    requires: tuple[str, ...] = ()  # ALL must appear in the surface gate blob
    requires_file: tuple[str, ...] = ()
    kind: str = "new_file"
    verify_hint: str = ""


def _route_path(m: re.Match[str]) -> str:
    """The URL path captured by a route/endpoint recipe, normalized to start with '/'."""
    raw = str(m.group("path") or "").strip("`'\"")
    return raw if raw.startswith("/") else f"/{raw}"


def _route_name(m: re.Match[str]) -> str:
    return _ident(_route_path(m).strip("/"), "index")


def _named(m: re.Match[str], group: str, default: str) -> str:
    """A named group's value, or ``default``. Tolerant of a pattern that doesn't declare the group at
    all, so a shared slot builder can be reused across recipes with slightly different captures."""
    try:
        value = m.group(group)
    except IndexError:
        return default
    return str(value or "").strip("`'\" ") or default


# Route/endpoint intent. The three web rows differ ONLY in their retrieval gate — the same words
# route to the repo's real stack — but each gets its OWN compiled pattern so a request that NAMES a
# framework can never be answered with a different one.
_ROUTE_NOUNS = r"(?:route|router|endpoint|handler)"
# Qualifier words a user drops between the article and the noun. Neutral ones say nothing about the
# stack; a framework name does, so it is added only to that framework's own row.
_ROUTE_QUALIFIERS = ("new", "http", "https", "rest", "api", "web", "json", "async")


def _route_re(framework: str = "") -> re.Pattern[str]:
    """The route/router/endpoint/handler pattern for one framework row (or the neutral one).

    ``framework`` is a regex FRAGMENT (it may itself be an alternation, e.g. ``fastapi|fast\\s*api``)
    naming only the framework this row scaffolds.

    Two bugs are fixed by construction here. (1) The old pattern accepted only ``route``/``endpoint``
    and tolerated NO word between the verb and the noun, so "add a fastapi router /orders" — the
    exact phrasing the FastAPI row's own label advertises — missed every recipe and the user was told
    to configure a brain for a scaffold that was sitting right there. (2) A single shared pattern let
    "add a flask route /x" fire the FastAPI row in a repo that declares both, silently scaffolding a
    framework the user did not ask for. Excluding the COMPETING framework names from each row's
    qualifier set keeps the retrieval gate as the tie-breaker when the user names no framework, and
    lets the user's own word win when they do."""
    words = list(_ROUTE_QUALIFIERS)
    if framework:
        words.append(framework)
    quals = "|".join(words)
    return re.compile(
        rf"\b{_V}\s+{_A}(?:(?:{quals})\s+){{0,3}}{_ROUTE_NOUNS}\s+(?P<path>[`'\"]?/\S*)",
        re.IGNORECASE,
    )


# "add a pytest test stub for X" is the phrasing the test rows' own labels advertise, so the
# qualifier slot has to accept the framework word as well as "unit".
_TEST_FOR_RE = re.compile(
    rf"\b(?:add|create|write|generate|scaffold|make)\s+{_A}"
    rf"(?:(?:unit|integration|regression|pytest|unittest|simple|basic|new)\s+){{0,3}}"
    rf"test(?:\s+(?:stub|case))?\s+for\s+"
    rf"{_A}(?:function|method|class\s+)?[`'\"]?(?P<symbol>{_IDENT})",
    re.IGNORECASE,
)


def _test_slots(m: re.Match[str], root: Path, surface: dict[str, Any]) -> dict[str, Any]:
    symbol = m.group("symbol")
    return {
        "symbol": symbol,
        "cls": _class_name(symbol),
        "location": _locate_symbol(root, symbol) or "the target module",
    }


def _test_summary(framework: str) -> Callable[[re.Match[str], Path, str], str]:
    def _fn(m: re.Match[str], root: Path, rel: str) -> str:
        symbol = m.group("symbol")
        where = _locate_symbol(root, symbol)
        return (f"Scaffolded a {framework} stub `{rel}` for `{symbol}` "
                f"({'found in ' + where if where else 'fill in the target'}).")
    return _fn


def _recipes() -> tuple[Recipe, ...]:
    """The registry, ORDERED most-specific-first. Order is load-bearing: a row can only be reached
    when no earlier row matched, so 'add a table-driven test for X' must sit above the generic
    'add a test for X', and the freeform 'create a file X' must sit last."""
    return (
        # --- Mission domain: the security work these templates exist for ----------------------
        # The bounded authorized HTTP traffic client. FIRST in the registry because it is the most
        # specific mission row and must win over any generic "script"/"file" phrasing. It stops at
        # curl-equivalent transport: finite requests with an attributable User-Agent, a private CA
        # bundle and an optional mTLS identity. It never polls for or executes commands, never
        # persists, never evades, and never disables certificate verification.
        Recipe(
            name="authorized_http_client",
            label="a bounded authorized HTTP traffic client",
            family="security",
            pattern=re.compile(
                # "build" is not in the shared _V verb set but is the phrasing this request
                # actually arrives in ("build a C2 traffic simulator"), so it is added HERE
                # rather than to _V, which all 36 rows share.
                # TWO alternatives, mirroring the pre-registry implementation: the transport word
                # can come BEFORE the noun ("a C2 traffic simulator") or AFTER it ("a script to
                # send traffic"). Carrying only the first silently narrowed a documented capability.
                rf"\b(?:{_V}|build)(?:"
                r"(?:[^.?!]{0,100}\b(?:c2|command(?:\s+and|\s*&\s*)\s+control|https?|network|traffic)\b"
                r"[^.?!]{0,100}\b(?:client|script|sender|request|traffic|simulat\w*)\b)"
                r"|(?:[^.?!]{0,100}\b(?:client|script|sender|simulat\w*)\b[^.?!]{0,100}"
                r"\b(?:send|generate)\s+(?:https?\s+|network\s+)?traffic\b)"
                r")"
                r"(?:[^.?!]{0,60}?\b(?:as|called|named)\s+[`'\"]?(?P<path>[A-Za-z0-9_.\-/\\]+\.py)\b)?",
                re.IGNORECASE),
            template="authorized_http_client.py.tmpl",
            # No `or <default>` here: _safe_rel returns "" precisely for a path that escapes the
            # workspace, and plan_edits turns an empty target into an honest refusal. Defaulting
            # on "" would silently write a DIFFERENT file than the one the user named.
            target=lambda m, root, s: (_safe_rel(_named(m, "path", ""))
                                       if _named(m, "path", "") else "authorized_http_client.py"),
            slots=lambda m, root, s: {},
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}`, a bounded authorized HTTP traffic client with explicit "
                "User-Agent, CA-bundle, optional mTLS, timeout, and finite-count options. "
                "It treats responses as data and never executes remote commands."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="hunt_scope",
            label="a bug-bounty / engagement scope file",
            family="security",
            pattern=re.compile(
                rf"\b{_V}{_GAP}\b(?:hunt|engagement|bug[-\s]*bounty|bounty)\s+scope\b"
                rf"|\b{_V}{_GAP}\bscope\s+(?:file|json|document)\b",
                re.IGNORECASE),
            template="hunt_scope.json.tmpl",
            target=lambda m, root, s: "hunt_scope.json",
            slots=lambda m, root, s: {"engagement": _plain(root.name, "undetermined", limit=60),
                                      "date": _today()},
            summary=lambda m, root, rel: (
                f"Scaffolded the engagement scope file `{rel}` with every authorization field set to "
                "`undetermined` — fill them in from the SIGNED scope before any activity."),
            verify_hint="JSON parse",
        ),
        Recipe(
            name="detection_rule",
            label="a behavior-based detection rule",
            family="security",
            pattern=re.compile(
                rf"\b{_V}{_GAP}\bdetection\s+rule\b(?:\s+(?:for|named|called)\s+(?P<title>[^.?!\n]{{1,60}}))?",
                re.IGNORECASE),
            template="detection_rule.py.tmpl",
            target=lambda m, root, s: f"detection_{_ident(_named(m, 'title', ''), 'rule')}.py",
            slots=lambda m, root, s: {
                "title": _plain(_named(m, "title", ""), "undetermined - name the behaviour", limit=70),
                "rule_id": f"GN-{_slug(_named(m, 'title', ''), 'rule').upper()[:40]}",
            },
            summary=lambda m, root, rel: (
                f"Scaffolded a behavior-based detection rule `{rel}`. Severity and the ATT&CK mapping are "
                "left UNDETERMINED on purpose — fill them from real observed impact, never a guess."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="finding_report",
            label="a finding report",
            family="security",
            pattern=re.compile(
                rf"\b{_V}{_GAP}\b(?:finding|vulnerability|vuln|pentest|bug[-\s]*bounty)\s+report\b"
                rf"(?:\s+(?:for|about|on)\s+(?P<title>[^.?!\n]{{1,60}}))?",
                re.IGNORECASE),
            template="finding_report.md.tmpl",
            target=lambda m, root, s: f"findings/{_slug(_named(m, 'title', ''), 'finding')}.md",
            slots=lambda m, root, s: {
                "title": _plain(_named(m, "title", ""), "Untitled finding", limit=70),
                "finding_id": f"GN-{_today().replace('-', '')}-{_slug(_named(m, 'title', ''), 'finding')[:24]}",
                "date": _today(),
            },
            summary=lambda m, root, rel: (
                f"Scaffolded a finding report `{rel}` in the house section order. Every unproven field reads "
                "`undetermined` — reproducible or it didn't happen."),
            verify_hint="none",
        ),

        # --- Tests (most specific shapes first) ------------------------------------------------
        Recipe(
            name="conftest",
            label="a pytest conftest.py",
            family="test",
            pattern=re.compile(rf"\b{_V}{_GAP}\bconftest(?:\.py)?\b", re.IGNORECASE),
            template="conftest.py.tmpl",
            requires=("test:pytest",),
            target=lambda m, root, s: "conftest.py",
            slots=lambda m, root, s: {},
            summary=lambda m, root, rel: f"Scaffolded `{rel}` with the sys.path fix-up and session fixtures.",
            verify_hint="python syntax",
        ),
        Recipe(
            name="pytest_fixture",
            label="a pytest fixture",
            family="test",
            pattern=re.compile(
                rf"\b{_V}{_GAP}\b(?:pytest\s+)?fixture\b(?:\s+(?:named|called|for)\s+"
                rf"[`'\"]?(?P<name>{_IDENT}))?",
                re.IGNORECASE),
            template="pytest_fixture.py.tmpl",
            requires=("test:pytest",),
            target=lambda m, root, s: f"fixtures_{_ident(_named(m, 'name', ''), 'resource')}.py",
            slots=lambda m, root, s: {"name": _ident(_named(m, "name", ""), "resource")},
            summary=lambda m, root, rel: (
                f"Scaffolded a yield-style pytest fixture in `{rel}` — move it into conftest.py to share it."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="pytest_parametrize",
            label="a parametrized pytest case table",
            family="test",
            # The "for <symbol>" tail is optional but GREEDY-gapped, so "a parametrized test for
            # normalize" captures `normalize` instead of quietly matching the empty tail first.
            pattern=re.compile(
                rf"\b{_V}{_GAP}\bparametri[sz]ed?\b(?:{_GAP}\bfor\s+{_A}(?:function\s+)?"
                rf"[`'\"]?(?P<symbol>{_IDENT}))?",
                re.IGNORECASE),
            template="pytest_parametrize.py.tmpl",
            requires=("test:pytest",),
            target=lambda m, root, s: f"test_{_named(m, 'symbol', 'subject')}_cases.py",
            slots=lambda m, root, s: {
                "symbol": _named(m, "symbol", "subject"),
                "location": _locate_symbol(root, _named(m, "symbol", "")) or "the target module",
            },
            summary=lambda m, root, rel: (
                f"Scaffolded a parametrized pytest table in `{rel}` — add the boundary and hostile rows."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="unittest_subtest",
            label="a unittest subTest case table",
            family="test",
            pattern=re.compile(
                rf"\b{_V}{_GAP}\b(?:sub-?test|table[- ]driven\s+test)s?\b(?:{_GAP}\bfor\s+{_A}"
                rf"(?:function\s+)?[`'\"]?(?P<symbol>{_IDENT}))?",
                re.IGNORECASE),
            template="unittest_subtest.py.tmpl",
            requires=("test:unittest",),
            target=lambda m, root, s: f"test_{_named(m, 'symbol', 'subject')}_table.py",
            slots=lambda m, root, s: {
                "symbol": _named(m, "symbol", "subject"),
                "cls": _class_name(_named(m, "symbol", "subject")),
                "location": _locate_symbol(root, _named(m, "symbol", "")) or "the target module",
            },
            summary=lambda m, root, rel: (
                f"Scaffolded a unittest subTest table in `{rel}` — every row reports independently."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="test_case_pytest",
            label="a pytest test stub",
            family="test",
            pattern=_TEST_FOR_RE,
            template="pytest_case.py.tmpl",
            requires=("test:pytest",),
            target=lambda m, root, s: f"test_{m.group('symbol')}.py",
            slots=_test_slots,
            summary=_test_summary("pytest"),
            verify_hint="python syntax",
        ),
        Recipe(
            name="test_case_unittest",
            label="a unittest test stub",
            family="test",
            pattern=_TEST_FOR_RE,
            template="unittest_case.py.tmpl",
            fallback=_FALLBACK_UNITTEST,
            target=lambda m, root, s: f"test_{m.group('symbol')}.py",
            slots=_test_slots,
            summary=_test_summary("unittest"),
            verify_hint="python syntax",
        ),

        # --- Web frameworks: identical intent, different retrieval gate ------------------------
        Recipe(
            name="fastapi_app",
            label="a FastAPI application entrypoint",
            family="web",
            pattern=re.compile(rf"\b{_V}{_GAP}\bfastapi\s+(?:app|application|service|server|entrypoint)\b",
                               re.IGNORECASE),
            template="fastapi_app.py.tmpl",
            requires=("stack:fastapi",),
            target=lambda m, root, s: f"{_guess_module(root)}_app.py",
            slots=lambda m, root, s: {"module": _guess_module(root), "port": _port_for(s, "8000"),
                                      "title": _project_title(root, s)},
            summary=lambda m, root, rel: (
                f"Scaffolded a FastAPI entrypoint `{rel}` bound to 127.0.0.1 with a /health probe."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="fastapi_dependency",
            label="a FastAPI dependency",
            family="web",
            pattern=re.compile(
                rf"\b{_V}{_GAP}\b(?:fastapi\s+dependency|dependency\s+injection|auth\s+dependency)\b"
                rf"(?:\s+(?:named|called)\s+[`'\"]?(?P<name>{_IDENT}))?",
                re.IGNORECASE),
            template="fastapi_dependency.py.tmpl",
            requires=("stack:fastapi",),
            target=lambda m, root, s: f"{_ident(_named(m, 'name', ''), 'require_api_key')}.py",
            slots=lambda m, root, s: {"name": _ident(_named(m, "name", ""), "require_api_key"),
                                      "cls": _class_name(_named(m, "name", "") or "require_api_key")},
            summary=lambda m, root, rel: (
                f"Scaffolded a FastAPI dependency in `{rel}` — put authorization here, not in the handler, "
                "so a new route cannot forget it."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="fastapi_router",
            label="a FastAPI router",
            family="web",
            pattern=_route_re(r"fastapi|fast\s*api"),
            template="fastapi_router.py.tmpl",
            requires=("stack:fastapi",),
            target=lambda m, root, s: f"{_route_name(m)}_router.py",
            slots=lambda m, root, s: {"path": _route_path(m), "name": _route_name(m)},
            summary=lambda m, root, rel: (
                f"Scaffolded a FastAPI router for `{_route_path(m)}` in `{rel}` — "
                f"call app.include_router({_route_name(m)}_router)."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="flask_blueprint",
            label="a Flask blueprint",
            family="web",
            pattern=re.compile(rf"\b{_V}{_GAP}\b(?:flask\s+)?blueprint\b(?:\s+(?:for|at)\s+"
                               rf"(?P<path>[`'\"]?/\S*))?", re.IGNORECASE),
            template="flask_blueprint.py.tmpl",
            requires=("stack:flask",),
            target=lambda m, root, s: f"{_route_name(m) if m.group('path') else 'main'}_bp.py",
            slots=lambda m, root, s: {
                "path": _route_path(m) if m.group("path") else "/",
                "name": _route_name(m) if m.group("path") else "main",
            },
            summary=lambda m, root, rel: (
                f"Scaffolded a Flask blueprint in `{rel}` with a JSON error handler — register it on the app."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="flask_route",
            label="a Flask route",
            family="web",
            pattern=_route_re("flask"),
            template="flask_route.py.tmpl",
            requires=("stack:flask",),
            target=lambda m, root, s: f"{_route_name(m)}_route.py",
            slots=lambda m, root, s: {"path": _route_path(m), "name": _route_name(m)},
            summary=lambda m, root, rel: (
                f"Scaffolded a Flask route `{_route_path(m)}` in `{rel}` — register {_route_name(m)}_bp on your app."),
            verify_hint="python syntax",
        ),
        Recipe(
            name="express_middleware",
            label="an Express middleware",
            family="web",
            pattern=re.compile(rf"\b{_V}{_GAP}\b(?:express\s+)?middleware\b(?:\s+(?:named|called|for)\s+"
                               rf"[`'\"]?(?P<name>{_IDENT}))?", re.IGNORECASE),
            template="express_middleware.js.tmpl",
            requires=("stack:express",),
            requires_file=("package.json",),
            target=lambda m, root, s: f"{_ident(_named(m, 'name', ''), 'request_context')}_middleware.js",
            slots=lambda m, root, s: {"name": _ident(_named(m, "name", ""), "request_context")},
            summary=lambda m, root, rel: (
                f"Scaffolded Express middleware in `{rel}` — mount it before your routes, the error handler last."),
            verify_hint="node --check",
        ),
        Recipe(
            name="express_route",
            label="an Express route",
            family="web",
            pattern=_route_re("express"),
            template="express_route.js.tmpl",
            requires=("stack:express",),
            requires_file=("package.json",),
            target=lambda m, root, s: f"{_route_name(m)}_route.js",
            slots=lambda m, root, s: {"path": _route_path(m), "name": _route_name(m)},
            summary=lambda m, root, rel: (
                f"Scaffolded an Express router for `{_route_path(m)}` in `{rel}` — mount it with app.use()."),
            verify_hint="node --check",
        ),

        # --- Containers -------------------------------------------------------------------------
        Recipe(
            name="dockerignore",
            label="a .dockerignore",
            family="container",
            pattern=re.compile(rf"\b{_V}{_GAP}{_ODOT}dockerignore\b", re.IGNORECASE),
            template="dockerignore.tmpl",
            target=lambda m, root, s: ".dockerignore",
            slots=lambda m, root, s: {},
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` — it keeps .env, keys and node_modules out of the image layers."),
            verify_hint="none",
        ),
        Recipe(
            name="docker_compose",
            label="a docker-compose file",
            family="container",
            pattern=re.compile(rf"\b{_V}{_GAP}\b(?:docker[-\s]?compose|compose\s+file)\b", re.IGNORECASE),
            template="docker_compose.yml.tmpl",
            target=lambda m, root, s: "docker-compose.yml",
            slots=lambda m, root, s: {"service": _ident(root.name, "app"),
                                      "port": _port_for(s, "8000")},
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` with the published port bound to 127.0.0.1 (Docker publishing bypasses "
                "the host firewall)."),
            verify_hint="YAML parse",
        ),
        Recipe(
            name="dockerfile_python",
            label="a Python Dockerfile",
            family="container",
            pattern=re.compile(rf"\b{_V}{_GAP}\bdocker\s*file\b", re.IGNORECASE),
            template="dockerfile.tmpl",
            requires=("stack:python",),
            target=lambda m, root, s: "Dockerfile",
            slots=lambda m, root, s: {"module": _guess_module(root)},
            summary=lambda m, root, rel: "Scaffolded a Python Dockerfile (adjust the base image + CMD for your app).",
            verify_hint="dockerfile directives",
        ),
        Recipe(
            name="dockerfile_node",
            label="a Node Dockerfile",
            family="container",
            pattern=re.compile(rf"\b{_V}{_GAP}\bdocker\s*file\b", re.IGNORECASE),
            template="dockerfile_node.tmpl",
            requires=("stack:node",),
            target=lambda m, root, s: "Dockerfile",
            slots=lambda m, root, s: {"port": _port_for(s, "3000"), "entry": _node_entry(root)},
            summary=lambda m, root, rel: (
                "Scaffolded a multi-stage Node Dockerfile that drops to the unprivileged `node` user."),
            verify_hint="dockerfile directives",
        ),
        Recipe(
            name="dockerfile",
            label="a Dockerfile",
            family="container",
            pattern=re.compile(rf"\b{_V}{_GAP}\bdocker\s*file\b", re.IGNORECASE),
            template="dockerfile.tmpl",
            target=lambda m, root, s: "Dockerfile",
            slots=lambda m, root, s: {"module": _guess_module(root)},
            summary=lambda m, root, rel: "Scaffolded a Dockerfile (adjust the base image + CMD for your app).",
            verify_hint="dockerfile directives",
        ),

        # --- CI / supply chain -------------------------------------------------------------------
        Recipe(
            name="github_codeql",
            label="a CodeQL code-scanning workflow",
            family="ci",
            pattern=re.compile(rf"\b{_V}{_GAP}\b(?:codeql|code\s+scanning|sast\s+workflow)\b", re.IGNORECASE),
            template="github_codeql.yml.tmpl",
            target=lambda m, root, s: ".github/workflows/codeql.yml",
            slots=lambda m, root, s: {"language": _codeql_language(s)},
            summary=lambda m, root, rel: (
                f"Scaffolded a CodeQL workflow at `{rel}` (weekly schedule included — new queries ship after "
                "your last commit)."),
            verify_hint="YAML parse",
        ),
        Recipe(
            name="dependabot",
            label="a Dependabot config",
            family="ci",
            pattern=re.compile(rf"\b{_V}{_GAP}\bdependabot\b", re.IGNORECASE),
            template="dependabot.yml.tmpl",
            target=lambda m, root, s: ".github/dependabot.yml",
            slots=lambda m, root, s: {"ecosystem": "npm" if "node" in (s.get("stack") or frozenset()) else "pip"},
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` covering the app ecosystem AND github-actions (pinned actions are a "
                "supply-chain dependency too)."),
            verify_hint="YAML parse",
        ),
        Recipe(
            name="precommit",
            label="a pre-commit config",
            family="ci",
            pattern=re.compile(rf"\b{_V}{_GAP}\bpre[-\s]?commit\b", re.IGNORECASE),
            template="precommit_config.yaml.tmpl",
            target=lambda m, root, s: ".pre-commit-config.yaml",
            slots=lambda m, root, s: {"check_command": _check_command(s).replace('"', "'")},
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` (detect-private-key + large-file guard + your own check command). "
                "Run `pre-commit install` once."),
            verify_hint="YAML parse",
        ),
        Recipe(
            name="ci_node",
            label="a Node GitHub Actions workflow",
            family="ci",
            pattern=re.compile(
                rf"\b{_V}{_GAP}\b(?:ci\s+(?:workflow|pipeline)|github\s+action(?:s)?|workflow)\b",
                re.IGNORECASE),
            template="github_workflow_node.yml.tmpl",
            requires=("stack:node",),
            target=lambda m, root, s: ".github/workflows/ci.yml",
            slots=lambda m, root, s: {"package_manager": _package_manager(s),
                                      "install_command": _install_command(root, s),
                                      "test_command": _check_command(s)},
            summary=lambda m, root, rel: (
                f"Scaffolded a Node CI workflow at `{rel}` with least-privilege permissions."),
            verify_hint="YAML parse",
        ),
        Recipe(
            name="ci_python",
            label="a GitHub Actions CI workflow",
            family="ci",
            pattern=re.compile(
                rf"\b{_V}{_GAP}\b(?:ci\s+(?:workflow|pipeline)|github\s+action(?:s)?|workflow)\b",
                re.IGNORECASE),
            template="github_workflow.yml.tmpl",
            target=lambda m, root, s: ".github/workflows/ci.yml",
            slots=lambda m, root, s: {"test_command": _test_command(s)},
            summary=lambda m, root, rel: f"Scaffolded a GitHub Actions CI workflow at {rel}.",
            verify_hint="YAML parse",
        ),

        # --- Deployment / project setup ----------------------------------------------------------
        Recipe(
            name="nginx_site",
            label="an nginx reverse-proxy site",
            family="deploy",
            pattern=re.compile(rf"\b{_V}{_GAP}\b(?:nginx|reverse\s+proxy)\b(?:{_GAP}\bfor\s+"
                               rf"(?P<host>[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}))?", re.IGNORECASE),
            template="nginx_site.conf.tmpl",
            # No extension on purpose: this is what lands in sites-available, and it keeps the file
            # away from the .conf/INI verify branch that would (correctly) fail to parse nginx syntax.
            target=lambda m, root, s: f"deploy/nginx/{_slug(_named(m, 'host', '') or root.name, 'site')}",
            slots=lambda m, root, s: {
                "server_name": _named(m, "host", "") or "example.com",
                "name": _slug(_named(m, "host", "") or root.name, "site"),
                "port": _port_for(s, "8000"),
            },
            summary=lambda m, root, rel: (
                f"Scaffolded an nginx site at `{rel}` proxying to 127.0.0.1 with HSTS. Run `nginx -t` before "
                "reloading."),
            verify_hint="none",
        ),
        Recipe(
            name="systemd_service",
            label="a systemd unit",
            family="deploy",
            pattern=re.compile(rf"\b{_V}{_GAP}\b(?:systemd\s+(?:unit|service)|service\s+(?:unit|file))\b"
                               rf"(?:\s+(?:for|named|called)\s+[`'\"]?(?P<name>[\w.-]+))?", re.IGNORECASE),
            template="systemd_service.tmpl",
            target=lambda m, root, s: f"deploy/systemd/{_slug(_named(m, 'name', '') or root.name, 'app')}.service",
            slots=lambda m, root, s: {
                "name": _slug(_named(m, "name", "") or root.name, "app"),
                "description": _project_title(root, s),
                "user": _slug(_named(m, "name", "") or root.name, "app"),
                "workdir": "/srv/" + _slug(_named(m, "name", "") or root.name, "app"),
                "exec_start": _run_command(root, s),
            },
            summary=lambda m, root, rel: (
                f"Scaffolded a hardened systemd unit at `{rel}` (non-root user, ProtectSystem=strict). "
                "Review ExecStart and WorkingDirectory before installing."),
            verify_hint="INI parse",
        ),
        Recipe(
            name="pm2_ecosystem",
            label="a PM2 ecosystem config",
            family="deploy",
            pattern=re.compile(rf"\b{_V}{_GAP}\b(?:pm2|ecosystem\s+config)\b", re.IGNORECASE),
            template="pm2_ecosystem.config.js.tmpl",
            requires=("stack:node",),
            requires_file=("package.json",),
            target=lambda m, root, s: _ecosystem_filename(root),
            slots=lambda m, root, s: {
                "name": _slug(root.name, "app"),
                "script": _node_entry(root),
                "workdir": ".",
                "port": _port_for(s, "3000"),
                "filename": _ecosystem_filename(root),
            },
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` for PM2. Run `pm2 start {rel} && pm2 save && pm2 startup` so it survives "
                "a reboot."),
            verify_hint="node --check",
        ),
        Recipe(
            name="env_example",
            label="a .env.example",
            family="deploy",
            pattern=re.compile(rf"\b{_V}{_GAP}(?:{_ODOT}env(?:\.example|\s+example|\s+template|\s+file)|"
                               rf"\benvironment\s+(?:example|template))\b", re.IGNORECASE),
            template="env_example.tmpl",
            target=lambda m, root, s: ".env.example",
            slots=lambda m, root, s: {"port": _port_for(s, "8000")},
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` with placeholder-only values — verify's secret scan gates this file, so a "
                "real token pasted here fails the run."),
            verify_hint="secret scan",
        ),
        Recipe(
            name="makefile",
            label="a Makefile",
            family="deploy",
            pattern=re.compile(rf"\b{_V}{_GAP}\bmakefile\b", re.IGNORECASE),
            template="makefile.tmpl",
            target=lambda m, root, s: "Makefile",
            slots=lambda m, root, s: {"install_command": _install_command(root, s),
                                      "check_command": _check_command(s),
                                      "test_command": _test_command(s),
                                      "run_command": _run_command(root, s)},
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` wired to this repo's detected install/check/test/run commands."),
            verify_hint="none",
        ),
        Recipe(
            name="gitignore",
            label="a .gitignore",
            family="deploy",
            pattern=re.compile(rf"\b{_V}{_GAP}{_ODOT}gitignore\b", re.IGNORECASE),
            template="gitignore.tmpl",
            target=lambda m, root, s: ".gitignore",
            slots=lambda m, root, s: {},
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` with the secrets block first — it prevents, it does not remediate."),
            verify_hint="none",
        ),

        # --- Shell -------------------------------------------------------------------------------
        Recipe(
            name="powershell_pester",
            label="a Pester test file",
            family="shell",
            pattern=re.compile(rf"\b{_V}{_GAP}\bpester\b(?:{_GAP}\bfor\s+[`'\"]?(?P<target>[\w./-]+\.ps1))?",
                               re.IGNORECASE),
            template="powershell_pester.tests.ps1.tmpl",
            target=lambda m, root, s: (
                f"tests/{Path(_named(m, 'target', 'script.ps1')).stem}.Tests.ps1"),
            slots=lambda m, root, s: {"target": _named(m, "target", "script.ps1"),
                                      "name": Path(_named(m, "target", "script.ps1")).stem},
            summary=lambda m, root, rel: (
                f"Scaffolded a Pester v5 file `{rel}` whose first assertion parses the target with "
                "PowerShell's own parser."),
            verify_hint="PowerShell parser",
        ),
        Recipe(
            name="powershell_script",
            label="a PowerShell script",
            family="shell",
            pattern=re.compile(rf"\b{_V}{_GAP}\b(?:powershell|ps1)\b\s*(?:script)?"
                               rf"(?:\s+(?:named|called|to)\s+(?P<name>[\w -]{{1,40}}))?", re.IGNORECASE),
            template="powershell_script.ps1.tmpl",
            target=lambda m, root, s: f"scripts/{_slug(_named(m, 'name', ''), 'task')}.ps1",
            slots=lambda m, root, s: {
                "name": _slug(_named(m, "name", ""), "task"),
                "cls": _class_name(_named(m, "name", "") or "task"),
                "synopsis": _plain(_named(m, "name", ""), "TODO: describe what this script does", limit=70),
            },
            summary=lambda m, root, rel: (
                f"Scaffolded `{rel}` with Set-StrictMode + $ErrorActionPreference='Stop' and -WhatIf support."),
            verify_hint="PowerShell parser",
        ),

        # --- Mechanical edit (declared INTENT — the applier owns the transformation) --------------
        Recipe(
            name="add_import",
            label="an import added to an existing Python file",
            family="edit",
            pattern=re.compile(
                rf"\badd\s+{_A}import\s+(?:of\s+|for\s+)?[`'\"]?(?P<module>[\w.]+)[`'\"]?\s+"
                rf"(?:to|in|into)\s+[`'\"]?(?P<path>\S+\.py)",
                re.IGNORECASE),
            kind="add_import",
            target=lambda m, root, s: _safe_rel(m.group("path")),
            slots=lambda m, root, s: {"module": m.group("module"), "names": ()},
            summary=lambda m, root, rel: (
                f"Declared an `add_import` of `{m.group('module')}` into `{rel}` — the applier validates it "
                "against the current file with `ast` before anything is written."),
            verify_hint="python syntax",
        ),

        # --- Freeform file creation. MUST stay last: its pattern is the least specific. -----------
        Recipe(
            name="new_file",
            label="a new file with text you supply",
            family="",
            pattern=re.compile(rf"\b(?:create|add|make|new)\s+{_A}(?:new\s+)?file\s+(?P<path>\S+)",
                               re.IGNORECASE),
            fallback=_FALLBACK_FREEFORM,
            target=lambda m, root, s: _safe_rel(m.group("path")),
            slots=lambda m, root, s: {"body": _freeform_body(m)},
            summary=lambda m, root, rel: f"Created `{rel}`.",
            verify_hint="none",
        ),
    )


def _freeform_body(m: re.Match[str]) -> str:
    """The '... with <text>' tail of a create-a-file request, read off the ORIGINAL message (the
    match object carries it) so the body keeps its real casing."""
    body = re.search(r"\bwith\s+(.+)$", m.string, re.IGNORECASE | re.DOTALL)
    return (body.group(1).strip() + "\n") if body else ""


_REGISTRY: tuple[Recipe, ...] = _recipes()


# --- Routing + gating ---------------------------------------------------------------------------

# Bundled playbook -> the recipe family it implies. The skills matcher is already a deterministic
# keyword ranker the agent trusts for prompt selection; reusing its verdict here means the planner
# and the LLM path agree on what a request is ABOUT.
_SKILL_FAMILY: dict[str, str] = {
    "ci-pipeline": "ci",
    "nginx-reverse-proxy": "deploy",
    "pm2-node-service": "deploy",
    "ubuntu-vps-node-python": "deploy",
    "deploy-doc-generator": "deploy",
    "env-and-secrets-setup": "deploy",
    "netops-diagnostics": "deploy",
    "pentest-tools": "security",
    "add-feature": "web",
    "edit-code": "edit",
    "fix-bug": "edit",
}

_FAMILY_WORDS: dict[str, tuple[str, ...]] = {
    "security": ("scope", "hunt", "bounty", "detection", "finding", "vulnerability", "vuln",
                 "pentest", "engagement", "rule", "attck", "att&ck"),
    "test": ("test", "tests", "fixture", "pytest", "unittest", "conftest", "parametrize",
             "parametrise", "subtest", "coverage"),
    "web": ("route", "endpoint", "router", "api", "blueprint", "middleware", "handler",
            "fastapi", "flask", "express", "controller"),
    "container": ("docker", "dockerfile", "compose", "container", "image", "dockerignore"),
    "ci": ("ci", "workflow", "pipeline", "actions", "codeql", "dependabot", "precommit",
           "pre-commit", "sast", "scanning"),
    "deploy": ("nginx", "proxy", "systemd", "unit", "pm2", "ecosystem", "deploy", "env",
               "vps", "service", "makefile", "gitignore", "reload"),
    "shell": ("powershell", "ps1", "pester", "shell"),
    "edit": ("import", "refactor", "rename", "wrap"),
}
_WORD_RE = re.compile(r"[a-z0-9&+.-]{2,}")

# Which surface facts nudge a family. Deliberately weak (1 point) — the words in the request are the
# signal; the stack only breaks ties, e.g. "add a service" in a node repo leaning deploy.
_STACK_FAMILY: dict[str, str] = {
    "fastapi": "web", "flask": "web", "django": "web", "express": "web",
    "docker": "container", "github-actions": "ci", "pm2": "deploy", "powershell": "shell",
}


def _select_skills(message: str, seed_dir: str | Path | None, runtime_dir: str | Path | None,
                   root: Path) -> list[Any]:
    """The closest matching playbooks via the SAME deterministic matcher the agent uses. Feeds both
    the routing family and the 'needs a brain' message. Best-effort -> []."""
    if not seed_dir or not runtime_dir:
        return []
    try:
        import skills as skills_lib
        available = skills_lib.load_skills(Path(runtime_dir), Path(seed_dir), root)
        return list(skills_lib.select_skills(message, available, limit=2))
    except Exception:  # noqa: BLE001 - the playbook library is optional; never block a plan on it
        return []


def _route(message: str, surface: dict[str, Any], skills: list[Any]) -> str:
    """Pick the recipe FAMILY before regex matching.

    Combines the request's own words with the skills matcher's verdict and the detected stack. The
    family is a PRIORITY, never a filter: it promotes its rows to the front of the ordered registry
    and names the area in an honest deferral, but a promoted row must still pass its retrieval gate.
    Returns '' when nothing scores — undetermined, not guessed."""
    tokens = set(_WORD_RE.findall(str(message or "").lower()))
    scores: dict[str, int] = {}
    for family, words in _FAMILY_WORDS.items():
        hits = sum(1 for w in words if w in tokens)
        if hits:
            scores[family] = scores.get(family, 0) + hits * 2
    for skill in skills:
        family = _SKILL_FAMILY.get(str(getattr(skill, "name", "")).strip().lower(), "")
        if family:
            scores[family] = scores.get(family, 0) + 2
    for token in surface.get("stack") or ():
        family = _STACK_FAMILY.get(token, "")
        if family:
            scores[family] = scores.get(family, 0) + 1
    if not scores:
        return ""
    best = max(scores.values())
    # Ties are undetermined by construction — sorted() only to keep the pick deterministic.
    winners = sorted(f for f, v in scores.items() if v == best)
    return winners[0]


def _pretty_require(token: str) -> str:
    if token.startswith("stack:"):
        return f"`{token.split(':', 1)[1]}` in its dependencies"
    if token.startswith("test:"):
        return f"a {token.split(':', 1)[1]} test suite"
    if token.startswith("pm:"):
        return f"the {token.split(':', 1)[1]} package manager"
    return f"`{token}` in the repo surface"


# Blocked-gate ranks, lowest = closest to firing. A deferral quotes the LOWEST-ranked near-miss,
# because "node isn't installed" is a far more actionable answer than "you have no FastAPI" when the
# user is standing in an Express repo and both rows matched the same words.
_RANK_VERIFY, _RANK_TEMPLATE, _RANK_FILE, _RANK_STACK = 0, 1, 2, 3


def _gate_block(recipe: Recipe, surface: dict[str, Any], root: Path,
                seed_dir: str | Path | None) -> tuple[str, int]:
    """('' , -1) when the recipe may fire here, else (CONCRETE reason, rank). The reason string is
    what makes a deferral honest instead of canned."""
    blob = str(surface.get("gate_blob") or "").lower()
    missing = [t for t in recipe.requires if t.lower() not in blob]
    if missing:
        return "this repo doesn't show " + ", ".join(_pretty_require(t) for t in missing), _RANK_STACK
    absent = [name for name in recipe.requires_file if not (root / name).is_file()]
    if absent:
        return "there is no " + ", ".join(f"`{n}`" for n in absent) + " here", _RANK_FILE
    if recipe.template and _load_snippet(seed_dir, recipe.template) is None and not recipe.fallback:
        # "isn't readable" is the honest claim: _load_snippet cannot tell a missing file from an
        # undecodable one, and asserting which it was would be a fact this code never observed.
        return (f"the bundled template `{recipe.template}` isn't readable in this install",
                _RANK_TEMPLATE)
    if not _gate_available(recipe.verify_hint):
        return (f"the `{recipe.verify_hint}` check isn't available here, and the offline coder never "
                "writes text it cannot verify"), _RANK_VERIFY
    return "", -1


def _gate_reason(recipe: Recipe, surface: dict[str, Any], root: Path,
                 seed_dir: str | Path | None) -> str:
    return _gate_block(recipe, surface, root, seed_dir)[0]


def _ordered(family: str) -> tuple[Recipe, ...]:
    """The registry with the routed family promoted, stably. Recipes with family '' (the freeform
    file row) are never promoted, so the least-specific pattern always stays last."""
    if not family:
        return _REGISTRY
    return tuple(sorted(_REGISTRY, key=lambda r: (0 if r.family == family else 1,)))


def _match_recipe(text: str, surface: dict[str, Any], *, root: Path | None = None,
                  seed_dir: str | Path | None = None,
                  family: str = "") -> tuple[Recipe, re.Match[str]] | None:
    """First recipe whose pattern matches AND whose gates all pass.

    ``text`` is the ORIGINAL message: every pattern is IGNORECASE, so matching the raw string keeps
    captured groups (paths, symbol names, hostnames) in their real casing — lowercasing the message
    first would quietly rename the file the user asked for."""
    base = root or Path(".")
    for recipe in _ordered(family):
        m = recipe.pattern.search(text)
        if not m:
            continue
        if _gate_reason(recipe, surface, base, seed_dir):
            continue
        return recipe, m
    return None


def _blocked(text: str, surface: dict[str, Any], root: Path,
             seed_dir: str | Path | None, family: str) -> list[tuple[Recipe, str]]:
    """Recipes whose PATTERN matched but whose gate refused, with the reason — the near-misses that
    let a deferral say what was actually missing."""
    ranked: list[tuple[int, Recipe, str]] = []
    for recipe in _ordered(family):
        if not recipe.pattern.search(text):
            continue
        reason, rank = _gate_block(recipe, surface, root, seed_dir)
        if reason:
            ranked.append((rank, recipe, reason))
    ranked.sort(key=lambda row: row[0])  # stable: family order breaks ties
    return [(recipe, reason) for _, recipe, reason in ranked]


def _offerable(surface: dict[str, Any], root: Path, seed_dir: str | Path | None,
               family: str = "", limit: int = 6) -> tuple[str, ...]:
    """The labels of the recipes that WOULD fire in this repo — the 'here I can scaffold X and Y'
    half of an honest deferral. Computed from the same gates, so it can never over-promise."""
    labels: list[str] = []
    for recipe in _ordered(family):
        if recipe.name == "new_file":
            continue
        if _gate_reason(recipe, surface, root, seed_dir):
            continue
        if recipe.label not in labels:
            labels.append(recipe.label)
        if len(labels) >= limit:
            break
    return tuple(labels)


_GENERIC_DEFERRAL = (
    "The offline coder handles scaffolds and mechanical edits. This task needs a configured brain — "
    "set up a Local model (Ollama) or Claude in Settings, then re-run."
)


def _needs_brain(summary: str = "", skill: str = "", *, surface: dict[str, Any] | None = None,
                 root: Path | None = None, seed_dir: str | Path | None = None,
                 family: str = "", blocked: list[tuple[Recipe, str]] | None = None) -> dict[str, Any]:
    """Defer to a real brain, naming the CONCRETE gap.

    The old message was one canned paragraph, which left the user guessing which half of their
    request the planner could not do. Here the gap is derived from the SAME gates that refused: what
    this repo can be scaffolded with, and precisely what was missing. Always keeps the words
    "configured brain" — that phrase is the user-facing contract for "offline can't, a brain can"."""
    if summary:
        base = summary
    else:
        parts: list[str] = []
        offerable = (_offerable(surface, root or Path("."), seed_dir, family)
                     if surface is not None else ())
        if offerable:
            shown = ", ".join(offerable[:4])
            parts.append(f"No offline template matches that. In this repo I can scaffold {shown}.")
        else:
            parts.append("No offline template matches that.")
        if blocked:
            recipe, reason = blocked[0]
            parts.append(f"I have a template for {recipe.label}, but {reason}.")
        elif family:
            parts.append(f"There is no {family} template for this request yet.")
        parts.append("Writing it needs a configured brain — set up a Local model (Ollama) or Claude in "
                     "Settings, then re-run.")
        base = " ".join(parts)
    if skill:
        base += f" (The `{skill}` playbook covers this once a brain is enabled.)"
    return {"ops": [], "needs_brain": True, "summary": base}


def plan_edits(message: str, root: str | Path, *, seed_dir: str | Path | None = None,
               runtime_dir: str | Path | None = None) -> dict[str, Any]:
    """Map a request to a CLOSED SET of deterministic edit ops, made repo-specific by retrieval.

    Returns ``{"ops": [...], "needs_brain": bool, "summary": str}``. An op is either
    ``{"kind": "new_file", "path", "content"}`` or a declared intent
    ``{"kind": "edit_op", "path", "op", "args"}`` — never an old_string/new_string pair, which is
    the applier's job to construct and validate. Empty ops + ``needs_brain=True`` means the request
    isn't a templated scaffold: defer to a real brain rather than guess."""
    text = str(message or "").strip()
    if not text:
        return _needs_brain(_GENERIC_DEFERRAL)
    root = Path(root)
    surface = _surface(root, runtime_dir=runtime_dir)
    chosen = _select_skills(text, seed_dir, runtime_dir, root)
    family = _route(text, surface, chosen)
    skill_name = str(getattr(chosen[0], "name", "")) if chosen else ""

    hit = _match_recipe(text, surface, root=root, seed_dir=seed_dir, family=family)
    if hit is None:
        return _needs_brain(skill=skill_name, surface=surface, root=root, seed_dir=seed_dir,
                            family=family, blocked=_blocked(text, surface, root, seed_dir, family))

    recipe, m = hit
    try:
        rel = _safe_rel(recipe.target(m, root, surface))
        slots = dict(recipe.slots(m, root, surface))
    except Exception:  # noqa: BLE001 - a malformed capture must degrade to a deferral, never a crash
        return _needs_brain(skill=skill_name, surface=surface, root=root, seed_dir=seed_dir, family=family)
    if not rel:
        # The requested path escapes the workspace (or is empty). Refuse rather than sanitize it into
        # some other file the user did not ask for.
        return _needs_brain(
            "That path is outside the workspace, so the offline coder won't write it. Give a path "
            "relative to the project root, or use a configured brain for anything beyond it.",
            skill=skill_name)

    if recipe.kind == "new_file":
        body = _load_snippet(seed_dir, recipe.template) if recipe.template else None
        if body is None:
            body = recipe.fallback
        op: dict[str, Any] = {"kind": "new_file", "path": rel, "content": _fill(body, slots)}
    else:
        # Declared INTENT only. The applier re-reads the file, validates the op with `ast`, and
        # builds the edit; a planner that shipped a diff could corrupt a file it never parsed.
        op = {"kind": "edit_op", "path": rel, "op": recipe.kind, "args": slots}

    try:
        summary = recipe.summary(m, root, rel)
    except Exception:  # noqa: BLE001 - a summary is cosmetic; never lose a valid op over one
        summary = f"Applied the `{recipe.name}` recipe to `{rel}`."
    return {"ops": [op], "needs_brain": False, "summary": summary}
