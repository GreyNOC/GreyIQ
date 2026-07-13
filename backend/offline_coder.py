"""Deterministic, no-LLM offline code provider — scaffolds + mechanical edits, verify-gated.

The coding analog of ``bughunter/offline_hunt.py``: a substring-rule planner over the repo that emits
only a small CLOSED SET of edit operations (never free-form text a tiny model would botch). The agent
applies each op through its existing ``ToolBox`` (so every write is snapshotted + undoable) and gates
the result with ``verify``. Honest ceiling: **scaffolds and mechanical edits** — a new test stub, a
new file from a template. Anything it can't confidently map returns ``needs_brain=True``: the offline
coder never guesses business logic; a configured Local/Claude brain should handle those.

This is the Phase-1 skeleton (strategy moves 1-2 — see ``docs/offline-coder-strategy.md``): the
``new_file`` op, the ``add_test`` / ``create_file`` intents, and the plan contract. Retrieval (move 3,
``repomap.search_repo`` + ``seed/snippets/``), the verify->repair loop (move 4), and distillation
(move 5, ``edit_trace.py``) build on this same closed-set-of-ops contract.

Pure / dependency-free: stdlib only, so it stays frozen-safe and runs anywhere the agent runs.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"

# A parameterized template is the ONLY way the offline coder produces file content — never generation.
_PY_TEST_TEMPLATE = '''\
"""Auto-scaffolded test stub for {symbol}. Fill in real assertions."""
from __future__ import annotations

import unittest


class Test{cls}(unittest.TestCase):
    def test_{symbol}_placeholder(self) -> None:
        # TODO: import and exercise {symbol}, then assert its real behavior.
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
'''


def _class_name(symbol: str) -> str:
    """CamelCase a symbol for a test class name (add_user -> AddUser)."""
    parts = [p for p in re.split(r"[_\W]+", str(symbol or "").strip()) if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) or "Thing"


def _safe_rel(candidate: str) -> str:
    """Normalize a user-named path and reject anything that escapes the workspace. ToolBox._resolve
    re-checks containment; this is a friendly early gate so a bad path is a clean 'skip', not a raise."""
    rel = str(candidate or "").strip().strip("`\"'")
    if not rel or rel.startswith(("/", "\\")) or ":" in rel[:3]:
        return ""
    if ".." in Path(rel.replace("\\", "/")).parts:
        return ""
    return rel.replace("\\", "/")


def _needs_brain(summary: str = "") -> dict[str, Any]:
    return {
        "ops": [],
        "needs_brain": True,
        "summary": summary or (
            "The offline coder handles scaffolds and mechanical edits (e.g. \"add a test for "
            "<function>\", \"create a file <path>\"). This task needs a configured brain — set up a "
            "Local model (Ollama) or Claude in Settings, then re-run."
        ),
    }


def plan_edits(message: str, root: str | Path) -> dict[str, Any]:
    """Map a request to a CLOSED SET of deterministic edit ops.

    Returns ``{"ops": [{"kind","path","content"}], "needs_brain": bool, "summary": str}``. Each op is
    one of the closed set (currently ``new_file``); the agent applies it through the ToolBox. Empty
    ops + ``needs_brain=True`` means the request isn't a templated scaffold — defer to a real brain."""
    text = str(message or "").strip()
    if not text:
        return _needs_brain()
    low = text.lower()

    # Intent: "add/create/write a [unit] test [stub] for <symbol>" -> a unittest scaffold.
    m = re.search(
        r"\b(?:add|create|write|generate|scaffold|make)\s+(?:a\s+|an\s+)?(?:unit\s+)?test(?:\s+stub)?\s+for\s+"
        r"(?:the\s+)?(?:function|method|class\s+)?[`'\"]?(" + _IDENT + r")",
        low,
    )
    if m:
        symbol = m.group(1)
        rel = f"test_{symbol}.py"
        content = _PY_TEST_TEMPLATE.format(symbol=symbol, cls=_class_name(symbol))
        return {
            "ops": [{"kind": "new_file", "path": rel, "content": content}],
            "needs_brain": False,
            "summary": f"Scaffolded a unittest stub `{rel}` for `{symbol}` — fill in the real assertions.",
        }

    # Intent: "create/add/make a [new] file <path> [with <text>]" -> a new file (won't overwrite).
    m = re.search(r"\b(?:create|add|make|new)\s+(?:a\s+|an\s+)?(?:new\s+)?file\s+(\S+)", text, re.IGNORECASE)
    if m:
        rel = _safe_rel(m.group(1))
        if rel:
            body = re.search(r"\bwith\s+(.+)$", text, re.IGNORECASE | re.DOTALL)
            content = (body.group(1).strip() + "\n") if body else ""
            return {
                "ops": [{"kind": "new_file", "path": rel, "content": content}],
                "needs_brain": False,
                "summary": f"Created `{rel}`.",
            }

    return _needs_brain()
