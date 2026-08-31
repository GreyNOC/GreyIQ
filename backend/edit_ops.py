"""AST-validated edit operations — the offline coder's hands, and the only reason a
no-LLM edit to an EXISTING file can be trusted.

Until this module the deterministic provider could only CREATE files (``offline_coder``
emitted one op kind, ``new_file``, and refused to overwrite), so it could not touch a real
codebase at all. Letting it edit means letting a rule table rewrite the operator's source —
which is only defensible if an unsafe transform is *impossible to write*, not merely
*likely to be caught later*. That is the invariant here:

    **Every op is realized as a pure (old_string, new_string) pair and the resulting text is
    re-parsed with stdlib ``ast`` BEFORE anything is handed to the ToolBox.** A transform that
    does not parse, drops a statement, deletes a top-level name, or changes a signature is
    REFUSED — the file is never written, so there is nothing to roll back.

That ordering matters. ``agent._tool_verify`` runs ``compile()`` *after* the write; relying on
it would mean shipping broken source and then scrambling to undo it. Validating first keeps the
fail-closed posture the rest of GreyIQ uses (a hunt plan is a targeting hint; the deterministic
prover owns every confirm — here the deterministic parser owns every write).

Every builder is PURE: given the file's CURRENT text it returns an exact edit pair or a refusal
with a reason. It never touches the filesystem. The applier (``agent._run_offline``) feeds that
pair to ``ToolBox._tool_edit_file``, so snapshot/undo/workspace-lock/change-payload and the
``verified_ok`` reset all apply for free and no new write path exists.

FROZEN OP SCHEMA (the interface with ``offline_coder.plan_edits``; the planner declares INTENT
as a plain dict and never imports this module, so the two halves can evolve independently)::

    {"kind": "new_file",  "path": "<workspace-relative>", "content": "<full text>"}
    {"kind": "edit_op",   "path": "<workspace-relative>", "op": <one of OPS>, "args": {...}}

``args`` per op (unknown keys are ignored; a missing required key is a refusal, never a guess):

    insert_anchor  {"anchor": str, "block": str, "position": "after"|"before"}
    add_import     {"module": str, "names": [str, ...], "asname": str}
    add_function   {"name": str, "params": str, "returns": str, "body": str,
                    "decorators": [str, ...], "after_symbol": str}
    add_field      {"target_class": str, "field": str, "annotation": str, "default": str|None}
    wrap_ast       {"target_fn": str, "transform": <one of _TRANSFORMS>,
                    "decorator": str (decorate only), "param": str (guard_none only)}

An op kind or op name outside these closed sets degrades to a refusal (the applier turns that
into an ``is_error`` transcript row), never a crash and never free-form code execution.
``_TRANSFORMS`` is deliberately a closed set of three named rewrites: a caller cannot hand
``wrap_ast`` a snippet to splice in, so "the planner emitted arbitrary code" is not a reachable
state.

COVERAGE RULE — an op may only run on a file type ``_tool_verify`` can actually gate. ``.py``
and ``.json`` are validated in-process here; ``.yml``/``.yaml`` need PyYAML importable;
``.js``/``.cjs``/``.mjs``/``.sh`` need ``allow_commands`` AND ``node``/``bash`` on PATH (the same
conditions ``_check_node_syntax``/``_check_shell_syntax`` require). When the gate is unavailable
the op is REFUSED rather than shipping text nothing can check. Anything else — Markdown, plain
text, an extensionless file — has no verify gate at all and is refused for the same reason.

Pure / dependency-free / frozen-safe: stdlib only (``ast``, ``collections``, ``json``, ``re``,
``shutil``, ``textwrap``). PyYAML is touched only through a guarded optional import.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import textwrap
from collections import Counter
from dataclasses import dataclass
from typing import Any

__all__ = ["OPS", "OpResult", "py_parses", "realize"]


@dataclass(frozen=True, slots=True)
class OpResult:
    """The outcome of realizing one op against one file's current text.

    ``ok=True`` means (old_string, new_string) is a validated edit pair: ``old_string`` occurs
    EXACTLY once in the text it was built from, and applying it produces source that already
    re-parsed cleanly. ``ok=False`` carries a human ``reason`` and NO edit — the caller must
    treat that as "leave the file alone", never as "try something close"."""

    ok: bool
    old_string: str = ""
    new_string: str = ""
    reason: str = ""


#: The closed set of op names. Anything else is a refusal.
OPS: tuple[str, ...] = ("insert_anchor", "add_import", "add_function", "add_field", "wrap_ast")

#: The closed set of ``wrap_ast`` rewrites. Named transforms only — never free-form code.
_TRANSFORMS: tuple[str, ...] = ("try_except_log", "guard_none", "decorate")

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DOTTED_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_LEADING_WS_RE = re.compile(r"[ \t]*")

_YAML_SUFFIXES = frozenset({".yml", ".yaml"})
#: suffix -> the external binary whose syntax check verify would use.
_COMMAND_GATED: dict[str, str] = {".js": "node", ".cjs": "node", ".mjs": "node", ".sh": "bash"}

# Statement types that own a nested statement body. Their ``ast.dump`` legitimately changes when
# something is inserted INTO them, so the "no statement was dropped" post-check compares only
# simple (leaf) statements — whose dump is invariant under re-parenting and re-indentation.
_COMPOUND_STMTS: tuple[type, ...] = tuple(
    node
    for node in (
        getattr(ast, name, None)
        for name in (
            "If", "For", "AsyncFor", "While", "With", "AsyncWith", "Try", "TryStar",
            "FunctionDef", "AsyncFunctionDef", "ClassDef", "Match",
        )
    )
    if isinstance(node, type)
)

_DEF_STMTS: tuple[type, ...] = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

# How many extra lines of leading context an edit pair may absorb while trying to become unique.
# A pair that still is not unique after this is refused: ToolBox._apply_one_edit would reject it
# anyway, and guessing which match to hit is exactly what this module exists to prevent.
_MAX_CONTEXT_GROW = 40


# --------------------------------------------------------------------------------------
# Parsing / fingerprinting helpers
# --------------------------------------------------------------------------------------


def py_parses(source: str, filename: str = "<offline-op>") -> str:
    """Return '' when ``source`` is parseable Python, else the parser's error text.

    Deliberately returns a string rather than raising: every caller here is deciding whether to
    REFUSE, and a refusal reason is more useful than a traceback. ``ast.parse`` (not ``compile``)
    because we only care about grammar — the semantic errors ``compile`` adds are not the ones a
    mechanical edit introduces."""
    try:
        ast.parse(source, filename=filename)
    except SyntaxError as exc:
        line = f", line {exc.lineno}" if exc.lineno else ""
        return f"{exc.msg}{line}"
    except ValueError as exc:  # e.g. source containing a NUL byte
        return str(exc)
    return ""


def _parse(source: str) -> ast.Module | None:
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError):
        return None


def _toplevel_names(tree: ast.AST) -> set[str]:
    """Every name bound at module top level. The post-condition ``after >= before`` on this set is
    what makes "an op may add a name, never delete one" checkable rather than aspirational."""
    names: set[str] = set()
    for node in getattr(tree, "body", None) or []:
        if isinstance(node, _DEF_STMTS):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
    return names


def _stmt_fingerprints(body: list[ast.stmt]) -> list[str]:
    """Position-free structural identity of a statement list. ``include_attributes=False`` is the
    whole point: re-indenting or re-parenting a statement must NOT change its fingerprint, so a
    surviving statement is recognizable no matter where a transform moved it."""
    return [ast.dump(stmt, include_attributes=False) for stmt in body]


def _walk_stmt_fingerprints(node: ast.AST) -> list[str]:
    return [ast.dump(n, include_attributes=False) for n in ast.walk(node) if isinstance(n, ast.stmt)]


def _simple_stmt_fingerprints(node: ast.AST) -> list[str]:
    return [
        ast.dump(n, include_attributes=False)
        for n in ast.walk(node)
        if isinstance(n, ast.stmt) and not isinstance(n, _COMPOUND_STMTS)
    ]


def _def_count(tree: ast.AST) -> int:
    return sum(1 for node in ast.walk(tree) if isinstance(node, _DEF_STMTS))


def _missing(before: list[str], after: list[str]) -> int:
    """How many of ``before``'s fingerprints are unaccounted for in ``after`` (multiset)."""
    return sum((Counter(before) - Counter(after)).values())


def _is_docstring(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


# --------------------------------------------------------------------------------------
# Text/span helpers — every op ends as a (old_string, new_string) pair over whole lines
# --------------------------------------------------------------------------------------


def _line_bounds(text: str, index: int) -> tuple[int, int]:
    """(start-of-line, one-past-its-newline) for the line containing ``index``."""
    start = text.rfind("\n", 0, index) + 1
    newline = text.find("\n", index)
    return start, (len(text) if newline < 0 else newline + 1)


def _line_offsets(text: str) -> list[int]:
    offsets = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def _span_for_lines(text: str, first: int, last: int) -> tuple[int, int]:
    """Char offsets covering the 1-based inclusive line range [first, last], including the
    trailing newline of ``last`` when there is one."""
    offsets = _line_offsets(text)
    start = offsets[first - 1] if 0 < first <= len(offsets) else len(text)
    end = offsets[last] if 0 < last < len(offsets) else len(text)
    return start, max(start, end)


def _leading_ws(text: str, start: int) -> str:
    return _LEADING_WS_RE.match(text, start).group(0)  # type: ignore[union-attr]


def _grow_unique_start(text: str, start: int, end: int) -> int | None:
    """Walk ``start`` backwards a whole line at a time until ``text[start:end]`` occurs exactly
    once. Returns None when uniqueness is unreachable within the cap — the op then refuses rather
    than handing ToolBox a pair it would reject (or, worse, one that matches the wrong place)."""
    grown = 0
    while grown <= _MAX_CONTEXT_GROW:
        if text.count(text[start:end]) == 1:
            return start
        if start <= 0:
            return None
        start = text.rfind("\n", 0, start - 1) + 1
        grown += 1
    return None


def _edit_pair(text: str, start: int, end: int, replacement: str) -> tuple[str, str, str] | None:
    """Build the (old_string, new_string, resulting_text) triple that replaces ``text[start:end]``
    with ``replacement``, absorbing leading context until ``old_string`` is unique."""
    grown = _grow_unique_start(text, start, end)
    if grown is None:
        return None
    old = text[grown:end]
    new = text[grown:start] + replacement
    return old, new, text[:grown] + new + text[end:]


def _seal(text: str, old: str, new: str, new_text: str) -> OpResult:
    """Final self-check before an op is declared ok. Re-derives the write the applier will
    actually perform (``ToolBox._apply_one_edit`` semantics) and requires it to reproduce the
    exact text that passed validation — so a builder bug can never smuggle unvalidated bytes
    onto disk."""
    if not old:
        return OpResult(False, reason="internal: empty anchor")
    if text.count(old) != 1:
        return OpResult(False, reason="internal: the computed anchor is not unique")
    if text.replace(old, new, 1) != new_text:
        return OpResult(False, reason="internal: the edit pair does not reproduce the validated text")
    return OpResult(True, old_string=old, new_string=new)


# --------------------------------------------------------------------------------------
# Verify-gate coverage
# --------------------------------------------------------------------------------------


def _gate_reason(suffix: str, allow_commands: bool) -> str:
    """'' when ``_tool_verify`` can gate this file type under the current settings, else the
    reason we refuse. Coverage may only grow where verify can check the result."""
    if suffix == ".py" or suffix == ".json":
        return ""
    if suffix in _YAML_SUFFIXES:
        try:
            import yaml  # type: ignore[import-untyped]  # noqa: F401
        except ImportError:
            return "PyYAML is not installed, so verify cannot gate a YAML edit — refusing to ship unverifiable text"
        return ""
    tool = _COMMAND_GATED.get(suffix)
    if tool:
        if not allow_commands:
            return (
                f"{tool} syntax checking needs commands enabled, so verify cannot gate a "
                f"'{suffix}' edit — refusing to ship unverifiable text"
            )
        if not shutil.which(tool):
            return (
                f"{tool} is not on PATH, so verify cannot gate a '{suffix}' edit — "
                "refusing to ship unverifiable text"
            )
        return ""
    return (
        f"verify has no syntax gate for '{suffix or 'extensionless'}' files — "
        "refusing to ship unverifiable text"
    )


def _validate_non_python(new_text: str, suffix: str) -> str:
    """In-process structural check for the non-Python types we CAN parse without a subprocess.
    ``.js``/``.sh`` have no stdlib parser, so their gate is the (already-confirmed-available)
    ``node --check`` / ``bash -n`` pass that ``verify`` runs right after the write."""
    if suffix == ".json":
        try:
            json.loads(new_text)
        except ValueError as exc:
            return f"the result is not valid JSON: {exc}"
        return ""
    if suffix in _YAML_SUFFIXES:
        try:
            import yaml  # type: ignore[import-untyped]

            yaml.safe_load(new_text)
        except ImportError:
            return "PyYAML is not installed; the YAML result cannot be checked"
        except Exception as exc:  # noqa: BLE001 - PyYAML raises several parser types; any of them means "do not write"
            return f"the result is not valid YAML: {exc}"
    return ""


def _python_insertion_ok(before_text: str, after_text: str) -> str:
    """The COMMON post-condition for a pure insertion into a ``.py`` file: it parses, no top-level
    name disappeared, no top-level statement disappeared, and every pre-existing simple statement
    survives byte-identical. Catches the realistic mechanical-edit failure — an insertion at the
    wrong indentation that silently re-parents or truncates surrounding code."""
    err = py_parses(after_text)
    if err:
        return f"the result does not parse: {err}"
    before = _parse(before_text)
    after = _parse(after_text)
    if before is None or after is None:
        return "the result does not parse"
    if not _toplevel_names(after) >= _toplevel_names(before):
        missing = sorted(_toplevel_names(before) - _toplevel_names(after))
        return f"the edit would remove top-level name(s): {', '.join(missing)}"
    if len(after.body) < len(before.body):
        return "the edit would remove a top-level statement"
    if _missing(_simple_stmt_fingerprints(before), _simple_stmt_fingerprints(after)):
        return "the edit would drop or alter an existing statement"
    return ""


def _require_current_python(text: str) -> str:
    """Refuse to AST-edit a file that does not parse RIGHT NOW. Without this the post-checks have
    no trustworthy baseline, and 'the result does not parse' would be blamed on our edit."""
    err = py_parses(text)
    return f"the file does not currently parse ({err}); refusing to edit it blind" if err else ""


# --------------------------------------------------------------------------------------
# The ops
# --------------------------------------------------------------------------------------


def _op_insert_anchor(text: str, args: dict[str, Any], *, suffix: str, allow_commands: bool) -> OpResult:
    anchor = str(args.get("anchor") or "")
    block = str(args.get("block") or "")
    position = str(args.get("position") or "after").strip().lower()
    if not anchor:
        return OpResult(False, reason="anchor must not be empty")
    if not block.strip():
        return OpResult(False, reason="block must not be empty")
    if position not in ("after", "before"):
        return OpResult(False, reason=f"unknown position '{position}'; use 'after' or 'before'")
    count = text.count(anchor)
    if count == 0:
        return OpResult(False, reason="anchor was not found in the file")
    if count > 1:
        # Same semantics as ToolBox._apply_one_edit: more than one match means we do not know
        # which site was meant, and guessing is how a mechanical edit corrupts a file.
        return OpResult(False, reason=f"anchor is not unique ({count} matches); refusing to guess which one")
    gate = _gate_reason(suffix, allow_commands)
    if gate:
        return OpResult(False, reason=gate)
    if suffix == ".py":
        stale = _require_current_python(text)
        if stale:
            return OpResult(False, reason=stale)

    start = text.index(anchor)
    line_start, _ = _line_bounds(text, start)
    _, line_end = _line_bounds(text, start + len(anchor) - 1)
    span = text[line_start:line_end]
    lead = _leading_ws(text, line_start)
    body = textwrap.indent(textwrap.dedent(block).strip("\n") + "\n", lead)
    if position == "after":
        replacement = (span if span.endswith("\n") else span + "\n") + body
    else:
        replacement = body + span

    pair = _edit_pair(text, line_start, line_end, replacement)
    if pair is None:
        return OpResult(False, reason="could not build a unique edit anchor for this insertion")
    old, new, new_text = pair
    if suffix == ".py":
        err = _python_insertion_ok(text, new_text)
    else:
        err = _validate_non_python(new_text, suffix)
    if err:
        return OpResult(False, reason=err)
    return _seal(text, old, new, new_text)


def _already_imported(tree: ast.Module, module: str, names: list[str], asname: str) -> bool:
    for node in tree.body:
        if names:
            if isinstance(node, ast.ImportFrom) and (node.module or "") == module and not node.level:
                have = {alias.name for alias in node.names}
                if set(names) <= have:
                    return True
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == module and (alias.asname or "") == asname:
                    return True
    return False


def _op_add_import(text: str, args: dict[str, Any], *, suffix: str, allow_commands: bool) -> OpResult:
    if suffix != ".py":
        return OpResult(False, reason="add_import only applies to .py files")
    module = str(args.get("module") or "").strip()
    raw_names = args.get("names") or ()
    names = [str(n).strip() for n in raw_names if str(n).strip()] if isinstance(raw_names, (list, tuple)) else []
    asname = str(args.get("asname") or "").strip()
    if not module or not _DOTTED_RE.fullmatch(module):
        return OpResult(False, reason=f"'{module}' is not a valid module name")
    for name in names:
        if not _IDENT_RE.fullmatch(name):
            return OpResult(False, reason=f"'{name}' is not a valid imported name")
    if asname and not _IDENT_RE.fullmatch(asname):
        return OpResult(False, reason=f"'{asname}' is not a valid alias")
    stale = _require_current_python(text)
    if stale:
        return OpResult(False, reason=stale)
    before = _parse(text)
    if before is None:
        return OpResult(False, reason="the file does not currently parse")
    if _already_imported(before, module, names, asname):
        # Idempotency is a REFUSAL, not a no-op write: the planner skips silently and the
        # transcript records why, instead of the file being rewritten identically.
        return OpResult(False, reason="already imported")

    if names:
        tail = names[0] + (f" as {asname}" if asname and len(names) == 1 else "")
        rendered = ", ".join([tail] + names[1:])
        statement = f"from {module} import {rendered}\n"
    else:
        statement = f"import {module}" + (f" as {asname}" if asname else "") + "\n"
    err = py_parses(statement, "<add_import fragment>")
    if err:
        return OpResult(False, reason=f"the import statement does not parse: {err}")

    body = before.body
    index = 1 if body and _is_docstring(body[0]) else 0
    docstring = body[0] if index == 1 else None
    last_import: ast.stmt | None = None
    while index < len(body) and isinstance(body[index], (ast.Import, ast.ImportFrom)):
        last_import = body[index]
        index += 1

    if last_import is not None:
        start, end = _span_for_lines(text, last_import.lineno, last_import.end_lineno or last_import.lineno)
        anchor_text = text[start:end]
        replacement = (anchor_text if anchor_text.endswith("\n") else anchor_text + "\n") + statement
    elif docstring is not None:
        start, end = _span_for_lines(text, docstring.lineno, docstring.end_lineno or docstring.lineno)
        anchor_text = text[start:end]
        replacement = (anchor_text if anchor_text.endswith("\n") else anchor_text + "\n") + "\n" + statement
    else:
        if not text.strip():
            return OpResult(False, reason="the file is empty; use a new_file op instead")
        start, end = _line_bounds(text, 0)
        replacement = statement + text[start:end]

    pair = _edit_pair(text, start, end, replacement)
    if pair is None:
        return OpResult(False, reason="could not build a unique edit anchor for the import block")
    old, new, new_text = pair
    err = py_parses(new_text)
    if err:
        return OpResult(False, reason=f"the result does not parse: {err}")
    after = _parse(new_text)
    if after is None:
        return OpResult(False, reason="the result does not parse")
    # Exactly ONE new top-level statement, it is an import, and every other statement is
    # byte-identical — an import op that moved or rewrote real code is a bug, not an import.
    if len(after.body) != len(before.body) + 1:
        return OpResult(False, reason="the import op changed more than one top-level statement")
    before_fp = _stmt_fingerprints(before.body)
    after_fp = _stmt_fingerprints(after.body)
    added_at = next(
        (i for i in range(len(after_fp)) if i >= len(before_fp) or after_fp[i] != before_fp[i]),
        None,
    )
    if added_at is None:
        return OpResult(False, reason="the import op did not add a statement")
    if after_fp[added_at + 1:] != before_fp[added_at:]:
        return OpResult(False, reason="the import op altered an existing top-level statement")
    if not isinstance(after.body[added_at], (ast.Import, ast.ImportFrom)):
        return OpResult(False, reason="the statement the import op added is not an import")
    return _seal(text, old, new, new_text)


def _op_add_function(text: str, args: dict[str, Any], *, suffix: str, allow_commands: bool) -> OpResult:
    if suffix != ".py":
        return OpResult(False, reason="add_function only applies to .py files")
    name = str(args.get("name") or "").strip()
    if not _IDENT_RE.fullmatch(name):
        return OpResult(False, reason=f"'{name}' is not a valid function name")
    params = str(args.get("params") or "").strip()
    returns = str(args.get("returns") or "").strip()
    body_src = str(args.get("body") or "").strip("\n") or "pass"
    raw_decorators = args.get("decorators") or ()
    decorators = (
        [str(d).strip().lstrip("@") for d in raw_decorators if str(d).strip()]
        if isinstance(raw_decorators, (list, tuple))
        else []
    )
    after_symbol = str(args.get("after_symbol") or "").strip()

    fragment = "".join(f"@{d}\n" for d in decorators)
    fragment += f"def {name}({params})" + (f" -> {returns}" if returns else "") + ":\n"
    fragment += textwrap.indent(textwrap.dedent(body_src).rstrip("\n") + "\n", "    ")
    # Parse the FRAGMENT ALONE first: a bad signature or body is caught before the target file is
    # even read for editing, so a malformed request cannot become a half-written file.
    err = py_parses(fragment, "<add_function fragment>")
    if err:
        return OpResult(False, reason=f"the function fragment does not parse: {err}")
    frag = _parse(fragment)
    if frag is None or len(frag.body) != 1 or not isinstance(frag.body[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
        return OpResult(False, reason="the fragment must be exactly one function definition")
    if frag.body[0].name != name:
        return OpResult(False, reason="the fragment defines a different function than requested")

    stale = _require_current_python(text)
    if stale:
        return OpResult(False, reason=stale)
    before = _parse(text)
    if before is None:
        return OpResult(False, reason="the file does not currently parse")
    if name in _toplevel_names(before):
        return OpResult(False, reason=f"'{name}' already exists at top level; the offline coder never shadows a name")

    anchor: ast.stmt | None = None
    if after_symbol:
        for node in before.body:
            if getattr(node, "name", "") == after_symbol:
                anchor = node
        if anchor is None:
            return OpResult(False, reason=f"after_symbol '{after_symbol}' is not a top-level definition")
    else:
        for node in before.body:
            if isinstance(node, _DEF_STMTS):
                anchor = node

    if anchor is not None:
        start, end = _span_for_lines(text, anchor.lineno, anchor.end_lineno or anchor.lineno)
        anchor_text = text[start:end]
        replacement = (anchor_text if anchor_text.endswith("\n") else anchor_text + "\n") + "\n\n" + fragment
    else:
        stripped = text.rstrip("\n")
        if not stripped.strip():
            return OpResult(False, reason="the file is empty; use a new_file op instead")
        start, _ = _line_bounds(text, len(stripped) - 1)
        end = len(text)
        tail = text[start:end].rstrip("\n") + "\n"
        replacement = tail + "\n\n" + fragment

    pair = _edit_pair(text, start, end, replacement)
    if pair is None:
        return OpResult(False, reason="could not build a unique edit anchor for the new function")
    old, new, new_text = pair
    err = py_parses(new_text)
    if err:
        return OpResult(False, reason=f"the result does not parse: {err}")
    after = _parse(new_text)
    if after is None:
        return OpResult(False, reason="the result does not parse")
    added = _toplevel_names(after) - _toplevel_names(before)
    if added != {name}:
        return OpResult(False, reason=f"adding '{name}' would change the top-level names to {sorted(added)}")
    if _missing(_stmt_fingerprints(before.body), _stmt_fingerprints(after.body)):
        return OpResult(False, reason="the edit would drop or alter an existing top-level statement")
    return _seal(text, old, new, new_text)


def _class_field_names(cls: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for stmt in cls.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            names.add(stmt.target.id)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _is_dataclass_decorated(cls: ast.ClassDef) -> bool:
    for decorator in cls.decorator_list:
        node = decorator.func if isinstance(decorator, ast.Call) else decorator
        label = node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")
        if "dataclass" in str(label):
            return True
    return False


def _op_add_field(text: str, args: dict[str, Any], *, suffix: str, allow_commands: bool) -> OpResult:
    if suffix != ".py":
        return OpResult(False, reason="add_field only applies to .py files")
    target_class = str(args.get("target_class") or "").strip()
    field = str(args.get("field") or "").strip()
    annotation = str(args.get("annotation") or "").strip()
    default = args.get("default")
    if not _IDENT_RE.fullmatch(target_class):
        return OpResult(False, reason=f"'{target_class}' is not a valid class name")
    if not _IDENT_RE.fullmatch(field):
        return OpResult(False, reason=f"'{field}' is not a valid field name")
    if not annotation:
        return OpResult(False, reason="annotation must not be empty")

    stale = _require_current_python(text)
    if stale:
        return OpResult(False, reason=stale)
    before = _parse(text)
    if before is None:
        return OpResult(False, reason="the file does not currently parse")
    cls = next((n for n in before.body if isinstance(n, ast.ClassDef) and n.name == target_class), None)
    if cls is None:
        nested = any(isinstance(n, ast.ClassDef) and n.name == target_class for n in ast.walk(before))
        return OpResult(
            False,
            reason=(
                f"class '{target_class}' is nested; add_field only edits top-level classes"
                if nested
                else f"class '{target_class}' was not found at top level"
            ),
        )
    if field in _class_field_names(cls):
        return OpResult(False, reason=f"'{field}' already exists on {target_class}")
    # DATACLASS ORDERING GUARD. `x: int` after `y: int = 0` is a TypeError raised at IMPORT time by
    # @dataclass — grammatically perfect, so ast.parse accepts it and _tool_verify's compile() would
    # never see it. This is the one failure class the post-parse gate structurally cannot catch, so
    # it is refused up front rather than shipped and discovered at runtime.
    if _is_dataclass_decorated(cls) and default is None:
        defaulted = [
            stmt.target.id
            for stmt in cls.body
            if isinstance(stmt, ast.AnnAssign) and stmt.value is not None and isinstance(stmt.target, ast.Name)
        ]
        if defaulted:
            return OpResult(
                False,
                reason=(
                    f"dataclass ordering: a field without a default cannot follow defaulted "
                    f"field(s) {', '.join(defaulted)} — that is a TypeError at import time"
                ),
            )

    anchor: ast.stmt | None = None
    for stmt in cls.body:
        if isinstance(stmt, (ast.AnnAssign, ast.Assign)):
            anchor = stmt
    if anchor is None and cls.body and _is_docstring(cls.body[0]):
        anchor = cls.body[0]
    reference = anchor if anchor is not None else (cls.body[0] if cls.body else None)
    if reference is None:
        return OpResult(False, reason=f"class '{target_class}' has no body to anchor on")
    indent = _leading_ws(text, _span_for_lines(text, reference.lineno, reference.lineno)[0])
    if not indent:
        return OpResult(False, reason="the class body is on the class header line; refusing to edit it")
    line = f"{indent}{field}: {annotation}" + (f" = {default}" if default is not None else "") + "\n"
    err = py_parses(textwrap.dedent(line), "<add_field fragment>")
    if err:
        return OpResult(False, reason=f"the field declaration does not parse: {err}")

    start, end = _span_for_lines(text, reference.lineno, reference.end_lineno or reference.lineno)
    anchor_text = text[start:end]
    if anchor is not None:
        replacement = (anchor_text if anchor_text.endswith("\n") else anchor_text + "\n") + line
    else:
        replacement = line + anchor_text

    pair = _edit_pair(text, start, end, replacement)
    if pair is None:
        return OpResult(False, reason="could not build a unique edit anchor for the new field")
    old, new, new_text = pair
    err = py_parses(new_text)
    if err:
        return OpResult(False, reason=f"the result does not parse: {err}")
    after = _parse(new_text)
    if after is None:
        return OpResult(False, reason="the result does not parse")
    after_cls = next((n for n in after.body if isinstance(n, ast.ClassDef) and n.name == target_class), None)
    if after_cls is None:
        return OpResult(False, reason=f"the edit removed class '{target_class}'")
    if len(after_cls.body) != len(cls.body) + 1:
        return OpResult(False, reason="the field op changed more than one statement in the class body")
    if _missing(_stmt_fingerprints(cls.body), _stmt_fingerprints(after_cls.body)):
        return OpResult(False, reason="the field op altered an existing class-body statement")
    added = next(
        (
            stmt
            for stmt in after_cls.body
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == field
        ),
        None,
    )
    if added is None:
        return OpResult(False, reason=f"the field op did not add an annotated '{field}'")
    return _seal(text, old, new, new_text)


def _op_wrap_ast(text: str, args: dict[str, Any], *, suffix: str, allow_commands: bool) -> OpResult:
    if suffix != ".py":
        return OpResult(False, reason="wrap_ast only applies to .py files")
    target_fn = str(args.get("target_fn") or "").strip()
    transform = str(args.get("transform") or "").strip()
    if not _IDENT_RE.fullmatch(target_fn):
        return OpResult(False, reason=f"'{target_fn}' is not a valid function name")
    if transform not in _TRANSFORMS:
        return OpResult(
            False, reason=f"unknown transform '{transform}'; the closed set is {', '.join(_TRANSFORMS)}"
        )
    stale = _require_current_python(text)
    if stale:
        return OpResult(False, reason=stale)
    before = _parse(text)
    if before is None:
        return OpResult(False, reason="the file does not currently parse")
    matches = [
        node
        for node in ast.walk(before)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == target_fn
    ]
    if not matches:
        return OpResult(False, reason=f"function '{target_fn}' was not found")
    if len(matches) > 1:
        return OpResult(False, reason=f"function '{target_fn}' is defined {len(matches)} times; refusing to guess")
    node = matches[0]

    if transform == "decorate":
        decorator = str(args.get("decorator") or "").strip().lstrip("@")
        if not decorator:
            return OpResult(False, reason="decorate needs a 'decorator' argument")
        err = py_parses(f"@{decorator}\ndef _greyiq_decorator_probe() -> None:\n    pass\n", "<decorator fragment>")
        if err:
            return OpResult(False, reason=f"the decorator does not parse: {err}")
        first_line = min([d.lineno for d in node.decorator_list] + [node.lineno])
        start, end = _span_for_lines(text, first_line, first_line)
        indent = _leading_ws(text, start)
        anchor_text = text[start:end]
        replacement = f"{indent}@{decorator}\n" + anchor_text
    else:
        body = node.body
        offset = 1 if body and _is_docstring(body[0]) else 0
        real = body[offset:]
        if not real:
            return OpResult(False, reason=f"'{target_fn}' has no body to transform (docstring only)")
        start, end = _span_for_lines(text, real[0].lineno, node.end_lineno or real[-1].end_lineno or real[0].lineno)
        block = text[start:end]
        if not block.endswith("\n"):
            block += "\n"
        indent = _leading_ws(text, start)
        if transform == "try_except_log":
            replacement = (
                f"{indent}try:\n"
                + textwrap.indent(block, "    ")
                + f"{indent}except Exception:\n"
                f"{indent}    import logging\n"
                f'{indent}    logging.getLogger(__name__).exception("{target_fn} failed")\n'
                f"{indent}    raise\n"
            )
        else:  # guard_none
            arg_names = [a.arg for a in (node.args.posonlyargs + node.args.args)]
            requested = str(args.get("param") or "").strip()
            if requested:
                if requested not in arg_names:
                    return OpResult(False, reason=f"'{target_fn}' has no parameter '{requested}'")
                param = requested
            else:
                candidates = [a for a in arg_names if a not in ("self", "cls")]
                if not candidates:
                    return OpResult(False, reason=f"'{target_fn}' takes no parameter to guard")
                param = candidates[0]
            replacement = f"{indent}if {param} is None:\n{indent}    return None\n" + block

    pair = _edit_pair(text, start, end, replacement)
    if pair is None:
        return OpResult(False, reason="could not build a unique edit anchor for the transform")
    old, new, new_text = pair
    err = py_parses(new_text)
    if err:
        return OpResult(False, reason=f"the result does not parse: {err}")
    after = _parse(new_text)
    if after is None:
        return OpResult(False, reason="the result does not parse")
    after_matches = [
        n
        for n in ast.walk(after)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == target_fn
    ]
    if len(after_matches) != 1:
        return OpResult(False, reason="the transform changed how many times the function is defined")
    if ast.dump(after_matches[0].args, include_attributes=False) != ast.dump(node.args, include_attributes=False):
        return OpResult(False, reason="the transform changed the function signature")
    if _def_count(after) != _def_count(before):
        return OpResult(False, reason="the transform added or removed a definition")
    # SUBTREE CONTAINMENT — the re-indentation a wrap performs would silently rewrite the contents
    # of a multi-line string literal; a changed literal changes its fingerprint, so that shows up
    # here as a dropped statement and the write is refused.
    if _missing(_stmt_fingerprints(node.body), _walk_stmt_fingerprints(after_matches[0])):
        return OpResult(False, reason="the transform would drop or alter a statement in the function body")
    return _seal(text, old, new, new_text)


_BUILDERS = {
    "insert_anchor": _op_insert_anchor,
    "add_import": _op_add_import,
    "add_function": _op_add_function,
    "add_field": _op_add_field,
    "wrap_ast": _op_wrap_ast,
}


def realize(
    text: str,
    op: str,
    args: dict[str, Any],
    *,
    suffix: str,
    allow_commands: bool = False,
) -> OpResult:
    """Realize one op against a file's CURRENT text. The single entry point the applier calls.

    ``suffix`` is the target's lowercased extension (it decides which verify gate must exist) and
    ``allow_commands`` mirrors the ToolBox setting (``node --check`` / ``bash -n`` only exist when
    commands are enabled). Never raises: an unknown op, malformed args, or an internal error all
    become ``OpResult(ok=False, reason=...)``, because the applier's contract is "a bad op is a
    transcript row, never a crashed run"."""
    name = str(op or "").strip()
    builder = _BUILDERS.get(name)
    if builder is None:
        return OpResult(False, reason=f"unknown edit op '{name}'; the closed set is {', '.join(OPS)}")
    try:
        return builder(
            str(text or ""),
            dict(args or {}),
            suffix=str(suffix or "").strip().lower(),
            allow_commands=bool(allow_commands),
        )
    except Exception as exc:  # noqa: BLE001 - a builder bug must degrade to a refusal, never abort the run
        return OpResult(False, reason=f"edit op failed: {type(exc).__name__}: {exc}")
