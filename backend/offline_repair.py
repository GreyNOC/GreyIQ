"""Deterministic verify -> repair loop for the offline coder (offline-coder strategy, move 4).

Move 4 was deferred on purpose while the offline provider only emitted pre-vetted `new_file`
templates that always passed verify. ``edit_ops`` changes that: the coder now rewrites files the
operator already owns, so "verify failed" became a state that can actually happen — and the only
acceptable answer to it, with no model in the loop, is a table of KNOWN failures mapped to KNOWN
responses, defaulting to *undo*.

The governing rule here is **REVERT BY DEFAULT**. A repair is attempted only for the handful of
failures whose cause is unambiguous from the verify text itself; for everything else the run puts
the file back exactly as it found it and says so. Nothing in this module ever "fixes" code by
guessing — that is what a configured brain is for, and deferring to one is the honest outcome.

Three deliberate hard edges:

  * **A secret finding is a HARD STOP.** ``_tool_verify``'s ``.env.example`` scanner flagging a
    likely-real credential gets ZERO repair attempts. Auto-editing a secret finding would either
    hide it or rewrite it into some other file; both are worse than stopping. Revert, surface the
    finding text verbatim, stop the loop.
  * **A file this run did not create is never "repaired".** The test-scaffold repair only ever
    touches a test module this same run wrote, matched by the exact scaffold name it emits.
  * **Its own bug scanner can veto the ship.** ``scanner_gate`` runs ``bughunter.code_scanner``
    over just the touched paths; a new HIGH/CRITICAL finding blocks the run. A tool that ships
    code its own scanner flags has no business flagging anyone else's.

Grammar coupling is deliberate: ``parse_verify_report`` keys on ``agent._tool_verify``'s OWN
literal line formats (``FAIL <rel>: <msg>``, ``FAIL <rel>: node --check failed…``, ``FAIL tests
failed (<label>)…``). That coupling is what makes the table testable against strings copied
straight from the producer instead of against a mock.

Pure / dependency-free / frozen-safe: stdlib + intra-repo imports only. Every optional dependency
(``repomap``, ``bughunter.code_scanner``) is imported behind a guard — absent means "propose
nothing / gate nothing", which degrades to plain revert-and-report, never a crash.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import edit_ops

__all__ = [
    "Failure",
    "hard_stop",
    "parse_verify_report",
    "propose_repairs",
    "repair_loop",
    "restore_all",
    "scanner_gate",
]


@dataclass(frozen=True, slots=True)
class Failure:
    """One ``FAIL`` row parsed out of a verify report.

    ``path`` is the workspace-relative file, or '' for a whole-run failure (the test suite, the
    configured verify command). ``check`` is the normalized gate name — the key the repair table
    dispatches on — and is 'unknown' rather than a guess when the line does not match any known
    producer format."""

    path: str
    check: str
    message: str
    line: int | None = None


# Repair rounds are clamped here as well as in settings: each round is a FULL verify pass (which
# can run the project's test suite), so an out-of-range value must cost bounded time, not spin.
_MAX_ROUNDS_CEILING = 3

# check name -> matcher against the message that follows "FAIL <rel>: ". Order matters; the first
# match wins and the fallback keys off the file suffix instead.
_CHECK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("secrets", re.compile(r"^likely real secrets in example file")),
    ("node", re.compile(r"^node --check failed")),
    ("node", re.compile(r"^ecosystem config did not load")),
    ("bash", re.compile(r"^bash syntax check failed")),
    ("yaml", re.compile(r"^YAML parse failed")),
    ("toml", re.compile(r"^TOML parse failed")),
    ("ini", re.compile(r"^config parse failed")),
    ("dockerfile", re.compile(r"^unknown Dockerfile directive")),
    ("powershell", re.compile(r"^PowerShell parse failed")),
)

_TESTS_RE = re.compile(r"^tests failed \((?P<label>[^)]*)\)(?::\s*(?P<detail>.*))?$")
_SUFFIX_CHECKS = {".py": "python", ".json": "json", ".yml": "yaml", ".yaml": "yaml"}
_LINE_RE = re.compile(r"\bline (\d+)")

# Lines that begin a NEW verify row; anything else after a FAIL is that failure's own multi-line
# detail tail (`_summarize_process_output` hands back up to 8 lines of a failing test run).
_ROW_PREFIXES = ("OK ", "SKIP ", "FAIL", "VERIFY ", "$ ", "(", "exit=")

_MISSING_MODULE_RE = re.compile(r"ModuleNotFoundError: No module named ['\"]([A-Za-z_][A-Za-z0-9_.]*)['\"]")
_MISSING_NAME_RE = re.compile(r"NameError: name ['\"]([A-Za-z_][A-Za-z0-9_]*)['\"] is not defined")
_SCAFFOLD_TEST_RE = re.compile(r"\btest_([A-Za-z_][A-Za-z0-9_]*)_placeholder\b")
_SYNTAX_RE = re.compile(r"SyntaxError|invalid syntax|was never closed|unexpected EOF|unexpected indent|IndentationError")
_CANDIDATE_PATH_RE = re.compile(r"^([\w./\\-]+\.py)(?=[\s:])", re.MULTILINE)


def parse_verify_report(report: str) -> list[Failure]:
    """Turn a ``VERIFY FAILED`` report into structured rows.

    Deliberately tolerant: an unrecognized ``FAIL`` line still yields a Failure with
    ``check='unknown'`` so the caller reverts and reports it, rather than silently ignoring a
    failure it could not classify."""
    failures: list[Failure] = []
    for raw in str(report or "").splitlines():
        line = raw.rstrip()
        if not line.startswith("FAIL"):
            if failures and line.strip() and not line.startswith(_ROW_PREFIXES):
                tail = (failures[-1].message + "\n" + line.strip()).strip()
                failures[-1] = replace(failures[-1], message=tail)
            continue
        body = line[len("FAIL"):].strip()
        tests = _TESTS_RE.match(body)
        if tests:
            detail = (tests.group("detail") or "").strip()
            failures.append(
                Failure(path="", check="tests", message=detail or f"tests failed ({tests.group('label')})")
            )
            continue
        path, separator, message = body.partition(": ")
        if not separator:
            failures.append(Failure(path="", check="unknown", message=body))
            continue
        path = path.strip()
        message = message.strip()
        failures.append(Failure(path=path, check=_classify(path, message), message=message, line=_line_of(message)))
    return failures


def _classify(path: str, message: str) -> str:
    for check, pattern in _CHECK_PATTERNS:
        if pattern.search(message):
            return check
    name = path.rsplit("/", 1)[-1]
    suffix = ("." + name.rsplit(".", 1)[1].lower()) if "." in name else ""
    # The bare `FAIL <rel>: <exc>` row is _tool_verify's generic `except (SyntaxError, ValueError)`
    # arm, so the SUFFIX is what identifies which gate raised it.
    return _SUFFIX_CHECKS.get(suffix, "parse")


def _line_of(message: str) -> int | None:
    match = _LINE_RE.search(message)
    return int(match.group(1)) if match else None


def hard_stop(failures: list[Failure]) -> str:
    """The verbatim finding text when a failure must end the run with zero repair attempts.
    Today that is exactly the secret scan: an auto-edit around a credential finding either hides
    it or copies it somewhere else, so the run stops and shows the operator what was found."""
    for failure in failures:
        if failure.check == "secrets":
            return f"{failure.path}: {failure.message}"
    return ""


# --------------------------------------------------------------------------------------
# The repair table
# --------------------------------------------------------------------------------------


def _run_paths(applied_ops: list[dict[str, Any]]) -> set[str]:
    """Workspace-relative paths THIS run wrote. The boundary on every repair: a file the run did
    not touch is never edited or reverted, whatever verify says about it."""
    paths: set[str] = set()
    for op in applied_ops or []:
        if not isinstance(op, dict):
            continue
        rel = str(op.get("path") or "").strip().replace("\\", "/")
        if rel:
            paths.add(rel)
    return paths


def _created_paths(applied_ops: list[dict[str, Any]]) -> set[str]:
    return {
        str(op.get("path") or "").strip().replace("\\", "/")
        for op in applied_ops or []
        if isinstance(op, dict) and op.get("kind") == "new_file" and str(op.get("path") or "").strip()
    }


def _revert(rel: str, reason: str, *, needs_brain: bool = False) -> dict[str, Any]:
    return {"action": "revert", "path": rel, "reason": reason, "needs_brain": bool(needs_brain)}


def _dotted_module(rel: str) -> str:
    parts = [p for p in rel.replace("\\", "/").split("/") if p]
    if not parts or not parts[-1].endswith(".py"):
        return ""
    parts[-1] = parts[-1][: -len(".py")]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _locate_symbol_module(root: Path, symbol: str) -> str:
    """Dotted module path of the file that DEFINES ``symbol``, confirmed by reading it — or ''.

    ``repomap.search_repo`` ranks candidates; the definition regex is what turns a ranked guess
    into a fact. Without that confirmation there is no proposal at all: 'undetermined' is a valid
    answer, an invented import is not."""
    try:
        import repomap

        listing = str(repomap.search_repo(root, f"def {symbol} class {symbol} {symbol}", max_results=5) or "")
    except Exception:  # noqa: BLE001 - retrieval is optional; absent means "propose nothing"
        return ""
    definition = re.compile(rf"^(?:async\s+def|def|class)\s+{re.escape(symbol)}\b", re.MULTILINE)
    # search_repo renders a ranked file header per hit ("pkg/mod.py  (score 10)") followed by
    # indented "<lineno>: <text>" match lines, so candidates are the paths at column 0.
    for candidate in dict.fromkeys(_CANDIDATE_PATH_RE.findall(listing)):
        rel = candidate.replace("\\", "/")
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if definition.search(text):
            return _dotted_module(rel)
    return ""


def _repair_tests(failure: Failure, root: Path, applied_ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The only two test failures with an unambiguous mechanical answer."""
    created = _created_paths(applied_ops)
    python_targets = sorted(p for p in created if p.endswith(".py"))

    # (a) a name the suite cannot resolve, whose definition we can actually LOCATE -> add the import.
    symbol = ""
    match = _MISSING_NAME_RE.search(failure.message)
    if match:
        symbol = match.group(1)
    else:
        match = _MISSING_MODULE_RE.search(failure.message)
        if match:
            symbol = match.group(1).split(".")[0]
    if symbol and len(python_targets) == 1:
        module = _locate_symbol_module(root, symbol)
        if module and module != _dotted_module(python_targets[0]):
            names = [symbol] if _MISSING_NAME_RE.search(failure.message) else []
            return [
                {
                    "action": "edit_op",
                    "path": python_targets[0],
                    "op": "add_import",
                    "args": {"module": module, "names": names},
                    "reason": f"'{symbol}' is defined in {module}; adding the missing import",
                }
            ]

    # (b) OUR OWN scaffold's placeholder failed -> mark it skipped rather than leaving a red suite.
    # Bounded hard to the exact file this run created with the exact name the template emits; a
    # test the run did not write is never touched.
    scaffold = _SCAFFOLD_TEST_RE.search(failure.message)
    if scaffold:
        expected = f"test_{scaffold.group(1)}.py"
        target = next((p for p in created if p.rsplit("/", 1)[-1] == expected), "")
        if target:
            try:
                text = (root / target).read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if "import unittest" in text:
                return [
                    {
                        "action": "edit_op",
                        "path": target,
                        "op": "wrap_ast",
                        "args": {
                            "target_fn": f"test_{scaffold.group(1)}_placeholder",
                            "transform": "decorate",
                            "decorator": "unittest.skip('scaffold - fill in real assertions')",
                        },
                        "reason": "the scaffolded placeholder failed; marking it skipped until it is filled in",
                    }
                ]

    return [
        _revert(p, f"tests failed and the cause is not mechanically repairable: {failure.message[:200]}")
        for p in sorted(created)
    ]


def propose_repairs(
    failures: list[Failure],
    root: Path,
    *,
    seed_dir: str | Path | None = None,
    applied_ops: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Map parsed failures to repair actions. REVERT BY DEFAULT.

    Returns a list of ``{"action": "revert"|"edit_op", "path", "reason", ...}``. An empty list
    means "nothing deterministic left to try" — including the hard-stop case, where returning
    zero proposals IS the decision (see ``hard_stop``)."""
    applied = list(applied_ops or [])
    if hard_stop(failures):
        return []
    root = Path(root)
    owned = _run_paths(applied)
    created = _created_paths(applied)
    proposals: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(proposal: dict[str, Any]) -> None:
        key = (str(proposal.get("action")), str(proposal.get("path")))
        if key not in seen:
            seen.add(key)
            proposals.append(proposal)

    for failure in failures:
        if failure.check == "tests":
            for proposal in _repair_tests(failure, root, applied):
                add(proposal)
            continue
        rel = failure.path.replace("\\", "/")
        if rel not in owned:
            # Verify is reporting on a file this run never wrote. Editing or reverting it would be
            # the tool damaging state it does not own.
            continue
        if failure.check == "python" and rel in created:
            # A file we CREATED that does not parse is a TEMPLATE bug. Never bracket-patch it — a
            # "was never closed" can only be repaired by understanding the intended code, which is
            # exactly what this layer refuses to guess. Undo the op, log it, defer to a brain.
            kind = "syntax error" if _SYNTAX_RE.search(failure.message) else "parse failure"
            add(_revert(rel, f"{kind} in a file this run created: {failure.message[:200]}", needs_brain=True))
            continue
        add(_revert(rel, f"{failure.check} check failed and has no deterministic repair: {failure.message[:200]}"))
    return proposals


# --------------------------------------------------------------------------------------
# Applying repairs / restoring
# --------------------------------------------------------------------------------------


def _emit(on_event: Any, event: dict[str, Any]) -> None:
    """Best-effort progress delivery. Mirrors ``agent._emit`` rather than importing it, so this
    module never depends on the module that imports it."""
    if on_event is None:
        return
    try:
        on_event(event)
    except Exception:  # noqa: BLE001 - a dead event consumer must never disturb a repair
        pass


def _drop_change(toolbox: Any, rel: str) -> None:
    """Forget the Workbench change record for a file that has just been put back. Leaving it would
    show the operator a diff that no longer exists on disk."""
    try:
        toolbox.changes[:] = [c for c in toolbox.changes if c.get("path") != rel]
    except Exception:  # noqa: BLE001 - the UI payload is cosmetic; a restore must not fail over it
        pass


def restore_all(toolbox: Any, rel_paths: list[str] | None = None) -> list[str]:
    """Put every named file (default: everything this run touched) back to its pre-run bytes from
    ``ToolBox.snapshot``. Returns one human line per path — including the paths it could NOT
    restore, because a silent partial rollback is worse than a loud one."""
    targets = sorted(rel_paths) if rel_paths is not None else sorted(getattr(toolbox, "touched", ()) or ())
    notes: list[str] = []
    for rel in targets:
        notes.append(_restore_one(toolbox, rel))
    return notes


def _restore_one(toolbox: Any, rel: str) -> str:
    snapshot = getattr(toolbox, "snapshot", {}) or {}
    entry = snapshot.get(rel)
    if entry is None:
        return f"{rel}: no pre-run snapshot; left as-is"
    if entry.get("content_unavailable"):
        # The file existed but could not be read at first touch, so there is no faithful original
        # to write back. Blanking or deleting it would destroy data — leave it and say so.
        return f"{rel}: pre-run content was unreadable; left as-is (restore it from version control)"
    try:
        target = toolbox._resolve(rel)
    except Exception as exc:  # noqa: BLE001 - a path that no longer resolves must not abort the rollback
        return f"{rel}: could not resolve ({exc})"
    if not entry.get("existed"):
        try:
            if target.is_file():
                target.unlink()
        except OSError as exc:
            return f"{rel}: could not remove ({exc})"
        try:
            toolbox.touched.discard(rel)
        except Exception:  # noqa: BLE001 - bookkeeping only
            pass
        _drop_change(toolbox, rel)
        return f"{rel}: removed (it did not exist before this run)"
    try:
        target.write_text(entry.get("content") or "", encoding="utf-8")
    except OSError as exc:
        return f"{rel}: could not restore ({exc})"
    _drop_change(toolbox, rel)
    return f"{rel}: restored to its pre-run content"


def _apply_repair(toolbox: Any, proposal: dict[str, Any]) -> dict[str, Any]:
    """Run one repair through the ToolBox and return a transcript row in the existing
    ``{tool, input, output, is_error}`` shape, so the Workbench stream is unchanged."""
    rel = str(proposal.get("path") or "")
    action = str(proposal.get("action") or "")
    if action == "revert":
        note = _restore_one(toolbox, rel)
        return {
            "tool": "revert",
            "input": {"path": rel},
            "output": f"{proposal.get('reason', '')}\n{note}".strip(),
            "is_error": True,
        }
    op_name = str(proposal.get("op") or "")
    try:
        target = toolbox._resolve(rel)
        current = target.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 - an unreadable target is a refusal, never a crashed loop
        return {"tool": "edit_op", "input": {"path": rel, "op": op_name},
                "output": f"refused: {exc}", "is_error": True}
    result = edit_ops.realize(
        current,
        op_name,
        dict(proposal.get("args") or {}),
        suffix=target.suffix.lower(),
        allow_commands=bool(getattr(toolbox, "allow_commands", False)),
    )
    if not result.ok:
        return {"tool": "edit_op", "input": {"path": rel, "op": op_name},
                "output": f"refused: {result.reason}", "is_error": True}
    output, is_error = toolbox.run(
        "edit_file", {"path": rel, "old_string": result.old_string, "new_string": result.new_string}
    )
    return {"tool": "edit_file", "input": {"path": rel, "op": op_name},
            "output": f"{proposal.get('reason', '')}\n{output}".strip(), "is_error": is_error}


# --------------------------------------------------------------------------------------
# The code-scanner ship gate
# --------------------------------------------------------------------------------------


def scanner_gate(root: Path, rel_paths: list[str]) -> tuple[bool, list[str]]:
    """Refuse to ship when a file this run touched carries a HIGH/CRITICAL finding from GreyIQ's
    OWN static scanner. Returns ``(ok, notes)``.

    Fails OPEN with an explicit note when the scanner cannot run (absent module, scan error): the
    gate then reports 'undetermined' rather than claiming a clean bill of health it never got."""
    paths = [p.replace("\\", "/") for p in (rel_paths or []) if str(p or "").strip()]
    if not paths:
        return True, []
    try:
        from bughunter.code_scanner import ScanRequest, ScanTargetType, Severity, scan_target

        result = scan_target(
            ScanRequest(target=str(root), target_type=ScanTargetType.PATH, include_globs=tuple(paths))
        )
    except Exception as exc:  # noqa: BLE001 - the gate is advisory; it must never crash a run
        return True, [f"code scanner unavailable ({type(exc).__name__}); findings undetermined"]
    blocking = [
        f"{f.file_path}:{f.line_start} {f.severity.value.upper()} {f.rule_id} — {f.title}"
        for f in result.findings
        if f.severity in (Severity.HIGH, Severity.CRITICAL)
    ]
    return (not blocking), blocking


# --------------------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------------------


def repair_loop(
    toolbox: Any,
    ops: list[dict[str, Any]],
    on_event: Any = None,
    *,
    root: Path,
    seed_dir: str | Path | None = None,
    max_rounds: int = 2,
) -> tuple[bool, str, list[dict[str, Any]]]:
    """Verify, and on failure apply deterministic repairs and verify again, up to ``max_rounds``.

    Returns ``(verified_ok, report, transcript_entries)`` where ``report`` is the FIRST failing
    verify output — the one that still names the file and check — so the caller can say what went
    wrong even after a later round cleared it. Never raises and never restores on its own: the
    caller decides what a final failure means and owns the rollback, so this stays a pure "did the
    workspace end up clean" question.

    ``verified_ok`` is False whenever a repair had to REVERT one of the run's own ops, even if the
    verify that follows passes. Undoing your own work and then reporting a clean verify would be a
    lie by omission: the change the operator asked for is not on disk.

    Every round re-runs the SAME ``verify`` tool the LLM loops use (through ``ToolBox.run``, which
    converts the ToolError it raises on failure into a ``(report, True)`` tuple), so an offline run
    can never claim a cleaner result than a Claude run would."""
    entries: list[dict[str, Any]] = []
    rounds = max(0, min(_MAX_ROUNDS_CEILING, int(max_rounds or 0)))

    report, failed = toolbox.run("verify", {})
    entry = {"tool": "verify", "input": {}, "output": report, "is_error": failed}
    entries.append(entry)
    _emit(on_event, {"type": "step", "entry": entry})
    first_failure = report if failed else ""
    reverted = False

    attempted = 0
    while failed and attempted < rounds:
        failures = parse_verify_report(report)
        stop = hard_stop(failures)
        if stop:
            entry = {
                "tool": "repair",
                "input": {},
                "output": f"hard stop — no repair will be attempted for a secret finding: {stop}",
                "is_error": True,
            }
            entries.append(entry)
            _emit(on_event, {"type": "step", "entry": entry})
            break
        proposals = propose_repairs(failures, Path(root), seed_dir=seed_dir, applied_ops=list(ops or []))
        if not proposals:
            break
        for proposal in proposals:
            if str(proposal.get("action")) == "revert":
                reverted = True
            entry = _apply_repair(toolbox, proposal)
            entries.append(entry)
            _emit(on_event, {"type": "step", "entry": entry})
        attempted += 1
        report, failed = toolbox.run("verify", {})
        entry = {"tool": "verify", "input": {}, "output": report, "is_error": failed}
        entries.append(entry)
        _emit(on_event, {"type": "step", "entry": entry})
        if failed and not first_failure:
            first_failure = report

    if not failed:
        ok, notes = scanner_gate(Path(root), sorted(getattr(toolbox, "touched", ()) or ()))
        if not ok:
            report = "SHIP BLOCKED\nGreyIQ's own code scanner flags the touched files:\n" + "\n".join(notes)
            failed = True
            try:
                toolbox.verified_ok = False
            except Exception:  # noqa: BLE001 - bookkeeping only
                pass
            entry = {"tool": "code_scan", "input": {}, "output": report, "is_error": True}
            entries.append(entry)
            _emit(on_event, {"type": "step", "entry": entry})
        elif notes:
            entry = {"tool": "code_scan", "input": {}, "output": "\n".join(notes), "is_error": False}
            entries.append(entry)
            _emit(on_event, {"type": "step", "entry": entry})
        if failed and not first_failure:
            first_failure = report

    return ((not failed) and not reverted), (first_failure or report), entries


def failure_summary(report: str, restored: list[str]) -> str:
    """The honest text an offline run ends on when verify never came clean: which file, which
    check, what was rolled back, and what to do next. No claim of partial success."""
    failures = parse_verify_report(report)
    lines = ["The offline coder could not produce a verified-clean change, so nothing was kept."]
    stop = hard_stop(failures)
    if stop:
        lines.append(f"Stopped without attempting a repair — a secret-scan finding: {stop}")
    if failures:
        lines.append("Verify reported:")
        for failure in failures[:8]:
            where = failure.path or "(whole run)"
            at = f" (line {failure.line})" if failure.line else ""
            lines.append(f"- {where} [{failure.check}]{at}: {failure.message.splitlines()[0][:300]}")
    else:
        lines.append("Verify reported a failure this run could not classify:")
        lines.append(str(report or "")[:600])
    if restored:
        lines.append("Rolled back:")
        lines.extend(f"- {note}" for note in restored[:12])
    lines.append(
        "Configure a Local model (Ollama) or a Claude brain in Settings and re-run — the "
        "deterministic coder only ships changes it can prove."
    )
    return "\n".join(lines)
