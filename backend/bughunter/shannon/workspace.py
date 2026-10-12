"""Locate a finished Shannon run on disk and import its candidates.

Shannon leaves its SARIF in one of three places depending on how it was invoked, and the
difference is not cosmetic — ``-o <dir>`` makes the worker write the three customer
artifacts to that directory *instead of* the workspace root, not in addition to it
(``apps/worker/src/temporal/activities.ts:1465-1468``). So "where is report.sarif" has no
single answer and a caller should not have to know which flags the operator used.

Resolution order, most explicit first:

1. ``<path>`` is itself a ``.sarif`` file.
2. ``<path>/report.sarif`` — a run root, or the ``-o`` directory.
3. ``<path>/.shannon/deliverables/report.sarif`` — the internal copy, which exists even
   when surfacing to the root failed.
4. ``<path>/*/report.sarif`` — ``<path>`` is a *workspaces* parent holding
   ``{hostname}_{sessionId}`` directories. The most recently modified one wins, and the
   fact that a choice was made is reported rather than hidden.

This module reads exactly one file: the SARIF. It never opens anything else in the
workspace, and the reason is worth stating where the code is. A Shannon workspace holds
``.shannon/auth-state.json`` — Playwright storage state, i.e. live cookies and localStorage
for an authenticated session on the target. It is deleted at the end of a clean run and
left behind by a crash. It is joined by raw agent logs, unfiltered exploitation queues,
screenshots of authenticated UI, and copies of the target's own API schemas. None of that
is import material, so the safe design is to read the one file that was built to be shared
and to warn when the dangerous one is still present.

Pure / frozen-safe: standard library only, no network.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .ingest import findings_from_run
from .sarif import ShannonRun, parse_sarif_file

SARIF_FILENAME = "report.sarif"
INTERNAL_DIR = ".shannon"
DELIVERABLES_SUBDIR = "deliverables"
#: Playwright storage state. Live session cookies for the target, in cleartext.
AUTH_STATE_FILENAME = "auth-state.json"


def _candidate_paths(root: Path) -> list[Path]:
    return [
        root / SARIF_FILENAME,
        root / INTERNAL_DIR / DELIVERABLES_SUBDIR / SARIF_FILENAME,
    ]


#: Windows MAX_PATH. Past it, and without the \\?\ prefix or long paths enabled,
#: ``Path.is_dir()`` and ``Path.is_file()`` return **False** rather than raising — so a
#: workspace that plainly exists reports as absent. This was hit for real while testing
#: this module from a deeply nested temp directory, and the bare "not found" it produced
#: sent the diagnosis in entirely the wrong direction. A guess is cheap; silence is not.
_WINDOWS_MAX_PATH = 260


def _long_path_hint(root: Path) -> list[str]:
    """A note when a lookup probably failed because of MAX_PATH, not absence."""
    if os.name != "nt":
        return []
    # Budget for what gets appended below a workspaces parent: a run directory name plus
    # ``\.shannon\deliverables\report.sarif``.
    if len(str(root)) + 60 < _WINDOWS_MAX_PATH:
        return []
    return [
        f"that path is {len(str(root))} characters, and Windows silently reports files past "
        f"{_WINDOWS_MAX_PATH} as absent — a workspace there can look empty when it is not. "
        "Move the run somewhere shorter, or pass the report.sarif directly."
    ]


def find_sarif(path: str | Path) -> tuple[Path | None, list[str]]:
    """(the SARIF to read, notes). ``None`` when nothing resolves.

    Notes are operator-facing facts about the resolution, not errors — chiefly "there were
    several runs here and this is the one I picked".
    """
    notes: list[str] = []
    try:
        root = Path(path).expanduser()
    except (OSError, ValueError, RuntimeError):
        return None, ["path could not be interpreted"]

    try:
        if root.is_file():
            if root.suffix.lower() == ".sarif":
                return root, notes
            return None, [f"{root.name} is not a .sarif file"]
        if not root.is_dir():
            return None, [f"no such file or directory: {root}"] + _long_path_hint(root)
    except OSError as error:
        return None, [f"could not stat {root}: {error}"]

    for candidate in _candidate_paths(root):
        try:
            if candidate.is_file():
                return candidate, notes
        except OSError:
            continue

    # A workspaces parent. Shannon's auto-generated names are {hostname}_shannon-{epoch_ms},
    # so lexical order is nearly mtime order — but only nearly, and a resumed run rewrites an
    # older directory. Sort by mtime and say which one was chosen.
    runs: list[tuple[float, Path]] = []
    try:
        children = sorted(root.iterdir())
    except OSError as error:
        return None, [f"could not list {root}: {error}"]
    for child in children:
        try:
            if not child.is_dir():
                continue
        except OSError:
            continue
        for candidate in _candidate_paths(child):
            try:
                if candidate.is_file():
                    runs.append((candidate.stat().st_mtime, candidate))
                    break
            except OSError:
                continue

    if not runs:
        return None, [
            f"no {SARIF_FILENAME} under {root}. A Shannon run only writes one in exploit mode "
            'with report.sarif left enabled (exploit="false" emits none).'
        ] + _long_path_hint(root)
    runs.sort(key=lambda row: row[0], reverse=True)
    if len(runs) > 1:
        notes.append(
            f"{len(runs)} Shannon runs found under {root}; read the most recent "
            f"({runs[0][1].parent.name}). Pass that run's directory to choose another."
        )
    return runs[0][1], notes


def _auth_state_warning(sarif_path: Path) -> str | None:
    """Warn when a run left live session state on disk.

    Not an import problem — this module never reads it — but the operator is about to have a
    directory they may be tempted to copy, zip into an engagement bundle, or let OneDrive
    sync. Both GreyIQ checkouts currently live under OneDrive.
    """
    for base in (sarif_path.parent, sarif_path.parent.parent.parent):
        try:
            leftover = base / INTERNAL_DIR / AUTH_STATE_FILENAME
            if leftover.is_file():
                return (
                    f"{leftover} is present — Playwright storage state holding LIVE session "
                    "cookies for the target. Shannon deletes it on a clean run, so this one "
                    "likely crashed. Do not copy, bundle or sync this workspace; delete it."
                )
        except OSError:
            continue
    return None


def ingest_workspace(path: str | Path) -> dict[str, Any]:
    """Import a finished Shannon run as GreyIQ candidate findings.

    Returns ``{"ok", "error", "sarif_path", "run", "findings", "warnings", "notes"}``.
    Total: every failure is reported in the envelope rather than raised, because this runs
    inside a hunt and an unreadable external artifact must never take one down.

    The findings come back as candidates (``source: "shannon"``, ``proof_status:
    "candidate"``). A caller splicing them into a hunt should append ``"shannon"`` to
    ``scanners_run``, which is the provenance channel ``bounty.py`` and the report already
    render.
    """
    sarif_path, notes = find_sarif(path)
    if sarif_path is None:
        return {
            "ok": False,
            "error": notes[0] if notes else "no Shannon SARIF found",
            "sarif_path": "",
            "run": None,
            "findings": [],
            "warnings": [],
            "notes": notes,
        }

    run: ShannonRun = parse_sarif_file(sarif_path)
    findings = findings_from_run(run)
    warnings = list(run.warnings)
    leftover = _auth_state_warning(sarif_path)
    if leftover:
        warnings.append(leftover)

    if not findings:
        return {
            "ok": False,
            "error": f"no usable findings in {sarif_path}",
            "sarif_path": str(sarif_path),
            "run": run,
            "findings": [],
            "warnings": warnings,
            "notes": notes,
        }

    return {
        "ok": True,
        "error": "",
        "sarif_path": str(sarif_path),
        "run": run,
        "findings": findings,
        "warnings": warnings,
        "notes": notes,
    }
