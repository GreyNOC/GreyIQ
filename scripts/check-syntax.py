#!/usr/bin/env python3
r"""Compile every Python module the backend ships, and treat a syntax WARNING as a failure.

``check:python`` used to open its static gate with exactly one file:

    python -B -c "... p=Path('backend/greyiq_api.py'); compile(p.read_text(), str(p), 'exec')"

which parsed 1 of the ~200 modules under ``backend/``. Everything else reached CI only if some
test happened to import it, and several sizeable modules -- ``training_runtime.py`` among them --
are imported lazily precisely so the frozen build and ``test_boot_no_torch`` stay torch-free. So a
syntax error in a lazily-imported module could ship, surfacing as a runtime ImportError on the one
machine that took that code path.

Warnings are errors here, which is not pedantry. ``bughunter/fsutil.py`` documented the Windows
``\\?\`` extended-length prefix in a non-raw docstring, making ``\\`` + a backtick an invalid escape
sequence: a SyntaxWarning on 3.12 and a scheduled SyntaxError in a later Python. It compiled and
imported fine, so nothing in the suite could see it, and the one-file gate did not look.

Every failure is collected before exiting, so one run names them all rather than stopping at the
first. Stdlib only, no third-party import: this gate has to run before anything is installed.
"""
from __future__ import annotations

import sys
import warnings
from pathlib import Path

# Vendored, generated, or build output — not ours to parse. `seed` holds data, not code.
SKIP_PARTS = frozenset({
    "node_modules", ".git", "runtime", "release", "dist", "__pycache__",
    ".venv-build", ".claude", ".pytest_cache",
})
ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("backend", "scripts")


def _modules() -> list[Path]:
    found: list[Path] = []
    for target in TARGETS:
        base = ROOT / target
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            # Match against the path RELATIVE to ROOT, never the absolute one: path.parts on an
            # absolute path carries every ancestor segment above the repo too, so a checkout that
            # merely LIVES under a directory named like one of these matched every file and the
            # sweep came back empty -- the "broken walk" bail-out below, on a perfectly good tree.
            # A .claude/worktrees/<name> checkout (this repo's own worktree convention) hit it on
            # ".claude", so the gate could not run at all where the work is done. check-syntax.mjs
            # is immune by construction: it walks with readdir and tests each directory's own name.
            if SKIP_PARTS.isdisjoint(path.relative_to(ROOT).parts):
                found.append(path)
    return sorted(found)


def main() -> int:
    modules = _modules()
    if not modules:
        # An empty sweep is a broken gate, not a clean repo — it would pass forever.
        print("check-syntax: found no Python modules to compile — the walk is broken.", file=sys.stderr)
        return 1

    failures: list[tuple[Path, str]] = []
    for path in modules:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            failures.append((path, f"{type(exc).__name__}: {exc}"))
            continue
        with warnings.catch_warnings():
            # SyntaxWarning and DeprecationWarning at COMPILE time are both "this is a syntax
            # error in a future Python"; anything raised at import time is a test's job, not this
            # gate's, because compile() never executes the module body.
            warnings.simplefilter("error", SyntaxWarning)
            warnings.simplefilter("error", DeprecationWarning)
            try:
                compile(source, str(path), "exec")
            except (SyntaxError, SyntaxWarning, DeprecationWarning, ValueError) as exc:
                failures.append((path, f"{type(exc).__name__}: {exc}"))

    if failures:
        print(f"check-syntax: {len(failures)} of {len(modules)} Python module(s) failed to compile:\n",
              file=sys.stderr)
        for path, why in failures:
            print(f"  {path.relative_to(ROOT).as_posix()}: {why}", file=sys.stderr)
        return 1

    print(f"check-syntax: {len(modules)} Python module(s) compile clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
