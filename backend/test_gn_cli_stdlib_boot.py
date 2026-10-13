"""Startup guard: the `gn` CLI must run on a BARE distribution Python.

This is the invariant the documented source install rests on — `git clone`, then
`scripts/install-cli.sh`, then `gn`, with no venv, no pip and no `.deb` (see the
Linux section of README.md). Parrot/Kali/Ubuntu operators land there whenever the
release package does not apply: its dependencies track the current Debian stable
and its architecture is amd64 only.

Each test re-runs the CLI in a subprocess whose import system REFUSES anything
resolved out of ``site-packages``/``dist-packages``, which is a stricter
condition than ``python -S`` (it holds inside a populated venv too, which is how
CI and every developer checkout actually run). ``test_guard_blocks_...`` keeps
the suite from passing vacuously if that refusal ever stops working.

Companion guard: ``test_boot_no_torch.py`` pins the same property for the API.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
GN_CLI = BACKEND_DIR / "gn_cli.py"

# Replace PathFinder.find_spec rather than filtering sys.path: a .pth file or an
# explicit PYTHONPATH entry can put site-packages back, and blocking by the
# spec's ORIGIN catches every one of those routes.
_GUARD = """
import sys, importlib.machinery as _machinery, runpy
_real = _machinery.PathFinder.find_spec


def _guarded(name, path=None, target=None):
    spec = _real(name, path, target)
    origin = getattr(spec, "origin", None) or ""
    if "site-packages" in origin or "dist-packages" in origin:
        raise ModuleNotFoundError(
            "third-party import blocked (stdlib-only boot): %s from %s" % (name, origin),
            name=name,
        )
    return spec


_machinery.PathFinder.find_spec = staticmethod(_guarded)
"""

# The CLI path and its argv arrive through argv, not string formatting: _GUARD
# carries its own % operators and must stay copy-pasteable into a debug session.
_RUNNER = _GUARD + """
_cli = sys.argv[1]
sys.argv = ["gn"] + sys.argv[2:]
runpy.run_path(_cli, run_name="__main__")
"""


def _run_cli(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    if env:
        environment.update(env)
    return subprocess.run(
        [sys.executable, "-c", _RUNNER, str(GN_CLI), *args],
        cwd=str(PROJECT_ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300, env=environment,
    )


def _installed_third_party() -> str | None:
    """A top-level module that really does live in site-packages, or None."""
    for name in ("pytest", "yaml", "cryptography", "pydantic"):
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):  # pragma: no cover - partially installed env
            continue
        origin = getattr(spec, "origin", None) or ""
        if "site-packages" in origin or "dist-packages" in origin:
            return name
    return None


class StdlibOnlyCliBootTests(unittest.TestCase):
    def test_guard_blocks_a_real_site_packages_import(self) -> None:
        name = _installed_third_party()
        if name is None:  # pragma: no cover - already a bare interpreter
            self.skipTest("no site-packages module available to prove the guard bites")
        proc = subprocess.run(
            [sys.executable, "-c", _GUARD + "import " + name],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
        )
        self.assertNotEqual(proc.returncode, 0, "the guard let a site-packages import through")
        self.assertIn("third-party import blocked", proc.stderr)

    def test_version(self) -> None:
        proc = _run_cli(["--version"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("GreyIQ gn", proc.stdout)

    def test_help_lists_the_hunt_verbs(self) -> None:
        proc = _run_cli(["--help"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for verb in ("hunt", "scan", "dashboard", "path"):
            self.assertIn(verb, proc.stdout)

    def test_read_only_verbs(self) -> None:
        for args in (["profiles"], ["classes"], ["platforms"], ["path"], ["tools", "xss"]):
            with self.subTest(args=args):
                proc = _run_cli(args)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertTrue(proc.stdout.strip(), f"{args} printed nothing")

    def test_local_code_scan_finds_a_planted_defect(self) -> None:
        """The engine itself — not just argparse — has to work on a bare Python."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            (target / "app.js").write_text("eval(location.hash);\n", encoding="utf-8")
            proc = _run_cli(
                ["scan", str(target)],
                env={"GREYIQ_RUNTIME_DIR": str(Path(tmp) / "runtime")},
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("js.eval", proc.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
