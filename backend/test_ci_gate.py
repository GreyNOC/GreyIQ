r"""The gate has to actually run the tests, and the syntax check has to actually read the code.

`npm run check` is this project's only quality gate — CI invokes it, `scripts/release.sh` invokes it,
and a contributor runs it before pushing. Two of its three parts were quietly covering far less than
they appeared to:

  * **The test runner could not see 59 tests.** `python -m unittest discover` collects only
    `unittest.TestCase` subclasses. Eight files write their tests as module-level `def test_*`
    functions, which pytest collects and unittest does not — so 59 tests ran NOWHERE in CI. Among
    them all 25 tests of the secret-reportability classifier (which decides whether a discovered
    credential may be reported at all), the 10 of the VDP policy gate, the 5 of the VDP report gate,
    and the DNS-rebinding guard. `pytest.ini` had been in the repo the whole time, pointing at
    `backend`; only `package.json` never caught up. The gap is invisible: both runners print a
    healthy-looking pass count.

  * **The static check compiled one file.** It compiled `backend/greyiq_api.py` and nothing else, so
    ~295 other modules reached CI only if some test happened to import them — and several are
    imported lazily on purpose, to keep the frozen build and `test_boot_no_torch` torch-free. That is
    how `bughunter/fsutil.py` shipped an invalid escape sequence (a SyntaxWarning on 3.12, a
    scheduled SyntaxError) in a docstring documenting the Windows `\\?\` prefix: it imported fine, so
    no test could see it, and the gate was not looking.

Both failure modes are the same shape — a gate that reports success over work it never did — so both
get a test that fails if the coverage narrows again. These are contract tests over `package.json` and
the gate scripts; they do not re-run the suite.
"""
from __future__ import annotations

import ast
import json
import re
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
ROOT = BACKEND_DIR.parent
PACKAGE_JSON = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
SCRIPTS = PACKAGE_JSON.get("scripts") or {}


def _files_with_bare_test_functions() -> dict[str, list[str]]:
    """Test files whose tests are module-level functions — the ones unittest cannot collect."""
    found: dict[str, list[str]] = {}
    for path in sorted(BACKEND_DIR.glob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # a broken test file is check:syntax's problem, not this test's
            continue
        names = [node.name for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name.startswith("test")]
        if names:
            found[path.name] = names
    return found


class TheRunnerMustCollectEveryTestTests(unittest.TestCase):
    def test_there_really_are_tests_only_pytest_can_see(self) -> None:
        # Anti-vacuity. If someone converts all eight files to unittest.TestCase, the assertion below
        # stops meaning anything, and this test should say so rather than passing hollowly.
        bare = _files_with_bare_test_functions()
        total = sum(len(names) for names in bare.values())
        self.assertGreater(total, 0,
                           "no module-level test functions remain — if every test is now a TestCase, "
                           "delete this guard rather than letting it pass over nothing")
        # A rough floor, not the exact count, so adding a test does not fail an unrelated guard.
        self.assertGreaterEqual(total, 40, f"expected the known pytest-style corpus, found {total}: {bare}")

    def test_the_gate_runs_pytest_and_not_unittest_discover(self) -> None:
        command = str(SCRIPTS.get("check:python") or "")
        self.assertTrue(command, "package.json has no check:python script")
        bare = _files_with_bare_test_functions()
        self.assertNotIn(
            "unittest discover", command,
            "check:python is back on `unittest discover`, which silently collects 0 tests from "
            f"{len(bare)} file(s) ({sum(len(v) for v in bare.values())} tests) that use module-level "
            "test functions — including the secret-reportability and VDP gates",
        )
        self.assertIn("pytest", command, "check:python no longer runs pytest, so those tests run nowhere")

    def test_the_runner_is_declared_as_a_dependency(self) -> None:
        # A gate that needs a package nobody installs is a gate that fails for the wrong reason.
        dev = (ROOT / "requirements-dev.txt")
        self.assertTrue(dev.is_file(), "requirements-dev.txt is missing, so CI cannot install the runner")
        self.assertRegex(dev.read_text(encoding="utf-8"), r"(?m)^pytest\b",
                         "requirements-dev.txt does not pin pytest")
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("requirements-dev.txt", ci, "CI never installs the test runner")

    def test_pytest_ini_still_points_at_the_backend(self) -> None:
        # Bare `pytest` in the script relies on this file for its testpaths; without it the gate
        # would collect from the repo root and sweep node_modules.
        ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
        self.assertRegex(ini, r"(?m)^testpaths\s*=\s*backend\b")


class TheSyntaxGateMustReadEveryModuleTests(unittest.TestCase):
    def test_the_gate_no_longer_compiles_a_single_hand_named_file(self) -> None:
        command = str(SCRIPTS.get("check:python") or "")
        self.assertNotIn("greyiq_api.py'); compile(", command,
                         "the one-file compile gate is back; ~295 modules would go unparsed again")
        self.assertIn("check-syntax.py", command, "check:python does not run the Python syntax gate")

    def test_the_python_gate_walks_the_tree_and_treats_a_warning_as_a_failure(self) -> None:
        source = (ROOT / "scripts" / "check-syntax.py").read_text(encoding="utf-8")
        self.assertIn("rglob", source, "the gate does not walk the tree")
        self.assertIn('simplefilter("error", SyntaxWarning)', source,
                      "an invalid escape sequence would pass as a warning again")
        # It must report every failure, not stop at the first — one run should name them all.
        self.assertIn("failures", source)
        # And an empty sweep must fail rather than pass forever.
        self.assertIn("the walk is broken", source)

    def test_no_skip_name_above_the_repo_can_empty_the_walk(self) -> None:
        """The skip list must be matched against a ROOT-RELATIVE path, never an absolute one.

        ``Path.parts`` on an absolute path carries every ancestor segment above the repo, so a
        checkout that merely LIVES under a directory named like a skip entry matched every file
        and the sweep came back empty — tripping the "broken walk" bail-out on a good tree. A
        ``.claude/worktrees/<name>`` checkout, which is this repo's own worktree convention, hit it
        on ".claude": `npm run check` could not run at all where the work is done, and the two
        walks in this file failed with "found only 0 modules". Those two only fail from inside such
        a checkout, so this asserts the shape instead — it fails anywhere.
        """
        for name in ("scripts/check-syntax.py", "backend/test_ci_gate.py"):
            with self.subTest(file=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                for walked in re.findall(r"isdisjoint\((\w+(?:\.\w+|\(\w*\))*)\.parts\)", source):
                    self.assertIn(
                        "relative_to(ROOT)", walked,
                        f"{name} matches the skip list against `{walked}.parts`; make it "
                        "`relative_to(ROOT).parts` or a checkout under a skip-named directory "
                        "silently skips every file",
                    )

    def test_the_js_gate_is_derived_rather_than_hand_listed(self) -> None:
        command = str(SCRIPTS.get("check:js") or "")
        self.assertIn("check-syntax.mjs", command)
        # The old hand-listed form had already drifted past two shipped files.
        self.assertNotIn("node --check server.mjs", command)
        source = (ROOT / "scripts" / "check-syntax.mjs").read_text(encoding="utf-8")
        self.assertIn("readdirSync", source, "the JS gate does not walk the tree")
        self.assertIn("the walk is broken", source)

    def test_every_javascript_file_the_repo_ships_is_reachable_by_that_walk(self) -> None:
        # The point of deriving it: these two were missing from the hand-listed set, and one of them
        # IS the gate that `npm run check` calls to catch version drift.
        skip = {"node_modules", ".git", "runtime", "release", "dist", "build", ".venv-build", ".claude"}
        shipped = sorted(
            path.relative_to(ROOT).as_posix()
            for suffix in ("*.js", "*.mjs", "*.cjs")
            for path in ROOT.rglob(suffix)
            # Relative to ROOT — see _no_skip_name_above_the_repo below for why an absolute
            # path.parts here matched every file and emptied the list.
            if skip.isdisjoint(path.relative_to(ROOT).parts)
        )
        for expected in ("ecosystem.config.cjs", "scripts/check-devops.cjs",
                         "server.mjs", "public/app.js",
                         "electron/main.cjs", "electron/preload.cjs"):
            self.assertIn(expected, shipped, f"{expected} would not be parsed by the gate")


class ReleaseCannotShipUntestedCodeTests(unittest.TestCase):
    """A tag push does not trigger the CI workflow, so the release workflow needs its own gate."""

    def setUp(self) -> None:
        self.release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    def test_ci_does_not_trigger_on_a_tag(self) -> None:
        # The premise of the guard below. CI runs on push-to-branch and pull_request; a tag is
        # neither, which is why a release needs to gate itself.
        triggers = self.ci.split("jobs:", 1)[0]
        self.assertNotIn("tags:", triggers,
                         "CI now triggers on tags — re-check whether release.yml still needs its own gate")

    def test_the_release_workflow_runs_the_quality_gate(self) -> None:
        self.assertIn("npm run check", self.release,
                      "a tag or manual dispatch can publish a signed build whose tests never ran")

    def test_every_build_job_depends_on_that_gate(self) -> None:
        # A gate that runs beside the builds instead of before them does not stop the release.
        self.assertRegex(self.release, r"(?s)\n  gate:\s*\n", "release.yml has no `gate` job")
        windows = self.release.split("\n  windows:", 1)
        self.assertEqual(len(windows), 2, "the windows build job moved")
        # `linux` needs `windows` and `publish` needs both, so gating `windows` gates the chain.
        head = windows[1].split("steps:", 1)[0]
        self.assertIn("needs: gate", head, "the Windows build does not wait for the quality gate")

    def test_the_gate_job_installs_the_test_runner(self) -> None:
        gate = self.release.split("\n  gate:", 1)[1].split("\n  windows:", 1)[0]
        self.assertIn("requirements-dev.txt", gate, "the release gate cannot run pytest")
        self.assertIn("npm run check", gate)


class NoTestIsRedForAMissingToolTests(unittest.TestCase):
    """A gate that is red on a correct refusal trains everyone to ignore a red gate."""

    def test_the_powershell_recipe_case_is_skipped_where_no_parser_exists(self) -> None:
        source = (BACKEND_DIR / "test_offline_coder.py").read_text(encoding="utf-8")
        # The decorator spans lines and its own argument contains parentheses, so anchor on the test
        # name and look back rather than trying to balance brackets with a regex.
        head = source.split("def test_powershell_script_sets_strict_mode", 1)
        self.assertEqual(len(head), 2, "the PowerShell recipe test was renamed or removed")
        # The LAST skipUnless before the test name, not the first: another test's decorator earlier in
        # the file would otherwise satisfy this guard while this test sat unguarded.
        cut = head[0].rfind("@unittest.skipUnless(")
        match = re.match(r"@unittest\.skipUnless\((.*)$", head[0][cut:], re.S) if cut != -1 else None
        # It must be THIS test's decorator, i.e. nothing but whitespace/comments between them.
        if match:
            between = head[0][cut:]
            self.assertNotIn("def test_", between,
                             "the nearest skipUnless belongs to an earlier test, not this one")
        self.assertIsNotNone(
            match, "the PowerShell recipe test has no skip guard, so `npm run check` is red on every "
                   "machine without PowerShell — for the coder correctly refusing, not a defect")
        # And the guard must ask the coder's own predicate, so the two can never disagree about
        # whether the recipe is reachable.
        self.assertIn("_gate_available", match.group(1))

    def test_this_machines_skips_are_only_ever_about_a_missing_tool(self) -> None:
        # Not a wiring assertion — a statement of intent that a skip is an environment fact. If a
        # skip reason stops naming what is absent, it is hiding a test rather than gating one.
        source = (BACKEND_DIR / "test_offline_coder.py").read_text(encoding="utf-8")
        for reason in re.findall(r"skipUnless\([^,]+,\s*(\"[^\"]+\"|'[^']+')", source):
            with self.subTest(reason=reason):
                self.assertRegex(reason.lower(), r"\b(no|not|missing|absent|unavailable|without)\b",
                                 f"skip reason does not say what is missing: {reason}")


class NoTestModuleCanAbortTheWholeRunTests(unittest.TestCase):
    """pytest treats a collection error as FATAL, which `unittest discover` did not.

    Under the old runner, `import torch` failing inside `test_core_contracts.py` was logged as one
    error and the other ~2950 tests still ran. pytest interrupts the entire session — so an
    unguarded module-scope import of an optional dependency now turns the release gate OFF on any
    machine that lacks it, instead of narrowing it by one file. torch is optional by design: the
    frozen build excludes it, and `test_boot_no_torch.py` exists to prove the app degrades without it.
    """

    #: Backend modules that import torch/pandas at MODULE scope, so importing them needs a guard.
    HEAVY_MODULES = ("solin_core", "training_runtime")

    def _module_scope_imports(self, tree: ast.Module) -> set[str]:
        names: set[str] = set()
        for node in tree.body:  # module scope only — a lazy import inside a function is fine
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names.add(node.module.split(".")[0])
        return names

    def test_the_heavy_module_list_is_still_accurate(self) -> None:
        # Anti-vacuity: derive the real set, so a new torch-importing module joins the guard below
        # instead of quietly slipping past a stale hand-written list.
        actual = set()
        for path in sorted(BACKEND_DIR.rglob("*.py")):
            if "__pycache__" in path.parts or path.name.startswith("test_"):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            if {"torch", "pandas"} & self._module_scope_imports(tree):
                actual.add(path.stem)
        self.assertEqual(actual, set(self.HEAVY_MODULES),
                         "the set of modules importing torch/pandas at module scope changed; every "
                         "test that imports one of them needs the skip guard asserted below")

    def test_every_test_importing_one_is_guarded_by_a_torch_probe(self) -> None:
        checked = 0
        for path in sorted(BACKEND_DIR.glob("test_*.py")):
            source = path.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            if not set(self.HEAVY_MODULES) & self._module_scope_imports(tree):
                continue
            checked += 1
            with self.subTest(module=path.name):
                self.assertIn('find_spec("torch")', source,
                              f"{path.name} imports a torch-backed module at module scope with no "
                              "availability probe, so pytest aborts the whole run without torch")
                self.assertIn("SkipTest", source,
                              f"{path.name} probes for torch but does not raise unittest.SkipTest, "
                              "so collection still fails")
                # The guard has to come BEFORE the import it protects, or it never runs.
                guard_at = source.index('find_spec("torch")')
                first_heavy = min(source.index(f"import {name}") for name in self.HEAVY_MODULES
                                  if f"import {name}" in source)
                self.assertLess(guard_at, first_heavy,
                                f"{path.name}'s torch probe sits after the import it is meant to guard")
        self.assertGreater(checked, 0, "no test module imports a torch-backed module — if that is now "
                                       "true, delete this guard rather than letting it pass over nothing")


class EveryModuleActuallyCompilesTests(unittest.TestCase):
    """Run the gate's own check here too, so a bad module fails the suite and not only `npm run`."""

    def test_no_backend_module_carries_a_scheduled_syntax_error(self) -> None:
        import warnings

        skip = {"node_modules", ".git", "runtime", "release", "dist", "__pycache__",
                ".venv-build", ".claude", ".pytest_cache"}
        failures: list[str] = []
        checked = 0
        for path in sorted(BACKEND_DIR.rglob("*.py")):
            if not skip.isdisjoint(path.relative_to(ROOT).parts):
                continue
            checked += 1
            with warnings.catch_warnings():
                warnings.simplefilter("error", SyntaxWarning)
                warnings.simplefilter("error", DeprecationWarning)
                try:
                    compile(path.read_text(encoding="utf-8"), str(path), "exec")
                except (SyntaxError, SyntaxWarning, DeprecationWarning, ValueError) as exc:
                    failures.append(f"{path.relative_to(ROOT).as_posix()}: {type(exc).__name__}: {exc}")
        self.assertGreater(checked, 100, f"the walk found only {checked} modules; it is broken")
        self.assertEqual(failures, [], "modules that will not compile on a future Python:\n"
                                       + "\n".join(failures))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
