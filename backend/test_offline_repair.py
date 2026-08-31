"""Tests for the deterministic verify -> repair loop (offline-coder strategy, move 4).

The report-parsing cases feed strings built with ``_tool_verify``'s OWN f-string formats, so the
table is tested against its actual producer rather than against a convenient mock — if someone
changes a FAIL line's wording, these fail instead of the repair table silently going blind.

The end-to-end case is the important one: a run whose verify fails must RETURN an honest failed
result, not raise (the old code called ``_tool_verify`` directly, and it raises ToolError), and it
must leave the workspace byte-identical to how it found it.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402
import offline_coder  # noqa: E402
import offline_repair  # noqa: E402


def _report(*fail_lines: str) -> str:
    return "VERIFY FAILED\n" + "\n".join(fail_lines)


class ParseVerifyReportTests(unittest.TestCase):
    """Table-driven against the literal grammar agent._tool_verify emits."""

    def test_each_producer_format_parses_to_the_right_check(self) -> None:
        rel, exc, output, label = "src/app.py", "invalid syntax", "SyntaxError: bad", "pytest"
        cases: list[tuple[str, str, str]] = [
            # (literal FAIL line, expected path, expected check)
            (f"FAIL {rel}: {exc}", rel, "python"),
            ("FAIL conf/data.json: Expecting value: line 1 column 1", "conf/data.json", "json"),
            (f"FAIL ci.yml: YAML parse failed: {exc}", "ci.yml", "yaml"),
            (f"FAIL app.js: node --check failed: {output}", "app.js", "node"),
            (f"FAIL run.sh: bash syntax check failed: {output}", "run.sh", "bash"),
            (f"FAIL pyproject.toml: TOML parse failed: {exc}", "pyproject.toml", "toml"),
            (f"FAIL app.service: config parse failed: {exc}", "app.service", "ini"),
            ("FAIL Dockerfile: unknown Dockerfile directive 'FRM' on line 1", "Dockerfile", "dockerfile"),
            (f"FAIL deploy.ps1: PowerShell parse failed: {output}", "deploy.ps1", "powershell"),
            (
                "FAIL .env.example: likely real secrets in example file: line 2 key API_KEY: looks like a GitHub token",
                ".env.example",
                "secrets",
            ),
            (f"FAIL tests failed ({label}): {output}", "", "tests"),
        ]
        for line, expected_path, expected_check in cases:
            with self.subTest(line=line):
                parsed = offline_repair.parse_verify_report(_report(line))
                self.assertEqual(len(parsed), 1, parsed)
                self.assertEqual(parsed[0].path, expected_path)
                self.assertEqual(parsed[0].check, expected_check)

    def test_a_passing_report_yields_no_failures(self) -> None:
        self.assertEqual(offline_repair.parse_verify_report("VERIFY PASSED\nOK   a.py (python syntax)"), [])

    def test_line_number_is_extracted_when_present(self) -> None:
        parsed = offline_repair.parse_verify_report(_report("FAIL a.py: '(' was never closed (a.py, line 7)"))
        self.assertEqual(parsed[0].line, 7)

    def test_multiline_test_output_folds_into_one_failure(self) -> None:
        report = _report("FAIL tests failed (pytest): E   assert 1 == 2", "  in test_thing", "1 failed")
        parsed = offline_repair.parse_verify_report(report)
        self.assertEqual(len(parsed), 1)
        self.assertIn("in test_thing", parsed[0].message)

    def test_unrecognized_fail_line_is_kept_as_unknown_not_dropped(self) -> None:
        parsed = offline_repair.parse_verify_report(_report("FAIL something entirely new"))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].check, "unknown")


class RepairTableTests(unittest.TestCase):
    def test_a_secret_finding_is_a_hard_stop_with_zero_proposals(self) -> None:
        report = _report(
            "FAIL .env.example: likely real secrets in example file: line 2 key API_KEY: looks like a GitHub token"
        )
        failures = offline_repair.parse_verify_report(report)
        self.assertTrue(offline_repair.hard_stop(failures))
        self.assertIn("GitHub token", offline_repair.hard_stop(failures))
        with tempfile.TemporaryDirectory() as td:
            proposals = offline_repair.propose_repairs(
                failures, Path(td), applied_ops=[{"kind": "new_file", "path": ".env.example"}]
            )
        self.assertEqual(proposals, [], "auto-editing a credential finding is exactly the wrong move")

    def test_a_broken_file_this_run_created_is_reverted_not_patched(self) -> None:
        failures = offline_repair.parse_verify_report(_report("FAIL new.py: '(' was never closed (new.py, line 1)"))
        with tempfile.TemporaryDirectory() as td:
            proposals = offline_repair.propose_repairs(
                failures, Path(td), applied_ops=[{"kind": "new_file", "path": "new.py"}]
            )
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0]["action"], "revert")
        self.assertTrue(proposals[0]["needs_brain"])
        self.assertIn("syntax error", proposals[0]["reason"])

    def test_a_file_this_run_never_touched_is_left_alone(self) -> None:
        failures = offline_repair.parse_verify_report(_report("FAIL theirs.py: invalid syntax"))
        with tempfile.TemporaryDirectory() as td:
            proposals = offline_repair.propose_repairs(
                failures, Path(td), applied_ops=[{"kind": "new_file", "path": "ours.py"}]
            )
        self.assertEqual(proposals, [], "the coder must never revert a file it did not write")

    def test_yaml_and_node_failures_revert_rather_than_guess(self) -> None:
        for line, rel in (
            ("FAIL ci.yml: YAML parse failed: mapping values are not allowed", "ci.yml"),
            ("FAIL app.js: node --check failed: SyntaxError", "app.js"),
        ):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as td:
                failures = offline_repair.parse_verify_report(_report(line))
                proposals = offline_repair.propose_repairs(
                    failures, Path(td), applied_ops=[{"kind": "new_file", "path": rel}]
                )
                self.assertEqual([p["action"] for p in proposals], ["revert"])

    def test_a_missing_name_becomes_an_add_import_when_the_definition_is_locatable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "corelib.py").write_text("def compute_total(items):\n    return sum(items)\n", encoding="utf-8")
            (root / "test_compute_total.py").write_text(
                "import unittest\n\n\nclass T(unittest.TestCase):\n"
                "    def test_compute_total_placeholder(self):\n        compute_total([])\n",
                encoding="utf-8",
            )
            failures = offline_repair.parse_verify_report(
                _report("FAIL tests failed (pytest): NameError: name 'compute_total' is not defined")
            )
            proposals = offline_repair.propose_repairs(
                failures, root, applied_ops=[{"kind": "new_file", "path": "test_compute_total.py"}]
            )
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0]["action"], "edit_op")
        self.assertEqual(proposals[0]["op"], "add_import")
        self.assertEqual(proposals[0]["args"], {"module": "corelib", "names": ["compute_total"]})

    def test_an_unlocatable_name_falls_back_to_revert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "test_x.py").write_text("import unittest\n", encoding="utf-8")
            failures = offline_repair.parse_verify_report(
                _report("FAIL tests failed (pytest): NameError: name 'nowhere_defined' is not defined")
            )
            proposals = offline_repair.propose_repairs(
                failures, root, applied_ops=[{"kind": "new_file", "path": "test_x.py"}]
            )
        self.assertEqual([p["action"] for p in proposals], ["revert"])

    def test_our_own_failing_scaffold_is_skipped_not_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "test_thing.py").write_text(
                "import unittest\n\n\nclass T(unittest.TestCase):\n"
                "    def test_thing_placeholder(self):\n        self.assertTrue(False)\n",
                encoding="utf-8",
            )
            failures = offline_repair.parse_verify_report(
                _report("FAIL tests failed (pytest): FAILED test_thing.py::T::test_thing_placeholder")
            )
            proposals = offline_repair.propose_repairs(
                failures, root, applied_ops=[{"kind": "new_file", "path": "test_thing.py"}]
            )
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0]["op"], "wrap_ast")
        self.assertEqual(proposals[0]["args"]["transform"], "decorate")
        self.assertIn("unittest.skip", proposals[0]["args"]["decorator"])

    def test_a_scaffold_name_the_run_did_not_create_is_never_touched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            failures = offline_repair.parse_verify_report(
                _report("FAIL tests failed (pytest): FAILED test_thing.py::T::test_thing_placeholder")
            )
            # applied_ops names a DIFFERENT file, so the scaffold repair must not fire on test_thing.py
            proposals = offline_repair.propose_repairs(
                failures, Path(td), applied_ops=[{"kind": "new_file", "path": "test_other.py"}]
            )
        self.assertTrue(all(p["path"] != "test_thing.py" for p in proposals), proposals)


class ScannerGateTests(unittest.TestCase):
    def test_clean_files_pass_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "ok.py").write_text("VALUE = 1\n", encoding="utf-8")
            ok, notes = offline_repair.scanner_gate(Path(td), ["ok.py"])
        self.assertTrue(ok, notes)

    def test_no_paths_is_a_trivial_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(offline_repair.scanner_gate(Path(td), []), (True, []))

    def test_an_unavailable_scanner_fails_open_but_says_undetermined(self) -> None:
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(sys.modules, {"bughunter.code_scanner": None}):
            ok, notes = offline_repair.scanner_gate(Path(td), ["a.py"])
        self.assertTrue(ok)
        self.assertTrue(any("undetermined" in note for note in notes), notes)


class RestoreTests(unittest.TestCase):
    def _box(self, root: Path) -> agent.ToolBox:
        return agent.ToolBox(root, dict(agent.AGENT_DEFAULTS))

    def test_restores_an_edited_file_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = "ALPHA = 1\nBETA = 2\n"
            (root / "keep.py").write_text(original, encoding="utf-8")
            box = self._box(root)
            box.run("edit_file", {"path": "keep.py", "old_string": "ALPHA = 1", "new_string": "ALPHA = 99"})
            self.assertNotEqual((root / "keep.py").read_text(encoding="utf-8"), original)
            notes = offline_repair.restore_all(box)
            self.assertEqual((root / "keep.py").read_text(encoding="utf-8"), original)
            self.assertTrue(any("restored" in n for n in notes), notes)
            self.assertEqual(box.changes, [], "a reverted file must not linger in the Workbench diff")

    def test_removes_a_file_the_run_created(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            box = self._box(root)
            box.run("write_file", {"path": "made.py", "content": "x = 1\n"})
            offline_repair.restore_all(box)
            self.assertFalse((root / "made.py").exists())
            self.assertNotIn("made.py", box.touched)


class RunAgentRepairIntegrationTests(unittest.TestCase):
    """The confirmed defect: _run_offline called toolbox._tool_verify() DIRECTLY, and that raises
    ToolError on failure — so a failing offline verify escaped run_agent as an exception instead of
    being reported. It must now come back as an honest failed result."""

    def _plan(self) -> dict:
        return {
            "ops": [
                {"kind": "edit_op", "path": "keeper.py", "op": "add_import", "args": {"module": "json"}},
                {"kind": "new_file", "path": "broken.py", "content": "def oops(:\n"},
            ],
            "needs_brain": False,
            "summary": "two ops",
        }

    def test_failed_verify_returns_an_honest_result_and_rolls_everything_back(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            original = "import os\n\n\ndef alpha():\n    return os.name\n"
            (root / "keeper.py").write_text(original, encoding="utf-8")
            with mock.patch.object(agent, "plan_task", return_value=[]), \
                 mock.patch.object(offline_coder, "plan_edits", return_value=self._plan()):
                result = agent.run_agent("do the thing", [], ws, {})  # must NOT raise
            self.assertEqual(result["provider"], "offline")
            self.assertFalse(result["verified"], "a run whose verify failed can never report verified")
            self.assertFalse(result["completed"])
            self.assertEqual(
                (root / "keeper.py").read_text(encoding="utf-8"), original,
                "an edited file must come back byte-identical from the snapshot",
            )
            self.assertFalse((root / "broken.py").exists(), "the invalid file must not survive")
            self.assertIn("broken.py", result["text"])
            self.assertIn("[python]", result["text"])

    def test_a_valid_edit_op_run_verifies_and_keeps_the_change(self) -> None:
        plan = {
            "ops": [{"kind": "edit_op", "path": "keeper.py", "op": "add_import", "args": {"module": "json"}}],
            "needs_brain": False,
            "summary": "added an import",
        }
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            (root / "keeper.py").write_text("import os\n\n\ndef alpha():\n    return os.name\n", encoding="utf-8")
            with mock.patch.object(agent, "plan_task", return_value=[]), \
                 mock.patch.object(offline_coder, "plan_edits", return_value=plan):
                result = agent.run_agent("add an import", [], ws, {})
            self.assertTrue(result["verified"], result["text"])
            self.assertTrue(result["completed"])
            self.assertIn("import json", (root / "keeper.py").read_text(encoding="utf-8"))
            self.assertEqual(result["touched_files"], ["keeper.py"])

    def test_an_unknown_op_kind_is_a_transcript_error_not_a_crash(self) -> None:
        plan = {"ops": [{"kind": "teleport", "path": "x.py"}], "needs_brain": False, "summary": "?"}
        with tempfile.TemporaryDirectory() as ws:
            with mock.patch.object(agent, "plan_task", return_value=[]), \
                 mock.patch.object(offline_coder, "plan_edits", return_value=plan):
                result = agent.run_agent("teleport", [], ws, {})
            rows = [r for r in result["transcript"] if r["tool"] == "unknown"]
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["is_error"])
            self.assertIn("unsupported op: teleport", rows[0]["output"])

    def test_an_edit_op_on_a_missing_file_is_refused_without_writing(self) -> None:
        plan = {
            "ops": [{"kind": "edit_op", "path": "gone.py", "op": "add_import", "args": {"module": "json"}}],
            "needs_brain": False,
            "summary": "?",
        }
        with tempfile.TemporaryDirectory() as ws:
            with mock.patch.object(agent, "plan_task", return_value=[]), \
                 mock.patch.object(offline_coder, "plan_edits", return_value=plan):
                result = agent.run_agent("edit it", [], ws, {})
            self.assertFalse((Path(ws) / "gone.py").exists())
            self.assertEqual(result["touched_files"], [])
            self.assertTrue(any(r["is_error"] for r in result["transcript"]))


if __name__ == "__main__":
    unittest.main()
