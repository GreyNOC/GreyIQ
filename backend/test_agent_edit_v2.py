"""Tests for the v2 coding-agent edit tools: edit_file replace_all + the atomic
multi_edit (all-or-nothing multi-site edits in one file, routed through the same
snapshot/rollback machinery as every other write)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402


def _settings(**overrides):
    s = dict(agent.AGENT_DEFAULTS)
    s.update(overrides)
    return s


class EditV2Tests(unittest.TestCase):
    def _box(self):
        tmp = tempfile.TemporaryDirectory()
        return agent.ToolBox(Path(tmp.name), _settings()), tmp

    def test_replace_all_replaces_every_occurrence(self):
        box, tmp = self._box()
        with tmp:
            p = Path(box.root) / "a.txt"
            p.write_text("foo foo foo\n", encoding="utf-8")
            out, err = box.run("edit_file", {"path": "a.txt", "old_string": "foo",
                                             "new_string": "bar", "replace_all": True})
            self.assertFalse(err, out)
            self.assertEqual(p.read_text(encoding="utf-8"), "bar bar bar\n")

    def test_non_unique_without_replace_all_is_error(self):
        box, tmp = self._box()
        with tmp:
            p = Path(box.root) / "a.txt"
            p.write_text("foo foo\n", encoding="utf-8")
            out, err = box.run("edit_file", {"path": "a.txt", "old_string": "foo", "new_string": "bar"})
            self.assertTrue(err)
            self.assertIn("not unique", out)
            self.assertEqual(p.read_text(encoding="utf-8"), "foo foo\n")  # untouched

    def test_multi_edit_applies_all_in_order(self):
        box, tmp = self._box()
        with tmp:
            p = Path(box.root) / "cfg.py"
            p.write_text("HOST = 'old'\nPORT = 1\nDEBUG = False\n", encoding="utf-8")
            out, err = box.run("multi_edit", {"path": "cfg.py", "edits": [
                {"old_string": "HOST = 'old'", "new_string": "HOST = 'new'"},
                {"old_string": "PORT = 1", "new_string": "PORT = 8080"},
                {"old_string": "DEBUG = False", "new_string": "DEBUG = True"},
            ]})
            self.assertFalse(err, out)
            self.assertIn("Applied 3 edit(s)", out)
            self.assertEqual(p.read_text(encoding="utf-8"), "HOST = 'new'\nPORT = 8080\nDEBUG = True\n")

    def test_multi_edit_is_atomic_on_failure(self):
        box, tmp = self._box()
        with tmp:
            p = Path(box.root) / "cfg.py"
            p.write_text("HOST = 'old'\nPORT = 1\n", encoding="utf-8")
            out, err = box.run("multi_edit", {"path": "cfg.py", "edits": [
                {"old_string": "HOST = 'old'", "new_string": "HOST = 'new'"},
                {"old_string": "NOT_PRESENT", "new_string": "x"},  # this fails
            ]})
            self.assertTrue(err)
            self.assertIn("edit #2 failed", out)
            self.assertIn("no changes written", out)
            # Atomic: the first (valid) edit must NOT have landed.
            self.assertEqual(p.read_text(encoding="utf-8"), "HOST = 'old'\nPORT = 1\n")
            self.assertNotIn("cfg.py", {c["path"] for c in box.change_payload()})

    def test_multi_edit_sequential_dependency(self):
        # Edit 2 matches text produced by edit 1 — edits apply to the running state, in order.
        box, tmp = self._box()
        with tmp:
            p = Path(box.root) / "a.txt"
            p.write_text("alpha\n", encoding="utf-8")
            out, err = box.run("multi_edit", {"path": "a.txt", "edits": [
                {"old_string": "alpha", "new_string": "beta"},
                {"old_string": "beta", "new_string": "gamma"},
            ]})
            self.assertFalse(err, out)
            self.assertEqual(p.read_text(encoding="utf-8"), "gamma\n")

    def test_multi_edit_records_change_for_rollback(self):
        box, tmp = self._box()
        with tmp:
            p = Path(box.root) / "a.txt"
            p.write_text("one\n", encoding="utf-8")
            box.run("multi_edit", {"path": "a.txt", "edits": [{"old_string": "one", "new_string": "two"}]})
            snap = {s["path"]: s for s in box.snapshot_payload()}
            self.assertIn("a.txt", snap)
            self.assertEqual(snap["a.txt"]["content"], "one\n")  # original captured for undo


if __name__ == "__main__":
    unittest.main()
