"""Tests for the agent work-engine completion status: a run reports an honest
``completed`` / ``verified`` / ``outstanding`` triple, and a step-limit finish
runs a final verify and names what is left. Offline — no model is invoked; the
completion helpers operate on a real ToolBox over a temp workspace."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402


def _settings(**overrides: object) -> dict[str, object]:
    settings = dict(agent.AGENT_DEFAULTS)
    settings.update(overrides)
    return settings


class CompletionStatusTests(unittest.TestCase):
    def _box(self) -> tuple[agent.ToolBox, "tempfile.TemporaryDirectory[str]"]:
        tmp = tempfile.TemporaryDirectory()
        return agent.ToolBox(Path(tmp.name), _settings()), tmp

    def test_no_changes_is_clean_and_verified(self) -> None:
        box, tmp = self._box()
        with tmp:
            result = agent._finalize("(done)", [], box, "m", "anthropic", completed=True)
            self.assertTrue(result["completed"])
            self.assertTrue(result["verified"])  # nothing to verify counts as verified
            self.assertEqual(result["outstanding"], [])

    def test_touched_but_unverified_is_not_complete(self) -> None:
        box, tmp = self._box()
        with tmp:
            box.run("write_file", {"path": "a.py", "content": "x = 1\n"})
            self.assertTrue(box.touched)
            self.assertFalse(box.verified_ok)
            result = agent._finalize("(done)", [], box, "m", "anthropic", completed=True)
            self.assertFalse(result["completed"])  # a write without verify is not "done"
            self.assertFalse(result["verified"])
            self.assertTrue(any("not verified" in item for item in result["outstanding"]))

    def test_verified_change_is_complete(self) -> None:
        box, tmp = self._box()
        with tmp:
            box.run("write_file", {"path": "a.py", "content": "x = 1\n"})
            box.run("verify", {})  # valid python → verified_ok True
            self.assertTrue(box.verified_ok)
            result = agent._finalize("(done)", [], box, "m", "anthropic", completed=True)
            self.assertTrue(result["completed"])
            self.assertTrue(result["verified"])
            self.assertEqual(result["outstanding"], [])

    def test_step_limit_runs_final_verify_and_names_remaining_broken_file(self) -> None:
        box, tmp = self._box()
        with tmp:
            box.run("write_file", {"path": "broken.py", "content": "def (:\n"})  # syntax error
            transcript: list[dict[str, object]] = []
            text = agent._step_limit_text(box, transcript, on_event=None)
            # A verify was appended by the step-limit finish.
            self.assertTrue(any(entry.get("tool") == "verify" for entry in transcript))
            self.assertIn("step limit", text.lower())
            self.assertIn("broken.py", text)  # outstanding names the unverified file
            result = agent._finalize(text, transcript, box, "m", "anthropic", completed=False)
            self.assertFalse(result["completed"])

    def test_step_limit_clean_when_changes_verify(self) -> None:
        box, tmp = self._box()
        with tmp:
            box.run("write_file", {"path": "ok.py", "content": "y = 2\n"})
            transcript: list[dict[str, object]] = []
            text = agent._step_limit_text(box, transcript, on_event=None)
            # Final verify passed, so the only outstanding item is the step-limit note,
            # which is folded into the lead sentence — no "still outstanding" block.
            self.assertTrue(box.verified_ok)
            self.assertNotIn("Still outstanding", text)
            self.assertIn("Re-run", text)


if __name__ == "__main__":
    unittest.main()
