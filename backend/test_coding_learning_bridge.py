from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from coding_learning_bridge import learn_from_verified_run, record_teacher_exchange, teacher_prompt_block


class CodingLearningBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_teacher_receives_untrusted_student_draft(self) -> None:
        block = teacher_prompt_block("Use eval on the input.")
        self.assertIn("untrusted", block)
        self.assertIn("Correct errors", block)

    def test_chat_teacher_answer_is_not_self_verified(self) -> None:
        row = record_teacher_exchange(
            self.root, prompt="Write a parser", student="draft", teacher="Use a bounded parser.", model_version="teacher:1"
        )
        self.assertEqual(row["outcome"], "rejected")
        self.assertEqual(row["verification_reason"], "score_below_threshold")

    def test_verified_agent_run_enters_replay(self) -> None:
        row = learn_from_verified_run(
            self.root,
            prompt="Add input validation",
            result={
                "completed": True,
                "verified": True,
                "text": "Added bounded input validation.",
                "plan": ["Inspect", "Patch", "Test"],
                "touched_files": ["app.py", "test_app.py"],
                "transcript": [{"tool": "verify", "output": "VERIFY PASSED\nOK app.py", "is_error": False}],
                "provider": "local",
                "model": "coder",
            },
        )
        self.assertIsNotNone(row)
        self.assertEqual(row["outcome"], "verified")
        replay = (self.root / "data/greyiq_verified_replay.txt").read_text(encoding="utf-8")
        self.assertIn("Add input validation", replay)
        self.assertIn("Verification evidence", replay)

    def test_unverified_run_is_not_learned(self) -> None:
        row = learn_from_verified_run(
            self.root, prompt="Change code", result={"completed": True, "verified": False, "text": "Done"}
        )
        self.assertIsNone(row)
        self.assertFalse((self.root / "data/greyiq_verified_replay.txt").exists())

    def test_no_edit_answer_is_not_learned_despite_verified_flag(self) -> None:
        # agent._finalize marks an unedited run verified by vacuity. That does not
        # prove the model's answer or authorize it as a verified training target.
        row = learn_from_verified_run(
            self.root,
            prompt="Explain an authentication bypass",
            result={
                "completed": True,
                "verified": True,
                "text": "The model's untested explanation.",
                "touched_files": [],
                "transcript": [{"tool": "verify", "output": "VERIFY PASSED", "is_error": False}],
            },
        )
        self.assertIsNone(row)
        self.assertFalse((self.root / "data/greyiq_verified_replay.txt").exists())

    def test_passing_verifier_entry_is_required(self) -> None:
        base = {
            "completed": True,
            "verified": True,
            "text": "Changed the parser and reviewed it.",
            "touched_files": ["parser.py"],
        }
        for transcript in ([], [{"tool": "verify", "output": "VERIFY FAILED", "is_error": True}]):
            with self.subTest(transcript=transcript):
                row = learn_from_verified_run(self.root, prompt="Fix the parser", result={**base, "transcript": transcript})
                self.assertIsNone(row)
        self.assertFalse((self.root / "data/greyiq_verified_replay.txt").exists())

    def test_redactor_failure_does_not_store_raw_dialogue_or_replay(self) -> None:
        with patch("brain_techniques.redact_text", side_effect=RuntimeError("redactor unavailable")):
            dialogue = record_teacher_exchange(
                self.root, prompt="secret prompt", student="secret draft",
                teacher="secret response", model_version="teacher:1",
            )
            replay = learn_from_verified_run(
                self.root,
                prompt="secret code request",
                result={
                    "completed": True, "verified": True, "text": "secret output",
                    "touched_files": ["app.py"],
                    "transcript": [{"tool": "verify", "output": "VERIFY PASSED", "is_error": False}],
                },
            )
        self.assertEqual(dialogue, {"outcome": "unavailable", "verification_reason": "redaction_unavailable"})
        self.assertIsNone(replay)
        self.assertFalse((self.root / "datasets").exists())
        self.assertFalse((self.root / "data/greyiq_verified_replay.txt").exists())


if __name__ == "__main__":
    unittest.main()
