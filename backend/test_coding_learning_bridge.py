from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
