"""Configured chat receives bounded curated security references when relevant."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api  # noqa: E402


class ConfiguredSecurityContextTests(unittest.TestCase):
    def test_relevant_chat_receives_bundled_reference_data(self) -> None:
        runtime = greyiq_api.GreyIQRuntime()
        captured: list[str] = []

        def fake_generate(_messages: object, cfg: dict[str, object]) -> dict[str, str]:
            captured.append(str(cfg["system_prompt"]))
            return {"text": "Use a control and preserve the evidence.",
                    "provider": "local", "model": "test"}

        with patch.object(runtime, "_coder_config", return_value={"enabled": True}), \
             patch.object(greyiq_api.coder, "reasoning_brain_enabled", return_value=True), \
             patch.object(greyiq_api.coder, "coder_config",
                          return_value={"provider": "local", "system_prompt": "Base prompt", "history_turns": 12}), \
             patch.object(greyiq_api.coder, "generate", side_effect=fake_generate), \
             patch.object(greyiq_api.coding_learning_bridge, "student_draft", return_value=""), \
             patch.object(greyiq_api.coding_learning_bridge, "record_teacher_exchange",
                          return_value={"outcome": "skipped"}):
            reply = runtime._coder_reply(greyiq_api.ChatRequest(
                message="How do I design a differential negative control to validate a security finding?"
            ))

        self.assertIsNotNone(reply)
        self.assertTrue(reply["brain_dialogue"]["knowledge_context_used"])
        self.assertEqual(len(captured), 1)
        self.assertIn("untrusted_reference_data", captured[0])
        self.assertIn("domain/assessment.md#design-a-differential-control", captured[0])
        self.assertIn("not proof of any target finding", captured[0])

    def test_unrelated_chat_does_not_receive_security_context(self) -> None:
        runtime = greyiq_api.GreyIQRuntime()
        captured: list[str] = []

        def fake_generate(_messages: object, cfg: dict[str, object]) -> dict[str, str]:
            captured.append(str(cfg["system_prompt"]))
            return {"text": "Hello.", "provider": "local", "model": "test"}

        with patch.object(runtime, "_coder_config", return_value={"enabled": True}), \
             patch.object(greyiq_api.coder, "reasoning_brain_enabled", return_value=True), \
             patch.object(greyiq_api.coder, "coder_config",
                          return_value={"provider": "local", "system_prompt": "Base prompt", "history_turns": 12}), \
             patch.object(greyiq_api.coder, "generate", side_effect=fake_generate), \
             patch.object(greyiq_api.coding_learning_bridge, "student_draft", return_value=""), \
             patch.object(greyiq_api.coding_learning_bridge, "record_teacher_exchange",
                          return_value={"outcome": "skipped"}):
            reply = runtime._coder_reply(greyiq_api.ChatRequest(message="How do I bake sourdough bread?"))

        self.assertIsNotNone(reply)
        self.assertFalse(reply["brain_dialogue"]["knowledge_context_used"])
        self.assertNotIn("untrusted_reference_data", captured[0])


if __name__ == "__main__":
    unittest.main()
