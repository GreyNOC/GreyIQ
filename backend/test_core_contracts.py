from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from solin_core import KnowledgeBase, ReplyDiagnostics, _format_core_contract  # noqa: E402


class CoreContractTests(unittest.TestCase):
    def test_core_contract_compacts_behavior_metadata(self) -> None:
        contract = _format_core_contract(
            {
                "mode": "Build Partner",
                "personality": "direct",
                "responseContract": ["lead_with_the_answer", "offer_the_next_useful_action"],
                "confidencePolicy": ["cite_local_sources", "name_uncertainty"],
                "trustContract": {
                    "uncertainty": "Separate fact from inference.",
                    "citations": "Cite local documents when they influence the answer.",
                },
            }
        )

        self.assertIn("Build Partner", contract)
        self.assertIn("lead with the answer", contract)
        self.assertIn("cite local sources", contract)
        self.assertIn("Separate fact from inference", contract)

    def test_reply_diagnostics_exposes_ui_fields(self) -> None:
        diagnostics = ReplyDiagnostics(used_fallback=True)

        self.assertTrue(diagnostics.used_fallback)
        self.assertEqual(diagnostics.intent_label, "")
        self.assertEqual(diagnostics.strategy, "")
        self.assertEqual(diagnostics.confidence, 0.0)
        self.assertEqual(diagnostics.retrieval_count, 0)


class PreferenceTrainingTests(unittest.TestCase):
    def test_disliked_response_is_avoidance_signal_not_preferred_exchange(self) -> None:
        previous_runtime_dir = os.environ.get("GREYIQ_RUNTIME_DIR")
        previous_module = sys.modules.get("greyiq_api")
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.environ["GREYIQ_RUNTIME_DIR"] = tmp
                sys.modules.pop("greyiq_api", None)
                greyiq_api = importlib.import_module("greyiq_api")

                disliked_request = greyiq_api.PreferenceRequest(
                    bot={"name": "Forge"},
                    user="Fix this failing test.",
                    assistant="Just rewrite everything without checking.",
                    rating="dislike",
                )
                disliked_file, disliked_text = greyiq_api.preference_training_entry(disliked_request)

                liked_request = greyiq_api.PreferenceRequest(
                    bot={"name": "Forge"},
                    user="Fix this failing test.",
                    assistant="Run the failing test, isolate the assertion, and patch the smallest boundary.",
                    rating="like",
                )
                liked_file, liked_text = greyiq_api.preference_training_entry(liked_request)
            finally:
                if previous_runtime_dir is None:
                    os.environ.pop("GREYIQ_RUNTIME_DIR", None)
                else:
                    os.environ["GREYIQ_RUNTIME_DIR"] = previous_runtime_dir
                if previous_module is None:
                    sys.modules.pop("greyiq_api", None)
                else:
                    sys.modules["greyiq_api"] = previous_module

        self.assertEqual(disliked_file, "greyiq_personal_choices.txt")
        self.assertIn("should avoid this response pattern", disliked_text)
        self.assertNotIn("<ASSISTANT>", disliked_text)
        self.assertEqual(liked_file, "greyiq_preferred_examples.txt")
        self.assertIn("<ASSISTANT>", liked_text)


class KnowledgeSourceFilterTests(unittest.TestCase):
    def test_search_respects_source_id_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            (data / "greyiq_starter_knowledge.txt").write_text(
                "Starter material covers general planning and troubleshooting.",
                encoding="utf-8",
            )
            (data / "greyiq_imported_docs.txt").write_text(
                "Vector database retrieval should rank semantic document matches.",
                encoding="utf-8",
            )

            kb = KnowledgeBase(root)

            starter_matches = kb.search(
                "vector database retrieval",
                source_ids=["src_starter_knowledge"],
                min_score=0.1,
            )
            imported_matches = kb.search(
                "vector database retrieval",
                source_ids=["src_imported_docs"],
                min_score=0.1,
            )

            self.assertEqual(starter_matches, [])
            self.assertEqual(len(imported_matches), 1)
            self.assertEqual(imported_matches[0].source_id, "src_imported_docs")


if __name__ == "__main__":
    unittest.main()
