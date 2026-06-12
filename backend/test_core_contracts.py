from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from solin_core import KnowledgeBase, _format_core_contract  # noqa: E402


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
