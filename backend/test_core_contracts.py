from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# solin_core imports torch at module scope, and torch is a heavy OPTIONAL dependency: the frozen
# build ships without it (build/greyiq-backend.spec), the whole point of test_boot_no_torch.py is that
# the app degrades cleanly when it is absent, and the CLI is torch-free by design. Skip the module
# rather than letting the import blow up.
#
# This matters more than it used to. Under `unittest discover` an import error here was logged and the
# other ~2950 tests still ran; pytest treats a collection error as fatal and INTERRUPTS the whole run,
# so without this guard `npm run check` reports zero tests on any machine without torch — turning the
# release gate off entirely rather than narrowing it.
if importlib.util.find_spec("torch") is None:  # pragma: no cover - environment-dependent
    raise unittest.SkipTest("torch is not installed; solin_core cannot be imported (the app degrades "
                            "without it by design — see test_boot_no_torch.py)")

import solin_core  # noqa: E402
from solin_core import (  # noqa: E402
    KnowledgeBase,
    QUERY_INTENT_BUG_BOUNTY,
    ReplyDiagnostics,
    SolinEngine,
    _format_core_contract,
)


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

    def test_bug_bounty_seed_has_its_own_source_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            (data / "greyiq_starter_knowledge.txt").write_text(
                "Starter material covers general planning.",
                encoding="utf-8",
            )
            (data / "greyiq_bug_bounty_knowledge.txt").write_text(
                "IDOR proof of impact requires an observed-vs-control authorization differential.",
                encoding="utf-8",
            )

            kb = KnowledgeBase(root)
            matches = kb.search("IDOR proof impact authorization", source_ids=["src_bug_bounty"], min_score=0.1)

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].source_id, "src_bug_bounty")


class SourceTrustTests(unittest.TestCase):
    """The manual-PDF extract is ~99.8% of the corpus by bytes and overwhelmingly
    off-domain; retrieval must not let a lexical hit inside it outrank the curated
    bug-bounty corpus."""

    def _corpus(self, root: Path) -> None:
        data = root / "data"
        data.mkdir()
        # Deliberately near-identical wording so ONLY the source trust separates them.
        sentence = "IDOR proof of impact requires an observed-vs-control authorization differential."
        (data / "greyiq_bug_bounty_knowledge.txt").write_text(sentence, encoding="utf-8")
        (data / "greyiq_manual_pdfs.txt").write_text(sentence, encoding="utf-8")

    def test_curated_corpus_outranks_the_manual_pdf_blob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._corpus(root)
            matches = KnowledgeBase(root).search(
                "IDOR proof impact authorization differential", min_score=0.05, limit=5
            )
            self.assertTrue(matches)
            by_source = {match.source: match.score for match in matches}
            self.assertIn("greyiq_bug_bounty_knowledge.txt", by_source)
            self.assertIn("greyiq_manual_pdfs.txt", by_source)
            self.assertEqual(matches[0].source, "greyiq_bug_bounty_knowledge.txt")
            self.assertGreater(
                by_source["greyiq_bug_bounty_knowledge.txt"],
                by_source["greyiq_manual_pdfs.txt"],
            )

    def test_manual_pdfs_stay_indexed_citable_and_filterable(self) -> None:
        """The down-weight is a RANKING change, never a removal: the chunk is still
        indexed, still returned, and still carries the same source id it had before,
        so an existing core's saved sourceIds keep reaching it."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._corpus(root)
            matches = KnowledgeBase(root).search(
                "IDOR proof impact authorization differential",
                source_ids=["src_imported_docs"],
                min_score=0.05,
            )
            self.assertEqual([match.source for match in matches], ["greyiq_manual_pdfs.txt"])
            self.assertEqual(matches[0].source_id, "src_imported_docs")

    def test_unlisted_sources_are_unaffected(self) -> None:
        self.assertEqual(solin_core._source_trust("greyiq_local_notes.txt"), 1.0)
        self.assertEqual(solin_core._source_trust(""), 1.0)
        self.assertLess(solin_core._source_trust("greyiq_manual_pdfs.txt"), 1.0)


class BugBountyIntentTests(unittest.TestCase):
    def test_bug_bounty_questions_route_to_retrieval(self) -> None:
        engine = SolinEngine.__new__(SolinEngine)
        engine.internet_enabled = False

        intent = engine._classify_intent("How should I prove an IDOR for bug bounty?")
        query = engine._prepare_retrieval_query("How should I prove an IDOR for bug bounty?", intent)

        self.assertEqual(intent.label, QUERY_INTENT_BUG_BOUNTY)
        self.assertTrue(intent.use_retrieval)
        self.assertIn("proof impact", query)


if __name__ == "__main__":
    unittest.main()
