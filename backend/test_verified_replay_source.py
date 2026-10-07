"""Verified lessons must reach TinyGPT training and retrieval as their own source."""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# solin_core imports torch at module scope. Keep the full test suite collectible
# in the lean build and on machines where that optional runtime is absent.
if importlib.util.find_spec("torch") is None:  # pragma: no cover - environment-dependent
    raise unittest.SkipTest("torch is not installed; TinyGPT retrieval is unavailable")

import greyiq_api as api
import solin_core
from ai_core.core_store import AICoreStore, default_sources
from learning_engine import LearningEngine
from training_runtime import _selected_text_paths, load_all_text


class VerifiedReplaySourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_new_verified_lesson_reaches_live_retrieval(self) -> None:
        knowledge = solin_core.KnowledgeBase(self.root)
        self.assertFalse(knowledge.search("specific boundary evidence", min_score=0.0))
        LearningEngine(self.root).record_correction(
            "How should we prove a boundary failure?",
            "Capture specific boundary evidence and a negative control.",
            source="GreyNOC operator correction",
            tool_verified=True,
            security_sensitive=True,
        )
        matches = knowledge.search("specific boundary evidence", min_score=0.0,
                                   source_ids=["src_verified_replay"])
        self.assertTrue(any(match.source_id == "src_verified_replay" for match in matches))

    def test_verified_lesson_is_selected_for_training_and_retrieval(self) -> None:
        record = LearningEngine(self.root).record_correction(
            "What must an authorized bug bounty proof include?",
            "A confirmed finding needs captured evidence and a meaningful negative control.",
            source="GreyNOC operator correction",
            tool_verified=True,
            security_sensitive=True,
        )
        self.assertEqual(record["outcome"], "verified")
        replay = self.root / "data" / "greyiq_verified_replay.txt"
        self.assertEqual(_selected_text_paths(replay.parent, ["src_verified_replay"]), [replay])
        self.assertNotIn(replay, _selected_text_paths(replay.parent, ["src_imported_docs"]))
        self.assertIn("meaningful negative control", load_all_text(
            self.root, source_ids=["src_verified_replay"]))

        knowledge = solin_core.KnowledgeBase(self.root)
        matches = knowledge.search("meaningful negative control", source_ids=["src_verified_replay"],
                                   min_score=0.0)
        self.assertTrue(any(match.source == replay.name and match.source_id == "src_verified_replay"
                            for match in matches))
        self.assertFalse(knowledge.search("meaningful negative control",
                                          source_ids=["src_imported_docs"], min_score=0.0))

    def test_bughunter_and_studio_select_verified_lessons(self) -> None:
        self.assertEqual(api.normalize_source_ids(["src_verified_replay"]), ["src_verified_replay"])
        self.assertIn("src_verified_replay", api.BUGHUNTER_CORE["sourceIds"])
        source = next(row for row in default_sources() if row["id"] == "src_verified_replay")
        self.assertIn(api.BUGHUNTER_CORE_ID, source["includedCores"])

        js = (BACKEND_DIR.parent / "public" / "app.js").read_text(encoding="utf-8")
        defaults = re.search(r"const DEFAULT_SELECTED_TRAINING_SOURCES = \[(.*?)\];", js, re.S)
        self.assertIsNotNone(defaults)
        self.assertIn('"src_verified_replay"', defaults.group(1))
        self.assertIn('id: "src_verified_replay"', js)

    def test_existing_bughunter_core_is_upgraded_once(self) -> None:
        store = AICoreStore(self.root)
        old_core = dict(api.BUGHUNTER_CORE)
        old_core.pop("_verified_replay_source_v1")
        old_core["sourceIds"] = ["src_bug_bounty"]
        store.save_core(old_core)
        runtime = object.__new__(api.GreyIQRuntime)
        runtime.store = store
        runtime._ensure_bughunter_core()

        core = next(row for row in store.load()["cores"] if row["id"] == api.BUGHUNTER_CORE_ID)
        self.assertIn("src_verified_replay", core["sourceIds"])
        self.assertTrue(core["_verified_replay_source_v1"])

        core["sourceIds"].remove("src_verified_replay")
        state = store.load()
        next(row for row in state["cores"] if row["id"] == api.BUGHUNTER_CORE_ID)["sourceIds"] = core["sourceIds"]
        store.save(state)
        runtime._ensure_bughunter_core()
        core = next(row for row in store.load()["cores"] if row["id"] == api.BUGHUNTER_CORE_ID)
        self.assertNotIn("src_verified_replay", core["sourceIds"])

    def test_preference_api_cannot_overwrite_verified_replay(self) -> None:
        with self.assertRaises(api.HTTPError) as caught:
            api.source_training_file("src_verified_replay")
        self.assertEqual(caught.exception.status_code, 422)


if __name__ == "__main__":
    unittest.main()
