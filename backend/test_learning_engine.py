from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from learning_engine import Experience, ExperienceScore, LearningEngine, ModelRegistry, is_security_sensitive


class LearningEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.engine = LearningEngine(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_unverified_self_rating_is_rejected(self) -> None:
        exp = Experience(
            prompt="What normally uses TCP port 443?",
            response="HTTPS normally uses TCP port 443.",
            score=ExperienceScore(knowledge_confidence=1, critic_score=1, novelty_score=1),
        )
        result = self.engine.record(exp)
        self.assertEqual(result["outcome"], "rejected")
        self.assertTrue((self.root / "datasets/failures/experiences.jsonl").exists())

    def test_verified_correction_enters_deduplicated_replay(self) -> None:
        for _ in range(2):
            result = self.engine.record_correction(
                "What service normally uses TCP port 443?",
                "HTTPS normally uses TCP port 443.",
                source="GreyNOC manual",
                tool_verified=True,
            )
            self.assertEqual(result["outcome"], "verified")
        replay = (self.root / "datasets/replay/verified_replay.txt").read_text(encoding="utf-8")
        self.assertEqual(replay.count("<START_CONVO>"), 1)
        self.assertEqual(replay.count("HTTPS normally uses TCP port 443."), 1)
        self.assertEqual(replay, (self.root / "data/greyiq_verified_replay.txt").read_text(encoding="utf-8"))

    def test_security_requires_explicit_verified_answer(self) -> None:
        score = ExperienceScore(1, 1, 1, 0, 1, 1, 1)
        exp = Experience(
            prompt="Explain an SSRF vulnerability safely.",
            response="An SSRF lets server-side requests cross a trust boundary.",
            source="manual",
            security_sensitive=True,
            score=score,
        )
        result = self.engine.record(exp)
        self.assertEqual(result["verification_reason"], "security_answer_not_explicitly_verified")
        self.assertTrue(is_security_sensitive("Explain an SSRF vulnerability"))
        self.assertFalse(is_security_sensitive("Write a friendly greeting"))

    def test_records_expected_schema(self) -> None:
        self.engine.record_correction("Question here", "Verified answer here", source="manual", tool_verified=True)
        line = (self.root / "datasets/verified/experiences.jsonl").read_text(encoding="utf-8").splitlines()[0]
        record = json.loads(line)
        self.assertIn("learning_score", record)
        self.assertIn("model_version", record)
        self.assertIn("timestamp", record)
        self.assertEqual(record["schema_version"], 1)

    def test_status_reports_pools_and_weaknesses(self) -> None:
        self.engine.record(Experience(prompt="Question here", response="An unverified answer here."))
        status = self.engine.status()
        self.assertEqual(status["conversations"], 1)
        self.assertEqual(status["failures"], 1)
        self.assertEqual(status["verified"], 0)
        self.assertTrue(status["weaknesses"])


class ModelRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.registry = ModelRegistry(self.root)
        self.source = self.root / "model.pt"
        self.source.write_bytes(b"candidate-weights")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_promotes_first_candidate_and_rejects_regression(self) -> None:
        first = self.registry.stage_candidate(self.source, {"accuracy": 0.8, "loss": 1.0})
        self.assertTrue(self.registry.promote_if_better(first, {"accuracy": 0.8, "loss": 1.0}))
        second = self.registry.stage_candidate(self.source, {"accuracy": 0.79, "loss": 0.9})
        self.assertFalse(self.registry.promote_if_better(second, {"accuracy": 0.79, "loss": 0.9}))
        manifest = json.loads((self.root / "checkpoints/registry.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["last_decision"], "rollback")
        self.assertEqual(manifest["stable_metrics"], {"accuracy": 0.8, "loss": 1.0})

    def test_promotes_only_when_no_metric_regresses(self) -> None:
        first = self.registry.stage_candidate(self.source, {"accuracy": 0.8, "loss": 1.0})
        self.registry.promote_if_better(first, {"accuracy": 0.8, "loss": 1.0})
        second = self.registry.stage_candidate(self.source, {"accuracy": 0.82, "loss": 0.9})
        self.assertTrue(self.registry.promote_if_better(second, {"accuracy": 0.82, "loss": 0.9}))
        self.assertTrue(any((self.root / "checkpoints/rollback").iterdir()))


if __name__ == "__main__":
    unittest.main()
