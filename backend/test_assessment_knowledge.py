"""Retrieval contract for the curated security assessment cards."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import solin_domain  # noqa: E402


class AssessmentKnowledgeTests(unittest.TestCase):
    def setUp(self) -> None:
        # Use the full shipped pack: the new cards must win against existing bounty,
        # red-team, and webapp cards for the questions they are meant to answer.
        self.pack = solin_domain.load_pack(BACKEND_DIR / "seed")

    def test_representative_questions_select_a_cited_verbatim_card(self) -> None:
        cases = (
            (
                "How should I choose the next falsifiable security hypothesis for an authorized target?",
                "choose-the-next-falsifiable-hypothesis",
            ),
            (
                "How do I design a differential negative control to distinguish a false positive from a vulnerability?",
                "design-a-differential-control",
            ),
            (
                "When should we stop an authorized assessment probe after an unexpected block or out-of-scope redirect?",
                "gate-the-experiment-by-authorization-and-stop-conditions",
            ),
            (
                "Is this security finding confirmed or only a candidate based on the evidence?",
                "calibrate-a-finding-to-the-observed-evidence",
            ),
            (
                "How do I verify the root cause and regression test a security fix?",
                "verify-the-root-cause-and-its-fix",
            ),
        )
        for question, section in cases:
            with self.subTest(section=section):
                matches = solin_domain.match_cards_scored(question, self.pack)
                self.assertTrue(matches, question)
                primary, score = matches[0]
                self.assertEqual(primary.card_id, f"domain/assessment.md#{section}")
                self.assertGreaterEqual(score, solin_domain.MIN_SCORE)

                excerpt = solin_domain.verbatim_excerpt(primary, question)
                answer = solin_domain.compose_answer(
                    question, [card for card, _ in matches], primary.domain
                )
                self.assertTrue(excerpt)
                self.assertIn(excerpt, primary.body)
                self.assertIn(excerpt, answer)
                self.assertIn("Source: domain/assessment.md", answer)
                self.assertNotIn("<!-- triggers:", answer)

    def test_off_domain_questions_do_not_inherit_security_advice(self) -> None:
        for question in (
            "What is the best way to choose a movie tonight?",
            "How do I make a great dinner?",
            "How do I choose a retirement account?",
        ):
            with self.subTest(question=question):
                self.assertEqual(
                    solin_domain.match_cards_scored(
                        question, self.pack, min_score=solin_domain.MIN_SCORE_RELAXED
                    ),
                    [],
                )


if __name__ == "__main__":
    unittest.main()
