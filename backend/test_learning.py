"""Tests for the BugHunter learning loop (deterministic outcome memory)."""
from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import learning  # noqa: E402


class ProgramKeyTests(unittest.TestCase):
    def test_explicit_handle_is_normalized(self) -> None:
        self.assertEqual(learning.program_key("Acme Corp!", ""), "acme-corp")

    def test_falls_back_to_registrable_domain(self) -> None:
        self.assertEqual(learning.program_key(None, "https://shop.example.com/x"), "example.com")
        # A multi-label public suffix (co.uk) must NOT collapse a real eTLD+1 down to the
        # bare suffix -- that would merge two unrelated programs' memory into one bucket.
        self.assertEqual(learning.program_key("", "api.staging.example.co.uk"), "example.co.uk")

    def test_different_co_uk_apexes_get_different_keys(self) -> None:
        # Regression: before the public-suffix-aware fix, BOTH of these collapsed to the
        # single bucket 'co.uk', contaminating cross-program learning/dedup state.
        a = learning.program_key(None, "https://shop.example.co.uk/x")
        b = learning.program_key(None, "https://foo.bar.co.uk/y")
        self.assertNotEqual(a, b)
        self.assertEqual(a, "example.co.uk")
        self.assertEqual(b, "bar.co.uk")

    def test_empty_is_default(self) -> None:
        self.assertEqual(learning.program_key(None, ""), "default")


class RecordAndPriorsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_unknown_status_rejected(self) -> None:
        with self.assertRaises(ValueError):
            learning.record_outcome(self.rt, program="p", class_id="xss", status="banana")

    def test_record_accumulates_and_persists(self) -> None:
        learning.record_outcome(self.rt, program="acme", class_id="xss", status="accepted", bounty=500.0)
        prog = learning.record_outcome(self.rt, program="acme", class_id="xss", status="resolved", bounty=250.0)
        stats = prog["class_stats"]["xss"]
        self.assertEqual(stats["submitted"], 2)
        self.assertEqual(stats["rewarded"], 2)
        self.assertEqual(stats["bounty_total"], 750.0)
        # Survives a reload.
        self.assertEqual(learning.program_summary(self.rt, "acme")["bounty_total"], 750.0)

    def test_rewarding_class_gets_boost_noise_gets_penalty(self) -> None:
        for _ in range(3):
            learning.record_outcome(self.rt, program="acme", class_id="xss", status="accepted", bounty=100.0)
        for _ in range(3):
            learning.record_outcome(self.rt, program="acme", class_id="clickjacking", status="duplicate")
        priors = learning.learned_priors(self.rt, "acme")
        self.assertGreater(priors["xss"], 1.0)
        self.assertLess(priors["clickjacking"], 1.0)
        # Bounded.
        self.assertLessEqual(priors["xss"], 2.0)
        self.assertGreaterEqual(priors["clickjacking"], 0.5)

    def test_priors_absent_without_history(self) -> None:
        self.assertEqual(learning.learned_priors(self.rt, "never-seen"), {})

    def test_unadjudicated_submissions_carry_no_prior(self) -> None:
        # A class with only "submitted" rows (no accepted/duplicate yet) has no signal.
        learning.record_outcome(self.rt, program="acme", class_id="xss", status="submitted")
        learning.record_outcome(self.rt, program="acme", class_id="xss", status="submitted")
        self.assertNotIn("xss", learning.learned_priors(self.rt, "acme"))

    def test_rescan_does_not_dilute_an_earned_prior(self) -> None:
        # The bug: re-running a campaign auto-logs the same confirmed finding as
        # "submitted", which must NOT pull an earned prior back toward neutral.
        learning.record_outcome(self.rt, program="acme", class_id="ssrf", status="accepted", bounty=300.0)
        baseline = learning.learned_priors(self.rt, "acme")["ssrf"]
        for _ in range(5):  # five weekly re-scans auto-log "submitted"
            learning.record_outcome(self.rt, program="acme", class_id="ssrf", status="submitted")
        self.assertEqual(learning.learned_priors(self.rt, "acme")["ssrf"], baseline)

    def test_intelligence_notes(self) -> None:
        learning.record_outcome(self.rt, program="acme", class_id="ssrf", status="resolved", bounty=1000.0)
        learning.record_outcome(self.rt, program="acme", class_id="clickjacking", status="duplicate")
        learning.record_outcome(self.rt, program="acme", class_id="clickjacking", status="informative")
        notes = learning.program_intelligence(self.rt, "acme")
        joined = "\n".join(notes)
        self.assertIn("ssrf", joined)
        self.assertIn("prioritize", joined)
        self.assertIn("clickjacking", joined)

    def test_concurrent_record_outcome_never_loses_an_update(self) -> None:
        # Regression: record_outcome() did a bare _load -> mutate -> _save with no
        # lock (unlike ledger.py/portfolio.py, which both wrap their read-modify-
        # write cycle in a threading.Lock()) -- two threads recording an outcome for
        # the SAME program at nearly the same time could both read the same stale
        # "submitted" count and each write back count+1, silently losing one of the
        # two updates (a classic lost-update race). This matters once campaign
        # targets can run concurrently (record_outcome is called once per
        # confirmed+submitted finding per target).
        threads = [threading.Thread(target=lambda: learning.record_outcome(
            self.rt, program="acme", class_id="xss", status="submitted")) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        stats = learning.program_summary(self.rt, "acme")["class_stats"]["xss"]
        self.assertEqual(stats["submitted"], 20, "no concurrent update may be silently lost")

    def test_summary_all_programs(self) -> None:
        learning.record_outcome(self.rt, program="a", class_id="xss", status="accepted", bounty=100.0)
        learning.record_outcome(self.rt, program="b", class_id="rce", status="resolved", bounty=2000.0)
        summary = learning.program_summary(self.rt)
        self.assertIn("a", summary["programs"])
        self.assertIn("b", summary["programs"])
        self.assertEqual(summary["programs"]["b"]["bounty_total"], 2000.0)


class CorruptedStoreTests(unittest.TestCase):
    """A hand-edited or corrupted bughunter_learning.json (non-numeric rewarded/noise/
    bounty_total) must degrade gracefully -- learned_priors feeds ranking.rank_by_ev,
    which campaign.py calls UNGUARDED mid-campaign, so any crash here aborts the run."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)
        corrupted = {
            "programs": {
                "acme": {
                    "class_stats": {
                        "xss": {"submitted": "many", "rewarded": "lots", "noise": None, "bounty_total": "lots-of-cash"},
                    },
                    "findings": [],
                    "updated_at": "now",
                }
            }
        }
        import json
        (self.rt / "bughunter_learning.json").write_text(json.dumps(corrupted), encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_learned_priors_does_not_crash(self) -> None:
        priors = learning.learned_priors(self.rt, "acme")
        self.assertIsInstance(priors, dict)

    def test_program_summary_does_not_crash(self) -> None:
        summary = learning.program_summary(self.rt, "acme")
        self.assertIsInstance(summary["bounty_total"], float)

    def test_program_intelligence_does_not_crash(self) -> None:
        notes = learning.program_intelligence(self.rt, "acme")
        self.assertIsInstance(notes, list)


if __name__ == "__main__":
    unittest.main()
