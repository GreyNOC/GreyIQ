"""The outcome loop: real platform verdicts into the learning store, autonomously.

WHY THIS IS THE LOOP THAT MATTERED
----------------------------------
Everything else the engine learns is self-observed and already worked: negative knowledge
cools an ``(endpoint, class)`` pair after two misses, and trace priors reweight classes from
its own confirmations. Neither needs a human.

What it could not learn on its own was what PAYS. At submit time the engine records
``status="submitted"``, which ``learning.learned_priors`` discards on purpose — "I sent it"
is not "it paid". The only adjudicated source is the platform, and the sync that reaches it
existed ONLY as a method on the HTTP API runtime. So on any terminal-driven install the
payout priors stayed ``{}`` for ever, ``ranking._program_pay_factor`` stayed at its neutral
1.0, and the operator hunted programs in alphabetical order no matter which had ever paid.

These tests pin, in order of consequence:
  1. A terminal verdict becomes a payout prior — the loop actually closes.
  2. An in-progress state records NO outcome, so a sync never invents a premature verdict.
  3. A closed report is never re-polled, which is what keeps the pass rate-limit-safe.
  4. The operator runs it BEFORE hunting, so the same cycle's ranking sees fresh outcomes.
  5. It fails soft — no credentials, a network error, a bad report: reported, never raised.

Every test injects ``fetch_status``; nothing here touches the network.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import learning, ledger, operator, outcome_sync, portfolio  # noqa: E402

TARGET = "https://app.example.com"


def _resolved(amount: float = 750.0):
    def fetch(report_id, username, token, **_):
        return {"ok": True, "id": report_id, "state": "resolved",
                "bounty_awarded_at": "2026-10-11T00:00:00Z", "total_awarded_amount": amount}
    return fetch


def _state(state: str):
    def fetch(report_id, username, token, **_):
        return {"ok": True, "id": report_id, "state": state}
    return fetch


class _Store(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def seed_submitted(self, program: str = "acme", class_id: str = "xss",
                       report_id: str = "123456") -> str:
        items = ledger.upsert_findings(self.rt, program, TARGET, [{
            "ref": "F1", "class_id": class_id, "title": "a finding",
            "severity": "high", "proof_status": "confirmed",
        }])
        key = items[0]["dedup_key"]
        ledger.record_submission(self.rt, program, TARGET, key, report_id)
        return key

    def sync(self, fetch, **kw):
        return outcome_sync.sync_outcomes(self.rt, api_username="u", api_token="t",
                                          fetch_status=fetch, **kw)


class LoopClosesTests(_Store):
    def test_a_terminal_verdict_becomes_a_payout_prior(self) -> None:
        self.seed_submitted()
        self.assertEqual(learning.learned_priors(self.rt, "acme", TARGET), {},
                         "a submitted-but-unadjudicated finding must carry no prior")
        result = self.sync(_resolved(750.0))
        self.assertTrue(result["ok"])
        self.assertEqual(result["outcomes"], 1)
        priors = learning.learned_priors(self.rt, "acme", TARGET)
        self.assertIn("xss", priors, "the loop did not close")
        self.assertGreater(priors["xss"], 1.0)

    def test_the_reward_amount_reaches_the_program_yield(self) -> None:
        """Program ordering reads this, so a lost amount is a lost ranking signal."""
        self.seed_submitted()
        self.sync(_resolved(1500.0))
        summary = learning.program_summary(self.rt, "acme", TARGET)
        self.assertEqual(summary["rewarded"], 1)
        self.assertEqual(summary["bounty_total"], 1500.0)

    def test_a_non_rewarded_terminal_state_still_teaches(self) -> None:
        """A duplicate is real information — it should damp the class, not be dropped."""
        self.seed_submitted(class_id="sqli")
        result = self.sync(_state("duplicate"))
        self.assertEqual(result["outcomes"], 1)
        self.assertEqual(learning.program_summary(self.rt, "acme", TARGET)["bounty_total"], 0.0)


class NeverInventsAVerdictTests(_Store):
    def test_an_in_progress_state_records_no_outcome(self) -> None:
        """new / triaged / needs-more-info / retesting are not over yet. Recording one as an
        outcome would teach the ranker a verdict the program has not reached."""
        for state in ("new", "triaged", "needs-more-info", "retesting", "pending-program-review"):
            with self.subTest(state=state):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                rt = Path(tmp.name)
                items = ledger.upsert_findings(rt, "acme", TARGET, [{
                    "ref": "F1", "class_id": "xss", "title": "t", "severity": "high",
                    "proof_status": "confirmed"}])
                ledger.record_submission(rt, "acme", TARGET, items[0]["dedup_key"], "1")
                result = outcome_sync.sync_outcomes(rt, api_username="u", api_token="t",
                                                    fetch_status=_state(state))
                self.assertEqual(result["outcomes"], 0, f"{state} must teach nothing")
                self.assertEqual(learning.learned_priors(rt, "acme", TARGET), {})

    def test_an_in_progress_state_still_updates_the_ledger(self) -> None:
        """It is real news for the ledger even when it is not yet an outcome."""
        self.seed_submitted()
        result = self.sync(_state("triaged"))
        self.assertEqual(result["updated"], 1)
        self.assertEqual(result["outcomes"], 0)

    def test_only_terminal_states_are_mapped(self) -> None:
        self.assertEqual(set(outcome_sync.H1_STATE_TO_LEARNING_OUTCOME),
                         {"resolved", "duplicate", "not-applicable", "informative", "spam"})


class RateSafetyTests(_Store):
    def test_a_closed_report_is_never_re_polled(self) -> None:
        """What keeps a per-pass sync inside the platform's report-read limit."""
        self.seed_submitted()
        first = self.sync(_resolved())
        self.assertEqual(first["checked"], 1)
        second = self.sync(_resolved())
        self.assertEqual(second["checked"], 0)
        self.assertEqual(second["outcomes"], 0)

    def test_an_unchanged_in_progress_report_records_nothing_twice(self) -> None:
        self.seed_submitted()
        self.sync(_state("triaged"))
        again = self.sync(_state("triaged"))
        self.assertEqual(again["updated"], 0)

    def test_the_poll_is_capped(self) -> None:
        """The cap is what keeps a per-pass sync under the platform's report-read limit.

        Distinct CLASSES, not distinct URLs: the ledger's dedup key normalizes digit runs,
        so eight `/0`..`/7` paths collapse into one record and would seed nothing to cap.
        """
        for cls in ("xss", "sqli", "ssrf", "rce", "auth", "csrf", "cors", "redirect"):
            items = ledger.upsert_findings(self.rt, "acme", TARGET, [{
                "ref": "F1", "class_id": cls, "title": cls, "severity": "high",
                "proof_status": "confirmed"}])
            ledger.record_submission(self.rt, "acme", TARGET, items[0]["dedup_key"], cls)
        self.assertEqual(self.sync(_state("triaged"), limit=3)["checked"], 3)


class FailSoftTests(_Store):
    def test_missing_credentials_is_reported_not_raised(self) -> None:
        for username, token in (("", "t"), ("u", ""), ("", "")):
            with self.subTest(creds=(bool(username), bool(token))):
                result = outcome_sync.sync_outcomes(self.rt, api_username=username, api_token=token)
                self.assertFalse(result["ok"])
                self.assertIn("token", result["error"])
                self.assertEqual(result["outcomes"], 0)

    def test_a_failed_fetch_is_collected_and_the_pass_continues(self) -> None:
        self.seed_submitted(report_id="1")
        def failing(report_id, username, token, **_):
            return {"ok": False, "error": "rate limited"}
        result = self.sync(failing)
        self.assertTrue(result["ok"], "one bad report must not fail the whole pass")
        self.assertEqual(result["outcomes"], 0)
        self.assertTrue(any("rate limited" in e for e in result["errors"]))

    def test_an_empty_ledger_is_a_clean_no_op(self) -> None:
        result = self.sync(_resolved())
        self.assertTrue(result["ok"])
        self.assertEqual((result["checked"], result["updated"], result["outcomes"]), (0, 0, 0))


class OperatorWiringTests(_Store):
    """The operator end: the sync must run, and must run BEFORE the hunt."""

    def _program(self, **over):
        return portfolio.upsert_program(self.rt, {
            "name": "acme", "scope_text": "example.com", "seed_targets": [TARGET],
            "active": True, **over})

    def test_the_cycle_syncs_before_it_hunts(self) -> None:
        """If it synced after, this cycle's EV ranking would still see stale priors."""
        self.seed_submitted(program="acme", class_id="sqli")
        program = self._program()
        seen = {}

        def run_fn(target, *, scope, program, active, live, deep=False, iterate=False, max_pages=12):
            seen["priors"] = learning.learned_priors(self.rt, program, target)
            return {"ok": True, "run_id": "r1", "findings": [], "proof_of_impact": {}}

        operator.run_program_cycle(
            str(self.rt), program, run_campaign_fn=run_fn,
            sync_fn=lambda: self.sync(_resolved(900.0)))
        self.assertIn("sqli", seen["priors"],
                      "the hunt ran before the sync — it saw stale priors")

    def test_no_sync_fn_is_a_silent_no_op(self) -> None:
        operator.run_program_cycle(str(self.rt), self._program(),
                                   run_campaign_fn=lambda *a, **k: {"ok": True, "findings": []})
        # sync_fn omitted

    def test_a_raising_sync_never_stops_the_cycle(self) -> None:
        events: list[str] = []
        def boom():
            raise RuntimeError("platform unreachable")
        summary = operator.run_program_cycle(
            str(self.rt), self._program(), run_campaign_fn=lambda *a, **k: {"ok": True, "findings": []},
            sync_fn=boom, on_event=events.append)
        self.assertIsNotNone(summary)
        self.assertTrue(any("outcome sync error" in e for e in events))

    def test_a_credentialless_sync_is_reported_once_and_tolerated(self) -> None:
        events: list[str] = []
        operator.run_program_cycle(
            str(self.rt), self._program(), run_campaign_fn=lambda *a, **k: {"ok": True, "findings": []},
            on_event=events.append,
            sync_fn=lambda: outcome_sync.sync_outcomes(self.rt, api_username="", api_token=""))
        self.assertTrue(any("outcome sync skipped" in e for e in events))


class YieldOrderingTests(_Store):
    """The operator must hunt what has paid first, and be unchanged until something has."""

    def _loop(self):
        return operator.OperatorLoop(str(self.rt), run_campaign_fn=lambda *a, **k: {})

    @staticmethod
    def _due(*ids: str) -> list[tuple[dict, None]]:
        """The queue shape _supervise builds: (program, grant) per due program.

        The grant is irrelevant to ordering — rank() reads entry[0] only — but passing the
        real pair is what keeps this test honest about the signature it is exercising.
        """
        return [({"id": pid}, None) for pid in ids]

    @staticmethod
    def _ids(ordered) -> list[str]:
        return [program["id"] for program, _grant in ordered]

    def test_a_cold_portfolio_keeps_the_old_alphabetical_order(self) -> None:
        due = self._due("alpha", "mid", "zeta")
        self.assertEqual(self._ids(self._loop()._by_yield(due)),
                         ["alpha", "mid", "zeta"])

    def test_the_payer_leads(self) -> None:
        learning.record_outcome(self.rt, program="zeta", target="", class_id="xss", title="t",
                                status="resolved", severity="high", bounty=5000.0)
        learning.record_outcome(self.rt, program="mid", target="", class_id="xss", title="t",
                                status="resolved", severity="low", bounty=100.0)
        learning.record_outcome(self.rt, program="alpha", target="", class_id="xss", title="t",
                                status="duplicate", severity="low")
        due = self._due("alpha", "mid", "zeta")
        self.assertEqual(self._ids(self._loop()._by_yield(due)),
                         ["zeta", "mid", "alpha"])

    def test_ordering_never_drops_a_program(self) -> None:
        due = self._due("a", "b", "c")
        self.assertEqual(len(self._loop()._by_yield(due)), 3)


class RetrainWiringTests(_Store):
    def test_only_a_written_model_is_announced(self) -> None:
        """`ok` is True for a dry run too, and `reason` is prose — `written` is the signal."""
        loop = operator.OperatorLoop(str(self.rt), run_campaign_fn=lambda *a, **k: {},
                                     train_fn=lambda: {"ok": True, "reason": "dry run"})
        loop._retrain()
        self.assertFalse([e for e in loop.events if "promoted" in e.get("message", "")])

        loop.train_fn = lambda: {"ok": True, "written": True, "active_model": "m.json",
                                 "trained_on": {"rows": 400}}
        loop._retrain()
        self.assertTrue([e for e in loop.events if "promoted" in e.get("message", "")])

    def test_a_refusal_is_silent(self) -> None:
        """Too few rows is the normal outcome for a long time; an event every pass is noise."""
        loop = operator.OperatorLoop(str(self.rt), run_campaign_fn=lambda *a, **k: {},
                                     train_fn=lambda: {"ok": False, "reason": "too few rows"})
        loop._retrain()
        self.assertEqual(list(loop.events), [])

    def test_a_raising_trainer_never_stops_the_loop(self) -> None:
        def boom():
            raise RuntimeError("corpus unreadable")
        loop = operator.OperatorLoop(str(self.rt), run_campaign_fn=lambda *a, **k: {},
                                     train_fn=boom)
        loop._retrain()
        self.assertTrue([e for e in loop.events if "retrain error" in e.get("message", "")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
