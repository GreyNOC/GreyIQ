"""Tests for the autonomous operator core: portfolio store, finding ledger
(cross-run dedup + funnel), EV ranking, and the run-cycle's submit safety gates."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import ledger, operator, portfolio, ranking  # noqa: E402


class PortfolioTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_upsert_and_get(self) -> None:
        p = portfolio.upsert_program(self.rt, {"name": "Acme", "scope_text": "*.acme.com", "seed_targets": ["https://acme.com"]})
        self.assertTrue(p["id"])
        self.assertEqual(portfolio.get_program(self.rt, p["id"])["name"], "Acme")

    def test_empty_scope_fails_closed(self) -> None:
        # No scope -> active/live/auto_submit forced off (an empty scope no-ops the gate).
        p = portfolio.upsert_program(self.rt, {"name": "NoScope", "active": True, "auto_submit": True})
        self.assertFalse(p["active"])
        self.assertFalse(p["auto_submit"])

    def test_deep_implies_active_and_requires_scope(self) -> None:
        # Deep on with scope -> deep stays on AND active is forced on (deep implies proof).
        p = portfolio.upsert_program(self.rt, {"name": "D", "scope_text": "d.com", "deep": True, "active": False})
        self.assertTrue(p["deep"])
        self.assertTrue(p["active"])
        # Deep with no scope -> forced off (fail-closed, like active/live).
        p2 = portfolio.upsert_program(self.rt, {"name": "NoScopeDeep", "deep": True})
        self.assertFalse(p2["deep"])

    def test_auto_submit_requires_handle(self) -> None:
        p = portfolio.upsert_program(self.rt, {"name": "X", "scope_text": "x.com", "auto_submit": True, "platform": "manual"})
        self.assertFalse(p["auto_submit"])  # no hackerone handle -> can't auto-submit
        p2 = portfolio.upsert_program(self.rt, {"name": "Y", "scope_text": "y.com", "auto_submit": True,
                                                "platform": "hackerone", "platform_handle": "yteam"})
        self.assertTrue(p2["auto_submit"])


def _finding(ref, cls, rule, loc, sev="high", proof="confirmed", cvss=8.0):
    return {"ref": ref, "class_id": cls, "rule_id": rule, "location": loc, "severity": sev,
            "title": f"{cls} at {loc}", "proof_status": proof}


def _item(ref, cls, rule, loc, sev="high", proof="confirmed", cvss=8.0):
    return {"finding": _finding(ref, cls, rule, loc, sev, proof), "source_url": loc,
            "proof_status": proof, "cvss": {"base_score": cvss}, "source_json": ""}


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_dedup_key_stable_across_digit_change(self) -> None:
        a = ledger.dedup_key(_finding("F1", "xss", "r", "https://x/a/123"))
        b = ledger.dedup_key(_finding("F2", "xss", "r", "https://x/a/456"))
        self.assertEqual(a, b)  # digits normalized to N

    def test_upsert_marks_duplicate_after_reported(self) -> None:
        items = [_item("C1", "xss", "r", "https://x/a")]
        ledger.upsert_findings(self.rt, "acme", "https://x", items)
        self.assertFalse(items[0]["duplicate_of_prior"])
        ledger.mark_reported(self.rt, "acme", "https://x", items[0]["finding"])
        # Re-run: same finding is now a prior-reported duplicate.
        items2 = [_item("C1", "xss", "r", "https://x/a")]
        ledger.upsert_findings(self.rt, "acme", "https://x", items2)
        self.assertTrue(items2[0]["duplicate_of_prior"])
        self.assertTrue(ledger.is_duplicate(self.rt, "acme", "https://x", items2[0]["finding"]))

    def test_confirmed_stage_only_on_confirmed_proof(self) -> None:
        ledger.upsert_findings(self.rt, "acme", "https://x", [_item("C1", "xss", "r", "https://x/a", proof="missing")])
        f = ledger.funnel(self.rt, "acme")
        self.assertEqual(f["stages"]["confirmed"], 0)
        self.assertEqual(f["stages"]["discovered"], 1)

    def test_recent_submission_throttle_count(self) -> None:
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        self.assertEqual(ledger.count_recent_submissions(self.rt, "acme"), 1)


class RankingTests(unittest.TestCase):
    def test_confirmed_outranks_unconfirmed_despite_pay_factor(self) -> None:
        confirmed = _item("A", "xss", "r", "x", sev="low", proof="confirmed", cvss=2.0)
        unconfirmed = _item("B", "rce", "r", "y", sev="critical", proof="missing", cvss=9.8)
        # Even a critical unconfirmed with a paying class must NOT outrank a confirmed.
        program_stats = {"rce": {"submitted": 5, "rewarded": 5, "noise": 0, "bounty_total": 5000.0}}
        ranked = ranking.rank_by_ev([unconfirmed, confirmed], {}, program_stats)
        self.assertEqual(ranked[0]["finding"]["ref"], "A")  # confirmed first

    def test_ev_factors_bounded(self) -> None:
        item = _item("A", "xss", "r", "x", proof="confirmed", cvss=8.0)
        ev = ranking.expected_value(item, {"xss": 99.0}, {"xss": {"rewarded": 99, "noise": 0, "bounty_total": 1e9, "submitted": 99}})
        self.assertLessEqual(ev["breakdown"]["prior"], 2.0)
        self.assertLessEqual(ev["breakdown"]["program_pay_factor"], 2.0)


class OperatorCycleTests(unittest.TestCase):
    """The submit safety gates: review-only never submits; armed+opt-in+confirmed does;
    dedup blocks re-file; the per-day throttle caps; the kill switch halts."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = self._tmp.name
        self.submits: list[tuple[str, str]] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _program(self, **kw):
        base = {"id": "acme", "scope_text": "*.acme.com", "seed_targets": ["https://acme.com"],
                "active": True, "auto_submit": True, "platform": "hackerone", "platform_handle": "acme",
                "max_submits_per_day": 3, "max_pages": 8, "interval_minutes": 1440}
        base.update(kw)
        return base

    def _run_campaign_fn(self, target, *, scope, program, active, live, deep=False, max_pages=12):
        self.last_deep = deep  # record so a test can assert deep was threaded through
        # One confirmed finding per run.
        f = _finding("C1", "xss", "active.reflected-xss", f"{target}/?q=", proof="confirmed")
        # ledger.upsert_findings normally runs inside run_campaign — simulate it here.
        ledger.upsert_findings(self.rt, program, target, [{"finding": f, "source_url": f["location"],
                                                           "proof_status": "confirmed", "cvss": {"base_score": 6.1}}])
        return {"ok": True, "run_id": "run-1", "findings": [f], "proof_of_impact": {"C1": {"status": "confirmed"}}}

    def _submit_fn(self, run_id, ref):
        self.submits.append((run_id, ref))
        return {"ok": True, "report_id": f"R{len(self.submits)}", "url": "https://h1/r"}

    def test_review_only_never_submits(self) -> None:
        # submit_fn=None => review-only, even though the program opts into auto_submit.
        s = operator.run_program_cycle(self.rt, self._program(), run_campaign_fn=self._run_campaign_fn, submit_fn=None)
        self.assertEqual(self.submits, [])
        self.assertEqual(s["confirmed"], 1)

    def test_deep_flag_is_threaded_to_the_campaign(self) -> None:
        self.last_deep = None
        operator.run_program_cycle(self.rt, self._program(deep=True), run_campaign_fn=self._run_campaign_fn, submit_fn=None)
        self.assertTrue(self.last_deep)   # the program's deep flag reached run_campaign_fn
        self.last_deep = None
        operator.run_program_cycle(self.rt, self._program(deep=False), run_campaign_fn=self._run_campaign_fn, submit_fn=None)
        self.assertFalse(self.last_deep)

    def test_armed_auto_submit_files_confirmed(self) -> None:
        s = operator.run_program_cycle(self.rt, self._program(), run_campaign_fn=self._run_campaign_fn, submit_fn=self._submit_fn)
        self.assertEqual(len(self.submits), 1)
        self.assertEqual(s["submitted"], 1)

    def test_dedup_blocks_refile_on_second_cycle(self) -> None:
        op = dict(self._program())
        operator.run_program_cycle(self.rt, op, run_campaign_fn=self._run_campaign_fn, submit_fn=self._submit_fn)
        operator.run_program_cycle(self.rt, op, run_campaign_fn=self._run_campaign_fn, submit_fn=self._submit_fn)
        self.assertEqual(len(self.submits), 1)  # the second cycle's identical finding is a dup -> not re-filed

    def test_throttle_caps_per_day(self) -> None:
        # Five distinct confirmed findings, cap of 2/day -> only 2 filed.
        calls = {"n": 0}
        def many_fn(target, *, scope, program, active, live, deep=False, max_pages=12):
            calls["n"] += 1
            f = _finding(f"C{calls['n']}", "xss", "active.reflected-xss", f"{target}/p{calls['n']}", proof="confirmed")
            ledger.upsert_findings(self.rt, program, target, [{"finding": f, "source_url": f["location"], "proof_status": "confirmed", "cvss": {"base_score": 6.1}}])
            return {"ok": True, "run_id": "r", "findings": [f], "proof_of_impact": {f["ref"]: {"status": "confirmed"}}}
        prog = self._program(max_submits_per_day=2, seed_targets=["https://a", "https://b", "https://c", "https://d", "https://e"])
        operator.run_program_cycle(self.rt, prog, run_campaign_fn=many_fn, submit_fn=self._submit_fn)
        self.assertEqual(len(self.submits), 2)


if __name__ == "__main__":
    unittest.main()
