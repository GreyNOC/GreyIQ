"""Tests for the BugHunter hunt trace log (the offline-brain distillation corpus)."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hunt_trace, ledger  # noqa: E402

_SURFACE = {
    "endpoints": ["https://app.example.com/search", "https://app.example.com/download"],
    "params": ["q", "file"],
    "tech": ["flask", "jinja"],
    "forms": [{"action": "/login", "method": "POST", "params": ["user", "pass"]}],
}
_PLAN = {
    "used": True, "provider": "offline", "model": "greyiq-offline-hunt",
    "param_hypotheses": ["redirect", "callback"],
    "probe_priority": [{"endpoint": "https://app.example.com/search", "classes": ["xss", "sqli"], "why": "reflected q"}],
    "idor_candidates": [], "privileged_endpoints": [], "ssrf_params": ["url"], "xss_params": ["q"],
}


def _consolidated(dedup_key: str = "") -> list[dict]:
    return [
        {"finding": {"class_id": "xss", "rule_id": "active.xss", "location": "https://app.example.com/search", "severity": "medium"},
         "source_url": "https://app.example.com/search", "proof_status": "confirmed", "dedup_key": dedup_key},
        {"finding": {"class_id": "sqli", "rule_id": "active.sqli", "location": "https://app.example.com/search", "severity": "high"},
         "source_url": "https://app.example.com/search", "proof_status": "missing"},
    ]


class RecordAndLoadTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_record_writes_one_jsonl_line_with_expected_shape(self) -> None:
        ok = hunt_trace.record_trace(self.rt, program="acme", target="https://app.example.com/",
                                     surface=_SURFACE, plan=_PLAN, consolidated=_consolidated())
        self.assertTrue(ok)
        path = self.rt / "hunt_traces.jsonl"
        self.assertTrue(path.exists())
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        rec = json.loads(lines[0])
        self.assertEqual(rec["v"], 1)
        self.assertEqual(rec["program"], "acme")
        self.assertEqual(rec["target"], "https://app.example.com/")
        self.assertIsInstance(rec["ts"], str)
        self.assertEqual(rec["surface"]["params"], ["q", "file"])
        self.assertEqual(rec["surface"]["tech"], ["flask", "jinja"])
        self.assertEqual(rec["plan"]["param_hypotheses"], ["redirect", "callback"])
        self.assertEqual(rec["plan"]["probe_priority"][0]["classes"], ["xss", "sqli"])
        # Two consolidated findings -> two outcome rows, carrying the confirm status.
        self.assertEqual(len(rec["outcomes"]), 2)
        statuses = {(o["class"], o["proof_status"]) for o in rec["outcomes"]}
        self.assertIn(("xss", "confirmed"), statuses)
        self.assertIn(("sqli", "missing"), statuses)

    def test_program_key_derived_from_target_when_program_none(self) -> None:
        hunt_trace.record_trace(self.rt, program=None, target="https://shop.example.com/x",
                                surface=_SURFACE, plan=_PLAN, outcomes=[])
        rec = hunt_trace.load_traces(self.rt)[0]
        self.assertEqual(rec["program"], "example.com")

    def test_explicit_outcomes_are_used_verbatim(self) -> None:
        rows = [{"endpoint": "https://t/e", "class": "redirect", "proof_status": "candidate",
                 "rule_id": "active.redirect", "severity": "low", "dedup_key": "abc"}]
        hunt_trace.record_trace(self.rt, program="p", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=rows)
        rec = hunt_trace.load_traces(self.rt)[0]
        self.assertEqual(rec["outcomes"][0]["class"], "redirect")
        self.assertEqual(rec["outcomes"][0]["proof_status"], "candidate")

    def test_appends_accumulate_in_order(self) -> None:
        hunt_trace.record_trace(self.rt, program="a", target="https://a/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        hunt_trace.record_trace(self.rt, program="b", target="https://b/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        traces = hunt_trace.load_traces(self.rt)
        self.assertEqual([t["program"] for t in traces], ["a", "b"])

    def test_load_limit_returns_tail(self) -> None:
        for i in range(5):
            hunt_trace.record_trace(self.rt, program=f"p{i}", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        tail = hunt_trace.load_traces(self.rt, limit=2)
        self.assertEqual([t["program"] for t in tail], ["p3", "p4"])

    def test_none_runtime_dir_is_fail_closed(self) -> None:
        self.assertFalse(hunt_trace.record_trace(None, program="p", target="t", surface=_SURFACE, plan=_PLAN, outcomes=[]))

    def test_load_missing_file_is_empty(self) -> None:
        self.assertEqual(hunt_trace.load_traces(self.rt), [])


class OutcomesFromFindingsTests(unittest.TestCase):
    def test_campaign_consolidated_shape(self) -> None:
        rows = hunt_trace.outcomes_from_findings(_consolidated("key1"))
        self.assertEqual(len(rows), 2)
        xss = next(r for r in rows if r["class"] == "xss")
        self.assertEqual(xss["endpoint"], "https://app.example.com/search")
        self.assertEqual(xss["proof_status"], "confirmed")
        self.assertEqual(xss["dedup_key"], "key1")
        self.assertEqual(xss["severity"], "medium")

    def test_plain_finding_dicts(self) -> None:
        rows = hunt_trace.outcomes_from_findings([
            {"class_id": "cors", "rule_id": "active.cors", "location": "https://t/api", "proof_status": "confirmed"},
        ])
        self.assertEqual(rows[0]["class"], "cors")
        self.assertEqual(rows[0]["endpoint"], "https://t/api")
        self.assertEqual(rows[0]["proof_status"], "confirmed")

    def test_tolerant_of_non_dict_and_empty_entries(self) -> None:
        rows = hunt_trace.outcomes_from_findings(["nope", 5, None, {}, {"finding": {}}])
        self.assertEqual(rows, [])

    def test_non_list_input_returns_empty(self) -> None:
        self.assertEqual(hunt_trace.outcomes_from_findings(None), [])
        self.assertEqual(hunt_trace.outcomes_from_findings(42), [])


class CompactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_oversized_surface_is_capped(self) -> None:
        big = {"endpoints": [f"https://t/{i}" for i in range(400)],
               "params": [f"p{i}" for i in range(400)], "tech": [f"t{i}" for i in range(80)], "forms": []}
        hunt_trace.record_trace(self.rt, program="p", target="https://t/", surface=big, plan=_PLAN, outcomes=[])
        rec = hunt_trace.load_traces(self.rt)[0]
        self.assertEqual(len(rec["surface"]["endpoints"]), 300)
        self.assertEqual(len(rec["surface"]["params"]), 300)
        self.assertEqual(len(rec["surface"]["tech"]), 40)

    def test_malformed_plan_rows_are_filtered(self) -> None:
        plan = {"provider": "offline", "param_hypotheses": ["a", "", None, "b"],
                "probe_priority": ["nope", {"endpoint": "", "classes": ["xss"]}, {"endpoint": "https://t/x", "classes": []},
                                   {"endpoint": "https://t/y", "classes": ["sqli"]}]}
        hunt_trace.record_trace(self.rt, program="p", target="https://t/", surface=_SURFACE, plan=plan, outcomes=[])
        rec = hunt_trace.load_traces(self.rt)[0]
        self.assertEqual(rec["plan"]["param_hypotheses"], ["a", "b"])  # empties dropped
        self.assertEqual(len(rec["plan"]["probe_priority"]), 1)  # only the valid endpoint+classes row
        self.assertEqual(rec["plan"]["probe_priority"][0]["endpoint"], "https://t/y")


class TolerantReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_torn_line_is_skipped_valid_lines_kept(self) -> None:
        hunt_trace.record_trace(self.rt, program="good1", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        # Simulate a crash mid-append: a partial/garbage line between two valid ones.
        with (self.rt / "hunt_traces.jsonl").open("a", encoding="utf-8") as handle:
            handle.write('{"v": 1, "program": "torn"')  # no newline, no closing brace
            handle.write("\n")
        hunt_trace.record_trace(self.rt, program="good2", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        traces = hunt_trace.load_traces(self.rt)
        self.assertEqual([t["program"] for t in traces], ["good1", "good2"])


class TrainingExamplesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_join_backfills_stage_and_bounty_from_ledger(self) -> None:
        finding = {"class_id": "sqli", "rule_id": "active.sqli", "location": "https://app.example.com/search",
                   "title": "SQLi", "severity": "high"}
        # Seed the ledger: record the finding as confirmed, then mark it paid.
        consolidated = [{"finding": finding, "proof_status": "confirmed", "source_url": finding["location"]}]
        ledger.upsert_findings(self.rt, "acme", "https://app.example.com/", consolidated)
        dk = consolidated[0]["dedup_key"]
        ledger.advance_stage(self.rt, "acme", "https://app.example.com/", dk, "paid", bounty=500.0, outcome="accepted")
        # Record a trace whose outcome carries that dedup key.
        hunt_trace.record_trace(self.rt, program="acme", target="https://app.example.com/", surface=_SURFACE, plan=_PLAN,
                                outcomes=[{"endpoint": finding["location"], "class": "sqli", "rule_id": "active.sqli",
                                           "proof_status": "confirmed", "severity": "high", "dedup_key": dk}])
        rows = hunt_trace.training_examples(self.rt)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["class"], "sqli")
        self.assertTrue(row["confirmed"])
        self.assertEqual(row["stage"], "paid")
        self.assertEqual(row["bounty"], 500.0)
        self.assertTrue(row["paid"])
        self.assertEqual(row["surface"]["tech"], ["flask", "jinja"])

    def test_unmatched_outcome_falls_back_without_ledger(self) -> None:
        hunt_trace.record_trace(self.rt, program="p", target="https://t/", surface=_SURFACE, plan=_PLAN,
                                outcomes=[{"endpoint": "https://t/x", "class": "xss", "proof_status": "candidate",
                                           "dedup_key": "no-such-key"}])
        rows = hunt_trace.training_examples(self.rt)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["confirmed"])
        self.assertEqual(rows[0]["stage"], "discovered")
        self.assertEqual(rows[0]["bounty"], 0.0)
        self.assertFalse(rows[0]["paid"])


class HardeningTests(unittest.TestCase):
    """Fixes driven by the Phase 0 adversarial review."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_load_limit_zero_returns_empty_not_whole_corpus(self) -> None:
        # Regression: `out[-0:]` is `out[0:]` == the WHOLE list, inverting "most recent 0".
        for i in range(3):
            hunt_trace.record_trace(self.rt, program=f"p{i}", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        self.assertEqual(hunt_trace.load_traces(self.rt, limit=0), [])
        self.assertEqual(hunt_trace.load_traces(self.rt, limit=-5), [])

    def test_program_key_is_capped(self) -> None:
        hunt_trace.record_trace(self.rt, program="a" * 5000, target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        self.assertLessEqual(len(hunt_trace.load_traces(self.rt)[0]["program"]), 120)

    def test_prebuilt_outcomes_are_field_capped(self) -> None:
        rows = [{"endpoint": "https://t/" + "x" * 2000, "class": "y" * 500, "rule_id": "r" * 500,
                 "proof_status": "s" * 100, "severity": "z" * 100, "dedup_key": "k" * 200}]
        hunt_trace.record_trace(self.rt, program="p", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=rows)
        o = hunt_trace.load_traces(self.rt)[0]["outcomes"][0]
        self.assertLessEqual(len(o["endpoint"]), 600)
        self.assertLessEqual(len(o["class"]), 60)
        self.assertLessEqual(len(o["rule_id"]), 120)
        self.assertLessEqual(len(o["proof_status"]), 20)
        self.assertLessEqual(len(o["severity"]), 20)
        self.assertLessEqual(len(o["dedup_key"]), 40)

    def test_torn_fragment_without_newline_does_not_lose_next_record(self) -> None:
        # A crash mid-append can leave a fragment with NO trailing newline. The next record must not
        # concatenate onto it into one unparseable physical line (which would lose the good record too).
        hunt_trace.record_trace(self.rt, program="good1", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        with (self.rt / "hunt_traces.jsonl").open("a", encoding="utf-8") as handle:
            handle.write('{"v": 1, "program": "torn"')  # NO trailing newline
        hunt_trace.record_trace(self.rt, program="good2", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        self.assertEqual([t["program"] for t in hunt_trace.load_traces(self.rt)], ["good1", "good2"])

    def test_secret_in_endpoint_url_is_redacted_idor_id_preserved(self) -> None:
        secret_url = "https://app.example.com/reset?token=abcd1234efgh5678ijkl&id=1001"
        idor_url = "https://app.example.com/order/1001"
        surface = {"endpoints": [secret_url, idor_url], "params": ["token", "id"], "tech": [],
                   "forms": [{"action": secret_url, "method": "GET", "params": ["token"]}]}
        plan = {"provider": "offline", "probe_priority": [{"endpoint": secret_url, "classes": ["redirect"]}],
                "idor_candidates": [idor_url], "param_hypotheses": [], "ssrf_params": [], "xss_params": []}
        hunt_trace.record_trace(self.rt, program="p", target="https://app.example.com/", surface=surface, plan=plan,
                                outcomes=[{"endpoint": secret_url, "class": "redirect", "proof_status": "candidate", "dedup_key": "k"}])
        rec = hunt_trace.load_traces(self.rt)[0]
        blob = json.dumps(rec)
        self.assertNotIn("abcd1234efgh5678ijkl", blob)  # the secret token value is gone EVERYWHERE
        self.assertIn("REDACTED", blob)                  # replaced by the standard marker
        self.assertIn("token=", blob)                    # param name / URL structure preserved
        self.assertIn("/order/1001", blob)               # the IDOR path-segment id (training signal) survives
        # Param NAMES are preserved verbatim in surface.params (names are never redacted) — that's the
        # signal the ranker consumes. (The URL query tail after a secret is acceptably over-redacted.)
        self.assertEqual(rec["surface"]["params"], ["token", "id"])


class StatsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_trace_stats_counts(self) -> None:
        hunt_trace.record_trace(self.rt, program="a", target="https://a/", surface=_SURFACE, plan=_PLAN,
                                consolidated=_consolidated())  # 1 confirmed + 1 missing
        hunt_trace.record_trace(self.rt, program="b", target="https://b/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        stats = hunt_trace.trace_stats(self.rt)
        self.assertEqual(stats["hunts"], 2)
        self.assertEqual(stats["programs"], 2)
        self.assertEqual(stats["outcome_rows"], 2)
        self.assertEqual(stats["confirmed_rows"], 1)


class ConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_concurrent_appends_never_lose_a_line(self) -> None:
        # Mirrors learning.py's lost-update regression: many threads appending at once
        # must all land (the append is serialized behind the module lock).
        def _rec(i: int) -> None:
            hunt_trace.record_trace(self.rt, program=f"p{i}", target="https://t/", surface=_SURFACE, plan=_PLAN, outcomes=[])
        threads = [threading.Thread(target=_rec, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        self.assertEqual(len(hunt_trace.load_traces(self.rt)), 20, "no concurrent append may be lost")


if __name__ == "__main__":
    unittest.main()
