"""Regression tests for the v1.8 QAQC ledger/portfolio fixes.

Each test FAILS against the pre-fix code and PASSES after. Offline/deterministic:
every store lives under a tempfile.TemporaryDirectory(); no network, no clock deps.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from bughunter import ledger, portfolio


def _deeply_nested_json(depth: int = 100_000) -> str:
    """Syntactically VALID but deeply-nested JSON. json.loads raises RecursionError
    (a RuntimeError subclass — NOT JSONDecodeError/OSError) on this, which the pre-fix
    _load did not catch."""
    return "[" * depth + "]" * depth


class PortfolioMaxSubmitsZero(unittest.TestCase):
    def test_zero_is_preserved_not_coerced_to_three(self):
        # max_submits_per_day=0 means "never auto-submit"; the old `or 3` re-inflated it to 3
        # on both write AND every read, silently re-arming the auto-submit path.
        with tempfile.TemporaryDirectory() as d:
            portfolio.upsert_program(d, {
                "name": "acme", "platform": "hackerone", "platform_handle": "acme",
                "scope_text": "acme.com", "auto_submit": True, "max_submits_per_day": 0,
            })
            got = portfolio.get_program(d, portfolio.program_key("acme"))
            self.assertIsNotNone(got)
            self.assertEqual(got["max_submits_per_day"], 0)
            # and re-normalize-on-read (list_programs) must not re-inflate it either
            listed = portfolio.list_programs(d)
            self.assertEqual(listed[0]["max_submits_per_day"], 0)

    def test_missing_still_defaults_to_three(self):
        with tempfile.TemporaryDirectory() as d:
            got = portfolio._normalize({"name": "x"})
            self.assertEqual(got["max_submits_per_day"], 3)


class PortfolioLoadRecursion(unittest.TestCase):
    def test_deeply_nested_store_degrades_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / portfolio._STORE_NAME).write_text(_deeply_nested_json(), encoding="utf-8")
            # Pre-fix: RecursionError propagates out of _load and aborts the read.
            self.assertEqual(portfolio.list_programs(d), [])


class LedgerLoadRecursion(unittest.TestCase):
    def test_deeply_nested_store_degrades_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ledger._STORE_NAME).write_text(_deeply_nested_json(), encoding="utf-8")
            # funnel() -> _load must not raise; it should degrade to an empty portfolio.
            out = ledger.funnel(d)
            self.assertIsInstance(out, dict)


class LedgerFunnelNonNumericBounty(unittest.TestCase):
    def test_bad_bounty_does_not_crash_funnel(self):
        with tempfile.TemporaryDirectory() as d:
            store = {"programs": {"acme": {"findings": {
                "k1": {"dedup_key": "k1", "stage": "paid", "severity": "high", "bounty": "1,000"},
            }}}}
            (Path(d) / ledger._STORE_NAME).write_text(json.dumps(store), encoding="utf-8")
            # Pre-fix: float('1,000') raises ValueError and 500s the whole money dashboard.
            out = ledger.funnel(d)
            self.assertEqual(out["portfolio"]["total"], 1)
            self.assertEqual(out["portfolio"]["bounty_total"], 0.0)  # bad value degrades to 0, record still counted


class LedgerArchiveCompositeKey(unittest.TestCase):
    def test_dual_bucket_delete_preserves_both_records(self):
        # The SAME dedup_key can live under both the saved-program bucket ("acme", carrying the
        # paid/bounty record) and a program=None domain bucket ("acme.com", a stale discovered dup),
        # both swept in one delete. A bare-key archive silently loses the richer paid copy.
        with tempfile.TemporaryDirectory() as d:
            store = {"programs": {
                "acme": {"findings": {"K": {
                    "dedup_key": "K", "severity": "high", "stage": "paid", "bounty": 500.0,
                    "h1_report_id": "R-1",
                }}},
                "acme.com": {"findings": {"K": {
                    "dedup_key": "K", "severity": "high", "stage": "discovered", "bounty": 0.0,
                }}},
            }}
            (Path(d) / ledger._STORE_NAME).write_text(json.dumps(store), encoding="utf-8")
            res = ledger.archive_and_purge_program(d, "acme", also_bucket_ids=["acme.com"])
            self.assertEqual(res["archived"], 2)
            archived = ledger.list_archived(d)
            # Pre-fix: bare-key overwrite left only 1 (the stale bounty-less) entry.
            self.assertEqual(len(archived), 2)
            self.assertTrue(any(r.get("bounty") == 500.0 and r.get("h1_report_id") == "R-1" for r in archived))
            # both keep the real bare dedup_key in the output despite the composite storage key
            self.assertTrue(all(r.get("dedup_key") == "K" for r in archived))


if __name__ == "__main__":
    unittest.main()
