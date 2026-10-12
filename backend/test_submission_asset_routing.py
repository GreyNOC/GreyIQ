"""A HackerOne report must be routed to the exact in-scope Asset (structured_scope_id).

A cached run carries TWO program keys that are not interchangeable: ``program`` is the display
label (a span caches the program's NAME) and ``program_id`` is the real key
``portfolio.get_program`` indexes on (``learning.program_key`` slugifies the name to derive it).
Reading the label handed ``get_program`` "Acme Corp" where the store is keyed "acme-corp", so the
lookup missed, the asset picker came back EMPTY and every report filed through the cockpit went up
with no Asset — which is what HackerOne routes triage on. Regression.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402
from bughunter import portfolio as bounty_portfolio  # noqa: E402
from bughunter import submission as bounty_submission  # noqa: E402

ASSET_ID = "55501"
FINDING = {
    "ref": "F1", "title": "IDOR on orders", "severity": "high", "class_id": "idor",
    "class_name": "Broken access control", "cwe": "CWE-639", "rule_id": "active.idor",
    "location": "https://app.example.com/api/orders/2", "confidence": "high",
}
PLAN = {
    "steps": ["Request another tenant's order id"], "impact": "Read any tenant's order",
    "proof_of_impact": {"status": "confirmed", "method": "GET",
                        "observed_result": "HTTP/1.1 200 OK\n{\"id\":2}",
                        "control_result": "HTTP/1.1 403 Forbidden"},
}


class StructuredScopeRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        self._orig_secrets = g.SECRETS_PATH
        g.RUNTIME_DIR = Path(self._tmp.name)
        g.SECRETS_PATH = Path(self._tmp.name) / "secrets.json"
        # A program whose derived id ("acme-corp") differs from its display name ("Acme Corp") --
        # the normal case, and the one the old lookup silently missed.
        self.program = bounty_portfolio.upsert_program(g.RUNTIME_DIR, {
            "name": "Acme Corp", "platform": "hackerone", "platform_handle": "acme",
            "scope_text": "app.example.com",
            "structured_scope": [
                {"id": ASSET_ID, "identifier": "app.example.com", "asset_type": "URL",
                 "eligible_for_submission": True},
                {"id": "55502", "identifier": "retired.example.com", "asset_type": "URL",
                 "eligible_for_submission": False},
            ],
        })
        self.assertNotEqual(self.program["id"], self.program["name"])  # the premise of the bug

    def tearDown(self) -> None:
        g.RUNTIME_DIR = self._orig_runtime_dir
        g.SECRETS_PATH = self._orig_secrets
        self._tmp.cleanup()

    def _cache_span_run(self) -> str:
        """Cache a run exactly as _run_program_campaign does: display NAME in `program`, real
        portfolio id in `program_id`."""
        result = {"ok": True, "generated_at": "2026-01-01 00:00 UTC",
                  "findings": [dict(FINDING)], "attack_plans": {"F1": PLAN}}
        self.rt._cache_bounty_run(result, target="Acme Corp — 1 in-scope target(s)",
                                  scope="app.example.com", program=str(self.program["name"]),
                                  program_id=str(self.program["id"]))
        return result["run_id"]

    def test_scope_id_resolves_from_the_run_s_program_id(self) -> None:
        run_id = self._cache_span_run()
        run = self.rt.bounty_runs[run_id]
        self.assertEqual(self.rt._match_structured_scope_id(run, dict(FINDING), ""), ASSET_ID)

    def test_preflight_offers_the_eligible_assets_and_the_match(self) -> None:
        run_id = self._cache_span_run()
        res = self.rt.preflight_submission(
            g.PreflightRequest(run_id=run_id, ref="F1", platform="hackerone", check_duplicates=False))
        self.assertTrue(res["ok"])
        self.assertEqual(res["matched_scope_id"], ASSET_ID)
        # Only submission-eligible assets are offered in the picker.
        self.assertEqual([a["id"] for a in res["assets"]], [ASSET_ID])

    def test_submit_files_the_report_against_the_matched_asset(self) -> None:
        run_id = self._cache_span_run()
        captured: dict = {}

        def _fake_submit(package, **kwargs):
            captured.update(kwargs)
            return {"report_id": "1", "url": "https://hackerone.com/reports/1"}

        orig = bounty_submission.submit_to_hackerone
        bounty_submission.submit_to_hackerone = _fake_submit
        try:
            res = self.rt.submit_finding(
                g.SubmitRequest(run_id=run_id, ref="F1", platform="hackerone", confirm=True,
                                include_attachments=False))
        finally:
            bounty_submission.submit_to_hackerone = orig
        self.assertTrue(res["ok"], res)
        self.assertEqual(captured.get("structured_scope_id"), ASSET_ID)

    def test_operator_override_still_wins_over_the_match(self) -> None:
        run_id = self._cache_span_run()
        run = self.rt.bounty_runs[run_id]
        self.assertEqual(self.rt._match_structured_scope_id(run, dict(FINDING), "99999"), "99999")

    def test_no_saved_program_resolves_to_no_asset(self) -> None:
        # A confirm-route / ad-hoc run binds no program: there is no scope to route to, and the
        # report must still file (un-routed), not error.
        result = {"ok": True, "generated_at": "2026-01-01 00:00 UTC",
                  "findings": [dict(FINDING)], "attack_plans": {"F1": PLAN}}
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="", program=None)
        run = self.rt.bounty_runs[result["run_id"]]
        self.assertEqual(self.rt._match_structured_scope_id(run, dict(FINDING), ""), "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
