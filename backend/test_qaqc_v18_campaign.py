"""Regression tests for the QA/QC v18 campaign/recon/bounty defect fixes.

Each test FAILS on the pre-fix code and PASSES after. Offline + deterministic:
the per-URL engine, recon, submission writer, and reasoning brain are stubbed, so
no network is touched and nothing depends on wall-clock or thread timing.
"""

from __future__ import annotations

import contextlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from bughunter import active_verify_service, bounty, campaign, recon  # noqa: E402
from bughunter.rate_limit import shared_governor  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


def _fake_recon(target, **kwargs):
    """A recon result that maps the seed to exactly itself — no network."""
    return {"urls": [target], "notes": [], "sources": {}, "js_secrets": [], "tech": [],
            "params": [], "api_findings": [], "forms": [], "hints": {},
            "dropped_out_of_scope": 0, "requests_used": 0}


def _make_fake_engine(sidecar_dir, findings_spec):
    """A stand-in for run_bounty_hunt: writes a per-target JSON sidecar carrying the
    given findings + their proof status + modelled cvss, and returns its path."""
    counter = {"n": 0}

    def _fake_engine(url, profile, vuln_class, output_dir, scope, authorized, coder_cfg, **kwargs):
        counter["n"] += 1
        doc = {
            "tool": "GreyIQ", "version": "test", "generated_at": "now", "target": url, "scope": scope,
            "findings": [dict(spec["finding"]) for spec in findings_spec],
            "proof_of_impact": {spec["finding"]["ref"]: {"status": spec["proof"]} for spec in findings_spec},
            "cvss": {spec["finding"]["ref"]: spec.get("cvss", {}) for spec in findings_spec},
            "attack_plans": {},
        }
        p = Path(sidecar_dir) / f"target-{counter['n']}.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        return {"ok": True, "report_path": str(p), "json_path": str(p), "finding_count": len(findings_spec)}

    return _fake_engine


def _finding(**over):
    base = {"ref": "F1", "class_id": "redirect", "class_name": "Open Redirect",
            "rule_id": "open-redirect", "title": "Open redirect", "severity": "medium",
            "location": "https://example.com/go?url=x", "cwe": "CWE-601"}
    base.update(over)
    return base


class ReconBraceGuardTests(unittest.TestCase):
    """recon.py:413 — braced template URLs (SPA / OIDC) must not reach the crawler/prover."""

    def test_extract_links_drops_braced_template_urls(self):
        body = '<a href="/user/{{id}}/profile">x</a><a href="/ok/page">y</a>'
        links = recon._extract_links(body, "https://host/")
        # The framework-template URL (literal braces after urljoin) must be dropped...
        self.assertNotIn("https://host/user/{{id}}/profile", links)
        self.assertFalse(any("{" in u or "}" in u for u in links))
        # ...while a normal link still passes through.
        self.assertIn("https://host/ok/page", links)


class BountyParseJsonRecursionTests(unittest.TestCase):
    """bounty.py:1364 — untrusted brain JSON must not crash on RecursionError."""

    def test_parse_json_object_survives_deeply_nested(self):
        # Deeply-nested JSON makes json.loads raise RecursionError (a RuntimeError, NOT a
        # ValueError/JSONDecodeError). Pre-fix this escaped _parse_json_object.
        text = '{"a":' + ("[" * 6000) + ("]" * 6000) + "}"
        self.assertIsNone(bounty._parse_json_object(text))


class CampaignSeverityFromCvssTests(unittest.TestCase):
    """campaign.py:871 — campaign tally must resolve severity through the plan CVSS."""

    def test_severity_counts_and_risk_use_plan_cvss(self):
        # A scanner-'medium' finding the active pass models as 'high' (cvss base_severity high).
        # _resolved_severity_finding must upgrade the stored 'medium' label to the modelled 'high'
        # so the campaign tally/risk agree with the per-target report.
        item = {"finding": {"severity": "medium", "title": "t"}, "cvss": {"base_severity": "high"}}
        resolved = campaign._resolved_severity_finding(item)
        self.assertEqual(resolved["severity"], "high")
        counts = campaign._severity_counts([resolved])
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 0)
        self.assertEqual(campaign._campaign_risk([{"finding": resolved}]), "high")


class SharedGovernorThreadingTests(unittest.TestCase):
    """recon.py:192 — passive recon must draw from the PROCESS-WIDE per-host governor."""

    def test_campaign_threads_shared_governor_into_recon(self):
        captured = {}

        def _rec(target, **kwargs):
            captured["governor"] = kwargs.get("governor")
            return _fake_recon(target, **kwargs)

        with tempfile.TemporaryDirectory() as td:
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(campaign.recon, "discover", _rec))
                stack.enter_context(mock.patch.object(campaign, "run_bounty_hunt", _make_fake_engine(td, [])))
                stack.enter_context(mock.patch.object(campaign.hunt_brain, "plan_hunt", lambda *a, **k: {}))
                stack.enter_context(mock.patch.object(campaign.hunt_trace, "record_trace", lambda *a, **k: None))
                campaign._run_campaign_body(
                    "https://example.com", scope="example.com", authorized=True, coder_cfg=None,
                    default_reports_dir=Path(td), version="test",
                )
        s = get_settings()
        expected = shared_governor(capacity=s.active_max_requests_per_host,
                                   min_interval_s=s.active_min_interval_ms / 1000.0, pool="recon")
        self.assertIsNotNone(captured.get("governor"), "recon.discover must receive a governor")
        self.assertIs(captured["governor"], expected)
        # The recon pool MUST be a SEPARATE per-host bucket from the active prover's (pool="") —
        # sharing one let the crawl drain every token and starve the active pass (0 findings).
        self.assertIsNot(captured["governor"], shared_governor(
            capacity=s.active_max_requests_per_host, min_interval_s=s.active_min_interval_ms / 1000.0))

    def test_bounty_threads_shared_governor_into_recon(self):
        captured = {}

        class _Stop(BaseException):
            """BaseException so bounty's `except Exception` recon guard cannot swallow it."""

        def _rec(target, **kwargs):
            captured["governor"] = kwargs.get("governor")
            raise _Stop()

        with tempfile.TemporaryDirectory() as td:
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    bounty, "_run_scanners", lambda *a, **k: ([], ["web"], {"web": {"ok": True}}, "low", 0)))
                stack.enter_context(mock.patch.object(bounty.recon, "discover", _rec))
                with self.assertRaises(_Stop):
                    bounty.run_bounty_hunt(
                        "https://example.com", "web-app", None, None, "example.com", True, None,
                        default_reports_dir=Path(td), active=True,
                    )
        s = active_verify_service.get_settings()
        expected = shared_governor(capacity=s.active_max_requests_per_host,
                                   min_interval_s=s.active_min_interval_ms / 1000.0, pool="recon")
        self.assertIsNotNone(captured.get("governor"), "active recon must receive a governor")
        self.assertIs(captured["governor"], expected)
        # Separate bucket from the active prover's default pool (regression: shared bucket starved active).
        self.assertIsNot(captured["governor"], shared_governor(
            capacity=s.active_max_requests_per_host, min_interval_s=s.active_min_interval_ms / 1000.0))


class CampaignSubmissionGatingTests(unittest.TestCase):
    """campaign.py:800 + :765 — submission-loop mark_reported gate + cross-target dedup."""

    def _run(self, *, runtime_dir, reports_dir, findings_spec, submission_claim=None):
        def _fake_pkg(ctx, finding, sub_dir, stem, platform):
            return {"markdown_path": str(Path(sub_dir) / f"{stem}.md")}

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(campaign.recon, "discover", _fake_recon))
            stack.enter_context(mock.patch.object(campaign, "run_bounty_hunt", _make_fake_engine(reports_dir, findings_spec)))
            stack.enter_context(mock.patch.object(campaign.submission, "write_submission_package", _fake_pkg))
            stack.enter_context(mock.patch.object(campaign.hunt_brain, "plan_hunt", lambda *a, **k: {}))
            stack.enter_context(mock.patch.object(campaign.hunt_trace, "record_trace", lambda *a, **k: None))
            return campaign._run_campaign_body(
                "https://example.com", scope="example.com", authorized=True, coder_cfg=None,
                default_reports_dir=Path(reports_dir), runtime_dir=Path(runtime_dir),
                version="test", program="acme", submission_claim=submission_claim,
            )

    def test_candidate_lead_does_not_block_later_confirmed(self):
        # Run 1 (passive) surfaces the finding as a CANDIDATE; run 2 (active) CONFIRMS the
        # same finding. Pre-fix, run 1 marked it 'reported' so run 2 was skipped as
        # duplicate_of_prior and no confirmed package was ever built.
        with tempfile.TemporaryDirectory() as rt, \
                tempfile.TemporaryDirectory() as rd1, tempfile.TemporaryDirectory() as rd2:
            r1 = self._run(runtime_dir=rt, reports_dir=rd1,
                           findings_spec=[{"finding": _finding(), "proof": "candidate"}])
            self.assertEqual(len(r1["submission_paths"]), 1)  # candidate still packaged locally
            r2 = self._run(runtime_dir=rt, reports_dir=rd2,
                           findings_spec=[{"finding": _finding(), "proof": "confirmed"}])
            self.assertEqual(len(r2["submission_paths"]), 1,
                             "a later confirmed run must still build its own submission package")

    def test_concurrent_targets_dedup_submission_by_key(self):
        # Two targets of the same span surface the SAME finding (identical dedup_key). The
        # shared submission claim must ensure exactly one package is built across the span.
        claim: tuple[set, threading.Lock] = (set(), threading.Lock())
        with tempfile.TemporaryDirectory() as rt, \
                tempfile.TemporaryDirectory() as rd1, tempfile.TemporaryDirectory() as rd2:
            r1 = self._run(runtime_dir=rt, reports_dir=rd1, submission_claim=claim,
                           findings_spec=[{"finding": _finding(), "proof": "candidate"}])
            r2 = self._run(runtime_dir=rt, reports_dir=rd2, submission_claim=claim,
                           findings_spec=[{"finding": _finding(), "proof": "candidate"}])
            self.assertEqual(len(r1["submission_paths"]), 1)
            self.assertEqual(len(r2["submission_paths"]), 0,
                             "the second concurrent target must not re-package the claimed finding")


if __name__ == "__main__":
    unittest.main()
