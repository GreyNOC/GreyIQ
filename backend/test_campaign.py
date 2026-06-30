"""End-to-end campaign test against a local source folder (no network)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import campaign, learning  # noqa: E402

_VULN_SRC = (
    "import os\n"
    "def run(cmd):\n"
    "    os.system('ping ' + cmd)  # command injection\n"
    "SECRET = 'AKIAIOSFODNN7EXAMPLE'\n"
)


class CampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()
        (self.src / "app.py").write_text(_VULN_SRC, encoding="utf-8")
        self.reports = self.root / "reports"
        self.runtime = self.root / "runtime"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, **kw):
        return campaign.run_campaign(
            str(self.src), scope="demo scope", authorized=True, coder_cfg={},
            default_reports_dir=self.reports, seed_dir=BACKEND_DIR / "seed",
            runtime_dir=self.runtime, version="9.9.9", program="demo", **kw,
        )

    def test_requires_authorization(self) -> None:
        result = campaign.run_campaign(
            str(self.src), scope="", authorized=False, coder_cfg={},
            default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9",
        )
        self.assertFalse(result["ok"])
        self.assertIn("authorized", result["error"].lower())

    def test_local_source_campaign(self) -> None:
        result = self._run()
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["program"], "demo")
        self.assertEqual(result["urls_scanned"], 1)
        self.assertGreaterEqual(result["finding_count"], 2)  # cmd-injection + secret
        # Index + per-finding submission packages exist on disk.
        self.assertTrue(Path(result["campaign_path"]).is_file())
        self.assertEqual(len(result["submission_paths"]), result["finding_count"])
        for path in result["submission_paths"]:
            self.assertTrue(Path(path).is_file())

    def test_campaign_returns_structured_findings_for_the_cockpit(self) -> None:
        result = self._run()
        self.assertTrue(result["ok"])
        # The cockpit drives one board off these — campaign-global refs, proof + cvss
        # maps, and a surface block, mirroring /api/bounty/scan.
        self.assertEqual(len(result["findings"]), result["finding_count"])
        self.assertTrue(all(f["ref"].startswith("C") for f in result["findings"]))
        for f in result["findings"]:
            self.assertIn(f["ref"], result["proof_of_impact"])
        self.assertIn("surface", result)
        self.assertIn("urls", result["surface"])
        self.assertIn(result["risk"], {"critical", "high", "moderate", "low", "clean"})

    def test_url_campaign_folds_in_known_cve_candidates(self) -> None:
        # A URL campaign auto-runs the passive known-CVE pass and folds each outdated
        # component in as a candidate finding with its own plan + CVSS. recon / the per-URL
        # hunt / the CVE fetch are all stubbed so the test stays offline.
        from bughunter import cve_service as cve

        target = "https://app.example.com/"
        comp = {"product": "jquery", "version": "1.8.0", "evidence": "/static/jquery-1.8.0.min.js"}
        cve_finding = cve._build_finding(comp, cve.match_cves("jquery", "1.8.0"), target)

        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves)
        campaign.recon.discover = lambda t, **k: {"urls": [t], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {
            "ok": True, "host": "app.example.com", "target": target,
            "components": [comp], "count": 1, "findings": [dict(cve_finding)]}
        try:
            result = campaign.run_campaign(
                target, scope="app.example.com", authorized=True, coder_cfg={},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo")
        finally:
            campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves = orig

        self.assertTrue(result["ok"], result.get("error"))
        cve_refs = [f["ref"] for f in result["findings"] if "Outdated jQuery" in f["title"]]
        self.assertEqual(len(cve_refs), 1, [f["title"] for f in result["findings"]])
        ref = cve_refs[0]
        self.assertEqual(result["proof_of_impact"][ref]["status"], "candidate")  # never confirmed
        self.assertIn(ref, result["attack_plans"])      # inline plan threaded onto the board
        self.assertIn(ref, result["cvss"])              # CVSS surfaced for ranking/severity
        self.assertGreaterEqual(len(result["submission_paths"]), 1)  # a report package was written

    def test_url_campaign_folds_in_api_discovery_findings(self) -> None:
        # recon's api_findings (e.g. GraphQL introspection) — each carrying an inline plan —
        # must land on the campaign board as candidates with their plan/CVSS.
        from bughunter import api_discovery_service as apidisc

        target = "https://api.example.com/"
        gql_finding = apidisc._graphql_finding(
            "https://api.example.com/graphql",
            {"query_type": "Query", "mutation_type": "Mutation", "type_count": 12, "types": ["User"]})

        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves)
        campaign.recon.discover = lambda t, **k: {
            "urls": [t], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [],
            "api_findings": [dict(gql_finding, _plan=dict(gql_finding["_plan"]))]}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "host": "api.example.com", "target": t, "components": [], "count": 0, "findings": []}
        try:
            result = campaign.run_campaign(
                target, scope="api.example.com", authorized=True, coder_cfg={},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo")
        finally:
            campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves = orig

        self.assertTrue(result["ok"], result.get("error"))
        refs = [f["ref"] for f in result["findings"] if "introspection" in f["title"].lower()]
        self.assertEqual(len(refs), 1, [f["title"] for f in result["findings"]])
        ref = refs[0]
        self.assertEqual(result["proof_of_impact"][ref]["status"], "candidate")
        self.assertIn(ref, result["attack_plans"])  # inline plan threaded through

    def test_static_findings_are_not_auto_recorded_as_submitted(self) -> None:
        # Source-code findings are candidates (no active proof) -> nothing logged
        # to the learning store, so we never pollute program memory with leads.
        self._run()
        summary = learning.program_summary(self.runtime, "demo")
        self.assertEqual(summary["submitted"], 0)

    def test_unknown_target_kind_errors(self) -> None:
        result = campaign.run_campaign(
            "??::not-a-thing", scope="", authorized=True, coder_cfg={},
            default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9",
        )
        self.assertFalse(result["ok"])


def _ctx_item(ref: str, *, duplicate: bool, package: bool) -> dict:
    item = {
        "finding": {"ref": ref, "title": f"Finding {ref}", "severity": "high"},
        "source_url": f"https://x/{ref}", "proof_status": "confirmed",
        "duplicate_of_prior": duplicate,
    }
    if package:
        item["submission_path"] = f"/out/{ref}.md"
    return item


def _minimal_ctx(confirmed: list[dict]) -> dict:
    return {
        "program": "acme", "target": "https://x", "kind": "url", "per_target": [],
        "consolidated": confirmed, "confirmed": confirmed, "active": True,
        "submission_count": sum(1 for c in confirmed if c.get("submission_path")),
        "generated_at": "now", "version": "9.9.9", "scope": "x", "intel": [],
        "urls": [], "recon_sources": {}, "recon_notes": [],
    }


def _section(md: str, heading: str) -> str:
    """The text of one '## heading' section, up to the next '## '."""
    start = md.index(heading) + len(heading)
    rest = md[start:]
    end = rest.find("\n## ")
    return rest if end == -1 else rest[:end]


class ReadyToSubmitRenderingTests(unittest.TestCase):
    """A confirmed finding the ledger marked duplicate_of_prior was DELIBERATELY skipped
    by the submission-package loop (campaign.py's `if item.get('duplicate_of_prior'):
    continue`) -- the report must never list it under 'Ready to submit' (it has no
    package), which would mislead the operator into trying to re-submit a finding the
    engine intentionally suppressed. (Note: the 'Findings (ranked)' table above always
    lists every consolidated finding incl. duplicates -- that table is intentionally
    complete; only the 'Ready to submit' section must exclude them.)"""

    def test_duplicate_of_prior_excluded_from_ready_to_submit(self) -> None:
        fresh = _ctx_item("F1", duplicate=False, package=True)
        stale = _ctx_item("F2", duplicate=True, package=False)
        md = campaign._render_campaign_markdown(_minimal_ctx([fresh, stale]))
        self.assertIn("## Ready to submit (confirmed)", md)
        ready_section = _section(md, "## Ready to submit (confirmed)")
        self.assertIn("Finding F1", ready_section)
        self.assertNotIn("Finding F2", ready_section)  # the duplicate must not appear as "ready"
        self.assertIn("1 other confirmed finding(s) were already reported", ready_section)

    def test_all_duplicates_renders_already_reported_section(self) -> None:
        stale = _ctx_item("F1", duplicate=True, package=False)
        md = campaign._render_campaign_markdown(_minimal_ctx([stale]))
        self.assertNotIn("## Ready to submit", md)
        self.assertIn("## Already reported", md)
        self.assertNotIn("Finding F1", _section(md, "## Already reported"))

    def test_no_duplicates_renders_exactly_as_before(self) -> None:
        fresh = _ctx_item("F1", duplicate=False, package=True)
        md = campaign._render_campaign_markdown(_minimal_ctx([fresh]))
        self.assertIn("## Ready to submit (confirmed)", md)
        ready_section = _section(md, "## Ready to submit (confirmed)")
        self.assertIn("Finding F1", ready_section)
        self.assertNotIn("already reported", ready_section)


if __name__ == "__main__":
    unittest.main()
