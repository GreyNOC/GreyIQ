"""End-to-end campaign test against a local source folder (no network)."""
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

from bughunter import campaign, learning  # noqa: E402

_VULN_SRC = (
    "import os\n"
    "def run(cmd):\n"
    "    os.system('ping ' + cmd)  # command injection\n"
    # A realistic (non-"EXAMPLE") AWS access key so strict secret classification keeps it as a
    # candidate secret rather than correctly filtering the AWS documentation placeholder.
    "SECRET = 'AKIAZ9Q8R7W6T5Y4U3I2'\n"
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

    def test_url_campaign_writes_hunt_trace(self) -> None:
        # Phase 0 (offline-brain distillation corpus): a URL campaign appends exactly one
        # hunt_traces.jsonl line carrying the recon surface, the (offline) plan produced from
        # it, and the consolidated findings' confirm outcomes. recon / the per-URL hunt / the
        # CVE fetch are stubbed so the test stays offline; the CVE pass injects one candidate
        # finding so the trace has a non-empty outcome row.
        from bughunter import cve_service as cve, hunt_trace

        target = "https://app.example.com/"
        comp = {"product": "jquery", "version": "1.8.0", "evidence": "/static/jquery-1.8.0.min.js"}
        cve_finding = cve._build_finding(comp, cve.match_cves("jquery", "1.8.0"), target)
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves)
        campaign.recon.discover = lambda t, **k: {
            "urls": [t, t + "search?q=1"], "notes": [], "sources": {}, "js_secrets": [],
            "tech": ["flask"], "params": ["q", "file"], "forms": [], "hints": {}}
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
        traces = hunt_trace.load_traces(self.runtime)
        self.assertEqual(len(traces), 1)
        trace = traces[0]
        self.assertEqual(trace["program"], "demo")
        self.assertEqual(trace["target"], target)
        # The recon surface was captured (params + tech), and the OFFLINE plan ran over it.
        self.assertIn("q", trace["surface"]["params"])
        self.assertIn("flask", trace["surface"]["tech"])
        self.assertEqual(trace["plan"]["provider"], "offline")
        # The injected CVE candidate flows through as an outcome row with its confirm status.
        classes = {o["class"] for o in trace["outcomes"]}
        self.assertIn(str(cve_finding.get("class_id")), classes)

    def test_target_host_excluded_survives_scheme_only_seed(self) -> None:
        # A malformed scheme-only seed makes urlparse(...).hostname None; the exclusion check must
        # skip it, not crash the whole portfolio/span run with AttributeError on .strip().
        for bad in ("http://", "https://", "//x", "ftp://:"):
            self.assertFalse(campaign._target_host_excluded(bad, ["evil.example"]))
        # A genuinely excluded host (and its subdomains) is still matched.
        self.assertTrue(campaign._target_host_excluded("https://sub.evil.example/x", ["evil.example"]))

    def test_later_confirmed_duplicate_replaces_earlier_candidate(self) -> None:
        # Cross-URL consolidation: the SAME class/rule at the same digit-normalized location appears
        # unconfirmed at an earlier URL and CONFIRMED at a later one. The confirmed, submittable
        # instance must win — not be dropped by the first-seen unconfirmed key.
        url_a, url_b = "https://app.example.com/", "https://app.example.com/p2"
        find_a = {"ref": "F1", "title": "Reflected XSS", "severity": "high", "class_id": "xss",
                  "class_name": "Reflected XSS", "rule_id": "active.reflected-xss",
                  "location": "https://app.example.com/search?item=1", "cwe": "CWE-79"}
        find_b = {**find_a, "location": "https://app.example.com/search?item=2"}  # same normalized location
        docs = {
            url_a: {"findings": [find_a], "proof_of_impact": {"F1": {"status": "candidate"}}, "cvss": {"F1": {}}},
            url_b: {"findings": [find_b], "proof_of_impact":
                    {"F1": {"status": "confirmed", "observed_result": "reflected raw", "control_result": "encoded"}},
                    "cvss": {"F1": {}}},
        }
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign._read_json)
        campaign.recon.discover = lambda t, **k: {"urls": [url_a, url_b], "notes": [], "sources": {},
                                                  "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": a[0], "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign._read_json = lambda p: docs.get(p, {})
        try:
            result = campaign.run_campaign(
                "https://app.example.com/", scope="app.example.com", authorized=True, coder_cfg={},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo")
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign._read_json) = orig
        self.assertTrue(result["ok"], result.get("error"))
        xss = [f for f in result["findings"] if f.get("rule_id") == "active.reflected-xss"]
        self.assertEqual(len(xss), 1, "the duplicate should collapse to one finding")
        self.assertEqual(result["proof_of_impact"][xss[0]["ref"]]["status"], "confirmed")

    def test_brain_selected_idor_candidates_run_the_dormant_prover(self) -> None:
        # The reasoning layer flags object-scoped endpoints; the campaign runs the (previously
        # never-autonomously-called) single-session IDOR prover on them WITH the operator's session,
        # and folds the candidate-grade finding in. recon / hunt / brain / prover all stubbed (offline).
        from bughunter import access_control_service as acs

        target = "https://app.example.com/"
        orders = target + "api/orders/42"
        idor_finding = {"title": "Possible IDOR on /api/orders/42", "severity": "high",
                        "class_id": "access-control", "rule_id": "active.idor-probe", "location": orders, "cwe": "CWE-639"}
        idor_plan = {"proof_of_impact": {"status": "candidate", "proof_obligation": "confirm with a second account"},
                     "cvss": {"base_score": 6.5}}
        calls: list = []
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign.hunt_brain.plan_hunt, acs.run_idor_probe)
        campaign.recon.discover = lambda t, **k: {"urls": [t, orders], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign.hunt_brain.plan_hunt = lambda *a, **k: {"used": True, "provider": "x", "model": "y",
            "param_hypotheses": [], "probe_priority": [], "idor_candidates": [orders], "notes": ""}
        acs.run_idor_probe = lambda url, **k: (calls.append((url, k.get("account"))),
            {"ok": True, "status": "candidate", "finding": dict(idor_finding), "attack_plan": idor_plan})[1]
        try:
            result = campaign.run_campaign(
                target, scope="app.example.com", authorized=True, coder_cfg={"provider": "x"},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo",
                active=True, auth={"cookie": "sid=abc"})
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign.hunt_brain.plan_hunt, acs.run_idor_probe) = orig

        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(calls[0][0], orders)                      # the prover ran on the brain-selected endpoint
        self.assertEqual(calls[0][1], {"cookie": "sid=abc"})       # ...with the operator's authenticated session
        idor_refs = [f["ref"] for f in result["findings"] if "IDOR" in f["title"]]
        self.assertEqual(len(idor_refs), 1)                        # the lead was folded into the board
        self.assertEqual(result["proof_of_impact"][idor_refs[0]]["status"], "candidate")  # never confirmed

    def test_brain_selected_privileged_endpoints_run_the_dual_account_bfla_prover(self) -> None:
        # The reasoning layer flags ADMIN/privileged functions; when the program has BOTH a low-priv
        # research account (auth) AND an admin account (admin_account_access), the campaign logs into the
        # admin account and runs the dual-account BFLA prover, folding a CONFIRMED bypass in. All stubbed.
        from bughunter import access_control_service as acs

        target = "https://app.example.com/"
        admin_ep = target + "admin/users"
        bfla_finding = {"title": "Broken function-level authorization at /admin/users", "severity": "high",
                        "class_id": "access-control", "rule_id": "active.bfla", "location": admin_ep, "cwe": "CWE-862"}
        bfla_plan = {"proof_of_impact": {"status": "confirmed", "observed_result": "low-priv reached admin response",
                                         "control_result": "anon denied"}, "cvss": {"base_score": 8.1}}
        calls: list = []
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign.hunt_brain.plan_hunt, campaign.account_login_service.login, acs.run_bfla_check)
        campaign.recon.discover = lambda t, **k: {"urls": [t, admin_ep], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign.hunt_brain.plan_hunt = lambda *a, **k: {"used": True, "provider": "x", "model": "y",
            "param_hypotheses": [], "probe_priority": [], "idor_candidates": [], "privileged_endpoints": [admin_ep], "notes": ""}
        campaign.account_login_service.login = lambda acc, scope, settings=None: {"ok": True, "cookie": "sid=admin", "note": "logged in"}
        acs.run_bfla_check = lambda url, **k: (calls.append((url, k.get("admin_account"), k.get("user_account"))),
            {"ok": True, "status": "confirmed", "finding": dict(bfla_finding), "attack_plan": bfla_plan})[1]
        try:
            result = campaign.run_campaign(
                target, scope="app.example.com", authorized=True, coder_cfg={"provider": "x"},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo",
                active=True, auth={"cookie": "sid=user"}, admin_account_access={"cookie": "sid=admin"})
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign.hunt_brain.plan_hunt, campaign.account_login_service.login, acs.run_bfla_check) = orig

        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(calls[0][0], admin_ep)                    # prover ran on the brain-selected privileged endpoint
        self.assertEqual(calls[0][1].get("cookie"), "sid=admin")   # admin session = high-privilege ground truth
        self.assertEqual(calls[0][2], {"cookie": "sid=user"})      # user session = the low-privilege attacker
        bfla_refs = [f["ref"] for f in result["findings"] if "function-level" in f["title"]]
        self.assertEqual(len(bfla_refs), 1)                        # folded into the board
        self.assertEqual(result["proof_of_impact"][bfla_refs[0]]["status"], "confirmed")  # prover's differential confirms

    def test_bfla_fires_on_recon_derived_admin_endpoint_even_when_brain_flags_none(self) -> None:
        # The deterministic recon feed (offline_hunt.admin_path_endpoints) must surface admin-path
        # endpoints for the BFLA prover even when the brain flags no privileged_endpoints.
        from bughunter import access_control_service as acs

        target = "https://app.example.com/"
        admin_ep = target + "admin/settings"   # brain did NOT flag it; recon found it
        bfla_finding = {"title": "Broken function-level authorization at /admin/settings", "severity": "high",
                        "class_id": "access-control", "rule_id": "active.bfla", "location": admin_ep, "cwe": "CWE-862"}
        bfla_plan = {"proof_of_impact": {"status": "confirmed", "observed_result": "low-priv reached admin response",
                                         "control_result": "anon denied"}, "cvss": {"base_score": 8.1}}
        calls: list = []
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign.hunt_brain.plan_hunt, campaign.account_login_service.login, acs.run_bfla_check)
        campaign.recon.discover = lambda t, **k: {"urls": [t, admin_ep], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign.hunt_brain.plan_hunt = lambda *a, **k: {"used": True, "provider": "x", "model": "y",
            "param_hypotheses": [], "probe_priority": [], "idor_candidates": [], "privileged_endpoints": [], "notes": ""}
        campaign.account_login_service.login = lambda acc, scope, settings=None: {"ok": True, "cookie": "sid=admin", "note": "ok"}
        acs.run_bfla_check = lambda url, **k: (calls.append(url),
            {"ok": True, "status": "confirmed", "finding": dict(bfla_finding), "attack_plan": bfla_plan})[1]
        try:
            result = campaign.run_campaign(
                target, scope="app.example.com", authorized=True, coder_cfg={"provider": "x"},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo",
                active=True, auth={"cookie": "sid=user"}, admin_account_access={"cookie": "sid=admin"})
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign.hunt_brain.plan_hunt, campaign.account_login_service.login, acs.run_bfla_check) = orig

        self.assertTrue(result["ok"], result.get("error"))
        self.assertIn(admin_ep, calls)                             # the recon-derived admin endpoint was tested
        bfla_refs = [f["ref"] for f in result["findings"] if f.get("rule_id") == "active.bfla"]
        self.assertEqual(len(bfla_refs), 1)

    def test_bfla_prover_is_not_run_without_an_admin_account(self) -> None:
        # only a low-priv session, no admin account -> the BFLA pass is skipped (needs BOTH sessions)
        from bughunter import access_control_service as acs
        target = "https://app.example.com/"
        admin_ep = target + "admin/users"
        called: list = []
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign.hunt_brain.plan_hunt, acs.run_bfla_check)
        campaign.recon.discover = lambda t, **k: {"urls": [t, admin_ep], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign.hunt_brain.plan_hunt = lambda *a, **k: {"used": True, "provider": "x", "model": "y",
            "param_hypotheses": [], "probe_priority": [], "idor_candidates": [], "privileged_endpoints": [admin_ep], "notes": ""}
        acs.run_bfla_check = lambda url, **k: called.append(url)
        try:
            campaign.run_campaign(target, scope="app.example.com", authorized=True, coder_cfg={"provider": "x"},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo",
                active=True, auth={"cookie": "sid=user"})  # no admin_account_access
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign.hunt_brain.plan_hunt, acs.run_bfla_check) = orig
        self.assertEqual(called, [])                               # BFLA never invoked without the second account

    def test_operator_supplied_idor_pairs_run_the_dual_session_cross_tenant_prover(self) -> None:
        # The operator supplies object-URL pairs their two accounts own; with BOTH accounts, the campaign
        # runs the dual-session cross-tenant IDOR prover on each pair and folds a CONFIRMED read in.
        from bughunter import access_control_service as acs

        target = "https://app.example.com/"
        obj_a = target + "api/orders/1001"   # account A owns this
        obj_b = target + "api/orders/2002"   # account B owns this (different object)
        idor_finding = {"title": "IDOR / broken access control at /api/orders/1001", "severity": "high",
                        "class_id": "access-control", "rule_id": "active.idor", "location": obj_a, "cwe": "CWE-639"}
        idor_plan = {"proof_of_impact": {"status": "confirmed", "observed_result": "B read A's object",
                                         "control_result": "distinct from B's own object"}, "cvss": {"base_score": 8.1}}
        calls: list = []
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign.hunt_brain.plan_hunt, campaign.account_login_service.login, acs.run_idor_check)
        campaign.recon.discover = lambda t, **k: {"urls": [t, obj_a], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign.hunt_brain.plan_hunt = lambda *a, **k: {"used": True, "provider": "x", "model": "y",
            "param_hypotheses": [], "probe_priority": [], "idor_candidates": [], "privileged_endpoints": [], "notes": ""}
        campaign.account_login_service.login = lambda acc, scope, settings=None: {"ok": True, "cookie": "sid=B", "note": "logged in"}
        acs.run_idor_check = lambda ua, ub, **k: (calls.append((ua, ub, k.get("account_a"), k.get("account_b"))),
            {"ok": True, "status": "confirmed", "finding": dict(idor_finding), "attack_plan": idor_plan})[1]
        try:
            result = campaign.run_campaign(
                target, scope="app.example.com", authorized=True, coder_cfg={"provider": "x"},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo",
                active=True, auth={"cookie": "sid=A"}, admin_account_access={"cookie": "sid=B"},
                idor_pairs=[{"url_a": obj_a, "url_b": obj_b}])
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign.hunt_brain.plan_hunt, campaign.account_login_service.login, acs.run_idor_check) = orig

        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(calls[0][0], obj_a)                       # A's object URL
        self.assertEqual(calls[0][1], obj_b)                       # B's own object URL
        self.assertEqual(calls[0][2], {"cookie": "sid=A"})         # account_a = the PRIMARY (owns obj_a)
        self.assertEqual(calls[0][3].get("cookie"), "sid=B")       # account_b = the SECOND account (owns obj_b)
        xidor_refs = [f["ref"] for f in result["findings"] if f.get("rule_id") == "active.idor"]
        self.assertEqual(len(xidor_refs), 1)                       # the confirmed cross-tenant read was folded in
        self.assertEqual(result["proof_of_impact"][xidor_refs[0]]["status"], "confirmed")  # prover's differential confirms

    def test_idor_pairs_skipped_without_a_second_account(self) -> None:
        # a pair but only ONE account -> the cross-tenant IDOR pass is skipped (needs two sessions)
        from bughunter import access_control_service as acs
        target = "https://app.example.com/"
        obj_a, obj_b = target + "api/orders/1001", target + "api/orders/2002"
        called: list = []
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign.hunt_brain.plan_hunt, acs.run_idor_check)
        campaign.recon.discover = lambda t, **k: {"urls": [t, obj_a], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign.hunt_brain.plan_hunt = lambda *a, **k: {"used": True, "provider": "x", "model": "y",
            "param_hypotheses": [], "probe_priority": [], "idor_candidates": [], "privileged_endpoints": [], "notes": ""}
        acs.run_idor_check = lambda ua, ub, **k: called.append(ua)
        try:
            campaign.run_campaign(target, scope="app.example.com", authorized=True, coder_cfg={"provider": "x"},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo",
                active=True, auth={"cookie": "sid=A"}, idor_pairs=[{"url_a": obj_a, "url_b": obj_b}])  # no admin account
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign.hunt_brain.plan_hunt, acs.run_idor_check) = orig
        self.assertEqual(called, [])                               # never invoked without the second account

    def test_idor_pair_off_campaign_host_is_not_tested(self) -> None:
        # a pair whose object is on a host this campaign didn't touch is skipped (so a program-wide pair
        # isn't re-tested once per target in a span) — even with both accounts present
        from bughunter import access_control_service as acs
        target = "https://app.example.com/"
        other_a = "https://other.example.com/api/orders/1001"   # NOT in this campaign's surface
        other_b = "https://other.example.com/api/orders/2002"
        called: list = []
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign.hunt_brain.plan_hunt, campaign.account_login_service.login, acs.run_idor_check)
        campaign.recon.discover = lambda t, **k: {"urls": [t], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign.hunt_brain.plan_hunt = lambda *a, **k: {"used": True, "provider": "x", "model": "y",
            "param_hypotheses": [], "probe_priority": [], "idor_candidates": [], "privileged_endpoints": [], "notes": ""}
        campaign.account_login_service.login = lambda acc, scope, settings=None: {"ok": True, "cookie": "sid=B", "note": "ok"}
        acs.run_idor_check = lambda ua, ub, **k: called.append(ua)
        try:
            campaign.run_campaign(target, scope="app.example.com", authorized=True, coder_cfg={"provider": "x"},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo",
                active=True, auth={"cookie": "sid=A"}, admin_account_access={"cookie": "sid=B"},
                idor_pairs=[{"url_a": other_a, "url_b": other_b}])
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign.hunt_brain.plan_hunt, campaign.account_login_service.login, acs.run_idor_check) = orig
        self.assertEqual(called, [])                               # off-host pair never tested in this campaign

    def test_idor_prover_is_not_run_without_a_session(self) -> None:
        # no session -> the IDOR pass is skipped entirely (the probe needs the operator's own object)
        from bughunter import access_control_service as acs
        target = "https://app.example.com/"
        called: list = []
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
                campaign.hunt_brain.plan_hunt, acs.run_idor_probe)
        campaign.recon.discover = lambda t, **k: {"urls": [t], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": "", "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda t, **k: {"ok": True, "findings": []}
        campaign.hunt_brain.plan_hunt = lambda *a, **k: {"used": True, "provider": "x", "model": "y",
            "param_hypotheses": [], "probe_priority": [], "idor_candidates": [target], "notes": ""}
        acs.run_idor_probe = lambda url, **k: called.append(url)
        try:
            campaign.run_campaign(target, scope="app.example.com", authorized=True, coder_cfg={"provider": "x"},
                default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9", program="demo", active=True)  # no auth
        finally:
            (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves,
             campaign.hunt_brain.plan_hunt, acs.run_idor_probe) = orig
        self.assertEqual(called, [])                               # prover never invoked without a session

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


class SeverityRollupTests(unittest.TestCase):
    """campaign._campaign_risk / _severity_counts -- the roll-up the cockpit's risk badge
    and severity dots surface -- had no direct test."""

    def _consolidated(self, *severities: str) -> list[dict]:
        return [{"finding": {"severity": s}} for s in severities]

    def test_severity_counts_tallies_each_band(self) -> None:
        findings = [{"severity": "critical"}, {"severity": "high"}, {"severity": "high"}, {"severity": "low"}]
        counts = campaign._severity_counts(findings)
        self.assertEqual(counts, {"critical": 1, "high": 2, "medium": 0, "low": 1, "info": 0})

    def test_severity_counts_missing_severity_defaults_to_info(self) -> None:
        counts = campaign._severity_counts([{}])
        self.assertEqual(counts["info"], 1)

    def test_severity_counts_unknown_label_is_silently_dropped(self) -> None:
        counts = campaign._severity_counts([{"severity": "made-up"}])
        self.assertEqual(sum(counts.values()), 0)

    def test_risk_empty_consolidated_is_clean(self) -> None:
        self.assertEqual(campaign._campaign_risk([]), "clean")

    def test_risk_info_only_is_low(self) -> None:
        self.assertEqual(campaign._campaign_risk(self._consolidated("info", "low")), "low")

    def test_risk_critical_present_outranks_everything(self) -> None:
        self.assertEqual(campaign._campaign_risk(self._consolidated("low", "medium", "critical")), "critical")

    def test_risk_high_without_critical_is_high(self) -> None:
        self.assertEqual(campaign._campaign_risk(self._consolidated("low", "high")), "high")

    def test_risk_medium_without_high_or_critical_is_moderate(self) -> None:
        self.assertEqual(campaign._campaign_risk(self._consolidated("info", "medium")), "moderate")


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


class ProgramCampaignTargetsTests(unittest.TestCase):
    """program_campaign_targets -- the "span this program's whole scope" target list.
    Prefers hand-typed seed_targets; falls back to deriving one target per eligible
    structured_scope entry so a HackerOne-imported program (no seed_targets) still has
    something to hunt."""

    def test_prefers_seed_targets_over_structured_scope(self) -> None:
        program = {
            "seed_targets": ["https://a.example.com", "https://a.example.com", "https://b.example.com"],
            "structured_scope": [{"identifier": "c.example.com", "eligible_for_submission": True}],
        }
        self.assertEqual(campaign.program_campaign_targets(program), ["https://a.example.com", "https://b.example.com"])

    def test_opted_in_repository_is_additive_to_web_seed_targets(self) -> None:
        program = {
            "seed_targets": ["https://app.example.com"],
            "clone_repositories": True,
            "repository_urls": ["https://github.com/acme/widget"],
        }
        self.assertEqual(campaign.program_campaign_targets(program), [
            "https://app.example.com", "https://github.com/acme/widget",
        ])

    def test_repository_in_structured_scope_requires_clone_opt_in(self) -> None:
        scoped = {"structured_scope": [{
            "identifier": "https://github.com/acme/widget", "eligible_for_submission": True,
        }]}
        self.assertEqual(campaign.program_campaign_targets(scoped), [])
        scoped["clone_repositories"] = True
        self.assertEqual(campaign.program_campaign_targets(scoped), ["https://github.com/acme/widget"])

    def test_falls_back_to_structured_scope_when_no_seed_targets(self) -> None:
        program = {"structured_scope": [
            {"identifier": "a.example.com", "eligible_for_submission": True},
            {"identifier": "b.example.com", "eligible_for_submission": True},
        ]}
        self.assertEqual(campaign.program_campaign_targets(program), ["https://a.example.com", "https://b.example.com"])

    def test_excludes_ineligible_entries(self) -> None:
        program = {"structured_scope": [
            {"identifier": "in.example.com", "eligible_for_submission": True},
            {"identifier": "out.example.com", "eligible_for_submission": False},
        ]}
        self.assertEqual(campaign.program_campaign_targets(program), ["https://in.example.com"])

    def test_strips_wildcard_to_a_concrete_apex(self) -> None:
        # A real HackerOne export uses *.tiktok.com-style wildcards; "*" itself isn't
        # a fetchable host, so a wildcard entry should still seed the bare apex.
        program = {"structured_scope": [{"identifier": "*.example.com", "eligible_for_submission": True}]}
        self.assertEqual(campaign.program_campaign_targets(program), ["https://example.com"])

    def test_excludes_non_host_identifiers(self) -> None:
        # Real HackerOne scope shapes: an Apple Store numeric id (no dots -> not a host),
        # an Android package (has dots -> normalizes fine), and a free-text asset label.
        program = {"structured_scope": [
            {"identifier": "835599320", "eligible_for_submission": True},
            {"identifier": "com.acme.app", "eligible_for_submission": True},
            {"identifier": "Other Asset (Campaigns)", "eligible_for_submission": True},
        ]}
        self.assertEqual(campaign.program_campaign_targets(program), ["https://com.acme.app"])

    def test_dedupes_across_structured_scope_entries(self) -> None:
        program = {"structured_scope": [
            {"identifier": "a.example.com", "eligible_for_submission": True},
            {"identifier": "a.example.com", "eligible_for_submission": True},
        ]}
        self.assertEqual(campaign.program_campaign_targets(program), ["https://a.example.com"])

    def test_capped_at_max_targets(self) -> None:
        program = {"structured_scope": [
            {"identifier": f"h{i}.example.com", "eligible_for_submission": True} for i in range(30)
        ]}
        self.assertEqual(len(campaign.program_campaign_targets(program, max_targets=5)), 5)

    def test_empty_program_returns_empty_list(self) -> None:
        self.assertEqual(campaign.program_campaign_targets({}), [])

    def test_out_of_scope_seed_target_is_never_hunted(self) -> None:
        # Regression: out_of_scope_hosts was stored but never consulted anywhere, so an
        # operator-excluded host could still become the literal target of a hunt just
        # because it was hand-typed as a seed.
        program = {
            "seed_targets": ["https://a.example.com", "https://staging-admin.example.com"],
            "out_of_scope_hosts": ["staging-admin.example.com"],
        }
        self.assertEqual(campaign.program_campaign_targets(program), ["https://a.example.com"])

    def test_out_of_scope_structured_scope_entry_is_never_hunted(self) -> None:
        program = {"structured_scope": [
            {"identifier": "in.example.com", "eligible_for_submission": True},
            {"identifier": "out.example.com", "eligible_for_submission": True},
        ], "out_of_scope_hosts": ["out.example.com"]}
        self.assertEqual(campaign.program_campaign_targets(program), ["https://in.example.com"])

    def test_out_of_scope_host_excludes_its_subdomains_too(self) -> None:
        program = {
            "seed_targets": ["https://admin.staging.example.com"],
            "out_of_scope_hosts": ["staging.example.com"],
        }
        self.assertEqual(campaign.program_campaign_targets(program), [])

    def test_falls_back_to_structured_scope_when_every_seed_is_excluded(self) -> None:
        program = {
            "seed_targets": ["https://excluded.example.com"],
            "out_of_scope_hosts": ["excluded.example.com"],
            "structured_scope": [{"identifier": "fallback.example.com", "eligible_for_submission": True}],
        }
        self.assertEqual(campaign.program_campaign_targets(program), ["https://fallback.example.com"])


class RunCampaignOverTargetsTests(unittest.TestCase):
    """run_campaign_over_targets -- one full campaign per target, merged. Offline: uses
    local source-folder targets (kind=path), matching CampaignTests' no-network style,
    so the merge/loop logic itself is under test, not recon/network."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.src_a = self.root / "src_a"
        self.src_a.mkdir()
        (self.src_a / "app.py").write_text(_VULN_SRC, encoding="utf-8")
        self.src_b = self.root / "src_b"
        self.src_b.mkdir()
        (self.src_b / "app.py").write_text(_VULN_SRC, encoding="utf-8")
        self.reports = self.root / "reports"
        self.runtime = self.root / "runtime"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, targets, **kw):
        return campaign.run_campaign_over_targets(
            targets, scope="demo scope", authorized=True, coder_cfg={},
            default_reports_dir=self.reports, seed_dir=BACKEND_DIR / "seed",
            runtime_dir=self.runtime, version="9.9.9", program="demo-program", **kw,
        )

    def test_requires_authorization(self) -> None:
        result = campaign.run_campaign_over_targets(
            [str(self.src_a)], scope="", authorized=False, coder_cfg={},
            default_reports_dir=self.reports, runtime_dir=self.runtime, version="9.9.9",
        )
        self.assertFalse(result["ok"])
        self.assertIn("authorized", result["error"].lower())

    def test_attack_map_option_is_forwarded_to_each_target(self) -> None:
        # QAQC regression: the span path must HONOR the attack-map opt-out (it was silently defaulting
        # to True). Prove the per-target run_campaign receives whatever include_attack_map the span got.
        original = campaign.run_campaign
        seen: list = []

        def fake_run_campaign(target, **kw):
            seen.append(kw.get("include_attack_map"))
            return {"ok": True, "campaign_path": "", "json_path": "", "urls_scanned": 1, "urls_discovered": 1,
                    "finding_count": 0, "confirmed_count": 0, "submission_paths": [], "findings": [],
                    "proof_of_impact": {}, "cvss": {}, "attack_plans": {}, "surface": {}, "risk": "clean"}

        campaign.run_campaign = fake_run_campaign
        try:
            self._run([str(self.src_a)], include_attack_map=False)   # opt OUT
            self._run([str(self.src_b)], include_attack_map=True)    # opt IN
        finally:
            campaign.run_campaign = original
        self.assertEqual(seen, [False, True])                        # the toggle reaches every target

    def test_no_targets_is_a_clean_error(self) -> None:
        result = self._run([])
        self.assertFalse(result["ok"])
        self.assertIn("no huntable targets", result["error"].lower())

    def test_merges_findings_across_targets_with_unique_refs(self) -> None:
        # Derive the expected per-target count from a real single-target scan of the
        # SAME fixture, rather than hardcode a magic number that would silently go
        # stale if the detection rules' finding count for _VULN_SRC ever changes.
        single = campaign.run_campaign(
            str(self.src_a), scope="demo scope", authorized=True, coder_cfg={},
            default_reports_dir=self.reports, seed_dir=BACKEND_DIR / "seed",
            runtime_dir=self.runtime, version="9.9.9", program="baseline",
        )
        per_target_count = single["finding_count"]
        self.assertGreaterEqual(per_target_count, 2)  # cmd-injection + secret, at minimum

        result = self._run([str(self.src_a), str(self.src_b)])
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["targets_total"], 2)
        self.assertEqual(result["targets_hunted"], 2)
        self.assertEqual(result["finding_count"], per_target_count * 2)
        refs = [f["ref"] for f in result["findings"]]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertTrue(all(r.startswith("C") for r in refs))
        for f in result["findings"]:
            self.assertIn(f["ref"], result["proof_of_impact"])

    def test_dedupes_identical_targets(self) -> None:
        result = self._run([str(self.src_a), str(self.src_a)])
        self.assertEqual(result["targets_total"], 1)

    def test_targets_run_concurrently_not_sequentially(self) -> None:
        # run_campaign_over_targets() used to loop over targets one at a time -- a
        # bounded thread pool now overlaps them, since each target's own hunt is
        # almost entirely network-I/O-bound. Prove genuine overlap by timing N fake
        # targets that each "work" for a fixed duration: sequential execution would
        # take N x duration; concurrent execution (up to _SPAN_MAX_WORKERS at once)
        # should take close to ONE duration.
        original = campaign.run_campaign
        duration = 0.3
        n_targets = 4

        def fake_run_campaign(target, **kw):
            time.sleep(duration)
            return {"ok": True, "campaign_path": "", "json_path": "", "urls_scanned": 1, "urls_discovered": 1,
                    "finding_count": 0, "confirmed_count": 0, "submission_paths": [], "findings": [],
                    "proof_of_impact": {}, "cvss": {}, "attack_plans": {}, "surface": {}, "risk": "clean"}

        campaign.run_campaign = fake_run_campaign
        try:
            targets = [f"{self.src_a}-{i}" for i in range(n_targets)]
            # These aren't real paths, but fake_run_campaign never looks at them.
            start = time.monotonic()
            result = self._run(targets)
            elapsed = time.monotonic() - start
        finally:
            campaign.run_campaign = original
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["targets_hunted"], n_targets)
        # Sequential would take n_targets * duration (1.2s here); concurrent (up to
        # 4 workers) should take close to one duration. Generous margin for CI jitter.
        self.assertLess(elapsed, duration * n_targets * 0.75)

    def test_findings_are_assigned_refs_in_target_order_not_completion_order(self) -> None:
        # Aggregation must stay deterministic: target A's findings always get lower
        # ref numbers than target B's, regardless of which target's worker thread
        # happens to finish first.
        original = campaign.run_campaign
        # Target "slow" finishes AFTER target "fast" despite being submitted first
        # (it's index 1) -- if aggregation used completion order instead of target
        # order, "fast"'s finding would get C1 instead of C2.
        order = {"slow": 0.25, "fast": 0.0}

        def fake_run_campaign(target, **kw):
            time.sleep(order.get(target, 0.0))
            return {"ok": True, "campaign_path": "", "json_path": "", "urls_scanned": 1, "urls_discovered": 1,
                    "finding_count": 1, "confirmed_count": 0, "submission_paths": [],
                    "findings": [{"ref": "F1", "title": f"finding for {target}"}],
                    "proof_of_impact": {"F1": {"status": "missing"}}, "cvss": {}, "attack_plans": {},
                    "surface": {}, "risk": "low"}

        campaign.run_campaign = fake_run_campaign
        try:
            result = self._run(["slow", "fast"])
        finally:
            campaign.run_campaign = original
        self.assertTrue(result["ok"], result.get("error"))
        titles_by_ref = {f["ref"]: f["title"] for f in result["findings"]}
        self.assertEqual(titles_by_ref["C1"], "finding for slow")
        self.assertEqual(titles_by_ref["C2"], "finding for fast")

    def test_writes_a_span_index_and_a_bundleable_output_dir(self) -> None:
        result = self._run([str(self.src_a), str(self.src_b)])
        self.assertTrue(Path(result["campaign_path"]).is_file())
        self.assertTrue(Path(result["json_path"]).is_file())
        out_dir = Path(result["output_dir"])
        self.assertTrue(out_dir.is_dir())
        # each target's own full campaign folder nests inside the span root, so the
        # existing recursive-zip bundler picks up every target's artifacts for free.
        subfolders = [p for p in out_dir.iterdir() if p.is_dir()]
        self.assertEqual(len(subfolders), 2)

    def test_one_bad_target_does_not_abort_the_rest(self) -> None:
        # A non-existent local path is NOT itself a run_campaign failure (the underlying
        # scanner just finds nothing to scan and reports ok:True/0 findings) -- use a
        # target string _infer_kind genuinely can't classify (unknown kind -> ok:False).
        unclassifiable = "not a real target at all"
        result = self._run([str(self.src_a), unclassifiable])
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["targets_hunted"], 1)
        self.assertEqual(len(result["errors"]), 1)

    def test_all_targets_failing_is_a_clean_error_not_ok_true(self) -> None:
        result = self._run(["not a real target at all", "also not a real target"])
        self.assertFalse(result["ok"])

    def test_capped_at_max_targets_and_discloses_the_cap(self) -> None:
        result = self._run([str(self.src_a), str(self.src_b)], max_targets=1)
        self.assertEqual(result["targets_total"], 2)
        self.assertEqual(result["targets_hunted"], 1)
        self.assertTrue(any("capped" in e.lower() for e in result["errors"]))


class PortfolioCampaignTests(unittest.TestCase):
    """run_portfolio_campaign — many programs, one merged run. Offline: the per-program span
    (run_campaign_over_targets) is stubbed so we test the ORCHESTRATION (concurrency merge,
    global re-ref, per-program roll-up, auth gate, program-unit progress) without network."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._orig = campaign.run_campaign_over_targets

    def tearDown(self) -> None:
        campaign.run_campaign_over_targets = self._orig
        self._tmp.cleanup()

    def _stub_span(self):
        # Each program returns one confirmed finding, streamed to the program's dashboard unit.
        def fake(targets, *, program=None, progress_run_id=None, progress_unit=None, **kw):
            ref = "F1"
            finding = {"ref": ref, "title": f"{program} finding", "severity": "high", "class_name": "xss",
                       "location": targets[0] if targets else "https://x", "source_url": targets[0] if targets else "https://x"}
            if progress_run_id and progress_unit:
                campaign.progress.add_findings(progress_run_id, progress_unit, [{**finding, "proof_status": "confirmed"}])
            return {"ok": True, "findings": [finding], "proof_of_impact": {ref: {"status": "confirmed"}},
                    "cvss": {}, "attack_plans": {}, "submission_paths": [], "finding_count": 1, "confirmed_count": 1,
                    "surface": {"urls": targets, "sources": {}, "notes": [], "tech": []}}
        campaign.run_campaign_over_targets = fake

    def _specs(self):
        return [
            {"label": "prog-a", "scope": "a.example", "targets": ["https://a.example"], "excluded_hosts": [], "disclose_automation": False},
            {"label": "prog-b", "scope": "b.example", "targets": ["https://b.example"], "excluded_hosts": [], "disclose_automation": False},
        ]

    def test_refuses_unauthorized(self) -> None:
        out = campaign.run_portfolio_campaign(self._specs(), authorized=False, coder_cfg={}, default_reports_dir=self.root)
        self.assertFalse(out["ok"])

    def test_no_huntable_programs_is_clean_error(self) -> None:
        specs = [{"label": "empty", "scope": "", "targets": [], "excluded_hosts": [], "disclose_automation": False}]
        out = campaign.run_portfolio_campaign(specs, authorized=True, coder_cfg={}, default_reports_dir=self.root)
        self.assertFalse(out["ok"])

    def test_merges_multiple_programs_with_global_refs(self) -> None:
        self._stub_span()
        campaign.progress.start_run("port-1")
        out = campaign.run_portfolio_campaign(self._specs(), authorized=True, coder_cfg={},
                                              default_reports_dir=self.root, version="9.9.9", progress_run_id="port-1")
        self.assertTrue(out["ok"], out.get("error"))
        self.assertEqual(out["programs_hunted"], 2)
        self.assertEqual(out["finding_count"], 2)
        self.assertEqual([f["ref"] for f in out["findings"]], ["C1", "C2"])  # globally re-reffed
        self.assertEqual(out["confirmed_count"], 2)
        self.assertEqual(len(out["per_program"]), 2)
        # PROGRAMS (not targets) are the dashboard units, and findings streamed under them.
        snap = campaign.progress.snapshot("port-1")
        self.assertEqual(sorted(t["target"] for t in snap["targets"]), ["prog-a", "prog-b"])
        self.assertEqual(snap["stats"]["findings_total"], 2)

    def test_one_bad_program_never_aborts_the_rest(self) -> None:
        def fake(targets, *, program=None, **kw):
            if program == "prog-a":
                raise RuntimeError("boom")
            return {"ok": True, "findings": [{"ref": "F1", "title": "ok", "severity": "low"}],
                    "proof_of_impact": {"F1": {"status": "candidate"}}, "cvss": {}, "attack_plans": {},
                    "submission_paths": [], "finding_count": 1, "confirmed_count": 0,
                    "surface": {"urls": targets, "sources": {}, "notes": [], "tech": []}}
        campaign.run_campaign_over_targets = fake
        out = campaign.run_portfolio_campaign(self._specs(), authorized=True, coder_cfg={}, default_reports_dir=self.root)
        self.assertTrue(out["ok"])
        self.assertEqual(out["programs_hunted"], 1)
        self.assertTrue(any("prog-a" in e for e in out["errors"]))


class ProofScreenshotCaptureTests(unittest.TestCase):
    """campaign._capture_proof_screenshots — the proof screenshot pass now runs for EVERY
    actively-confirmed finding (not only deep mode). It records the shot path (+ the plain-text
    request/response proof) on each finding, is best-effort (a missing PoC URL or a capture error
    is a clean skip), and never raises — a broken/absent Playwright must never break the campaign.
    screenshot_service is stubbed so the test stays offline."""

    def setUp(self) -> None:
        self._orig = (campaign.screenshot_service.poc_url_for_finding,
                      campaign.screenshot_service.capture_screenshot)

    def tearDown(self) -> None:
        (campaign.screenshot_service.poc_url_for_finding,
         campaign.screenshot_service.capture_screenshot) = self._orig

    @staticmethod
    def _items(n: int) -> list[dict]:
        return [{"finding": {"ref": f"C{i}"}, "source_url": f"https://in-scope.example/{i}"} for i in range(n)]

    def test_records_path_and_source_text_on_each_confirmed_finding(self) -> None:
        campaign.screenshot_service.poc_url_for_finding = lambda finding, ctx: ctx["target"]
        campaign.screenshot_service.capture_screenshot = lambda url, path, **kw: {
            "ok": True, "path": str(path), "source_text_path": str(path) + ".txt"}
        items = self._items(3)
        n = campaign._capture_proof_screenshots(items, Path("shots"), "https://in-scope.example", "in-scope.example", with_attack_map=False)
        self.assertEqual(n, 3)
        for it in items:
            self.assertTrue(str(it["finding"]["screenshot_path"]).endswith(".png"))
            self.assertTrue(str(it["finding"]["source_text_path"]).endswith(".txt"))

    def test_capture_error_is_a_clean_skip_never_raises(self) -> None:
        def boom(url, path, **kw):
            raise RuntimeError("playwright not installed")
        campaign.screenshot_service.poc_url_for_finding = lambda finding, ctx: ctx["target"]
        campaign.screenshot_service.capture_screenshot = boom
        items = self._items(2)
        n = campaign._capture_proof_screenshots(items, Path("shots"), "https://in-scope.example", "in-scope.example", with_attack_map=False)
        self.assertEqual(n, 0)
        self.assertNotIn("screenshot_path", items[0]["finding"])

    def test_missing_poc_url_skips_without_calling_capture(self) -> None:
        calls: list[int] = []
        campaign.screenshot_service.poc_url_for_finding = lambda finding, ctx: ""
        campaign.screenshot_service.capture_screenshot = lambda *a, **k: calls.append(1) or {"ok": True, "path": "x"}
        items = self._items(2)
        n = campaign._capture_proof_screenshots(items, Path("shots"), "t", "s", with_attack_map=False)
        self.assertEqual(n, 0)
        self.assertEqual(calls, [])  # no PoC URL -> capture is never attempted


if __name__ == "__main__":
    unittest.main()
