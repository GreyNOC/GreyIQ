"""The Download-leads endpoint (greyiq_api.export_leads) behind the Hunt cockpit button.

It renders a finished hunt's investigation queue as ONE Markdown brief. Two properties matter and
are pinned here: the sidecar is located from the CACHED RUN (never a client-supplied path, so the
route cannot be walked into an arbitrary file read), and the brief goes through the redaction-safe
lead bridge, so a credential in the target URL or the captured proof never reaches the download."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402
from bughunter import investigator  # noqa: E402
from bughunter import leads  # noqa: E402
from bughunter import report as report_lib  # noqa: E402

_SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _sidecar(target: str) -> dict:
    finding = {
        "ref": "F1", "title": "IDOR on account export", "class_id": "access-control",
        "severity": "high", "confidence": "high", "rule_id": "active.idor",
        "location": "https://app.example.com/api/account/1001/export",
    }
    plan = {"proof_of_impact": {
        "status": "confirmed",
        "observed_result": f"HTTP 200 — export returned; session token {_SECRET} was accepted",
        "control_result": "HTTP 403 — the attacker's own id was refused",
    }}
    inv = investigator.build_investigation([finding], {"F1": plan})
    ctx = {"tool": "GreyIQ BugHunter", "version": "9.9.9", "generated_at": "now",
           "target": target, "scope": "*.example.com", "authorized": True,
           "scanners_run": ["web"], "risk": "high", "score": 70,
           "findings": [finding], "attack_plans": {"F1": plan}, "investigation": inv,
           "next_steps": [], "profile": {"id": "web-app", "name": "Web app"}}
    return report_lib.build_json(ctx)


class ExportLeadsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.json_path = Path(self._tmp.name) / "bounty-web-app-app-20260903-000000-abcd1234.json"

    def _cache_run(self, target: str = "https://app.example.com") -> str:
        self.json_path.write_text(json.dumps(_sidecar(target)), encoding="utf-8")
        run_id = "test-run-leads"
        with self.rt.lock:
            self.rt.bounty_runs[run_id] = {
                "ctx": {"target": target}, "findings": {}, "program": None, "target": target,
                "artifacts": {"is_campaign": False, "json_path": str(self.json_path),
                              "report_path": "", "output_dir": str(self._tmp.name)},
            }
        self.addCleanup(lambda: self.rt.bounty_runs.pop(run_id, None))
        return run_id

    def test_renders_a_markdown_brief_for_the_cached_run(self) -> None:
        run_id = self._cache_run()
        res = self.rt.export_leads(g.LeadsRequest(run_id=run_id))
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["lead_count"], 1)
        self.assertTrue(res["filename"].endswith(".md"))
        # The host is slugged into a filesystem-safe form (dots -> hyphens).
        self.assertIn("app-example-com", res["filename"])
        md = res["markdown"]
        self.assertIn("F1", md)
        self.assertIn("To confirm", md)          # the proof obligation an analyst acts on
        self.assertIn("UNTRUSTED", md.upper())   # wrapped as data for a model

    def test_secret_in_captured_proof_never_reaches_the_download(self) -> None:
        run_id = self._cache_run()
        res = self.rt.export_leads(g.LeadsRequest(run_id=run_id))
        self.assertNotIn(_SECRET, res["markdown"])
        # The structured rows are the SAME projection the brief renders from, but assert them
        # explicitly: a redaction guarantee that holds only for the rendered string would be a
        # guarantee the in-app view does not have.
        self.assertNotIn(_SECRET, json.dumps(res["report"], default=str))

    def test_the_structured_queue_is_returned_for_the_in_app_view(self) -> None:
        """The cockpit renders the queue; it cannot read a Markdown blob. This pins that the rows
        the CLI's --json exposes are reachable in-app too, with the fields an operator acts on."""
        run_id = self._cache_run()
        res = self.rt.export_leads(g.LeadsRequest(run_id=run_id))
        report = res["report"]
        self.assertEqual(report["schema"], leads.SCHEMA_VERSION)
        hunts = report["hunts"]
        self.assertEqual(len(hunts), 1)
        lead = hunts[0]["leads"][0]
        self.assertEqual(lead["id"], "F1")
        # The fields the view is built on.
        for key in ("status", "severity", "confidence_score", "proof_obligation", "decision", "rank"):
            self.assertIn(key, lead)
        self.assertTrue(lead["proof_obligation"])

    def test_credential_in_the_target_never_reaches_the_download(self) -> None:
        run_id = self._cache_run(target=f"https://app.example.com/cb?token={_SECRET}")
        res = self.rt.export_leads(g.LeadsRequest(run_id=run_id))
        self.assertNotIn(_SECRET, res["markdown"])
        self.assertNotIn(_SECRET, json.dumps(res, default=str))

    def test_credential_in_a_non_url_target_never_reaches_the_filename(self) -> None:
        """A source hunt names a local folder, so urlparse yields no hostname and the filename falls
        back to the raw target. The slugger only rewrites punctuation, so a credential in an opaque
        target would survive into the download filename even though the brief itself is scrubbed."""
        run_id = self._cache_run(target=f"/tmp/token-{_SECRET}/repo")
        res = self.rt.export_leads(g.LeadsRequest(run_id=run_id))
        self.assertTrue(res["ok"], res)
        self.assertNotIn(_SECRET, res["filename"])
        self.assertNotIn(_SECRET, json.dumps(res, default=str))
        self.assertTrue(res["filename"].endswith(".md"))

    def test_unknown_run_is_refused_without_reading_anything(self) -> None:
        res = self.rt.export_leads(g.LeadsRequest(run_id="no-such-run"))
        self.assertFalse(res["ok"])
        self.assertIn("no longer cached", res["error"])

    def test_missing_sidecar_on_disk_is_reported_not_raised(self) -> None:
        run_id = self._cache_run()
        self.json_path.unlink()
        res = self.rt.export_leads(g.LeadsRequest(run_id=run_id))
        self.assertFalse(res["ok"])
        self.assertIn("no longer on disk", res["error"])

    def test_run_id_is_required_so_no_path_can_be_supplied(self) -> None:
        # The request model carries ONLY a run_id: there is no field a caller could use to point
        # the route at an arbitrary file, which is what keeps this download off the traversal surface.
        self.assertEqual(set(g.LeadsRequest.model_fields), {"run_id"})
        with self.assertRaises(Exception):
            g.LeadsRequest(run_id="")


if __name__ == "__main__":
    unittest.main()
