"""Tests for GreyIQ v2 evidence-bundle upgrades — the triager-facing INDEX.md, the
negative-control differential in replay.sh, and single-hunt replay.sh/findings.har parity
(previously campaign-only) plus INDEX in every downloadable bundle."""
from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402
from bughunter import bundle  # noqa: E402


class BuildIndexTests(unittest.TestCase):
    def _meta(self):
        return {"tool": "GreyIQ BugHunter", "version": "2.0.0", "generated_at": "2026-07-14",
                "target": "app.example.com", "scope": "*.example.com",
                "findings": [{"ref": "F1", "title": "IDOR in orders", "severity": "high", "proof_status": "confirmed"},
                             {"ref": "F2", "title": "Reflected XSS", "severity": "medium", "proof_status": "candidate"}]}

    def test_header_and_findings_table(self):
        idx = bundle.build_index(self._meta(), {"report.md"})
        self.assertIn("# Evidence bundle", idx)
        self.assertIn("app.example.com", idx)
        self.assertIn("| F1 |", idx)
        self.assertIn("IDOR in orders", idx)
        self.assertIn("confirmed", idx)

    def test_severity_ordering_high_before_medium(self):
        idx = bundle.build_index(self._meta(), set())
        self.assertLess(idx.index("IDOR in orders"), idx.index("Reflected XSS"))

    def test_guide_lists_only_present_artifacts(self):
        idx = bundle.build_index(self._meta(), {"replay.sh", "screenshots"})
        self.assertIn("`replay.sh`", idx)
        self.assertIn("`screenshots/`", idx)
        self.assertNotIn("`findings.har`", idx)  # not present -> not listed

    def test_verify_and_reproduce_sections(self):
        idx = bundle.build_index(self._meta(), {"replay.sh", "findings.har"})
        self.assertIn("sha256sum -c MANIFEST.sha256", idx)
        self.assertIn("## Reproduce", idx)
        self.assertIn("bash replay.sh", idx)

    def test_no_reproduce_section_without_artifacts(self):
        idx = bundle.build_index(self._meta(), {"report.md"})
        self.assertNotIn("## Reproduce", idx)

    def test_total_on_empty_meta(self):
        idx = bundle.build_index({}, set())
        self.assertIn("# Evidence bundle", idx)
        self.assertIn("Verify integrity", idx)


class ExportBundleParityTests(unittest.TestCase):
    """A single hunt's downloadable bundle now carries INDEX.md + replay.sh + findings.har,
    the machine-replayable artifacts that were previously written only for campaigns."""

    def setUp(self):
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.RUNTIME_DIR = Path(self._tmp.name)
        result = {
            "ok": True,
            "findings": [{
                "ref": "F1", "title": "Host header injection", "severity": "high", "class_id": "ssrf",
                "class_name": "Host header injection", "cwe": "CWE-918",
                "location": "https://app.example.com/reset",
                "rule_id": "active.host-header",
                # a captured, single runnable crafted request line -> replay.sh/findings.har materialize
                "proof_evidence": {"request_line": "GET https://app.example.com/reset",
                                   "request_header": "Host: evil.example",
                                   "response_status": "200"},
            }],
            "attack_plans": {"F1": {"steps": ["send crafted Host"], "impact": "poisoned reset link",
                                    "proof_of_impact": {"status": "confirmed",
                                                        "observed_result": "reset link pointed at evil.example",
                                                        "control_result": "real Host did not"}}},
        }
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="app.example.com", program="acme")
        self.run_id = result["run_id"]

    def tearDown(self):
        g.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def test_single_hunt_bundle_has_index_replay_and_har(self):
        res = self.rt.export_bundle(g.BundleRequest(run_id=self.run_id))
        self.assertTrue(res["ok"], res)
        with zipfile.ZipFile(res["path"]) as zf:
            names = set(zf.namelist())
            self.assertIn("INDEX.md", names)
            self.assertIn("replay.sh", names)
            self.assertIn("findings.har", names)
            self.assertIn("EVIDENCE-MANIFEST.json", names)
            index = zf.read("INDEX.md").decode("utf-8")
            replay = zf.read("replay.sh").decode("utf-8")
        # INDEX documents the finding + points at the reproduction artifacts.
        self.assertIn("Host header injection", index)
        self.assertIn("bash replay.sh", index)
        # replay.sh carries the observed-vs-control differential as comments.
        self.assertIn("negative control (baseline): real Host did not", replay)

    def test_index_is_fingerprinted_in_manifest(self):
        import json
        res = self.rt.export_bundle(g.BundleRequest(run_id=self.run_id))
        with zipfile.ZipFile(res["path"]) as zf:
            manifest = json.loads(zf.read("EVIDENCE-MANIFEST.json").decode("utf-8"))
        paths = {a["path"] for a in manifest["artifacts"]}
        self.assertIn("INDEX.md", paths)  # chain of custody covers the index too
        self.assertIn("replay.sh", paths)


if __name__ == "__main__":
    unittest.main()
