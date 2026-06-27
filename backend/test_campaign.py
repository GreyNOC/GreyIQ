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


if __name__ == "__main__":
    unittest.main()
