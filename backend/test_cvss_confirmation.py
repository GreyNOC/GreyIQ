"""Regression test: a finding actively confirmed by the in-hunt active-verify pass must
carry a CVSS marked estimated=False (backed by real evidence), not the static/passive
template's estimated=True — while a finding that never got active proof stays estimated.

Before the fix, bounty.py's "active proof wins last" fold discarded active_verify_service's
_active_cvss carrier and left the deterministic attack_plans[ref]['cvss'] (always
estimated=True) untouched even for confirmed findings, so a report could show
"proof of impact: confirmed" right next to "CVSS v3.1 (estimated)" -- an internal
contradiction. The fix recomputes impact_model.cvss_for_class(class_id, confirmed=True)
whenever report._proof_of_impact_detail agrees the fold-in evidence is real (the exact
same gate the report itself uses), so the two can never disagree.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import campaign  # noqa: E402


class _ReflectHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        reflected = " ".join(v for vals in q.values() for v in vals)
        body = f"<html>echo {reflected}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


class CvssConfirmationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.server.shutdown()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev
        self._tmp.cleanup()

    def test_actively_confirmed_finding_gets_non_estimated_cvss(self) -> None:
        url = f"http://127.0.0.1:{self.port}/?q=x"
        out = Path(self._tmp.name) / "reports"
        res = campaign.run_campaign(
            url, scope="127.0.0.1", authorized=True, coder_cfg=None,
            default_reports_dir=out, runtime_dir=Path(self._tmp.name),
            active=True, time_based=False, deep=False,
        )
        self.assertTrue(res.get("ok"), res.get("error"))
        active_findings = [f for f in res["findings"] if str(f.get("rule_id") or "").startswith("active.")]
        self.assertTrue(active_findings, "the reflected-XSS fixture should have triggered an active finding")
        confirmed_refs = [ref for ref, p in (res.get("proof_of_impact") or {}).items() if p.get("status") == "confirmed"]
        self.assertTrue(confirmed_refs, "expected at least one actively-confirmed finding")
        for ref in confirmed_refs:
            cvss = res["cvss"].get(ref)
            self.assertIsNotNone(cvss, ref)
            self.assertFalse(cvss["estimated"], f"{ref} is confirmed but its CVSS still says estimated")
            self.assertIn("confirmed", cvss["justification"].lower())

    def test_passive_only_hunt_keeps_estimated_cvss(self) -> None:
        # No --active: nothing can be confirmed, so every CVSS in the report stays the
        # honest static-template estimate.
        url = f"http://127.0.0.1:{self.port}/?q=x"
        out = Path(self._tmp.name) / "reports-passive"
        res = campaign.run_campaign(
            url, scope="127.0.0.1", authorized=True, coder_cfg=None,
            default_reports_dir=out, runtime_dir=Path(self._tmp.name),
            active=False, time_based=False, deep=False,
        )
        self.assertTrue(res.get("ok"), res.get("error"))
        for ref, cvss in (res.get("cvss") or {}).items():
            self.assertTrue(cvss.get("estimated", True), f"{ref} should stay estimated with no active proof")


if __name__ == "__main__":
    unittest.main()
