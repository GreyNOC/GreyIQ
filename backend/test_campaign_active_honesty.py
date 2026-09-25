"""Regression test: deep mode must not silently fire active probing (incl. the opt-in
time-based SQLi SLEEP) while the campaign report claims 'active: off'.

Before the fix, run_campaign(active=False, deep=True) passed time_based=(time_based or
deep) into the per-target hunt -- enabling the active pass via bounty.py's
`(active or time_based)` check -- but recorded ctx_meta['active']=active (False), so the
report lied about whether an executing probe ran. The fix derives one honest
`effective_active = active or time_based or deep` and uses it both for the per-target run
and for the report.
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

from bughunter import campaign, rate_limit  # noqa: E402


def setUpModule() -> None:
    """Start from a full per-host active-request budget — see rate_limit.reset_shared_governors().

    Especially load-bearing here: this module asserts the campaign is HONEST about what the active
    pass did, and it runs alphabetically after test_bounty_progress has spent 573 of the shared
    bucket's 700 tokens. Inheriting that drained bucket throttles this module's own probes, so it
    would be checking honesty about a pass that never really ran.
    """
    rate_limit.reset_shared_governors()


class _Handler(BaseHTTPRequestHandler):
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


class CampaignActiveHonestyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev
        self._tmp.cleanup()

    def test_deep_without_active_still_records_active_true(self) -> None:
        url = f"http://127.0.0.1:{self.port}/?q=x"
        out = Path(self._tmp.name) / "reports"
        res = campaign.run_campaign(
            url, scope="127.0.0.1", authorized=True, coder_cfg=None,
            default_reports_dir=out, runtime_dir=Path(self._tmp.name),
            active=False, time_based=False, deep=True,
        )
        self.assertTrue(res.get("ok"), res.get("error"))
        doc = json.loads(Path(res["json_path"]).read_text(encoding="utf-8"))
        # The report must NOT claim active was off when deep mode forced the active pass on.
        self.assertTrue(doc["active"])
        # And the active pass genuinely ran (not just the report flag) — the reflected-XSS
        # probe against this fixture confirms with rule_id 'active.reflected-xss'.
        rule_ids = {f.get("rule_id") for f in res.get("findings", [])}
        self.assertTrue(any(str(r or "").startswith("active.") for r in rule_ids), rule_ids)

    def test_active_false_time_based_false_deep_false_stays_honestly_off(self) -> None:
        url = f"http://127.0.0.1:{self.port}/?q=x"
        out = Path(self._tmp.name) / "reports2"
        res = campaign.run_campaign(
            url, scope="127.0.0.1", authorized=True, coder_cfg=None,
            default_reports_dir=out, runtime_dir=Path(self._tmp.name),
            active=False, time_based=False, deep=False,
        )
        self.assertTrue(res.get("ok"), res.get("error"))
        doc = json.loads(Path(res["json_path"]).read_text(encoding="utf-8"))
        self.assertFalse(doc["active"])  # no flag implies it -> stays honestly off


if __name__ == "__main__":
    unittest.main()
