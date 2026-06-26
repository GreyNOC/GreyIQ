from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.bounty import run_bounty_hunt  # noqa: E402
from bughunter.web_scan_service import run_web_scan  # noqa: E402


class WebScanRedactionTests(unittest.TestCase):
    def test_web_secret_findings_are_redacted_before_reporting(self) -> None:
        raw_key = "AIza" + ("A" * 35)
        body = f'<html><script>window.GOOGLE_API_KEY="{raw_key}";</script></html>'.encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        previous_allow = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            scan = run_web_scan(url)

            self.assertTrue(scan["ok"])
            secret_findings = [
                finding
                for finding in scan["findings"]
                if finding["rule_id"] == "web.exposed.secret.google-api-key"
            ]
            self.assertEqual(1, len(secret_findings))
            self.assertTrue(secret_findings[0].get("redacted"))
            self.assertNotIn(raw_key, json.dumps(secret_findings))
            self.assertIn("[REDACTED_SECRET", secret_findings[0]["snippet"])

            with tempfile.TemporaryDirectory() as tmp:
                report = run_bounty_hunt(
                    url,
                    "web-app",
                    "secrets",
                    tmp,
                    "local QA fixture",
                    True,
                    {},
                    default_reports_dir=Path(tmp),
                    seed_dir=BACKEND_DIR / "seed",
                    runtime_dir=REPO_ROOT / "runtime",
                )
                self.assertTrue(report["ok"])
                markdown = Path(report["report_path"]).read_text(encoding="utf-8")
                json_doc = json.loads(Path(report["json_path"]).read_text(encoding="utf-8"))

            self.assertNotIn(raw_key, markdown)
            self.assertNotIn(raw_key, json.dumps(json_doc))
            self.assertIn("[REDACTED_SECRET", markdown)
            self.assertEqual("CWE-200", json_doc["findings"][0]["cwe"])
            self.assertEqual("missing", json_doc["proof_of_impact"]["F1"]["status"])
            self.assertFalse(json_doc["proof_of_impact"]["F1"]["ready"])
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
            if previous_allow is None:
                os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
            else:
                os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = previous_allow


if __name__ == "__main__":
    unittest.main()
