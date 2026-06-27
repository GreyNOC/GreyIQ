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
from bughunter.web_scan_service import _analyze, run_web_scan  # noqa: E402


class WebProofEvidenceTests(unittest.TestCase):
    def test_cookie_finding_carries_redacted_proof_evidence(self) -> None:
        token = "sk-" + ("A" * 40)
        fetched = {
            "headers": {},
            "cookies": [f"session={token}; Path=/"],
            "body": "<html></html>",
            "final_url": "https://example.test/",
            "status": 200,
        }
        findings = _analyze(fetched)
        cookie = next(f for f in findings if f["rule_id"] == "web.cookie-no-httponly")
        proof = cookie.get("proof_evidence") or {}
        self.assertEqual(proof.get("request_line"), "GET https://example.test/")
        self.assertEqual(proof.get("response_status"), "HTTP 200")
        # The Set-Cookie is carried as proof — but its token is redacted.
        self.assertIn("set_cookie", proof)
        self.assertNotIn(token, json.dumps(cookie))


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
                # The run result now carries structured per-finding data for a GUI
                # (mirrors the on-disk sidecar; redacted) — not just counts + markdown.
                self.assertIn("findings", report)
                self.assertIn("proof_of_impact", report)
                self.assertIn("cvss", report)
                self.assertTrue(report["findings"])
                self.assertNotIn(raw_key, json.dumps(report["findings"]))
                markdown = Path(report["report_path"]).read_text(encoding="utf-8")
                json_doc = json.loads(Path(report["json_path"]).read_text(encoding="utf-8"))

            self.assertNotIn(raw_key, markdown)
            self.assertNotIn(raw_key, json.dumps(json_doc))
            self.assertIn("[REDACTED_SECRET", markdown)
            self.assertEqual("CWE-200", json_doc["findings"][0]["cwe"])
            # An exposed secret IS a captured artifact, so the deterministic proof is
            # a 'candidate' (exposure shown) — not 'missing' — but never 'ready'
            # (a static scan hasn't proven the key is live/impactful).
            self.assertEqual("candidate", json_doc["proof_of_impact"]["F1"]["status"])
            self.assertFalse(json_doc["proof_of_impact"]["F1"]["ready"])
            # ...and the report tells the operator exactly what to capture to prove it.
            self.assertTrue(json_doc["proof_of_impact"]["F1"]["proof_obligation"])
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
            if previous_allow is None:
                os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
            else:
                os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = previous_allow


class SensitivePathProbeTests(unittest.TestCase):
    """The probe must flag a real exposed artifact but never an SPA's 200-HTML shell."""

    def _serve(self, handler_cls: type[BaseHTTPRequestHandler]):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        return server

    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def test_real_git_config_flagged_spa_env_not(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/.git/config":
                    body = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                    ctype = "text/plain"
                else:  # an SPA returns its HTML shell (200) for every unknown path
                    body = b"<!doctype html><html><body>app</body></html>"
                    ctype = "text/html"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                return

        server = self._serve(Handler)
        url = f"http://127.0.0.1:{server.server_port}/"
        scan = run_web_scan(url, probe_paths=True)
        self.assertTrue(scan["ok"])
        rule_ids = {f["rule_id"] for f in scan["findings"]}
        self.assertIn("web.exposed-path.git-config", rule_ids)   # real artifact -> flagged
        self.assertNotIn("web.exposed-path.env", rule_ids)        # SPA 200-HTML -> not flagged

    def test_probe_off_by_default_makes_no_extra_requests(self) -> None:
        seen: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen.append(self.path)
                body = b"<!doctype html><html>app</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                return

        server = self._serve(Handler)
        url = f"http://127.0.0.1:{server.server_port}/"
        run_web_scan(url)  # probe_paths defaults to False -> a single GET
        self.assertEqual(seen, ["/"])


if __name__ == "__main__":
    unittest.main()
