from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import attack_chain  # noqa: E402
from bughunter.bounty import run_bounty_hunt  # noqa: E402
from bughunter.web_ingest import WebsiteFetchError  # noqa: E402
from bughunter.web_scan_service import _analyze, _guard_url, run_web_scan  # noqa: E402


class GuardUrlIpv6Tests(unittest.TestCase):
    """_guard_url is reused by _fetch_raw, _GuardedRedirect, playwright_request_allowed,
    and recon.discover() -- a malformed sanitized URL here breaks all of them at once."""

    def test_public_ipv6_literal_keeps_its_brackets_after_sanitizing(self) -> None:
        # Regression: the netloc rebuild used the bracket-less ascii_host (urlparse().
        # hostname strips [brackets] for IPv6) directly, producing a malformed URL like
        # "http://2001:4860:4860::8888/". Re-parsing that string reads a WRONG host
        # than the one just validated as public -- every public IPv6-literal target
        # was unscannable across web_scan_service, recon, and campaign flows built on it.
        out = _guard_url("http://[2001:4860:4860::8888]/path", False, frozenset({80, 443}))
        self.assertEqual(urlparse(out).hostname, "2001:4860:4860::8888")

    def test_public_ipv6_literal_with_explicit_port_stays_well_formed(self) -> None:
        out = _guard_url("http://[2001:4860:4860::8888]:443/path", False, frozenset({80, 443}))
        self.assertEqual(urlparse(out).hostname, "2001:4860:4860::8888")
        self.assertEqual(urlparse(out).port, 443)


class CookieDemotionTests(unittest.TestCase):
    """Cookie flags are escalation signals for the attack-chain engine, never findings.

    A flag gap describes no attacker capability on its own, so reporting it standalone is
    pure queue noise. It earns a place in the report only as a step of a real chain.
    """

    FETCHED = {
        "headers": {},
        "cookies": ["session=" + ("A" * 40) + "; Path=/", "theme=dark; Path=/"],
        "body": "<html></html>",
        "final_url": "https://example.test/",
        "status": 200,
    }

    def test_no_cookie_flag_finding_is_emitted(self) -> None:
        findings = _analyze(dict(self.FETCHED))
        rule_ids = {f["rule_id"] for f in findings}
        self.assertNotIn("web.cookie-no-httponly", rule_ids)
        self.assertNotIn("web.cookie-insecure", rule_ids)
        # Nothing may sneak back in under a different id or the old category.
        self.assertFalse([f for f in findings if "cookie" in f["rule_id"].lower()])
        self.assertFalse([f for f in findings if f.get("category") == "cookies"])

    def test_flag_gap_becomes_a_chain_signal_instead(self) -> None:
        signals = attack_chain.cookie_signals(self.FETCHED["cookies"], self.FETCHED["final_url"])
        kinds = {s["kind"] for s in signals}
        self.assertIn("cookie.session-no-httponly", kinds)
        self.assertIn("cookie.session-no-samesite", kinds)
        self.assertTrue(all(s["escalation_only"] for s in signals))

    def test_only_session_looking_cookies_produce_signals(self) -> None:
        # A preference cookie without HttpOnly is not a clue about anything.
        signals = attack_chain.cookie_signals(["theme=dark; Path=/"], "https://example.test/")
        self.assertEqual(signals, [])

    def test_signal_never_carries_the_cookie_value(self) -> None:
        token = "sk-" + ("B" * 40)
        signals = attack_chain.cookie_signals([f"session={token}; Path=/"], "https://example.test/")
        self.assertTrue(signals)
        self.assertNotIn(token, json.dumps(signals))


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
                self.assertIn("proof_of_exploitability", report)
                self.assertIn("cvss", report)
                self.assertTrue(report["findings"])
                self.assertNotIn(raw_key, json.dumps(report["findings"]))
                markdown = Path(report["report_path"]).read_text(encoding="utf-8")
                json_doc = json.loads(Path(report["json_path"]).read_text(encoding="utf-8"))

            self.assertNotIn(raw_key, markdown)
            self.assertNotIn(raw_key, json.dumps(json_doc))
            self.assertIn("[REDACTED_SECRET", markdown)
            self.assertEqual("CWE-200", json_doc["findings"][0]["cwe"])
            # A Google/Firebase AIza key is a PUBLIC client key by default — strict classification
            # downgrades it and marks it INFORMATIONAL, so the deterministic proof is 'missing'
            # (a lead, not a candidate secret) and never 'ready'. It is NOT a captured artifact.
            self.assertEqual("public_client_key", json_doc["findings"][0].get("secret_classification"))
            self.assertEqual("missing", json_doc["proof_of_impact"]["F1"]["status"])
            self.assertFalse(json_doc["proof_of_impact"]["F1"]["ready"])
            # ...and the report tells the operator exactly what to capture to prove impact.
            self.assertTrue(json_doc["proof_of_impact"]["F1"]["proof_obligation"])
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
            if previous_allow is None:
                os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
            else:
                os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = previous_allow


class DirectActiveReconTests(unittest.TestCase):
    def test_active_hunt_checks_discovered_linked_endpoint(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith("/search"):
                    val = (parse_qs(urlparse(self.path).query, keep_blank_values=True).get("search") or [""])[0]
                    body = f"<html><body>{val}</body></html>".encode()
                else:
                    body = b'<html><a href="/search">Search</a></html>'
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
            lines: list[str] = []
            with tempfile.TemporaryDirectory() as tmp:
                report = run_bounty_hunt(
                    url,
                    "web-app",
                    None,
                    tmp,
                    "127.0.0.1",
                    True,
                    {},
                    active=True,
                    default_reports_dir=Path(tmp),
                    seed_dir=BACKEND_DIR / "seed",
                    runtime_dir=REPO_ROOT / "runtime",
                    on_progress=lines.append,
                )
            self.assertTrue(report["ok"], report.get("error"))
            rule_ids = {finding.get("rule_id") for finding in report["findings"]}
            self.assertIn("active.reflected-xss", rule_ids)
            xss_ref = next(finding.get("ref") for finding in report["findings"] if finding.get("rule_id") == "active.reflected-xss")
            poe = report["proof_of_exploitability"][xss_ref]
            self.assertEqual("confirmed", poe["status"])
            self.assertTrue(poe["captured"])
            self.assertIn("Captured exploit request/response", poe["text_artifact"])
            self.assertGreaterEqual(report["active_authorization"].get("targets_checked", 0), 2)
            self.assertTrue(any("active recon" in line for line in lines))
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


class TruncatedResponseTests(unittest.TestCase):
    """A server that claims a Content-Length larger than what it actually sends (or any
    mid-body connection drop) makes response.read() raise http.client.IncompleteRead --
    NOT a URLError/HTTPError/ValueError. run_web_scan's 'never raises' contract must hold."""

    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self._stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.port = self.listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve_one_truncated, daemon=True)
        self._thread.start()

    def tearDown(self) -> None:
        self._stop.set()
        self.listener.close()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def _serve_one_truncated(self) -> None:
        self.listener.settimeout(5.0)
        try:
            conn, _ = self.listener.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5.0)
            try:
                conn.recv(4096)  # drain the request
                # Chunked encoding: announce a 0x3e8 (1000)-byte chunk, send a partial
                # chunk, then close mid-chunk -> http.client.IncompleteRead on read().
                # (A plain Content-Length mismatch does NOT reliably raise -- http.client
                # just returns the short read -- chunked framing is what actually triggers it.)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"3e8\r\nshort-chunk-body-tru"
                )
            except OSError:
                pass

    def test_run_web_scan_does_not_raise_on_truncated_body(self) -> None:
        url = f"http://127.0.0.1:{self.port}/"
        res = run_web_scan(url)  # must return, never raise IncompleteRead/HTTPException
        self.assertFalse(res["ok"])
        self.assertIn("scan_type", res)
        self.assertEqual(res["scan_type"], "web")


class HttpErrorPathTests(unittest.TestCase):
    """_fetch_raw's HTTPError branch (a 4xx/5xx final response) must mirror the success
    path: close the response (it leaks a socket/fd otherwise) and re-guard the final URL
    (defence-in-depth against a redirect chain ending somewhere it shouldn't)."""

    def setUp(self) -> None:
        # Explicit + self-contained regardless of sibling test class execution order:
        # the re-guard test needs private/link-local hosts REFUSED (the default).
        self._prev = os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)

    def tearDown(self) -> None:
        if self._prev is not None:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def _fake_http_error(self, url: str, code: int = 404, body: bytes = b"not found"):
        import io
        from email.message import Message
        from urllib.error import HTTPError

        hdrs = Message()
        hdrs["Content-Type"] = "text/plain"
        return HTTPError(url, code, "Not Found", hdrs, io.BytesIO(body))

    def test_http_error_response_is_closed_not_leaked(self) -> None:
        from bughunter import web_scan_service as wss

        error = self._fake_http_error("http://8.8.8.8/missing")
        closed = {"v": False}
        orig_close = error.close

        def tracking_close():
            closed["v"] = True
            orig_close()
        error.close = tracking_close

        class FakeOpener:
            def open(self, request, timeout=None):
                raise error

        orig_opener = wss.build_opener
        wss.build_opener = lambda *a, **k: FakeOpener()
        try:
            result = wss._fetch_raw("http://8.8.8.8/x")
        finally:
            wss.build_opener = orig_opener
        self.assertEqual(result["status"], 404)
        self.assertTrue(closed["v"], "the HTTPError response was never closed -- socket/fd leak")

    def test_http_error_final_url_is_reguarded(self) -> None:
        from bughunter import web_scan_service as wss

        # error.url claims the chain ended at a link-local/metadata-endpoint host -- the
        # classic cloud-SSRF target. Even though _GuardedRedirect validates each hop, the
        # final error response itself must still be re-validated, mirroring the success path.
        error = self._fake_http_error("http://169.254.169.254/latest/meta-data/")

        class FakeOpener:
            def open(self, request, timeout=None):
                raise error

        orig_opener = wss.build_opener
        wss.build_opener = lambda *a, **k: FakeOpener()
        try:
            with self.assertRaises(WebsiteFetchError):
                wss._fetch_raw("http://8.8.8.8/x")
        finally:
            wss.build_opener = orig_opener
            error.close()


if __name__ == "__main__":
    unittest.main()
