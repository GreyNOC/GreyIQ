"""Tests for bughunter.triage -- had NO test coverage at all before this.

summarize_findings (incl. the not-ok/install path and the finding_count-vs-len
fallback), remote_triage (remote_enabled gating, _completions_endpoint URL
normalization, the urlopen-failure fallback to None, and successful response
parsing), _citations (severity-keyed weight + the unknown/uppercase-severity
default), and the triage() compose path.
"""
from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import triage as T  # noqa: E402


def _finding(rule_id="x", severity="high", title="T", file_path="a.py", line_start=1, snippet="", remediation=""):
    return {"rule_id": rule_id, "severity": severity, "title": title, "file_path": file_path,
            "line_start": line_start, "snippet": snippet, "remediation": remediation}


class SummarizeFindingsTests(unittest.TestCase):
    def test_not_ok_returns_error_message(self) -> None:
        out = T.summarize_findings({"ok": False, "error": "scanner unavailable"})
        self.assertIn("scanner unavailable", out)
        self.assertIn("could not complete", out)

    def test_not_ok_with_install_hint_includes_it(self) -> None:
        out = T.summarize_findings({"ok": False, "error": "missing dep", "install": "pip install x"})
        self.assertIn("pip install x", out)

    def test_no_findings_uses_recommendation(self) -> None:
        out = T.summarize_findings({"ok": True, "scan_type": "code", "target": "x", "risk": "low",
                                     "finding_count": 0, "findings": [], "recommendation": "Looks clean."})
        self.assertIn("Looks clean.", out)
        self.assertIn("0 finding(s)", out)

    def test_finding_count_falls_back_to_len_findings_when_absent(self) -> None:
        # No explicit finding_count key -> derived from len(findings).
        out = T.summarize_findings({"ok": True, "findings": [_finding(), _finding()]})
        self.assertIn("2 finding(s)", out)

    def test_explicit_finding_count_is_honored_over_len(self) -> None:
        # finding_count can legitimately differ from len(findings) (e.g. truncated list).
        out = T.summarize_findings({"ok": True, "finding_count": 50, "findings": [_finding()]})
        self.assertIn("50 finding(s)", out)

    def test_more_than_top_n_appends_remaining_count(self) -> None:
        findings = [_finding(rule_id=f"r{i}") for i in range(12)]
        out = T.summarize_findings({"ok": True, "finding_count": 12, "findings": findings})
        self.assertIn("+4 more finding(s) not shown", out)  # _TOP=8, 12-8=4


class CitationsTests(unittest.TestCase):
    def test_severity_keyed_weight(self) -> None:
        result = {"findings": [_finding(severity="critical"), _finding(severity="low")]}
        cites = T._citations(result)
        self.assertEqual(cites[0]["score"], 0.99)
        self.assertEqual(cites[1]["score"], 0.4)

    def test_unknown_severity_falls_back_to_default_weight(self) -> None:
        result = {"findings": [_finding(severity="made-up-severity")]}
        self.assertEqual(T._citations(result)[0]["score"], 0.3)

    def test_uppercase_severity_does_not_match_lowercase_keys_falls_back_to_default(self) -> None:
        # PINS the current behavior: _CITATION_WEIGHT keys are lowercase and the lookup
        # does NOT normalize case, so an uppercase severity label misses the weighting
        # table entirely and silently gets the generic 0.3 default instead of 0.85.
        result = {"findings": [_finding(severity="HIGH")]}
        self.assertEqual(T._citations(result)[0]["score"], 0.3)

    def test_limit_caps_citation_count(self) -> None:
        result = {"findings": [_finding(rule_id=f"r{i}") for i in range(10)]}
        self.assertEqual(len(T._citations(result, limit=3)), 3)


class CompletionsEndpointTests(unittest.TestCase):
    def test_bare_host_gets_full_v1_path_appended(self) -> None:
        self.assertEqual(T._completions_endpoint("http://localhost:11434"), "http://localhost:11434/v1/chat/completions")

    def test_v1_suffix_gets_chat_completions_appended(self) -> None:
        self.assertEqual(T._completions_endpoint("http://localhost:11434/v1"), "http://localhost:11434/v1/chat/completions")

    def test_full_path_is_used_verbatim(self) -> None:
        url = "http://localhost:8000/custom/v1/chat/completions"
        self.assertEqual(T._completions_endpoint(url), url)

    def test_trailing_slash_is_stripped_before_normalizing(self) -> None:
        self.assertEqual(T._completions_endpoint("http://localhost:11434/v1/"), "http://localhost:11434/v1/chat/completions")


class RemoteTriageGatingTests(unittest.TestCase):
    def test_no_config_returns_none(self) -> None:
        self.assertIsNone(T.remote_triage({"ok": True, "findings": []}, None))

    def test_remote_not_enabled_returns_none(self) -> None:
        self.assertIsNone(T.remote_triage({"ok": True}, {"remote_enabled": False, "remote_url": "http://x", "remote_model": "m"}))

    def test_missing_url_returns_none(self) -> None:
        self.assertIsNone(T.remote_triage({"ok": True}, {"remote_enabled": True, "remote_url": "", "remote_model": "m"}))

    def test_missing_model_returns_none(self) -> None:
        self.assertIsNone(T.remote_triage({"ok": True}, {"remote_enabled": True, "remote_url": "http://x", "remote_model": ""}))

    def test_urlopen_failure_falls_back_to_none(self) -> None:
        # Point at a port nothing is listening on -- urlopen raises, caught, returns None.
        cfg = {"remote_enabled": True, "remote_url": "http://127.0.0.1:1", "remote_model": "m", "remote_timeout_s": 1.0}
        self.assertIsNone(T.remote_triage({"ok": True, "findings": []}, cfg))


class _ChatCompletionsHandler(BaseHTTPRequestHandler):
    response_body = b'{"choices":[{"message":{"content":"Prioritize finding #1: SQLi"}}]}'

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.last_request = json.loads(body)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.response_body)))
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, *args: object) -> None:
        return


class RemoteTriageRealCallTests(unittest.TestCase):
    def _serve(self) -> int:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _ChatCompletionsHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_port

    def test_successful_response_returns_message_content(self) -> None:
        port = self._serve()
        cfg = {"remote_enabled": True, "remote_url": f"http://127.0.0.1:{port}", "remote_model": "m", "remote_timeout_s": 5.0}
        result = T.remote_triage({"ok": True, "findings": [_finding()]}, cfg)
        self.assertEqual(result, "Prioritize finding #1: SQLi")

    def test_empty_choices_returns_none(self) -> None:
        _ChatCompletionsHandler.response_body = b'{"choices":[]}'
        try:
            port = self._serve()
            cfg = {"remote_enabled": True, "remote_url": f"http://127.0.0.1:{port}", "remote_model": "m", "remote_timeout_s": 5.0}
            self.assertIsNone(T.remote_triage({"ok": True, "findings": []}, cfg))
        finally:
            _ChatCompletionsHandler.response_body = b'{"choices":[{"message":{"content":"Prioritize finding #1: SQLi"}}]}'


class TriageComposeTests(unittest.TestCase):
    def test_local_only_when_remote_unconfigured(self) -> None:
        out = T.triage({"ok": True, "findings": [_finding()], "finding_count": 1}, None)
        self.assertFalse(out["used_remote"])
        self.assertNotIn("---\nTriage:", out["summary"])
        self.assertEqual(len(out["citations"]), 1)

    def test_remote_skipped_entirely_when_scan_not_ok(self) -> None:
        # remote_triage is never even attempted when result['ok'] is False -- pure local
        # error message, regardless of remote_config.
        cfg = {"remote_enabled": True, "remote_url": "http://127.0.0.1:1", "remote_model": "m"}
        out = T.triage({"ok": False, "error": "boom"}, cfg)
        self.assertFalse(out["used_remote"])
        self.assertIn("boom", out["summary"])

    def test_remote_success_is_appended_to_local_summary(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _ChatCompletionsHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        cfg = {"remote_enabled": True, "remote_url": f"http://127.0.0.1:{server.server_port}", "remote_model": "m", "remote_timeout_s": 5.0}
        out = T.triage({"ok": True, "findings": [_finding()], "finding_count": 1}, cfg)
        self.assertTrue(out["used_remote"])
        self.assertIn("---\nTriage:", out["summary"])
        self.assertIn("Prioritize finding #1: SQLi", out["summary"])


if __name__ == "__main__":
    unittest.main()
