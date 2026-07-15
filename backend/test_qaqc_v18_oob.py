"""QAQC v1.8 regression tests for the OOB (out-of-band) collaborator poll.

Two verified defects in bughunter.oob_service.poll_collaborator:

  1. A deeply-nested JSON body from the public tunnel (proxy/LB/MITM) makes json.loads raise
     RecursionError (a RuntimeError subclass, NOT a ValueError), which escaped the except tuple
     and aborted the whole OOB confirm sweep instead of degrading to {ok: False, error}.

  2. A JSON object with wrong-typed fields was not normalized: a non-int-convertible `count`
     raised outside the try, and a `count>0` with empty/non-list `hits` false-confirmed a
     blind SSRF/XXE finding with no source/UA evidence.

Each test FAILS against the pre-fix code and PASSES after. Offline/deterministic: the real
poll_collaborator is exercised against a throwaway local HTTP server; confirm-level tests stub
the poll to the exact malformed shape a sanitizing poll can still surface (count>0, hits=[]).
"""
from __future__ import annotations

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import oob_service as oob  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


class _FakeHttp:
    def __init__(self):
        self.fetched: list[str] = []

    def fetch(self, url, **kwargs):
        self.fetched.append(url)
        return {"status": 200, "headers": {}, "body": "", "cookies": [], "final_url": url, "location": None}


class PollCollaboratorMalformedBodyTests(unittest.TestCase):
    """The REAL poll against a local server: a tainted tunnel/proxy body must degrade cleanly."""

    def _serve(self, body: bytes) -> int:
        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_port

    def test_deeply_nested_body_degrades_not_recursionerror(self) -> None:
        # Finding 1: json.loads('[' * N) raises RecursionError (not a ValueError); the poll must
        # catch it and return a graceful error instead of aborting the sweep.
        port = self._serve(b"[" * 100000)
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertFalse(res["ok"])
        self.assertIn("poll failed", res["error"])

    def test_non_numeric_count_degrades_to_zero(self) -> None:
        # Finding 2: int("N/A") would raise ValueError OUTSIDE the try before the fix.
        port = self._serve(b'{"count": "N/A", "hits": []}')
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 0)

    def test_list_count_degrades_to_zero(self) -> None:
        # int([1, 2]) raises TypeError before the fix.
        port = self._serve(b'{"count": [1, 2], "hits": []}')
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 0)

    def test_non_list_hits_sanitized_to_empty(self) -> None:
        # A string hits field must become [] (not the raw string) so a confirm site can't index it.
        port = self._serve(b'{"count": 1, "hits": "garbage"}')
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["hits"], [])

    def test_non_dict_hit_entries_are_filtered(self) -> None:
        port = self._serve(b'{"count": 2, "hits": ["x", {"ip": "1.1.1.1"}]}')
        res = oob.poll_collaborator(f"http://127.0.0.1:{port}", "secret", "tok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["hits"], [{"ip": "1.1.1.1"}])


class ConfirmDoesNotFalseConfirmOnEmptyHitsTests(unittest.TestCase):
    """count>0 with empty/non-list hits (a real post-sanitization state) must not confirm."""

    def setUp(self) -> None:
        self._guard = oob._guard_url
        self._poll = oob.poll_collaborator
        self._post = oob._post_xml
        oob._guard_url = lambda u, *a, **k: u  # bypass DNS/SSRF guard in tests

    def tearDown(self) -> None:
        oob._guard_url = self._guard
        oob.poll_collaborator = self._poll
        oob._post_xml = self._post

    def _staged_empty_hits(self):
        """Pre-probe empty (negative control passes), then a malformed count>0/hits=[] body."""
        calls: dict[str, int] = {}

        def fake_poll(base, secret, token, **k):
            calls[token] = calls.get(token, 0) + 1
            if calls[token] == 1:
                return {"ok": True, "count": 0, "hits": []}
            return {"ok": True, "count": 1, "hits": []}

        return fake_poll

    def test_ssrf_count_gt_zero_empty_hits_does_not_confirm(self) -> None:
        # Before the fix `(res.get("hits") or [{}])[0]` yielded {} -> ua="" -> confirmed=True,
        # fabricating an evidence-less "confirmed" SSRF finding.
        oob.poll_collaborator = self._staged_empty_hits()
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=_FakeHttp(),
            poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "no-callback")
        self.assertNotIn("finding", res)

    def test_xxe_count_gt_zero_empty_hits_does_not_confirm(self) -> None:
        oob._post_xml = lambda url, xml, **k: {"ok": True, "status": 200}
        oob.poll_collaborator = self._staged_empty_hits()
        res = oob.confirm_blind_xxe(
            "https://app.example.com/import", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(),
            send=True, poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "no-callback")
        self.assertNotIn("finding", res)


if __name__ == "__main__":
    unittest.main()
