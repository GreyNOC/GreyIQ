"""Tests for greyiq_api's request-body parsing, payload validation, and the cached
run-state locking around concurrent /api/* calls.

read_json_body / validate_payload had no dedicated tests at all -- both are now covered:
an invalid-UTF-8 body must produce a clean 400 (not an unhandled 500), and a pydantic
validation error must never reflect the submitted values back to the client.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import threading
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402


def _receive_once(body: bytes):
    sent = {"v": False}

    async def receive():
        if sent["v"]:
            return {"type": "http.disconnect"}
        sent["v"] = True
        return {"type": "http.request", "body": body, "more_body": False}
    return receive


class ReadJsonBodyTests(unittest.TestCase):
    def test_valid_json_parses(self) -> None:
        result = asyncio.run(g.read_json_body(_receive_once(b'{"a": 1}')))
        self.assertEqual(result, {"a": 1})

    def test_empty_body_returns_empty_dict(self) -> None:
        result = asyncio.run(g.read_json_body(_receive_once(b"")))
        self.assertEqual(result, {})

    def test_malformed_json_raises_400(self) -> None:
        with self.assertRaises(g.HTTPError) as ctx:
            asyncio.run(g.read_json_body(_receive_once(b"{not json")))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_invalid_utf8_body_raises_400_not_500(self) -> None:
        # Before the fix, UnicodeDecodeError (a ValueError, but NOT a json.JSONDecodeError)
        # escaped read_json_body entirely and surfaced as a generic 500 to the client.
        with self.assertRaises(g.HTTPError) as ctx:
            asyncio.run(g.read_json_body(_receive_once(b"\xff\xfe{")))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_non_object_json_raises_422(self) -> None:
        with self.assertRaises(g.HTTPError) as ctx:
            asyncio.run(g.read_json_body(_receive_once(b"[1, 2, 3]")))
        self.assertEqual(ctx.exception.status_code, 422)

    def test_oversized_body_raises_413(self) -> None:
        orig = g.MAX_REQUEST_BYTES
        g.MAX_REQUEST_BYTES = 10
        try:
            with self.assertRaises(g.HTTPError) as ctx:
                asyncio.run(g.read_json_body(_receive_once(b'{"a": "way too long for the cap"}')))
            self.assertEqual(ctx.exception.status_code, 413)
        finally:
            g.MAX_REQUEST_BYTES = orig


class ValidatePayloadTests(unittest.TestCase):
    def test_valid_payload_passes(self) -> None:
        req = g.validate_payload(g.ScreenshotRequest, {"run_id": "r1", "ref": "F1"})
        self.assertEqual(req.run_id, "r1")

    def test_invalid_payload_raises_422_with_field_name_not_value(self) -> None:
        # run_id has min_length=1 -- an empty string fails validation. The 422 detail
        # must name the field but NEVER echo the submitted value back to the client.
        secret_value = "TOP-SECRET-MARKER-XYZ"
        with self.assertRaises(g.HTTPError) as ctx:
            g.validate_payload(g.ScreenshotRequest, {"run_id": "", "ref": secret_value * 3})
        self.assertEqual(ctx.exception.status_code, 422)
        detail = str(ctx.exception.detail)
        self.assertIn("run_id", detail)            # names the failing field
        self.assertNotIn(secret_value, detail)      # never echoes a submitted value
        self.assertNotIn("pydantic.dev", detail)     # never leaks pydantic's internal error-doc URL

    def test_missing_required_field_message_is_safe(self) -> None:
        with self.assertRaises(g.HTTPError) as ctx:
            g.validate_payload(g.ScreenshotRequest, {})
        detail = str(ctx.exception.detail)
        self.assertIn("run_id", detail)
        self.assertIn("ref", detail)


class ConcurrentRunMutationTests(unittest.TestCase):
    """Two /api/* calls against the SAME run_id+ref (e.g. screenshot + research) run on
    different asyncio.to_thread worker threads and mutate the same cached finding/run
    dicts -- this must not corrupt the run cache under concurrent access."""

    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.RUNTIME_DIR = Path(self._tmp.name)

    def tearDown(self) -> None:
        g.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def test_concurrent_screenshot_and_research_do_not_corrupt_run_state(self) -> None:
        result = {
            "ok": True,
            "findings": [{"ref": f"F{i}", "title": f"Finding {i}", "severity": "low",
                          "class_id": "x", "rule_id": "x"} for i in range(20)],
            "attack_plans": {},
        }
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="app.example.com", program=None)
        run_id = result["run_id"]

        # Monkeypatch the heavy I/O each handler does so this stays a pure concurrency
        # test of the shared-dict mutation, not a real screenshot/brain call.
        orig_capture = g.bounty_screenshot.capture_screenshot
        orig_dossier = g.bounty_research.build_dossier
        g.bounty_screenshot.capture_screenshot = lambda *a, **k: {"ok": True, "path": "/x.png", "url": "x", "warning": ""}
        g.bounty_research.build_dossier = lambda finding, ctx, cfg: {"markdown": "# x", "used_brain": False, "model": ""}
        try:
            errors: list[Exception] = []

            def worker(ref: str) -> None:
                try:
                    self.rt.capture_screenshot(g.ScreenshotRequest(run_id=run_id, ref=ref))
                    self.rt.research_finding(g.ResearchRequest(run_id=run_id, ref=ref))
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(f"F{i}",)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            self.assertEqual(errors, [])
            run = self.rt.bounty_runs[run_id]
            self.assertEqual(len(run.get("screenshots", {})), 20)
            self.assertEqual(len(run.get("research_paths", {})), 20)
        finally:
            g.bounty_screenshot.capture_screenshot = orig_capture
            g.bounty_research.build_dossier = orig_dossier


if __name__ == "__main__":
    unittest.main()
