"""Tests for the screenshot API endpoint's CAPTURE-TIME scope resolution.

The fail-closed scope binding inside screenshot_service is covered by
test_screenshot_service.py. These cover the runtime layer added so that editing a
saved program's scope (or typing a host into the cockpit Scope box) takes effect
WITHOUT re-running the hunt: the endpoint unions the cached run's scope, the LIVE
program's current scope_text, and the request's optional scope override — while
still failing closed when no source names the PoC host.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402

try:  # Real-gate ALLOW tests drive the actual service; only safe to navigate-free when absent.
    import playwright  # noqa: F401
    _PLAYWRIGHT_AVAILABLE = True
except Exception:  # noqa: BLE001
    _PLAYWRIGHT_AVAILABLE = False


def _run_result() -> dict:
    return {
        "ok": True,
        "findings": [
            {"ref": "F1", "title": "Reflected XSS", "severity": "high", "class_id": "xss",
             "class_name": "Cross-site scripting", "cwe": "CWE-79",
             "location": "https://app.example.com/?q=", "rule_id": "active.reflected-xss"},
        ],
        "attack_plans": {},
    }


class ScreenshotScopeResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        # Isolate the portfolio store so get_program reads ours, never the real one.
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.RUNTIME_DIR = Path(self._tmp.name)
        # Capture the scope the (mocked) screenshot service is actually called with.
        self._orig_capture = g.bounty_screenshot.capture_screenshot
        self.calls: list[dict] = []

        def _fake_capture(url, out_path, *, scope="", authorized=False, full_page=False, **_kw):
            self.calls.append({"url": url, "scope": scope, "authorized": authorized})
            return {"ok": True, "path": str(out_path), "url": url, "final_url": url,
                    "title": "", "bytes": 0, "warning": "review before sharing"}

        g.bounty_screenshot.capture_screenshot = _fake_capture

    def tearDown(self) -> None:
        g.bounty_screenshot.capture_screenshot = self._orig_capture
        g.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def _cache(self, *, scope: str, program: str | None) -> str:
        result = _run_result()
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope=scope, program=program)
        return result["run_id"]

    def test_live_program_scope_unioned_without_rerun(self) -> None:
        # The run was cached with a scope that does NOT name the PoC host.
        run_id = self._cache(scope="staging.example", program="acme")
        # Operator later edits + saves the program scope to add the PoC host.
        g.bounty_portfolio.upsert_program(g.RUNTIME_DIR, {
            "id": "acme", "name": "Acme", "scope_text": "app.example.com",
        })
        res = self.rt.capture_screenshot(g.ScreenshotRequest(run_id=run_id, ref="F1"))
        self.assertTrue(res["ok"])
        used = self.calls[-1]["scope"]
        # Both the frozen run scope and the freshly-edited program scope are present.
        self.assertIn("staging.example", used)
        self.assertIn("app.example.com", used)

    def test_request_scope_override_unioned(self) -> None:
        # A manual cockpit run (no program) whose frozen scope misses the PoC host.
        run_id = self._cache(scope="staging.example", program=None)
        res = self.rt.capture_screenshot(
            g.ScreenshotRequest(run_id=run_id, ref="F1", scope="app.example.com"))
        self.assertTrue(res["ok"])
        used = self.calls[-1]["scope"]
        self.assertIn("staging.example", used)
        self.assertIn("app.example.com", used)

    def test_missing_program_record_is_tolerated(self) -> None:
        # Run references a program id that no longer exists in the portfolio. With NO
        # request override, the lookup must return None and degrade to the run scope —
        # isolating "missing record tolerated" from "override works". Nothing is
        # fabricated from the absent program, and the call does not raise.
        run_id = self._cache(scope="staging.example", program="deleted-program")
        res = self.rt.capture_screenshot(g.ScreenshotRequest(run_id=run_id, ref="F1"))
        self.assertTrue(res["ok"])
        used = self.calls[-1]["scope"]
        self.assertIn("staging.example", used)       # the run scope survived the missing lookup
        self.assertNotIn("app.example.com", used)    # nothing invented from the deleted program

    def test_unknown_run_id_returns_before_capture(self) -> None:
        # An unknown run_id makes _resolve_run_finding return (None, None, None); the
        # early ctx-is-None guard returns before the scope union / capture, so the
        # service is never invoked (the '(run or {})' path is never reached with a
        # truthy run from this layer).
        res = self.rt.capture_screenshot(g.ScreenshotRequest(run_id="does-not-exist", ref="F1"))
        self.assertFalse(res["ok"])
        self.assertEqual(self.calls, [])  # capture was never called

    def test_source_text_flows_to_response_and_run(self) -> None:
        # The plain-text request/response/source proof is returned to the cockpit (for the POC
        # zip) AND recorded on the run so the engagement bundle can include the .txt.
        run_id = self._cache(scope="app.example.com", program=None)

        def _fake_text(url, out_path, *, scope="", authorized=False, full_page=False, **_kw):
            return {"ok": True, "path": str(out_path), "shots": [{"path": str(out_path), "kind": "source"}],
                    "url": url, "final_url": url, "title": "", "warning": "review",
                    "source_text": "REQUEST\nGET /me\n\nRESPONSE\nHTTP 200\n\n...leaked-secret...",
                    "source_text_path": str(out_path) + ".txt"}
        g.bounty_screenshot.capture_screenshot = _fake_text
        res = self.rt.capture_screenshot(g.ScreenshotRequest(run_id=run_id, ref="F1"))
        self.assertTrue(res["ok"])
        self.assertIn("leaked-secret", res["source_text"])
        self.assertIn("F1", self.rt.bounty_runs[run_id].get("source_texts", {}))


class ScreenshotStillFailsClosedTests(unittest.TestCase):
    """With NO source naming the PoC host, the real service still refuses — no override,
    no live program, no widening. Uses the real screenshot_service (the scope check
    returns BEFORE any browser launch or network call, so this stays offline)."""

    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.RUNTIME_DIR = Path(self._tmp.name)

    def tearDown(self) -> None:
        g.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def test_out_of_scope_fails_closed(self) -> None:
        result = _run_result()
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="other.example", program=None)
        res = self.rt.capture_screenshot(g.ScreenshotRequest(run_id=result["run_id"], ref="F1"))
        self.assertFalse(res["ok"])
        self.assertIn("scope", res["error"].lower())

    # --- ALLOW direction through the REAL gate -------------------------------------
    # These prove the union actually WIDENS enforcement end-to-end (the bug fixed): a
    # host NOT in the frozen run scope is let PAST host_in_active_scope when a live
    # program / request override names it. We assert the result is anything BUT the
    # scope refusal — offline the capture then degrades to the URL guard / Playwright-
    # missing step (no scope error). If the union were dropped, the host would be
    # refused and the error WOULD mention scope, failing the assertion. Skipped when
    # Playwright is present so a real navigation can never escape to the network.

    def _assert_passed_scope_gate(self, res: dict) -> None:
        self.assertFalse(res["ok"])  # no browser offline -> capture can't succeed
        self.assertNotIn("scope", res.get("error", "").lower())  # but it was NOT a scope refusal

    @unittest.skipIf(_PLAYWRIGHT_AVAILABLE, "real capture could navigate the network when Playwright is installed")
    def test_live_program_scope_passes_real_gate(self) -> None:
        # Frozen run scope omits the PoC host; only the freshly-edited live program names it.
        result = _run_result()
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="staging.example", program="acme")
        g.bounty_portfolio.upsert_program(g.RUNTIME_DIR, {"id": "acme", "name": "Acme", "scope_text": "app.example.com"})
        self._assert_passed_scope_gate(self.rt.capture_screenshot(g.ScreenshotRequest(run_id=result["run_id"], ref="F1")))

    @unittest.skipIf(_PLAYWRIGHT_AVAILABLE, "real capture could navigate the network when Playwright is installed")
    def test_request_override_passes_real_gate(self) -> None:
        # Manual cockpit run (no program); the host is named only via the request override.
        result = _run_result()
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="staging.example", program=None)
        self._assert_passed_scope_gate(
            self.rt.capture_screenshot(g.ScreenshotRequest(run_id=result["run_id"], ref="F1", scope="app.example.com")))

    @unittest.skipIf(_PLAYWRIGHT_AVAILABLE, "real capture could navigate the network when Playwright is installed")
    def test_run_scope_alone_passes_real_gate(self) -> None:
        # Source (1) on its own: a host named ONLY in the frozen run scope still passes.
        result = _run_result()
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="app.example.com", program=None)
        self._assert_passed_scope_gate(self.rt.capture_screenshot(g.ScreenshotRequest(run_id=result["run_id"], ref="F1")))


if __name__ == "__main__":
    unittest.main()
