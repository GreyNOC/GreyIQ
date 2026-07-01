"""Tests for the Playwright-driven dynamic live-app scan -- had NO dedicated
coverage before this. The real ``playwright`` package is not installed in this dev
environment (nor assumed on a user machine without the opt-in install), so:
  - the pre-Playwright guard gates (empty URL, SSRF guard, not-installed fallback)
    are exercised directly, with no mocking, since they run before the optional
    import is even attempted;
  - the browser-driving path (console/pageerror/requestfailed/response capture,
    the per-request SSRF route guard, capture-cap overflow) is exercised via a
    minimal fake ``playwright.sync_api`` module injected into ``sys.modules`` --
    this drives run_live_scan's real code, not a re-implementation of it.
"""
from __future__ import annotations

import sys
import types
import unittest
from unittest import mock

from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import live_scan_service as LS  # noqa: E402
from bughunter.settings import ScannerSettings  # noqa: E402


class RiskBandTests(unittest.TestCase):
    """_risk()'s severity-weighted scoring bands."""

    def _f(self, severity: str) -> dict:
        return {"severity": severity}

    def test_no_findings_is_clean(self) -> None:
        risk, score = LS._risk([])
        self.assertEqual(risk, "clean")
        self.assertEqual(score, 0.0)

    def test_only_info_is_low(self) -> None:
        risk, score = LS._risk([self._f("info"), self._f("info")])
        self.assertEqual(risk, "low")
        self.assertLess(score, 0.2)

    def test_single_low_severity_finding_is_low(self) -> None:
        risk, score = LS._risk([self._f("low")])
        self.assertEqual(risk, "low")
        self.assertAlmostEqual(score, 0.06)

    def test_medium_present_is_moderate_even_below_score_threshold(self) -> None:
        risk, score = LS._risk([self._f("medium")])
        self.assertEqual(risk, "moderate")
        self.assertAlmostEqual(score, 0.18)

    def test_score_crossing_0_2_without_medium_is_moderate(self) -> None:
        # 4 lows = 0.24 >= 0.2, no medium/high/critical present.
        risk, score = LS._risk([self._f("low")] * 4)
        self.assertEqual(risk, "moderate")
        self.assertGreaterEqual(score, 0.2)

    def test_high_present_is_high_even_below_score_threshold(self) -> None:
        risk, score = LS._risk([self._f("high")])
        self.assertEqual(risk, "high")
        self.assertAlmostEqual(score, 0.32)

    def test_critical_present_is_high(self) -> None:
        risk, score = LS._risk([self._f("critical")])
        self.assertEqual(risk, "high")

    def test_score_crossing_0_5_without_high_or_critical_is_high(self) -> None:
        # 3 mediums = 0.54 >= 0.5, no high/critical present.
        risk, score = LS._risk([self._f("medium")] * 3)
        self.assertEqual(risk, "high")
        self.assertGreaterEqual(score, 0.5)

    def test_score_is_capped_at_1_0(self) -> None:
        risk, score = LS._risk([self._f("critical")] * 10)
        self.assertEqual(risk, "high")
        self.assertEqual(score, 1.0)

    def test_unknown_severity_contributes_zero_weight(self) -> None:
        risk, score = LS._risk([self._f("nonsense")])
        self.assertEqual(risk, "low")  # non-empty findings, but zero-weighted -> "low" branch
        self.assertEqual(score, 0.0)


class FindingBuilderTests(unittest.TestCase):
    def test_snippet_is_clipped_to_240_chars(self) -> None:
        f = LS._finding("live.js-exception", "Uncaught JavaScript exception", "high", "high", "https://x/", "a" * 500)
        self.assertEqual(len(f["snippet"]), 240)

    def test_secret_in_snippet_is_redacted(self) -> None:
        f = LS._finding("live.console-error", "Console error", "medium", "medium", "https://x/",
                         "AKIAABCDEFGHIJKLMNOP leaked in console")
        self.assertTrue(f["redacted"])
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", f["snippet"])

    def test_core_fields_carried_through(self) -> None:
        f = LS._finding("live.bad-status", "Sub-resource returned HTTP 500", "medium", "high", "https://x/a", "https://x/a")
        self.assertEqual(f["file_path"], "https://x/a")
        self.assertEqual(f["category"], "runtime")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["confidence"], "high")


class NotInstalledShapeTests(unittest.TestCase):
    def test_shape(self) -> None:
        result = LS._not_installed("https://example.com/")
        self.assertFalse(result["ok"])
        self.assertFalse(result["available"])
        self.assertEqual(result["scan_type"], "live")
        self.assertIn("install", result)


class RunLiveScanGuardGateTests(unittest.TestCase):
    """The URL-validation / SSRF-guard gate runs BEFORE the optional playwright
    import, so it's exercised directly without any mocking."""

    def test_empty_url_is_rejected(self) -> None:
        result = LS.run_live_scan("")
        self.assertFalse(result["ok"])
        self.assertIn("No URL provided", result["error"])

    def test_private_host_is_refused_by_default(self) -> None:
        # Explicitly force the default (allow_private_urls=False) rather than relying
        # on the ambient GREYIQ_SCAN_ALLOW_PRIVATE_URLS env var: other test modules
        # (e.g. test_access_control.py) set it at import time with no teardown, so in
        # a full-suite run the real get_settings() can't be trusted to reflect "off".
        with mock.patch.object(LS, "get_settings", return_value=ScannerSettings(allow_private_urls=False)):
            result = LS.run_live_scan("http://127.0.0.1:9999/")
        self.assertFalse(result["ok"])
        self.assertIn("Private", result["error"])

    def test_disallowed_scheme_is_refused(self) -> None:
        result = LS.run_live_scan("ftp://example.com/")
        self.assertFalse(result["ok"])

    def test_playwright_not_installed_returns_structured_result(self) -> None:
        # playwright genuinely isn't installed in this environment -- this exercises
        # the real ImportError-handling branch, not a simulation of it.
        with mock.patch.object(LS, "get_settings", return_value=ScannerSettings(allow_private_urls=True)):
            result = LS.run_live_scan("http://127.0.0.1:9999/")
        self.assertFalse(result["ok"])
        self.assertFalse(result["available"])
        self.assertIn("install", result)


# --- A minimal fake playwright.sync_api, just enough surface for run_live_scan's
# usage, to drive the real event-handler / route-guard / risk-scoring code without a
# real browser. ---

class _FakeRoute:
    def __init__(self, request: "_FakeRequest") -> None:
        self.request = request
        self.outcome: str | None = None

    def continue_(self) -> None:
        self.outcome = "continue"

    def abort(self) -> None:
        self.outcome = "abort"


class _FakeRequest:
    def __init__(self, url: str) -> None:
        self.url = url


class _FakeConsoleMessage:
    def __init__(self, type_: str, text: str) -> None:
        self.type = type_
        self.text = text


class _FakeFailedRequest:
    def __init__(self, url: str, failure: str) -> None:
        self.url = url
        self.failure = failure


class _FakeResponse:
    def __init__(self, url: str, status: int) -> None:
        self.url = url
        self.status = status


class _FakeContext:
    def __init__(self, *, final_url: str = "https://example.com/", title: str = "Example",
                 console=(), page_errors=(), requestfailed=(), bad_responses=(),
                 route_requests=(), goto_exception: Exception | None = None) -> None:
        self.route_handler = None
        self.route_calls: list[tuple[str, str | None]] = []
        self.final_url = final_url
        self.title = title
        self.console = console
        self.page_errors = page_errors
        self.requestfailed = requestfailed
        self.bad_responses = bad_responses
        self.route_requests = route_requests
        self.goto_exception = goto_exception
        self.closed = False

    def route(self, pattern: str, handler) -> None:
        self.route_handler = handler

    def new_page(self) -> "_FakePage":
        return _FakePage(self)

    def close(self) -> None:
        self.closed = True


class _FakePage:
    def __init__(self, context: _FakeContext) -> None:
        self.context = context
        self.url = context.final_url
        self._handlers: dict[str, object] = {}

    def on(self, event: str, handler) -> None:
        self._handlers[event] = handler

    def goto(self, url: str, wait_until=None, timeout=None) -> None:
        ctx = self.context
        if ctx.goto_exception is not None:
            raise ctx.goto_exception
        for req_url in ctx.route_requests:
            route = _FakeRoute(_FakeRequest(req_url))
            ctx.route_handler(route)
            ctx.route_calls.append((req_url, route.outcome))
        for type_, text in ctx.console:
            self._handlers["console"](_FakeConsoleMessage(type_, text))
        for err in ctx.page_errors:
            self._handlers["pageerror"](err)
        for req_url, failure in ctx.requestfailed:
            self._handlers["requestfailed"](_FakeFailedRequest(req_url, failure))
        for res_url, status in ctx.bad_responses:
            self._handlers["response"](_FakeResponse(res_url, status))

    def wait_for_timeout(self, ms) -> None:
        pass

    def title(self) -> str:
        return self.context.title


class _FakeBrowser:
    def __init__(self, context: _FakeContext) -> None:
        self.context = context
        self.closed = False

    def new_context(self, ignore_https_errors=None) -> _FakeContext:
        return self.context

    def close(self) -> None:
        self.closed = True


class _FakeChromium:
    def __init__(self, context: _FakeContext) -> None:
        self.context = context

    def launch(self, headless=None) -> _FakeBrowser:
        return _FakeBrowser(self.context)


class _FakePlaywrightCM:
    def __init__(self, context: _FakeContext) -> None:
        self.chromium = _FakeChromium(context)

    def __enter__(self) -> "_FakePlaywrightCM":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _fake_playwright_modules(context: _FakeContext) -> dict[str, types.ModuleType]:
    def sync_playwright() -> _FakePlaywrightCM:
        return _FakePlaywrightCM(context)

    sync_api_mod = types.ModuleType("playwright.sync_api")
    sync_api_mod.sync_playwright = sync_playwright  # type: ignore[attr-defined]
    playwright_mod = types.ModuleType("playwright")
    playwright_mod.sync_api = sync_api_mod  # type: ignore[attr-defined]
    return {"playwright": playwright_mod, "playwright.sync_api": sync_api_mod}


class RunLiveScanDrivenTests(unittest.TestCase):
    """Drives run_live_scan's real browser-event-handling code via a fake
    playwright.sync_api injected into sys.modules."""

    def _run(self, context: _FakeContext, url: str = "https://example.com/"):
        modules = _fake_playwright_modules(context)
        with mock.patch.object(LS, "get_settings", return_value=ScannerSettings()):
            with mock.patch.dict(sys.modules, modules):
                return LS.run_live_scan(url, wait_seconds=0.0)

    def test_clean_run_no_findings(self) -> None:
        result = self._run(_FakeContext())
        self.assertTrue(result["ok"])
        self.assertEqual(result["risk"], "clean")
        self.assertEqual(result["finding_count"], 0)

    def test_page_error_console_and_bad_response_are_captured_and_ranked(self) -> None:
        ctx = _FakeContext(
            page_errors=["TypeError: x is not a function"],
            console=[("error", "console boom"), ("warning", "console warn")],
            requestfailed=[("https://example.com/api", "net::ERR_CONNECTION_REFUSED")],
            bad_responses=[("https://example.com/img.png", 404), ("https://example.com/api2", 503)],
        )
        result = self._run(ctx)
        self.assertTrue(result["ok"])
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("live.js-exception", rule_ids)
        self.assertIn("live.console-error", rule_ids)
        self.assertIn("live.console-warning", rule_ids)
        self.assertIn("live.request-failed", rule_ids)
        self.assertIn("live.bad-status", rule_ids)
        # 500-class bad response is medium, 400-class is low
        status_findings = [f for f in result["findings"] if f["rule_id"] == "live.bad-status"]
        sev_404 = next(f["severity"] for f in status_findings if "img.png" in f["snippet"])
        sev_503 = next(f["severity"] for f in status_findings if "api2" in f["snippet"])
        self.assertEqual(sev_404, "low")
        self.assertEqual(sev_503, "medium")
        # sorted by severity rank descending -> the js-exception (high) leads
        self.assertEqual(result["findings"][0]["rule_id"], "live.js-exception")
        self.assertEqual(result["counts"]["page_errors"], 1)
        self.assertEqual(result["counts"]["console_errors"], 1)
        self.assertEqual(result["counts"]["console_warnings"], 1)
        self.assertEqual(result["counts"]["failed_requests"], 1)
        self.assertEqual(result["counts"]["bad_responses"], 2)
        self.assertFalse(result["counts"]["capture_capped"])

    def test_capture_cap_overflow_is_flagged_and_bounded(self) -> None:
        with mock.patch.object(LS, "_CAPTURE_CAP", 3):
            ctx = _FakeContext(page_errors=[f"err-{i}" for i in range(10)])
            result = self._run(ctx)
        self.assertTrue(result["ok"])
        self.assertEqual(result["counts"]["page_errors"], 3)  # capped, not 10
        self.assertTrue(result["counts"]["capture_capped"])

    def test_route_guard_allows_public_and_blocks_private_sub_resource(self) -> None:
        ctx = _FakeContext(route_requests=["https://example.com/ok.js", "http://127.0.0.1/evil.js"])
        self._run(ctx)
        outcomes = dict(ctx.route_calls)
        self.assertEqual(outcomes["https://example.com/ok.js"], "continue")
        self.assertEqual(outcomes["http://127.0.0.1/evil.js"], "abort")

    def test_navigation_exception_returns_structured_error_not_a_crash(self) -> None:
        ctx = _FakeContext(goto_exception=TimeoutError("Navigation timeout of 15000ms exceeded"))
        result = self._run(ctx)
        self.assertFalse(result["ok"])
        self.assertIn("TimeoutError", result["error"])

    def test_final_url_and_title_reflect_post_navigation_state(self) -> None:
        ctx = _FakeContext(final_url="https://example.com/redirected", title="Landed Here")
        result = self._run(ctx)
        self.assertEqual(result["final_url"], "https://example.com/redirected")
        self.assertEqual(result["title"], "Landed Here")

    def test_max_findings_truncates_but_finding_count_reflects_the_true_total(self) -> None:
        ctx = _FakeContext(page_errors=[f"err-{i}" for i in range(5)])
        modules = _fake_playwright_modules(ctx)
        with mock.patch.object(LS, "get_settings", return_value=ScannerSettings()):
            with mock.patch.dict(sys.modules, modules):
                result = LS.run_live_scan("https://example.com/", wait_seconds=0.0, max_findings=2)
        self.assertEqual(result["finding_count"], 5)
        self.assertEqual(len(result["findings"]), 2)


if __name__ == "__main__":
    unittest.main()
