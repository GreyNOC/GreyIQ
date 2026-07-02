"""Tests for opt-in screenshot (visual evidence) capture.

The Playwright capture itself needs a browser, so these cover the parts that must hold
WITHOUT a browser: the PoC-URL extraction, the fail-closed gating (not authorized / out
of scope make ZERO network calls and never launch a browser), the report embedding of a
captured screenshot, and the submission package co-locating the PNG next to the .md.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import playwright_env as pe  # noqa: E402
from bughunter import report_formats as rf  # noqa: E402
from bughunter import screenshot_service as ss  # noqa: E402
from bughunter import submission as sub  # noqa: E402


class PocUrlTests(unittest.TestCase):
    def test_prefers_captured_request_line(self) -> None:
        f = {"proof_evidence": {"request_line": "GET https://app.example.com/?q=<svg/onload=1>"},
             "location": "https://app.example.com/other"}
        self.assertEqual(ss.poc_url_for_finding(f), "https://app.example.com/?q=<svg/onload=1>")

    def test_falls_back_to_location_then_target(self) -> None:
        self.assertEqual(ss.poc_url_for_finding({"location": "https://h/x"}), "https://h/x")
        self.assertEqual(ss.poc_url_for_finding({}, {"target": "https://h/"}), "https://h/")
        self.assertEqual(ss.poc_url_for_finding({"location": "/relative/path"}, {"target": "nota url"}), "")


class CaptureGatingTests(unittest.TestCase):
    """The gate must fail closed BEFORE any browser launch or network call."""

    def test_refuses_without_authorization(self) -> None:
        r = ss.capture_screenshot("https://app.example.com/", "/tmp/x.png", scope="app.example.com", authorized=False)
        self.assertFalse(r["ok"])
        self.assertIn("authorized", r["error"].lower())

    def test_refuses_empty_url(self) -> None:
        self.assertFalse(ss.capture_screenshot("", "/tmp/x.png", authorized=True)["ok"])

    def test_out_of_scope_host_is_skipped_fail_closed(self) -> None:
        # Host not named in scope -> refused via the no-DNS token check (no browser, no net).
        r = ss.capture_screenshot("https://evil.example/", "/tmp/x.png", scope="other.example", authorized=True)
        self.assertFalse(r["ok"])
        self.assertIn("scope", r["error"].lower())

    def test_not_installed_shape(self) -> None:
        r = ss._not_installed("https://h/")
        self.assertFalse(r["ok"])
        self.assertFalse(r["available"])
        self.assertIn("playwright", r["install"].lower())


class FrozenBrowserPathTests(unittest.TestCase):
    """The release build ships Chromium under <bundle>/playwright-browsers; the runtime must
    point PLAYWRIGHT_BROWSERS_PATH at it (an end-user machine has no ms-playwright cache).
    Must be a no-op in dev, when unset-but-absent, and when the operator set it themselves."""

    def setUp(self) -> None:
        self._prev_env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
        self._prev_meipass = getattr(sys, "_MEIPASS", None)
        self._prev_frozen = getattr(sys, "frozen", None)
        os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)

    def tearDown(self) -> None:
        if self._prev_env is None:
            os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)
        else:
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = self._prev_env
        if self._prev_meipass is None:
            if hasattr(sys, "_MEIPASS"):
                del sys._MEIPASS
        else:
            sys._MEIPASS = self._prev_meipass
        if self._prev_frozen is None:
            if hasattr(sys, "frozen"):
                del sys.frozen
        else:
            sys.frozen = self._prev_frozen

    def test_noop_in_dev(self) -> None:
        # Not frozen, no _MEIPASS -> nothing set.
        if hasattr(sys, "_MEIPASS"):
            del sys._MEIPASS
        if hasattr(sys, "frozen"):
            del sys.frozen
        pe.ensure_bundled_browsers_path()
        self.assertNotIn("PLAYWRIGHT_BROWSERS_PATH", os.environ)

    def test_sets_path_when_bundled_dir_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "playwright-browsers").mkdir()
            sys._MEIPASS = td
            pe.ensure_bundled_browsers_path()
            self.assertEqual(os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), os.path.join(td, "playwright-browsers"))

    def test_noop_when_bundled_dir_absent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sys._MEIPASS = td  # frozen root exists but no playwright-browsers inside it
            pe.ensure_bundled_browsers_path()
            self.assertNotIn("PLAYWRIGHT_BROWSERS_PATH", os.environ)

    def test_respects_operator_set_value(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "playwright-browsers").mkdir()
            sys._MEIPASS = td
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "/operator/choice"
            pe.ensure_bundled_browsers_path()
            self.assertEqual(os.environ["PLAYWRIGHT_BROWSERS_PATH"], "/operator/choice")  # left untouched


class EmbeddingTests(unittest.TestCase):
    def _ctx_finding(self):
        ctx = {"target": "https://app.example.com/", "generated_at": "now", "tool": "GreyIQ", "version": "0.28.0", "attack_plans": {}}
        finding = {"ref": "F1", "title": "Reflected XSS", "severity": "high", "confidence": "high",
                   "class_name": "XSS", "cwe": "CWE-79", "location": "https://app.example.com/?q="}
        return ctx, finding

    def test_screenshot_embedded_in_every_platform_when_present(self) -> None:
        ctx, finding = self._ctx_finding()
        finding["screenshot_path"] = "/runtime/screenshots/run-F1.png"
        for p in ("hackerone", "yeswehack", "bugcrowd", "intigriti"):
            md = rf.render_finding(ctx, finding, p)
            self.assertIn("Screenshot evidence", md, p)
            self.assertIn("![Proof-of-concept screenshot](run-F1.png)", md, p)   # referenced by basename
            self.assertIn("NOT auto-redacted", md, p)                            # the caveat travels with it

    def test_no_screenshot_section_when_absent(self) -> None:
        ctx, finding = self._ctx_finding()
        self.assertNotIn("Screenshot evidence", rf.render_finding(ctx, finding, "hackerone"))

    def test_submission_package_colocates_the_png(self) -> None:
        import tempfile
        ctx, finding = self._ctx_finding()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            png = tdp / "src" / "run-F1.png"
            png.parent.mkdir(parents=True)
            png.write_bytes(b"\x89PNG\r\n\x1a\nFAKE")  # not a real PNG; copy is byte-wise
            finding["screenshot_path"] = str(png)
            out = tdp / "pkg"
            out.mkdir()
            pkg = sub.write_submission_package(ctx, finding, out, "sub-01-xss", "bugcrowd")
            self.assertIsNotNone(pkg)
            copied = out / "run-F1.png"
            self.assertTrue(copied.is_file(), "screenshot was not co-located with the package")
            self.assertEqual(copied.read_bytes(), png.read_bytes())
            md = Path(pkg["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("![Proof-of-concept screenshot](run-F1.png)", md)


if __name__ == "__main__":
    unittest.main()
