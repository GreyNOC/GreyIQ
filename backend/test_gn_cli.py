"""Tests for the `gn` bug-bounty CLI."""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_cli  # noqa: E402


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = gn_cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class GnCliTests(unittest.TestCase):
    def test_version_and_help(self) -> None:
        code, out, _ = _run(["version"])
        self.assertEqual(code, 0)
        self.assertIn(gn_cli.VERSION, out)
        # No args prints help, exit 0.
        self.assertEqual(_run([])[0], 0)

    def test_profiles_classes_tools(self) -> None:
        self.assertEqual(_run(["profiles"])[0], 0)
        code, out, _ = _run(["classes"])
        self.assertEqual(code, 0)
        self.assertIn("ssti", out)
        code, out, _ = _run(["tools", "xss"])
        self.assertEqual(code, 0)
        self.assertEqual(_run(["tools", "no-such-class"])[0], 2)  # nothing mapped -> error

    def test_hunt_requires_authorization(self) -> None:
        code, _, err = _run(["hunt", str(BACKEND_DIR / "bughunter"), "-p", "source-code"])
        self.assertEqual(code, 2)
        self.assertIn("authorize", err.lower())

    def test_hunt_runs_deterministically_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "src"
            target.mkdir()
            (target / "leak.py").write_text("AWS_KEY = 'AKIA" + "A" * 16 + "'\n", encoding="utf-8")
            out_dir = Path(tmp) / "reports"
            code, out, _ = _run(["hunt", str(target), "-p", "source-code", "-y", "-o", str(out_dir)])
            self.assertEqual(code, 0)
            self.assertIn("GreyIQ hunt", out)
            self.assertTrue(list(out_dir.glob("*.md")), "a markdown report should be written")

    def test_hunt_json_output(self) -> None:
        import json
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = _run(["hunt", str(BACKEND_DIR / "bughunter" / "settings.py"), "-p", "source-code", "-y", "-o", tmp, "--json"])
            # settings.py is a file; the code profile accepts a path. Result is JSON.
            self.assertEqual(code, 0)
            doc = json.loads(out)
            self.assertIn("risk", doc)
            self.assertNotIn("report_markdown", doc)  # trimmed from JSON (it's in the file)

    def test_cli_commands_match_dispatch_list(self) -> None:
        # run_frozen dispatches on these verbs; keep them aligned with the parser.
        for verb in ("hunt", "campaign", "osint", "scan", "learn", "stats", "traces", "profiles", "classes", "tools", "version"):
            self.assertIn(verb, gn_cli.CLI_COMMANDS)

    def test_osint_hunt_requires_authorization_and_scope_before_lookup(self) -> None:
        with mock.patch("bughunter.osint.run_campaign") as run:
            code, _, err = _run(["osint", "example.com", "--hunt"])
            self.assertEqual(code, 2)
            self.assertIn("authorize", err.lower())
            run.assert_not_called()

            code, _, err = _run(["osint", "example.com", "--hunt", "-y"])
            self.assertEqual(code, 2)
            self.assertIn("scope", err.lower())
            run.assert_not_called()

    def test_osint_cli_prints_passive_campaign_summary(self) -> None:
        payload = {
            "status": "complete", "domain": "example.com", "report_path": "OSINT.md",
            "summary": {"assets_total": 2, "hunt_eligible": 1, "claims_verified": 3, "claims_observed": 2},
        }
        with mock.patch("bughunter.osint.run_campaign", return_value=payload) as run:
            code, out, err = _run(["osint", "example.com"])
        self.assertEqual(code, 0)
        self.assertNotIn("gn:", err)
        self.assertIn("GreyIQ OSINT", out)
        self.assertIn("DNS-verified", out)
        run.assert_called_once()

    def test_traces_command_reports_corpus(self) -> None:
        import json

        from bughunter import hunt_trace
        with tempfile.TemporaryDirectory() as tmp:
            original = gn_cli.RUNTIME_DIR
            gn_cli.RUNTIME_DIR = Path(tmp)
            try:
                # Empty corpus: friendly nudge, exit 0.
                code, out, _ = _run(["traces"])
                self.assertEqual(code, 0)
                self.assertIn("No hunt traces", out)
                # Record one trace, then the corpus readout reflects it.
                hunt_trace.record_trace(
                    Path(tmp), program="demo", target="https://app.example.com/",
                    surface={"endpoints": ["https://app.example.com/search"], "params": ["q"], "tech": ["flask"], "forms": []},
                    plan={"provider": "offline", "probe_priority": [{"endpoint": "https://app.example.com/search", "classes": ["xss"]}]},
                    outcomes=[{"endpoint": "https://app.example.com/search", "class": "xss", "proof_status": "confirmed", "dedup_key": "k1"}])
                code, out, _ = _run(["traces"])
                self.assertEqual(code, 0)
                self.assertIn("1 hunt(s)", out)
                self.assertIn("1 confirmed", out)
                code, out, _ = _run(["traces", "--json"])
                self.assertEqual(code, 0)
                doc = json.loads(out)
                self.assertEqual(doc["hunts"], 1)
                self.assertEqual(doc["confirmed_rows"], 1)
            finally:
                gn_cli.RUNTIME_DIR = original

    def test_learn_and_stats_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original = gn_cli.RUNTIME_DIR
            gn_cli.RUNTIME_DIR = Path(tmp)
            try:
                code, out, _ = _run(["learn", "-c", "xss", "--status", "accepted",
                                     "--target", "https://shop.example.com", "--bounty", "500"])
                self.assertEqual(code, 0)
                self.assertIn("Recorded", out)
                # Unknown status is rejected with a usage error.
                self.assertEqual(_run(["learn", "-c", "xss", "--status", "banana", "--program", "p"])[0], 2)
                # Stats for the derived program shows the class breakdown.
                code, out, _ = _run(["stats", "--target", "https://shop.example.com"])
                self.assertEqual(code, 0)
                self.assertIn("xss", out)
                self.assertIn("500", out)
                # Stats across all programs.
                self.assertEqual(_run(["stats"])[0], 0)
            finally:
                gn_cli.RUNTIME_DIR = original

    def test_campaign_requires_authorization(self) -> None:
        code, _, err = _run(["campaign", str(BACKEND_DIR / "bughunter")])
        self.assertEqual(code, 2)
        self.assertIn("authorize", err.lower())

    def test_campaign_osint_flag_reaches_engine(self) -> None:
        payload = {
            "ok": True, "program": "demo", "urls_scanned": 0, "urls_discovered": 0,
            "finding_count": 0, "confirmed_count": 0, "submission_paths": [],
        }
        with mock.patch("bughunter.campaign.run_campaign", return_value=payload) as run:
            code, _, err = _run(["campaign", "https://example.com", "--osint", "-y", "--json"])
        # Other browser tests can finalize an un-awaited Playwright future while stderr is redirected
        # here on Windows; the CLI contract is its exit code + engine call, not ambient GC warnings.
        self.assertEqual(code, 0)
        self.assertNotIn("gn:", err)
        self.assertTrue(run.call_args.kwargs["osint"])

    def test_operator_cli_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original = gn_cli.RUNTIME_DIR
            gn_cli.RUNTIME_DIR = Path(tmp)
            try:
                # Add a program, list it, show the (empty) pipeline.
                self.assertEqual(_run(["operator", "add", "--name", "Acme", "--scope", "*.acme.com",
                                       "--targets", "https://acme.com", "--handle", "acme", "--active"])[0], 0)
                code, out, _ = _run(["operator", "list"])
                self.assertEqual(code, 0)
                self.assertIn("acme", out)
                self.assertEqual(_run(["operator", "pipeline"])[0], 0)
                # run is gated on -y/--authorize (it fires live campaigns).
                code, _, err = _run(["operator", "run"])
                self.assertEqual(code, 2)
                self.assertIn("authorize", err.lower())
                # auto-submit without a handle is dropped fail-closed.
                _run(["operator", "add", "--name", "NoHandle", "--scope", "x.com", "--auto-submit"])
                self.assertEqual(_run(["operator", "remove", "acme"])[0], 0)
            finally:
                gn_cli.RUNTIME_DIR = original


if __name__ == "__main__":
    unittest.main()
