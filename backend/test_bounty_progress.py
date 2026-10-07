"""Tests for the live progress log (bughunter.progress) and its wiring into
run_bounty_hunt / run_campaign's on_progress callback — the UI's only way to see
technical progress while a scan/campaign blocks on asyncio.to_thread."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402
from bughunter import progress, rate_limit  # noqa: E402
from bughunter.bounty import run_bounty_hunt  # noqa: E402
from bughunter.campaign import run_campaign  # noqa: E402


def setUpModule() -> None:
    """Start from a full per-host active-request budget — see rate_limit.reset_shared_governors().

    This module is the suite's heaviest consumer of the process-wide 127.0.0.1 bucket (573 of its
    700 tokens), so without a module-boundary reset it both inherits an already-drained bucket and
    starves every active-layer module that runs after it.
    """
    rate_limit.reset_shared_governors()


class ProgressBufferTests(unittest.TestCase):
    def test_log_before_start_run_is_a_no_op(self) -> None:
        progress.log("never-started-run", "hello")
        self.assertEqual(progress.tail("never-started-run"), {"events": [], "count": 0})

    def test_start_run_then_log_then_tail(self) -> None:
        progress.start_run("run-a")
        progress.log("run-a", "first")
        progress.log("run-a", "second")
        result = progress.tail("run-a")
        self.assertEqual(result["count"], 2)
        self.assertEqual([e["message"] for e in result["events"]], ["first", "second"])
        self.assertTrue(all("at" in e for e in result["events"]))

    def test_tail_after_cursor_only_returns_new_events(self) -> None:
        progress.start_run("run-b")
        progress.log("run-b", "one")
        first = progress.tail("run-b")
        progress.log("run-b", "two")
        second = progress.tail("run-b", after=first["count"])
        self.assertEqual([e["message"] for e in second["events"]], ["two"])

    def test_start_run_resets_a_prior_buffer(self) -> None:
        progress.start_run("run-c")
        progress.log("run-c", "stale")
        progress.start_run("run-c")
        self.assertEqual(progress.tail("run-c"), {"events": [], "count": 0})

    def test_empty_run_id_is_always_a_no_op(self) -> None:
        progress.start_run("")
        progress.log("", "ignored")
        self.assertEqual(progress.tail(""), {"events": [], "count": 0})

    def test_trimming_keeps_the_cursor_correct_via_base_seq(self) -> None:
        # A client's "after" cursor is an ABSOLUTE count returned by tail(), not a raw
        # index into the (bounded) buffer -- so once old events get trimmed off the
        # front, a cursor from before the trim must still land on the right event.
        progress.start_run("run-d")
        original_max = progress._MAX_LINES_PER_RUN
        progress._MAX_LINES_PER_RUN = 5
        try:
            for i in range(8):
                progress.log("run-d", f"event-{i}")
            result = progress.tail("run-d")
            self.assertEqual(result["count"], 8)
            self.assertEqual(len(result["events"]), 5, "the buffer itself is bounded")
            self.assertEqual(result["events"][0]["message"], "event-3")
            # A cursor from BEFORE the trim (e.g. after=2) must still resolve sanely --
            # clamped to the oldest retained event, never a negative slice or a crash.
            resumed = progress.tail("run-d", after=2)
            self.assertEqual(resumed["events"][0]["message"], "event-3")
        finally:
            progress._MAX_LINES_PER_RUN = original_max

    def test_sink_returns_a_callable_bound_to_the_run_id(self) -> None:
        progress.start_run("run-e")
        emit = progress.sink("run-e")
        emit("via sink")
        self.assertEqual([e["message"] for e in progress.tail("run-e")["events"]], ["via sink"])

    def test_run_eviction_caps_total_tracked_runs(self) -> None:
        original_max_runs = progress._MAX_RUNS
        progress._MAX_RUNS = 2
        try:
            progress.start_run("evict-1")
            progress.start_run("evict-2")
            progress.start_run("evict-3")
            self.assertEqual(progress.tail("evict-1"), {"events": [], "count": 0}, "oldest run must be evicted")
            progress.log("evict-2", "x")
            self.assertEqual(progress.tail("evict-2")["count"], 1)
        finally:
            progress._MAX_RUNS = original_max_runs


class _EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<html>hello</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


class RunBountyHuntProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def test_on_progress_receives_the_hunt_lifecycle_checkpoints(self) -> None:
        url = f"http://127.0.0.1:{self.server.server_port}/"
        lines: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            report = run_bounty_hunt(
                url, "web-app", None, tmp, "127.0.0.1", True, {},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed",
                runtime_dir=REPO_ROOT / "runtime", on_progress=lines.append,
            )
        self.assertTrue(report["ok"])
        joined = " | ".join(lines)
        self.assertIn("running scanner(s)", joined)
        self.assertIn("scan complete", joined)
        self.assertIn("writing report", joined)
        self.assertTrue(any(line.startswith("done —") for line in lines))

    def test_a_raising_on_progress_callback_never_breaks_the_hunt(self) -> None:
        url = f"http://127.0.0.1:{self.server.server_port}/"

        def boom(_msg: str) -> None:
            raise RuntimeError("a broken progress sink must not break the hunt")

        with tempfile.TemporaryDirectory() as tmp:
            report = run_bounty_hunt(
                url, "web-app", None, tmp, "127.0.0.1", True, {},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed",
                runtime_dir=REPO_ROOT / "runtime", on_progress=boom,
            )
        self.assertTrue(report["ok"])

    def test_blind_xxe_oob_probe_runs_autonomously_when_a_collaborator_is_configured(self) -> None:
        # The built-but-dormant confirm_blind_xxe prover now runs beside blind SSRF in the active pass,
        # gated on a configured collaborator (base+secret). Stub both provers (no real OOB network).
        from bughunter import bounty
        url = f"http://127.0.0.1:{self.server.server_port}/"
        calls: list = []
        xxe_finding = {"rule_id": "active.xxe", "title": "Blind XXE", "severity": "high", "class_id": "xxe",
                       "location": url, "category": "xxe", "proof_evidence": {"request_line": f"POST {url}"}}
        orig = (bounty.oob_service.confirm_blind_ssrf, bounty.oob_service.confirm_blind_xxe)
        bounty.oob_service.confirm_blind_ssrf = lambda *a, **k: {"ok": True, "status": "no-callback"}
        bounty.oob_service.confirm_blind_xxe = lambda target, **k: (calls.append((target, k.get("send"))),
            {"ok": True, "status": "confirmed", "finding": dict(xxe_finding)})[1]
        lines: list[str] = []
        try:
            with tempfile.TemporaryDirectory() as tmp:
                report = run_bounty_hunt(
                    url, "web-app", None, tmp, "127.0.0.1", True, {}, active=True,
                    oob_base="https://collab.example", oob_secret="s3cr3t",
                    default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", on_progress=lines.append)
        finally:
            bounty.oob_service.confirm_blind_ssrf, bounty.oob_service.confirm_blind_xxe = orig
        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertEqual(len(calls), 1)                          # the XXE prover ran once
        self.assertEqual(calls[0][0], url)                       # against the target
        self.assertIs(calls[0][1], True)                         # in AUTO mode (send=True)
        self.assertTrue(any("blind-XXE OOB: confirmed" in ln for ln in lines))

    def test_blind_xxe_is_skipped_without_a_collaborator(self) -> None:
        from bughunter import bounty
        url = f"http://127.0.0.1:{self.server.server_port}/"
        called: list = []
        orig = bounty.oob_service.confirm_blind_xxe
        bounty.oob_service.confirm_blind_xxe = lambda *a, **k: called.append(1)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                run_bounty_hunt(url, "web-app", None, tmp, "127.0.0.1", True, {}, active=True,
                                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed")  # no oob_base/secret
        finally:
            bounty.oob_service.confirm_blind_xxe = orig
        self.assertEqual(called, [])                             # no collaborator -> the XXE pass never fires

    def test_blind_rce_and_jwt_key_probes_run_when_a_collaborator_is_configured(self) -> None:
        # The two unauthenticated provers added in v4.4.0 run beside blind SSRF/XXE, behind the same
        # collaborator gate, and their findings must reach the report like any other active finding.
        from bughunter import bounty
        url = f"http://127.0.0.1:{self.server.server_port}/"
        seen: list = []
        rce_finding = {"rule_id": "active.blind-rce-oob", "title": "Blind OS command injection",
                       "severity": "critical", "class_id": "rce", "location": url, "category": "injection",
                       "proof_evidence": {"request_line": f"GET {url}"}}
        jwt_finding = {"rule_id": "active.jwt-key-url-injection-oob", "title": "JWT jku injection",
                       "severity": "high", "class_id": "jwt", "location": url, "category": "auth",
                       "proof_evidence": {"request_line": f"GET {url}"}}
        orig = (bounty.oob_service.confirm_blind_ssrf, bounty.oob_service.confirm_blind_xxe,
                bounty.oob_service.confirm_blind_rce, bounty.oob_service.confirm_jwt_key_injection)
        bounty.oob_service.confirm_blind_ssrf = lambda *a, **k: {"ok": True, "status": "no-callback"}
        bounty.oob_service.confirm_blind_xxe = lambda *a, **k: {"ok": True, "status": "no-callback"}
        bounty.oob_service.confirm_blind_rce = lambda target, **k: (seen.append(("rce", target)),
            {"ok": True, "status": "confirmed", "param": "cmd", "finding": dict(rce_finding)})[1]
        bounty.oob_service.confirm_jwt_key_injection = lambda target, **k: (seen.append(("jwt", target)),
            {"ok": True, "status": "confirmed", "field": "jku", "finding": dict(jwt_finding)})[1]
        lines: list[str] = []
        try:
            with tempfile.TemporaryDirectory() as tmp:
                report = run_bounty_hunt(
                    url, "web-app", None, tmp, "127.0.0.1", True, {}, active=True,
                    oob_base="https://collab.example", oob_secret="s3cr3t",
                    default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", on_progress=lines.append)
        finally:
            (bounty.oob_service.confirm_blind_ssrf, bounty.oob_service.confirm_blind_xxe,
             bounty.oob_service.confirm_blind_rce, bounty.oob_service.confirm_jwt_key_injection) = orig
        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertEqual(seen, [("rce", url), ("jwt", url)])
        self.assertTrue(any("blind-RCE OOB: confirmed via cmd" in ln for ln in lines), lines)
        self.assertTrue(any("JWT key-URL OOB: confirmed via 'jku'" in ln for ln in lines), lines)

    def test_blind_rce_and_jwt_key_probes_are_skipped_without_a_collaborator(self) -> None:
        from bughunter import bounty
        url = f"http://127.0.0.1:{self.server.server_port}/"
        called: list = []
        orig = (bounty.oob_service.confirm_blind_rce, bounty.oob_service.confirm_jwt_key_injection)
        bounty.oob_service.confirm_blind_rce = lambda *a, **k: called.append("rce")
        bounty.oob_service.confirm_jwt_key_injection = lambda *a, **k: called.append("jwt")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                run_bounty_hunt(url, "web-app", None, tmp, "127.0.0.1", True, {}, active=True,
                                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed")
        finally:
            (bounty.oob_service.confirm_blind_rce, bounty.oob_service.confirm_jwt_key_injection) = orig
        self.assertEqual(called, [])

    def test_a_raising_oob_prover_never_breaks_the_hunt(self) -> None:
        # Each OOB block is best-effort: infrastructure the operator runs (a tunnel, a phone) is the
        # least reliable part of a hunt, and it must never be able to take the hunt down with it.
        from bughunter import bounty
        url = f"http://127.0.0.1:{self.server.server_port}/"
        orig = (bounty.oob_service.confirm_blind_rce, bounty.oob_service.confirm_jwt_key_injection)

        def boom(*a, **k):
            raise RuntimeError("collaborator tunnel is down")

        bounty.oob_service.confirm_blind_rce = boom
        bounty.oob_service.confirm_jwt_key_injection = boom
        lines: list[str] = []
        try:
            with tempfile.TemporaryDirectory() as tmp:
                report = run_bounty_hunt(
                    url, "web-app", None, tmp, "127.0.0.1", True, {}, active=True,
                    oob_base="https://collab.example", oob_secret="s3cr3t",
                    default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", on_progress=lines.append)
        finally:
            (bounty.oob_service.confirm_blind_rce, bounty.oob_service.confirm_jwt_key_injection) = orig
        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertTrue(any("blind-RCE OOB probe error" in ln for ln in lines), lines)

    def test_run_id_bound_sink_lands_in_the_shared_progress_buffer(self) -> None:
        url = f"http://127.0.0.1:{self.server.server_port}/"
        progress.start_run("hunt-run-1")
        with tempfile.TemporaryDirectory() as tmp:
            report = run_bounty_hunt(
                url, "web-app", None, tmp, "127.0.0.1", True, {},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed",
                runtime_dir=REPO_ROOT / "runtime", on_progress=progress.sink("hunt-run-1"),
            )
        self.assertTrue(report["ok"])
        events = progress.tail("hunt-run-1")
        self.assertGreater(events["count"], 0)

    def test_two_back_to_back_hunts_on_the_same_target_never_collide_on_disk(self) -> None:
        # Regression: the report filename stem was built from only profile_id + target
        # slug + second-granularity timestamp -- two hunts on the same target/profile
        # started within the same wall-clock second (a double-click on "Run Hunt", or a
        # manual hunt racing a campaign's per-URL run_bounty_hunt call for the same URL)
        # produced an IDENTICAL stem, so the second call's write silently clobbered the
        # first's report on disk even though the first's API response had already
        # returned ok:True pointing at that same (now-overwritten) path.
        url = f"http://127.0.0.1:{self.server.server_port}/"
        with tempfile.TemporaryDirectory() as tmp:
            first = run_bounty_hunt(
                url, "web-app", None, tmp, "127.0.0.1", True, {},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", runtime_dir=REPO_ROOT / "runtime",
            )
            second = run_bounty_hunt(
                url, "web-app", None, tmp, "127.0.0.1", True, {},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", runtime_dir=REPO_ROOT / "runtime",
            )
            self.assertTrue(first["ok"])
            self.assertTrue(second["ok"])
            self.assertNotEqual(first["report_path"], second["report_path"])
            self.assertNotEqual(first["json_path"], second["json_path"])
            # Both files must actually exist on disk (neither call's write clobbered the other's).
            self.assertTrue(Path(first["report_path"]).is_file())
            self.assertTrue(Path(second["report_path"]).is_file())


    def test_active_url_hunt_writes_a_hunt_trace(self) -> None:
        # Phase 0 (bounty path): a direct ACTIVE URL hunt does its own recon+plan, so it appends one
        # hunt_traces.jsonl line (surface + offline plan + reportable-finding outcomes). Exercises the
        # standalone integration (guarded so a campaign's per-URL call — which passes extra_params —
        # never reaches here) plus the fail-closed row-building and the reportable-findings iteration.
        from bughunter import hunt_trace
        url = f"http://127.0.0.1:{self.server.server_port}/"
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as rt:
            report = run_bounty_hunt(
                url, "web-app", None, tmp, "127.0.0.1", True, {}, active=True,
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", runtime_dir=Path(rt))
            self.assertTrue(report["ok"], report.get("error"))
            traces = hunt_trace.load_traces(Path(rt))
            self.assertEqual(len(traces), 1)
            trace = traces[0]
            self.assertEqual(trace["plan"]["provider"], "offline")  # coder_cfg={} -> offline plan
            self.assertIn("127.0.0.1", trace["target"])
            self.assertIn("endpoints", trace["surface"])
            self.assertIsInstance(trace["outcomes"], list)


class RunCampaignProgressChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self._prev = os.environ.get("GREYIQ_SCAN_ALLOW_PRIVATE_URLS")
        os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = "1"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._prev is None:
            os.environ.pop("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["GREYIQ_SCAN_ALLOW_PRIVATE_URLS"] = self._prev

    def test_campaign_progress_includes_the_nested_hunts_own_checkpoints(self) -> None:
        # run_campaign's own "hunt N/M: url" line, AND the per-target run_bounty_hunt's
        # checkpoints (now that campaign.py passes on_progress=_emit through) must both
        # reach the same sink -- proving the whole chain, not just the outer layer.
        url = f"http://127.0.0.1:{self.server.server_port}/"
        lines: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            result = run_campaign(
                url, scope="127.0.0.1", authorized=True, coder_cfg={},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed",
                runtime_dir=REPO_ROOT / "runtime", max_pages=1, on_progress=lines.append,
            )
        self.assertTrue(result["ok"])
        joined = " | ".join(lines)
        self.assertIn("hunt 1/", joined)
        self.assertIn("running scanner(s)", joined, "the nested run_bounty_hunt's own checkpoints must surface too")

    def test_span_mode_streams_findings_to_the_named_unit_not_the_urls(self) -> None:
        # Regression: in a program span the dashboard's work units are the NAMED targets.
        # With progress_unit set, a campaign must (a) NOT register its discovered URLs as
        # their own units, and (b) stream each URL's findings attributed to the named unit
        # as they're found — so a big multi-URL target's findings appear live, not only when
        # the whole target finishes.
        url = f"http://127.0.0.1:{self.server.server_port}/"
        progress.start_run("span-run")
        progress.set_targets("span-run", ["tiktok.com"])  # the span registers the named target
        with tempfile.TemporaryDirectory() as tmp:
            result = run_campaign(
                url, scope="127.0.0.1", authorized=True, coder_cfg={},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed",
                runtime_dir=REPO_ROOT / "runtime", max_pages=1,
                progress_run_id="span-run", progress_unit="tiktok.com",
            )
        self.assertTrue(result["ok"])
        snap = progress.snapshot("span-run")
        # Only the ONE named unit exists — the crawled URL is NOT registered as its own unit.
        self.assertEqual([t["target"] for t in snap["targets"]], ["tiktok.com"])
        # The header-less fixture yields missing-header findings; they were streamed and
        # every one is attributed to the named unit (not the URL).
        self.assertGreater(snap["stats"]["findings_total"], 0)
        self.assertTrue(all(f["target"] == "tiktok.com" for f in snap["findings"]))
        self.assertEqual(snap["targets"][0]["findings"], snap["stats"]["findings_total"])

    def test_stop_request_halts_the_campaign_url_loop(self) -> None:
        # A campaign whose run is stop-requested must break out of the per-URL hunt loop
        # and return cleanly with nothing hunted (partial result), rather than running to
        # completion — proving the Stop button's cooperative-cancellation wiring.
        url = f"http://127.0.0.1:{self.server.server_port}/"
        progress.start_run("halt-run")
        progress.request_stop("halt-run")  # pre-cancel: the loop checks this before each URL
        with tempfile.TemporaryDirectory() as tmp:
            result = run_campaign(
                url, scope="127.0.0.1", authorized=True, coder_cfg={},
                default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed",
                runtime_dir=REPO_ROOT / "runtime", max_pages=3, progress_run_id="halt-run",
            )
        self.assertTrue(result["ok"])                 # returns cleanly (partial), never raises
        self.assertEqual(result.get("urls_scanned"), 0)  # broke before hunting any URL
        self.assertEqual(result.get("finding_count"), 0)


class StructuredSnapshotTests(unittest.TestCase):
    def test_snapshot_unknown_run_is_empty(self) -> None:
        snap = progress.snapshot("nope-none")
        self.assertEqual(snap["targets"], [])
        self.assertEqual(snap["stats"]["targets_total"], 0)

    def test_targets_findings_and_stats_rollup(self) -> None:
        progress.start_run("snap-a")
        progress.set_targets("snap-a", ["https://a.example", "https://b.example"])
        progress.mark_target("snap-a", "https://a.example", "running")
        progress.add_findings("snap-a", "https://a.example", [
            {"ref": "F1", "title": "XSS", "severity": "high", "class_name": "XSS", "proof_status": "confirmed"},
            {"ref": "F2", "title": "Missing CSP", "severity": "low", "class_name": "headers", "proof_status": "missing"},
        ])
        progress.mark_target("snap-a", "https://a.example", "done", elapsed_s=4.2)
        progress.mark_target("snap-a", "https://b.example", "error", error="boom")
        snap = progress.snapshot("snap-a")
        a = next(t for t in snap["targets"] if t["target"].endswith("a.example"))
        b = next(t for t in snap["targets"] if t["target"].endswith("b.example"))
        self.assertEqual((a["status"], a["findings"], a["confirmed"], a["top_severity"], a["elapsed_s"]), ("done", 2, 1, "high", 4.2))
        self.assertEqual((b["status"], b["error"]), ("error", "boom"))
        self.assertEqual(snap["stats"], {
            "targets_total": 2, "targets_done": 2, "findings_total": 2, "confirmed_total": 1,
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0},
        })
        # Order preserved as registered.
        self.assertEqual([t["target"] for t in snap["targets"]], ["https://a.example", "https://b.example"])

    def test_set_targets_is_idempotent_and_findings_capped(self) -> None:
        progress.start_run("snap-b")
        progress.set_targets("snap-b", ["t1"])
        progress.mark_target("snap-b", "t1", "running")
        progress.set_targets("snap-b", ["t1", "t2"])  # re-registering t1 must not reset its status
        self.assertEqual(next(t for t in progress.snapshot("snap-b")["targets"] if t["target"] == "t1")["status"], "running")
        many = [{"ref": f"F{i}", "title": "x", "severity": "info", "proof_status": "missing"} for i in range(progress._MAX_FINDINGS_PER_RUN + 50)]
        progress.add_findings("snap-b", "t1", many)
        self.assertEqual(progress.snapshot("snap-b")["stats"]["findings_total"], progress._MAX_FINDINGS_PER_RUN)

    def test_add_findings_carries_investigate_fields(self) -> None:
        # location/cwe/rule are streamed so the dashboard's investigate drawer + on-demand
        # re-verify have real content (the URL to re-probe, the CWE, the rule that fired).
        progress.start_run("enrich")
        progress.set_targets("enrich", ["t1"])
        progress.add_findings("enrich", "t1", [{
            "ref": "F1", "title": "Reflected XSS", "severity": "high", "proof_status": "confirmed",
            "class_name": "xss", "location": "https://t1/search?q=1", "cwe": "CWE-79", "rule_id": "xss-reflected",
        }])
        f = progress.snapshot("enrich")["findings"][0]
        self.assertEqual(f["location"], "https://t1/search?q=1")
        self.assertEqual(f["cwe"], "CWE-79")
        self.assertEqual(f["rule"], "xss-reflected")

    def test_stop_flag_set_query_and_cleared_by_start_run(self) -> None:
        self.assertFalse(progress.is_stopped("stopflag"))
        progress.start_run("stopflag")
        self.assertFalse(progress.is_stopped("stopflag"))
        progress.request_stop("stopflag")
        self.assertTrue(progress.is_stopped("stopflag"))
        progress.start_run("stopflag")  # a fresh run clears any prior stop request
        self.assertFalse(progress.is_stopped("stopflag"))

    def test_structured_helpers_before_start_run_are_noops(self) -> None:
        # No start_run for this id — every structured helper must be a safe no-op.
        progress.set_targets("ghost-run", ["x"])
        progress.mark_target("ghost-run", "x", "running")
        progress.add_findings("ghost-run", "x", [{"ref": "F1", "severity": "high"}])
        self.assertEqual(progress.snapshot("ghost-run")["stats"]["targets_total"], 0)


if __name__ == "__main__":
    unittest.main()


class KillSwitchReachesADirectHuntTests(unittest.TestCase):
    """Stop must halt a SINGLE hunt's probing, not just relabel the UI.

    campaign.py polls progress.is_stopped between targets and between URLs, but a direct hunt only
    ever received ``on_progress`` — a one-way message sink. So clicking Stop flipped the pill to
    "Stopped" and disabled the button while the active fan-out, the re-plan wave and all four OOB
    provers kept sending requests at a host the operator had just realised was out of scope. That is
    the one control in an authorized-testing tool that has to work.

    These tests assert the wiring rather than driving a live hunt: the predicate exists, every probe
    launch site consults it, and a broken predicate cannot abort a legitimate run.
    """

    def test_the_hunt_body_accepts_and_consults_a_stop_predicate(self) -> None:
        import inspect

        from bughunter import bounty

        signature = inspect.signature(bounty._run_bounty_hunt_body)
        self.assertIn("should_stop", signature.parameters,
                      "the hunt body cannot be told to stop")
        source = inspect.getsource(bounty._run_bounty_hunt_body)
        self.assertIn("def _stopped()", source)
        # Every place that starts sending must check it: the per-target active fan-out, the re-plan
        # wave, and each of the four OOB provers (which inject callback tokens and then poll).
        self.assertGreaterEqual(source.count("_stopped()"), 6,
                                "a probe launch site is not gated on the kill switch")

    def test_a_raising_predicate_does_not_abort_the_hunt(self) -> None:
        # A broken kill switch must fail OPEN — aborting a legitimate, authorized hunt because a
        # status lookup raised would be its own bug.
        import inspect

        from bughunter import bounty

        source = inspect.getsource(bounty._run_bounty_hunt_body)
        start = source.index("def _stopped()")
        # The helper's own body: from its def to the first line at the enclosing indent that follows it.
        body = source[start:start + 700]
        self.assertIn("except Exception", body,
                      "_stopped() does not swallow a raising predicate, so a broken status lookup "
                      "would abort an authorized hunt")
        self.assertIn("return False", body)

    def test_both_entry_points_pass_the_predicate(self) -> None:
        api = (BACKEND_DIR / "greyiq_api.py").read_text(encoding="utf-8")
        self.assertIn("should_stop=(lambda rid=run_id: bounty_progress.is_stopped(rid))", api,
                      "the direct-hunt route does not pass the kill switch")
        campaign_src = (BACKEND_DIR / "bughunter" / "campaign.py").read_text(encoding="utf-8")
        self.assertIn("should_stop=(lambda rid=progress_run_id: progress.is_stopped(rid))", campaign_src,
                      "a campaign's per-URL hunt does not pass the kill switch, so Stop waits out the URL")

    def test_the_flag_itself_round_trips(self) -> None:
        run_id = "killswitch-contract-test"
        progress.start_run(run_id)
        self.assertFalse(progress.is_stopped(run_id))
        progress.request_stop(run_id)
        self.assertTrue(progress.is_stopped(run_id))


class StopFlagLifetimeTests(unittest.TestCase):
    """The stop flag has to outlive its run's BUFFER, and still be bounded.

    Buffer eviction is driven only by how many OTHER runs have since started — it says nothing about
    whether this one is still probing someone's production host. The long campaign an operator just
    cancelled is precisely the run most likely to still be going when eight newer ones begin, so
    clearing its flag on eviction silently un-cancelled it: the loops in campaign.py/bounty.py poll
    is_stopped and would have carried straight on with the pill still reading "Stopped".
    """

    def setUp(self) -> None:
        # These assert on the FIFO's exact contents, so never inherit (or leave) other tests' flags.
        self._clear_stop_state()
        self.addCleanup(self._clear_stop_state)

    @staticmethod
    def _clear_stop_state() -> None:
        with progress._lock:
            progress._stopped.clear()
            progress._stopped_order.clear()

    def test_a_stop_request_survives_the_eviction_of_eight_newer_runs(self) -> None:
        progress.start_run("long-campaign")
        progress.request_stop("long-campaign")
        for i in range(progress._MAX_RUNS):
            progress.start_run(f"newer-{i}")
        # The buffer is gone -- that half of eviction is intended and unchanged.
        self.assertEqual(progress.tail("long-campaign"), {"events": [], "count": 0})
        self.assertNotIn("long-campaign", progress._run_order)
        # The kill switch is not.
        self.assertTrue(progress.is_stopped("long-campaign"))

    def test_start_run_on_the_same_id_still_clears_the_flag(self) -> None:
        # The one event that genuinely means "this id is a new run" -- and the only place the flag
        # may be dropped. A sticky flag here would pre-cancel a legitimate restart.
        progress.request_stop("recycled")
        self.assertTrue(progress.is_stopped("recycled"))
        progress.start_run("recycled")
        self.assertFalse(progress.is_stopped("recycled"))

    def test_start_run_clears_the_flag_from_both_the_set_and_its_fifo(self) -> None:
        # A discard that forgot the FIFO would leave a ghost entry, and the bound would then trim a
        # LIVE stop request to make room for it: the same silent revocation, one step removed.
        progress.request_stop("recycled-2")
        progress.start_run("recycled-2")
        self.assertNotIn("recycled-2", progress._stopped_order)
        self.assertEqual(len(progress._stopped), len(progress._stopped_order))

    def test_the_stop_flag_set_is_bounded(self) -> None:
        # It no longer rides on eviction, so it needs its own bound or it grows for the life of the
        # process. Oldest requests are the ones dropped.
        original = progress._MAX_STOPPED
        progress._MAX_STOPPED = 3
        try:
            for i in range(5):
                progress.request_stop(f"bound-{i}")
            self.assertEqual(progress._stopped_order, ["bound-2", "bound-3", "bound-4"])
            self.assertEqual(progress._stopped, {"bound-2", "bound-3", "bound-4"})
            self.assertFalse(progress.is_stopped("bound-0"))
            self.assertTrue(progress.is_stopped("bound-4"))
        finally:
            progress._MAX_STOPPED = original

    def test_repeating_a_stop_request_never_evicts_an_older_one(self) -> None:
        # An operator leaning on Stop must not be able to push another run's live cancellation out
        # of the bound.
        original = progress._MAX_STOPPED
        progress._MAX_STOPPED = 2
        try:
            progress.request_stop("first")
            progress.request_stop("second")
            for _ in range(10):
                progress.request_stop("second")
            self.assertEqual(progress._stopped_order, ["first", "second"])
            self.assertTrue(progress.is_stopped("first"))
        finally:
            progress._MAX_STOPPED = original


class ListRunsTests(unittest.TestCase):
    """``list_runs`` is the discovery step that makes attaching to somebody else's run possible.

    A run_id is minted by whichever client launched the run and written down nowhere a second
    process can read it, so without this a shell can only watch runs it started itself.
    """

    def _row(self, run_id: str) -> dict:
        row = next((r for r in progress.list_runs() if r["run_id"] == run_id), None)
        self.assertIsNotNone(row, f"{run_id} is not listed")
        return row  # type: ignore[return-value]

    def test_lists_live_runs_newest_first_with_a_real_started_at(self) -> None:
        progress.start_run("lr-old")
        progress.start_run("lr-new")
        ids = [r["run_id"] for r in progress.list_runs()]
        self.assertLess(ids.index("lr-new"), ids.index("lr-old"))
        # A parseable ISO stamp, not "" -- it is the only wall-clock fact about a run with no
        # events yet, so an attaching client has nothing else to order or date by.
        datetime.fromisoformat(self._row("lr-new")["started_at"])

    def test_reports_the_stop_request_and_a_restart_clears_it(self) -> None:
        progress.start_run("lr-stop")
        self.assertFalse(self._row("lr-stop")["stopped"])
        progress.request_stop("lr-stop")
        self.assertTrue(self._row("lr-stop")["stopped"])
        progress.start_run("lr-stop")
        self.assertFalse(self._row("lr-stop")["stopped"])

    def test_carries_the_first_work_unit_and_the_live_counts(self) -> None:
        progress.start_run("lr-counts")
        progress.set_targets("lr-counts", ["acme.com", "beta.example"])
        progress.add_findings("lr-counts", "acme.com",
                              [{"ref": "F1", "severity": "high", "proof_status": "missing"}])
        progress.log("lr-counts", "recon")
        row = self._row("lr-counts")
        self.assertEqual(row["target"], "acme.com")
        self.assertEqual((row["targets_total"], row["findings_total"], row["events"]), (2, 1, 1))

    def test_the_label_is_empty_rather_than_guessed_before_units_are_registered(self) -> None:
        # A direct hunt that has not reached set_targets has no work unit to name. Empty says so;
        # inventing a label from the run id would read as a target.
        progress.start_run("lr-bare")
        self.assertEqual(self._row("lr-bare")["target"], "")

    def test_an_evicted_run_disappears_from_the_listing(self) -> None:
        original = progress._MAX_RUNS
        progress._MAX_RUNS = 2
        try:
            progress.start_run("lr-e1")
            progress.start_run("lr-e2")
            progress.start_run("lr-e3")
            self.assertEqual([r["run_id"] for r in progress.list_runs()], ["lr-e3", "lr-e2"])
        finally:
            progress._MAX_RUNS = original


class _Capture:
    """A minimal in-process ASGI client -- no socket, the real route_http entry point."""

    def __init__(self, body: bytes = b"{}") -> None:
        self.status: int | None = None
        self.body = b""
        self._request_body = body

    async def send(self, message: dict) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")

    async def receive(self) -> dict:
        return {"type": "http.request", "body": self._request_body, "more_body": False}


def _post_runs(headers: dict | None = None, body: bytes = b"{}") -> _Capture:
    hdrs = {"Host": "127.0.0.1:8791"}
    hdrs.update(headers or {})
    cap = _Capture(body)
    scope = {
        "method": "POST", "path": "/api/bounty/runs", "scheme": "http", "query_string": b"",
        "headers": [(k.lower().encode("ascii"), v.encode("latin-1")) for k, v in hdrs.items()],
    }
    asyncio.run(g.route_http(scope, cap.receive, cap.send))
    return cap


class BountyRunsRouteTests(unittest.TestCase):
    """POST /api/bounty/runs -- the HTTP face of list_runs, for `gn dash --attach`.

    It is session-gated exactly like its neighbours: the run ids it hands out are the keys to
    /api/bounty/progress and /api/bounty/campaign/stop, so an unauthenticated caller must not be
    able to enumerate them.
    """

    def test_the_route_403s_without_the_session_token_header(self) -> None:
        progress.start_run("route-secret-run")
        cap = _post_runs()
        self.assertEqual(cap.status, 403)
        self.assertNotIn(b"route-secret-run", cap.body)  # and leaks no id on the way out

    def test_a_wrong_token_is_refused_too(self) -> None:
        cap = _post_runs(headers={"X-GreyIQ-Token": "not-the-token"})
        self.assertEqual(cap.status, 403)

    def test_with_the_token_it_returns_the_live_runs(self) -> None:
        progress.start_run("route-run")
        progress.set_targets("route-run", ["acme.com"])
        cap = _post_runs(headers={"X-GreyIQ-Token": g.SESSION_TOKEN})
        self.assertEqual(cap.status, 200)
        payload = json.loads(cap.body)
        self.assertTrue(payload["ok"])
        row = next(r for r in payload["runs"] if r["run_id"] == "route-run")
        self.assertEqual(set(row), {"run_id", "started_at", "stopped", "target",
                                    "targets_total", "findings_total", "events"})
        self.assertEqual((row["target"], row["stopped"]), ("acme.com", False))

    def test_the_route_is_read_only_and_takes_no_steering_input(self) -> None:
        # The request model is field-free, so a body cannot start, stop or name anything. Pinned
        # because this route's whole job is handing out ids that unlock the other bounty routes.
        self.assertEqual(set(g.BountyRunsRequest.model_fields), set())
        cap = _post_runs(headers={"X-GreyIQ-Token": g.SESSION_TOKEN},
                         body=b'{"run_id": "route-ghost", "stopped": true}')
        self.assertEqual(cap.status, 200)
        self.assertNotIn("route-ghost", [r["run_id"] for r in json.loads(cap.body)["runs"]])
        self.assertFalse(progress.is_stopped("route-ghost"))

    def test_the_accessor_does_not_shadow_the_cached_run_store(self) -> None:
        # `runtime.bounty_runs` is the finished-run artifact cache several routes read. A METHOD of
        # that name is silently shadowed by it -- the attribute simply wins -- so every call here
        # 500s. That is how this was found; the name stays distinct.
        self.assertIsInstance(g.runtime.bounty_runs, dict)
        self.assertTrue(callable(g.runtime.list_bounty_runs))

    def test_an_empty_body_is_accepted(self) -> None:
        # The attaching client has nothing to say; it must not have to send "{}" to be understood.
        cap = _post_runs(headers={"X-GreyIQ-Token": g.SESSION_TOKEN}, body=b"")
        self.assertEqual(cap.status, 200)
