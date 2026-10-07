"""Focused checks for the read-only GreyIQ terminal dashboard."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_cli  # noqa: E402
import terminal_dashboard as dashboard  # noqa: E402


class TerminalDashboardTests(unittest.TestCase):
    def test_snapshot_uses_local_stores_and_redacts_terminal_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp)
            portfolio = runtime / "portfolio.json"
            ledger = runtime / "bughunter_ledger.json"
            portfolio.write_text(json.dumps({"programs": {
                "alpha": {"name": "Alpha\x1b[2J", "enabled": True, "last_run_at": "2026-10-06T10:00:00+00:00"},
                "beta": {"name": "Beta", "enabled": False},
            }}), encoding="utf-8")
            ledger.write_text(json.dumps({"programs": {"alpha": {"findings": {
                "one": {"title": "Header\x1b[31m leak", "stage": "confirmed", "report_ready": True,
                        "bounty": 50, "updated_at": "2026-10-06T10:10:00+00:00"},
                "two": {"title": "Dismissed", "stage": "discovered", "dismissed": True},
            }}}}), encoding="utf-8")
            report_dir = runtime / "reports"
            report_dir.mkdir()
            (report_dir / "finding.md").write_text("report content", encoding="utf-8")
            (runtime / "hunt_traces.jsonl").write_text(json.dumps({
                "ts": "2026-10-06T10:05:00+00:00", "program": "alpha", "outcomes": [{"proof_status": "confirmed"}],
            }) + "\n", encoding="utf-8")
            before = {p: p.read_bytes() for p in (portfolio, ledger, report_dir / "finding.md", runtime / "hunt_traces.jsonl")}

            with mock.patch.object(dashboard, "_api_health", return_value="offline"), \
                 mock.patch.object(dashboard, "_system_health", return_value=("0.10 / 0.20 / 0.30", 25.0, "1.0/4.0 GiB")), \
                 mock.patch.object(dashboard, "_cpu_ticks", return_value=(250, 1200)), \
                 mock.patch.object(dashboard, "_local_processes", return_value=[]):
                snapshot = dashboard.collect_snapshot(runtime, previous_cpu=(150, 1000))

            self.assertEqual(len(snapshot["programs"]), 2)
            self.assertEqual(snapshot["enabled"], 1)
            self.assertEqual(snapshot["total"], 1)
            self.assertEqual(snapshot["stages"]["confirmed"], 1)
            self.assertEqual(snapshot["ready"], 1)
            self.assertEqual(snapshot["bounty"], 50.0)
            self.assertEqual(snapshot["cpu_percent"], 50.0)
            self.assertEqual(snapshot["memory_percent"], 25.0)
            self.assertEqual(snapshot["reports"][0][1], "finding.md")
            self.assertIn("Hunt alpha: 1 outcome(s)", [message for _, message in snapshot["activity"]])
            self.assertNotIn("\x1b", str(snapshot))
            self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_health_probe_never_follows_redirect(self) -> None:
        response = mock.Mock(status=302)
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(dashboard.http.client, "HTTPConnection", return_value=connection) as ctor:
            self.assertEqual(dashboard._api_health(8766), "HTTP 302")
        ctor.assert_called_once_with("127.0.0.1", 8766, timeout=0.35)
        connection.request.assert_called_once_with("GET", "/api/health", headers={"Accept": "application/json"})
        connection.close.assert_called_once()

    def test_cli_refuses_noninteractive_terminal(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = gn_cli.main(["dashboard"])
        self.assertEqual(code, 2)
        self.assertIn("interactive terminal", err.getvalue())
        self.assertIn("dashboard", gn_cli.CLI_COMMANDS)

    def test_corrupt_store_is_a_visible_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp)
            (runtime / "portfolio.json").write_text("{broken", encoding="utf-8")
            with mock.patch.object(dashboard, "_api_health", return_value="offline"):
                snapshot = dashboard.collect_snapshot(runtime)
        self.assertEqual(snapshot["programs"], [])
        self.assertTrue(any("portfolio.json" in warning for warning in snapshot["errors"]))

    def test_cpu_ticks_use_interval_delta(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / "stat").write_text("cpu 100 0 50 850 0 0 0 0 3 4\n", encoding="ascii")
            first = dashboard._cpu_ticks(proc)
            (proc / "stat").write_text("cpu 150 0 80 970 0 0 0 0 5 8\n", encoding="ascii")
            second = dashboard._cpu_ticks(proc)
        self.assertEqual(first, (150, 1000))
        self.assertEqual(second, (230, 1200))
        self.assertEqual(dashboard._cpu_percent(first, second), 40.0)
        self.assertIsNone(dashboard._cpu_percent(None, first))
        self.assertIsNone(dashboard._cpu_percent(second, first))

    def test_process_list_is_bounded_and_never_displays_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)

            def add_process(pid: int, name: str, command: bytes, rss_kib: int, uid: int = 1000) -> None:
                folder = proc / str(pid)
                folder.mkdir()
                (folder / "comm").write_text(name + "\n", encoding="ascii")
                (folder / "status").write_text(f"Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nVmRSS:\t{rss_kib} kB\n", encoding="ascii")
                (folder / "cmdline").write_bytes(command)

            add_process(101, "greyiq-backend", b"/opt/GreyIQ/greyiq-backend\0", 40_960)
            add_process(102, "python3", b"python3\0-m\0backend.greyiq_api\0--cookie\0SECRET-COOKIE\0", 20_480)
            add_process(103, "python3", b"python3\0other.py\0", 100_000)
            add_process(104, "greyiq-backend", b"/opt/GreyIQ/greyiq-backend\0", 80_000, uid=2000)
            rows = dashboard._local_processes(proc, uid=1000, limit=2)
        self.assertEqual([row["pid"] for row in rows], [101, 102])
        self.assertEqual(rows[0]["rss_mib"], 40)
        self.assertNotIn("SECRET-COOKIE", str(rows))

    def test_render_fits_standard_and_wide_terminals(self) -> None:
        fake_curses = types.SimpleNamespace(A_BOLD=1, error=RuntimeError, has_colors=lambda: False)

        class Screen:
            def __init__(self, width: int, height: int) -> None:
                self.width, self.height = width, height
                self.lines: list[str] = []

            def getmaxyx(self) -> tuple[int, int]:
                return self.height, self.width

            def erase(self) -> None:
                self.lines.clear()

            def addnstr(self, y: int, x: int, value: str, length: int, _style: int) -> None:
                assert 0 <= y < self.height and 0 <= x < self.width
                self.lines.append(value[:length])

            def refresh(self) -> None:
                pass

        sample = {
            "as_of": 1_780_000_000, "api": "offline", "port": 8766, "load": "0.1 / 0.2 / 0.3",
            "memory": "2.0/10.0 GiB", "memory_percent": 20.0,
            "cpu_percent": 42.0, "processes": [{"pid": 123, "role": "Backend", "rss_mib": 40}],
            "runtime": "/home/operator/.local/share/greyiq/runtime",
            "programs": [{"name": "Demo", "enabled": True, "last_run": 0}], "enabled": 1,
            "total": 1, "ready": 0, "bounty": 0.0,
            "stages": {stage: int(stage == "discovered") for stage in dashboard._STAGES},
            "reports": [(1_780_000_000, "demo.md")],
            "activity": [(1_780_000_000, "Hunt demo: 1 outcome(s)")], "errors": [],
        }
        with mock.patch.dict(sys.modules, {"curses": fake_curses}):
            for width, height in ((80, 24), (120, 30)):
                screen = Screen(width, height)
                dashboard._render(screen, sample, 0, [0, 0, 0], "2.7.0")
                self.assertTrue(any("PORTFOLIO" in line for line in screen.lines))
                self.assertTrue(any("RECENT REPORTS" in line for line in screen.lines))
                self.assertTrue(any("CPU" in line and "42%" in line for line in screen.lines))
                self.assertTrue(any("Processes" in line or "processes" in line for line in screen.lines))


if __name__ == "__main__":
    unittest.main()
