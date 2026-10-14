"""Regression checks for the local defender board and its evidence boundary."""

from __future__ import annotations

import copy
import io
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import gn_cli  # noqa: E402
import gn_tui  # noqa: E402
from defender import cli as defender_cli  # noqa: E402
from defender.dashboard import BoardState, _handle_key, render, run_dashboard  # noqa: E402


def _result(*, finding: bool = False) -> dict:
    return {
        "at": "2026-10-14T12:00:00Z", "baseline_sha256": "a" * 64,
        "observation": {"connections": [
            {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": 8080,
             "state": "LISTEN", "pid": 100001},
        ]},
        "inventory": {"errors": []},
        "tools": {"tshark": {"ok": True, "packets": [
            {"timestamp": "2026-10-14T12:00:00Z", "source": "8.8.8.8", "source_port": 54321,
             "destination": "10.0.0.2", "destination_port": 22, "protocol": "tcp",
             "length": 128, "tcp_syn": True, "tcp_ack": False},
        ]}},
        "findings": ([{"rule_id": "defender.tcp_syn_port_probe",
                      "title": "TCP SYN port-probe indicator from 8.8.8.8"}] if finding else []),
        "artifact": {"artifact_path": "/private/runs/scan.json.gz"},
    }


class DefenderDashboardTests(unittest.TestCase):
    def test_port_proxy_packet_navigation_and_selection_survive_rescan(self) -> None:
        state = BoardState(capture_enabled=True)
        result = _result()
        result["observation"]["connections"] = [
            {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": port,
             "state": "LISTEN", "pid": port, "remote_address": ""}
            for port in range(8000, 8015)
        ]
        result["observation"]["proxies"] = [
            {"kind": "http", "host": f"proxy-{index}.example", "port": 3128 + index,
             "source": "env:HTTP_PROXY", "scheme": "http"} for index in range(8)
        ]
        result["tools"]["tshark"]["packets"] = [
            {"timestamp": f"2026-10-14T12:00:{index:02d}Z", "source": "192.0.2.1",
             "source_port": 50000 + index, "destination": "10.0.0.2",
             "destination_port": 443, "protocol": "tcp", "length": 80 + index,
             "tcp_syn": True, "tcp_ack": False} for index in range(15)
        ]
        state.ingest(result)
        editor = gn_tui.CommandLine()
        size = gn_tui.Size(100, 25)
        _handle_key(state, "TAB", editor, size)
        self.assertEqual(state.focus, "ports")
        _handle_key(state, "PGDN", editor, size)
        self.assertGreater(state.selected_port, 0)
        _handle_key(state, "END", editor, size)
        self.assertEqual(state.selected_port, 14)
        self.assertIn("PID 8014", state.selected_detail())
        self.assertIn("8014", "\n".join(render(state, size, color=False)))
        changed = copy.deepcopy(result)
        changed["observation"]["connections"].append(
            {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": 7999,
             "state": "LISTEN", "pid": 7999, "remote_address": ""})
        state.ingest(changed)
        self.assertEqual(state.ports[state.selected_port]["local_port"], 8014)
        _handle_key(state, "RIGHT", editor, size)
        self.assertEqual(state.focus, "proxies")
        _handle_key(state, "END", editor, size)
        self.assertEqual(state.selected_proxy, 7)
        frame = "\n".join(render(state, size, color=False))
        self.assertIn("PROXY MAP // 8 CONFIGURED", frame)
        self.assertIn("proxy-7.example", state.selected_detail())
        self.assertIn("proxy-7.example", frame)
        narrow = render(state, gn_tui.Size(78, 22), color=False)
        self.assertEqual(len(narrow), 22)
        self.assertTrue(all(gn_tui.visible_len(row) <= 78 for row in narrow))
        self.assertIn("q quit", "\n".join(narrow))
        _handle_key(state, "RIGHT", editor, size)
        self.assertEqual(state.focus, "packets")
        _handle_key(state, "END", editor, size)
        self.assertEqual(state.selected_packet, len(state.matching_packets()) - 1)
        _handle_key(state, "PGUP", editor, size)
        self.assertLess(state.selected_packet, len(state.matching_packets()) - 1)
        _handle_key(state, "HOME", editor, size)
        selected = state.selected_detail()
        self.assertIn("12:00:14Z", selected)
        state.ingest(copy.deepcopy(result))
        self.assertEqual(state.selected_detail(), selected)
        _handle_key(state, "LEFT", editor, size)
        self.assertEqual(state.focus, "proxies")
        self.assertEqual(state.selected_proxy, 7)

    def test_green_to_red_is_evidence_driven_and_latched(self) -> None:
        state = BoardState(capture_enabled=True)
        state.ingest(_result())
        green = render(state, gn_tui.Size(100, 25))
        self.assertIn("\033[38;5;46m", "\n".join(green))
        self.assertIn("NO INDICATORS", "\n".join(green))
        self.assertIn("PID 100001", state.selected_detail() if state.focus == "ports" else
                      self._port_detail(state))

        state.ingest(_result(finding=True))
        red = render(state, gn_tui.Size(100, 25))
        self.assertIn("\033[38;5;196m", "\n".join(red))
        self.assertIn("SUSPECTED ACTIVITY", "\n".join(red))
        self.assertIn("defender.tcp_syn_port_probe", "\n".join(red))
        state.ingest(_result())
        self.assertTrue(state.alert_latched)
        self.assertIn("SUSPECTED ACTIVITY", "\n".join(render(state, gn_tui.Size(100, 25), color=False)))

    @staticmethod
    def _port_detail(state: BoardState) -> str:
        state.focus = "ports"
        return state.selected_detail()

    def test_packet_search_and_safe_frame(self) -> None:
        state = BoardState(capture_enabled=True)
        result = _result()
        result["observation"]["connections"][0]["local_address"] = "127.0.0.1\x1b[31mBAD"
        state.ingest(result)
        editor = gn_tui.CommandLine()
        self.assertEqual(_handle_key(state, "/", editor), "")
        for key in "8.8.8.8":
            self.assertEqual(_handle_key(state, key, editor), "")
        _handle_key(state, "ENTER", editor)
        self.assertEqual(len(state.matching_packets()), 1)
        state.query = "example.net"
        self.assertEqual(state.matching_packets(), [])
        state.query = "8.8.8.8"
        plain = render(state, gn_tui.Size(100, 25), color=False)
        self.assertEqual(len(plain), 25)
        self.assertTrue(all(gn_tui.visible_len(row) <= 100 for row in plain))
        self.assertNotIn("\x1b", "\n".join(plain))
        self.assertIn("127.0.0.1 [31mBAD", "\n".join(plain))
        self.assertIn("PROTO  LOCAL ADDRESS", "\n".join(plain))
        self.assertIn("SNAPSHOT 12:00:00Z", "\n".join(plain))
        self.assertIn("SYN:1 ACK:0", state.selected_detail())
        self.assertIn("SYN:1 ACK:0", "\n".join(plain))

    def test_retro_signal_and_bounded_alert_queue_keep_strongest_lead_visible(self) -> None:
        state = BoardState(capture_enabled=True, sweep=2)
        result = _result()
        result["findings"] = [
            {"finding_id": "low-1", "severity": "low", "rule_id": "defender.new_listener",
             "title": "New local listener"},
            {"finding_id": "high-1", "severity": "high", "rule_id": "defender.ioc_match",
             "title": "Reviewed indicator match"},
        ]
        state.ingest(result)
        frame = "\n".join(render(state, gn_tui.Size(100, 25), color=False))
        self.assertIn("LIVE CIRCUIT", frame)
        self.assertIn("[==>  ]", frame)
        self.assertIn("SUSPECTED ACTIVITY [HIGH]", frame)
        self.assertIn("ALERT 1/2 [HIGH] defender.ioc_match", frame)
        self.assertEqual(_handle_key(state, "a", gn_tui.CommandLine()), "")
        self.assertIn("ALERT 2/2 [LOW] defender.new_listener",
                      "\n".join(render(state, gn_tui.Size(100, 25), color=False)))
        clean = _result()
        clean["artifact"]["artifact_path"] = "/private/runs/clean.json.gz"
        state.ingest(clean)
        self.assertTrue(state.alert_latched)
        self.assertEqual(len(state.alert_history), 2)
        after_clean = "\n".join(render(state, gn_tui.Size(100, 25), color=False))
        self.assertIn("ALERT 2/2 [LOW]", after_clean)
        self.assertIn("EVIDENCE /private/runs/scan.json.gz", after_clean)
        self.assertNotIn("EVIDENCE /private/runs/clean.json.gz", after_clean)
        state.ingest(result)
        self.assertEqual(len(state.alert_history), 2)
        self.assertEqual(_handle_key(state, "a", gn_tui.CommandLine()), "")
        self.assertIn("ALERT 1/2 [HIGH]", "\n".join(render(state, gn_tui.Size(100, 25), color=False)))
        many = _result()
        many["findings"] = [
            {"finding_id": f"low-{index}", "severity": "low", "rule_id": "defender.new_listener",
             "title": f"Listener {index}"} for index in range(80)
        ] + [{"finding_id": "critical-1", "severity": "critical", "rule_id": "defender.ioc_match",
              "title": "Strongest reviewed lead"}]
        state.ingest(many)
        self.assertEqual(len(state.alert_history), 64)
        self.assertEqual(state.alert_history[0]["severity"], "critical")

    def test_discarded_weak_alert_does_not_reset_operator_selection(self) -> None:
        state = BoardState()
        strong = _result()
        strong["findings"] = [
            {"finding_id": f"high-{index}", "severity": "high", "rule_id": "test.strong",
             "title": f"Strong lead {index}"} for index in range(64)
        ]
        state.ingest(strong)
        state.selected_alert = 25
        selected_key = state.alert_history[25]["key"]
        weak = _result()
        weak["findings"] = [
            {"finding_id": "weak", "severity": "low", "rule_id": "test.weak",
             "title": "Weak lead"}
        ]
        state.ingest(weak)
        self.assertEqual(len(state.alert_history), 64)
        self.assertEqual(state.alert_history[state.selected_alert]["key"], selected_key)
        state.ingest(weak)
        self.assertEqual(state.alert_history[state.selected_alert]["key"], selected_key)

    def test_search_cancel_restores_filter_and_q_does_not_quit_while_typing(self) -> None:
        state = BoardState(query="tcp")
        editor = gn_tui.CommandLine()
        _handle_key(state, "/", editor)
        self.assertEqual(_handle_key(state, "q", editor), "")
        self.assertEqual(state.query, "tcpq")
        self.assertEqual(_handle_key(state, "CTRL-C", editor), "quit")
        _handle_key(state, "ESC", editor)
        self.assertEqual(state.query, "tcp")
        self.assertEqual(_handle_key(state, "q", editor), "quit")

    def test_failed_capture_pauses_automatic_scans_without_false_alert(self) -> None:
        state = BoardState(capture_enabled=True)
        result = _result()
        result["tools"]["tshark"] = {"ok": False, "status": "tool_missing", "error": "not installed"}
        state.ingest(result)
        self.assertTrue(state.stopped)
        self.assertFalse(state.alert_latched)
        self.assertIn("tool_missing", state.message)
        self.assertEqual(_handle_key(state, "r", gn_tui.CommandLine()), "refresh")
        self.assertFalse(state.stopped)

    def test_live_runner_paints_red_finding_and_restores_screen(self) -> None:
        frames: list[list[str]] = []

        class FakeScreen:
            active = True
            restored = False

            def __enter__(self) -> "FakeScreen":
                return self

            def __exit__(self, *_args: object) -> None:
                self.restored = True

            def take_resize(self) -> bool:
                return False

            def size(self) -> gn_tui.Size:
                return gn_tui.Size(100, 25)

            def frame(self, rows: list[str]) -> None:
                frames.append(rows)

        class FakeKeys:
            def __enter__(self) -> "FakeKeys":
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def read(self, _timeout: float) -> str | None:
                if any("SUSPECTED ACTIVITY" in row for frame in frames for row in frame):
                    return "q"
                if time.monotonic() - started > 2:
                    return "q"
                time.sleep(0.01)
                return None

        screen = FakeScreen()
        started = time.monotonic()
        with mock.patch.object(gn_tui, "refusal", return_value=""), \
             mock.patch.object(gn_tui, "Screen", return_value=screen), \
             mock.patch.object(gn_tui, "KeyReader", return_value=FakeKeys()):
            self.assertEqual(run_dashboard(SimpleNamespace(capture_interface="test0", interval=2),
                                           scan=lambda: _result(finding=True)), 0)
        self.assertTrue(screen.restored)
        self.assertTrue(any("\033[38;5;196m" in row and "SUSPECTED ACTIVITY" in row
                            for frame in frames for row in frame))

    def test_dashboard_uses_evidence_producing_scan_and_keeps_observation_private(self) -> None:
        snapshot = {"schema_version": 1, "collected_at": "2026-10-14T12:00:00Z",
                    "host": {"hostname": "fixture"},
                    **{name: [] for name in ("processes", "connections", "interfaces", "routes",
                                              "services", "startup", "packages", "files")},
                    "file_roots": [], "coverage": {}, "errors": []}
        observed: list[dict] = []

        def inspect_dashboard(_args: object, *, scan: object) -> int:
            observed.append(scan())  # type: ignore[operator]
            return 0

        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(defender_cli, "_runtime", return_value=Path(temp)), \
             mock.patch("defender.inventory.collect_inventory", return_value=snapshot), \
             mock.patch("defender.dashboard.run_dashboard", side_effect=inspect_dashboard):
            self.assertEqual(gn_cli.main(["defend", "dash"]), 0)
        self.assertEqual(observed[0]["observation"], snapshot)
        self.assertTrue(observed[0]["artifact"]["artifact_path"])
        self.assertEqual(len(observed[0]["findings"]), 0)

    def test_dashboard_pins_baseline_after_first_observed_cycle(self) -> None:
        required: list[bool] = []

        def fake_scan(_args: object, **kwargs: object) -> dict:
            required.append(bool(kwargs["require_baseline"]))
            return {"baseline_sha256": "a" * 64}

        def two_cycles(_args: object, *, scan: object) -> int:
            scan()  # type: ignore[operator]
            scan()  # type: ignore[operator]
            return 0

        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(defender_cli, "_runtime", return_value=Path(temp)), \
             mock.patch.object(defender_cli, "_scan_once", side_effect=fake_scan), \
             mock.patch("defender.dashboard.run_dashboard", side_effect=two_cycles):
            self.assertEqual(gn_cli.main(["defend", "dash"]), 0)
        self.assertEqual(required, [False, True])

    def test_cli_requires_authorized_capture_and_terminal_before_scanning(self) -> None:
        def run(args: list[str]) -> tuple[int, str]:
            output = io.StringIO()
            with mock.patch.object(sys, "stderr", output), \
                 mock.patch("defender.inventory.collect_inventory", side_effect=AssertionError("scan ran")):
                return gn_cli.main(["defend", "dash", *args]), output.getvalue()

        self.assertIn("defend", gn_cli.CLI_COMMANDS)
        code, error = run(["--capture-interface", "test0"])
        self.assertEqual(code, 2)
        self.assertIn("-y/--authorize-local-scan", error)
        code, error = run(["--capture-interface", "test0", "-y"])
        self.assertEqual(code, 2)
        self.assertIn("terminal", error)
        code, error = run(["--nmap-target", "8.8.8.8", "--scope", "8.8.8.8", "-y"])
        self.assertEqual(code, 2)
        self.assertIn("local/private", error)
        with tempfile.TemporaryDirectory() as temp:
            code, error = run(["--baseline", str(Path(temp) / "missing.json")])
        self.assertEqual(code, 2)
        self.assertIn("requires the selected baseline", error)


if __name__ == "__main__":
    unittest.main()
