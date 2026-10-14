"""Defender CLI integration: baseline, evidence persistence, scope gates, and trace."""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock


BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import gn_cli  # noqa: E402
from defender.baseline import load_baseline  # noqa: E402
from defender.events import verify_events  # noqa: E402
from defender import cli as defender_cli  # noqa: E402


def _run(argv: list[str]) -> tuple[int, str, str]:
    output, errors = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        code = gn_cli.main(argv)
    return code, output.getvalue(), errors.getvalue()


def _snapshot() -> dict:
    return {
        "schema_version": 1,
        "collected_at": "2026-10-13T12:00:00+00:00",
        "host": {"hostname": "test-host", "platform": "test", "machine": "x86_64"},
        "processes": [{"pid": 10, "ppid": 1, "name": "server", "exe": "/opt/server"}],
        "connections": [{"protocol": "tcp", "family": "ipv4", "local_address": "127.0.0.1",
                         "local_port": 8080, "remote_address": "", "remote_port": 0,
                         "state": "LISTEN", "pid": 10}],
        "interfaces": [], "routes": [], "services": [], "startup": [], "packages": [], "files": [],
        "file_roots": [],
        "coverage": {name: "ok" for name in ("processes", "connections", "interfaces",
                                              "routes", "services", "startup", "packages")}
                    | {"files": "not_requested"},
        "errors": [],
    }


class DefenderCliTests(unittest.TestCase):
    def test_default_private_runtime_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            self.assertEqual(defender_cli._private_runtime("win32", {"APPDATA": temp}, home),
                             (home / "GreyIQ" / "runtime").resolve())
            self.assertEqual(defender_cli._private_runtime("darwin", {}, home),
                             (home / "Library" / "Application Support" / "GreyIQ" / "runtime").resolve())
            self.assertIsNone(defender_cli._private_runtime("linux", {}, home))

    def test_alias_and_active_scan_gate_before_inventory(self) -> None:
        self.assertIn("defend", gn_cli.CLI_COMMANDS)
        self.assertIn("defender", gn_cli.CLI_COMMANDS)
        with mock.patch("defender.inventory.collect_inventory", side_effect=AssertionError("inventory ran")):
            code, _, err = _run(["defender", "scan", "--nmap-target", "8.8.8.8",
                                 "--scope", "8.8.8.8", "-y"])
        self.assertEqual(code, 2)
        self.assertIn("local/private", err)

    def test_bad_indicator_file_fails_before_collection_or_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            missing = str(Path(temp) / "missing.json")
            with mock.patch.object(defender_cli, "_runtime", return_value=Path(temp)), \
                 mock.patch("defender.inventory.collect_inventory", side_effect=AssertionError("inventory ran")), \
                 mock.patch("defender.tools.capture_tshark", side_effect=AssertionError("capture ran")):
                code, _, err = _run(["defend", "scan", "--indicators", missing,
                                     "--capture-interface", "test0", "-y"])
        self.assertEqual(code, 2)
        self.assertIn("indicator file could not be used", err)

    def test_sha256_feed_enables_bounded_process_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            feed = root / "indicators.json"
            feed.write_text(json.dumps({
                "source": "reviewed fixture", "url": "https://example.test/indicators",
                "retrieved_at": "2020-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "indicators": [{"type": "sha256", "value": "a" * 64}],
            }), encoding="utf-8")
            with mock.patch.object(defender_cli, "_runtime", return_value=root), \
                 mock.patch("defender.inventory.collect_inventory", return_value=_snapshot()) as collect:
                code, _, error = _run(["defend", "scan", "--indicators", str(feed)])
            self.assertEqual(code, 0, error)
            self.assertTrue(collect.call_args.kwargs["hash_processes"])

    def test_scan_integrates_bounded_tshark_probe_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            current = _snapshot()
            current["interfaces"] = [{"name": "test0", "addresses": ["10.0.0.2/24"]}]
            packets = [{"timestamp": f"2026-10-13T12:00:{port - 1000:02d}Z",
                        "source": "8.8.8.8", "destination": "10.0.0.2",
                        "protocol": "tcp", "destination_port": port,
                        "tcp_syn": True, "tcp_ack": False}
                       for port in range(1000, 1008)]
            capture = {"ok": True, "tool": "tshark", "status": "complete",
                       "interface": "test0", "duration_seconds": 10,
                       "finished_at": "2026-10-13T12:00:10Z", "packets": packets,
                       "flows": [], "summary": {"packet_count": 8}}
            with mock.patch.object(defender_cli, "_runtime", return_value=Path(temp)), \
                 mock.patch("defender.inventory.collect_inventory", return_value=current), \
                 mock.patch("defender.tools.capture_tshark", return_value=capture):
                code, output, error = _run(["defend", "scan", "--capture-interface",
                                            "test0", "-y", "--json"])
            self.assertEqual(code, 0, error)
            self.assertIn("defender.tcp_syn_port_probe",
                          {row["rule_id"] for row in json.loads(output)["findings"]})

    def test_baseline_scan_artifact_and_verified_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reference = _snapshot()
            changed = deepcopy(reference)
            changed["collected_at"] = "2026-10-13T12:01:00+00:00"
            changed["processes"].append({"pid": 20, "ppid": 1, "name": "share", "exe": "/opt/share"})
            changed["connections"].append({"protocol": "tcp", "family": "ipv4",
                                           "local_address": "0.0.0.0", "local_port": 445,
                                           "remote_address": "", "remote_port": 0,
                                           "state": "LISTEN", "pid": 20})
            with mock.patch.object(defender_cli, "_runtime", return_value=root), \
                 mock.patch("defender.inventory.collect_inventory", side_effect=[reference, changed]):
                create_code, _, create_err = _run(["defend", "baseline", "create",
                                                    "--accept-current-state"])
                scan_code, scan_out, scan_err = _run(["defend", "scan", "--json"])
                events_code, events_out, events_err = _run(["defend", "events", "--verify-artifacts", "--json"])
            self.assertEqual(create_code, 0, create_err)
            self.assertEqual(scan_code, 0, scan_err)
            self.assertEqual(events_code, 0, events_err)
            report = json.loads(scan_out)
            self.assertEqual(report["diff"]["summary"]["added"], 2)
            self.assertTrue(any(row["rule_id"] == "defender.risky_listener"
                                for row in report["findings"]))
            self.assertTrue(any(row["rule_id"] == "defender.endpoint_process_correlation"
                                for row in report["findings"]))
            artifact = report["artifact"]
            with gzip.open(artifact["artifact_path"], "rt", encoding="utf-8") as handle:
                saved = json.load(handle)
            self.assertEqual(saved["inventory"]["connections"], changed["connections"])
            self.assertEqual(saved["result"]["findings"], report["findings"])
            events = json.loads(events_out)
            self.assertTrue(events["verification"]["ok"])
            self.assertTrue(events["artifacts"]["ok"])
            self.assertEqual(events["artifacts"]["verified"], 1)
            self.assertEqual(events["events"][0]["evidence"]["artifact_sha256"],
                             artifact["artifact_sha256"])
            self.assertTrue(verify_events(root)["ok"])

    def test_baseline_replacement_preserves_prior_reference_and_logs_link(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = _snapshot()
            second = deepcopy(first)
            second["collected_at"] = "2026-10-13T12:10:00+00:00"
            with mock.patch.object(defender_cli, "_runtime", return_value=root), \
                 mock.patch("defender.inventory.collect_inventory", side_effect=[first, second]):
                code, _, error = _run(["defend", "baseline", "create", "--accept-current-state"])
                self.assertEqual(code, 0, error)
                prior_digest = load_baseline(root / "defender" / "baseline.json")["sha256"]
                code, output, error = _run(["defend", "baseline", "create",
                                            "--accept-current-state", "--replace", "--json"])
                self.assertEqual(code, 0, error)
                events_code, events_output, events_error = _run(["defend", "events", "--json"])
            self.assertEqual(events_code, 0, events_error)
            archive = json.loads(output)["baseline"]["archive"]
            self.assertEqual(load_baseline(archive["path"])["sha256"], prior_digest)
            latest = json.loads(events_output)[0]["evidence"]
            self.assertEqual(latest["archive_path"], archive["path"])
            self.assertEqual(latest["archive_relpath"], Path(archive["path"]).name)
            self.assertEqual(latest["prior_baseline_sha256"], prior_digest)

    def test_trace_remote_matches_exact_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            current = _snapshot()
            current["connections"] += [
                {"protocol": "tcp", "family": "ipv4", "local_address": "10.0.0.2",
                 "local_port": 50001, "remote_address": "192.0.2.1", "remote_port": 443,
                 "state": "ESTABLISHED", "pid": 10},
                {"protocol": "tcp", "family": "ipv4", "local_address": "10.0.0.2",
                 "local_port": 50002, "remote_address": "192.0.2.10", "remote_port": 443,
                 "state": "ESTABLISHED", "pid": 10},
            ]
            with mock.patch.object(defender_cli, "_runtime", return_value=Path(temp)), \
                 mock.patch("defender.inventory.collect_inventory", return_value=current):
                code, output, error = _run(["defend", "trace", "--remote", "192.0.2.1", "--json"])
            self.assertEqual(code, 0, error)
            traced = json.loads(output)
            self.assertEqual(len(traced["connections"]), 1)
            self.assertEqual(traced["connections"][0]["remote_address"], "192.0.2.1")
            self.assertIn("does not identify", traced["note"])

    def test_watch_one_cycle_and_missing_baseline_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch.object(defender_cli, "_runtime", return_value=root):
                code, _, err = _run(["defend", "watch", "--iterations", "1"])
                self.assertEqual(code, 2)
                self.assertIn("requires a reviewed baseline", err)
                with mock.patch("defender.inventory.collect_inventory", return_value=_snapshot()):
                    self.assertEqual(_run(["defend", "baseline", "create",
                                           "--accept-current-state"])[0], 0)
                    code, output, error = _run(["defend", "watch", "--iterations", "1", "--json"])
            self.assertEqual(code, 0, error)
            self.assertEqual(json.loads(output)["cycle"], 1)
            self.assertEqual(verify_events(root)["event_count"], 3)

    def test_watch_stops_if_baseline_disappears_between_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "defender" / "baseline.json"
            with mock.patch.object(defender_cli, "_runtime", return_value=root), \
                 mock.patch("defender.inventory.collect_inventory", return_value=_snapshot()):
                self.assertEqual(_run(["defend", "baseline", "create",
                                       "--accept-current-state"])[0], 0)
                with mock.patch("time.sleep", side_effect=lambda _: baseline.unlink()):
                    code, output, error = _run(["defend", "watch", "--iterations", "2", "--json"])
            self.assertEqual(code, 2)
            self.assertEqual(len(output.splitlines()), 1)
            self.assertEqual(json.loads(output)["cycle"], 1)
            self.assertIn("watch baseline disappeared", error)
            events = verify_events(root)
            self.assertTrue(events["ok"])
            self.assertEqual(events["event_count"], 3)

    def test_evidence_budget_stops_without_deleting_existing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(defender_cli, "_runtime", return_value=Path(temp)), \
                 mock.patch.object(defender_cli, "_MAX_RUN_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "evidence budget reached"):
                    defender_cli._artifact("test", {"value": "sample"})
            self.assertEqual(list((Path(temp) / "defender" / "runs").iterdir()), [])

    def test_watch_stops_after_active_tool_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch.object(defender_cli, "_runtime", return_value=root), \
                 mock.patch("defender.inventory.collect_inventory", return_value=_snapshot()):
                self.assertEqual(_run(["defend", "baseline", "create",
                                       "--accept-current-state"])[0], 0)
            failed = {"tools": {"tshark": {"ok": False, "status": "tool_error"}},
                      "at": "2026-10-13T12:00:00+00:00", "host": {}, "baseline": str(root / "defender" / "baseline.json"),
                      "inventory": {}, "diff": None, "findings": [], "artifact": {}}
            with mock.patch.object(defender_cli, "_runtime", return_value=root), \
                 mock.patch.object(defender_cli, "_scan_once", return_value=failed) as scan, \
                 mock.patch("time.sleep", side_effect=AssertionError("watch retried")):
                code, output, error = _run(["defend", "watch", "--iterations", "5",
                                            "--capture-interface", "test0", "-y", "--json"])
            self.assertEqual(code, 1, error)
            self.assertEqual(json.loads(output)["cycle"], 1)
            scan.assert_called_once()
            self.assertEqual(verify_events(root)["event_count"], 2)

    def test_events_verify_reports_corrupt_journal_as_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch.object(defender_cli, "_runtime", return_value=root), \
                 mock.patch("defender.inventory.collect_inventory", return_value=_snapshot()):
                self.assertEqual(_run(["defend", "inventory"])[0], 0)
            journal = root / "defender" / "events.jsonl"
            journal.write_bytes(journal.read_bytes()[:-1])
            with mock.patch.object(defender_cli, "_runtime", return_value=root):
                code, output, error = _run(["defend", "events", "--verify", "--json"])
            self.assertEqual(code, 1, error)
            self.assertFalse(json.loads(output)["verification"]["ok"])


if __name__ == "__main__":
    unittest.main()
