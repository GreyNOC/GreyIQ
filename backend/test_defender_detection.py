"""Focused negative controls for local defender rule evaluation."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from defender.detection import (  # noqa: E402
    detect_tcp_syn_probes, evaluate_homeguard_devices, evaluate_inventory, list_rules,
    load_indicators, match_indicators,
)


class DefenderDetectionTests(unittest.TestCase):
    def test_risky_loopback_listener_is_not_claimed_externally_exposed(self) -> None:
        inventory = {
            "collected_at": "2026-10-13T12:00:00Z",
            "processes": [{"pid": 42, "ppid": 4, "name": "filesvc", "exe": "/usr/bin/filesvc"}],
            "connections": [
                {"protocol": "tcp", "family": "ipv4", "local_address": "127.0.0.1", "local_port": 445,
                 "remote_address": "", "state": "LISTEN", "pid": 42},
            ],
        }
        diff = {"sections": {"listeners": {"added": [
            {"protocol": "tcp", "family": "ipv4", "local_address": "127.0.0.1", "local_port": 445,
             "process_exe": "/usr/bin/filesvc"}
        ]}}}
        findings = evaluate_inventory(inventory, diff)
        self.assertEqual({f["rule_id"] for f in findings}, {"defender.risky_listener", "defender.new_listener"})
        risky = next(f for f in findings if f["rule_id"] == "defender.risky_listener")
        self.assertEqual(risky["severity"], "low")
        self.assertTrue(risky["evidence"]["loopback_only"])
        self.assertIn("does not show exposure", risky["explanation"])

    def test_non_loopback_risky_listener_carries_pid_and_process(self) -> None:
        inventory = {
            "processes": [{"pid": 123, "name": "remote", "exe": "/opt/remote"}],
            "connections": [{"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 23,
                             "remote_address": "", "state": "LISTEN", "pid": 123}],
        }
        findings = evaluate_inventory(inventory)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertFalse(findings[0]["evidence"]["loopback_only"])
        self.assertEqual(findings[0]["evidence"]["pid"], 123)
        self.assertEqual(findings[0]["evidence"]["process_name"], "remote")
        self.assertEqual(findings[0]["assessment"], "review_indicator")

    def test_first_snapshot_does_not_invent_new_listener(self) -> None:
        inventory = {"processes": [], "connections": [{"protocol": "tcp", "local_address": "127.0.0.1",
                                                       "local_port": 9876, "state": "LISTEN", "pid": 1}]}
        self.assertEqual(evaluate_inventory(inventory), [])
        self.assertIn("defender.new_listener", {r["rule_id"] for r in list_rules()})

    def test_changed_ephemeral_udp_binding_does_not_emit_listener_finding(self) -> None:
        inventory = {
            "processes": [{"pid": 9, "name": "dns-client", "exe": "/usr/bin/dns-client"}],
            "connections": [{"protocol": "udp", "local_address": "0.0.0.0",
                             "local_port": 54555, "remote_address": "", "state": "BOUND", "pid": 9}],
        }
        # Even if an older baseline/diff supplied the row as a listener,
        # detection independently refuses the weak UDP service inference.
        diff = {"sections": {"listeners": {"added": [
            {"protocol": "udp", "local_address": "0.0.0.0", "local_port": 54555,
             "process_exe": "/usr/bin/dns-client"}
        ]}}}
        self.assertEqual(evaluate_inventory(inventory, diff), [])

    def test_persistence_and_process_path_changes_are_review_indicators(self) -> None:
        inventory = {
            "processes": [{"pid": 91, "ppid": 2, "name": "setup", "exe": "C:/Users/Test/Downloads/setup.exe"}],
            "connections": [],
        }
        diff = {"sections": {
            "startup": {"added": [{"name": "Updater", "location": "HKCU\\Run"}]},
            "services": {"added": [{"name": "UpdaterSvc", "start_type": "Automatic", "status": "running"}]},
            "processes": {"added": [{"name": "setup", "exes": ["C:/Users/Test/Downloads/setup.exe"], "count": 1}],
                          "changed": [{"before": {"name": "agent", "exes": ["C:/old/agent.exe"]},
                                       "after": {"name": "agent", "exes": ["C:/new/agent.exe"]}}]},
        }}
        ids = {item["rule_id"] for item in evaluate_inventory(inventory, diff)}
        self.assertEqual(ids, {"defender.new_startup_entry", "defender.new_auto_service",
                               "defender.executable_path_change", "defender.process_in_temp"})

    def test_same_name_persistence_definition_drift_requires_two_hashes(self) -> None:
        inventory = {"processes": [], "connections": []}
        before_service = {"name": "UpdaterSvc", "status": "running", "start_type": "auto",
                          "definition_sha256": "a" * 64, "definition_status": "hashed",
                          "Command": "secret=do-not-log"}
        after_service = {**before_service, "definition_sha256": "b" * 64}
        before_startup = {"name": "Updater", "location": "HKCU\\Run",
                          "definition_sha256": "c" * 64, "definition_status": "hashed"}
        after_startup = {**before_startup, "definition_sha256": "d" * 64}
        diff = {"sections": {
            "services": {"changed": [
                {"before": before_service, "after": after_service},
                {"before": {**before_service, "name": "StatusOnly"},
                 "after": {**before_service, "name": "StatusOnly", "status": "stopped"}},
                {"before": {**before_service, "name": "Unknown", "definition_sha256": ""},
                 "after": {**after_service, "name": "Unknown", "definition_status": "unavailable"}},
            ]},
            "startup": {"changed": [{"before": before_startup, "after": after_startup}]},
        }}
        findings = evaluate_inventory(inventory, diff)
        self.assertEqual({item["rule_id"] for item in findings}, {
            "defender.service_definition_change", "defender.startup_definition_change"})
        self.assertEqual({item["assessment"] for item in findings}, {"review_indicator"})
        self.assertNotIn("secret=do-not-log", json.dumps(findings))
        self.assertNotIn("a" * 64, json.dumps(findings))
        self.assertIn("defender.service_definition_change", {rule["rule_id"] for rule in list_rules()})

    def test_new_or_redefined_persistence_matches_running_staging_executable(self) -> None:
        inventory = {"processes": [
            {"pid": 101, "name": "setup.exe", "exe": "C:/USERS/Test/Downloads/setup.exe"},
            {"pid": 202, "name": "agent", "exe": "/tmp/agent"},
        ], "connections": []}
        diff = {"sections": {
            "startup": {"added": [
                {"name": "Updater", "location": "HKCU\\Run",
                 "target_path": "C:\\Users\\Test\\Downloads\\setup.exe"},
                {"name": "Other", "location": "HKCU\\Run", "target_path": "C:\\Apps\\other.exe"},
            ]},
            "services": {"changed": [{
                "before": {"name": "Agent", "start_type": "enabled",
                           "definition_sha256": "a" * 64, "definition_status": "hashed",
                           "target_path": "/usr/bin/agent"},
                "after": {"name": "Agent", "start_type": "enabled",
                          "definition_sha256": "b" * 64, "definition_status": "hashed",
                          "target_path": "/tmp/agent"},
            }]},
        }}
        correlations = [row for row in evaluate_inventory(inventory, diff)
                        if row["rule_id"] == "defender.active_staging_persistence"]
        self.assertEqual(len(correlations), 2)
        self.assertEqual({tuple(row["evidence"]["pids"]) for row in correlations}, {(101,), (202,)})
        self.assertEqual({row["evidence"]["change_type"] for row in correlations},
                         {"added", "definition_changed"})
        self.assertTrue(all(row["assessment"] == "review_indicator" for row in correlations))

        # An entry in a staging directory is not enough: it must match an
        # observed running executable and have baseline-supported drift.
        no_match = {"sections": {"startup": {"added": [
            {"name": "Mismatch", "location": "HKCU\\Run",
             "target_path": "C:\\Users\\Test\\Downloads\\different.exe"}
        ]}}}
        self.assertFalse(any(row["rule_id"] == "defender.active_staging_persistence"
                             for row in evaluate_inventory(inventory, no_match)))
        self.assertFalse(any(row["rule_id"] == "defender.active_staging_persistence"
                             for row in evaluate_inventory(inventory)))
        capped = "C:\\Users\\Test\\Downloads\\" + "a" * 1000 + ".exe"
        long_inventory = {"processes": [{"pid": 303, "exe": capped[:1024]}], "connections": []}
        long_diff = {"sections": {"startup": {"added": [
            {"name": "Long", "location": "HKCU\\Run", "target_path": capped}
        ]}}}
        self.assertFalse(any(row["rule_id"] == "defender.active_staging_persistence"
                             for row in evaluate_inventory(long_inventory, long_diff)))

    def test_tshark_syn_probe_requires_external_source_and_eight_local_ports(self) -> None:
        inventory = {"interfaces": [{"name": "eth0", "addresses": ["192.168.1.10/24"]}]}

        def packet(port: int, second: int, *, source: str = "8.8.8.8",
                   destination: str = "192.168.1.10", syn: bool = True,
                   ack: bool = False) -> dict[str, Any]:
            return {"timestamp": f"2026-10-13T12:00:{second:02d}Z", "source": source,
                    "destination": destination, "protocol": "tcp", "destination_port": port,
                    "tcp_syn": syn, "tcp_ack": ack}

        def capture(rows: list[dict[str, Any]]) -> dict[str, Any]:
            return {"ok": True, "tool": "tshark", "interface": "eth0",
                    "duration_seconds": 30, "packets": rows}

        positive = detect_tcp_syn_probes(capture([packet(port, index) for index, port in enumerate(range(20, 28))]), inventory)
        self.assertEqual(len(positive), 1)
        self.assertEqual(positive[0]["rule_id"], "defender.tcp_syn_port_probe")
        self.assertEqual(positive[0]["evidence"]["distinct_port_count"], 8)
        self.assertEqual(positive[0]["evidence"]["source_ip"], "8.8.8.8")
        self.assertEqual(positive[0]["assessment"], "review_indicator")
        self.assertIn("does not prove an intrusion", positive[0]["explanation"])

        negative_rows = (
            [packet(port, index) for index, port in enumerate(range(20, 27))],
            [packet(22, index) for index in range(8)],
            [packet(port, index, source="192.168.1.11") for index, port in enumerate(range(20, 28))],
            [packet(port, index, destination="192.168.1.99") for index, port in enumerate(range(20, 28))],
            [packet(port, index, ack=True) for index, port in enumerate(range(20, 28))],
            [packet(port, index * 5) for index, port in enumerate(range(20, 28))],
        )
        for rows in negative_rows:
            with self.subTest(first=rows[0], last=rows[-1]):
                self.assertEqual(detect_tcp_syn_probes(capture(rows), inventory), [])
        self.assertEqual(detect_tcp_syn_probes({"ok": False, "tool": "tshark"}, inventory), [])
        self.assertEqual(detect_tcp_syn_probes({"ok": True, "tool": "tshark", "packets": [],
                                                "duration_seconds": 31}, inventory), [])

    def test_same_path_executable_hash_drift_needs_two_valid_hashes(self) -> None:
        inventory = {"processes": [], "connections": []}
        base = {"name": "agent", "exe": "/opt/agent", "exes": ["/opt/agent"], "count": 1}

        def diff(old: dict[str, str], new: dict[str, str]) -> dict[str, Any]:
            return {"sections": {"processes": {"changed": [{
                "before": {**base, "sha256_by_exe": old},
                "after": {**base, "sha256_by_exe": new},
            }]}}}

        positive = evaluate_inventory(inventory, diff({"/opt/agent": "a" * 64},
                                                      {"/opt/agent": "b" * 64}))
        self.assertEqual(len(positive), 1)
        self.assertEqual(positive[0]["rule_id"], "defender.executable_hash_change")
        self.assertEqual(positive[0]["evidence"]["exe"], "/opt/agent")
        self.assertIn("does not prove the in-memory process image changed", positive[0]["explanation"])

        for old, new in (
            ({}, {"/opt/agent": "b" * 64}),
            ({"/opt/agent": "a" * 64}, {}),
            ({"/opt/agent": "not-a-hash"}, {"/opt/agent": "b" * 64}),
            ({"/opt/agent": "a" * 64}, {"/opt/agent": "a" * 64}),
            ({"/opt/agent": "a" * 64}, {"/opt/other": "b" * 64}),
        ):
            with self.subTest(old=old, new=new):
                self.assertEqual(evaluate_inventory(inventory, diff(old, new)), [])

    def test_single_watched_file_change_is_negative_control_for_burst(self) -> None:
        before = {"path": "/watched/one", "sha256": "a" * 64, "status": "hashed"}
        after = {"path": "/watched/one", "sha256": "b" * 64, "status": "hashed"}
        inventory = {"processes": [], "connections": [], "files": [after] + [
            {"path": f"/watched/{i}", "sha256": "c" * 64, "status": "hashed"} for i in range(39)
        ]}
        diff = {"file_roots": ["/watched"], "sections": {"files": {
            "changed": [{"before": before, "after": after}], "removed": [], "added": [],
        }}}
        self.assertEqual(evaluate_inventory(inventory, diff), [])

    def test_watched_file_change_burst_is_labeled_for_review(self) -> None:
        changes = [{"before": {"path": f"/watched/{i}", "sha256": "a" * 64, "status": "hashed"},
                    "after": {"path": f"/watched/{i}", "sha256": "b" * 64, "status": "hashed"}}
                   for i in range(10)]
        inventory = {"processes": [], "connections": [], "files": [
            {"path": f"/watched/{i}", "sha256": "b" * 64, "status": "hashed"} for i in range(40)
        ]}
        diff = {"file_roots": ["/watched"], "sections": {"files": {
            "changed": changes, "removed": [], "added": [],
        }}}
        findings = evaluate_inventory(inventory, diff)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "defender.file_integrity_burst")
        self.assertEqual(findings[0]["evidence"]["affected_count"], 10)
        self.assertIn("not proof of ransomware", findings[0]["explanation"])

    def test_ioc_feed_requires_fresh_provenance_and_exact_matches(self) -> None:
        now = datetime(2026, 10, 13, tzinfo=timezone.utc)
        payload = {
            "source": "Analyst-reviewed test list", "url": "https://example.test/indicators",
            "retrieved_at": "2026-10-12T00:00:00Z", "expires_at": "2026-10-20T00:00:00Z",
            "indicators": [
                {"type": "ip", "value": "203.0.113.7"},
                {"type": "domain", "value": "bad.example"},
                {"type": "sha256", "value": "A" * 64},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ioc.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            feed = load_indicators(path, now=now)
        inventory = {
            "processes": [{"pid": 1, "name": "worker", "sha256": "a" * 64}],
            "connections": [
                {"remote_address": "203.0.113.7", "remote_port": 443, "pid": 1},
                {"remote_address": "prefix.bad.example", "remote_port": 443, "pid": 1},
                {"remote_address": "bad.example", "remote_port": 443, "pid": 1},
            ],
        }
        findings = match_indicators(inventory, feed, now=now)
        self.assertEqual(len(findings), 3)
        self.assertEqual({f["evidence"]["indicator_type"] for f in findings}, {"ip", "domain", "sha256"})
        self.assertTrue(all("actor" in f["explanation"] or "false positives" in f["explanation"] for f in findings))
        with self.assertRaisesRegex(ValueError, "expired"):
            match_indicators(inventory, feed, now=datetime(2026, 10, 21, tzinfo=timezone.utc))

    def test_lazy_homeguard_adapter_bridges_real_engine_shape(self) -> None:
        # A stub package proves that no HomeGuard import is required at boot
        # and that explicit evaluation calls the package API with our devices.
        package = ModuleType("greynoc_homeguard")
        package.__path__ = []  # type: ignore[attr-defined]
        baseline_mod = ModuleType("greynoc_homeguard.baseline")
        definitions_mod = ModuleType("greynoc_homeguard.definitions")
        detection_mod = ModuleType("greynoc_homeguard.detection")
        models_mod = ModuleType("greynoc_homeguard.models")

        class FakeBaseline:
            def __init__(self, path: str | Path):
                self.path = path

            def load(self) -> "FakeBaseline":
                return self

        class FakeDefinitions:
            def load(self) -> dict:
                return {"definitions_version": "test"}

        class FakeDevice:
            @classmethod
            def from_dict(cls, row: dict) -> dict:
                return row

        class FakeFinding:
            def as_dict(self) -> dict:
                return {"rule_id": "new_device", "evidence": {"ip": "192.0.2.1"}}

        class FakeEngine:
            def __init__(self, definitions: dict):
                self.definitions = definitions

            def evaluate(self, devices: list, baseline: Any) -> list:
                self_test.assertEqual(devices, [{"ip": "192.0.2.1"}])
                self_test.assertIsNone(baseline)
                return [FakeFinding()]

        self_test = self
        baseline_mod.BaselineStore = FakeBaseline  # type: ignore[attr-defined]
        definitions_mod.DefinitionManager = FakeDefinitions  # type: ignore[attr-defined]
        detection_mod.HomeGuardDetectionEngine = FakeEngine  # type: ignore[attr-defined]
        models_mod.Device = FakeDevice  # type: ignore[attr-defined]
        modules = {"greynoc_homeguard": package, "greynoc_homeguard.baseline": baseline_mod,
                   "greynoc_homeguard.definitions": definitions_mod,
                   "greynoc_homeguard.detection": detection_mod, "greynoc_homeguard.models": models_mod}
        with patch.dict(sys.modules, modules):
            findings = evaluate_homeguard_devices([{"ip": "192.0.2.1"}])
        self.assertEqual(findings[0]["source"], "homeguard_optional_engine")
        self.assertEqual(findings[0]["assessment"], "review_indicator")

    def test_ioc_matching_uses_only_exact_tshark_flow_ips(self) -> None:
        now = datetime(2026, 10, 13, tzinfo=timezone.utc)
        feed = {
            "source": "Reviewed test feed", "url": "https://example.test/feed",
            "retrieved_at": "2026-10-12T00:00:00Z", "expires_at": "2026-10-20T00:00:00Z",
            "indicators": [{"type": "ip", "value": "203.0.113.9"},
                           {"type": "domain", "value": "bad.example"}],
        }
        inventory = {"connections": [], "processes": [], "flows": [
            {"source": "192.0.2.4", "destination": "203.0.113.9", "protocol": "tcp",
             "source_port": 51515, "destination_port": 443, "packets": 3},
            {"source": "192.0.2.4", "destination": "bad.example", "protocol": "tcp",
             "source_port": 51516, "destination_port": 443, "packets": 1},
        ]}
        findings = match_indicators(inventory, feed, now=now)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "tshark_flow")
        self.assertEqual(findings[0]["evidence"]["observation_source"], "tshark_flow")
        self.assertEqual(findings[0]["evidence"]["observed_endpoint"], "destination")
        self.assertEqual(findings[0]["evidence"]["packet_count"], 3)
        self.assertIn("does not reveal payload", findings[0]["explanation"])


if __name__ == "__main__":
    unittest.main()
