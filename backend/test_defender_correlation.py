"""Strict process/socket correlation with negative controls; no live probes."""

from __future__ import annotations

import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from defender.correlation import correlate_endpoint_changes  # noqa: E402


def _case() -> tuple[dict, dict]:
    inventory = {
        "collected_at": "2026-10-13T12:00:00Z",
        "host": {"platform": "linux"},
        "processes": [
            {"pid": 41, "ppid": 1, "name": "edge-agent", "exe": "/opt/edge-agent"},
            {"pid": 77, "ppid": 1, "name": "other", "exe": "/opt/other"},
        ],
        "connections": [
            {"protocol": "tcp", "family": "ipv4", "local_address": "0.0.0.0",
             "local_port": 8443, "remote_address": "", "remote_port": 0,
             "state": "LISTEN", "pid": 41, "payload": "do-not-emit"},
            {"protocol": "tcp", "family": "ipv4", "local_address": "10.0.0.2",
             "local_port": 50123, "remote_address": "203.0.113.5", "remote_port": 443,
             "state": "ESTABLISHED", "pid": 41},
        ],
    }
    diff = {
        "baseline_created_at": "2026-10-12T12:00:00Z",
        "sections": {
            "listeners": {"added": [
                {"protocol": "tcp", "family": "ipv4", "local_address": "0.0.0.0",
                 "local_port": 8443, "process_name": "edge-agent", "process_exe": "/opt/edge-agent"},
            ]},
            "processes": {"added": [
                {"name": "edge-agent", "exes": ["/opt/edge-agent"], "count": 1},
            ], "changed": []},
        },
    }
    return inventory, diff


class DefenderCorrelationTests(unittest.TestCase):
    def test_exact_new_listener_and_process_join_includes_same_pid_peers(self) -> None:
        inventory, diff = _case()
        results = correlate_endpoint_changes(inventory, diff)
        self.assertEqual(len(results), 1)
        finding = results[0]
        self.assertEqual(finding["rule_id"], "defender.endpoint_process_correlation")
        self.assertEqual(finding["assessment"], "review_indicator")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["evidence"]["pid"], 41)
        self.assertEqual(finding["evidence"]["process_change"], "new_process")
        self.assertEqual(finding["evidence"]["remote_peers_sample"],
                         [{"address": "203.0.113.5", "port": 443}])
        self.assertIn("direction is unknown", finding["explanation"])
        self.assertIn("firewall", finding["explanation"])
        self.assertNotIn("do-not-emit", json.dumps(finding))

    def test_same_pid_reviewed_ioc_enriches_without_actor_attribution(self) -> None:
        inventory, diff = _case()
        iocs = [
            {"rule_id": "defender.ioc_match", "source": "reviewed_local_ioc",
             "evidence": {"pid": 41, "indicator_type": "ip", "indicator_value": "203.0.113.5"}},
            {"rule_id": "defender.ioc_match", "source": "reviewed_local_ioc",
             "evidence": {"pid": 77, "indicator_type": "ip", "indicator_value": "192.0.2.7"}},
            {"rule_id": "defender.ioc_match", "source": "tshark_flow",
             "evidence": {"indicator_type": "ip", "indicator_value": "198.51.100.9"}},
        ]
        finding = correlate_endpoint_changes(inventory, diff, iocs)[0]
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["evidence"]["reviewed_ioc_matches"],
                         [{"type": "ip", "value": "203.0.113.5"}])
        self.assertIn("shared infrastructure", finding["explanation"])
        self.assertNotIn("actor identity", finding["title"])

    def test_changed_executable_path_must_match_current_owner_exactly(self) -> None:
        inventory, diff = _case()
        diff["sections"]["processes"] = {"added": [], "changed": [{
            "before": {"name": "edge-agent", "exes": ["/usr/bin/edge-agent"]},
            "after": {"name": "edge-agent", "exes": ["/opt/edge-agent"]},
        }]}
        results = correlate_endpoint_changes(inventory, diff)
        self.assertEqual(results[0]["evidence"]["process_change"], "executable_path_changed")
        diff["sections"]["processes"]["changed"][0]["after"]["exes"] = ["/opt/not-the-owner"]
        self.assertEqual(correlate_endpoint_changes(inventory, diff), [])

    def test_existing_listener_repointed_to_new_executable_is_correlated(self) -> None:
        inventory, diff = _case()
        before = {"protocol": "tcp", "family": "ipv4", "local_address": "0.0.0.0",
                  "local_port": 8443, "process_name": "edge-agent", "process_exe": "/usr/bin/edge-agent"}
        after = diff["sections"]["listeners"]["added"].pop()
        diff["sections"]["listeners"]["changed"] = [{"before": before, "after": after}]
        diff["sections"]["processes"] = {"added": [], "changed": [{
            "before": {"name": "edge-agent", "exes": ["/usr/bin/edge-agent"]},
            "after": {"name": "edge-agent", "exes": ["/opt/edge-agent"]},
        }]}
        finding = correlate_endpoint_changes(inventory, diff)[0]
        self.assertEqual(finding["evidence"]["listener_change"], "owner_executable_changed")
        self.assertEqual(finding["evidence"]["process_change"], "executable_path_changed")

    def test_no_baseline_loopback_udp_and_count_only_drift_are_negative_controls(self) -> None:
        inventory, diff = _case()
        self.assertEqual(correlate_endpoint_changes(inventory, None), [])
        loopback = deepcopy(inventory)
        loopback["connections"][0]["local_address"] = "127.0.0.1"
        loopback_diff = deepcopy(diff)
        loopback_diff["sections"]["listeners"]["added"][0]["local_address"] = "127.0.0.1"
        self.assertEqual(correlate_endpoint_changes(loopback, loopback_diff), [])
        udp = deepcopy(inventory)
        udp["connections"][0]["protocol"] = "udp"
        udp["connections"][0]["state"] = "BOUND"
        udp_diff = deepcopy(diff)
        udp_diff["sections"]["listeners"]["added"][0]["protocol"] = "udp"
        self.assertEqual(correlate_endpoint_changes(udp, udp_diff), [])
        count_only = deepcopy(diff)
        count_only["sections"]["processes"] = {"added": [], "changed": [{
            "before": {"name": "edge-agent", "exes": ["/opt/edge-agent"], "count": 1},
            "after": {"name": "edge-agent", "exes": ["/opt/edge-agent"], "count": 2},
        }]}
        self.assertEqual(correlate_endpoint_changes(inventory, count_only), [])

    def test_diff_owner_mismatch_and_ambiguous_pid_are_negative_controls(self) -> None:
        inventory, diff = _case()
        wrong_owner = deepcopy(diff)
        wrong_owner["sections"]["listeners"]["added"][0]["process_exe"] = "/opt/other"
        self.assertEqual(correlate_endpoint_changes(inventory, wrong_owner), [])
        no_owner = deepcopy(inventory)
        no_owner["connections"][0]["pid"] = None
        self.assertEqual(correlate_endpoint_changes(no_owner, diff), [])

    def test_windows_name_and_path_matching_is_case_insensitive(self) -> None:
        inventory, diff = _case()
        inventory["host"]["platform"] = "WIN32"
        inventory["processes"][0]["name"] = "Edge-Agent"
        inventory["processes"][0]["exe"] = "C:\\Apps\\Edge.EXE"
        diff["sections"]["listeners"]["added"][0]["process_exe"] = "c:\\apps\\edge.exe"
        diff["sections"]["processes"]["added"][0]["exes"] = ["c:\\apps\\edge.exe"]
        self.assertEqual(len(correlate_endpoint_changes(inventory, diff)), 1)

    def test_finding_id_survives_pid_churn_and_peer_sample_is_bounded(self) -> None:
        inventory, diff = _case()
        inventory["connections"] += [
            {"protocol": "tcp", "remote_address": f"198.51.100.{address}",
             "remote_port": 443, "pid": 41} for address in range(1, 13)
        ]
        before = correlate_endpoint_changes(inventory, diff)[0]
        self.assertEqual(before["evidence"]["remote_peer_count"], 13)
        self.assertEqual(len(before["evidence"]["remote_peers_sample"]), 8)
        later = deepcopy(inventory)
        later["processes"][0]["pid"] = 99
        for row in later["connections"]:
            if row.get("pid") == 41:
                row["pid"] = 99
        after = correlate_endpoint_changes(later, diff)[0]
        self.assertEqual(after["evidence"]["pid"], 99)
        self.assertEqual(before["finding_id"], after["finding_id"])


if __name__ == "__main__":
    unittest.main()
