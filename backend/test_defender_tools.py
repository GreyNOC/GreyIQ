"""Safety and parser tests for opt-in local nmap/TShark adapters.

All external tool calls are mocked. This suite never scans or captures traffic.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from defender import tools  # noqa: E402


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.96">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/></port>
    </ports>
  </host>
</nmaprun>
"""


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


class NmapAdapterTests(unittest.TestCase):
    def test_pure_scope_guard_accepts_only_bounded_local_pairs(self) -> None:
        self.assertIsNone(tools.validate_nmap_scope("127.0.0.1", "127.0.0.1"))
        self.assertIsNone(tools.validate_nmap_scope("192.168.1.0/28", "192.168.1.0/24"))
        self.assertIsNone(tools.validate_nmap_scope("fd00::1", "fd00::/124"))
        for target, scope in (
            ("8.8.8.8", "8.8.8.8"),
            ("192.168.1.10", "192.168.1.11"),
            ("192.168.1.0/24", "192.168.1.0/24"),
            ("192.168.1.10", "192.168.0.0/16"),
        ):
            with self.subTest(target=target, scope=scope):
                self.assertIsInstance(tools.validate_nmap_scope(target, scope), str)

    def test_authorization_scope_and_local_address_guards_precede_tool_lookup(self) -> None:
        cases = (
            {"target": "192.168.1.10", "scope": "192.168.1.10"},
            {"target": "8.8.8.8", "scope": "8.8.8.8", "authorized": True},
            {"target": "example.com", "scope": "example.com", "authorized": True},
            {"target": "192.168.1.10", "scope": "192.168.1.11", "authorized": True},
            {"target": "192.168.1.0/24", "scope": "192.168.1.0/24", "authorized": True},
            {"target": "192.168.1.1; echo bad", "scope": "192.168.1.1", "authorized": True},
            {"target": "192.168.1.0/28", "scope": "10.0.0.0/8", "authorized": True},
        )
        with mock.patch.object(tools.shutil, "which") as which, \
             mock.patch.object(tools.subprocess, "run") as run:
            for kwargs in cases:
                with self.subTest(kwargs=kwargs):
                    result = tools.run_nmap(**kwargs)
                    self.assertFalse(result["ok"])
                    self.assertEqual(result["status"], "denied")
            which.assert_not_called()
            run.assert_not_called()

    def test_missing_tool_is_a_distinct_nonfatal_result(self) -> None:
        with mock.patch.object(tools.shutil, "which", return_value=None), \
             mock.patch.object(tools.subprocess, "run") as run:
            result = tools.run_nmap("127.0.0.1", authorized=True, scope="127.0.0.1")
        self.assertEqual(result["status"], "tool_missing")
        run.assert_not_called()

    def test_bounded_tcp_scan_parses_only_scoped_host_and_open_ports(self) -> None:
        with mock.patch.object(tools.shutil, "which", return_value="nmap"), \
             mock.patch.object(tools.subprocess, "run", return_value=_completed(NMAP_XML)) as run:
            result = tools.run_nmap("192.168.1.10", authorized=True,
                                    scope="192.168.1.0/28", timeout=15)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tool_version"], "7.96")
        self.assertEqual(result["summary"], {"host_count": 1, "up_hosts": 1, "open_ports": 1})
        self.assertEqual(result["hosts"][0]["address"], "192.168.1.10")
        self.assertEqual(result["hosts"][0]["state"], "up")
        self.assertEqual([port["port"] for port in result["hosts"][0]["ports"]], [22, 443])
        command = run.call_args.args[0]
        self.assertEqual(command[-1], "192.168.1.10")
        self.assertIn("-sT", command)
        self.assertIn("-n", command)
        self.assertIn("--max-rate", command)
        self.assertNotIn("--script", command)
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        self.assertEqual(run.call_args.kwargs["timeout"], 15)

    def test_xml_declarations_and_out_of_scope_hosts_are_rejected(self) -> None:
        bad_xml = (
            '<!DOCTYPE nmaprun [<!ENTITY x "bad">]><nmaprun/>',
            NMAP_XML.replace("192.168.1.10", "192.168.1.11"),
            "<other/>",
        )
        with mock.patch.object(tools.shutil, "which", return_value="nmap"):
            for xml in bad_xml:
                with self.subTest(xml=xml[:32]):
                    with mock.patch.object(tools.subprocess, "run", return_value=_completed(xml)):
                        result = tools.run_nmap("192.168.1.10", authorized=True,
                                                scope="192.168.1.0/28")
                    self.assertEqual(result["status"], "invalid_output")

    def test_timeout_is_bounded_and_does_not_leak_tool_output(self) -> None:
        with mock.patch.object(tools.shutil, "which", return_value="nmap"), \
             mock.patch.object(tools.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("nmap", 5, output=b"SECRET")):
            result = tools.run_nmap("127.0.0.1", authorized=True, scope="127.0.0.1",
                                    timeout=5)
        self.assertEqual(result["status"], "timeout")
        self.assertNotIn("SECRET", json.dumps(result))


class TSharkAdapterTests(unittest.TestCase):
    def test_interface_and_capture_limits_precede_tool_lookup(self) -> None:
        cases = (
            {"interface": "eth0"},
            {"interface": "any", "authorized": True},
            {"interface": "rpcap://remote", "authorized": True},
            {"interface": "-i", "authorized": True},
            {"interface": "eth0\nother", "authorized": True},
            {"interface": "eth0", "authorized": True, "seconds": 31},
            {"interface": "eth0", "authorized": True, "packet_limit": 1001},
            {"interface": "eth0", "authorized": True, "seconds": 10, "timeout": 5},
        )
        with mock.patch.object(tools.shutil, "which") as which, \
             mock.patch.object(tools.subprocess, "run") as run:
            for kwargs in cases:
                with self.subTest(kwargs=kwargs):
                    self.assertEqual(tools.capture_tshark(**kwargs)["status"], "denied")
            which.assert_not_called()
            run.assert_not_called()

    def test_missing_tool_is_distinct(self) -> None:
        with mock.patch.object(tools.shutil, "which", return_value=None), \
             mock.patch.object(tools.subprocess, "run") as run:
            result = tools.capture_tshark("Ethernet 2", authorized=True)
        self.assertEqual(result["status"], "tool_missing")
        run.assert_not_called()

    def test_capture_returns_metadata_and_directional_flow_summary_without_payload(self) -> None:
        # Timestamp, addresses, ports, IP protocol, frame length, TCP SYN/ACK.
        rows = (
            "1760350000.100,192.168.1.10,,93.184.216.34,,52300,443,,,6,,100,1,0\n"
            "1760350001.200,192.168.1.10,,93.184.216.34,,52300,443,,,6,,150,0,1\n"
            "1760350002.300,93.184.216.34,,192.168.1.10,,443,52300,,,6,,80,1,1\n"
            "SECRET,payload,never,valid\n"
        )
        calls = [_completed(rows), _completed("TShark (Wireshark) 4.4.1")]
        with mock.patch.object(tools.shutil, "which", return_value="tshark"), \
             mock.patch.object(tools.subprocess, "run", side_effect=calls) as run:
            result = tools.capture_tshark("eth0", authorized=True, seconds=2, packet_limit=8)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tool_version"], "4.4.1")
        self.assertEqual(result["summary"], {"packet_count": 3, "flow_count": 2,
                                              "invalid_rows": 1, "total_bytes": 330})
        self.assertEqual(result["flows"][0]["packets"], 2)
        self.assertEqual(result["flows"][0]["bytes"], 250)
        self.assertEqual(result["flows"][0]["syn_only_packets"], 1)
        self.assertEqual(result["packets"][0]["tcp_syn"], True)
        self.assertEqual(result["packets"][0]["tcp_ack"], False)
        self.assertEqual(result["duration_seconds"], 2)
        self.assertNotIn("SECRET", json.dumps(result))
        capture_command = run.call_args_list[0].args[0]
        self.assertEqual(capture_command[:5], ["tshark", "-n", "-p", "-i", "eth0"])
        self.assertIn("duration:2", capture_command)
        self.assertIn("frame.len", capture_command)
        self.assertIn("tcp.flags.syn", capture_command)
        self.assertIn("tcp.flags.ack", capture_command)
        self.assertNotIn("data.data", capture_command)
        self.assertNotIn("-w", capture_command)
        self.assertFalse(run.call_args_list[0].kwargs.get("shell", False))

    def test_capture_timeout_does_not_return_partial_payload(self) -> None:
        with mock.patch.object(tools.shutil, "which", return_value="tshark"), \
             mock.patch.object(tools.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("tshark", 3, output=b"SECRET")):
            result = tools.capture_tshark("eth0", authorized=True, seconds=2,
                                          packet_limit=8, timeout=3)
        self.assertEqual(result["status"], "timeout")
        self.assertNotIn("SECRET", json.dumps(result))

    def test_unknown_tcp_flags_are_retained_as_unknown_not_syn(self) -> None:
        row = "1760350000.100,93.184.216.34,,192.168.1.10,,55000,22,,,6,,64,,bogus\n"
        packets, flows, invalid = tools._parse_tshark_fields(row, 10)
        self.assertEqual(invalid, 0)
        self.assertIsNone(packets[0]["tcp_syn"])
        self.assertIsNone(packets[0]["tcp_ack"])
        self.assertEqual(flows[0]["syn_only_packets"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
