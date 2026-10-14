"""Conservative packet-to-local-socket attribution checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from defender.packet_owner import annotate_packet_owners  # noqa: E402


def packet(src: str, sp: int, dst: str, dp: int, protocol: str = "tcp") -> dict:
    return {"source": src, "source_port": sp, "destination": dst,
            "destination_port": dp, "protocol": protocol}


class PacketOwnerTests(unittest.TestCase):
    def test_connected_both_directions_and_endpoint_fallback(self) -> None:
        inventory = {"interfaces": [{"addresses": ["10.0.0.2/24", "::1/128"]}],
                     "connections": [
                         {"protocol": "tcp", "local_address": "10.0.0.2", "local_port": 50000,
                          "remote_address": "198.51.100.3", "remote_port": 443,
                          "state": "ESTABLISHED", "pid": 1234},
                         {"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 22,
                          "state": "LISTEN", "pid": 5678},
                         {"protocol": "udp", "local_address": "10.0.0.2", "local_port": 5353,
                          "state": "BOUND", "pid": 9012},
                     ]}
        capture = {"ok": True, "packets": [
            packet("10.0.0.2", 50000, "198.51.100.3", 443),
            packet("198.51.100.3", 443, "10.0.0.2", 50000),
            packet("198.51.100.4", 40000, "10.0.0.2", 22),
            packet("10.0.0.2", 5353, "224.0.0.251", 5353, "udp"),
            packet("198.51.100.4", 40000, "203.0.113.2", 22),
        ]}
        annotate_packet_owners(capture, inventory)
        self.assertEqual([(row["pid"], row["pid_attribution"]) for row in capture["packets"]], [
            (1234, "socket_snapshot"), (1234, "socket_snapshot"),
            (5678, "listener_endpoint"), (9012, "bound_endpoint"), (None, "unknown")])
        self.assertEqual(capture["pid_attribution"]["socket_snapshot"], 2)

    def test_ambiguous_and_stale_or_unowned_socket_stay_unknown(self) -> None:
        inventory = {"interfaces": [{"addresses": ["127.0.0.1/8"]}],
                     "connections": [
                         {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": 5000,
                          "remote_address": "127.0.0.1", "remote_port": 6000,
                          "state": "ESTABLISHED", "pid": 111},
                         {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": 6000,
                          "remote_address": "127.0.0.1", "remote_port": 5000,
                          "state": "ESTABLISHED", "pid": 222},
                         {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": 7000,
                          "state": "LISTEN", "pid": True},
                     ]}
        capture = {"ok": True, "packets": [packet("127.0.0.1", 5000, "127.0.0.1", 6000),
                                            packet("127.0.0.1", 8000, "127.0.0.1", 7000),
                                            packet("127.0.0.1", 5000, "127.0.0.1", 6000, "icmp")]}
        annotate_packet_owners(capture, inventory)
        self.assertEqual([row["pid"] for row in capture["packets"]], [None, None, None])
        self.assertEqual(capture["packets"][0]["pid_attribution"], "ambiguous")
        self.assertEqual(capture["packets"][1]["pid_attribution"], "unknown")
        self.assertEqual(capture["packets"][2]["pid_attribution"], "unknown")


if __name__ == "__main__":
    unittest.main()
