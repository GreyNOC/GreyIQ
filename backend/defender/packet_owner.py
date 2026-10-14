"""Best-effort local PID attribution for bounded packet metadata.

TShark does not report a process owner. A PID here is a join to the host's
socket snapshot, never an assertion about a remote sender or actor.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).split("%", 1)[0]))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    return value if type(value) is int and 0 < value <= 65535 else None


def annotate_packet_owners(capture: dict[str, Any], inventory: Mapping[str, Any]) -> None:
    """Add local PID and attribution status to each packet, in place.

    Prefer exact connected socket tuples. Listener/bound socket matches require
    an inventoried local interface address. Conflicting owners remain unknown.
    """
    if capture.get("ok") is not True:
        return
    packets = capture.get("packets")
    if not isinstance(packets, list):
        return

    local_ips: set[str] = set()
    for interface in inventory.get("interfaces") or []:
        if not isinstance(interface, Mapping):
            continue
        for address in interface.get("addresses") or []:
            normalized = _ip(str(address).split("/", 1)[0])
            if normalized:
                local_ips.add(normalized)
    local_ips.update({"127.0.0.1", "::1"})

    connected: dict[tuple[str, str, int, str, int], set[int]] = {}
    endpoints: dict[tuple[str, str, int], set[int]] = {}
    for row in inventory.get("connections") or []:
        if not isinstance(row, Mapping):
            continue
        protocol = str(row.get("protocol") or "").lower()
        local, remote = _ip(row.get("local_address")), _ip(row.get("remote_address"))
        local_port, remote_port = _port(row.get("local_port")), _port(row.get("remote_port"))
        pid = row.get("pid")
        if protocol not in {"tcp", "udp"} or local is None or local_port is None:
            continue
        if type(pid) is not int or pid <= 0:
            continue
        if remote is not None and remote_port is not None:
            connected.setdefault((protocol, local, local_port, remote, remote_port), set()).add(pid)
        elif (protocol == "tcp" and str(row.get("state") or "").upper() == "LISTEN") or protocol == "udp":
            endpoints.setdefault((protocol, local, local_port), set()).add(pid)

    counts = {"socket_snapshot": 0, "listener_endpoint": 0, "bound_endpoint": 0,
              "ambiguous": 0, "unknown": 0}
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        packet["pid"] = None
        packet["pid_attribution"] = "unknown"
        protocol = str(packet.get("protocol") or "").lower()
        source, destination = _ip(packet.get("source")), _ip(packet.get("destination"))
        source_port, destination_port = _port(packet.get("source_port")), _port(packet.get("destination_port"))
        if protocol in {"tcp", "udp"} and source and destination and source_port and destination_port:
            owners: set[int] = set()
            for local, local_port, remote, remote_port in (
                (source, source_port, destination, destination_port),
                (destination, destination_port, source, source_port),
            ):
                owners.update(connected.get((protocol, local, local_port, remote, remote_port), set()))
            attribution = "socket_snapshot"
            if not owners:
                attribution = "bound_endpoint" if protocol == "udp" else "listener_endpoint"
                for local, local_port in ((source, source_port), (destination, destination_port)):
                    if local not in local_ips:
                        continue
                    wildcard = "::" if ":" in local else "0.0.0.0"
                    owners.update(endpoints.get((protocol, local, local_port), set()))
                    owners.update(endpoints.get((protocol, wildcard, local_port), set()))
            if len(owners) == 1:
                packet["pid"] = next(iter(owners))
                packet["pid_attribution"] = attribution
            elif owners:
                packet["pid_attribution"] = "ambiguous"
        counts[packet["pid_attribution"]] += 1
    capture["pid_attribution"] = counts
