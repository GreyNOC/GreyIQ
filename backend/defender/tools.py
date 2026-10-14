"""Bounded, opt-in local network inventory and packet metadata collection.

Both adapters use fixed argument lists and return structured observations. Neither
adapter classifies a peer as an intruder, saves packet payloads, or broadens the
operator's declared scope. The caller owns persistence and scheduling.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import math
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Any


_LOCAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128",
))
_NMAP_PORTS = (21, 22, 53, 80, 135, 139, 443, 445, 3389, 5900, 8080)
_NMAP_MAX_HOSTS = 16
_SCOPE_MAX_ADDRESSES = 256
_MAX_TOOL_OUTPUT = 2_000_000
_TSHARK_FIELDS = (
    "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "ip.proto", "ipv6.nxt", "frame.len", "tcp.flags.syn", "tcp.flags.ack",
)
_INTERFACE_RE = re.compile(r"[A-Za-z0-9_.:@{}\\\- ]{1,128}\Z")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _failure(tool: str, status: str, error: str, **fields: Any) -> dict[str, Any]:
    return {"ok": False, "tool": tool, "status": status, "error": error,
            "timestamp": _now(), **fields}


def _local_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Accept only literal, canonical local IP addresses or CIDRs; never DNS."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("use a literal local IP address or canonical CIDR")
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=True)
        else:
            address = ipaddress.ip_address(value)
            network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
    except ValueError as exc:
        raise ValueError("use a literal local IP address or canonical CIDR") from exc
    if not any(network.subnet_of(allowed) for allowed in _LOCAL_NETWORKS
               if network.version == allowed.version):
        raise ValueError("target and scope must be local/private addresses")
    return network


def _bounded_timeout(value: int | float, *, minimum: int, maximum: int) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"timeout must be between {minimum} and {maximum} seconds")
    value = float(value)
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"timeout must be between {minimum} and {maximum} seconds")
    return value


def _parse_nmap_xml(xml_text: str, target: ipaddress.IPv4Network | ipaddress.IPv6Network
                    ) -> tuple[str | None, list[dict[str, Any]]]:
    if not xml_text or len(xml_text.encode("utf-8")) > _MAX_TOOL_OUTPUT:
        raise ValueError("nmap XML is empty or exceeds the output limit")
    # ElementTree must never see DTD/entity declarations from a tool output file.
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", xml_text, re.IGNORECASE):
        raise ValueError("nmap XML contains a prohibited declaration")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("nmap returned invalid XML") from exc
    if root.tag != "nmaprun":
        raise ValueError("nmap returned an unexpected XML document")
    raw_version = str(root.get("version") or "").strip()
    version_match = re.fullmatch(r"\d+(?:\.\d+){1,3}", raw_version)
    version = version_match.group(0) if version_match else None
    hosts: list[dict[str, Any]] = []
    seen: set[str] = set()
    nodes = root.findall("host")
    if len(nodes) > _NMAP_MAX_HOSTS:
        raise ValueError("nmap returned more hosts than the configured limit")
    for node in nodes:
        addresses: list[str] = []
        for item in node.findall("address"):
            if item.get("addrtype") not in {"ipv4", "ipv6"}:
                continue
            try:
                address = ipaddress.ip_address(item.get("addr") or "")
            except ValueError:
                continue
            if address in target:
                addresses.append(str(address))
        if not addresses:
            raise ValueError("nmap returned a host outside the authorized target")
        address_text = addresses[0]
        if address_text in seen:
            raise ValueError("nmap returned duplicate host records")
        seen.add(address_text)
        status_node = node.find("status")
        state = str(status_node.get("state") if status_node is not None else "unknown")
        if state not in {"up", "down", "unknown"}:
            state = "unknown"
        ports: list[dict[str, Any]] = []
        for item in node.findall("./ports/port"):
            if item.get("protocol") != "tcp":
                continue
            try:
                number = int(item.get("portid") or "")
            except ValueError:
                continue
            if number not in _NMAP_PORTS:
                continue
            port_state = item.find("state")
            value = str(port_state.get("state") if port_state is not None else "unknown")
            if value not in {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}:
                value = "unknown"
            ports.append({"port": number, "protocol": "tcp", "state": value})
        hosts.append({"address": address_text, "state": state,
                      "ports": sorted(ports, key=lambda row: row["port"])})
    return version, sorted(hosts, key=lambda row: ipaddress.ip_address(row["address"]))


def validate_nmap_scope(target: str, scope: str) -> str | None:
    """Return a refusal reason, or ``None`` for a bounded local target/scope pair.

    This pure guard lets callers refuse invalid targets before taking a host
    inventory. It grants no authorization; ``run_nmap`` separately requires the
    operator's explicit authorization assertion.
    """
    try:
        target_network = _local_network(target)
        scope_network = _local_network(scope)
        if target_network.version != scope_network.version or not target_network.subnet_of(scope_network):
            raise ValueError("target must be contained by the exact authorized scope")
        if target_network.num_addresses > _NMAP_MAX_HOSTS:
            raise ValueError(f"target exceeds the {_NMAP_MAX_HOSTS}-address scan limit")
        if scope_network.num_addresses > _SCOPE_MAX_ADDRESSES:
            raise ValueError("authorized scope exceeds the 256-address limit")
    except ValueError as exc:
        return str(exc)
    return None


def run_nmap(target: str, *, authorized: bool = False, scope: str = "",
             timeout: int | float = 60) -> dict[str, Any]:
    """Scan at most 16 explicitly scoped local IPs with a fixed, modest TCP port set.

    ``authorized`` is an operator assertion. ``scope`` is mandatory and is parsed
    as an exact address or CIDR boundary; the target must be fully contained by it.
    No hostnames, scripts, UDP scan, version probes, or arbitrary nmap flags enter
    this path. A missing nmap binary is a distinct, nonfatal result.
    """
    if authorized is not True:
        return _failure("nmap", "denied", "explicit local scan authorization is required",
                        target=target, scope=scope)
    scope_error = validate_nmap_scope(target, scope)
    if scope_error:
        return _failure("nmap", "denied", scope_error, target=target, scope=scope)
    try:
        target_network = _local_network(target)
        scope_network = _local_network(scope)
        timeout_seconds = _bounded_timeout(timeout, minimum=5, maximum=120)
    except ValueError as exc:
        return _failure("nmap", "denied", str(exc), target=target, scope=scope)

    binary = shutil.which("nmap")
    if not binary:
        return _failure("nmap", "tool_missing", "nmap is not installed or is not on PATH",
                        target=target, scope=scope)
    target_arg = (str(target_network.network_address) if target_network.num_addresses == 1
                  else str(target_network))
    command = [binary]
    if target_network.version == 6:
        command.append("-6")
    command += ["-sT", "-Pn", "-n", "-T2", "--max-retries", "1",
                "--host-timeout", "10s", "--max-rate", "20", "--max-parallelism", "2",
                "-p", ",".join(map(str, _NMAP_PORTS)), "-oX", "-", target_arg]
    started_at = _now()
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=timeout_seconds,
                                   check=False)
    except subprocess.TimeoutExpired:
        return _failure("nmap", "timeout", "nmap exceeded the time limit",
                        target=target_arg, scope=str(scope_network), started_at=started_at,
                        command=command)
    except OSError:
        return _failure("nmap", "tool_error", "nmap could not be started",
                        target=target_arg, scope=str(scope_network), started_at=started_at,
                        command=command)
    if completed.returncode != 0:
        return _failure("nmap", "tool_error", f"nmap exited with code {completed.returncode}",
                        target=target_arg, scope=str(scope_network), started_at=started_at,
                        command=command)
    try:
        version, hosts = _parse_nmap_xml(completed.stdout, target_network)
    except ValueError as exc:
        return _failure("nmap", "invalid_output", str(exc), target=target_arg,
                        scope=str(scope_network), started_at=started_at, command=command)
    return {"ok": True, "status": "complete", "tool": "nmap", "tool_version": version,
            "target": target_arg, "scope": str(scope_network), "started_at": started_at,
            "finished_at": _now(), "command": command, "hosts": hosts,
            "summary": {"host_count": len(hosts),
                        "up_hosts": sum(host["state"] == "up" for host in hosts),
                        "open_ports": sum(port["state"] == "open" for host in hosts
                                          for port in host["ports"])}}


def _packet_protocol(tcp_src: str, tcp_dst: str, udp_src: str, udp_dst: str,
                     ip_proto: str, ipv6_next: str) -> str:
    if tcp_src or tcp_dst:
        return "tcp"
    if udp_src or udp_dst:
        return "udp"
    number = ip_proto or ipv6_next
    return {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}.get(number,
                                                                       f"ip-{number}" if number.isdigit() else "ip")


def _tcp_flag(value: str) -> bool | None:
    """Parse a TShark Boolean field; unknown values cannot support a SYN claim."""

    if value.strip().lower() in {"1", "true"}:
        return True
    if value.strip().lower() in {"0", "false"}:
        return False
    return None


def _parse_tshark_fields(output: str, packet_limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    if len(output.encode("utf-8")) > _MAX_TOOL_OUTPUT:
        raise ValueError("tshark metadata exceeds the output limit")
    packets: list[dict[str, Any]] = []
    flows: dict[tuple[str, str, str, int | None, int | None], dict[str, Any]] = {}
    invalid_rows = 0
    for row in csv.reader(io.StringIO(output)):
        if len(packets) + invalid_rows >= packet_limit:
            raise ValueError("tshark returned more rows than the configured packet limit")
        if len(row) != len(_TSHARK_FIELDS):
            invalid_rows += 1
            continue
        (stamp, src4, src6, dst4, dst6, tcp_src, tcp_dst, udp_src, udp_dst,
         ip_proto, ipv6_next, frame_len, syn_flag, ack_flag) = row
        try:
            source = str(ipaddress.ip_address(src4 or src6))
            destination = str(ipaddress.ip_address(dst4 or dst6))
            epoch = float(stamp)
            if not math.isfinite(epoch):
                raise ValueError("invalid timestamp")
            seen_at = datetime.fromtimestamp(epoch, UTC).isoformat(timespec="milliseconds")
            length = int(frame_len)
            if not 0 <= length <= 1_000_000:
                raise ValueError("invalid frame length")
            protocol = _packet_protocol(tcp_src, tcp_dst, udp_src, udp_dst,
                                        ip_proto, ipv6_next)
            raw_src = tcp_src if protocol == "tcp" else udp_src if protocol == "udp" else ""
            raw_dst = tcp_dst if protocol == "tcp" else udp_dst if protocol == "udp" else ""
            src_port = int(raw_src) if raw_src else None
            dst_port = int(raw_dst) if raw_dst else None
            if any(port is not None and not 0 <= port <= 65535 for port in (src_port, dst_port)):
                raise ValueError("invalid port")
        except (ValueError, OverflowError, OSError):
            invalid_rows += 1
            continue
        packet = {"timestamp": seen_at, "source": source, "destination": destination,
                  "protocol": protocol, "source_port": src_port,
                  "destination_port": dst_port, "length": length,
                  "tcp_syn": _tcp_flag(syn_flag) if protocol == "tcp" else None,
                  "tcp_ack": _tcp_flag(ack_flag) if protocol == "tcp" else None}
        packets.append(packet)
        key = (source, destination, protocol, src_port, dst_port)
        flow = flows.get(key)
        if flow is None:
            flow = {"source": source, "destination": destination, "protocol": protocol,
                    "source_port": src_port, "destination_port": dst_port,
                    "packets": 0, "bytes": 0, "syn_only_packets": 0,
                    "first_seen": seen_at, "last_seen": seen_at}
            flows[key] = flow
        flow["packets"] += 1
        flow["bytes"] += length
        if packet["tcp_syn"] is True and packet["tcp_ack"] is False:
            flow["syn_only_packets"] += 1
        if seen_at < flow["first_seen"]:
            flow["first_seen"] = seen_at
        if seen_at > flow["last_seen"]:
            flow["last_seen"] = seen_at
    return packets, sorted(flows.values(), key=lambda row: (-row["packets"], row["source"],
                                                       row["destination"], row["protocol"])), invalid_rows


def _tshark_version(binary: str) -> str | None:
    try:
        completed = subprocess.run([binary, "--version"], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    match = re.search(r"\b(?:TShark|Wireshark)\s*(?:\(Wireshark\))?\s*(\d+\.\d+(?:\.\d+)?)",
                      completed.stdout[:300], re.IGNORECASE)
    return match.group(1) if match else None


def capture_tshark(interface: str, *, authorized: bool = False, seconds: int = 10,
                   packet_limit: int = 256, timeout: int | float | None = None) -> dict[str, Any]:
    """Capture only selected packet fields on one explicitly authorized interface.

    TShark still inspects frames in memory; only timestamp, addresses, transport
    ports, protocol, TCP SYN/ACK bits, and frame length leave the process. No
    pcap or payload file is created. Duration and packet count are capped.
    """
    if authorized is not True:
        return _failure("tshark", "denied", "explicit interface capture authorization is required",
                        interface=interface)
    if (not isinstance(interface, str) or interface != interface.strip()
            or not _INTERFACE_RE.fullmatch(interface) or interface.lower() == "any"
            or interface.startswith("-")):
        return _failure("tshark", "denied", "name one exact local capture interface",
                        interface=interface)
    if type(seconds) is not int or not 1 <= seconds <= 30:
        return _failure("tshark", "denied", "duration must be 1 to 30 seconds",
                        interface=interface)
    if type(packet_limit) is not int or not 1 <= packet_limit <= 1000:
        return _failure("tshark", "denied", "packet limit must be 1 to 1000",
                        interface=interface)
    try:
        timeout_seconds = _bounded_timeout(timeout if timeout is not None else seconds + 10,
                                           minimum=seconds + 1, maximum=60)
    except ValueError as exc:
        return _failure("tshark", "denied", str(exc), interface=interface)
    binary = shutil.which("tshark")
    if not binary:
        return _failure("tshark", "tool_missing", "tshark is not installed or is not on PATH",
                        interface=interface)
    command = [binary, "-n", "-p", "-i", interface, "-a", f"duration:{seconds}",
               "-c", str(packet_limit), "-T", "fields", "-E", "separator=,",
               "-E", "quote=d", "-E", "occurrence=f"]
    for field in _TSHARK_FIELDS:
        command.extend(("-e", field))
    started_at = _now()
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=timeout_seconds,
                                   check=False)
    except subprocess.TimeoutExpired:
        return _failure("tshark", "timeout", "tshark exceeded the time limit",
                        interface=interface, started_at=started_at, command=command)
    except OSError:
        return _failure("tshark", "tool_error", "tshark could not be started",
                        interface=interface, started_at=started_at, command=command)
    if completed.returncode != 0:
        return _failure("tshark", "tool_error", f"tshark exited with code {completed.returncode}",
                        interface=interface, started_at=started_at, command=command)
    try:
        packets, flows, invalid_rows = _parse_tshark_fields(completed.stdout, packet_limit)
    except ValueError as exc:
        return _failure("tshark", "invalid_output", str(exc), interface=interface,
                        started_at=started_at, command=command)
    return {"ok": True, "status": "complete", "tool": "tshark",
            "tool_version": _tshark_version(binary), "interface": interface,
            "started_at": started_at, "finished_at": _now(), "duration_seconds": seconds,
            "command": command,
            "packets": packets, "flows": flows,
            "summary": {"packet_count": len(packets), "flow_count": len(flows),
                        "invalid_rows": invalid_rows,
                        "total_bytes": sum(packet["length"] for packet in packets)}}
