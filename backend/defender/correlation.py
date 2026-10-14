"""Correlate baseline process drift with new or changed local TCP listeners.

The join is deliberately strict. A listener, its owning PID and executable, and
the process baseline change must agree before a combined review indicator is
emitted. Remote socket peers add context, but socket tables do not reveal which
side initiated a connection or whether a firewall permits inbound access.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any, Mapping


RULE_ID = "defender.endpoint_process_correlation"
_MAX_PEER_SAMPLE = 8
_MAX_IOC_SAMPLE = 8


def _rows(value: Any) -> list[Mapping[str, Any]]:
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, list) else []


def _text(value: Any, limit: int = 1024) -> str:
    return str(value or "").strip()[:limit]


def _number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if number >= 0 else None


def _paths(row: Mapping[str, Any]) -> set[str]:
    values = row.get("exes")
    if isinstance(values, list):
        return {_text(value) for value in values if _text(value)}
    path = _text(row.get("exe"))
    return {path} if path else set()


def _ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    address = _text(value, 128).strip("[]").split("%", 1)[0]
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        return None


def _network_facing(value: Any) -> bool:
    address = _ip(value)
    if address is None:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return not (address.is_loopback or (mapped is not None and mapped.is_loopback))


def _peer_context(connections: list[Mapping[str, Any]]) -> dict[int, tuple[int, list[dict[str, Any]]]]:
    peers_by_pid: dict[int, set[tuple[str, int]]] = {}
    for row in connections:
        pid = _number(row.get("pid"))
        if pid is None or pid <= 0:
            continue
        address = _ip(row.get("remote_address"))
        port = _number(row.get("remote_port"))
        if address is None or address.is_unspecified or port is None or not 1 <= port <= 65535:
            continue
        peers_by_pid.setdefault(pid, set()).add((str(address), port))
    output = {}
    for pid, peers in peers_by_pid.items():
        ordered = sorted(peers, key=lambda item: (ipaddress.ip_address(item[0]).version, item[0], item[1]))
        output[pid] = (len(ordered), [{"address": address, "port": port}
                                      for address, port in ordered[:_MAX_PEER_SAMPLE]])
    return output


def _ioc_context(findings: list[Mapping[str, Any]]) -> dict[int, list[dict[str, str]]]:
    matches_by_pid: dict[int, set[tuple[str, str]]] = {}
    for finding in findings:
        if finding.get("rule_id") != "defender.ioc_match":
            continue
        evidence = finding.get("evidence")
        if not isinstance(evidence, Mapping):
            continue
        pid = _number(evidence.get("pid"))
        if pid is None or pid <= 0:
            continue
        kind = _text(evidence.get("indicator_type"), 16)
        value = _text(evidence.get("indicator_value"), 253)
        if kind in {"ip", "domain", "sha256"} and value:
            matches_by_pid.setdefault(pid, set()).add((kind, value))
    return {pid: [{"type": kind, "value": value} for kind, value in sorted(matches)[:_MAX_IOC_SAMPLE]]
            for pid, matches in matches_by_pid.items()}


def correlate_endpoint_changes(
    inventory: Mapping[str, Any], baseline_diff: Mapping[str, Any] | None,
    findings: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] = (),
) -> list[dict[str, Any]]:
    """Return strict process/listener joins for operator review.

    A baseline is required. This function does not infer exposure, malware, an
    attacker, or connection direction. IOC enrichment is accepted only from an
    exact reviewed indicator finding carrying the same local PID; packet-only
    flow matches cannot be attributed to a process here.
    """
    if not isinstance(inventory, Mapping) or not isinstance(baseline_diff, Mapping):
        return []
    sections = baseline_diff.get("sections")
    if not isinstance(sections, Mapping):
        return []
    listener_diff = sections.get("listeners")
    process_diff = sections.get("processes")
    if not isinstance(listener_diff, Mapping) or not isinstance(process_diff, Mapping):
        return []

    host = inventory.get("host")
    is_windows = isinstance(host, Mapping) and _text(host.get("platform"), 32).casefold().startswith("win")
    normalize = str.casefold if is_windows else str
    new_paths: set[tuple[str, str]] = set()
    replaced_paths: set[tuple[str, str]] = set()
    for row in _rows(process_diff.get("added")):
        name = _text(row.get("name"), 255)
        for path in _paths(row):
            if name:
                new_paths.add((normalize(name), normalize(path)))
    for change in _rows(process_diff.get("changed")):
        before, after = change.get("before"), change.get("after")
        if not isinstance(before, Mapping) or not isinstance(after, Mapping):
            continue
        old_paths = {normalize(path) for path in _paths(before)}
        name = _text(after.get("name"), 255)
        if not old_paths or not name:
            continue
        for path in _paths(after):
            if normalize(path) not in old_paths:
                replaced_paths.add((normalize(name), normalize(path)))
    if not new_paths and not replaced_paths:
        return []

    candidate_listeners: dict[tuple[str, str, int, str, str], str] = {}

    def add_listener(row: Mapping[str, Any], change_type: str) -> None:
        if _text(row.get("protocol"), 16).lower() != "tcp":
            return
        name = _text(row.get("process_name"), 255)
        exe = _text(row.get("process_exe"))
        port = _number(row.get("local_port"))
        if name and exe and port is not None and _network_facing(row.get("local_address")):
            key = (_text(row.get("family"), 16), _text(row.get("local_address"), 128),
                   port, normalize(name), normalize(exe))
            candidate_listeners[key] = change_type

    for row in _rows(listener_diff.get("added")):
        add_listener(row, "added")
    for change in _rows(listener_diff.get("changed")):
        before, after = change.get("before"), change.get("after")
        if not isinstance(before, Mapping) or not isinstance(after, Mapping):
            continue
        old_exe = _text(before.get("process_exe"))
        new_exe = _text(after.get("process_exe"))
        if old_exe and new_exe and normalize(old_exe) != normalize(new_exe):
            add_listener(after, "owner_executable_changed")
    if not candidate_listeners:
        return []

    processes = {pid: row for row in _rows(inventory.get("processes"))
                 if (pid := _number(row.get("pid"))) is not None and pid > 0}
    connections = _rows(inventory.get("connections"))
    known_findings = _rows(list(findings)) if isinstance(findings, (list, tuple)) else []
    peers_by_pid = _peer_context(connections)
    iocs_by_pid = _ioc_context(known_findings)
    output: list[dict[str, Any]] = []
    seen: set[tuple[int, str, int]] = set()
    for row in connections:
        if (_text(row.get("protocol"), 16).lower() != "tcp"
                or _text(row.get("state"), 32).upper() not in {"LISTEN", "LISTENING"}
                or not _network_facing(row.get("local_address"))):
            continue
        pid = _number(row.get("pid"))
        port = _number(row.get("local_port"))
        if pid is None or pid <= 0 or port is None or not 1 <= port <= 65535:
            continue
        owner = processes.get(pid)
        if owner is None:
            continue
        name, exe = _text(owner.get("name"), 255), _text(owner.get("exe"))
        endpoint = _text(row.get("local_address"), 128)
        listener_key = (_text(row.get("family"), 16), endpoint, port,
                        normalize(name), normalize(exe))
        if not name or not exe or listener_key not in candidate_listeners:
            continue
        identity = (normalize(name), normalize(exe))
        change = ("executable_path_changed" if identity in replaced_paths else
                  "new_process" if identity in new_paths else "")
        if not change or (pid, endpoint, port) in seen:
            continue
        seen.add((pid, endpoint, port))
        peer_count, peers = peers_by_pid.get(pid, (0, []))
        iocs = iocs_by_pid.get(pid, [])
        evidence: dict[str, Any] = {
            "pid": pid, "ppid": _number(owner.get("ppid")),
            "process_name": name, "exe": exe,
            "protocol": "tcp", "local_address": endpoint, "local_port": port,
            "listener_change": candidate_listeners[listener_key],
            "process_change": change, "remote_peer_count": peer_count,
            "remote_peers_sample": peers, "reviewed_ioc_matches": iocs,
            "baseline_created_at": _text(baseline_diff.get("baseline_created_at"), 64),
        }
        # PID reuse and ordinary process restarts must not make the same
        # baseline drift look like a wholly different finding to a log consumer.
        # PID remains in evidence for point-in-time operator tracing.
        stable = {key: evidence[key] for key in ("process_name", "exe", "local_address",
                                                "local_port", "listener_change", "process_change",
                                                "reviewed_ioc_matches")}
        finding_id = "def_" + hashlib.sha256(json.dumps(stable, sort_keys=True).encode("utf-8")).hexdigest()[:20]
        explanation = (
            "A new or redefined TCP listener is bound beyond loopback and its exact owning "
            "process executable is new or changed against the reviewed host baseline. "
            "Remote peers are socket observations; their direction is unknown. Local firewall "
            "policy may prevent inbound reachability, and this does not prove compromise."
        )
        if iocs:
            explanation += (" The same PID also has an exact match to a supplied, reviewed "
                            "indicator; shared infrastructure and stale intelligence can still mislead.")
        output.append({
            "finding_id": finding_id, "rule_id": RULE_ID,
            "title": "New or changed network-facing listener owned by a new or changed executable",
            "severity": "high" if iocs else "medium",
            "confidence": 0.84 if iocs else 0.74,
            "category": "network_change", "assessment": "review_indicator",
            "source": "local_inventory_correlation",
            "observed_at": _text(inventory.get("collected_at"), 64),
            "evidence": evidence, "explanation": explanation,
            "recommended_action": (
                "Verify the executable hash and publisher, the approved change, socket owner, "
                "firewall reachability, and any indicator provenance before escalation."
            ),
        })
    return sorted(output, key=lambda finding: finding["finding_id"])
