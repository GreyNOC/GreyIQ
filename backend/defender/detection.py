"""Conservative defender rules over local inventory snapshots.

Design provenance: GreyNOC/HomeGuard's MIT-licensed detection engine inspired
the rule metadata, baseline comparison, and indicator wording used here:
https://github.com/GreyNOC/HomeGuard/tree/47dd57e073170bf38b236562e81790e510c9a503
The small service-port review set adapts HomeGuard's detection concepts; no
HomeGuard implementation code is copied. Its full device engine can be used
explicitly through ``evaluate_homeguard_devices``
when that optional package is installed. We do not import it during CLI boot.

These rules describe review indicators. A port, unusual path, or IOC match is
not proof of malware, intrusion, actor identity, or exploitation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import posixpath
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


_RULES = (
    {"rule_id": "defender.risky_listener", "title": "Listener service requiring review", "category": "exposed_service", "severity": "medium", "requires": "Observed local TCP LISTEN socket on a selected service port"},
    {"rule_id": "defender.new_listener", "title": "New listening endpoint", "category": "network_change", "severity": "low", "requires": "Observed listener added since an explicit host baseline"},
    {"rule_id": "defender.new_startup_entry", "title": "New startup entry", "category": "persistence_change", "severity": "medium", "requires": "Startup entry added since an explicit host baseline"},
    {"rule_id": "defender.new_auto_service", "title": "New automatic service", "category": "persistence_change", "severity": "medium", "requires": "Automatic service added since an explicit host baseline"},
    {"rule_id": "defender.startup_definition_change", "title": "Startup definition changed", "category": "persistence_change", "severity": "medium", "requires": "Same startup entry with two differing definition SHA-256 digests since baseline"},
    {"rule_id": "defender.service_definition_change", "title": "Service definition changed", "category": "persistence_change", "severity": "medium", "requires": "Same service with two differing definition SHA-256 digests since baseline"},
    {"rule_id": "defender.active_staging_persistence", "title": "Persistence entry targets a running staging-path executable", "category": "persistence_change", "severity": "medium", "requires": "New or redefined startup/automatic service targets a running executable under tmp, temp, or downloads"},
    {"rule_id": "defender.endpoint_process_correlation", "title": "New or changed listener associated with a changed process", "category": "network_change", "severity": "medium", "requires": "New or changed non-loopback TCP listener and new or changed owning executable on exact PID"},
    {"rule_id": "defender.tcp_syn_port_probe", "title": "TCP SYN port-probe indicator", "category": "network_probe", "severity": "medium", "requires": "At least eight distinct local destination ports receive external SYN-only packets within 30 seconds of one authorized TShark capture"},
    {"rule_id": "defender.executable_path_change", "title": "Process executable path changed", "category": "process_change", "severity": "medium", "requires": "Process name with different executable path since baseline"},
    {"rule_id": "defender.executable_hash_change", "title": "On-disk process executable changed at the same path", "category": "file_integrity", "severity": "medium", "requires": "Same process executable path with valid differing on-disk SHA-256 digests since an explicit baseline"},
    {"rule_id": "defender.process_in_temp", "title": "Process running from a temporary or downloads path", "category": "process_review", "severity": "low", "requires": "Observed process executable path within tmp, temp, or downloads"},
    {"rule_id": "defender.file_integrity_burst", "title": "Burst of watched-file integrity changes", "category": "file_integrity", "severity": "medium", "requires": "Explicit watched roots, baseline, and at least 20 changed/removed files or 20% with at least 10"},
    {"rule_id": "defender.ioc_match", "title": "Exact match to a reviewed indicator", "category": "threat_intelligence", "severity": "medium", "requires": "Fresh local IOC JSON and exact IP/domain/SHA-256 observation"},
)
_RULE_INDEX = {rule["rule_id"]: rule for rule in _RULES}

# A small, review-oriented subset of the service-risk ideas in HomeGuard.
# Port numbers identify possible services, not software or hostile activity.
_REVIEW_PORTS = {
    23: ("Telnet", "Unencrypted remote administration may be exposed."),
    139: ("NetBIOS", "File sharing may be reachable."),
    445: ("SMB", "File sharing may be reachable."),
    3389: ("Remote Desktop", "Remote administration may be reachable."),
    5900: ("VNC", "Remote control may be reachable."),
    5555: ("ADB or debug service", "A debug service may be reachable."),
    7547: ("TR-069", "Router management may be reachable."),
}
_TEMP_PATH = re.compile(r"(?:^|[/\\])(?:tmp|temp|downloads)(?:[/\\]|$)", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_MAX_IOC_FILE_BYTES = 2_000_000
_MAX_IOCS = 10_000


def list_rules() -> list[dict[str, str]]:
    """Return stable rule metadata for CLI discovery and reporting."""

    return [dict(rule) for rule in _RULES]


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(row) for row in value if isinstance(row, Mapping)]


def _section_added(diff: Mapping[str, Any] | None, section: str) -> list[dict[str, Any]]:
    if not isinstance(diff, Mapping):
        return []
    sections = diff.get("sections")
    if not isinstance(sections, Mapping):
        return []
    row = sections.get(section)
    return _rows(row.get("added")) if isinstance(row, Mapping) else []


def _section_changed(diff: Mapping[str, Any] | None, section: str) -> list[dict[str, Any]]:
    if not isinstance(diff, Mapping):
        return []
    sections = diff.get("sections")
    if not isinstance(sections, Mapping):
        return []
    row = sections.get(section)
    return _rows(row.get("changed")) if isinstance(row, Mapping) else []


def _integer(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _text(value: Any, limit: int = 512) -> str:
    return str(value or "").strip()[:limit]


def _finding(
    rule_id: str,
    *,
    title: str,
    evidence: Mapping[str, Any],
    explanation: str,
    action: str,
    observed_at: str = "",
    confidence: float = 0.65,
    severity: str | None = None,
    source: str = "local_inventory",
    provenance: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    stable = json.dumps({"rule_id": rule_id, "evidence": dict(evidence)}, sort_keys=True, default=str)
    digest = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]
    rule = _RULE_INDEX[rule_id]
    result: dict[str, Any] = {
        "finding_id": f"def_{digest}",
        "rule_id": rule_id,
        "title": title,
        "severity": severity or rule["severity"],
        "confidence": round(confidence, 2),
        "category": rule["category"],
        "assessment": "review_indicator",
        "source": source,
        "observed_at": observed_at,
        "evidence": dict(evidence),
        "explanation": explanation,
        "recommended_action": action,
    }
    if provenance:
        result["provenance"] = dict(provenance)
    return result


def _listener(row: Mapping[str, Any]) -> bool:
    state = _text(row.get("state"), 32).upper()
    # A UDP binding may be an ephemeral outbound client port. Until a sensor
    # supplies reliable service evidence, it must not enter listener rules.
    return _text(row.get("protocol"), 16).lower() == "tcp" and state in {"LISTEN", "LISTENING"}


def _listener_key(row: Mapping[str, Any]) -> tuple[str, str, int | None, int | None]:
    return (
        _text(row.get("protocol"), 16).lower(),
        _text(row.get("local_address"), 128),
        _integer(row.get("local_port")),
        _integer(row.get("pid")),
    )


def _listener_diff_key(row: Mapping[str, Any], owner: Mapping[str, Any] | None = None) -> tuple[str, str, int | None, str]:
    owner = owner or {}
    return (
        _text(row.get("protocol"), 16).lower(),
        _text(row.get("local_address"), 128),
        _integer(row.get("local_port")),
        _text(row.get("process_exe") or owner.get("exe") or row.get("process_name") or owner.get("name"), 512).casefold(),
    )


def _is_loopback(address: str) -> bool:
    cleaned = address.strip("[]").split("%", 1)[0]
    if cleaned.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return ip.is_loopback or bool(getattr(ip, "ipv4_mapped", None) and ip.ipv4_mapped.is_loopback)


def _exe_paths(row: Mapping[str, Any]) -> set[str]:
    paths = row.get("exes")
    if isinstance(paths, list):
        return {_text(path) for path in paths if _text(path)}
    exe = _text(row.get("exe"))
    return {exe} if exe else set()


def _definition_changed(change: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    """Require two complete fingerprints before describing definition drift."""

    before, after = change.get("before"), change.get("after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return None
    old_digest = _text(before.get("definition_sha256"), 64).lower()
    new_digest = _text(after.get("definition_sha256"), 64).lower()
    if (not _SHA256.fullmatch(old_digest) or not _SHA256.fullmatch(new_digest)
            or old_digest == new_digest):
        return None
    if before.get("definition_status", "hashed") != "hashed" or after.get("definition_status", "hashed") != "hashed":
        return None
    return before, after


def _path_key(value: Any) -> str:
    """Normalize only absolute executable paths for an exact local join."""

    raw_path = str(value or "").strip()
    # Inventory caps executable paths at 1024 characters. A capped prefix is
    # not an exact path, so it cannot support a correlation finding.
    if not raw_path or len(raw_path) >= 1024:
        return ""
    path = raw_path
    if re.match(r"^(?:[a-zA-Z]:[\\/]|\\\\)", path):
        return ntpath.normcase(ntpath.normpath(path)) if ntpath.isabs(path) else ""
    return posixpath.normpath(path) if posixpath.isabs(path) else ""


def evaluate_inventory(
    inventory: Mapping[str, Any], baseline_diff: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Evaluate a snapshot and optional *explicitly trusted* baseline diff.

    Without a baseline, change rules stay quiet. Risky listeners and processes
    in temporary paths remain reviewable observations. Absence of findings does
    not mean the machine is clean, especially when coverage is incomplete.
    This function performs no network requests, file reads, or remediation.
    """

    if not isinstance(inventory, Mapping):
        raise TypeError("inventory must be a mapping")
    observed_at = _text(inventory.get("collected_at"), 64)
    processes = _rows(inventory.get("processes"))
    by_pid = {pid: row for row in processes if (pid := _integer(row.get("pid"))) is not None}
    connections = [row for row in _rows(inventory.get("connections")) if _listener(row)]
    added_listeners = {_listener_diff_key(row) for row in _section_added(baseline_diff, "listeners")}
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for conn in connections:
        protocol, local_address, port, pid = _listener_key(conn)
        if port is None:
            continue
        owner = by_pid.get(pid or -1, {})
        loopback_only = _is_loopback(local_address)
        evidence = {
            "protocol": protocol,
            "local_address": local_address,
            "local_port": port,
            "pid": pid,
            "process_name": _text(owner.get("name"), 128),
            "exe": _text(owner.get("exe"), 512),
            "loopback_only": loopback_only,
        }
        service = _REVIEW_PORTS.get(port)
        if service is not None:
            key = ("defender.risky_listener", f"{protocol}:{local_address}:{port}:{pid}")
            if key not in seen:
                seen.add(key)
                findings.append(_finding(
                    "defender.risky_listener",
                    title=f"{'Local-only ' if loopback_only else ''}{service[0]} listener on port {port} requires review",
                    evidence=evidence,
                    explanation=(
                        f"A listener was observed on a port commonly used by {service[0]}. "
                        + ("It is bound to loopback, so this observation does not show exposure to network peers. " if loopback_only else "It is bound beyond loopback, but local firewall policy may still restrict peers. ")
                        + "The port alone does not identify the service or prove intrusion."
                    ),
                    action="Confirm the owning process and whether this listener is expected; restrict or disable it if unnecessary.",
                    observed_at=observed_at,
                    confidence=0.78,
                    severity="low" if loopback_only else "high" if port == 23 else "medium",
                ))
        if baseline_diff is not None and _listener_diff_key(conn, owner) in added_listeners:
            key = ("defender.new_listener", f"{protocol}:{local_address}:{port}:{pid}")
            if key not in seen:
                seen.add(key)
                findings.append(_finding(
                    "defender.new_listener",
                    title=f"New {protocol.upper()} listener on {local_address}:{port}",
                    evidence=evidence,
                    explanation="This listener was absent from the approved baseline. A new listener can be a normal update or configuration change.",
                    action="Check the process owner and change record, then update the baseline only after review.",
                    observed_at=observed_at,
                    confidence=0.72,
                ))

    for row in _section_added(baseline_diff, "startup"):
        evidence = {"name": _text(row.get("name"), 128), "location": _text(row.get("location"), 512)}
        findings.append(_finding(
            "defender.new_startup_entry", title=f"New startup entry: {evidence['name'] or 'unnamed'}",
            evidence=evidence,
            explanation="A startup entry was added since the approved baseline. This is a persistence change, but may be a normal install.",
            action="Verify the publisher and installation change that created the entry.", observed_at=observed_at,
            confidence=0.74,
        ))

    for row in _section_added(baseline_diff, "services"):
        start_type = _text(row.get("start_type"), 64).lower()
        if start_type not in {"auto", "automatic", "automatic (delayed start)", "enabled"}:
            continue
        evidence = {"name": _text(row.get("name"), 128), "start_type": start_type, "status": _text(row.get("status"), 64)}
        findings.append(_finding(
            "defender.new_auto_service", title=f"New automatic service: {evidence['name'] or 'unnamed'}",
            evidence=evidence,
            explanation="An automatically starting service was added since the approved baseline. It may be legitimate software or an unwanted persistence point.",
            action="Check the service binary, publisher, and installation change.", observed_at=observed_at,
            confidence=0.7,
        ))

    for change in _section_changed(baseline_diff, "startup"):
        pair = _definition_changed(change)
        if pair is None:
            continue
        _, after = pair
        evidence = {"name": _text(after.get("name"), 128),
                    "location": _text(after.get("location"), 512),
                    "definition_changed": True}
        findings.append(_finding(
            "defender.startup_definition_change",
            title=f"Startup definition changed: {evidence['name'] or 'unnamed'}",
            evidence=evidence,
            explanation="The same startup entry has a different definition fingerprint from the approved baseline. This can be a routine update or a persistence change; the digest alone does not reveal the cause.",
            action="Review the current launch definition on the host and the expected installation change before updating the baseline.",
            observed_at=observed_at, confidence=0.82,
        ))

    for change in _section_changed(baseline_diff, "services"):
        pair = _definition_changed(change)
        if pair is None:
            continue
        _, after = pair
        evidence = {"name": _text(after.get("name"), 128), "definition_changed": True}
        findings.append(_finding(
            "defender.service_definition_change",
            title=f"Service definition changed: {evidence['name'] or 'unnamed'}",
            evidence=evidence,
            explanation="The same service has a different definition fingerprint from the approved baseline. This can be a routine update or a persistence change; the digest alone does not reveal the cause.",
            action="Review the current service definition on the host and the expected installation change before updating the baseline.",
            observed_at=observed_at, confidence=0.82,
        ))

    # A definition change alone is noisy. Joining a new/redefined persistence
    # entry to a *running* executable in a writable staging path produces a
    # more actionable triage lead without claiming the entry is malicious.
    running_by_exe: dict[str, list[dict[str, Any]]] = {}
    for process in processes:
        path_key = _path_key(process.get("exe"))
        if path_key and _integer(process.get("pid")) is not None:
            running_by_exe.setdefault(path_key, []).append(process)
    persistence_candidates: list[tuple[str, str, dict[str, Any]]] = []
    for section, kind in (("startup", "startup"), ("services", "service")):
        persistence_candidates.extend((kind, "added", row) for row in _section_added(baseline_diff, section))
        for change in _section_changed(baseline_diff, section):
            pair = _definition_changed(change)
            if pair is not None:
                persistence_candidates.append((kind, "definition_changed", dict(pair[1])))
    correlation_keys: set[tuple[str, str, str, str]] = set()
    for kind, change_type, entry in persistence_candidates:
        if kind == "service" and _text(entry.get("start_type"), 64).lower() not in {
                "auto", "automatic", "automatic (delayed start)", "enabled"}:
            continue
        target = _text(entry.get("target_path"), 1024)
        target_key = _path_key(target)
        if not target_key or not _TEMP_PATH.search(target):
            continue
        running = running_by_exe.get(target_key, [])
        if not running:
            continue
        entry_name = _text(entry.get("name"), 128)
        location = _text(entry.get("location"), 512) if kind == "startup" else ""
        unique = (kind, entry_name, location, target_key)
        if unique in correlation_keys:
            continue
        correlation_keys.add(unique)
        evidence = {
            "entry_kind": kind, "change_type": change_type, "entry_name": entry_name,
            "location": location, "target_path": target,
            "pids": sorted({_integer(row.get("pid")) for row in running if _integer(row.get("pid")) is not None})[:16],
            "process_count": len(running),
        }
        findings.append(_finding(
            "defender.active_staging_persistence",
            title=f"{kind.capitalize()} entry targets a running staging-path executable: {entry_name or 'unnamed'}",
            evidence=evidence,
            explanation="A new or redefined persistence entry points to a currently running executable under a temporary or downloads directory. Installers and developer tools can produce this pattern; it does not confirm malicious persistence.",
            action="Inspect the entry, executable signature or hash, installation record, and parent process before updating the baseline.",
            observed_at=observed_at, confidence=0.82,
        ))

    for change in _section_changed(baseline_diff, "processes"):
        before, after = change.get("before"), change.get("after")
        if not isinstance(before, Mapping) or not isinstance(after, Mapping):
            continue
        old_paths, new_paths = _exe_paths(before), _exe_paths(after)
        if not old_paths or not new_paths or {path.casefold() for path in old_paths} == {path.casefold() for path in new_paths}:
            continue
        old_exe, new_exe = ", ".join(sorted(old_paths))[:512], ", ".join(sorted(new_paths))[:512]
        evidence = {"pid": _integer(after.get("pid")), "process_name": _text(after.get("name"), 128), "old_exe": old_exe, "new_exe": new_exe}
        findings.append(_finding(
            "defender.executable_path_change", title=f"Executable path changed for {evidence['process_name'] or 'a process'}",
            evidence=evidence,
            explanation="The observed process executable path differs from the approved baseline. PID reuse and software updates are possible explanations.",
            action="Confirm the process identity, publisher, and expected update path.", observed_at=observed_at,
            confidence=0.62,
        ))

    for change in _section_changed(baseline_diff, "processes"):
        before, after = change.get("before"), change.get("after")
        if not isinstance(before, Mapping) or not isinstance(after, Mapping):
            continue
        old_hashes, new_hashes = before.get("sha256_by_exe"), after.get("sha256_by_exe")
        if not isinstance(old_hashes, Mapping) or not isinstance(new_hashes, Mapping):
            continue
        for exe in sorted(path for path in old_hashes.keys() & new_hashes.keys()
                          if isinstance(path, str)):
            if not exe or len(exe) >= 1024:
                continue
            old_digest = _text(old_hashes.get(exe), 64).lower()
            new_digest = _text(new_hashes.get(exe), 64).lower()
            if (not _SHA256.fullmatch(old_digest) or not _SHA256.fullmatch(new_digest)
                    or old_digest == new_digest):
                continue
            evidence = {"process_name": _text(after.get("name"), 128), "exe": exe,
                        "old_sha256": old_digest, "new_sha256": new_digest,
                        "hash_source": "executable_path_file"}
            findings.append(_finding(
                "defender.executable_hash_change",
                title=f"On-disk executable changed at the same path: {evidence['process_name'] or 'unnamed'}",
                evidence=evidence,
                explanation="The SHA-256 of the file currently at this process executable path differs from the approved baseline. This may be a software update or replacement; it does not prove the in-memory process image changed or that the file is malware.",
                action="Check package or signing history, file metadata, and the process launch time before accepting the new baseline.",
                observed_at=observed_at, confidence=0.84,
            ))

    # Use newly added processes when a diff exists. A first scan still reviews
    # suspicious execution locations, but does not claim a baseline change.
    new_process_names = {_text(row.get("name"), 128).casefold() for row in _section_added(baseline_diff, "processes")}
    process_candidates = [row for row in processes if _text(row.get("name"), 128).casefold() in new_process_names] if baseline_diff is not None else processes
    for row in process_candidates:
        exe = _text(row.get("exe"))
        if not exe or not _TEMP_PATH.search(exe):
            continue
        evidence = {"pid": _integer(row.get("pid")), "ppid": _integer(row.get("ppid")), "process_name": _text(row.get("name"), 128), "exe": exe}
        findings.append(_finding(
            "defender.process_in_temp", title=f"Process running from a writable staging path: {evidence['process_name'] or 'unnamed'}",
            evidence=evidence,
            explanation="An executable is running from a temporary or downloads directory. Installers and developer tools can do this legitimately.",
            action="Check the file signature or hash and the parent process before deciding whether to investigate further.",
            observed_at=observed_at, confidence=0.45,
        ))

    # Only explicit watched roots and a trusted baseline can support a file
    # integrity change claim. A lone update must not become ransomware noise.
    sections = baseline_diff.get("sections") if isinstance(baseline_diff, Mapping) else None
    file_section = sections.get("files") if isinstance(sections, Mapping) else None
    watched_roots = (baseline_diff or {}).get("file_roots") if isinstance(baseline_diff, Mapping) else None
    if isinstance(file_section, Mapping) and isinstance(watched_roots, list) and watched_roots:
        changed_hashes = [row for row in _rows(file_section.get("changed"))
                          if isinstance(row.get("before"), Mapping) and isinstance(row.get("after"), Mapping)
                          and row["before"].get("status") == row["after"].get("status") == "hashed"
                          and row["before"].get("sha256") and row["after"].get("sha256")
                          and row["before"]["sha256"] != row["after"]["sha256"]]
        removed = [row for row in _rows(file_section.get("removed")) if row.get("status") == "hashed"]
        added = _rows(file_section.get("added"))
        affected = len(changed_hashes) + len(removed)
        baseline_count = max(0, len(_rows(inventory.get("files"))) - len(added) + len(removed))
        if affected >= 20 or (affected >= 10 and baseline_count > 0 and affected / baseline_count >= 0.2):
            evidence = {"changed_count": len(changed_hashes), "removed_count": len(removed),
                        "affected_count": affected, "baseline_file_count": baseline_count,
                        "watched_root_count": len(watched_roots)}
            findings.append(_finding(
                "defender.file_integrity_burst", title=f"{affected} watched files changed or disappeared",
                evidence=evidence,
                explanation="A substantial group of files under explicitly watched roots changed content or disappeared since the approved baseline. Updates, builds, and cleanup can cause this too; it is not proof of ransomware.",
                action="Review the changed paths, process and backup activity around this time before changing the baseline.",
                observed_at=observed_at, confidence=0.75,
            ))

    return sorted(findings, key=lambda item: (item["rule_id"], item["finding_id"]))


def detect_tcp_syn_probes(
    capture: Mapping[str, Any], inventory: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Correlate only bounded TShark TCP SYN metadata with exact local IPs.

    A short SYN burst across ports is a probe *indicator*. It does not establish
    intrusion, successful connection, actor intent, or malicious identity.
    Source must be globally routable; private/local sources are excluded here
    to avoid treating local software and LAN discovery as an external probe.
    """

    if not isinstance(capture, Mapping) or not isinstance(inventory, Mapping):
        raise TypeError("capture and inventory must be mappings")
    if capture.get("ok") is not True or capture.get("tool") != "tshark":
        return []
    duration = capture.get("duration_seconds")
    packets = capture.get("packets")
    if type(duration) is not int or not 1 <= duration <= 30 or not isinstance(packets, list) or len(packets) > 1000:
        return []

    local_addresses: set[str] = set()
    for interface in _rows(inventory.get("interfaces")):
        addresses = interface.get("addresses")
        if not isinstance(addresses, list):
            continue
        for item in addresses:
            try:
                address = str(item).split("/", 1)[0].split("%", 1)[0]
                local_addresses.add(str(ipaddress.ip_address(address)))
            except ValueError:
                continue
    if not local_addresses:
        return []

    observations: dict[tuple[str, str], list[tuple[datetime, int]]] = {}
    for packet in packets:
        if not isinstance(packet, Mapping) or packet.get("protocol") != "tcp":
            continue
        if packet.get("tcp_syn") is not True or packet.get("tcp_ack") is not False:
            continue
        try:
            source_ip = ipaddress.ip_address(str(packet.get("source") or ""))
            destination = str(ipaddress.ip_address(str(packet.get("destination") or "")))
            stamp = _timestamp(packet.get("timestamp"), "packet timestamp")
        except ValueError:
            continue
        port = packet.get("destination_port")
        if (not source_ip.is_global or str(source_ip) in local_addresses
                or destination not in local_addresses or type(port) is not int
                or not 1 <= port <= 65535):
            continue
        observations.setdefault((str(source_ip), destination), []).append((stamp, port))

    findings: list[dict[str, Any]] = []
    for (source, destination), rows in observations.items():
        rows.sort(key=lambda row: row[0])
        left = 0
        port_counts: Counter[int] = Counter()
        best: list[tuple[datetime, int]] = []
        best_port_count = 0
        for right, row in enumerate(rows):
            port_counts[row[1]] += 1
            while (row[0] - rows[left][0]).total_seconds() > 30:
                old_port = rows[left][1]
                port_counts[old_port] -= 1
                if port_counts[old_port] == 0:
                    del port_counts[old_port]
                left += 1
            if len(port_counts) > best_port_count:
                best_port_count = len(port_counts)
                best = rows[left:right + 1]
        if best_port_count < 8:
            continue
        ports = sorted({row[1] for row in best})
        evidence = {
            "source_ip": source, "interface": _text(capture.get("interface"), 128),
            "local_destinations": [destination], "distinct_port_count": len(ports),
            "destination_ports": ports[:64], "syn_packet_count": len(best),
            "first_seen": best[0][0].isoformat(timespec="milliseconds"),
            "last_seen": best[-1][0].isoformat(timespec="milliseconds"),
            "capture_duration_seconds": duration,
        }
        findings.append(_finding(
            "defender.tcp_syn_port_probe",
            title=f"TCP SYN port-probe indicator from {source}",
            evidence=evidence,
            explanation="One external source sent SYN-only TCP packets to at least eight distinct ports on an observed local address within 30 seconds. This pattern warrants review but does not prove an intrusion or identify an actor.",
            action="Review the local firewall, service exposure, and surrounding capture metadata; preserve the scan artifact for triage.",
            observed_at=_text(capture.get("finished_at"), 64), confidence=0.82,
            source="tshark_capture",
        ))
    return sorted(findings, key=lambda item: item["finding_id"])


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be an ISO-8601 timestamp with timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp with timezone") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _normalize_indicator(row: Mapping[str, Any]) -> dict[str, str]:
    kind = _text(row.get("type"), 16).lower()
    value = _text(row.get("value"), 253)
    if kind == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(f"invalid IP indicator: {value!r}") from exc
    elif kind == "domain":
        value = value.rstrip(".").lower()
        if not _DOMAIN.fullmatch(value):
            raise ValueError(f"invalid exact domain indicator: {value!r}")
    elif kind == "sha256":
        value = value.lower()
        if not _SHA256.fullmatch(value):
            raise ValueError("SHA-256 indicator must contain exactly 64 hex digits")
    else:
        raise ValueError(f"unsupported indicator type: {kind!r}")
    return {"type": kind, "value": value}


def _validate_feed(payload: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    source = _text(payload.get("source"), 200)
    url = _text(payload.get("url"), 1000)
    parsed_url = urlparse(url)
    if (not source or parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname or parsed_url.username or parsed_url.password
            or parsed_url.query or parsed_url.fragment):
        raise ValueError("indicator feed needs a source and an HTTP(S) provenance URL")
    retrieved = _timestamp(payload.get("retrieved_at"), "retrieved_at")
    expires = _timestamp(payload.get("expires_at"), "expires_at")
    if expires <= retrieved:
        raise ValueError("expires_at must be later than retrieved_at")
    if now is not None and now.tzinfo is None:
        raise ValueError("current time must include a timezone")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if retrieved > current:
        raise ValueError("indicator feed retrieved_at is in the future")
    if expires <= current:
        raise ValueError("indicator feed is expired; refresh and review it before use")
    rows = payload.get("indicators")
    if not isinstance(rows, list) or len(rows) > _MAX_IOCS:
        raise ValueError("indicators must be a list of at most 10000 entries")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("every indicator must be an object")
        item = _normalize_indicator(row)
        key = (item["type"], item["value"])
        if key not in seen:
            normalized.append(item)
            seen.add(key)
    return {
        "schema_version": "1",
        "source": source,
        "url": url,
        "retrieved_at": retrieved.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "indicators": normalized,
    }


def load_indicators(path: str | Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Load a reviewed local IOC file; never fetch or silently trust a feed.

    Schema: ``{"source":"...", "url":"https://...", "retrieved_at":"...Z",
    "expires_at":"...Z", "indicators":[{"type":"ip|domain|sha256",
    "value":"..."}]}``. Matching is exact only. An expired feed is refused.
    """

    target = Path(path)
    if target.stat().st_size > _MAX_IOC_FILE_BYTES:
        raise ValueError("indicator file exceeds 2 MB")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("indicator file must be UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("indicator file must contain a JSON object")
    return _validate_feed(payload, now=now)


def match_indicators(
    inventory: Mapping[str, Any], indicators: Mapping[str, Any], *, now: datetime | None = None
) -> list[dict[str, Any]]:
    """Match reviewed IP/domain/SHA-256 IOCs to observed local metadata.

    Exact network matches may still be benign because addresses and domains can
    be shared or reassigned. A hash match identifies bytes, not a threat actor.
    """

    if not isinstance(inventory, Mapping):
        raise TypeError("inventory must be a mapping")
    feed = _validate_feed(indicators, now=now)
    lookup = {(row["type"], row["value"]) for row in feed["indicators"]}
    provenance = {key: feed[key] for key in ("source", "url", "retrieved_at", "expires_at")}
    observed_at = _text(inventory.get("collected_at"), 64)
    processes = _rows(inventory.get("processes"))
    by_pid = {pid: row for row in processes if (pid := _integer(row.get("pid"))) is not None}
    findings: list[dict[str, Any]] = []
    matched: set[tuple[str, str, str]] = set()

    for conn in _rows(inventory.get("connections")):
        remote = _text(conn.get("remote_address"), 253).rstrip(".").lower()
        if not remote:
            continue
        try:
            kind, value = "ip", str(ipaddress.ip_address(remote))
        except ValueError:
            kind, value = "domain", remote
        if (kind, value) not in lookup:
            continue
        pid = _integer(conn.get("pid"))
        key = (kind, value, f"connection:{pid}:{_text(conn.get('remote_port'), 16)}")
        if key in matched:
            continue
        matched.add(key)
        owner = by_pid.get(pid or -1, {})
        evidence = {"indicator_type": kind, "indicator_value": value, "remote_address": remote,
                    "remote_port": _integer(conn.get("remote_port")), "pid": pid,
                    "process_name": _text(owner.get("name"), 128)}
        findings.append(_finding(
            "defender.ioc_match", title=f"Network endpoint matched a reviewed {kind.upper()} indicator",
            evidence=evidence,
            explanation="A connection endpoint exactly matches the supplied indicator. Shared or reassigned infrastructure can produce false positives; this does not identify an actor.",
            action="Check the source's current context, process owner, timing, and other independent evidence.",
            observed_at=observed_at, confidence=0.72, source="reviewed_local_ioc", provenance=provenance,
        ))

    # Optional TShark metadata flows have IP endpoints only. Treat both ends
    # as observed endpoints, not as an inferred remote actor or DNS identity.
    for flow in _rows(inventory.get("flows")):
        source_ip = _text(flow.get("source"), 128)
        destination_ip = _text(flow.get("destination"), 128)
        for endpoint_name, raw_ip in (("source", source_ip), ("destination", destination_ip)):
            try:
                value = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                continue
            if ("ip", value) not in lookup:
                continue
            key = ("ip", value, f"flow:{source_ip}:{destination_ip}:{_text(flow.get('protocol'), 16)}:{_text(flow.get('source_port'), 16)}:{_text(flow.get('destination_port'), 16)}")
            if key in matched:
                continue
            matched.add(key)
            evidence = {
                "indicator_type": "ip", "indicator_value": value,
                "observation_source": "tshark_flow", "observed_endpoint": endpoint_name,
                "source_ip": source_ip, "destination_ip": destination_ip,
                "protocol": _text(flow.get("protocol"), 16),
                "source_port": _integer(flow.get("source_port")),
                "destination_port": _integer(flow.get("destination_port")),
                "packet_count": _integer(flow.get("packets")),
            }
            findings.append(_finding(
                "defender.ioc_match", title="Packet-flow IP matched a reviewed indicator",
                evidence=evidence,
                explanation="A bounded packet-metadata flow included this exact IP indicator. It does not reveal payload contents, a domain, or an actor; shared or reassigned addresses can be benign.",
                action="Review the flow timing, local endpoint, and current indicator context before escalating.",
                observed_at=observed_at, confidence=0.72, source="tshark_flow", provenance=provenance,
            ))

    for row in processes + [row for row in _rows(inventory.get("files")) if row.get("status") == "hashed"]:
        value = _text(row.get("sha256"), 64).lower()
        if ("sha256", value) not in lookup:
            continue
        path = _text(row.get("exe") or row.get("path"))
        key = ("sha256", value, path)
        if key in matched:
            continue
        matched.add(key)
        evidence = {"indicator_type": "sha256", "indicator_value": value,
                    "pid": _integer(row.get("pid")), "process_name": _text(row.get("name"), 128), "exe": path}
        findings.append(_finding(
            "defender.ioc_match", title="File hash matched a reviewed SHA-256 indicator",
            evidence=evidence,
            explanation="Observed file bytes match an exact SHA-256 indicator. The indicator's source and age still need review; this does not identify an actor.",
            action="Preserve the hash and file metadata, then validate the source and investigate the owning process.",
            observed_at=observed_at, confidence=0.92, severity="high", source="reviewed_local_ioc", provenance=provenance,
        ))

    return sorted(findings, key=lambda item: item["finding_id"])


def evaluate_homeguard_devices(
    devices: Iterable[Mapping[str, Any]], *, definitions: Mapping[str, Any] | None = None,
    baseline_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Explicit, lazy adapter for HomeGuard's actual network device engine.

    Install HomeGuard separately to use it. This adapter only evaluates the
    supplied device observations; it does not discover hosts, update a baseline,
    fetch feeds, or modify network settings. Loading HomeGuard's local
    definition cache may initialize bundled starter definitions on first use.
    The package remains optional so a bare Python ``gn`` install boots.
    """

    try:
        from greynoc_homeguard.baseline import BaselineStore
        from greynoc_homeguard.definitions import DefinitionManager
        from greynoc_homeguard.detection import HomeGuardDetectionEngine
        from greynoc_homeguard.models import Device
    except ImportError as exc:
        raise RuntimeError("HomeGuard is optional; install GreyNOC/HomeGuard to evaluate device rules") from exc
    active_definitions = dict(definitions) if definitions is not None else DefinitionManager().load()
    baseline = BaselineStore(baseline_path).load() if baseline_path is not None else None
    observations = [Device.from_dict(dict(row)) for row in devices]
    raw_findings = HomeGuardDetectionEngine(active_definitions).evaluate(observations, baseline)
    output: list[dict[str, Any]] = []
    for finding in raw_findings:
        row = finding.as_dict()
        row["source"] = "homeguard_optional_engine"
        row["assessment"] = "review_indicator"
        row["provenance"] = {
            "project": "GreyNOC/HomeGuard",
            "url": "https://github.com/GreyNOC/HomeGuard",
            "license": "MIT",
        }
        output.append(row)
    return output
