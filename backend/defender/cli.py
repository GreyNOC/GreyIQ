"""``gn defend``: bounded, local endpoint inventory and defensive monitoring.

Registration is deliberately import-light.  The source CLI runs with a bare
Python installation; collectors and optional tool adapters load only after an
operator invokes a defender subcommand.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import secrets
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


_MAX_RUN_ARTIFACTS = 10_000
_MAX_RUN_BYTES = 512 * 1024 * 1024
_MIN_FREE_BYTES = 128 * 1024 * 1024


def register_cli(sub: Any) -> None:
    defend = sub.add_parser("defend", aliases=["defender"],
                            help="inventory this host, compare a trusted baseline, and monitor local threats")
    commands = defend.add_subparsers(dest="defend_command", required=True)

    inventory = commands.add_parser("inventory", help="read-only local host and process map")
    _paths(inventory)
    _process_hashes(inventory)
    _json(inventory)
    inventory.set_defaults(func=_inventory)

    baseline = commands.add_parser("baseline", help="manage an operator-selected host reference snapshot")
    baseline_commands = baseline.add_subparsers(dest="baseline_command", required=True)
    create = baseline_commands.add_parser("create", help="capture the current operator-reviewed state")
    _paths(create)
    _process_hashes(create)
    create.add_argument("--file", default="", help="baseline file (default: GreyIQ runtime/defender/baseline.json)")
    create.add_argument("--accept-current-state", action="store_true", required=True,
                        help="assert that the current host state was reviewed and is safe to trust")
    create.add_argument("--replace", action="store_true", help="replace an existing baseline")
    _json(create)
    create.set_defaults(func=_baseline_create)
    compare = baseline_commands.add_parser("compare", help="compare the current state to the operator reference")
    _paths(compare)
    _process_hashes(compare)
    compare.add_argument("--file", default="", help="baseline file")
    _json(compare)
    compare.set_defaults(func=_baseline_compare)
    show = baseline_commands.add_parser("show", help="show baseline metadata and collection coverage")
    show.add_argument("--file", default="", help="baseline file")
    _json(show)
    show.set_defaults(func=_baseline_show)

    scan = commands.add_parser("scan", help="inventory and evaluate local indicators once")
    _scan_flags(scan)
    scan.set_defaults(func=_scan)

    watch = commands.add_parser("watch", help="repeat local scans and append a structured event each cycle")
    _scan_flags(watch)
    watch.add_argument("--interval", type=int, default=60, metavar="SECONDS",
                       help="seconds between cycles (60-3600; default: 60)")
    watch.add_argument("--iterations", type=int, default=0, metavar="N",
                       help="stop after N cycles; 0 watches until Ctrl-C")
    watch.set_defaults(func=_watch)

    dashboard = commands.add_parser("dash", aliases=["dashboard"],
                                    help="live neon terminal view of local ports, packet metadata, and indicators")
    _scan_flags(dashboard, capture_seconds=3, include_json=False)
    dashboard.add_argument("--interval", type=int, default=5, metavar="SECONDS",
                           help="seconds between completed scans, 2-3600 (default: 5)")
    dashboard.set_defaults(func=_dashboard)

    trace = commands.add_parser("trace", help="correlate a local PID or remote IP with observed sockets")
    target = trace.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int, help="local process ID")
    target.add_argument("--remote", help="remote IP address seen in a local socket")
    _json(trace)
    trace.set_defaults(func=_trace)

    events = commands.add_parser("events", help="read the local defender event journal")
    events.add_argument("--limit", type=int, default=50, help="last N events (1-1000)")
    events.add_argument("--verify", action="store_true", help="verify the journal hash chain and head checkpoint")
    events.add_argument("--verify-artifacts", action="store_true",
                        help="also verify every journal-linked compressed observation")
    _json(events)
    events.set_defaults(func=_events)

    rules = commands.add_parser("rules", help="list built-in indicators and provenance")
    _json(rules)
    rules.set_defaults(func=_rules)

    homeguard = commands.add_parser("homeguard", help="evaluate a local device export with the optional HomeGuard engine")
    homeguard.add_argument("devices", help="JSON file containing a devices array from an authorized local inventory")
    homeguard.add_argument("--homeguard-baseline", default="", help="optional HomeGuard device baseline file")
    _json(homeguard)
    homeguard.set_defaults(func=_homeguard)

    status = commands.add_parser("status", help="show baseline, journal, and optional tool availability")
    _json(status)
    status.set_defaults(func=_status)


def _json(parser: Any) -> None:
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")


def _paths(parser: Any) -> None:
    parser.add_argument("--path", action="append", default=[], metavar="DIR",
                        help="explicit directory or file for bounded SHA-256 integrity inventory (repeatable)")


def _process_hashes(parser: Any) -> None:
    parser.add_argument("--hash-processes", action="store_true",
                        help="hash observed process executable files within fixed file and byte limits")


def _scan_flags(parser: Any, *, capture_seconds: int = 10, include_json: bool = True) -> None:
    _paths(parser)
    _process_hashes(parser)
    parser.add_argument("--baseline", default="", help="trusted baseline file (default: runtime/defender/baseline.json)")
    parser.add_argument("--indicators", default="", metavar="JSON",
                        help="reviewed IOC file with source and expiry metadata")
    parser.add_argument("--nmap-target", default="", metavar="HOST_OR_CIDR",
                        help="optional bounded local network scan target")
    parser.add_argument("--scope", default="", metavar="HOST_OR_CIDR",
                        help="exact authorized local scan boundary (required with --nmap-target)")
    parser.add_argument("--capture-interface", default="", metavar="IFACE",
                        help="optional non-promiscuous TShark metadata capture interface")
    parser.add_argument("--capture-seconds", type=int, default=capture_seconds, metavar="N",
                        help=f"TShark capture duration, 1-30 seconds (default: {capture_seconds})")
    parser.add_argument("--packet-limit", type=int, default=500, metavar="N",
                        help="TShark packet cap, 1-1000 (default: 500)")
    parser.add_argument("-y", "--authorize-local-scan", action="store_true",
                        help="assert authorization for the named local network/interface")
    if include_json:
        _json(parser)


def _root() -> Path:
    return _runtime() / "defender"


def _private_runtime(platform_name: str, env: dict[str, str], home: Path) -> Path | None:
    """Use a per-user data directory where source/bundle paths may sync or be read-only."""
    if platform_name == "win32":
        # Electron's userData defaults to appData/GreyIQ; use the same location
        # for a standalone frozen CLI so its evidence survives app upgrades.
        candidate = Path(env.get("APPDATA") or "")
        base = candidate if candidate.is_absolute() else home / "AppData" / "Roaming"
        return (base / "GreyIQ" / "runtime").resolve()
    if platform_name == "darwin":
        return (home / "Library" / "Application Support" / "GreyIQ" / "runtime").resolve()
    return None


def _runtime() -> Path:
    from gn_cli import RUNTIME_DIR

    if os.getenv("GREYIQ_RUNTIME_DIR") is not None:
        return RUNTIME_DIR
    return _private_runtime(sys.platform, os.environ, Path.home()) or RUNTIME_DIR


def _baseline_file(raw: str) -> Path:
    return Path(raw).expanduser().resolve() if raw else _root() / "baseline.json"


def _err(message: str) -> int:
    print(f"gn defend: {message}", file=sys.stderr)
    return 2


def _print(payload: Any, *, as_json: bool, heading: str = "") -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return
    if heading:
        print(heading)
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(value, (dict, list)):
                print(f"  {key}: {json.dumps(value, sort_keys=True, default=str)}")
            else:
                print(f"  {key}: {value}")
    elif isinstance(payload, list):
        for item in payload:
            print(json.dumps(item, sort_keys=True, default=str))
    else:
        print(payload)


def _event(kind: str, *, evidence: dict[str, Any] | None = None,
           status: str = "complete", message: str = "") -> dict[str, Any]:
    from defender.events import append_event

    return append_event(_runtime(), {"type": kind, "title": kind.replace("_", " ").title(),
                                     "source": "greyiq_defender", "status": status,
                                     "message": message, "evidence": evidence or {}})


def _artifact(kind: str, payload: Any) -> dict[str, Any]:
    """Retain complete evidence within a disk budget; never prune referenced runs."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, default=str).encode("utf-8")
    if len(encoded) > 32 * 1024 * 1024:
        raise ValueError("defender observation exceeds the 32 MiB artifact limit")
    compressed = gzip.compress(encoded, mtime=0)
    directory = _root() / "runs"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        directory.parent.chmod(0o700)
        directory.chmod(0o700)
    if len(compressed) > _MAX_RUN_BYTES:
        raise ValueError("defender evidence budget reached; archive the runtime/defender directory "
                         "and select a fresh GREYIQ_RUNTIME_DIR before continuing")
    count = 0
    used = 0
    with os.scandir(directory) as entries:
        for entry in entries:
            if not entry.name.endswith(".json.gz") or not entry.is_file(follow_symlinks=False):
                continue
            count += 1
            used += entry.stat(follow_symlinks=False).st_size
    if count >= _MAX_RUN_ARTIFACTS or used + len(compressed) > _MAX_RUN_BYTES:
        raise ValueError("defender evidence budget reached; archive the runtime/defender directory "
                         "and select a fresh GREYIQ_RUNTIME_DIR before continuing")
    if shutil.disk_usage(directory).free < max(_MIN_FREE_BYTES, len(compressed) + 16 * 1024 * 1024):
        raise OSError("defender stopped: less than 128 MiB of free disk space remains")
    name = (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" +
            secrets.token_hex(6) + f"-{kind}.json.gz")
    target = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(compressed)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return {"artifact_path": str(target), "artifact_relpath": f"runs/{name}",
            "artifact_sha256": hashlib.sha256(compressed).hexdigest(),
            "artifact_bytes": len(compressed)}


def _evidence(current: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    counts = _counts(current)
    return {**artifact, "process_count": counts["processes"],
            "connection_count": counts["connections"],
            "file_count": counts["files"], "error_count": len(current.get("errors") or [])}


def _inventory(args: argparse.Namespace) -> int:
    from defender.inventory import collect_inventory

    current = collect_inventory(paths=tuple(args.path), hash_processes=args.hash_processes)
    artifact = _artifact("inventory", current)
    _event("inventory", evidence=_evidence(current, artifact))
    _print(current if args.json else {**_inventory_summary(current), **artifact}, as_json=args.json,
           heading="Local host inventory")
    return 0


def _counts(current: dict[str, Any]) -> dict[str, int]:
    return {key: len(current.get(key) or []) for key in
            ("processes", "connections", "interfaces", "routes", "services", "startup", "packages", "files")}


def _inventory_summary(current: dict[str, Any]) -> dict[str, Any]:
    return {"host": current.get("host"), "collected_at": current.get("collected_at"),
            "counts": _counts(current), "file_roots": current.get("file_roots") or [],
            "coverage": current.get("coverage"), "errors": current.get("errors") or []}


def _baseline_create(args: argparse.Namespace) -> int:
    from defender.baseline import save_baseline
    from defender.inventory import collect_inventory

    path = _baseline_file(args.file)
    if path.exists() and not args.replace:
        return _err(f"baseline exists at {path}; use --replace after reviewing the host state")
    current = collect_inventory(paths=tuple(args.path), hash_processes=args.hash_processes)
    baseline = save_baseline(current, path, replace=args.replace)
    archive = baseline.get("archive") or {}
    _event("baseline_created", evidence={"baseline_path": str(path),
           "baseline_sha256": baseline["sha256"], "process_count": len(current["processes"]),
           "connection_count": len(current["connections"]),
           "file_count": len(current["files"]), "error_count": len(current["errors"]),
           "archive_path": archive.get("path"), "archive_sha256": archive.get("sha256"),
           "archive_relpath": Path(archive["path"]).name if archive.get("path") else None,
           "prior_baseline_sha256": archive.get("baseline_sha256")})
    summary = {"path": str(path), "created_at": baseline["created_at"],
               "sha256": baseline["sha256"], "archive": archive or None,
               "inventory": _inventory_summary(current)}
    _print({"path": str(path), "baseline": baseline} if args.json else summary, as_json=args.json,
           heading="Operator reference baseline created")
    return 0


def _baseline_compare(args: argparse.Namespace) -> int:
    from defender.baseline import compare_baseline, load_baseline
    from defender.inventory import collect_inventory

    path = _baseline_file(args.file)
    if not path.is_file():
        return _err(f"no baseline at {path}; first run `gn defend baseline create --accept-current-state`")
    baseline = load_baseline(path)
    roots = tuple(args.path or baseline["inventory"].get("file_roots") or ())
    reference_hashes = baseline["inventory"].get("coverage", {}).get("process_binaries")
    hash_processes = args.hash_processes or reference_hashes in {"ok", "partial"}
    current = collect_inventory(paths=roots, hash_processes=hash_processes)
    diff = compare_baseline(current, baseline)
    artifact = _artifact("comparison", {"inventory": current, "diff": diff,
                                        "baseline_sha256": baseline["sha256"]})
    _event("baseline_compared", evidence={**_evidence(current, artifact),
                                          "baseline_sha256": baseline["sha256"]})
    _print(diff, as_json=args.json, heading="Baseline differences (review indicators, not confirmed threats)")
    return 0


def _baseline_show(args: argparse.Namespace) -> int:
    from defender.baseline import load_baseline

    path = _baseline_file(args.file)
    if not path.is_file():
        return _err(f"no baseline at {path}")
    baseline = load_baseline(path)
    reference = baseline["inventory"]
    info = {"created_at": baseline["created_at"], "sha256": baseline["sha256"],
            "host": reference["host"], "counts": _counts(reference),
            "file_roots": reference["file_roots"], "coverage": reference["coverage"],
            "errors": reference["errors"]}
    _print({"path": str(path), **info}, as_json=args.json, heading="Operator reference baseline metadata")
    return 0


def _validate_active(args: argparse.Namespace) -> str:
    if args.nmap_target and not args.scope:
        return "--nmap-target requires an exact --scope and -y/--authorize-local-scan"
    if (args.nmap_target or args.capture_interface) and not args.authorize_local_scan:
        return "active network scan/capture requires -y/--authorize-local-scan"
    if args.scope and not args.nmap_target:
        return "--scope requires --nmap-target"
    if not 1 <= args.capture_seconds <= 30:
        return "--capture-seconds must be 1-30"
    if not 1 <= args.packet_limit <= 1000:
        return "--packet-limit must be 1-1000"
    return ""


def _scan_once(args: argparse.Namespace, *, require_baseline: bool = False,
               include_observation: bool = False) -> dict[str, Any]:
    from defender.baseline import compare_baseline, load_baseline
    from defender.detection import evaluate_inventory
    from defender.inventory import collect_inventory

    feed = None
    if args.indicators:
        from defender.detection import load_indicators

        try:
            feed = load_indicators(Path(args.indicators))
        except (OSError, ValueError) as exc:
            raise ValueError(f"indicator file could not be used: {exc}") from exc
    path = _baseline_file(args.baseline)
    if require_baseline and not path.is_file():
        raise ValueError(f"watch baseline disappeared at {path}; watch stopped")
    baseline = load_baseline(path) if require_baseline or path.is_file() else None
    roots = tuple(args.path or (baseline["inventory"].get("file_roots") or () if baseline else ()))
    feed_hashes = any(row.get("type") == "sha256" for row in feed["indicators"]) if feed else False
    reference_hashes = (baseline["inventory"].get("coverage", {}).get("process_binaries")
                        if baseline else None)
    hash_processes = args.hash_processes or feed_hashes or reference_hashes in {"ok", "partial"}
    current = collect_inventory(paths=roots, hash_processes=hash_processes)
    diff = compare_baseline(current, baseline) if baseline else None
    findings = evaluate_inventory(current, baseline_diff=diff)
    tools: dict[str, Any] = {}
    if args.nmap_target or args.capture_interface:
        from defender.tools import capture_tshark, run_nmap

        if args.nmap_target:
            tools["nmap"] = run_nmap(args.nmap_target, authorized=args.authorize_local_scan,
                                      scope=args.scope)
        if args.capture_interface:
            tools["tshark"] = capture_tshark(args.capture_interface,
                                               authorized=args.authorize_local_scan,
                                               seconds=args.capture_seconds,
                                               packet_limit=args.packet_limit)
            from defender.detection import detect_tcp_syn_probes

            findings.extend(detect_tcp_syn_probes(tools["tshark"], current))
    if feed is not None:
        from defender.detection import match_indicators

        observations = {**current, "flows": (tools.get("tshark") or {}).get("flows") or []}
        findings.extend(match_indicators(observations, feed))
    if diff is not None:
        from defender.correlation import correlate_endpoint_changes

        findings.extend(correlate_endpoint_changes(current, diff, findings))
    findings.sort(key=lambda item: (item.get("rule_id", ""), item.get("finding_id", "")))
    result = {"at": current.get("collected_at"), "host": current.get("host"),
              "baseline": str(path) if baseline else None,
              "baseline_sha256": baseline["sha256"] if baseline else None,
              "inventory": _inventory_summary(current), "diff": diff,
              "findings": findings, "tools": tools}
    artifact = _artifact("scan", {"result": result, "inventory": current})
    result["artifact"] = artifact
    tool_failures = [name for name, data in tools.items() if not data.get("ok")]
    _event("scan", status="partial" if tool_failures or current.get("errors") else "complete",
           evidence={**_evidence(current, artifact), "finding_count": len(findings),
                     "baseline_sha256": baseline["sha256"] if baseline else None,
                     "tool": ",".join(sorted(tools)) if tools else "passive",
                     "error_code": ",".join(tool_failures) if tool_failures else ""})
    if include_observation:
        result["observation"] = current
    return result


def _scan(args: argparse.Namespace) -> int:
    refusal = _validate_active(args)
    if refusal:
        return _err(refusal)
    if args.nmap_target:
        from defender.tools import validate_nmap_scope

        guard_error = validate_nmap_scope(args.nmap_target, args.scope)
        if guard_error:
            return _err(guard_error)
    try:
        result = _scan_once(args)
    except (OSError, ValueError) as exc:
        return _err(str(exc))
    _print(result if args.json else _scan_summary(result), as_json=args.json,
           heading="Local defender scan")
    return 1 if any(not data.get("ok") for data in result["tools"].values()) else 0


def _scan_summary(result: dict[str, Any]) -> dict[str, Any]:
    return {"at": result["at"], "host": result["host"],
            "baseline": result["baseline"] or "none (create after reviewing a known-good state)",
            "baseline_sha256": result.get("baseline_sha256"),
            "inventory": result["inventory"],
            "changes": result["diff"].get("summary") if result["diff"] else None,
            "findings": result["findings"],
            "tools": {name: {"ok": data.get("ok"), "status": data.get("status"),
                             "summary": data.get("summary"), "error": data.get("error")}
                      for name, data in result["tools"].items()},
            "artifact": result["artifact"]}


def _watch(args: argparse.Namespace) -> int:
    import time

    refusal = _validate_active(args)
    if refusal:
        return _err(refusal)
    if args.nmap_target:
        from defender.tools import validate_nmap_scope

        guard_error = validate_nmap_scope(args.nmap_target, args.scope)
        if guard_error:
            return _err(guard_error)
    if not 60 <= args.interval <= 3600:
        return _err("--interval must be 60-3600 seconds")
    if args.iterations < 0 or args.iterations > 10000:
        return _err("--iterations must be 0-10000")
    if args.nmap_target and args.interval < 300:
        return _err("recurring Nmap scans require --interval of at least 300 seconds")
    path = _baseline_file(args.baseline)
    if not path.is_file():
        return _err(f"watch requires a reviewed baseline at {path}")
    cycle = 0
    try:
        while not args.iterations or cycle < args.iterations:
            try:
                result = _scan_once(args, require_baseline=True)
            except (OSError, ValueError) as exc:
                _event("watch_stopped", status="failed", evidence={"count": cycle},
                       message=f"scan failed: {type(exc).__name__}")
                return _err(str(exc))
            cycle += 1
            failed_tools = [name for name, data in result["tools"].items() if not data.get("ok")]
            if args.json:
                print(json.dumps({"cycle": cycle, **result}, sort_keys=True, default=str), flush=True)
            else:
                _print(_scan_summary(result), as_json=False, heading=f"Defender watch cycle {cycle}")
            if failed_tools:
                _event("watch_stopped", status="failed",
                       evidence={"count": cycle, "tool": ",".join(failed_tools),
                                 "error_code": ",".join(str(result["tools"][name].get("status") or "tool_error")
                                                        for name in failed_tools)},
                       message="active network tool failed; watch stopped")
                return 1
            if args.iterations and cycle >= args.iterations:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        _event("watch_stopped", evidence={"count": cycle}, message="operator interrupt")
        return 0
    _event("watch_stopped", evidence={"count": cycle}, message="iteration limit")
    return 0


def _dashboard(args: argparse.Namespace) -> int:
    refusal = _validate_active(args)
    if refusal:
        return _err(refusal)
    if not 2 <= args.interval <= 3600:
        return _err("--interval must be 2-3600 seconds")
    if args.nmap_target:
        from defender.tools import validate_nmap_scope

        guard_error = validate_nmap_scope(args.nmap_target, args.scope)
        if guard_error:
            return _err(guard_error)
        if args.interval < 300:
            return _err("recurring Nmap scans require --interval of at least 300 seconds")
    from defender.dashboard import run_dashboard

    return run_dashboard(args, scan=lambda: _scan_once(args, include_observation=True))


def _trace(args: argparse.Namespace) -> int:
    from defender.inventory import collect_inventory
    from defender.trace import trace_pid

    current = collect_inventory()
    if args.pid is not None:
        if args.pid <= 0:
            return _err("--pid must be a positive local process ID")
        result = trace_pid(args.pid, inventory=current)
    else:
        import ipaddress

        try:
            remote = str(ipaddress.ip_address(args.remote))
        except ValueError:
            return _err("--remote must be an IP address observed in a local socket")
        matches = []
        for row in current.get("connections") or []:
            try:
                observed = str(ipaddress.ip_address(str(row.get("remote_address") or "")))
            except ValueError:
                continue
            if observed == remote:
                matches.append(row)
        pids = sorted({int(row["pid"]) for row in matches if str(row.get("pid") or "").isdigit()})
        result = {"remote": remote, "connections": matches,
                  "processes": [trace_pid(pid, inventory=current) for pid in pids],
                  "note": "Socket/PID correlation does not identify a remote person or actor."}
    artifact = _artifact("trace", result)
    _event("trace", evidence={**artifact, "pid": args.pid, "remote_address": args.remote,
                              "connection_count": len(result.get("connections") or [])})
    _print(result, as_json=args.json, heading="Local process/socket trace")
    return 0


def _events(args: argparse.Namespace) -> int:
    from defender.events import EventLogIntegrityError, read_events, verify_artifacts, verify_events

    if not 1 <= args.limit <= 1000:
        return _err("--limit must be 1-1000")
    journal = verify_events(_runtime()) if args.verify or args.verify_artifacts else None
    artifacts = verify_artifacts(_runtime()) if args.verify_artifacts else None
    if journal is not None and not journal.get("ok"):
        records = []
    else:
        try:
            records = read_events(_runtime(), limit=args.limit)
        except EventLogIntegrityError as exc:
            return _err(str(exc))
    payload = ({"verification": journal, "artifacts": artifacts, "events": records}
               if journal is not None else records)
    _print(payload, as_json=args.json, heading="Defender events")
    return 0 if (journal is None or journal.get("ok")) and (artifacts is None or artifacts.get("ok")) else 1


def _rules(args: argparse.Namespace) -> int:
    from defender.detection import list_rules

    _print(list_rules(), as_json=args.json, heading="Defender indicator rules")
    return 0


def _homeguard(args: argparse.Namespace) -> int:
    from defender.detection import evaluate_homeguard_devices

    source = Path(args.devices).expanduser().resolve()
    if not source.is_file() or source.stat().st_size > 2_000_000:
        return _err("HomeGuard devices file must exist and be at most 2 MB")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _err("HomeGuard devices file must be UTF-8 JSON")
    devices = payload.get("devices") if isinstance(payload, dict) else payload
    if not isinstance(devices, list) or len(devices) > 1024 or not all(isinstance(row, dict) for row in devices):
        return _err("HomeGuard devices file needs an array of at most 1024 device objects")
    try:
        findings = evaluate_homeguard_devices(
            devices, baseline_path=args.homeguard_baseline or None)
    except RuntimeError as exc:
        return _err(str(exc))
    result = {"source": str(source), "device_count": len(devices),
              "findings": findings, "engine": "GreyNOC/HomeGuard"}
    artifact = _artifact("homeguard", result)
    _event("homeguard", evidence={**artifact, "finding_count": len(findings),
                                  "count": len(devices), "tool": "HomeGuard"})
    _print({**result, "artifact": artifact}, as_json=args.json, heading="HomeGuard device indicators")
    return 0


def _status(args: argparse.Namespace) -> int:
    import shutil

    from defender.baseline import load_baseline
    from defender.events import verify_events

    root = _root()
    baseline = root / "baseline.json"
    journal = verify_events(_runtime())
    baseline_info = None
    if baseline.is_file():
        try:
            reference = load_baseline(baseline)
            baseline_info = {"path": str(baseline), "created_at": reference["created_at"],
                             "sha256": reference["sha256"],
                             "coverage": reference["inventory"].get("coverage", {})}
        except (OSError, ValueError) as exc:
            baseline_info = {"path": str(baseline), "error": str(exc)}
    payload = {"runtime": str(root), "baseline": baseline_info,
               "journal": journal,
               "nmap": shutil.which("nmap"), "tshark": shutil.which("tshark"),
               "note": "Nmap and TShark run only with explicit authorization and scope/interface."}
    _print(payload, as_json=args.json, heading="Defender status")
    return 0 if journal.get("ok") and not (baseline_info and baseline_info.get("error")) else 1
