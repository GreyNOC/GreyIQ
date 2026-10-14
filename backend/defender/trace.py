"""Local PID and socket correlation without external actor attribution."""

from __future__ import annotations

from typing import Any

from .inventory import collect_inventory

_MAX_ANCESTORS = 32
_MAX_CHILDREN = 256
_MAX_CONNECTIONS = 4096


def trace_pid(pid: int, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Trace a local process to parent/child PIDs and observed socket endpoints.

    PID ownership comes from the operating system's inventory at one point in
    time. A remote peer address is an observation, not an identified person or
    a conclusion that the peer is malicious.
    """
    try:
        target = int(pid)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("PID must be a non-negative integer") from exc
    if target < 0:
        raise ValueError("PID must be a non-negative integer")
    if inventory is None:
        inventory = collect_inventory()
    if not isinstance(inventory, dict):
        raise ValueError("inventory must be a snapshot dictionary")
    processes = [row for row in inventory.get("processes", []) if isinstance(row, dict)]
    by_pid = {row.get("pid"): row for row in processes if isinstance(row.get("pid"), int)}
    process = by_pid.get(target)
    output: dict[str, Any] = {
        "pid": target,
        "status": "observed" if process else "not_observed",
        "collected_at": inventory.get("collected_at"),
        "host": inventory.get("host", {}),
        "process": process,
        "ancestors": [],
        "children": [],
        "connections": [],
        "remote_peers": [],
        "coverage": {
            "processes": inventory.get("coverage", {}).get("processes", "unavailable"),
            "connections": inventory.get("coverage", {}).get("connections", "unavailable"),
        },
        "limitations": [
            "A PID can be reused after a process exits; verify the executable and start marker before acting.",
            "Remote socket endpoints are network observations, not identities or malicious-actor attribution.",
        ],
    }
    if process is None:
        output["limitations"].append("The process was absent or unavailable in this snapshot.")
        return output
    seen = {target}
    current = process
    for _ in range(_MAX_ANCESTORS):
        parent_pid = current.get("ppid")
        if not isinstance(parent_pid, int) or parent_pid in seen:
            break
        parent = by_pid.get(parent_pid)
        if parent is None:
            break
        output["ancestors"].append(parent)
        seen.add(parent_pid)
        current = parent
    output["children"] = sorted(
        (row for row in processes if row.get("ppid") == target and row.get("pid") != target),
        key=lambda row: row.get("pid", 0),
    )[:_MAX_CHILDREN]
    output["connections"] = sorted(
        (row for row in inventory.get("connections", [])
         if isinstance(row, dict) and row.get("pid") == target),
        key=lambda row: (str(row.get("protocol")), str(row.get("local_address")),
                         int(row.get("local_port") or 0), str(row.get("remote_address"))),
    )[:_MAX_CONNECTIONS]
    peers = {
        (str(row.get("remote_address") or ""), int(row.get("remote_port") or 0))
        for row in output["connections"] if row.get("remote_address") and row.get("remote_port")
    }
    output["remote_peers"] = [
        {"address": address, "port": port} for address, port in sorted(peers)
    ]
    if output["coverage"]["connections"] != "ok":
        output["limitations"].append("Socket inventory was incomplete; unlisted connections may exist.")
    return output
