"""GreyIQ BugHunter — live progress log for ad-hoc bounty scans/campaigns.

A scan or campaign route blocks on ``asyncio.to_thread`` until the whole hunt
finishes, so this is the only way the UI can show what's happening before the
response returns: a bounded, in-memory, per-run-id ring buffer the UI polls,
fed by the ``on_progress`` callback ``run_bounty_hunt``/``run_campaign``/
``run_campaign_over_targets`` already accept.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any, Callable

_MAX_RUNS = 8
_MAX_LINES_PER_RUN = 500
_lock = threading.Lock()
_runs: dict[str, dict[str, Any]] = {}
_run_order: list[str] = []


def start_run(run_id: str) -> None:
    """Reset (or create) the buffer for run_id, evicting the oldest run past _MAX_RUNS."""
    if not run_id:
        return
    with _lock:
        _runs[run_id] = {"events": [], "base_seq": 0}
        if run_id in _run_order:
            _run_order.remove(run_id)
        _run_order.append(run_id)
        while len(_run_order) > _MAX_RUNS:
            _runs.pop(_run_order.pop(0), None)


def log(run_id: str, message: str) -> None:
    if not run_id:
        return
    try:
        with _lock:
            entry = _runs.get(run_id)
            if entry is None:
                return
            entry["events"].append({"at": datetime.now(UTC).isoformat(), "message": str(message)})
            # base_seq tracks how many events were trimmed off the front, so a client's
            # "after" cursor (an absolute count from tail()) never desyncs once the
            # buffer wraps -- unlike a plain deque(maxlen=...), where old items vanish
            # silently and a stale cursor value would just stop returning anything new.
            overflow = len(entry["events"]) - _MAX_LINES_PER_RUN
            if overflow > 0:
                entry["events"] = entry["events"][overflow:]
                entry["base_seq"] += overflow
    except Exception:  # noqa: BLE001 - a progress log must never break a real hunt
        pass


def sink(run_id: str) -> Callable[[str], None]:
    """An on_progress callback bound to run_id, for run_bounty_hunt/run_campaign."""
    return lambda message: log(run_id, message)


def tail(run_id: str, after: int = 0) -> dict[str, Any]:
    with _lock:
        entry = _runs.get(run_id)
        if entry is None:
            return {"events": [], "count": 0}
        base = entry["base_seq"]
        events = list(entry["events"])
    total = base + len(events)
    start_idx = max(0, after - base)
    return {"events": events[start_idx:], "count": total}
