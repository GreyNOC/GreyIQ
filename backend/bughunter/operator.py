"""GreyIQ BugHunter — portfolio hunt scheduler.

Runs due, enabled programs through the injected campaign function and leaves
findings and local submission packages for human review. No submission callback
is accepted: an unattended loop must never contact a reporting platform.

The campaign owns scope and authorization checks. A stop event is checked
between targets and programs; cycles run sequentially to avoid store races.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from bughunter import campaign, portfolio


def _emit(on_event: Callable[[str], None] | None, message: str) -> None:
    if callable(on_event):
        try:
            on_event(message)
        except Exception:  # noqa: BLE001 - an event sink must never break the loop
            pass


def run_program_cycle(
    runtime_dir: str,
    program: dict[str, Any],
    *,
    run_campaign_fn: Callable[..., dict[str, Any]],
    on_event: Callable[[str], None] | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """Hunt every seed target of one program for operator review.

    ``run_campaign_fn(target, *, scope, program, active, live, deep, max_pages)`` must
    return the runtime.run_campaign result (with findings + proof_of_impact)."""
    pid = program["id"]
    # Uses hand-typed seed_targets plus opted-in source repositories; falls back to
    # deriving one target per eligible structured_scope entry so an imported program
    # still gets hunted, not silently skipped.
    targets = campaign.program_campaign_targets(program)
    summary = {"program": pid, "targets_run": 0, "findings": 0, "confirmed": 0, "submitted": 0, "errors": []}

    for target in targets:
        if stop is not None and stop.is_set():
            break
        _emit(on_event, f"hunt {pid}: {target}")
        try:
            result = run_campaign_fn(
                target, scope=program.get("scope_text", ""), program=pid,
                active=bool(program.get("active")), live=bool(program.get("live")),
                deep=bool(program.get("deep")), max_pages=int(program.get("max_pages") or 12),
            )
        except Exception as exc:  # noqa: BLE001 - one bad target never kills the loop
            summary["errors"].append(f"{target}: {type(exc).__name__}: {exc}")
            continue
        if not result.get("ok"):
            summary["errors"].append(f"{target}: {result.get('error', 'campaign failed')}")
            continue
        summary["targets_run"] += 1
        findings = result.get("findings") or []
        proof = result.get("proof_of_impact") or {}
        summary["findings"] += len(findings)
        confirmed = [f for f in findings if str((proof.get(f.get("ref"), {}) or {}).get("status")) == "confirmed"]
        summary["confirmed"] += len(confirmed)
    return summary


class OperatorLoop:
    """A single background supervisor that runs due programs sequentially until
    stopped. Owns the kill switch and a bounded event ring buffer the UI polls."""

    def __init__(self, runtime_dir: str, *, run_campaign_fn: Callable[..., dict[str, Any]]) -> None:
        self.runtime_dir = runtime_dir
        self.run_campaign_fn = run_campaign_fn
        self.stop_event = threading.Event()
        self.events: deque[dict[str, Any]] = deque(maxlen=500)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.running = False
        self.allow_submit = False
        self.started_at: str | None = None

    def _emit(self, message: str) -> None:
        with self._lock:
            self.events.append({"at": datetime.now(UTC).isoformat(), "message": str(message)})

    def event_tail(self, after: int = 0) -> dict[str, Any]:
        with self._lock:
            evs = list(self.events)
        return {"running": self.running, "allow_submit": self.allow_submit, "started_at": self.started_at,
                "events": evs[after:], "count": len(evs)}

    def start(self, *, allow_submit: bool = False) -> bool:
        if allow_submit:
            raise ValueError("Automatic submission is disabled; review findings and submit manually.")
        # The check-then-act on self.running must be atomic: each API request runs on
        # its own asyncio.to_thread worker, so two concurrent /api/operator/start calls
        # (a UI double-click, a client retry, two tabs) could otherwise spawn two
        # supervisor threads that independently hunt the same programs.
        with self._lock:
            if self.running:
                return False
            self.running = True
        self.stop_event.clear()
        self.allow_submit = False
        self.started_at = datetime.now(UTC).isoformat()
        self._thread = threading.Thread(target=self._supervise, daemon=True, name="greyiq-operator")
        self._thread.start()
        return True

    def stop(self) -> None:
        self.stop_event.set()
        self._emit("kill switch — stopping after the current step")

    def _is_due(self, program: dict[str, Any]) -> bool:
        nxt = program.get("next_run_at")
        if not nxt:
            return True
        try:
            return datetime.fromisoformat(str(nxt)) <= datetime.now(UTC)
        except ValueError:
            return True
        except TypeError:
            # A timezone-NAIVE stamp (e.g. a hand-edited portfolio.json, or any external
            # writer that stamps next_run_at without an offset) makes the comparison raise
            # TypeError, not ValueError -- it must be caught here too, or it escapes the
            # list comprehension in _supervise() and kills the whole supervisor thread.
            return True

    def _supervise(self) -> None:
        self._emit("operator started — review-only (no auto-submit)")
        try:
            while not self.stop_event.is_set():
                due = [p for p in portfolio.list_programs(self.runtime_dir) if p.get("enabled") and self._is_due(p)]
                if not due:
                    self.stop_event.wait(timeout=15)  # idle tick; responsive to stop
                    continue
                for program in due:
                    if self.stop_event.is_set():
                        break
                    self._run_one(program)
        finally:
            self.running = False
            self._emit("operator stopped")

    def _run_one(self, program: dict[str, Any]) -> None:
        pid = program["id"]
        self._emit(f"cycle start: {pid}")
        try:
            summary = run_program_cycle(self.runtime_dir, program, run_campaign_fn=self.run_campaign_fn,
                                        on_event=self._emit, stop=self.stop_event)
        except Exception as exc:  # noqa: BLE001
            self._emit(f"cycle error {pid}: {type(exc).__name__}: {exc}")
            summary = {"findings": 0, "confirmed": 0, "submitted": 0}
        next_run = (datetime.now(UTC) + timedelta(minutes=int(program.get("interval_minutes") or 1440))).isoformat()
        portfolio.touch_run(self.runtime_dir, pid, next_run_at=next_run)
        self._emit(f"cycle done: {pid} — {summary.get('findings', 0)} findings, "
                   f"{summary.get('confirmed', 0)} confirmed for review")
