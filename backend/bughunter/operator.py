"""GreyIQ BugHunter — portfolio hunt scheduler.

Runs due, enabled programs through the injected campaign function and leaves
findings and local submission packages for human review. No submission callback
is accepted: an unattended loop must never contact a reporting platform.

Each start requires a short-lived grant for every enabled program. The grant
binds its exact saved scope, policy, targets, and testing settings; request
hooks recheck that binding before network activity. Cycles run sequentially.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any, Callable
from uuid import uuid4

from bughunter import campaign, operator_guard, portfolio, progress


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
    guard: operator_guard.RunGuard | None = None,
    on_target_start: Callable[[str], None] | None = None,
    on_target_done: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Hunt every seed target of one program for operator review.

    ``run_campaign_fn(target, *, scope, program, active, live, deep, max_pages)`` must
    return the runtime.run_campaign result (with findings + proof_of_impact).
    When ``guard`` is supplied, it also receives a unique ``run_id`` so Stop
    cancels the current campaign through the existing progress API."""
    pid = program["id"]
    # Uses hand-typed seed_targets plus opted-in source repositories; falls back to
    # deriving one target per eligible structured_scope entry so an imported program
    # still gets hunted, not silently skipped.
    targets = campaign.program_campaign_targets(program)
    summary = {"program": pid, "targets_run": 0, "findings": 0, "confirmed": 0,
               "submitted": 0, "errors": [], "stopped": False, "stop_reason": ""}

    for target in targets:
        if stop is not None and stop.is_set():
            summary["stopped"] = True
            break
        run_id = f"operator-{uuid4().hex}" if guard is not None else ""
        try:
            if guard is not None:
                guard.check_target(target)
            _emit(on_event, f"hunt {pid}: {target}")
            if run_id and callable(on_target_start):
                on_target_start(run_id)
            kwargs: dict[str, Any] = {
                "scope": program.get("scope_text", ""), "program": pid,
                "active": bool(program.get("active")), "live": bool(program.get("live")),
                "deep": bool(program.get("deep")), "max_pages": int(program.get("max_pages") or 12),
            }
            if run_id:
                kwargs["run_id"] = run_id
            if guard is not None:
                with operator_guard.bind(guard):
                    result = run_campaign_fn(target, **kwargs)
            else:
                result = run_campaign_fn(target, **kwargs)
        except operator_guard.GuardHalt as exc:
            summary["stopped"] = True
            summary["stop_reason"] = str(exc)
            summary["errors"].append(f"{target}: {exc}")
            break
        except Exception as exc:  # noqa: BLE001 - one bad target never kills the loop
            summary["errors"].append(f"{target}: {type(exc).__name__}: {exc}")
            if guard is not None and guard.halt_reason:
                summary["stopped"] = True
                summary["stop_reason"] = guard.halt_reason
                break
            continue
        finally:
            if run_id and callable(on_target_done):
                on_target_done()
        if guard is not None and guard.halt_reason:
            summary["stopped"] = True
            summary["stop_reason"] = guard.halt_reason
            break
        if not result.get("ok"):
            summary["errors"].append(f"{target}: {result.get('error', 'campaign failed')}")
            continue
        summary["targets_run"] += 1
        findings = result.get("findings") or []
        proof = result.get("proof_of_impact") or {}
        summary["findings"] += len(findings)
        confirmed = [f for f in findings if str((proof.get(f.get("ref"), {}) or {}).get("status")) == "confirmed"]
        summary["confirmed"] += len(confirmed)
    if guard is not None:
        summary["requests_used"] = guard.requests_used
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
        self._grants: dict[str, operator_guard.ProgramGrant] = {}
        self._cycles_used: dict[str, int] = {}
        self._current_run_id: str | None = None
        self._event_count = 0
        self._session_id = ""
        self._stop_reason = ""
        self._requests_total: dict[str, int] = {}
        self._lease_fd: int | None = None

    def _emit(self, message: str) -> None:
        with self._lock:
            self._event_count += 1
            self.events.append({"at": datetime.now(UTC).isoformat(), "message": str(message), "seq": self._event_count})

    def event_tail(self, after: int = 0) -> dict[str, Any]:
        with self._lock:
            evs = [event for event in self.events if event["seq"] > after]
            status = {"running": self.running, "allow_submit": False, "started_at": self.started_at,
                      "events": evs, "count": self._event_count,
                      "current_run_id": self._current_run_id,
                      "grants": [{"program_id": pid, "expires_at": grant.expires_at.isoformat(),
                                  "cycles_used": self._cycles_used.get(pid, 0), "max_cycles": grant.max_cycles}
                                 for pid, grant in self._grants.items()]}
        return status

    def start(self, *, grants: list[dict[str, Any]] | None = None, allow_submit: bool = False) -> bool:
        if allow_submit:
            raise ValueError("Automatic submission is disabled; review findings and submit manually.")
        # The check-then-act on self.running must be atomic: each API request runs on
        # its own asyncio.to_thread worker, so two concurrent /api/operator/start calls
        # (a UI double-click, a client retry, two tabs) could otherwise spawn two
        # supervisor threads that independently hunt the same programs.
        with self._lock:
            if self.running:
                return False
            lease_fd = operator_guard.acquire_operator_lease(self.runtime_dir)
            try:
                prepared = operator_guard.create_grants(portfolio.list_programs(self.runtime_dir), grants)
                session_id = uuid4().hex
                # An armed grant must have a durable, reviewable authority record
                # before any supervisor thread can perform network activity.
                for grant in prepared.values():
                    operator_guard.audit_event(self.runtime_dir, "armed", grant=grant, session_id=session_id)
            except BaseException:
                operator_guard.release_operator_lease(lease_fd)
                raise
            self._lease_fd = lease_fd
            self._grants = prepared
            self._cycles_used = {pid: 0 for pid in prepared}
            self._requests_total = {pid: 0 for pid in prepared}
            self._session_id = session_id
            self._stop_reason = ""
            self._current_run_id = None
            self.stop_event.clear()
            self.running = True
            self.allow_submit = False
            self.started_at = datetime.now(UTC).isoformat()
        self._thread = threading.Thread(target=self._supervise, daemon=True, name="greyiq-operator")
        try:
            self._thread.start()
        except BaseException:
            with self._lock:
                self.running = False
                operator_guard.release_operator_lease(self._lease_fd)
                self._lease_fd = None
            raise
        return True

    def stop(self) -> None:
        self.stop_event.set()
        with self._lock:
            run_id = self._current_run_id
            if not self._stop_reason:
                self._stop_reason = "operator stop requested"
        if run_id:
            progress.request_stop(run_id)
        self._emit("kill switch — stopping current campaign before another request")

    def _target_started(self, run_id: str) -> None:
        with self._lock:
            self._current_run_id = run_id
        if self.stop_event.is_set():
            progress.request_stop(run_id)

    def _target_done(self) -> None:
        with self._lock:
            self._current_run_id = None

    def _is_due(self, program: dict[str, Any]) -> bool:
        nxt = program.get("next_run_at")
        if not nxt:
            return True
        try:
            stamp = datetime.fromisoformat(str(nxt))
            return stamp.tzinfo is not None and stamp <= datetime.now(UTC)
        except (ValueError, TypeError):
            return False  # a corrupt schedule never triggers an unscheduled hunt

    def _supervise(self) -> None:
        self._emit("operator started — review-only (no auto-submit)")
        try:
            while not self.stop_event.is_set():
                due: list[tuple[dict[str, Any], operator_guard.ProgramGrant]] = []
                remaining = 0
                for pid, grant in self._grants.items():
                    if self._cycles_used.get(pid, 0) >= grant.max_cycles:
                        continue
                    current = portfolio.get_program(self.runtime_dir, pid)
                    reason = grant.current_reason(current)
                    if reason:
                        self._emit(f"authorization stopped for {pid}: {reason}")
                        self._stop_reason = reason
                        self.stop_event.set()
                        break
                    remaining += 1
                    if current is not None and self._is_due(current):
                        due.append((current, grant))
                if self.stop_event.is_set():
                    break
                if not remaining:
                    self._emit("all authorized cycle limits reached; re-arm to continue")
                    self._stop_reason = "authorized cycle limits reached"
                    break
                if not due:
                    self.stop_event.wait(timeout=15)  # idle tick; responsive to stop
                    continue
                for program, grant in due:
                    if self.stop_event.is_set():
                        break
                    self._run_one(program, grant)
        finally:
            for pid, grant in self._grants.items():
                try:
                    operator_guard.audit_event(
                        self.runtime_dir, "stopped", grant=grant, session_id=self._session_id,
                        cycles_used=self._cycles_used.get(pid, 0),
                        requests_used=self._requests_total.get(pid, 0),
                        stop_reason=self._stop_reason or "operator stopped",
                    )
                except OSError as exc:
                    self._emit(f"authorization audit unavailable for {pid}: {exc}")
            with self._lock:
                self.running = False
                self._current_run_id = None
                operator_guard.release_operator_lease(self._lease_fd)
                self._lease_fd = None
            self._emit("operator stopped")

    def _run_one(self, program: dict[str, Any], grant: operator_guard.ProgramGrant) -> None:
        pid = program["id"]
        self._emit(f"cycle start: {pid}")
        self._cycles_used[pid] = self._cycles_used.get(pid, 0) + 1
        try:
            operator_guard.audit_event(self.runtime_dir, "cycle_started", grant=grant,
                                       session_id=self._session_id,
                                       cycles_used=self._cycles_used[pid],
                                       requests_used=self._requests_total.get(pid, 0))
        except OSError as exc:
            self._stop_reason = f"authorization audit unavailable: {exc}"
            self.stop_event.set()
            self._emit(self._stop_reason)
            return
        guard = operator_guard.RunGuard(self.runtime_dir, grant, self.stop_event, session_id=self._session_id)
        try:
            summary = run_program_cycle(self.runtime_dir, program, run_campaign_fn=self.run_campaign_fn,
                                        on_event=self._emit, stop=self.stop_event, guard=guard,
                                        on_target_start=self._target_started, on_target_done=self._target_done)
        except Exception as exc:  # noqa: BLE001
            self._emit(f"cycle error {pid}: {type(exc).__name__}: {exc}")
            summary = {"findings": 0, "confirmed": 0, "submitted": 0}
        if guard.halt_reason or summary.get("stopped"):
            reason = guard.halt_reason or summary.get("stop_reason") or "stop requested"
            self._stop_reason = str(reason)
            self._emit(f"cycle halted: {pid} — {reason}")
            self.stop_event.set()
        else:
            next_run = (datetime.now(UTC) + timedelta(minutes=int(program.get("interval_minutes") or 1440))).isoformat()
            portfolio.touch_run(self.runtime_dir, pid, next_run_at=next_run)
        self._requests_total[pid] = self._requests_total.get(pid, 0) + guard.requests_used
        try:
            operator_guard.audit_event(
                self.runtime_dir, "cycle_finished", grant=grant, session_id=self._session_id,
                cycles_used=self._cycles_used[pid], requests_used=guard.requests_used,
                stop_reason=self._stop_reason if self.stop_event.is_set() else "",
            )
        except OSError as exc:
            self._stop_reason = f"authorization audit unavailable: {exc}"
            self.stop_event.set()
            self._emit(self._stop_reason)
        self._emit(f"cycle done: {pid} — {summary.get('findings', 0)} findings, "
                   f"{summary.get('confirmed', 0)} confirmed for review; "
                   f"{summary.get('requests_used', 0)} guarded requests")
