"""GreyIQ BugHunter — portfolio hunt scheduler.

Runs due, enabled programs through the injected campaign function and leaves
findings and local submission packages for human review. No submission callback
is accepted: an unattended loop must never contact a reporting platform.

Each start requires a short-lived grant for every enabled program. The grant
binds its exact saved scope, policy, targets, and testing settings; request
hooks recheck that binding before network activity. A stop event is checked
between targets and programs; cycles run sequentially to avoid store races.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any, Callable
from uuid import uuid4

from bughunter import campaign, learning, operator_guard, portfolio, progress


def _emit(on_event: Callable[[str], None] | None, message: str) -> None:
    if callable(on_event):
        try:
            on_event(message)
        except Exception:  # noqa: BLE001 - an event sink must never break the loop
            pass


def sync_outcomes(
    sync_fn: Callable[[], dict[str, Any]] | None,
    on_event: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Pull adjudicated platform outcomes into the learning store before hunting.

    Everything else the engine learns is self-observed and already works: negative knowledge
    cools an ``(endpoint, class)`` after two misses, and trace priors reweight classes from
    its own confirmations. But at submission time it records ``status="submitted"``, which
    ``learning.learned_priors`` discards on purpose ("I sent it" is not "it paid"), so
    without this pass payout priors stay ``{}`` for ever and ``_program_pay_factor`` stays at
    its neutral 1.0 no matter how many cycles run.

    Runs BEFORE the hunt so this cycle's ranking already sees the fresh verdicts.

    ``sync_fn`` is injected because this module deliberately holds no network or credential
    code; the caller that owns the platform credentials owns the call. ``None`` = sync off.
    """
    if sync_fn is None:
        return {"ok": False, "skipped": True}
    try:
        result = sync_fn()
    except Exception as exc:  # noqa: BLE001 - a sync failure must never stop a hunt
        _emit(on_event, f"outcome sync error: {type(exc).__name__}: {exc}")
        return {"ok": False, "error": str(exc)}
    if not result.get("ok"):
        _emit(on_event, f"outcome sync skipped: {result.get('error', 'unavailable')}")
        return result
    learned = int(result.get("outcomes") or 0)
    # `outcomes` is the number that matters: a ledger-only state move (new -> triaged)
    # changes no ranking, so reporting `updated` alone would overstate what was learned.
    if learned:
        _emit(on_event, f"outcome sync: {learned} adjudicated outcome(s) learned "
                        f"from {result.get('checked', 0)} report(s)")
    for problem in (result.get("errors") or ())[:5]:
        _emit(on_event, f"outcome sync problem: {problem}")
    return result


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
    sync_fn: Callable[[], dict[str, Any]] | None = None,
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
    # Before anything is hunted, so this cycle's EV ranking and class ordering already see
    # any verdict the platform reached since the last pass. A no-op when sync_fn is None.
    sync_outcomes(sync_fn, on_event)
    if not targets:
        # A program resolving to nothing used to emit ZERO events and reschedule, so a
        # scope-only or mobile-only program looked identical to a clean cycle, for ever. The
        # attended span path already refuses this loudly ("This program has no huntable
        # targets — add seed targets, opt in a source repository, or import/build its
        # structured scope"); the unattended path said nothing at all.
        summary["errors"].append(
            "no huntable targets — add seed_targets, opt in a source repository, "
            "or import/build the structured scope"
        )
        _emit(on_event, f"hunt {pid}: SKIPPED — no huntable targets")
        return summary

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
                # Without this an unattended cycle could never run the theorize -> act wave:
                # the flag was readable only from process-wide env, so a per-program choice
                # was impossible and every auto hunt was a single flat pass per URL.
                "iterate": bool(program.get("iterate")),
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
            if result.get("needs_operator"):
                # A protected surface is unfinished work, never a clean cycle.
                # Unattended runs stop for human input instead of rescheduling
                # the same missing-session attempt indefinitely.
                summary["needs_operator"] = True
                summary["stopped"] = True
                summary["stop_reason"] = "operator authentication required"
            summary["errors"].append(f"{target}: {result.get('error', 'campaign failed')}")
            if summary.get("needs_operator"):
                break
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

    def __init__(self, runtime_dir: str, *, run_campaign_fn: Callable[..., dict[str, Any]],
                 sync_fn: Callable[[], dict[str, Any]] | None = None,
                 train_fn: Callable[[], dict[str, Any]] | None = None) -> None:
        self.runtime_dir = runtime_dir
        self.run_campaign_fn = run_campaign_fn
        # Injected by whoever owns the platform credentials. When present the loop pulls
        # adjudicated outcomes once per pass — the only way payout priors and yield-based
        # program ordering ever become non-trivial.
        self.sync_fn = sync_fn
        # Local, no network. Retrains the offline hunt ranker from the corpus this loop is
        # itself growing. The trainer was previously reachable ONLY as a CLI verb, so a model
        # could never come into existence on an unattended install however long it ran.
        self.train_fn = train_fn
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

    def _retrain(self) -> None:
        """Retrain the offline hunt ranker from the corpus this loop is growing.

        Only a promotion is worth an event: a refusal is the normal outcome until the corpus
        is big and varied enough, and emitting one every pass would be noise. ``written`` is
        the signal, not ``ok`` — ``ok`` is also True for a dry run, and ``reason`` is prose.
        """
        if self.train_fn is None:
            return
        try:
            result = self.train_fn()
        except Exception as exc:  # noqa: BLE001 - training must never stop the loop
            self._emit(f"retrain error: {type(exc).__name__}: {exc}")
            return
        if result.get("ok") and result.get("written"):
            self._emit(f"retrain: new hunt ranker promoted -> {result.get('active_model')} "
                       f"(trained on {result.get('trained_on', {})})")

    def _by_yield(
        self, due: list[tuple[dict[str, Any], "operator_guard.ProgramGrant"]]
    ) -> list[tuple[dict[str, Any], "operator_guard.ProgramGrant"]]:
        """Hunt the programs that have actually paid first.

        Nothing read the yield the learning store was already accumulating, so a program that
        had paid and one that had returned duplicates took the same place in the queue for
        ever. Ordered by bounty total, then rewarded count, then submitted count; a cold
        portfolio is all zeroes, so this is a no-op until something has actually paid. It can
        only ever reorder — never drop a program, never change what a hunt does.
        """
        try:
            summary = (learning.program_summary(self.runtime_dir) or {}).get("programs") or {}
        except Exception:  # noqa: BLE001 - ordering must never break the loop
            return due

        def rank(entry: tuple[dict[str, Any], Any]) -> tuple[float, int, int]:
            stats = summary.get(str((entry[0] or {}).get("id") or "")) or {}
            try:
                return (-float(stats.get("bounty_total") or 0.0),
                        -int(stats.get("rewarded") or 0),
                        -int(stats.get("submitted") or 0))
            except (TypeError, ValueError):
                return (0.0, 0, 0)

        return sorted(due, key=rank)

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
                # Once per PASS, not once per program: the poll is capped per call, so
                # syncing inside every program's cycle would multiply the platform reads by
                # the number of due programs for no new information.
                sync_outcomes(self.sync_fn, self._emit)
                for program, grant in self._by_yield(due):
                    if self.stop_event.is_set():
                        break
                    self._run_one(program, grant)
                # After the pass, with this pass's traces in the corpus. The trainer owns its
                # own honest gate — too few rows, a single-program corpus, or a model that
                # does not beat the hand-tuned rules are all refusals — so calling it every
                # pass costs a cheap refusal until the corpus can support a model.
                self._retrain()
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
                                        on_target_start=self._target_started,
                                        on_target_done=self._target_done, sync_fn=self.sync_fn)
        except Exception as exc:  # noqa: BLE001
            self._emit(f"cycle error {pid}: {type(exc).__name__}: {exc}")
            summary = {"findings": 0, "confirmed": 0, "submitted": 0}
        finally:
            # The per-cycle guard is the only holder of a resolved research
            # session. Release it as soon as the target loop finishes, including
            # error and stop paths.
            guard.research_auth = None
        if guard.halt_reason or summary.get("stopped"):
            reason = guard.halt_reason or summary.get("stop_reason") or "stop requested"
            self._stop_reason = str(reason)
            self._emit(f"cycle halted: {pid} — {reason}")
            self.stop_event.set()
        else:
            next_run = (datetime.now(UTC) + timedelta(minutes=int(program.get("interval_minutes") or 1440))).isoformat()
            # Its own failure (disk full, a OneDrive lock on portfolio.json — this repo lives
            # under OneDrive) used to escape _run_one, escape both loops, and kill the
            # supervisor via _supervise's finally with a bare "operator stopped", the
            # traceback going to the thread excepthook where no operator looks. A cycle that
            # cannot be rescheduled is worth reporting, not worth taking the loop down for.
            try:
                portfolio.touch_run(self.runtime_dir, pid, next_run_at=next_run)
            except Exception as exc:  # noqa: BLE001
                self._emit(f"cycle reschedule FAILED {pid}: {type(exc).__name__}: {exc} — "
                           "this program stays due and will re-run immediately")
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
        for problem in (summary.get("errors") or ()):
            self._emit(f"cycle problem {pid}: {problem}")
