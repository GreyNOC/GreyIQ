"""GreyIQ BugHunter — the autonomous operator loop.

Runs the full money loop UNATTENDED over a portfolio of programs: for each due,
enabled program it hunts every seed target (recon -> scan -> active proof ->
consolidate -> dedup -> rank -> submission packages), records the pipeline in the
ledger, and — only when explicitly armed — auto-FILES confirmed, non-duplicate
findings, throttled per program. Then it reschedules and moves on.

SAFETY (this is where a bounty tool could become a weapon or a spam-cannon — it does
not):
  * ZERO new network/scanning code. It calls the injected ``run_campaign_fn`` (the
    runtime's run_campaign, which fails closed on authorized=False and keeps recon
    same-origin + active probing scope-bound via host_in_active_scope) and the
    injected ``submit_fn`` (the runtime's hard-gated submit, which re-requires confirm
    + server-recomputed proof_status=='confirmed' + real creds). It cannot bypass any
    gate it doesn't touch.
  * Auto-submit is TRIPLE-gated: the loop must be started with allow_submit=True
    (operator-wide arm) AND the program must have auto_submit=True AND the finding must
    be proof_status=='confirmed' AND not already reported/submitted (ledger dedup) AND
    within the program's max_submits_per_day. Default everywhere is OFF / review-only.
  * A stop_event KILL SWITCH is checked between every program and before every submit.
  * Sequential cycles (no concurrent store writes) — no read-modify-write race on the
    portfolio/ledger.

Pure / frozen-safe: stdlib threading + the existing portfolio/ledger stores. The API
or the `gn operator` CLI owns one OperatorLoop and injects the two callables.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from bughunter import campaign, ledger, portfolio


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
    submit_fn: Callable[[str, str], dict[str, Any]] | None,
    on_event: Callable[[str], None] | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """Hunt every seed target of one program and (if submit_fn is provided AND the
    program opts in) auto-file confirmed, non-duplicate findings within budget.

    ``run_campaign_fn(target, *, scope, program, active, live, deep, max_pages)`` must
    return the runtime.run_campaign result (with run_id + findings + proof_of_impact).
    ``submit_fn(run_id, ref) -> {ok, report_id, url} | {ok: False, error}`` is the
    runtime's hard-gated submit; None => review-only (never submits)."""
    pid = program["id"]
    # Prefers hand-typed seed_targets; falls back to deriving one target per eligible
    # structured_scope entry (a HackerOne API/CSV-imported program) so a program built
    # purely from an imported scope table still gets hunted, not silently skipped.
    targets = campaign.program_campaign_targets(program)
    summary = {"program": pid, "targets_run": 0, "findings": 0, "confirmed": 0, "submitted": 0, "errors": []}
    auto = bool(submit_fn) and bool(program.get("auto_submit"))
    budget = _remaining_submit_budget(runtime_dir, program) if auto else 0

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
        run_id = result.get("run_id")

        if not (auto and run_id):
            continue
        for finding in confirmed:
            if budget <= 0 or (stop is not None and stop.is_set()):
                break
            if ledger.is_submitted(runtime_dir, pid, target, finding):
                continue  # already FILED in a prior run — never re-file (a 'reported' finding,
                          # i.e. one this run just built a package for, must still be fileable)
            res = submit_fn(run_id, finding["ref"])  # hard-gated server-side
            if res.get("ok"):
                ledger.record_submission(runtime_dir, pid, target, ledger.dedup_key(finding),
                                         str(res.get("report_id", "")), str(res.get("url", "")))
                summary["submitted"] += 1
                budget -= 1
                _emit(on_event, f"submitted {pid}: {str(finding.get('title', ''))[:48]} -> {res.get('url', '')}")
            else:
                summary["errors"].append(f"submit {finding.get('ref')}: {res.get('error')}")
    return summary


def _remaining_submit_budget(runtime_dir: str, program: dict[str, Any]) -> int:
    cap = int(program.get("max_submits_per_day") or 0)
    if cap <= 0:
        return 0
    return max(0, cap - ledger.count_recent_submissions(runtime_dir, program["id"], within_hours=24))


class OperatorLoop:
    """A single background supervisor that runs due programs sequentially until
    stopped. Owns the kill switch and a bounded event ring buffer the UI polls."""

    def __init__(self, runtime_dir: str, *, run_campaign_fn: Callable[..., dict[str, Any]],
                 submit_fn: Callable[[str, str], dict[str, Any]]) -> None:
        self.runtime_dir = runtime_dir
        self.run_campaign_fn = run_campaign_fn
        self.submit_fn = submit_fn
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
        if self.running:
            return False
        self.stop_event.clear()
        self.allow_submit = bool(allow_submit)
        self.running = True
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
        self._emit("operator started" + (" — AUTO-SUBMIT ARMED" if self.allow_submit else " — review-only (no auto-submit)"))
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
        submit = self.submit_fn if (self.allow_submit and program.get("auto_submit")) else None
        try:
            summary = run_program_cycle(self.runtime_dir, program, run_campaign_fn=self.run_campaign_fn,
                                        submit_fn=submit, on_event=self._emit, stop=self.stop_event)
        except Exception as exc:  # noqa: BLE001
            self._emit(f"cycle error {pid}: {type(exc).__name__}: {exc}")
            summary = {"findings": 0, "confirmed": 0, "submitted": 0}
        next_run = (datetime.now(UTC) + timedelta(minutes=int(program.get("interval_minutes") or 1440))).isoformat()
        portfolio.touch_run(self.runtime_dir, pid, next_run_at=next_run)
        self._emit(f"cycle done: {pid} — {summary.get('findings', 0)} findings, "
                   f"{summary.get('confirmed', 0)} confirmed, {summary.get('submitted', 0)} submitted")
