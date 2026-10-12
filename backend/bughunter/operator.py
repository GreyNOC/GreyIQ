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

from bughunter import campaign, learning, ledger, portfolio


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

    This is what makes the money loop autonomous. Everything else the engine learns comes
    from its own observations — negative knowledge cools a pair after two misses, and trace
    priors reweight classes from its own confirmations. But at submit time it records
    ``status="submitted"``, which ``learning.learned_priors`` discards on purpose ("I sent
    it" is not "it paid"), so without this pass payout priors stay ``{}`` forever and
    ``ranking._program_pay_factor`` stays at its neutral 1.0 no matter how many cycles run.

    It runs BEFORE the hunt so this cycle's ranking already sees the fresh outcomes.

    ``sync_fn`` is injected rather than built here: this module deliberately contains no
    network or credential code (see the module docstring), so the caller that owns the
    platform credentials owns the call. ``None`` means outcome sync is simply off.
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
    submit_fn: Callable[[str, str], dict[str, Any]] | None,
    on_event: Callable[[str], None] | None = None,
    stop: threading.Event | None = None,
    sync_fn: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Hunt every seed target of one program and (if submit_fn is provided AND the
    program opts in) auto-file confirmed, non-duplicate findings within budget.

    ``run_campaign_fn(target, *, scope, program, active, live, deep, max_pages)`` must
    return the runtime.run_campaign result (with run_id + findings + proof_of_impact).
    ``submit_fn(run_id, ref) -> {ok, report_id, url} | {ok: False, error}`` is the
    runtime's hard-gated submit; None => review-only (never submits)."""
    pid = program["id"]
    # Before anything is hunted, so this cycle's EV ranking and class ordering already see
    # any verdict the platform reached since the last pass. A no-op when sync_fn is None.
    sync_outcomes(sync_fn, on_event)
    # Uses hand-typed seed_targets plus opted-in source repositories; falls back to
    # deriving one target per eligible structured_scope entry so an imported program
    # still gets hunted, not silently skipped.
    targets = campaign.program_campaign_targets(program)
    summary = {"program": pid, "targets_run": 0, "findings": 0, "confirmed": 0, "submitted": 0, "errors": []}
    if not targets:
        # A program that resolves to nothing used to emit ZERO events and reschedule, so a
        # scope-only or mobile-only program looked identical to a clean cycle, forever. The
        # attended span path already refuses this case loudly (greyiq_api: "This program has no
        # huntable targets — add seed targets, opt in a source repository, or import/build its
        # structured scope"); the unattended path said nothing at all.
        summary["errors"].append(
            "no huntable targets — add seed_targets, opt in a source repository, "
            "or import/build the structured scope"
        )
        _emit(on_event, f"hunt {pid}: SKIPPED — no huntable targets")
        return summary
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
                deep=bool(program.get("deep")),
                # Without this an unattended cycle could never run the theorize -> act wave:
                # the flag was readable only from process-wide env, so a per-program choice
                # was impossible and every auto hunt was a single pass per URL.
                iterate=bool(program.get("iterate")),
                max_pages=int(program.get("max_pages") or 12),
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
                 submit_fn: Callable[[str, str], dict[str, Any]],
                 sync_fn: Callable[[], dict[str, Any]] | None = None,
                 train_fn: Callable[[], dict[str, Any]] | None = None) -> None:
        self.runtime_dir = runtime_dir
        self.run_campaign_fn = run_campaign_fn
        self.submit_fn = submit_fn
        # Local, no network. Retrains the offline hunt ranker from the corpus this loop is
        # itself growing. Previously the trainer existed ONLY as a CLI verb, so a model
        # could never come into existence on an unattended install however long it ran.
        self.train_fn = train_fn
        # Optional, injected by whoever owns the platform credentials. When present the
        # loop pulls adjudicated outcomes once per pass, which is the only way payout
        # priors and yield-based program ordering ever become non-trivial.
        self.sync_fn = sync_fn
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
        # The check-then-act on self.running must be atomic: each API request runs on
        # its own asyncio.to_thread worker, so two concurrent /api/operator/start calls
        # (a UI double-click, a client retry, two tabs) could otherwise both observe
        # running=False before either sets it True, spawning two supervisor threads
        # that independently hunt the same programs and can double-submit the same
        # confirmed finding to HackerOne.
        with self._lock:
            if self.running:
                return False
            self.running = True
        self.stop_event.clear()
        self.allow_submit = bool(allow_submit)
        self.started_at = datetime.now(UTC).isoformat()
        self._thread = threading.Thread(target=self._supervise, daemon=True, name="greyiq-operator")
        self._thread.start()
        return True

    def stop(self) -> None:
        self.stop_event.set()
        self._emit("kill switch — stopping after the current step")

    def _retrain(self) -> None:
        """Retrain the offline hunt ranker from the corpus this loop is growing.

        Only a promotion is worth an event: a refusal is the normal, expected outcome until
        the corpus is big and varied enough, and emitting one every pass would be noise.
        """
        if self.train_fn is None:
            return
        try:
            result = self.train_fn()
        except Exception as exc:  # noqa: BLE001 - training must never stop the loop
            self._emit(f"retrain error: {type(exc).__name__}: {exc}")
            return
        # `written` is the real signal — `ok` is also True for a dry run, and `reason` is
        # prose. Only an actually-written model changes how the next hunt orders probes.
        if result.get("ok") and result.get("written"):
            self._emit(f"retrain: new hunt ranker promoted -> {result.get('active_model')} "
                       f"(trained on {result.get('trained_on', {})})")

    def _by_yield(self, due: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Hunt the programs that have actually paid first.

        ``portfolio.list_programs`` returns ``sorted(programs)`` — alphabetical by slug — and
        the loop iterated it unchanged, so a program that had paid $10k and one that had
        returned twenty duplicates got the same place in the queue forever. Nothing read the
        yield the learning store was already accumulating.

        Ordered by bounty total, then rewarded count, then submitted count, then the old
        alphabetical order as a stable tie-break. A cold portfolio is all zeroes, so this is
        byte-identical to the previous behaviour until something has actually paid — it can
        only ever reorder, never drop a program or change what any hunt does.
        """
        try:
            summary = (learning.program_summary(self.runtime_dir) or {}).get("programs") or {}
        except Exception:  # noqa: BLE001 - ordering must never break the loop
            return due

        def rank(program: dict[str, Any]) -> tuple[float, int, int]:
            stats = summary.get(str(program.get("id") or "")) or {}
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
                # Once per PASS, not once per program: the poll is capped per call, so
                # syncing inside every program's cycle would multiply the platform reads by
                # the number of due programs for no new information.
                sync_outcomes(self.sync_fn, self._emit)
                due = self._by_yield(due)
                for program in due:
                    if self.stop_event.is_set():
                        break
                    self._run_one(program)
                # After the pass, with this pass's traces in the corpus. The trainer has its
                # own honest gate — too few rows, a single-program corpus, or a model that
                # does not beat the hand-tuned rules are all refusals — so calling it every
                # pass costs a cheap refusal until the corpus can actually support a model.
                self._retrain()
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
        # touch_run sits OUTSIDE the try above on purpose, but its own failure (disk full, a
        # OneDrive lock on portfolio.json — this repo lives under OneDrive) used to escape
        # _run_one, escape both loops, and kill the supervisor via _supervise's finally with a
        # bare "operator stopped" and the traceback going to the thread excepthook, which in the
        # packaged backend is nowhere the operator looks. A cycle that cannot be rescheduled is
        # worth reporting, not worth taking the loop down for.
        next_run = (datetime.now(UTC) + timedelta(minutes=int(program.get("interval_minutes") or 1440))).isoformat()
        try:
            portfolio.touch_run(self.runtime_dir, pid, next_run_at=next_run)
        except Exception as exc:  # noqa: BLE001
            self._emit(f"cycle reschedule FAILED {pid}: {type(exc).__name__}: {exc} — "
                       "this program stays due and will re-run immediately")
        self._emit(f"cycle done: {pid} — {summary.get('targets_run', 0)} targets, "
                   f"{summary.get('findings', 0)} findings, "
                   f"{summary.get('confirmed', 0)} confirmed, {summary.get('submitted', 0)} submitted")
        # Every error the cycle collected. run_program_cycle appends one per failed target, per
        # ok:False campaign, and per rejected submit — and none of them were ever read, so a
        # program whose every target crashed emitted the identical "cycle done … 0 findings" as a
        # clean one. An operator could run a broken portfolio for weeks believing it was clean.
        for problem in (summary.get("errors") or ()):
            self._emit(f"cycle problem {pid}: {problem}")
