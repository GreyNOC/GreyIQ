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
_MAX_FINDINGS_PER_RUN = 400  # cap the live findings stream (the Findings tab holds the full set)
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_lock = threading.Lock()
_runs: dict[str, dict[str, Any]] = {}
_run_order: list[str] = []
_stopped: set[str] = set()  # run_ids the operator asked to cancel (cooperative-cancellation flags)
# _stopped deliberately OUTLIVES its run's buffer (see start_run), so it needs its own bound or it
# is the one structure here that grows for the life of the process. Its FIFO is kept exactly
# parallel to the set — every add and every removal touches both — because a drifting order list
# would trim entries that are still in the set, i.e. revoke a live stop request. 256 is ~32x
# _MAX_RUNS: far past any plausible backlog of stop requests, still a few KB at worst.
_MAX_STOPPED = 256
_stopped_order: list[str] = []

# --- App-wide (cross-run) event ring -------------------------------------------
# A single global stream the UI polls at /api/bounty/events so ANY tab can react
# live to work happening in another run/program (a finding confirmed in a campaign,
# a report readied in the Report Center, a submission filed). This is the app-wide
# counterpart to the per-run `events` log above; kept small since it's a notify
# channel, not the system of record (the ledger is).
_MAX_GLOBAL_EVENTS = 300
_global_events: list[dict[str, Any]] = []
_global_base_seq = 0  # how many events have been trimmed off the front (keeps 'after' cursors stable)


def start_run(run_id: str) -> None:
    """Reset (or create) the buffer for run_id, evicting the oldest run past _MAX_RUNS.

    Eviction drops the run's BUFFER but deliberately leaves its stop flag alone. Buffer eviction is
    driven purely by how many OTHER runs have since started, which says nothing about whether this
    one is still probing somebody's production host: a long campaign that has been asked to stop is
    exactly the run most likely to still be running when eight newer ones begin, and discarding its
    flag there silently un-cancelled it — the loops in campaign.py/bounty.py poll ``is_stopped`` and
    would have simply carried on. The flag is cleared HERE instead, on the one event that genuinely
    means "this id is a new run": ``start_run`` for the same id. ``_stopped`` is bounded on its own
    (see ``request_stop``) rather than by riding on eviction.
    """
    if not run_id:
        return
    with _lock:
        # `events` is the text log (existing); `targets`/`target_index`/`findings` are the
        # structured campaign-dashboard state streamed as targets complete. `started_at` is the
        # only wall-clock stamp for the run itself: every other stamp here belongs to an event, so
        # without it a run with no events yet cannot be dated or ordered by an attaching client.
        _runs[run_id] = {"events": [], "base_seq": 0, "targets": [], "target_index": {}, "findings": [],
                         "started_at": datetime.now(UTC).isoformat()}
        _clear_stop_locked(run_id)  # a fresh run is never pre-cancelled
        if run_id in _run_order:
            _run_order.remove(run_id)
        _run_order.append(run_id)
        while len(_run_order) > _MAX_RUNS:
            evicted = _run_order.pop(0)
            _runs.pop(evicted, None)


def _clear_stop_locked(run_id: str) -> None:
    """Drop ``run_id``'s stop flag from BOTH the set and its FIFO. Caller holds ``_lock``."""
    if run_id in _stopped:
        _stopped.discard(run_id)
        try:
            _stopped_order.remove(run_id)
        except ValueError:  # never observed; the two are kept parallel, but a desync must not raise
            pass


def request_stop(run_id: str) -> None:
    """Ask a running campaign to cancel. The campaign loops poll ``is_stopped`` between
    targets/URLs and wind down cleanly, returning whatever was found so far.

    Idempotent: re-requesting a stop does not re-queue the id in the FIFO, so an operator leaning on
    the Stop button cannot push older, still-live stop requests out of the bound."""
    if not run_id:
        return
    with _lock:
        rid = str(run_id)
        if rid in _stopped:
            return
        _stopped.add(rid)
        _stopped_order.append(rid)
        while len(_stopped_order) > _MAX_STOPPED:
            _stopped.discard(_stopped_order.pop(0))


def is_stopped(run_id: str) -> bool:
    if not run_id:
        return False
    with _lock:
        return str(run_id) in _stopped


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


# --- App-wide event stream (cross-run notify channel) -----------------------------

def global_log(kind: str, payload: dict[str, Any] | None = None) -> None:
    """Append a cross-run event (``finding_confirmed`` | ``report_ready`` | ``submitted``)
    to the single app-wide ring the UI polls. Mirrors ``log``'s ``base_seq`` bookkeeping so a
    client's absolute ``after`` cursor never desyncs once the ring wraps. Must NOT be called
    while ``_lock`` is already held (it takes the same lock)."""
    global _global_base_seq
    if not kind:
        return
    try:
        with _lock:
            _global_events.append({
                "at": datetime.now(UTC).isoformat(),
                "kind": str(kind)[:40],
                "payload": payload if isinstance(payload, dict) else {},
            })
            overflow = len(_global_events) - _MAX_GLOBAL_EVENTS
            if overflow > 0:
                del _global_events[:overflow]
                _global_base_seq += overflow
    except Exception:  # noqa: BLE001 - a notify event must never break a hunt
        pass


def global_tail(after: int = 0) -> dict[str, Any]:
    """Global events since the client's absolute cursor + the new absolute count (mirrors ``tail``)."""
    with _lock:
        base = _global_base_seq
        events = list(_global_events)
    total = base + len(events)
    try:
        start_idx = max(0, int(after) - base)
    except (TypeError, ValueError):
        start_idx = 0
    return {"events": events[start_idx:], "count": total}


# --- Structured campaign-dashboard state (per run) --------------------------------
# A campaign registers its work units (named targets for a program span, or discovered
# URLs for a single-target campaign) and streams status + findings as each finishes, so
# the UI can render a live dashboard instead of waiting for the whole run to return.

def set_targets(run_id: str, targets: list[str]) -> None:
    """Register the planned work units as 'queued', preserving order. Idempotent — a unit
    already known keeps its current status/counts."""
    if not run_id:
        return
    try:
        with _lock:
            entry = _runs.get(run_id)
            if entry is None:
                return
            for raw in targets or []:
                name = str(raw or "").strip()
                if name and name not in entry["target_index"]:
                    rec = {"target": name, "status": "queued", "findings": 0, "confirmed": 0,
                           "top_severity": "", "error": "", "elapsed_s": None}
                    entry["target_index"][name] = rec
                    entry["targets"].append(rec)
    except Exception:  # noqa: BLE001 - progress must never break a hunt
        pass


def mark_target(run_id: str, target: str, status: str, *, error: str = "", elapsed_s: float | None = None) -> None:
    """Set a work unit's status (queued|running|done|error). Auto-registers an unknown one."""
    if not run_id:
        return
    try:
        with _lock:
            entry = _runs.get(run_id)
            if entry is None:
                return
            name = str(target or "").strip()
            rec = entry["target_index"].get(name)
            if rec is None:
                rec = {"target": name, "status": status, "findings": 0, "confirmed": 0,
                       "top_severity": "", "error": "", "elapsed_s": None}
                entry["target_index"][name] = rec
                entry["targets"].append(rec)
            rec["status"] = str(status)
            if error:
                rec["error"] = str(error)[:300]
            if elapsed_s is not None:
                rec["elapsed_s"] = round(float(elapsed_s), 1)
    except Exception:  # noqa: BLE001
        pass


def _compact_proof_detail(pd: Any) -> dict[str, Any] | None:
    """A bounded copy of a finding's ACTIVE proof (observed-vs-control differential + evidence) so the
    dashboard drawer's "View full report" can render a campaign-confirmed finding as CONFIRMED without a
    manual re-verify. Only the fields the on-demand report consumes, size-bounded to keep the polled
    snapshot light."""
    if not isinstance(pd, dict):
        return None
    out = {k: str(pd.get(k))[:3000] for k in ("status", "method", "observed_result", "control_result",
                                              "evidence", "affected_asset", "limitations") if pd.get(k)}
    return out or None


def _compact_proof_evidence(pe: Any) -> dict[str, Any] | None:
    """A bounded copy of a finding's captured request/response artifact for the same on-demand report."""
    if not isinstance(pe, dict):
        return None
    # Singular request_header/response_header — the real proof_evidence schema (matches
    # ProofEvidenceInput + the report builder); the plural forms would silently drop the crafted
    # request / response header evidence a CORS / redirect / host-header report reproduces from.
    # sensitive_data_labels too: it names the disclosed data in generic English (never the data), and
    # it is what remains once read_data is redacted — the dashboard drawer and any report rebuilt from
    # this snapshot would otherwise be unable to say what was at risk.
    out = {k: str(pe.get(k))[:3000] for k in ("request_line", "request_header", "response_header",
                                             "response_status", "matched_value", "read_data",
                                             "sensitive_data_labels") if pe.get(k)}
    return out or None


def add_findings(run_id: str, target: str, findings: list[dict[str, Any]]) -> None:
    """Append compact findings discovered for a work unit and roll their counts into it."""
    if not run_id:
        return
    confirmed_events: list[dict[str, Any]] = []  # emitted to the app-wide stream AFTER the lock releases
    try:
        with _lock:
            entry = _runs.get(run_id)
            if entry is None:
                return
            name = str(target or "").strip()
            rec = entry["target_index"].get(name)
            added = confirmed = 0
            top = ""
            for f in findings or []:
                if len(entry["findings"]) >= _MAX_FINDINGS_PER_RUN:
                    break
                sev = str(f.get("severity") or "info").lower()
                if sev not in _SEV_RANK:
                    sev = "info"
                proof = str(f.get("proof_status") or f.get("proof") or "").lower()
                # Carry a few extra fields so the dashboard's click-to-investigate drawer
                # (and its on-demand re-verify) has real content: where the finding lives
                # (the URL to re-probe), its CWE, and the rule that raised it.
                entry["findings"].append({
                    "target": name, "ref": str(f.get("ref") or ""),
                    "title": str(f.get("title") or "")[:160],
                    "severity": sev, "cls": str(f.get("class_name") or f.get("class_id") or ""),
                    "proof": proof, "at": datetime.now(UTC).isoformat(),
                    "location": str(f.get("location") or f.get("source_url") or "")[:600],
                    "cwe": str(f.get("cwe") or "")[:40],
                    "rule": str(f.get("rule_id") or f.get("rule") or "")[:80],
                    "class_id": str(f.get("class_id") or "")[:80],
                    # The captured active proof (differential) + request/response artifact, so a
                    # campaign-confirmed finding's full report renders CONFIRMED straight from the drawer.
                    "proof_detail": _compact_proof_detail(f.get("proof_detail")),
                    "proof_evidence": _compact_proof_evidence(f.get("proof_evidence")),
                })
                added += 1
                if proof == "confirmed":
                    confirmed += 1
                    confirmed_events.append({
                        "run_id": str(run_id), "target": name, "ref": str(f.get("ref") or ""),
                        "title": str(f.get("title") or "")[:160], "severity": sev,
                        "cls": str(f.get("class_name") or f.get("class_id") or ""),
                        "location": str(f.get("location") or f.get("source_url") or "")[:600],
                        "class_id": str(f.get("class_id") or "")[:80],
                    })
                if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(top, 0):
                    top = sev
            if rec is not None:
                rec["findings"] = int(rec.get("findings", 0)) + added
                rec["confirmed"] = int(rec.get("confirmed", 0)) + confirmed
                if _SEV_RANK.get(top, 0) > _SEV_RANK.get(rec.get("top_severity", ""), 0):
                    rec["top_severity"] = top
    except Exception:  # noqa: BLE001
        pass
    # Emit outside the lock — global_log takes the same (non-reentrant) _lock.
    for ev in confirmed_events:
        global_log("finding_confirmed", ev)


def snapshot(run_id: str) -> dict[str, Any]:
    """The current structured dashboard state: work units (status + counts), the streamed
    findings, and rolled-up stats. Safe on an unknown run_id (returns an empty shape)."""
    empty = {"targets": [], "findings": [],
             "stats": {"targets_total": 0, "targets_done": 0, "findings_total": 0,
                       "confirmed_total": 0, "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}}
    with _lock:
        entry = _runs.get(run_id) if run_id else None
        if entry is None:
            return empty
        targets = [dict(t) for t in entry["targets"]]
        findings = list(entry["findings"])
    done = sum(1 for t in targets if t.get("status") in ("done", "error"))
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confirmed = 0
    for f in findings:
        s = f.get("severity", "info")
        if s in sev_counts:
            sev_counts[s] += 1
        if f.get("proof") == "confirmed":
            confirmed += 1
    return {"targets": targets, "findings": findings,
            "stats": {"targets_total": len(targets), "targets_done": done,
                      "findings_total": len(findings), "confirmed_total": confirmed,
                      "severity_counts": sev_counts}}


def list_runs() -> list[dict[str, Any]]:
    """The runs this process is holding progress for, newest first — a picker, not a report.

    A ``run_id`` is minted by the client that launched the run (``crypto.randomUUID()`` in the
    browser) and is written down nowhere a second process can read it, so an operator attaching from
    a shell can only ever watch a run they started themselves. This is the discovery step that makes
    attaching to somebody else's run possible at all.

    **There is no "finished" here to report, and none is invented.** Nothing marks a run complete —
    the route simply returns when the hunt returns — so a run that ended an hour ago is
    indistinguishable from one still probing. ``stopped`` means a stop was REQUESTED, never that the
    run has wound down. The honest signals a caller can act on are ``started_at`` and whether the
    counts are still moving between polls.

    Ordered by ``_run_order``, reversed: that is the same FIFO ``_MAX_RUNS`` evicts from, so the
    first row is the run furthest from being evicted. Not sorted by ``started_at`` — restarting an
    id refreshes its place in the eviction queue, and eviction order is what a watcher actually
    cares about.

    Read-only: it creates nothing and evicts nothing. Cheap enough to poll (one lock, no copying of
    event or finding bodies).
    """
    with _lock:
        rows = []
        for run_id in reversed(_run_order):
            entry = _runs.get(run_id)
            if entry is None:
                continue
            targets = entry["targets"]
            rows.append({
                "run_id": run_id,
                "started_at": str(entry.get("started_at") or ""),
                "stopped": run_id in _stopped,
                # The first registered work unit, which is what makes two live runs tellable apart
                # in a picker. Empty until the campaign registers its units (a direct hunt that has
                # not reached set_targets yet, or a run that only ever logged text), so a caller
                # must fall back to the run id rather than render a blank label.
                "target": str(targets[0].get("target") or "") if targets else "",
                "targets_total": len(targets),
                "findings_total": len(entry["findings"]),
                "events": entry["base_seq"] + len(entry["events"]),
            })
        return rows
