"""GreyIQ BugHunter — hunt trace log (the offline-brain distillation corpus).

Every URL hunt reasons over a recon SURFACE and produces a PLAN — which parameter
NAMES to try and which vuln class each endpoint most likely hides (``hunt_brain.
plan_hunt`` / ``offline_hunt.offline_plan``) — then the deterministic, scope-gated
prover CONFIRMS a subset. This module records that ``(surface, plan, outcomes)``
triple as ONE append-only JSONL line per hunt under the runtime dir.

It is the immutable event log the offline-brain distillation learns from
(see ``docs/offline-hunt-brain-distillation.md``): a learned endpoint->class ranker
and param-name model trained on what ACTUALLY confirmed/paid, so the offline hunt
brain grows sharper than its hand-tuned rules in ``offline_hunt.py`` — fully offline.

Design:
  * APPEND-ONLY JSONL (one hunt = one line). The log is never rewritten, so a bounty
    that lands weeks later is picked up by joining to the ledger at READ time
    (``training_examples``), not by mutating past lines.
  * The trace stores only what the plan already safely contains: endpoint URLs
    (recon'd from an AUTHORIZED target, exactly like the ledger's ``source_url``),
    parameter NAMES, vuln-class labels, and confirm STATUSES. Never a payload,
    secret, or request/response body — the plan is names + class orderings by
    construction (the same invariant that makes ``hunt_brain`` safe).
  * Local-only / privacy-preserving: same runtime dir + same authorized-target data
    as ``ledger.py`` / ``learning.py``. Nothing leaves the machine.

Pure / dependency-free / frozen-safe: stdlib + intra-repo imports only. Appends are
serialized behind a process lock; the reader tolerates (skips) a torn final line, so
a crash mid-append can never poison the corpus. Best-effort + fail-closed: a write
error (bad runtime dir, OneDrive/Windows lock) returns False and never raises — a
trace write must never break a hunt.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bughunter.code_scanner.redaction import redact_text
from bughunter.learning import program_key

_STORE_NAME = "hunt_traces.jsonl"
_LOCK = threading.Lock()  # serialize appends (mirrors ledger.py/learning.py write discipline)
_SCHEMA_VERSION = 1
_MAX_PROGRAM = 120  # cap the program key so a pathological operator-supplied handle can't bloat a line

# Per-record caps so one hunt's line stays bounded even on a huge surface. Training
# wants more than the LLM prompt cap (hunt_brain._MAX_ENDPOINTS_IN_PROMPT == 40) but
# not an unbounded dump; these keep the JSONL lean while preserving learning signal.
_MAX_ENDPOINTS = 300
_MAX_PARAMS = 300
_MAX_TECH = 40
_MAX_FORMS = 60
_MAX_FORM_FIELDS = 30
_MAX_PLAN_LIST = 60
_MAX_OUTCOMES = 400


def _store_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / _STORE_NAME


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _clip_strs(values: Any, cap: int) -> list[str]:
    """Coerce a model/recon-supplied value to a capped list of non-empty strings.
    Tolerant of a non-list (a hijacked/garbled field): returns [] rather than raising.
    For NAMES only (params, tech, class labels) — no redaction (a name carries no secret)."""
    out: list[str] = []
    for v in values if isinstance(values, (list, tuple)) else []:
        s = str(v or "").strip()
        if s:
            out.append(s[:600])
        if len(out) >= cap:
            break
    return out


def _redact_url(value: Any) -> str:
    """Strip secret VALUES (a ``?token=``/``?access_token=``/``AKIA…``/``eyJ…`` a recon endpoint can
    carry from the target's served HTML/JS) out of a URL while keeping its structure and parameter
    NAMES — via the codebase's standard ``redact_text``. Leaves bare numeric/uuid path segments (the
    IDOR training signal) untouched. Redact BEFORE the length cap so a secret spanning the cap boundary
    can't slip through half-matched. Fail-open to the raw string: redaction must never break a trace."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return redact_text(raw)[0][:600]
    except Exception:  # noqa: BLE001 - redaction must never break trace recording
        return raw[:600]


def _clip_urls(values: Any, cap: int) -> list[str]:
    """Like _clip_strs but for endpoint URL lists — each is secret-redacted via _redact_url."""
    out: list[str] = []
    for v in values if isinstance(values, (list, tuple)) else []:
        s = _redact_url(v)
        if s:
            out.append(s)
        if len(out) >= cap:
            break
    return out


def _compact_surface(surface: dict[str, Any] | None) -> dict[str, Any]:
    """Bounded, self-contained copy of the recon surface (endpoints/params/tech/forms)."""
    s = surface if isinstance(surface, dict) else {}
    forms_out: list[dict[str, Any]] = []
    for f in (s.get("forms") or [])[:_MAX_FORMS]:
        if not isinstance(f, dict):
            continue
        forms_out.append({
            "action": _redact_url(f.get("action")),  # a form action is a URL — redact any secret value
            "method": str(f.get("method") or "GET").strip().upper()[:10],
            "params": _clip_strs(f.get("params"), _MAX_FORM_FIELDS),  # field NAMES — no redaction
        })
    return {
        "endpoints": _clip_urls(s.get("endpoints"), _MAX_ENDPOINTS),  # URLs — redact secret values
        "params": _clip_strs(s.get("params"), _MAX_PARAMS),  # NAMES only
        "tech": _clip_strs(s.get("tech"), _MAX_TECH),
        "forms": forms_out,
    }


def _compact_plan(plan: dict[str, Any] | None) -> dict[str, Any]:
    """Bounded copy of the plan_hunt/offline_plan output (names + class orderings only)."""
    p = plan if isinstance(plan, dict) else {}
    priority: list[dict[str, Any]] = []
    for row in (p.get("probe_priority") or [])[:_MAX_PLAN_LIST]:
        if not isinstance(row, dict):
            continue
        endpoint = _redact_url(row.get("endpoint"))  # an endpoint URL — redact secret values
        classes = _clip_strs(row.get("classes"), 10)
        if endpoint and classes:
            priority.append({"endpoint": endpoint, "classes": classes})
    return {
        "provider": str(p.get("provider") or "")[:40],
        "model": str(p.get("model") or "")[:120],
        "used": bool(p.get("used")),
        "param_hypotheses": _clip_strs(p.get("param_hypotheses"), _MAX_PLAN_LIST),  # NAMES only
        "probe_priority": priority,
        "idor_candidates": _clip_urls(p.get("idor_candidates"), _MAX_PLAN_LIST),  # URLs — redact
        "privileged_endpoints": _clip_urls(p.get("privileged_endpoints"), _MAX_PLAN_LIST),  # URLs — redact
        "ssrf_params": _clip_strs(p.get("ssrf_params"), _MAX_PLAN_LIST),  # NAMES only
        "xss_params": _clip_strs(p.get("xss_params"), _MAX_PLAN_LIST),  # NAMES only
    }


def outcomes_from_findings(items: Any) -> list[dict[str, Any]]:
    """Build the LABEL side — one outcome row per (endpoint, class) with its confirm
    status — from either campaign ``consolidated`` items (each ``{finding, source_url,
    proof_status, dedup_key}``) OR plain finding dicts. Tolerant of both shapes so both
    hunt paths feed one corpus. ``proof_status`` is the canonical confirmed/candidate/
    missing signal; ``dedup_key`` (when present) lets ``training_examples`` join the
    ledger later for the final stage/bounty."""
    rows: list[dict[str, Any]] = []
    for it in items if isinstance(items, (list, tuple)) else []:
        if not isinstance(it, dict):
            continue
        finding = it.get("finding") if isinstance(it.get("finding"), dict) else it
        endpoint = str(it.get("source_url") or finding.get("source_url") or finding.get("location") or "").strip()
        cls = str(finding.get("class_id") or "").strip()
        if not cls and not endpoint:
            continue
        status = str(it.get("proof_status") or finding.get("proof_status") or "missing").strip().lower()
        rows.append({
            "endpoint": endpoint[:600],
            "class": cls[:60],
            "rule_id": str(finding.get("rule_id") or "").strip()[:120],
            "proof_status": status[:20],
            "severity": str(finding.get("severity") or "").strip().lower()[:20],
            "dedup_key": str(it.get("dedup_key") or finding.get("dedup_key") or "").strip()[:40],
        })
        if len(rows) >= _MAX_OUTCOMES:
            break
    return rows


def _normalize_outcomes(rows: Any) -> list[dict[str, Any]]:
    """Cap every field and redact the endpoint on outcome rows — whether they were derived by
    :func:`outcomes_from_findings` (campaign path) or hand-built by a caller (bounty path). Applied
    uniformly by :func:`record_trace` so a hand-built row can never store an uncapped/unredacted
    value. Idempotent (redacting an already-redacted string is a no-op)."""
    out: list[dict[str, Any]] = []
    for r in rows if isinstance(rows, (list, tuple)) else []:
        if not isinstance(r, dict):
            continue
        out.append({
            "endpoint": _redact_url(r.get("endpoint")),  # a URL — redact any secret value + cap
            "class": str(r.get("class") or "").strip()[:60],
            "rule_id": str(r.get("rule_id") or "").strip()[:120],
            "proof_status": str(r.get("proof_status") or "").strip()[:20],
            "severity": str(r.get("severity") or "").strip()[:20],
            "dedup_key": str(r.get("dedup_key") or "").strip()[:40],
        })
        if len(out) >= _MAX_OUTCOMES:
            break
    return out


def record_trace(
    runtime_dir: str | Path | None,
    *,
    program: str | None,
    target: str,
    surface: dict[str, Any] | None,
    plan: dict[str, Any] | None,
    outcomes: list[dict[str, Any]] | None = None,
    consolidated: Any = None,
    now: str | None = None,
) -> bool:
    """Append ONE hunt trace line and return True if written.

    Provide EITHER pre-built ``outcomes`` (rows from :func:`outcomes_from_findings`)
    OR raw ``consolidated`` findings (campaign items / finding dicts) to derive them.
    Either way the rows pass through :func:`_normalize_outcomes` (field caps + endpoint
    redaction), and every stored URL/name is bounded and secret-redacted.

    Best-effort + fail-closed: ``runtime_dir is None`` or any write error (bad path,
    OneDrive/Windows lock) returns False and never raises — a trace write must never
    break a hunt."""
    if runtime_dir is None:
        return False
    try:
        rows = _normalize_outcomes(outcomes if outcomes is not None else outcomes_from_findings(consolidated))
        record = {
            "v": _SCHEMA_VERSION,
            "ts": now or _now(),
            "program": program_key(program, target)[:_MAX_PROGRAM],
            "target": _redact_url(target),  # a full target URL can carry a secret (?access_token=, magic-link) — redact like every other URL in the record
            "surface": _compact_surface(surface),
            "plan": _compact_plan(plan),
            "outcomes": rows,
        }
        line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
        path = _store_path(runtime_dir)
        with _LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            # If a prior append left a torn fragment WITHOUT its trailing newline (a crash mid-write —
            # a single record can be hundreds of KB, well past the OS write buffer), terminate it with a
            # newline before this record. Otherwise {torn}{good}\n concatenate into ONE physical line
            # that the reader can't parse, losing BOTH the fragment AND this good record.
            prefix = ""
            try:
                if path.exists() and path.stat().st_size:
                    with path.open("rb") as probe:
                        probe.seek(-1, 2)
                        if probe.read(1) != b"\n":
                            prefix = "\n"
            except OSError:
                prefix = ""
            with path.open("a", encoding="utf-8") as handle:
                handle.write(prefix + line)
        return True
    except Exception:  # noqa: BLE001 - a trace write must never break a hunt
        return False


def load_traces(runtime_dir: str | Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Read the hunt traces in chronological (file) order, skipping any torn/corrupt
    line (a crash mid-append). ``limit`` returns the most RECENT N (the tail)."""
    path = _store_path(runtime_dir)
    out: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (ValueError, TypeError):
                    continue  # torn/partial line — skip (self-healing corpus)
                if isinstance(rec, dict):
                    out.append(rec)
    except OSError:
        return []
    if limit is None:
        return out
    # limit N > 0 -> the most recent N (tail); limit <= 0 -> nothing (never out[-0:], which
    # is out[0:] == the WHOLE list — the classic lst[-n:]-at-n=0 slice inversion).
    return out[-limit:] if limit > 0 else []


def trace_stats(runtime_dir: str | Path) -> dict[str, Any]:
    """Quick corpus summary for a CLI/UI 'training data' readout: hunts logged,
    distinct programs, total outcome rows, and how many outcome rows confirmed."""
    traces = load_traces(runtime_dir)
    programs: set[str] = set()
    outcome_rows = 0
    confirmed = 0
    for t in traces:
        programs.add(str(t.get("program") or ""))
        for o in t.get("outcomes") or []:
            if not isinstance(o, dict):
                continue
            outcome_rows += 1
            if str(o.get("proof_status") or "").strip().lower() == "confirmed":
                confirmed += 1
    return {
        "hunts": len(traces),
        "programs": len(programs),
        "outcome_rows": outcome_rows,
        "confirmed_rows": confirmed,
    }


def training_examples(runtime_dir: str | Path) -> list[dict[str, Any]]:
    """Join each trace's outcomes to the CURRENT ledger (by ``dedup_key``) to attach the
    finding's final pipeline stage + bounty — the 'backfill from the ledger' the
    distillation plan calls for, done LAZILY at read time so a bounty that lands after
    the hunt is reflected without ever rewriting the append-only log.

    Yields one labeled row per (endpoint, class): the surface it came from, the confirm
    status at hunt time, and the ledger's final stage/bounty/paid. This is the
    supervised corpus the Phase 2 endpoint->class ranker consumes."""
    from bughunter import ledger  # lazy: keep this module import-light and avoid any cycle

    try:
        records = ledger.list_all(runtime_dir, limit=100000)
    except Exception:  # noqa: BLE001 - a missing/corrupt ledger just means no backfill
        records = []
    by_key = {str(r.get("dedup_key") or ""): r for r in records if isinstance(r, dict)}

    rows: list[dict[str, Any]] = []
    for t in load_traces(runtime_dir):
        surface = t.get("surface") if isinstance(t.get("surface"), dict) else {}
        program = str(t.get("program") or "")
        target = str(t.get("target") or "")
        for o in t.get("outcomes") or []:
            if not isinstance(o, dict):
                continue
            key = str(o.get("dedup_key") or "")
            rec = by_key.get(key) if key else None
            confirmed = str(o.get("proof_status") or "").strip().lower() == "confirmed"
            stage = str((rec or {}).get("stage") or ("confirmed" if confirmed else "discovered"))
            try:
                bounty = float((rec or {}).get("bounty") or 0.0)
            except (TypeError, ValueError):
                bounty = 0.0
            rows.append({
                "program": program,
                "target": target,
                "surface": surface,
                "endpoint": str(o.get("endpoint") or ""),
                "class": str(o.get("class") or ""),
                "proof_status": str(o.get("proof_status") or ""),
                "confirmed": confirmed,
                "stage": stage,
                "bounty": bounty,
                "paid": bounty > 0.0,
            })
    return rows
