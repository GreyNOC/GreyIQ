"""GreyIQ BugHunter — persistent finding ledger (cross-run dedup + pipeline funnel).

Every finding the engine surfaces is recorded here by a stable dedup key so that:
  * a re-run never re-reports a finding it already reported (the #1 thing that gets a
    bounty hunter banned for duplicates/spam), and
  * the operator can show a real money pipeline funnel: discovered -> confirmed ->
    reported -> submitted -> paid, with $ per program.

The submit path consults ``is_duplicate`` before filing — a PURELY ADDITIVE refusal
on top of the unbypassable hard gate in submission.submit_to_hackerone (confirm +
server-recomputed proof_status=='confirmed' + real creds). This store can never
relax a gate; it only ever blocks a re-file.

Pure / dependency-free / frozen-safe: one atomically-written JSON file under the
runtime dir, mutations serialized behind a process lock. Keyed on the SAME
``program_key`` as the portfolio and learning stores (one program = one memory).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from bughunter.learning import program_key

_STORE_NAME = "bughunter_ledger.json"
_LOCK = threading.Lock()

# Pipeline stages, ordered. A finding only ever moves FORWARD.
STAGES = ("discovered", "confirmed", "reported", "submitted", "paid")
_STAGE_RANK = {s: i for i, s in enumerate(STAGES)}


def _store_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / _STORE_NAME


def _load(runtime_dir: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(_store_path(runtime_dir).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"programs": {}}
    except (OSError, json.JSONDecodeError):
        return {"programs": {}}


def _save(runtime_dir: str | Path, data: dict[str, Any]) -> None:
    path = _store_path(runtime_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    replaced = False
    try:
        tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, path)
        replaced = True
    finally:
        if not replaced:
            tmp.unlink(missing_ok=True)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _normalized_location(finding: dict[str, Any]) -> str:
    # Same normalization the campaign in-run dedup uses, so the in-run set and the
    # persistent store share ONE definition (no drift): digits -> N.
    loc = str(finding.get("location") or finding.get("file_path") or finding.get("source_url") or "")
    return re.sub(r"\d+", "N", loc)


def dedup_key(finding: dict[str, Any]) -> str:
    """Stable per-finding key: class + rule + digit-normalized location."""
    raw = f"{finding.get('class_id')}|{finding.get('rule_id')}|{_normalized_location(finding)}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:20]


def _prog_bucket(data: dict[str, Any], pid: str) -> dict[str, Any]:
    return data.setdefault("programs", {}).setdefault(pid, {"findings": {}})


def upsert_findings(
    runtime_dir: str | Path, program: str | None, target: str, consolidated: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Record/refresh each consolidated finding. Returns the SAME list with each item
    annotated: item['dedup_key'] and item['duplicate_of_prior'] (True if this key was
    already at stage >= reported in a prior run — i.e. don't re-report it). New keys are
    recorded at stage 'confirmed' only when proof_status=='confirmed' (server truth),
    else 'discovered' — the funnel's confirmed count can never inflate the submit pool."""
    pid = program_key(program, target)
    with _LOCK:
        data = _load(runtime_dir)
        bucket = _prog_bucket(data, pid)
        findings = bucket["findings"]
        for item in consolidated:
            finding = item.get("finding") or item
            key = dedup_key(finding)
            proof = str(item.get("proof_status") or finding.get("proof_status") or "missing")
            item["dedup_key"] = key
            rec = findings.get(key)
            prior_stage = _STAGE_RANK.get(rec.get("stage"), 0) if rec else -1
            item["duplicate_of_prior"] = prior_stage >= _STAGE_RANK["reported"]
            new_stage = "confirmed" if proof == "confirmed" else "discovered"
            if rec is None:
                findings[key] = {
                    "dedup_key": key, "program": pid, "class_id": finding.get("class_id"),
                    "rule_id": finding.get("rule_id"), "title": str(finding.get("title") or "")[:200],
                    "severity": str(finding.get("severity") or ""), "source_url": item.get("source_url") or finding.get("location") or "",
                    "proof_status": proof, "stage": new_stage,
                    "cvss_base": (item.get("cvss") or {}).get("base_score"),
                    "first_seen": _now(), "last_seen": _now(), "updated_at": _now(),
                    "h1_report_id": "", "bounty": 0.0, "outcome": "",
                    "h1_state": "", "h1_synced_at": "",
                }
            else:
                rec["last_seen"] = _now()
                rec["proof_status"] = proof
                # Promote discovered->confirmed if it now confirms; never regress.
                if _STAGE_RANK.get(new_stage, 0) > _STAGE_RANK.get(rec.get("stage"), 0):
                    rec["stage"] = new_stage
                    rec["updated_at"] = _now()
        _save(runtime_dir, data)
    return consolidated


def advance_stage(runtime_dir: str | Path, program: str | None, target: str, key: str, stage: str, **fields: Any) -> None:
    """Move one finding forward to ``stage`` (never backward) and merge extra fields."""
    if stage not in _STAGE_RANK:
        return
    pid = program_key(program, target)
    with _LOCK:
        data = _load(runtime_dir)
        rec = _prog_bucket(data, pid)["findings"].get(key)
        if not rec:
            return
        if _STAGE_RANK[stage] > _STAGE_RANK.get(rec.get("stage"), 0):
            rec["stage"] = stage
        for k, v in fields.items():
            rec[k] = v
        rec["updated_at"] = _now()
        _save(runtime_dir, data)


def record_submission(runtime_dir: str | Path, program: str | None, target: str, key: str, report_id: str, url: str = "") -> None:
    advance_stage(runtime_dir, program, target, key, "submitted", h1_report_id=report_id, report_url=url)


def record_paid(runtime_dir: str | Path, program: str | None, target: str, key: str, bounty: float, outcome: str = "accepted") -> None:
    advance_stage(runtime_dir, program, target, key, "paid", bounty=float(bounty or 0.0), outcome=outcome)


# HackerOne report states that will never change again — once a record is synced to one
# of these, a later sync pass skips it (never re-polls a closed report).
_H1_TERMINAL_STATES = {"resolved", "not-applicable", "informative", "duplicate", "spam"}


def record_h1_sync(runtime_dir: str | Path, pid: str, key: str, *, state: str, resolved_with_reward: bool) -> None:
    """Update a finding's last-known HackerOne state after a status-sync poll, given the
    ledger's own program-bucket id (``pid``, as returned by ``submitted_records`` —
    bypasses ``program_key()`` re-derivation since the caller already has the exact
    bucket the record lives in). Advances the local stage to 'paid' ONLY when the sync
    confirms a real reward (bounty_awarded_at/swag_awarded_at was set on the live
    report); a bare state change (e.g. 'triaged') never moves the stage on its own."""
    with _LOCK:
        data = _load(runtime_dir)
        rec = data.get("programs", {}).get(pid, {}).get("findings", {}).get(key)
        if not rec:
            return
        rec["h1_state"] = str(state or "")
        rec["h1_synced_at"] = _now()
        if resolved_with_reward and _STAGE_RANK.get(rec.get("stage"), 0) < _STAGE_RANK["paid"]:
            rec["stage"] = "paid"
        rec["updated_at"] = _now()
        _save(runtime_dir, data)


def submitted_records(runtime_dir: str | Path, limit: int = 25) -> list[dict[str, Any]]:
    """Every finding across the whole portfolio still worth polling HackerOne for: at
    stage 'submitted', with a real ``h1_report_id``, and NOT already synced to a
    known-terminal HackerOne state (so a repeat sync never re-polls a report that's
    already resolved/duplicate/informative/not-applicable/spam). Capped to the ``limit``
    most-recently-submitted so a sync action can never blow through HackerOne's tighter
    report-read rate limit (300/min). Each item carries ``pid``/``key`` so the caller can
    pass them straight to ``record_h1_sync``."""
    data = _load(runtime_dir).get("programs", {})
    candidates: list[dict[str, Any]] = []
    for pid, bucket in data.items():
        for key, rec in (bucket.get("findings") or {}).items():
            if rec.get("stage") != "submitted":
                continue
            if not str(rec.get("h1_report_id") or "").strip():
                continue
            if str(rec.get("h1_state") or "") in _H1_TERMINAL_STATES:
                continue
            candidates.append({**rec, "pid": pid, "key": key})
    candidates.sort(key=lambda r: str(r.get("updated_at") or ""), reverse=True)
    return candidates[: max(0, limit)]


def is_duplicate(runtime_dir: str | Path, program: str | None, target: str, finding: dict[str, Any]) -> bool:
    """True if this finding was already reported/submitted/paid — the operator/submit
    path refuses to re-file it (anti-duplicate)."""
    pid = program_key(program, target)
    rec = _load(runtime_dir).get("programs", {}).get(pid, {}).get("findings", {}).get(dedup_key(finding))
    return bool(rec and _STAGE_RANK.get(rec.get("stage"), 0) >= _STAGE_RANK["reported"])


def is_submitted(runtime_dir: str | Path, program: str | None, target: str, finding: dict[str, Any]) -> bool:
    """True only once a finding was actually FILED (stage >= submitted). The operator's
    auto-submit gates on THIS, not is_duplicate: building a local submission package marks a
    finding 'reported' in the SAME cycle, so an is_duplicate (>= reported) check would skip
    every confirmed finding before it could ever be filed. Only a real prior submission
    blocks a re-file."""
    pid = program_key(program, target)
    rec = _load(runtime_dir).get("programs", {}).get(pid, {}).get("findings", {}).get(dedup_key(finding))
    return bool(rec and _STAGE_RANK.get(rec.get("stage"), 0) >= _STAGE_RANK["submitted"])


def mark_reported(runtime_dir: str | Path, program: str | None, target: str, finding: dict[str, Any]) -> None:
    """Move a finding to 'reported' once a submission package has been produced for it."""
    advance_stage(runtime_dir, program, target, dedup_key(finding), "reported")


def count_recent_submissions(runtime_dir: str | Path, program: str | None, within_hours: int = 24, target: str = "") -> int:
    """How many findings this program filed in the last ``within_hours`` — drives the
    operator's per-program max_submits_per_day throttle."""
    from datetime import timedelta
    pid = program_key(program, target)
    cutoff = datetime.now(UTC) - timedelta(hours=within_hours)
    recs = _load(runtime_dir).get("programs", {}).get(pid, {}).get("findings", {}) or {}
    count = 0
    for rec in recs.values():
        if _STAGE_RANK.get(rec.get("stage"), 0) < _STAGE_RANK["submitted"]:
            continue
        try:
            if datetime.fromisoformat(str(rec.get("updated_at"))) >= cutoff:
                count += 1
        except (ValueError, TypeError):
            count += 1  # unparseable stamp — count it (fail toward the throttle)
    return count


def funnel(runtime_dir: str | Path, program: str | None = None, target: str = "") -> dict[str, Any]:
    """Per-program (or whole-portfolio) pipeline counts per stage + bounty totals — the
    money dashboard's source of truth."""
    data = _load(runtime_dir).get("programs", {})
    keys = [program_key(program, target)] if (program or target) else list(data)

    def _count(pids: list[str]) -> dict[str, Any]:
        counts = dict.fromkeys(STAGES, 0)
        bounty = 0.0
        total = 0
        for pid in pids:
            for rec in (data.get(pid, {}).get("findings", {}) or {}).values():
                total += 1
                stage = rec.get("stage", "discovered")
                if stage in counts:
                    counts[stage] += 1
                bounty += float(rec.get("bounty") or 0.0)
        return {"total": total, "stages": counts, "bounty_total": round(bounty, 2)}

    if program or target:
        return {"program": keys[0], **_count(keys)}
    return {
        "portfolio": _count(keys),
        "programs": {pid: _count([pid]) for pid in keys},
    }
