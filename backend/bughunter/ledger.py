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
    """Stable per-finding key: class + rule + digit-normalized location (+ CVE product).

    Known-CVE ("vulnerable-component") findings for DIFFERENT libraries served from the same
    page all share an identical class_id/rule_id/location, so without the product they collapse
    to ONE key — deleting one library's finding would then silently suppress every other
    library's finding on that page (and the campaign's own in-run dedup keys them per product,
    so they legitimately co-exist as separate rows). Folding in the deterministic
    ``_cve_product`` keeps distinct libraries distinct while staying stable across runs. The
    field is absent on every non-CVE finding, so their keys are byte-for-byte unchanged."""
    product = str(finding.get("_cve_product") or "")
    extra = f"|{product}" if product else ""
    raw = f"{finding.get('class_id')}|{finding.get('rule_id')}|{_normalized_location(finding)}{extra}"
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
                    "h1_state": "", "h1_synced_at": "", "submitted_at": "",
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
    # submitted_at is stamped ONLY here, at the moment of actual filing -- unlike
    # updated_at (bumped by every later stage transition, e.g. a routine HackerOne
    # status-sync poll moving the record to 'paid'), it stays fixed forever after,
    # so count_recent_submissions can't mistake an old submission for one made today.
    advance_stage(runtime_dir, program, target, key, "submitted", h1_report_id=report_id, report_url=url, submitted_at=_now())


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


# --- Deletion / suppression -------------------------------------------------------
# A finding the operator DELETES is recorded here by its stable dedup key. Every future
# hunt/campaign filters these out, and the durable history + funnel + CSV export hide
# them — so a deleted finding is never surfaced again (the same class+rule+normalized-
# location match, so the delete sticks across runs, targets, and programs). Fully
# reversible via ``restore`` (the record's money/stage data is preserved, just hidden).


def dismissed_keys(runtime_dir: str | Path) -> set[str]:
    """The set of deleted (suppressed) dedup keys — what the engine filters out."""
    return set((_load(runtime_dir).get("dismissed") or {}))


def is_dismissed(runtime_dir: str | Path, finding: dict[str, Any]) -> bool:
    return dedup_key(finding) in (_load(runtime_dir).get("dismissed") or {})


def dismiss(
    runtime_dir: str | Path,
    *,
    finding: dict[str, Any] | None = None,
    dedup_key_str: str = "",
    program: str | None = None,
    target: str = "",
) -> dict[str, Any]:
    """Delete a finding: permanently suppress it. Keyed by the stable cross-run dedup key,
    taken from an explicit ``dedup_key_str`` (a durable-history record already carries one)
    or derived from a ``finding`` dict. Best-effort metadata (class/rule/title/location) is
    recorded alongside; any live ledger record with that key is flagged too. Reversible via
    ``restore``. Returns the stored entry, or ``{}`` when no key could be derived."""
    key = str(dedup_key_str or "").strip()
    if not key and finding is not None:
        key = dedup_key(finding)
    if not key:
        return {}
    f = finding or {}
    with _LOCK:
        data = _load(runtime_dir)
        dismissed = data.setdefault("dismissed", {})
        prior = dismissed.get(key) or {}
        entry = {
            "dedup_key": key,
            "class_id": f.get("class_id") or prior.get("class_id") or "",
            "rule_id": f.get("rule_id") or prior.get("rule_id") or "",
            "title": str(f.get("title") or "")[:200] or prior.get("title") or "",
            "location": str(f.get("location") or f.get("source_url") or "") or prior.get("location") or "",
            "program": (program_key(program, target) if (program or target) else prior.get("program", "")),
            "dismissed_at": _now(),
        }
        dismissed[key] = entry
        # Flag the live record too, wherever it lives, so a later restore can find it.
        for bucket in data.get("programs", {}).values():
            rec = (bucket.get("findings") or {}).get(key)
            if rec is not None:
                rec["dismissed"] = True
                rec["dismissed_at"] = entry["dismissed_at"]
        _save(runtime_dir, data)
    return entry


def restore(runtime_dir: str | Path, dedup_key_str: str) -> bool:
    """Undo a ``dismiss`` — the finding can surface again. Returns True if it was deleted."""
    key = str(dedup_key_str or "").strip()
    if not key:
        return False
    with _LOCK:
        data = _load(runtime_dir)
        dismissed = data.get("dismissed") or {}
        was = key in dismissed
        if was:
            del dismissed[key]
            data["dismissed"] = dismissed
            for bucket in data.get("programs", {}).values():
                rec = (bucket.get("findings") or {}).get(key)
                if rec is not None:
                    rec.pop("dismissed", None)
                    rec.pop("dismissed_at", None)
            _save(runtime_dir, data)
    return was


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
        # submitted_at (set once, at filing time — see record_submission) is the
        # correct signal here, not updated_at, which is bumped by every later stage
        # transition (a status-sync poll marking the record 'paid' would otherwise
        # make a submission from 10 days ago look like it happened in the last 24h,
        # wrongly eating into today's max_submits_per_day throttle). Records that
        # predate this field fall back to updated_at, their only prior signal.
        stamp = rec.get("submitted_at") or rec.get("updated_at")
        try:
            if datetime.fromisoformat(str(stamp)) >= cutoff:
                count += 1
        except (ValueError, TypeError):
            count += 1  # unparseable stamp — count it (fail toward the throttle)
    return count


def funnel(runtime_dir: str | Path, program: str | None = None, target: str = "") -> dict[str, Any]:
    """Per-program (or whole-portfolio) pipeline counts per stage + bounty totals — the
    money dashboard's source of truth."""
    store = _load(runtime_dir)
    dismissed = store.get("dismissed") or {}
    data = store.get("programs", {})
    keys = [program_key(program, target)] if (program or target) else list(data)

    def _count(pids: list[str]) -> dict[str, Any]:
        counts = dict.fromkeys(STAGES, 0)
        bounty = 0.0
        total = 0
        for pid in pids:
            for key, rec in (data.get(pid, {}).get("findings", {}) or {}).items():
                if key in dismissed or rec.get("dismissed"):
                    continue  # deleted findings are out of the pipeline entirely
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


# Column order for to_csv_rows() -- every field a bounty hunter would want in a
# spreadsheet for manual tracking or income reporting. Fixed and explicit (not
# `rec.keys()`) so the CSV shape never silently changes if a record gains an
# internal-only field later.
CSV_COLUMNS: tuple[str, ...] = (
    "program", "dedup_key", "class_id", "rule_id", "title", "severity", "stage",
    "proof_status", "cvss_base", "source_url", "bounty", "outcome", "h1_report_id",
    "h1_state", "first_seen", "last_seen", "submitted_at", "updated_at",
)

# Leading characters Excel/Sheets/LibreOffice treat as the start of a formula when a
# cell is opened. `title`/`source_url`/`program` can carry text influenced by a
# scanned target (a URL path, a page title) -- a hostile program could otherwise land
# a formula (data exfiltration via HYPERLINK/WEBSERVICE, or DDE) in a hunter's own
# spreadsheet export.
_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _defang_csv_cell(value: Any) -> Any:
    """A leading apostrophe is rendered as literal text (never evaluated) by every
    mainstream spreadsheet app -- the standard CSV-formula-injection mitigation."""
    text = value if isinstance(value, str) else str(value if value is not None else "")
    return "'" + text if text.startswith(_CSV_FORMULA_TRIGGERS) else value


_MAX_LIST_ALL = 2000  # cap the history response so a huge ledger can't balloon one JSON payload


def list_all(runtime_dir: str | Path, limit: int = _MAX_LIST_ALL) -> list[dict[str, Any]]:
    """The most-recently-updated finding records across the WHOLE portfolio (capped at
    ``limit``) — the durable finding/report history the UI surfaces (survives an app restart,
    unlike the in-memory run cache). Read-only; each record carries its own ``program`` bucket
    id and ``dedup_key`` so the caller can act on it (build a report, export, sync) without a
    re-derivation. Raw records (not CSV-defanged) — the UI renders text, not a spreadsheet. The
    cap bounds the response size for a very large history; the full ledger is always available
    via the CSV export (streamed column rows) for spreadsheet/audit use."""
    store = _load(runtime_dir)
    dismissed = store.get("dismissed") or {}
    data = store.get("programs", {})
    out: list[dict[str, Any]] = []
    for pid, bucket in data.items():
        for key, rec in (bucket.get("findings") or {}).items():
            if key in dismissed or rec.get("dismissed"):
                continue  # deleted — never surfaced in the durable history
            out.append({**rec, "program": pid, "dedup_key": key})
    out.sort(key=lambda r: str(r.get("updated_at") or r.get("last_seen") or ""), reverse=True)
    return out[: max(1, limit)]


def to_csv_rows(runtime_dir: str | Path, program: str | None = None, target: str = "") -> list[dict[str, Any]]:
    """Flatten every finding record (one program, or the whole portfolio) into
    spreadsheet-friendly rows with a fixed, stable column set (CSV_COLUMNS). Read-
    only -- never mutates the store."""
    store = _load(runtime_dir)
    dismissed = store.get("dismissed") or {}
    data = store.get("programs", {})
    pids = [program_key(program, target)] if (program or target) else list(data)
    rows: list[dict[str, Any]] = []
    for pid in pids:
        for key, rec in (data.get(pid, {}).get("findings", {}) or {}).items():
            if key in dismissed or rec.get("dismissed"):
                continue  # deleted — kept out of the spreadsheet/audit export too
            row = {col: _defang_csv_cell(rec.get(col, "")) for col in CSV_COLUMNS}
            row["program"] = _defang_csv_cell(pid)  # authoritative -- rec["program"] may be stale/absent on an old record
            rows.append(row)
    return rows
