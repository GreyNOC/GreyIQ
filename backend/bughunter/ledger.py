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
    except (OSError, json.JSONDecodeError, RecursionError):
        # RecursionError: a hand-edited/corrupt store with deeply-nested JSON makes
        # json.loads blow the recursion limit; degrade to empty like any other bad load.
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


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Tolerant float() for a stored value from this hand-editable JSON store (matches
    learning._safe_float). A corrupt/hand-edited bounty like '1,000' or a list/dict must
    degrade to the default instead of raising and 500-ing the whole money dashboard."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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


# sensitive_data_labels rides along deliberately: it is the generic-English NAME of the data a
# captured body disclosed ("a JWT (session/bearer token); email address(es)"), never the data itself,
# so the ledger's redact-before-persist posture is unaffected. It is also the only surviving impact
# evidence once read_data has been redacted to [REDACTED_…] markers — report._sensitive_read_captured,
# report.py's "Sensitive data exposed:" line and bounty._write_sensitive_data_files all key off it, so
# a report rebuilt from history after a restart lost the disclosure's strongest claim without it.
_PE_KEYS = ("request_line", "request_header", "response_status", "response_header", "set_cookie",
            "matched_value", "read_data", "sensitive_data_labels")
_POI_KEYS = ("status", "method", "observed_result", "control_result", "evidence", "affected_asset",
             "blast_radius", "impact_narrative", "authenticated_read_request", "authenticated_read_response")


def _captured_proof(finding: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    """The captured EXPLOIT EVIDENCE worth persisting to the durable ledger so a report rebuilt from
    history (after cache eviction / restart) still shows the concrete proof — the request/response
    artifact, the live-credential/Firebase proof, the observed-vs-control differential, and the
    screenshot path. Bounded (each string capped) so the ledger stays lean."""
    out: dict[str, Any] = {}
    pe = finding.get("proof_evidence")
    if isinstance(pe, dict):
        pe_out = {k: str(pe.get(k))[:3000] for k in _PE_KEYS if str(pe.get(k) or "").strip()}
        if pe_out:
            out["proof_evidence"] = pe_out
    cred = finding.get("_credential_proof")
    if isinstance(cred, dict) and cred.get("checked"):
        out["credential_proof"] = {k: cred.get(k) for k in
            ("live", "http_status", "endpoint", "project_id", "authorized_domains", "principal", "scopes",
             "detail", "poc", "response_excerpt", "no_data_read") if cred.get(k) not in (None, "")}
    # The observed-vs-control differential lives in the attack plan for synthetic findings (CVE/IDOR/
    # BFLA carry an inline "plan"); per-URL active findings carry it directly on the item as
    # "proof_of_impact" instead (the "plan" key is reserved as the synthetic-vs-sidecar sentinel in
    # campaign.py). Persist it from whichever the caller supplied, so a rebuilt-from-history report of a
    # confirmed finding of EITHER origin still shows the concrete differential, never an empty shell.
    plan = item.get("plan") if isinstance(item.get("plan"), dict) else {}
    poi = plan.get("proof_of_impact") if isinstance(plan.get("proof_of_impact"), dict) else {}
    if not poi and isinstance(item.get("proof_of_impact"), dict):
        poi = item["proof_of_impact"]
    poi_out = {k: str(poi.get(k))[:3000] for k in _POI_KEYS if str(poi.get(k) or "").strip()}
    if poi_out:
        out["proof_of_impact"] = poi_out
    if finding.get("secret_hits"):
        out["secret_hits"] = True
    sp = str(finding.get("screenshot_path") or finding.get("source_text_path") or "").strip()
    if sp:
        out["screenshot_path"] = sp[:600]
    return out


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
            captured = _captured_proof(finding, item)  # the actual exploit evidence (bounded), for a rebuilt report
            if rec is None:
                findings[key] = {
                    "dedup_key": key, "program": pid, "class_id": finding.get("class_id"),
                    "rule_id": finding.get("rule_id"), "title": str(finding.get("title") or "")[:200],
                    "severity": str(finding.get("severity") or ""), "source_url": item.get("source_url") or finding.get("location") or "",
                    "proof_status": proof, "stage": new_stage,
                    "cvss_base": (item.get("cvss") or {}).get("base_score"),
                    # The captured exploit artifacts (request/response, live-credential/Firebase proof,
                    # observed-vs-control differential, screenshot) — so a report REBUILT from history
                    # after a restart/eviction still shows the concrete proof, not an empty shell.
                    "captured_proof": captured,
                    "first_seen": _now(), "last_seen": _now(), "updated_at": _now(),
                    "h1_report_id": "", "bounty": 0.0, "outcome": "",
                    "h1_state": "", "h1_synced_at": "", "submitted_at": "",
                }
            else:
                rec["last_seen"] = _now()
                rec["proof_status"] = proof
                # Refresh the persisted proof whenever this pass carried richer captured evidence (e.g.
                # a later Prove/confirm), so the durable record keeps the best proof we've captured.
                if captured and (proof == "confirmed" or not rec.get("captured_proof")):
                    rec["captured_proof"] = captured
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


# HackerOne report states that will never change again — once a record is synced to one
# of these, a later sync pass skips it (never re-polls a closed report).
_H1_TERMINAL_STATES = {"resolved", "not-applicable", "informative", "duplicate", "spam"}


def record_h1_sync(runtime_dir: str | Path, pid: str, key: str, *, state: str, resolved_with_reward: bool,
                   bounty: float = 0.0) -> None:
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
        # Record the REAL reward amount (not just the paid stage) so bounty_total / the learned
        # 'paid' EV boost reflect actual money. Only ever raise it — a later poll never zeroes a
        # recorded bounty. Empty/absent amount leaves the existing value untouched.
        try:
            amount = float(bounty or 0.0)
        except (TypeError, ValueError):
            amount = 0.0
        if amount > float(rec.get("bounty") or 0.0):
            rec["bounty"] = amount
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


def mark_report_ready(runtime_dir: str | Path, program: str | None, target: str, key: str, *,
                      report_index: dict[str, Any] | None = None,
                      proof_flags: dict[str, Any] | None = None) -> bool:
    """Flag a finding's report as ASSEMBLED — "ready to review/submit" in the Report Center.
    Records ``report_ready``/``report_ready_at``, which of POC/POI/POE the assembled report
    actually carries (``report_ready_proof``), and a small artifact index (platform/filename/
    proof_status). Deliberately ORTHOGONAL to the pipeline ``stage`` (never advances/regresses it)
    so "ready" is independent of report/submit state and can't perturb the funnel or the
    anti-duplicate gate. Locates the record in the given program bucket, else searches the whole
    portfolio (a history finding's bucket id may differ from ``program_key(program, target)``).
    No-op returning False when the key isn't recorded (the caller upserts the finding first)."""
    pid = program_key(program, target)
    with _LOCK:
        data = _load(runtime_dir)
        # Non-mutating lookup (don't use _prog_bucket — it would create an empty bucket for a wrong pid).
        rec = data.get("programs", {}).get(pid, {}).get("findings", {}).get(key)
        if rec is None:
            for bucket in data.get("programs", {}).values():
                cand = (bucket.get("findings") or {}).get(key)
                if cand is not None:
                    rec = cand
                    break
        if rec is None:
            return False
        rec["report_ready"] = True
        rec["report_ready_at"] = _now()
        rec["report_ready_proof"] = {k: bool((proof_flags or {}).get(k)) for k in ("poc", "poi", "poe")}
        rec["report_index"] = report_index if isinstance(report_index, dict) else {}
        rec["updated_at"] = _now()
        _save(runtime_dir, data)
    return True


# --- Deletion / suppression -------------------------------------------------------
# A finding the operator DELETES is recorded here by its stable dedup key. Every future
# hunt/campaign filters these out, and the durable history + funnel + CSV export hide
# them — so a deleted finding is never surfaced again (the same class+rule+normalized-
# location match, so the delete sticks across runs, targets, and programs). Fully
# reversible via ``restore`` (the record's money/stage data is preserved, just hidden).


def dismissed_keys(runtime_dir: str | Path) -> set[str]:
    """The set of deleted (suppressed) dedup keys — what the engine filters out."""
    return set((_load(runtime_dir).get("dismissed") or {}))


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


def archive_and_purge_program(runtime_dir: str | Path, program_id: str,
                              also_bucket_ids: "list[str] | tuple[str, ...]" = ()) -> dict[str, int]:
    """Cascade a PROGRAM deletion to its findings: the program's whole ledger bucket is removed,
    but its HIGH/CRITICAL findings are MOVED into the archive ("history subcategory") first —
    kept read-only so a serious finding is never silently lost when a program is deleted. Lower-
    severity findings are purged with the bucket. Returns {'archived': n, 'purged': m}.

    ``also_bucket_ids`` covers the program's findings that were written under a DIFFERENT bucket
    key than its id: a cockpit/ad-hoc run with ``program=None`` keys its bucket by the target's
    registrable domain (e.g. ``acme.com``), so deleting the saved program ``acme`` must also sweep
    those domain buckets or its HIGH/CRITICAL findings would orphan and keep being counted for a
    program that no longer exists. The caller derives the domain keys from the program's scope."""
    pids = [program_key(program_id)] + [program_key(b) for b in also_bucket_ids if str(b or "").strip()]
    seen: set[str] = set()
    with _LOCK:
        data = _load(runtime_dir)
        dismissed = data.get("dismissed") or {}
        archive = data.setdefault("archived", {})
        n_arch = n_purge = 0
        changed = False
        for pid in pids:
            if pid in seen:
                continue
            seen.add(pid)
            bucket = (data.get("programs") or {}).get(pid)
            if not bucket:
                continue
            for key, rec in (bucket.get("findings") or {}).items():
                severity = str(rec.get("severity") or "").strip().lower()
                keep = severity in ("high", "critical") and key not in dismissed and not rec.get("dismissed")
                if keep:
                    # Key the archive by a per-record composite (pid:dedup_key), NOT the bare
                    # dedup_key: the SAME finding can live under both the saved-program bucket and a
                    # program=None domain bucket (both swept here), and two different programs can
                    # share a class/rule/location. A bare-key archive[key]= would let the second
                    # bucket's (possibly stale/bounty-less) record silently overwrite the richer one.
                    archive[f"{pid}:{key}"] = {**rec, "program": pid, "archived_from": pid, "archived_at": _now()}
                    n_arch += 1
                else:
                    n_purge += 1
            data.get("programs", {}).pop(pid, None)  # remove the bucket; kept ones now live in `archived`
            changed = True
        if changed:
            _save(runtime_dir, data)
    return {"archived": n_arch, "purged": n_purge}


def list_archived(runtime_dir: str | Path, limit: int | None = None) -> list[dict[str, Any]]:
    """The "history subcategory": HIGH/CRITICAL findings preserved from DELETED programs. Kept
    out of the live history/funnel/CSV (their program is gone) but surfaced here so the operator
    can still see — and report — a serious finding from a program they removed."""
    store = _load(runtime_dir)
    archive = store.get("archived") or {}
    dismissed = store.get("dismissed") or {}
    # The archive dict key is now a pid:dedup_key composite (see archive_and_purge_program), so
    # recover the bare dedup_key from the stored record (falling back to the dict key for any
    # legacy bare-keyed entry) for both the dismissed filter and the returned dedup_key.
    out = []
    for akey, rec in archive.items():
        dk = str(rec.get("dedup_key") or akey)
        if dk in dismissed:
            continue
        out.append({**rec, "dedup_key": dk})
    out.sort(key=lambda r: str(r.get("archived_at") or r.get("updated_at") or ""), reverse=True)
    return out[: max(1, limit or _MAX_LIST_ALL)]


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
        ready = 0
        for pid in pids:
            for key, rec in (data.get(pid, {}).get("findings", {}) or {}).items():
                if key in dismissed or rec.get("dismissed"):
                    continue  # deleted findings are out of the pipeline entirely
                total += 1
                stage = rec.get("stage", "discovered")
                if stage in counts:
                    counts[stage] += 1
                if rec.get("report_ready"):
                    ready += 1  # orthogonal to stage: how many have an assembled report in the Report Center
                bounty += _safe_float(rec.get("bounty"), 0.0)  # tolerate a hand-edited/corrupt bounty rather than 500 the whole funnel
        return {"total": total, "stages": counts, "bounty_total": round(bounty, 2), "ready": ready}

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
    mainstream spreadsheet app -- the standard CSV-formula-injection mitigation. Test the
    LEFT-STRIPPED text against the triggers: Google Sheets and some Excel import paths trim
    leading whitespace/tabs before evaluating, so ' =WEBSERVICE(...)' would otherwise slip past
    a first-character-only check and run as a formula."""
    text = value if isinstance(value, str) else str(value if value is not None else "")
    return "'" + text if text.lstrip().startswith(_CSV_FORMULA_TRIGGERS) else value


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
            out.append({**rec, "program": pid, "dedup_key": key, "readyable": _readyable(rec)})
    out.sort(key=lambda r: str(r.get("updated_at") or r.get("last_seen") or ""), reverse=True)
    return out[: max(1, limit)]


def _readyable(rec: dict[str, Any]) -> bool:
    """Whether a "Get report ready" action can produce a meaningful report for this record: it
    carries captured proof (POE/POI) or its server-truth proof_status is at least a candidate.
    (A bare 'missing' record with no captured evidence can still be reported, but there's nothing
    to assemble beyond the deterministic steps — the UI de-emphasizes it.)"""
    cap = rec.get("captured_proof") if isinstance(rec.get("captured_proof"), dict) else {}
    return bool(cap.get("proof_evidence") or cap.get("proof_of_impact") or cap.get("credential_proof")) \
        or str(rec.get("proof_status") or "").lower() in ("candidate", "confirmed")


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
