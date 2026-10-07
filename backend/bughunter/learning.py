"""GreyIQ BugHunter — learn from the bounty.

A local, deterministic feedback loop: after a hunt the operator submits findings
and the program returns an outcome (accepted / duplicate / informative / N-A /
resolved, plus any bounty). Recording those outcomes here builds a per-program,
per-vuln-class memory that sharpens the NEXT hunt:

  * classes that have paid out for a program get a priority boost,
  * classes that are consistently duplicate / not-applicable get a penalty,
  * the report surfaces this "program intelligence" so the operator focuses where
    the program actually rewards.

Pure / dependency-free / frozen-safe: a single JSON file under the runtime dir,
written atomically. No network, no ML — just bookkeeping the engine reads back.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from bughunter.registrable_domain import registrable_domain

_STORE_NAME = "bughunter_learning.json"
_LOCK = threading.Lock()  # serialize read-modify-write (os.replace is atomic but not RMW-safe) -- mirrors ledger.py/portfolio.py

# Outcome a submitted finding can have. Weighted toward "did this earn / matter?".
OUTCOMES = ("submitted", "triaged", "accepted", "resolved", "duplicate", "informative", "not-applicable", "spam")
_REWARDING = {"accepted", "resolved"}          # the program valued it
_NOISE = {"duplicate", "informative", "not-applicable", "spam"}  # don't keep filing these
_ADJUDICATED = _REWARDING | _NOISE


def _safe_int(value: Any, default: int = 0) -> int:
    """Tolerant int() for values read back from the persisted learning store: a
    hand-edited or corrupted JSON file (e.g. {'rewarded': 'lots'}) must degrade to the
    default instead of raising and aborting whatever read it (learned_priors feeds
    ranking.rank_by_ev, which is called unguarded mid-campaign)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _store_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / _STORE_NAME


def program_key(program: str | None, target: str | None = None) -> str:
    """A stable key for a program: an explicit handle if given, else the target's
    registrable domain (so all of *.example.com share one memory)."""
    if program and str(program).strip():
        return re.sub(r"[^a-z0-9._-]+", "-", str(program).strip().lower()).strip("-.") or "default"
    host = ""
    raw = str(target or "").strip()
    if raw:
        host = (urlparse(raw if "://" in raw else "http://" + raw).hostname or "").lower()
    return registrable_domain(host) or "default"


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


def _blank_program() -> dict[str, Any]:
    return {"findings": [], "class_stats": {}, "updated_at": None}


def _adjust_stats(prog: dict[str, Any], row: dict[str, Any], direction: int) -> None:
    """Apply one report's current state, preserving legacy aggregate-only stores."""
    cls = str(row.get("class_id") or "other").strip().lower() or "other"
    stats = prog["class_stats"].setdefault(
        cls, {"submitted": 0, "rewarded": 0, "noise": 0, "bounty_total": 0.0})
    status = str(row.get("status") or "").strip().lower()
    stats["submitted"] = max(0, _safe_int(stats.get("submitted")) + direction)
    stats["rewarded"] = max(0, _safe_int(stats.get("rewarded")) + direction * (status in _REWARDING))
    stats["noise"] = max(0, _safe_int(stats.get("noise")) + direction * (status in _NOISE))
    stats["bounty_total"] = round(max(
        0.0, _safe_float(stats.get("bounty_total")) + direction * _safe_float(row.get("bounty"))), 2)


def record_outcome(
    runtime_dir: str | Path,
    *,
    program: str | None,
    target: str = "",
    class_id: str,
    title: str = "",
    status: str,
    bounty: float = 0.0,
    severity: str = "",
    notes: str = "",
    finding_id: str = "",
    now: str | None = None,
) -> dict[str, Any]:
    """Record one report's latest outcome. An optional stable ID makes retries and
    status transitions update that report instead of teaching from it repeatedly.
    Rows without an ID keep the legacy append-only behavior."""
    status = str(status or "").strip().lower()
    if status not in OUTCOMES:
        raise ValueError(f"unknown status '{status}'. Use one of: {', '.join(OUTCOMES)}.")
    amount = float(bounty or 0.0)
    if not math.isfinite(amount) or amount < 0:
        raise ValueError("bounty must be a finite, non-negative amount")
    amount = round(amount, 2)
    key = program_key(program, target)
    cls = str(class_id or "other").strip().lower() or "other"
    identity = str(finding_id or "").strip()
    if len(identity) > 200:
        raise ValueError("finding_id must be at most 200 characters")
    stamp = now or datetime.now(UTC).isoformat()
    with _LOCK:
        data = _load(runtime_dir)
        programs = data.setdefault("programs", {})
        prog = programs.setdefault(key, _blank_program())
        findings = prog.setdefault("findings", [])
        previous = next((row for row in findings if identity and isinstance(row, dict)
                         and row.get("finding_id") == identity), None)
        # An automatic re-scan can log "submitted" after HackerOne already gave a
        # terminal verdict. It must not erase the adjudicated signal.
        if previous and str(previous.get("status") or "").lower() in _ADJUDICATED and status not in _ADJUDICATED:
            return prog
        row = {
            "class_id": cls, "title": str(title)[:200], "status": status,
            "bounty": amount, "severity": str(severity or "").lower(), "notes": str(notes)[:500], "at": stamp,
        }
        if identity:
            row["finding_id"] = identity
        if previous:
            # Keep useful metadata when an automated sync only knows the new state.
            for field in ("title", "severity", "notes"):
                if not row[field]:
                    row[field] = previous.get(field, "")
            if all(previous.get(field) == row.get(field) for field in
                   ("class_id", "title", "status", "bounty", "severity", "notes", "finding_id")):
                return prog
            _adjust_stats(prog, previous, -1)
            previous.update(row)
        else:
            findings.append(row)
        _adjust_stats(prog, row, 1)
        prog["updated_at"] = stamp
        data["updated_at"] = stamp
        _save(runtime_dir, data)
        return prog


def learned_priors(runtime_dir: str | Path, program: str | None, target: str = "") -> dict[str, float]:
    """Per-class priority multipliers in roughly [0.5, 2.0] derived from outcomes.
    >1 = this program rewards the class (focus); <1 = mostly noise (deprioritize).
    Classes with no history are absent (treated as 1.0 by callers)."""
    prog = _load(runtime_dir).get("programs", {}).get(program_key(program, target))
    if not prog:
        return {}
    priors: dict[str, float] = {}
    for cls, stats in (prog.get("class_stats") or {}).items():
        rewarded = _safe_int(stats.get("rewarded", 0))
        noise = _safe_int(stats.get("noise", 0))
        # Drive the reward-rate off ADJUDICATED outcomes only (rewarded + noise),
        # never the raw "submitted" count. Otherwise a weekly re-scan that auto-logs
        # the same confirmed finding as "submitted" would keep diluting an already
        # earned prior toward neutral. A class with only un-adjudicated submissions
        # carries no signal yet, so it stays absent (callers treat absent as 1.0).
        adjudicated = rewarded + noise
        if adjudicated == 0:
            continue
        paid = _safe_float(stats.get("bounty_total", 0.0)) > 0
        # Reward-rate centered at 0 (no info) -> map to a bounded multiplier.
        score = (rewarded - noise) / adjudicated
        weight = 1.0 + 0.8 * score + (0.2 if paid else 0.0)
        priors[cls] = round(max(0.5, min(2.0, weight)), 3)
    return priors


def program_summary(runtime_dir: str | Path, program: str | None = None, target: str = "") -> dict[str, Any]:
    """Stats for `gn stats` — one program (when named/targeted) or all programs."""
    data = _load(runtime_dir)
    programs = data.get("programs", {})
    if program or target:
        key = program_key(program, target)
        return {"program": key, **_summarize(programs.get(key) or _blank_program())}
    return {
        "programs": {key: _summarize(prog) for key, prog in programs.items()},
        "updated_at": data.get("updated_at"),
    }


def _summarize(prog: dict[str, Any]) -> dict[str, Any]:
    stats = prog.get("class_stats") or {}
    total_submitted = sum(_safe_int(s.get("submitted", 0)) for s in stats.values())
    total_rewarded = sum(_safe_int(s.get("rewarded", 0)) for s in stats.values())
    total_bounty = round(sum(_safe_float(s.get("bounty_total", 0.0)) for s in stats.values()), 2)
    top = sorted(stats.items(), key=lambda kv: (-_safe_float(kv[1].get("bounty_total", 0.0)), -_safe_int(kv[1].get("rewarded", 0))))
    return {
        "submitted": total_submitted, "rewarded": total_rewarded, "bounty_total": total_bounty,
        "class_stats": dict(top), "findings": len(prog.get("findings") or []), "updated_at": prog.get("updated_at"),
    }


def program_intelligence(runtime_dir: str | Path, program: str | None, target: str = "") -> list[str]:
    """Human-readable 'what this program rewards' notes for the report (or [])."""
    prog = _load(runtime_dir).get("programs", {}).get(program_key(program, target))
    if not prog or not prog.get("class_stats"):
        return []
    notes: list[str] = []
    for cls, stats in sorted((prog["class_stats"]).items(), key=lambda kv: -_safe_float(kv[1].get("bounty_total", 0.0))):
        sub, rew, noise = _safe_int(stats.get("submitted", 0)), _safe_int(stats.get("rewarded", 0)), _safe_int(stats.get("noise", 0))
        bounty = _safe_float(stats.get("bounty_total", 0.0))
        if rew and bounty:
            notes.append(f"`{cls}` has paid out (${bounty:.0f} across {rew}/{sub}) — prioritize it here.")
        elif noise >= 2 and noise >= sub - 1:
            notes.append(f"`{cls}` was {noise}/{sub} duplicate/N-A for this program — deprioritize unless impact is clear.")
    return notes[:6]
