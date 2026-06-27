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
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

_STORE_NAME = "bughunter_learning.json"

# Outcome a submitted finding can have. Weighted toward "did this earn / matter?".
OUTCOMES = ("submitted", "triaged", "accepted", "resolved", "duplicate", "informative", "not-applicable", "spam")
_REWARDING = {"accepted", "resolved"}          # the program valued it
_NOISE = {"duplicate", "informative", "not-applicable", "spam"}  # don't keep filing these


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
    labels = host.strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else (host or "default")


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
    now: str | None = None,
) -> dict[str, Any]:
    """Record one finding outcome. Returns the updated program stats."""
    status = str(status or "").strip().lower()
    if status not in OUTCOMES:
        raise ValueError(f"unknown status '{status}'. Use one of: {', '.join(OUTCOMES)}.")
    key = program_key(program, target)
    cls = str(class_id or "other").strip().lower() or "other"
    data = _load(runtime_dir)
    programs = data.setdefault("programs", {})
    prog = programs.setdefault(key, _blank_program())
    stamp = now or datetime.now(UTC).isoformat()
    prog["findings"].append({
        "class_id": cls, "title": str(title)[:200], "status": status,
        "bounty": float(bounty or 0.0), "severity": str(severity or "").lower(), "notes": str(notes)[:500], "at": stamp,
    })
    stats = prog["class_stats"].setdefault(cls, {"submitted": 0, "rewarded": 0, "noise": 0, "bounty_total": 0.0})
    stats["submitted"] += 1
    if status in _REWARDING:
        stats["rewarded"] += 1
    if status in _NOISE:
        stats["noise"] += 1
    stats["bounty_total"] = round(stats["bounty_total"] + float(bounty or 0.0), 2)
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
        submitted = max(1, int(stats.get("submitted", 0)))
        rewarded = int(stats.get("rewarded", 0))
        noise = int(stats.get("noise", 0))
        paid = float(stats.get("bounty_total", 0.0)) > 0
        # Reward-rate centered at 0 (no info) -> map to a bounded multiplier.
        score = (rewarded - noise) / submitted
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
    total_submitted = sum(int(s.get("submitted", 0)) for s in stats.values())
    total_rewarded = sum(int(s.get("rewarded", 0)) for s in stats.values())
    total_bounty = round(sum(float(s.get("bounty_total", 0.0)) for s in stats.values()), 2)
    top = sorted(stats.items(), key=lambda kv: (-float(kv[1].get("bounty_total", 0.0)), -int(kv[1].get("rewarded", 0))))
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
    for cls, stats in sorted((prog["class_stats"]).items(), key=lambda kv: -float(kv[1].get("bounty_total", 0.0))):
        sub, rew, noise = int(stats.get("submitted", 0)), int(stats.get("rewarded", 0)), int(stats.get("noise", 0))
        bounty = float(stats.get("bounty_total", 0.0))
        if rew and bounty:
            notes.append(f"`{cls}` has paid out (${bounty:.0f} across {rew}/{sub}) — prioritize it here.")
        elif noise >= 2 and noise >= sub - 1:
            notes.append(f"`{cls}` was {noise}/{sub} duplicate/N-A for this program — deprioritize unless impact is clear.")
    return notes[:6]
