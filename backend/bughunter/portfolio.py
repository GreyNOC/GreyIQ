"""GreyIQ BugHunter — program portfolio (the operator's target list).

A small, atomically-written JSON store of the bug-bounty PROGRAMS the autonomous
operator works: each carries its scope (fed verbatim to the same fail-closed
``host_in_active_scope`` gate the active prover uses), its cadence, and its
fail-closed automation flags (active/live/auto_submit all default to the SAFE value).

Pure / dependency-free / frozen-safe: one JSON file under the runtime dir, written
atomically, mutations serialized behind a process lock. No network. Storing a
program sends zero packets — the data model alone can never probe or submit; the
operator engine reads these flags and is the only thing that acts on them.

SCOPE POSTURE (fail-closed): a host is NEVER auto-added to in-scope. ``scope_text``
is the single source of truth handed to the scanner; ``out_of_scope_hosts`` is only
ever an EXCLUSION filter, never an expansion. A program with empty scope cannot be
marked active (an empty scope makes the active gate no-op silently).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from bughunter.learning import program_key

_STORE_NAME = "portfolio.json"
_LOCK = threading.Lock()  # serialize read-modify-write (os.replace is atomic but not RMW-safe)

# Field defaults — every automation flag defaults to the SAFE/off value.
_DEFAULTS: dict[str, Any] = {
    "name": "",
    "platform": "manual",          # 'hackerone' | 'manual'
    "platform_handle": "",         # HackerOne team handle (for auto-submit)
    "scope_text": "",              # free-text, passed verbatim to run_campaign(scope=)
    "in_scope_hosts": [],
    "out_of_scope_hosts": [],
    "seed_targets": [],            # URLs/hosts to hunt (each within scope)
    "active": False,               # capture proof-of-impact (active verification)
    "live": False,                 # dynamic Playwright pass
    "deep": False,                 # aggressive: time-based SQLi + auto screenshot + research per confirmed lead
    "auto_submit": False,          # FILE confirmed findings automatically — DANGER, default off
    "max_pages": 12,
    "interval_minutes": 1440,      # how often the operator re-runs this program
    "max_submits_per_day": 3,      # hard throttle on auto-submission
    "enabled": True,               # the operator schedules it
    "created_at": None,
    "last_run_at": None,
    "next_run_at": None,
}


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


def _normalize(record: dict[str, Any]) -> dict[str, Any]:
    out = {**_DEFAULTS, **{k: v for k, v in record.items() if k in _DEFAULTS or k == "id"}}
    # Fail-closed coupling: active/live/deep/auto_submit require a non-empty scope.
    if not str(out.get("scope_text") or "").strip():
        out["active"] = False
        out["live"] = False
        out["deep"] = False
        out["auto_submit"] = False
    # Deep implies proof-of-impact (it adds time-based SQLi + screenshot/research per
    # confirmed lead), so a deep program is always active.
    if out.get("deep"):
        out["active"] = True
    # Auto-submit additionally requires a platform handle to even attempt a file.
    if out["auto_submit"] and not (out["platform"] == "hackerone" and str(out.get("platform_handle") or "").strip()):
        out["auto_submit"] = False
    out["max_pages"] = max(1, min(int(out.get("max_pages") or 12), 50))
    out["interval_minutes"] = max(5, int(out.get("interval_minutes") or 1440))
    out["max_submits_per_day"] = max(0, min(int(out.get("max_submits_per_day") or 3), 25))
    out["in_scope_hosts"] = [str(h).strip() for h in (out.get("in_scope_hosts") or []) if str(h).strip()]
    out["out_of_scope_hosts"] = [str(h).strip() for h in (out.get("out_of_scope_hosts") or []) if str(h).strip()]
    out["seed_targets"] = [str(t).strip() for t in (out.get("seed_targets") or []) if str(t).strip()]
    return out


def list_programs(runtime_dir: str | Path) -> list[dict[str, Any]]:
    progs = _load(runtime_dir).get("programs", {})
    return [progs[k] for k in sorted(progs)]


def get_program(runtime_dir: str | Path, program_id: str) -> dict[str, Any] | None:
    return _load(runtime_dir).get("programs", {}).get(str(program_id))


def upsert_program(runtime_dir: str | Path, record: dict[str, Any]) -> dict[str, Any]:
    """Create or update a program. The id is derived from the program name/handle via
    the shared program_key, so the portfolio, ledger, and learning store all key on
    the SAME id (one program = one memory)."""
    name = str(record.get("name") or "").strip()
    handle = str(record.get("platform_handle") or "").strip()
    seed = str((record.get("seed_targets") or [""])[0] if record.get("seed_targets") else "")
    pid = str(record.get("id") or "").strip() or program_key(name or handle, record.get("scope_text") or seed)
    with _LOCK:
        data = _load(runtime_dir)
        programs = data.setdefault("programs", {})
        existing = programs.get(pid, {})
        merged = _normalize({**existing, **record, "id": pid})
        merged["name"] = name or existing.get("name") or pid
        merged["created_at"] = existing.get("created_at") or _now()
        programs[pid] = merged
        _save(runtime_dir, data)
        return merged


def remove_program(runtime_dir: str | Path, program_id: str) -> bool:
    with _LOCK:
        data = _load(runtime_dir)
        if str(program_id) in data.get("programs", {}):
            del data["programs"][str(program_id)]
            _save(runtime_dir, data)
            return True
    return False


def set_enabled(runtime_dir: str | Path, program_id: str, enabled: bool) -> dict[str, Any] | None:
    with _LOCK:
        data = _load(runtime_dir)
        prog = data.get("programs", {}).get(str(program_id))
        if not prog:
            return None
        prog["enabled"] = bool(enabled)
        _save(runtime_dir, data)
        return prog


def touch_run(runtime_dir: str | Path, program_id: str, *, next_run_at: str | None) -> None:
    """Stamp last_run_at=now and the scheduled next_run_at after a cycle completes."""
    with _LOCK:
        data = _load(runtime_dir)
        prog = data.get("programs", {}).get(str(program_id))
        if not prog:
            return
        prog["last_run_at"] = _now()
        prog["next_run_at"] = next_run_at
        _save(runtime_dir, data)
