"""GreyIQ Workbench — edit trace log (the offline-coder distillation corpus).

The coding sibling of ``bughunter/hunt_trace.py``. Every SUCCESSFUL, verify-passing agent run driven by
a real brain (Claude/Ollama) is recorded as one append-only JSONL line: the request intent, the
provider, the skills selected, and the STRUCTURAL SHAPE of the diff (which files, what operation, size
deltas — never the content). It is the corpus a later mining step clusters to promote recurring
(intent -> diff-shape) patterns into ``seed/snippets/`` templates + ``skills`` playbooks, so the
DETERMINISTIC offline coder (``offline_coder.py``) can replay — offline, at low compute — an edit
pattern a strong brain performed online. This is the coding analog of the hunt-trace distillation.

Design (identical discipline to ``hunt_trace``):
  * APPEND-ONLY JSONL, one run = one line. Never rewritten.
  * STRUCTURE ONLY — file paths + operation + size deltas, the request intent, provider/model, skills.
    NEVER file content or a diff body (the promotion step generalizes shapes, not code); the intent
    string and paths run through ``redact_text`` so a secret pasted into a prompt can't land here.
  * Local-only / privacy-preserving: same runtime dir as the ledger / hunt_trace. Nothing leaves the
    machine. Only real-brain runs are logged (offline runs ARE the templates — logging them is circular).
  * Best-effort + fail-closed: a trace write can never break or slow an agent run.

Pure / dependency-free / frozen-safe: stdlib + intra-repo imports only. Appends are serialized behind a
process lock; the reader skips a torn final line, so a crash mid-append can't poison the corpus.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bughunter.code_scanner.redaction import redact_text

_STORE_NAME = "edit_traces.jsonl"
_LOCK = threading.Lock()
_SCHEMA_VERSION = 1

_MAX_INTENT = 500
_MAX_FILES = 100
_MAX_SKILLS = 12
# Only a real brain's runs are worth distilling; an offline run IS the template already.
_LEARNABLE_PROVIDERS = frozenset({"anthropic", "local", "openai"})


def _store_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / _STORE_NAME


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _redact(text: Any, cap: int) -> str:
    """Redact secrets from a free-form string (intent/path) and cap it. Fail-open to the raw (capped)
    string — redaction must never break a trace write."""
    raw = str(text or "").strip()
    if not raw:
        return ""
    try:
        return redact_text(raw)[0][:cap]
    except Exception:  # noqa: BLE001
        return raw[:cap]


def _workspace_id(workspace: str | Path | None) -> dict[str, str]:
    """A privacy-preserving handle for a workspace: its folder name + a short hash of the resolved
    path (so runs group per project without storing the full local path)."""
    try:
        p = Path(str(workspace or "")).expanduser()
        name = p.name or "workspace"
        key = hashlib.sha1(str(p.resolve()).encode("utf-8", "replace")).hexdigest()[:12]
    except (OSError, RuntimeError, ValueError):
        name, key = "workspace", ""
    return {"name": name[:120], "id": key}


def _diff_shapes(changes: Any) -> list[dict[str, Any]]:
    """STRUCTURAL summary of the run's file changes — path + operation + size deltas, NO content."""
    out: list[dict[str, Any]] = []
    for c in changes if isinstance(changes, (list, tuple)) else []:
        if not isinstance(c, dict):
            continue
        out.append({
            "path": _redact(c.get("path"), 300),
            "operation": str(c.get("operation") or "")[:20],
            "existed": bool(c.get("existed")),
            "before_size": int(c.get("before_size") or 0),
            "after_size": int(c.get("after_size") or 0),
        })
        if len(out) >= _MAX_FILES:
            break
    return out


def record_trace(
    runtime_dir: str | Path | None,
    *,
    message: str,
    provider: str,
    model: str = "",
    workspace: str | Path | None = None,
    changes: Any = None,
    touched_files: Any = None,
    verified: bool = False,
    steps: int = 0,
    skills: Any = None,
    now: str | None = None,
) -> bool:
    """Append ONE edit trace for a SUCCESSFUL real-brain agent run. Returns True if written.

    Recorded only when: runtime_dir is set, the provider is a real brain (not the offline coder), the
    run VERIFIED, and it actually touched files. Structure only, secret-redacted, fail-closed."""
    if runtime_dir is None:
        return False
    if str(provider or "").strip().lower() not in _LEARNABLE_PROVIDERS:
        return False
    if not verified:
        return False
    try:
        shapes = _diff_shapes(changes)
        touched = [_redact(f, 300) for f in (touched_files or [])][:_MAX_FILES] if isinstance(touched_files, (list, tuple)) else []
        if not shapes and not touched:
            return False  # nothing to learn from
        record = {
            "v": _SCHEMA_VERSION,
            "ts": now or _now(),
            "intent": _redact(message, _MAX_INTENT),
            "provider": str(provider or "").strip().lower()[:20],
            "model": str(model or "")[:120],
            "workspace": _workspace_id(workspace),
            "skills": [str(s)[:80] for s in (skills or [])][:_MAX_SKILLS] if isinstance(skills, (list, tuple)) else [],
            "files": shapes,
            "touched": touched,
            "verified": bool(verified),
            "steps": int(steps or 0),
        }
        line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
        path = _store_path(runtime_dir)
        with _LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            prefix = ""
            try:
                if path.exists() and path.stat().st_size:
                    with path.open("rb") as probe:
                        probe.seek(-1, 2)
                        if probe.read(1) != b"\n":
                            prefix = "\n"  # terminate a torn prior line so this record stays parseable
            except OSError:
                prefix = ""
            with path.open("a", encoding="utf-8") as handle:
                handle.write(prefix + line)
        return True
    except Exception:  # noqa: BLE001 - a trace write must never break an agent run
        return False


def load_traces(runtime_dir: str | Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Read the edit traces in chronological order, skipping any torn/corrupt line. ``limit`` returns
    the most RECENT N."""
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
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
    except OSError:
        return []
    if limit is None:
        return out
    return out[-limit:] if limit > 0 else []


def trace_stats(runtime_dir: str | Path) -> dict[str, Any]:
    """Quick corpus summary for a CLI/UI readout: real-brain runs logged, distinct projects, and the
    most common file-operation shapes (the raw material for promoting templates)."""
    traces = load_traces(runtime_dir)
    projects: set[str] = set()
    ops: dict[str, int] = {}
    for t in traces:
        ws = t.get("workspace") or {}
        projects.add(str(ws.get("id") or ws.get("name") or ""))
        for f in t.get("files") or []:
            if isinstance(f, dict):
                op = str(f.get("operation") or "")
                ops[op] = ops.get(op, 0) + 1
    return {
        "runs": len(traces),
        "projects": len(projects),
        "operations": dict(sorted(ops.items(), key=lambda kv: -kv[1])),
    }
