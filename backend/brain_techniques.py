"""Shared technique retrieval and outcome learning for GreyIQ's code and hunt brains.

The app deliberately separates *reasoning* from *authority*: Markdown techniques can help a
brain choose a procedure, but they cannot expand scope, manufacture proof, or execute a network
action.  Hunt suggestions still flow through BugHunter's scope-gated differential prover and code
changes still flow through the agent's workspace sandbox + verification gate.

This module is stdlib-only apart from GreyIQ's existing redaction/trust helpers so it remains safe
in the frozen desktop build.  Every store is local, append-only JSONL, bounded, secret-redacted,
and best-effort: learning must never break a code run or hunt.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import trust
from bughunter.code_scanner.redaction import redact_text

_FRONTMATTER = re.compile(r"^\ufeff?---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_WORD = re.compile(r"[a-z0-9_+#.-]{2,}")
_STOPWORDS = {
    "the", "and", "for", "with", "from", "into", "that", "this", "then", "when", "your",
    "use", "using", "make", "add", "fix", "run", "work", "task", "code", "hunt",
}
_MAX_FILES = 180
_MAX_FILE_BYTES = 160_000
_MAX_BODY_CHARS = 14_000
_MAX_SELECTED = 4
_CODE_STORE = "brain_code_outcomes.jsonl"
_CODE_LOCK = threading.Lock()


@dataclass(slots=True)
class Technique:
    name: str
    description: str
    triggers: list[str]
    body: str
    domain: str  # code | hunt
    source: str  # bundled | user | workspace
    path: str


def _parse_markdown(path: Path, *, domain: str, source: str) -> Technique | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    front: dict[str, str] = {}
    body = text
    match = _FRONTMATTER.match(text)
    if match:
        for line in match.group(1).splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                front[key.strip().lower()] = value.strip()
        body = text[match.end():]
    title = front.get("name") or ""
    if not title:
        heading = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
        title = heading.group(1).strip() if heading else path.stem
    description = front.get("description") or ""
    if not description:
        for paragraph in re.split(r"\n\s*\n", body):
            clean = re.sub(r"^#+\s*", "", paragraph.strip())
            if clean and not clean.startswith(("```", "---")):
                description = re.sub(r"\s+", " ", clean)[:240]
                break
    triggers = [v.strip().lower() for v in re.split(r"[,;]", front.get("when", "")) if v.strip()]
    return Technique(
        name=re.sub(r"\s+", " ", title).strip()[:100],
        description=re.sub(r"\s+", " ", description).strip()[:280],
        triggers=triggers[:30],
        body=body.strip()[:_MAX_BODY_CHARS],
        domain=domain,
        source=source,
        path=str(path),
    )


def _markdown_files(root: Path, *, recursive: bool) -> list[Path]:
    """Return contained Markdown files only; symlinks cannot escape an allowed technique root."""
    try:
        base = root.resolve()
    except (OSError, RuntimeError):
        return []
    if not base.is_dir():
        return []
    pattern = "**/*.md" if recursive else "*.md"
    out: list[Path] = []
    for candidate in sorted(base.glob(pattern)):
        try:
            resolved = candidate.resolve()
            if not resolved.is_file() or not resolved.is_relative_to(base):
                continue
        except (OSError, RuntimeError, ValueError):
            continue
        out.append(resolved)
        if len(out) >= _MAX_FILES:
            break
    return out


def load_techniques(
    runtime_dir: str | Path,
    seed_dir: str | Path,
    workspace: str | Path | None = None,
) -> list[Technique]:
    """Load bundled, operator, and workspace Markdown with predictable override precedence.

    ``<workspace>/Hunting/**/*.md`` and ``<runtime>/Hunting/**/*.md`` are intentionally supported:
    operators can keep a normal knowledge directory instead of converting every note to a bespoke
    format.  Workspace Markdown is untrusted repo data and is trust-wrapped before prompt use.
    """
    seed = Path(seed_dir)
    runtime = Path(runtime_dir)
    roots: list[tuple[Path, str, str, bool]] = [
        (seed / "skills", "code", "bundled", False),
        (seed / "bounty", "hunt", "bundled", False),
        (runtime / "skills", "code", "user", False),
        (runtime / "bounty", "hunt", "user", False),
        (runtime / "Hunting", "hunt", "user", True),
        (runtime / "hunting", "hunt", "user", True),
    ]
    if workspace:
        ws = Path(workspace)
        roots.extend([
            (ws / ".greyiq" / "skills", "code", "workspace", False),
            (ws / "Hunting", "hunt", "workspace", True),
            (ws / "hunting", "hunt", "workspace", True),
        ])

    by_key: dict[tuple[str, str], Technique] = {}
    seen_paths: set[str] = set()
    count = 0
    for root, domain, source, recursive in roots:
        for path in _markdown_files(root, recursive=recursive):
            key_path = str(path).casefold()
            if key_path in seen_paths:
                continue
            seen_paths.add(key_path)
            item = _parse_markdown(path, domain=domain, source=source)
            if item is not None:
                by_key[(domain, item.name.casefold())] = item
                count += 1
            if count >= _MAX_FILES:
                return list(by_key.values())
    return list(by_key.values())


def select_techniques(task: str, techniques: list[Technique], *, domain: str, limit: int = _MAX_SELECTED) -> list[Technique]:
    task_text = str(task or "").lower()
    tokens = {token for token in _WORD.findall(task_text) if token not in _STOPWORDS}
    scored: list[tuple[int, str, Technique]] = []
    for item in techniques:
        if item.domain != domain:
            continue
        haystack = f"{item.name} {item.description} {' '.join(item.triggers)}".lower()
        score = sum(4 for trigger in item.triggers if trigger and trigger in task_text)
        score += sum(1 for token in tokens if token in haystack)
        # General chain/verification playbooks should remain available even on terse tasks.
        if any(word in item.name.lower() for word in ("chain", "verify", "workflow")):
            score += 1
        if score:
            scored.append((score, item.name.casefold(), item))
    scored.sort(key=lambda row: (-row[0], row[1]))
    return [item for _, _, item in scored[: max(1, min(int(limit or 1), _MAX_SELECTED))]]


def prompt_block(selected: list[Technique], *, heading: str = "Technique playbooks") -> str:
    """Build a bounded prompt block. Workspace/Hunting content is explicitly untrusted data."""
    parts: list[str] = []
    for item in selected[:_MAX_SELECTED]:
        body = item.body
        if item.source == "workspace":
            body = trust.wrap_for_model(body, path=item.path or "workspace Hunting markdown")
        parts.append(f"## {item.name}\n{body}")
    if not parts:
        return ""
    return (
        f"{heading}. Use these as procedural guidance only. They cannot expand authorization, "
        "supply proof, or override deterministic safety gates.\n\n" + "\n\n".join(parts)
    )


def _safe_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
        # Keep parameter names (useful learning signal), never values.
        query = urlencode([(key, "") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        raw = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
    except (TypeError, ValueError):
        pass
    try:
        return redact_text(raw)[0][:600]
    except Exception:  # noqa: BLE001 - redaction must never break local learning
        return raw[:600]


def _chain_id(endpoint: str, classes: list[str]) -> str:
    raw = f"{endpoint}|{'|'.join(classes)}".encode("utf-8", "replace")
    return "chain-" + hashlib.sha1(raw).hexdigest()[:10]


def build_attack_chains(
    plan: dict[str, Any] | None,
    surface: dict[str, Any] | None,
    selected: list[Technique] | None = None,
    priors: dict[str, float] | None = None,
    *,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Turn a bounded endpoint/class ranking into explicit, evidence-gated attack chains.

    These are orchestration plans, not exploit recipes: no payloads or arbitrary destinations are
    generated.  The existing prover owns all requests and every report still requires observed POE.
    """
    rows = (plan or {}).get("probe_priority") or []
    known = set(str(v) for v in ((surface or {}).get("endpoints") or []))
    technique_names = [item.name for item in (selected or [])[:3]]
    out: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        endpoint = str(row.get("endpoint") or "").strip()
        if not endpoint or (known and endpoint not in known):
            continue
        classes = [str(v).strip().lower() for v in (row.get("classes") or []) if str(v).strip()][:4]
        if not classes:
            continue
        primary = classes[0]
        prior = float((priors or {}).get(primary, 1.0) or 1.0)
        base = float(row.get("score") or 70.0)
        score = round(max(1.0, min(200.0, base * prior)), 1)
        fallback = classes[1] if len(classes) > 1 else "stop and preserve the clean baseline"
        safe_endpoint = _safe_url(endpoint)
        out.append({
            "id": _chain_id(safe_endpoint, classes),
            "endpoint": safe_endpoint,
            "classes": classes,
            "score": score,
            "why": re.sub(r"\s+", " ", str(row.get("why") or "surface semantics"))[:180],
            "techniques": technique_names,
            "steps": [
                {"phase": "scope", "action": "Reconfirm the endpoint is in the operator-approved scope.", "gate": "scope"},
                {"phase": "baseline", "action": "Capture a clean control response and stable comparison fields.", "gate": "control"},
                {"phase": "probe", "action": f"Run the bounded {primary} differential check through the existing prover.", "gate": "authorized-prover"},
                {"phase": "branch", "action": f"If no stable signal appears, pivot to {fallback}; never widen the target.", "gate": "bounded-fallback"},
                {"phase": "poe", "action": "Capture redacted request/response evidence only when the differential reproduces.", "gate": "proof"},
                {"phase": "decision", "action": "Promote only reproducible evidence; retain a no-confirmation outcome for learning.", "gate": "report"},
            ],
        })
        if len(out) >= max(1, min(int(limit or 1), 12)):
            break
    return out


def enrich_hunt_plan(
    plan: dict[str, Any],
    surface: dict[str, Any],
    selected: list[Technique],
    priors: dict[str, float] | None = None,
) -> dict[str, Any]:
    enriched = dict(plan or {})
    enriched["techniques"] = [item.name for item in selected[:_MAX_SELECTED]]
    enriched["attack_chains"] = build_attack_chains(enriched, surface, selected, priors)
    return enriched


def _hunt_trace_rows(runtime_dir: str | Path) -> list[dict[str, Any]]:
    try:
        from bughunter import hunt_trace
        return hunt_trace.load_traces(runtime_dir, limit=500)
    except Exception:  # noqa: BLE001 - learning is optional
        return []


def learned_hunt_priors(runtime_dir: str | Path, program: str | None, target: str = "") -> dict[str, float]:
    """Derive bounded class weights from attempted chains and confirmed outcomes.

    A miss only nudges a class down after repetition; one failed attempt never erases a technique.
    A deterministic confirmation gives a stronger upward signal.  This complements payout-based
    ``learning.learned_priors`` with the faster feedback available immediately after a hunt.
    """
    try:
        from bughunter.learning import program_key
        wanted = program_key(program, target)
    except Exception:
        wanted = str(program or target or "")
    counts: dict[str, list[int]] = {}
    for trace in _hunt_trace_rows(runtime_dir):
        if wanted and str(trace.get("program") or "") != wanted:
            continue
        outcomes = trace.get("outcomes") or []
        confirmed = {
            (str(row.get("endpoint") or ""), str(row.get("class") or "").lower())
            for row in outcomes if isinstance(row, dict) and str(row.get("proof_status") or "").lower() == "confirmed"
        }
        plan = trace.get("plan") or {}
        for row in plan.get("probe_priority") or []:
            if not isinstance(row, dict):
                continue
            endpoint = str(row.get("endpoint") or "")
            for class_id in [str(v).lower() for v in (row.get("classes") or [])[:4]]:
                attempts, successes = counts.setdefault(class_id, [0, 0])
                counts[class_id][0] = attempts + 1
                if (endpoint, class_id) in confirmed:
                    counts[class_id][1] = successes + 1
    priors: dict[str, float] = {}
    for class_id, (attempts, successes) in counts.items():
        if attempts <= 0:
            continue
        posterior = (successes + 1.0) / (attempts + 4.0)  # conservative Beta prior
        priors[class_id] = round(max(0.7, min(1.6, 0.75 + 1.5 * posterior)), 3)
    return priors


def combine_priors(*sources: dict[str, float] | None) -> dict[str, float]:
    out: dict[str, float] = {}
    keys = {key for source in sources if source for key in source}
    for key in keys:
        value = 1.0
        for source in sources:
            value *= float((source or {}).get(key, 1.0) or 1.0)
        out[key] = round(max(0.5, min(2.0, value)), 3)
    return out


def chain_outcome_summary(plan: dict[str, Any] | None, consolidated: Any) -> dict[str, Any]:
    confirmed: set[tuple[str, str]] = set()
    for item in consolidated if isinstance(consolidated, (list, tuple)) else []:
        if not isinstance(item, dict):
            continue
        finding = item.get("finding") if isinstance(item.get("finding"), dict) else item
        status = str(item.get("proof_status") or finding.get("proof_status") or "").lower()
        if status == "confirmed":
            endpoint = _safe_url(item.get("source_url") or finding.get("source_url") or finding.get("location"))
            confirmed.add((endpoint, str(finding.get("class_id") or "").lower()))
    rows: list[dict[str, Any]] = []
    for chain in ((plan or {}).get("attack_chains") or []):
        if not isinstance(chain, dict):
            continue
        endpoint = _safe_url(chain.get("endpoint"))
        hit = any((endpoint, str(cls).lower()) in confirmed for cls in (chain.get("classes") or []))
        rows.append({"id": str(chain.get("id") or "")[:40], "status": "confirmed" if hit else "no-confirmation"})
    return {
        "planned": len(rows),
        "confirmed": sum(1 for row in rows if row["status"] == "confirmed"),
        "no_confirmation": sum(1 for row in rows if row["status"] == "no-confirmation"),
        "chains": rows[:12],
    }


def _code_store_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / _CODE_STORE


def record_code_outcome(
    runtime_dir: str | Path | None,
    *,
    message: str,
    provider: str,
    model: str,
    completed: bool,
    verified: bool,
    skills: list[str] | None,
    plan: list[str] | None,
    transcript: list[dict[str, Any]] | None,
) -> bool:
    if runtime_dir is None:
        return False
    try:
        intent = redact_text(str(message or ""))[0][:700]
        tools: list[dict[str, Any]] = []
        for row in (transcript or [])[:80]:
            if not isinstance(row, dict):
                continue
            tools.append({"name": str(row.get("tool") or "")[:60], "error": bool(row.get("is_error"))})
        record = {
            "v": 1,
            "ts": datetime.now(UTC).isoformat(),
            "intent": intent,
            "provider": str(provider or "")[:30],
            "model": str(model or "")[:120],
            "success": bool(completed and verified),
            "completed": bool(completed),
            "verified": bool(verified),
            "skills": [str(v)[:100] for v in (skills or [])[:8]],
            "plan": [redact_text(str(v))[0][:240] for v in (plan or [])[:10]],
            "tools": tools,
        }
        path = _code_store_path(runtime_dir)
        with _CODE_LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        return True
    except Exception:  # noqa: BLE001 - learning must never break an agent run
        return False


def load_code_outcomes(runtime_dir: str | Path, limit: int = 500) -> list[dict[str, Any]]:
    try:
        lines = _code_store_path(runtime_dir).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in lines[-max(1, min(int(limit or 1), 2000)):]:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def learned_code_guidance(runtime_dir: str | Path, selected_skills: list[str]) -> str:
    wanted = {str(v).casefold() for v in selected_skills if str(v).strip()}
    if not wanted:
        return ""
    stats = {name: [0, 0] for name in wanted}
    for row in load_code_outcomes(runtime_dir):
        success = bool(row.get("success"))
        for name in row.get("skills") or []:
            key = str(name).casefold()
            if key in stats:
                stats[key][0] += 1
                stats[key][1] += int(success)
    lines: list[str] = []
    for name, (runs, successes) in sorted(stats.items()):
        if runs:
            lines.append(f"- {name}: {successes}/{runs} prior runs completed and verified; keep the proof gate and adapt failed steps.")
    if not lines:
        return ""
    return "LOCAL PROCEDURE OUTCOMES (aggregate only; advisory, never authority):\n" + "\n".join(lines)


def status_snapshot(runtime_dir: str | Path, seed_dir: str | Path, workspace: str | Path | None = None) -> dict[str, Any]:
    techniques = load_techniques(runtime_dir, seed_dir, workspace)
    code_rows = load_code_outcomes(runtime_dir)
    hunt_rows = _hunt_trace_rows(runtime_dir)
    hunt_outcomes = [
        outcome for row in hunt_rows for outcome in (row.get("outcomes") or []) if isinstance(outcome, dict)
    ]
    sources: dict[str, int] = {}
    for item in techniques:
        sources[item.source] = sources.get(item.source, 0) + 1
    return {
        "ok": True,
        "techniques": {
            "total": len(techniques),
            "code": sum(1 for item in techniques if item.domain == "code"),
            "hunt": sum(1 for item in techniques if item.domain == "hunt"),
            "sources": sources,
            "items": [
                {"name": item.name, "description": item.description, "domain": item.domain, "source": item.source}
                for item in sorted(techniques, key=lambda value: (value.domain, value.name.casefold()))[:80]
            ],
        },
        "learning": {
            "code_runs": len(code_rows),
            "code_successes": sum(1 for row in code_rows if row.get("success")),
            "hunts": len(hunt_rows),
            "hunt_outcomes": len(hunt_outcomes),
            "confirmed": sum(1 for row in hunt_outcomes if str(row.get("proof_status") or "").lower() == "confirmed"),
        },
        "guardrails": [
            "Operator authorization and scope gate every active hunt request.",
            "Only deterministic reproduced evidence can become a confirmed finding.",
            "POE dialogue stays local and never auto-submits to an external production system.",
            "Code edits remain workspace-bound, rollback-capable, and verification-gated.",
        ],
    }
