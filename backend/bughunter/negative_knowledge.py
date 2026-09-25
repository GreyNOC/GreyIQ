"""GreyIQ BugHunter — negative knowledge: remember what was tested and did NOT confirm.

A hunt's probe budget is hard-capped (``offline_hunt._MAX_PRIORITY``): the prover walks a ranked
``probe_priority`` list in order and stops when the budget is spent. On a RE-SCAN of a program that
budget was, until now, re-spent on the same (endpoint, class) pairs that were probed and produced
nothing last time — inert ground crowding out new surface. This module remembers those misses so the
next run's budget flows to endpoints it has not already exhausted.

This COMPLEMENTS, and does not duplicate, ``brain_techniques.learned_hunt_priors`` — that nudges a
whole vulnerability CLASS down after repeated misses across a program. This layer is finer and
endpoint-scoped: it remembers a specific ``(endpoint, class)`` pair, so a class that is dead on one
route stays fully hunted on every other.

Honest and self-limiting by construction — negative knowledge must never blind the hunt:

  * A pair is recorded a MISS only from the same ``(plan, outcomes)`` the hunt trace already stores:
    an ``(endpoint, class)`` that was PLANNED but is absent from the confirmed outcomes. No finer
    signal is invented than the engine actually observed.
  * ``ever_confirmed`` immunizes a pair permanently — a route that has ever yielded a real bug is
    never suppressed.
  * Misses DECAY. A pair not re-missed within ``TTL_DAYS`` is dropped from the cooled set and probed
    again, because a program's surface and defenses change over time.
  * A pair is re-enabled the instant ``surface_drift`` reports its endpoint changed — the explicit
    "unless new evidence changes the situation" clause.
  * Suppression only DOWNRANKS within a plan (and drops an endpoint row only when EVERY class on it
    is cooled and unchanged); it never hard-blocks, and ``GREYIQ_NO_NEGATIVE_KNOWLEDGE=1`` turns the
    whole layer off. One bad hunt can never permanently hide a target from the next.

Pure / dependency-free / frozen-safe: a single JSON file under the runtime dir, written atomically
under a lock, mirroring ``learning.py`` / ``ledger.py``. No network, no ML.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from bughunter.learning import program_key

_STORE_NAME = "bughunter_negative_knowledge.json"
_LOCK = threading.Lock()  # serialize read-modify-write; os.replace is atomic but not RMW-safe

# A pair must be missed this many times before it is eligible to be downranked — one inconclusive
# probe (a transient error, a budget cut-off before it was reached) must never suppress a route.
MIN_MISSES = 2
# A miss older than this is forgotten: the surface, the defenses, and our own tooling all move, so a
# probe that was inert six weeks ago earns a fresh look.
TTL_DAYS = 45
# Bound the per-program store so a long-running program can never grow it without limit. When full,
# the least-recently-touched pairs are evicted (they are also the ones closest to TTL expiry anyway).
_MAX_PAIRS_PER_PROGRAM = 4000
_KEY_SEP = "\t"  # separates endpoint-key from class inside a stored pair id; neither field contains it

_ENV_DISABLE = "GREYIQ_NO_NEGATIVE_KNOWLEDGE"

# Sentinel meaning "the whole host changed, re-enable everything". surface_drift COLLAPSES a
# site-wide control loss into ONE delta whose subject is prose ("3 endpoint(s)"), not a URL — see
# surface_drift._collapse — so there is no endpoint to name. Treating that as an endpoint key
# produced an unmatched string and silently re-enabled nothing, in exactly the case with the
# strongest reason to re-probe: a protection came off across the whole surface.
ALL_ENDPOINTS = "*"

# Endpoint identity: host + path with volatile id segments collapsed, so /order/1001 and /order/1002
# share one memory. Query strings are dropped — the class dimension already separates concerns, and a
# per-value key would never repeat across runs. Mirrors offline_hunt's numeric/uuid segment shapes.
_UUID_SEG = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)")
_HEX_SEG = re.compile(r"/[0-9a-fA-F]{16,}(?=/|$)")
_NUM_SEG = re.compile(r"/\d+(?=/|$)")


def enabled() -> bool:
    """False when the operator has turned negative knowledge off for this process."""
    return str(os.getenv(_ENV_DISABLE, "")).strip().lower() not in {"1", "true", "yes", "on"}


def endpoint_key(url: str) -> str:
    """A stable, cross-run identity for an endpoint: ``host/path`` with numeric, hex, and UUID path
    segments collapsed to ``{id}``. Query and fragment are dropped. '' for an unparseable input."""
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else "http://" + raw)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    path = _UUID_SEG.sub("/{id}", path)
    path = _HEX_SEG.sub("/{id}", path)
    path = _NUM_SEG.sub("/{id}", path)
    path = re.sub(r"/{2,}", "/", path).rstrip("/") or "/"
    return f"{host}{path}"[:300].lower()


def _pair_id(ep_key: str, class_id: str) -> str:
    return f"{ep_key}{_KEY_SEP}{str(class_id or '').strip().lower()}"


def _split_pair(pair_id: str) -> tuple[str, str]:
    ep, _, cls = str(pair_id or "").partition(_KEY_SEP)
    return ep, cls


# --- persistence (mirrors learning.py) --------------------------------------------

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


def _now_iso(now: str | None) -> str:
    return now or datetime.now(UTC).isoformat()


def _parse_ts(value: Any) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _confirmed_pairs(outcomes: Any) -> set[str]:
    """Pair ids that reached a confirmed proof status this hunt — from the SAME outcome rows the hunt
    trace records (``proof_status == 'confirmed'``).

    An outcome's ``class`` is the IMPACT the finding carries, while a planned pair's class is the
    prover's CHECK TAG, and for five checks those differ (see
    ``prover_classes.IMPACT_TO_CHECK_TAGS``). Immunity is therefore recorded under every tag that
    could have produced the impact, not just the impact's own name. Without the fold the two halves
    could never meet for those checks: a confirmed CRLF injection banked immunity under ``redirect``
    while the plan accrued misses under ``crlf``, and after two clean runs the engine cooled the one
    check that had proven a submittable bug on that route — the exact opposite of this module's
    promise that anything ever confirmed is immune.

    Folding widens immunity slightly (a confirmed open redirect also immunises ``crlf`` and
    ``host-header`` on that route). That is the safe direction, and the direction this module already
    chooses elsewhere: a false re-enable costs a little budget, a false suppression silently removes
    coverage.
    """
    from bughunter.prover_classes import check_tags_for_impact

    confirmed: set[str] = set()
    for row in outcomes if isinstance(outcomes, list) else []:
        if not isinstance(row, dict):
            continue
        if str(row.get("proof_status") or "").strip().lower() != "confirmed":
            continue
        ep = endpoint_key(row.get("endpoint"))
        cls = str(row.get("class") or "").strip().lower()
        if not ep or not cls:
            continue
        confirmed.add(_pair_id(ep, cls))
        for tag in check_tags_for_impact(cls):
            confirmed.add(_pair_id(ep, tag))
    return confirmed


def _planned_pairs(plan: Any) -> set[str]:
    """Every ``(endpoint, class)`` the plan set out to probe — the attempt side, exactly as
    ``learned_hunt_priors`` reads it, so the two negative-knowledge layers agree on what an attempt is."""
    planned: set[str] = set()
    rows = (plan or {}).get("probe_priority") if isinstance(plan, dict) else None
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        ep = endpoint_key(row.get("endpoint"))
        if not ep:
            continue
        for cls in (row.get("classes") or []):
            cid = str(cls or "").strip().lower()
            if cid:
                planned.add(_pair_id(ep, cid))
    return planned


def record_hunt(runtime_dir: str | Path | None, *, program: str | None, target: str,
                plan: dict[str, Any] | None, outcomes: list[dict[str, Any]] | None,
                complete: bool = False, now: str | None = None) -> bool:
    """Fold one finished hunt into the store. A planned pair that did not confirm is a miss; a pair
    that confirmed is immunized (and any prior miss count on it is cleared). Best-effort and
    fail-closed — returns False and changes nothing on ``runtime_dir is None`` or any error, so a
    bookkeeping write can never break a hunt.

    ``plan`` and ``outcomes`` are the SAME objects the hunt trace records, so this adds a durable,
    cross-run memory without observing anything the engine did not already log.

    ``complete`` asserts the run actually WORKED ITS WAY THROUGH the plan — no scanner error, active
    verification in scope, not rate-limited or cut short. It defaults to False, and misses are
    recorded ONLY when it is True, because "never executed" and "executed and inert" are different
    facts and only the second is negative knowledge. The prover walks ``probe_priority`` in order and
    stops when its request budget is gone, so the TAIL of every truncated run would otherwise accrue
    misses for pairs nothing ever probed — a systematic bias that would cool exactly the endpoints
    that never got a fair chance. Confirmations are always recorded (they only ever GRANT immunity,
    so they are safe on a partial run); the default is conservative so a caller that cannot vouch for
    completeness can never poison the store."""
    if runtime_dir is None or not enabled():
        return False
    try:
        confirmed = _confirmed_pairs(outcomes)
        planned = _planned_pairs(plan) if complete else set()
        # A pair can confirm without having been in probe_priority (a passive/static finding), so both
        # sides matter: every confirmed pair is immunized, and — on a complete run only — every
        # planned-but-unconfirmed pair is a miss.
        if not planned and not confirmed:
            return False
        stamp = _now_iso(now)
        key = program_key(program, target)
        with _LOCK:
            data = _load(runtime_dir)
            programs = data.setdefault("programs", {})
            prog = programs.setdefault(key, {"pairs": {}, "updated_at": None})
            pairs = prog.setdefault("pairs", {})
            for pid in confirmed:
                row = pairs.setdefault(pid, {"miss": 0, "last_ts": stamp, "confirmed": False})
                row["confirmed"] = True
                row["miss"] = 0
                row["last_ts"] = stamp
            # Misses only from a run that actually got through its plan — see ``complete``.
            for pid in (planned if complete else set()):
                if pid in confirmed:
                    continue
                row = pairs.setdefault(pid, {"miss": 0, "last_ts": stamp, "confirmed": False})
                if row.get("confirmed"):
                    continue  # a proven route is never re-cooled by a later inconclusive run
                row["miss"] = int(row.get("miss") or 0) + 1
                row["last_ts"] = stamp
            _evict_if_full(pairs)
            prog["updated_at"] = stamp
            data["updated_at"] = stamp
            _save(runtime_dir, data)
        return True
    except Exception:  # noqa: BLE001 - negative knowledge is an optimizer, never a hunt breaker
        return False


def _evict_if_full(pairs: dict[str, Any]) -> None:
    """Keep the per-program store bounded by dropping the least-recently-touched pairs."""
    if len(pairs) <= _MAX_PAIRS_PER_PROGRAM:
        return
    ordered = sorted(pairs.items(), key=lambda kv: str((kv[1] or {}).get("last_ts") or ""))
    for pid, _ in ordered[: len(pairs) - _MAX_PAIRS_PER_PROGRAM]:
        pairs.pop(pid, None)


def cooled_pairs(runtime_dir: str | Path | None, *, program: str | None, target: str,
                 min_misses: int = MIN_MISSES, ttl_days: int = TTL_DAYS,
                 now: str | None = None) -> set[str]:
    """Pair ids eligible for suppression: missed ``>= min_misses`` times, never confirmed, and last
    missed within ``ttl_days``. Returns an empty set when the layer is disabled or has no memory —
    so a caller that always applies suppression is a no-op on a first-ever hunt."""
    if runtime_dir is None or not enabled():
        return set()
    prog = _load(runtime_dir).get("programs", {}).get(program_key(program, target))
    if not isinstance(prog, dict):
        return set()
    cutoff = (_parse_ts(_now_iso(now)) or datetime.now(UTC)) - timedelta(days=max(0, ttl_days))
    cooled: set[str] = set()
    for pid, row in (prog.get("pairs") or {}).items():
        if not isinstance(row, dict) or row.get("confirmed"):
            continue
        if int(row.get("miss") or 0) < max(1, min_misses):
            continue
        ts = _parse_ts(row.get("last_ts"))
        if ts is None or ts < cutoff:
            continue  # decayed — earn a fresh probe
        cooled.add(str(pid))
    return cooled


def changed_endpoint_keys(drift: dict[str, Any] | None) -> set[str]:
    """Endpoint keys whose surface changed this run, per ``surface_drift`` — these are RE-ENABLED
    (never suppressed), because a changed endpoint is exactly new evidence that the old miss no longer
    applies. Reads the delta ``kind``s that concern an endpoint appearing or changing shape."""
    out: set[str] = set()
    deltas = (drift or {}).get("deltas") if isinstance(drift, dict) else None
    for delta in deltas if isinstance(deltas, list) else []:
        if not isinstance(delta, dict):
            continue
        kind = str(delta.get("kind") or "")
        # Every endpoint-scoped drift kind, INCLUDING the ones that mean a defense came OFF.
        # `auth.removed` is surface_drift's highest-weighted signal ("a gate came off — the single
        # highest-signal change there is") and `cookie.flag-lost` / `header.security-removed` are the
        # same shape: a route that was inert while protected is the first thing to re-probe once the
        # protection is gone. Omitting them left the engine cooling exactly the endpoints that had
        # just become interesting.
        if kind in {"endpoint.new", "shape.changed", "auth.added", "form.new",
                    "auth.removed", "cookie.flag-lost", "header.security-removed"}:
            key = _subject_endpoint_key(delta.get("subject"))
            # A collapsed, site-wide subject names no endpoint — it means the change hit the whole
            # host, so nothing on it should stay cooled.
            out.add(key if key else ALL_ENDPOINTS)
    return out


def _subject_endpoint_key(subject: Any) -> str:
    """The endpoint key a drift delta's subject names, or '' when it names no single endpoint.

    ``surface_drift`` subjects are URLs except when ``_collapse`` folds a site-wide change into one
    row, whose subject is prose like ``"3 endpoint(s)"``. Whitespace is the reliable tell: a URL
    never contains a space, and every collapsed subject does."""
    raw = str(subject or "").strip()
    if not raw or " " in raw:
        return ""
    key = endpoint_key(raw)
    return key if key.split("/", 1)[0] else ""


def apply_suppression(plan: dict[str, Any] | None, cooled: set[str], *,
                      changed_endpoints: set[str] | None = None) -> tuple[dict[str, Any], dict[str, int]]:
    """Return ``(new_plan, stats)`` with cooled ``(endpoint, class)`` pairs downranked in
    ``probe_priority``. Pure — the input plan is never mutated; every other plan field is carried
    through unchanged.

    Within an endpoint row, cooled classes are moved AFTER the still-hot ones, so the prover reaches
    them only if budget remains. An endpoint flagged by ``changed_endpoints`` is left exactly as
    planned — a changed surface overrides its own history.

    Rows are REORDERED, never removed, even when every class on them is cooled. Dropping looked like
    it freed a probe slot, but the caller does not work from this list: ``active_targets`` is fixed
    before suppression runs and is never re-filtered, and the only consumer of ``probe_priority``
    (``bounty._plan_priorities_by_endpoint``) FALLS BACK to an inferred priority for an endpoint it
    cannot find. Dropping a row therefore saved no requests and merely replaced an explicit,
    evidence-based ordering with a guess — strictly worse than the partial-cool path it was meant to
    strengthen. Keeping the row preserves the ordering that actually reaches the prover."""
    if not isinstance(plan, dict):
        return ({} if plan is None else plan), {"downranked": 0, "dropped": 0}
    new_plan = dict(plan)
    rows = plan.get("probe_priority")
    if not cooled or not isinstance(rows, list):
        # Still hand back a copy of the list so callers can treat the result as owned.
        new_plan["probe_priority"] = list(rows) if isinstance(rows, list) else rows
        return new_plan, {"downranked": 0, "fully_cooled": 0}
    changed = changed_endpoints or set()
    if ALL_ENDPOINTS in changed:
        # A site-wide change (a security header or cookie flag lost across the host) invalidates
        # every stored miss for this surface at once — suppress nothing this run.
        new_plan["probe_priority"] = list(rows)
        return new_plan, {"downranked": 0, "fully_cooled": 0}
    out_rows: list[dict[str, Any]] = []
    downranked = 0
    fully_cooled = 0
    for row in rows:
        if not isinstance(row, dict):
            out_rows.append(row)
            continue
        ep = endpoint_key(row.get("endpoint"))
        classes = [c for c in (row.get("classes") or [])]
        if not ep or ep in changed or not classes:
            out_rows.append(row)
            continue
        hot = [c for c in classes if _pair_id(ep, c) not in cooled]
        cold = [c for c in classes if _pair_id(ep, c) in cooled]
        if not cold:
            out_rows.append(row)
            continue
        if not hot:
            fully_cooled += 1  # every class here is inert; keep the row, just fully deprioritised
        downranked += len(cold)
        out_rows.append({**row, "classes": hot + cold})
    new_plan["probe_priority"] = out_rows
    return new_plan, {"downranked": downranked, "fully_cooled": fully_cooled}


def summary(runtime_dir: str | Path | None, *, program: str | None, target: str,
            now: str | None = None) -> dict[str, Any]:
    """A small, human-readable digest for ``gn`` / diagnostics: how much the engine has learned NOT
    to re-test for a program."""
    if runtime_dir is None:
        return {"program": "", "pairs": 0, "cooled": 0, "confirmed": 0}
    key = program_key(program, target)
    prog = _load(runtime_dir).get("programs", {}).get(key) or {}
    pairs = prog.get("pairs") or {}
    cooled = cooled_pairs(runtime_dir, program=program, target=target, now=now)
    confirmed = sum(1 for row in pairs.values() if isinstance(row, dict) and row.get("confirmed"))
    return {"program": key, "pairs": len(pairs), "cooled": len(cooled),
            "confirmed": confirmed, "updated_at": prog.get("updated_at")}
