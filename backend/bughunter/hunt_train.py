"""GreyIQ BugHunter — in-tree trainer for the offline hunt ranker (`gn train-brain`).

Phase 4 of ``docs/offline-hunt-brain-distillation.md``, and the reason the whole distillation
idea is honest rather than aspirational: the corpus (``hunt_traces.jsonl``) lives on the
operator's machine, so the TRAINER has to live there too. Shipping a cloud pipeline would
mean uploading a record of every authorized target ever hunted, which is exactly the privacy
premise GreyIQ is built on. Pure stdlib, no numpy, no toolchain, no network — a few thousand
rows of sparse logistic regression is seconds of CPU, and it runs identically from the source
tree and from the frozen ``greyiq-backend.exe``.

WHAT IT LEARNS. One independent binary logistic regression per vuln class, over the features
``hunt_features`` extracts from each trace's OWN persisted recon surface, labeled by what the
deterministic prover actually CONFIRMED and weighted up by what actually PAID. Plus the two
side models the plan calls for: a conditional param-name frequency table (3b) and the
object/privileged endpoint selectors (3c). The competitor is never the knowledge base — the
hint tables are the model's INPUT — it is the fixed hand-guessed ORDER those tables are
applied in.

WHERE THE NEGATIVES COME FROM. A class that confirmed is a positive; the negatives are the
classes that were actually PROBED on that endpoint and did NOT confirm, read from the trace's
own persisted ``plan.probe_priority``. This is precisely why Phase 0 persists the plan and
not just the findings: without the probed set, "did not confirm" is indistinguishable from
"was never tried", and a model trained on that confusion learns to avoid whatever the rules
already avoided — the one thing it must not do.

THE PROMOTION GATE IS A WRITE GATE, NOT A REPORT. The corpus is split BY PROGRAM (never by
row — two rows off one hunt share a surface, so a row split leaks the answer across it), and
recall@3 of the confirmed classes is computed on the held-out programs for BOTH the learned
ranker and the rules baseline (``offline_hunt._reorder_by_priors`` over the same candidate
lists). The file is written ONLY if the model is at least as good as the rules. Otherwise
nothing is written, any previously promoted model is left untouched, and the command says so
and exits 1. Below ``min_rows`` it refuses outright, and if the held-out split contains no
confirmed outcome at all it reports UNDETERMINED rather than inventing a number — there is
no metric to report, and a fabricated one would defeat the only safeguard here.

The same rule is why GreyIQ ships NO bootstrap weight file. Hand-written weights placed in
``backend/seed/hunt_model/`` would be fabricated evidence of learning. Absent means rules,
which is the honest cold-start answer and costs nothing.

SAFETY is unchanged and is not this module's to relax: the trained model can only PERMUTE a
candidate class list (``hunt_model.Ranker.rank_endpoint_classes``), plans stay targeting
hints, and the deterministic scope+SSRF-gated prover owns every confirmation.

Module-level imports are stdlib ONLY: ``gn_cli`` imports this module on every CLI start to
register the verb, so pulling the bughunter stack in at import time would regress startup and
``test_boot_no_torch.py``. Every engine import lives inside a function body, matching the
``_cmd_traces`` convention.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

# Output location. ``hunt_model`` owns the canonical constants (it has to resolve the same
# path at load time); these are duplicated so this module stays stdlib-only at import time,
# and a test asserts the two never drift apart.
_OUT_SUBDIR = "hunt_model"
_OUT_NAME = "hunt_ranker.json"

_DEFAULT_MIN_ROWS = 200
_WEIGHT_PAID = 3.0        # sample weight of a finding that earned a bounty
_WEIGHT_BASE = 1.0
_ROUND = 6                # weight precision on disk: enough to reproduce a score, small enough to diff
_TOP_K = 3                # the k of recall@k — a probe_priority row's realistic attention budget
_MAX_PARAM_SUGGESTIONS = 12

# rule_id prefixes that discriminate the two access-control selectors. Both IDOR and BFLA
# land under the single ``access-control`` class_id, so the CLASS cannot tell them apart —
# the prover's rule_id can. A confirmed access-control row with neither prefix trains
# NEITHER selector: "undetermined which kind" is not evidence for both.
_IDOR_RULE_PREFIXES = ("active.idor",)
_PRIV_RULE_PREFIXES = ("active.bfla", "active.mass-assignment")
_SELECTOR_KINDS = (("idor", _IDOR_RULE_PREFIXES), ("privileged", _PRIV_RULE_PREFIXES))

_Z_CLAMP = 30.0


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _r6(value: float) -> float:
    """Round to the on-disk precision. ``or 0.0`` folds -0.0 onto 0.0 so two runs that differ
    only by the sign of a zero still serialize byte-identically."""
    return round(float(value), _ROUND) or 0.0


def _sigmoid(z: float) -> float:
    z = _Z_CLAMP if z > _Z_CLAMP else (-_Z_CLAMP if z < -_Z_CLAMP else z)
    return 1.0 / (1.0 + math.exp(-z))


def _program_in_holdout(program: str, holdout: float) -> bool:
    """Deterministic BY-PROGRAM split. Hashing the program name (not the row, not a shuffled
    index) means the same program always lands on the same side across retrains, so a metric
    is comparable over time, and no surface can appear on both sides of the split.

    sha1 is used as a stable hash function, not as a security primitive — hence
    ``usedforsecurity=False``."""
    share = int(max(0.0, min(1.0, float(holdout))) * 100)
    if share <= 0:
        return False
    digest = hashlib.sha1(str(program).encode("utf-8"), usedforsecurity=False).hexdigest()
    return int(digest[:8], 16) % 100 < share


# --- dataset -----------------------------------------------------------------------------


def _collect(runtime_dir: str | Path) -> list[dict[str, Any]]:
    """The full training rows, each carrying the context the evaluator needs.

    ``build_dataset`` is the narrow public projection of this; the evaluator additionally
    needs the endpoint URL and its surface context so it can reconstruct the RULES ordering
    for the same endpoint and compare like with like."""
    from bughunter import hunt_features, hunt_trace

    # LABEL side: hunt_trace.training_examples has already re-joined the ledger, so a bounty
    # that landed weeks after the hunt is reflected without ever rewriting the append-only
    # log. OR-merged across traces: a class that confirmed on an endpoint ONCE is a positive
    # for that endpoint, even in a hunt where the probe happened to miss it.
    labels: dict[tuple[str, str, str], list[bool]] = {}
    for row in hunt_trace.training_examples(runtime_dir):
        key = (str(row.get("program") or ""), str(row.get("endpoint") or ""),
               str(row.get("class") or "").strip().lower())
        prev = labels.get(key) or [False, False]
        labels[key] = [prev[0] or bool(row.get("confirmed")), prev[1] or bool(row.get("paid"))]

    out: list[dict[str, Any]] = []
    for trace in hunt_trace.load_traces(runtime_dir):
        program = str(trace.get("program") or "")
        surface = trace.get("surface") if isinstance(trace.get("surface"), dict) else {}
        # Lowercased + sorted + unique, exactly like offline_plan's `sorted(recon_params)`, so
        # the learned features and the rules baseline read identical names off one surface.
        recon = sorted({str(p).strip().lower() for p in (surface.get("params") or []) if str(p or "").strip()})
        tech = " ".join(str(t) for t in (surface.get("tech") or [])).lower()
        forms: dict[str, dict[str, Any]] = {}
        for form in surface.get("forms") or []:
            if isinstance(form, dict) and str(form.get("action") or "").strip():
                forms.setdefault(str(form["action"]).strip(), form)

        rule_ids: dict[tuple[str, str], list[str]] = {}
        for outcome in trace.get("outcomes") or []:
            if not isinstance(outcome, dict):
                continue
            endpoint = str(outcome.get("endpoint") or "").strip()
            class_id = str(outcome.get("class") or "").strip().lower()
            rule_id = str(outcome.get("rule_id") or "").strip().lower()
            if endpoint and class_id and rule_id:
                rule_ids.setdefault((endpoint, class_id), []).append(rule_id)

        # PROBED pairs first (the plan's own order), then any outcome pair the plan never
        # listed — a class that confirmed without being planned is the sharpest signal there
        # is, and dropping it would teach the model the rules' blind spots.
        pairs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        plan = trace.get("plan") if isinstance(trace.get("plan"), dict) else {}
        for prow in plan.get("probe_priority") or []:
            if not isinstance(prow, dict):
                continue
            endpoint = str(prow.get("endpoint") or "").strip()
            if not endpoint:
                continue
            for raw_class in prow.get("classes") or []:
                class_id = str(raw_class or "").strip().lower()
                if class_id and (endpoint, class_id) not in seen:
                    seen.add((endpoint, class_id))
                    pairs.append((endpoint, class_id))
        for endpoint, class_id in rule_ids:
            if (endpoint, class_id) not in seen:
                seen.add((endpoint, class_id))
                pairs.append((endpoint, class_id))
        for outcome in trace.get("outcomes") or []:
            if not isinstance(outcome, dict):
                continue
            endpoint = str(outcome.get("endpoint") or "").strip()
            class_id = str(outcome.get("class") or "").strip().lower()
            if endpoint and class_id and (endpoint, class_id) not in seen:
                seen.add((endpoint, class_id))
                pairs.append((endpoint, class_id))

        for endpoint, class_id in pairs:
            names = hunt_features.query_names(endpoint)
            feats = hunt_features.endpoint_features(endpoint, names, recon, tech, forms.get(endpoint))
            confirmed, paid = labels.get((program, endpoint, class_id), (False, False))
            out.append({
                "feats": feats,
                "class_id": class_id,
                "label": 1 if confirmed else 0,
                # Sample weight: a paid finding is worth 3x an unpaid confirm. Clamped to
                # [1, 3] so a single large bounty cannot dominate the whole corpus.
                "weight": _WEIGHT_PAID if paid else _WEIGHT_BASE,
                "program": program,
                "endpoint": endpoint,
                "query_names": names,
                "recon_params": recon,
                "tech": tech,
                # Carried so _evaluate can score the SAME vector production builds.
                "form": forms.get(endpoint),
                "rule_ids": rule_ids.get((endpoint, class_id), []),
                "paid": bool(paid),
            })
    return out


def build_dataset(runtime_dir: str | Path) -> list[tuple[dict[str, float], str, int, float, str]]:
    """The supervised corpus as ``(features, class_id, label, sample_weight, program)``.

    Sourced entirely from ``hunt_trace`` — the ledger join already happened there — and
    recomputed from each trace's own persisted surface, which is exactly why the surface is
    stored in full: features must be reproducible offline, long after the hunt."""
    return [(r["feats"], r["class_id"], r["label"], r["weight"], r["program"]) for r in _collect(runtime_dir)]


# --- learning ----------------------------------------------------------------------------


def _train_binary(
    rows: list[tuple[dict[str, float], int, float]],
    *,
    epochs: int,
    lr: float,
    l2: float,
    rng_seed: int,
) -> dict[str, float]:
    """Sparse binary logistic regression by plain SGD. Returns the weight map, which INCLUDES
    the ``bias`` feature — the intercept is learned as an ordinary weight and is only split
    out into its own field at serialization time, so there is one update rule, not two.

    Bit-reproducible on purpose: the shuffle is ``random.Random(rng_seed + epoch)`` and each
    example's features are visited in ``sorted()`` order, so the float sum is identical run to
    run. Without that, two retrains of the same corpus would produce different weights and the
    promotion gate's comparison would be noise. L2 is applied lazily (only to the features
    present in the example), the standard sparse approximation."""
    weights: dict[str, float] = {}
    count = len(rows)
    for epoch in range(max(0, int(epochs))):
        order = list(range(count))
        random.Random(rng_seed + epoch).shuffle(order)
        for index in order:
            feats, label, weight = rows[index]
            names = sorted(feats)
            z = 0.0
            for name in names:
                current = weights.get(name)
                if current is not None:
                    z += current * feats[name]
            gradient = (_sigmoid(z) - label) * weight
            for name in names:
                current = weights.get(name, 0.0)
                weights[name] = current - lr * (gradient * feats[name] + l2 * current)
    return weights


def _block(weights: dict[str, float]) -> dict[str, Any]:
    """Serialize a trained weight map into the on-disk ``{"bias", "w"}`` block: the intercept
    lifted out, everything rounded, and weights that round to zero dropped (they contribute
    nothing to a score and only bloat a file meant to be read by a human)."""
    bias = _r6(weights.get("bias", 0.0))
    out: dict[str, float] = {}
    for name in sorted(weights):
        if name == "bias":
            continue
        value = _r6(weights[name])
        if value:
            out[name] = value
    return {"bias": bias, "w": out}


def _train_selectors(rows: list[dict[str, Any]], **kwargs: Any) -> dict[str, dict[str, Any]]:
    """The object-level (``idor``) / function-level (``privileged``) endpoint selectors.

    One example per distinct (program, endpoint), labeled by whether a CONFIRMED access-control
    finding at that endpoint carried an IDOR- or BFLA-flavored ``rule_id``. A kind with zero
    positives is NOT emitted: an all-negative classifier has learned nothing, and
    ``Ranker.select`` reads a missing kind as 0.5 == "no opinion, use the heuristics"."""
    by_endpoint: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["program"], row["endpoint"])
        entry = by_endpoint.get(key)
        if entry is None:
            entry = by_endpoint[key] = {"feats": row["feats"], "paid": False,
                                        "idor": 0, "privileged": 0}
        if row["label"] != 1:
            continue
        entry["paid"] = entry["paid"] or row["paid"]
        for rule_id in row["rule_ids"]:
            for kind, prefixes in _SELECTOR_KINDS:
                if rule_id.startswith(prefixes):
                    entry[kind] = 1

    out: dict[str, dict[str, Any]] = {}
    for kind, _prefixes in _SELECTOR_KINDS:
        examples = [(e["feats"], int(e[kind]), _WEIGHT_PAID if e["paid"] else _WEIGHT_BASE)
                    for e in by_endpoint.values()]
        if not any(label for _f, label, _w in examples):
            continue
        out[kind] = _block(_train_binary(examples, **kwargs))
    return out


def _param_model(rows: list[dict[str, Any]]) -> dict[str, list[list[Any]]]:
    """``P(param name | endpoint purpose bucket, tech)`` from CONFIRMED rows only.

    A frequency table, not a network: KB-scale, human-readable, and trivially explainable
    ("these names paid off on download endpoints running PHP"). Only names actually observed
    are ever emitted — the table can rank, it cannot invent."""
    from bughunter import hunt_features

    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        if row["label"] != 1:
            continue
        key = f"{hunt_features.purpose_bucket(row['endpoint'])}|{hunt_features.tech_key(row['tech'])}"
        bucket = counts.setdefault(key, {})
        for name in row["query_names"]:
            clean = str(name or "").strip().lower()
            if clean:
                bucket[clean] = bucket.get(clean, 0) + 1

    out: dict[str, list[list[Any]]] = {}
    for key in sorted(counts):
        bucket = counts[key]
        total = sum(bucket.values())
        if not total:
            continue
        ranked = sorted(bucket.items(), key=lambda item: (-item[1], item[0]))[:_MAX_PARAM_SUGGESTIONS]
        out[key] = [[name, round(count / total, 4)] for name, count in ranked]
    return out


# --- evaluation ---------------------------------------------------------------------------


def _rules_order(row: dict[str, Any], observed: list[str]) -> list[str]:
    """The candidate list in the RULES' own order — the baseline the model must beat.

    ``offline_hunt._classes_for_endpoint`` decides the order for the classes it proposes;
    every other observed class is appended in sorted order, because the rules genuinely never
    proposed it and "last" is the honest position for a suggestion that was never made."""
    from bughunter import offline_hunt

    names = list(row["query_names"]) + list(row["recon_params"])
    tech = row["tech"]
    boost = tuple(dict.fromkeys(c for key, classes in offline_hunt._TECH_CLASS.items()
                                if key in tech for c in classes))
    ruled = offline_hunt._classes_for_endpoint(row["endpoint"], names, boost)
    order = [c for c in ruled if c in observed]
    order += sorted(c for c in observed if c not in order)
    return order


def _recall_at_k(order: list[str], relevant: set[str], k: int = _TOP_K) -> float:
    """Fraction of the classes that ACTUALLY confirmed which appear in the top ``k``. This is
    the metric the plan names, and it is the right one: ``probe_priority`` is an attention
    budget, so what matters is whether the truth is near the front, not the whole ordering."""
    return len(set(order[:k]) & relevant) / len(relevant)


def _evaluate(model: Any, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Mean recall@3 on the held-out programs, for the model AND for the rules baseline.

    Grouped by (program, endpoint): one endpoint is one ranking decision, so scoring per row
    would silently weight endpoints by how many classes happened to be probed on them. Groups
    with no confirmed class are skipped — there is no recall to measure — and if that leaves
    NOTHING, both numbers come back None (undetermined), never 0.0."""
    from bughunter import offline_hunt

    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["program"], row["endpoint"])
        group = groups.get(key)
        if group is None:
            group = groups[key] = {"ctx": row, "classes": [], "relevant": set()}
        if row["class_id"] not in group["classes"]:
            group["classes"].append(row["class_id"])
        if row["label"] == 1:
            group["relevant"].add(row["class_id"])

    model_scores: list[float] = []
    rules_scores: list[float] = []
    for group in groups.values():
        relevant = group["relevant"]
        if not relevant:
            continue
        ctx = group["ctx"]
        candidates = _rules_order(ctx, group["classes"])
        # priors=None: the baseline is the hand-tuned knowledge ordering itself. With no
        # priors _reorder_by_priors is the identity, which is exactly the intent — it is
        # called explicitly so the baseline is literally the shipped rules function.
        rules = offline_hunt._reorder_by_priors(candidates, None)
        learned = model.rank_endpoint_classes(
            ctx["endpoint"], ctx["query_names"], ctx["recon_params"], ctx["tech"], candidates, None,
            form=ctx.get("form"))
        rules_scores.append(_recall_at_k(rules, relevant))
        model_scores.append(_recall_at_k(learned, relevant))

    if not model_scores:
        return {"recall_at_3_model": None, "recall_at_3_rules": None, "scored_endpoints": 0}
    return {
        "recall_at_3_model": round(sum(model_scores) / len(model_scores), 4),
        "recall_at_3_rules": round(sum(rules_scores) / len(rules_scores), 4),
        "scored_endpoints": len(model_scores),
    }


# --- training entry point -------------------------------------------------------------------


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    """tmp file in the same directory + ``os.replace``, mirroring ``learning._save``: a
    crashed or interrupted retrain must never leave a half-written weight file where the next
    hunt will try to load it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    replaced = False
    try:
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
        replaced = True
    finally:
        if not replaced:
            tmp.unlink(missing_ok=True)


def train(
    runtime_dir: str | Path,
    *,
    seed_dir: str | Path | None = None,
    epochs: int = 40,
    lr: float = 0.1,
    l2: float = 1e-4,
    rng_seed: int = 1337,
    holdout: float = 0.2,
    min_rows: int = _DEFAULT_MIN_ROWS,
    dry_run: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    """Train, evaluate against the rules baseline, and promote ONLY on a win.

    Returns a result dict in every case — this function never raises on a refusal, because a
    refusal is a normal, expected outcome of an honest gate. ``ok`` is True only when the
    model was evaluated and either written (or would have been, under ``dry_run``).
    ``now`` overrides the ``created_at`` stamp so a retrain of an unchanged corpus is
    byte-identical, which is how the determinism guarantee is actually testable."""
    from bughunter import hunt_features, hunt_model, hunt_trace

    rows = _collect(runtime_dir)
    stats = hunt_trace.trace_stats(runtime_dir)
    programs = sorted({r["program"] for r in rows})
    confirmed = sum(1 for r in rows if r["label"] == 1)
    paid = sum(1 for r in rows if r["paid"])
    out_path = Path(runtime_dir) / _OUT_SUBDIR / _OUT_NAME
    active = hunt_model.model_file(seed_dir, runtime_dir)
    base: dict[str, Any] = {
        "ok": False,
        "reason": "",
        "written": False,
        "dry_run": bool(dry_run),
        "path": str(out_path),
        "active_model": str(active) if active else None,
        "traces": int(stats.get("hunts") or 0),
        "rows": len(rows),
        "programs": len(programs),
        "confirmed": confirmed,
        "paid": paid,
        "min_rows": int(min_rows),
        "rows_needed": max(0, int(min_rows) - len(rows)),
        "train_rows": 0,
        "held_out_rows": 0,
        "held_out_programs": 0,
        "classes": [],
        "recall_at_3_model": None,
        "recall_at_3_rules": None,
        "scored_endpoints": 0,
    }

    if len(rows) < int(min_rows):
        base["reason"] = (f"not enough training data: {len(rows)} labeled row(s) from "
                          f"{len(programs)} program(s), need at least {int(min_rows)}")
        return base

    train_rows = [r for r in rows if not _program_in_holdout(r["program"], holdout)]
    hold_rows = [r for r in rows if _program_in_holdout(r["program"], holdout)]
    base["train_rows"] = len(train_rows)
    base["held_out_rows"] = len(hold_rows)
    base["held_out_programs"] = len({r["program"] for r in hold_rows})
    if not train_rows or not hold_rows:
        base["reason"] = ("undetermined: every program hashed onto one side of the split, so "
                          "there is nothing to evaluate against — hunt more distinct programs")
        return base

    hyper = {"epochs": int(epochs), "lr": float(lr), "l2": float(l2), "rng_seed": int(rng_seed)}
    classes = sorted({r["class_id"] for r in train_rows})
    ranker: dict[str, Any] = {}
    for class_id in classes:
        examples = [(r["feats"], r["label"], r["weight"]) for r in train_rows if r["class_id"] == class_id]
        ranker[class_id] = _block(_train_binary(examples, **hyper))
    base["classes"] = classes

    payload: dict[str, Any] = {
        "v": hunt_model.SCHEMA_VERSION,
        "kind": "greyiq-hunt-ranker",
        "feature_version": hunt_features.FEATURE_VERSION,
        "created_at": now or _now(),
        "trained_on": {"traces": base["traces"], "rows": len(rows), "programs": len(programs),
                       "confirmed": confirmed, "paid": paid},
        "eval": {},
        "classes": classes,
        "ranker": ranker,
        "param_model": _param_model(train_rows),
        "selectors": _train_selectors(train_rows, **hyper),
    }

    coerced = hunt_model._coerce(payload)
    if coerced is None:
        # Unreachable unless the on-disk contract and this writer have drifted. Refuse rather
        # than write a file the loader would silently reject at the next hunt.
        base["reason"] = "internal: the trained model failed its own on-disk validation; nothing written"
        return base
    scores = _evaluate(hunt_model.Ranker(coerced), hold_rows)
    base.update(scores)

    if scores["recall_at_3_model"] is None:
        base["reason"] = ("undetermined: no held-out endpoint has a confirmed class, so the model "
                          "cannot be compared to the rules — nothing written")
        return base
    if scores["recall_at_3_model"] < scores["recall_at_3_rules"]:
        base["reason"] = (f"model did not beat the rules (recall@3 {scores['recall_at_3_model']} vs "
                          f"{scores['recall_at_3_rules']}); the existing model is untouched")
        return base

    payload["eval"] = {
        "recall_at_3_model": scores["recall_at_3_model"],
        "recall_at_3_rules": scores["recall_at_3_rules"],
        "scored_endpoints": scores["scored_endpoints"],
        "held_out_rows": base["held_out_rows"],
        "held_out_programs": base["held_out_programs"],
        "k": _TOP_K,
    }
    base["ok"] = True
    if dry_run:
        base["reason"] = "dry run: the model passed the gate, nothing was written"
        return base
    _write_atomic(out_path, payload)
    base["written"] = True
    base["active_model"] = str(out_path)
    base["reason"] = "promoted"
    return base


# --- CLI (`gn train-brain`, registered through gn_cli's plugin hook) --------------------------


def _resolve_dirs() -> tuple[Path, Path | None]:
    """(runtime_dir, seed_dir). Read off ``gn_cli`` when we are running under the CLI so the
    command honors ``GREYIQ_RUNTIME_DIR`` and any test that repoints it; falls back to the
    same frozen-vs-dev resolution if this is ever driven without the CLI present."""
    try:
        import gn_cli

        return Path(gn_cli.RUNTIME_DIR), Path(gn_cli.SEED_DIR)
    except Exception:  # noqa: BLE001 - the trainer must still run if the CLI module is unavailable
        backend = Path(__file__).resolve().parent.parent
        runtime = Path(os.getenv("GREYIQ_RUNTIME_DIR", str(backend.parent / "runtime"))).resolve()
        return runtime, backend / "seed"


def register_cli(sub: Any) -> None:
    """gn_cli plugin hook. MUST stay import-light — this runs on every ``import gn_cli``."""
    parser = sub.add_parser(
        "train-brain",
        help="train the offline hunt ranker from your local hunt traces (offline, deterministic)")
    parser.add_argument("--dry-run", action="store_true", help="evaluate and print, write nothing")
    parser.add_argument("--show", action="store_true",
                        help="print the ACTIVE model (seed vs runtime, created_at, eval) and exit")
    parser.add_argument("--min-rows", type=int, default=_DEFAULT_MIN_ROWS,
                        help=f"refuse to train below this many labeled rows (default {_DEFAULT_MIN_ROWS})")
    # train() has accepted these five since it was written and the CLI passed NONE of them, so the
    # only reachable configuration was the default one. They are the whole of the fit: holdout decides
    # how honest the promotion gate is, and epochs/lr/l2 decide whether the fit converges at all on a
    # corpus whose size the operator cannot control.
    parser.add_argument("--holdout", type=float, default=0.2, metavar="FRACTION",
                        help="fraction of PROGRAMS held out to score against the rules baseline "
                             "(default 0.2; 0 disables the gate and is refused)")
    parser.add_argument("--epochs", type=int, default=40, help="gradient steps per class (default 40)")
    parser.add_argument("--lr", type=float, default=0.1, help="learning rate (default 0.1)")
    parser.add_argument("--l2", type=float, default=1e-4, help="L2 penalty (default 1e-4)")
    parser.add_argument("--seed", type=int, default=1337, dest="rng_seed",
                        help="RNG seed; the same corpus and seed retrain byte-identically (default 1337)")
    parser.add_argument("--json", action="store_true")
    parser.set_defaults(func=_cmd_train_brain)


# Public aliases. The CLI reached the two names below through their private spellings, which meant a
# second caller (the Studio's hunt-brain panel, via GET /api/hunt/model) had to import underscored
# names to ask "which ranker is active and is a retrain worth it?". Naming them makes that a supported
# read rather than a reach into module internals.
DEFAULT_MIN_ROWS = _DEFAULT_MIN_ROWS


def show_status(runtime_dir: Path | str, seed_dir: Path | str | None = None,
                min_rows: int = _DEFAULT_MIN_ROWS) -> dict[str, Any]:
    """Which hunt ranker is ACTIVE, what it scored, and how much corpus exists — see ``_show``."""
    return _show(Path(runtime_dir), Path(seed_dir) if seed_dir is not None else None, int(min_rows))


def _show(runtime_dir: Path, seed_dir: Path | None, min_rows: int) -> dict[str, Any]:
    """The ``--show`` payload: which model is ACTIVE (and whether it is the bundled seed or a
    locally trained one), what it scored when it was promoted, and — the part that keeps the
    cold start honest — exactly how much corpus exists and how much more is needed."""
    from bughunter import hunt_model, hunt_trace

    path = hunt_model.model_file(seed_dir, runtime_dir)
    model = hunt_model.load_model(seed_dir, runtime_dir)
    rows = _collect(runtime_dir)
    stats = hunt_trace.trace_stats(runtime_dir)
    runtime_candidate = Path(runtime_dir) / _OUT_SUBDIR / _OUT_NAME
    return {
        "active_model": str(path) if path else None,
        "source": None if path is None else ("runtime" if path == runtime_candidate else "seed"),
        "loaded": model is not None,
        "version_tag": model.version_tag if model else None,
        "classes": model.classes if model else [],
        "eval": model.evaluation if model else {},
        "corpus": {
            "hunts": int(stats.get("hunts") or 0),
            "programs": len({r["program"] for r in rows}),
            "labeled_rows": len(rows),
            "confirmed_rows": sum(1 for r in rows if r["label"] == 1),
            "paid_rows": sum(1 for r in rows if r["paid"]),
            "min_rows": int(min_rows),
            "rows_needed": max(0, int(min_rows) - len(rows)),
        },
    }


def _cmd_train_brain(args: Any) -> int:
    """Engine imports live here, not at module scope (the ``_cmd_traces`` convention).
    Exit 0 when the model was promoted (or passed under --dry-run), 1 when the gate refused."""
    runtime_dir, seed_dir = _resolve_dirs()
    as_json = bool(getattr(args, "json", False))
    min_rows = int(getattr(args, "min_rows", _DEFAULT_MIN_ROWS) or _DEFAULT_MIN_ROWS)

    if getattr(args, "show", False):
        info = _show(runtime_dir, seed_dir, min_rows)
        if as_json:
            print(json.dumps(info, indent=2, default=str))
            return 0
        corpus = info["corpus"]
        if info["active_model"]:
            print(f"active model: {info['active_model']} ({info['source']})")
            print(f"  version:    {info['version_tag']}")
            print(f"  loaded:     {'yes' if info['loaded'] else 'NO - rejected, the rules are in force'}")
            evaluation = info["eval"] or {}
            if evaluation:
                print(f"  recall@3:   model {evaluation.get('recall_at_3_model')} vs "
                      f"rules {evaluation.get('recall_at_3_rules')} "
                      f"on {evaluation.get('held_out_programs')} held-out program(s)")
        else:
            print("active model: none - the hand-tuned rules in offline_hunt.py are in force.")
            print("  GreyIQ ships no pre-trained weights; a model appears only once YOUR corpus earns one.")
        print(f"corpus: {corpus['hunts']} hunt(s), {corpus['programs']} program(s), "
              f"{corpus['labeled_rows']} labeled row(s), {corpus['confirmed_rows']} confirmed, "
              f"{corpus['paid_rows']} paid")
        if corpus["rows_needed"]:
            print(f"  {corpus['rows_needed']} more row(s) needed before `gn train-brain` will train "
                  f"(minimum {corpus['min_rows']}).")
        else:
            print("  enough rows to train: run `gn train-brain`.")
        return 0

    # Every knob train() takes, forwarded. getattr with the signature default so a caller that builds
    # its own Namespace (the tests do) keeps working without listing all of them.
    holdout = float(getattr(args, "holdout", 0.2))
    if not 0.0 < holdout < 1.0:
        print("refused: --holdout must be between 0 and 1 (exclusive). It is the held-out program "
              "fraction the promotion gate scores against the rules baseline; without it a model "
              "would be promoted on its own training data.", file=sys.stderr)
        return 1
    result = train(
        runtime_dir,
        seed_dir=seed_dir,
        min_rows=min_rows,
        dry_run=bool(getattr(args, "dry_run", False)),
        holdout=holdout,
        epochs=int(getattr(args, "epochs", 40)),
        lr=float(getattr(args, "lr", 0.1)),
        l2=float(getattr(args, "l2", 1e-4)),
        rng_seed=int(getattr(args, "rng_seed", 1337)),
    )
    if as_json:
        print(json.dumps(result, indent=2, default=str))
        return 0 if result["ok"] else 1

    print(f"corpus: {result['traces']} hunt(s), {result['rows']} labeled row(s) from "
          f"{result['programs']} program(s), {result['confirmed']} confirmed, {result['paid']} paid")
    if result["held_out_rows"]:
        print(f"split:  {result['train_rows']} train / {result['held_out_rows']} held-out row(s) "
              f"across {result['held_out_programs']} held-out program(s)")
    model_recall, rules_recall = result["recall_at_3_model"], result["recall_at_3_rules"]
    if model_recall is None:
        print("recall@3: undetermined (no held-out confirmed outcome to score against)")
    else:
        print(f"recall@3: model {model_recall} vs rules {rules_recall} "
              f"over {result['scored_endpoints']} held-out endpoint(s)")
    if result["ok"] and result["written"]:
        print(f"promoted: {result['path']}")
        return 0
    if result["ok"]:
        print(f"{result['reason']}: {result['path']}")
        return 0
    print(f"refused: {result['reason']}")
    return 1
