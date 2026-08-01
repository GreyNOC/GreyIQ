"""GreyIQ BugHunter — the learned offline hunt ranker (inference side).

Phase 2/3 of ``docs/offline-hunt-brain-distillation.md``. ``hunt_train`` compresses a local
corpus of real hunt outcomes into ONE plain-JSON weight file; this module reads it back and
scores. That is the whole "burst compute once, extract it cheap forever" trade: training is
seconds of CPU on the operator's own machine, inference is a few dict lookups and one
``exp()`` per endpoint-class pair, offline, with no network and no tensor library.

WHAT THIS MODEL IS ALLOWED TO DO — the safety contract, unchanged from the rules path:

  * :meth:`Ranker.rank_endpoint_classes` may ONLY PERMUTE the candidate list it is handed.
    It cannot add a class, drop a class, invent an endpoint, or emit a payload. The caller
    re-checks that the result is a permutation and discards it otherwise, so a corrupt or
    adversarial weight file costs at most a worse ORDER.
  * A hunt plan is a targeting HINT. The deterministic, scope+SSRF-gated prover still owns
    every confirmation. Per ``offline_hunt``'s standing invariant, a learned ranker can
    raise RECALL and can never touch PRECISION — a 70%-good model wastes a little probe
    budget, it cannot manufacture a finding.

ABSENT MEANS "EXACTLY AS BEFORE". :func:`load_model` returns ``None`` — never raises, never
warns, never half-loads — for a missing file, an OSError, truncated JSON, a non-dict root,
the wrong ``kind``/``v``/``feature_version``, or any weight that is not a finite float. The
absent model IS the feature flag: no file, no learned ranking, the hand-tuned rules run
untouched. NaN and Inf are rejected specifically because they poison a comparison sort into
producing a NON-permutation, which is the one failure the safety contract cannot absorb
quietly; ``z`` is additionally clamped to +/-30 before ``exp`` so a large finite weight
cannot raise OverflowError mid-hunt.

ON-DISK: ``<runtime>/hunt_model/hunt_ranker.json`` overrides ``<seed>/hunt_model/
hunt_ranker.json`` — the same runtime-wins-over-bundled resolution + mtime cache as
``toolkit.load_catalog``, so an operator who retrains locally immediately outranks whatever
shipped. The extension is ``.json`` and NOT ``.pt``: the PyInstaller spec drops ``*.pt``
silently, and a weight file that vanishes only in the frozen build is the worst possible
failure mode. Ungzipped on purpose so ``grep path:kw=search hunt_ranker.json`` works — the
model must stay auditable by a human who wants to know why it probed what it probed.

NOTE: GreyIQ ships NO seed weight file. Hand-written weights would be fabricated evidence of
learning; the honest cold start is "no model, use the rules", which costs nothing.

Pure stdlib (``json``/``math``/``pathlib``), frozen-safe, no network.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from bughunter import hunt_features

SCHEMA_VERSION = 1
_KIND = "greyiq-hunt-ranker"
_SUBDIR = "hunt_model"
_FILENAME = "hunt_ranker.json"

# exp(30) ~ 1e13; the sigmoid is saturated long before this, so clamping costs no resolution
# and removes OverflowError from the hot path entirely.
_Z_CLAMP = 30.0
# learned_priors are reward multipliers around a neutral 1.0. Clamped so one lucky bounty
# cannot let the program memory override the model outright.
_PRIOR_MIN, _PRIOR_MAX = 0.5, 2.0

# Resolved-path -> {"_mtime": (mtime, size), "model": Ranker}. Mirrors toolkit._CACHE: weights
# are static between retrains, and a hunt scores hundreds of endpoint-class pairs. The SIZE is
# folded into the stamp because filesystem mtime resolution is coarse (notably on Windows/
# OneDrive) and two retrains inside one tick would otherwise serve a stale model.
_CACHE: dict[str, dict[str, Any]] = {}


def _sigmoid(z: float) -> float:
    z = _Z_CLAMP if z > _Z_CLAMP else (-_Z_CLAMP if z < -_Z_CLAMP else z)
    return 1.0 / (1.0 + math.exp(-z))


def _finite(value: Any) -> float | None:
    """``float(value)`` if it is a real, finite number — else None. The gate that keeps NaN
    and Inf out of the sort key (see the module docstring)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    out = float(value)
    return out if math.isfinite(out) else None


def _coerce_block(raw: Any) -> tuple[float, dict[str, float]] | None:
    """Validate one ``{"bias": float, "w": {feature: float}}`` block. None on ANY defect —
    a partially-loaded model is worse than no model, because it looks like it works."""
    if not isinstance(raw, dict):
        return None
    bias = _finite(raw.get("bias", 0.0))
    if bias is None:
        return None
    weights_raw = raw.get("w", {})
    if not isinstance(weights_raw, dict):
        return None
    weights: dict[str, float] = {}
    for name, value in weights_raw.items():
        number = _finite(value)
        if not isinstance(name, str) or number is None:
            return None
        weights[name] = number
    return bias, weights


def _coerce(data: Any) -> dict[str, Any] | None:
    """Full structural + numeric validation of a decoded weight file. None => use the rules."""
    if not isinstance(data, dict):
        return None
    if data.get("kind") != _KIND or data.get("v") != SCHEMA_VERSION:
        return None
    if data.get("feature_version") != hunt_features.FEATURE_VERSION:
        return None

    ranker_raw = data.get("ranker")
    if not isinstance(ranker_raw, dict):
        return None
    bias: dict[str, float] = {}
    weights: dict[str, dict[str, float]] = {}
    for class_id, block in ranker_raw.items():
        coerced = _coerce_block(block)
        if not isinstance(class_id, str) or coerced is None:
            return None
        bias[class_id], weights[class_id] = coerced

    selectors_raw = data.get("selectors") or {}
    if not isinstance(selectors_raw, dict):
        return None
    selectors: dict[str, tuple[float, dict[str, float]]] = {}
    for kind, block in selectors_raw.items():
        coerced = _coerce_block(block)
        if not isinstance(kind, str) or coerced is None:
            return None
        selectors[kind] = coerced

    params_raw = data.get("param_model") or {}
    if not isinstance(params_raw, dict):
        return None
    param_model: dict[str, list[tuple[str, float]]] = {}
    for key, rows in params_raw.items():
        if not isinstance(key, str) or not isinstance(rows, (list, tuple)):
            return None
        entries: list[tuple[str, float]] = []
        for row in rows:
            if not isinstance(row, (list, tuple)) or len(row) != 2:
                return None
            name, weight = row
            number = _finite(weight)
            if not isinstance(name, str) or number is None:
                return None
            entries.append((name, number))
        param_model[key] = entries

    classes = [c for c in (data.get("classes") or []) if isinstance(c, str)]
    return {
        "v": SCHEMA_VERSION,
        "feature_version": hunt_features.FEATURE_VERSION,
        "created_at": str(data.get("created_at") or "unknown"),
        "classes": classes or sorted(weights),
        "bias": bias,
        "w": weights,
        "selectors": selectors,
        "param_model": param_model,
        "eval": data.get("eval") if isinstance(data.get("eval"), dict) else {},
    }


class Ranker:
    """A loaded, validated weight file. Immutable in practice; scoring never mutates it."""

    __slots__ = ("version_tag", "_classes", "_w", "_bias", "_param_model", "_selectors", "_eval")

    def __init__(self, payload: dict[str, Any]) -> None:
        # payload MUST have come through _coerce — the constructor deliberately trusts it so
        # there is exactly ONE validation path and no second, weaker one.
        self.version_tag: str = (
            f"hunt-ranker/{payload['v']}.{payload['feature_version']}@{payload['created_at']}"
        )
        self._classes: list[str] = list(payload["classes"])
        self._w: dict[str, dict[str, float]] = payload["w"]
        self._bias: dict[str, float] = payload["bias"]
        self._param_model: dict[str, list[tuple[str, float]]] = payload["param_model"]
        self._selectors: dict[str, tuple[float, dict[str, float]]] = payload["selectors"]
        self._eval: dict[str, Any] = payload["eval"]

    # --- introspection (the CLI's `--show` and the plan's provenance note) ---------------

    @property
    def classes(self) -> list[str]:
        return list(self._classes)

    @property
    def evaluation(self) -> dict[str, Any]:
        """The held-out recall@3 of the model AND of the rules baseline it had to beat.
        Reported verbatim; this module never computes or estimates a metric."""
        return dict(self._eval)

    # --- scoring ------------------------------------------------------------------------

    def score(self, class_id: str, feats: dict[str, float]) -> float:
        """P(this class confirms on this endpoint), in (0, 1).

        A class with NO trained block scores 0.5 — the neutral sigmoid of z=0, i.e. "the
        model has no opinion" — never 0.0. Scoring an unknown class as zero would sink every
        class the corpus has not seen yet below every class it has, which is precisely the
        absent-is-not-neutral bug ``_reorder_by_priors`` was fixed for."""
        weights = self._w.get(class_id)
        if weights is None:
            return 0.5
        z = self._bias.get(class_id, 0.0)
        for name in sorted(feats):  # sorted: identical float sum regardless of caller dict order
            weight = weights.get(name)
            if weight is not None:
                z += weight * feats[name]
        return _sigmoid(z)

    def rank_endpoint_classes(
        self,
        url: str,
        query_names: list[str],
        recon_params: list[str],
        tech: str,
        candidates: list[str],
        priors: dict[str, float] | None = None,
    ) -> list[str]:
        """Reorder ``candidates`` most-likely-first. ALWAYS a permutation of the input.

        Total by construction: features are built once, every candidate is scored (an
        unknown class gets the neutral 0.5), the learned score is multiplied by the program's
        clamped learned prior, and the result is a STABLE sort — ties keep the caller's
        order, so the hand-tuned ordering survives wherever the model has nothing to say.
        Any unexpected failure returns the candidates untouched: degrading to the rules is
        always available and always safe."""
        ordered = [str(c) for c in (candidates or [])]
        if len(ordered) < 2:
            return ordered
        try:
            feats = hunt_features.endpoint_features(url, query_names, recon_params, tech)
            scored = [self.score(c, feats) * self._prior(priors, c) for c in ordered]
            index = sorted(range(len(ordered)), key=lambda i: (-scored[i], i))
            return [ordered[i] for i in index]
        except Exception:  # noqa: BLE001 - a ranking hint must never break a hunt; rules order is the floor
            return ordered

    @staticmethod
    def _prior(priors: dict[str, float] | None, class_id: str) -> float:
        """The program's learned reward multiplier for ``class_id``, clamped to [0.5, 2.0].

        ABSENT PRIOR == 1.0 (neutral), by construction: a class the program has never
        rewarded keeps its raw model score instead of being zeroed out. Corrupt persisted
        values degrade to neutral for the same reason."""
        if not priors:
            return 1.0
        try:
            value = float(priors.get(class_id, 1.0))
        except (TypeError, ValueError):
            return 1.0
        if not math.isfinite(value):
            return 1.0
        return _PRIOR_MIN if value < _PRIOR_MIN else (_PRIOR_MAX if value > _PRIOR_MAX else value)

    def suggest_params(self, bucket: str, tech: str, cap: int) -> list[str]:
        """Parameter NAMES this (purpose bucket, tech) has historically confirmed on, best
        first — the learned replacement for ``offline_hunt._SUGGEST``'s fixed 18 names.

        Names only, always; the caller still filters to names recon has not already found and
        re-validates every one through ``hunt_brain._validate_plan``. Falls back to the
        tech-agnostic row for the bucket, then to nothing — an empty list means "no learned
        opinion", and the caller keeps its curated list."""
        if cap <= 0:
            return []
        key = f"{str(bucket or 'other')}|{hunt_features.tech_key(tech)}"
        rows = self._param_model.get(key)
        if rows is None:
            rows = self._param_model.get(f"{str(bucket or 'other')}|none")
        if not rows:
            return []
        ranked = sorted(rows, key=lambda row: (-row[1], row[0]))
        return [name for name, _ in ranked[:cap]]

    def select(self, kind: str, feats: dict[str, float]) -> float:
        """P(this endpoint is worth an object-level (``idor``) / function-level
        (``privileged``) access-control probe). 0.5 == "no trained selector for this kind",
        which the caller reads as "fall back to the path/param heuristics"."""
        block = self._selectors.get(str(kind or ""))
        if block is None:
            return 0.5
        bias, weights = block
        z = bias
        for name in sorted(feats):
            weight = weights.get(name)
            if weight is not None:
                z += weight * feats[name]
        return _sigmoid(z)


def model_file(seed_dir: str | Path | None, runtime_dir: str | Path | None) -> Path | None:
    """The ACTIVE weight file, or None. Runtime (locally trained) wins over seed (bundled) —
    the same resolution order as ``toolkit._catalog_file``. Public so the CLI can tell the
    operator WHICH file is in force without loading it."""
    for base in (runtime_dir, seed_dir):
        if base is None:
            continue
        path = Path(base) / _SUBDIR / _FILENAME
        try:
            if path.is_file():
                return path
        except OSError:
            continue
    return None


def load_model(seed_dir: str | Path | None, runtime_dir: str | Path | None = None) -> Ranker | None:
    """Load + validate the active ranker, or return None to mean "use the rules".

    Never raises. Every rejection path is silent and total: missing file, unreadable file,
    truncated/invalid JSON, non-dict root, wrong kind, wrong schema version, wrong
    feature version, or any non-finite weight anywhere in the file."""
    path = model_file(seed_dir, runtime_dir)
    if path is None:
        return None
    key = str(path)
    try:
        stat = path.stat()
        mtime = (stat.st_mtime, stat.st_size)
    except OSError:
        return None
    cached = _CACHE.get(key)
    if cached and cached.get("_mtime") == mtime:
        return cached["model"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # JSONDecodeError is a ValueError
        return None
    payload = _coerce(data)
    if payload is None:
        return None
    model = Ranker(payload)
    _CACHE[key] = {"_mtime": mtime, "model": model}
    return model
