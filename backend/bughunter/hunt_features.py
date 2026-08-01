"""GreyIQ BugHunter — deterministic feature extractor for the offline hunt ranker.

Phase 1 of ``docs/offline-hunt-brain-distillation.md``. The offline hunt brain's job is
NOT language modeling: it SELECTS in-scope endpoints and RANKS a bounded class vocabulary.
That is structured prediction, so the whole learned layer needs exactly one thing from the
recon surface — a deterministic, value-free ``endpoint -> features`` map that can be
recomputed offline, months later, from a stored ``hunt_traces.jsonl`` line. This module is
that map, and nothing else: no I/O, no model, no scoring.

Two properties are load-bearing and both are tested:

  * DETERMINISM. The same endpoint always yields the same dict with the same key order.
    Training (``hunt_train``) recomputes features from each trace's own persisted surface,
    so a non-deterministic extractor would silently retrain a different model from the
    same corpus and make the promotion gate's numbers meaningless.
  * NO VALUES, EVER. A feature string may contain a parameter NAME, a path token, a tech
    key or a bare keyword — never a parameter VALUE. ``?token=s3cret`` must produce
    ``param:name=token`` and must never, anywhere, produce ``s3cret``. Weight files are
    plain JSON that an operator can grep, diff and hand-audit, and they are derived from
    hunts against real authorized targets; a value in a feature name would turn the model
    file into an exfiltration channel for the very secrets ``hunt_trace`` redacts.

The features are SPARSE and NAMED (string -> float, almost always 1.0) rather than a dense
vector, so ``hunt_ranker.json`` reads as ``{"path:kw=search": 0.84}`` — auditable by eye and
diffable across retrains. The hand-tuned tables in ``offline_hunt`` (the path keywords
``_classes_for_endpoint`` tests, the eight parameter hint lists, ``_TECH_CLASS``, the
numeric/uuid segment shapes) are imported and emitted AS INPUTS. The learned model's
competitor is not the knowledge base — it is the fixed, hand-guessed ORDER the knowledge
base is applied in. The model gets to learn the interactions a flat hint list cannot express
(``id`` param x PHP x ``/search`` -> SQLi), which is the entire capability claim.

``FEATURE_VERSION`` is part of the on-disk model contract: ``hunt_model.load_model`` refuses
any weight file whose ``feature_version`` differs, because weights indexed by a namespace
this module no longer emits are silently wrong rather than loudly broken. Change a namespace,
bump the version, retrain.

Imports of ``offline_hunt`` / ``hunt_brain`` are LAZY (inside the functions, cached in module
globals). ``offline_hunt`` is the consumer of the learned ranker, so a module-level import
here would close an import cycle; ``hunt_brain`` additionally drags the coder stack in, which
must stay off the offline hunt path. Pure stdlib otherwise — this runs inside the frozen exe
with no toolchain and no network.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

# Bumped whenever a NAMESPACE changes (a new/renamed/removed feature family). Weight files
# carry this number and are rejected on mismatch — see hunt_model.load_model.
FEATURE_VERSION = 1

# Hard ceiling on the features one endpoint may emit. Bounds both the training cost and the
# blast radius of a pathological recon URL (a 4 KB path with 300 segments). Truncation is
# applied to the SORTED key list, so it is deterministic; note the consequence — sorted order
# is bias < form: < param: < path: < shape: < tech:, so a truncated endpoint loses its tech
# one-hots first and always keeps `bias`. The per-namespace sub-caps below keep real-world
# endpoints far under the ceiling, so truncation is a safety valve, not a normal path.
MAX_FEATURES = 64

_MAX_PATH_SEGS = 12       # camelCase-split path tokens
_MAX_PARAM_NAMES = 12     # query-string names (the interaction signal)
_MAX_FORM_FIELDS = 12     # form field names
_MAX_NAME_LEN = 40        # per-name character cap inside a feature string

# The exact path keywords `offline_hunt._classes_for_endpoint` already tests, in its own
# order. Emitting them as features hands the model the hand-tuned knowledge as INPUT.
_PATH_KEYWORDS: tuple[str, ...] = (
    "redirect", "login", "logout", "sso", "oauth", "auth", "callback",
    "download", "file", "attachment", "export", "include", "template", "view",
    "search", "query", "find", "lookup",
    "admin", "internal", "exec", "run", "cmd", "ping", "convert", "import",
    "api", "graphql", "json", "actuator", "jolokia", "ws", "token", "env", "upload",
)

# purpose_bucket vocabulary, in PRECEDENCE order: the first bucket whose cues appear in the
# path wins. Declaration order IS the tie-break rule, so `/admin/login` buckets as `auth`
# (what the endpoint DOES) rather than `admin` (where it lives). Fixed and documented because
# the bucket is a persisted key in the param model (`"download|php"`).
_BUCKET_CUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("auth", ("login", "logout", "signin", "sign-in", "sso", "oauth", "auth", "session",
              "password", "passwd", "register", "signup", "reset", "callback", "token")),
    ("download", ("download", "attachment", "export", "file", "document", "media",
                  "upload", "import", "backup")),
    ("search", ("search", "query", "find", "lookup", "filter", "autocomplete", "suggest")),
    ("api", ("/api", "graphql", ".json", "/v1/", "/v2/", "/v3/", "/rest", "/rpc",
             "actuator", "jolokia", "/ws")),
    ("admin", ("admin", "internal", "manage", "console", "dashboard", "staff", "moderat",
               "superuser", "config", "settings", "audit")),
    ("render", ("template", "render", "view", "preview", "theme", "layout", "report",
                "print", "page")),
)

# Characters a NAME may contribute to a feature string. Everything else is dropped rather
# than escaped: a feature key is an identifier, not a payload carrier, and a permissive key
# would let a hostile parameter name inject `=` / newlines into an auditable weight file.
_NAME_SAFE_RE = re.compile(r"[^a-z0-9_.\-]+")
_EXT_RE = re.compile(r"\.([a-z0-9]{1,8})$")

# Lazily bound intra-repo tables (see the module docstring on why these cannot be top-level).
_HINT_TABLES: tuple[tuple[str, tuple[str, ...]], ...] | None = None
_TECH_KEYS: tuple[str, ...] | None = None


def _hint_tables() -> tuple[tuple[str, tuple[str, ...]], ...]:
    """The eight ``offline_hunt`` parameter hint lists, labeled and in a FIXED order.

    Compressing eight curated tables into eight boolean inputs is the point: the model
    learns how much each table is worth on THIS program instead of the flat, equal,
    hand-assumed weighting ``_classes_for_endpoint`` gives them."""
    global _HINT_TABLES
    if _HINT_TABLES is None:
        from bughunter import offline_hunt

        _HINT_TABLES = (
            ("ssrf", offline_hunt._SSRF_HINTS),
            ("xss", offline_hunt._XSS_HINTS),
            ("redirect", offline_hunt._REDIRECT_HINTS),
            ("rce", offline_hunt._RCE_HINTS),
            ("traversal", offline_hunt._TRAVERSAL_HINTS),
            ("ssti", offline_hunt._SSTI_HINTS),
            ("sqli", offline_hunt._SQLI_HINTS),
            ("idor", offline_hunt._IDOR_PARAM_HINTS),
        )
    return _HINT_TABLES


def _tech_keys() -> tuple[str, ...]:
    """``offline_hunt._TECH_CLASS`` keys in declaration order (php, flask, wordpress, ...)."""
    global _TECH_KEYS
    if _TECH_KEYS is None:
        from bughunter import offline_hunt

        _TECH_KEYS = tuple(offline_hunt._TECH_CLASS)
    return _TECH_KEYS


def _path_of(url: Any) -> str:
    """The path component of ``url``, or '' — total, because recon endpoints reach here
    straight off a stored trace line and a malformed one must not abort a whole retrain."""
    try:
        return urlparse(str(url or "")).path or ""
    except ValueError:
        return ""


def _norm_name(value: Any) -> str:
    """Lowercase a parameter/field NAME down to the safe feature alphabet, capped."""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    return _NAME_SAFE_RE.sub("", raw)[:_MAX_NAME_LEN]


def query_names(url: Any) -> list[str]:
    """The query-string parameter NAMES of ``url`` (never the values), in URL order.

    Mirrors ``offline_hunt._endpoint_params`` so the learned path and the rules path read
    the same names off the same endpoint; exposed publicly because both ``hunt_train`` and
    ``offline_hunt``'s ranker call site need it."""
    try:
        return [k for k, _ in parse_qsl(urlparse(str(url or "")).query, keep_blank_values=True) if k]
    except ValueError:
        return []


def tech_key(tech: Any) -> str:
    """Fold a whole tech-fingerprint string onto ONE ``_TECH_CLASS`` key, or ``"none"``.

    The param model is keyed ``"<bucket>|<tech>"``; a single key keeps that table small
    enough to stay a frequency table rather than a sparse desert. First match in
    ``_TECH_CLASS`` declaration order wins, which is fixed and therefore reproducible."""
    low = str(tech or "").lower()
    for key in _tech_keys():
        if key in low:
            return key
    return "none"


def purpose_bucket(url: Any) -> str:
    """Coarse purpose of an endpoint: auth | download | search | api | admin | render | other.

    Used as the conditioning key of the learned param-name model (3b in the distillation
    plan): ``P(param name | purpose bucket, tech)``. Derived from the path ONLY — never from
    a query value — so it is stable across two hunts of the same endpoint."""
    low = _path_of(url).lower()
    if not low:
        return "other"
    for bucket, cues in _BUCKET_CUES:
        if any(cue in low for cue in cues):
            return bucket
    return "other"


def endpoint_features(
    url: str,
    query_names: list[str],
    recon_params: list[str],
    tech: str,
    form: dict[str, Any] | None = None,
) -> dict[str, float]:
    """The sparse, named, VALUE-FREE feature map for one endpoint.

    ``query_names`` are the endpoint's own query parameter names, ``recon_params`` the whole
    surface's discovered names, ``tech`` the joined tech fingerprint string, ``form`` the
    ``{method, params}`` record when this endpoint is a form action. Every argument is
    tolerated in a malformed shape (``None``, a non-list, a dict of junk): this runs over
    operator-local trace lines during training and inside a live hunt, and neither may crash
    on one bad row.

    Namespaces (see the module docstring): ``bias``, ``path:kw=``, ``path:seg=``,
    ``path:depth=``, ``path:ext=``, ``shape:``, ``param:hint=``, ``param:name=``, ``tech:``,
    ``form:method=``, ``form:field=``. Returned in sorted key order, truncated to
    ``MAX_FEATURES``."""
    from bughunter.hunt_brain import _signal_words  # lazy: hunt_brain pulls in the coder stack
    from bughunter import offline_hunt

    feats: dict[str, float] = {"bias": 1.0}
    path = _path_of(url)
    low = path.lower()

    # --- path shape ---------------------------------------------------------------------
    for keyword in _PATH_KEYWORDS:
        if keyword in low:
            feats[f"path:kw={keyword}"] = 1.0
    for token in sorted(_signal_words(path))[:_MAX_PATH_SEGS]:
        safe = _norm_name(token)
        if safe:
            feats[f"path:seg={safe}"] = 1.0
    depth = len([seg for seg in low.split("/") if seg])
    feats[f"path:depth={depth if depth < 3 else '3plus'}"] = 1.0
    last = low.rsplit("/", 1)[-1]
    ext = _EXT_RE.search(last)
    if ext:
        feats[f"path:ext={ext.group(1)}"] = 1.0
    # Matched against the PATH, not the whole URL, so a digit sequence inside a query VALUE
    # can never flip an object-shape feature. This is the IDOR/BOLA signal.
    if offline_hunt._NUMERIC_SEG_RE.search(path):
        feats["shape:numeric_seg"] = 1.0
    if offline_hunt._UUID_SEG_RE.search(path):
        feats["shape:uuid_seg"] = 1.0

    # --- parameter names ----------------------------------------------------------------
    own: list[str] = []
    for name in query_names if isinstance(query_names, (list, tuple)) else []:
        safe = _norm_name(name)
        if safe and safe not in own:
            own.append(safe)
    surface: list[str] = []
    for name in recon_params if isinstance(recon_params, (list, tuple)) else []:
        safe = _norm_name(name)
        if safe and safe not in surface:
            surface.append(safe)
    every = own + [n for n in surface if n not in own]
    for label, table in _hint_tables():
        if any(offline_hunt._hit(name, table) for name in every):
            feats[f"param:hint={label}"] = 1.0
    # Only the endpoint's OWN query names become identity features. The surface-wide list is
    # the same on every endpoint of a hunt, so it carries no per-endpoint signal and would
    # only dilute the model with a constant.
    for name in sorted(own)[:_MAX_PARAM_NAMES]:
        feats[f"param:name={name}"] = 1.0

    # --- tech stack ---------------------------------------------------------------------
    tech_low = str(tech or "").lower()
    present = [key for key in _tech_keys() if key in tech_low]
    for key in present:
        feats[f"tech:{_norm_name(key)}"] = 1.0
    if not present:
        # An explicit "we fingerprinted nothing" one-hot. Without it, an unfingerprinted
        # endpoint is indistinguishable from one whose tech features were truncated away.
        feats["tech:none"] = 1.0

    # --- form cues ----------------------------------------------------------------------
    if isinstance(form, dict):
        method = _norm_name(str(form.get("method") or "GET"))[:10]
        if method:
            feats[f"form:method={method}"] = 1.0
        fields: list[str] = []
        raw_fields = form.get("params")
        for name in raw_fields if isinstance(raw_fields, (list, tuple)) else []:
            safe = _norm_name(name)
            if safe and safe not in fields:
                fields.append(safe)
        for name in sorted(fields)[:_MAX_FORM_FIELDS]:
            feats[f"form:field={name}"] = 1.0

    return {key: feats[key] for key in sorted(feats)[:MAX_FEATURES]}
