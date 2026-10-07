"""Offline hunt intelligence — the no-LLM hunt brain.

TinyGPT (the tiny, well-under-10M-param char-level model) is far too small to reason about vulnerability classes or
emit the structured guidance the hunt needs, so the OFFLINE path (no Claude/Ollama configured) used to
get an EMPTY plan — it hunted blind. ``offline_plan`` fills that: it produces the SAME plan shape
``hunt_brain.plan_hunt`` does (param_hypotheses / probe_priority / ssrf_params / xss_params /
idor_candidates), derived from curated bug-bounty KNOWLEDGE RULES over the recon surface and SHARPENED
by what the program has actually confirmed before (``learning.learned_priors``). No LLM, no network.

An OPTIONAL learned ranker (``hunt_model``, loaded from a local weight file) may be passed in to
reorder the rule-proposed classes on each endpoint. It is a strict permutation seam — see ``_rank``
— so an absent, stale, or corrupt model degrades to exactly the hand-tuned rule ordering, and the
class VOCABULARY itself is pinned to ``prover_classes.PROVER_CLASSES``: the offline brain can never
propose a class the deterministic prover has no check for.

SAFETY: identical to the LLM brain's contract — it only ever emits parameter NAMES, verbatim in-scope
endpoint selections, and class orderings. Every one is re-validated by hunt_brain._validate_plan and
executed by the deterministic, scope+SSRF-gated prover, which owns every confirmation. It can raise
recall, never precision.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from bughunter.prover_classes import PROVER_CLASSES

# param-name substring -> the vuln class it most likely feeds. Ordered by specificity in _classify.
_SSRF_HINTS = ("url", "uri", "dest", "target", "callback", "webhook", "image", "avatar", "photo", "feed",
               "rss", "proxy", "fetch", "load", "site", "link", "source", "remote", "xml", "endpoint",
               "redirect_uri", "return_to", "continue", "domain", "host", "server", "upload",
               "notify", "connect")
_XSS_HINTS = ("q", "s", "query", "search", "keyword", "term", "name", "title", "message", "comment",
              "text", "body", "content", "desc", "subject", "error", "msg", "lang", "return", "ref",
              "html", "note", "reply")
_REDIRECT_HINTS = ("redirect", "next", "return", "url", "goto", "dest", "continue", "target", "back", "callback")
_RCE_HINTS = ("cmd", "exec", "command", "ping", "host", "ip", "run", "shell", "exe", "system", "func")
_TRAVERSAL_HINTS = ("file", "path", "page", "include", "doc", "document", "download", "attachment", "dir",
                    "folder", "load", "read", "view", "template", "img", "export", "resource")
_SSTI_HINTS = ("template", "tpl", "render", "theme", "view", "layout", "format", "pattern")
_SQLI_HINTS = ("id", "user", "uid", "order", "sort", "filter", "category", "cat", "product", "item",
               "search", "query", "num", "page", "select", "where", "column", "field", "code")
_IDOR_PARAM_HINTS = ("id", "user_id", "userid", "uid", "account", "account_id", "order", "order_id",
                     "invoice", "customer", "profile", "doc_id", "file_id", "record", "object",
                     "uuid", "guid", "reference")

# tech fingerprint -> classes to boost (a rendering/interpreter stack implies its injection surface).
_TECH_CLASS = {
    "flask": ("ssti",), "django": ("ssti",), "jinja": ("ssti",), "twig": ("ssti",), "php": ("rce", "sqli"),
    "wordpress": ("sqli", "xss"), "express": ("nosqli",), "node": ("nosqli",), "mongo": ("nosqli",),
    "asp.net": ("host-header",), "rails": ("ssti",), "graphql": ("nosqli",), "spring": ("ssti", "path-traversal"),
}

_NUMERIC_SEG_RE = re.compile(r"/\d+(?:/|$)")
_UUID_SEG_RE = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:/|$)")
# path substrings that mark an ADMIN / privileged FUNCTION worth a dual-session BFLA check (is the
# privileged action reachable by a low-privilege session?). Distinct from IDOR — this is function-level.
_PRIV_PATH_HINTS = ("/admin", "/internal", "/manage", "/moderat", "/staff", "/superuser", "/root/",
                    "/console", "/dashboard/admin", "/settings", "/config", "/audit", "/approve",
                    "/promote", "/grant", "/role", "/permission", "/impersonat", "/billing", "/payout")
# Membership gate for ``add()`` below — a rule may only propose a class the deterministic prover can
# actually CONFIRM. This used to be a hand-maintained 10-tuple that drifted behind the prover's real
# 18 tags, which silently made jwt/graphql/debug/websocket/sensitive/cloud-exposure/csrf/clickjacking
# unreachable from the offline path. Deriving it mechanically closes that hole and keeps it closed.
# Membership only: this set has NO bearing on ordering (the cue order in _classes_for_endpoint does).
_ACTIVE_CLASSES = PROVER_CLASSES
# param-name substrings that mark a bearer/session token worth a JWT signature-bypass probe.
_JWT_HINTS = ("token", "jwt", "bearer", "id_token", "access_token", "refresh", "assertion", "session")
_CAP = 24
# probe_priority is HARD-CAPPED (the prover spends its request budget walking this list in order), so
# the cap is a zero-sum contest between endpoints — a fact the widened class vocabulary made load-
# bearing. Endpoints that previously produced ZERO classes were skipped entirely and consumed no
# slot; now they qualify, and in raw discovery order a run of low-signal endpoints (ten /ws/* rooms
# scoring only ``websocket``) could occupy the whole cap and evict already-planned high-signal ones
# (fifteen /download?file= path-traversal candidates). Added recall must never cost existing recall,
# so the cap now keeps the HIGHEST-SIGNAL endpoints instead of the first ones encountered.
_MAX_PRIORITY = 20
# Per-class signal weight: what a probe-budget slot spent on this class is worth, as severity x how
# directly a recon cue evidences it. Injection classes with a concrete injectable parameter rank
# above path-shape "this looks like an X surface" cues, which rank above header/config observations.
# Values are ordinal only — nothing reads them as a probability, and no output claims a likelihood.
# Completeness against PROVER_CLASSES is asserted by test_offline_hunt so a newly provable class
# cannot silently inherit the neutral default.
_CLASS_SIGNAL: dict[str, int] = {
    "rce": 100, "sqli": 92, "ssti": 90, "path-traversal": 88, "nosqli": 84,
    "sensitive": 80, "debug": 78, "xss": 70, "redirect": 66, "jwt": 64,
    "graphql": 60, "cloud-exposure": 56, "crlf": 50, "host-header": 48,
    "csrf": 44, "cors": 40, "websocket": 34, "clickjacking": 20,
}
# An unweighted class is treated as MID signal — never silently buried, never silently promoted.
# Guessing high or low here would be asserting a ranking we cannot observe.
_DEFAULT_CLASS_SIGNAL = 50
# Ordered deliberately: plans are persisted as training traces, so the cold-start
# corpus must not change merely because Python chose a different set hash order.
_SUGGEST = (
    "url", "redirect", "next", "callback", "file", "path", "id", "q", "search", "template",
    "image_url", "webhook", "return", "dest", "user_id", "order_id", "cmd", "page",
)


def _hit(name: str, hints: tuple[str, ...]) -> bool:
    low = name.lower()
    return any(h in low for h in hints)


def admin_path_endpoints(urls: list[str], cap: int = 8) -> list[str]:
    """The subset of ``urls`` whose PATH looks like an ADMIN / privileged FUNCTION (/admin, /internal,
    /manage, /role, /permission, /settings, /config, /audit, ...) — the deterministic, recon-derived
    feed for the dual-account BFLA prover, so it fires on privileged endpoints the recon surface
    revealed even when no reasoning brain flagged them. Verbatim in-scope URLs only (each is copied
    from the discovered set), deduped and capped. This only raises RECALL: the prover's three-session
    admin/user/anon gate still owns the confirm, and a non-privileged pick fails its anon-denied control."""
    out: list[str] = []
    for u in urls:
        url = str(u or "").strip()
        if not url:
            continue
        try:
            low_path = urlparse(url).path.lower()
        except ValueError:
            continue
        if any(h in low_path for h in _PRIV_PATH_HINTS) and url not in out:
            out.append(url)
        if len(out) >= cap:
            break
    return out


def _endpoint_params(url: str) -> list[str]:
    try:
        return [k for k, _ in parse_qsl(urlparse(url).query) if k]
    except ValueError:
        return []


def _classes_for_endpoint(url: str, names: list[str], tech_boost: tuple[str, ...]) -> list[str]:
    """The vuln classes worth prioritising on ONE endpoint, most-likely first — from its path shape,
    its parameter names, and the observed tech stack."""
    path = urlparse(url).path.lower()
    classes: list[str] = []

    def add(c: str) -> None:
        if c in _ACTIVE_CLASSES and c not in classes:
            classes.append(c)

    # path-shape cues (high signal)
    if any(k in path for k in ("redirect", "login", "logout", "sso", "oauth", "auth", "callback")):
        add("redirect")
    if any(k in path for k in ("download", "file", "attachment", "export", "include", "template", "view")):
        add("path-traversal")
    if any(k in path for k in ("search", "query", "find", "lookup")):
        add("xss"); add("sqli")
    if any(k in path for k in ("admin", "internal", "exec", "run", "cmd", "ping", "convert", "import")):
        add("rce")
    if "/api" in path or "graphql" in path or path.endswith(".json"):
        add("cors")
    # parameter-name cues
    for n in names:
        if _hit(n, _RCE_HINTS): add("rce")
        if _hit(n, _TRAVERSAL_HINTS): add("path-traversal")
        if _hit(n, _SSTI_HINTS): add("ssti")
        if _hit(n, _REDIRECT_HINTS): add("redirect")
        if _hit(n, _SQLI_HINTS): add("sqli")
        if _hit(n, _XSS_HINTS): add("xss")
        if _hit(n, _SSRF_HINTS): add("redirect")  # ssrf isn't a verify_active class; its url-params also feed redirect
    for c in tech_boost:
        add(c)
    # Prover classes the rules could not reach before (the vocabulary was capped at 10 while the
    # prover grew to 18). Appended LAST, after every pre-existing cue, so the first six entries of any
    # endpoint that already produced six are byte-identical to before this change — plans are
    # persisted as training traces (see _SUGGEST's note), so a reordering here would silently
    # invalidate the cold-start corpus. Only endpoints that previously produced FEWER than six
    # classes gain anything.
    #
    # Per-endpoint that is pure gain; PLAN-wide it is not, because probe_priority is capped. An
    # endpoint that used to produce ZERO classes was skipped and consumed no slot, and now competes
    # for one. That is why the cap is applied to a SIGNAL-RANKED list (_priority_sort_key) rather
    # than to discovery order — see _MAX_PRIORITY.
    if "graphql" in path:
        add("graphql")
    if any(k in path for k in ("/actuator", "/jolokia", "heapdump", "/debug", "/trace", "/env", "/metrics")):
        add("debug")
    if any(k in path for k in ("/ws", "/socket.io", "/cable", "/websocket")):
        add("websocket")
    if any(k in path for k in ("/token", "/oauth", "/jwt", "/session", "/refresh", "/login")) or any(_hit(n, _JWT_HINTS) for n in names):
        add("jwt")
    if any(k in path for k in ("/.git", "/.env", "/backup", "/.svn", "/dump", "/.well-known")):
        add("sensitive")
    if any(k in path for k in ("/upload", "/s3", "/blob", "/bucket", "/storage", "/cdn", "/media")):
        add("cloud-exposure")
    if any(k in path for k in ("/account", "/profile", "/password", "/email", "/delete", "/transfer", "/invite")):
        add("csrf")
    return classes[:6]


def _reorder_by_priors(classes: list[str], priors: dict[str, float] | None) -> list[str]:
    """Stable-sort a class list so the classes the program has REWARDED before come first — the
    learning signal. Ties keep the knowledge order."""
    if not priors:
        return classes

    def weight(class_id: str) -> float:
        # learned_priors are multipliers around a neutral 1.0. Treating an unseen
        # class as 0.0 accidentally promoted a known-noisy 0.5 class above every
        # unseen class. Corrupt persisted values also degrade to neutral.
        try:
            return float(priors.get(class_id, 1.0))
        except (TypeError, ValueError):
            return 1.0

    return sorted(classes, key=lambda c: -weight(c))


def _rank(candidates: list[str], priors: dict[str, float] | None, model: Any | None,
          url: str, names: list[str], recon: list[str], tech: str,
          form: dict[str, Any] | None = None) -> list[str]:
    """Order the candidate classes for ONE endpoint — the single seam a learned ranker may occupy.

    The model may only PERMUTE ``candidates``. A returned value that is not a permutation of exactly
    what the rules proposed is DISCARDED and the deterministic prior ordering is used instead, so a
    corrupt, stale, or hostile weight file can never add, drop, or invent a class — the worst it can
    do is order the same allowlisted classes badly, which costs a little request budget and nothing
    else (the prover still owns every confirmation). ``model=None`` is exactly today's behaviour.

    The narrow ``rank_endpoint_classes`` call keeps ALL feature extraction inside the model module,
    which is what lets this file stay on its ``re``/``typing``/``urllib.parse`` import set.
    """
    if model is None:
        return _reorder_by_priors(candidates, priors)
    try:
        ranked = list(model.rank_endpoint_classes(url, names, recon, tech, list(candidates), priors,
                                                  form=form))
    except Exception:  # noqa: BLE001 - a corrupt model must never break the offline plan
        return _reorder_by_priors(candidates, priors)
    if sorted(ranked) != sorted(candidates):  # not a permutation -> the model invented/dropped a class
        return _reorder_by_priors(candidates, priors)
    return ranked


def _learned_params(model: Any | None, url: str, tech: str, cap: int) -> list[str]:
    """Parameter NAMES the learned table has historically confirmed for this endpoint's purpose.

    ``gn train-brain`` distils this table from the program's own CONFIRMED hunts and promotes it into
    ``hunt_ranker.json`` — and until now nothing at hunt time ever read it, so two of the three things
    the trainer learns were dead weight and what the engine discovered about its own targets never
    reached the next hunt.

    Fail-open to nothing: no model, no learned opinion, or any error yields ``[]`` and the caller
    keeps its curated list, so recall cannot drop. Names only; ``hunt_brain._validate_plan`` still
    re-checks every one against the parameter-name regex before it can reach the prober."""
    if model is None:
        return []
    try:
        return [str(n) for n in model.suggest_params_for_endpoint(url, tech, cap)]
    except Exception:  # noqa: BLE001 - a corrupt model must never break the offline plan
        return []


def _model_selects(model: Any | None, kind: str, url: str, names: list[str],
                   recon: list[str], tech: str, form: dict[str, Any] | None) -> bool:
    """Does the learned selector want an object- (``idor``) or function-level (``privileged``) probe?

    COMPLEMENTS the path/param heuristics — it can only ADD a candidate the rules missed, never
    remove one they found — so a program whose confirmed IDORs never matched ``_IDOR_PARAM_HINTS``
    can still teach the engine what its own object endpoints look like. Pure selection over endpoints
    recon already discovered in scope; the prover re-gates scope and SSRF regardless."""
    if model is None:
        return False
    try:
        return bool(model.selects_endpoint(kind, url, names, recon, tech, form))
    except Exception:  # noqa: BLE001 - fall back to the heuristics, never break a hunt
        return False


def _priority_sort_key(row: dict[str, Any], index: int) -> tuple[int, int, int]:
    """Rank ONE probe_priority row for the hard cap: strongest class, then breadth, then discovery.

    The key is deliberately PERMUTATION-INVARIANT in the row's class list (``max`` and ``len`` both
    are), so neither the learned ranker nor the learned priors — which may only reorder classes
    WITHIN an endpoint (see ``_rank``) — can change WHICH endpoints survive the cap. Endpoint
    selection stays rule-owned, exactly as the ranker seam's contract promises.

    ``index`` (the endpoint's discovery position) is the final tie-break, which makes the ordering
    TOTAL and STABLE: two runs over the same surface produce byte-identical plans. That matters
    beyond aesthetics — plans are persisted verbatim as training traces, and a non-total order would
    let a set/dict hash reshuffle the cold-start corpus between runs.
    """
    classes = row.get("classes") or []
    strongest = max((_CLASS_SIGNAL.get(c, _DEFAULT_CLASS_SIGNAL) for c in classes), default=0)
    return (-strongest, -len(classes), index)


def offline_plan(surface: dict[str, Any], priors: dict[str, float] | None = None, *,
                 model: Any | None = None) -> dict[str, Any]:
    """Produce a hunt plan (same shape as hunt_brain.plan_hunt) from knowledge rules + learned priors.
    ``surface`` = {endpoints, params, tech, forms}; ``priors`` = learning.learned_priors (class->weight).

    ``probe_priority`` is returned STRONGEST-ENDPOINT-FIRST and capped at ``_MAX_PRIORITY``: the
    prover walks it in order, so the cap must keep the highest-signal endpoints rather than the
    first ones recon happened to discover.

    ``model`` is an OPTIONAL learned ranker (hunt_model). It is keyword-only and defaults to None so
    every existing caller keeps byte-identical behaviour. It occupies exactly three seams, all of
    them ADDITIVE and all of them re-validated downstream by ``hunt_brain._validate_plan``:

      * per-endpoint class ORDER — it may only permute what the rules proposed (see ``_rank``);
      * ``param_hypotheses`` — learned names lead, the curated ``_SUGGEST`` list still follows, so an
        empty learned table changes nothing and recall cannot drop;
      * ``idor_candidates`` / ``privileged_endpoints`` — OR'd with the path/param heuristics, so the
        selector can only ADD an endpoint whose shape the hand-written hints miss, never remove one.

    It still cannot decide WHICH ENDPOINTS SURVIVE the probe cap: ``_priority_sort_key`` stays
    permutation-invariant, so endpoint selection remains rule-owned. Nor can it introduce an endpoint
    — every candidate is drawn from the discovered in-scope set — or confirm anything, because the
    deterministic prover still owns every confirmation."""
    endpoints = [str(u).strip() for u in (surface.get("endpoints") or []) if str(u or "").strip()]
    recon_params = {str(p).strip().lower() for p in (surface.get("params") or []) if str(p or "").strip()}
    tech = " ".join(str(t) for t in (surface.get("tech") or [])).lower()
    # Keyed by form action, EXACTLY as hunt_train._collect keys it -- the learned ranker is fitted
    # on the form:* feature namespace, so the serving path has to be able to produce it too.
    # SANITISED on the way in: only the method and the field NAMES cross the seam, never a field
    # VALUE. hunt_features reads nothing else, and the seam's contract is that a weight file --
    # possibly stale or hostile -- is handed no page content.
    forms_by_action: dict[str, dict[str, Any]] = {}
    for _form in (surface.get("forms") or []):
        if not isinstance(_form, dict):
            continue
        _action = str(_form.get("action") or "").strip()
        if not _action or _action in forms_by_action:
            continue
        _fields = _form.get("params")
        forms_by_action[_action] = {
            "method": str(_form.get("method") or "GET"),
            "params": [str(f) for f in _fields] if isinstance(_fields, list) else [],
        }
    tech_boost = tuple(dict.fromkeys(c for key, cs in _TECH_CLASS.items() if key in tech for c in cs))

    ssrf_params: list[str] = []
    xss_params: list[str] = []
    param_hypotheses: list[str] = []
    idor_candidates: list[str] = []
    privileged_endpoints: list[str] = []
    # Model-selected candidates, kept apart so the rule-derived ones above always win the capped
    # slots and the learned selector can only ever fill what the rules left unused.
    model_idor: list[str] = []
    model_priv: list[str] = []
    priority: list[dict[str, Any]] = []
    seen_pri: set[str] = set()

    # A curated set of high-yield param names to TRY even when recon didn't surface them — the offline
    # analogue of the LLM proposing param_hypotheses. Only NEW names (not already discovered) are added.
    for url in endpoints[:60]:
        names = _endpoint_params(url) or []
        # Match the parameter cues against THIS endpoint's own inputs — its query names plus, when it is
        # a form action, that form's fields. It used to be `names + sorted(recon_params)`: the whole
        # HOST's recon params, the same list for every endpoint. That made the per-endpoint ranking
        # meaningless, and because _classes_for_endpoint caps at six classes and appends the
        # newly-reachable ones LAST, the shared params saturated every slot and truncated them away.
        #
        # Measured on a surface of ten /ws/room-N plus fifteen /download?file= endpoints with twelve
        # ordinary host params: all twenty rows collapsed to just TWO distinct class-sets, `websocket`
        # never appeared on the websocket endpoints at all, and because every score was identical the
        # _MAX_PRIORITY cap broke the tie by discovery order — evicting five /download?file= endpoints
        # in favour of ws rooms. Own-params only restores path-traversal as the top class on the
        # download endpoints and keeps all fifteen.
        #
        # The host-wide list is NOT lost, and no coverage is dropped. _rank still receives it
        # separately, so the learned ranker keeps that feature; and the prover gets the same list as
        # `extra_params`, where active_verify_service._candidate_params unions it into EVERY
        # param-keyed check on EVERY endpoint. So a name discovered on one endpoint is still TRIED on
        # the others — it just no longer votes on which CLASS that other endpoint looks like. Only the
        # ORDER the prover spends its budget in changes, which is the one thing this ranking is for.
        _own_form = forms_by_action.get(url) or {}
        own = names + [str(field) for field in (_own_form.get("params") or []) if str(field or "").strip()]
        candidates = _classes_for_endpoint(url, own, tech_boost)
        classes = _rank(candidates, priors, model, url, names, sorted(recon_params), tech,
                        forms_by_action.get(url))
        if classes and url not in seen_pri:
            seen_pri.add(url)
            priority.append({"endpoint": url, "classes": classes})
        # object-scoped endpoint -> IDOR candidate. Model picks go in a SEPARATE list because both
        # are capped at six and filled in discovery order, so a model firing early would crowd out
        # a rule hit found later — removal by the back door, when the selector may only add. Rule
        # hits claim their slots at the return; the model fills what is left.
        _form = forms_by_action.get(url)
        _recon = sorted(recon_params)
        if _NUMERIC_SEG_RE.search(url) or _UUID_SEG_RE.search(url) or any(_hit(n, _IDOR_PARAM_HINTS) for n in names):
            if url not in idor_candidates:
                idor_candidates.append(url)
        elif url not in model_idor and _model_selects(model, "idor", url, names, _recon, tech, _form):
            model_idor.append(url)
        # admin / privileged FUNCTION path -> BFLA candidate (function-level, not object-level)
        low_path = urlparse(url).path.lower()
        if any(h in low_path for h in _PRIV_PATH_HINTS):
            if url not in privileged_endpoints:
                privileged_endpoints.append(url)
        elif url not in model_priv and _model_selects(model, "privileged", url, names, _recon, tech, _form):
            model_priv.append(url)
        for n in names + list(recon_params):
            if _hit(n, _SSRF_HINTS) and n not in ssrf_params:
                ssrf_params.append(n)
            if _hit(n, _XSS_HINTS) and n not in xss_params:
                xss_params.append(n)

    # LEARNED names lead — they are the ones this program's confirmed hunts landed on, and leading
    # is what counts because each check applies its own small per-call param cap. But they are
    # capped at the slots _SUGGEST does not need: the result is truncated at _CAP, so an unbounded
    # learned table would push every curated name past the end and silently delete the hand-tuned
    # surface. Ordering wins; displacement does not.
    learned_slots = max(0, _CAP - len(_SUGGEST))
    learned_names: list[str] = []
    for url in endpoints[:60]:
        if len(learned_names) >= learned_slots:
            break
        for name in _learned_params(model, url, tech, learned_slots):
            if (name.lower() not in recon_params and name not in learned_names
                    and len(learned_names) < learned_slots):
                learned_names.append(name)
    for n in (*learned_names, *_SUGGEST):
        if n.lower() not in recon_params and n not in param_hypotheses:
            param_hypotheses.append(n)

    # Rank BEFORE truncating so the cap keeps the highest-signal endpoints rather than the first
    # ones discovered — see _MAX_PRIORITY. Ordering is total (discovery index breaks every tie), so
    # the plan stays byte-reproducible for the persisted training corpus.
    ranked_priority = [priority[i] for i in
                       sorted(range(len(priority)), key=lambda i: _priority_sort_key(priority[i], i))]

    return {
        "used": bool(endpoints), "provider": "offline", "model": "greyiq-offline-hunt",
        "param_hypotheses": param_hypotheses[:_CAP],
        "probe_priority": ranked_priority[:_MAX_PRIORITY],
        "ssrf_params": ssrf_params[:12],
        "xss_params": xss_params[:12],
        # Rule hits first, then the learned selector's picks into whatever slots remain — so the
        # selector adds and never displaces.
        "idor_candidates": (idor_candidates + [u for u in model_idor if u not in idor_candidates])[:6],
        "privileged_endpoints": (
            privileged_endpoints + [u for u in model_priv if u not in privileged_endpoints])[:6],
        # ``notes`` is persisted verbatim in the hunt trace, so the training corpus records WHICH
        # brain produced each plan. A model with no readable version tag is reported as
        # "undetermined" rather than guessed — an unlabelled corpus row is worse than an honest one.
        "notes": (f"offline knowledge-rule plan over {len(endpoints)} endpoint(s)"
                  + (" (sharpened by learned priors)" if priors else "")
                  + (f" +ranker {str(getattr(model, 'version_tag', '') or 'undetermined')[:40]}"
                     if model is not None else "")),
    }
