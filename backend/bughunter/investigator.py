"""Evidence-grounded investigation cortex shared by code, hunt, and report paths.

The cortex is deliberately deterministic.  A model or heuristic may create a
hypothesis, but this module never turns prose into proof.  It inventories typed
artifacts, calibrates confidence, calls out contradictions, correlates findings
into bounded attack-chain leads, and orders the next proof-gathering decisions.

The returned object is JSON-friendly and contains no raw credential values.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from bughunter import secret_classification


ALGORITHM_VERSION = "investigation-cortex-v1"

_MAX_HYPOTHESES = 200
_MAX_CHAINS = 16
# Derived (never observed) rows the synthesis pass may append to the probe queue.
_MAX_SYNTHESIZED = 6
# How many DISTINCT locations must share one class on one registrable domain before the engine
# will call it systemic rather than a run of unrelated findings. Two is a coincidence.
_SYSTEMIC_MIN_LOCATIONS = 3
# Classes too weak to carry a systemic conclusion: a missing header on nine routes is one server
# default, not a control that was designed and then forgotten on nine routes.
_NO_SYNTHESIS_CLASSES = frozenset({"headers", "unclassified", ""})
# Bound on the structured probe plan handed to an executor.
_MAX_PROBE_PLAN_ROWS = 40
_SEVERITY_VALUE = {"critical": 100, "high": 80, "medium": 58, "low": 32, "info": 10}
_CONFIDENCE_BASE = {"high": 54, "medium": 40, "low": 24, "unknown": 30, "": 30}
# A hypothesis reaches the "supported" band at this score; without an artifact the confirm
# gate accepts, the ceiling below keeps it one point short, so unproven evidence stays a lead.
_SUPPORTED_THRESHOLD = 55
_UNPROVEN_CONFIDENCE_CEILING = _SUPPORTED_THRESHOLD - 1
# Unproven scores are RESCALED into [0, ceiling] rather than clipped at it. Clipping made every
# lead score exactly the ceiling, which flattened the ranked queue into input order — ranking a
# missing header level with a captured stack trace, in the one situation ("nothing is confirmed
# yet, what do I chase?") the queue exists to answer. This is the top of the pre-scale range.
_UNPROVEN_SCORE_MAX = 104
# The report's proof vocabulary (report._CONFIRMED_PROOF_STATUSES / _CANDIDATE_PROOF_STATUSES).
_CONFIRMED_STATUS_WORDS = frozenset({"confirmed", "verified", "proven", "reproduced"})
_CANDIDATE_STATUS_WORDS = frozenset(
    {"candidate", "unverified", "partial", "needs_confirmation", "needs-confirmation"}
)
_CLASS_VALUE = {
    "rce": 10, "sqli": 9, "ssti": 9, "ssrf": 9, "xxe": 8,
    "access-control": 8, "auth": 8, "secrets": 8, "file-upload": 7,
    "jwt": 7, "nosqli": 7, "request-smuggling": 7, "graphql": 6,
    "path-traversal": 6, "supply-chain": 6, "xss": 5, "cors": 4,
    "redirect": 3, "csrf": 3, "disclosure": 3, "headers": 1,
}

_PROOF_OBLIGATIONS = {
    "access-control": "Replay the same object or function as a lower-privilege actor and capture an authorized-vs-unauthorized differential.",
    "auth": "Capture the complete authentication-state transition and a control showing the action is impossible without the weakness.",
    "cors": "Capture a real browser cross-origin read of authenticated sensitive data, plus a disallowed-origin control.",
    "csrf": "Capture a cross-site state change in a victim session and the unchanged control request.",
    "disclosure": "Capture the exact sensitive field or artifact returned to an unauthorized actor, with secrets redacted.",
    "graphql": "Show unauthorized object or field access across two roles and capture the response differential.",
    "jwt": "Replay the altered or exposed token successfully and capture the rejected control token.",
    "path-traversal": "Capture an allowed file read outside the intended root and a benign in-root control.",
    "rce": "Capture a harmless, unique execution marker and a control request without the injected input.",
    "redirect": "Capture the final off-origin Location/navigation and a same-origin control through the affected workflow.",
    "secrets": "Validate the credential against its issuer with the least-privileged safe call and record scope without storing the raw value.",
    "sqli": "Capture a stable true/false or error differential attributable to the input, without modifying data.",
    "ssrf": "Capture an authorized callback or internal-response differential tied uniquely to the tested request.",
    "ssti": "Capture a harmless deterministic expression result and a literal-text control.",
    "xss": "Capture execution in the real browser context and a safely encoded control value.",
    "xxe": "Capture an authorized out-of-band callback or harmless file-read differential and a parser control.",
}

_CLASS_ALIASES = {
    "open-redirect": "redirect", "command-injection": "rce", "cmd-injection": "rce",
    "os-command-injection": "rce", "sql-injection": "sqli", "nosql-injection": "nosqli",
    "template-injection": "ssti", "secret": "secrets", "credential": "secrets",
    "idor": "access-control", "bola": "access-control", "bfla": "access-control",
    "injection": "rce", "backdoor": "rce", "obfuscation": "rce",
    # Spelling drift, not a distinct class: the API-discovery detector reported GraphQL
    # introspection as "info-disclosure" while the active detector reported the SAME
    # vulnerability as "graphql". An unaliased id reaches no technique in the chain engine, so
    # the finding contributed nothing. The producers now agree; this alias is kept for stored
    # ledger/history rows that still carry the old id.
    "info-disclosure": "disclosure",
}

_RULE_CLASS_HINTS: tuple[tuple[str, str], ...] = (
    ("command", "rce"), ("cmd", "rce"), ("exec", "rce"), ("eval", "rce"), ("os.system", "rce"),
    ("sql", "sqli"), ("nosql", "nosqli"), ("ssrf", "ssrf"), ("xxe", "xxe"),
    ("ssti", "ssti"), ("template", "ssti"), ("secret", "secrets"),
    ("credential", "secrets"), ("idor", "access-control"), ("access-control", "access-control"),
    ("auth", "auth"), ("jwt", "jwt"), ("cors", "cors"), ("csrf", "csrf"),
    ("redirect", "redirect"), ("traversal", "path-traversal"), ("xss", "xss"),
    ("deserialize", "deserialization"), ("upload", "file-upload"), ("disclosure", "disclosure"),
    ("network", "network"), ("crypto", "crypto"), ("header", "headers"),
    ("supply", "supply-chain"), ("dependency", "supply-chain"), ("ci", "supply-chain"),
)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    """Coerce to a list. ``x or []`` only rescues FALSY values, so a graph field holding a truthy
    non-list (``7``, ``"nope"`` — shapes a model reply or a hand-edited sidecar can produce) would
    be iterated and raise. This module's contract is that malformed input degrades to empty."""
    return value if isinstance(value, list) else []


def _text(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def _severity(finding: dict[str, Any], plan: dict[str, Any]) -> str:
    cvss = _dict(plan.get("cvss"))
    value = _text(cvss.get("base_severity") or finding.get("severity") or "info", 20).lower()
    return value if value in _SEVERITY_VALUE else "info"


def normalize_class(finding: dict[str, Any]) -> str:
    """Return the shared class vocabulary for scanner and hunt finding shapes."""
    direct = _text(finding.get("class_id") or finding.get("_active_class_hint"), 80).lower()
    direct = direct.replace("_", "-").replace(" ", "-")
    if direct:
        return _CLASS_ALIASES.get(direct, direct)
    haystack = " ".join(
        _text(finding.get(key), 180).lower()
        for key in ("rule_id", "category", "class_name", "title")
    )
    for hint, class_id in _RULE_CLASS_HINTS:
        if hint in haystack:
            return class_id
    category = _text(finding.get("category"), 80).lower().replace("_", "-").replace(" ", "-")
    return _CLASS_ALIASES.get(category, category) or "unclassified"


def proof_obligation(class_id: str) -> str:
    return _PROOF_OBLIGATIONS.get(
        _CLASS_ALIASES.get(str(class_id or "").lower(), str(class_id or "").lower()),
        "Trace the lead from attacker-controlled input to the claimed impact and capture a repeatable observed-vs-control artifact.",
    )


def _proof_sources(finding: dict[str, Any], plan: dict[str, Any]) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for value in (finding.get("_active_proof"), plan.get("proof_of_impact"), finding.get("proof_of_impact")):
        if isinstance(value, dict):
            sources.append(value)
    return sources


def has_confirming_artifact(finding: dict[str, Any], plan: dict[str, Any] | None = None) -> bool:
    """True only when ``report._has_captured_artifact`` — the single confirm authority for
    the whole engine — accepts this finding's evidence.

    The cortex MUST NOT re-derive this rule. It did, and the two drifted: a passive web
    ``proof_evidence`` (request line + response status, which every header/cookie/disclosure
    finding carries) counted as a typed artifact here but is deliberately refused there,
    because it proves a GET happened, not impact. That gap let a brain — or prompt-injected
    text echoed through one — pair a claimed ``status: confirmed`` with a passive GET and
    print "confirmed / report-ready" for a missing-header finding whose canonical proof
    status was still ``candidate``. Delegating is what keeps the two from parting again.

    ``report`` is the higher-level module, so the import is local to this call.
    """
    from bughunter import report  # local: report sits above this module

    return report._has_captured_artifact(finding, _canonical_proof(finding, _dict(plan)))


def _canonical_proof(finding: dict[str, Any], plan: dict[str, Any]) -> Any:
    """The proof the confirm gate would be applied to — same precedence as ``report._proof_value``.

    Delegating the RULE but choosing our own input would re-open the drift by the back door:
    OR-ing the gate across every proof source is strictly more permissive than the report, so a
    plan proof with no differential sitting beside a finding proof with one would read
    ``confirmed`` in the brief and "not yet captured" in the report. ``_active_proof`` is the
    tail fallback because the hunt loop builds its snapshot before bounty pops that carrier
    into the plan.
    """
    for source in (plan, finding):
        for key in ("proof_of_impact", "impact_proof", "proof", "impact_evidence"):
            value = source.get(key)
            if value:
                return value
    return finding.get("_active_proof") or None


def _proof_status(finding: dict[str, Any], plan: dict[str, Any], confirming: bool) -> str:
    """The status the finding CLAIMS. Kept as claimed on purpose: the caller pairs it with
    ``confirming`` so an unbacked claim surfaces as a contradiction the operator can see,
    rather than being quietly rewritten into a weaker status."""
    # Same source ORDER as report._explicit_proof_status: the canonical proof, then the plan,
    # then the finding. Reading a different proof than the gate was applied to is how a
    # ``confirmed`` on one carrier got paired with a differential on another.
    canonical = _canonical_proof(finding, plan)
    ordered: list[dict[str, Any]] = [canonical] if isinstance(canonical, dict) else []
    for source in ordered + [plan, finding]:
        status = _text(source.get("status") or source.get("proof_status"), 30).lower()
        # Same vocabulary the report accepts. Reading a narrower one was the mirror image of the
        # drift this module just closed: a prover writing "verified" beside a real differential
        # rendered Confirmed in the report and "gather-proof" in the brief.
        if status in _CONFIRMED_STATUS_WORDS:
            return "confirmed"
        if status in _CANDIDATE_STATUS_WORDS:
            return "candidate"
        if status in {"missing", "rejected", "false_positive", "contradicted"}:
            return status
    credential = _dict(finding.get("_credential_proof"))
    # Liveness alone is not confirmation: a live Google/Firebase browser key answering its
    # own issuer is the EXPECTED behaviour of a public client key, not an exploit. The
    # canonical gate requires a validator-backed server token, so defer to it.
    if credential.get("live") is True and confirming:
        return "confirmed"
    return "missing"


def _artifact_types(finding: dict[str, Any], plan: dict[str, Any]) -> list[str]:
    """Inventory typed artifacts; descriptive prose alone intentionally earns nothing."""
    artifacts: list[str] = []
    credential = _dict(finding.get("_credential_proof"))
    # Only a credential strict classification actually confirmed counts. A live PUBLIC client
    # key is expected behaviour, not proof, and weighting it as validation was scoring an
    # Informational finding at 98/100.
    if credential.get("live") is True and secret_classification.has_confirmed_secret_proof(finding):
        artifacts.append("live-credential-validation")
    if _text(finding.get("screenshot_path"), 1000):
        artifacts.append("screenshot")

    evidence = _dict(finding.get("proof_evidence"))
    if _text(evidence.get("matched_value") or evidence.get("set_cookie"), 1000):
        artifacts.append("captured-matched-value")
    body = _text(
        evidence.get("response_body") or evidence.get("response_body_excerpt")
        or evidence.get("body_excerpt") or evidence.get("sensitive_data"), 2000
    )
    if body:
        artifacts.append("captured-response-body")
    request = _text(evidence.get("request_line") or evidence.get("request"), 1000)
    response = _text(
        evidence.get("response_status") or evidence.get("response_header")
        or evidence.get("response_headers") or body, 2000
    )
    if request and response:
        artifacts.append("captured-request-response")

    from bughunter import report  # local: report sits above this module

    for proof in _proof_sources(finding, plan):
        observed = _text(proof.get("observed_result"), 2000)
        control = _text(proof.get("control_result"), 2000)
        if observed and control and not report.proof_is_non_differential(proof):
            # Inventory a differential ONLY when the pair actually differs. Crediting an identical
            # pair here advertised a "differential" the confirm gate had just refused — the
            # operator-facing artifact list contradicting the operator-facing status. An identical
            # pair still falls through to 'captured-observation' below: something WAS observed,
            # it just proves nothing on its own.
            artifacts.append("observed-control-differential")
        elif observed and _text(proof.get("method") or proof.get("request_line"), 1000):
            artifacts.append("captured-observation")
        if _text(proof.get("callback_id") or proof.get("interaction_id"), 500):
            artifacts.append("out-of-band-callback")
    return list(dict.fromkeys(artifacts))


def _same_observed_and_control(finding: dict[str, Any], plan: dict[str, Any]) -> bool:
    """True when ANY proof carrier pairs an observed result with an identical control.

    Delegates the RULE to ``report.proof_is_non_differential`` — the confirm gate's own
    predicate — so the two can never disagree on what "identical" means; this module used to
    hold its own copy of the normalization, which is how the gate came to accept a pair this
    function was simultaneously calling a contradiction. The INPUT set is deliberately wider
    than the gate's: the gate judges the one canonical proof, whereas this scans every carrier
    (``_active_proof``, plan and finding proofs) and raises a contradiction if any of them is
    bogus. That asymmetry errs toward flagging, never toward confirming, so it is kept on
    purpose rather than papered over.

    ``report`` sits above this module; the import is local, as in ``has_confirming_artifact``."""
    from bughunter import report  # local: report sits above this module

    return any(report.proof_is_non_differential(proof) for proof in _proof_sources(finding, plan))


def _contradictions(
    finding: dict[str, Any], plan: dict[str, Any], ref: str, status: str,
    severity: str, artifacts: list[str], confirming: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def add(code: str, message: str, *, blocking: bool = True) -> None:
        rows.append({"ref": ref, "code": code, "message": message, "blocking": blocking})

    # Tested against the confirm authority, not the raw artifact list: passive evidence that a
    # GET happened is a typed artifact but proves no impact, so it must not satisfy this.
    if status == "confirmed" and not confirming:
        add("confirmation-without-artifact", "The finding claims confirmation but has no captured artifact the confirm gate accepts; narrative text and a passive request/response are not proof.")
    if _same_observed_and_control(finding, plan):
        add("non-differential-control", "Observed and control results are identical, so the claimed differential is not established.")
    secret_class = _text(finding.get("secret_classification"), 80).lower()
    # Severity alone can't be the trigger: classification FORCES these classes down to
    # info/low, so a severity test never fires on the mainline path. A claimed confirmation
    # is the reachable conflict.
    if secret_class in {"public_client_key", "candidate_unverified", "false_positive"} and (
        severity in {"medium", "high", "critical"} or status == "confirmed"
    ):
        add("secret-severity-conflict", f"A {secret_class} value cannot support a {severity}-severity confirmation without separate proven impact.")
    if status in {"rejected", "false_positive", "contradicted"}:
        add("negative-verdict", f"The evidence state is {status}; do not report this hypothesis as confirmed.")
    return rows


def _evidence_score(
    finding: dict[str, Any], status: str, artifacts: list[str], contradictions: list[dict[str, Any]],
    confirming: bool,
) -> int:
    score = _CONFIDENCE_BASE.get(_text(finding.get("confidence"), 20).lower(), 30)
    weights = {
        "live-credential-validation": 40,
        "observed-control-differential": 34,
        "out-of-band-callback": 34,
        "captured-request-response": 24,
        "captured-response-body": 22,
        "captured-matched-value": 18,
        "captured-observation": 18,
        "screenshot": 10,
    }
    if artifacts:
        score += max(weights.get(item, 8) for item in artifacts)
        score += min(12, max(0, len(artifacts) - 1) * 4)
    elif _text(finding.get("snippet"), 1000):
        score += 5  # static evidence is a lead, never confirmation
    if status == "confirmed" and confirming:
        score += 8
    elif status == "candidate":
        score += 4
    if not confirming:
        # Without an artifact the confirm gate accepts, this is a LEAD. Passive evidence that
        # a GET happened used to carry a missing-header finding to 86/100 and a "supported"
        # verdict. Rescale rather than clip: leads must stay under the supported band, but
        # they still have to be RANKABLE against each other, and clipping made them all equal.
        score = min(
            _UNPROVEN_CONFIDENCE_CEILING,
            round(max(0, score) * _UNPROVEN_CONFIDENCE_CEILING / _UNPROVEN_SCORE_MAX),
        )
    if any(row.get("blocking") for row in contradictions):
        score = min(score, 24)
    return max(0, min(99, int(score)))


# The chain layer's status vocabulary is the attacker's ("did every step actually happen?");
# the cortex's is the evidence layer's. Map rather than let two vocabularies leak into one
# report: a chain whose every step is backed by an accepted artifact IS confirmed, a chain
# with at least one such step is supported, and a chain of pure leads stays a candidate.
_CHAIN_STATE_TO_CORTEX = {"proven": "confirmed", "partial": "supported", "projected": "candidate"}


def _chain_next_action(chain: dict[str, Any], status: str, refs: list[str],
                       by_ref: dict[str, dict[str, Any]]) -> str:
    """What to do next with this chain, honest about which of the two gates it failed.

    The chain layer and the cortex ask different questions — "did every STEP capture an
    artifact?" versus "is this FINDING's evidence sound?" — and a chain can pass the first while
    failing the second. When that happens the engine has already written "every step is backed
    by a captured artifact — package the chain as one report", and printing that under a status
    the cortex just downgraded invites a submission the evidence does not support.
    """
    if status == "blocked":
        return ("Resolve the blocking evidence contradiction on the cited finding before "
                "treating this chain as reportable.")
    engine_action = _text(chain.get("next_action"), 600)
    # `blocking_step` is 0 exactly when the engine found no unproven step.
    fully_proven = not chain.get("blocking_step")
    if fully_proven and status != "confirmed":
        weak = [ref for ref in refs if by_ref[ref]["status"] != "confirmed"]
        obligation = _text(by_ref[weak[0]]["next_action"], 400) if weak else ""
        named = ", ".join(weak[:3]) or "a cited finding"
        return (f"Every step captured an artifact, but {named} is not confirmed on its own "
                f"evidence — close that gap before packaging this chain. {obligation}").strip()
    return engine_action


def _build_chains(
    hypotheses: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    plans: dict[str, Any],
    signals: list[dict[str, Any]] | None,
    surface: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Correlate findings into ORDERED, multi-step attack chains.

    Returns ``(chains, probes)`` — chains that cite at least one real finding, and
    signal-only chains routed to the planner as untested probe leads.

    Delegates to ``attack_chain``, which models attacker capabilities rather than matching
    class pairs. The old recipe table could only ever say "these two classes co-occur"; it
    could not order the steps, state what the attacker holds between them, or use a
    sub-finding clue (a session cookie readable by script) that is not a finding at all.

    Imported locally: ``attack_chain`` imports this module for the confirm gate and the
    class vocabulary, so a module-level import here would be circular.
    """
    from bughunter import attack_chain as chain_engine

    result = chain_engine.build_attack_chains(
        findings, plans, signals=signals, surface=surface,
    )
    by_ref = {item["ref"]: item for item in hypotheses}

    chains: list[dict[str, Any]] = []
    probes: list[dict[str, Any]] = []
    for chain in result.get("chains") or []:
        refs = [ref for ref in chain.get("refs") or [] if ref in by_ref]
        # A chain must cite hypotheses that survived into THIS graph. The engine works from the
        # same filtered finding set, but a ref that is not in the queue would render a
        # cross-reference to a finding the report never prints.
        #
        # A chain citing NO finding at all is a chain built purely from signals — "there is an
        # is_admin field on this form, so mass assignment might work". That is a genuinely
        # useful thing to go TEST, and a fabrication to put in a report: nothing in it has been
        # observed to be broken. So it is routed to the probe queue for the planner instead of
        # being printed as a chain, and it is the reason the report's chain list can be shorter
        # than the engine's.
        if not refs:
            probes.append({
                "id": chain.get("id") or "", "title": chain.get("title") or "",
                "hypothesis": chain.get("narrative") or "",
                "impact": chain.get("impact_label") or "",
                "next_action": chain.get("next_action") or "",
                "signals": [s.get("signal") for s in (chain.get("steps") or [])
                            if isinstance(s, dict) and s.get("signal")],
                "status": "untested",
            })
            continue
        classes = sorted({by_ref[ref]["class_id"] for ref in refs})
        status = _CHAIN_STATE_TO_CORTEX.get(chain.get("status", ""), "candidate")
        confidence = int(chain.get("confidence_score") or 0)
        # A chain can never read stronger than the findings it rests on. The two layers
        # answer different questions — the chain layer asks "did every STEP capture an
        # artifact?", the cortex asks "is this FINDING's evidence sound?" — and a finding can
        # satisfy the first while failing the second (a real differential paired with a
        # claimed status the cortex flagged, say). Without this clamp the report printed a
        # chain as "confirmed / 82-of-100" whose only cited finding rendered two sections
        # earlier as a mere candidate, which is exactly the overstatement the cortex exists
        # to prevent — just moved up a layer.
        cited = [by_ref[ref]["status"] for ref in refs]
        if "contradicted" in cited:
            status = "blocked"
        elif status == "confirmed" and not all(s == "confirmed" for s in cited):
            status = "supported"
        if status in {"blocked", "candidate", "supported"}:
            confidence = min(confidence, _UNPROVEN_CONFIDENCE_CEILING)
        if status == "blocked":
            # A contradiction outranks any step evidence: resolving it comes before reporting.
            confidence = min(confidence, 24)
        chains.append({
            "id": chain.get("id") or "", "title": chain.get("title") or "Attack chain",
            "refs": refs, "classes": classes, "status": status,
            "confidence_score": confidence,
            "why": chain.get("narrative") or "",
            "projected_impact": chain.get("impact_label") or "",
            # A chain the cortex has downgraded must not carry "package this as one report" as
            # its next action, which is what the engine writes for a chain whose every step
            # captured something. The guard used to cover only `blocked`, so the OTHER downgrade
            # — every step proven, but a cited finding's evidence is not sound enough to call
            # the chain confirmed — still told the operator to submit it, in the report's
            # closing line and in the action plan. Only the fully-proven case is overridden: a
            # genuinely partial chain's action is already its blocking step's own instruction,
            # which is more specific than anything written here.
            "next_action": _chain_next_action(chain, status, refs, by_ref),
            # The ordered ladder — what makes this a chain and not a pair.
            "entry": chain.get("entry_label") or "",
            "chain_state": chain.get("status") or "projected",
            "steps": chain.get("steps") or [],
            "step_count": chain.get("step_count") or 0,
            "proven_steps": chain.get("proven_steps") or 0,
            "blocking_step": chain.get("blocking_step") or 0,
        })
    chains.sort(key=lambda row: (row["status"] == "confirmed", row["confidence_score"]), reverse=True)
    chains = chains[:_MAX_CHAINS]
    # `AC`, not `C`: a campaign pools its findings under refs C1..Cn, and a span report printed
    # both namespaces side by side, so "chain C1 cites C1" named two unrelated things in one
    # sentence. Chain ids are ephemeral (regenerated at every render, nothing persists or keys
    # off them) whereas the finding refs are stored and test-pinned, so the chain side is the
    # one that moves. `CP` for probes is already disjoint from both.
    for index, chain in enumerate(chains, 1):
        chain["id"] = f"AC{index}"
    for index, probe in enumerate(probes[:_MAX_CHAINS], 1):
        probe["id"] = f"CP{index}"
    return chains, probes[:_MAX_CHAINS]


def _location_domain(location: Any) -> str:
    """The registrable domain a finding sits on, or '' for a non-URL location (a source file).

    Grouping is by registrable domain rather than exact host for the same reason the chain engine
    composes across siblings: one control missing on ``api.x.com`` and ``www.x.com`` is one missing
    control on one property, not two coincidences.
    """
    raw = str(location or "").strip()
    if "://" not in raw:
        return ""
    try:
        host = (urlparse(raw).hostname or "").lower()
    except ValueError:
        return ""  # a malformed authority is not a grouping key
    if not host:
        return ""
    try:
        from bughunter.registrable_domain import registrable_domain

        return registrable_domain(host) or host
    except Exception:  # noqa: BLE001 - grouping is advisory; the exact host is a fine fallback
        return host


def _synthesize_hypotheses(
    hypotheses: list[dict[str, Any]], chains: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Derive theories neither the per-finding pass nor the pairwise technique table can reach.

    ``build_investigation`` maps each finding to exactly one hypothesis, and the chain engine
    composes only the class pairs its technique table already knows. Neither can say "the same
    control is absent on nine routes, so the control itself was never applied" — a systemic
    conclusion that is frequently the real, higher-severity bug behind a pile of individually
    unremarkable rows, and the thing an experienced hunter notices first.

    These rows are DERIVED, never observed. Each carries a proof obligation and nothing else, is
    marked ``derived``/``kind: synthesis``, and is routed to ``chain_probes`` — the queue that
    already means "worth testing", never "found". So a synthesized theory can be read as a
    question to go answer and can never be read as a result, which is the same separation that
    keeps signal-only chains out of the report.
    """
    locations_by_key: dict[tuple[str, str], set[str]] = {}
    refs_by_key: dict[tuple[str, str], list[str]] = {}
    refs_by_class: dict[str, list[str]] = {}
    for item in hypotheses:
        class_id = str(item.get("class_id") or "")
        ref = str(item.get("ref") or "")
        refs_by_class.setdefault(class_id, []).append(ref)
        domain = _location_domain(item.get("location"))
        if not domain or class_id in _NO_SYNTHESIS_CLASSES:
            continue
        key = (domain, class_id)
        locations_by_key.setdefault(key, set()).add(str(item.get("location") or ""))
        refs_by_key.setdefault(key, []).append(ref)

    rows: list[dict[str, Any]] = []
    # (1) One class, many routes, one property -> the control is absent, not forgotten N times.
    for (domain, class_id), locations in sorted(locations_by_key.items()):
        if len(locations) < _SYSTEMIC_MIN_LOCATIONS:
            continue
        refs = sorted(dict.fromkeys(refs_by_key.get((domain, class_id)) or []))
        rows.append({
            "id": "", "title": f"Systemic {class_id} weakness across {domain}",
            "hypothesis": (
                f"{len(locations)} separate locations on {domain} carry the same {class_id} "
                f"weakness ({', '.join(refs[:4])}). Individually those read as a run of findings; "
                "together they are the signature of a control missing at the framework or gateway "
                "layer, which is a different and usually higher-severity report than any single "
                "row. DERIVED from the pattern — nothing here has been observed to be broken "
                "systemically."),
            "impact": (
                f"A control gap covering every {class_id} surface on {domain}, rather than "
                f"{len(locations)} isolated routes."),
            "next_action": (
                f"Test a {class_id} case on a route that is NOT in the cited set. If it also "
                f"holds, the finding is the missing control itself, not the individual routes. "
                f"{proof_obligation(class_id)}"),
            "signals": [], "status": "untested", "kind": "synthesis", "derived": True,
            "refs": refs[:8], "class_id": class_id,
        })

    # (2) A credential and an exposed cloud surface in one graph. The chain engine pairs them only
    # where its table has a technique and provenance allows it, but "does this key open that
    # bucket?" is one cheap authorized call to answer and worth asking regardless. Suppressed when
    # a chain already pairs them, so it never restates a lead the report is making properly.
    secret_refs = sorted(dict.fromkeys(refs_by_class.get("secrets") or []))
    cloud_refs = sorted(dict.fromkeys(refs_by_class.get("cloud-exposure") or []))
    if secret_refs and cloud_refs:
        already = any(
            set(_list(chain.get("refs"))) & set(secret_refs)
            and set(_list(chain.get("refs"))) & set(cloud_refs)
            for chain in chains
        )
        if not already:
            rows.append({
                "id": "", "title": "Exposed credential against the exposed cloud surface",
                "hypothesis": (
                    f"This graph holds both an exposed credential ({', '.join(secret_refs[:3])}) and "
                    f"an exposed cloud surface ({', '.join(cloud_refs[:3])}), and no chain pairs "
                    "them. Whether the one opens the other is unproven and untested — DERIVED from "
                    "their co-occurrence, not from any observed access."),
                "impact": "Credentialed access to the exposed cloud surface, if the two are related.",
                "next_action": (
                    "Make the least-privileged authorized call that would distinguish the two cases, "
                    f"and record scope without storing the raw value. {proof_obligation('secrets')}"),
                "signals": [], "status": "untested", "kind": "synthesis", "derived": True,
                "refs": (secret_refs[:4] + cloud_refs[:4]), "class_id": "secrets",
            })
    return rows[:_MAX_SYNTHESIZED]


def _unlocked_chain_ids(
    ref: str, chains: list[dict[str, Any]], status_by_ref: dict[str, str]
) -> list[str]:
    """Chain ids that would reach ``confirmed`` if — and only if — ``ref`` became confirmed.

    Deliberately narrow. ``chain_state == 'proven'`` means the chain layer already saw a captured
    artifact behind EVERY step, so the only thing still holding the chain below ``confirmed`` is
    the cortex's clamp on a cited finding whose own evidence is not sound. A chain that is merely
    ``partial`` is missing an artifact, which confirming this finding would not supply, and a
    ``blocked`` chain needs its contradiction resolved before any of this matters.
    """
    out: list[str] = []
    for chain in chains:
        refs = [str(r) for r in _list(chain.get("refs"))]
        if ref not in refs:
            continue
        if chain.get("status") in {"confirmed", "blocked"} or chain.get("chain_state") != "proven":
            continue
        if all(status_by_ref.get(other) == "confirmed" for other in refs if other != ref):
            chain_id = str(chain.get("id") or "")
            if chain_id:
                out.append(chain_id)
    return out[:6]


def _score_information_gain(
    hypotheses: list[dict[str, Any]], chains: list[dict[str, Any]]
) -> None:
    """Annotate each lead with what TESTING it would buy, and let that sharpen the ranking.

    Payoff ranking answers "which finding is worth the most?". The queue exists to answer a
    different question — "which single test should I run next?" — and the lead brief has always
    promised to favour the test that eliminates the most hypothesis space while nothing actually
    computed it. Two terms do:

    * **uncertainty** peaks for a lead near 50/100 and falls to zero at either pole. A lead at 95
      or at 5 is already settled in practice; testing it teaches almost nothing.
    * **leverage** counts the chains resting on the lead. Collapsing a finding three chains depend
      on resolves far more of the graph than an equally uncertain dead end — which is also why the
      flat chain bonus this replaces was too blunt to express it.

    Information gain steers LEADS only. Adding it to a confirmed row would rank settled evidence by
    how little is left to learn about it, so the ``report-now`` band keeps its existing ordering and
    is reached first by the decision sort key regardless. Mutates in place; ordering stays total and
    deterministic.
    """
    leverage: dict[str, int] = {}
    for chain in chains:
        for ref in _list(chain.get("refs")):
            leverage[str(ref)] = leverage.get(str(ref), 0) + 1
    status_by_ref = {str(item.get("ref")): str(item.get("status")) for item in hypotheses}
    for item in hypotheses:
        ref = str(item["ref"])
        count = leverage.get(ref, 0)
        item["chain_candidate"] = count > 0
        item["chain_leverage"] = count
        uncertainty = max(0.0, 1.0 - abs(int(item["confidence_score"]) - 50) / 50.0)
        value = _CLASS_VALUE.get(item["class_id"], 2) + _SEVERITY_VALUE.get(item["severity"], 10) * 0.12
        item["expected_information_gain"] = round(uncertainty * value * (1 + count), 1)
        item["unlocks_chains"] = _unlocked_chain_ids(ref, chains, status_by_ref)
        bonus = 3.0 + 2.0 * count if count else 0.0
        if item["status"] != "confirmed":
            bonus += item["expected_information_gain"]
        if bonus:
            item["priority_score"] = round(min(140.0, item["priority_score"] + bonus), 1)


def build_investigation(
    findings: list[dict[str, Any]] | None,
    attack_plans: dict[str, Any] | None = None,
    *,
    surface: dict[str, Any] | None = None,
    scan_meta: dict[str, Any] | None = None,
    signals: list[dict[str, Any]] | None = None,
    response_digest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a bounded evidence graph and ranked decision queue.

    ``signals`` carries sub-finding escalation clues (a session cookie readable by script,
    a role-like field name, a captured out-of-band callback). They are never evidence and
    can never confirm anything; they exist so the chain layer can order real findings into
    an attack. When omitted, they are derived from ``response_digest`` and ``surface``.

    Malformed inputs degrade to an empty investigation.  The function is pure and
    does not mutate findings or plans.
    """
    raw_findings = findings if isinstance(findings, list) else []
    plans = attack_plans if isinstance(attack_plans, dict) else {}
    hypotheses: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []

    seen_refs: set[str] = set()
    # Findings carrying the ref this graph RESOLVED for them. The chain layer keys its steps
    # by ref, so it has to see the same identity the queue does — a finding with no explicit
    # ref is "H3" here, and letting the chain layer synthesize its own name for it would make
    # every chain over such a finding cite a ref that appears nowhere in the report. Shallow
    # copies keep this function's no-mutation contract.
    identified: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_findings[:_MAX_HYPOTHESES], 1):
        if not isinstance(raw, dict):
            continue
        ref = _text(raw.get("ref"), 40) or f"H{index}"
        # Refs key the chain builder and the report's cross-references, so a synthesized ref
        # colliding with an explicit one would merge two distinct hypotheses.
        while ref in seen_refs:
            ref = f"{ref}-{index}"
        seen_refs.add(ref)
        identified.append({**raw, "ref": ref})
        plan = _dict(plans.get(ref))
        class_id = normalize_class(raw)
        severity = _severity(raw, plan)
        confirming = has_confirming_artifact(raw, plan)
        claimed = _proof_status(raw, plan, confirming)
        artifacts = _artifact_types(raw, plan)
        conflicts = _contradictions(raw, plan, ref, claimed, severity, artifacts, confirming)
        contradictions.extend(conflicts)
        confidence_score = _evidence_score(raw, claimed, artifacts, conflicts, confirming)
        blocking = any(row["blocking"] for row in conflicts)
        if blocking:
            status = "contradicted"
        elif claimed == "confirmed" and confirming:
            status = "confirmed"
        elif artifacts and confidence_score >= _SUPPORTED_THRESHOLD:
            status = "supported"
        else:
            status = "candidate"

        proof = _dict(plan.get("proof_of_impact"))
        obligation = _text(proof.get("proof_obligation"), 800) or proof_obligation(class_id)
        gaps: list[str] = []
        if not confirming:
            gaps.append(
                "No typed captured artifact backs the claim."
                if not artifacts
                else "The captured evidence shows the request was made, not that impact occurred."
            )
        if status != "confirmed":
            gaps.append(obligation)
        if severity in {"critical", "high"} and status != "confirmed":
            gaps.append("High-impact severity remains provisional until impact is reproduced.")

        severity_value = _SEVERITY_VALUE.get(severity, 10)
        priority = round(severity_value * 0.56 + confidence_score * 0.34 + _CLASS_VALUE.get(class_id, 2), 1)
        if status == "confirmed":
            priority += 8
        if blocking:
            priority = min(priority, 20.0)
        report_ready = status == "confirmed" and confirming and not blocking
        decision = "report-now" if report_ready else ("resolve-contradiction" if blocking else "gather-proof")
        hypotheses.append({
            "ref": ref,
            "title": _text(raw.get("title") or raw.get("rule_id") or "Finding", 240),
            "class_id": class_id,
            "severity": severity,
            "location": _text(raw.get("location") or raw.get("file_path"), 1000),
            "status": status,
            "claimed_proof_status": claimed,
            "confidence_score": confidence_score,
            "confidence_band": "high" if confidence_score >= 75 else ("medium" if confidence_score >= 50 else "low"),
            "priority_score": priority,
            "artifacts": artifacts,
            "gaps": list(dict.fromkeys(gaps))[:4],
            "next_action": obligation,
            "decision": decision,
            "report_ready": report_ready,
        })

    from bughunter import attack_chain as chain_engine

    # MERGE rather than replace. Passing ``signals`` means "here are clues you cannot derive
    # yourself" (what a scanner saw in a Set-Cookie header), not "these are the only clues" —
    # treating them as a replacement silently dropped every surface- and digest-derived clue
    # the moment a caller supplied one, which is the easiest possible way to lose half the
    # chain graph without any error. collect_signals dedupes on (kind, subject).
    signals = chain_engine.collect_signals(
        findings=identified, response_digest=response_digest, surface=surface,
        extra=signals if isinstance(signals, list) else None,
    )
    chains, chain_probes = _build_chains(hypotheses, identified, plans, signals, surface)
    # Derived theories join the PROBE queue, never ``attack_chains``: a synthesized pattern is a
    # question to go answer, and the probe queue is the one place that already means exactly that.
    # `SH` keeps them distinguishable from the engine's `CP` signal-only leads at a glance.
    synthesized = _synthesize_hypotheses(hypotheses, chains)
    for index, row in enumerate(synthesized, 1):
        row["id"] = f"SH{index}"
    chain_probes = list(chain_probes) + synthesized
    _score_information_gain(hypotheses, chains)
    hypotheses.sort(
        key=lambda row: (row["decision"] == "report-now", row["priority_score"], row["confidence_score"]),
        reverse=True,
    )
    for rank, item in enumerate(hypotheses, 1):
        item["rank"] = rank

    confirmed = sum(item["status"] == "confirmed" for item in hypotheses)
    ready = sum(bool(item["report_ready"]) for item in hypotheses)
    supported = sum(item["status"] == "supported" for item in hypotheses)
    avg = round(sum(item["confidence_score"] for item in hypotheses) / len(hypotheses), 1) if hypotheses else 0.0
    verdict = (
        "actionable evidence captured" if ready
        else "supported leads require final confirmation" if supported
        else "leads require evidence" if hypotheses
        else "no hypothesis surfaced at this depth"
    )
    surface_obj = _dict(surface)
    meta_obj = _dict(scan_meta)
    return {
        "algorithm": ALGORITHM_VERSION,
        # A hunt can carry more than one graph (the loop takes a provisional snapshot before
        # classification and plans). Callers must be able to tell which one is the report's.
        "stage": "final",
        "authoritative": True,
        "verdict": verdict,
        "metrics": {
            "hypotheses": len(hypotheses), "confirmed": confirmed, "supported": supported,
            "report_ready": ready, "contradictions": len(contradictions),
            "attack_chains": len(chains), "chain_probes": len(chain_probes),
            "average_confidence": avg,
        },
        "hypotheses": hypotheses,
        "attack_chains": chains,
        # Signal-only chains: what to go TEST, not what was found. Kept separate from
        # attack_chains precisely so nothing unobserved can be read as a result.
        "chain_probes": chain_probes,
        "contradictions": contradictions,
        "coverage": {
            "endpoints_observed": len(surface_obj.get("endpoints") or []) if isinstance(surface_obj.get("endpoints"), list) else 0,
            "parameters_observed": len(surface_obj.get("params") or []) if isinstance(surface_obj.get("params"), list) else 0,
            "verified_classes": list(meta_obj.get("verified_classes") or [])[:30] if isinstance(meta_obj.get("verified_classes"), list) else [],
            "requests_used": int(meta_obj.get("requests_used") or 0) if str(meta_obj.get("requests_used") or "0").isdigit() else 0,
        },
    }


def build_probe_hypotheses(plan: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Expand a hunt probe plan into an explicit, evidence-seeking hypothesis queue."""
    obj = _dict(plan)
    rows = obj.get("probe_priority") if isinstance(obj.get("probe_priority"), list) else []
    hypotheses: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows[:40]):
        if not isinstance(row, dict):
            continue
        endpoint = _text(row.get("endpoint"), 1000)
        classes = row.get("classes") if isinstance(row.get("classes"), list) else []
        try:
            # OverflowError too: json.loads accepts a bare Infinity, and int(float("inf"))
            # raises it -- which would empty the whole hypothesis queue.
            row_score = max(0, min(130, int(row.get("score") or (100 - row_index))))
        except (TypeError, ValueError, OverflowError):
            row_score = max(0, 100 - row_index)
        for class_index, value in enumerate(classes[:8]):
            class_id = _CLASS_ALIASES.get(_text(value, 80).lower(), _text(value, 80).lower())
            if not endpoint or not class_id:
                continue
            likelihood = max(1, min(99, round(row_score * 0.68 + _CLASS_VALUE.get(class_id, 2) - class_index * 3)))
            hypotheses.append({
                "id": "", "endpoint": endpoint, "class_id": class_id, "status": "untested",
                "likelihood_score": likelihood, "reason": _text(row.get("why"), 300),
                "evidence_required": proof_obligation(class_id),
            })
    hypotheses.sort(key=lambda item: item["likelihood_score"], reverse=True)
    hypotheses = hypotheses[:80]
    for index, item in enumerate(hypotheses, 1):
        item["id"] = f"P{index}"
    return hypotheses


def project_if_confirmed(investigation: dict[str, Any] | None, ref: str) -> dict[str, Any]:
    """What would confirming ``ref`` buy, computed without running anything.

    The graph already knows which chains are one sound finding away from complete, but that
    knowledge only ever reached the operator as a chain's own next_action — so "which pending test
    is worth the most?" had to be answered by eye. This answers it directly, and is what lets a
    planner spend its next request on the lead that resolves the most graph.

    STRICTLY A PROJECTION. It assumes an outcome that has not happened, returns a fresh dict, and
    mutates nothing. It never writes a status, never persists the assumed state, and never reaches
    the confirm gate: ``report._has_captured_artifact`` still decides what is actually confirmed,
    and it decides that only from a captured artifact.
    """
    obj = _dict(investigation)
    chains = [c for c in _list(obj.get("attack_chains")) if isinstance(c, dict)]
    hypotheses = [h for h in _list(obj.get("hypotheses")) if isinstance(h, dict)]
    status_by_ref = {str(h.get("ref")): str(h.get("status")) for h in hypotheses}
    target = _text(ref, 40)
    unlocks = _unlocked_chain_ids(target, chains, status_by_ref) if target else []
    impacts = [
        _text(chain.get("projected_impact"), 240)
        for chain in chains
        if str(chain.get("id") or "") in set(unlocks)
    ]
    return {
        "ref": target,
        "unlocks_chains": unlocks,
        "would_complete_chain": bool(unlocks),
        "projected_impacts": [item for item in dict.fromkeys(impacts) if item],
        "note": "Projection only. Nothing is confirmed until the confirm gate accepts a captured artifact.",
    }


def _prover_classes() -> frozenset[str]:
    """The classes the active differential prover can actually confirm, or an empty set.

    Read lazily so this module stays importable (and the cortex stays usable) in a build that
    ships without the prover. Empty means "unknown", and the caller then filters nothing rather
    than silently emitting an empty plan.
    """
    try:
        from bughunter.prover_classes import PROVER_CLASSES

        return PROVER_CLASSES
    except Exception:  # noqa: BLE001 - an absent prover vocabulary must not break planning
        return frozenset()


def build_probe_plan(investigation: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Project the cortex's own unproven leads into STRUCTURED probe specifications.

    ``build_probe_hypotheses`` expands a probe plan the planner already wrote. This closes the
    loop from the other end: it reads the finished evidence graph and states, per unproven lead and
    per blocked chain, the exact ``(endpoint, class)`` an executor would have to probe to change the
    verdict. Until now that instruction existed only as English inside ``next_action``, so the one
    decision the cortex is best placed to make — what to test next — could not be handed to the
    prover that would test it, and died in the report.

    This EMITS A PLAN. It runs nothing, fetches nothing, confirms nothing, and authorizes nothing.
    Every row is an input to the same scope-gated, SSRF-gated, rate-governed differential prover,
    which remains the sole authority on whether anything is confirmed. Two restrictions keep it
    inside the engine's existing box:

    * a row's class must be one the prover can actually confirm, so a plan can never steer budget
      at a class whose only possible outcome is another unconfirmable lead;
    * a row's endpoint must be a verbatim ``http(s)`` location THIS graph already observed, so a
      plan can never introduce a host the hunt did not already reach. Scope is still re-decided by
      the prover, which is what makes this safe rather than merely conventional.
    """
    obj = _dict(investigation)
    hypotheses = [h for h in _list(obj.get("hypotheses")) if isinstance(h, dict)]
    chains = [c for c in _list(obj.get("attack_chains")) if isinstance(c, dict)]
    prover = _prover_classes()
    by_ref = {str(h.get("ref") or ""): h for h in hypotheses}
    rows: dict[tuple[str, str], dict[str, Any]] = {}

    def add(item: dict[str, Any], *, source: str, chain_id: str = "", boost: float = 0.0) -> None:
        endpoint = _text(item.get("location"), 1000)
        if not endpoint.lower().startswith(("http://", "https://")):
            return  # a source file is nothing the ACTIVE prover can point at
        class_id = _CLASS_ALIASES.get(
            _text(item.get("class_id"), 80).lower(), _text(item.get("class_id"), 80).lower()
        )
        if not class_id or (prover and class_id not in prover):
            return
        try:
            priority = float(item.get("expected_information_gain") or 0.0) + boost
        except (TypeError, ValueError):
            priority = boost
        key = (endpoint, class_id)
        existing = rows.get(key)
        if existing is not None and float(existing.get("priority") or 0.0) >= priority:
            return
        rows[key] = {
            "ref": _text(item.get("ref"), 40),
            "chain_id": chain_id,
            "endpoint": endpoint,
            "class_id": class_id,
            "source": source,
            "obligation": _text(item.get("next_action"), 800) or proof_obligation(class_id),
            "priority": round(priority, 1),
            "status": "untested",
        }

    for item in hypotheses:
        if str(item.get("status")) != "confirmed":
            add(item, source="unconfirmed-hypothesis")

    # A blocked chain's blocking step is the single highest-value test in the graph: it is what
    # stands between a part-proven ladder and a real, reportable impact, so it outranks a loose
    # lead of the same class even when the lead looks individually more uncertain.
    for chain in chains:
        if chain.get("status") in {"confirmed", "blocked"}:
            continue
        for step in _list(chain.get("steps")):
            if not isinstance(step, dict) or step.get("proven"):
                continue
            cited = by_ref.get(_text(step.get("evidence_ref"), 40))
            if cited:
                add(cited, source="chain-blocking-step",
                    chain_id=_text(chain.get("id"), 20), boost=12.0)
            break  # only the FIRST unproven step is actionable; the rest are gated behind it

    ordered = sorted(
        rows.values(), key=lambda row: (row["priority"], row["endpoint"], row["class_id"]), reverse=True
    )
    return ordered[:_MAX_PROBE_PLAN_ROWS]
