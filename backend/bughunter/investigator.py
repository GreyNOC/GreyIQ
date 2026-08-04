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

_CHAIN_RECIPES: tuple[dict[str, Any], ...] = (
    {"classes": {"disclosure", "access-control"}, "title": "Disclosure-assisted object authorization bypass",
     "why": "Leaked identifiers or hidden paths can make an access-control lead reproducible.",
     "projected_impact": "Unauthorized access to another user's data or object.",
     "validation": "Use only identifiers already disclosed, compare two authorized test roles, and capture the response differential."},
    {"classes": {"secrets", "auth"}, "title": "Credential exposure into authentication compromise",
     "why": "A usable privileged credential can turn an authentication weakness into account or environment access.",
     "projected_impact": "Account, service, or environment compromise, bounded by the credential's proven scope.",
     "validation": "Validate the credential with a least-privileged issuer call, then prove the auth boundary separately; never place the raw secret in the report."},
    {"classes": {"redirect", "auth"}, "title": "Authentication-flow redirect chain",
     "why": "An off-origin redirect in login, OAuth, invitation, or reset flows may expose tokens or trusted navigation.",
     "projected_impact": "Token disclosure, trusted phishing, or authentication workflow abuse.",
     "validation": "Walk the affected auth flow end to end and capture whether sensitive state reaches the off-origin destination."},
    {"classes": {"cors", "auth"}, "title": "Credentialed cross-origin data read",
     "why": "CORS becomes materially exploitable when an attacker origin can read authenticated data.",
     "projected_impact": "Cross-origin theft of victim-accessible data.",
     "validation": "Run a browser PoC against an authenticated test account and capture the readable sensitive response plus a disallowed-origin control."},
    {"classes": {"xss", "auth"}, "title": "Browser execution into authenticated action",
     "why": "Script execution can become higher impact when it reaches victim session data or privileged actions.",
     "projected_impact": "Victim-session data access or authenticated state change.",
     "validation": "Use a harmless marker in a test account and capture the exact authenticated action or data read; do not infer impact from an alert box."},
    {"classes": {"ssrf", "cloud-exposure"}, "title": "Server-side request pivot into cloud control plane",
     "why": "A confirmed server-side fetch may reach cloud-only services when network controls permit it.",
     "projected_impact": "Internal service access or cloud credential exposure.",
     "validation": "Use an engagement-approved callback or metadata-safe control and capture a target-bound response differential."},
    {"classes": {"xxe", "ssrf"}, "title": "XML parser to server-side network pivot",
     "why": "External entity resolution can act as a server-side request primitive.",
     "projected_impact": "Internal network access or bounded file disclosure.",
     "validation": "Capture a unique authorized callback for each primitive and a parser configuration control."},
    {"classes": {"prototype-pollution", "xss"}, "title": "Prototype pollution gadget chain",
     "why": "Pollution requires a reachable gadget to become a concrete browser vulnerability.",
     "projected_impact": "Browser code execution in the affected application context.",
     "validation": "Prove the polluted property reaches a specific sink and capture execution plus a clean-object control."},
    {"classes": {"access-control", "graphql"}, "title": "GraphQL object/field authorization bypass",
     "why": "Hidden GraphQL operations can expose the same object boundary missed by REST authorization.",
     "projected_impact": "Unauthorized object or sensitive field access.",
     "validation": "Replay the same query across two test roles and capture object- and field-level response differences."},
)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


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

    for proof in _proof_sources(finding, plan):
        observed = _text(proof.get("observed_result"), 2000)
        control = _text(proof.get("control_result"), 2000)
        if observed and control:
            artifacts.append("observed-control-differential")
        elif observed and _text(proof.get("method") or proof.get("request_line"), 1000):
            artifacts.append("captured-observation")
        if _text(proof.get("callback_id") or proof.get("interaction_id"), 500):
            artifacts.append("out-of-band-callback")
    return list(dict.fromkeys(artifacts))


def _same_observed_and_control(finding: dict[str, Any], plan: dict[str, Any]) -> bool:
    for proof in _proof_sources(finding, plan):
        observed = re.sub(r"\s+", " ", _text(proof.get("observed_result"), 2000)).lower()
        control = re.sub(r"\s+", " ", _text(proof.get("control_result"), 2000)).lower()
        if observed and control and observed == control:
            return True
    return False


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


def _location_scope(location: str) -> str:
    # urlparse RAISES on a malformed authority ("https://example.com]/x", "http://[foo]/x",
    # anything whose netloc fails NFKC normalization). This runs at report-writing time on a
    # finished hunt, so an escape here would discard a completed run's whole report. Advisory
    # intelligence fails closed: an unparseable location just contributes no scope.
    try:
        parsed = urlparse(location)
    except ValueError:
        parsed = None
    if parsed is not None and parsed.hostname:
        return parsed.hostname.lower()
    # Drop any scheme before falling back, or every malformed URL collapses to the scheme
    # itself ("https:") -- one bogus shared "scope" that hands unrelated findings the
    # same-scope chain bonus.
    normalized = re.sub(r"^[a-z][a-z0-9+.-]*:", "", location.strip(), flags=re.IGNORECASE)
    normalized = normalized.replace("\\", "/").strip("/")
    return normalized.split("/", 1)[0].lower() if normalized else ""


def _build_chains(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_class: dict[str, list[dict[str, Any]]] = {}
    for item in hypotheses:
        by_class.setdefault(item["class_id"], []).append(item)
    for rows in by_class.values():
        rows.sort(key=lambda row: (row["priority_score"], row["confidence_score"]), reverse=True)

    chains: list[dict[str, Any]] = []
    for recipe in _CHAIN_RECIPES:
        required = sorted(recipe["classes"])
        if not all(by_class.get(class_id) for class_id in required):
            continue
        nodes = [by_class[class_id][0] for class_id in required]
        refs = [node["ref"] for node in nodes]
        if len(set(refs)) != len(refs):
            continue
        confidence = round(sum(node["confidence_score"] for node in nodes) / len(nodes))
        scopes = {_location_scope(node.get("location", "")) for node in nodes} - {""}
        if len(scopes) == 1:
            confidence = min(99, confidence + 5)
        statuses = {node["status"] for node in nodes}
        if statuses == {"confirmed"}:
            status = "confirmed"
        elif "contradicted" in statuses:
            status = "blocked"
        elif "confirmed" in statuses:
            status = "supported"
        else:
            # Every node is a lead, so the chain is a PROJECTION. Calling it "supported" and
            # letting the mean plus the same-scope bonus carry it past the unproven ceiling
            # (two 54s became 59) re-created above the node layer exactly the overstatement the
            # node layer refuses.
            status = "candidate"
            confidence = min(confidence, _UNPROVEN_CONFIDENCE_CEILING)
        chains.append({
            "id": "", "title": recipe["title"], "refs": refs, "classes": required,
            "status": status, "confidence_score": confidence, "why": recipe["why"],
            "projected_impact": recipe["projected_impact"], "next_action": recipe["validation"],
        })
    chains.sort(key=lambda row: (row["status"] == "confirmed", row["confidence_score"]), reverse=True)
    chains = chains[:_MAX_CHAINS]
    for index, chain in enumerate(chains, 1):
        chain["id"] = f"C{index}"
    return chains


def build_investigation(
    findings: list[dict[str, Any]] | None,
    attack_plans: dict[str, Any] | None = None,
    *,
    surface: dict[str, Any] | None = None,
    scan_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a bounded evidence graph and ranked decision queue.

    Malformed inputs degrade to an empty investigation.  The function is pure and
    does not mutate findings or plans.
    """
    raw_findings = findings if isinstance(findings, list) else []
    plans = attack_plans if isinstance(attack_plans, dict) else {}
    hypotheses: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []

    seen_refs: set[str] = set()
    for index, raw in enumerate(raw_findings[:_MAX_HYPOTHESES], 1):
        if not isinstance(raw, dict):
            continue
        ref = _text(raw.get("ref"), 40) or f"H{index}"
        # Refs key the chain builder and the report's cross-references, so a synthesized ref
        # colliding with an explicit one would merge two distinct hypotheses.
        while ref in seen_refs:
            ref = f"{ref}-{index}"
        seen_refs.add(ref)
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

    chains = _build_chains(hypotheses)
    chain_refs = {ref for chain in chains for ref in chain["refs"]}
    for item in hypotheses:
        if item["ref"] in chain_refs:
            item["priority_score"] = round(min(110.0, item["priority_score"] + 5), 1)
            item["chain_candidate"] = True
        else:
            item["chain_candidate"] = False
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
            "attack_chains": len(chains), "average_confidence": avg,
        },
        "hypotheses": hypotheses,
        "attack_chains": chains,
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
