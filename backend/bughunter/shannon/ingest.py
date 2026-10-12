"""Shannon candidates -> GreyIQ hunt findings. Candidates, never proofs.

This is the ingest half of the Shannon bridge. It takes the neutral records from
:mod:`bughunter.shannon.sarif` and produces GreyIQ hunt-finding dicts that can flow
through the normal annotate -> rank -> report pipeline.

THE ONE RULE THIS MODULE EXISTS TO ENFORCE
------------------------------------------
``docs/shannon-integration.md`` §6, following the TACNOC precedent: *"Block the submit
path for any finding whose proof status was never raised by GreyIQ's own prover."*

GreyIQ's single confirm authority is ``report._has_captured_artifact``, and its actual
distinguishing signal is a populated ``observed_result`` **and** ``control_result`` pair —
a captured response plus its negative-control differential. Shannon supplies exactly that
shape of material, and it believes its findings are exploited: every result in a Shannon
SARIF carries ``status: "exploited"`` because unproven candidates never reach that file
at all.

So if this module wrote Shannon's evidence into those two fields, every Shannon finding
would promote itself to ``confirmed`` on Shannon's word and walk straight to the
auto-submit gate. It therefore **never populates**:

    observed_result · control_result · proof_of_impact · impact_proof · proof ·
    impact_evidence · impact_confirmed · proof_confirmed · replay_authenticated

and it sets ``proof_status: "candidate"`` explicitly, which
``report._explicit_proof_status`` reads deterministically. Shannon's own verdict is kept
as *provenance* under ``source_detail.shannon_status``, never under a key the gate scans.

That is belt. The braces are a source veto inside ``_has_captured_artifact`` itself, so a
future caller that does populate those fields still cannot promote an external finding.
Two independent mechanisms, because this is the path to a live submission.

WHAT IS DELIBERATELY NOT IMPORTED
---------------------------------
Shannon's reproduction steps and proof-of-impact. They live in ``report.json``, not the
SARIF, and Shannon's own prompt rule keeps "a session token you captured, a key you
extracted, data you exfiltrated" in them by design. Importing that would pull live
third-party secrets into GreyIQ's store for no gain: a candidate does not need evidence,
it needs a proof obligation, which is what a GreyIQ lead already carries.

SEVERITY AND CWE ARE NOT INVENTED HERE
--------------------------------------
SARIF collapses ``critical`` and ``high`` into ``level: "error"``, so the band is recorded
and the finding is stamped at the band's floor rather than claiming a critical nobody
measured. CWE comes only from Shannon's validated SAST rule id; a class-level guess is
refused (see :mod:`bughunter.shannon.sarif`). An unresolved class leaves ``class_id``
unset so ``bounty.py``'s existing ``_classify`` annotation pass handles it exactly as it
handles any other unclassified finding.

Pure / frozen-safe: standard library only, no network. Heavy GreyIQ modules are imported
lazily so importing this module stays cheap and cycle-free.
"""

from __future__ import annotations

from typing import Any

from .sarif import ShannonCandidate, ShannonRun

#: Marks a finding as produced by an external engine rather than by GreyIQ.
#: ``report._has_captured_artifact`` vetoes any finding whose ``source`` is set to
#: anything but GreyIQ's own, so this string is load-bearing, not decorative.
SOURCE = "shannon"

# SARIF level band -> the severity word GreyIQ stamps. "error" is ambiguous between
# critical and high (sarif-renderer.ts emits no security-severity property), so it lands
# on the band floor: a candidate that turns out to be critical gets re-rated by
# report.resolve_severity from the plan's CVSS once something actually proves it, whereas
# a claimed critical nobody measured is a fabrication that survives into a report.
_BAND_TO_SEVERITY: dict[str, str] = {
    "critical-or-high": "high",
    "medium": "medium",
    "low": "low",
}

# Shannon class -> GreyIQ class_id, used ONLY when no CWE resolved. Deliberately omits
# `shannon/injection`: GreyIQ's own cortex aliases the bare word "injection" to `rce`
# (investigator.py:82), and Shannon's injection class also covers SQLi, path traversal
# and SSTI — so honouring that alias would silently promote a SQLi candidate to remote
# code execution. Also omits `shannon/miscellaneous`, which is a renderer fall-through
# bucket and not a class at all. Both abstain and let `_classify` decide.
_CLASS_FALLBACK: dict[str, str] = {
    "shannon/xss": "xss",
    "shannon/ssrf": "ssrf",
    "shannon/auth": "auth",
    "shannon/authz": "access-control",
}

# Classes excluded from the derived CWE -> class_id reverse map.
#   secrets      - CWE-200 in GreyIQ means "exposed secret / credential" and routes into
#                  secret_classification, which clamps severity and owns its own confirm
#                  veto. Shannon's CWE-200 means ordinary information disclosure. Mapping
#                  one onto the other would file a disclosure as a leaked credential.
#   supply-chain - CWE-1104/1395 are dependency-manifest findings from a static scan;
#                  Shannon is not a dependency scanner.
_EXCLUDED_CLASSES: frozenset[str] = frozenset({"secrets", "supply-chain"})

# Preference order for CWEs claimed by more than one GreyIQ class. First match wins.
# CWE-284 is claimed by access-control, cors and websocket; CWE-94 by rce and ssti;
# CWE-639 by access-control and graphql. Without a fixed order the reverse map would
# depend on dict iteration and could change class under a finding between releases.
_CLASS_PRIORITY: tuple[str, ...] = (
    "sqli", "rce", "xss", "ssrf", "access-control", "auth", "jwt",
    "path-traversal", "ssti", "xxe", "nosqli", "csrf", "redirect",
    "file-upload", "cors", "subdomain-takeover", "request-smuggling",
    "prototype-pollution", "race-condition", "graphql", "websocket",
    "business-logic", "cloud-exposure",
)

_cwe_class_cache: dict[str, str] | None = None


def _cwe_to_class() -> dict[str, str]:
    """CWE number -> GreyIQ ``class_id``, derived from ``bounty.VULN_CLASSES``.

    Derived rather than hardcoded so a class whose CWE changes upstream cannot leave a
    stale duplicate here. Lazily built and cached; a failed import yields an empty map and
    every finding simply abstains on class.
    """
    global _cwe_class_cache
    if _cwe_class_cache is not None:
        return _cwe_class_cache

    try:
        from .. import bounty, taxonomy
    except ImportError:
        _cwe_class_cache = {}
        return _cwe_class_cache

    classes = getattr(bounty, "VULN_CLASSES", None)
    if not isinstance(classes, dict):
        _cwe_class_cache = {}
        return _cwe_class_cache

    ordered = [cid for cid in _CLASS_PRIORITY if cid in classes]
    ordered += [cid for cid in classes if cid not in _CLASS_PRIORITY]

    mapping: dict[str, str] = {}
    for class_id in ordered:
        if class_id in _EXCLUDED_CLASSES:
            continue
        meta = classes.get(class_id)
        if not isinstance(meta, dict):
            continue
        for number in taxonomy.cwe_numbers(meta.get("cwe")):
            mapping.setdefault(number, class_id)
    _cwe_class_cache = mapping
    return mapping


def _redact(value: Any) -> str:
    """Scrub a string through GreyIQ's shared pattern redactor.

    Mirrors ``active_verify_service._redact`` so an external finding is scrubbed by the
    same code as a native one. A missing redactor is treated as fatal for the field: we
    return '' rather than pass unscrubbed external text through, because the whole point
    of this module is that Shannon's text may carry third-party secrets.
    """
    text = str(value or "")
    if not text:
        return ""
    try:
        from ..code_scanner.redaction import redact_text
    except ImportError:
        return ""
    try:
        return redact_text(text)[0]
    except Exception:
        return ""


def _resolve_class(candidate: ShannonCandidate) -> tuple[str, str]:
    """(class_id, how) for one candidate. ('', '') when nothing resolves exactly."""
    if candidate.cwe:
        class_id = _cwe_to_class().get(candidate.cwe, "")
        if class_id:
            return class_id, f"cwe:{candidate.cwe}:{candidate.cwe_source}"
    fallback = _CLASS_FALLBACK.get(candidate.rule_id, "")
    if fallback:
        return fallback, f"shannon-class:{candidate.rule_id}"
    return "", ""


def _source_detail(run: ShannonRun, candidate: ShannonCandidate, class_how: str) -> dict[str, Any]:
    """Pinned provenance for one imported candidate.

    Everything Shannon asserted that GreyIQ has not verified lives here, including
    Shannon's own ``exploited`` verdict. Nothing in this dict is read by the confirm gate.
    """
    detail: dict[str, Any] = {
        "engine": SOURCE,
        "tool_name": run.tool_name,
        "shannon_finding_id": candidate.finding_id,
        "shannon_rule_id": candidate.rule_id,
        "shannon_status": candidate.shannon_status,
        "shannon_severity_band": candidate.severity_band,
        "owasp_taxon": candidate.owasp_taxon,
        "class_resolved_by": class_how,
        "greyiq_proved": False,
    }
    if candidate.cwe:
        # Kept even when the class abstained. Shannon's validated SAST rule ids include
        # real CWEs that GreyIQ has no class for (CWE-476, CWE-613, CWE-833, CWE-209 all
        # appear in the benchmark runs), and bounty.py's annotation pass overwrites the
        # finding's own ``cwe`` field from VULN_CLASSES — so this is the only place that
        # weakness id survives. Dropping it would discard the most precise fact Shannon
        # supplied about the finding.
        detail["cwe"] = f"CWE-{candidate.cwe}"
        detail["cwe_source"] = candidate.cwe_source
    if candidate.severity_band == "critical-or-high":
        detail["severity_note"] = (
            "SARIF collapses critical and high into level 'error'; stamped at the band "
            "floor (high). Shannon's report.json carries the true severity."
        )
    if run.automation_id:
        detail["automation_id"] = run.automation_id
    if run.model:
        detail["model"] = run.model
    if run.assessment_date:
        detail["assessment_date"] = run.assessment_date
    if candidate.sast_rule_id:
        detail["sast_rule_id"] = candidate.sast_rule_id
    if candidate.auth_state:
        detail["auth_state"] = _redact(candidate.auth_state)
    if candidate.prerequisites:
        detail["prerequisites"] = _redact(candidate.prerequisites)
    if run.execution_successful is False:
        detail["partial_run"] = True
    return detail


def _code_locations(candidate: ShannonCandidate) -> list[dict[str, Any]]:
    """Shannon's data-flow locations, flattened for the report.

    Paths are repository-relative inside the *target's* source tree. They are not secret
    but they do disclose the target's codebase structure, so they are carried as
    structured provenance rather than spliced into narrative prose.
    """
    out: list[dict[str, Any]] = []
    for location in (*candidate.locations, *candidate.related_locations):
        row: dict[str, Any] = {"file": location.file, "role": location.role}
        if location.start_line is not None:
            row["start_line"] = location.start_line
        if location.end_line is not None:
            row["end_line"] = location.end_line
        if location.symbol:
            row["symbol"] = location.symbol
        out.append(row)
    return out


#: Classes the active prover cannot confirm, and the GreyIQ path that could. ``ssrf``,
#: ``auth`` and ``access-control`` are absent from ``prover_classes.PROVER_CLASSES``, so
#: promising "run --active to confirm this" for them would be an obligation GreyIQ cannot
#: discharge. Naming the real path instead is the difference between a lead and a dead end.
_ALTERNATE_PROOF_PATH: dict[str, str] = {
    "access-control": (
        "the cross-tenant differential in access_control_service, which needs two "
        "operator-owned accounts — the active prover cannot confirm this class"
    ),
    "ssrf": (
        "oob_service with a configured out-of-band collaborator — the active prover "
        "cannot confirm this class in-band"
    ),
    "auth": (
        "a session/token differential; the nearest class the active prover can confirm "
        "is jwt — it cannot confirm 'auth' itself"
    ),
}


def _proof_obligation(class_id: str, candidate: ShannonCandidate, url: str) -> str:
    """What GreyIQ must do to turn this candidate into a finding of its own.

    This is the field that makes an imported candidate worth having. Shannon's evidence is
    deliberately not imported, so the lead carries an obligation rather than a proof — which
    is what GreyIQ's investigation queue consumes anyway.
    """
    where = url or "the affected endpoint"
    if candidate.parameter:
        where = f"{where} (parameter {candidate.parameter})"

    alternate = _ALTERNATE_PROOF_PATH.get(class_id)
    if alternate:
        return (
            f"Reproduce independently via {alternate}. Shannon reported this against {where}; "
            "GreyIQ has captured nothing."
        )

    try:
        from .. import prover_classes
        provable = class_id in prover_classes.PROVER_CLASSES
    except ImportError:
        provable = False

    if class_id and provable:
        return (
            f"Re-run GreyIQ's active prover against {where} and capture an observed-vs-control "
            f"differential for class '{class_id}'. Until then this is Shannon's claim, not GreyIQ's."
        )
    if class_id:
        return (
            f"Class '{class_id}' is not in prover_classes.PROVER_CLASSES, so the active prover "
            f"cannot confirm it. Reproduce {where} by hand and capture the differential."
        )
    return (
        f"Classify this finding first — Shannon's class did not resolve to a GreyIQ class — then "
        f"reproduce {where} and capture an observed-vs-control differential."
    )


def finding_from_candidate(run: ShannonRun, candidate: ShannonCandidate) -> dict[str, Any]:
    """One GreyIQ hunt-finding dict for one Shannon candidate.

    ``confidence`` is pinned to "medium" rather than "high". Shannon's SARIF contains only
    findings it believed it exploited, so there is real signal — but ``confidence`` feeds
    the cortex's ranking base (``investigator._CONFIDENCE_BASE``), and letting an external
    engine seed "high" would let it outrank GreyIQ's own confirmed work in the queue.
    """
    class_id, class_how = _resolve_class(candidate)
    title = _redact(candidate.title) or f"Shannon candidate {candidate.finding_id}"
    url = candidate.http_target or run.target

    finding: dict[str, Any] = {
        # Namespaced like GreyIQ's own origins (active.* / secret.* / web.exposed.*) so a
        # Shannon finding is identifiable from its rule_id alone, in any log or report.
        "rule_id": f"{SOURCE}.{candidate.rule_id.rsplit('/', 1)[-1] or 'unknown'}."
                   f"{candidate.finding_id.lower()}",
        "title": title,
        "description": _redact(candidate.narrative),
        "severity": _BAND_TO_SEVERITY.get(candidate.severity_band, "low"),
        "confidence": "medium",
        # NEVER Shannon's own class word. bounty._classify matches `category` against each
        # VULN_CLASSES entry's scanner-category set, and `rce`'s set contains the literal
        # "injection" — so `category: "injection"` classifies as REMOTE CODE EXECUTION, the
        # exact inflation abstaining on _active_class_hint exists to prevent. When the class
        # resolved we pass the resolved GreyIQ class_id (which round-trips or falls through,
        # never inflates); when it abstained we pass nothing and let _classify return its own
        # "other" fallback. Shannon's class is preserved in rule_id and source_detail.
        "category": class_id,
        "file_path": url,
        "location": url,
        "line_start": 1,
        "line_end": 1,
        "snippet": _redact(candidate.narrative)[:240],
        "remediation": "",
        "redacted": True,
        # The explicit candidate stamp. report._explicit_proof_status reads this key and
        # "candidate" is in its _CANDIDATE_PROOF_STATUSES set, so the status is pinned
        # deterministically instead of being inferred from prose.
        "proof_status": "candidate",
        # The proof carrier. report._proof_of_impact_detail returns early at 'missing' when a
        # finding has no proof dict at all, which would file an imported lead with no stated
        # obligation — the one thing that makes it actionable. So the dict is supplied, with
        # `status` pinned to the literal "candidate" and the three fields that drive promotion
        # (evidence / observed_result / control_result) left EMPTY on purpose: a populated
        # observed+control pair that differs is exactly what _has_captured_artifact accepts.
        # method/actor/affected_asset are descriptive only and never drive promotion.
        "proof_of_impact": {
            "status": "candidate",
            "method": f"reported by Shannon ({run.tool_name or 'external engine'}); not reproduced by GreyIQ",
            "actor": _redact(candidate.auth_state) or "unspecified",
            "affected_asset": url,
            "evidence": "",
            "observed_result": "",
            "control_result": "",
            "proof_obligation": _proof_obligation(class_id, candidate, url),
        },
        "source": SOURCE,
        "source_detail": _source_detail(run, candidate, class_how),
    }

    if candidate.http_method:
        finding["http_method"] = candidate.http_method
    if candidate.parameter:
        finding["parameter"] = _redact(candidate.parameter)
    locations = _code_locations(candidate)
    if locations:
        finding["code_locations"] = locations
    # Only stamp the class when it resolved exactly. bounty.py reads _active_class_hint to
    # take name/cwe/owasp straight from VULN_CLASSES; leaving it unset routes the finding
    # through _classify, which is the existing path for anything unclassified.
    if class_id:
        finding["_active_class_hint"] = class_id
    return finding


def findings_from_run(run: ShannonRun) -> list[dict[str, Any]]:
    """Every candidate in a parsed Shannon run, as GreyIQ hunt-finding dicts."""
    return [finding_from_candidate(run, candidate) for candidate in run.candidates]


def is_external(finding: Any) -> bool:
    """True when a finding came from an engine other than GreyIQ's own.

    The predicate behind the confirm veto in ``report._has_captured_artifact``. Kept here,
    beside the ingest that sets the field, so the writer and the reader of ``source``
    cannot drift apart. Total: a non-dict or a missing/blank ``source`` is GreyIQ's own,
    which keeps every pre-existing finding — none of which carries ``source`` — unaffected.
    """
    if not isinstance(finding, dict):
        return False
    source = str(finding.get("source") or "").strip().lower()
    return bool(source) and source not in ("greyiq", "bughunter")


def greyiq_proved(finding: Any) -> bool:
    """True when GreyIQ's own prover later raised this external finding.

    Nothing sets this today: no GreyIQ service currently re-proves an imported candidate,
    and ``ssrf`` / ``auth`` / ``access-control`` are not in ``prover_classes.PROVER_CLASSES``
    at all, so candidates in those classes are not reachable by the active prover even in
    principle. The hook exists so that when a re-prove path is built it has one documented
    place to assert itself, rather than each caller inventing a flag.
    """
    if not isinstance(finding, dict):
        return False
    if finding.get("_greyiq_proved") is True:
        return True
    detail = finding.get("source_detail")
    return isinstance(detail, dict) and detail.get("greyiq_proved") is True
