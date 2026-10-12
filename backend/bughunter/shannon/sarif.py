"""Shannon SARIF 2.1.0 -> neutral candidate records.

Shannon (``KeygraphHQ/shannon``, AGPL-3.0) is an external autonomous web-pentest
engine. It is NOT vendored: it runs as an arm's-length subprocess and GreyIQ reads
its output files. This module is the parser for one of those files.

WHY SARIF AND NOT ``report.json``
---------------------------------
Shannon writes richer findings to ``.shannon/deliverables/report.json`` — severity
granularity, confidence, reproduction steps, proof-of-impact. We deliberately do not
read it yet, for two independent reasons:

1. **No fixture exists.** There is no ``report.json`` committed anywhere in Shannon's
   tree — no sample, no test, no fixture (upstream has no ``*.test.ts`` at all). A
   parser written against its TypeBox schema alone would be a parser written against
   bytes nobody has seen, which is the failure ``docs/tacnoc-integration.md`` refused
   to repeat. ``report.sarif`` by contrast has three real committed generated files
   under Shannon's ``benchmark/``, and this parser is tested against all three.
2. **We do not want the evidence.** ``report.json``'s ``exploitation_steps`` and
   ``proof_of_impact`` carry raw HTTP transcripts, and Shannon's own prompt rule
   (``prompts/shared/exploitation/_credentials-in-findings.txt``) redacts only the
   credentials it was *configured* with while explicitly keeping "a session token you
   captured, a key you extracted, data you exfiltrated". Importing that wholesale
   would pull live third-party secrets into GreyIQ's store. The SARIF omits those
   fields by construction (``sarif-renderer.ts``: "Exploitation steps and proof of
   impact are deliberately absent"), which makes it the *safer* surface, not just the
   testable one.

WHAT THIS MODULE REFUSES TO DO
------------------------------
It does not assign severity and it does not assign a CWE from a Shannon class alone.

SARIF ``level`` collapses ``critical`` and ``high`` into ``"error"``
(``sarif-renderer.ts:119-129``, and there is no ``security-severity`` property), so the
true severity is simply not in this file. We record the band and let GreyIQ's own
engine rate the finding if it ever confirms it.

For CWE, the only honest source here is ``properties.sastRuleId``, which in practice
holds a real CWE id ("CWE-89", "CWE-639", ...). Shannon's coarse 6-value class is not a
CWE and neither is its OWASP taxon: measured across the three benchmark SARIFs,
``shannon/auth`` findings carry A01, A02, A04 *and* A07, and ``shannon/miscellaneous``
carries six different taxa. A class-level CWE guess would be invented precision, so
classes that cannot resolve exactly abstain and return ''. ``taxonomy.match_weakness_id``
already fails closed on '' by omitting the weakness id, which is the pre-existing
behaviour for an unmapped finding.

Pure / frozen-safe: standard library only, no I/O beyond an explicit file read, no
network. Every function is total — malformed input yields an empty result rather than
raising, because a half-parsed scan must not take a hunt down.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Shannon's one-rule-per-class ids (sarif-renderer.ts:39-112). The sixth, miscellaneous,
# is the fall-through for any category the renderer does not recognize.
SHANNON_RULE_CLASSES: tuple[str, ...] = (
    "shannon/injection",
    "shannon/xss",
    "shannon/auth",
    "shannon/authz",
    "shannon/ssrf",
    "shannon/miscellaneous",
)

# Shannon class -> GreyIQ CWE, for the classes where one CWE is genuinely the class and
# not a guess. Deliberately partial:
#   * xss  -> 79 is the class itself; 80 (stored) is NOT claimed, because the SARIF does
#             not say whether the sink was stored or reflected.
#   * ssrf -> 918 is exact and unambiguous.
#   * auth/authz -> the generic parents GreyIQ's own engine already uses for these
#             classes ("CWE-287 / CWE-384" for auth, "CWE-639 / CWE-284" for access
#             control, per taxonomy.cwe_numbers). We take the parent, never the specific
#             child, because nothing in the SARIF establishes session fixation over
#             broken auth, or IDOR over missing access control.
#   * injection -> ABSENT ON PURPOSE. The class spans SQLi (89), command injection and
#             RCE (78/94), path traversal (22) and SSTI (1336). Picking one would be
#             fabricated precision. These resolve only via sastRuleId.
#   * miscellaneous -> ABSENT ON PURPOSE. It is a fall-through bucket, not a class.
_CLASS_TO_CWE: dict[str, str] = {
    "shannon/xss": "79",
    "shannon/ssrf": "918",
    "shannon/auth": "287",
    "shannon/authz": "284",
}

# SARIF level -> the severity band Shannon could still express. "error" is ambiguous
# between critical and high and is recorded as such rather than resolved.
_LEVEL_TO_BAND: dict[str, str] = {
    "error": "critical-or-high",
    "warning": "medium",
    "note": "low",
}

_CWE_IN_TEXT = re.compile(r"CWE[-\s_]?(\d+)", re.IGNORECASE)
_FIRST_BOLD = re.compile(r"\*\*(.+?)\*\*", re.DOTALL)


@dataclass(frozen=True)
class CodeLocation:
    """One source location Shannon attached to a finding.

    ``role`` is Shannon's own word for the location's part in the data flow — "sink",
    "source" or "guard" — carried in the SARIF location's ``message.text``. A validated
    SAST source location instead carries the prose "Validated SAST source location
    (CWE-89)", which we normalize to role ``"sast-source"``.

    ``message`` keeps that ``message.text`` verbatim, because normalizing ``role`` discards
    the only place the CWE appears. _resolve_cwe mines this field; it used to mine ``file``,
    an artifact URI that never carries a CWE, which made the mining branch unreachable.
    """

    file: str = ""
    start_line: int | None = None
    end_line: int | None = None
    role: str = ""
    symbol: str = ""
    message: str = ""


@dataclass(frozen=True)
class ShannonCandidate:
    """One Shannon SARIF result, normalized. A CANDIDATE, never a proof.

    Shannon's ``status: "exploited"`` means Shannon's own agent believed it demonstrated
    impact. It is recorded in ``shannon_status`` as provenance and is NOT a GreyIQ proof
    state: GreyIQ's captured-artifact gate is the only thing that confirms a finding.
    """

    finding_id: str = ""
    rule_id: str = ""
    title: str = ""
    severity_band: str = ""
    owasp_taxon: str = ""
    cwe: str = ""
    cwe_source: str = ""
    http_method: str = ""
    http_target: str = ""
    parameter: str = ""
    shannon_status: str = ""
    auth_state: str = ""
    prerequisites: str = ""
    sast_rule_id: str = ""
    narrative: str = ""
    locations: tuple[CodeLocation, ...] = ()
    related_locations: tuple[CodeLocation, ...] = ()


@dataclass(frozen=True)
class ShannonRun:
    """A parsed ``report.sarif``, plus the run-level provenance GreyIQ should record."""

    target: str = ""
    assessment_date: str = ""
    model: str = ""
    automation_id: str = ""
    tool_name: str = ""
    execution_successful: bool | None = None
    candidates: tuple[ShannonCandidate, ...] = ()
    dropped: int = 0
    warnings: tuple[str, ...] = field(default=())


def _text(value: Any) -> str:
    """A trimmed string for any input. Total: None and non-strings yield ''."""
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    return str(value).strip()


def _positive_int(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _cwe_from_text(value: Any) -> str:
    """The bare CWE number named in a string, or ''.

    Shannon's ``sastRuleId`` is documented as "Validated SAST rule or CWE identifier",
    so it is not guaranteed to be a CWE — in the three benchmark SARIFs it always is.
    A value that names no CWE yields '' and the caller abstains rather than inventing one.
    """
    match = _CWE_IN_TEXT.search(_text(value))
    return match.group(1) if match else ""


def _title(message: dict[str, Any]) -> str:
    """The finding title.

    ``message.markdown`` opens with the title as a bold span and ``message.text`` opens
    with the same title as its first sentence (verified against all three benchmark
    SARIFs). The bold span is preferred because a title containing ". " would split the
    plain-text form in the wrong place.
    """
    bold = _FIRST_BOLD.search(_text(message.get("markdown")))
    if bold:
        title = bold.group(1).strip()
        if title:
            return title
    plain = _text(message.get("text"))
    if not plain:
        return ""
    # Fall back to the first sentence. Guard the degenerate case where the whole message
    # is one unpunctuated blob by capping what we are willing to call a title.
    head = plain.split(". ")[0].strip()
    return head if head and len(head) <= 300 else plain[:300].strip()


def _location(raw: Any) -> CodeLocation | None:
    """Normalize one SARIF location. Returns None when it carries no usable path."""
    if not isinstance(raw, dict):
        return None
    physical = raw.get("physicalLocation")
    physical = physical if isinstance(physical, dict) else {}
    artifact = physical.get("artifactLocation")
    artifact = artifact if isinstance(artifact, dict) else {}
    path = _text(artifact.get("uri"))
    if not path:
        return None

    region = physical.get("region")
    region = region if isinstance(region, dict) else {}

    message = raw.get("message")
    message = message if isinstance(message, dict) else {}
    text = _text(message.get("text"))
    role = text
    # "Validated SAST source location (CWE-89)" is prose, not a data-flow role. Normalize
    # it so a consumer can switch on role without string-matching an English sentence, and
    # keep the prose in `message` — the CWE it names is not recoverable from anywhere else.
    if role.lower().startswith("validated sast source location"):
        role = "sast-source"

    logical = raw.get("logicalLocations")
    symbol = ""
    if isinstance(logical, list):
        for entry in logical:
            if isinstance(entry, dict) and _text(entry.get("name")):
                symbol = _text(entry.get("name"))
                break

    return CodeLocation(
        file=path,
        start_line=_positive_int(region.get("startLine")),
        end_line=_positive_int(region.get("endLine")),
        role=role,
        symbol=symbol,
        message=text,
    )


def _locations(raw: Any) -> tuple[CodeLocation, ...]:
    if not isinstance(raw, list):
        return ()
    out = [loc for loc in (_location(item) for item in raw) if loc is not None]
    return tuple(out)


def _resolve_cwe(rule_id: str, sast_rule_id: str, locations: tuple[CodeLocation, ...]) -> tuple[str, str]:
    """(cwe, cwe_source). Exact sources first; abstain rather than guess.

    Order: the validated SAST rule id, then a CWE named in a SAST location's prose, then
    the class-level map for the four unambiguous classes. ``injection`` and
    ``miscellaneous`` have no class-level entry and so return ('', '') unless a SAST id
    supplied one.
    """
    from_sast = _cwe_from_text(sast_rule_id)
    if from_sast:
        return from_sast, "shannon-sast-rule"

    for loc in locations:
        if loc.role == "sast-source":
            mined = _cwe_from_text(loc.message)
            if mined:
                return mined, "shannon-sast-location"

    class_level = _CLASS_TO_CWE.get(rule_id, "")
    if class_level:
        return class_level, "shannon-class"
    return "", ""


def _candidate(raw: Any) -> ShannonCandidate | None:
    """Normalize one SARIF result. Returns None when it carries no finding id.

    A result with no ``properties.findingId`` is unusable: that id is the only stable key
    Shannon emits (it writes no ``partialFingerprints`` at all), so without it a finding
    cannot be correlated across resumes or re-runs.
    """
    if not isinstance(raw, dict):
        return None

    properties = raw.get("properties")
    properties = properties if isinstance(properties, dict) else {}
    finding_id = _text(properties.get("findingId"))
    if not finding_id:
        return None

    message = raw.get("message")
    message = message if isinstance(message, dict) else {}

    web_request = raw.get("webRequest")
    web_request = web_request if isinstance(web_request, dict) else {}

    taxa = raw.get("taxa")
    owasp = ""
    if isinstance(taxa, list):
        for entry in taxa:
            if isinstance(entry, dict) and _text(entry.get("id")):
                owasp = _text(entry.get("id"))
                break

    rule_id = _text(raw.get("ruleId"))
    locations = _locations(raw.get("locations"))
    sast_rule_id = _text(properties.get("sastRuleId"))
    cwe, cwe_source = _resolve_cwe(rule_id, sast_rule_id, locations)

    return ShannonCandidate(
        finding_id=finding_id,
        rule_id=rule_id,
        title=_title(message),
        severity_band=_LEVEL_TO_BAND.get(_text(raw.get("level")), ""),
        owasp_taxon=owasp,
        cwe=cwe,
        cwe_source=cwe_source,
        http_method=_text(web_request.get("method")),
        http_target=_text(web_request.get("target")),
        parameter=_text(properties.get("parameter")),
        shannon_status=_text(properties.get("status")),
        auth_state=_text(properties.get("authState")),
        prerequisites=_text(properties.get("prerequisites")),
        sast_rule_id=sast_rule_id,
        narrative=_text(message.get("text")),
        locations=locations,
        related_locations=_locations(raw.get("relatedLocations")),
    )


def parse_sarif_text(text: str) -> ShannonRun:
    """Parse SARIF content. Total: malformed input yields an empty run with a warning."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError):
        return ShannonRun(warnings=("report.sarif is not valid JSON",))
    if not isinstance(data, dict):
        return ShannonRun(warnings=("report.sarif is not a SARIF object",))

    warnings: list[str] = []
    version = _text(data.get("version"))
    if version and version != "2.1.0":
        # Recorded, not fatal: a newer SARIF is still very likely readable, and refusing
        # it outright would strand a scan that already spent real requests.
        warnings.append(f"unexpected SARIF version {version!r}; expected 2.1.0")

    runs = data.get("runs")
    if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
        return ShannonRun(warnings=tuple(warnings) + ("report.sarif carries no runs",))
    run = runs[0]
    if len(runs) > 1:
        warnings.append(f"report.sarif carries {len(runs)} runs; only the first was read")

    results = run.get("results")
    results = results if isinstance(results, list) else []
    candidates: list[ShannonCandidate] = []
    seen: set[str] = set()
    dropped = 0
    for item in results:
        candidate = _candidate(item)
        if candidate is None:
            dropped += 1
            continue
        if candidate.finding_id in seen:
            # Shannon rejects duplicate finding_ids upstream, so this means the file was
            # edited or merged. Keep the first and say so rather than silently collapsing.
            dropped += 1
            warnings.append(f"duplicate findingId {candidate.finding_id!r} ignored")
            continue
        seen.add(candidate.finding_id)
        candidates.append(candidate)
    if dropped:
        warnings.append(f"{dropped} SARIF result(s) carried no usable findingId and were dropped")

    run_properties = run.get("properties")
    run_properties = run_properties if isinstance(run_properties, dict) else {}

    driver = ((run.get("tool") or {}) if isinstance(run.get("tool"), dict) else {}).get("driver")
    driver = driver if isinstance(driver, dict) else {}

    automation = run.get("automationDetails")
    automation = automation if isinstance(automation, dict) else {}

    execution: bool | None = None
    invocations = run.get("invocations")
    if isinstance(invocations, list) and invocations and isinstance(invocations[0], dict):
        value = invocations[0].get("executionSuccessful")
        if isinstance(value, bool):
            execution = value
    if execution is False:
        # Shannon sets this false when a vuln class failed and was never assessed. An
        # un-assessed class is not a clean result, and a hunt must not read it as one.
        warnings.append("Shannon reported a partial run: at least one class was not assessed")

    return ShannonRun(
        target=_text(run_properties.get("target")),
        assessment_date=_text(run_properties.get("assessmentDate")),
        model=_text(run_properties.get("model")),
        automation_id=_text(automation.get("id")),
        tool_name=_text(driver.get("name")),
        execution_successful=execution,
        candidates=tuple(candidates),
        dropped=dropped,
        warnings=tuple(warnings),
    )


def parse_sarif_file(path: str | Path) -> ShannonRun:
    """Read and parse a ``report.sarif``. A missing/unreadable file yields an empty run."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return ShannonRun(warnings=(f"could not read {path}: {error}",))
    return parse_sarif_text(text)
