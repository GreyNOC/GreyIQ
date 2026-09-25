"""Bug-bounty report rendering for GreyIQ BugHunter.

Pure, dependency-free, frozen-safe. Takes a fully-prepared *report context*
(built by ``bounty.run_bounty_hunt``) and renders a human-readable Markdown
report and a machine-readable JSON sidecar. The Markdown report is written for
an authorized bug-bounty submission: executive summary, scope/authorization,
methodology, per-finding evidence + attack plan (reproduction / PoC steps),
impact, remediation, references, and a manual-testing checklist.

This module never reaches the network or an LLM itself — the optional analyst
narrative (``ctx["brain"]``) is produced upstream and merely formatted here, so
a report is always produced even fully offline.
"""

from __future__ import annotations

import re
from typing import Any

from bughunter import impact_model
from bughunter import secret_classification
from bughunter import sensitive_data
from bughunter.code_scanner.redaction import redact_secret, redact_text

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# Upper bound of each CVSS v3.1 severity band. Used to stamp a representative base_score when the QA
# gate must force a finding's tier DOWN directly (no conforming vector could be produced) so the
# score and the capped word never disagree.
_CVSS_TIER_CEIL = {"critical": 10.0, "high": 8.9, "medium": 6.9, "low": 3.9, "info": 0.0, "none": 0.0}
_SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

_SUBMISSION_CHECKLIST = [
    "Target, endpoint, account role, and program scope are named.",
    "Steps reproduce the issue from a clean session with minimal assumptions.",
    "Evidence proves security impact without exposing unrelated sensitive data.",
    "Impact is tied to realistic attacker capability and affected data or action.",
    "Remediation is concrete enough for the owner to verify a fix.",
]

_RETEST_CHECKLIST = [
    "Replay the original proof after the fix and confirm the vulnerable behavior is gone.",
    "Try the closest bypass variants: alternate HTTP verb, content type, role, object id, or encoding.",
    "Confirm the fix did not only hide the client-side path while leaving the server-side action exposed.",
]

_CHAIN_RULES = [
    ({"disclosure", "access-control"}, "Information disclosure plus access-control leads can become stronger IDOR/BOLA reports."),
    ({"secrets", "auth"}, "Exposed credentials plus weak session/auth controls may support account or environment compromise."),
    ({"redirect", "auth"}, "Open redirects inside auth flows may increase phishing, OAuth, or token-leak impact."),
    ({"cors", "auth"}, "CORS trust issues matter most when credentialed browser reads expose authenticated data."),
    ({"supply-chain", "secrets"}, "Build/dependency issues become higher value when they can reach release secrets or deploy artifacts."),
]

# Short uppercase tag per next-step priority (severity word or action tier), for
# the guided-next-steps list. Plain text — frozen-safe, no glyph dependency.
_NEXT_STEP_TAG = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO",
    "setup": "SETUP", "hunt": "HUNT", "chain": "CHAIN", "expand": "EXPAND",
    "submit": "SUBMIT", "retest": "RETEST",
}

_JWT_CREDENTIAL_RULE_IDS = {"secret.jwt", "web.exposed.secret.jwt"}


def normalize_steps(raw: Any) -> list[str]:
    """Coerce reproduction ``steps`` into a clean list ready for 1-based numbering.

    ``steps`` is meant to be a list of strings, but the LLM brain (or a cached/imported
    ctx) can hand us a single newline-delimited string, or list items that already carry
    their own ``1.`` / ``-`` marker. Numbering those naively double-numbers ("1. 1. …"),
    or — for a bare string — iterates it CHARACTER by character ("1. S" / "2. e" / "3. n"
    …), which is exactly the garbled "steps to reproduce" a HackerOne triager rejects.
    This splits a string on newlines (never char-by-char), drops blanks, and strips any
    leading enumerator the source already added, so the renderer's numbering is the only
    numbering. Returns a list of clean step strings.

    Newlines are split out of LIST ITEMS too, not just a bare string. A brain that returns
    ``["1. Send the request\n2. Observe the reflection\n3. Confirm it executes"]`` means three
    steps; treating it as one left the inner ``2.``/``3.`` markers embedded in step 1, so the
    rendered procedure was numbered by two different authorities at once and every consumer
    that counts steps saw a single step where the triager reads three.

    But a multiline list item is NOT always several steps. One step legitimately carries a
    multi-line ``curl`` continuation or a fenced block, and splitting those turns every request
    line and every fence marker into its own numbered step — which breaks the fence and hands the
    triager a garbled procedure, the same failure this function exists to prevent. So a LIST item
    is split only when its lines really are several enumerated steps; otherwise it stays one step,
    and a fenced region is never split at all. Lines inside an enumerated block that do not start
    their own step are kept as continuation of the step above them.

    A bare STRING is different: it carries no step boundaries of its own, so newlines are the only
    signal available and each line is a step (never characters — that produced "1. S" / "2. e")."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return _split_steps_block(raw, split_plain_lines=True)
    items = raw if isinstance(raw, (list, tuple)) else [raw]
    out: list[str] = []
    for item in items:
        out.extend(_split_steps_block(str(item), split_plain_lines=False))
    return out


_STEP_ENUMERATOR_RE = re.compile(r"^\s*(?:\d+[.)]|[-*•])\s+")
_STEP_FENCE_RE = re.compile(r"^\s*(?:```|~~~)")


def _split_steps_block(text: str, *, split_plain_lines: bool) -> list[str]:
    """Split ONE steps block into clean steps. See :func:`normalize_steps` for the rules."""
    lines = text.splitlines()
    if not lines:
        return []
    # Two or more enumerators mean the block really is a list of steps written into one value.
    enumerated = sum(1 for line in lines if _STEP_ENUMERATOR_RE.match(line)) >= 2
    out: list[str] = []
    buf: list[str] = []
    in_fence = False

    def flush() -> None:
        if buf:
            joined = "\n".join(buf).strip()
            if joined:
                out.append(joined)
            buf.clear()

    for line in lines:
        if _STEP_FENCE_RE.match(line):
            in_fence = not in_fence
            buf.append(line)
            continue
        if in_fence:  # never split inside a fenced example
            buf.append(line)
            continue
        if enumerated:
            if _STEP_ENUMERATOR_RE.match(line):
                flush()
                buf.append(_STEP_ENUMERATOR_RE.sub("", line.strip()).strip())
            elif line.strip():
                buf.append(line.rstrip())  # continuation of the step above
        elif split_plain_lines:
            flush()
            stripped = _STEP_ENUMERATOR_RE.sub("", line.strip()).strip()
            if stripped:
                buf.append(stripped)
        else:
            buf.append(line.rstrip())
    flush()
    # A single-step item may still carry one leading enumerator to strip.
    return [_STEP_ENUMERATOR_RE.sub("", s, count=1).strip() if _STEP_ENUMERATOR_RE.match(s) else s
            for s in out if s.strip()]


def resolve_severity(finding: dict[str, Any], plan: dict[str, Any] | None = None) -> str:
    """The single source of truth for a finding's severity word (lowercased).

    The CVSS base severity modelled for the attack plan (impact_model) is authoritative
    when present AND a real recognized tier — it reflects the analysed impact — and wins
    over the raw scanner label carried on the finding. impact_model.cvss_severity() can
    return the literal string "None" for a base score of 0.0 (e.g. a brain-supplied
    vector with C:N/I:N/A:N) — that is a valid CVSS OUTCOME, not a valid SEVERITY TIER,
    so it is never trusted as authoritative here; it falls through to the finding's own
    severity instead, exactly like a missing/absent CVSS block would. Falls back to the
    finding's own ``severity``, then ``"low"``. Every render path (the default report's
    table/detail/triage, the per-platform report, and the HackerOne ``severity_rating``)
    routes through here, so the severity shown for a finding can never disagree across
    the different outputs the operator submits."""
    cvss = plan.get("cvss") if isinstance(plan, dict) else None
    tier = ""
    if isinstance(cvss, dict):
        cvss_severity = str(cvss.get("base_severity") or "").strip().lower()
        if cvss_severity in _SEVERITY_ORDER:
            tier = cvss_severity
    if not tier:
        tier = str(finding.get("severity") or "low").strip().lower()
    # Strict-secret clamp (defense in depth): an exposed key/token that classification did NOT confirm
    # can NEVER read Medium+, regardless of any plan/brain CVSS. The classification cap wins over CVSS —
    # a page-source / regex match must not be dressed up as a High secret.
    cls = str(finding.get("secret_classification") or "")
    if cls and cls != secret_classification.CONFIRMED_SECRET:
        capped = secret_classification.severity_for_classification(cls, tier)
        if _SEVERITY_ORDER.get(capped, 0) < _SEVERITY_ORDER.get(tier, 0):
            return capped
    return tier


def _sev_rank(finding: dict[str, Any], plan: dict[str, Any] | None = None) -> int:
    return _SEVERITY_ORDER.get(resolve_severity(finding, plan), 0)


def _jwt_replay_value(finding: dict[str, Any]) -> bool | None:
    if "replay_authenticated" in finding:
        value = finding.get("replay_authenticated")
    elif "jwt_replay_authenticated" in finding:
        value = finding.get("jwt_replay_authenticated")
    else:
        jwt_exposure = finding.get("jwt_exposure")
        # jwt_exposure can arrive malformed (a non-dict) from a corrupted run cache or an
        # unexpected upstream shape -- guard before .get(), or this crashes the whole
        # report render (_reportable_findings calls this for every secret.jwt finding).
        value = jwt_exposure.get("replay_authenticated") if isinstance(jwt_exposure, dict) else None
    return value if isinstance(value, bool) else None


def _reportable_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop findings that must never reach a report: unconfirmed JWT credential candidates, and
    exposed-secret findings classified ``false_positive`` (a credential the issuer rejected as
    dead/revoked, or a placeholder) — those are noise, not findings. Public-client keys and unverified
    candidates are KEPT (already downgraded to Info/Low) so the report can show them clearly marked
    'not reportable yet' / 'informational only' rather than silently hiding them."""
    out: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id in _JWT_CREDENTIAL_RULE_IDS and _jwt_replay_value(finding) is not True:
            continue
        if str(finding.get("secret_classification") or "") == secret_classification.FALSE_POSITIVE:
            continue
        out.append(finding)
    return out


def severity_counts(findings: list[dict[str, Any]], attack_plans: dict[str, Any] | None = None) -> dict[str, int]:
    plans = attack_plans or {}
    counts = {key: 0 for key in _SEVERITY_ORDER}
    for finding in findings:
        sev = resolve_severity(finding, plans.get(finding.get("ref")))
        if sev in counts:
            counts[sev] += 1
    return counts


# ----------------------------- pre-export QA gate -----------------------------
# Response statuses that, on their own, do NOT demonstrate sensitive-data exposure — a
# reflected-Origin CORS header on one of these proves the header behaviour, not impact.
_NON_SENSITIVE_STATUS = {"301", "302", "303", "307", "308", "204", "401", "403", "404", "410"}
# Confidentiality-driven classes where a C:H / High claim MUST be backed by a captured
# sensitive read. Injection/RCE/SQLi keep their modelled C:H (their impact isn't a data read).
_CONFIDENTIALITY_CLASSES = {"cors", "disclosure"}


def _response_status_code(finding: dict[str, Any]) -> str:
    pe = finding.get("proof_evidence") if isinstance(finding.get("proof_evidence"), dict) else {}
    m = re.search(r"\b([1-5]\d{2})\b", str(pe.get("response_status") or ""))
    return m.group(1) if m else ""


def _sensitive_read_captured(finding: dict[str, Any]) -> bool:
    """True only when the captured readable body actually NAMES high-confidence sensitive data —
    either the labels the capturing check classified on the raw body, or (fallback) a re-scan of the
    redacted excerpt. This is the single 'sensitive data was really read' signal the QA gate trusts."""
    pe = finding.get("proof_evidence") if isinstance(finding.get("proof_evidence"), dict) else {}
    if str(pe.get("sensitive_data_labels") or "").strip():
        return True
    rd = str(pe.get("read_data") or "").strip()
    return bool(rd and sensitive_data.summarize(rd))


def _browser_poc_confirmed(finding: dict[str, Any]) -> bool:
    """True only when a browser-hosted PoC on an ATTACKER origin actually read the cross-origin
    response — the one evidence that lifts a credentialed-CORS misconfig to High. The active prover
    reads same-site (curl-equivalent) and never sets this, so it is False unless an operator/dynamic
    PoC explicitly records ``cross_origin_read_confirmed`` on the finding."""
    return finding.get("cross_origin_read_confirmed") is True


def _sub_metric(vector: str, key: str, value: str) -> str:
    """Replace CVSS metric ``key`` with ``value``, boundary-anchored so ``C`` (Confidentiality) is
    never matched inside ``AC`` (Attack Complexity) — a naive ``vector.replace("C:H","C:L")`` corrupts
    ``AC:H`` into ``AC:L``. Leaves the vector unchanged when the metric is absent."""
    return re.sub(rf"(^|/){re.escape(key)}:[A-Za-z]+", rf"\1{key}:{value}", vector)


def _has_metric(vector: str, key: str, value: str) -> bool:
    return re.search(rf"(^|/){re.escape(key)}:{re.escape(value)}(/|$)", vector) is not None


def _set_cvss_vector(cvss: dict[str, Any], vector: str, note: str) -> None:
    scored = impact_model.cvss_base_score(vector)
    cvss["vector"] = vector
    cvss["base_score"] = scored["score"]
    cvss["base_severity"] = scored["severity"]
    prior = str(cvss.get("justification") or "").rstrip(". ")
    cvss["justification"] = (f"{prior}. " if prior else "") + note


def qa_validate_report(findings: list[dict[str, Any]], attack_plans: dict[str, Any] | None = None) -> dict[str, Any]:
    """Final QA pass GreyIQ runs BEFORE it exports a report. It answers the evidence-vs-claim
    questions a triager would ask and applies SAFE, downgrade-only corrections in place — a report can
    only get MORE conservative here, never more severe. Returns::

        {"ok": bool, "issues": [ {ref, severity, question, verdict, action, detail} , ... ]}

    Enforced invariants (the claims that must be backed by real evidence):
      * Claims sensitive-data exposure / C:H  → a sensitive read must be captured, else strip C:H.
      * Claims High on a CORS finding          → a browser cross-origin PoC must exist, else cap Medium.
      * Response was 404/403/204/redirect + no sensitive read → cap the demonstrated impact to Low.
    Class-general claim-integrity checks (every class, INFORMATIONAL — recorded, never a cap):
      * Observed and control results are identical → no differential is established.
      * Proof CLAIMS 'confirmed' but the confirm gate rejects the evidence → rendered as candidate.
    Both are gated on what the finding CLAIMS, never on artifact ABSENCE: a static code finding has
    no runtime artifact by nature and claims nothing, so it passes untouched — a naive
    "no artifact ⇒ cap" rule would collapse the entire source-scanning profile (a static SQLi
    resolves to Critical from its class template alone) to Low.
    Every correction is recorded as an issue so the change is auditable in the report + JSON."""
    plans = attack_plans or {}
    issues: list[dict[str, Any]] = []

    def _record(finding, ref, question, verdict, action="", detail=""):
        # Stash the finding OBJECT under a private key: the caller (bounty._order_by_resolved_severity)
        # re-sorts findings and reassigns finding["ref"]=F1..N IN PLACE AFTER this QA pass runs — and a
        # QA downgrade is the very thing that moves a finding in that sort — so the frozen ``ref`` string
        # here goes stale precisely for the findings the QA section discusses. ``_resync_qa_refs`` reads
        # this object's CURRENT ref at render time (and strips the key) so the audit trail names the
        # right finding. See the report.py:237 QAQC finding.
        issues.append({"ref": ref, "severity": resolve_severity(finding, plans.get(ref)),
                       "question": question, "verdict": verdict, "action": action, "detail": detail,
                       "_finding": finding})

    def _cap(finding, plan, target_tier, reason):
        cur = resolve_severity(finding, plan)
        target_rank = _SEVERITY_ORDER.get(target_tier, 0)
        if target_rank >= _SEVERITY_ORDER.get(cur, 0):
            return False  # already at/below the cap — nothing to downgrade
        finding["severity"] = target_tier
        cvss = plan.get("cvss") if isinstance(plan.get("cvss"), dict) else None
        if cvss and isinstance(cvss.get("vector"), str):
            # Rewrite to a vector whose computed severity matches the cap so score + word never disagree:
            # drop C:H→C:L and Scope-Changed→Unchanged, then, while STILL above the cap, weaken the
            # remaining leverage metrics one at a time. A single C+AC weaken can leave a residual High
            # (e.g. a brain-supplied vector carrying I:H/A:H), which resolve_severity — trusting the
            # recomputed base_severity — would then re-inflate above the tier the QA section records.
            vec = _sub_metric(_sub_metric(cvss["vector"], "C", "L"), "S", "U")
            for key, low in (("AC", "H"), ("I", "L"), ("A", "L")):
                if _SEVERITY_ORDER.get(impact_model.cvss_base_score(vec)["severity"].lower(), 0) <= target_rank:
                    break
                vec = _sub_metric(vec, key, low)
            _set_cvss_vector(cvss, vec, f"QA cap to {target_tier.title()}: {reason}")
        # Final guard: if there was no usable vector, or the weakened vector STILL computes above the
        # cap, stamp the tier directly. resolve_severity trusts cvss.base_severity when it is a
        # recognized tier, so a residual-High base_severity would silently re-inflate the finding above
        # the downgrade the QA section reports — never record a downgrade resolve_severity won't honor.
        if cvss and _SEVERITY_ORDER.get(str(cvss.get("base_severity") or "").strip().lower(), 0) > target_rank:
            cvss["base_severity"] = _SEVERITY_LABEL.get(target_tier, target_tier.title())
            cvss["base_score"] = _CVSS_TIER_CEIL.get(target_tier, 0.0)
        return True

    for finding in findings:
        ref = finding.get("ref")
        plan = plans.get(ref) or {}
        cls = str(finding.get("class_id") or "").lower()
        detail = _proof_of_impact_detail(finding, plan)
        status_code = _response_status_code(finding)
        sensitive = _sensitive_read_captured(finding)
        browser_poc = _browser_poc_confirmed(finding)

        # Q1 — claims High/Critical on a CORS finding? Requires a browser cross-origin PoC.
        if cls == "cors" and _SEVERITY_ORDER.get(resolve_severity(finding, plan), 0) >= _SEVERITY_ORDER["high"] and not browser_poc:
            if _cap(finding, plan, "medium", "no browser cross-origin PoC read sensitive victim data; curl/same-site "
                                              "evidence proves header behaviour only"):
                _record(finding, ref, "Does the report claim High CORS severity?", "unsupported",
                        "downgraded to Medium", "High CORS requires a browser-hosted PoC reading sensitive data cross-origin.")

        # Q2 — response is 404/403/204/redirect and no sensitive read → cap demonstrated impact to Low.
        if cls in _CONFIDENTIALITY_CLASSES and status_code in _NON_SENSITIVE_STATUS and not sensitive:
            if _cap(finding, plan, "low", f"the tested endpoint returned HTTP {status_code} with no sensitive data in "
                                          "the readable response"):
                _record(finding, ref, "Does the response status show 404/403/204/redirect?", "yes",
                        "capped demonstrated impact to Low",
                        f"HTTP {status_code} with no sensitive read — misconfiguration confirmed, impact not demonstrated.")

        # Q3 — claims sensitive-data exposure (C:H) with no sensitive read captured → strip C:H. Re-read
        # the plan CVSS live (Q1/Q2 may already have rewritten it) so a stale vector can't re-inflate it.
        cvss = plan.get("cvss") if isinstance(plan.get("cvss"), dict) else None
        vector = str((cvss or {}).get("vector") or "")
        if cls in _CONFIDENTIALITY_CLASSES and cvss and _has_metric(vector, "C", "H") and not sensitive:
            _set_cvss_vector(cvss, _sub_metric(vector, "C", "L"),
                             "QA: C:H removed — no sensitive authenticated data was captured in the readable response")
            # Re-cap the finding severity to the recomputed CVSS tier so the two agree.
            finding["severity"] = min(resolve_severity(finding, plan), cvss["base_severity"].lower(),
                                      key=lambda t: _SEVERITY_ORDER.get(t, 0))
            _record(finding, ref, "Does the report claim sensitive data exposure (C:H)?", "unsupported",
                    "removed C:H from the CVSS vector", "No sensitive data was present in the captured readable response.")

        # Q4 — curl-only evidence must be labelled server behaviour, not browser exploitability. The
        # active prover already writes this into the proof, so here we only flag when a confirmed CORS
        # finding lacks the browser-PoC note (informational; no downgrade beyond Q1).
        if cls == "cors" and detail.get("status") == "confirmed" and not browser_poc:
            _record(finding, ref, "Is CORS evidence curl-only (server behaviour)?", "yes", "",
                    "Labelled as server-side header behaviour; cross-origin browser exploitability is not "
                    "proven from curl/same-site evidence.")

        # Q5/Q6 — class-general claim integrity. These two are the checks the investigation cortex
        # already makes for EVERY class (its `non-differential-control` and
        # `confirmation-without-artifact` contradictions); the export gate never surfaced them, so a
        # triager reading only the report saw a silent 'candidate' with no explanation of why.
        # Both are INFORMATIONAL (empty action): they never move severity and never flip `ok`.
        # _proof_of_impact_detail already renders these findings as 'candidate' — re-punishing them
        # with a severity cap would double-count, and a severity cap keyed on evidence would also
        # be the exact rule that guts the static-scanning profile (see the docstring).
        proof = _proof_value(finding, plan)
        claimed = _explicit_proof_status(finding, plan, proof)
        if proof_is_non_differential(proof):
            # The specific reason wins: an identical pair IS why there is no accepted artifact,
            # so Q5 is not recorded on top of it — one bullet per root cause.
            _record(finding, ref, "Do the observed and control results actually differ?", "no", "",
                    "Observed and control are identical once normalized, so no differential is "
                    "established; the confirm gate refuses it and the finding is not confirmed on "
                    "this evidence.")
        elif claimed == "confirmed" and not _has_captured_artifact(finding, proof):
            _record(finding, ref, "Does the claimed 'confirmed' proof have a captured artifact?", "unsupported", "",
                    "The proof asserts confirmation but no artifact the confirm gate accepts backs it "
                    "(narrative text and a passive request are not proof); rendered as candidate, not "
                    "confirmed.")

    return {"ok": not any(i.get("action") for i in issues), "issues": issues}


def _md_escape_cell(text: str) -> str:
    """Neutralize a value for a markdown TABLE CELL.

    Escaping only ``|`` and ``\\n`` left a bare carriage return intact, and every renderer
    treats a lone CR as a line break — so a target-derived string (a JSON key, a cookie name,
    a finding title) carrying ``\\r`` ended the table row early and let whatever followed be
    parsed as markdown at document level, including a heading. Strip the whole C0 range plus
    DEL rather than enumerate the breaking characters."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(text))
    return cleaned.replace("|", "\\|").strip()


def _safe_display_int(value: Any) -> int:
    """Tolerant integer coercion for advisory report metadata."""
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _safe_display_number(value: Any) -> int | float:
    try:
        number = float(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    if number != number or abs(number) > 1_000_000:  # NaN / infinity / absurd advisory values
        return 0
    return int(number) if number.is_integer() else round(number, 1)


def _fence(text: str) -> str:
    """A code-fence longer than any backtick run in ``text`` so embedded
    triple-backticks (from scanned target content or LLM output) can't break out."""
    longest = max((len(run) for run in re.findall(r"`+", text or "")), default=0)
    return "`" * max(3, longest + 1)


def _poc_lang(text: str) -> str:
    """Language tag for a fenced PoC block so a reviewer — and HackerOne's automated report
    check — recognizes it as code. A bare ``` fence around an HTML PoC gets flagged as
    "missing PoC code", so tag the runnable-HTML shape GreyIQ emits (CORS/CSRF/redirect PoCs)
    as ``html``. Returns "" (bare fence) for anything we can't confidently classify."""
    t = (text or "").lstrip().lower()
    if t.startswith(("<!doctype", "<html", "<meta", "<body", "<script")) or "<script" in t:
        return "html"
    return ""


def _code(value: str) -> str:
    """Inline code span that can't be broken by a backtick in the value, and is
    safe inside a Markdown table cell (pipes/newlines neutralized)."""
    text = str(value or "").replace("\n", " ")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if (text.startswith("`") or text.endswith("`")) else ""
    return f"{ticks}{pad}{text}{pad}{ticks}".replace("|", "\\|")


def _location(finding: dict[str, Any]) -> str:
    loc = str(finding.get("location") or finding.get("file_path") or "")
    line = finding.get("line") or finding.get("line_start")
    if line and str(line) not in loc:
        end = finding.get("line_end")
        if end and end != line:  # a multi-line sink renders as a range, not just the first line
            return f"{loc}:{line}-{end}"
        return f"{loc}:{line}"
    return loc


def _grouped_locations(finding: dict[str, Any]) -> list[str]:
    """The full affected-location list for a finding that collapsed duplicate leads
    (bounty._group_duplicate_leads) — only when there are genuinely 2+, so a
    non-grouped finding renders exactly as it did before grouping existed."""
    count = finding.get("group_count")
    locs = finding.get("grouped_locations")
    if isinstance(count, int) and count > 1 and isinstance(locs, list) and len(locs) > 1:
        return [str(loc).strip() for loc in locs if str(loc).strip()]
    return []


def _location_cell(finding: dict[str, Any]) -> str:
    """Findings-table location cell — the representative location, plus a '(+N more)'
    hint when this row stands in for several grouped duplicate leads."""
    cell = _code(_location(finding))
    grouped = _grouped_locations(finding)
    if grouped:
        cell += f" _(+{len(grouped) - 1} more)_"
    return cell


def _append_grouped_locations(out: list[str], finding: dict[str, Any]) -> None:
    """List every location a grouped duplicate-lead finding covers, with the 'file once'
    guidance. No-op for a normal (ungrouped) finding."""
    grouped = _grouped_locations(finding)
    if not grouped:
        return
    out.append(
        f"- **Instances:** {len(grouped)} locations share this root cause — "
        "file a single report and list every affected path:"
    )
    for loc in grouped[:25]:
        out.append(f"  - {_code(loc)}")
    if len(grouped) > 25:
        out.append(f"  - _(+{len(grouped) - 25} more)_")


def _class_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        name = str(finding.get("class_name") or finding.get("category") or "Other").strip() or "Other"
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0].lower())))


def _chain_leads(findings: list[dict[str, Any]]) -> list[str]:
    present = {str(f.get("class_id") or f.get("category") or "").lower() for f in findings}
    present |= {str(f.get("category") or "").lower() for f in findings}
    return [note for required, note in _CHAIN_RULES if required <= present]


def _checkbox(done: bool, text: str) -> str:
    return f"- [{'x' if done else ' '}] {text}"


# The chain engine bounds its own step count; this bounds what the MARKDOWN prints per chain
# so one long chain can't dominate the report body (the JSON sidecar keeps every step).
_MAX_CHAIN_STEPS = 8
_CONFIRMED_PROOF_STATUSES = {"confirmed", "verified", "proven", "reproduced"}
_CANDIDATE_PROOF_STATUSES = {"candidate", "unverified", "partial", "needs_confirmation", "needs-confirmation"}
_GENERIC_PROOF_RE = re.compile(
    r"^(?:n/?a|none|unknown|tbd|todo|not captured|needs? confirmation|verify manually|manual verification required)$",
    re.IGNORECASE,
)
_CONCRETE_IMPACT_RE = re.compile(
    r"\b(?:returned|exposed|disclosed|read|downloaded|listed|created|updated|deleted|changed|"
    r"bypassed|authenticated|impersonated|forged|admin|cross-tenant|account|user|customer|order|"
    r"invoice|email|token|secret|session|owned by|as account|before/after|http\s*(?:200|201|204|403))\b",
    re.IGNORECASE,
)


def _proof_value(finding: dict[str, Any], plan: dict[str, Any]) -> Any:
    for source in (plan, finding):
        for key in ("proof_of_impact", "impact_proof", "proof", "impact_evidence"):
            value = source.get(key)
            if value:
                return value
    return None


def _explicit_proof_status(finding: dict[str, Any], plan: dict[str, Any], proof: Any) -> str:
    sources: list[Any] = []
    if isinstance(proof, dict):
        sources.append(proof)
    sources.extend([plan, finding])
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("proof_status", "impact_status", "proof_of_impact_status", "status"):
            raw = str(source.get(key) or "").strip().lower()
            if raw in _CONFIRMED_PROOF_STATUSES:
                return "confirmed"
            if raw in _CANDIDATE_PROOF_STATUSES:
                return "candidate"
        for key in ("impact_confirmed", "proof_confirmed", "replay_authenticated"):
            value = source.get(key)
            if isinstance(value, bool):
                return "confirmed" if value else "candidate"
    if _jwt_replay_value(finding) is True:
        return "confirmed"
    return ""


def _proof_text_is_concrete(text: str) -> bool:
    cleaned = str(text or "").strip()
    if len(cleaned) < 20 or _GENERIC_PROOF_RE.match(cleaned):
        return False
    return bool(_CONCRETE_IMPACT_RE.search(cleaned))


# --- Shared observed-vs-control predicate ---------------------------------------
# ONE definition of "does this proof carry a real differential?", used by the confirm gate below
# AND by the investigation cortex. The two used to hold separate copies of the rule: the gate
# accepted any proof whose observed_result and control_result were both merely NON-EMPTY, while
# investigator._same_observed_and_control flagged an IDENTICAL pair as a blocking contradiction.
# A finding carrying the same bytes on both sides therefore rendered `proof_status: confirmed`
# (and passed submission.submit_to_hackerone's hard gate) in the very report whose Investigation
# section called it `contradicted`. A pair that does not differ is, by definition, not a
# differential — so it is not an artifact. Keeping the normalization in one place is what stops
# the two authorities from parting again; see investigator.has_confirming_artifact for the
# post-mortem of the last time they did.
# A generous SAFETY bound only — never a comparison window. Equality must be decided on the WHOLE
# normalized value: a full HTTP/HTML capture routinely shares thousands of characters of boilerplate
# before the record or marker that differs, so deciding "identical" from a prefix would refuse a
# REAL differential and silently downgrade a confirmed finding to candidate. Captured proof text is
# already bounded far below this upstream (proof_evidence.read_data caps at 8 kB).
_PROOF_TEXT_LIMIT = 200_000


def normalize_proof_text(value: Any, limit: int = _PROOF_TEXT_LIMIT) -> str:
    """Canonical form for comparing an observed result against its control: whitespace-collapsed and
    case-folded over the ENTIRE value, with only a pathological-input safety bound applied."""
    text = str(value or "").strip()[:limit]
    return re.sub(r"\s+", " ", text).strip().lower()


def proof_is_non_differential(proof: Any) -> bool:
    """True when a proof carries an observed/control pair that does NOT differ.

    Both sides must be present. An empty pair is "no differential captured" — the honest default
    of every static/deterministic plan (bounty._deterministic_attack_plan writes "" for both) —
    which is not a differential that FAILED. Only the latter is a claim the evidence contradicts,
    so only the latter is what this predicate names. Written as a positive "non-differential"
    test so a naive ``observed == control`` can never be reintroduced and fire on "" == ""."""
    if not isinstance(proof, dict):
        return False
    observed = normalize_proof_text(proof.get("observed_result"))
    control = normalize_proof_text(proof.get("control_result"))
    return bool(observed) and bool(control) and observed == control


def _has_captured_artifact(
    finding: dict[str, Any],
    proof: Any,
    _observed_result: str = "",
) -> bool:
    """True only when there is a REAL captured artifact proving IMPACT — never from
    narrative prose alone, and never from a bare explicit status. NOTE: the passive web
    ``proof_evidence`` (request line + 'header absent' + response status) is deliberately
    NOT counted here: it proves a GET happened, not security impact, so letting it satisfy
    this gate would let brain prose flip a hardening finding to 'confirmed'. Only
    genuinely impact-proving artifacts qualify.

    A populated ``observed_result`` AND ``control_result`` pair is the actual
    distinguishing signal: every active-prover confirmed check (active_verify_service.py)
    sets BOTH — a captured response plus its negative-control differential — whereas a
    brain (possibly hallucinating, or echoing scanned-page prompt-injection) writing a bare
    ``status: confirmed`` with vague prose essentially never supplies a real differential.
    This keeps an explicit status from single-handedly flipping proof_status (and the
    auto-submit gate behind it) without backing evidence.

    ``_observed_result`` remains as an ignored compatibility argument for callers from
    the v2.1 report API. Narrative text -- even an HTTP-looking string -- is not a
    captured artifact and must never satisfy this gate by itself."""
    # A secret / exposed-key finding that strict classification did NOT confirm can NEVER be a captured
    # artifact — no synthesized issuer narrative, "HTTP 200" mention, or brain prose may promote a public
    # client key or an unverified candidate to confirmed. This is the single authoritative guard.
    _sc = str(finding.get("secret_classification") or "")
    if _sc and _sc != secret_classification.CONFIRMED_SECRET:
        return False
    if _jwt_replay_value(finding) is True:
        return True
    if finding.get("secret_hits"):
        return True
    # A credential the engine actively validated as LIVE is a proven finding — a benign read to the
    # credential's own issuer confirmed it authenticates — BUT ONLY for a genuinely privileged secret.
    # A live Google/Firebase BROWSER key (getProjectConfig 200) is the EXPECTED behaviour of a public
    # client key, not an exploit; secret_classification.has_confirmed_secret_proof requires a
    # validator-backed server token (or a captured active artifact / embedded secret), never a public
    # key's shape — so a live public key never counts as a captured artifact here.
    cred = finding.get("_credential_proof")
    if isinstance(cred, dict) and cred.get("live") is True and secret_classification.has_confirmed_secret_proof(finding):
        return True
    if isinstance(proof, dict) and str(proof.get("observed_result") or "").strip() and str(proof.get("control_result") or "").strip():
        # Both sides present AND they differ. A pair that does not differ is not a differential
        # (proof_is_non_differential). This check lives ONLY in this final branch on purpose: the
        # credential, JWT-replay and secret_hits routes above are independent confirmations and
        # must never be vetoed by a stray identical pair riding alongside a real one.
        return not proof_is_non_differential(proof)
    return False


def _proof_of_impact_detail(finding: dict[str, Any], plan: dict[str, Any]) -> dict[str, str | bool]:
    # A credential the engine validated as LIVE is a proven finding: it has a real observed vs
    # control differential (the issuer accepted this key; an invalid key is rejected). Render that
    # as a confirmed proof of impact directly — the project/domains are impact, not secrets, and the
    # raw key itself lives only in the dedicated credential section, never here.
    cred = finding.get("_credential_proof")
    if isinstance(cred, dict) and cred.get("live") is True and secret_classification.has_confirmed_secret_proof(finding):
        project = str(cred.get("project_id") or "").strip()
        domains = [str(d) for d in (cred.get("authorized_domains") or []) if str(d).strip()]
        principal = str(cred.get("principal") or "").strip()
        scopes = str(cred.get("scopes") or "").strip()
        endpoint = str(cred.get("endpoint") or "the credential's own issuer").strip()
        if project:  # Firebase / Google key
            asset = f"Firebase project '{project}'" + (f" (authorized domains: {', '.join(domains[:20])})" if domains else "")
        elif principal:  # GitHub / Slack token — the account/workspace it controls
            asset = f"the account/workspace the token controls: {principal}" + (f" (scopes: {scopes})" if scopes else "")
        else:
            asset = "the account/project the credential authenticates to"
        poc = redact_text(str(cred.get("poc") or "").strip())[0]
        response = redact_text(str(cred.get("response_excerpt") or cred.get("detail") or "").strip())[0]
        return {
            "status": "confirmed", "ready": True,
            "method": f"benign read-only GET to the credential's issuer ({endpoint}), carrying only the found credential",
            "actor": "an unauthenticated attacker holding the leaked credential",
            "affected_asset": asset,
            "observed_result": f"the leaked credential authenticated successfully (HTTP {cred.get('http_status', '?')})"
                               + (f" to Firebase project '{project}'" if project else (f" as {principal}" if principal else "")),
            "control_result": "an invalid/revoked credential is rejected by the same endpoint — this credential is genuinely live",
            "evidence": str(cred.get("detail") or "").strip(),
            "authenticated_read_request": poc,
            "authenticated_read_response": response,
            "blast_radius": asset,
            "limitations": "", "proof_obligation": "",
        }
    proof = _proof_value(finding, plan)
    detail: dict[str, str | bool] = {
        "status": "missing",
        "ready": False,
        "evidence": "",
        "method": "",
        "observed_result": "",
        "affected_asset": "",
        "actor": "",
        "control_result": "",
        "authenticated_read_request": "",
        "authenticated_read_response": "",
        "blast_radius": "",
        "impact_narrative": "",
        "limitations": "",
        "proof_obligation": "",
    }
    if proof is None:
        return detail

    if isinstance(proof, dict):
        detail["evidence"] = str(
            proof.get("evidence")
            or proof.get("summary")
            or proof.get("description")
            or proof.get("observed_result")
            or ""
        ).strip()
        detail["method"] = str(proof.get("method") or proof.get("test_method") or "").strip()
        detail["observed_result"] = str(proof.get("observed_result") or proof.get("result") or "").strip()
        detail["affected_asset"] = str(proof.get("affected_asset") or proof.get("asset") or proof.get("data") or "").strip()
        detail["actor"] = str(proof.get("actor") or proof.get("role") or proof.get("account") or "").strip()
        detail["control_result"] = str(proof.get("control_result") or proof.get("negative_control") or "").strip()
        detail["authenticated_read_request"] = str(
            proof.get("authenticated_read_request")
            or proof.get("benign_authenticated_read_request")
            or proof.get("validation_request")
            or proof.get("read_request")
            or proof.get("request")
            or ""
        ).strip()
        detail["authenticated_read_response"] = str(
            proof.get("authenticated_read_response")
            or proof.get("benign_authenticated_read_response")
            or proof.get("success_response")
            or proof.get("validation_response")
            or proof.get("read_response")
            or proof.get("response")
            or ""
        ).strip()
        detail["blast_radius"] = str(
            proof.get("blast_radius")
            or proof.get("access_scope")
            or proof.get("impact_scope")
            or ""
        ).strip()
        # AI-written impact statement, grounded in the captured artifacts (brain_narrative). A purely
        # DESCRIPTIVE field — it is never read by _has_captured_artifact / the status gate / CVSS.
        detail["impact_narrative"] = str(proof.get("impact_narrative") or "").strip()
        detail["limitations"] = str(proof.get("limitations") or proof.get("scope_limitations") or proof.get("notes") or "").strip()
        detail["proof_obligation"] = str(proof.get("proof_obligation") or proof.get("obligation") or "").strip()
    else:
        detail["evidence"] = str(proof or "").strip()

    # Re-redact EVERY proof string that lands in the rendered report — a captured
    # response (or an operator-supplied proof field) can carry the very secret/token/PII
    # the finding is about; never double-leak it. All of these are emitted by
    # _append_proof_of_impact, so redact them all, not just evidence/observed_result.
    for _k in (
        "evidence",
        "observed_result",
        "method",
        "affected_asset",
        "actor",
        "control_result",
        "authenticated_read_request",
        "authenticated_read_response",
        "blast_radius",
        "impact_narrative",
        "limitations",
        "proof_obligation",
    ):
        if detail[_k]:
            detail[_k] = redact_text(str(detail[_k]))[0]

    # Status: only a REAL captured artifact + concrete text earns 'confirmed';
    # concrete-looking prose alone caps at 'candidate'. (The descriptive
    # affected_asset/actor fields never drive promotion — only true proof fields do.)
    combined = f"{detail['evidence']} {detail['observed_result']}".strip()
    explicit_status = _explicit_proof_status(finding, plan, proof)
    artifact = _has_captured_artifact(finding, proof)
    if explicit_status == "confirmed":
        # An explicit 'confirmed' — from the active prover, an attack plan, or the brain —
        # is honored ONLY when a real captured artifact backs it. Brain/plan prose alone
        # caps at 'candidate', so a narrative status can never flip a finding to confirmed
        # (and through the auto-submit gate) without proof.
        detail["status"] = "confirmed" if artifact else "candidate"
    elif explicit_status:
        detail["status"] = explicit_status
    elif artifact and _proof_text_is_concrete(combined):
        detail["status"] = "confirmed"
    elif _proof_text_is_concrete(combined) or str(detail["evidence"]).strip() or str(detail["observed_result"]).strip():
        detail["status"] = "candidate"
    detail["ready"] = detail["status"] == "confirmed" and bool(str(detail["evidence"]).strip() or str(detail["observed_result"]).strip())
    return detail


def _proof_status_label(status: str) -> str:
    return {
        "confirmed": "Confirmed",
        "candidate": "Candidate / unverified",
        "missing": "Missing",
    }.get(status, status.replace("_", " ").title() or "Missing")


def _append_proof_of_impact(out: list[str], finding: dict[str, Any], plan: dict[str, Any], *, heading: str) -> None:
    detail = _proof_of_impact_detail(finding, plan)
    status = str(detail["status"])
    obligation = str(detail.get("proof_obligation") or "").strip()
    out.append(heading)
    if status == "missing":
        # Even with nothing captured, the deterministic proof obligation tells the
        # operator the exact artifact to grab — far more useful than a bare warning.
        if obligation:
            out.append("- **Status:** Not yet captured — this is a lead, not a proven finding.")
            affected = str(detail.get("affected_asset") or "").strip()
            if affected:
                out.append(f"- **Affected asset or data:** {affected}")
            out.append(f"- **Proof obligation (capture this to prove impact):** {obligation}")
            out.append("- _Do not submit until the proof obligation above is captured within your authorized scope._")
        else:
            out.append("_Not captured yet. Do not submit until reproduction evidence proves affected data, privilege, or state change._")
        out.append("")
        return
    out.append(f"- **Status:** {_proof_status_label(status)}")
    labels = (
        ("method", "Method"),
        ("actor", "Actor / role"),
        ("affected_asset", "Affected asset or data"),
        ("authenticated_read_request", "Authenticated read request"),
        ("authenticated_read_response", "Authenticated read success response"),
        ("blast_radius", "Blast radius"),
        ("impact_narrative", "Impact (assessed from the captured proof)"),
        ("observed_result", "Observed result"),
        ("control_result", "Control / expected result"),
        ("evidence", "Evidence"),
        ("limitations", "Limitations"),
    )
    for key, label in labels:
        value = str(detail.get(key) or "").strip()
        if value:
            out.append(f"- **{label}:** {value}")
    # A CONFIRMED finding has ALREADY met its proof obligation — the captured artifacts above (the
    # benign authenticated read request + success response + blast radius, or the observed-vs-control
    # differential) ARE the proof. Never print the "capture this to prove impact" obligation, nor the
    # lead "Gap", on a proven finding: asking the operator to prove what the engine already proved is
    # exactly the contradiction that makes a confirmed report read as unproven.
    if status != "confirmed":
        if obligation:
            out.append(f"- **Proof obligation (capture this to prove impact):** {obligation}")
        out.append("- **Gap:** Treat this as a lead until an authorized replay or dynamic check proves the effect.")
    out.append("")


def _captured_request_response_text(finding: dict[str, Any], *, include_read_data: bool = True) -> str:
    """Return the already-captured request/response proof as a plain-text artifact.

    This does not synthesize a new exploit. It only formats fields the scanner or active
    prover already captured and redacts them again before they are rendered in reports.
    """
    pe = finding.get("proof_evidence")
    if not isinstance(pe, dict) or not pe:
        return ""
    request_line = str(pe.get("request_line") or "").strip()
    lines: list[str] = []
    if request_line:
        lines.append(request_line)
        request_header = str(pe.get("request_header") or "").strip()
        if request_header:
            lines.append(request_header)
        lines.append("")
    status = str(pe.get("response_status") or "").strip()
    if status:
        lines.append(status)
    for key in ("response_header", "set_cookie", "matched_value"):
        value = str(pe.get(key) or "").strip()
        if not value:
            continue
        parts = [p.strip() for p in value.split(";") if p.strip()]
        if key == "matched_value" and len(parts) > 1 and all(": " in p for p in parts):
            lines.extend(parts)
        else:
            lines.append(value)
    if include_read_data:
        read_data = str(pe.get("read_data") or "").strip()
        if read_data:
            if lines:
                lines.append("")
            lines.append("Exploit output / response body excerpt:")
            lines.append(read_data[:1500])
    return redact_text("\n".join(lines).strip())[0]


def _screenshot_names(finding: dict[str, Any]) -> list[str]:
    paths = finding.get("screenshot_paths")
    if not isinstance(paths, list) or not paths:
        single = str(finding.get("screenshot_path") or "").strip()
        paths = [single] if single else []
    out: list[str] = []
    for path in paths:
        text = str(path or "").strip()
        if not text:
            continue
        out.append(text.replace("\\", "/").rsplit("/", 1)[-1])
    return out


def _proof_of_concept_text(finding: dict[str, Any], plan: dict[str, Any]) -> str:
    poc = str(plan.get("poc") or "").strip()
    if poc:
        return redact_text(poc[:1500])[0]
    request_response = _captured_request_response_text(finding, include_read_data=False)
    return request_response[:1500]


def _append_proof_of_concept(out: list[str], finding: dict[str, Any], plan: dict[str, Any], *, heading: str) -> None:
    """Render a Proof of concept section on every report surface.

    Prefer the runnable PoC from the attack plan. If there is no standalone command/body,
    fall back to the captured request/response as a text PoC artifact. When neither exists,
    keep the section visible and state exactly what must be captured before submission.
    """
    out.append(heading)
    poc = _proof_of_concept_text(finding, plan)
    if poc:
        fence = _fence(poc)
        out.append(fence + _poc_lang(poc))
        out.append(poc)
        out.append(fence)
    else:
        out.append("_No runnable PoC artifact is captured yet. Attach an authorized request, command, saved HTML PoC, or working screenshot before submission._")
    out.append("")


def _exploitability_artifact_text(finding: dict[str, Any], plan: dict[str, Any]) -> str:
    detail = _proof_of_impact_detail(finding, plan)
    chunks: list[str] = []
    poc = str(plan.get("poc") or "").strip()
    if poc:
        chunks.append("Proof of concept used:\n" + redact_text(poc[:1500])[0])
    request_response = _captured_request_response_text(finding, include_read_data=True)
    if request_response:
        chunks.append("Captured exploit request/response:\n" + request_response)
    source_text = str(finding.get("source_text") or "").strip()
    if source_text:
        chunks.append("Captured browser/source proof sheet:\n" + redact_text(source_text[:2500])[0])
    observed: list[str] = []
    for key, label in (
        ("method", "Method"),
        ("observed_result", "Observed result"),
        ("control_result", "Negative control"),
        ("authenticated_read_request", "Authenticated read request"),
        ("authenticated_read_response", "Authenticated read response"),
        ("evidence", "Evidence"),
    ):
        value = str(detail.get(key) or "").strip()
        if value:
            observed.append(f"{label}: {value}")
    if observed:
        chunks.append("Observed exploit behavior:\n" + "\n".join(observed))
    return "\n\n".join(chunks).strip()[:4500]


def _proof_of_exploit_capture_recipe(finding: dict[str, Any], plan: dict[str, Any],
                                     poi: dict[str, Any]) -> str:
    """Deterministic fallback for reports that do not yet have a live exploit artifact.

    This is not marked "ready"; it is the exact authorized artifact the operator needs to
    capture so every report still carries a useful proof-of-exploit section instead of a
    dead "missing" block.
    """
    location = _location(finding) or "the affected location"
    class_name = str(finding.get("class_name") or finding.get("category") or "the reported issue").strip()
    rule_id = str(finding.get("rule_id") or "").strip()
    obligation = str(poi.get("proof_obligation") or "").strip()
    if not obligation:
        obligation = (
            "Capture the minimal authorized request/response pair that shows the issue working, "
            "plus a negative control that shows the same effect does not happen for a safe input, "
            "different role, invalid credential, or expected baseline."
        )
    steps = normalize_steps(plan.get("steps"))
    replay_step = next((str(step).strip() for step in steps if str(step).strip()), "")
    if not replay_step:
        if str(location).startswith(("http://", "https://")):
            replay_step = f"Replay a benign request to `{location}` and apply the smallest class-specific payload/control needed for {class_name}."
        else:
            replay_step = f"Trace `{location}` to the reachable input or endpoint, then replay the smallest authorized test for {class_name}."
    expected = str(poi.get("observed_result") or poi.get("evidence") or "").strip()
    if not expected:
        expected = (
            "the exploit signal described by the finding appears in the response, browser, account state, "
            "issuer response, callback log, or source-controlled output"
        )
    control = str(poi.get("control_result") or "").strip()
    if not control:
        control = (
            "repeat the same test with the safe baseline: a permitted object, escaped payload, invalid token, "
            "non-attacker origin, unchanged identifier, or non-vulnerable input; capture that it does not produce the exploit signal"
        )
    lines = [
        "Exploit proof capture recipe:",
        f"1. Target: `{location}`" + (f" (rule `{rule_id}`)." if rule_id else "."),
        f"2. Trigger: {replay_step}",
        f"3. Capture required: {obligation}",
        f"4. Expected exploit signal: {expected}",
        f"5. Negative control: {control}",
        "6. Attach the redacted request/response, terminal output, callback log, before/after state, or screenshot that shows the signal.",
    ]
    return redact_text("\n".join(lines))[0][:3000]


def _proof_of_exploitability_detail(finding: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    poi = _proof_of_impact_detail(finding, plan)
    captured_text = _exploitability_artifact_text(finding, plan)
    recipe_text = "" if captured_text else _proof_of_exploit_capture_recipe(finding, plan, poi)
    screenshots = _screenshot_names(finding)
    status = "missing"
    if captured_text or screenshots:
        # A screenshot can support an already-confirmed exploit, but it cannot turn a
        # client/model assertion into confirmation by itself. Keep proof of impact and
        # proof of exploitability on the same evidence gate.
        status = "confirmed" if str(poi.get("status")) == "confirmed" else "candidate"
    elif recipe_text:
        status = "candidate"
    artifact_text = captured_text or recipe_text
    artifact_type = ""
    if captured_text and screenshots:
        artifact_type = "captured text and screenshot"
    elif captured_text:
        artifact_type = "captured text"
    elif screenshots:
        artifact_type = "screenshot"
    elif recipe_text:
        artifact_type = "exploit proof capture recipe"
    return {
        "status": status,
        "ready": status == "confirmed",
        "artifact_type": artifact_type,
        "text_artifact": artifact_text,
        "screenshot_files": screenshots,
        "source_text_file": str(finding.get("source_text_path") or "").replace("\\", "/").rsplit("/", 1)[-1],
        "proof_obligation": str(poi.get("proof_obligation") or "").strip(),
        "captured": bool(captured_text or screenshots),
        "capture": finding.get("proof_capture") if isinstance(finding.get("proof_capture"), dict) else {},
    }


def _append_proof_of_exploitability(out: list[str], finding: dict[str, Any], plan: dict[str, Any], *, heading: str) -> None:
    """Render proof that the exploit actually works: text artifact and/or screenshot."""
    detail = _proof_of_exploitability_detail(finding, plan)
    status = str(detail.get("status") or "missing")
    out.append(heading)
    if status == "missing":
        obligation = str(detail.get("proof_obligation") or "").strip()
        out.append("- **Status:** Missing - no exploit proof artifact is attached yet.")
        if obligation:
            out.append(f"- **Capture required:** {obligation}")
        out.append("- **Accepted artifact:** a redacted request/response text proof or a screenshot showing the exploit working.")
        out.append("")
        return
    out.append(f"- **Status:** {_proof_status_label(status)}")
    artifact_type = str(detail.get("artifact_type") or "").strip()
    if artifact_type:
        out.append(f"- **Exploit proof artifact:** {artifact_type}.")
    if not detail.get("captured"):
        out.append("- **Readiness:** Capture the artifact below before submission; this section is a proof recipe, not confirmed exploit evidence yet.")
    screenshots = detail.get("screenshot_files") or []
    if screenshots:
        out.append("- **Working exploit screenshot(s):** " + ", ".join(_code(str(name)) for name in screenshots))
    source_text_file = str(detail.get("source_text_file") or "").strip()
    if source_text_file:
        out.append(f"- **Browser/source proof text:** {_code(source_text_file)}")
    text_artifact = str(detail.get("text_artifact") or "").strip()
    if text_artifact:
        fence = _fence(text_artifact)
        out.append("")
        out.append("Exploitability proof (captured text artifact):")
        out.append(f"{fence}text")
        out.append(text_artifact)
        out.append(fence)
    if status != "confirmed":
        out.append("- **Gap:** The artifact is present, but the finding is not confirmed until the observed exploit result is tied to a negative control or equivalent live validation.")
    out.append("")


_PROOF_EVIDENCE_LABELS = (
    ("request_line", "Request"),
    ("request_header", "Request header"),
    ("response_status", "Response status"),
    ("response_header", "Response header"),
    ("set_cookie", "Set-Cookie"),
    ("matched_value", "Matched value"),
)


_SCREENSHOT_WARNING = ("Screenshot is NOT auto-redacted — review it for secrets, session "
                       "tokens, and other users' data before attaching it to a report.")


def _append_screenshot(out: list[str], finding: dict[str, Any], plan: dict[str, Any] | None = None) -> None:
    """Embed the captured VISUAL evidence by basename (so the .md and the .png resolve from the same
    folder): the proof screenshot AND the graphical attack-plan map, each optional and independent.
    Shared by the default report and the per-platform report so the visuals land on *every* report
    surface, not only the platform package.

    ``plan`` feeds the one confirm authority (_proof_of_impact_detail) so the map's caption states the
    finding's real state — a map can be rendered for any lead, and calling that flow 'confirmed' in
    the caption asserted a proof the gate never accepted."""
    names = _screenshot_names(finding)
    if names:
        out.append("## Screenshot evidence\n")
        for name in names:
            out.append(f"![Proof-of-concept screenshot]({name})")
            out.append("")
        out.append(f"> {_SCREENSHOT_WARNING}")
        out.append("")
    # Graphical attack-plan map (optional) — embedded by basename like the screenshot; the .png is
    # co-located in the submission package by submission.write_submission_package.
    amap = str(finding.get("attack_map_path") or "").strip()
    if amap:
        name = amap.replace("\\", "/").rsplit("/", 1)[-1]
        out.append("## Attack-plan map\n")
        if str(_proof_of_impact_detail(finding, plan or {})["status"]) == "confirmed":
            out.append(f"![Attack-plan map — the attack GreyIQ used to confirm this finding]({name})")
            out.append("")
            out.append("> A visual map of the confirmed attack flow (actor → crafted probe → observed tell "
                       "vs negative control → confirmed impact). The .png is included in this POC package.")
        else:
            out.append(f"![Attack-plan map — the attack path GreyIQ tested for this candidate finding]({name})")
            out.append("")
            out.append("> A visual map of the attack path under test (actor → crafted probe → observed tell "
                       "vs negative control → the impact still to prove). The confirm gate has not accepted "
                       "this finding, so the map shows what is still outstanding, not a proven flow. The .png "
                       "is included in this POC package.")
        out.append("")


_CREDENTIAL_WARNING = ("The credential above is shown REDACTED (prefix…suffix) — the raw key never appears in "
                       "this report. Retrieve the full value from your own source finding / validation step "
                       "before pasting it into a submission, and treat this document as sensitive, sharing it "
                       "only with the program you are reporting to.")


def _append_credential_proof(out: list[str], finding: dict[str, Any]) -> None:
    """Render the exact-location + real-key + live-validation block a triager demands for a leaked
    credential: the precise file:line and variable, the ACTUAL (un-redacted) key, and — when the
    engine validated it — whether it is live plus the Firebase project/data it grants. Only fires
    for a secret finding that carried a raw ``secret_value`` and/or a ``_credential_proof``."""
    secret = str(finding.get("secret_value") or "").strip()
    proof = finding.get("_credential_proof") if isinstance(finding.get("_credential_proof"), dict) else {}
    ev = finding.get("secret_evidence") if isinstance(finding.get("secret_evidence"), dict) else {}
    if not secret and not proof and not ev:
        return
    cls = str(finding.get("secret_classification") or ev.get("secret_classification") or "")
    confirmed = cls == secret_classification.CONFIRMED_SECRET
    out.append("## Credential — classification, evidence, and validation\n")
    var = str(finding.get("variable_name") or "").strip()
    out.append(f"- **Exact location:** {_code(_location(finding))}" + (f" — variable {_code(var)}" if var else ""))
    # NEVER print the full key — always a safe prefix…suffix redaction, whatever the classification.
    redacted = str(ev.get("redacted_secret") or (redact_secret(secret) if secret else "")).strip()
    if redacted:
        out.append(f"- **Credential (redacted — prefix…suffix, never the full key):** {_code(redacted)}")
    # The strict-classification evidence block: the fields a triager needs to trust — or correctly
    # discount — this finding, so an unproven key is never dressed up as an exploited secret.
    if ev:
        out.append(f"- **Classification:** {_code(cls or secret_classification.CANDIDATE_UNVERIFIED)} — {ev.get('impact_summary', '')}")
        out.append(f"- **Evidence status:** {ev.get('evidence_status', 'unverified')} · "
                   f"proof required: {'yes' if ev.get('proof_required') else 'no'} · "
                   f"proof present: {'yes' if ev.get('proof_present') else 'no'} · "
                   f"impact proven: {'yes' if ev.get('impact_proven') else 'no'}")
        out.append(f"- **Reportability:** {ev.get('reportability', 'not_reportable_yet')} — {ev.get('not_reportable_note', '')}")
        out.append(f"- **Validation method:** {ev.get('validation_method', '')}")
        out.append(f"- **Request evidence:** {_code(str(ev.get('request_evidence', '')))}")
        out.append(f"- **Response evidence:** {ev.get('response_evidence', '')}")
        missing = ev.get("missing_proof") or []
        if missing and not confirmed:
            out.append("- **Missing proof — required before this is reportable:**")
            for m in missing:
                out.append(f"  - {m}")
    if proof and proof.get("checked"):
        live = proof.get("live")
        label = "**LIVE** (validated)" if live is True else "not live / revoked" if live is False else "inconclusive"
        out.append(f"- **Validation:** {label} — {proof.get('detail', '')}")
        if proof.get("project_id"):
            out.append(f"- **Firebase project:** {_code(str(proof['project_id']))}")
        domains = proof.get("authorized_domains") or []
        if domains:
            out.append(f"- **Authorized domains:** {_code(', '.join(str(d) for d in domains))}")
        if str(proof.get("principal") or "").strip():  # GitHub account / Slack workspace the token controls
            out.append(f"- **Account / workspace:** {_code(str(proof['principal']))}")
        if str(proof.get("scopes") or "").strip():
            out.append(f"- **Granted scopes:** {_code(str(proof['scopes']))}")
        issuer = str(proof.get("endpoint") or "the credential's own issuer").strip()
        no_data = " No account data was read." if proof.get("no_data_read") else ""
        out.append(f"- **Request sent:** one benign, read-only request to the credential's own issuer "
                   f"(`{issuer}`) carrying only the found credential — never the target." + no_data)
        verdict = ("authenticated — the credential is LIVE" if live is True
                   else "rejected — not live / revoked" if live is False else "inconclusive")
        out.append(f"- **Return code:** HTTP {proof.get('http_status', '?')} ({verdict}).")
    # A runnable liveness PoC + issuer response ONLY for a CONFIRMED secret — and with the key redacted
    # even there (the report must never carry a usable key). A public/unverified key gets an explicit
    # not-reportable banner instead of a polished PoC that would make it read as exploited.
    if confirmed and str(proof.get("poc") or "").strip():
        out.append("")
        out.append("**Proof of concept — reproduce liveness (one benign, read-only request to the issuer; key redacted):**\n")
        out.append("```bash")
        out.append(secret_classification.redact_value_in(str(proof.get("poc")), secret))
        out.append("```")
        excerpt = str(proof.get("response_excerpt") or "").strip()
        if excerpt:
            out.append("Issuer response — proof the key is live and what it grants (redacted):\n")
            out.append("```json")
            out.append(secret_classification.redact_value_in(excerpt, secret)[:900])
            out.append("```")
    elif not confirmed:
        if cls == secret_classification.PUBLIC_CLIENT_KEY:
            out.append("\n> **Informational only: public client key or unverified browser key.** A Google/Firebase "
                       "browser key, OAuth client id, or analytics/CDN config is designed to be public — it is NOT a "
                       "reportable secret without proof of unauthorized access or real security impact (see missing proof above).")
        else:
            out.append(f"\n> **{ev.get('not_reportable_note') or 'Not reportable yet: candidate secret without confirmed impact.'}**")
    out.append("")
    if secret and confirmed:
        out.append(f"> {_CREDENTIAL_WARNING}")
        out.append("")


def _append_proof_evidence(out: list[str], finding: dict[str, Any]) -> None:
    """Render the captured passive proof artifacts (request line + crafted header,
    response status, offending header/cookie) a web finding carries — the strongest
    passive proof. When a crafted request line is present (active probes), also emit
    a copy-pasteable raw request->response block reconstructed purely from the
    already-redacted captured fields (no request is synthesized)."""
    pe = finding.get("proof_evidence")
    if not isinstance(pe, dict) or not pe:
        return
    rows = [(label, str(pe.get(key) or "").strip()) for key, label in _PROOF_EVIDENCE_LABELS]
    rows = [(label, value) for label, value in rows if value]
    if not rows:
        return
    out.append("**Captured proof (passive — already redacted):**\n")
    for label, value in rows:
        out.append(f"- **{label}:** {_code(value)}")
    out.append("")
    # A reconstructed raw request/response is the single most convincing artifact for
    # a triager. Only render it when a crafted request line was captured (active
    # probes); passive header-only findings legitimately have no request to show.
    request_line = str(pe.get("request_line") or "").strip()
    if request_line:
        lines = [request_line]
        request_header = str(pe.get("request_header") or "").strip()
        if request_header:
            lines.append(request_header)
        lines.append("")  # blank line separates request from response
        status = str(pe.get("response_status") or "").strip()
        if status:
            lines.append(status)  # already 'HTTP <code>' — do not double-prefix
        for key in ("response_header", "set_cookie", "matched_value"):
            value = str(pe.get(key) or "").strip()
            if not value:
                continue
            # CORS (and similar) checks pack several response headers into one matched
            # value ("Access-Control-Allow-Origin: x; Access-Control-Allow-Credentials:
            # true"). Split them onto separate lines so the reconstructed response reads
            # like the real wire response and each header is unambiguously visible — a
            # triager rejects a CORS report that doesn't clearly show the CORS headers.
            parts = [p.strip() for p in value.split(";") if p.strip()]
            if key == "matched_value" and len(parts) > 1 and all(": " in p for p in parts):
                lines.extend(parts)
            else:
                lines.append(value)
        body = "\n".join(lines)
        fence = _fence(body)
        out.append("Captured request/response (reconstructed from redacted artifacts — benign GET probe):\n")
        out.append(f"{fence}http")
        out.append(body)
        out.append(fence)
        out.append("")
    # The captured readable body. For a disclosure the data IS returned to any reader; for CORS this
    # is a SAME-SITE (curl-equivalent) capture that shows the endpoint returns this data — the browser
    # cross-origin read stays PoC-gated (see the heading below). Already redacted by the capturing check.
    read_data = str(pe.get("read_data") or "").strip()
    if read_data:
        rd = read_data[:1500]
        rd_fence = _fence(rd)
        cls = str(finding.get("class_id") or "").lower()
        rid = str(finding.get("rule_id") or "").lower()
        _DISCLOSURE = ("disclosure", "cloud-exposure")
        _DISCLOSURE_RID = ("traversal", "exposed", "firebase", "graphql", "bucket", "sensitive", "jwt")
        is_disclosure = False
        if cls == "cors" or "cors" in rid:
            is_disclosure = True
            heading = (
                "**Captured authenticated response (same-site read)** — requested with the tool's own "
                "session, this endpoint returned the body below. The confirmed CORS headers above WOULD "
                "let an attacker-controlled origin read a response like this, but the capture is same-site "
                "(curl-equivalent); a browser-hosted PoC on an attacker origin is still required to prove "
                "the cross-origin read and its sensitive impact:"
            )
        elif cls in _DISCLOSURE or any(t in rid for t in _DISCLOSURE_RID):
            is_disclosure = True
            heading = (
                "**Demonstrated impact — data disclosed** — the request above returned the content "
                "below, proving the sensitive data is actually retrievable (not merely that the "
                "endpoint exists). Already redacted; review before sharing:"
            )
        else:
            # Injection / reflection classes (XSS, SSTI, SQLi, RCE): the payload's EFFECT captured
            # verbatim from the live response — the concrete proof a triager wants, not a description.
            heading = (
                "**Demonstrated proof — the vulnerable behavior in the live response** — the excerpt "
                "below is the server's ACTUAL response, showing the injected payload's effect "
                "(reflected unescaped / evaluated / DB error) exactly as returned. Already redacted:"
            )
        out.append(heading + "\n")
        out.append(rd_fence)
        out.append(rd)
        out.append(rd_fence)
        # Name the high-confidence sensitive data actually present in the captured body — the "so-what"
        # that raises a data-disclosure finding's severity. Prefer the labels the capturing check
        # classified on the RAW body (``sensitive_data_labels``): redaction rewrites JWT/token/session
        # material to markers this classifier can no longer see, so re-summarizing the redacted excerpt
        # (the fallback) silently under-reports. Only for disclosure classes: for injection classes the
        # body is the payload's own effect, not data an attacker reads.
        if is_disclosure:
            exposed = str(pe.get("sensitive_data_labels") or "").strip() or sensitive_data.summarize(rd)
            if exposed:
                out.append("")
                if cls == "cors" or "cors" in rid:
                    # Same-site capture — the data is PRESENT on the endpoint, but the cross-origin read
                    # is still browser-PoC-gated, so do not assert it is already in an attacker's hands.
                    out.append(f"**Sensitive data present in the captured response:** {exposed}. "
                               "A browser-hosted PoC that reads this cross-origin would confirm an attacker "
                               "can obtain it; until then this establishes the data at risk, not a completed theft.")
                else:
                    out.append(f"**Sensitive data exposed:** the disclosed content includes {exposed} — "
                               "directly usable by an attacker, which raises the real-world impact.")
                # Point at the separate redacted capture file bundled in the PoC download.
                sd_path = str(finding.get("sensitive_data_path") or "").strip()
                if sd_path:
                    out.append(f"_Saved as a separate evidence file in the PoC download: "
                               f"`evidence/sensitive-data/{sd_path.replace(chr(92), '/').rsplit('/', 1)[-1]}`._")
        out.append("")


def _append_cvss(out: list[str], plan: dict[str, Any]) -> None:
    """Render the CVSS v3.1 estimate (vector + computed base score + 'why')."""
    cvss = plan.get("cvss") if isinstance(plan, dict) else None
    if not isinstance(cvss, dict) or not cvss.get("vector"):
        return
    est = " (estimated)" if cvss.get("estimated") else ""
    score = cvss.get("base_score")
    sev = str(cvss.get("base_severity") or "").strip()
    tail = ""
    if score is not None:
        tail = f" — {score}" + (f" {sev}" if sev else "")
    elif sev:
        tail = f" — {sev}"
    out.append(f"- **CVSS v3.1{est}:** {_code(str(cvss['vector']))}{tail}")
    justification = str(cvss.get("justification") or "").strip()
    if justification:
        out.append(f"- **Why this severity:** {justification}")


def _resync_qa_refs(qa: Any) -> None:
    """Re-point each QA issue's ``ref`` at its finding's CURRENT ref, then drop the private ``_finding``
    carrier so it never reaches the JSON sidecar. qa_validate_report freezes the ref at QA time, but
    the findings are re-sorted and re-numbered (bounty._order_by_resolved_severity) AFTERWARD, so the
    frozen ref would otherwise misattribute a downgrade to the wrong finding in the rendered QA section.
    Idempotent: once ``_finding`` is stripped, subsequent calls are no-ops."""
    if not isinstance(qa, dict):
        return
    for issue in qa.get("issues") or []:
        if not isinstance(issue, dict):
            continue
        finding = issue.pop("_finding", None)
        if isinstance(finding, dict) and finding.get("ref"):
            issue["ref"] = finding.get("ref")


def _append_qa(out: list[str], ctx: dict[str, Any]) -> None:
    """Render the pre-export QA gate: the evidence-vs-claim checks and any downgrade-only
    corrections GreyIQ applied. Shown so a triager can see the tool actively guards against
    overclaiming — and why a severity may read lower than a raw header match would suggest."""
    _resync_qa_refs(ctx.get("qa"))
    qa = ctx.get("qa") if isinstance(ctx.get("qa"), dict) else None
    issues = (qa or {}).get("issues") or []
    if not issues:
        return
    corrections = [i for i in issues
                   if any(word in str(i.get("action") or "").lower() for word in ("downgrad", "cap", "removed"))]
    # An issue can flag a claim the evidence does not support WITHOUT applying a severity correction
    # (the class-general claim-integrity checks are informational — the renderer has already shown the
    # finding as `candidate`, so re-punishing it on the severity side would double-count). The closing
    # line must therefore not be derived from the corrections list alone: doing so printed "all claims
    # matched the captured evidence" directly beneath a bullet reading "(unsupported)", in the one
    # section whose entire purpose is showing a triager that GreyIQ audits its own claims.
    flagged = [i for i in issues if str(i.get("verdict") or "").strip().lower() in {"unsupported", "no"}]
    out.append("## Pre-export QA (evidence vs claim)\n")
    out.append(
        "Before export, GreyIQ verifies that every severity and impact claim is backed by the captured "
        "evidence and applies **conservative, downgrade-only** corrections. This is why a severity may read "
        "lower than a bare header/status match would suggest — the tool refuses to assert impact it did not prove."
    )
    out.append("")
    for i in issues:
        ref = str(i.get("ref") or "-")
        question = str(i.get("question") or "").strip()
        verdict = str(i.get("verdict") or "").strip()
        action = str(i.get("action") or "checked — no change needed").strip()
        detail = str(i.get("detail") or "").strip()
        line = f"- **{ref}** — {question}"
        if verdict:
            line += f" _({verdict})_"
        line += f" → **{action}**."
        if detail:
            line += f" {detail}"
        out.append(line)
    out.append("")
    if corrections:
        out.append(f"_{len(corrections)} downgrade-only correction(s) applied. GreyIQ never raises a severity here — "
                   "only lowers one to match the evidence._")
    elif flagged:
        out.append(f"_No severity correction was required, but {len(flagged)} claim(s) above are not backed by the "
                   "captured evidence and are reported as unconfirmed rather than proven._")
    else:
        out.append("_All claims matched the captured evidence; no severity corrections were required._")
    out.append("")


def _append_active_authorization(out: list[str], ctx: dict[str, Any]) -> None:
    """Record what the opt-in active verification layer did (or why it was skipped)."""
    if not ctx.get("active_requested"):
        return
    meta = ctx.get("active_authorization") or {}
    if meta.get("in_scope"):
        classes = ", ".join(meta.get("verified_classes") or []) or "none confirmed"
        note = (
            f"- **Active verification:** ran against `{meta.get('host', '')}` (in scope) — "
            f"benign GET/HEAD/OPTIONS only, rate-limited; classes confirmed by a captured artifact: {classes}."
        )
        if meta.get("rate_limited"):
            note += " (request budget reached — some checks were skipped.)"
        out.append(note)
    else:
        reason = str(meta.get("skipped_reason") or "host not in asserted scope").strip()
        out.append(f"- **Active verification:** skipped (passive only) — {reason}")


def _finding_check_results(finding: dict[str, Any], plan: dict[str, Any]) -> list[tuple[bool, str]]:
    """The single source of truth for both the rendered submission-readiness checklist
    and the machine-readable completeness score, so the two can never drift. This is a
    DOCUMENTATION-completeness signal only — the request-line point below is evidence
    bookkeeping and must NEVER feed proof['ready']/status (proof confirmation has its
    own gate in _has_captured_artifact)."""
    # Count the steps the READER will actually see. Reading the raw field measured something
    # else entirely: a newline-delimited string made `len` a CHARACTER count, so any plan whose
    # steps arrived as prose passed "specific enough to replay" on length alone, while a list
    # holding one multi-line blob counted as a single step and failed the check despite
    # rendering a full numbered procedure. Both the checklist and the completeness score read
    # this, so they have to agree with the renderer, which normalizes.
    steps = normalize_steps(plan.get("steps"))
    impact = plan.get("impact") or finding.get("impact")
    proof = _proof_of_impact_detail(finding, plan)
    remediation = finding.get("remediation") or plan.get("remediation")
    pe = finding.get("proof_evidence") if isinstance(finding.get("proof_evidence"), dict) else {}
    return [
        (bool(_location(finding)), "Precise affected location is captured."),
        (bool(finding.get("snippet") or finding.get("description")), "Evidence is present and safe to share."),
        (len(steps) >= 2, "Reproduction steps are specific enough to replay."),
        (bool(impact), "Impact is stated in bounty-review language."),
        (bool(proof["ready"]), "Confirmed proof of impact is captured as concrete evidence."),
        (bool(remediation), "A concrete fix recommendation is included."),
        (bool(pe.get("request_line")), "A captured request/PoC artifact is attached."),
        (bool(str(proof.get("control_result") or "").strip()), "A negative control distinguishes it from baseline."),
    ]


def _finding_readiness(finding: dict[str, Any], plan: dict[str, Any]) -> list[str]:
    return [_checkbox(done, label) for done, label in _finding_check_results(finding, plan)]


def finding_completeness(finding: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """Evidence-completeness score for a finding — advisory only (never a submit
    precondition). {score, max, missing[]} computed from the SAME predicate list as the
    rendered readiness checklist."""
    results = _finding_check_results(finding, plan)
    return {
        "score": sum(1 for done, _ in results if done),
        "max": len(results),
        "missing": [label for done, label in results if not done],
    }


_OWASP_TOP10_URLS = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10:2021": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}


def _linkify_cwe(text: str) -> str:
    """Turn each 'CWE-<n>' token into a Markdown link to its MITRE page (handles the
    compound 'CWE-639 / CWE-284' form). No-op if no token matches."""
    return re.sub(r"CWE-(\d+)", lambda m: f"[CWE-{m.group(1)}](https://cwe.mitre.org/data/definitions/{m.group(1)}.html)", str(text or ""))


def _linkify_owasp(text: str) -> str:
    """Link an 'Axx:2021 ...' OWASP Top-10 token to its category page (or the Top-10
    index for an unknown prefix). No-op if no token matches."""
    s = str(text or "")
    m = re.match(r"\s*(A\d\d:2021)", s)
    if not m:
        return s
    url = _OWASP_TOP10_URLS.get(m.group(1), "https://owasp.org/Top10/")
    return f"[{s.strip()}]({url})"


def build_markdown(ctx: dict[str, Any]) -> str:
    findings: list[dict[str, Any]] = _reportable_findings(ctx.get("findings", []))
    counts = severity_counts(findings, ctx.get("attack_plans"))
    profile = ctx.get("profile", {}) or {}
    vuln_class = ctx.get("vuln_class") or None
    brain = ctx.get("brain") or {}
    out: list[str] = []

    # --- Title + metadata ---
    title = f"Bug Bounty Report — {profile.get('name', 'Security Review')}"
    if vuln_class:
        title += f" · {vuln_class.get('name')}"
    out.append(f"# {title}\n")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| **Target** | {_code(ctx.get('target', ''))} |")
    out.append(f"| **Profile** | {profile.get('name', '')} |")
    if vuln_class:
        out.append(f"| **Focus class** | {vuln_class.get('name')} |")
    out.append(f"| **Overall risk** | {str(ctx.get('risk', 'unknown')).upper()} (score {ctx.get('score', 0)}) |")
    out.append(f"| **Findings** | {len(findings)} ({counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, {counts['low']} low, {counts['info']} info) |")
    out.append(f"| **Scanners** | {', '.join(ctx.get('scanners_run', [])) or 'none'} |")
    if ctx.get("run_live_requested") or "live" in ctx.get("scanners_run", []):
        live_state = "ran" if "live" in ctx.get("scanners_run", []) else "requested"
        out.append(f"| **Live browser pass** | {live_state} |")
    out.append(f"| **Generated** | {ctx.get('generated_at', '')} |")
    out.append(f"| **Tool** | {ctx.get('tool', 'GreyIQ BugHunter')} v{ctx.get('version', '')} |")
    out.append("")

    # --- Scan errors (a failed scan must never read as a clean target) ---
    if ctx.get("scan_errors"):
        out.append("## ⚠ Scan errors\n")
        out.append(
            "One or more scanners did **not** complete — these results are partial, and a "
            "low/empty finding count here does **not** mean the target is clean:"
        )
        out.append("")
        for err in ctx["scan_errors"]:
            out.append(f"- {err}")
        out.append("")

    # --- Authorization & scope ---
    out.append("## Authorization & scope\n")
    active_ran = "active" in (ctx.get("scanners_run") or []) or bool((ctx.get("active_authorization") or {}).get("in_scope"))
    verification_mode = (
        "static/passive analysis plus opt-in active verification. Active checks are benign, scope-bound, and rate-limited"
        if active_ran
        else "static or passive; nothing was exploited against a live target"
    )
    out.append(
        "> This report covers **authorized** security testing only — your own assets, an "
        "explicit engagement, an in-scope bug-bounty program, or a CTF. All checks below are "
        f"{verification_mode}."
    )
    scope = str(ctx.get("scope") or "").strip()
    out.append("")
    out.append(f"- **In-scope authorization confirmed:** {'yes' if ctx.get('authorized') else 'NOT confirmed'}")
    if scope:
        out.append(f"- **Program / scope notes:** {scope}")
    _append_active_authorization(out, ctx)
    out.append("")

    # --- Executive summary ---
    out.append("## Executive summary\n")
    tldr = str(brain.get("tldr") or "").strip()
    if tldr:
        out.append(f"> **TL;DR —** {tldr}")
        out.append("")
    # Exactly ONE summary paragraph: the analyst's when present, else the operator's
    # recommendation, else the deterministic default — never the analyst summary AND a
    # generic one stacked.
    summary = (
        str(brain.get("summary") or "").strip()
        or str(ctx.get("recommendation") or "").strip()
        or _default_summary(counts, len(findings))
    )
    out.append(summary)
    out.append("")

    _append_bounty_triage(out, ctx, counts)
    _append_surface_drift(out, ctx)
    _append_investigation(out, ctx)
    _append_next_steps(out, ctx)

    # --- Methodology ---
    out.append("## Methodology\n")
    out.append(ctx.get("methodology") or "Automated static/passive analysis via GreyIQ BugHunter.")
    out.append("")

    if not findings:
        out.append("## Findings\n")
        if ctx.get("focus_unmatched") and vuln_class:
            other = ctx.get("other_findings_count") or 0
            note = f"No findings matched the **{vuln_class.get('name')}** focus at this scan depth."
            if other:
                note += f" ({other} finding(s) of other classes were found — re-run with 'Any class' to see them.)"
            note += " The manual-testing checklist below is where the value is for this class."
            out.append(note)
        else:
            out.append("No findings at this scan depth. See the manual-testing checklist below for "
                       "leads the automated scanners cannot cover.")
        out.append("")
        _append_checklist(out, ctx)
        _append_tools(out, ctx)
        _append_footer(out, ctx)
        return "\n".join(out)

    # --- Findings table ---
    attack_plans = ctx.get("attack_plans", {}) or {}
    out.append("## Findings\n")
    out.append("| # | Severity | Class | Title | Location |")
    out.append("|---|---|---|---|---|")
    for finding in findings:
        sev = _SEVERITY_LABEL.get(resolve_severity(finding, attack_plans.get(finding.get("ref"))), "?")
        out.append(
            f"| {finding.get('ref', '')} "
            f"| {sev} "
            f"| {_md_escape_cell(finding.get('class_name') or finding.get('category') or '')} "
            f"| {_md_escape_cell(finding.get('title', ''))} "
            f"| {_location_cell(finding)} |"
        )
    out.append("")
    _append_qa(out, ctx)

    # --- Per-finding detail ---
    out.append("## Finding details\n")
    for finding in findings:
        ref = finding.get("ref", "")
        plan = attack_plans.get(ref) or {}
        sev = _SEVERITY_LABEL.get(resolve_severity(finding, plan), "?")
        out.append(f"### {ref} · {finding.get('title', 'Finding')} — {sev}\n")
        out.append(f"- **Severity / confidence:** {sev} / {finding.get('confidence', 'unknown')}")
        if finding.get("class_name"):
            out.append(f"- **Class:** {finding['class_name']}")
        if finding.get("cwe"):
            out.append(f"- **CWE:** {_linkify_cwe(finding['cwe'])}")
        if finding.get("owasp"):
            out.append(f"- **OWASP:** {_linkify_owasp(finding['owasp'])}")
        if finding.get("vrt"):
            out.append(f"- **Bugcrowd VRT (est.):** {_code(str(finding['vrt']))}")
        _append_cvss(out, plan)
        out.append(f"- **Location:** {_code(_location(finding))}")
        _append_grouped_locations(out, finding)
        out.append(f"- **Rule:** {_code(finding.get('rule_id', ''))}")
        out.append("")
        if finding.get("description"):
            out.append(finding["description"].strip())
            out.append("")
        _append_proof_evidence(out, finding)
        snippet = str(finding.get("snippet") or "").strip()
        if snippet:
            clipped = snippet[:1200]
            fence = _fence(clipped)
            out.append("**Evidence**\n")
            out.append(fence)
            out.append(clipped)
            out.append(fence)
            out.append("")

        out.append("**Attack plan / steps to reproduce**\n")
        steps = normalize_steps(plan.get("steps"))
        if steps:
            for i, step in enumerate(steps, 1):
                out.append(f"{i}. {step}")
        else:
            out.append("_No automated reproduction steps; see the class guidance and verify manually._")
        out.append("")
        _append_proof_of_concept(out, finding, plan, heading="**Proof of concept:**")
        if plan.get("impact") or finding.get("impact"):
            out.append(f"**Impact:** {plan.get('impact') or finding.get('impact')}")
            out.append("")
        _append_chain_role(out, ctx, ref)
        _append_proof_of_impact(out, finding, plan, heading="**Proof of impact:**")
        _append_proof_of_exploitability(out, finding, plan, heading="**Proof of exploitability:**")
        _append_screenshot(out, finding, plan)
        _append_credential_proof(out, finding)
        remediation = finding.get("remediation") or plan.get("remediation")
        if remediation:
            out.append(f"**Remediation:** {remediation}")
            out.append("")
        out.append("**Submission readiness**\n")
        out.extend(_finding_readiness(finding, plan))
        out.append("")
        if finding.get("references"):
            out.append("**References:** " + ", ".join(finding["references"]))
            out.append("")

    # --- Analyst narrative (raw brain text that wasn't structured) ---
    if brain.get("notes"):
        out.append("## Analyst notes\n")
        out.append(brain["notes"].strip())
        out.append("")

    _append_checklist(out, ctx)
    _append_tools(out, ctx)
    _append_footer(out, ctx)
    return "\n".join(out)


def _append_bounty_triage(out: list[str], ctx: dict[str, Any], counts: dict[str, int]) -> None:
    findings = _reportable_findings(ctx.get("findings") or [])
    plans = ctx.get("attack_plans", {}) or {}
    report_title = str((ctx.get("brain") or {}).get("report_title") or "").strip()
    out.append("## Bounty triage\n")
    if report_title:
        out.append(f"- **Suggested report title:** {_md_escape_cell(report_title)}")
    if findings:
        top = sorted(findings, key=lambda f: _sev_rank(f, plans.get(f.get("ref"))), reverse=True)[0]
        top_sev = _SEVERITY_LABEL.get(resolve_severity(top, plans.get(top.get("ref"))), "?")
        out.append(
            f"- **Highest priority:** {top.get('ref', '')} - {top.get('title', 'Finding')} "
            f"({top_sev}, {top.get('class_name') or top.get('category') or 'unclassified'})."
        )
        classes = _class_counts(findings)
        if classes:
            out.append(
                "- **Class mix:** "
                + ", ".join(f"{name}: {count}" for name, count in list(classes.items())[:8])
                + "."
            )
        chain_notes = _chain_leads(findings)
        if chain_notes:
            out.append("- **Chain leads:** " + " ".join(chain_notes))
    else:
        out.append("- **Highest priority:** no automated finding yet; use the manual checklist for in-scope leads.")
    high = counts["critical"] + counts["high"]
    if high:
        out.append("- **Submission order:** confirm and submit critical/high findings first, one report per root cause.")
    elif counts["medium"]:
        out.append("- **Submission order:** validate medium findings for real impact or chainability before filing.")
    else:
        out.append("- **Submission order:** treat low/info items as hardening unless a policy-approved chain raises impact.")
    if ctx.get("scan_errors"):
        out.append("- **Coverage caution:** scanner errors make this a partial result; rerun after fixing scanner access.")
    if ctx.get("run_live_requested"):
        out.append("- **Dynamic coverage:** live browser telemetry was requested; review console/network findings separately from passive HTTP findings.")
    out.append("")
    out.append("### Submission preflight\n")
    for item in _SUBMISSION_CHECKLIST:
        out.append(f"- [ ] {item}")
    out.append("")


def _append_chain_role(out: list[str], ctx: dict[str, Any], ref: str) -> None:
    """Name the chains this finding is a step of, right where the finding is read.

    This is the other half of demoting cookie flags: the flag stops being its own Low, and
    the finding it escalates gains the line saying what it now reaches. A triager reading a
    reflected XSS in isolation prices it as an XSS; the same finding labelled "step 1 of a
    chain to account takeover" is priced as what it actually is.

    THIS finding's step state is printed alongside the chain's, attributed to different things: the
    chain status is a roll-up over the STRONGEST evidence in the chain, so printing it alone let a
    purely projected step borrow another finding's credibility.
    """
    investigation = ctx.get("investigation") if isinstance(ctx.get("investigation"), dict) else {}
    chains = investigation.get("attack_chains") if isinstance(investigation.get("attack_chains"), list) else []
    lines: list[str] = []
    for chain in chains:
        if not isinstance(chain, dict):
            continue
        for step in chain.get("steps") or []:
            if not isinstance(step, dict) or str(step.get("evidence_ref") or "") != str(ref):
                continue
            # 'proven'/'projected' is the SAME vocabulary the chain table prints, so the two surfaces
            # cannot drift; the chain status keeps the table's 'candidate' default.
            state = _md_escape_cell(str(step.get("state") or "projected"))
            lines.append(
                f"- Step {_safe_display_int(step.get('n'))} of **{_md_escape_cell(chain.get('id') or '')} · "
                f"{_md_escape_cell(chain.get('title') or '')}** — this step is *{state}*; the chain is "
                f"{_md_escape_cell(chain.get('status') or 'candidate')} and its projected impact is "
                f"{_md_escape_cell(chain.get('projected_impact') or 'higher impact')}."
            )
    if not lines:
        return
    out.append("**Chain role:**\n")
    # The standalone per-finding file carries no chain table, so the two state words would be
    # undefined there — the legend travels with the line that uses them.
    out.append("_A *proven* step is backed by a captured artifact the confirm gate accepted; "
               "a *projected* step is the next thing to prove._\n")
    out.extend(dict.fromkeys(lines))
    out.append("")


def _append_surface_drift(out: list[str], ctx: dict[str, Any]) -> None:
    """What changed on this host since the last run.

    Deliberately its own section, well away from the findings table: "a new admin endpoint
    appeared" reads like a finding in a skim, and it is not one — nothing here was observed to
    be broken. The section is emitted even when nothing changed, because "compared, nothing
    moved" and "never compared" are different statements and only one of them is reassuring.
    """
    from bughunter import surface_drift

    drift = ctx.get("drift")
    if not isinstance(drift, dict) or not drift.get("status") or drift.get("status") == "unavailable":
        return
    lines = surface_drift.summary_lines(drift)
    if not lines:
        return
    out.append("## Surface drift\n")
    out.append(
        "How this host's attack surface compares with the previous hunt. These are OBSERVATIONS "
        "about the target's history, not findings: a change is a reason to go and test "
        "something, never evidence that anything is exploitable."
    )
    out.append("")
    for line in lines:
        out.append(_md_escape_cell(line) if not line.startswith("- ") else f"- {_md_escape_cell(line[2:])}")
    stale = ctx.get("stale_proofs") if isinstance(ctx.get("stale_proofs"), list) else []
    if stale:
        out.append("")
        out.append("**Proofs to re-verify before submitting** — an endpoint these rest on has moved:")
        for row in stale[:6]:
            if isinstance(row, dict):
                out.append(f"- {_md_escape_cell(row.get('chain') or '')}: {_md_escape_cell(row.get('why') or '')}")
    out.append("")


def _append_investigation(out: list[str], ctx: dict[str, Any]) -> None:
    """Render the shared evidence graph as an analyst decision brief.

    This section intentionally reports proof state and gaps, never raw credentials or
    model-authored evidence.  It is omitted for legacy/custom contexts that have not
    run the investigation cortex.
    """
    investigation = ctx.get("investigation")
    if not isinstance(investigation, dict):
        return
    metrics = investigation.get("metrics") if isinstance(investigation.get("metrics"), dict) else {}
    hypotheses = investigation.get("hypotheses") if isinstance(investigation.get("hypotheses"), list) else []
    chains = investigation.get("attack_chains") if isinstance(investigation.get("attack_chains"), list) else []
    contradictions = investigation.get("contradictions") if isinstance(investigation.get("contradictions"), list) else []

    out.append("## Investigation intelligence\n")
    out.append(
        "This evidence-grounded decision layer correlates scanner leads and captured proof. "
        "It cannot promote model prose or a heuristic match to confirmed status."
    )
    out.append("")
    out.append(f"- **Verdict:** {_md_escape_cell(investigation.get('verdict') or 'unknown')}")
    out.append(
        "- **Evidence state:** "
        f"{_safe_display_int(metrics.get('confirmed'))} confirmed; "
        f"{_safe_display_int(metrics.get('supported'))} supported; "
        f"{_safe_display_int(metrics.get('report_ready'))} report-ready; "
        f"{_safe_display_int(metrics.get('contradictions'))} contradiction(s)."
    )
    out.append(
        f"- **Correlation:** {_safe_display_int(metrics.get('attack_chains'))} chain lead(s); "
        f"average calibrated confidence {_safe_display_number(metrics.get('average_confidence'))}/100."
    )
    out.append("")

    if hypotheses:
        out.append("### Ranked hypothesis queue\n")
        out.append("| Rank | Ref | State | Confidence | Decision | Next proof |")
        out.append("|---:|---|---|---:|---|---|")
        for item in hypotheses[:12]:
            if not isinstance(item, dict):
                continue
            out.append(
                f"| {_safe_display_int(item.get('rank'))} "
                f"| {_md_escape_cell(item.get('ref') or '')} "
                f"| {_md_escape_cell(item.get('status') or '')} "
                f"| {_safe_display_int(item.get('confidence_score'))}/100 "
                f"| {_md_escape_cell(item.get('decision') or '')} "
                f"| {_md_escape_cell(item.get('next_action') or '')} |"
            )
        if len(hypotheses) > 12:
            out.append(f"\n_Only the top 12 of {len(hypotheses)} hypotheses are shown; the JSON sidecar contains the full bounded queue._")
        out.append("")

    if chains:
        out.append("### Attack chains\n")
        out.append(
            "Each chain is an ORDERED path from an attacker's starting position to a concrete "
            "impact. A step marked *proven* is backed by a captured artifact the confirm gate "
            "accepted; a step marked *projected* is the next thing to prove, and the chain is "
            "worth only as much as its weakest step."
        )
        out.append("")
        for chain in chains[:8]:
            if not isinstance(chain, dict):
                continue
            raw_refs = chain.get("refs")
            refs = ", ".join(str(ref) for ref in raw_refs[:6]) if isinstance(raw_refs, list) else ""
            steps = chain.get("steps") if isinstance(chain.get("steps"), list) else []
            out.append(
                f"#### {_md_escape_cell(chain.get('id') or '')} · {_md_escape_cell(chain.get('title') or 'Attack chain')}\n"
            )
            out.append(
                f"- **State:** {_md_escape_cell(chain.get('status') or 'candidate')} "
                f"({_safe_display_int(chain.get('proven_steps'))} of {_safe_display_int(chain.get('step_count'))} "
                f"step(s) proven); calibrated confidence {_safe_display_int(chain.get('confidence_score'))}/100."
            )
            out.append(f"- **Starting position:** {_md_escape_cell(chain.get('entry') or 'unknown')}")
            out.append(f"- **Projected impact:** {_md_escape_cell(chain.get('projected_impact') or 'unknown')}")
            if refs:
                out.append(f"- **Findings used:** {_md_escape_cell(refs)}")
            out.append("")
            if steps:
                out.append("| # | Step | Evidence | State | What it gives the attacker |")
                out.append("|---:|---|---|---|---|")
                for step in steps[:_MAX_CHAIN_STEPS]:
                    if not isinstance(step, dict):
                        continue
                    # A step is carried by a finding (cite its ref), by a sub-finding signal
                    # (name the observation — the whole point of the demotion is that the reader
                    # sees "no HttpOnly" doing a job rather than sitting in a list), or by
                    # neither, when it is a pure consequence of what the attacker already holds.
                    signal_text = str(step.get("signal_why") or step.get("signal") or "")
                    evidence = (
                        str(step.get("evidence_ref") or "")
                        or (f"signal: {signal_text}" if signal_text else "follows from the previous step")
                    )
                    grants = step.get("grants") if isinstance(step.get("grants"), list) else []
                    out.append(
                        f"| {_safe_display_int(step.get('n'))} "
                        f"| {_md_escape_cell(step.get('title') or '')} "
                        f"| {_md_escape_cell(evidence)} "
                        f"| {_md_escape_cell(step.get('state') or '')} "
                        f"| {_md_escape_cell('; '.join(str(g) for g in grants[:3]))} |"
                    )
                if len(steps) > _MAX_CHAIN_STEPS:
                    out.append(f"\n_{len(steps) - _MAX_CHAIN_STEPS} further step(s) are in the JSON sidecar._")
                out.append("")
            notes = [str(step.get("note")) for step in steps
                     if isinstance(step, dict) and str(step.get("note") or "").strip()]
            for note in dict.fromkeys(notes):
                out.append(f"> {_md_escape_cell(note)}")
            if notes:
                out.append("")
            out.append(f"**Close the chain next:** {_md_escape_cell(chain.get('next_action') or '')}")
            out.append("")

    probes = investigation.get("chain_probes") if isinstance(investigation.get("chain_probes"), list) else []
    if probes:
        out.append("### Chain leads worth testing\n")
        out.append(
            "Built from observed structure alone — no finding backs these yet, so they are "
            "test plans, not results."
        )
        out.append("")
        for probe in probes[:6]:
            if not isinstance(probe, dict):
                continue
            out.append(
                f"- **{_md_escape_cell(probe.get('id') or '')} · {_md_escape_cell(probe.get('title') or '')}** "
                f"— {_md_escape_cell(probe.get('hypothesis') or '')} "
                f"**Test:** {_md_escape_cell(probe.get('next_action') or '')}"
            )
        out.append("")

    if contradictions:
        out.append("### Contradictions requiring analyst resolution\n")
        for issue in contradictions[:12]:
            if not isinstance(issue, dict):
                continue
            out.append(
                f"- **{_md_escape_cell(issue.get('ref') or '?')} · {_md_escape_cell(issue.get('code') or 'evidence-conflict')}:** "
                f"{_md_escape_cell(issue.get('message') or '')}"
            )
        out.append("")


def _append_next_steps(out: list[str], ctx: dict[str, Any]) -> None:
    """The guided, ordered operator action plan — the 'what do I do now' section.
    Steps arrive pre-ordered and grouped by phase from ``next_steps.build_next_steps``."""
    steps = ctx.get("next_steps") or []
    out.append("## Guided next steps\n")
    out.append(
        "A prioritized, ordered plan — work it top to bottom. Highest-impact first; each step names the "
        "opening move and the single tool to reach for."
    )
    out.append("")
    if not steps:
        out.append("_No next steps were generated for this run._")
        out.append("")
        return
    current_phase: str | None = None
    for step in steps:
        phase = str(step.get("phase") or "").strip()
        if phase and phase != current_phase:
            out.append(f"### {phase}\n")
            current_phase = phase
        tag = _NEXT_STEP_TAG.get(str(step.get("priority")).lower(), "")
        prefix = f"`{tag}` " if tag else ""
        action = str(step.get("action") or "").strip() or "Next step"
        out.append(f"{step.get('order', '')}. {prefix}**{action}**")
        detail = str(step.get("detail") or "").strip()
        if detail:
            out.append(f"   {detail}")
        meta_bits: list[str] = []
        if step.get("ref"):
            meta_bits.append(f"finding {step['ref']}")
        if step.get("tool"):
            meta_bits.append(f"tool: {step['tool']}")
        if meta_bits:
            out.append(f"   _({' · '.join(meta_bits)})_")
        out.append("")

    coverage = ctx.get("coverage") or {}
    covered = coverage.get("covered") or []
    gaps = coverage.get("gaps") or []
    if covered or gaps:
        out.append("### Coverage & gaps\n")
        if covered:
            out.append("**Covered by this run:**")
            out.append("")
            for item in covered:
                out.append(f"- {item}")
            out.append("")
        if gaps:
            out.append("**Not covered — where the blind spots are:**")
            out.append("")
            for item in gaps:
                out.append(f"- {item}")
            out.append("")


def _append_checklist(out: list[str], ctx: dict[str, Any]) -> None:
    checklist = ctx.get("manual_checklist") or []
    if not checklist:
        return
    out.append("## Manual testing checklist\n")
    out.append("Leads the automated scanners cannot confirm on their own — verify by hand, "
               "within scope:")
    out.append("")
    for item in checklist:
        out.append(f"- [ ] {str(item).strip()}")
    out.append("")

    out.append("### Retest after fix\n")
    for item in _RETEST_CHECKLIST:
        out.append(f"- [ ] {item}")
    out.append("")


def _append_tools(out: list[str], ctx: dict[str, Any]) -> None:
    tools = ctx.get("recommended_tools") or []
    if not tools:
        return
    out.append("## Recommended tooling\n")
    out.append(
        "Curated tools that fit this target's vuln classes — to confirm the leads above "
        "within your authorized scope:"
    )
    out.append("")
    out.append("| Tool | What it's for | Classes | Link |")
    out.append("|---|---|---|---|")
    for tool in tools:
        classes = ", ".join(tool.get("maps_to") or []) or "—"
        out.append(
            f"| {_md_escape_cell(tool.get('name', ''))} "
            f"| {_md_escape_cell(tool.get('description', ''))} "
            f"| {_md_escape_cell(classes)} "
            f"| {_md_escape_cell(tool.get('url', ''))} |"
        )
    out.append("")
    src = ctx.get("toolkit_source") or {}
    if src.get("attribution"):
        out.append(f"_Tooling list: {src['attribution']}_")
        out.append("")


def _append_footer(out: list[str], ctx: dict[str, Any]) -> None:
    brain = ctx.get("brain") or {}
    attribution = ""
    if brain.get("used") and brain.get("model"):
        attribution = f" · analysis assisted by {brain.get('provider')}:{brain.get('model')}"
    out.append("---")
    out.append(
        f"_Generated by {ctx.get('tool', 'GreyIQ BugHunter')} v{ctx.get('version', '')}"
        f"{attribution}. Findings are leads, not verdicts — confirm exploitability within "
        f"your authorized scope before submitting._"
    )


def _default_summary(counts: dict[str, int], total: int) -> str:
    if total == 0:
        return "No issues surfaced by the automated pass."
    high = counts["critical"] + counts["high"]
    if high:
        return (
            f"{high} high-impact finding(s) warrant immediate review and likely qualify for a "
            f"report. Confirm exploitability, then submit the most severe first."
        )
    if counts["medium"]:
        return f"{counts['medium']} medium finding(s) — review for chainability before submitting."
    return "Low-severity hardening findings only; triage as routine."


def build_json(ctx: dict[str, Any]) -> dict[str, Any]:
    """Machine-readable sidecar mirroring the report."""
    _resync_qa_refs(ctx.get("qa"))  # correct QA refs after renumber + strip the private _finding carrier
    findings = _reportable_findings(ctx.get("findings", []))
    attack_plans = ctx.get("attack_plans", {}) or {}
    return {
        "tool": ctx.get("tool", "GreyIQ BugHunter"),
        "version": ctx.get("version", ""),
        "generated_at": ctx.get("generated_at", ""),
        "target": ctx.get("target", ""),
        "profile": ctx.get("profile", {}),
        "vuln_class": ctx.get("vuln_class"),
        "scope": ctx.get("scope", ""),
        "authorized": bool(ctx.get("authorized")),
        "scanners_run": ctx.get("scanners_run", []),
        "risk": ctx.get("risk", "unknown"),
        "score": ctx.get("score", 0),
        "severity_counts": severity_counts(findings, ctx.get("attack_plans")),
        "class_counts": _class_counts(findings),
        "finding_count": len(findings),
        "findings": findings,
        "attack_plans": attack_plans,
        "proof_of_impact": {
            str(finding.get("ref") or ""): _proof_of_impact_detail(
                finding,
                attack_plans.get(finding.get("ref")) or {},
            )
            for finding in findings
            if finding.get("ref")
        },
        "proof_of_exploitability": {
            str(finding.get("ref") or ""): _proof_of_exploitability_detail(
                finding,
                attack_plans.get(finding.get("ref")) or {},
            )
            for finding in findings
            if finding.get("ref")
        },
        "cvss": {
            str(finding.get("ref") or ""): (attack_plans.get(finding.get("ref")) or {}).get("cvss")
            for finding in findings
            if finding.get("ref") and isinstance((attack_plans.get(finding.get("ref")) or {}).get("cvss"), dict)
        },
        # Advisory evidence-completeness per finding (documentation signal only — never
        # a submit precondition; the submit gate stays confirm + confirmed proof + creds).
        "completeness": {
            str(finding.get("ref") or ""): finding_completeness(finding, attack_plans.get(finding.get("ref")) or {})
            for finding in findings
            if finding.get("ref")
        },
        "next_steps": ctx.get("next_steps", []),
        "coverage": ctx.get("coverage", {}),
        # Shared code/hunt/report evidence graph: calibrated hypotheses, proof gaps,
        # contradictions, and correlated chain leads. It is advisory and never a
        # substitute for the canonical proof_of_impact fields above.
        "investigation": ctx.get("investigation") or {
            "algorithm": "", "verdict": "not-run", "metrics": {},
            "hypotheses": [], "attack_chains": [], "chain_probes": [], "contradictions": [],
        },
        # How this host's surface compares with the previous hunt. Advisory and explicitly
        # separate from `findings`: a delta is never a finding.
        "drift": ctx.get("drift") or {},
        "stale_proofs": ctx.get("stale_proofs") or [],
        "manual_checklist": ctx.get("manual_checklist", []),
        "submission_checklist": list(_SUBMISSION_CHECKLIST),
        "retest_checklist": list(_RETEST_CHECKLIST),
        "recommended_tools": ctx.get("recommended_tools", []),
        "run_live_requested": bool(ctx.get("run_live_requested")),
        "brain": {
            "used": bool(ctx.get("brain", {}).get("used")),
            "provider": ctx.get("brain", {}).get("provider", ""),
            "model": ctx.get("brain", {}).get("model", ""),
        },
        "scan_meta": ctx.get("scan_meta", {}),
        "proof_artifacts_captured": int(ctx.get("proof_artifacts_captured") or 0),
        # Pre-export QA gate result: the evidence-vs-claim checks + any downgrade-only corrections
        # GreyIQ applied so a triager can audit why a severity reads the way it does.
        "qa": ctx.get("qa") or {"ok": True, "issues": []},
    }


def build_finding_markdown(ctx: dict[str, Any], finding: dict[str, Any]) -> str:
    """A self-contained, submission-ready Markdown report for a single finding —
    everything a bounty platform needs in one paste."""
    if not _reportable_findings([finding]):
        return ""
    plan = (ctx.get("attack_plans") or {}).get(finding.get("ref"), {}) or {}
    sev = _SEVERITY_LABEL.get(resolve_severity(finding, plan), "?")
    out: list[str] = []
    out.append(f"# {finding.get('title', 'Finding')} — {sev}\n")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| **Target** | {_code(ctx.get('target', ''))} |")
    out.append(f"| **Severity / confidence** | {sev} / {finding.get('confidence', '?')} |")
    if finding.get("class_name"):
        out.append(f"| **Class** | {finding['class_name']} |")
    if finding.get("cwe"):
        out.append(f"| **CWE** | {_linkify_cwe(finding['cwe'])} |")
    if finding.get("owasp"):
        out.append(f"| **OWASP** | {_linkify_owasp(finding['owasp'])} |")
    if finding.get("vrt"):
        out.append(f"| **Bugcrowd VRT (est.)** | {_code(str(finding['vrt']))} |")
    cvss = plan.get("cvss") if isinstance(plan, dict) else None
    if isinstance(cvss, dict) and cvss.get("vector"):
        score = cvss.get("base_score")
        sev_word = str(cvss.get("base_severity") or "").strip()
        tail = f" — {score} {sev_word}".rstrip() if score is not None else (f" — {sev_word}" if sev_word else "")
        out.append(f"| **CVSS v3.1 (est.)** | {_code(str(cvss['vector']))}{tail} |")
    out.append(f"| **Location** | {_code(_location(finding))} |")
    out.append(f"| **Generated** | {ctx.get('generated_at', '')} |")
    out.append("")

    grouped = _grouped_locations(finding)
    if grouped:
        out.append("## Affected locations\n")
        out.append(f"{len(grouped)} locations share this root cause — file once and list each affected path:")
        out.append("")
        for loc in grouped[:25]:
            out.append(f"- {_code(loc)}")
        if len(grouped) > 25:
            out.append(f"- _(+{len(grouped) - 25} more)_")
        out.append("")

    out.append("## Authorization & scope\n")
    out.append("> Authorized testing only — reported against an in-scope target.")
    if str(ctx.get("scope") or "").strip():
        out.append(f"\n- Scope / program: {ctx['scope']}")
    out.append("")

    if finding.get("description"):
        out.append("## Summary\n")
        out.append(finding["description"].strip())
        out.append("")

    _append_proof_evidence(out, finding)

    snippet = str(finding.get("snippet") or "").strip()
    if snippet:
        clipped = snippet[:1200]
        fence = _fence(clipped)
        out.append("## Evidence\n")
        out.append(fence)
        out.append(clipped)
        out.append(fence)
        out.append("")

    out.append("## Steps to reproduce\n")
    steps = normalize_steps(plan.get("steps"))
    if steps:
        for i, step in enumerate(steps, 1):
            out.append(f"{i}. {step}")
    else:
        out.append("_Verify manually within your authorized scope._")
    out.append("")

    _append_proof_of_concept(out, finding, plan, heading="## Proof of concept\n")

    impact = plan.get("impact") or finding.get("impact")
    if impact:
        out.append(f"## Impact\n\n{impact}\n")
    # A per-finding submission file is read on its own, so the chain context has to travel
    # with it — otherwise the standalone package prices the finding lower than the report does.
    _append_chain_role(out, ctx, str(finding.get("ref") or ""))
    _append_proof_of_impact(out, finding, plan, heading="## Proof of impact\n")
    _append_proof_of_exploitability(out, finding, plan, heading="## Proof of exploitability\n")
    _append_screenshot(out, finding, plan)
    _append_credential_proof(out, finding)
    remediation = finding.get("remediation") or plan.get("remediation")
    if remediation:
        out.append(f"## Remediation\n\n{remediation}\n")
    out.append("## Submission readiness\n")
    out.extend(_finding_readiness(finding, plan))
    out.append("")
    out.append("## Retest after fix\n")
    for item in _RETEST_CHECKLIST:
        out.append(f"- [ ] {item}")
    out.append("")
    if finding.get("references"):
        out.append("## References\n\n" + ", ".join(finding["references"]) + "\n")

    out.append("---")
    out.append(
        f"_Generated by {ctx.get('tool', 'GreyIQ BugHunter')} v{ctx.get('version', '')}. "
        f"Confirm exploitability within your authorized scope before submitting._"
    )
    return "\n".join(out)
