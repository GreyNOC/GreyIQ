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

from bughunter.code_scanner.redaction import redact_text

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
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


def _sev_rank(finding: dict[str, Any]) -> int:
    return _SEVERITY_ORDER.get(str(finding.get("severity", "info")).lower(), 0)


def _jwt_replay_value(finding: dict[str, Any]) -> bool | None:
    if "replay_authenticated" in finding:
        value = finding.get("replay_authenticated")
    elif "jwt_replay_authenticated" in finding:
        value = finding.get("jwt_replay_authenticated")
    else:
        value = (finding.get("jwt_exposure") or {}).get("replay_authenticated")
    return value if isinstance(value, bool) else None


def _reportable_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop unconfirmed JWT credential candidates before report rendering."""
    out: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id in _JWT_CREDENTIAL_RULE_IDS and _jwt_replay_value(finding) is not True:
            continue
        out.append(finding)
    return out


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {key: 0 for key in _SEVERITY_ORDER}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _md_escape_cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _fence(text: str) -> str:
    """A code-fence longer than any backtick run in ``text`` so embedded
    triple-backticks (from scanned target content or LLM output) can't break out."""
    longest = max((len(run) for run in re.findall(r"`+", text or "")), default=0)
    return "`" * max(3, longest + 1)


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
        return f"{loc}:{line}"
    return loc


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


_HTTP_RESULT_RE = re.compile(r"\bHTTP\s*[1-5]\d{2}\b|\b(?:returned|response|status)\b[^.]{0,40}\b[1-5]\d{2}\b", re.IGNORECASE)


def _has_captured_artifact(finding: dict[str, Any], proof: Any, observed_result: str) -> bool:
    """True only when there is a REAL captured artifact proving IMPACT — never from
    narrative prose alone. NOTE: the passive web ``proof_evidence`` (request line +
    'header absent' + response status) is deliberately NOT counted here: it proves a
    GET happened, not security impact, so letting it satisfy this gate would let
    brain prose flip a hardening finding to 'confirmed'. Only genuinely
    impact-proving artifacts qualify."""
    if _jwt_replay_value(finding) is True:
        return True
    if finding.get("secret_hits"):
        return True
    if isinstance(proof, dict) and proof.get("proof_evidence"):
        return True
    if observed_result and _HTTP_RESULT_RE.search(observed_result):
        return True
    return False


def _proof_of_impact_detail(finding: dict[str, Any], plan: dict[str, Any]) -> dict[str, str | bool]:
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
        detail["limitations"] = str(proof.get("limitations") or proof.get("scope_limitations") or proof.get("notes") or "").strip()
        detail["proof_obligation"] = str(proof.get("proof_obligation") or proof.get("obligation") or "").strip()
    else:
        detail["evidence"] = str(proof or "").strip()

    # Re-redact any evidence/observed_result the brain echoed — a captured response
    # can contain the very secret/token the finding is about; never double-leak it.
    if detail["evidence"]:
        detail["evidence"] = redact_text(str(detail["evidence"]))[0]
    if detail["observed_result"]:
        detail["observed_result"] = redact_text(str(detail["observed_result"]))[0]

    # Status: only a REAL captured artifact + concrete text earns 'confirmed';
    # concrete-looking prose alone caps at 'candidate'. (The descriptive
    # affected_asset/actor fields never drive promotion — only true proof fields do.)
    combined = f"{detail['evidence']} {detail['observed_result']}".strip()
    explicit_status = _explicit_proof_status(finding, plan, proof)
    artifact = _has_captured_artifact(finding, proof, str(detail["observed_result"]))
    if explicit_status:
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
        ("observed_result", "Observed result"),
        ("control_result", "Control / expected result"),
        ("evidence", "Evidence"),
        ("limitations", "Limitations"),
    )
    for key, label in labels:
        value = str(detail.get(key) or "").strip()
        if value:
            out.append(f"- **{label}:** {value}")
    if obligation:
        out.append(f"- **Proof obligation (capture this to prove impact):** {obligation}")
    if status != "confirmed":
        out.append("- **Gap:** Treat this as a lead until an authorized replay or dynamic check proves the effect.")
    out.append("")


_PROOF_EVIDENCE_LABELS = (
    ("request_line", "Request"),
    ("response_status", "Response status"),
    ("response_header", "Response header"),
    ("set_cookie", "Set-Cookie"),
    ("matched_value", "Matched value"),
)


def _append_proof_evidence(out: list[str], finding: dict[str, Any]) -> None:
    """Render the captured passive proof artifacts (request line, response status,
    offending header/cookie) a web finding carries — the strongest passive proof."""
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


def _finding_readiness(finding: dict[str, Any], plan: dict[str, Any]) -> list[str]:
    steps = plan.get("steps") or []
    impact = plan.get("impact") or finding.get("impact")
    proof = _proof_of_impact_detail(finding, plan)
    remediation = finding.get("remediation") or plan.get("remediation")
    return [
        _checkbox(bool(_location(finding)), "Precise affected location is captured."),
        _checkbox(bool(finding.get("snippet") or finding.get("description")), "Evidence is present and safe to share."),
        _checkbox(len(steps) >= 2, "Reproduction steps are specific enough to replay."),
        _checkbox(bool(impact), "Impact is stated in bounty-review language."),
        _checkbox(bool(proof["ready"]), "Confirmed proof of impact is captured as concrete evidence."),
        _checkbox(bool(remediation), "A concrete fix recommendation is included."),
    ]


def build_markdown(ctx: dict[str, Any]) -> str:
    findings: list[dict[str, Any]] = _reportable_findings(ctx.get("findings", []))
    counts = severity_counts(findings)
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
    out.append(
        "> This report covers **authorized** security testing only — your own assets, an "
        "explicit engagement, an in-scope bug-bounty program, or a CTF. All checks below are "
        "static or passive; nothing was exploited against a live target."
    )
    scope = str(ctx.get("scope") or "").strip()
    out.append("")
    out.append(f"- **In-scope authorization confirmed:** {'yes' if ctx.get('authorized') else 'NOT confirmed'}")
    if scope:
        out.append(f"- **Program / scope notes:** {scope}")
    out.append("")

    # --- Executive summary ---
    out.append("## Executive summary\n")
    if brain.get("summary"):
        out.append(brain["summary"].strip())
        out.append("")
    out.append(ctx.get("recommendation") or _default_summary(counts, len(findings)))
    out.append("")

    _append_bounty_triage(out, ctx, counts)
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
    out.append("## Findings\n")
    out.append("| # | Severity | Class | Title | Location |")
    out.append("|---|---|---|---|---|")
    for finding in findings:
        out.append(
            f"| {finding.get('ref', '')} "
            f"| {_SEVERITY_LABEL.get(str(finding.get('severity')).lower(), '?')} "
            f"| {_md_escape_cell(finding.get('class_name') or finding.get('category') or '')} "
            f"| {_md_escape_cell(finding.get('title', ''))} "
            f"| {_code(_location(finding))} |"
        )
    out.append("")

    # --- Per-finding detail ---
    out.append("## Finding details\n")
    attack_plans = ctx.get("attack_plans", {}) or {}
    for finding in findings:
        ref = finding.get("ref", "")
        plan = attack_plans.get(ref) or {}
        sev = _SEVERITY_LABEL.get(str(finding.get("severity")).lower(), "?")
        out.append(f"### {ref} · {finding.get('title', 'Finding')} — {sev}\n")
        out.append(f"- **Severity / confidence:** {sev} / {finding.get('confidence', 'unknown')}")
        if finding.get("class_name"):
            out.append(f"- **Class:** {finding['class_name']}")
        if finding.get("cwe"):
            out.append(f"- **CWE:** {finding['cwe']}")
        if finding.get("owasp"):
            out.append(f"- **OWASP:** {finding['owasp']}")
        _append_cvss(out, plan)
        out.append(f"- **Location:** {_code(_location(finding))}")
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
        steps = plan.get("steps") or []
        if steps:
            for i, step in enumerate(steps, 1):
                out.append(f"{i}. {str(step).strip()}")
        else:
            out.append("_No automated reproduction steps; see the class guidance and verify manually._")
        out.append("")
        if plan.get("poc"):
            poc = str(plan["poc"]).strip()[:1500]
            poc_fence = _fence(poc)
            out.append("**Proof-of-concept outline**\n")
            out.append(poc_fence)
            out.append(poc)
            out.append(poc_fence)
            out.append("")
        if plan.get("impact") or finding.get("impact"):
            out.append(f"**Impact:** {plan.get('impact') or finding.get('impact')}")
            out.append("")
        _append_proof_of_impact(out, finding, plan, heading="**Proof of impact:**")
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
    out.append("## Bounty triage\n")
    if findings:
        top = sorted(findings, key=_sev_rank, reverse=True)[0]
        top_sev = _SEVERITY_LABEL.get(str(top.get("severity")).lower(), "?")
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
        "severity_counts": severity_counts(findings),
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
        "cvss": {
            str(finding.get("ref") or ""): (attack_plans.get(finding.get("ref")) or {}).get("cvss")
            for finding in findings
            if finding.get("ref") and isinstance((attack_plans.get(finding.get("ref")) or {}).get("cvss"), dict)
        },
        "next_steps": ctx.get("next_steps", []),
        "coverage": ctx.get("coverage", {}),
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
    }


def build_finding_markdown(ctx: dict[str, Any], finding: dict[str, Any]) -> str:
    """A self-contained, submission-ready Markdown report for a single finding —
    everything a bounty platform needs in one paste."""
    if not _reportable_findings([finding]):
        return ""
    sev = _SEVERITY_LABEL.get(str(finding.get("severity")).lower(), "?")
    plan = (ctx.get("attack_plans") or {}).get(finding.get("ref"), {}) or {}
    out: list[str] = []
    out.append(f"# {finding.get('title', 'Finding')} — {sev}\n")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| **Target** | {_code(ctx.get('target', ''))} |")
    out.append(f"| **Severity / confidence** | {sev} / {finding.get('confidence', '?')} |")
    if finding.get("class_name"):
        out.append(f"| **Class** | {finding['class_name']} |")
    if finding.get("cwe"):
        out.append(f"| **CWE** | {finding['cwe']} |")
    if finding.get("owasp"):
        out.append(f"| **OWASP** | {finding['owasp']} |")
    cvss = plan.get("cvss") if isinstance(plan, dict) else None
    if isinstance(cvss, dict) and cvss.get("vector"):
        score = cvss.get("base_score")
        sev_word = str(cvss.get("base_severity") or "").strip()
        tail = f" — {score} {sev_word}".rstrip() if score is not None else (f" — {sev_word}" if sev_word else "")
        out.append(f"| **CVSS v3.1 (est.)** | {_code(str(cvss['vector']))}{tail} |")
    out.append(f"| **Location** | {_code(_location(finding))} |")
    out.append(f"| **Generated** | {ctx.get('generated_at', '')} |")
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
    steps = plan.get("steps") or []
    if steps:
        for i, step in enumerate(steps, 1):
            out.append(f"{i}. {str(step).strip()}")
    else:
        out.append("_Verify manually within your authorized scope._")
    out.append("")

    if plan.get("poc"):
        poc = str(plan["poc"]).strip()[:1500]
        poc_fence = _fence(poc)
        out.append("## Proof of concept\n")
        out.append(poc_fence)
        out.append(poc)
        out.append(poc_fence)
        out.append("")

    impact = plan.get("impact") or finding.get("impact")
    if impact:
        out.append(f"## Impact\n\n{impact}\n")
    _append_proof_of_impact(out, finding, plan, heading="## Proof of impact\n")
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
