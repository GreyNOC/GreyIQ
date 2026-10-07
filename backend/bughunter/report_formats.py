"""GreyIQ BugHunter — platform-shaped submission report formats.

The canonical per-finding report (``report.build_finding_markdown``) is HackerOne-
flavoured. Different bug-bounty platforms expect different field labels, taxonomy
emphasis (Bugcrowd leads with its VRT; YesWeHack/Intigriti lead with a CVSS vector +
bug type), severity vocabularies (HackerOne critical..none; Bugcrowd P1..P5; the others
a qualitative band), and section framing. This module re-shapes the SAME finding and the
SAME gathered evidence into each platform's expected layout, so an operator can copy a
report that already matches the destination program's form.

It does NOT invent content: it composes ``report.py``'s existing section builders, so the
captured proof / evidence rendering is identical everywhere. The gathered evidence (the
captured request/response, matched values, code/response excerpt) is ALWAYS included when
the finding carries it. Pure / frozen-safe.
"""

from __future__ import annotations

import re
from typing import Any

from bughunter import report as R
from bughunter import submission_writer
from bughunter import taxonomy


def _ai_summary(ctx: dict[str, Any], finding: dict[str, Any], plan: dict[str, Any], platform: str) -> str | None:
    """The AI-written platform-voiced summary, generated once per (finding, platform) and cached on the
    finding so a re-render / platform toggle doesn't re-call the brain. Only when ctx carries a brain
    config; fail-closed (any problem -> None -> the deterministic description is used)."""
    cfg = ctx.get("coder_cfg")
    if not cfg:
        return None
    cache = finding.setdefault("_ai_summary_cache", {})
    if platform not in cache:
        try:
            cache[platform] = submission_writer.write_summary(cfg, finding, plan, platform) or ""
        except Exception:  # noqa: BLE001 - summary is enrichment; never break a render
            cache[platform] = ""
    return cache.get(platform) or None

# Ordered so the UI lists HackerOne first, then YesWeHack and the next two crowdsourced
# platforms, then HackenProof (web3-focused: exchanges, protocols, smart contracts).
PLATFORMS: tuple[dict[str, str], ...] = (
    {"id": "hackerone", "name": "HackerOne",
     "blurb": "Weakness (CWE) + severity rating; Summary / Steps / Supporting material / Impact."},
    {"id": "yeswehack", "name": "YesWeHack",
     "blurb": "Bug type (CWE) + CVSS vector; Description / Steps / PoC / Impact / Remediation."},
    {"id": "bugcrowd", "name": "Bugcrowd",
     "blurb": "VRT-led + P1–P5 priority; Description / Steps / PoC / Impact / Remediation."},
    {"id": "intigriti", "name": "Intigriti",
     "blurb": "Type (OWASP/CWE) + CVSS; Description / Endpoint / PoC / Impact / Recommended fix."},
    {"id": "hackenproof", "name": "HackenProof",
     "blurb": "Target + Vulnerability category + Critical–Low severity (web/mobile + smart contracts); Description / Validation steps / PoC / Impact."},
)
_PLATFORM_IDS = {p["id"] for p in PLATFORMS}
DEFAULT_PLATFORM = "hackerone"
_NESTED_REDACTION = re.compile(
    r"\[REDACTED_SECRET:\[REDACTED_SECRET:sha256:[0-9a-f]{12}\]:([0-9a-f]{12})\]"
)


def _safe_report_text(text: str, finding: dict[str, Any]) -> str:
    """Redact the complete rendered surface, including fields added by callers."""
    secret = str(finding.get("secret_value") or "")
    if secret:
        # Replace the known value before the generic pass, even for short keys.
        # A neutral marker is not mistaken for a fresh Bearer token, and the
        # single generic pass still catches unrelated credentials.
        text = text.replace(secret, "<redacted>")
    redacted = R.redact_text(text)[0]
    # The generic redactor can match the word "SECRET" inside a marker it
    # created earlier in the same pass. Flatten that display artifact without
    # applying another redaction pass or revealing the original value.
    while True:
        flattened = _NESTED_REDACTION.sub(r"[REDACTED_SECRET:sha256:\1]", redacted)
        if flattened == redacted:
            return redacted
        redacted = flattened


def list_platforms() -> list[dict[str, str]]:
    """The platform registry for the API / CLI / cockpit selector."""
    return [dict(p) for p in PLATFORMS]


def normalize_platform(platform: str | None) -> str:
    """Coerce caller input to a known platform id; unknown -> the default (never raises)."""
    p = str(platform or "").strip().lower()
    return p if p in _PLATFORM_IDS else DEFAULT_PLATFORM


def platform_name(platform: str) -> str:
    for entry in PLATFORMS:
        if entry["id"] == platform:
            return entry["name"]
    return "HackerOne"


# --- severity vocabularies -----------------------------------------------------
_H1_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "none", "none": "none"}
# Bugcrowd uses a P1 (most severe) .. P5 (informational) priority scale.
_BUGCROWD_PRIORITY = {"critical": "P1 (Critical)", "high": "P2 (Severe)", "medium": "P3 (Moderate)",
                      "low": "P4 (Low)", "info": "P5 (Informational)", "none": "P5 (Informational)"}
_TITLE_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
                   "info": "Informational", "none": "Informational"}
# HackenProof classifies web/mobile and smart-contract findings on a four-band Critical..Low
# scale (docs.hackenproof.com/bug-bounty/vulnerability-classification) — it defines no
# "Informational" or "None" band. An internal info/none therefore maps to Low, the nearest
# real band HackenProof recognizes, rather than emitting a band the platform doesn't define.
_HACKENPROOF_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
                         "info": "Low", "none": "Low"}
# Per-platform section headings that differ from the neutral defaults.
_PROFILES: dict[str, dict[str, str]] = {
    "hackerone": {"evidence": "Supporting material / evidence", "remediation": "Remediation"},
    "yeswehack": {"evidence": "Proof / evidence", "remediation": "Suggested remediation"},
    "bugcrowd": {"evidence": "Proof / evidence", "remediation": "Remediation"},
    "intigriti": {"evidence": "Proof / evidence", "remediation": "Recommended fix"},
    "hackenproof": {"evidence": "Proof / evidence", "remediation": "Remediation"},
}


def _base_severity(finding: dict[str, Any], plan: dict[str, Any]) -> str:
    """The severity bucket — delegates to the single source of truth (``report.resolve_severity``)
    so the per-platform label can never disagree with the default report or the H1 rating."""
    return R.resolve_severity(finding, plan)


def platform_severity(platform: str, finding: dict[str, Any], plan: dict[str, Any]) -> str:
    """The severity label in the destination platform's own vocabulary."""
    platform = normalize_platform(platform)
    sev = _base_severity(finding, plan)
    if platform == "hackerone":
        return _H1_SEVERITY.get(sev, "low")
    if platform == "bugcrowd":
        return _BUGCROWD_PRIORITY.get(sev, "P4 (Low)")
    if platform == "hackenproof":
        return _HACKENPROOF_SEVERITY.get(sev, "Low")
    return _TITLE_SEVERITY.get(sev, "Low")  # yeswehack / intigriti


# --- section builders (reuse report.py so evidence is identical everywhere) -----
def _meta_table(out: list[str], ctx: dict[str, Any], finding: dict[str, Any], plan: dict[str, Any], platform: str) -> None:
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| **Asset / endpoint** | {R._code(R._location(finding) or ctx.get('target', ''))} |")
    out.append(f"| **Severity** | {platform_severity(platform, finding, plan)} |")
    cwe = str(finding.get("cwe") or "")
    owasp = str(finding.get("owasp") or "")
    vrt = str(finding.get("vrt") or "").strip()
    if platform == "bugcrowd":
        # Prefer any VRT the finding carries, else derive a best-effort estimate from the
        # CWE so the Bugcrowd form's required Bug-Type field isn't left as a placeholder.
        vrt_est = vrt or (taxonomy.cwe_to_vrt(cwe) or "")
        if vrt_est:
            out.append(f"| **Bug type (VRT, est.)** | {R._code(vrt_est)} |")
        else:
            out.append("| **Bug type (VRT)** | (map to the closest VRT category) |")
        if cwe:
            out.append(f"| **CWE** | {R._linkify_cwe(cwe)} |")
    elif platform == "yeswehack":
        if cwe:
            out.append(f"| **Bug type (CWE)** | {R._linkify_cwe(cwe)} |")
        if finding.get("class_name"):
            out.append(f"| **Category** | {finding['class_name']} |")
    elif platform == "intigriti":
        if owasp:
            out.append(f"| **Type (OWASP)** | {R._linkify_owasp(owasp)} |")
        if cwe:
            out.append(f"| **CWE** | {R._linkify_cwe(cwe)} |")
    elif platform == "hackenproof":
        # HackenProof's report form leads with Target (the Asset/endpoint row above) +
        # Vulnerability category + Severity; CVSS (appended below) is the fallback score.
        if finding.get("class_name"):
            out.append(f"| **Vulnerability category** | {finding['class_name']} |")
        if cwe:
            out.append(f"| **CWE** | {R._linkify_cwe(cwe)} |")
        if owasp:
            out.append(f"| **OWASP** | {R._linkify_owasp(owasp)} |")
    else:  # hackerone
        if cwe:
            out.append(f"| **Weakness (CWE)** | {R._linkify_cwe(cwe)} |")
        if owasp:
            out.append(f"| **OWASP** | {R._linkify_owasp(owasp)} |")
    cvss = plan.get("cvss") if isinstance(plan, dict) else None
    if isinstance(cvss, dict) and cvss.get("vector"):
        score = cvss.get("base_score")
        sev_word = str(cvss.get("base_severity") or "").strip()
        tail = f" — {score} {sev_word}".rstrip() if score is not None else (f" — {sev_word}" if sev_word else "")
        out.append(f"| **CVSS v3.1 (est.)** | {R._code(str(cvss['vector']))}{tail} |")
    out.append(f"| **Confidence** | {finding.get('confidence', '?')} |")
    out.append(f"| **Generated** | {ctx.get('generated_at', '')} |")
    out.append("")


def _section_affected_locations(out: list[str], finding: dict[str, Any]) -> None:
    """Every location a grouped duplicate-lead finding covers.

    ``bounty._group_duplicate_leads`` collapses near-identical leads into ONE representative
    carrying ``grouped_locations`` — so the meta table's single "Asset / endpoint" row is the
    representative only, and without this section the submission body claims one affected URL
    where the engine found several. That understates impact and invites an "informational"
    close. ``report.build_finding_markdown`` already renders this; the per-platform bodies
    (and, through ``submission.build_submission``, the HackerOne API payload) must match, or
    the same finding reads differently depending on which surface produced it. No-op for an
    ungrouped finding, so a normal report is byte-identical to before."""
    grouped = R._grouped_locations(finding)
    if not grouped:
        return
    out.append("## Affected locations\n")
    out.append(f"{len(grouped)} locations share this root cause — filed once, listing each affected path:")
    out.append("")
    for loc in grouped[:25]:
        out.append(f"- {R._code(loc)}")
    if len(grouped) > 25:
        out.append(f"- _(+{len(grouped) - 25} more)_")
    out.append("")


def _section_authorization(out: list[str], ctx: dict[str, Any]) -> None:
    out.append("## Authorization & scope\n")
    out.append("> Authorized testing only — reported against an in-scope target.")
    if str(ctx.get("scope") or "").strip():
        out.append(f"\n- Scope / program: {ctx['scope']}")
    out.append("")


def _section_summary(out: list[str], finding: dict[str, Any], summary: str | None = None) -> None:
    # The AI-written platform-voiced summary (submission_writer) when present; else the finding's own
    # deterministic description. Either way this is opening PROSE — every evidence/proof section that
    # follows is deterministic and authoritative.
    text = str(summary or finding.get("description") or "").strip()
    if text:
        out.append("## Description\n")
        out.append(text)
        out.append("")


def _section_steps(out: list[str], plan: dict[str, Any]) -> None:
    out.append("## Steps to reproduce\n")
    steps = R.normalize_steps(plan.get("steps"))
    if steps:
        for i, step in enumerate(steps, 1):
            out.append(f"{i}. {step}")
    else:
        out.append("_Verify manually within your authorized scope._")
    out.append("")


def _section_poc(out: list[str], finding: dict[str, Any], plan: dict[str, Any]) -> None:
    R._append_proof_of_concept(out, finding, plan, heading="## Proof of concept\n")


def _section_evidence(out: list[str], finding: dict[str, Any], *, heading: str) -> None:
    """The gathered evidence — captured request/response + matched values (always when
    present) plus any code/response excerpt. This is the artifact a triager wants."""
    captured: list[str] = []
    R._append_proof_evidence(captured, finding)
    snippet = str(finding.get("snippet") or "").strip()
    if not captured and not snippet:
        return
    out.append(f"## {heading}\n")
    if captured:
        out.extend(captured)
    if snippet:
        clipped = snippet[:1200]
        fence = R._fence(clipped)
        out.append("Code / response excerpt:\n")
        out.append(fence)
        out.append(clipped)
        out.append(fence)
        out.append("")


def _section_screenshot(out: list[str], finding: dict[str, Any], plan: dict[str, Any]) -> None:
    """Embed a captured proof screenshot — delegates to the shared ``report._append_screenshot``
    so the default report and every per-platform report render screenshot evidence identically.
    ``plan`` rides along so the attack-map caption reads the same confirm gate here as there."""
    R._append_screenshot(out, finding, plan)
    R._append_credential_proof(out, finding)


def _section_impact(out: list[str], ctx: dict[str, Any], finding: dict[str, Any], plan: dict[str, Any]) -> None:
    impact = plan.get("impact") or finding.get("impact")
    if impact:
        out.append(f"## Impact\n\n{impact}\n")
    # The chain role sits between the impact prose and the proof sections — the position
    # build_finding_markdown uses — because this body is what the operator pastes into the platform
    # form, read on its own with no report around it to supply the chain context. Delegated so the
    # clamped status/state wording is identical on both surfaces.
    R._append_chain_role(out, ctx, str(finding.get("ref") or ""))
    R._append_proof_of_impact(out, finding, plan, heading="## Proof of impact\n")
    R._append_proof_of_exploitability(out, finding, plan, heading="## Proof of exploitability\n")


def _section_remediation(out: list[str], finding: dict[str, Any], plan: dict[str, Any], *, heading: str) -> None:
    remediation = finding.get("remediation") or plan.get("remediation")
    if remediation:
        out.append(f"## {heading}\n\n{remediation}\n")


def _section_references(out: list[str], finding: dict[str, Any]) -> None:
    if finding.get("references"):
        out.append("## References\n\n" + ", ".join(finding["references"]) + "\n")


def _section_retest(out: list[str]) -> None:
    out.append("## Retest after fix\n")
    for item in R._RETEST_CHECKLIST:
        out.append(f"- [ ] {item}")
    out.append("")


def render_finding(ctx: dict[str, Any], finding: dict[str, Any], platform: str = DEFAULT_PLATFORM) -> str:
    """Detailed analyst report for one finding, framed for the chosen platform.

    This keeps the metadata, proof gates, retest checklist, and every evidence
    section for local review. ``render_submission_body`` is the shorter text the
    operator pastes into a platform's description field.
    """
    platform = normalize_platform(platform)
    if not R._reportable_findings([finding]):
        return ""
    plan = (ctx.get("attack_plans") or {}).get(finding.get("ref"), {}) or {}
    profile = _PROFILES[platform]
    sev_word = _TITLE_SEVERITY.get(_base_severity(finding, plan), "")

    out: list[str] = []
    out.append((f"# [{sev_word}] " if sev_word else "# ") + str(finding.get("title", "Finding")) + "\n")
    banner = f"> {platform_name(platform)} submission · severity **{platform_severity(platform, finding, plan)}**"
    if finding.get("class_name"):
        banner += f" · {finding['class_name']}"
    out.append(banner)
    out.append("")

    _meta_table(out, ctx, finding, plan, platform)
    _section_affected_locations(out, finding)
    _section_authorization(out, ctx)
    _section_summary(out, finding, _ai_summary(ctx, finding, plan, platform))
    _section_steps(out, plan)
    _section_poc(out, finding, plan)
    _section_evidence(out, finding, heading=profile["evidence"])
    _section_screenshot(out, finding, plan)
    _section_impact(out, ctx, finding, plan)
    _section_remediation(out, finding, plan, heading=profile["remediation"])
    _section_references(out, finding)
    _section_retest(out)

    # No tool/bot self-identification by default — most programs' terms don't require
    # it, and unprompted "generated by an automated tool" framing can bias a triager
    # before they've even read the evidence. Only add a disclosure line when the
    # operator has explicitly set disclose_automation=True for this program (Program
    # tab -> "This program's terms require disclosing automated-tool assistance"),
    # which is the one case where omitting it would violate the destination program's
    # own rules.
    if ctx.get("disclose_automation"):
        out.append("---")
        tool = str(ctx.get("tool") or "an automated testing tool").strip()
        version = str(ctx.get("version") or "").strip()
        suffix = f" v{version}" if version else ""
        out.append(
            f"_Disclosure: this finding was identified and validated with the assistance of {tool}{suffix}. "
            "All results were manually reviewed before submission._"
        )
    return _safe_report_text("\n".join(out), finding)


def render_submission_body(ctx: dict[str, Any], finding: dict[str, Any], platform: str = DEFAULT_PLATFORM) -> str:
    """Render the operator-facing description field from captured, redacted data.

    Platform forms carry title, severity, asset, CWE/VRT, and CVSS separately.
    Keeping those fields and internal QA prose out of this body makes the finding
    easier to read without discarding them from the submission package. A candidate
    remains explicitly unconfirmed; narrative text cannot promote it to proof.
    """
    platform = normalize_platform(platform)
    if not R._reportable_findings([finding]):
        return ""
    plan = (ctx.get("attack_plans") or {}).get(finding.get("ref"), {}) or {}
    proof = R._proof_of_impact_detail(finding, plan)
    confirmed = proof.get("status") == "confirmed"
    out: list[str] = ["**Summary**", ""]

    location = str(R._location(finding) or ctx.get("target") or "").strip()
    # The paste body uses deterministic source text. Model-written prose remains in
    # the analyst report, where the operator can compare it with the artifacts.
    summary = str(finding.get("description") or "").strip()
    if not confirmed:
        # Candidate titles and descriptions can themselves say "confirmed" or
        # assert an impact. The platform form carries the title separately.
        out.append("This location was flagged for review. The behavior and impact have not been confirmed.")
    elif summary:
        out.append(R.redact_text(summary)[0])
    else:
        out.append(R.redact_text(str(finding.get("title") or "Finding under review"))[0] + ".")
    if location:
        out.append(f"Affected location: {R.redact_text(location)[0]}")
    if str(finding.get("secret_classification") or "") == R.secret_classification.PUBLIC_CLIENT_KEY:
        out.append("Informational only: this is a public client key. Unauthorized access has not been confirmed.")

    grouped = R._grouped_locations(finding)
    if grouped:
        out.extend(["", "Affected locations sharing this finding:"])
        out.extend(f"- {R.redact_text(loc)[0]}" for loc in grouped)

    out.extend(["", "**Proof of Concept**", ""])
    steps = R.normalize_steps(plan.get("steps"))
    poc = str(plan.get("poc") or "").strip()
    if steps:
        out.extend(f"{index}. {R.redact_text(step)[0]}" for index, step in enumerate(steps, 1))
        out.append("")
    elif poc:
        out.extend(["1. Run the reproduction artifact below within the authorized scope.", ""])
    else:
        out.append("Reproduction steps have not been captured yet.")
        out.append("")

    if poc:
        poc = R.redact_text(poc)[0]
        fence = R._fence(poc)
        out.extend(["Reproduction artifact:", f"{fence}{R._poc_lang(poc)}", poc, fence, ""])

    pe = finding.get("proof_evidence") if isinstance(finding.get("proof_evidence"), dict) else {}
    captured_parts: list[str] = []
    request = [str(pe.get(key) or "").strip() for key in ("request_line", "request_header")]
    response = [str(pe.get(key) or "").strip() for key in
                ("response_status", "response_header", "set_cookie", "matched_value", "read_data")]
    captured_parts.extend(part for part in request if part)
    if any(request) and any(response):
        captured_parts.append("")
    captured_parts.extend(part for part in response if part)
    if captured_parts:
        capture = R.redact_text("\n".join(captured_parts))[0]
        fence = R._fence(capture)
        out.extend(["Captured request/response fields:", f"{fence}http", capture, fence, ""])
    elif not poc:
        out.extend(["No request or runnable command was captured in this report.", ""])

    snippet = str(finding.get("snippet") or "").strip()
    if snippet:
        snippet = R.redact_text(snippet)[0]
        fence = R._fence(snippet)
        out.extend(["Captured source or response excerpt:", fence, snippet, fence, ""])

    observed = R.redact_text(str(proof.get("observed_result") or proof.get("evidence") or ""))[0].strip()
    control = R.redact_text(str(proof.get("control_result") or ""))[0].strip()
    if observed:
        out.extend(["Confirmed result:" if confirmed else "Observed result (unconfirmed):", observed, ""])
    if control:
        out.extend(["Control result:", control, ""])
    else:
        out.extend(["No negative-control result was captured.", ""])
    limitations = R.redact_text(str(proof.get("limitations") or ""))[0].strip()
    if limitations:
        out.extend(["Limitations: " + limitations, ""])
    if not confirmed:
        out.extend(["Impact has not been confirmed. Verify the result and its control before filing.", ""])

    screenshots = [name for name in R._screenshot_names(finding) if R.redact_text(name)[0] == name]
    if screenshots:
        out.extend(["**Screenshots**", ""])
        out.extend(f"![Captured screenshot]({name})" for name in screenshots)
        out.append("")

    out.extend(["## Impact", ""])
    impact = str(plan.get("impact") or finding.get("impact") or "").strip()
    if confirmed and impact:
        out.append("Assessed impact: " + R.redact_text(impact)[0])
    elif confirmed:
        # The observed result is already proof-gated, but a business consequence
        # should not be invented when no impact statement was supplied.
        out.append("The captured result above is the demonstrated effect. Further impact has not been established.")
    else:
        out.append("The available evidence does not yet establish security impact.")
    investigation = ctx.get("investigation") if isinstance(ctx.get("investigation"), dict) else {}
    chains = investigation.get("attack_chains") if isinstance(investigation.get("attack_chains"), list) else []
    for chain in chains:
        if not isinstance(chain, dict):
            continue
        steps_in_chain = chain.get("steps") if isinstance(chain.get("steps"), list) else []
        for step in steps_in_chain:
            if not isinstance(step, dict) or str(step.get("evidence_ref") or "") != str(finding.get("ref") or ""):
                continue
            title = R.redact_text(str(chain.get("title") or chain.get("id") or "the related chain"))[0]
            projected = R.redact_text(str(chain.get("projected_impact") or ""))[0]
            if confirmed and str(step.get("state") or "").lower() == "proven":
                out.append(f"This is a proven step in {title}.")
            else:
                note = f"This is a projected step in {title}."
                if projected:
                    note += f" The projected impact, {projected}, has not been demonstrated here."
                out.append(note)
    out.append("")

    remediation = str(finding.get("remediation") or plan.get("remediation") or "").strip()
    required = ctx.get("required_report_sections") or []
    if remediation and (platform != "hackerone" or ctx.get("include_remediation") or "remediation" in required):
        out.extend(["## Remediation", "", R.redact_text(remediation)[0], ""])
    if ctx.get("disclose_automation"):
        tool = str(ctx.get("tool") or "an automated testing tool").strip()
        version = str(ctx.get("version") or "").strip()
        version = R.redact_text(version)[0]
        out.append(f"Automated testing assistance: {R.redact_text(tool)[0]}{(' v' + version) if version else ''}.")
    return _safe_report_text("\n".join(out).strip() + "\n", finding)
