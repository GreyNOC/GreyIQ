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

from typing import Any

from bughunter import report as R

# Ordered so the UI lists HackerOne first, then YesWeHack, then the next two most
# popular crowdsourced platforms.
PLATFORMS: tuple[dict[str, str], ...] = (
    {"id": "hackerone", "name": "HackerOne",
     "blurb": "Weakness (CWE) + severity rating; Summary / Steps / Supporting material / Impact."},
    {"id": "yeswehack", "name": "YesWeHack",
     "blurb": "Bug type (CWE) + CVSS vector; Description / Steps / PoC / Impact / Remediation."},
    {"id": "bugcrowd", "name": "Bugcrowd",
     "blurb": "VRT-led + P1–P5 priority; Description / Steps / PoC / Impact / Remediation."},
    {"id": "intigriti", "name": "Intigriti",
     "blurb": "Type (OWASP/CWE) + CVSS; Description / Endpoint / PoC / Impact / Recommended fix."},
)
_PLATFORM_IDS = {p["id"] for p in PLATFORMS}
DEFAULT_PLATFORM = "hackerone"


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
# Per-platform section headings that differ from the neutral defaults.
_PROFILES: dict[str, dict[str, str]] = {
    "hackerone": {"evidence": "Supporting material / evidence", "remediation": "Remediation"},
    "yeswehack": {"evidence": "Proof / evidence", "remediation": "Suggested remediation"},
    "bugcrowd": {"evidence": "Proof / evidence", "remediation": "Remediation"},
    "intigriti": {"evidence": "Proof / evidence", "remediation": "Recommended fix"},
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
        out.append(f"| **Bug type (VRT)** | {R._code(vrt) if vrt else '(map to the closest VRT category)'} |")
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


def _section_authorization(out: list[str], ctx: dict[str, Any]) -> None:
    out.append("## Authorization & scope\n")
    out.append("> Authorized testing only — reported against an in-scope target.")
    if str(ctx.get("scope") or "").strip():
        out.append(f"\n- Scope / program: {ctx['scope']}")
    out.append("")


def _section_summary(out: list[str], finding: dict[str, Any]) -> None:
    if str(finding.get("description") or "").strip():
        out.append("## Description\n")
        out.append(str(finding["description"]).strip())
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


def _section_poc(out: list[str], plan: dict[str, Any]) -> None:
    if not str(plan.get("poc") or "").strip():
        return
    poc = str(plan["poc"]).strip()[:1500]
    fence = R._fence(poc)
    out.append("## Proof of concept\n")
    out.append(fence + R._poc_lang(poc))
    out.append(poc)
    out.append(fence)
    out.append("")


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


def _section_screenshot(out: list[str], finding: dict[str, Any]) -> None:
    """Embed a captured proof screenshot — delegates to the shared ``report._append_screenshot``
    so the default report and every per-platform report render screenshot evidence identically."""
    R._append_screenshot(out, finding)


def _section_impact(out: list[str], finding: dict[str, Any], plan: dict[str, Any]) -> None:
    impact = plan.get("impact") or finding.get("impact")
    if impact:
        out.append(f"## Impact\n\n{impact}\n")
    R._append_proof_of_impact(out, finding, plan, heading="## Proof of impact\n")


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
    """A self-contained, submission-ready Markdown report for one finding, framed for the
    chosen platform. Returns '' if the finding isn't reportable (mirrors
    report.build_finding_markdown)."""
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
    _section_authorization(out, ctx)
    _section_summary(out, finding)
    _section_steps(out, plan)
    _section_poc(out, plan)
    _section_evidence(out, finding, heading=profile["evidence"])
    _section_screenshot(out, finding)
    _section_impact(out, finding, plan)
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
    return "\n".join(out)
