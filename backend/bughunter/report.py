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

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def _sev_rank(finding: dict[str, Any]) -> int:
    return _SEVERITY_ORDER.get(str(finding.get("severity", "info")).lower(), 0)


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


def build_markdown(ctx: dict[str, Any]) -> str:
    findings: list[dict[str, Any]] = ctx.get("findings", [])
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
        sev = _SEVERITY_LABEL.get(str(finding.get("severity")).lower(), "?")
        out.append(f"### {ref} · {finding.get('title', 'Finding')} — {sev}\n")
        out.append(f"- **Severity / confidence:** {sev} / {finding.get('confidence', 'unknown')}")
        if finding.get("class_name"):
            out.append(f"- **Class:** {finding['class_name']}")
        if finding.get("cwe"):
            out.append(f"- **CWE:** {finding['cwe']}")
        if finding.get("owasp"):
            out.append(f"- **OWASP:** {finding['owasp']}")
        out.append(f"- **Location:** {_code(_location(finding))}")
        out.append(f"- **Rule:** {_code(finding.get('rule_id', ''))}")
        out.append("")
        if finding.get("description"):
            out.append(finding["description"].strip())
            out.append("")
        snippet = str(finding.get("snippet") or "").strip()
        if snippet:
            clipped = snippet[:1200]
            fence = _fence(clipped)
            out.append("**Evidence**\n")
            out.append(fence)
            out.append(clipped)
            out.append(fence)
            out.append("")

        plan = attack_plans.get(ref) or {}
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
        remediation = finding.get("remediation") or plan.get("remediation")
        if remediation:
            out.append(f"**Remediation:** {remediation}")
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
    _append_footer(out, ctx)
    return "\n".join(out)


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
    findings = ctx.get("findings", [])
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
        "finding_count": len(findings),
        "findings": findings,
        "attack_plans": ctx.get("attack_plans", {}),
        "manual_checklist": ctx.get("manual_checklist", []),
        "brain": {
            "used": bool(ctx.get("brain", {}).get("used")),
            "provider": ctx.get("brain", {}).get("provider", ""),
            "model": ctx.get("brain", {}).get("model", ""),
        },
        "scan_meta": ctx.get("scan_meta", {}),
    }
