"""Wardrive — Markdown rendering for the RF posture assessment.

Pure formatting: it takes the dict :func:`analyze.analyze_survey` produced and writes the
deliverable. It never re-derives a verdict, never reaches the network, and never opens a
file except through ``bughunter.fsutil`` (survey exports live under deep engagement paths
and Windows' MAX_PATH bites there constantly).

Two sections carry the weight of the whole package and are rendered BEFORE the findings on
purpose, not appended as a footnote:

  * **Provenance & scope** — the header states, in the deliverable itself, that every
    finding came from a PASSIVE export the operator already captured, that nothing was
    transmitted, and which tool wrote each file. A reader must never have to guess whether
    a line came from an observation or from an active test.
  * **Undetermined** — what the capture could not tell us, why, and the capture that would
    resolve it. Printing this above the findings is the structural defence against the
    report being read as a clean bill of health: "zero WPS findings" and "no WPS" are
    different statements, and an airodump-only survey can only ever make the first one.

Inferences are rendered in their own table and labelled INFERRED, never mixed into
findings. Markdown special characters in operator-supplied strings (an SSID is arbitrary
bytes chosen by a stranger) are escaped so a broadcast name can never restructure the
report or smuggle a link into a client deliverable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bughunter.fsutil import write_text_safe

# The five severities `bughunter.report._SEVERITY_ORDER` knows. A sixth value would sort as
# unknown there and print uncolored through gn_cli, which is why analyze.py clamps to this set.
_SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

_HEADER_NOTE = (
    "**This assessment is derived entirely from a PASSIVE survey export.** GreyIQ parsed capture "
    "files the operator had already collected under their own authorization. No frame was "
    "transmitted, no network was joined, no key material was captured and no passphrase work was "
    "performed. Every finding below is therefore an OBSERVATION plus the verification it still "
    "needs — see each finding's *Verify by* line."
)


def _esc(value: Any) -> str:
    """Escape operator-supplied text for a Markdown TABLE cell. An SSID is arbitrary bytes a
    stranger chose; it must never become markup, a link, or a new table column."""
    text = str(value if value is not None else "")
    text = text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
    text = text.replace("[", "\\[").replace("]", "\\]").replace("<", "&lt;").replace(">", "&gt;")
    return " ".join(text.split())[:200]


def _code(value: Any) -> str:
    """Escape a value that is rendered INSIDE backticks. A code span already suppresses
    markup, so only the two characters that can still break out matter: a backtick (ends the
    span) and a pipe (ends the table cell). Running :func:`_esc` here instead would print a
    WiGLE evidence token as ``\\[WPS\\]`` — visible backslashes in a client deliverable, and
    no longer the verbatim bytes the finding claims to quote."""
    text = str(value if value is not None else "").replace("`", "'").replace("|", "\\|")
    return " ".join(text.split())[:300]


def _sev_label(severity: Any) -> str:
    return _SEVERITY_LABEL.get(str(severity or "").lower(), "Info")


def build_rf_markdown(result: dict[str, Any], *, ctx: dict[str, Any] | None = None) -> str:
    """Render the assessment. ``ctx`` is the same optional shape gn_cli assembles for its
    other reports (``title``/``scope``/``generated``/``version``); everything in it is
    optional and its absence only costs a header line."""
    ctx = dict(ctx or {})
    result = dict(result or {})
    stats = dict(result.get("stats") or {})
    lines: list[str] = []

    lines.append(f"# {ctx.get('title') or 'RF survey — wireless posture assessment'}")
    lines.append("")
    lines.append(_HEADER_NOTE)
    lines.append("")
    if not result.get("ok", False):
        lines.append(f"> **Analysis did not complete:** {_esc(result.get('error') or 'unknown error')}")
        lines.append("")
        return "\n".join(lines) + "\n"

    # --- provenance
    lines.append("## Provenance")
    lines.append("")
    meta = [
        ("Scope", ctx.get("scope") or "not stated"),
        ("Generated", ctx.get("generated") or "not stated"),
        ("GreyIQ version", ctx.get("version") or "not stated"),
        ("Formats parsed", ", ".join(result.get("source_formats") or []) or "none"),
    ]
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    for key, value in meta:
        lines.append(f"| {key} | {_esc(value)} |")
    lines.append("")
    sources = result.get("sources") or []
    if sources:
        lines.append("| Export | Format | Access points | Reports WPS | Reports PMF |")
        lines.append("| --- | --- | ---: | --- | --- |")
        for source in sources:
            lines.append(
                f"| {_esc(source.get('path') or '<text>')} | {_esc(source.get('format'))} "
                f"| {int(source.get('aps') or 0)} "
                f"| {'yes' if source.get('reports_wps') else 'no'} "
                f"| {'yes' if source.get('reports_pmf') else 'no'} |")
        lines.append("")
    table_info = result.get("oui_table") or {}
    lines.append(f"OUI table: {int(table_info.get('entries') or 0)} curated prefixes "
                 f"({_esc(table_info.get('vintage') or 'unavailable')}). A BSSID absent from it is reported "
                 f"as *vendor undetermined*, which is a statement about the table, not about the device.")
    lines.append("")

    # --- summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Access points observed: **{int(stats.get('access_points') or 0)}** "
                 f"({int(stats.get('hidden') or 0)} with a suppressed SSID)")
    lines.append(f"- Clients observed: **{int(stats.get('stations') or 0)}** "
                 f"({int(stats.get('clients_with_probes') or 0)} broadcasting a preferred-network list)")
    by_enc = stats.get("by_encryption") or {}
    if by_enc:
        lines.append("- Encryption mix: " + ", ".join(f"**{count}** {_esc(name)}" for name, count in by_enc.items()))
    by_sev = stats.get("by_severity") or {}
    if by_sev:
        lines.append("- Findings: " + ", ".join(
            f"**{by_sev.get(sev, 0)}** {_sev_label(sev).lower()}"
            for sev in ("critical", "high", "medium", "low", "info") if by_sev.get(sev)))
    lines.append("")

    # --- undetermined, deliberately ABOVE the findings
    lines.append("## Undetermined — what this capture could not tell us")
    lines.append("")
    undetermined = result.get("undetermined") or []
    if not undetermined:
        lines.append("Every fact the detectors reason over was observable in the supplied exports.")
    else:
        lines.append("Absence of a finding below is **not** evidence the control is present. Each row names a "
                     "fact the export format cannot carry, so no finding was raised either way.")
        lines.append("")
        lines.append("| Fact | BSS affected | Why it is undetermined | Resolved by |")
        lines.append("| --- | ---: | --- | --- |")
        for row in undetermined:
            lines.append(f"| `{_code(row.get('fact'))}` | {int(row.get('ap_count') or 0)} "
                         f"| {_esc(row.get('reason'))} | {_esc(row.get('resolved_by'))} |")
        lines.append("")
        for row in undetermined:
            note = row.get("not_a_finding")
            if note:
                lines.append(f"- `{_code(row.get('fact'))}`: {_esc(note)}.")
    lines.append("")

    inferences = result.get("inferences") or []
    if inferences:
        lines.append("## Inferred — believed, but not observed")
        lines.append("")
        lines.append("These are conclusions drawn from the standard rather than read out of the capture. They "
                     "are kept out of the findings list on purpose.")
        lines.append("")
        lines.append("| BSSID | Fact | Inferred value | Basis |")
        lines.append("| --- | --- | --- | --- |")
        for row in inferences:
            lines.append(f"| `{_code(row.get('bssid'))}` | {_esc(row.get('fact'))} | {_esc(row.get('value'))} "
                         f"| {_esc(row.get('detail'))} |")
        lines.append("")

    # --- findings
    findings = result.get("findings") or []
    lines.append(f"## Findings ({len(findings)})")
    lines.append("")
    if not findings:
        lines.append("No finding was raised from the supplied exports. Read this together with the "
                     "*Undetermined* section above before treating the RF posture as sound.")
        lines.append("")
    for index, finding in enumerate(findings, start=1):
        lines.append(f"### {index}. [{_sev_label(finding.get('severity'))}] {_esc(finding.get('title'))}")
        lines.append("")
        lines.append(f"- **Rule**: `{_code(finding.get('rule_id'))}` "
                     f"| **Confidence**: {_esc(finding.get('confidence'))} "
                     f"| **Source format**: `{_code(finding.get('source_format'))}`")
        lines.append(f"- **Where**: `{_code(finding.get('location'))}` (export line {int(finding.get('line_start') or 0)})")
        lines.append(f"- **Class**: {_esc(finding.get('class_name'))} | **CWE**: {_esc(finding.get('cwe'))} "
                     f"| **OWASP**: {_esc(finding.get('owasp'))}")
        evidence = str(finding.get("evidence") or "")
        if evidence:
            lines.append(f"- **Evidence (verbatim from the export)**: `{_code(evidence)}`")
        proof = finding.get("proof_evidence") or {}
        matched = str(proof.get("matched_value") or "")
        if matched:
            lines.append(f"- **Observation**: {_esc(matched)}")
        snippet = str(finding.get("snippet") or "")
        if snippet:
            lines.append("")
            lines.append("```text")
            lines.append(snippet.replace("```", "'''"))
            lines.append("```")
        lines.append("")
        lines.append(f"**Remediation.** {finding.get('remediation') or ''}")
        lines.append("")
        lines.append(f"**Verify by.** {finding.get('verification_obligation') or 'not stated'}")
        lines.append("")

    # --- inventory
    lines.append("## Access points observed")
    lines.append("")
    aps = ctx.get("access_points") or []
    if aps:
        lines.append("| BSSID | SSID | Ch | Band | Encryption | Cipher | WPS | PMF | Signal |")
        lines.append("| --- | --- | ---: | --- | --- | --- | --- | --- | --- |")
        for ap in aps:
            lines.append(
                f"| `{_code(ap.get('bssid'))}` | {_esc(ap.get('ssid') or '(hidden)')} "
                f"| {ap.get('channel') if ap.get('channel') is not None else '?'} "
                f"| {_esc(ap.get('band') or '?')} | {_esc(ap.get('encryption'))} "
                f"| {_esc(ap.get('cipher') or '-')} | {_tri(ap.get('wps'))} "
                f"| {_esc(ap.get('pmf') or 'undetermined')} | {_signal(ap)} |")
        lines.append("")
    else:
        lines.append("Access-point inventory was not supplied to the renderer.")
        lines.append("")

    warnings = result.get("warnings") or []
    lines.append("## Parser notes")
    lines.append("")
    if warnings:
        for warning in warnings:
            lines.append(f"- {_esc(warning)}")
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines) + "\n"


def _tri(value: Any) -> str:
    """Render a tri-state as three DISTINCT words. ``None`` must never print as "no"."""
    if value is True:
        return "enabled"
    if value is False:
        return "disabled"
    return "undetermined"


def _signal(ap: dict[str, Any]) -> str:
    """dBm when measured, percentage when that is all the tool recorded, never a conversion."""
    if ap.get("signal_dbm") is not None:
        return f"{ap['signal_dbm']} dBm"
    if ap.get("signal_pct") is not None:
        return f"{ap['signal_pct']}% (quality, not dBm)"
    return "undetermined"


def write_rf_report(path: Any, result: dict[str, Any], *, ctx: dict[str, Any] | None = None) -> Path:
    """Render and write the report, through ``fsutil`` so a deep engagement path on Windows
    still lands. Returns the path actually written."""
    return write_text_safe(Path(str(path)), build_rf_markdown(result, ctx=ctx))
