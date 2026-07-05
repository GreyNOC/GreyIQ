"""GreyIQ BugHunter — submission packaging (HackerOne-shaped).

Turns a confirmed/reportable finding into a submission-ready package: the
human-readable, self-contained Markdown (reused from report.py) plus the
structured fields a platform wants — title, severity rating, CWE, impact, and the
vulnerability_information body. Default behavior is EXPORT (write files); pushing
to the HackerOne API is a separate, hard-gated, opt-in action.

Pure / frozen-safe for the export path. The optional API submit is the only thing
that touches the network, and only when the caller passes real credentials and an
explicit confirmation for a CONFIRMED finding.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from bughunter import fsutil
from bughunter import report as report_lib
from bughunter import report_formats

# H1 severity_rating vocabulary.
_H1_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "none", "none": "none"}


def severity_rating(finding: dict[str, Any], plan: dict[str, Any]) -> str:
    """Map the finding's resolved severity onto HackerOne's rating vocabulary. Uses the
    single source of truth (``report.resolve_severity``) so the API rating can't disagree
    with the severity shown in the report the operator pastes alongside it."""
    return _H1_SEVERITY.get(report_lib.resolve_severity(finding, plan), "low")


def _cwe_number(finding: dict[str, Any]) -> str:
    match = re.search(r"CWE-(\d+)", str(finding.get("cwe") or ""), re.IGNORECASE)
    return match.group(1) if match else ""


def build_submission(ctx: dict[str, Any], finding: dict[str, Any], platform: str = "hackerone") -> dict[str, Any] | None:
    """The structured submission package for one finding, framed for ``platform``
    (hackerone | yeswehack | bugcrowd | intigriti), or None if the report drops it
    (e.g. an unconfirmed JWT credential). ``vulnerability_information`` is the platform-
    shaped Markdown; the gathered evidence is always included when present."""
    platform = report_formats.normalize_platform(platform)
    body = report_formats.render_finding(ctx, finding, platform)
    if not body.strip():
        return None
    plan = (ctx.get("attack_plans") or {}).get(finding.get("ref"), {}) or {}
    proof = report_lib._proof_of_impact_detail(finding, plan)
    impact = str(plan.get("impact") or finding.get("impact") or proof.get("affected_asset") or "").strip()
    sev = report_lib.resolve_severity(finding, plan).title()
    title = f"[{sev}] {finding.get('title', 'Security finding')} at {finding.get('location') or ctx.get('target', '')}"
    return {
        "ref": finding.get("ref", ""),
        "title": title[:255],
        "platform": platform,
        "platform_name": report_formats.platform_name(platform),
        # severity_rating stays the HackerOne API vocabulary (used by submit_to_hackerone);
        # platform_severity is the chosen platform's own label for display.
        "severity_rating": severity_rating(finding, plan),
        "platform_severity": report_formats.platform_severity(platform, finding, plan),
        "cwe": str(finding.get("cwe") or ""),
        "weakness": _cwe_number(finding),
        "vrt": str(finding.get("vrt") or ""),  # Bugcrowd VRT category (est.), '' if unmapped
        "proof_status": str(proof.get("status") or "missing"),
        "vulnerability_information": body,
        "impact": impact,
        "target": ctx.get("target", ""),
    }


def write_submission_package(ctx: dict[str, Any], finding: dict[str, Any], out_dir: Path, stem: str,
                             platform: str = "hackerone") -> dict[str, Any] | None:
    """Write a finding's submission .md + .json to out_dir. Returns the package
    (with paths) or None if the finding isn't reportable / write failed."""
    package = build_submission(ctx, finding, platform)
    if package is None:
        return None
    md_path = out_dir / f"{stem}.md"
    json_path = out_dir / f"{stem}.json"
    try:
        fsutil.write_text_safe(md_path, package["vulnerability_information"])
        fsutil.write_text_safe(json_path, json.dumps(package, indent=2, default=str))
    except OSError:
        return None
    # Co-locate the proof screenshot (if any) with the .md so its embedded
    # ![](basename) reference resolves wherever the package folder is opened. The
    # report embeds by basename, so keep the same name. Best-effort: a copy failure
    # must not drop the package.
    # Co-locate the proof screenshot AND the graphical attack-plan map (each optional) with the .md so
    # their embedded ![](basename) references resolve wherever the package folder is opened.
    for artifact in (finding.get("screenshot_path"), finding.get("attack_map_path")):
        p = str(artifact or "").strip()
        if not p:
            continue
        src = Path(p)
        try:
            if src.is_file() and src.resolve() != (out_dir / src.name).resolve():
                shutil.copyfile(src, out_dir / src.name)
        except OSError:
            pass
    return {**package, "markdown_path": str(md_path), "json_path": str(json_path)}


class SubmissionError(RuntimeError):
    """A HackerOne submit could not proceed (gate failed or API error)."""


def submit_to_hackerone(
    package: dict[str, Any],
    *,
    team_handle: str,
    api_username: str,
    api_token: str,
    confirm: bool,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """POST one package to the HackerOne API. HARD-GATED: requires an explicit
    confirm, real credentials, a team handle, and a CONFIRMED proof status — this
    must never fire on an unproven lead. Returns the API response summary or raises
    SubmissionError. Network is only touched here."""
    if not confirm:
        raise SubmissionError("refused: pass an explicit confirmation to submit to a live program.")
    if package.get("proof_status") != "confirmed":
        raise SubmissionError(
            f"refused: only CONFIRMED findings may be auto-submitted (this one is '{package.get('proof_status')}'). "
            "Run with --active to prove it, or submit manually after capturing the proof."
        )
    if not (team_handle and api_username and api_token):
        raise SubmissionError("refused: team handle + HACKERONE_API_USERNAME + HACKERONE_API_TOKEN are required.")
    payload = {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle": team_handle,
                "title": package["title"],
                "vulnerability_information": package["vulnerability_information"],
                "impact": package.get("impact") or "See the report.",
                "severity_rating": package.get("severity_rating", "low"),
            },
        }
    }
    auth = base64.b64encode(f"{api_username}:{api_token}".encode()).decode()
    request = urllib.request.Request(
        "https://api.hackerone.com/v1/reports",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore")[:500] if hasattr(exc, "read") else ""
        raise SubmissionError(f"HackerOne API HTTP {exc.code}: {detail or exc.reason}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SubmissionError(f"HackerOne submit failed: {exc}") from exc
    report_id = str(((data.get("data") or {}).get("id")) or "")
    return {"ok": True, "report_id": report_id, "url": f"https://hackerone.com/reports/{report_id}" if report_id else ""}
