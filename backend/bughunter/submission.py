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
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from bughunter import fsutil
from bughunter import report as report_lib

# H1 severity_rating vocabulary.
_H1_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "none", "none": "none"}


def severity_rating(finding: dict[str, Any], plan: dict[str, Any]) -> str:
    """Map the finding/CVSS severity onto HackerOne's rating vocabulary."""
    cvss = plan.get("cvss") if isinstance(plan, dict) else None
    if isinstance(cvss, dict) and cvss.get("base_severity"):
        return _H1_SEVERITY.get(str(cvss["base_severity"]).strip().lower(), "low")
    return _H1_SEVERITY.get(str(finding.get("severity") or "low").strip().lower(), "low")


def _cwe_number(finding: dict[str, Any]) -> str:
    match = re.search(r"CWE-(\d+)", str(finding.get("cwe") or ""), re.IGNORECASE)
    return match.group(1) if match else ""


def build_submission(ctx: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any] | None:
    """The structured submission package for one finding, or None if the report
    drops it (e.g. an unconfirmed JWT credential)."""
    body = report_lib.build_finding_markdown(ctx, finding)
    if not body.strip():
        return None
    plan = (ctx.get("attack_plans") or {}).get(finding.get("ref"), {}) or {}
    proof = report_lib._proof_of_impact_detail(finding, plan)
    impact = str(plan.get("impact") or finding.get("impact") or proof.get("affected_asset") or "").strip()
    sev = str(finding.get("severity") or "").title()
    title = f"[{sev}] {finding.get('title', 'Security finding')} at {finding.get('location') or ctx.get('target', '')}"
    return {
        "ref": finding.get("ref", ""),
        "title": title[:255],
        "severity_rating": severity_rating(finding, plan),
        "cwe": str(finding.get("cwe") or ""),
        "weakness": _cwe_number(finding),
        "vrt": str(finding.get("vrt") or ""),  # Bugcrowd VRT category (est.), '' if unmapped
        "proof_status": str(proof.get("status") or "missing"),
        "vulnerability_information": body,
        "impact": impact,
        "target": ctx.get("target", ""),
    }


def write_submission_package(ctx: dict[str, Any], finding: dict[str, Any], out_dir: Path, stem: str) -> dict[str, Any] | None:
    """Write a finding's submission .md + .json to out_dir. Returns the package
    (with paths) or None if the finding isn't reportable / write failed."""
    package = build_submission(ctx, finding)
    if package is None:
        return None
    md_path = out_dir / f"{stem}.md"
    json_path = out_dir / f"{stem}.json"
    try:
        fsutil.write_text_safe(md_path, package["vulnerability_information"])
        fsutil.write_text_safe(json_path, json.dumps(package, indent=2, default=str))
    except OSError:
        return None
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
