"""GreyIQ BugHunter — submission packaging (HackerOne-shaped).

Turns a confirmed/reportable finding into a submission-ready package: the
human-readable, self-contained Markdown (reused from report.py) plus the
structured fields a platform wants — title, severity rating, CWE/weakness, Bugcrowd
VRT, CVSS vector, the target asset, and the vulnerability_information body. Default
behavior is EXPORT (write files); pushing to the HackerOne API is a separate,
hard-gated, opt-in action.

V2 additions:
  * ``preflight`` — a per-platform required-field validator, so an operator sees
    exactly what THIS program's form still needs (H1: asset+weakness; Bugcrowd:
    VRT+priority; …) before submitting, instead of discovering empty required fields
    on paste.
  * ``submit_to_hackerone`` now files a *routed* report — the in-scope asset
    (structured_scope_id), the HackerOne weakness id (matched from the finding's CWE),
    and the CVSS vector ride along, and the captured evidence is uploaded as report
    attachments — all behind the same unbypassable hard gate.

Pure / frozen-safe for the export path. The optional API submit + attachment upload
are the only things that touch the network, and only when the caller passes real
credentials and an explicit confirmation for a CONFIRMED finding.
"""

from __future__ import annotations

import base64
import json
import mimetypes
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from bughunter import fsutil
from bughunter import report as report_lib
from bughunter import report_formats
from bughunter import taxonomy

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
    location = str(finding.get("location") or "").strip()
    title = f"[{sev}] {finding.get('title', 'Security finding')} at {location or ctx.get('target', '')}"
    # Bugcrowd VRT: prefer any explicit value the finding already carries, else derive it
    # deterministically from the CWE (best-effort estimate) so a Bugcrowd submission no
    # longer lands on the literal "(map to the closest VRT category)" placeholder.
    vrt = str(finding.get("vrt") or "").strip() or (taxonomy.cwe_to_vrt(finding.get("cwe")) or "")
    cvss = plan.get("cvss") if isinstance(plan.get("cvss"), dict) else {}
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
        "vrt": vrt,  # Bugcrowd VRT category (est.), '' if the CWE is unmapped
        "cvss_vector": str(cvss.get("vector") or "").strip(),
        "cvss_score": cvss.get("base_score"),
        # The concrete affected asset/endpoint — used to route an H1 submission to its
        # structured_scope entry and to preflight the platforms that require an endpoint.
        "location": location,
        "proof_status": str(proof.get("status") or "missing"),
        "vulnerability_information": body,
        "impact": impact,
        "target": ctx.get("target", ""),
    }


# ---------------------------------------------------------------------------
# Per-platform submission preflight (required-field readiness)
# ---------------------------------------------------------------------------
# What each destination program's submission form actually REQUIRES, so preflight can
# report "missing for THIS program" instead of a generic completeness score. Each entry:
# a package-field key -> the human label shown when it's absent.
_PLATFORM_REQUIRED: dict[str, list[tuple[str, str]]] = {
    "hackerone": [("title", "Title"), ("vulnerability_information", "Report body"),
                  ("severity_rating", "Severity"), ("weakness", "Weakness (CWE)"),
                  ("location", "Affected asset / endpoint")],
    "bugcrowd": [("title", "Title"), ("vulnerability_information", "Description"),
                 ("platform_severity", "Priority (P1–P5)"), ("vrt", "Bug type (VRT)")],
    "intigriti": [("title", "Title"), ("vulnerability_information", "Description"),
                  ("location", "Endpoint / domain"), ("cvss_vector", "CVSS vector")],
    "yeswehack": [("title", "Title"), ("vulnerability_information", "Description"),
                  ("weakness", "Bug type (CWE)"), ("cvss_vector", "CVSS vector")],
    # HackenProof's form is Title / Target / Vulnerability category / Severity / Vulnerability
    # details / Validation steps — it has NO CWE field (it uses a Vulnerability category), so
    # readiness must NOT demand a CWE the platform doesn't collect.
    "hackenproof": [("title", "Title"), ("vulnerability_information", "Vulnerability details"),
                    ("platform_severity", "Severity"), ("location", "Target")],
}


def preflight(package: dict[str, Any], platform: str | None = None) -> dict[str, Any]:
    """Validate a submission package against the destination platform's required fields.

    Returns ``{"ok", "platform", "platform_name", "ready", "missing": [labels],
    "warnings": [str], "checklist": [{"label", "present"}]}``. ``ready`` is True only when
    every required field is present AND the finding is proof-confirmed. Pure/no-network —
    this is the paste-and-submit readiness gate the UI shows before a submit.
    """
    platform = report_formats.normalize_platform(platform or package.get("platform"))
    required = _PLATFORM_REQUIRED.get(platform, _PLATFORM_REQUIRED["hackerone"])
    checklist: list[dict[str, Any]] = []
    missing: list[str] = []
    for key, label in required:
        present = bool(str(package.get(key) or "").strip())
        checklist.append({"label": label, "present": present})
        if not present:
            missing.append(label)

    warnings: list[str] = []
    proof_status = str(package.get("proof_status") or "missing")
    proof_ok = proof_status == "confirmed"
    checklist.append({"label": "Proof captured (confirmed)", "present": proof_ok})
    if not proof_ok:
        warnings.append(
            f"Proof status is '{proof_status}', not 'confirmed' — capture the observed-vs-control "
            "differential (run with --active) before submitting to a live program."
        )
    if not str(package.get("cvss_vector") or "").strip():
        warnings.append("No CVSS vector — most programs accept the report without one, but it speeds triage.")

    return {
        "ok": True,
        "platform": platform,
        "platform_name": report_formats.platform_name(platform),
        "ready": not missing and proof_ok,
        "missing": missing,
        "warnings": warnings,
        "checklist": checklist,
    }


def write_submission_package(ctx: dict[str, Any], finding: dict[str, Any], out_dir: Path, stem: str,
                             platform: str = "hackerone") -> dict[str, Any] | None:
    """Write a finding's submission .md + .json to out_dir. Returns the package
    (with paths) or None if the finding isn't reportable / write failed."""
    # Preflight reportability before touching disk. Screenshot paths are normalized below
    # only for the on-disk package; the caller's finding remains unchanged.
    if build_submission(ctx, finding, platform) is None:
        return None
    package_finding = dict(finding)
    raw_shots = finding.get("screenshot_paths")
    if not isinstance(raw_shots, list) or not raw_shots:
        single = str(finding.get("screenshot_path") or "").strip()
        raw_shots = [single] if single else []

    # Copy every referenced screenshot and give basename collisions a deterministic,
    # package-specific name. The report is rendered only from successful copies, which
    # prevents stale/broken image links and prevents one finding's proof from silently
    # replacing another finding's screenshot in a shared submissions folder.
    copied_shots: list[str] = []
    newly_created: list[Path] = []
    seen_sources: set[Path] = set()
    if raw_shots:
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        for index, shot in enumerate(raw_shots, 1):
            src = Path(str(shot or "").strip())
            try:
                resolved_src = src.resolve()
                if not src.is_file() or resolved_src in seen_sources:
                    continue
                seen_sources.add(resolved_src)
                dest = out_dir / src.name
                if dest.exists() and resolved_src != dest.resolve():
                    suffix = src.suffix or ".png"
                    dest = out_dir / f"{stem}-proof-{index:02d}{suffix}"
                    serial = 2
                    while dest.exists() and resolved_src != dest.resolve():
                        dest = out_dir / f"{stem}-proof-{index:02d}-{serial}{suffix}"
                        serial += 1
                if resolved_src != dest.resolve():
                    shutil.copyfile(src, dest)
                    newly_created.append(dest)
                copied_shots.append(str(dest))
            except OSError:
                continue

    package_finding.pop("screenshot_path", None)
    package_finding.pop("screenshot_paths", None)
    if copied_shots:
        package_finding["screenshot_path"] = copied_shots[0]
        package_finding["screenshot_paths"] = copied_shots
    package = build_submission(ctx, package_finding, platform)
    if package is None:  # defensive: the screenshot-only rewrite cannot change reportability
        for path in newly_created:
            try:
                path.unlink()
            except OSError:
                pass
        return None
    md_path = out_dir / f"{stem}.md"
    json_path = out_dir / f"{stem}.json"
    try:
        fsutil.write_text_safe(md_path, package["vulnerability_information"])
        fsutil.write_text_safe(json_path, json.dumps(package, indent=2, default=str))
    except OSError:
        for path in newly_created:
            try:
                path.unlink()
            except OSError:
                pass
        return None
    # Co-locate the graphical attack-plan map with the report. Screenshots were already
    # copied and collision-safe-normalized above before rendering the package.
    for artifact in (finding.get("attack_map_path"),):
        p = str(artifact or "").strip()
        if not p:
            continue
        src = Path(p)
        try:
            if src.is_file() and src.resolve() != (out_dir / src.name).resolve():
                shutil.copyfile(src, out_dir / src.name)
        except OSError:
            pass
    return {**package, "markdown_path": str(md_path), "json_path": str(json_path),
            "screenshot_paths": copied_shots}


class SubmissionError(RuntimeError):
    """A HackerOne submit could not proceed (gate failed or API error)."""


_H1_API = "https://api.hackerone.com/v1"
# Cap each uploaded attachment so a stray large artifact can't stall a submit; the
# evidence bundle stays available locally regardless of what uploads.
_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
_MAX_ATTACHMENTS = 12


def _basic_auth(api_username: str, api_token: str) -> str:
    return "Basic " + base64.b64encode(f"{api_username}:{api_token}".encode()).decode()


def _multipart_encode(field_name: str, filename: str, data: bytes, content_type: str) -> tuple[bytes, str]:
    """Build a minimal RFC 2388 multipart/form-data body (stdlib only). Returns
    (body_bytes, content_type_header)."""
    boundary = "----GreyIQ" + uuid.uuid4().hex
    disp = f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f"{disp}\r\n".encode(),
        f"Content-Type: {content_type}\r\n\r\n".encode(),
        data,
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    return body, f"multipart/form-data; boundary={boundary}"


def upload_hackerone_attachments(
    report_id: str,
    attachments: list[str | Path],
    *,
    api_username: str,
    api_token: str,
    timeout: float = 60.0,
    _urlopen: Any = None,
) -> dict[str, Any]:
    """Best-effort upload of evidence files to a just-created HackerOne report.

    Never raises and never blocks the submit: a filed report must stand even if an
    attachment upload fails (the operator still has the complete local evidence bundle).
    Returns ``{"uploaded": [names], "failed": [{"name", "error"}]}``. Each file is posted
    as multipart/form-data to ``/reports/{id}/attachments``; oversized/unreadable files are
    skipped. Bounded to _MAX_ATTACHMENTS so a big engagement can't fan out unbounded POSTs.
    """
    urlopen = _urlopen or urllib.request.urlopen
    uploaded: list[str] = []
    failed: list[dict[str, str]] = []
    if not report_id:
        return {"uploaded": uploaded, "failed": failed}
    seen: set[str] = set()
    for spec in attachments or []:
        if len(uploaded) + len(failed) >= _MAX_ATTACHMENTS:
            break
        path = Path(str(spec))
        name = path.name
        if not name or name in seen:
            continue
        seen.add(name)
        try:
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size == 0 or size > _MAX_ATTACHMENT_BYTES:
                failed.append({"name": name, "error": "too large" if size else "empty"})
                continue
            data = path.read_bytes()
        except OSError as exc:
            failed.append({"name": name, "error": str(exc)})
            continue
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        body, ct_header = _multipart_encode("file", name, data, content_type)
        req = urllib.request.Request(
            f"{_H1_API}/reports/{urllib.parse.quote(str(report_id), safe='')}/attachments",
            data=body, method="POST",
            headers={"Authorization": _basic_auth(api_username, api_token),
                     "Content-Type": ct_header, "Accept": "application/json"},
        )
        try:
            with urlopen(req, timeout=timeout) as resp:
                resp.read()
            uploaded.append(name)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "ignore")[:200]
            except Exception:  # noqa: BLE001
                pass
            failed.append({"name": name, "error": f"HTTP {exc.code}: {detail or exc.reason}"})
        except (urllib.error.URLError, OSError, ValueError) as exc:
            failed.append({"name": name, "error": str(exc)})
    return {"uploaded": uploaded, "failed": failed}


def submit_to_hackerone(
    package: dict[str, Any],
    *,
    team_handle: str,
    api_username: str,
    api_token: str,
    confirm: bool,
    weakness_id: int | None = None,
    structured_scope_id: str | None = None,
    attachments: list[str | Path] | None = None,
    timeout: float = 30.0,
    _urlopen: Any = None,
) -> dict[str, Any]:
    """POST one package to the HackerOne API. HARD-GATED: requires an explicit
    confirm, real credentials, a team handle, and a CONFIRMED proof status — this
    must never fire on an unproven lead. Returns the API response summary or raises
    SubmissionError. Network is only touched here.

    V2: the report is *routed* — ``weakness_id`` (matched from the finding's CWE against
    the program's enabled weakness list) and ``structured_scope_id`` (the in-scope asset)
    are added to the payload when known, so the report lands weakness-set and asset-routed
    rather than in the triage backlog. When ``attachments`` are supplied, the captured
    evidence is uploaded to the created report — best-effort, reported under ``attachments``,
    and NEVER able to fail the submit itself.
    """
    if not confirm:
        raise SubmissionError("refused: pass an explicit confirmation to submit to a live program.")
    if package.get("proof_status") != "confirmed":
        raise SubmissionError(
            f"refused: only CONFIRMED findings may be auto-submitted (this one is '{package.get('proof_status')}'). "
            "Run with --active to prove it, or submit manually after capturing the proof."
        )
    if not (team_handle and api_username and api_token):
        raise SubmissionError("refused: team handle + HACKERONE_API_USERNAME + HACKERONE_API_TOKEN are required.")
    urlopen = _urlopen or urllib.request.urlopen
    attributes: dict[str, Any] = {
        "team_handle": team_handle,
        "title": package["title"],
        "vulnerability_information": package["vulnerability_information"],
        "impact": package.get("impact") or "See the report.",
        "severity_rating": package.get("severity_rating", "low"),
    }
    # Only add the routing attributes when they resolved — an unknown weakness/asset must
    # not send a null and risk the create call rejecting an otherwise-valid report.
    if weakness_id is not None:
        try:
            attributes["weakness_id"] = int(weakness_id)
        except (TypeError, ValueError):
            pass
    if structured_scope_id:
        attributes["structured_scope_id"] = str(structured_scope_id)
    payload = {"data": {"type": "report", "attributes": attributes}}
    request = urllib.request.Request(
        f"{_H1_API}/reports",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Authorization": _basic_auth(api_username, api_token),
                 "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore")[:500] if hasattr(exc, "read") else ""
        raise SubmissionError(f"HackerOne API HTTP {exc.code}: {detail or exc.reason}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SubmissionError(f"HackerOne submit failed: {exc}") from exc
    report_id = str(((data.get("data") or {}).get("id")) or "")
    result: dict[str, Any] = {
        "ok": True, "report_id": report_id,
        "url": f"https://hackerone.com/reports/{report_id}" if report_id else "",
        "routed": {"weakness_id": attributes.get("weakness_id"),
                   "structured_scope_id": attributes.get("structured_scope_id")},
    }
    if attachments and report_id:
        result["attachments"] = upload_hackerone_attachments(
            report_id, list(attachments), api_username=api_username, api_token=api_token, _urlopen=urlopen)
    return result
