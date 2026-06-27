"""GreyIQ BugHunter — end-to-end bounty campaign.

One command takes a target through the whole bounty: map the surface (recon),
hunt every discovered URL (scan + optional active proof), consolidate and rank
the findings (sharpened by what the program has rewarded before), and emit a
campaign index plus a submission-ready package per reportable finding. It learns
across runs: confirmed findings are logged so the operator can record outcomes
(`gn learn`) and the NEXT campaign prioritizes what actually pays.

Reuses the per-target engine (``run_bounty_hunt``) verbatim per URL — so every
finding keeps its impact model, proof obligation, CVSS, and (with --active) its
captured proof — then layers discovery, consolidation, submission, and learning
on top. Frozen-safe; the only network is the engine's own guarded scanners.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bughunter import active_verify_service, fsutil, learning, recon, submission
from bughunter.bounty import _infer_kind, _safe_slug, run_bounty_hunt

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _read_json(path: str) -> dict[str, Any]:
    try:
        return json.loads(fsutil.read_text_safe(Path(path)))
    except (OSError, json.JSONDecodeError):
        return {}


def _proof_status(doc: dict[str, Any], ref: str) -> str:
    return str(((doc.get("proof_of_impact") or {}).get(ref) or {}).get("status") or "missing")


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _campaign_risk(consolidated: list[dict[str, Any]]) -> str:
    present = {str(item["finding"].get("severity", "")).lower() for item in consolidated}
    for sev, label in (("critical", "critical"), ("high", "high"), ("medium", "moderate")):
        if sev in present:
            return label
    return "low" if consolidated else "clean"


def run_campaign(
    target: str,
    *,
    scope: str,
    authorized: bool,
    coder_cfg: dict[str, Any] | None,
    default_reports_dir: Path,
    seed_dir: Path | None = None,
    runtime_dir: Path | None = None,
    version: str = "",
    active: bool = False,
    live: bool = False,
    program: str | None = None,
    max_pages: int = 12,
    on_progress: Any = None,
) -> dict[str, Any]:
    """Run a full campaign. Returns {ok, campaign_path, json_path, urls_scanned,
    finding_count, confirmed_count, submission_paths, ...} or {ok: False, error}."""
    clean_target = str(target or "").strip()
    if not clean_target:
        return {"ok": False, "error": "No target provided."}
    if not authorized:
        return {"ok": False, "error": "Confirm you're authorized and in scope before running a campaign."}
    kind = _infer_kind(clean_target)
    if kind == "unknown":
        return {"ok": False, "error": "Could not tell if the target is a URL or a repo/path."}

    rt = runtime_dir
    priors = learning.learned_priors(rt, program, clean_target) if rt is not None else {}
    intel = learning.program_intelligence(rt, program, clean_target) if rt is not None else []
    prog_key = learning.program_key(program, clean_target)

    def _emit(msg: str) -> None:
        if callable(on_progress):
            try:
                on_progress(msg)
            except Exception:  # noqa: BLE001
                pass

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out_root = Path(default_reports_dir) / f"campaign-{_safe_slug(prog_key)}-{stamp}"
    out_root.mkdir(parents=True, exist_ok=True)

    # --- Surface mapping (URL targets) → the list of targets to hunt. ---
    if kind == "url":
        _emit("recon: mapping the surface…")
        rec = recon.discover(clean_target, max_pages=max_pages)
        urls = rec.get("urls") or [clean_target]
        recon_notes = rec.get("notes") or []
        recon_sources = rec.get("sources") or {}
    else:
        urls = [clean_target]
        recon_notes, recon_sources = [], {}

    # --- Hunt each target with the full engine. ---
    per_target: list[dict[str, Any]] = []
    consolidated: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for index, url in enumerate(urls, 1):
        _emit(f"hunt {index}/{len(urls)}: {url}")
        profile = "source-code" if kind in {"path", "git"} else "web-app"
        result = run_bounty_hunt(
            url, profile, None, str(out_root / "targets"), scope, True, coder_cfg,
            default_reports_dir=out_root / "targets", seed_dir=seed_dir, runtime_dir=runtime_dir,
            version=version, run_live=live, active=active, per_finding=False,
        )
        per_target.append({"target": url, "ok": result.get("ok", False),
                           "report_path": result.get("report_path", ""), "error": result.get("error", "")})
        if not result.get("ok"):
            continue
        doc = _read_json(result.get("json_path", ""))
        for finding in doc.get("findings") or []:
            # Dedup across targets by class + rule + normalized location.
            norm_loc = re.sub(r"\d+", "N", str(finding.get("location") or ""))
            key = f"{finding.get('class_id')}|{finding.get('rule_id')}|{norm_loc}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            ref = str(finding.get("ref") or "")
            consolidated.append({
                "finding": finding,
                "source_url": url,
                "source_report": result.get("report_path", ""),
                "source_json": result.get("json_path", ""),
                "proof_status": _proof_status(doc, ref),
                "cvss": (doc.get("cvss") or {}).get(ref) or {},
            })

    # --- Rank: severity, then learned program priors, then CVSS, then proof. ---
    def _rank(item: dict[str, Any]) -> tuple:
        finding = item["finding"]
        sev = _SEV_RANK.get(str(finding.get("severity")).lower(), 0)
        prior = priors.get(str(finding.get("class_id") or ""), 1.0)
        confirmed = 1 if item["proof_status"] == "confirmed" else 0
        score = float(item["cvss"].get("base_score") or 0.0)
        return (confirmed, sev * prior, score, sev)

    consolidated.sort(key=_rank, reverse=True)
    confirmed = [c for c in consolidated if c["proof_status"] == "confirmed"]

    # --- Submission packages (reportable findings; confirmed first). ---
    submission_paths: list[str] = []
    sub_dir = out_root / "submissions"
    for rank_i, item in enumerate(consolidated, 1):
        doc = _read_json(item["source_json"])
        ctx = _ctx_from_doc(doc)
        finding = item["finding"]
        stem = f"sub-{rank_i:02d}-{_safe_slug(finding.get('class_id', 'finding'))}-{_safe_slug(finding.get('title', ''), 'finding')}"
        package = submission.write_submission_package(ctx, finding, sub_dir, stem)
        if package:
            item["submission_path"] = package["markdown_path"]
            submission_paths.append(package["markdown_path"])
            # Log confirmed findings to the learning store so outcomes can be recorded.
            if rt is not None and item["proof_status"] == "confirmed":
                learning.record_outcome(
                    rt, program=program, target=clean_target, class_id=str(finding.get("class_id") or "other"),
                    title=str(finding.get("title") or ""), status="submitted", severity=str(finding.get("severity") or ""),
                )

    # --- Campaign index report + JSON. ---
    ctx_meta = {
        "target": clean_target, "program": prog_key, "kind": kind, "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "version": version, "active": active, "scope": scope, "urls": urls, "recon_notes": recon_notes,
        "recon_sources": recon_sources, "intel": intel, "consolidated": consolidated, "confirmed": confirmed,
        "per_target": per_target, "submission_count": len(submission_paths),
    }
    md = _render_campaign_markdown(ctx_meta)
    campaign_path = out_root / "CAMPAIGN.md"
    json_path = out_root / "campaign.json"
    fsutil.write_text_safe(campaign_path, md)
    fsutil.write_text_safe(json_path, json.dumps(_render_campaign_json(ctx_meta), indent=2, default=str))
    _emit("done")

    # Compact structured findings so a GUI can render one board for campaigns just
    # like single hunts. Refs are reassigned campaign-globally (C1, C2…) so the
    # per-target F1/F2 don't collide across targets.
    findings_out: list[dict[str, Any]] = []
    proof_out: dict[str, Any] = {}
    cvss_out: dict[str, Any] = {}
    plans_out: dict[str, Any] = {}
    for index, item in enumerate(consolidated, 1):
        finding = dict(item["finding"])
        ref = f"C{index}"
        finding["ref"] = ref
        finding["source_url"] = item["source_url"]
        finding["proof_status"] = item["proof_status"]
        findings_out.append(finding)
        proof_out[ref] = {"status": item["proof_status"]}
        if item.get("cvss"):
            cvss_out[ref] = item["cvss"]
        plan = (_read_json(item["source_json"]).get("attack_plans") or {}).get(item["finding"].get("ref"))
        if isinstance(plan, dict):
            plans_out[ref] = plan

    return {
        "ok": True,
        "campaign_path": str(campaign_path),
        "json_path": str(json_path),
        "output_dir": str(out_root),
        "program": prog_key,
        "kind": kind,
        "urls_scanned": len([t for t in per_target if t["ok"]]),
        "urls_discovered": len(urls),
        "finding_count": len(consolidated),
        "confirmed_count": len(confirmed),
        "submission_paths": submission_paths,
        "report_markdown": md,
        # Structured payload for the cockpit (mirrors /api/bounty/scan).
        "findings": findings_out,
        "proof_of_impact": proof_out,
        "cvss": cvss_out,
        "attack_plans": plans_out,
        "surface": {"urls": urls, "sources": recon_sources, "notes": recon_notes},
        "severity_counts": _severity_counts([item["finding"] for item in consolidated]),
        "risk": _campaign_risk(consolidated),
    }


def _ctx_from_doc(doc: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the minimal report context a single finding's submission needs
    from a per-target JSON sidecar."""
    return {
        "tool": doc.get("tool", "GreyIQ BugHunter"), "version": doc.get("version", ""),
        "generated_at": doc.get("generated_at", ""), "target": doc.get("target", ""),
        "scope": doc.get("scope", ""), "attack_plans": doc.get("attack_plans", {}),
    }


def _render_campaign_markdown(ctx: dict[str, Any]) -> str:
    out: list[str] = []
    consolidated, confirmed = ctx["consolidated"], ctx["confirmed"]
    out.append(f"# Bounty Campaign — {ctx['program']}\n")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| **Target** | `{ctx['target']}` |")
    out.append(f"| **Surface scanned** | {len([t for t in ctx['per_target'] if t['ok']])} target(s) ({ctx['kind']}) |")
    out.append(f"| **Findings** | {len(consolidated)} consolidated · **{len(confirmed)} actively confirmed** |")
    out.append(f"| **Active proof** | {'on' if ctx['active'] else 'off (re-run with --active to prove)'} |")
    out.append(f"| **Submission packages** | {ctx['submission_count']} |")
    out.append(f"| **Generated** | {ctx['generated_at']} · GreyIQ v{ctx['version']} |")
    out.append("")

    out.append("## Authorization & scope\n")
    out.append("> Authorized testing only. " + (ctx.get("scope") or "(scope not provided)"))
    out.append("")

    if ctx.get("intel"):
        out.append("## Program intelligence (learned from past outcomes)\n")
        for note in ctx["intel"]:
            out.append(f"- {note}")
        out.append("")

    out.append("## Surface mapped\n")
    out.append(f"- Recon found **{len(ctx['urls'])}** in-scope URL(s)" + (
        f" (sources: {', '.join(f'{k}: {v}' for k, v in (ctx['recon_sources'] or {}).items())})" if ctx.get("recon_sources") else "") + ".")
    for note in ctx.get("recon_notes") or []:
        out.append(f"- {note}")
    out.append("")

    out.append("## Findings (ranked)\n")
    if not consolidated:
        out.append("No findings surfaced across the mapped surface at this depth. See the per-target reports + the manual checklists.")
    else:
        out.append("| # | Sev | Class | Proof | Finding | Where |")
        out.append("|---|---|---|---|---|---|")
        for i, item in enumerate(consolidated[:40], 1):
            f = item["finding"]
            proof = "✅ confirmed" if item["proof_status"] == "confirmed" else item["proof_status"]
            out.append(
                f"| {i} | {str(f.get('severity', '?')).title()} | {f.get('class_name') or f.get('class_id') or ''} "
                f"| {proof} | {str(f.get('title', '')).replace('|', '/')} | `{item['source_url']}` |"
            )
        if len(consolidated) > 40:
            out.append(f"\n_(+{len(consolidated) - 40} more — see campaign.json)_")
    out.append("")

    if confirmed:
        out.append("## Ready to submit (confirmed)\n")
        out.append("These carry a captured proof artifact and a submission package under `submissions/`:")
        out.append("")
        for item in confirmed:
            f = item["finding"]
            path = item.get("submission_path", "")
            out.append(f"- **{f.get('title', '')}** ({str(f.get('severity', '')).title()}) — `{item['source_url']}`" + (f"  → `{Path(path).name}`" if path else ""))
        out.append("")
        out.append("Submit each from its package (paste the `.md`), or `gn submit` to export/file. After the program "
                   "responds, record the outcome with `gn learn` so the next campaign prioritizes what pays.")
    else:
        out.append("## Next\n")
        out.append("No findings are auto-confirmed yet. Re-run with active proof on (`--active`, in scope), then submit the "
                   "confirmed ones and `gn learn` their outcomes to sharpen the next run.")
    out.append("")

    out.append("## Per-target reports\n")
    for t in ctx["per_target"]:
        status = t["report_path"] if t["ok"] else f"FAILED — {t['error']}"
        out.append(f"- `{t['target']}` → {status}")
    out.append("")
    out.append("---")
    out.append(f"_GreyIQ BugHunter campaign v{ctx['version']}. Findings are leads until a captured proof confirms them; "
               f"submit only within your authorized scope._")
    return "\n".join(out)


def _render_campaign_json(ctx: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "GreyIQ BugHunter", "version": ctx["version"], "generated_at": ctx["generated_at"],
        "target": ctx["target"], "program": ctx["program"], "kind": ctx["kind"], "active": ctx["active"],
        "urls": ctx["urls"], "recon_sources": ctx["recon_sources"], "program_intelligence": ctx["intel"],
        "finding_count": len(ctx["consolidated"]), "confirmed_count": len(ctx["confirmed"]),
        "findings": [
            {
                "rank": i, "source_url": item["source_url"], "proof_status": item["proof_status"],
                "cvss": item["cvss"], "submission": item.get("submission_path", ""), **item["finding"],
            }
            for i, item in enumerate(ctx["consolidated"], 1)
        ],
        "per_target": ctx["per_target"], "submission_count": ctx["submission_count"],
    }
