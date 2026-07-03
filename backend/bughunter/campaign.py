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

import concurrent.futures
import dataclasses
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bughunter import (
    active_verify_service,
    cve_service,
    fsutil,
    hunt_brain,
    ledger,
    learning,
    progress,
    ranking,
    recon,
    research,
    screenshot_service,
    submission,
)
from bughunter.bounty import _classify, _infer_kind, _safe_slug, run_bounty_hunt
from bughunter.registrable_domain import registrable_domain
from bughunter.settings import get_settings
from bughunter.target_ingest import _normalize_one

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_MAX_PROGRAM_TARGETS = 25  # a "span the whole program" campaign is N full campaigns -- bound it
# Each target's own run_campaign() call is almost entirely network-I/O-bound (rate-
# governor sleeps, real HTTP round trips) -- a bounded pool of concurrent targets cuts
# real wall-clock time for a multi-target span without changing run_campaign()'s own
# internals at all. Kept modest (not e.g. 25 == every target at once) so a program
# with several targets sharing one apex/host doesn't multiply the effective request
# rate that host sees beyond what its own HostRateGovernor was tuned for.
_SPAN_MAX_WORKERS = 4


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


def _capture_proof_screenshots(items: list[dict[str, Any]], shot_dir: Path, target: str, scope: Any) -> int:
    """Capture a scope-gated proof screenshot for each confirmed finding and record its path on the
    finding (+ the plain-text request/response proof if any). Bounded by the caller, best-effort:
    every step is wrapped so a missing Playwright / a capture error is a clean no-op, never a break.
    Returns the number of screenshots captured. Reused for BOTH the every-confirmed pass and deep."""
    captured = 0
    for index, item in enumerate(items, 1):
        finding = item["finding"]
        stem = f"{index:02d}-{_safe_slug(str(finding.get('ref') or 'finding'))}"
        ictx = {"target": item.get("source_url") or target, "scope": scope, "attack_plans": {}}
        try:
            poc = screenshot_service.poc_url_for_finding(finding, ictx)
            if not poc:
                continue
            shot = screenshot_service.capture_screenshot(poc, shot_dir / f"{stem}.png", scope=scope, authorized=True)
        except Exception:  # noqa: BLE001 - proof screenshot is enrichment; never break the campaign
            continue
        if shot.get("ok"):
            finding["screenshot_path"] = shot["path"]
            if shot.get("source_text_path"):  # plain-text request/response/source proof
                finding["source_text_path"] = shot["source_text_path"]
            captured += 1
    return captured


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
    time_based: bool = False,
    auth: dict[str, Any] | None = None,
    live: bool = False,
    program: str | None = None,
    max_pages: int = 12,
    platform: str = "hackerone",
    deep: bool = False,
    on_progress: Any = None,
    disclose_automation: bool = False,
    excluded_hosts: tuple[str, ...] = (),
    progress_run_id: str | None = None,
    progress_unit: str | None = None,
) -> dict[str, Any]:
    """Run a full campaign. Returns {ok, campaign_path, json_path, urls_scanned,
    finding_count, confirmed_count, submission_paths, ...} or {ok: False, error}.

    Live dashboard streaming (via the ``progress`` module) when ``progress_run_id`` is set:
    - ``progress_unit is None`` (a top-level single-target campaign): the discovered URLs
      ARE the dashboard's work units — each is registered, its status tracked, and its
      findings attributed to it.
    - ``progress_unit`` set (a per-target run inside a program span): the URLs are NOT their
      own units (the span already registered the NAMED targets); findings are streamed AS
      EACH URL FINISHES and attributed to ``progress_unit`` (the named target) — so a big
      multi-URL target's findings appear live instead of only when the whole target ends."""
    clean_target = str(target or "").strip()
    if not clean_target:
        return {"ok": False, "error": "No target provided."}
    if not authorized:
        return {"ok": False, "error": "Confirm you're authorized and in scope before running a campaign."}
    kind = _infer_kind(clean_target)
    if kind == "unknown":
        return {"ok": False, "error": "Could not tell if the target is a URL or a repo/path."}
    # A saved program's out_of_scope_hosts (when the caller resolved one) rides on the
    # settings object every scope check downstream already takes, so recon's discovery
    # gate and run_bounty_hunt's own active-verification pass both honor it without
    # each needing their own separate exclusion parameter.
    campaign_settings = dataclasses.replace(get_settings(), excluded_hosts=tuple(excluded_hosts or ()))

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
    # A short hash of the FULL (untruncated) target, not just its slug, so two targets
    # whose _safe_slug output shares a long common prefix (e.g. similarly-pathed local
    # source folders, or a "span this program's whole scope" run hunting several targets
    # inside the same second) can never collide onto the same output folder and silently
    # clobber each other's on-disk artifacts.
    target_fp = hashlib.sha1(clean_target.encode("utf-8", "replace")).hexdigest()[:8]
    out_root = Path(default_reports_dir) / f"campaign-{_safe_slug(prog_key)}-{stamp}-{target_fp}"
    out_root.mkdir(parents=True, exist_ok=True)

    # --- Surface mapping (URL targets) → the list of targets to hunt. ---
    rec_js_secrets: list[dict[str, Any]] = []
    recon_tech: list[str] = []
    recon_params: list[str] = []
    recon_api_findings: list[dict[str, Any]] = []
    # Per-endpoint vuln-class priorities from the reasoning layer — {url: [classes]} — used to steer
    # each URL's active pass toward the classes most likely to hit there (empty = default order).
    hunt_priority: dict[str, list[str]] = {}
    if kind == "url":
        _emit("recon: mapping the surface…")
        # Bind discovery to the SAME fail-closed scope gate the active prover uses, so
        # in-scope cross-host expansion (a wildcard program) is followed and ONLY
        # in-scope hosts are ever fetched -- excluded_hosts rides on campaign_settings.
        scope_gate = (lambda h: active_verify_service.host_in_active_scope(h, scope, campaign_settings)) if str(scope or "").strip() else None
        rec = recon.discover(clean_target, max_pages=max_pages, scope_in=scope_gate)
        urls = rec.get("urls") or [clean_target]
        recon_notes = rec.get("notes") or []
        recon_sources = rec.get("sources") or {}
        rec_js_secrets = rec.get("js_secrets") or []
        recon_tech = rec.get("tech") or []
        # Parameter names recon mined from the target's own JS/HTML. Fed to every
        # per-URL active pass so a discovered endpoint that carries no query string of
        # its own still gets its real parameters probed (XSS/SQLi/redirect/SSTI/CRLF).
        recon_params = rec.get("params") or []
        # GraphQL-introspection (and future API-discovery) candidates, each with an inline plan.
        recon_api_findings = rec.get("api_findings") or []
        recon_forms = rec.get("forms") or []
        # Tech fingerprint hints are {class_id: reason} — host-global vuln classes the observed stack
        # implies (Flask/Django/Next -> ssti; PHP/WordPress/ASP.NET -> rce; Angular -> xss; GraphQL ->
        # graphql). Their class_ids steer the active check order alongside the brain's per-endpoint picks.
        hint_classes = [c for c in (rec.get("hints") or {}).keys() if c]

        # Reasoning layer: let the configured brain read the mapped surface and propose
        # target-specific parameter NAMES the heuristics miss (e.g. returnUrl/callback on a login,
        # tpl on a renderer, file/path on a download). These are unioned into recon_params and thus
        # flow to every per-URL active pass's benign differential checks — so an LLM hypothesis is
        # only ever REPORTED if the deterministic prover independently confirms it (recall up,
        # precision unchanged). Best-effort + fail-closed: no brain / any error keeps current behaviour.
        try:
            hb = hunt_brain.plan_hunt(coder_cfg, clean_target, scope,
                                      {"endpoints": urls, "params": recon_params, "tech": recon_tech, "forms": recon_forms})
            new_params = [p for p in (hb.get("param_hypotheses") or [])
                          if p.lower() not in {q.lower() for q in recon_params}]
            if new_params:
                recon_params = list(recon_params) + new_params
                _emit(f"hunt-brain: +{len(new_params)} target-specific param hypothesis(es) to probe "
                      f"via the differential checks ({hb.get('provider') or 'brain'})")
            # Per-endpoint class priorities steer each URL's active pass (the endpoints are already
            # verbatim from `urls`, so they map straight onto the per-URL run below).
            for row in (hb.get("probe_priority") or []):
                ep, classes = row.get("endpoint"), row.get("classes") or []
                if ep and classes:
                    hunt_priority[ep] = classes
            if hunt_priority:
                _emit(f"hunt-brain: prioritised probe classes on {len(hunt_priority)} endpoint(s)")
        except Exception:  # noqa: BLE001 - the reasoning layer must never break a hunt
            pass
        # Merge the host-global tech-fingerprint hints into EVERY url's priority: the brain's
        # per-endpoint classes come first (most specific), then the stack-implied hint classes,
        # de-duped. URLs the brain didn't flag still get steered by the fingerprint alone. Pure
        # reordering downstream (_apply_class_priority never creates a finding) — zero FP risk.
        if hint_classes:
            for u in urls:
                hunt_priority[u] = list(dict.fromkeys((hunt_priority.get(u) or []) + hint_classes))
    else:
        urls = [clean_target]
        recon_notes, recon_sources = [], {}

    # --- Hunt each target with the full engine. ---
    # `deep` and `time_based` BOTH trigger the (already-gated, scope-bound) active pass in
    # run_bounty_hunt (it runs on `active or time_based`, and deep forces time_based on), so
    # the honest "did active probing run" flag is their union. Use it for the per-target run
    # AND the campaign report so the report can never claim "active: off" while an executing
    # probe (e.g. the deep-mode time-based SLEEP) actually fired.
    effective_active = bool(active or time_based or deep)
    per_target: list[dict[str, Any]] = []
    consolidated: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    # Register the discovered URLs as the dashboard's work units — but ONLY for a top-level
    # single-target campaign. In a program span the NAMED targets are the units (already
    # registered by the span); here we just stream that target's findings as URLs finish.
    if progress_unit is None:
        progress.set_targets(progress_run_id, urls)
    for index, url in enumerate(urls, 1):
        # Cooperative cancellation: the operator's Stop halts BETWEEN url hunts (a hunt
        # in flight finishes its current url, then we bail with whatever's been found).
        if progress.is_stopped(progress_run_id):
            _emit("stop requested — halting this target after the current URL")
            break
        _emit(f"hunt {index}/{len(urls)}: {url}")
        if progress_unit is None:
            progress.mark_target(progress_run_id, url, "running")
        profile = "source-code" if kind in {"path", "git"} else "web-app"
        result = run_bounty_hunt(
            url, profile, None, str(out_root / "targets"), scope, True, coder_cfg,
            default_reports_dir=out_root / "targets", seed_dir=seed_dir, runtime_dir=runtime_dir,
            version=version, run_live=live, active=effective_active, time_based=(time_based or deep), auth=auth, per_finding=False,
            extra_params=recon_params, on_progress=_emit, settings=campaign_settings, class_priority=hunt_priority.get(url),
        )
        per_target.append({"target": url, "ok": result.get("ok", False),
                           "report_path": result.get("report_path", ""), "error": result.get("error", "")})
        if not result.get("ok"):
            if progress_unit is None:
                progress.mark_target(progress_run_id, url, "error", error=str(result.get("error") or ""))
            continue
        doc = _read_json(result.get("json_path", ""))
        url_new: list[dict[str, Any]] = []  # findings first-seen at THIS url, for the live dashboard
        for finding in doc.get("findings") or []:
            # Dedup across targets by class + rule + normalized location.
            norm_loc = re.sub(r"\d+", "N", str(finding.get("location") or ""))
            key = f"{finding.get('class_id')}|{finding.get('rule_id')}|{norm_loc}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            ref = str(finding.get("ref") or "")
            proof_status = _proof_status(doc, ref)
            consolidated.append({
                "finding": finding,
                "source_url": url,
                "source_report": result.get("report_path", ""),
                "source_json": result.get("json_path", ""),
                "proof_status": proof_status,
                "cvss": (doc.get("cvss") or {}).get(ref) or {},
            })
            url_new.append({"ref": ref, "title": finding.get("title"), "severity": finding.get("severity"),
                            "class_name": finding.get("class_name") or finding.get("class_id"), "proof_status": proof_status,
                            # Carried for the dashboard's investigate drawer + on-demand re-verify/report:
                            # where the finding lives (the URL), its CWE, rule id, and the canonical
                            # class_id (so an on-demand report gets class-specific reproduction steps).
                            "location": finding.get("location") or url, "cwe": finding.get("cwe"),
                            "rule_id": finding.get("rule_id"), "class_id": finding.get("class_id")})
        # Stream this URL's findings live — attributed to the span's named target when
        # running under one, else to the URL itself (single-target campaign).
        progress.add_findings(progress_run_id, progress_unit or url, url_new)
        if progress_unit is None:
            progress.mark_target(progress_run_id, url, "done")

    # --- Secrets mined from served JS (recon-sourced) — classify + dedup + add. ---
    for index, secret in enumerate(rec_js_secrets, 1):
        cid, cname, cwe, owasp = _classify(secret)
        finding = {**secret, "ref": f"JS{index}", "class_id": cid, "class_name": cname, "cwe": cwe, "owasp": owasp,
                   "location": secret.get("file_path") or clean_target}
        norm_loc = re.sub(r"\d+", "N", str(finding.get("location") or ""))
        key = f"{cid}|{finding.get('rule_id')}|{norm_loc}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        consolidated.append({"finding": finding, "source_url": finding["location"], "source_report": "",
                             "source_json": "", "proof_status": "candidate", "cvss": {}})

    # --- API-discovery candidates (GraphQL introspection): each carries its own inline plan. ---
    for finding in recon_api_findings:
        norm_loc = re.sub(r"\d+", "N", str(finding.get("location") or ""))
        key = f"{finding.get('class_id')}|{finding.get('rule_id')}|{norm_loc}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        plan = finding.pop("_plan", None) or {}
        consolidated.append({
            "finding": finding, "source_url": finding.get("location") or clean_target,
            "source_report": "", "source_json": "", "proof_status": "candidate",
            "cvss": plan.get("cvss") or {}, "plan": plan,
        })

    # --- Known-CVE / outdated-component pass (passive, candidate-grade). One scope-bound,
    # SSRF-guarded GET of the target fingerprints its front-end libraries and folds each
    # outdated component with known CVEs in as a CANDIDATE (never confirmed — exploitability
    # is unproven), carrying its own attack plan. Best-effort: never breaks the campaign. The
    # scope defaults to the target's own host when the campaign was run without an explicit
    # scope, matching recon's "fetch the thing you pointed at" behaviour. ---
    if kind == "url":
        cve_scope = str(scope or "").strip() or cve_service._target_host(clean_target)
        try:
            _emit("cve: fingerprinting front-end components…")
            cve_res = cve_service.scan_known_cves(clean_target, scope=cve_scope)
            for c_index, finding in enumerate(cve_res.get("findings") or [], 1):
                # Dedup by product (one finding per outdated library, whichever page served it).
                key = f"cve|{finding.get('_cve_product')}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                finding["ref"] = f"CVE{c_index}"
                plan = cve_service.build_plan(finding)
                consolidated.append({
                    "finding": finding, "source_url": finding.get("location") or clean_target,
                    "source_report": "", "source_json": "", "proof_status": "candidate",
                    "cvss": plan.get("cvss") or {}, "plan": plan,
                })
        except Exception:  # noqa: BLE001 - the CVE pass is enrichment; never break the campaign
            pass

    # --- Drop operator-deleted findings before ranking/submission. The per-URL engine
    # already filtered its own hunts; this pass also covers the synthetic leads added
    # above (JS secrets, known-CVE, API-discovery), which never went through it — so a
    # deleted finding of any origin stays gone. Same stable dedup key: the delete sticks. ---
    if rt is not None:
        _dismissed = ledger.dismissed_keys(rt)
        if _dismissed:
            consolidated = [c for c in consolidated if ledger.dedup_key(c["finding"]) not in _dismissed]

    # --- Rank by EXPECTED VALUE (confirmed outermost, then EV, severity, CVSS) so the
    # most-likely-to-pay findings sort first. ---
    program_stats = (learning.program_summary(rt, program, clean_target).get("class_stats") if rt is not None else {}) or {}
    ranking.rank_by_ev(consolidated, priors, program_stats)
    confirmed = [c for c in consolidated if c["proof_status"] == "confirmed"]

    # --- Proof screenshot for EVERY actively-confirmed finding (not just deep mode): a visual PoC
    # of the vulnerable behaviour lands in the campaign folder and the finding's submission package,
    # which measurably speeds/raises triage acceptance. Scope-gated, degrades cleanly without
    # Playwright, bounded to 8 so a big campaign can't launch unbounded browsers.
    if effective_active and confirmed:
        n = _capture_proof_screenshots(confirmed[:8], out_root / "screenshots", clean_target, scope)
        if n:
            _emit(f"captured {n} proof screenshot(s) for confirmed finding(s).")

    # --- DEEP mode ALSO writes a brain-researched dossier per confirmed lead (the expensive part,
    # deterministic offline fallback). The screenshot above already ran for these findings. ---
    if deep and confirmed:
        _emit(f"deep: researching {min(len(confirmed), 8)} confirmed lead(s)…")
        research_dir = out_root / "research"
        for index, item in enumerate(confirmed[:8], 1):
            finding = item["finding"]
            stem = f"{index:02d}-{_safe_slug(str(finding.get('ref') or 'finding'))}"
            ictx = {"target": item.get("source_url") or clean_target, "scope": scope, "attack_plans": {}}
            try:
                dossier = research.build_dossier(finding, ictx, coder_cfg)
                rpath = research_dir / f"{stem}.md"
                fsutil.write_text_safe(rpath, dossier["markdown"])
                finding["research_path"] = str(rpath)
            except Exception:  # noqa: BLE001 - enrichment is best-effort; never break the campaign
                pass

    # --- Cross-run dedup: record every finding in the persistent ledger and learn
    # which were ALREADY reported in a prior run (so a re-run never re-files them). ---
    if rt is not None:
        ledger.upsert_findings(rt, program, clean_target, consolidated)

    # --- Submission packages (reportable findings; confirmed first; never re-package a
    # finding already reported in a prior run). ---
    submission_paths: list[str] = []
    sub_dir = out_root / "submissions"
    for rank_i, item in enumerate(consolidated, 1):
        if item.get("duplicate_of_prior"):
            continue  # already reported in a previous run — don't re-emit a package
        finding = item["finding"]
        if item.get("plan") is not None:
            # Synthetic finding (e.g. known-CVE) carries its plan inline — build the minimal
            # ctx its submission needs instead of reading a per-target JSON sidecar it has none.
            ctx = {"tool": "GreyIQ BugHunter", "version": version,
                   "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                   "target": item.get("source_url") or clean_target, "scope": scope,
                   "attack_plans": {str(finding.get("ref") or ""): item["plan"]},
                   "disclose_automation": disclose_automation}
        else:
            ctx = _ctx_from_doc(_read_json(item["source_json"]))
            ctx["disclose_automation"] = disclose_automation
        stem = f"sub-{rank_i:02d}-{_safe_slug(finding.get('class_id', 'finding'))}-{_safe_slug(finding.get('title', ''), 'finding')}"
        package = submission.write_submission_package(ctx, finding, sub_dir, stem, platform)
        if package:
            item["submission_path"] = package["markdown_path"]
            submission_paths.append(package["markdown_path"])
            if rt is not None:
                ledger.mark_reported(rt, program, clean_target, finding)
            # Log confirmed findings to the learning store so outcomes can be recorded.
            if rt is not None and item["proof_status"] == "confirmed":
                learning.record_outcome(
                    rt, program=program, target=clean_target, class_id=str(finding.get("class_id") or "other"),
                    title=str(finding.get("title") or ""), status="submitted", severity=str(finding.get("severity") or ""),
                )

    # --- Campaign index report + JSON. ---
    ctx_meta = {
        "target": clean_target, "program": prog_key, "kind": kind, "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "version": version, "active": effective_active, "scope": scope, "urls": urls, "recon_notes": recon_notes,
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
        finding["ev"] = item.get("ev")  # expected-value rank score for the dashboard
        # Carry the exact stable dedup key so a "delete finding" from the board suppresses THIS
        # finding precisely. The board only has class_id/rule_id/location, which can't
        # reproduce a CVE finding's product-aware key — so the UI sends this back verbatim.
        finding["dedup_key"] = item.get("dedup_key") or ledger.dedup_key(item["finding"])
        findings_out.append(finding)
        proof_out[ref] = {"status": item["proof_status"]}
        if item.get("cvss"):
            cvss_out[ref] = item["cvss"]
        # Synthetic findings (known-CVE) carry their plan inline; per-target findings have it
        # in their JSON sidecar.
        plan = item.get("plan")
        if not isinstance(plan, dict):
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
        "surface": {"urls": urls, "sources": recon_sources, "notes": recon_notes, "tech": recon_tech},
        "severity_counts": _severity_counts([item["finding"] for item in consolidated]),
        "risk": _campaign_risk(consolidated),
    }


def _representative_host(identifier: str) -> str:
    """Best-effort concrete, fetchable URL for a structured-scope identifier — strips a
    leading wildcard (``*.tiktok.com`` -> ``tiktok.com``) so a wildcard scope entry still
    seeds a real crawl from its apex. Non-host identifiers (app-store IDs, free-text
    asset labels like "Other Asset (Campaigns)") fall through ``_normalize_one``'s
    dotted-host requirement and return "" — they aren't web targets, so a "span the
    program's scope" campaign silently skips them as SEEDS (they still gate scope
    normally; they're just never something to point a crawler at)."""
    token = (identifier or "").strip().lstrip("*").lstrip(".")
    return _normalize_one(token)


def _target_host_excluded(candidate: str, excluded_hosts: list[str]) -> bool:
    """True if candidate's host matches (or is a subdomain of) one of excluded_hosts —
    the same exact/dotted-suffix/registrable-domain match host_in_active_scope() uses
    for its own excluded_hosts check, applied here at target-SELECTION time so an
    excluded host can never become the literal target of a hunt in the first place."""
    if not excluded_hosts:
        return False
    raw = str(candidate or "").strip()
    host = (urlparse(raw).hostname if "://" in raw else raw).strip().lower().strip("[]")
    if not host:
        return False
    reg = registrable_domain(host)
    for excluded in excluded_hosts:
        token = str(excluded or "").strip().lower().strip("[]").lstrip("*").lstrip(".")
        if not token:
            continue
        if host == token or host.endswith("." + token) or reg == token:
            return True
    return False


def program_campaign_targets(program: dict[str, Any], max_targets: int = _MAX_PROGRAM_TARGETS) -> list[str]:
    """The list of concrete URLs a "hunt this program's whole scope" campaign should
    run. Prefers ``seed_targets`` (an operator's own hand-curated hunt list) when
    present; otherwise derives one representative, deduped target per ELIGIBLE
    ``structured_scope`` entry (a HackerOne API/CSV-imported program), so a program
    built purely from an imported scope table still has something to hunt. Bounded —
    this feeds directly into a real active-probing pipeline, never an unbounded fan-out.
    A host in the program's own out_of_scope_hosts is filtered out here too — it must
    never become the literal target of a hunt just because it was hand-typed as a seed
    or matched a wildcard structured_scope entry."""
    excluded_hosts = [str(h) for h in (program.get("out_of_scope_hosts") or [])]
    seeds = [str(t).strip() for t in (program.get("seed_targets") or []) if str(t or "").strip()]
    seeds = [t for t in seeds if not _target_host_excluded(t, excluded_hosts)]
    if seeds:
        return list(dict.fromkeys(seeds))[:max_targets]
    out: list[str] = []
    seen: set[str] = set()
    for entry in program.get("structured_scope") or []:
        if not isinstance(entry, dict) or not entry.get("eligible_for_submission", True):
            continue
        url = _representative_host(str(entry.get("identifier") or ""))
        if url and url not in seen and not _target_host_excluded(url, excluded_hosts):
            seen.add(url)
            out.append(url)
        if len(out) >= max_targets:
            break
    return out


def run_campaign_over_targets(
    targets: list[str],
    *,
    scope: str,
    authorized: bool,
    coder_cfg: dict[str, Any] | None,
    default_reports_dir: Path,
    seed_dir: Path | None = None,
    runtime_dir: Path | None = None,
    version: str = "",
    active: bool = False,
    time_based: bool = False,
    auth: dict[str, Any] | None = None,
    live: bool = False,
    program: str | None = None,
    max_pages: int = 12,
    platform: str = "hackerone",
    deep: bool = False,
    on_progress: Any = None,
    max_targets: int = _MAX_PROGRAM_TARGETS,
    disclose_automation: bool = False,
    excluded_hosts: tuple[str, ...] = (),
    progress_run_id: str | None = None,
    progress_unit: str | None = None,
) -> dict[str, Any]:
    """Run one full ``run_campaign`` per target (bounded, deduped, best-effort — one
    bad target never aborts the rest) and merge the results into a single combined
    payload SHAPED LIKE a single campaign's return value, so the cockpit's Findings
    board renders a "span the whole program" hunt exactly like a single-target one.
    Reuses ``run_campaign`` verbatim per target — no change to its internals, so every
    existing safety property (fail-closed scope, GET-only defaults, opt-in active
    probing) applies identically to each target.

    ``progress_unit`` (portfolio mode): when set, this span is ONE unit of a larger
    portfolio run — the caller already registered the PROGRAM as the dashboard unit, so we
    don't register per-target units or mark them; instead every target's findings stream to
    that named program unit (via each inner run_campaign's own ``progress_unit``)."""
    clean_targets = list(dict.fromkeys(str(t).strip() for t in targets if str(t or "").strip()))
    capped = clean_targets[:max_targets]
    if not capped:
        return {"ok": False, "error": "No huntable targets found for this program's scope."}
    if not authorized:
        return {"ok": False, "error": "Confirm you're authorized and in scope before running a campaign."}

    def _emit(msg: str) -> None:
        if callable(on_progress):
            try:
                on_progress(msg)
            except Exception:  # noqa: BLE001
                pass

    # One wrapping folder for the whole span; each per-target run_campaign() call nests
    # its OWN campaign-<slug>-<stamp> folder inside it (run_campaign builds that path
    # itself from whatever default_reports_dir it's given) -- so the existing "download
    # everything" bundler (which zips a folder recursively) picks up every target's full
    # artifacts for free, and a SPAN index below ties them together.
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    # Same collision guard as run_campaign's own out_root: two spans of the same program
    # within the same second (e.g. a quick re-click) must never land on the same folder.
    span_fp = hashlib.sha1("\n".join(capped).encode("utf-8", "replace")).hexdigest()[:8]
    span_root = Path(default_reports_dir) / f"span-{_safe_slug(program or 'program')}-{stamp}-{span_fp}"
    span_root.mkdir(parents=True, exist_ok=True)

    per_target: list[dict[str, Any]] = []
    findings_out: list[dict[str, Any]] = []
    proof_out: dict[str, Any] = {}
    cvss_out: dict[str, Any] = {}
    plans_out: dict[str, Any] = {}
    submission_paths: list[str] = []
    surface_urls: list[str] = []
    surface_notes: list[str] = []
    surface_tech: list[str] = []
    surface_sources: dict[str, int] = {}
    errors: list[str] = []
    ref_counter = 0
    ok_count = 0

    def _hunt_one(index: int, target: str) -> tuple[str, dict[str, Any] | None, Exception | None]:
        # Each target's on_progress lines are prefixed with its own [i/N host] tag --
        # otherwise interleaved lines from concurrently-running targets would be
        # unreadable in the shared live-progress log.
        def _target_emit(msg: str) -> None:
            _emit(f"[{index}/{len(capped)} {target}] {msg}")

        # Cooperative cancellation: a target that hasn't started yet when Stop is pressed
        # is skipped outright (the executor may have it queued behind the running batch);
        # a target already in flight winds down via run_campaign's own between-URL check.
        # The dashboard unit is the TARGET for a normal span, or the PROGRAM for a portfolio
        # run (progress_unit set) — in portfolio mode the portfolio owns the program unit, so
        # we don't mark per-target here; findings still stream to the program unit below.
        unit = progress_unit or target
        if progress.is_stopped(progress_run_id):
            if progress_unit is None:
                progress.mark_target(progress_run_id, target, "skipped")
            _target_emit("skipped — campaign stopped")
            return (target, {"ok": False, "error": "campaign stopped", "stopped": True}, None)
        _target_emit("starting…")
        if progress_unit is None:
            progress.mark_target(progress_run_id, target, "running")
        try:
            # Pass progress_unit so the inner campaign streams each URL's findings to the
            # dashboard AS THEY'RE FOUND (attributed to the named target, or the program in a
            # portfolio run) instead of landing only when the target finishes.
            result = run_campaign(
                target, scope=scope, authorized=authorized, coder_cfg=coder_cfg,
                default_reports_dir=span_root, seed_dir=seed_dir, runtime_dir=runtime_dir,
                version=version, active=active, time_based=time_based, auth=auth, live=live,
                program=program, max_pages=max_pages, platform=platform, deep=deep,
                disclose_automation=disclose_automation, on_progress=_target_emit, excluded_hosts=excluded_hosts,
                progress_run_id=progress_run_id, progress_unit=unit,
            )
            if progress_unit is None:
                if result.get("ok"):
                    progress.mark_target(progress_run_id, target, "done")
                else:
                    progress.mark_target(progress_run_id, target, "error", error=str(result.get("error") or ""))
            return (target, result, None)
        except Exception as exc:  # noqa: BLE001 - one bad target must never abort the span
            if progress_unit is None:
                progress.mark_target(progress_run_id, target, "error", error=f"{type(exc).__name__}: {exc}")
            return (target, None, exc)

    # Bounded concurrency: targets run in parallel (each on its own OS thread, exactly
    # like the ASGI layer already runs each API request), but results are aggregated
    # back in ORIGINAL target order (not completion order) so the C1/C2/... ref
    # numbering and per_target ordering stay fully deterministic regardless of which
    # target happens to finish first -- concurrency changes only the WALL-CLOCK time,
    # never the shape of the combined result.
    if progress_unit is None:
        progress.set_targets(progress_run_id, capped)  # register the named targets as the dashboard's work units
    _emit(f"campaign span: hunting {len(capped)} target(s), up to {min(_SPAN_MAX_WORKERS, len(capped))} at a time…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_SPAN_MAX_WORKERS, len(capped))) as executor:
        futures = [executor.submit(_hunt_one, i, t) for i, t in enumerate(capped, 1)]
        outcomes = [f.result() for f in futures]

    for target, result, exc in outcomes:
        if exc is not None:
            errors.append(f"{target}: {type(exc).__name__}: {exc}")
            per_target.append({"target": target, "ok": False, "campaign_path": "", "error": str(exc)})
            continue
        per_target.append({
            "target": target, "ok": bool(result.get("ok")),
            "campaign_path": result.get("campaign_path", ""), "error": result.get("error", ""),
        })
        if not result.get("ok"):
            # A target skipped because the operator stopped the campaign is not a failure —
            # keep it out of the errors list (it just wasn't run).
            if not result.get("stopped"):
                errors.append(f"{target}: {result.get('error', 'campaign failed')}")
            continue
        ok_count += 1
        proof = result.get("proof_of_impact") or {}
        cvss = result.get("cvss") or {}
        plans = result.get("attack_plans") or {}
        for finding in result.get("findings") or []:
            old_ref = str(finding.get("ref") or "")
            ref_counter += 1
            new_ref = f"C{ref_counter}"
            finding = {**finding, "ref": new_ref}
            findings_out.append(finding)
            if old_ref in proof:
                proof_out[new_ref] = proof[old_ref]
            if old_ref in cvss:
                cvss_out[new_ref] = cvss[old_ref]
            if old_ref in plans:
                plans_out[new_ref] = plans[old_ref]
        submission_paths.extend(result.get("submission_paths") or [])
        surf = result.get("surface") or {}
        surface_urls.extend(surf.get("urls") or [])
        surface_notes.extend(surf.get("notes") or [])
        for tech in surf.get("tech") or []:
            if tech not in surface_tech:
                surface_tech.append(tech)
        for source, count in (surf.get("sources") or {}).items():
            surface_sources[source] = surface_sources.get(source, 0) + (count or 0)

    if not ok_count:
        return {"ok": False, "error": "Every target in this program's scope failed: " + "; ".join(errors[:5])}
    if len(clean_targets) > len(capped):
        errors.insert(0, f"Capped to the first {max_targets} of {len(clean_targets)} in-scope targets.")

    confirmed_count = len([f for f in findings_out if (proof_out.get(f["ref"], {}) or {}).get("status") == "confirmed"])
    span_ctx = {
        "program": program or "", "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "version": version, "scope": scope, "targets_total": len(clean_targets), "targets_hunted": ok_count,
        "per_target": per_target, "errors": errors, "finding_count": len(findings_out), "confirmed_count": confirmed_count,
        "submission_count": len(submission_paths),
    }
    span_md_path = span_root / "SPAN.md"
    span_json_path = span_root / "span.json"
    fsutil.write_text_safe(span_md_path, _render_span_markdown(span_ctx))
    fsutil.write_text_safe(span_json_path, json.dumps(span_ctx, indent=2, default=str))

    return {
        "ok": True,
        "program": program or "",
        "campaign_path": str(span_md_path),
        "json_path": str(span_json_path),
        "output_dir": str(span_root),
        "targets_total": len(clean_targets),
        "targets_hunted": ok_count,
        "per_target": per_target,
        "errors": errors,
        "urls_scanned": ok_count,
        "urls_discovered": len(surface_urls),
        "finding_count": len(findings_out),
        "confirmed_count": confirmed_count,
        "submission_paths": submission_paths,
        "findings": findings_out,
        "proof_of_impact": proof_out,
        "cvss": cvss_out,
        "attack_plans": plans_out,
        "surface": {"urls": surface_urls, "sources": surface_sources, "notes": surface_notes, "tech": surface_tech},
        "severity_counts": _severity_counts(findings_out),
        "risk": _campaign_risk([{"finding": f} for f in findings_out]),
    }


_PORTFOLIO_MAX_PROGRAMS = 3  # bounded & polite: how many programs' campaigns run concurrently


def run_portfolio_campaign(
    programs: list[dict[str, Any]],
    *,
    authorized: bool,
    coder_cfg: dict[str, Any] | None,
    default_reports_dir: Path,
    seed_dir: Path | None = None,
    runtime_dir: Path | None = None,
    version: str = "",
    active: bool = False,
    time_based: bool = False,
    auth: dict[str, Any] | None = None,
    live: bool = False,
    max_pages: int = 12,
    platform: str = "hackerone",
    deep: bool = False,
    on_progress: Any = None,
    progress_run_id: str | None = None,
    max_concurrent_programs: int = _PORTFOLIO_MAX_PROGRAMS,
) -> dict[str, Any]:
    """Run a full campaign across MULTIPLE saved programs CONCURRENTLY (bounded), merged into
    one combined result shaped like a single campaign — so the Findings board + Submissions hub
    render a portfolio hunt exactly like a single one. Each program is a dashboard unit; its
    findings stream under it as they surface. ``programs`` is a list of resolved specs:
    ``{label, scope, targets, excluded_hosts, disclose_automation}``.

    Reuses ``run_campaign_over_targets`` verbatim per program (portfolio mode:
    ``progress_unit=<program label>``), so every fail-closed safety property (scope binding,
    GET-only defaults, opt-in active probing, per-host rate governor) still applies per target.
    Bounded & polite: the per-host HostRateGovernor caps traffic to any single host, and
    ``max_concurrent_programs`` caps how many programs run at once — fast at portfolio scale
    without multiplying the request rate any one host sees."""
    if not authorized:
        return {"ok": False, "error": "Confirm you're authorized and in scope before running a portfolio hunt."}
    clean: list[dict[str, Any]] = []
    seen_labels: set[str] = set()
    for p in programs or []:
        label = str(p.get("label") or "").strip()
        targets = [str(t).strip() for t in (p.get("targets") or []) if str(t or "").strip()]
        if not label or label in seen_labels or not targets:
            continue
        seen_labels.add(label)
        clean.append({"label": label, "scope": str(p.get("scope") or ""), "targets": targets,
                      "excluded_hosts": tuple(str(h) for h in (p.get("excluded_hosts") or [])),
                      "disclose_automation": bool(p.get("disclose_automation"))})
    if not clean:
        return {"ok": False, "error": "No huntable programs — each needs seed targets or an imported/built structured scope."}

    def _emit(msg: str) -> None:
        if callable(on_progress):
            try:
                on_progress(msg)
            except Exception:  # noqa: BLE001
                pass

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    port_fp = hashlib.sha1("\n".join(sorted(seen_labels)).encode("utf-8", "replace")).hexdigest()[:8]
    portfolio_root = Path(default_reports_dir) / f"portfolio-{stamp}-{port_fp}"
    portfolio_root.mkdir(parents=True, exist_ok=True)

    progress.set_targets(progress_run_id, [p["label"] for p in clean])  # PROGRAMS are the dashboard units

    per_program: list[dict[str, Any]] = []
    findings_out: list[dict[str, Any]] = []
    proof_out: dict[str, Any] = {}
    cvss_out: dict[str, Any] = {}
    plans_out: dict[str, Any] = {}
    submission_paths: list[str] = []
    surface_urls: list[str] = []
    surface_notes: list[str] = []
    surface_tech: list[str] = []
    surface_sources: dict[str, int] = {}
    errors: list[str] = []
    ref_counter = 0
    ok_count = 0

    def _hunt_program(index: int, spec: dict[str, Any]) -> tuple[str, dict[str, Any] | None, Exception | None]:
        label = spec["label"]

        def _p_emit(msg: str) -> None:
            _emit(f"[{index}/{len(clean)} {label}] {msg}")

        # Cooperative cancellation: a program not yet started when Stop is pressed is skipped;
        # one in flight winds down via run_campaign's own between-URL checks.
        if progress.is_stopped(progress_run_id):
            progress.mark_target(progress_run_id, label, "skipped")
            _p_emit("skipped — portfolio stopped")
            return (label, {"ok": False, "error": "portfolio stopped", "stopped": True}, None)
        progress.mark_target(progress_run_id, label, "running")
        try:
            result = run_campaign_over_targets(
                spec["targets"], scope=spec["scope"], authorized=authorized, coder_cfg=coder_cfg,
                default_reports_dir=portfolio_root, seed_dir=seed_dir, runtime_dir=runtime_dir, version=version,
                active=active, time_based=time_based, auth=auth, live=live, program=label, max_pages=max_pages,
                platform=platform, deep=deep, disclose_automation=spec["disclose_automation"],
                excluded_hosts=spec["excluded_hosts"], on_progress=_p_emit,
                progress_run_id=progress_run_id, progress_unit=label,
            )
            progress.mark_target(progress_run_id, label, "done" if result.get("ok") else "error",
                                 error="" if result.get("ok") else str(result.get("error") or ""))
            return (label, result, None)
        except Exception as exc:  # noqa: BLE001 - one bad program must never abort the portfolio
            progress.mark_target(progress_run_id, label, "error", error=f"{type(exc).__name__}: {exc}")
            return (label, None, exc)

    # Bounded concurrency across programs (per-host governors keep individual hosts polite).
    # Results are aggregated in original program order for deterministic C1/C2… ref numbering.
    _emit(f"portfolio hunt: {len(clean)} program(s), up to {min(max_concurrent_programs, len(clean))} at a time…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_concurrent_programs, len(clean))) as executor:
        futures = [executor.submit(_hunt_program, i, p) for i, p in enumerate(clean, 1)]
        outcomes = [f.result() for f in futures]

    for label, result, exc in outcomes:
        if exc is not None:
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            per_program.append({"program": label, "ok": False, "error": str(exc)})
            continue
        per_program.append({
            "program": label, "ok": bool(result.get("ok")),
            "finding_count": result.get("finding_count", 0), "confirmed_count": result.get("confirmed_count", 0),
            "error": result.get("error", ""),
        })
        if not result.get("ok"):
            if not result.get("stopped"):
                errors.append(f"{label}: {result.get('error', 'campaign failed')}")
            continue
        ok_count += 1
        proof = result.get("proof_of_impact") or {}
        cvss = result.get("cvss") or {}
        plans = result.get("attack_plans") or {}
        for finding in result.get("findings") or []:
            old_ref = str(finding.get("ref") or "")
            ref_counter += 1
            new_ref = f"C{ref_counter}"
            finding = {**finding, "ref": new_ref}
            findings_out.append(finding)
            if old_ref in proof:
                proof_out[new_ref] = proof[old_ref]
            if old_ref in cvss:
                cvss_out[new_ref] = cvss[old_ref]
            if old_ref in plans:
                plans_out[new_ref] = plans[old_ref]
        submission_paths.extend(result.get("submission_paths") or [])
        surf = result.get("surface") or {}
        surface_urls.extend(surf.get("urls") or [])
        surface_notes.extend(surf.get("notes") or [])
        for tech in surf.get("tech") or []:
            if tech not in surface_tech:
                surface_tech.append(tech)
        for source, count in (surf.get("sources") or {}).items():
            surface_sources[source] = surface_sources.get(source, 0) + (count or 0)

    if not ok_count:
        return {"ok": False, "error": "Every program in the portfolio failed: " + "; ".join(errors[:5])}

    confirmed_count = len([f for f in findings_out if (proof_out.get(f["ref"], {}) or {}).get("status") == "confirmed"])
    port_ctx = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"), "version": version,
        "programs_total": len(clean), "programs_hunted": ok_count, "per_program": per_program, "errors": errors,
        "finding_count": len(findings_out), "confirmed_count": confirmed_count, "submission_count": len(submission_paths),
    }
    port_md_path = portfolio_root / "PORTFOLIO.md"
    port_json_path = portfolio_root / "portfolio.json"
    fsutil.write_text_safe(port_md_path, _render_portfolio_markdown(port_ctx))
    fsutil.write_text_safe(port_json_path, json.dumps(port_ctx, indent=2, default=str))

    return {
        "ok": True, "campaign_path": str(port_md_path), "json_path": str(port_json_path),
        "output_dir": str(portfolio_root), "programs_total": len(clean), "programs_hunted": ok_count,
        "per_program": per_program, "errors": errors,
        "urls_scanned": ok_count, "urls_discovered": len(surface_urls),
        "finding_count": len(findings_out), "confirmed_count": confirmed_count, "submission_paths": submission_paths,
        "findings": findings_out, "proof_of_impact": proof_out, "cvss": cvss_out, "attack_plans": plans_out,
        "surface": {"urls": surface_urls, "sources": surface_sources, "notes": surface_notes, "tech": surface_tech},
        "severity_counts": _severity_counts(findings_out), "risk": _campaign_risk([{"finding": f} for f in findings_out]),
    }


def _render_portfolio_markdown(ctx: dict[str, Any]) -> str:
    """Top-level index for a portfolio hunt — rolls up each program (which wrote its own
    SPAN.md / CAMPAIGN.md under the same folder)."""
    out: list[str] = []
    out.append("# Portfolio Hunt\n")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| **Programs hunted** | {ctx['programs_hunted']} of {ctx['programs_total']} |")
    out.append(f"| **Findings** | {ctx['finding_count']} consolidated · **{ctx['confirmed_count']} actively confirmed** |")
    out.append(f"| **Submission packages** | {ctx['submission_count']} |")
    out.append(f"| **Generated** | {ctx['generated_at']} · GreyIQ v{ctx['version']} |")
    out.append("")
    if ctx.get("errors"):
        out.append("## Notes\n")
        for note in ctx["errors"]:
            out.append(f"- {note}")
        out.append("")
    out.append("## Programs\n")
    for t in ctx["per_program"]:
        if t.get("ok"):
            out.append(f"- `{t['program']}` → {t.get('finding_count', 0)} finding(s), {t.get('confirmed_count', 0)} confirmed")
        else:
            out.append(f"- `{t['program']}` → FAILED — {t.get('error', 'campaign failed')}")
    out.append("")
    out.append("---")
    out.append("_GreyIQ Portfolio Hunt — many programs, one run. Each program's full CAMPAIGN.md/SPAN.md is under this folder._")
    return "\n".join(out)


def _render_span_markdown(ctx: dict[str, Any]) -> str:
    """A top-level index for a "span the whole program" run — points at each target's
    own full CAMPAIGN.md (written by run_campaign) for the complete per-target detail;
    this file is just the roll-up + navigation."""
    out: list[str] = []
    out.append(f"# Program Campaign — {ctx['program']}\n")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| **Targets hunted** | {ctx['targets_hunted']} of {ctx['targets_total']} in-scope target(s) |")
    out.append(f"| **Findings** | {ctx['finding_count']} consolidated · **{ctx['confirmed_count']} actively confirmed** |")
    out.append(f"| **Submission packages** | {ctx['submission_count']} |")
    out.append(f"| **Generated** | {ctx['generated_at']} · GreyIQ v{ctx['version']} |")
    out.append("")
    out.append("## Authorization & scope\n")
    out.append("> Authorized testing only. " + (ctx.get("scope") or "(scope not provided)"))
    out.append("")
    if ctx.get("errors"):
        out.append("## Notes\n")
        for note in ctx["errors"]:
            out.append(f"- {note}")
        out.append("")
    out.append("## Targets\n")
    out.append("Each target ran its own full campaign — open its `CAMPAIGN.md` for the complete detail "
               "(surface map, per-finding evidence, ready-to-submit packages). This index only rolls them up.\n")
    for t in ctx["per_target"]:
        status = t["campaign_path"] if t["ok"] else f"FAILED — {t['error']}"
        out.append(f"- `{t['target']}` → {status}")
    out.append("")
    out.append("---")
    out.append(f"_GreyIQ BugHunter — one campaign per in-scope target, this program's whole scope in one run._")
    return "\n".join(out)


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

    # A confirmed finding the ledger already marked duplicate_of_prior was DELIBERATELY
    # suppressed from this run's submission packages (campaign.py's submission loop skips
    # it) -- it must never be listed as "Ready to submit" with no package, or the operator
    # is told to file something the engine intentionally did not re-package.
    ready = [item for item in confirmed if not item.get("duplicate_of_prior")]
    already_reported = [item for item in confirmed if item.get("duplicate_of_prior")]
    if ready:
        out.append("## Ready to submit (confirmed)\n")
        out.append("These carry a captured proof artifact and a submission package under `submissions/`:")
        out.append("")
        for item in ready:
            f = item["finding"]
            path = item.get("submission_path", "")
            out.append(f"- **{f.get('title', '')}** ({str(f.get('severity', '')).title()}) — `{item['source_url']}`" + (f"  → `{Path(path).name}`" if path else ""))
        out.append("")
        out.append("Submit each from its package (paste the `.md`), or `gn submit` to export/file. After the program "
                   "responds, record the outcome with `gn learn` so the next campaign prioritizes what pays.")
        if already_reported:
            out.append("")
            out.append(f"_{len(already_reported)} other confirmed finding(s) were already reported in a prior run and are not re-listed here._")
    elif already_reported:
        out.append("## Already reported\n")
        out.append(f"All {len(already_reported)} confirmed finding(s) this run were already reported in a prior run (no new package built).")
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
