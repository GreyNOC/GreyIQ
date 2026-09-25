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
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import brain_techniques

from bughunter import (
    account_login_service,
    active_verify_service,
    attack_map,
    cve_service,
    fsutil,
    hunt_brain,
    hunt_trace,
    investigator,
    ledger,
    learning,
    negative_knowledge,
    offline_hunt,
    progress,
    ranking,
    recon,
    report,
    research,
    scan_auth,
    screenshot_service,
    secret_classification,
    submission,
    surface_drift,
    vdp_policy,
    web_ingest,
)
from bughunter.bounty import _classify, _infer_kind, _safe_slug, build_findings_har, build_replay_script, run_bounty_hunt
from bughunter.rate_limit import shared_governor
from bughunter.registrable_domain import registrable_domain
from bughunter.settings import get_settings
from bughunter.target_ingest import _normalize_one
from bughunter.code_scanner.sources.git_remote import is_supported_remote_git_url

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


_PROOF_RANK = {"confirmed": 2, "candidate": 1, "missing": 0}


def _proof_rank(status: str) -> int:
    """Proof strength ordering (confirmed > candidate > missing/unknown) for dedup-replacement."""
    return _PROOF_RANK.get(str(status or "").strip().lower(), 0)


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _span_investigation(
    findings: list[dict[str, Any]],
    plans: dict[str, Any],
    proof: dict[str, Any],
    signals: list[dict[str, Any]],
    surface_urls: list[str],
    surface_tech: list[str],
) -> dict[str, Any]:
    """The cross-target evidence graph for a whole span/portfolio.

    Per-target hunts each chained within one host. This runs the same cortex over the POOLED,
    re-keyed (C1, C2…) findings, so a chain whose steps live on different hosts becomes
    visible for the first time.

    The per-target proof verdicts are re-attached first: the confirm gate reads a finding's own
    evidence, and the span's re-keying moves the canonical status into ``proof_out`` — without
    this, every finding a per-target hunt CONFIRMED would re-enter the graph as an unproven
    lead and the span would silently under-report its own strongest chains.

    Fail-open: a span that hunted successfully must never fail because its summary graph did.
    """
    try:
        merged: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            ref = str(finding.get("ref") or "")
            verdict = proof.get(ref) if isinstance(proof.get(ref), dict) else {}
            merged.append({**finding, "proof_of_impact": {**verdict}} if verdict else dict(finding))
        return investigator.build_investigation(
            merged, plans if isinstance(plans, dict) else {},
            surface={"endpoints": list(surface_urls)[:400], "tech": list(surface_tech)[:60]},
            signals=signals,
        )
    except Exception:  # noqa: BLE001 - the span graph is advisory; never sink a finished span
        return {}


def _chain_locations(findings: list[dict[str, Any]]) -> dict[str, str]:
    """ref -> location, for the roll-up's cross-host test. A compact map rather than the whole
    finding list: this lands in span.json/portfolio.json, which are navigation indexes."""
    return {
        str(f.get("ref") or ""): str(f.get("location") or f.get("file_path") or "")
        for f in findings if isinstance(f, dict) and f.get("ref")
    }


def _campaign_risk(consolidated: list[dict[str, Any]]) -> str:
    present = {str(item["finding"].get("severity", "")).lower() for item in consolidated}
    for sev, label in (("critical", "critical"), ("high", "high"), ("medium", "moderate")):
        if sev in present:
            return label
    return "low" if consolidated else "clean"


def _resolved_severity_finding(item: dict[str, Any]) -> dict[str, Any]:
    """A shallow copy of a consolidated item's finding whose ``severity`` has been resolved the
    SAME way the per-target report resolves it — the modelled plan CVSS (impact_model) wins over
    the raw scanner label. Feeding these into _severity_counts/_campaign_risk keeps the campaign
    tally in agreement with each per-target report; reading finding['severity'] directly
    under-reports an active-confirmed finding whose scanner label ('medium') sits below the
    modelled tier ('high'), the exact miscount the per-target layer already guards (bounty.py)."""
    finding = item.get("finding") or {}
    cvss = item.get("cvss")
    plan = {"cvss": cvss} if isinstance(cvss, dict) and cvss else None
    return {**finding, "severity": report.resolve_severity(finding, plan)}


def _capture_proof_screenshots(items: list[dict[str, Any]], shot_dir: Path, target: str, scope: Any,
                               with_attack_map: bool = True) -> int:
    """Capture a scope-gated proof screenshot for each confirmed finding and record its path on the
    finding (+ the plain-text request/response proof if any). When ``with_attack_map`` is on, also
    render a GRAPHICAL attack-plan map (a .png of the attack flow) beside it in the POC folder. Bounded
    by the caller, best-effort: every step is wrapped so a missing Playwright / a capture error is a
    clean no-op, never a break. Returns the number of screenshots captured. Reused by the
    every-confirmed pass and deep."""
    captured = 0
    for index, item in enumerate(items, 1):
        finding = item["finding"]
        stem = f"{index:02d}-{_safe_slug(str(finding.get('ref') or 'finding'))}"
        # Attack-plan map — rendered FIRST and INDEPENDENTLY of the screenshot: it's built from the
        # finding's own data (no network, no POC URL needed), so a finding whose screenshot can't be
        # captured still gets its visual attack map. Best-effort + fail-open.
        if with_attack_map:
            try:
                mplan = item.get("plan") if isinstance(item.get("plan"), dict) else {
                    "proof_of_impact": (finding.get("_active_proof") if isinstance(finding.get("_active_proof"), dict)
                                        else item.get("proof_of_impact")) or {}}
                res = attack_map.render_attack_map(finding, mplan, shot_dir / f"{stem}-attack-map.png")
                if res.get("ok"):
                    finding["attack_map_path"] = res["path"]
            except Exception:  # noqa: BLE001 - the map is enrichment; never break the campaign
                pass
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
            if shot.get("source_text"):
                finding["source_text"] = str(shot.get("source_text") or "")[:6000]
            captured += 1
    return captured


def _login_auth(account_access: dict[str, Any] | None, scope: str,
                excluded_hosts: Any, emit: Any) -> dict[str, Any] | None:
    """Resolve a program's research-account session to an ``auth`` dict (or None on any failure).
    Benign + scope-gated + fail-closed inside account_login_service.login; emits the outcome note."""
    if not account_access:
        return None
    settings = dataclasses.replace(get_settings(), excluded_hosts=tuple(excluded_hosts or ()))
    session = account_login_service.login(account_access, scope, settings)
    if callable(emit):
        emit(f"account access: {session.get('note', '')}")
    if session.get("ok") and session.get("cookie"):
        # Carry the ISSUING host with the session. A span logs in ONCE and reuses this dict
        # for every in-scope target; build_auth uses issuer_host to refuse to replay the
        # cookie to a target on a different registrable domain than the login host.
        return {"cookie": session["cookie"], "headers": session.get("headers") or [],
                "issuer_host": session.get("host") or ""}
    return None


def run_campaign(target: str, *, account_access: dict[str, Any] | None = None,
                 user_agent_suffix: str = "", **kwargs: Any) -> dict[str, Any]:
    """Run a campaign, first honoring this program's HUNTING REQUIREMENTS:

    - ``account_access`` (the program's research-account block): when set and the caller passed no
      explicit ``auth``, log in to the program's own account (``account_login_service.login`` —
      benign, scope-gated, fails closed) and hunt as that authenticated user.
    - ``user_agent_suffix``: a mandatory UA tag the program requires; set for the whole hunt in THIS
      thread (contextvar) so it rides on every in-scope request — recon, scan, and the active prover.

    Everything else forwards verbatim to the campaign body. This thin wrapper keeps the hunting-
    requirement plumbing (a login + a contextvar with a guaranteed reset) out of the long body."""
    scope = str(kwargs.get("scope") or "")
    on_progress = kwargs.get("on_progress")

    def _emit(msg: str) -> None:
        if callable(on_progress):
            try:
                on_progress(msg)
            except Exception:  # noqa: BLE001
                pass

    # Auto-login from the program's stored credentials (unless the caller already supplied a session —
    # e.g. a multi-target span resolves the login ONCE and passes the session to each target).
    if kwargs.get("auth") is None and account_access:
        auth = _login_auth(account_access, scope, kwargs.get("excluded_hosts"), _emit)
        if auth:
            kwargs["auth"] = auth
    # The program's required UA tag rides every in-scope request for the duration of this hunt.
    ua_token = web_ingest.set_ua_suffix(user_agent_suffix or "")
    try:
        return _run_campaign_body(target, **kwargs)
    finally:
        web_ingest.reset_ua_suffix(ua_token)


def _run_campaign_body(
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
    osint: bool = False,
    platform: str = "hackerone",
    deep: bool = False,
    on_progress: Any = None,
    disclose_automation: bool = False,
    excluded_hosts: tuple[str, ...] = (),
    admin_account_access: dict[str, Any] | None = None,
    idor_pairs: list[dict[str, Any]] | None = None,
    include_attack_map: bool = True,
    policy_profile: str = "",
    progress_run_id: str | None = None,
    progress_unit: str | None = None,
    submission_claim: tuple[set[str], "threading.Lock"] | None = None,
    # The operator's OOB collaborator. Without these reaching the per-URL hunt below, the four
    # out-of-band provers -- blind SSRF, blind XXE, blind RCE and JWT key-URL injection -- were
    # unreachable from EVERY autonomous path: run_bounty_hunt gates each one on a configured
    # collaborator, only the single-hunt API route passed one, and a campaign passed nothing. Four
    # confirmable classes, three of them Critical, that could only ever fire from a manual one-URL
    # hunt. Forwarding them weakens no gate: the provers stay behind active + authorized + in-scope
    # inside run_bounty_hunt, and a collaborator only exists because the operator pasted one into
    # Settings, which is the opt-in.
    oob_base: str = "",
    oob_secret: str = "",
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
    base_settings = get_settings()
    campaign_settings = dataclasses.replace(
        base_settings,
        excluded_hosts=tuple(excluded_hosts or ()),
        recon_osint_enabled=bool(osint or base_settings.recon_osint_enabled),
    )

    rt = runtime_dir
    payout_priors = learning.learned_priors(rt, program, clean_target) if rt is not None else {}
    chain_priors = brain_techniques.learned_hunt_priors(rt, program, clean_target) if rt is not None else {}
    priors = brain_techniques.combine_priors(payout_priors, chain_priors)
    intel = learning.program_intelligence(rt, program, clean_target) if rt is not None else []
    prog_key = learning.program_key(program, clean_target)

    def _emit(msg: str) -> None:
        if callable(on_progress):
            try:
                on_progress(msg)
            except Exception:  # noqa: BLE001
                pass

    # A research-account session is minted ONCE per span and reused for every target. When a
    # target is on a DIFFERENT registrable domain than the login host that issued it, build_auth
    # withholds the session (never replays a token off its own issuer); surface that so a target
    # hunted unauthenticated for this reason isn't misread as a missing/broken login.
    if kind == "url" and isinstance(auth, dict) and str(auth.get("issuer_host") or ""):
        tgt_host = urlparse(clean_target).hostname or ""
        if tgt_host and not scan_auth.same_registrable_site(tgt_host, str(auth["issuer_host"])):
            _emit(f"note: '{tgt_host}' is off the research login's domain ({auth['issuer_host']}) — "
                  f"hunting it unauthenticated (that session is never replayed off its issuer).")

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
    # Every hunted URL's sub-finding escalation clues, pooled for the span/portfolio layers
    # above. Without this the campaign swallowed them and cross-target chaining could never
    # fire — span_signals stayed permanently empty however many targets ran.
    campaign_signals: list[dict[str, Any]] = []
    recon_api_findings: list[dict[str, Any]] = []
    # Per-endpoint vuln-class priorities from the reasoning layer — {url: [classes]} — used to steer
    # each URL's active pass toward the classes most likely to hit there (empty = default order).
    hunt_priority: dict[str, list[str]] = {}
    # Endpoints the reasoning layer judged object-scoped (worth a single-session IDOR probe) — each is
    # verbatim from the in-scope discovered set; the prover re-gates scope+SSRF before touching one.
    idor_candidates: list[str] = []
    # Endpoints the reasoning layer judged ADMIN / privileged functions (worth a dual-session BFLA
    # check — is the privileged action reachable by a low-priv session?) — verbatim in-scope only.
    privileged_endpoints: list[str] = []
    # Param NAMES the reasoning layer judged the SSRF (url-taking) / XSS (reflective) surface — steer
    # WHICH params those two checks try first; the checks still supply the payload and confirm.
    brain_ssrf_params: list[str] = []
    brain_xss_params: list[str] = []
    # The recon SURFACE and the PLAN produced from it — captured for the hunt trace log
    # (hunt_trace, the offline-brain distillation corpus). Stay None on a repo/path target
    # or if the reasoning layer errored, so a trace is only written when both really exist.
    hunt_trace_surface: dict[str, Any] | None = None
    hunt_trace_plan: dict[str, Any] | None = None
    # Computed BEFORE the fan-out so they can steer it, read again after — drift to decide whether
    # this run may become the next baseline, the CVE result to consolidate without a second fetch.
    drift: dict[str, Any] = {}
    drift_host = ""
    drift_observations: dict[str, Any] = {}
    drift_surface: dict[str, Any] = {}
    cve_result: dict[str, Any] = {}
    if kind == "url":
        _emit("recon: mapping the surface…")
        # Bind discovery to the SAME fail-closed scope gate the active prover uses, so
        # in-scope cross-host expansion (a wildcard program) is followed and ONLY
        # in-scope hosts are ever fetched -- excluded_hosts rides on campaign_settings.
        scope_gate = (lambda h: active_verify_service.host_in_active_scope(h, scope, campaign_settings)) if str(scope or "").strip() else None
        # Draw passive recon from the PROCESS-WIDE per-host token bucket, so concurrent span/portfolio
        # workers crawling the same host (a wildcard program whose targets recon-expand to a shared
        # host/CDN) don't each build their own governor and multiply the per-host request rate/burst.
        rec = recon.discover(
            clean_target, max_pages=max_pages, scope_in=scope_gate,
            settings=campaign_settings,
            governor=shared_governor(
                capacity=campaign_settings.active_max_requests_per_host,
                min_interval_s=campaign_settings.active_min_interval_ms / 1000.0,
                pool="recon",  # a SEPARATE per-host bucket from the active prover — recon must not drain it
            ),
            # Name-only response shapes for surface_drift to diff against the last run. No extra
            # request: they are already in memory and would otherwise be discarded.
            observe=rt is not None,
        )
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

        # Always-available veteran baseline: rank existing check classes from observed endpoint,
        # parameter, form, and stack semantics. This is deterministic/offline and only reorders
        # checks, so installations without a configured model still spend small request budgets
        # on the classes most suited to each route.
        hunt_surface = {"endpoints": urls, "params": recon_params, "tech": recon_tech, "forms": recon_forms}
        hunt_techniques: list[brain_techniques.Technique] = []
        technique_context = ""
        try:
            catalog = brain_techniques.load_techniques(rt or default_reports_dir, seed_dir or default_reports_dir)
            hunt_task = " ".join([clean_target, *map(str, recon_tech), *map(str, recon_params[:30])])
            hunt_techniques = brain_techniques.select_techniques(hunt_task, catalog, domain="hunt")
            technique_context = brain_techniques.prompt_block(hunt_techniques, heading="Hunt techniques")
        except Exception:  # noqa: BLE001 - Markdown guidance is advisory
            pass
        hp = hunt_brain.heuristic_plan(hunt_surface)
        for row in (hp.get("probe_priority") or []):
            ep, classes = row.get("endpoint"), row.get("classes") or []
            if ep and classes:
                hunt_priority[ep] = list(classes)
        if hunt_priority:
            _emit(f"hunt-planner: prioritised probe classes on {len(hunt_priority)} endpoint(s) from observed semantics")

        # Reasoning layer: let the configured brain read the mapped surface and propose
        # target-specific parameter NAMES the heuristics miss (e.g. returnUrl/callback on a login,
        # tpl on a renderer, file/path on a download). These are unioned into recon_params and thus
        # flow to every per-URL active pass's benign differential checks — so an LLM hypothesis is
        # only ever REPORTED if the deterministic prover independently confirms it (recall up,
        # precision unchanged). Best-effort + fail-closed: no brain / any error keeps current behaviour.
        try:
            surface_for_brain = hunt_surface
            # seed_dir/runtime_dir locate the OPTIONAL learned offline ranker's weight file. With no
            # file present the planner is byte-identical to the hand-tuned rules, so this is safe to
            # pass unconditionally. technique_context feeds the operator technique playbooks to a
            # REASONING brain; the two are independent (offline ranker vs LLM prompt) and compose.
            hb = hunt_brain.plan_hunt(
                coder_cfg, clean_target, scope, surface_for_brain, priors=priors,
                seed_dir=seed_dir, runtime_dir=rt,
                technique_context=technique_context,
            )
            hb = brain_techniques.enrich_hunt_plan(hb, surface_for_brain, hunt_techniques, priors)
            # Capture the (surface, plan) input side for the trace log. recon_params is only ever
            # REBOUND below (never mutated in place), so this reference stays the recon-only surface.
            hunt_trace_surface, hunt_trace_plan = surface_for_brain, hb
            chains = hb.get("attack_chains") or []
            if chains:
                _emit(f"hunt-brain: generated {len(chains)} evidence-gated attack chain(s)")
                for chain in chains[:6]:
                    progress.global_log("brain_dialog", {
                        "domain": "hunt", "stage": "plan", "run_id": progress_run_id or "",
                        "message": f"Planned {', '.join(chain.get('classes') or [])} chain; POE required",
                        "chain_id": chain.get("id"), "classes": chain.get("classes") or [],
                        "endpoint": chain.get("endpoint") or "",
                    })
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
                    # The optional model is target-specific refinement, so its ranking precedes
                    # the offline baseline while retaining every deterministic suggestion.
                    hunt_priority[ep] = list(dict.fromkeys(list(classes) + (hunt_priority.get(ep) or [])))
            if hb.get("probe_priority"):
                _emit(f"hunt-brain: refined probe priorities on {len(hb.get('probe_priority') or [])} endpoint(s)")
            idor_candidates = [e for e in (hb.get("idor_candidates") or []) if e in set(urls)]
            privileged_endpoints = [e for e in (hb.get("privileged_endpoints") or []) if e in set(urls)]
            brain_ssrf_params = list(hb.get("ssrf_params") or [])
            brain_xss_params = list(hb.get("xss_params") or [])
            if brain_ssrf_params or brain_xss_params:
                _emit(f"hunt-brain: {len(brain_ssrf_params)} SSRF + {len(brain_xss_params)} XSS param candidate(s) to steer those checks")
            if privileged_endpoints:
                _emit(f"hunt-brain: {len(privileged_endpoints)} privileged endpoint(s) flagged for a dual-session BFLA check")
        except Exception:  # noqa: BLE001 - the reasoning layer must never break a hunt
            pass
        # Deterministic recon-derived BFLA feed: union in endpoints whose path looks like an admin /
        # privileged FUNCTION (offline_hunt.admin_path_endpoints) so the dual-account BFLA prover fires
        # on privileged endpoints the surface revealed even when no brain flagged them (or no brain is
        # configured). Verbatim in-scope only; the prover's anon-denied control still owns the confirm,
        # so a non-privileged pick is a clean no-op — this only raises recall. Capped to bound requests.
        for ep in offline_hunt.admin_path_endpoints(urls):
            if ep not in privileged_endpoints:
                privileged_endpoints.append(ep)
        privileged_endpoints = privileged_endpoints[:8]
        # Merge the host-global tech-fingerprint hints into EVERY url's priority: the brain's
        # per-endpoint classes come first (most specific), then the stack-implied hint classes,
        # de-duped. URLs the brain didn't flag still get steered by the fingerprint alone. Pure
        # reordering downstream (_apply_class_priority never creates a finding) — zero FP risk.
        if hint_classes:
            for u in urls:
                hunt_priority[u] = list(dict.fromkeys((hunt_priority.get(u) or []) + hint_classes))

        # --- KNOWN-CVE fingerprint, ahead of the active pass so it can STEER it -----------------
        # A matched advisory names the weakness class of the exact library this host serves, which
        # is worth far more as targeting than as a report line. One GET, and the findings are still
        # consolidated further down from this same result, so nothing is fetched twice.
        try:
            _emit("cve: fingerprinting front-end components…")
            cve_result = cve_service.scan_known_cves(
                clean_target,
                scope=str(scope or "").strip() or cve_service._target_host(clean_target),
                settings=campaign_settings)
            cve_hints = cve_service.cve_probe_hints(cve_result.get("findings") or [])
            if cve_hints:
                # In FRONT of the generic stack hints: "this page serves a library with a known XSS"
                # is evidence about this target, where a fingerprint hint is only an implication.
                for u in urls:
                    hunt_priority[u] = list(dict.fromkeys(cve_hints + (hunt_priority.get(u) or [])))
                _emit(f"cve: matched advisories prioritise {', '.join(cve_hints[:4])} on this target")
        except Exception:  # noqa: BLE001 - the CVE pass is enrichment; never break the campaign
            cve_result = {}

        # --- CROSS-RUN MEMORY ------------------------------------------------------------------
        # The campaign has to steer itself here: run_bounty_hunt applies drift and negative
        # knowledge only behind `extra_params is None and class_priority is None`, and a campaign
        # always supplies both, so its per-URL hunts skip that branch (and the writes at the end of
        # it — see the record step further down). Both engines are fail-open and only reorder.
        if rt is not None:
            try:
                # Kept for the snapshot write at the end of the run.
                drift_host = rec.get("host") or ""
                drift_observations = rec.get("observations") or {}
                # OBSERVED params only — `rec["params"]`, never the rebound `recon_params`, which
                # also carries the brain's hypotheses. A hypothesis is by construction a name the
                # target did NOT serve (the validator keeps it only if absent from the surface), so
                # baselining one makes the next run diff guesses against guesses and emit param.new
                # for names nothing served — which also flips on the heavier js.bundle-changed.
                drift_surface = {"endpoints": list(urls),
                                 "params": list(rec.get("params") or []),
                                 "forms": list(recon_forms)}
                drift = surface_drift.build_drift(
                    rt, program=program, target=clean_target, host=drift_host,
                    observations=drift_observations, surface=drift_surface)
                # A delta's subject is a DIFF IDENTITY (query-stripped so a page does not look new
                # every run), not a probe URL — map it back to the URL this crawl saw. A subject
                # matching nothing crawled is DROPPED, not hunted: it comes from the previous run's
                # observations, and with no explicit scope `scope_gate` is None, so nothing would
                # re-check it. This can only reorder the set recon already produced.
                crawled: dict[str, str] = {}
                for u in urls:
                    crawled.setdefault(surface_drift.canonical_url(u), str(u))
                changed: list[str] = []
                for subject in surface_drift.delta_targets(drift, limit=2):
                    key = surface_drift.canonical_url(subject)
                    probe = crawled.get(key) if key else None
                    if not probe or probe in changed:
                        continue
                    if scope_gate is not None and not scope_gate((urlparse(probe).hostname or "").lower()):
                        continue
                    changed.append(probe)
                if changed:
                    # Hunt what MOVED first: the operator can stop between hunts and a long span may
                    # never reach the tail, so fan-out order is real budget.
                    _already = set(changed)
                    urls = changed + [u for u in urls if u not in _already]
                    _emit(f"surface drift: {len(drift.get('deltas') or [])} change(s) since "
                          f"{drift.get('baseline_ts') or 'the last run'}; hunting what moved first")
            except Exception:  # noqa: BLE001 - steering is an optimization, never a blocker
                drift = {}
            # Downrank (endpoint, class) pairs probed before that never confirmed, so the capped
            # per-URL budget flows to unexhausted surface. `hunt_priority` is {url: [classes]}, so
            # it is projected into the probe_priority shape apply_suppression takes, then read back.
            try:
                cooled = negative_knowledge.cooled_pairs(rt, program=program, target=clean_target)
                if cooled and hunt_priority:
                    projected = {"probe_priority": [{"endpoint": u, "classes": list(cs)}
                                                    for u, cs in hunt_priority.items()]}
                    suppressed, stats = negative_knowledge.apply_suppression(
                        projected, cooled,
                        changed_endpoints=negative_knowledge.changed_endpoint_keys(drift))
                    for row in suppressed.get("probe_priority") or []:
                        if isinstance(row, dict) and row.get("endpoint"):
                            hunt_priority[str(row["endpoint"])] = list(row.get("classes") or [])
                    if stats.get("downranked"):
                        _emit(f"negative knowledge: deprioritised {stats['downranked']} tested-inert "
                              f"endpoint/class pair(s) from earlier hunts "
                              f"({stats.get('fully_cooled', 0)} endpoint(s) fully cooled)")
            except Exception:  # noqa: BLE001 - suppression is an optimizer, never a hunt breaker
                pass
    else:
        urls = [clean_target]
        recon_notes, recon_sources = [], {}

    # A VDP profile with avoid_dos (e.g. NASA) forbids DoS/rate/spam testing — so the executing
    # time-based SLEEP probes and the aggressive deep mode are FORCED OFF for this program, no matter
    # what the request asked for. The rest of the active pass stays benign GET-only.
    _policy_pre = vdp_policy.get_profile(policy_profile) if policy_profile else None
    if _policy_pre and _policy_pre.get("avoid_dos"):
        if time_based or deep:
            _emit(f"{_policy_pre['name']} policy: disabling time-based/deep probing (no DoS/rate testing).")
        time_based = False
        deep = False

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
    key_to_idx: dict[str, int] = {}  # dedup key -> index in `consolidated`, for confirmed-upgrade replacement
    # Register the discovered URLs as the dashboard's work units — but ONLY for a top-level
    # single-target campaign. In a program span the NAMED targets are the units (already
    # registered by the span); here we just stream that target's findings as URLs finish.
    if progress_unit is None:
        progress.set_targets(progress_run_id, urls)
    # Negative knowledge may only learn a MISS from a run that finished its plan: "never executed"
    # and "executed and inert" are different facts, and only the second is knowledge. Two ways this
    # run can fall short — the fan-out stopping early, and any single URL's active pass being
    # rate-limited, refused, or cut off by its budget (the per-URL mirror of run_bounty_hunt's own
    # condition for a direct hunt).
    stopped_early = False
    active_clean = True
    # IMMUNITY IS DECIDED ON WHAT THE ENGINE PROVED, NOT ON WHAT THE REPORT SHOWED. `consolidated`
    # is later narrowed by dismissals and the VDP filter, and deduped across urls on a location
    # that collapses digits anywhere — so a confirmed pair can vanish from it while still sitting
    # in the plan, and would be written down as a miss. Bank every confirmation unfiltered here.
    nk_confirmed: list[dict[str, Any]] = []
    # Chains from each per-target investigation, pooled for the drift snapshot: an empty `chains`
    # list reads as "nothing is blocked any more" and resets reopened_chains' blocked-run streak.
    campaign_chains: list[dict[str, Any]] = []
    for index, url in enumerate(urls, 1):
        # Cooperative cancellation: the operator's Stop halts BETWEEN url hunts (a hunt
        # in flight finishes its current url, then we bail with whatever's been found).
        if progress.is_stopped(progress_run_id):
            _emit("stop requested — halting this target after the current URL")
            stopped_early = True
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
            ssrf_params=brain_ssrf_params, xss_params=brain_xss_params,
            # Make Stop responsive WITHIN a URL, not only between them. The loop above already breaks on
            # progress.is_stopped, but a single URL's active fan-out, re-plan wave and OOB provers can run
            # for a long time — so without this the operator waits out the current URL after hitting Stop.
            should_stop=(lambda rid=progress_run_id: progress.is_stopped(rid)) if progress_run_id else None,
            oob_base=oob_base, oob_secret=oob_secret,
        )
        per_target.append({"target": url, "ok": result.get("ok", False),
                           "report_path": result.get("report_path", ""), "error": result.get("error", "")})
        if not result.get("ok"):
            if progress_unit is None:
                progress.mark_target(progress_run_id, url, "error", error=str(result.get("error") or ""))
            continue
        # Did THIS url's pass get through its plan? Anything less and no miss may be learned.
        _am = result.get("active_authorization")
        _am = _am if isinstance(_am, dict) else {}
        if (result.get("scan_errors") or _am.get("in_scope") is not True
                or _am.get("rate_limited") or str(_am.get("skipped_reason") or "").strip()):
            active_clean = False
        if isinstance(result.get("chain_signals"), list):
            campaign_signals.extend(result["chain_signals"])
        doc = _read_json(result.get("json_path", ""))
        # Already computed by this target's investigation, so pooling costs nothing.
        _inv = doc.get("investigation") if isinstance(doc.get("investigation"), dict) else {}
        campaign_chains.extend(c for c in (_inv.get("attack_chains") or []) if isinstance(c, dict))
        url_new: list[dict[str, Any]] = []  # findings first-seen at THIS url, for the live dashboard
        confirmed_here: list[str] = []      # classes THIS url proved — see the promotion below
        for finding in doc.get("findings") or []:
            # Dedup across targets by class + rule + normalized location.
            norm_loc = re.sub(r"\d+", "N", str(finding.get("location") or ""))
            key = f"{finding.get('class_id')}|{finding.get('rule_id')}|{norm_loc}"
            ref = str(finding.get("ref") or "")
            proof_status = _proof_status(doc, ref)
            # Collected BEFORE the dedup guard: a class this URL proved is evidence about the host
            # whether or not an earlier URL already reported the same finding.
            if proof_status == "confirmed":
                _cls = str(finding.get("class_id") or "").strip()
                if _cls and _cls not in confirmed_here:
                    confirmed_here.append(_cls)
                # Against BOTH the planned url and the finding's own location, since the plan is
                # keyed by url and the finding may name another endpoint. Over-granting immunity
                # only costs a re-probe; a false suppression silently removes coverage.
                for _ep in dict.fromkeys([url, str(finding.get("location") or "")]):
                    if _ep and _cls:
                        nk_confirmed.append({"endpoint": _ep, "class": _cls,
                                             "proof_status": "confirmed"})
            item = {
                "finding": finding,
                "source_url": url,
                "source_report": result.get("report_path", ""),
                "source_json": result.get("json_path", ""),
                "proof_status": proof_status,
                "cvss": (doc.get("cvss") or {}).get(ref) or {},
                # The captured observed-vs-control differential for THIS finding, carried on the item
                # (NOT under "plan" — that key is the synthetic-vs-sidecar sentinel below) so the ledger
                # persists it. Without this, a per-URL finding confirmed by the active pass records an
                # EMPTY differential and a report rebuilt from history after a restart/eviction loses the
                # very proof that earned "confirmed". The differential lives in the run JSON's proof map.
                "proof_of_impact": (doc.get("proof_of_impact") or {}).get(ref) or {},
            }
            if key in seen_keys:
                # Same class/rule at the same normalized location was already recorded at an earlier URL.
                # Normally skip the duplicate — but if THIS occurrence is confirmed while the retained one
                # is weaker (candidate/missing), REPLACE it so a real, submittable confirmed finding isn't
                # silently lost to a first-seen unconfirmed instance (confirmed > candidate > missing).
                prev = key_to_idx.get(key)
                if prev is not None and _proof_rank(proof_status) > _proof_rank(consolidated[prev].get("proof_status")):
                    consolidated[prev] = item
                continue
            seen_keys.add(key)
            key_to_idx[key] = len(consolidated)
            consolidated.append(item)
            url_new.append({"ref": ref, "title": finding.get("title"), "severity": finding.get("severity"),
                            "class_name": finding.get("class_name") or finding.get("class_id"), "proof_status": proof_status,
                            # Carried for the dashboard's investigate drawer + on-demand re-verify/report:
                            # where the finding lives (the URL), its CWE, rule id, and the canonical
                            # class_id (so an on-demand report gets class-specific reproduction steps).
                            "location": finding.get("location") or url, "cwe": finding.get("cwe"),
                            "rule_id": finding.get("rule_id"), "class_id": finding.get("class_id"),
                            # The ACTIVE proof itself — the observed-vs-control differential + evidence the
                            # active pass already captured. Streaming it (not just the status STRING) lets the
                            # drawer's "View full report" render a campaign-confirmed finding as CONFIRMED with
                            # its proof, WITHOUT a manual re-verify: the report's confirmed gate needs the
                            # captured artifact, which a bare status can't supply.
                            "proof_detail": (doc.get("proof_of_impact") or {}).get(ref) or {},
                            "proof_evidence": finding.get("proof_evidence") or None})
        # --- Let this target teach the ones still queued ---------------------------------------
        # A class confirmed here is the best evidence available that it is live on a sibling route
        # of the same property — a proven IDOR on one object endpoint is a reason to try IDOR on
        # the next — so it leads the priority for the URLs not yet hunted. Same registrable domain
        # only, since a confirmation on one property says nothing about another (the chain engine
        # draws that boundary too). Additive and order-only; the gated prover still owns confirm.
        if confirmed_here:
            try:
                here = registrable_domain((urlparse(url).hostname or "").lower())
                for later in urls[index:]:
                    if not here or registrable_domain((urlparse(later).hostname or "").lower()) != here:
                        continue
                    hunt_priority[later] = list(dict.fromkeys(
                        confirmed_here + (hunt_priority.get(later) or [])))
            except ValueError:
                pass  # a malformed URL is not a reason to abandon the campaign
        # Stream this URL's findings live — attributed to the span's named target when
        # running under one, else to the URL itself (single-target campaign).
        progress.add_findings(progress_run_id, progress_unit or url, url_new)
        if progress_unit is None:
            progress.mark_target(progress_run_id, url, "done")

    # --- Secrets mined from served JS (recon-sourced) — STRICT-classify + dedup + add. ---
    # These served-JS secrets are folded straight into the campaign report WITHOUT going through a
    # per-URL run_bounty_hunt, so they must be classified here too — otherwise a public Google/Firebase
    # key (or an OAuth/analytics id) keeps mine_js's raw High/Critical severity and inflates the campaign
    # risk. apply_secret_classification downgrades unproven keys to Info/Low and scrubs the raw value.
    secret_classification.apply_secret_classification(rec_js_secrets)
    for index, secret in enumerate(rec_js_secrets, 1):
        cid, cname, cwe, owasp = _classify(secret)
        finding = {**secret, "ref": f"JS{index}", "class_id": cid, "class_name": cname, "cwe": cwe, "owasp": owasp,
                   "location": secret.get("file_path") or clean_target}
        norm_loc = re.sub(r"\d+", "N", str(finding.get("location") or ""))
        key = f"{cid}|{finding.get('rule_id')}|{norm_loc}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        # A public client key / dead credential is informational, not a submittable candidate.
        _sc = str(finding.get("secret_classification") or "")
        pstatus = "missing" if _sc in (secret_classification.PUBLIC_CLIENT_KEY, secret_classification.FALSE_POSITIVE) else "candidate"
        consolidated.append({"finding": finding, "source_url": finding["location"], "source_report": "",
                             "source_json": "", "proof_status": pstatus, "cvss": {}})

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
        try:
            # Fingerprinted before the fan-out (above) so its advisories could steer the probe
            # order; reuse that result rather than fetching twice. Empty if the early pass errored.
            cve_res = cve_result if isinstance(cve_result, dict) else {}
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

    # --- Brain-selected IDOR probe pass: the reasoning layer flagged these endpoints as object-scoped
    # (a numeric/uuid id the session owns). Run the single-session IDOR DISCOVERY prover
    # (access_control_service.run_idor_probe) — built + tested + scope-gated but until now NEVER called
    # in the autonomous loop — on each, with the operator's authenticated session. GET-only, re-gates
    # scope+SSRF itself, CANDIDATE-grade (one session can't prove cross-tenant, so it points at the
    # dual-session confirm). Only when the active pass is on AND a session exists; a hallucinated pick
    # with no numeric id is a clean no-op. Bounded + best-effort — never breaks the campaign. ---
    if effective_active and idor_candidates and isinstance(auth, dict) and (str(auth.get("cookie") or "").strip() or auth.get("headers")):
        try:
            from bughunter import access_control_service
            idor_n = 0
            for ep in idor_candidates:
                res = access_control_service.run_idor_probe(ep, account=auth, scope=scope, settings=campaign_settings)
                fnd = res.get("finding") if isinstance(res, dict) else None
                if not fnd:
                    continue
                plan = res.get("attack_plan") or {}
                norm_loc = re.sub(r"\d+", "N", str(fnd.get("location") or ep))
                key = f"{fnd.get('class_id')}|{fnd.get('rule_id')}|{norm_loc}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                idor_n += 1
                fnd["ref"] = f"IDOR{idor_n}"
                consolidated.append({
                    "finding": fnd, "source_url": ep, "source_report": "", "source_json": "",
                    "proof_status": str((plan.get("proof_of_impact") or {}).get("status") or "candidate"),
                    "cvss": plan.get("cvss") or {}, "plan": plan,
                })
            if idor_n:
                _emit(f"hunt-brain IDOR: {idor_n} object-authorization lead(s) from brain-selected endpoint(s)")
        except Exception:  # noqa: BLE001 - the IDOR pass is enrichment; never break the campaign
            pass

    # --- Dual-account access-control passes (BFLA + cross-tenant IDOR). Both need a SECOND owned
    # session, so resolve the admin/second-account login ONCE and share it. Only when the active pass is
    # on, the program supplied a second account (`admin_account_access`), the primary `auth` session
    # exists, and there's actually work for it (brain-flagged privileged endpoints and/or operator-
    # supplied IDOR pairs). The login is benign + scope-gated + fail-closed inside `_login_auth`. ---
    _has_primary = isinstance(auth, dict) and (str(auth.get("cookie") or "").strip() or auth.get("headers"))
    admin_auth: dict[str, Any] | None = None
    if (effective_active and admin_account_access and _has_primary and (privileged_endpoints or idor_pairs)):
        admin_auth = _login_auth(admin_account_access, scope, excluded_hosts, _emit)
        if not (isinstance(admin_auth, dict) and (str(admin_auth.get("cookie") or "").strip() or admin_auth.get("headers"))):
            admin_auth = None
            _emit("dual-account access-control: skipped — the second account did not resolve a session (fail-closed).")

    # --- Brain-selected BFLA probe pass: the reasoning layer flagged these endpoints as ADMIN /
    # privileged FUNCTIONS. Run the DUAL-ACCOUNT BFLA prover (access_control_service.run_bfla_check) —
    # a three-session admin/user/anon GET-only differential that CONFIRMS only when the low-privilege
    # session receives the admin-only response WHILE an anonymous request is denied (so the endpoint is
    # genuinely privilege-gated, not public). The DETERMINISTIC prover owns the confirm via that captured
    # differential (observed_result + control_result) — the brain only SELECTED the endpoint, it never
    # flips a finding to confirmed. Re-gates scope+SSRF itself; a hallucinated pick that isn't really
    # gated falls to enforced/candidate (a clean no-op). Bounded + best-effort — never breaks the campaign. ---
    if admin_auth and privileged_endpoints:
        try:
            from bughunter import access_control_service
            bfla_n = 0
            for ep in privileged_endpoints:
                res = access_control_service.run_bfla_check(
                    ep, admin_account=admin_auth, user_account=auth, scope=scope, settings=campaign_settings)
                if not (isinstance(res, dict) and res.get("status") == "confirmed"):
                    continue
                fnd = res.get("finding")
                if not fnd:
                    continue
                plan = res.get("attack_plan") or {}
                norm_loc = re.sub(r"\d+", "N", str(fnd.get("location") or ep))
                key = f"{fnd.get('class_id')}|{fnd.get('rule_id')}|{norm_loc}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                bfla_n += 1
                fnd["ref"] = f"BFLA{bfla_n}"
                consolidated.append({
                    "finding": fnd, "source_url": ep, "source_report": "", "source_json": "",
                    "proof_status": str((plan.get("proof_of_impact") or {}).get("status") or "confirmed"),
                    "cvss": plan.get("cvss") or {}, "plan": plan,
                })
            if bfla_n:
                _emit(f"hunt-brain BFLA: {bfla_n} confirmed function-level authorization bypass(es) via the dual-account differential")
        except Exception:  # noqa: BLE001 - the BFLA pass is enrichment; never break the campaign
            pass

    # --- Operator-supplied cross-tenant IDOR pass: for each object-URL pair the operator explicitly
    # provided (url_a owned by the PRIMARY account, url_b a different object owned by the SECOND
    # account), run the DUAL-SESSION IDOR prover (access_control_service.run_idor_check) — a three-
    # request differential (A reads A's object / B reads B's object / B reads A's object) that CONFIRMS
    # only when B receives A's specific object, distinct from B's own. The pairs are NEVER auto-derived
    # (auto-pairing a neighbour id corrupts the ownership control → false confirmeds); the operator
    # asserts the ownership. The prover owns the confirm and re-gates scope+SSRF; the captured proof is
    # the differential only, never the cross-tenant body. Scoped to pairs whose object is on a host this
    # campaign actually touched, so a program-wide pair isn't re-tested once per target in a span.
    # Bounded + best-effort — never breaks the campaign. ---
    if admin_auth and idor_pairs:
        try:
            from bughunter import access_control_service
            campaign_hosts = {(urlparse(str(u)).hostname or "").lower() for u in urls if u}
            xidor_n = 0
            for pair in idor_pairs:
                url_a = str((pair or {}).get("url_a") or "").strip()
                url_b = str((pair or {}).get("url_b") or "").strip()
                if not url_a or not url_b:
                    continue
                if (urlparse(url_a).hostname or "").lower() not in campaign_hosts:
                    continue   # this pair's object isn't on a host this campaign covered — skip (a span re-run tests it under its own target)
                res = access_control_service.run_idor_check(
                    url_a, url_b, account_a=auth, account_b=admin_auth, scope=scope, settings=campaign_settings)
                if not (isinstance(res, dict) and res.get("status") == "confirmed"):
                    continue
                fnd = res.get("finding")
                if not fnd:
                    continue
                plan = res.get("attack_plan") or {}
                norm_loc = re.sub(r"\d+", "N", str(fnd.get("location") or url_a))
                key = f"{fnd.get('class_id')}|{fnd.get('rule_id')}|{norm_loc}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                xidor_n += 1
                fnd["ref"] = f"XIDOR{xidor_n}"
                consolidated.append({
                    "finding": fnd, "source_url": url_a, "source_report": "", "source_json": "",
                    "proof_status": str((plan.get("proof_of_impact") or {}).get("status") or "confirmed"),
                    "cvss": plan.get("cvss") or {}, "plan": plan,
                })
            if xidor_n:
                _emit(f"cross-tenant IDOR: {xidor_n} confirmed cross-account object read(s) from operator-supplied pair(s)")
        except Exception:  # noqa: BLE001 - the IDOR pass is enrichment; never break the campaign
            pass

    # --- Drop operator-deleted findings before ranking/submission. The per-URL engine
    # already filtered its own hunts; this pass also covers the synthetic leads added
    # above (JS secrets, known-CVE, API-discovery), which never went through it — so a
    # deleted finding of any origin stays gone. Same stable dedup key: the delete sticks. ---
    if rt is not None:
        _dismissed = ledger.dismissed_keys(rt)
        if _dismissed:
            consolidated = [c for c in consolidated if ledger.dedup_key(c["finding"]) not in _dismissed]

    # --- VDP policy profile (e.g. NASA mode): drop findings the program's Vulnerability Disclosure
    # Policy does not authorize reporting — excluded endpoints, always-rejected classes, and (for a
    # confirmed-only policy) anything without a captured proof of exploit. The dropped items are
    # reported transparently in the progress log (never silently), and this only NARROWS the report;
    # the engine's own scope+SSRF gates are unchanged. ---
    _policy = vdp_policy.get_profile(policy_profile) if policy_profile else None
    if _policy:
        consolidated, _pol_dropped = vdp_policy.filter_findings(consolidated, _policy)
        if _pol_dropped:
            _emit(f"{_policy['name']} policy: withheld {len(_pol_dropped)} finding(s) not reportable under "
                  f"this program's rules (excluded endpoint / rejected class / not confirmed).")

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
        n = _capture_proof_screenshots(confirmed[:8], out_root / "screenshots", clean_target, scope,
                                       with_attack_map=include_attack_map)
        if n:
            _emit(f"captured {n} proof screenshot(s) for confirmed finding(s).")
        if include_attack_map:
            mapped = sum(1 for c in confirmed[:8] if c["finding"].get("attack_map_path"))
            if mapped:
                _emit(f"rendered {mapped} graphical attack-plan map(s) into the POC download.")

    # --- Replayable proof-of-exploit artifacts: a copy-paste `replay.sh` (each confirmed finding's
    # benign crafted request as curl) + a `findings.har` (importable into Burp/browser devtools),
    # written to the campaign folder so the "download everything" bundle ships a machine-replayable
    # reproduction of every confirmed finding. Requests only — no response bodies embedded (the
    # differential-only proof discipline); secrets redacted. Best-effort, never breaks the campaign. ---
    if confirmed:
        try:
            replay, replay_n = build_replay_script(confirmed)
            if replay_n:
                fsutil.write_text_safe(out_root / "replay.sh", replay)
            har, har_n = build_findings_har(confirmed, version=version,
                                            generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
            if har_n:
                fsutil.write_text_safe(out_root / "findings.har", json.dumps(har, indent=2))
            if replay_n or har_n:
                _emit(f"wrote replayable PoC artifacts (replay.sh: {replay_n}, findings.har: {har_n} request(s)).")
        except Exception:  # noqa: BLE001 - artifact export is best-effort; never break the campaign
            pass

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
        # Append this hunt to the trace log (offline-brain distillation corpus): the recon
        # surface + the plan the brain produced + what actually confirmed. upsert_findings
        # ran first so each consolidated item now carries its dedup_key (for the later ledger
        # join in hunt_trace.training_examples). Best-effort + fail-closed inside record_trace.
        if hunt_trace_surface is not None and hunt_trace_plan is not None:
            hunt_trace.record_trace(rt, program=program, target=clean_target,
                                    surface=hunt_trace_surface, plan=hunt_trace_plan,
                                    consolidated=consolidated)
        # The two memories bounty writes only on the branch a campaign skips, so the steering added
        # before the fan-out has something to read next run.
        if kind == "url":
            try:
                # The plan as it was actually spent, in the probe_priority shape the store reads.
                nk_plan = {"probe_priority": [{"endpoint": u, "classes": list(cs)}
                                              for u, cs in hunt_priority.items()]}
                # Gates MISSES only — confirmations are always recorded, since they only grant
                # immunity. See stopped_early / active_clean where they are declared.
                nk_complete = bool(
                    effective_active and per_target and not stopped_early and active_clean
                    and all(t.get("ok") for t in per_target))
                negative_knowledge.record_hunt(
                    rt, program=program, target=clean_target, plan=nk_plan,
                    # Report-shaped outcomes PLUS the unfiltered confirmations banked above —
                    # without the second half a filtered-out confirm is recorded as a miss.
                    outcomes=hunt_trace.outcomes_from_findings(consolidated) + nk_confirmed,
                    complete=nk_complete)
                # This run becomes the next run's baseline — unless it saw too little of the host
                # to be compared, when storing it would make the next run call everything new.
                if drift.get("status") != "degraded-run" and drift_observations:
                    surface_drift.record_snapshot(
                        rt, program=program, target=clean_target,
                        host=drift_host or urlparse(clean_target).hostname or "",
                        observations=drift_observations, surface=drift_surface,
                        chains=campaign_chains,  # omitting these resets the blocked-run streak
                        deltas=drift.get("deltas"))
            except Exception:  # noqa: BLE001 - bookkeeping must never break a completed campaign
                pass

    # Publish a local, redacted POE decision into the in-product operations stream. This is
    # dialogue for the running app, never an external submission or production-side mutation.
    if hunt_trace_plan is not None:
        try:
            chain_result = brain_techniques.chain_outcome_summary(hunt_trace_plan, consolidated)
            target_label = urlparse(clean_target).hostname or _safe_slug(clean_target)
            progress.global_log("poe_dialog", {
                "domain": "hunt", "stage": "outcome", "run_id": progress_run_id or "",
                "message": (f"POE decision: {chain_result['confirmed']} of {chain_result['planned']} "
                            "planned chains produced independently confirmed evidence"),
                "confirmed": chain_result["confirmed"], "planned": chain_result["planned"],
                "target": target_label,
            })
        except Exception:  # noqa: BLE001 - live dialogue must never break a completed hunt
            pass

    # --- Submission packages (reportable findings; confirmed first; never re-package a
    # finding already reported in a prior run). ---
    submission_paths: list[str] = []
    sub_dir = out_root / "submissions"
    claimed_keys, claim_lock = submission_claim if submission_claim else (None, None)
    for rank_i, item in enumerate(consolidated, 1):
        if item.get("duplicate_of_prior"):
            continue  # already reported in a previous run — don't re-emit a package
        finding = item["finding"]
        # Cross-target dedup within a CONCURRENT span/portfolio: two targets of a wildcard program
        # can recon-expand to the same in-scope URL and surface the SAME finding (identical
        # dedup_key). duplicate_of_prior is decided at upsert time but the ledger isn't advanced to
        # 'reported' until below (after write_submission_package's disk I/O), so the per-ledger gate
        # can't stop two concurrent workers from EACH packaging it. Atomically claim the dedup_key
        # here so exactly one identical package is built across the span (no double-counted funnel,
        # no duplicate-report/spam risk if the bundle is bulk-filed).
        if claim_lock is not None:
            key = str(item.get("dedup_key") or "")
            if key:
                with claim_lock:
                    if key in claimed_keys:
                        continue  # another concurrent target already packaged this exact finding
                    claimed_keys.add(key)
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
            # Only advance the ledger to 'reported' for a CONFIRMED package. A candidate/unconfirmed
            # lead still gets its local package written above, but must NOT mark itself 'reported':
            # otherwise a later --active run that CONFIRMS the same finding sees the prior stage
            # (>= reported), is flagged duplicate_of_prior, and is skipped — its confirmed proof
            # package (screenshot/replay/differential) is never built and the operator is told a
            # payable bug was "already reported" when nothing was ever filed. (ledger.is_submitted's
            # own docstring warns against gating re-packaging on >= reported for exactly this reason.)
            if rt is not None and item["proof_status"] == "confirmed":
                ledger.mark_reported(rt, program, clean_target, finding)
                # Log confirmed findings to the learning store so outcomes can be recorded.
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
        "chain_signals": campaign_signals,
        # Resolve each finding's severity through its modelled cvss (matching the per-target
        # report tally) before counting, so an active-confirmed finding isn't under-reported.
        "severity_counts": _severity_counts([_resolved_severity_finding(item) for item in consolidated]),
        "risk": _campaign_risk([{"finding": _resolved_severity_finding(item)} for item in consolidated]),
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
    # urlparse('http://').hostname is None for a scheme-only/malformed seed — coalesce to '' before
    # .strip() so one bad seed is skipped, not allowed to crash the whole portfolio/span run.
    host = ((urlparse(raw).hostname if "://" in raw else raw) or "").strip().lower().strip("[]")
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


# Structured-scope asset types that are IN SCOPE but are not web endpoints, so a
# "hunt the whole scope" campaign must not derive a URL from one. Named in HackerOne's
# vocabulary, which yeswehack_import maps its own scope_type values onto. "OTHER" and ""
# are deliberately absent: CSV and hand-entered rows leave asset_type empty, and those
# must keep working exactly as before.
_NON_WEB_ASSET_TYPES = frozenset({
    "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "WINDOWS_APP_STORE_APP_ID", "OTHER_APK",
    "TESTFLIGHT", "SOURCE_CODE", "DOWNLOADABLE_EXECUTABLES", "HARDWARE", "SMART_CONTRACT",
})


def program_campaign_targets(program: dict[str, Any], max_targets: int = _MAX_PROGRAM_TARGETS) -> list[str]:
    """The list of concrete URLs a "hunt this program's whole scope" campaign should
    run. Uses ``seed_targets`` (an operator's own hand-curated hunt list) plus any
    explicitly opted-in ``repository_urls``; otherwise derives one representative,
    deduped target per ELIGIBLE ``structured_scope`` entry (a HackerOne API/CSV-imported
    program), so a program built purely from an imported scope table still has something
    to hunt. Bounded —
    this feeds directly into a real active-probing pipeline, never an unbounded fan-out.
    A host in the program's own out_of_scope_hosts is filtered out here too — it must
    never become the literal target of a hunt just because it was hand-typed as a seed
    or matched a wildcard structured_scope entry."""
    excluded_hosts = [str(h) for h in (program.get("out_of_scope_hosts") or [])]
    seeds = [str(t).strip() for t in (program.get("seed_targets") or []) if str(t or "").strip()]
    seeds = [t for t in seeds if not _target_host_excluded(t, excluded_hosts)]
    repositories = []
    if program.get("clone_repositories"):
        configured_repositories = list(program.get("repository_urls") or [])
        if not configured_repositories:
            configured_repositories = [
                entry.get("identifier") for entry in (program.get("structured_scope") or [])
                if isinstance(entry, dict) and entry.get("eligible_for_submission", True)
            ]
        repositories = [
            str(t).strip().rstrip("/") for t in configured_repositories
            if is_supported_remote_git_url(str(t or "").strip())
        ]
    # Seed targets still take precedence over derived web assets, but explicitly
    # opted-in repositories are additive: a program can hunt its app and source in
    # the same span/portfolio/operator cycle.
    explicit = list(dict.fromkeys(seeds + repositories))
    if explicit:
        return explicit[:max_targets]
    out: list[str] = []
    seen: set[str] = set()
    for entry in program.get("structured_scope") or []:
        if not isinstance(entry, dict) or not entry.get("eligible_for_submission", True):
            continue
        identifier = str(entry.get("identifier") or "").strip()
        # A forge repository is never fetched as a web page. It is included only
        # through the explicit clone_repositories opt-in above.
        if is_supported_remote_git_url(identifier):
            continue
        # Neither is a mobile app, a binary, a smart contract or source: those assets are
        # in scope for the PROGRAM but are not web endpoints, and deriving a target from
        # one sends traffic somewhere nobody authorized. A YesWeHack Android asset is
        # published as its store URL, so this row would otherwise schedule a scan of
        # play.google.com or apps.apple.com -- a third party -- and a bare package id like
        # "com.vendor.mobile" resolves to https://com.vendor.mobile, an unrelated host.
        # HackerOne imports carry the same asset types and the same hazard.
        if str(entry.get("asset_type") or "").strip().upper() in _NON_WEB_ASSET_TYPES:
            continue
        url = _representative_host(identifier)
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
    account_access: dict[str, Any] | None = None,
    user_agent_suffix: str = "",
    live: bool = False,
    program: str | None = None,
    max_pages: int = 12,
    osint: bool = False,
    platform: str = "hackerone",
    deep: bool = False,
    on_progress: Any = None,
    max_targets: int = _MAX_PROGRAM_TARGETS,
    disclose_automation: bool = False,
    excluded_hosts: tuple[str, ...] = (),
    admin_account_access: dict[str, Any] | None = None,
    idor_pairs: list[dict[str, Any]] | None = None,
    include_attack_map: bool = True,
    policy_profile: str = "",
    progress_run_id: str | None = None,
    progress_unit: str | None = None,
    # Forwarded verbatim to every per-target run_campaign — see _run_campaign_body for why the four
    # out-of-band provers were otherwise unreachable from any autonomous path.
    oob_base: str = "",
    oob_secret: str = "",
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

    # Log in to the program's research account ONCE for the whole span (not once per target), then
    # pass the resulting session to every target's run_campaign (which skips re-login when auth is set).
    if auth is None and account_access:
        auth = _login_auth(account_access, scope, excluded_hosts, _emit)

    # Shared submission claim: the span's targets run CONCURRENTLY (below), and two targets can
    # surface the same finding (identical dedup_key). This process-local set + lock lets each
    # inner run_campaign atomically claim a dedup_key before packaging, so exactly one identical
    # submission package is produced across the span instead of a race-duplicated pair.
    submission_claim: tuple[set[str], threading.Lock] = (set(), threading.Lock())

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
    # Every target's sub-finding clues, pooled. Chaining across targets is the only way to
    # see an attack whose halves live on different hosts.
    span_signals: list[dict[str, Any]] = []
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
                version=version, active=active, time_based=time_based, auth=auth,
                account_access=account_access, user_agent_suffix=user_agent_suffix, live=live,
                program=program, max_pages=max_pages, osint=osint, platform=platform, deep=deep,
                disclose_automation=disclose_automation, on_progress=_target_emit, excluded_hosts=excluded_hosts,
                admin_account_access=admin_account_access, idor_pairs=idor_pairs, include_attack_map=include_attack_map,
                policy_profile=policy_profile,
                progress_run_id=progress_run_id, progress_unit=unit,
                submission_claim=submission_claim,  # dedup identical findings across concurrent targets
                oob_base=oob_base, oob_secret=oob_secret,
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
        if isinstance(result.get("chain_signals"), list):
            span_signals.extend(result["chain_signals"])
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
    # CROSS-TARGET chaining. Each per-target hunt already chained within its own host; only
    # here do findings from different hosts sit in one graph, which is where the chains that
    # matter most in a wide scope live (a claimable subdomain on one host plus a
    # parent-domain session cookie on another is an account takeover neither hunt can see).
    span_investigation = _span_investigation(findings_out, plans_out, proof_out, span_signals,
                                             surface_urls, surface_tech)
    span_ctx = {
        "program": program or "", "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "version": version, "scope": scope, "targets_total": len(clean_targets), "targets_hunted": ok_count,
        "per_target": per_target, "errors": errors, "finding_count": len(findings_out), "confirmed_count": confirmed_count,
        "submission_count": len(submission_paths),
        "investigation": span_investigation,
        "chain_locations": _chain_locations(findings_out),
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
        "investigation": span_investigation,
        "chain_signals": span_signals,
        # Resolve severity through each finding's modelled cvss (cvss_out shares the C-ref key)
        # so the span tally matches each per-target report instead of the raw scanner label.
        "severity_counts": _severity_counts(
            [_resolved_severity_finding({"finding": f, "cvss": cvss_out.get(f.get("ref"), {})}) for f in findings_out]),
        "risk": _campaign_risk(
            [{"finding": _resolved_severity_finding({"finding": f, "cvss": cvss_out.get(f.get("ref"), {})})} for f in findings_out]),
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
    include_attack_map: bool = True,
    progress_run_id: str | None = None,
    max_concurrent_programs: int = _PORTFOLIO_MAX_PROGRAMS,
    # Forwarded to every program's span. The operator loop is the MOST autonomous path, so it is the
    # one where an unreachable prover costs the most: it runs unattended, for hours.
    oob_base: str = "",
    oob_secret: str = "",
) -> dict[str, Any]:
    # (policy_profile is per-program here; read from each spec below, not a portfolio-wide arg.)
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
                      "disclose_automation": bool(p.get("disclose_automation")),
                      "account_access": p.get("account_access") if isinstance(p.get("account_access"), dict) else {},
                      "admin_account_access": p.get("admin_account_access") if isinstance(p.get("admin_account_access"), dict) else {},
                      "idor_pairs": p.get("idor_pairs") if isinstance(p.get("idor_pairs"), list) else [],
                      "policy_profile": str(p.get("policy_profile") or ""),
                      "user_agent_suffix": str(p.get("user_agent_suffix") or "")})
    if not clean:
        return {"ok": False, "error": "No huntable programs — each needs seed targets, an opted-in source repository, or an imported/built structured scope."}

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
    span_signals: list[dict[str, Any]] = []
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
                account_access=spec["account_access"], admin_account_access=spec.get("admin_account_access"),
                idor_pairs=spec.get("idor_pairs"), policy_profile=spec.get("policy_profile", ""),
                user_agent_suffix=spec["user_agent_suffix"],
                excluded_hosts=spec["excluded_hosts"], include_attack_map=include_attack_map, on_progress=_p_emit,
                progress_run_id=progress_run_id, progress_unit=label,
                oob_base=oob_base, oob_secret=oob_secret,
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
        if isinstance(result.get("chain_signals"), list):
            span_signals.extend(result["chain_signals"])
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
    port_investigation = _span_investigation(findings_out, plans_out, proof_out, span_signals,
                                             surface_urls, surface_tech)
    port_ctx = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"), "version": version,
        "programs_total": len(clean), "programs_hunted": ok_count, "per_program": per_program, "errors": errors,
        "finding_count": len(findings_out), "confirmed_count": confirmed_count, "submission_count": len(submission_paths),
        "investigation": port_investigation,
        "chain_locations": _chain_locations(findings_out),
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
        "investigation": port_investigation,
        "chain_signals": span_signals,
        # Resolve severity through each finding's modelled cvss (cvss_out shares the C-ref key),
        # so the portfolio tally matches the per-program/per-target reports.
        "severity_counts": _severity_counts(
            [_resolved_severity_finding({"finding": f, "cvss": cvss_out.get(f.get("ref"), {})}) for f in findings_out]),
        "risk": _campaign_risk(
            [{"finding": _resolved_severity_finding({"finding": f, "cvss": cvss_out.get(f.get("ref"), {})})} for f in findings_out]),
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
    _append_cross_target_chains(out, ctx)
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


def _append_cross_target_chains(out: list[str], ctx: dict[str, Any]) -> None:
    """Render the chains the roll-up can see that no single target could.

    Only chains whose findings actually span more than one host are printed here — a chain
    confined to one target is already in that target's own report, and repeating it in the
    index is noise that buries the genuinely new, cross-host ones.
    """
    investigation = ctx.get("investigation") if isinstance(ctx.get("investigation"), dict) else {}
    chains = investigation.get("attack_chains") if isinstance(investigation.get("attack_chains"), list) else []
    locations = ctx.get("chain_locations") if isinstance(ctx.get("chain_locations"), dict) else {}

    def _hosts(chain: dict[str, Any]) -> set[str]:
        hosts: set[str] = set()
        for ref in chain.get("refs") or []:
            try:
                host = urlparse(str(locations.get(str(ref)) or "")).hostname
            except ValueError:
                host = None  # a malformed authority contributes no host, never an exception
            if host:
                hosts.add(host.lower())
        return hosts

    cross = [c for c in chains if isinstance(c, dict) and len(_hosts(c)) > 1]
    if not cross:
        return
    out.append("## Cross-target attack chains\n")
    out.append(
        "These chains link findings on DIFFERENT hosts, so no single target's report can show "
        "them. Each is an ordered path; a step is *proven* only when a captured artifact backs it."
    )
    out.append("")
    for chain in cross[:6]:
        refs = ", ".join(str(r) for r in (chain.get("refs") or [])[:6])
        out.append(
            f"- **{chain.get('id')} · {chain.get('title')}** ({chain.get('status')}, "
            f"{chain.get('proven_steps')}/{chain.get('step_count')} step(s) proven; refs: {refs}) — "
            f"{chain.get('why') or ''} **Close it next:** {chain.get('next_action') or ''}"
        )
    out.append("")


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
    _append_cross_target_chains(out, ctx)
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
        # The chain role travels with the submission body. A per-finding package is read on its
        # own, so without this the file the operator pastes into the platform prices the finding
        # as an isolated bug while the campaign report prices it as step 1 of an account
        # takeover — the report and the submission disagreeing about the same finding.
        "investigation": doc.get("investigation") or {},
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
