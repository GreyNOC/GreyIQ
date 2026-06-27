"""GreyIQ BugHunter — guided next-step planner.

After a hunt runs, the operator's real question is *"what do I do now?"*. This
module turns a finished report context into an **ordered, prioritized action
plan** — concrete, sequenced steps the operator takes next, from stabilizing
scan coverage through confirming findings, hunting the high-value classes by
hand, chaining, and preparing a submission.

Pure / dependency-free / frozen-safe: it reads only the report context that
``bounty.run_bounty_hunt`` already assembled (findings, profile, focus class,
scan state, recommended tools). The optional LLM "brain" can *augment* the plan
with target-specific leads, but a useful plan is always produced offline.

Design notes
------------
* Steps are grouped into ordered **phases** (stabilize → confirm → hunt → chain
  → expand → submit → retest) and numbered 1..N across the whole plan, so the
  operator can work top to bottom.
* Confirmation steps are emitted highest-impact first, ranked by severity *and*
  confidence (a high-confidence medium can outrank a low-confidence high for
  where you spend the next hour).
* Every step is concrete: it names the finding ref, the first reproduction
  action, and the single best tool to reach for (from the curated toolkit).
"""

from __future__ import annotations

from typing import Any

# Severity / confidence → numeric weight. A finding's "act on this next" score is
# severity-dominant but confidence-aware, so we don't send the operator chasing a
# low-confidence lead before a solid one.
_SEVERITY_WEIGHT = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}
_CONFIDENCE_WEIGHT = {"high": 9, "medium": 5, "low": 2, "unknown": 3, "": 3}

# Intrinsic bounty value per class — the tie-breaker that floats the
# higher-payout, higher-impact bug types first *within* a severity band (it never
# overrides severity, since the gap between severity tiers dwarfs this range).
_CLASS_VALUE = {
    "rce": 8, "ssti": 7, "sqli": 7, "ssrf": 7, "nosqli": 6,
    "access-control": 6, "auth": 6, "xxe": 6, "jwt": 6, "secrets": 6,
    "request-smuggling": 5, "graphql": 5, "file-upload": 5, "business-logic": 5,
    "race-condition": 5, "supply-chain": 4, "subdomain-takeover": 4, "cloud-exposure": 4,
    "xss": 4, "csrf": 4, "cors": 3, "redirect": 3, "prototype-pollution": 3,
    "crypto": 2, "disclosure": 2, "network": 2, "headers": 1,
}

# How many findings get their own confirmation step before the rest are batched
# into a single "work through the remaining N" step (keeps the plan scannable).
_MAX_INDIVIDUAL_CONFIRMS = 8

# Findings at/above this severity are treated as "high-impact" for submission
# ordering and individual confirmation.
_HIGH_IMPACT = {"critical", "high"}

# Class-pairs that combine into a stronger report. Mirrors the report's triage
# chain notes but framed as a *do-this* action.
_CHAIN_ACTIONS: list[tuple[set[str], str]] = [
    ({"disclosure", "access-control"}, "Combine the information disclosure with the access-control lead — leaked ids/paths often turn a maybe-IDOR into a confirmed BOLA."),
    ({"secrets", "auth"}, "Pair the exposed secret with the auth/session weakness — test whether the credential plus a session flaw reaches account or environment takeover."),
    ({"redirect", "auth"}, "Walk the open redirect through the auth flow (login, OAuth, reset) and measure token-leak or phishing impact."),
    ({"cors", "auth"}, "Prove a credentialed cross-origin read with the CORS misconfig against an authenticated endpoint — that is what raises it above informational."),
    ({"supply-chain", "secrets"}, "Trace the build/dependency issue toward release secrets or deploy artifacts; reaching them turns a moderate into a high."),
    ({"xss", "auth"}, "Chain the XSS with session handling — show cookie/session theft or an authenticated action to lift it past self-XSS."),
    ({"ssrf", "cloud-exposure"}, "Point the SSRF at cloud metadata (169.254.169.254) — reaching instance credentials turns a medium SSRF into a critical."),
    ({"xxe", "ssrf"}, "Use the XXE as an SSRF primitive — internal service reach or OOB file read is what makes it report-worthy."),
    ({"subdomain-takeover", "auth"}, "A claimable subdomain inside the auth/cookie scope can capture sessions or pass OAuth allow-lists — test that reach."),
    ({"prototype-pollution", "xss"}, "Land the prototype-pollution gadget on a sink (XSS/auth bypass) — pollution without a gadget usually closes as informational."),
    ({"access-control", "graphql"}, "Walk GraphQL field-level authorization for the same object-id weakness — BOLA via a hidden query is a common high."),
]

# Per-profile expansion advice: how to broaden coverage once the first pass is
# triaged. Keyed by profile id; falls back to a generic note.
_EXPANSION_BY_PROFILE: dict[str, str] = {
    "web-app": "Spider past the landing page: enumerate forms, query params, JSON bodies, and upload points, then re-scan the authenticated areas with a logged-in session.",
    "api": "Enumerate the full route surface (swagger/openapi, JS bundles, mobile traffic) and diff responses across roles for the same object id (BOLA).",
    "source-code": "Raise the file cap or point the scan at the whole tree, then trace untrusted input (request/env/file) to each flagged sink to confirm reachability.",
    "secrets": "Check served JS bundles, source maps, and .env-style files, and scan git history — secrets are most often in deleted commits and old branches.",
    "full-sweep": "Pick the highest-severity class this sweep surfaced and switch to that focused profile for a deeper, class-specific pass.",
}


def _sev(finding: dict[str, Any]) -> str:
    return str(finding.get("severity") or "info").lower()


def _conf(finding: dict[str, Any]) -> str:
    return str(finding.get("confidence") or "unknown").lower()


def _priority_score(finding: dict[str, Any]) -> int:
    class_id = str(finding.get("class_id") or "")
    return (
        _SEVERITY_WEIGHT.get(_sev(finding), 5)
        + _CONFIDENCE_WEIGHT.get(_conf(finding), 3)
        + _CLASS_VALUE.get(class_id, 2)
    )


def _tool_for_class(class_id: str, recommended_tools: list[dict[str, Any]] | None) -> str:
    """The single best curated tool for a finding's class — the first recommended
    tool whose ``maps_to`` covers it (recommended_tools is already relevance-ranked)."""
    if not class_id:
        return ""
    for tool in recommended_tools or []:
        if class_id in (tool.get("maps_to") or []):
            return str(tool.get("name") or "")
    return ""


def _first_actions(ref: str, attack_plans: dict[str, Any], fallback: list[str]) -> str:
    """The most concrete opening move for a finding: the first 1-2 reproduction
    steps from its attack plan, else the first class-checklist item."""
    plan = (attack_plans or {}).get(ref) or {}
    steps = [str(s).strip() for s in (plan.get("steps") or []) if str(s).strip()]
    # Skip the generic "Locate the issue at ..." lead the deterministic planner
    # prepends — the operator wants the *test*, not "go look at it".
    meaningful = [s for s in steps if not s.lower().startswith("locate the issue")]
    chosen = (meaningful or steps)[:2]
    if chosen:
        return " ".join(chosen)
    for item in fallback:
        if str(item).strip():
            return str(item).strip()
    return "Confirm the lead is reachable from untrusted input, then capture request/response evidence."


def chain_actions(findings: list[dict[str, Any]]) -> list[str]:
    """Do-this chain notes for the class combinations present in the findings."""
    present = {str(f.get("class_id") or f.get("category") or "").lower() for f in findings}
    return [note for required, note in _CHAIN_ACTIONS if required <= present]


def coverage_summary(ctx: dict[str, Any]) -> dict[str, Any]:
    """What the hunt did and did *not* cover — so the operator knows where the
    blind spots are. Pure derivation from the run context."""
    scanners = ctx.get("scanners_run") or []
    kind = str(ctx.get("kind") or "")
    covered: list[str] = []
    gaps: list[str] = []
    if "code" in scanners:
        covered.append("Static source analysis (injection sinks, secrets, deps, CI, backdoors).")
    if "web" in scanners:
        covered.append("Passive web review (headers, cookies, mixed content, client sinks, disclosure).")
    if "live" in scanners:
        covered.append("Dynamic browser pass (runtime console/network telemetry).")
    verified = ctx.get("active_verified_classes") or []
    if verified:
        covered.append(f"Active verification (authorized, rate-limited) confirmed by captured artifact: {', '.join(verified)}.")
    if not covered:
        covered.append("No scanner completed — coverage is effectively nil.")

    # Gaps the automated pass structurally cannot cover.
    if kind == "url" and "live" not in scanners:
        gaps.append("No dynamic/runtime pass — DOM XSS and client-rendered flows are unverified. Re-run with the live browser pass on.")
    gaps.append("No authenticated testing — IDOR/BOLA, broken access control, and workflow abuse need a logged-in session and a second account.")
    if kind in {"path", "git"}:
        gaps.append("Static scan only — reachability of each sink from real untrusted input is unconfirmed.")
    if kind == "git":
        gaps.append("Git history (deleted commits, old branches) is not scanned for secrets.")
    if ctx.get("scan_errors"):
        gaps.append("One or more scanners errored — this result is partial, not a clean bill of health.")
    return {"covered": covered, "gaps": gaps}


def build_next_steps(ctx: dict[str, Any], brain_next_steps: list[str] | None = None) -> list[dict[str, Any]]:
    """Build the ordered, numbered operator action plan from a report context.

    Each step: ``{order, phase, priority, action, detail, ref, tool}``. ``order``
    is 1-based across the whole plan; ``priority`` is a severity word for
    finding-bound steps or an action tier (``setup``/``hunt``/``submit``/
    ``retest``) for procedural ones.
    """
    findings: list[dict[str, Any]] = list(ctx.get("findings") or [])
    attack_plans = ctx.get("attack_plans") or {}
    recommended_tools = ctx.get("recommended_tools") or []
    manual_checklist = [str(s).strip() for s in (ctx.get("manual_checklist") or []) if str(s).strip()]
    profile = ctx.get("profile") or {}
    profile_id = str(profile.get("id") or "")
    vuln_class = ctx.get("vuln_class") or None
    kind = str(ctx.get("kind") or "")

    steps: list[dict[str, Any]] = []

    def add(phase: str, priority: str, action: str, detail: str, ref: str = "", tool: str = "") -> None:
        steps.append({"phase": phase, "priority": priority, "action": action, "detail": detail, "ref": ref, "tool": tool})

    # --- Phase 1 · Stabilize coverage (only when something is missing) ---
    scan_errors = ctx.get("scan_errors") or []
    scanners = ctx.get("scanners_run") or []
    if scan_errors:
        add(
            "Stabilize coverage", "setup",
            "Restore scanner access and re-run",
            "A scanner errored, so this is a partial result — a low finding count here does NOT mean the target is clean. "
            "Fix the access issue (" + "; ".join(str(e) for e in scan_errors[:3]) + ") and run the hunt again before trusting it.",
        )
    if kind == "url" and "live" not in scanners and not ctx.get("run_live_requested"):
        add(
            "Stabilize coverage", "setup",
            "Add a dynamic (live browser) pass",
            "The pass so far was a single passive GET. Re-run with the live browser pass on to catch DOM-based XSS, "
            "client-rendered sinks, and runtime console/network leaks the static pass can't see.",
        )

    # --- Phase 2 · Confirm findings (highest impact first) ---
    ranked = sorted(findings, key=_priority_score, reverse=True)
    individual = ranked[:_MAX_INDIVIDUAL_CONFIRMS]
    remainder = ranked[_MAX_INDIVIDUAL_CONFIRMS:]
    for finding in individual:
        ref = str(finding.get("ref") or "")
        sev = _sev(finding)
        class_id = str(finding.get("class_id") or "")
        class_name = str(finding.get("class_name") or finding.get("category") or "issue")
        title = str(finding.get("title") or "Finding")
        class_checklist = []  # class-specific fallback comes from the attack plan already
        opening = _first_actions(ref, attack_plans, class_checklist)
        tool = _tool_for_class(class_id, recommended_tools)
        detail = (
            f"{class_name} at {finding.get('location') or 'the flagged location'}. "
            f"Start here: {opening} "
            "Capture the exact request/response and the before/after state as evidence."
        )
        add("Confirm findings", sev, f"Confirm {ref}: {title}".strip(), detail, ref=ref, tool=tool)
    if remainder:
        lows = ", ".join(str(f.get("ref") or "") for f in remainder[:12])
        add(
            "Confirm findings", "low",
            f"Triage the remaining {len(remainder)} lower-priority finding(s)",
            f"Work through {lows}{' …' if len(remainder) > 12 else ''} as a batch. Treat low/info items as hardening "
            "unless one chains into something with real impact.",
        )

    # --- Phase 3 · Hunt the high-value classes by hand ---
    if vuln_class:
        focus_name = str(vuln_class.get("name") or vuln_class.get("id") or "the focus class")
        if ctx.get("focus_unmatched"):
            other = ctx.get("other_findings_count") or 0
            extra = f" The scanners found {other} finding(s) of other classes — re-run with 'Any class' to see them." if other else ""
            add(
                "Hunt by hand", "hunt",
                f"Manually hunt {focus_name} — this is where the value is",
                "The automated pass found nothing for this class, which is expected: it needs manual testing. "
                f"Work the {focus_name} checklist methodically against in-scope input points.{extra}",
            )
        else:
            add(
                "Hunt by hand", "hunt",
                f"Extend the {focus_name} hunt beyond the automated leads",
                f"The scanners surfaced starting points; manually probe the rest of the {focus_name} surface using the checklist.",
            )
    elif manual_checklist:
        top = manual_checklist[:3]
        add(
            "Hunt by hand", "hunt",
            "Work the manual-testing checklist",
            "These are leads the scanners can't confirm on their own. Start with: " + " / ".join(top)
            + (f"  (+{len(manual_checklist) - len(top)} more in the checklist below)" if len(manual_checklist) > 3 else ""),
        )

    # Brain-suggested, target-specific leads fold into the hunt phase.
    for lead in (brain_next_steps or [])[:5]:
        text = str(lead).strip()
        if text:
            add("Hunt by hand", "hunt", "Analyst lead", text)

    # --- Phase 4 · Chain & escalate ---
    for note in chain_actions(findings):
        add("Chain & escalate", "chain", "Chain related findings for higher impact", note)

    # --- Phase 5 · Expand coverage ---
    expansion = _EXPANSION_BY_PROFILE.get(profile_id) or _EXPANSION_BY_PROFILE["full-sweep"]
    add("Expand coverage", "expand", "Broaden the next pass", expansion)

    # --- Phase 6 · Prepare submission (severity-aware) ---
    counts = {sev: 0 for sev in _SEVERITY_WEIGHT}
    for finding in findings:
        s = _sev(finding)
        if s in counts:
            counts[s] += 1
    high_impact = counts["critical"] + counts["high"]
    top_ref = next((str(f.get("ref") or "") for f in ranked if _sev(f) in _HIGH_IMPACT), "")
    if high_impact:
        lead = f"Lead with {top_ref}. " if top_ref else ""
        add(
            "Prepare submission", "submit",
            "Write up and submit the high-impact finding(s) first",
            f"{lead}One report per root cause. Run the submission preflight (scope named, clean-session repro, "
            "impact in bounty-review language, concrete fix) before filing.",
            ref=top_ref,
        )
    elif counts["medium"]:
        add(
            "Prepare submission", "submit",
            "Validate the medium finding(s) for real impact before filing",
            "Confirm exploitability or a chain that raises severity; a bare medium with no demonstrated impact is often "
            "closed as informational. File only what you can prove.",
        )
    else:
        add(
            "Prepare submission", "submit",
            "Decide whether the low/info items are worth a report",
            "Treat these as hardening unless a policy-approved chain raises impact. If nothing is eligible, the value of "
            "this run is the manual checklist and the expanded next pass.",
        )

    # --- Phase 7 · Retest after fix (always last) ---
    add(
        "Retest after fix", "retest",
        "Retest once the owner ships a fix",
        "Replay the original proof, then try the closest bypass variants (alternate verb, content-type, role, object id, "
        "encoding) and confirm the server-side action — not just the client path — is actually closed.",
    )

    for i, step in enumerate(steps, 1):
        step["order"] = i
    return steps
