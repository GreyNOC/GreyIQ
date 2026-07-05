"""VDP policy profiles — a program's rules of engagement, encoded from its Vulnerability Disclosure
Policy and applied to the hunt so GreyIQ operates strictly within that program's authorized scope and
reporting guidelines. A profile pins the in-scope hosts, the endpoints/classes the program will NOT
accept, and whether only exploitability-demonstrated (confirmed) findings may be reported.

First profile: **NASA VDP** (https://bugcrowd.com/engagements/nasa-vdp). Applying it makes "NASA mode":
same engine, constrained to the NASA program's scope + reporting rules.

Pure/leaf module (stdlib only). The engine's own scope + SSRF gates still apply independently — a
profile only NARROWS what is probed/reported, it can never widen scope or authorize anything.
"""

from __future__ import annotations

from typing import Any

# --- NASA VDP -------------------------------------------------------------------------------------
_NASA: dict[str, Any] = {
    "id": "nasa",
    "name": "NASA VDP",
    "program_name": "NASA VDP",
    # The only registered domains in scope (subdomains included by the engine's scope matcher).
    "scope_hosts": ("nasa.gov", "usgeo.gov", "globe.gov", "nspires.nasaprs.com", "nsc.nasa.gov"),
    # Endpoints the policy explicitly does NOT authorize reports for — never reported (substring match
    # on a finding's location, case-insensitive).
    "excluded_path_substrings": ("/wp-json/wp/v2/users", "xmlrpc.php"),
    # Finding classes the policy rejects outright (missing best-practices / non-sensitive clickjacking /
    # missing-CSRF-token) — dropped even if the engine flagged them.
    "always_rejected_rule_ids": (
        "active.clickjacking",          # "Clickjacking on pages with no sensitive actions"
        "active.csrf-missing-token",    # "Missing best practices"
    ),
    # NASA rejects "reports from automated tools or scans without accompanying demonstration of
    # exploitability" and "software/library version disclosure without exploitability" — so ONLY
    # findings with a captured proof of exploit (proof_status == confirmed) are reportable.
    "confirmed_only": True,
    # No Denial-of-Service / rate-limit / spam testing, and no aggressive time-based probing.
    "avoid_dos": True,
    "report_channel": "Bugcrowd — https://bugcrowd.com/engagements/nasa-vdp",
    "disclosure_days": 90,
    "notes": (
        "NASA VDP rules of engagement: test ONLY the in-scope registered domains (internal-only and "
        "vendor/contractor systems are out of scope). Prefer a non-production/test environment where one "
        "exists (e.g. test.gcn.nasa.gov, NOT gcn.nasa.gov). Only confirmed, exploitability-demonstrated "
        "findings are reportable; no DoS/rate-limit/spam; only use exploits to the extent needed to "
        "confirm — no data modification, exfiltration, persistence, or pivoting. STOP and report "
        "immediately if sensitive data (PII, financial, ITAR/EAR, 'Top Secret') is encountered. Report via "
        "Bugcrowd (nasa-vdp); keep confidential for 90 days coordinated disclosure. No compensation (LORs "
        "only, for validated+fixed P1-P4)."
    ),
}

PROFILES: dict[str, dict[str, Any]] = {"nasa": _NASA}


def get_profile(name: str | None) -> dict[str, Any] | None:
    """The VDP profile for ``name`` (case-insensitive), or None if unknown / empty."""
    return PROFILES.get(str(name or "").strip().lower()) or None


def scope_text(profile: dict[str, Any]) -> str:
    """The profile's in-scope hosts as newline-joined scope text for a saved program."""
    return "\n".join(profile.get("scope_hosts") or ())


def program_preset(name: str) -> dict[str, Any] | None:
    """A ready-to-save program record for a profile (scope + policy binding + disclosure), or None.
    The operator saves this to create e.g. the NASA program in one click."""
    p = get_profile(name)
    if not p:
        return None
    hosts = list(p.get("scope_hosts") or ())
    return {
        "name": p["program_name"],
        "platform": "bugcrowd",
        "scope_text": scope_text(p),
        "in_scope_hosts": hosts,
        # A structured-scope row per in-scope host so the program is immediately huntable via
        # "span this program's whole scope" too (not only single-target). Purely a convenience seed —
        # the engine's scope + SSRF gates and this profile's own narrowing still bound every request.
        "structured_scope": [
            {"identifier": h, "asset_type": "URL", "eligible_for_submission": True} for h in hosts
        ],
        "policy_profile": p["id"],
        "disclose_automation": True,   # a VDP submission should note automated-tool assistance
        "notes": p["notes"],
    }


def _excluded_path(location: str, profile: dict[str, Any]) -> bool:
    low = str(location or "").lower()
    return any(sub in low for sub in profile.get("excluded_path_substrings") or ())


def filter_findings(consolidated: list[dict[str, Any]], profile: dict[str, Any]
                    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply a VDP profile to a campaign's consolidated findings — return ``(kept, dropped)``. A finding
    is DROPPED (not reportable under this program's policy) when its location hits an excluded endpoint,
    its rule is an always-rejected class, or (confirmed_only) it lacks a captured proof of exploit.
    ``dropped`` items carry a one-line ``reason`` so the operator sees WHY (transparency, never silent).
    Never raises; a malformed item is kept (fail-open — the profile only narrows, and the engine's own
    gates still apply)."""
    if not profile:
        return list(consolidated or []), []
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    excluded = tuple(profile.get("always_rejected_rule_ids") or ())
    confirmed_only = bool(profile.get("confirmed_only"))
    for item in (consolidated or []):
        try:
            finding = item.get("finding") if isinstance(item.get("finding"), dict) else {}
            rule = str(finding.get("rule_id") or "")
            status = str(item.get("proof_status") or finding.get("proof_status") or "")
            location = finding.get("location") or finding.get("file_path") or ""
            reason = ""
            if _excluded_path(location, profile):
                reason = "excluded endpoint — this program's policy does not authorize reports here"
            elif rule in excluded:
                reason = "class not accepted by this program's policy (missing best-practice / non-sensitive)"
            elif confirmed_only and status != "confirmed":
                reason = "not confirmed — policy requires a demonstrated proof of exploitability"
            if reason:
                dropped.append({"ref": finding.get("ref"), "rule_id": rule, "title": finding.get("title"),
                                "status": status, "reason": reason})
            else:
                kept.append(item)
        except Exception:  # noqa: BLE001 - a policy filter must never break a hunt
            # Fail SAFE, not merely fail-open: if the item couldn't be evaluated and the program is
            # confirmed-only, we cannot vouch that it carries a captured proof of exploit — so WITHHOLD
            # it (never over-report to a VDP program that rejects unconfirmed findings). Without
            # confirmed_only the engine's own scope/SSRF gates still apply, so keep it.
            if confirmed_only:
                dropped.append({"ref": None, "rule_id": "", "title": None, "status": "",
                                "reason": "could not evaluate under confirmed-only policy — withheld to avoid over-reporting"})
            else:
                kept.append(item)
    return kept, dropped
