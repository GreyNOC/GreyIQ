"""GreyIQ BugHunter — IDOR / BOLA / broken access control (dual-session confirm).

The highest-paying bug-bounty class, and the one a single-session scanner cannot prove:
it needs TWO authenticated accounts. The operator supplies their own two test accounts
(authorized) and one object URL per account; the engine proves a cross-tenant read by a
three-request differential, GET-only and scope-bound:

    rA  = account A's session GET A's object   (ground truth: what A's object looks like)
    rBB = account B's session GET B's object   (control: B's session is valid + B's data)
    rBA = account B's session GET A's object    (the attack: can B read A's object?)

It confirms IDOR only when B's response to A's object is ~identical to A's OWN response
AND clearly different from B's own object (so it's a genuine cross-tenant read, not a
shared/static page or B's own data). Anything else is reported honestly as access-control
ENFORCED or an ambiguous candidate — never a false "confirmed".

SAFETY — the captured proof here is ANOTHER USER'S DATA (A's object that B read), so the
report NEVER includes the raw cross-tenant body; the proof is the DIFFERENTIAL only
(statuses + similarity ratios + a description). Each session is attached SAME-SITE only
(scan_auth), both URLs are scope-bound + SSRF-guarded, GET-only, no redirects followed.
"""

from __future__ import annotations

import difflib
from typing import Any
from urllib.parse import urlparse

from bughunter import impact_model
from bughunter.active_verify_service import (
    _ActiveError,
    _Http,
    host_in_active_scope,
)
from bughunter.rate_limit import HostRateGovernor
from bughunter.scan_auth import build_auth
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _guard_url

# Confirm thresholds (body similarity in [0,1] over whitespace-normalized, capped text).
# The dispositive signal is that B's response to A's object matches A's OWN response, and
# matches it MORE than it matches B's own object — so a cross-tenant read is told apart
# from a properly-scoped endpoint even when two users' records are structurally similar.
_SAME = 0.95      # B's response to A's object is ~identical to A's own response
_CANDIDATE = 0.80  # ...or only resembles A's (e.g. A's object inside B's page chrome) -> a lead to inspect
_MARGIN = 0.03    # ...and matches A at least this much MORE than it matches B's own object
_DISTINCT = 0.98  # A's and B's objects must differ at least this much (else static/shared page)
_BODY_CMP_CAP = 6000
_MIN_BODY = 24    # a near-empty 200 is not proof of reading anything


def _norm(body: str) -> str:
    return " ".join((body or "").split())[:_BODY_CMP_CAP]


def _ratio(a: str, b: str) -> float:
    na, nb = _norm(a), _norm(b)
    if not na and not nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


def _err(reason: str) -> dict[str, Any]:
    return {"ok": False, "error": reason}


_AC_META = {
    "class_id": "access-control",
    "class_name": "Broken access control (IDOR/BOLA)",
    "cwe": "CWE-639 / CWE-284",
    "owasp": "A01:2021 Broken Access Control",
}


def run_idor_check(
    url_a: str,
    url_b: str,
    *,
    account_a: dict[str, Any],
    account_b: dict[str, Any],
    scope: str = "",
    settings: Any = None,
    governor: HostRateGovernor | None = None,
) -> dict[str, Any]:
    """Confirm IDOR/BOLA via the dual-session differential. ``account_a``/``account_b``
    are ``{cookie, headers}`` (the operator's two test sessions). Returns
    ``{ok, status, ...}`` where status is ``confirmed`` | ``enforced`` | ``candidate``,
    plus (on confirmed/candidate) an annotated ``finding`` + ``attack_plan`` ready for the
    report pipeline, or ``{ok: False, error}`` on a setup/gate failure."""
    settings = settings or get_settings()
    ua, ub = str(url_a or "").strip(), str(url_b or "").strip()
    if not ua or not ub:
        return _err("Provide both object URLs: account A's object and account B's object.")
    if ua == ub:
        return _err("The two object URLs are identical — give A's object and a DIFFERENT object B owns.")
    try:
        na, nb = normalize_website_url(ua), normalize_website_url(ub)
    except WebsiteFetchError as exc:
        return _err(str(exc))
    host_a, host_b = (urlparse(na).hostname or ""), (urlparse(nb).hostname or "")
    if host_a.lower() != host_b.lower():
        return _err("Both object URLs must be on the same host (same app, two objects).")
    if not host_in_active_scope(host_a, scope, settings):
        return _err(f"'{host_a}' is not named in your scope — access-control testing is fail-closed. Add it to Scope.")
    try:
        sa = _guard_url(na, settings.allow_private_urls, settings.web_allowed_ports)
        sb = _guard_url(nb, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return _err(f"target refused by the URL guard: {exc}")

    auth_a = build_auth(sa, cookie=account_a.get("cookie", ""), headers=account_a.get("headers") or [])
    auth_b = build_auth(sb, cookie=account_b.get("cookie", ""), headers=account_b.get("headers") or [])
    if auth_a is None or auth_b is None:
        return _err("IDOR testing needs TWO sessions — supply a cookie and/or auth headers for BOTH account A and account B.")

    governor = governor or HostRateGovernor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http_a = _Http(settings, governor, max_requests=4, auth=auth_a)
    http_b = _Http(settings, governor, max_requests=4, auth=auth_b)
    try:
        r_a = http_a.fetch(sa)     # A reads A's object (ground truth)
        r_bb = http_b.fetch(sb)    # B reads B's own object (control)
        r_ba = http_b.fetch(sa)    # B reads A's object (the attack)
    except _ActiveError as exc:
        return _err(f"request failed: {exc}")

    body_a, body_bb, body_ba = (r_a.get("body") or ""), (r_bb.get("body") or ""), (r_ba.get("body") or "")
    st_a, st_bb, st_ba = int(r_a.get("status") or 0), int(r_bb.get("status") or 0), int(r_ba.get("status") or 0)

    # The control must hold for the test to mean anything: A can read A's object, and B
    # can read B's OWN object (B's session is valid). Otherwise we can't attribute.
    if st_a != 200 or len(_norm(body_a)) < _MIN_BODY:
        return {"ok": True, "status": "candidate", "reason": f"account A's object did not return a readable 200 (HTTP {st_a}) — check A's session / object URL.",
                "detail": {"status_a": st_a, "status_bb": st_bb, "status_ba": st_ba}}
    if st_bb != 200 or len(_norm(body_bb)) < _MIN_BODY:
        return {"ok": True, "status": "candidate", "reason": f"account B could not read its OWN object (HTTP {st_bb}) — B's session may be invalid/expired, so a cross-read can't be attributed.",
                "detail": {"status_a": st_a, "status_bb": st_bb, "status_ba": st_ba}}

    r_ba_a = _ratio(body_ba, body_a)     # B-on-A vs A-on-A  (did B get A's object?)
    r_ba_bb = _ratio(body_ba, body_bb)   # B-on-A vs B-on-B  (or did B just get its own/generic?)
    r_a_bb = _ratio(body_a, body_bb)     # A-on-A vs B-on-B  (are the two objects actually distinct?)
    detail = {"status_a": st_a, "status_bb": st_bb, "status_ba": st_ba,
              "ratio_BonA_vs_A": round(r_ba_a, 3), "ratio_BonA_vs_BownB": round(r_ba_bb, 3), "ratio_A_vs_BownB": round(r_a_bb, 3)}

    if r_a_bb >= _DISTINCT:
        # A's object and B's object return ~identical content -> the endpoint isn't
        # object-specific (a shared/static page). We can't prove a cross-tenant read.
        return {"ok": True, "status": "candidate", "reason": "account A's and B's objects returned near-identical content, so this endpoint isn't object-specific — pick two objects with visibly DIFFERENT data and re-test.", "detail": detail}

    # Confirmed: B's response to A's object is ~identical to A's OWN response AND matches A
    # by a clear margin MORE than it matches B's own object — i.e. B received A's specific
    # object, not its own (a properly-scoped endpoint would return B's data or a 403).
    margin = r_ba_a - r_ba_bb
    if st_ba == 200 and r_ba_a >= _SAME and margin >= _MARGIN:
        finding, plan = _build_finding(sa, sb, detail)
        return {"ok": True, "status": "confirmed", "finding": finding, "attack_plan": plan, "detail": detail}

    # Borderline lead: B's response RESEMBLES A's object (and more than B's own) but below
    # the auto-confirm bar — typically A's object wrapped in B's page chrome (SPA shell /
    # JSON in an HTML frame). Surface it as a candidate to inspect rather than silently
    # calling it enforced.
    if st_ba == 200 and r_ba_a >= _CANDIDATE and margin >= _MARGIN:
        return {"ok": True, "status": "candidate",
                "reason": (f"account B's response to A's object was {r_ba_a:.0%} similar to A's own (below the {_SAME:.0%} "
                           f"auto-confirm bar) but more similar to A than to B's own object — possible IDOR behind page "
                           f"chrome/SPA shell. Inspect the response manually within scope."),
                "detail": detail}

    # B was denied, redirected to login, or got its own/different data -> access control
    # held (or is at least not provably broken).
    return {"ok": True, "status": "enforced",
            "reason": f"account B did NOT obtain account A's object (HTTP {st_ba}; similarity to A {r_ba_a:.2f}). Access control appears enforced here.",
            "detail": detail}


def _build_finding(url_a: str, url_b: str, detail: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a fully-annotated access-control finding + its attack plan from a confirmed
    differential. The proof is the DIFFERENTIAL ONLY — never the cross-tenant body."""
    loc = f"{urlparse(url_a).path or '/'} (object id swapped between two accounts)"
    model = impact_model.impact_for_class("access-control")
    matched = (f"account B's session returned account A's object (HTTP {detail['status_ba']}); "
               f"body matched A's own response (similarity {detail['ratio_BonA_vs_A']}) and differed from "
               f"B's own object (similarity {detail['ratio_BonA_vs_BownB']})")
    finding = {
        "rule_id": "active.idor",
        "title": f"IDOR / broken access control at {urlparse(url_a).path or '/'}",
        "severity": "high",
        "confidence": "high",
        "category": "access-control",
        "location": url_a,
        "file_path": url_a,
        "line_start": 1, "line_end": 1,
        "class_id": _AC_META["class_id"], "class_name": _AC_META["class_name"],
        "cwe": _AC_META["cwe"], "owasp": _AC_META["owasp"],
        "references": impact_model.references_for_class("access-control"),
        "vrt": impact_model.bugcrowd_vrt("access-control"),
        "remediation": impact_model.remediation_for_class("access-control"),
        # NO body snippet: the proof body is another user's data — never embed it.
        "snippet": "",
        "proof_evidence": {
            "request_line": f"GET {url_a}",
            "request_header": "Cookie: <account B session>  (B's own credentials)",
            "response_status": f"HTTP {detail['status_ba']}",
            "matched_value": matched,
        },
    }
    plan = {
        "steps": [
            "Authenticate as account B (your second, lower-privilege test account).",
            f"With B's session, request account A's object: GET {url_a}",
            f"Observe HTTP {detail['status_ba']} returning A's object (body matched A's own response).",
            f"Control: with B's session, request B's OWN object ({url_b}) — it returns B's distinct data, proving the cross-tenant read.",
            "Note the object-id pattern (sequential / guessable?) and the blast radius (all users' objects).",
        ],
        "poc": (f"# As account B (B's own session), request account A's object id:\n"
                f"curl -s -i '{url_a}' -H 'Cookie: <B session>'\n"
                f"# -> HTTP {detail['status_ba']} with Account A's data (cross-tenant read)"),
        "impact": model.get("business_impact", ""),
        "cvss": impact_model.cvss_for_class("access-control"),
        "remediation": impact_model.remediation_for_class("access-control"),
        "proof_of_impact": {
            "status": "confirmed",
            "method": "dual-session object-id differential (GET-only, no data exfiltrated into the report)",
            "actor": "authenticated account B (no special privilege)",
            "affected_asset": "every other user's objects exposed by this endpoint",
            "observed_result": matched,
            "control_result": ("B reading B's own object returned distinct data, and A's vs B's objects differ "
                               f"(similarity {detail['ratio_A_vs_BownB']}) — so B's match to A is a genuine cross-tenant read, not a shared/static page"),
            "evidence": "B-on-A response ≈ A-on-A response, and ≠ B-on-B response (ratios captured; raw bodies withheld as they are another user's data)",
            "proof_obligation": model.get("proof_obligation", ""),
        },
    }
    return finding, plan
