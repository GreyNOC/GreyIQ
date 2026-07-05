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
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse

import json
import urllib.error
import urllib.request

from bughunter import impact_model
from bughunter.active_verify_service import (
    _ActiveError,
    _Http,
    _NoRedirect,
    _with_query,
    host_in_active_scope,
)
from bughunter.rate_limit import HostRateGovernor
from bughunter.scan_auth import auth_headers_for, build_auth
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, guarded_dns_scope, normalize_website_url
from bughunter.web_scan_service import _USER_AGENT, _guard_url, current_user_agent

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
              "ratio_BonA_vs_A": round(r_ba_a, 3), "ratio_BonA_vs_BownB": round(r_ba_bb, 3), "ratio_A_vs_BownB": round(r_a_bb, 3),
              # Normalized response lengths — the concrete differential proving B received A's object.
              "len_BonA": len(_norm(body_ba)), "len_BownB": len(_norm(body_bb)), "len_A": len(_norm(body_a))}

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


_ANON_DENIED = 0.80   # an anonymous request must look clearly UNLIKE the admin response
                      # (denied / login / different) for the endpoint to count as protected

# IDOR id-mutation probe bands. A neighbouring id that returns a 200 whose body is the SAME
# TEMPLATE but DIFFERENT DATA (similarity in [floor, same)) is a distinct valid object — a
# likely missing per-object check. Identical (>= same) is the same/static object; below floor
# is a different page / error, not an enumerable object.
_PROBE_SAME = 0.98
_PROBE_FLOOR = 0.45
_ID_PATH_RE = re.compile(r"(?<=/)(\d{1,12})(?=/|$)")


def _id_positions(url: str) -> list[tuple[str, Any, str]]:
    """Numeric ids to mutate: ``("path", (start, end), value)`` for path segments and
    ``("query", key, value)`` for digit-valued query params."""
    parsed = urlparse(url)
    out: list[tuple[str, Any, str]] = []
    for m in _ID_PATH_RE.finditer(parsed.path):
        out.append(("path", (m.start(), m.end()), m.group(1)))
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        if v.isdigit():
            out.append(("query", k, v))
    return out


def _mutate_id(url: str, kind: str, key: Any, new_value: str) -> str:
    if kind == "query":
        return _with_query(url, {key: new_value})
    parsed = urlparse(url)
    start, end = key
    return urlunparse(parsed._replace(path=parsed.path[:start] + new_value + parsed.path[end:]))


def run_idor_probe(
    url: str,
    *,
    account: dict[str, Any],
    scope: str = "",
    settings: Any = None,
    governor: HostRateGovernor | None = None,
    max_ids: int = 2,
) -> dict[str, Any]:
    """Single-session IDOR DISCOVERY (GET-only): mutate the numeric ids in the URL — path
    segments and query values, including a URL carrying two ids — and flag when a neighbouring
    id returns a DISTINCT valid object (same template, different data) without re-auth, i.e. a
    likely missing per-object authorization. CANDIDATE-grade: one session can't prove the
    neighbour belongs to ANOTHER tenant, so it points the operator at the dual-session IDOR
    confirm. Returns ``{ok, status, finding?, attack_plan?, detail}``."""
    settings = settings or get_settings()
    u = str(url or "").strip()
    if not u:
        return _err("Provide an authenticated object URL containing a numeric id (path or query).")
    try:
        nu = normalize_website_url(u)
    except WebsiteFetchError as exc:
        return _err(str(exc))
    host = urlparse(nu).hostname or ""
    if not host_in_active_scope(host, scope, settings):
        return _err(f"'{host}' is not named in your scope — access-control testing is fail-closed. Add it to Scope.")
    try:
        su = _guard_url(nu, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return _err(f"target refused by the URL guard: {exc}")
    auth = build_auth(su, cookie=account.get("cookie", ""), headers=account.get("headers") or [])
    if auth is None:
        return _err("Provide your authenticated session (a cookie and/or auth headers) so the probe reads YOUR object.")

    positions = _id_positions(su)
    if not positions:
        return {"ok": True, "status": "no-id", "reason": "no numeric id found in the URL path or query to mutate."}

    governor = governor or HostRateGovernor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http = _Http(settings, governor, max_requests=2 + max_ids * 2, auth=auth)
    try:
        r0 = http.fetch(su)
    except _ActiveError as exc:
        return _err(f"request failed: {exc}")
    if int(r0.get("status") or 0) != 200 or len(_norm(r0.get("body") or "")) < _MIN_BODY:
        return {"ok": True, "status": "candidate",
                "reason": f"the original object did not return a readable 200 (HTTP {r0.get('status')}) — check the URL and session."}

    body0 = r0.get("body") or ""
    tried: list[str] = []
    for kind, key, value in positions[:max_ids]:
        for delta in (1, -1):
            neighbour = int(value) + delta
            if neighbour < 0:
                continue
            mutated = _mutate_id(su, kind, key, str(neighbour))
            if mutated == su:
                continue
            try:
                rn = http.fetch(mutated)
            except _ActiveError:
                continue
            tried.append(mutated)
            st = int(rn.get("status") or 0)
            ratio = _ratio(rn.get("body") or "", body0)
            if st == 200 and len(_norm(rn.get("body") or "")) >= _MIN_BODY and _PROBE_FLOOR <= ratio < _PROBE_SAME:
                detail = {"original": su, "mutated": mutated, "old_id": value, "new_id": str(neighbour),
                          "ratio_neighbour_vs_original": round(ratio, 3), "status": st}
                finding, plan = _build_probe_finding(su, mutated, value, str(neighbour), detail)
                return {"ok": True, "status": "candidate", "finding": finding, "attack_plan": plan, "detail": detail}

    return {"ok": True, "status": "enforced",
            "reason": ("mutating the id returned no distinct valid object (denied, identical, or a different page). "
                       "No IDOR signal from a single session here."),
            "detail": {"tried": tried}}


def _build_probe_finding(original: str, mutated: str, old_id: str, new_id: str,
                         detail: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """A candidate IDOR finding from the single-session id-mutation probe. The neighbour body
    is NEVER embedded (it may be another user's data) — the proof is the differential."""
    path = urlparse(original).path or "/"
    model = impact_model.impact_for_class("access-control")
    matched = (f"changing the id {old_id} -> {new_id} returned a DISTINCT valid object (HTTP 200; body similarity to the "
               f"original {detail['ratio_neighbour_vs_original']} — same template, different data) with the same session")
    finding = {
        "rule_id": "active.idor-probe",
        "title": f"Possible IDOR: object id is mutable at {path} (single-session probe)",
        "severity": "medium",
        "confidence": "medium",  # single session can't prove cross-tenant ownership
        "category": "access-control",
        "location": original,
        "file_path": original,
        "line_start": 1, "line_end": 1,
        "class_id": _AC_META["class_id"], "class_name": _AC_META["class_name"],
        "cwe": _AC_META["cwe"], "owasp": _AC_META["owasp"],
        "references": impact_model.references_for_class("access-control"),
        "vrt": impact_model.bugcrowd_vrt("access-control"),
        "remediation": impact_model.remediation_for_class("access-control"),
        "snippet": "",  # neighbour body withheld (possible another user's data)
        "proof_evidence": {
            "request_line": f"GET {mutated}",
            "request_header": "Cookie: <your own session>",
            "response_status": "HTTP 200",
            "matched_value": matched,
        },
    }
    plan = {
        "steps": [
            f"With your session, request the object: GET {original}",
            f"Change the id {old_id} -> {new_id} and request: GET {mutated}",
            "Observe a DISTINCT valid object returned (same template, different data) — the endpoint serves objects by id without a per-object ownership check.",
            "CONFIRM cross-tenant access with the dual-session IDOR check (your two accounts): prove account B reads account A's object.",
        ],
        "poc": (f"# Same session, neighbouring id:\n"
                f"curl -s -i '{original}' -H 'Cookie: <session>'   # your object\n"
                f"curl -s -i '{mutated}' -H 'Cookie: <session>'   # a DIFFERENT valid object via id {new_id}"),
        "impact": model.get("business_impact", ""),
        "cvss": impact_model.cvss_for_class("access-control"),
        "remediation": impact_model.remediation_for_class("access-control"),
        "proof_of_impact": {
            "status": "candidate",
            "method": "single-session id-mutation probe (GET-only, no data exfiltrated into the report)",
            "actor": "the authenticated test account (one session)",
            "affected_asset": "objects addressable by a guessable/sequential id at this endpoint",
            "observed_result": matched,
            "control_result": "the original id returned your object; a neighbouring id returned a different valid object of the same shape",
            "evidence": "neighbour-id response is a distinct same-template 200 (ratios captured; body withheld)",
            "proof_obligation": ("Confirm CROSS-TENANT access with the dual-session IDOR check (two accounts) — a single "
                                 "session can't prove the neighbouring object belongs to another user."),
        },
    }
    return finding, plan


def run_bfla_check(
    priv_url: str,
    *,
    admin_account: dict[str, Any],
    user_account: dict[str, Any],
    scope: str = "",
    settings: Any = None,
    governor: HostRateGovernor | None = None,
) -> dict[str, Any]:
    """Confirm BFLA (broken function-level authorization) on a PRIVILEGED endpoint via a
    three-session differential, GET-only and scope-bound:

        r_admin = high-privilege session GET priv_url   (ground truth: the authorized response)
        r_user  = low-privilege session  GET priv_url    (the attack: does the user get it too?)
        r_anon  = NO session             GET priv_url    (control: is the endpoint protected at all?)

    Confirms only when the low-privilege user's response is ~identical to the ADMIN response
    AND an anonymous request is denied/different (so the function is genuinely access-controlled,
    not a public page). As with IDOR, the proof is the DIFFERENTIAL only — the privileged body
    (which may be another user's / sensitive data) is never embedded."""
    settings = settings or get_settings()
    u = str(priv_url or "").strip()
    if not u:
        return _err("Provide the privileged endpoint URL to test (e.g. the admin/API function).")
    try:
        nu = normalize_website_url(u)
    except WebsiteFetchError as exc:
        return _err(str(exc))
    host = urlparse(nu).hostname or ""
    if not host_in_active_scope(host, scope, settings):
        return _err(f"'{host}' is not named in your scope — access-control testing is fail-closed. Add it to Scope.")
    try:
        su = _guard_url(nu, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return _err(f"target refused by the URL guard: {exc}")

    auth_admin = build_auth(su, cookie=admin_account.get("cookie", ""), headers=admin_account.get("headers") or [])
    auth_user = build_auth(su, cookie=user_account.get("cookie", ""), headers=user_account.get("headers") or [])
    if auth_admin is None or auth_user is None:
        return _err("BFLA testing needs TWO sessions — supply a cookie and/or auth headers for BOTH the high-privilege and the low-privilege account.")

    governor = governor or HostRateGovernor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http_admin = _Http(settings, governor, max_requests=3, auth=auth_admin)
    http_user = _Http(settings, governor, max_requests=3, auth=auth_user)
    http_anon = _Http(settings, governor, max_requests=3, auth=None)   # unauthenticated control
    try:
        r_admin = http_admin.fetch(su)
        r_user = http_user.fetch(su)
        r_anon = http_anon.fetch(su)
    except _ActiveError as exc:
        return _err(f"request failed: {exc}")

    body_admin, body_user, body_anon = (r_admin.get("body") or ""), (r_user.get("body") or ""), (r_anon.get("body") or "")
    st_admin, st_user, st_anon = int(r_admin.get("status") or 0), int(r_user.get("status") or 0), int(r_anon.get("status") or 0)

    # Control 1: the admin session must actually obtain the privileged page.
    if st_admin != 200 or len(_norm(body_admin)) < _MIN_BODY:
        return {"ok": True, "status": "candidate",
                "reason": f"the high-privilege session did not return a readable 200 for {urlparse(su).path or '/'} (HTTP {st_admin}) — check the admin session / URL.",
                "detail": {"status_admin": st_admin, "status_user": st_user, "status_anon": st_anon}}

    r_user_admin = _ratio(body_user, body_admin)
    r_anon_admin = _ratio(body_anon, body_admin)
    detail = {"status_admin": st_admin, "status_user": st_user, "status_anon": st_anon,
              "ratio_user_vs_admin": round(r_user_admin, 3), "ratio_anon_vs_admin": round(r_anon_admin, 3),
              # Concrete artifacts: the size match (user got the admin page) + the anonymous control's
              # denial (proving the endpoint is genuinely privilege-gated), rendered as proof.
              "len_user": len(_norm(body_user)), "len_admin": len(_norm(body_admin)),
              "anon_location": (r_anon.get("location") or "").strip()[:200]}

    # Control 2: the endpoint must be access-CONTROLLED — an anonymous request must be denied
    # or clearly different. If anon sees the same thing as admin, the page is just PUBLIC.
    anon_denied = st_anon != 200 or r_anon_admin < _ANON_DENIED
    if not anon_denied:
        return {"ok": True, "status": "candidate",
                "reason": ("an anonymous (no-session) request returned ~the same content as the admin session, so this "
                           "endpoint appears PUBLIC, not privilege-gated — BFLA does not apply. Pick a genuinely "
                           "admin-only function and re-test."),
                "detail": detail}

    # The attack: the low-privilege user's response ~matches the ADMIN response -> the user
    # invoked a function they shouldn't reach (a properly-gated endpoint would 403/redirect).
    if st_user == 200 and r_user_admin >= _SAME:
        finding, plan = _build_bfla_finding(su, detail)
        return {"ok": True, "status": "confirmed", "finding": finding, "attack_plan": plan, "detail": detail}

    if st_user == 200 and r_user_admin >= _CANDIDATE:
        return {"ok": True, "status": "candidate",
                "reason": (f"the low-privilege user's response was {r_user_admin:.0%} similar to the admin response "
                           f"(below the {_SAME:.0%} auto-confirm bar) while anonymous access was denied — possible BFLA "
                           f"behind page chrome/SPA shell. Inspect within scope."),
                "detail": detail}

    return {"ok": True, "status": "enforced",
            "reason": (f"the low-privilege user did NOT obtain the privileged response (HTTP {st_user}; similarity to admin "
                       f"{r_user_admin:.2f}). Function-level access control appears enforced here."),
            "detail": detail}


def _build_bfla_finding(url: str, detail: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a BFLA finding + attack plan from a confirmed three-session differential. The
    proof is the DIFFERENTIAL ONLY — never the privileged body."""
    path = urlparse(url).path or "/"
    model = impact_model.impact_for_class("access-control")
    matched = (f"the low-privilege session received the privileged response (HTTP {detail['status_user']}); body matched "
               f"the admin response (similarity {detail['ratio_user_vs_admin']}) while an anonymous request was denied/"
               f"different (similarity {detail['ratio_anon_vs_admin']})")
    finding = {
        "rule_id": "active.bfla",
        "title": f"Broken function-level authorization at {path}",
        "severity": "high",
        "confidence": "high",
        "category": "access-control",
        "location": url,
        "file_path": url,
        "line_start": 1, "line_end": 1,
        "class_id": _AC_META["class_id"], "class_name": "Broken function-level authorization (BFLA)",
        "cwe": "CWE-862 / CWE-285",
        "owasp": _AC_META["owasp"],
        "references": impact_model.references_for_class("access-control"),
        "vrt": impact_model.bugcrowd_vrt("access-control"),
        "remediation": impact_model.remediation_for_class("access-control"),
        "snippet": "",  # privileged body withheld (may be sensitive / another user's data)
        "proof_evidence": {
            "request_line": f"GET {url}",
            "request_header": "Cookie: <low-privilege account session>",
            "response_status": f"HTTP {detail['status_user']}",
            # Concrete non-body proof: the size match to admin + the anonymous control's denial.
            "response_header": (f"normalized length: low-priv ~{detail.get('len_user', '?')} bytes matches admin "
                                f"~{detail.get('len_admin', '?')}; anonymous control denied (HTTP {detail['status_anon']}"
                                + (f" → {detail['anon_location']}" if detail.get("anon_location") else "") + ")"),
            "matched_value": matched,
        },
    }
    plan = {
        "steps": [
            "Authenticate as the low-privilege account (your second test account).",
            f"With that session, request the privileged function: GET {url}",
            f"Observe HTTP {detail['status_user']} returning the admin-only response (body matched the admin session).",
            f"Control: the same request with NO session is denied/different (similarity to admin {detail['ratio_anon_vs_admin']}), "
            f"proving the endpoint is access-controlled — yet the low-privilege user reached it.",
            "Map the blast radius: which other privileged functions (admin actions, other users' management) the low-privilege role can invoke.",
        ],
        "poc": (f"# As the low-privilege account, request the admin-only function:\n"
                f"curl -s -i '{url}' -H 'Cookie: <low-priv session>'\n"
                f"# -> HTTP {detail['status_user']} with the privileged (admin) response"),
        "impact": model.get("business_impact", ""),
        "cvss": impact_model.cvss_for_class("access-control", confirmed=True),
        "remediation": impact_model.remediation_for_class("access-control"),
        "proof_of_impact": {
            "status": "confirmed",
            "method": "three-session function-level differential (GET-only, no data exfiltrated into the report)",
            "actor": "authenticated low-privilege account (no admin role)",
            "affected_asset": "privileged functions reachable by an under-privileged role",
            "observed_result": matched,
            "control_result": ("an anonymous request to the same endpoint was denied/different, so the function is genuinely "
                               "access-controlled — the low-privilege user bypassed the function-level check"),
            "evidence": "user response ≈ admin response, and anon response ≠ admin response (ratios captured; privileged body withheld)",
            "proof_obligation": model.get("proof_obligation", ""),
        },
    }
    return finding, plan


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
            # The size differential is concrete proof B got A's object — WITHOUT ever embedding the
            # other user's body. Rendered as a response-header line + a bullet on every report surface.
            "response_header": (f"normalized length: B-on-A ~{detail['len_BonA']} bytes matches A's own "
                                f"~{detail['len_A']}, not B's own object ~{detail['len_BownB']}"),
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
        "cvss": impact_model.cvss_for_class("access-control", confirmed=True),
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


# --- Mass assignment / privilege escalation ------------------------------------------------------
# Boolean ROLE/ADMIN flags a client must NEVER be able to set on its own object — universally a
# server-only authorization attribute, so a client-set true is unambiguous vertical privilege
# escalation. Deliberately EXCLUDES context-dependent booleans (verified / approved / premium / pro /
# owner) that many apps legitimately let the owner self-set on their own object — flagging those would
# false-confirm, since "the owner can set this field on their own object" is expected there.
_PRIV_BOOL_FIELD_RE = re.compile(
    r"^(?:is[_-]?admin|admin|is[_-]?staff|staff|is[_-]?superuser|superuser|is[_-]?super|"
    r"is[_-]?moderator|moderator|can[_-]?admin|is[_-]?root|root[_-]?user|is[_-]?sysadmin|sysadmin)$",
    re.IGNORECASE,
)
_MA_META = {"class_id": "access-control", "class_name": "Mass assignment / privilege escalation",
            "cwe": "CWE-915 / CWE-269", "owasp": "A01:2021 Broken Access Control"}


def _json_write(url: str, method: str, payload: dict[str, Any], *, auth: Any, settings: Any, timeout: float) -> dict[str, Any]:
    """Send a JSON body via ``method`` (PATCH/PUT/POST), the operator session attached SAME-SITE only
    (auth_headers_for), no redirect followed. Used to write a benign, reversible value to the operator's
    OWN object. Returns ``{ok, status}`` / ``{ok: False, error}`` -- never raises for the common failures.

    SSRF: re-validates + DNS-PINS the host in its OWN guarded scope IMMEDIATELY before the connect, so
    the write always lands on the freshly-checked IP. This must be self-contained -- the surrounding
    prover interleaves GET reads (each opening/closing its own DNS-pin scope), so a single outer pin is
    already gone by the time a write runs; without this, urllib would re-resolve via live DNS and a
    rebind could point the session-bearing write at an internal/metadata host."""
    headers = {"Content-Type": "application/json", "Accept": "*/*", "User-Agent": current_user_agent(_USER_AGENT)}
    headers.update(auth_headers_for(urlparse(url).hostname or "", auth))
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method=method, headers=headers)
    opener = urllib.request.build_opener(_NoRedirect())
    with guarded_dns_scope():
        try:
            _guard_url(url, settings.allow_private_urls, settings.web_allowed_ports)  # re-check + PIN right before connect
        except WebsiteFetchError as exc:
            return {"ok": False, "error": f"target refused by the URL guard: {exc}"}
        try:
            with opener.open(request, timeout=timeout) as resp:
                body = resp.read(settings.web_fetch_max_bytes + 1)[: settings.web_fetch_max_bytes]
                return {"ok": True, "status": int(getattr(resp, "status", 0) or 0),
                        "body": body.decode("utf-8", "replace")}
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(settings.web_fetch_max_bytes + 1)[: settings.web_fetch_max_bytes].decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                body = ""
            return {"ok": True, "status": int(exc.code), "body": body}
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"ok": False, "error": f"{method} failed: {exc}"}


def _get_json(http: _Http, url: str) -> dict[str, Any] | None:
    """GET ``url`` and parse a top-level JSON object, or None if not a JSON object / fetch failed."""
    try:
        r = http.fetch(url)
    except _ActiveError:
        return None
    try:
        obj = json.loads(r.get("body") or "")
    except (ValueError, json.JSONDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def run_mass_assignment_check(
    object_url: str,
    *,
    account: dict[str, Any],
    scope: str = "",
    settings: Any = None,
    governor: HostRateGovernor | None = None,
) -> dict[str, Any]:
    """Confirm MASS ASSIGNMENT -> privilege escalation on the operator's OWN object: the session can set
    a boolean PRIVILEGE FLAG (is_admin / is_verified / is_staff / ...) the server should never accept
    from a client. Benign + reversible -- every request targets the operator's own object, the write
    flips ONE boolean flag, and it is RESTORED afterward. GET reads + JSON PATCH writes only.

    Differential (all on the operator's own object):
      baseline GET  -> a known-privilege boolean field F is present and FALSE
      control PATCH -> an empty {} write does NOT flip F (F stays false; rules out "F flips on any write")
      mutate  PATCH -> {F: true}, then a FRESH GET shows F == true (the bug: a client set a privilege flag)
      restore PATCH -> {F: false} (best-effort cleanup)
    Confirmed iff the control keeps F false AND the mutate makes F true via an authoritative re-read."""
    settings = settings or get_settings()
    u = str(object_url or "").strip()
    if not u:
        return _err("Provide the URL of a JSON object you OWN (e.g. /api/users/me) to test for mass assignment.")
    try:
        nu = normalize_website_url(u)
    except WebsiteFetchError as exc:
        return _err(str(exc))
    host = urlparse(nu).hostname or ""
    if not host_in_active_scope(host, scope, settings):
        return _err(f"'{host}' is not named in your scope -- mass-assignment testing is fail-closed. Add it to Scope.")
    try:
        su = _guard_url(nu, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return _err(f"target refused by the URL guard: {exc}")
    auth = build_auth(su, cookie=account.get("cookie", ""), headers=account.get("headers") or [])
    if auth is None:
        return _err("Mass-assignment testing needs your session -- supply a cookie and/or auth headers for the account that owns the object.")

    governor = governor or HostRateGovernor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http = _Http(settings, governor, max_requests=8, auth=auth)
    timeout = settings.web_fetch_timeout_seconds

    baseline = _get_json(http, su)
    if baseline is None:
        return {"ok": True, "status": "candidate",
                "reason": "the object URL didn't return a readable JSON object -- point this at a JSON object you own (e.g. /api/users/me)."}
    field = next((k for k, v in baseline.items()
                  if isinstance(v, bool) and v is False and _PRIV_BOOL_FIELD_RE.match(str(k))), None)
    if not field:
        return {"ok": True, "status": "enforced",
                "reason": "no client-visible ROLE/ADMIN flag (is_admin / is_staff / is_superuser / ...) is present and false on this object -- nothing to escalate via mass assignment here."}
    # A benign NON-privilege scalar field to drive a CONTENT-BEARING control write (prefer a string,
    # rewritten with its OWN current value = a true no-op). Writing content WITHOUT the privilege field
    # is what distinguishes a client-set escalation from a server that recomputes the flag as a
    # side-effect of ANY content write (an empty {} write wouldn't trigger such a recompute, so it can't
    # tell them apart). Without a benign field we can only run the weaker empty control -> candidate.
    control_body: dict[str, Any] = {}
    for k, v in baseline.items():
        if k == field or _PRIV_BOOL_FIELD_RE.match(str(k)):
            continue
        if isinstance(v, str) or (isinstance(v, (int, float)) and not isinstance(v, bool)):
            control_body = {k: v}
            if isinstance(v, str):
                break  # a string no-op is the safest content control; take the first one

    # Each _json_write self-pins DNS right before its connect, and each _get_json (http.fetch) pins for
    # its GET, so every request lands on a freshly-validated IP (no single-outer-pin TOCTOU).
    ctl_w = _json_write(su, "PATCH", control_body, auth=auth, settings=settings, timeout=timeout)
    control = _get_json(http, su)
    if control is not None and control.get(field) is True:
        return {"ok": True, "status": "candidate",
                "reason": (f"the '{field}' flag became true after a control write that did NOT set it, so the server "
                           "recomputes it as a side-effect rather than accepting a client-supplied value -- not a "
                           "mass-assignment escalation. Inspect manually."),
                "detail": {"field": field, "control_body_keys": list(control_body), "control_write_status": ctl_w.get("status")}}
    # The attack: set the privilege flag, then AUTHORITATIVELY re-read (not the write's echo).
    mut_w = _json_write(su, "PATCH", {field: True}, auth=auth, settings=settings, timeout=timeout)
    after = _get_json(http, su)
    escalated = bool(after is not None and after.get(field) is True)
    # Restore (best-effort) -- leave the operator's own object as we found it.
    _json_write(su, "PATCH", {field: False}, auth=auth, settings=settings, timeout=timeout)

    detail = {"field": field, "baseline": False, "content_control": bool(control_body),
              "mutate_write_status": mut_w.get("status"),
              "after_value": (after.get(field) if isinstance(after, dict) else None)}
    if not escalated:
        return {"ok": True, "status": "enforced",
                "reason": (f"setting '{field}' to true was NOT reflected on an authoritative re-read (write HTTP "
                           f"{mut_w.get('status')}) -- the server rejects the client-supplied privilege flag. Enforced."),
                "detail": detail}
    if not control_body:
        # No non-privilege field was available for a content-bearing control, so we can't fully rule out
        # a content-triggered server recompute -> report as a strong CANDIDATE, never an auto-confirm.
        return {"ok": True, "status": "candidate",
                "reason": (f"setting '{field}' to true persisted, but this object had no other field to run a "
                           "content-bearing control against, so a server-side recompute can't be fully excluded. "
                           "Verify by hand that the client value caused the change."),
                "detail": detail}
    finding, plan = _build_mass_assignment_finding(su, field, detail)
    return {"ok": True, "status": "confirmed", "finding": finding, "attack_plan": plan, "detail": detail}


def _build_mass_assignment_finding(url: str, field: str, detail: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    path = urlparse(url).path or "/"
    matched = (f"the low-privilege session set the privilege flag '{field}' to true on its own object via a "
               f"client write, and an authoritative re-read confirmed the value persisted (HTTP "
               f"{detail.get('mutate_write_status')})")
    model = impact_model.impact_for_class("access-control")
    finding = {
        "rule_id": "active.mass-assignment",
        "title": f"Mass assignment -> privilege escalation via '{field}' at {path}",
        "severity": "high", "confidence": "high", "category": "access-control",
        "location": url, "file_path": url, "line_start": 1, "line_end": 1,
        "class_id": _MA_META["class_id"], "class_name": _MA_META["class_name"],
        "cwe": _MA_META["cwe"], "owasp": _MA_META["owasp"],
        "references": impact_model.references_for_class("access-control"),
        "vrt": impact_model.bugcrowd_vrt("access-control"),
        "remediation": ("Allow-list the fields a client may write (never bind request bodies straight to the "
                        "model); reject or ignore privilege/authorization attributes on user-facing create/update "
                        "endpoints and set them only server-side."),
        "snippet": "",
        "proof_evidence": {
            "request_line": f'PATCH {url}  (body: {{"{field}": true}})  then  GET {url}',
            "request_header": "Content-Type: application/json; <the low-privilege account session>",
            "response_status": f"re-read reflects {field}=true",
            "matched_value": matched,
        },
    }
    plan = {
        "steps": [
            "Authenticate as your low-privilege test account (the object's owner).",
            f"Read the object to confirm '{field}' is present and false: GET {url}",
            f'Send a client update adding the privilege flag: PATCH {url} with body {{"{field}": true}}.',
            f"Re-read the object (GET {url}) and observe '{field}' is now true -- the server accepted a privilege "
            "attribute the client should never be able to set (mass assignment -> privilege escalation).",
            "Control: an empty write did NOT flip the flag, so the change is attributable to the client-set value.",
            "Map the blast radius: what the elevated flag unlocks (admin UI, other users' data, privileged actions).",
        ],
        "poc": (f"# As the low-privilege account (its own object):\n"
                f"curl -s -X PATCH '{url}' -H 'Content-Type: application/json' -H 'Cookie: <session>' "
                f"-d '{{\"{field}\": true}}'\n"
                f"curl -s '{url}' -H 'Cookie: <session>'   # -> \"{field}\": true"),
        "impact": model.get("business_impact", ""),
        "cvss": impact_model.cvss_for_class("access-control", confirmed=True),
        "remediation": finding["remediation"],
        "proof_of_impact": {
            "status": "confirmed",
            "method": "client PATCH of a privilege flag on the operator's own object + authoritative re-read (benign, reversible; the flag was restored)",
            "actor": "authenticated low-privilege account (the object's owner)",
            "affected_asset": "any privilege/authorization attribute a client can set -- vertical privilege escalation",
            "observed_result": matched,
            "control_result": f"an EMPTY write to the same object did NOT change '{field}', so the escalation is attributable to the client-supplied value, not any write",
            "evidence": f"'{field}' false->true across a client PATCH, confirmed by an authoritative GET; empty-write control left it false",
            "proof_obligation": model.get("proof_obligation", ""),
        },
    }
    return finding, plan


# --- Session not invalidated after logout --------------------------------------------------------
_SESS_META = {"class_id": "auth", "class_name": "Session not invalidated after logout",
              "cwe": "CWE-613", "owasp": "A07:2021 Identification and Authentication Failures"}


def run_session_invalidation_check(
    authed_url: str,
    logout_url: str,
    *,
    account: dict[str, Any],
    scope: str = "",
    settings: Any = None,
    governor: HostRateGovernor | None = None,
) -> dict[str, Any]:
    """Confirm a session STAYS VALID AFTER LOGOUT (server-side session not destroyed). The operator
    supplies an authenticated endpoint (returns their own account content) and the logout endpoint, with
    the session. Differential, GET-only reads + one logout call, all on the operator's OWN session:

      baseline GET authed_url (session)  -> authenticated 200
      anon     GET authed_url (NO session) -> DENIED (proves the endpoint is genuinely auth-gated)
      logout   POST/GET logout_url (session) -> succeeds (2xx/3xx)
      replay   GET authed_url (SAME session) -> STILL authenticated (~= baseline, != anon)

    Confirmed iff the endpoint is auth-gated AND logout succeeded AND the old session still authenticates
    afterward. If the replay is denied, the session was properly invalidated (enforced). Only the
    operator's own session is used; nothing another user owns is touched."""
    settings = settings or get_settings()
    au, lo = str(authed_url or "").strip(), str(logout_url or "").strip()
    if not au or not lo:
        return _err("Provide both an authenticated endpoint (your own account content) and the logout endpoint.")
    try:
        nau, nlo = normalize_website_url(au), normalize_website_url(lo)
    except WebsiteFetchError as exc:
        return _err(str(exc))
    host_a, host_l = (urlparse(nau).hostname or ""), (urlparse(nlo).hostname or "")
    if host_a.lower() != host_l.lower():
        return _err("The authenticated URL and the logout URL must be on the same host (same app/session).")
    if not host_in_active_scope(host_a, scope, settings):
        return _err(f"'{host_a}' is not named in your scope -- session testing is fail-closed. Add it to Scope.")
    try:
        sau = _guard_url(nau, settings.allow_private_urls, settings.web_allowed_ports)
        slo = _guard_url(nlo, settings.allow_private_urls, settings.web_allowed_ports)
    except WebsiteFetchError as exc:
        return _err(f"target refused by the URL guard: {exc}")
    auth = build_auth(sau, cookie=account.get("cookie", ""), headers=account.get("headers") or [])
    if auth is None:
        return _err("Session testing needs your session -- supply a cookie and/or auth headers for the account.")

    governor = governor or HostRateGovernor(
        capacity=settings.active_max_requests_per_host, min_interval_s=settings.active_min_interval_ms / 1000.0)
    http = _Http(settings, governor, max_requests=6, auth=auth)
    http_anon = _Http(settings, governor, max_requests=2, auth=None)   # unauthenticated control
    try:
        r_base = http.fetch(sau)          # authenticated ground truth
        r_anon = http_anon.fetch(sau)     # control: is the endpoint actually auth-gated?
    except _ActiveError as exc:
        return _err(f"request failed: {exc}")
    body_base, body_anon = (r_base.get("body") or ""), (r_anon.get("body") or "")
    st_base, st_anon = int(r_base.get("status") or 0), int(r_anon.get("status") or 0)

    if st_base != 200 or len(_norm(body_base)) < _MIN_BODY:
        return {"ok": True, "status": "candidate",
                "reason": f"the authenticated endpoint did not return a readable 200 with your session (HTTP {st_base}) -- check the session / URL."}
    r_anon_base = _ratio(body_anon, body_base)
    if st_anon == 200 and r_anon_base >= _ANON_DENIED:
        return {"ok": True, "status": "candidate",
                "reason": ("an anonymous request returned ~the same content as your authenticated one, so this endpoint "
                           "isn't session-gated (it's public) -- pick an endpoint that shows YOUR account data and re-test."),
                "detail": {"status_base": st_base, "status_anon": st_anon, "ratio_anon_vs_base": round(r_anon_base, 3)}}

    # A catch-all CONTROL: a non-existent path at the same origin. A site that serves a generic 200 page
    # for ANY path (SPA/proxy catch-all) would make a bogus logout URL look "successful" -> a false
    # confirm. If the logout endpoint's response is indistinguishable from this non-route, we cannot
    # verify a real logout occurred.  (The logout must be a genuinely DISTINCT route, or a redirect.)
    origin = f"{urlparse(sau).scheme}://{urlparse(sau).netloc}"
    catchall_body, catchall_status = "", 0
    try:
        cg = http_anon.fetch(f"{origin}/greyiq-{'x' * 6}-no-such-route")
        catchall_body, catchall_status = (cg.get("body") or ""), int(cg.get("status") or 0)
    except _ActiveError:
        pass

    # Log out (the operator's OWN session). Try POST (the modern default), then GET for link-style logout.
    logout = _json_write(slo, "POST", {}, auth=auth, settings=settings, timeout=settings.web_fetch_timeout_seconds)
    logout_ok = bool(logout.get("ok") and 200 <= int(logout.get("status") or 0) < 400)
    if not logout_ok:
        try:
            g = http.fetch(slo)
            logout_ok = 200 <= int(g.get("status") or 0) < 400
            logout = {"ok": True, "status": int(g.get("status") or 0), "body": g.get("body") or "", "method": "GET"}
        except _ActiveError:
            pass
    if not logout_ok:
        return {"ok": True, "status": "candidate",
                "reason": f"could not complete a logout (POST/GET to the logout URL did not return 2xx/3xx, HTTP {logout.get('status')}) -- supply the exact logout endpoint.",
                "detail": {"logout_status": logout.get("status")}}
    # Verify the logout endpoint is REAL, not a catch-all: a redirect (3xx) is a genuine logout action;
    # otherwise its 200 response must DIFFER from the non-existent-route control (a distinct route).
    lo_status, lo_body = int(logout.get("status") or 0), str(logout.get("body") or "")
    is_redirect = 300 <= lo_status < 400
    looks_catchall = (not is_redirect and lo_status == 200 and catchall_status == 200
                      and _ratio(lo_body, catchall_body) >= 0.90)
    if looks_catchall:
        return {"ok": True, "status": "candidate",
                "reason": ("the logout URL returns the same generic page as a non-existent path (an SPA/proxy catch-all), "
                           "so a real server-side logout can't be verified -- supply the exact logout endpoint (or the one "
                           "that redirects / clears the session)."),
                "detail": {"logout_status": lo_status, "ratio_logout_vs_nonroute": round(_ratio(lo_body, catchall_body), 3)}}

    try:
        r_replay = http.fetch(sau)        # the SAME session, AFTER logout
    except _ActiveError as exc:
        return _err(f"replay request failed: {exc}")
    body_replay, st_replay = (r_replay.get("body") or ""), int(r_replay.get("status") or 0)
    r_replay_base = _ratio(body_replay, body_base)
    detail = {"status_base": st_base, "status_anon": st_anon, "status_replay": st_replay,
              "ratio_replay_vs_base": round(r_replay_base, 3), "ratio_anon_vs_base": round(r_anon_base, 3),
              "logout_status": logout.get("status")}
    still_authed = st_replay == 200 and r_replay_base >= _SAME
    if not still_authed:
        return {"ok": True, "status": "enforced",
                "reason": (f"after logout the same session no longer returned your authenticated content (HTTP {st_replay}, "
                           f"similarity to the pre-logout response {r_replay_base:.2f}) -- the session was invalidated. Enforced."),
                "detail": detail}
    finding, plan = _build_session_invalidation_finding(sau, slo, detail)
    return {"ok": True, "status": "confirmed", "finding": finding, "attack_plan": plan, "detail": detail}


def _build_session_invalidation_finding(authed_url: str, logout_url: str, detail: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    path = urlparse(authed_url).path or "/"
    matched = (f"after a successful logout (HTTP {detail.get('logout_status')}), the SAME session still returned the "
               f"authenticated response at {path} (HTTP {detail.get('status_replay')}, {detail.get('ratio_replay_vs_base')} "
               f"similar to the pre-logout response) while an anonymous request was denied")
    model = impact_model.impact_for_class("auth")
    finding = {
        "rule_id": "active.session-not-invalidated",
        "title": f"Session not invalidated after logout at {path}",
        "severity": "medium", "confidence": "high", "category": "auth",
        "location": authed_url, "file_path": authed_url, "line_start": 1, "line_end": 1,
        "class_id": _SESS_META["class_id"], "class_name": _SESS_META["class_name"],
        "cwe": _SESS_META["cwe"], "owasp": _SESS_META["owasp"],
        "references": ["https://cwe.mitre.org/data/definitions/613.html",
                       "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
        "vrt": "", "remediation": ("Destroy the session SERVER-SIDE on logout (invalidate the session record / rotate the "
                                   "token), not just by clearing the client cookie; expire tokens and reject a logged-out "
                                   "session identifier on every subsequent request."),
        "snippet": "",
        "proof_evidence": {
            "request_line": f"GET {authed_url} (session)  ->  logout  ->  GET {authed_url} (SAME session)",
            "request_header": "Cookie: <your account session, reused after logout>",
            "response_status": f"HTTP {detail.get('status_replay')} (still authenticated post-logout)",
            "matched_value": matched,
        },
    }
    plan = {
        "steps": [
            "Log in with your test account and capture the session cookie/token.",
            f"Confirm it authenticates: GET {authed_url} -> your account content (an anonymous request is denied).",
            f"Log out via {logout_url}.",
            f"Re-send the ORIGINAL session to {authed_url} -- it still returns your authenticated content, so the server "
            "never destroyed the session (only the client cookie was cleared).",
            "Impact: a stolen/leaked session (proxy log, shared device, XSS-exfil) stays valid after the victim logs out.",
        ],
        "poc": (f"# After logout, replay the ORIGINAL session:\n"
                f"curl -s -i '{authed_url}' -H 'Cookie: <pre-logout session>'\n"
                f"# -> HTTP {detail.get('status_replay')} with your authenticated content (session still alive)"),
        "impact": model.get("business_impact", ""),
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "base_score": 6.5, "base_severity": "medium", "estimated": False,
                 "justification": "Actively confirmed: the same session authenticated after a successful logout (anonymous control denied)."},
        "remediation": finding["remediation"],
        "proof_of_impact": {
            "status": "confirmed",
            "method": "authenticated GET, logout, then replay of the same session (GET-only reads + the operator's own logout)",
            "actor": "the account owner (own session, replayed after logout)",
            "affected_asset": "every user whose session outlives their logout -- stolen/leaked sessions remain usable",
            "observed_result": matched,
            "control_result": "an anonymous (no-session) request to the same endpoint was denied, so it is genuinely session-gated -- yet the post-logout session still worked",
            "evidence": "post-logout session response == pre-logout authenticated response and != the anonymous response (ratios captured)",
            "proof_obligation": ("Capture the full exchange: the authenticated GET before logout, the logout request + its 2xx/3xx "
                                 "response, and the SAME session replayed after logout still returning your account content (with the "
                                 "anonymous-request denial as the control) -- proving the session was not destroyed server-side."),
        },
    }
    return finding, plan
