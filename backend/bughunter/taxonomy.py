"""GreyIQ BugHunter — CWE → platform taxonomy mapping.

A finding carries a CWE (the one universal weakness id). Each destination platform,
though, wants the weakness in ITS own taxonomy: HackerOne routes on a numeric
``weakness_id`` from the program's enabled weakness list, and Bugcrowd's form is
VRT-led (its Vulnerability Rating Taxonomy category path). Historically GreyIQ left
Bugcrowd's VRT as a literal "(map to the closest VRT category)" placeholder and never
mapped CWE onto HackerOne's weakness id at all — so a filed report landed with no
machine-readable weakness and an operator hand-picked the taxonomy on every submission.

This module closes that gap deterministically:

* ``cwe_to_vrt(cwe)`` — a curated CWE → Bugcrowd VRT category-path map for the classes
  GreyIQ actually detects. Best-effort and clearly an *estimate* (the report labels it
  "(est.)"); an unmapped CWE returns None and the caller keeps its existing fallback.
* ``match_weakness_id(weaknesses, cwe)`` — matches a finding's CWE against a program's
  enabled HackerOne weakness list (fetched live by ``hackerone_import.fetch_weaknesses``,
  whose entries carry an ``external_id`` like "cwe-79"). Returns the integer weakness id
  or None. No hardcoded HackerOne ids — those are program-specific and would rot; the
  authoritative list is always the one the program itself exposes.

Pure / frozen-safe (no I/O, no third-party deps). Every function is total and never
raises on malformed input — a bad CWE string just yields None.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# CWE parsing
# ---------------------------------------------------------------------------

_CWE_RE = re.compile(r"CWE[-\s_]?(\d+)", re.IGNORECASE)


def cwe_number(cwe: Any) -> str:
    """The bare numeric part of a CWE reference, or '' if none is present.

    Accepts "CWE-79", "cwe 79", "79", "CWE-79 / CWE-80" (takes the first), etc. Total:
    any non-matching input (None, "", "n/a") yields ''.
    """
    match = _CWE_RE.search(str(cwe or ""))
    if match:
        return match.group(1)
    stripped = str(cwe or "").strip()
    return stripped if stripped.isdigit() else ""


# ---------------------------------------------------------------------------
# CWE → Bugcrowd VRT (Vulnerability Rating Taxonomy) category path
# ---------------------------------------------------------------------------
# Best-effort estimates for the vulnerability classes GreyIQ detects. Values are the
# human-readable VRT category path a Bugcrowd submission form expects; kept deliberately
# to the stable top/second level so a taxonomy revision doesn't silently mislabel. An
# unmapped CWE returns None so the caller can keep its "(map to the closest VRT
# category)" fallback rather than assert a wrong category.
_CWE_TO_VRT: dict[str, str] = {
    "79": "Cross-Site Scripting (XSS) > Reflected",
    "80": "Cross-Site Scripting (XSS) > Stored",
    "89": "Server-Side Injection > SQL Injection",
    "90": "Server-Side Injection > LDAP Injection",
    "91": "Server-Side Injection > XML Injection",
    "94": "Server-Side Injection > Remote Code Execution (RCE)",
    "78": "Server-Side Injection > Remote Code Execution (RCE)",
    "77": "Server-Side Injection > Command Injection",
    "98": "Server-Side Injection > File Inclusion > Remote",
    "22": "Server-Side Injection > Path Traversal",
    "611": "Server-Side Injection > XML External Entity Injection (XXE)",
    "918": "Server-Side Request Forgery (SSRF)",
    "1336": "Server-Side Injection > Server-Side Template Injection (SSTI)",
    "601": "Unvalidated Redirects and Forwards > Open Redirect",
    "352": "Broken Authentication and Session Management > Cross-Site Request Forgery (CSRF)",
    "384": "Broken Authentication and Session Management > Session Fixation",
    "287": "Broken Authentication and Session Management",
    "639": "Broken Access Control (BAC) > Insecure Direct Object References (IDOR)",
    "566": "Broken Access Control (BAC) > Insecure Direct Object References (IDOR)",
    "284": "Broken Access Control (BAC)",
    "285": "Broken Access Control (BAC)",
    "862": "Broken Access Control (BAC) > Missing Function-Level Access Control",
    "863": "Broken Access Control (BAC)",
    "915": "Broken Access Control (BAC) > Mass Assignment",
    "200": "Sensitive Data Exposure",
    "213": "Sensitive Data Exposure",
    "312": "Sensitive Data Exposure > Sensitive Token in URL",
    "522": "Broken Authentication and Session Management > Weak Credential Storage",
    "798": "Sensitive Data Exposure > Disclosure of Secrets",
    "204": "Sensitive Data Exposure",
    "16": "Server Security Misconfiguration",
    "942": "Server Security Misconfiguration > Misconfigured CORS Policy",
    "350": "Server Security Misconfiguration > Misconfigured DNS > Subdomain Takeover",
    "693": "Server Security Misconfiguration > Missing Security Header",
    "1021": "Server Security Misconfiguration > Clickjacking",
    "434": "Unrestricted File Upload",
    "502": "Server-Side Injection > Insecure Deserialization",
    "444": "Server-Side Injection > HTTP Request Smuggling",
    "400": "Server Security Misconfiguration > Rate Limiting",
    "307": "Broken Authentication and Session Management > Lack of Rate Limiting",
    "1333": "Server Security Misconfiguration > Denial of Service > Regex",
    "776": "Server-Side Injection > XML External Entity Injection (XXE)",
}


def cwe_to_vrt(cwe: Any) -> str | None:
    """Bugcrowd VRT category path for a CWE (best-effort estimate), or None if unmapped."""
    return _CWE_TO_VRT.get(cwe_number(cwe))


# ---------------------------------------------------------------------------
# CWE → HackerOne weakness_id (matched against the program's live weakness list)
# ---------------------------------------------------------------------------


def _external_cwe(entry: dict[str, Any]) -> str:
    """The CWE number a HackerOne weakness entry maps to, from its ``external_id``.

    HackerOne weakness entries expose ``attributes.external_id`` shaped like "cwe-79".
    Accepts the entry either already flattened ({external_id, id, name}) or in raw
    JSON:API shape ({id, attributes:{external_id,...}}). Returns '' when absent.
    """
    attrs = entry.get("attributes") if isinstance(entry.get("attributes"), dict) else entry
    return cwe_number((attrs or {}).get("external_id"))


def match_weakness_id(weaknesses: list[dict[str, Any]] | None, cwe: Any) -> int | None:
    """Return the integer HackerOne ``weakness_id`` whose ``external_id`` matches ``cwe``.

    ``weaknesses`` is the list from ``hackerone_import.fetch_weaknesses`` (each entry has
    an ``id`` and an ``external_id`` like "cwe-79"). Fail-closed: no list, no CWE, or no
    match -> None, and the caller simply omits weakness_id (the pre-v2 behavior). Never
    raises on malformed entries.
    """
    number = cwe_number(cwe)
    if not number or not weaknesses:
        return None
    for entry in weaknesses:
        if not isinstance(entry, dict):
            continue
        if _external_cwe(entry) != number:
            continue
        raw_id = entry.get("id")
        try:
            return int(str(raw_id).strip())
        except (TypeError, ValueError):
            continue
    return None
