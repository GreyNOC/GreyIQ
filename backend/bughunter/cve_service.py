"""GreyIQ BugHunter — known-CVE / outdated-component detection.

Fingerprints the *versions* of well-known front-end libraries a page ships (jQuery, Lodash,
Bootstrap, Moment, AngularJS, Handlebars, DOMPurify) from the response — script ``src``
filenames and the libraries' own version banners — and maps each detected version to a
curated table of real, commonly-bounty-relevant CVEs whose fixed version is higher.

Honesty matters: a version fingerprint is **evidence of an outdated component**, not proof
the CVE is exploitable on this target. So every result is a **candidate** (confidence
"medium", ``proof_of_impact.status = "candidate"``) carrying the version evidence + the
applicable CVE list + an estimated exploit-likelihood (EPSS-style) and KEV flag to prioritise
— never a "confirmed" exploit. The operator (or a deeper active check) confirms exploitability.

GET-only, scope-bound (fail-closed via ``host_in_active_scope``), SSRF-guarded (the shared
``_guard_url`` + ``_fetch_raw``). Pure / frozen-safe (stdlib + the existing guarded fetch).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from bughunter.active_verify_service import host_in_active_scope
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _fetch_raw, _guard_url

# --- Curated CVE knowledge (offline) ------------------------------------------------------
# Per product: an ordered list of CVE records keyed by the version they are FIXED in
# ("fixed_in"); a detected version strictly LOWER than fixed_in is affected. Severities /
# vectors / CWEs are the published values; ``epss`` is an estimated exploit-likelihood
# (0-1) and ``kev`` flags CISA Known-Exploited — both for prioritisation, not as facts.
_KNOWN_CVES: dict[str, list[dict[str, Any]]] = {
    "jquery": [
        {"cve": "CVE-2012-6708", "fixed_in": "1.9.0", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.10, "kev": False,
         "summary": "Selector interpreted as HTML — DOM XSS via $(location.hash)."},
        {"cve": "CVE-2015-9251", "fixed_in": "3.0.0", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.22, "kev": False,
         "summary": "Cross-domain AJAX of text/javascript executes — reflected XSS."},
        {"cve": "CVE-2019-11358", "fixed_in": "3.4.0", "cwe": "CWE-1321", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.50, "kev": False,
         "summary": "Prototype pollution in jQuery.extend(true, {}, ...)."},
        {"cve": "CVE-2020-11023", "fixed_in": "3.5.0", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.42, "kev": False,
         "summary": "HTML containing <option> elements passed to DOM methods executes — XSS (with CVE-2020-11022)."},
    ],
    "bootstrap": [
        {"cve": "CVE-2018-14042", "fixed_in": "3.4.0", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.20, "kev": False,
         "summary": "XSS in data-container of tooltip/popover."},
        {"cve": "CVE-2019-8331", "fixed_in": "3.4.1", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.30, "kev": False,
         "summary": "XSS in data-template / data-content of tooltip/popover (also fixed in 4.3.1)."},
    ],
    "lodash": [
        {"cve": "CVE-2018-16487", "fixed_in": "4.17.11", "cwe": "CWE-1321", "severity": "medium", "base_score": 5.6,
         "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", "epss": 0.30, "kev": False,
         "summary": "Prototype pollution via merge/mergeWith/defaultsDeep."},
        {"cve": "CVE-2019-10744", "fixed_in": "4.17.12", "cwe": "CWE-1321", "severity": "critical", "base_score": 9.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "epss": 0.55, "kev": False,
         "summary": "Prototype pollution via defaultsDeep — can taint Object.prototype globally."},
        {"cve": "CVE-2020-8203", "fixed_in": "4.17.19", "cwe": "CWE-1321", "severity": "high", "base_score": 7.4,
         "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "epss": 0.40, "kev": False,
         "summary": "Prototype pollution via zipObjectDeep/set."},
        {"cve": "CVE-2021-23337", "fixed_in": "4.17.21", "cwe": "CWE-94", "severity": "high", "base_score": 7.2,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "epss": 0.45, "kev": False,
         "summary": "Command injection via template (_.template) with crafted options."},
    ],
    "moment": [
        {"cve": "CVE-2017-18214", "fixed_in": "2.19.3", "cwe": "CWE-1333", "severity": "high", "base_score": 7.5,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "epss": 0.20, "kev": False,
         "summary": "ReDoS in moment(...) parsing of a long crafted date string."},
        {"cve": "CVE-2022-31129", "fixed_in": "2.29.2", "cwe": "CWE-1333", "severity": "high", "base_score": 7.5,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "epss": 0.35, "kev": False,
         "summary": "ReDoS in RFC-2822 / ISO date parsing of attacker-controlled input."},
    ],
    "angularjs": [
        {"cve": "CVE-2020-7676", "fixed_in": "1.8.0", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.18, "kev": False,
         "summary": "angular.element xlink:href / SVG handling — XSS; legacy AngularJS is end-of-life."},
    ],
    "handlebars": [
        {"cve": "CVE-2019-19919", "fixed_in": "4.5.3", "cwe": "CWE-1321", "severity": "critical", "base_score": 9.8,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "epss": 0.60, "kev": False,
         "summary": "Prototype pollution via crafted template leading to RCE."},
        {"cve": "CVE-2021-23369", "fixed_in": "4.7.7", "cwe": "CWE-94", "severity": "critical", "base_score": 9.8,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "epss": 0.50, "kev": False,
         "summary": "Template compiled with compat/no-escape options allows RCE via prototype access."},
    ],
    "dompurify": [
        {"cve": "CVE-2020-26870", "fixed_in": "2.0.17", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.25, "kev": False,
         "summary": "Mutation-XSS (mXSS) sanitizer bypass via crafted markup."},
    ],
    "jquery-ui": [
        {"cve": "CVE-2021-41182", "fixed_in": "1.13.0", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.20, "kev": False,
         "summary": "XSS via the altField option of the Datepicker widget."},
        {"cve": "CVE-2021-41184", "fixed_in": "1.13.0", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.18, "kev": False,
         "summary": "XSS via the of option of the .position() util."},
        {"cve": "CVE-2022-31160", "fixed_in": "1.13.2", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.20, "kev": False,
         "summary": "XSS via crafted values rendered by the checkboxradio widget label."},
    ],
    "axios": [
        {"cve": "CVE-2020-28168", "fixed_in": "0.21.1", "cwe": "CWE-918", "severity": "medium", "base_score": 5.9,
         "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "epss": 0.30, "kev": False,
         "summary": "Proxy bypass / SSRF — a 3xx to an internal host follows despite no_proxy."},
        {"cve": "CVE-2021-3749", "fixed_in": "0.21.2", "cwe": "CWE-1333", "severity": "high", "base_score": 7.5,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "epss": 0.30, "kev": False,
         "summary": "ReDoS via a crafted trim-able header value."},
        {"cve": "CVE-2023-45857", "fixed_in": "1.6.0", "cwe": "CWE-200", "severity": "medium", "base_score": 6.5,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "epss": 0.35, "kev": False,
         "summary": "XSRF-TOKEN leaked to a third-party host via the absolute-URL request path."},
    ],
    "underscore": [
        {"cve": "CVE-2021-23358", "fixed_in": "1.12.1", "cwe": "CWE-94", "severity": "high", "base_score": 7.2,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "epss": 0.40, "kev": False,
         "summary": "Arbitrary code execution via the template function with a crafted variable option."},
    ],
    "mustache": [
        {"cve": "CVE-2015-8862", "fixed_in": "2.2.1", "cwe": "CWE-79", "severity": "medium", "base_score": 6.1,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "epss": 0.15, "kev": False,
         "summary": "XSS — unescaped output when a view value is a function returning HTML."},
    ],
    "wordpress": [
        {"cve": "CVE-2022-21661", "fixed_in": "5.8.3", "cwe": "CWE-89", "severity": "high", "base_score": 8.1,
         "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "epss": 0.40, "kev": False,
         "summary": "SQL injection via WP_Query (authenticated, affecting plugins/themes that pass crafted input)."},
        {"cve": "CVE-2022-21663", "fixed_in": "5.8.3", "cwe": "CWE-94", "severity": "medium", "base_score": 6.6,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "epss": 0.20, "kev": False,
         "summary": "Object-injection mitigations bypass for high-privilege users (multisite)."},
        {"cve": "CVE-2023-2745", "fixed_in": "6.2.1", "cwe": "CWE-200", "severity": "medium", "base_score": 5.3,
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "epss": 0.25, "kev": False,
         "summary": "Directory-traversal / information disclosure via the block editor in some configs."},
    ],
}

_LABELS = {"jquery": "jQuery", "bootstrap": "Bootstrap", "lodash": "Lodash", "moment": "Moment.js",
           "angularjs": "AngularJS", "handlebars": "Handlebars", "dompurify": "DOMPurify",
           "jquery-ui": "jQuery UI", "axios": "Axios", "underscore": "Underscore.js",
           "mustache": "Mustache.js", "wordpress": "WordPress (core)"}

# Version pulled from a script `src`/`href` filename. Anchored on a separator so `jquery-ui`
# / `jquery-migrate` / `jquery.validate` do NOT register as jQuery core (their CVEs differ).
# jquery-ui is matched BEFORE jquery so it wins on a shared path.
_SRC_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jquery-ui", re.compile(r"(?:^|[/\\])jquery[-.]ui[-.](\d+\.\d+(?:\.\d+)?)(?:\.min|\.custom)?\.js", re.I)),
    ("jquery", re.compile(r"(?:^|[/\\])jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.slim)?(?:\.min)?\.js", re.I)),
    ("bootstrap", re.compile(r"(?:^|[/\\])bootstrap(?:\.bundle)?[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)),
    ("lodash", re.compile(r"(?:^|[/\\])lodash(?:\.core)?[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("moment", re.compile(r"(?:^|[/\\])moment(?:-with-locales)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("angularjs", re.compile(r"(?:^|[/\\])angular[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("handlebars", re.compile(r"(?:^|[/\\])handlebars(?:\.runtime)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("dompurify", re.compile(r"(?:^|[/\\])(?:purify|dompurify)[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("axios", re.compile(r"(?:^|[/\\])axios[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("underscore", re.compile(r"(?:^|[/\\])underscore[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("mustache", re.compile(r"(?:^|[/\\])mustache[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
)

# Version pulled from the library's own banner/comment in inline or fetched script bodies.
_BANNER_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jquery-ui", re.compile(r"jQuery\s+UI[\s\S]{0,40}?(\d+\.\d+\.\d+)", re.I)),
    ("jquery", re.compile(r"jQuery(?:\s+JavaScript\s+Library)?\s+v(\d+\.\d+\.\d+)", re.I)),
    ("bootstrap", re.compile(r"Bootstrap\s+v(\d+\.\d+\.\d+)", re.I)),
    ("lodash", re.compile(r"\blodash(?:\.js)?\s+(?:<[^>]*>\s+)?(\d+\.\d+\.\d+)", re.I)),
    ("moment", re.compile(r"moment(?:\.js)?[\s\S]{0,40}?version\s*:?\s*['\"]?(\d+\.\d+\.\d+)", re.I)),
    ("angularjs", re.compile(r"AngularJS\s+v(\d+\.\d+\.\d+)", re.I)),
    ("handlebars", re.compile(r"Handlebars(?:\.js)?\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("dompurify", re.compile(r"DOMPurify[\s\S]{0,40}?VERSION\s*[:=]\s*['\"](\d+\.\d+\.\d+)", re.I)),
    ("underscore", re.compile(r"Underscore\.js\s+(\d+\.\d+\.\d+)", re.I)),
)

# Version pulled from an HTML <meta name="generator"> tag (CMS / framework fingerprint).
_META_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("wordpress", re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\s+(\d+\.\d+(?:\.\d+)?)", re.I)),
)

# Version pulled from a response HEADER. Server-software versions (Server:, X-Powered-By:
# nginx/Apache/PHP) are DELIBERATELY not mapped to CVEs — banner version alone is low-signal,
# rarely remotely exploitable, and routinely rejected by programs, which would be a false
# positive against this engine's confirm-grade promise. Only products with a clean version +
# a real, accepted CVE go here; today that is WordPress when it advertises itself in a header.
_HEADER_RES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("wordpress", "x-powered-by", re.compile(r"WordPress[/ ](\d+\.\d+(?:\.\d+)?)", re.I)),
)


def _ver_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(v))
    return tuple(int(p) for p in parts[:4]) or (0,)


def _ver_lt(a: str, b: str) -> bool:
    """True if version a is strictly lower than version b (numeric, zero-padded)."""
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta < tb


def _target_host(target: str) -> str:
    raw = str(target or "").strip()
    if "://" in raw:
        return (urlparse(raw).hostname or "").lower()
    return raw.split("/", 1)[0].strip().lower()


def detect_components(body: str, headers: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """Extract (product, version, evidence) tuples from a page/script body — src filenames
    first (most reliable), then version banners, then the <meta generator> tag — plus a few
    response headers (e.g. an X-Powered-By that advertises WordPress). De-duplicated to the
    LOWEST version seen per product (the most-vulnerable instance is what we report on)."""
    found: dict[str, dict[str, str]] = {}
    text = body or ""

    def _offer(product: str, version: str, evidence: str) -> None:
        if not version:
            return
        cur = found.get(product)
        if cur is None or _ver_lt(version, cur["version"]):
            found[product] = {"product": product, "version": version, "evidence": evidence[:160]}

    for product, rex in _SRC_RES:
        for m in rex.finditer(text):
            _offer(product, m.group(1), m.group(0).strip())
    for product, rex in _BANNER_RES:
        m = rex.search(text)
        if m:
            _offer(product, m.group(1), m.group(0).strip())
    for product, rex in _META_RES:
        m = rex.search(text)
        if m:
            _offer(product, m.group(1), m.group(0).strip())

    # Headers (case-insensitive). Only the curated, high-signal header products are matched.
    hmap = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    for product, header_name, rex in _HEADER_RES:
        m = rex.search(hmap.get(header_name, ""))
        if m:
            _offer(product, m.group(1), f"{header_name}: {m.group(0).strip()}")
    return list(found.values())


def match_cves(product: str, version: str) -> list[dict[str, Any]]:
    """Every curated CVE for ``product`` whose fixed version is higher than ``version``."""
    out = [dict(rec) for rec in _KNOWN_CVES.get(product, []) if _ver_lt(version, rec["fixed_in"])]
    out.sort(key=lambda r: (r.get("base_score") or 0.0, r.get("epss") or 0.0), reverse=True)
    return out


def _build_finding(component: dict[str, str], cves: list[dict[str, Any]], url: str) -> dict[str, Any]:
    product, version = component["product"], component["version"]
    label = _LABELS.get(product, product)
    head = cves[0]  # highest base_score (sorted)
    fixed = max((c["fixed_in"] for c in cves), key=_ver_tuple)
    cve_ids = ", ".join(c["cve"] for c in cves)
    lines = [f"{c['cve']} ({c['severity']}, CVSS {c['base_score']}, fixed in {c['fixed_in']}; "
             f"EPSS~{c['epss']:.2f}{'; CISA-KEV' if c.get('kev') else ''}): {c['summary']}" for c in cves]
    return {
        "rule_id": "passive.known-cve",
        "title": f"Outdated {label} {version} — {len(cves)} known CVE(s) (highest: {head['cve']}, {head['severity']})",
        "severity": head["severity"],
        "confidence": "medium",  # version fingerprint — exploitability not yet proven
        "category": "vulnerable-component",
        "location": url,
        "file_path": url,
        "line_start": 1, "line_end": 1,
        "class_id": "vulnerable-component",
        "class_name": "Vulnerable / outdated component",
        "cwe": head["cwe"],
        "owasp": "A06:2021 Vulnerable and Outdated Components",
        "vrt": "",
        "references": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            *[f"https://nvd.nist.gov/vuln/detail/{c['cve']}" for c in cves],
        ],
        "remediation": (f"Upgrade {label} to {fixed} or later (the highest fixed version among the matched CVEs). "
                        f"Track front-end dependencies with an SCA tool and a lockfile so regressions are caught in CI."),
        # The 'snippet' is OUR fingerprint of a public library version — no target/user data.
        "snippet": f"{label} {version} detected — {cve_ids}",
        "proof_evidence": {
            "request_line": f"GET {url}",
            "matched_value": f"{label} v{version} (evidence: {component['evidence']})",
        },
        "_cve_product": product,
        "_cve_version": version,
        "_cve_fixed_in": fixed,
        "_cve_list": cves,
        "_cve_max_epss": max((c.get("epss") or 0.0) for c in cves),
        "_cve_kev": any(c.get("kev") for c in cves),
        "_cve_summary_lines": lines,
    }


def build_plan(finding: dict[str, Any]) -> dict[str, Any]:
    """A candidate (version-fingerprint) attack plan for the report pipeline. The CVSS is the
    headline CVE's published vector; proof_of_impact is a CANDIDATE with a clear obligation —
    detection proves the outdated version, not that the CVE fires on this target."""
    product = finding.get("_cve_product", "")
    label = _LABELS.get(product, product)
    version = finding.get("_cve_version", "")
    fixed = finding.get("_cve_fixed_in", "")
    cves: list[dict[str, Any]] = finding.get("_cve_list") or []
    head = cves[0] if cves else {"cve": "", "vector": "", "base_score": None, "severity": finding.get("severity", "medium")}
    host = _target_host(finding.get("location", "")) or finding.get("location", "")
    return {
        "steps": [
            f"Confirm the page loads {label} v{version} (view-source / the script src in {finding.get('location', '')}).",
            f"Cross-check the version against the published advisories: {', '.join(c['cve'] for c in cves)}.",
            f"Determine whether the target's usage reaches the vulnerable code path (e.g. user-controlled input flowing "
            f"into the affected {label} API) — that is what turns this candidate into a confirmed, exploitable finding.",
            f"If exploitable, build a minimal PoC within scope; otherwise report as an outdated-component risk and recommend the upgrade to {fixed}.",
        ],
        "poc": f"# {finding.get('location', '')}\n# loads {label} v{version} — see the script src / version banner\n"
               + "\n".join(f"# {ln}" for ln in finding.get("_cve_summary_lines", [])),
        "impact": (f"{label} v{version} carries {len(cves)} publicly-known vulnerabilit{'y' if len(cves) == 1 else 'ies'} "
                   f"(highest {head.get('cve', '')}). Depending on how {host} uses the library, impact ranges from "
                   f"DOM/stored XSS and prototype pollution to, for some libraries, RCE."),
        "cvss": {"vector": head.get("vector", ""), "base_score": head.get("base_score"),
                 "base_severity": head.get("severity", finding.get("severity", "medium")), "estimated": True},
        "remediation": finding.get("remediation", ""),
        "proof_of_impact": {
            "status": "candidate",
            "method": "passive version fingerprint (script src + library banner) matched to a curated CVE table",
            "affected_asset": f"the client-side {label} bundle served by {host}",
            "observed_result": f"{host} serves {label} v{version}; {len(cves)} CVE(s) are fixed only in {fixed} or later",
            "control_result": f"an up-to-date {label} (≥ {fixed}) would not match any entry in the CVE table",
            "evidence": finding.get("proof_evidence", {}).get("matched_value", ""),
            "proof_obligation": (f"Show user-controlled input reaching the vulnerable {label} API on {host} (a working PoC) "
                                 f"to upgrade this from a candidate to a confirmed exploit; many programs also accept the "
                                 f"outdated-component report on its own."),
        },
    }


def scan_known_cves(target: str, *, scope: str = "", settings: Any = None) -> dict[str, Any]:
    """Fetch ``target`` (GET-only, in-scope, SSRF-guarded), fingerprint its front-end library
    versions, and return ``{ok, target, components, findings}`` — one candidate finding per
    outdated component that matches a curated CVE. No exploitation is attempted."""
    settings = settings or get_settings()
    host = _target_host(target)
    if not host:
        return {"ok": False, "error": "Provide a URL or host to scan for known-CVE components."}
    if not host_in_active_scope(host, scope, settings):
        return {"ok": False, "error": f"{host} is not in the active scope — refusing to fetch (fail-closed)."}

    body = ""
    resp_headers: dict[str, Any] = {}
    fetched_url = ""
    for scheme in ("https", "http"):
        try:
            sanitized = _guard_url(normalize_website_url(f"{scheme}://{host}/"),
                                   settings.allow_private_urls, settings.web_allowed_ports)
            resp = _fetch_raw(sanitized)
        except (WebsiteFetchError, OSError, ValueError):
            continue
        fetched_url = resp.get("final_url") or sanitized
        body = resp.get("body") or ""
        resp_headers = resp.get("headers") or {}
        break
    if not fetched_url:
        return {"ok": False, "error": f"Could not fetch {host} over https/http within scope."}

    components = detect_components(body, resp_headers)
    findings: list[dict[str, Any]] = []
    for comp in components:
        cves = match_cves(comp["product"], comp["version"])
        if cves:
            findings.append(_build_finding(comp, cves, fetched_url))
    # Strongest (highest base_score, then EPSS) first.
    findings.sort(key=lambda f: ((f.get("_cve_list") or [{}])[0].get("base_score") or 0.0,
                                 f.get("_cve_max_epss") or 0.0), reverse=True)
    return {"ok": True, "target": fetched_url, "host": host,
            "components": components, "count": len(findings), "findings": findings}
