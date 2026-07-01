"""GreyIQ BugHunter — subdomain enumeration + takeover confirmation.

Expands the attack surface (more subdomains = more bugs) and confirms a high-value, easy-
to-prove class: a **dangling subdomain takeover** — a DNS record still pointing at a
third-party service (GitHub Pages, S3, Heroku, Fastly, Shopify, …) whose resource has been
deleted, so an attacker can claim it and serve content on the target's subdomain.

Enumeration is self-contained: a bounded, curated label wordlist resolved via DNS (no
external API), plus any hosts recon already discovered. Each subdomain that resolves and is
IN SCOPE is fetched GET-only through the passive scanner's SSRF/private-host guard; a
takeover is CONFIRMED only on a strong, service-specific "unclaimed" fingerprint in the
response body (the public can-i-take-over-xyz corpus, curated to unique signatures to keep
false positives near zero). Pure / frozen-safe (stdlib socket + the existing guarded fetch).
"""

from __future__ import annotations

import json
import secrets
import socket
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse

from bughunter import dns_mini
from bughunter.active_verify_service import host_in_active_scope
from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _fetch_raw, _guard_url

# Bounded, curated common subdomain labels (DNS-resolved; no external API).
_LABELS = (
    "www", "api", "dev", "develop", "staging", "stage", "test", "qa", "uat", "admin", "app", "apps",
    "portal", "dashboard", "mail", "webmail", "smtp", "vpn", "remote", "git", "gitlab", "jenkins",
    "jira", "confluence", "blog", "shop", "store", "cdn", "assets", "static", "media", "files", "img",
    "images", "docs", "support", "help", "status", "beta", "demo", "internal", "intranet", "corp",
    "m", "mobile", "secure", "login", "auth", "sso", "old", "new", "legacy", "backup", "db", "data",
    "analytics", "grafana", "kibana", "ci", "build", "deploy", "preview",
)

# Dangling-service fingerprints — STRONG, service-specific "unclaimed" signatures ONLY, and
# matched only on an ERROR response (see check_host_takeover), so a normal page that merely
# quotes one of these phrases never confirms. Generic-404-grade phrases (e.g. Webflow's
# "The page you are looking for doesn't exist", Heroku's "There's nothing here, yet.") are
# DELIBERATELY excluded — they false-positive on countless normal sites. (service, signature
# substring, the service host the dangling record points to.)
_FINGERPRINTS: tuple[dict[str, str], ...] = (
    {"service": "GitHub Pages", "signature": "There isn't a GitHub Pages site here.", "points_to": "*.github.io"},
    {"service": "AWS S3", "signature": "The specified bucket does not exist", "points_to": "*.s3.amazonaws.com"},
    {"service": "AWS S3", "signature": "NoSuchBucket", "points_to": "*.s3.amazonaws.com"},
    {"service": "Heroku", "signature": "herokucdn.com/error-pages/no-such-app.html", "points_to": "*.herokuapp.com"},
    {"service": "Fastly", "signature": "Fastly error: unknown domain", "points_to": "*.fastly.net"},
    {"service": "Shopify", "signature": "Sorry, this shop is currently unavailable", "points_to": "*.myshopify.com"},
    {"service": "Pantheon", "signature": "The gods are wise, but do not know of the site which you seek", "points_to": "*.pantheonsite.io"},
    {"service": "Tumblr", "signature": "Whatever you were looking for doesn't currently exist at this address", "points_to": "domains.tumblr.com"},
    {"service": "Ghost", "signature": "The thing you were looking for is no longer here", "points_to": "*.ghost.io"},
    {"service": "Surge.sh", "signature": "project not found", "points_to": "*.surge.sh"},
    {"service": "Help Scout", "signature": "No settings were found for this company", "points_to": "*.helpscoutdocs.com"},
    {"service": "Cargo", "signature": "If you're moving your domain away from Cargo", "points_to": "subdomain.cargocollective.com"},
    {"service": "Wordpress", "signature": "Do you want to register *.wordpress.com?", "points_to": "*.wordpress.com"},
)


# CNAME targets that indicate a third-party hosting service which can be claimed if the
# resource is gone (dangling CNAME). Correlating a subdomain's CNAME with one of these catches
# takeovers the page-body fingerprint misses (e.g. the service returns nothing fetchable).
_CNAME_SERVICES: tuple[tuple[str, str], ...] = (
    (".github.io", "GitHub Pages"),
    (".s3.amazonaws.com", "AWS S3"),
    (".s3-website", "AWS S3"),
    (".herokudns.com", "Heroku"),
    (".herokuapp.com", "Heroku"),
    (".fastly.net", "Fastly"),
    (".myshopify.com", "Shopify"),
    (".pantheonsite.io", "Pantheon"),
    (".ghost.io", "Ghost"),
    (".surge.sh", "Surge.sh"),
    (".bitbucket.io", "Bitbucket"),
    (".helpscoutdocs.com", "Help Scout"),
    (".cargocollective.com", "Cargo"),
    (".wordpress.com", "Wordpress"),
    (".azurewebsites.net", "Azure App Service"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".cloudapp.net", "Azure"),
    (".readthedocs.io", "Read the Docs"),
    (".netlify.app", "Netlify"),
    (".wpengine.com", "WP Engine"),
    (".zendesk.com", "Zendesk"),
    (".tumblr.com", "Tumblr"),
)


def _match_cname_service(cnames: list[str] | None) -> tuple[str, str] | None:
    """Return (service, cname_target) if any CNAME target points at a takeoverable service."""
    for target in cnames or []:
        t = str(target or "").lower()
        for suffix, service in _CNAME_SERVICES:
            if suffix in t:
                return service, t
    return None


def _target_host(target: str) -> str:
    raw = str(target or "").strip()
    if "://" in raw:
        return (urlparse(raw).hostname or "").lower()
    return raw.split("/", 1)[0].strip().lower()


_CT_UA = "GreyIQ-BugHunter/ct"


def _ct_fetch_json(url: str, *, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": _CT_UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https crt.sh host
        return json.loads(resp.read(4_000_000).decode("utf-8", "replace"))


def cert_transparency_subdomains(apex: str, *, fetch_json: Callable[..., Any] | None = None,
                                 timeout: float = 10.0, max_names: int = 200) -> list[str]:
    """Seed subdomain enumeration from certificate-transparency logs (crt.sh). This is an
    OSINT lookup the operator explicitly opted into — it queries the public CT logs for the
    apex's issued certs, never the target itself. Returns a bounded, de-duplicated list of
    hostnames under ``apex`` (wildcards stripped). Best-effort: any failure returns ``[]`` so
    enumeration falls back to the wordlist + recon-discovered hosts."""
    apex = str(apex or "").strip().lower().strip(".")
    if not apex or "." not in apex:
        return []
    fetch_json = fetch_json or _ct_fetch_json
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    try:
        data = fetch_json(url, timeout=timeout)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return []
    if not isinstance(data, list):
        return []
    names: set[str] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        for raw in str(row.get("name_value") or "").split("\n"):
            h = raw.strip().lower().lstrip("*.").strip(".")
            if h and (h == apex or h.endswith("." + apex)) and " " not in h and "@" not in h:
                names.add(h)
        if len(names) >= max_names:
            break
    return sorted(names)[:max_names]


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except (OSError, UnicodeError):
        return False


def check_host_takeover(host: str, settings: Any = None) -> dict[str, Any] | None:
    """Fetch ``host`` (GET-only, SSRF-guarded) and return a takeover finding if its body
    carries a dangling-service fingerprint, else None."""
    settings = settings or get_settings()
    for scheme in ("https", "http"):
        try:
            sanitized = _guard_url(normalize_website_url(f"{scheme}://{host}/"),
                                   settings.allow_private_urls, settings.web_allowed_ports)
            resp = _fetch_raw(sanitized)
        except (WebsiteFetchError, OSError, ValueError):
            continue
        status = int(resp.get("status") or 0)
        # A genuinely dangling service serves its 'unclaimed' page as an ERROR (4xx/5xx).
        # Requiring a non-2xx status kills the false positive where a normal 200 page (a
        # status dashboard, a security blog, an aggregator) merely QUOTES one of these
        # phrases, and the case where a 30x redirects to such a page.
        if status < 400:
            continue
        body_low = (resp.get("body") or "").lower()
        for fp in _FINGERPRINTS:
            if fp["signature"].lower() in body_low:
                return _build_finding(host, fp, sanitized, status)
    return None


def _build_finding(host: str, fp: dict[str, str], url: str, status: int) -> dict[str, Any]:
    return {
        "rule_id": "active.subdomain-takeover",
        "title": f"Subdomain takeover: {host} → unclaimed {fp['service']}",
        "severity": "high",
        "confidence": "high",
        "category": "subdomain-takeover",
        "location": url,
        "file_path": url,
        "line_start": 1, "line_end": 1,
        "class_id": "subdomain-takeover",
        "class_name": "Subdomain takeover",
        "cwe": "CWE-350 / CWE-284",
        "owasp": "A05:2021 Security Misconfiguration",
        "references": [
            "https://owasp.org/www-community/attacks/Subdomain_Takeover",
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ],
        "vrt": "",
        "remediation": (f"Remove the dangling DNS record for {host}, or reclaim the {fp['service']} resource it "
                        f"points to. Audit all CNAME records for decommissioned third-party services."),
        # The fingerprint text is the THIRD-PARTY service's own 'unclaimed' page, not target data.
        "snippet": fp["signature"],
        "proof_evidence": {
            "request_line": f"GET {url}",
            "response_status": f"HTTP {status}",
            "matched_value": f"dangling {fp['service']} fingerprint (claimable): \"{fp['signature']}\"",
        },
        "_takeover_service": fp["service"],
        "_takeover_points_to": fp.get("points_to", ""),
    }


def _cname_candidate(host: str, service: str, target: str) -> dict[str, Any]:
    """A CANDIDATE takeover from CNAME correlation alone: the subdomain CNAMEs to a
    takeoverable service but serves no body fingerprint (the resource may simply be gone).
    The operator verifies the resource is claimable."""
    url = f"https://{host}/"
    return {
        "rule_id": "active.subdomain-takeover-cname",
        "title": f"Dangling CNAME: {host} → {service} (takeover candidate)",
        "severity": "medium",
        "confidence": "medium",
        "category": "subdomain-takeover",
        "location": url, "file_path": url,
        "line_start": 1, "line_end": 1,
        "class_id": "subdomain-takeover",
        "class_name": "Subdomain takeover",
        "cwe": "CWE-350 / CWE-284",
        "owasp": "A05:2021 Security Misconfiguration",
        "references": [
            "https://owasp.org/www-community/attacks/Subdomain_Takeover",
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ],
        "vrt": "",
        "remediation": f"Remove the dangling CNAME for {host}, or reclaim the {service} resource it points to.",
        "snippet": "",
        "proof_evidence": {
            "request_line": f"DNS CNAME {host} → {target}",
            "matched_value": (f"{host} CNAMEs to {target} ({service}) but serves no live takeover fingerprint — verify whether "
                              f"the {service} resource is unclaimed/claimable."),
        },
        "_takeover_service": service, "_takeover_points_to": target, "_takeover_cname": target,
        "_candidate": True,
    }


def build_plan(finding: dict[str, Any]) -> dict[str, Any]:
    """An attack plan for a takeover finding, for the report pipeline. Confirmed (body
    fingerprint) and CNAME-only candidates (``_candidate``) get the right proof tier + CVSS."""
    host = _target_host(finding.get("location", "")) or finding.get("location", "")
    service = finding.get("_takeover_service", "the third-party service")
    points_to = finding.get("_takeover_points_to", "")
    candidate = bool(finding.get("_candidate"))
    if candidate:
        steps = [
            f"Confirm {host} CNAMEs to {points_to or service} (a dangling CNAME).",
            f"Check whether the {service} resource is unclaimed — the page returns no live content / an error.",
            f"If claimable, register the matching {service} resource, serve a benign marker to prove control, then release it.",
        ]
        cvss = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "base_score": 6.5, "base_severity": "medium", "estimated": True}
        poi = {
            "status": "candidate",
            "method": "DNS CNAME correlation to a takeoverable service (no resource was claimed)",
            "affected_asset": f"the subdomain {host} and any cookie/trust scoped to its parent domain",
            "observed_result": f"{host} CNAMEs to {points_to} ({service}) but serves no live content — the resource may be claimable",
            "control_result": f"a live, claimed {service} resource would serve content, not a missing/error response",
            "evidence": finding.get("proof_evidence", {}).get("matched_value", ""),
            "proof_obligation": f"Confirm the {service} resource is unclaimed, then claim it + serve a benign marker (then release) to prove control.",
        }
    else:
        steps = [
            f"Confirm {host} still resolves to {points_to or service} (a dangling CNAME to a deleted resource).",
            f"Fetch https://{host}/ and observe the {service} 'unclaimed' page (fingerprint: \"{finding.get('snippet', '')}\").",
            f"Claim the {service} resource (register the matching bucket/app/page), serve a benign marker file to prove control, then release it.",
        ]
        cvss = {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N", "base_score": 7.6, "base_severity": "high",
            "estimated": False,
            "justification": (
                f"Actively confirmed: {host} serves the {service} 'unclaimed resource' fingerprint page, which "
                "only appears when the DNS record dangles to a claimable resource — not a template estimate."
            ),
        }
        poi = {
            "status": "confirmed",
            "method": "GET fetch + dangling-service fingerprint match (no resource was claimed)",
            "affected_asset": f"the subdomain {host} and any cookie/trust scoped to its parent domain",
            "observed_result": f"{host} serves the {service} 'unclaimed' page — its DNS record dangles to a claimable resource",
            "control_result": f"a live, claimed site would not return {service}'s 'no such site/bucket/app' response",
            "evidence": finding.get("proof_evidence", {}).get("matched_value", ""),
            "proof_obligation": f"Claim the {service} resource and serve a benign marker (then release it) to demonstrate full control of the subdomain.",
        }
    return {
        "steps": steps,
        "poc": f"curl -s https://{host}/    # the {service} resource the subdomain points to",
        "impact": (f"An attacker can claim {host} and serve arbitrary content on the target's own subdomain — phishing under a "
                   f"trusted name, OAuth/redirect abuse, and theft of any cookie scoped to the parent domain."),
        "cvss": cvss,
        "remediation": finding.get("remediation", ""),
        "proof_of_impact": poi,
    }


def scan_subdomain_takeover(
    target: str,
    *,
    scope: str = "",
    settings: Any = None,
    extra_hosts: list[str] | None = None,
    max_check: int = 80,
    resolver: Callable[[str], bool] | None = None,
    include_ct: bool = True,
    ct_fetch_json: Callable[..., Any] | None = None,
    cname_resolver: Callable[[str], list[str]] | None = None,
    max_cname: int = 40,
) -> dict[str, Any]:
    """Enumerate subdomains of ``target``'s apex (wordlist + recon-discovered hosts),
    resolve them, and confirm takeovers on the in-scope, resolving ones. Returns
    ``{ok, apex, candidates, resolved, findings}`` (findings are confirmed takeovers)."""
    settings = settings or get_settings()
    resolver = resolver or _resolves
    apex = _target_host(target)
    if not apex or "." not in apex:
        return {"ok": False, "error": "Provide a domain/host (e.g. example.com) to enumerate."}

    # Wildcard-DNS guard: if a random nonexistent label resolves, the apex has a catch-all
    # record so EVERY wordlist label would "resolve" to the same page and every fetch would
    # hit one catch-all — useless and noisy. Detect it and skip the pure-wordlist expansion,
    # relying on recon-discovered hosts (real CNAMEs) instead.
    wildcard = bool(resolver(f"greyiq-nx-{secrets.token_hex(6)}.{apex}"))
    candidates: set[str] = {apex}
    if not wildcard:
        candidates.update(f"{label}.{apex}" for label in _LABELS)
    candidates.update((h or "").strip().lower() for h in (extra_hosts or []) if (h or "").strip())
    # Certificate-transparency seeding (crt.sh) — OSINT the operator opted into. Surfaces real
    # subdomains the wordlist would miss (the highest-yield takeover source). Best-effort.
    ct_hosts = cert_transparency_subdomains(apex, fetch_json=ct_fetch_json) if include_ct else []
    candidates.update(ct_hosts)

    # Only ever touch hosts the operator put in scope (fail-closed), then resolve, then check.
    in_scope = [h for h in sorted(candidates) if host_in_active_scope(h, scope, settings)]
    resolved = [h for h in in_scope if resolver(h)][:max_check]
    cname_resolver = cname_resolver or (lambda h: dns_mini.resolve_cname(h, timeout=2.5))
    findings: list[dict[str, Any]] = []
    cname_lookups = 0
    for host in resolved:
        finding = check_host_takeover(host, settings)
        # CNAME correlation (bounded): enrich a confirmed finding, or surface a dangling-CNAME
        # candidate the body fingerprint missed.
        svc = None
        if cname_lookups < max_cname:
            cname_lookups += 1
            svc = _match_cname_service(cname_resolver(host))
        if finding:
            if svc:
                finding["_takeover_cname"] = svc[1]
                finding["proof_evidence"]["matched_value"] += f"; the subdomain also CNAMEs to {svc[1]} ({svc[0]})"
            findings.append(finding)
        elif svc:
            findings.append(_cname_candidate(host, svc[0], svc[1]))
    return {"ok": True, "apex": apex, "candidates": len(candidates), "in_scope": len(in_scope),
            "ct_count": len(ct_hosts), "cname_lookups": cname_lookups, "resolved": resolved, "findings": findings}
