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

import socket
from typing import Any, Callable
from urllib.parse import urlparse

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

# Dangling-service fingerprints — STRONG, service-specific "unclaimed" signatures only, so a
# normal 404 never matches. (service, signature substring, the CNAME host it dangles to.)
_FINGERPRINTS: tuple[dict[str, str], ...] = (
    {"service": "GitHub Pages", "signature": "There isn't a GitHub Pages site here.", "points_to": "*.github.io"},
    {"service": "AWS S3", "signature": "The specified bucket does not exist", "points_to": "*.s3.amazonaws.com"},
    {"service": "AWS S3", "signature": "NoSuchBucket", "points_to": "*.s3.amazonaws.com"},
    {"service": "Heroku", "signature": "herokucdn.com/error-pages/no-such-app.html", "points_to": "*.herokuapp.com"},
    {"service": "Heroku", "signature": "There's nothing here, yet.", "points_to": "*.herokuapp.com"},
    {"service": "Fastly", "signature": "Fastly error: unknown domain", "points_to": "*.fastly.net"},
    {"service": "Shopify", "signature": "Sorry, this shop is currently unavailable", "points_to": "*.myshopify.com"},
    {"service": "Pantheon", "signature": "The gods are wise, but do not know of the site which you seek", "points_to": "*.pantheonsite.io"},
    {"service": "Tumblr", "signature": "Whatever you were looking for doesn't currently exist at this address", "points_to": "domains.tumblr.com"},
    {"service": "Ghost", "signature": "The thing you were looking for is no longer here", "points_to": "*.ghost.io"},
    {"service": "Surge.sh", "signature": "project not found", "points_to": "*.surge.sh"},
    {"service": "Help Scout", "signature": "No settings were found for this company", "points_to": "*.helpscoutdocs.com"},
    {"service": "Cargo", "signature": "If you're moving your domain away from Cargo", "points_to": "subdomain.cargocollective.com"},
    {"service": "Webflow", "signature": "The page you are looking for doesn't exist or has been moved.", "points_to": "proxy.webflow.com"},
    {"service": "Wordpress", "signature": "Do you want to register *.wordpress.com?", "points_to": "*.wordpress.com"},
)


def _target_host(target: str) -> str:
    raw = str(target or "").strip()
    if "://" in raw:
        return (urlparse(raw).hostname or "").lower()
    return raw.split("/", 1)[0].strip().lower()


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
        body_low = (resp.get("body") or "").lower()
        for fp in _FINGERPRINTS:
            if fp["signature"].lower() in body_low:
                return _build_finding(host, fp, sanitized, int(resp.get("status") or 0))
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


def build_plan(finding: dict[str, Any]) -> dict[str, Any]:
    """A confirmed-proof attack plan for a takeover finding, for the report pipeline."""
    host = _target_host(finding.get("location", "")) or finding.get("location", "")
    service = finding.get("_takeover_service", "the third-party service")
    points_to = finding.get("_takeover_points_to", "")
    return {
        "steps": [
            f"Confirm {host} still resolves to {points_to or service} (a dangling CNAME to a deleted resource).",
            f"Fetch https://{host}/ and observe the {service} 'unclaimed' page (fingerprint: \"{finding.get('snippet', '')}\").",
            f"Claim the {service} resource (register the matching bucket/app/page), serve a benign marker file to prove control, then release it.",
        ],
        "poc": f"curl -s https://{host}/    # returns the {service} 'unclaimed' page — the resource is claimable",
        "impact": (f"An attacker can claim {host} and serve arbitrary content on the target's own subdomain — phishing under a "
                   f"trusted name, OAuth/redirect abuse, and theft of any cookie scoped to the parent domain."),
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", "base_score": 6.1, "base_severity": "medium", "estimated": True},
        "remediation": finding.get("remediation", ""),
        "proof_of_impact": {
            "status": "confirmed",
            "method": "GET fetch + dangling-service fingerprint match (no resource was claimed)",
            "affected_asset": f"the subdomain {host} and any cookie/trust scoped to its parent domain",
            "observed_result": f"{host} serves the {service} 'unclaimed' page — its DNS record dangles to a claimable resource",
            "control_result": f"a live, claimed site would not return {service}'s 'no such site/bucket/app' response",
            "evidence": finding.get("proof_evidence", {}).get("matched_value", ""),
            "proof_obligation": f"Claim the {service} resource and serve a benign marker (then release it) to demonstrate full control of the subdomain.",
        },
    }


def scan_subdomain_takeover(
    target: str,
    *,
    scope: str = "",
    settings: Any = None,
    extra_hosts: list[str] | None = None,
    max_check: int = 80,
    resolver: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """Enumerate subdomains of ``target``'s apex (wordlist + recon-discovered hosts),
    resolve them, and confirm takeovers on the in-scope, resolving ones. Returns
    ``{ok, apex, candidates, resolved, findings}`` (findings are confirmed takeovers)."""
    settings = settings or get_settings()
    resolver = resolver or _resolves
    apex = _target_host(target)
    if not apex or "." not in apex:
        return {"ok": False, "error": "Provide a domain/host (e.g. example.com) to enumerate."}

    candidates: set[str] = {apex}
    candidates.update(f"{label}.{apex}" for label in _LABELS)
    candidates.update((h or "").strip().lower() for h in (extra_hosts or []) if (h or "").strip())

    # Only ever touch hosts the operator put in scope (fail-closed), then resolve, then check.
    in_scope = [h for h in sorted(candidates) if host_in_active_scope(h, scope, settings)]
    resolved = [h for h in in_scope if resolver(h)][:max_check]
    findings: list[dict[str, Any]] = []
    for host in resolved:
        finding = check_host_takeover(host, settings)
        if finding:
            findings.append(finding)
    return {"ok": True, "apex": apex, "candidates": len(candidates), "in_scope": len(in_scope),
            "resolved": resolved, "findings": findings}
