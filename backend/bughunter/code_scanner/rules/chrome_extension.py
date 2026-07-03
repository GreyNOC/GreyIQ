"""Chrome / browser extension security rules.

Google runs a paid Chrome Extensions security program, and extensions are plain JS/HTML/JSON you
can analyze statically. This pack parses ``manifest.json`` and — ONLY when it is a real browser
extension manifest (``manifest_version`` present) — flags the dangerous configurations reviewers pay
for: over-broad host access, a page-scriptable CSP (``unsafe-eval``), an ``externally_connectable``
open to any site, and high-privilege permissions. Gating on ``manifest_version`` keeps it off web-app
/ PWA manifests, so it does not false-positive on non-extension ``manifest.json`` files.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass

from bughunter.code_scanner.model import Confidence, Finding, Severity
from bughunter.code_scanner.rules.base import Rule

# Host patterns that grant the extension access to EVERY site the user visits.
_BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*", "http://*", "https://*")
# Permissions that are individually high-privilege (data theft / traffic control / code injection).
_DANGEROUS_PERMS = {
    "debugger": ("full DevTools-protocol control of pages (arbitrary script, network, storage)", Severity.HIGH),
    "nativeMessaging": ("a bridge to a native host binary (extension → local code execution)", Severity.HIGH),
    "management": ("enumerate/disable/enable other extensions", Severity.MEDIUM),
    "proxy": ("reroute all of the user's traffic", Severity.HIGH),
    "cookies": ("read the user's cookies (session theft when combined with broad hosts)", Severity.MEDIUM),
    "webRequest": ("observe/modify the user's network requests", Severity.MEDIUM),
    "webRequestBlocking": ("block/rewrite the user's network requests", Severity.MEDIUM),
    "declarativeNetRequestFeedback": ("inspect matched network requests", Severity.LOW),
    "clipboardRead": ("read the user's clipboard", Severity.MEDIUM),
}


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return (text.count("\n", 0, idx) + 1) if idx >= 0 else 1


@dataclass(frozen=True)
class ChromeManifestRule(Rule):
    """Parse a browser-extension ``manifest.json`` and yield a finding per dangerous setting.
    Each emitted Finding carries its OWN rule_id/severity (the instance fields are placeholders)."""

    def scan(self, *, path: str, text: str) -> Iterable[Finding]:
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return
        if not isinstance(data, dict) or "manifest_version" not in data:
            return  # not a browser-extension manifest -> never fires on a web-app / PWA manifest.json

        def finding(rule_id: str, title: str, description: str, severity: Severity,
                    confidence: Confidence, needle: str, remediation: str) -> Finding:
            line = _line_of(text, needle)
            return Finding(
                rule_id=rule_id, title=title, description=description, severity=severity,
                confidence=confidence, category="chrome-extension", file_path=path,
                line_start=line, line_end=line, snippet=(needle or "")[:240], remediation=remediation,
            )

        # --- Over-broad host access (permissions / host_permissions / content_scripts matches) ---
        host_lists: list[str] = []
        for field in ("permissions", "host_permissions", "optional_permissions", "optional_host_permissions"):
            host_lists += [str(x) for x in (data.get(field) or []) if isinstance(x, str)]
        for cs in (data.get("content_scripts") or []):
            if isinstance(cs, dict):
                host_lists += [str(m) for m in (cs.get("matches") or []) if isinstance(m, str)]
        broad = sorted({h for h in host_lists if h in _BROAD_HOSTS})
        if broad:
            yield finding(
                "chrome.ext.broad-host-access",
                "Extension requests access to ALL sites",
                f"The manifest grants the extension host access to every site the user visits ({', '.join(broad)}). "
                "Any XSS/compromise in the extension becomes universal access to the user's browsing.",
                Severity.HIGH, Confidence.HIGH, broad[0],
                "Scope host_permissions / content_scripts matches to the specific origins the extension needs.",
            )

        # --- Content Security Policy allowing unsafe-eval (page-scriptable extension) ---
        csp = data.get("content_security_policy")
        csp_str = ""
        if isinstance(csp, str):
            csp_str = csp
        elif isinstance(csp, dict):
            csp_str = " ".join(str(v) for v in csp.values())
        if "unsafe-eval" in csp_str.lower():
            yield finding(
                "chrome.ext.csp-unsafe-eval",
                "Extension CSP allows unsafe-eval",
                "The extension's content_security_policy permits 'unsafe-eval', re-enabling eval()/new Function() in a "
                "high-privilege context — untrusted data reaching it is code execution in the extension.",
                Severity.HIGH, Confidence.HIGH, "unsafe-eval",
                "Remove 'unsafe-eval'; refactor away from eval/new Function (required for Manifest V3).",
            )

        # --- externally_connectable open to any website ---
        ec = data.get("externally_connectable")
        if isinstance(ec, dict):
            ec_matches = [str(m) for m in (ec.get("matches") or []) if isinstance(m, str)]
            if any(m in _BROAD_HOSTS for m in ec_matches):
                yield finding(
                    "chrome.ext.externally-connectable-any",
                    "externally_connectable open to any site",
                    "Any web page can send messages to this extension (externally_connectable matches all sites). If the "
                    "message handler is not strictly validated, a malicious page drives the extension's privileged APIs.",
                    Severity.HIGH, Confidence.MEDIUM,
                    next(m for m in ec_matches if m in _BROAD_HOSTS),
                    "Restrict externally_connectable.matches to the specific first-party origins allowed to message the extension.",
                )

        # --- Individually high-privilege permissions ---
        perms = {str(p) for p in (data.get("permissions") or []) + (data.get("optional_permissions") or []) if isinstance(p, str)}
        for perm, (why, severity) in _DANGEROUS_PERMS.items():
            if perm in perms:
                yield finding(
                    "chrome.ext.dangerous-permission",
                    f"High-privilege extension permission: {perm}",
                    f"The extension requests the '{perm}' permission — {why}. Confirm it is necessary and, combined with "
                    "broad host access, treat it as a data-exfiltration / control primitive.",
                    severity, Confidence.MEDIUM, f'"{perm}"',
                    f"Drop '{perm}' if unused; otherwise document why and minimise its blast radius.",
                )


RULES: tuple[Rule, ...] = (
    ChromeManifestRule(
        rule_id="chrome.ext.manifest",
        title="Chrome extension manifest",
        description="Analyzes a browser-extension manifest for dangerous permissions/config.",
        severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, category="chrome-extension",
        path_globs=("**/manifest.json",),
    ),
)
