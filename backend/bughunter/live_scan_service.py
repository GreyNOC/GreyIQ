"""GreyIQ BugHunter — dynamic live-app scan (Playwright).

Loads a URL in a real headless browser and observes runtime behavior that
static and passive scans cannot see: uncaught JavaScript exceptions, console
errors/warnings, failed network requests, and sub-resources returning 4xx/5xx.
This is where "bugs in live applications of all sorts" actually surface.

Playwright (Python) is an optional, heavy dependency (it downloads a browser).
If it is not installed, this returns a structured, non-fatal result with
install instructions rather than raising. The same SSRF guard as the passive
web scanner applies: private/loopback hosts are refused unless
GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1.

Install to enable:
    pip install playwright
    python -m playwright install chromium
"""

from __future__ import annotations

from typing import Any

from bughunter.settings import get_settings
from bughunter.web_ingest import WebsiteFetchError, normalize_website_url
from bughunter.web_scan_service import _guard_url

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 0.5,
    "high": 0.32,
    "medium": 0.18,
    "low": 0.06,
    "info": 0.02,
}
_SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_RISK_ADVICE = {
    "high": "Runtime errors detected in the live app. Reproduce and fix the exceptions/5xx before shipping.",
    "moderate": "Runtime warnings and failed requests detected. Review for broken features.",
    "low": "Minor runtime noise only. Triage as routine.",
    "clean": "No runtime errors observed during the load window.",
}


def _finding(rule_id: str, title: str, severity: str, confidence: str, url: str, snippet: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "category": "runtime",
        "file_path": url,
        "line_start": 1,
        "line_end": 1,
        "snippet": snippet[:240],
        "remediation": "",
    }


def _risk(findings: list[dict[str, Any]]) -> tuple[str, float]:
    score = round(min(1.0, sum(_SEVERITY_WEIGHT.get(f["severity"], 0.0) for f in findings)), 3)
    severities = {f["severity"] for f in findings}
    if severities & {"critical", "high"} or score >= 0.5:
        return "high", score
    if "medium" in severities or score >= 0.2:
        return "moderate", score
    if findings:
        return "low", score
    return "clean", score


def _not_installed(target: str) -> dict[str, Any]:
    return {
        "ok": False,
        "scan_type": "live",
        "target": target,
        "engine": "playwright",
        "available": False,
        "error": "Playwright (Python) is not installed; dynamic live-app scanning is unavailable.",
        "install": "pip install playwright && python -m playwright install chromium",
    }


def run_live_scan(url: str, wait_seconds: float = 6.0, max_findings: int = 300) -> dict[str, Any]:
    """Drive a URL in a headless browser and report runtime errors. Returns a
    JSON-serializable result; never raises for the common failure modes
    (missing dependency, bad URL, navigation error)."""
    target = str(url or "").strip()
    if not target:
        return {"ok": False, "scan_type": "live", "error": "No URL provided."}

    settings = get_settings()
    try:
        sanitized = _guard_url(
            normalize_website_url(target), settings.allow_private_urls, settings.web_allowed_ports
        )
    except WebsiteFetchError as exc:
        return {"ok": False, "scan_type": "live", "target": target, "error": str(exc)}

    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 - optional dependency
        return _not_installed(target)

    console_msgs: list[tuple[str, str]] = []
    page_errors: list[str] = []
    failed_requests: list[tuple[str, str]] = []
    bad_responses: list[tuple[str, int]] = []

    def on_console(message: Any) -> None:
        if message.type in {"error", "warning"}:
            console_msgs.append((message.type, message.text))

    def on_pageerror(error: Any) -> None:
        page_errors.append(str(error))

    def on_requestfailed(request: Any) -> None:
        failed_requests.append((request.url, request.failure or "failed"))

    def on_response(response: Any) -> None:
        if response.status >= 400:
            bad_responses.append((response.url, response.status))

    wait_ms = int(max(0.0, wait_seconds) * 1000)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.on("console", on_console)
            page.on("pageerror", on_pageerror)
            page.on("requestfailed", on_requestfailed)
            page.on("response", on_response)
            page.goto(sanitized, wait_until="load", timeout=wait_ms + 15000)
            page.wait_for_timeout(wait_ms)
            final_url = page.url
            title = page.title()
            browser.close()
    except Exception as exc:  # noqa: BLE001 - navigation/runtime errors -> data
        return {
            "ok": False,
            "scan_type": "live",
            "target": target,
            "engine": "playwright",
            "error": f"{type(exc).__name__}: {exc}",
        }

    findings: list[dict[str, Any]] = []
    for error in page_errors:
        findings.append(_finding("live.js-exception", "Uncaught JavaScript exception", "high", "high", final_url, error))
    for kind, text in console_msgs:
        severity = "medium" if kind == "error" else "low"
        findings.append(_finding(f"live.console-{kind}", f"Console {kind}", severity, "medium", final_url, text))
    for req_url, reason in failed_requests:
        findings.append(_finding("live.request-failed", "Failed network request", "medium", "high", final_url, f"{req_url} ({reason})"))
    for res_url, status in bad_responses:
        severity = "medium" if status >= 500 else "low"
        findings.append(_finding("live.bad-status", f"Sub-resource returned HTTP {status}", severity, "high", final_url, res_url))

    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 0), reverse=True)
    risk, score = _risk(findings)
    return {
        "ok": True,
        "scan_type": "live",
        "engine": "playwright",
        "target": target,
        "final_url": final_url,
        "title": title,
        "risk": risk,
        "score": score,
        "recommendation": _RISK_ADVICE[risk],
        "finding_count": len(findings),
        "findings": findings[:max_findings],
        "counts": {
            "page_errors": len(page_errors),
            "console_errors": sum(1 for k, _ in console_msgs if k == "error"),
            "console_warnings": sum(1 for k, _ in console_msgs if k == "warning"),
            "failed_requests": len(failed_requests),
            "bad_responses": len(bad_responses),
        },
    }
