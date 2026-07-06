"""Triage scan findings into a prioritized, human-readable summary.

Always produces a deterministic local summary (works fully offline). If a remote
model is configured via GreyIQ's existing code_router config
(remote_enabled + remote_url + remote_model), it ALSO asks that model to
prioritize and explain, falling back to the local summary on any error. The
remote call targets an OpenAI-compatible /v1/chat/completions endpoint, which
covers Ollama, llama.cpp, LM Studio, vLLM, and hosted gateways.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import coder
from bughunter import secret_classification

_TOP = 8
_CITATION_WEIGHT = {"critical": 0.99, "high": 0.85, "medium": 0.6, "low": 0.4, "info": 0.2}

_CLASS_NOTE = {
    secret_classification.PUBLIC_CLIENT_KEY: "public client key — informational only, not a reportable secret without proof of impact",
    secret_classification.CANDIDATE_UNVERIFIED: "unverified candidate — regex/source match without validation",
    secret_classification.FALSE_POSITIVE: "false positive — issuer rejected it (dead/revoked) or a placeholder",
}


def _secret_class(finding: dict[str, Any]) -> str:
    """The strict classification for an exposed-key finding — an already-stamped one, or computed on the
    fly (the CLI code-scan path doesn't run the hunt's normalization). Empty for non-secret findings."""
    cls = str(finding.get("secret_classification") or "")
    if cls:
        return cls
    if secret_classification._is_secret_finding(finding):
        try:
            return secret_classification.classify_secret_finding(finding)
        except Exception:  # noqa: BLE001 - triage must never break on a malformed finding
            return ""
    return ""


def _display_severity(finding: dict[str, Any], cls: str) -> str:
    """The severity to SHOW — capped by classification so an unverified/public API key never prints High.
    For a non-secret finding the raw severity is returned UNCHANGED (preserving existing behaviour,
    including the case-sensitive citation-weight lookup)."""
    if cls and cls != secret_classification.CONFIRMED_SECRET:
        sev = str(finding.get("severity") or "").lower()
        return secret_classification.severity_for_classification(cls, sev or "info")
    return str(finding.get("severity") or "")


def _format_finding(index: int, finding: dict[str, Any]) -> str:
    location = finding.get("file_path", "")
    line = finding.get("line_start")
    where = f"{location}:{line}" if line else location
    cls = _secret_class(finding)
    severity = _display_severity(finding, cls).upper()
    lines = [f"{index}. [{severity}] {finding.get('rule_id', '')} - {where}"]
    if cls and cls != secret_classification.CONFIRMED_SECRET:
        lines.append(f"   [{cls}] {_CLASS_NOTE.get(cls, cls)}")
    if finding.get("title"):
        lines.append(f"   {finding['title']}")
    if finding.get("snippet"):
        lines.append(f"   `{str(finding['snippet'])[:160]}`")
    if finding.get("remediation"):
        lines.append(f"   Fix: {finding['remediation']}")
    return "\n".join(lines)


def summarize_findings(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        error = result.get("error", "scan failed")
        hint = f"\n\nInstall: `{result['install']}`" if result.get("install") else ""
        return f"**BugHunter** could not complete the scan: {error}{hint}"

    scan_type = result.get("scan_type", "code")
    target = result.get("target", "")
    risk = (result.get("risk") or "unknown").upper()
    score = result.get("score")
    count = result.get("finding_count", len(result.get("findings", [])))
    findings = result.get("findings", [])

    header = (
        f"**BugHunter - {scan_type} scan of `{target}`**\n"
        f"Risk: {risk}" + (f" (score {score})" if score is not None else "") + f" - {count} finding(s)"
    )
    if not findings:
        return f"{header}\n\n{result.get('recommendation') or 'No issues found at this depth.'}"

    top = findings[:_TOP]
    body = "\n".join(_format_finding(i + 1, f) for i, f in enumerate(top))
    more = f"\n\n(+{count - len(top)} more finding(s) not shown)" if count > len(top) else ""
    recommendation = result.get("recommendation", "")
    return f"{header}\n\nTop findings:\n{body}{more}\n\n{recommendation}".strip()


def _citations(result: dict[str, Any], limit: int = 6) -> list[dict[str, Any]]:
    citations: list[dict[str, Any]] = []
    for finding in result.get("findings", [])[:limit]:
        location = finding.get("file_path", "")
        line = finding.get("line_start")
        # Weight by the classification-adjusted severity so an unverified/public API key doesn't cite
        # as strongly as a proven finding.
        disp_sev = _display_severity(finding, _secret_class(finding))
        citations.append(
            {
                "source": f"{location}:{line}" if line else location,
                "score": _CITATION_WEIGHT.get(disp_sev, 0.3),
                "excerpt": f"{finding.get('title', '')} - {finding.get('snippet', '')}"[:200],
            }
        )
    return citations


def _completions_endpoint(url: str) -> str:
    endpoint = url.strip().rstrip("/")
    if "/chat/completions" in endpoint:
        return endpoint
    if endpoint.endswith("/v1"):
        return f"{endpoint}/chat/completions"
    return f"{endpoint}/v1/chat/completions"


def remote_triage(result: dict[str, Any], remote_config: dict[str, Any] | None) -> str | None:
    if not remote_config or not remote_config.get("remote_enabled"):
        return None
    url = str(remote_config.get("remote_url") or "").strip()
    model = str(remote_config.get("remote_model") or "").strip()
    if not url or not model:
        return None
    api_key = str(remote_config.get("remote_api_key") or "").strip()
    try:  # a hand-edited config can hold a truthy non-numeric ("5s"); never let it 500 the reply
        timeout = float(remote_config.get("remote_timeout_s") or 60.0)
    except (TypeError, ValueError):
        timeout = 60.0

    findings = result.get("findings", [])[:30]
    prompt = (
        "You are GreyIQ BugHunter, a security triage assistant. Given these scan findings "
        "(JSON), produce a short prioritized triage: the single most important issue first, "
        "group duplicates, flag likely false positives, and give the most valuable fix. Be "
        "concise and concrete.\n\n"
        "BE STRICT WITH SECRET / API-KEY FINDINGS — do NOT inflate their severity:\n"
        "- A value appearing in page/app source is NOT proof of a vulnerability. A regex match is NOT "
        "proof of a secret.\n"
        "- Only a `confirmed_secret` (each finding carries a `secret_classification` field) — a real "
        "privileged credential PROVEN usable, or a data store proven readable — may be Medium/High/"
        "Critical. Respect that field; never upgrade an unverified/public one to confirmed.\n"
        "- A Google/Firebase `AIza` browser key, OAuth client id, analytics id (GA/GTM), Firebase web "
        "config, CDN/endpoint URL, or public app id is a `public_client_key` — INFORMATIONAL only, not "
        "a reportable secret without proof of unauthorized access/impact.\n"
        "- Group unverified/public API-key findings in a SEPARATE section from confirmed secrets, and "
        "state plainly when a finding is NOT reportable yet (and what proof is missing).\n\n"
        "Findings JSON:\n"
        + json.dumps(
            {
                "scan_type": result.get("scan_type"),
                "target": result.get("target"),
                "risk": result.get("risk"),
                "findings": findings,
            },
            default=str,
        )[:12000]
    )
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    coder.apply_chat_completion_temperature(payload, url, model, 0.2)
    coder.apply_chat_completion_token_limit(payload, url, model, 700)

    def _send(body_payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            _completions_endpoint(url),
            data=json.dumps(body_payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if api_key:
            request.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))

    try:
        body = _send(payload)
        choices = body.get("choices") or []
        if choices:
            message = choices[0].get("message", {}).get("content") or choices[0].get("text")
            if message:
                return str(message).strip()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore")[:400] if hasattr(exc, "read") else ""
        retry_payload = coder.retry_payload_for_chat_completion_compat(payload, detail)
        if retry_payload:
            try:
                body = _send(retry_payload)
                choices = body.get("choices") or []
                if choices:
                    message = choices[0].get("message", {}).get("content") or choices[0].get("text")
                    if message:
                        return str(message).strip()
            except Exception:  # noqa: BLE001 - remote is best-effort; fall back to local
                return None
    except Exception:  # noqa: BLE001 - remote is best-effort; fall back to local
        return None
    return None


def triage(result: dict[str, Any], remote_config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return {summary, used_remote, citations}. Local summary always present;
    remote explanation appended when a model is configured and reachable."""
    local = summarize_findings(result)
    remote = remote_triage(result, remote_config) if result.get("ok") else None
    if remote:
        return {
            "summary": f"{local}\n\n---\nTriage:\n{remote}",
            "used_remote": True,
            "citations": _citations(result),
        }
    return {"summary": local, "used_remote": False, "citations": _citations(result)}
