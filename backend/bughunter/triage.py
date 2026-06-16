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
import urllib.request
from typing import Any

_TOP = 8
_CITATION_WEIGHT = {"critical": 0.99, "high": 0.85, "medium": 0.6, "low": 0.4, "info": 0.2}


def _format_finding(index: int, finding: dict[str, Any]) -> str:
    location = finding.get("file_path", "")
    line = finding.get("line_start")
    where = f"{location}:{line}" if line else location
    severity = (finding.get("severity") or "").upper()
    lines = [f"{index}. [{severity}] {finding.get('rule_id', '')} - {where}"]
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
        citations.append(
            {
                "source": f"{location}:{line}" if line else location,
                "score": _CITATION_WEIGHT.get(finding.get("severity"), 0.3),
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
    timeout = float(remote_config.get("remote_timeout_s") or 60.0)

    findings = result.get("findings", [])[:30]
    prompt = (
        "You are GreyIQ BugHunter, a security triage assistant. Given these scan findings "
        "(JSON), produce a short prioritized triage: the single most important issue first, "
        "group duplicates, flag likely false positives, and give the most valuable fix. Be "
        "concise and concrete.\n\nFindings JSON:\n"
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
        "temperature": 0.2,
        "max_tokens": 700,
        "stream": False,
    }
    request = urllib.request.Request(
        _completions_endpoint(url),
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    if api_key:
        request.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8", errors="replace"))
        choices = body.get("choices") or []
        if choices:
            message = choices[0].get("message", {}).get("content") or choices[0].get("text")
            if message:
                return str(message).strip()
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
