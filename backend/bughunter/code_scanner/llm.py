"""Bring-your-own-LLM adapter.

The static scanner never makes network calls. This module is the
opt-in seam where a user pastes their own API key, picks a provider
(OpenAI-compatible chat API or Anthropic Messages API), and asks the
LLM to second-guess findings.

The adapter is deliberately conservative:
  * No keys are persisted to disk by this module — the caller hands a
    key in per request.
  * Each prompt sends only the rule context and a bounded snippet of
    code, never the whole repo.
  * Output is forced into a small JSON schema ({verdict, rationale}).
    Anything that doesn't match maps to ``verdict="error"``.
  * Network calls go through stdlib urllib so we don't add a runtime
    dependency on httpx / requests.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

from bughunter.code_scanner.model import Finding, LlmVerification
from bughunter.code_scanner.redaction import redact_text

# Cap egress so a user holding a finger to the API doesn't accidentally
# spend big.
_MAX_SNIPPET_CHARS: Final = 4_000
_MAX_FILE_CHARS_PER_LLM_FILE_SCAN: Final = 16_000
_REQUEST_TIMEOUT_SECONDS: Final = 30
_ALLOWED_PROVIDERS: Final = frozenset({"openai", "anthropic"})


@dataclass(frozen=True)
class LlmConfig:
    provider: str  # "openai" or "anthropic"
    model: str
    api_key: str
    base_url: str = ""
    max_tokens: int = 512


class LlmBaseUrlError(ValueError):
    """Raised when the user-supplied LLM base_url fails the safety check."""


_LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})


def _validate_base_url(base_url: str) -> str:
    """Reject base_urls that would leak the API key or hit private networks.

    Rules:
      * Empty string is fine — the dispatcher falls back to the public
        provider default.
      * Plain http:// is only accepted for loopback hosts (developer
        proxies). Everything else must be https://. Sending an API key
        over cleartext to a non-loopback host would expose it on any
        intermediate hop.
      * The hostname must resolve to a public IP. This blocks
        SSRF-style payloads pointed at the AWS metadata service
        (169.254.169.254), the container network (172.17.x.x), the
        loopback range, and any private/reserved space.
    """
    if not base_url:
        return ""
    parsed = urlparse(base_url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise LlmBaseUrlError("LLM base_url must be http(s).")
    host = (parsed.hostname or "").strip()
    if not host:
        raise LlmBaseUrlError("LLM base_url is missing a host.")
    if parsed.scheme == "http" and host.lower() not in _LOOPBACK_HOSTS:
        raise LlmBaseUrlError(
            "Plain http:// is only allowed for loopback hosts. Use https:// to keep your API key off the wire."
        )
    if parsed.username or parsed.password:
        raise LlmBaseUrlError("LLM base_url may not embed credentials.")
    if host.lower() in _LOOPBACK_HOSTS:
        return base_url.strip()
    try:
        addresses = []
        try:
            addresses.append(ipaddress.ip_address(host))
        except ValueError:
            for entry in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
                addresses.append(ipaddress.ip_address(entry[4][0]))
        for address in addresses:
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
            ):
                raise LlmBaseUrlError(
                    "LLM base_url resolves to a private / loopback / reserved address."
                )
    except socket.gaierror as error:
        raise LlmBaseUrlError(f"LLM base_url host could not be resolved: {host}") from error
    return base_url.strip()


_SYSTEM_PROMPT = (
    "You are a senior application-security reviewer. The user will paste a "
    "static-analysis finding plus the surrounding code. Respond with JSON only, "
    "matching this schema exactly:\n"
    '{"verdict": "likely_true_positive"|"likely_false_positive"|"uncertain", '
    '"rationale": "<one short sentence>"}\n'
    "Do not output anything outside the JSON object."
)


_WHOLE_FILE_SYSTEM_PROMPT = (
    "You are a senior application-security reviewer. The user will paste a "
    "complete source file. Identify any backdoor, RCE primitive, or planted "
    "credential. Respond with JSON only, an array of findings each shaped:\n"
    '{"title": "<short label>", "line": <int>, "rationale": "<one sentence>", '
    '"severity": "low"|"medium"|"high"|"critical"}\n'
    "If nothing is wrong, respond with an empty JSON array."
)


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n…[truncated]"


def _post_json(url: str, body: dict, headers: dict[str, str]) -> dict | str:
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
    except urllib.error.HTTPError as error:
        return f"HTTPError {error.code}: {error.reason}"
    except urllib.error.URLError as error:
        return f"URLError: {error.reason}"
    except TimeoutError:
        return "Request timed out."


def _extract_first_json(text: str) -> dict | list | None:
    """Pull the first JSON object or array out of a possibly noisy response.

    LLMs sometimes wrap structured output in markdown fences or
    leading prose. The static scanner contract is "the model can lie
    but it must not crash us", so we extract aggressively but never
    raise.
    """
    if not isinstance(text, str):
        return None
    # Strip markdown fences and surrounding prose.
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text)
    text = re.sub(r"```$", "", text)
    text = text.strip()
    # Find first balanced JSON object or array.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for index, ch in enumerate(text[start:], start=start):
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    chunk = text[start : index + 1]
                    try:
                        return json.loads(chunk)
                    except json.JSONDecodeError:
                        break
    return None


def verify_finding(config: LlmConfig, finding: Finding, code: str) -> LlmVerification:
    """Send a single finding + surrounding code to the user's LLM."""
    if config.provider not in _ALLOWED_PROVIDERS:
        return LlmVerification(
            provider=config.provider,
            model=config.model,
            verdict="error",
            rationale=f"unsupported provider: {config.provider}",
        )
    try:
        _validate_base_url(config.base_url)
    except LlmBaseUrlError as error:
        return LlmVerification(
            provider=config.provider,
            model=config.model,
            verdict="error",
            rationale=f"base_url rejected: {error}",
        )
    snippet = _truncate(code, _MAX_SNIPPET_CHARS)
    user_text = (
        f"Rule: {finding.rule_id} — {finding.title}\n"
        f"Severity: {finding.severity.value} / confidence: {finding.confidence.value}\n"
        f"File: {finding.file_path}:{finding.line_start}-{finding.line_end}\n"
        f"Description: {finding.description}\n\n"
        f"Code:\n{snippet}\n"
    )
    response = _call_provider(config, _SYSTEM_PROMPT, user_text)
    parsed = _extract_first_json(response)
    if not isinstance(parsed, dict):
        return LlmVerification(
            provider=config.provider,
            model=config.model,
            verdict="error",
            rationale=str(response)[:240],
        )
    verdict = str(parsed.get("verdict", "uncertain")).lower()
    if verdict not in {"likely_true_positive", "likely_false_positive", "uncertain"}:
        verdict = "uncertain"
    # Sanitize the model's free-form rationale on the way back. If the
    # LLM echoed any of the snippet it just saw (or fabricated a secret
    # token in its explanation), the redactor catches it before we
    # surface the string to API clients / reports.
    safe_rationale, _ = redact_text(str(parsed.get("rationale", ""))[:240])
    return LlmVerification(
        provider=config.provider,
        model=config.model,
        verdict=verdict,
        rationale=safe_rationale,
    )


def scan_whole_file(config: LlmConfig, file_path: str, code: str) -> list[dict]:
    """Ask the user's LLM to scan a complete file end-to-end.

    Returns a list of `{title, line, rationale, severity}` dicts. The
    caller folds them into the ScanResult findings list.
    """
    if config.provider not in _ALLOWED_PROVIDERS:
        return []
    try:
        _validate_base_url(config.base_url)
    except LlmBaseUrlError:
        return []
    snippet = _truncate(code, _MAX_FILE_CHARS_PER_LLM_FILE_SCAN)
    user_text = f"Path: {file_path}\n\n{snippet}"
    response = _call_provider(config, _WHOLE_FILE_SYSTEM_PROMPT, user_text)
    parsed = _extract_first_json(response)
    if not isinstance(parsed, list):
        return []
    cleaned: list[dict] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        safe_title, _ = redact_text(str(entry.get("title", ""))[:160])
        safe_rationale, _ = redact_text(str(entry.get("rationale", ""))[:240])
        cleaned.append(
            {
                "title": safe_title,
                "line": int(entry.get("line", 1)) if str(entry.get("line", "")).isdigit() else 1,
                "rationale": safe_rationale,
                "severity": str(entry.get("severity", "medium")).lower(),
            }
        )
    return cleaned


def _call_provider(config: LlmConfig, system: str, user: str) -> str:
    """Dispatch the configured provider and return raw response text."""
    if config.provider == "openai":
        return _call_openai_compatible(config, system, user)
    if config.provider == "anthropic":
        return _call_anthropic(config, system, user)
    return ""


def _call_openai_compatible(config: LlmConfig, system: str, user: str) -> str:
    base = config.base_url.rstrip("/") if config.base_url else "https://api.openai.com"
    url = f"{base}/v1/chat/completions"
    body = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.0,
        "max_tokens": config.max_tokens,
    }
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }
    response = _post_json(url, body, headers)
    if isinstance(response, str):
        return response
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(response)[:240]


def _call_anthropic(config: LlmConfig, system: str, user: str) -> str:
    base = config.base_url.rstrip("/") if config.base_url else "https://api.anthropic.com"
    url = f"{base}/v1/messages"
    body = {
        "model": config.model,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "max_tokens": config.max_tokens,
        "temperature": 0.0,
    }
    headers = {
        "x-api-key": config.api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    response = _post_json(url, body, headers)
    if isinstance(response, str):
        return response
    try:
        return response["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(response)[:240]
