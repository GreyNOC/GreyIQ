"""Redaction helpers for the code scanner.

Secret findings come back with their raw value embedded in the snippet
(it's how the regex matched). Returning that to the API or writing it
into a downloadable report just creates a second copy of the
credential. We post-process every secret.* finding through this module
so the snippet retains enough context for triage without exposing the
secret itself.

The redaction format is deterministic so two findings of the same
secret in different files collapse to the same redacted form, making
review across a report easier.
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

from bughunter.code_scanner.model import Finding

# Patterns we redact, keyed by category. Each pattern matches the
# secret literally inside a snippet. The same regex is used to walk
# the snippet and replace every hit.
_SECRET_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    # AWS secret value following an aws_secret_access_key=...
    re.compile(r"(?<=[\"' :=])[A-Za-z0-9/+=]{40}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}\b"),
)

# Generic password-style assignment: keyword = "value". For these we
# redact the *value* portion only, keeping the keyword visible so the
# analyst still sees which variable was assigned.
_GENERIC_PASSWORD_RE: Final = re.compile(
    r"((?:password|passwd|pwd|secret|api[_\-]?key|token|access[_\-]?token)"
    r"[\"' ]*[:=][\"' ]*)([A-Za-z0-9!@#$%^&*()_+=\-/]{6,})",
    re.IGNORECASE,
)

# .env style KEY=VALUE, one line. Redact the VALUE.
_DOTENV_RE: Final = re.compile(
    r"^([A-Z][A-Z0-9_]{2,}\s*=\s*)([A-Za-z0-9_+/=\-]{10,})\s*$",
    re.MULTILINE,
)

# PEM block start line. We keep the line but mark the block redacted —
# the actual body is rarely in the bounded snippet anyway, but we
# guarantee it never leaks.
_PEM_RE: Final = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----[\s\S]*?-----END"
)


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _format_redacted(value: str) -> str:
    """Return a redacted placeholder that keeps a few chars of context.

    For values >= 12 chars: prefix4...suffix4 [REDACTED_SECRET:sha256:12].
    For short values: full [REDACTED_SECRET:sha256:12] without prefix
    so the analyst doesn't accidentally guess the secret from 2 chars.
    """
    short = _short_hash(value)
    if len(value) >= 12:
        return f"{value[:4]}...{value[-4:]} [REDACTED_SECRET:sha256:{short}]"
    return f"[REDACTED_SECRET:sha256:{short}]"


def redact_text(text: str) -> tuple[str, bool]:
    """Public entry point — apply every secret pattern to ``text``.

    Returns ``(redacted_text, was_redacted)``. Used by the LLM adapter to
    sanitize free-form model output (rationale strings, title strings)
    that could echo a literal credential the model just saw.
    """
    return _redact_text(text)


def _redact_text(text: str) -> tuple[str, bool]:
    """Apply every secret pattern to ``text``; return (new_text, was_redacted)."""
    redacted_any = False

    # PEM blocks: stamp the entire block. Run first so the subsequent
    # patterns don't independently chew on its body.
    new_text, count = _PEM_RE.subn("[REDACTED_PRIVATE_KEY_BLOCK]", text)
    if count:
        redacted_any = True
        text = new_text

    # Generic password assignment — redact the value half.
    def _replace_password(match: re.Match[str]) -> str:
        prefix, value = match.group(1), match.group(2)
        return f"{prefix}{_format_redacted(value)}"

    new_text, count = _GENERIC_PASSWORD_RE.subn(_replace_password, text)
    if count:
        redacted_any = True
        text = new_text

    new_text, count = _DOTENV_RE.subn(
        lambda m: f"{m.group(1)}{_format_redacted(m.group(2))}", text
    )
    if count:
        redacted_any = True
        text = new_text

    # Vendor-specific value patterns.
    for pattern in _SECRET_VALUE_PATTERNS:
        def _replace(match: re.Match[str]) -> str:
            return _format_redacted(match.group(0))

        new_text, count = pattern.subn(_replace, text)
        if count:
            redacted_any = True
            text = new_text

    return text, redacted_any


def redact_finding_snippets(findings: list[Finding]) -> tuple[list[Finding], dict[str, bool]]:
    """Return a new list of findings whose snippets are redacted.

    We run the secret-value patterns over *every* finding's snippet, not
    just `secret.*` rules. A backdoor / network / crypto rule that
    happens to match a line containing a hardcoded AWS key would
    otherwise leak the secret into the response and downloadable report.

    Returns a map keyed by the finding's identity (rule_id + file_path
    + line_start) → True when that finding was redacted. The
    orchestrator uses this map to set ``redacted=True`` on the
    response schema.
    """
    out: list[Finding] = []
    redacted_map: dict[str, bool] = {}
    for finding in findings:
        new_snippet, was_redacted = _redact_text(finding.snippet)
        new_desc, desc_redacted = _redact_text(finding.description)
        if not was_redacted and not desc_redacted:
            out.append(finding)
            continue
        out.append(
            Finding(
                rule_id=finding.rule_id,
                title=finding.title,
                description=new_desc,
                severity=finding.severity,
                confidence=finding.confidence,
                category=finding.category,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                snippet=new_snippet,
                remediation=finding.remediation,
                column_start=finding.column_start,
                column_end=finding.column_end,
            )
        )
        redacted_map[
            f"{finding.rule_id}@{finding.file_path}:{finding.line_start}"
        ] = True
    return out, redacted_map
