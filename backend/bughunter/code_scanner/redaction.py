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

import dataclasses
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
    # GitLab / npm / SendGrid / DigitalOcean tokens — all treated as real secrets elsewhere, so their
    # raw value must be redacted out of a snippet the same as the AWS/GitHub/Stripe shapes above.
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    # JWT by shape. Thresholds MIRROR ``sensitive_data._JWT_RE`` ({5,}/{5,}/{5,}) so every JWT the
    # classifier NAMES is also strippable here — a stricter {8,}/{8,}/{16,} let a short-signature or
    # compact-payload JWT be named "a JWT" yet left verbatim in an "already redacted" excerpt.
    re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b"),
)

# Generic password-style assignment: keyword = "value". For these we
# redact the *value* portion only, keeping the keyword visible so the
# analyst still sees which variable was assigned.
_GENERIC_PASSWORD_RE: Final = re.compile(
    r"((?:password|passwd|pwd|secret|api[_\-]?key|token|access[_\-]?token)"
    r"[\"' ]*[:=][\"' ]*)([A-Za-z0-9!@#$%^&*()_+=\-/]{6,})",
    re.IGNORECASE,
)

# .env style KEY=VALUE. Redact the VALUE. NOT anchored to ^...$ — snippets are
# often whitespace-collapsed to a single line (the web/live scanners do this), so
# anchored matching would silently miss every KEY=VALUE on a collapsed line and
# leak the adjacent credentials. We match each KEY=VALUE at a word boundary.
_DOTENV_RE: Final = re.compile(
    r"(?:^|(?<=\s))([A-Z][A-Z0-9_]{2,}\s*=\s*)([A-Za-z0-9_+/=\-]{10,})",
    re.MULTILINE,
)

# PEM block start line. We keep the line but mark the block redacted —
# the actual body is rarely in the bounded snippet anyway, but we
# guarantee it never leaks.
_PEM_RE: Final = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----[\s\S]*?-----END"
)

# Fallback for a private-key header with NO matching -----END----- (the snippet
# was truncated mid-key, which is exactly when the body would otherwise leak).
# Stamp from the header to the end of the text so the key material never escapes.
_PEM_LONE_RE: Final = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----[\s\S]*"
)

# Key-anchored authenticated-session material — session identifiers, CSRF/anti-forgery tokens,
# OAuth access/refresh/id tokens, and opaque ``Authorization: Bearer`` values. These are the exact
# classes ``bughunter.sensitive_data.classify`` NAMES as sensitive in a captured proof body, but the
# vendor-secret patterns above only strip vendor-shaped keys and JWTs — an opaque bearer token or a
# lowercase ``"session_id": "…"`` (common in JSON bodies) has no vendor shape and would otherwise be
# rendered verbatim into a report/evidence file whose header claims it is "already redacted". Each
# pattern captures ``(key + delimiter prefix, value)`` so only the value half is stamped, keeping the
# field name visible for triage. The field-name alternations MIRROR
# ``sensitive_data._KEYED_SESSION_PATTERNS`` — ``test_security_fixes`` asserts the two cannot drift so
# that anything the classifier can name is guaranteed redactable. Linear-time (no nested quantifiers).
_KEYED_SESSION_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # CSRF / anti-forgery tokens.
    re.compile(
        r"(?i)(\b(?:csrf[_-]?token|csrfmiddlewaretoken|xsrf[_-]?token|authenticity_token|"
        r"request(?:_)?verification_?token|anti[_-]?csrf[_-]?token)\b['\"]?\s*[:=]\s*['\"]?)"
        r"([A-Za-z0-9._+/\-]{16,})"
    ),
    # Session identifiers (cookie or JSON, any case; value charset allows %-encoding and dots).
    re.compile(
        r"(?i)(\b(?:session[_-]?id|sessionid|phpsessid|jsessionid|connect\.sid|asp\.net_sessionid|"
        r"auth[_-]?session)\b['\"]?\s*[:=]\s*['\"]?)([A-Za-z0-9._%\-]{12,})"
    ),
    # OAuth access / refresh / id tokens.
    re.compile(
        r"(?i)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token)\b['\"]?\s*[:=]\s*['\"]?)"
        r"([A-Za-z0-9._+/\-]{16,})"
    ),
    # Opaque (or JWT) bearer authorization value.
    re.compile(
        r"(?i)(\bauthorization\b['\"]?\s*[:=]\s*['\"]?bearer\s+)([A-Za-z0-9._+/\-]{16,})"
    ),
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


def redact_secret(value: str) -> str:
    """Redact an EXACT secret value to a safe prefix…suffix placeholder — never the full key.

    Unlike ``redact_text`` (which only redacts substrings matching a known vendor pattern), this
    redacts the whole value you hand it, so a report can show that a credential exists and enough of
    it to correlate ("AIzaSyAB…w3xyz") without ever printing the usable key. Deterministic: the same
    value always yields the same placeholder."""
    v = str(value or "").strip()
    if not v:
        return ""
    return _format_redacted(v)


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
    # Then catch a truncated key whose END marker was clipped off (the lone-BEGIN
    # case). If the block above already stamped it, the BEGIN header is gone, so
    # this can't double-match.
    new_text, count = _PEM_LONE_RE.subn("[REDACTED_PRIVATE_KEY_BLOCK]", text)
    if count:
        redacted_any = True
        text = new_text

    # Key-anchored session/bearer/OAuth/CSRF material — redact the value half, keep the field name.
    # MUST run BEFORE the generic-password pass: its value charset includes '.', so it strips a whole
    # dotted JWT in an ``access_token``/``session_id`` field. The generic-password pass's value charset
    # EXCLUDES '.', so if it ran first it would match only the JWT header (up to the first dot), break
    # the ``eyJ.eyJ.`` structure, and leave the payload+signature verbatim where neither the keyed nor
    # the JWT-shape pass could re-match — leaking a recoverable token into an "already redacted" excerpt.
    for pattern in _KEYED_SESSION_VALUE_PATTERNS:
        new_text, count = pattern.subn(
            lambda m: f"{m.group(1)}{_format_redacted(m.group(2))}", text
        )
        if count:
            redacted_any = True
            text = new_text

    # Vendor-specific value patterns (incl. the JWT shape) — also BEFORE generic-password so a bare
    # JWT in a non-keyword field is stripped by structure before the dot-truncating pass can chew it.
    for pattern in _SECRET_VALUE_PATTERNS:
        def _replace(match: re.Match[str]) -> str:
            return _format_redacted(match.group(0))

        new_text, count = pattern.subn(_replace, text)
        if count:
            redacted_any = True
            text = new_text

    # Generic password assignment — redact the value half. Runs after the structured passes above so a
    # dotted token in a password/token field was already fully stripped by shape.
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
        # replace() preserves every OTHER field (variable_name, secret_value, columns) while
        # overriding only the two we redact — the raw secret_value is intentionally kept so the
        # report's credential section can show/validate the real key; snippet/description are the
        # surfaces that must never leak it.
        out.append(dataclasses.replace(finding, description=new_desc, snippet=new_snippet))
        redacted_map[
            f"{finding.rule_id}@{finding.file_path}:{finding.line_start}"
        ] = True
    return out, redacted_map
