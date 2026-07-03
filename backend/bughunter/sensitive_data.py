"""Name the SENSITIVE DATA a captured proof body actually disclosed, so a confirmed data-disclosure
finding's impact reads "leaks a victim JWT + email" instead of "returned 800 bytes". Naming the
exposed data is what lifts a CORS-read / IDOR / error-SQLi dump from Low to High in a triager's eyes.

Detection reuses the HIGH-CONFIDENCE secret rules from ``code_scanner/rules/secrets.py`` VERBATIM
(their exact patterns + their own precision gates — no new, looser regexes here) plus one anchored
email match. DELIBERATELY EXCLUDED from this confident tier: credit-card/Luhn, phone numbers,
national IDs, and ``password``-field-name heuristics — those over-claim and are advisory leads at
best. Pure, no I/O, frozen-safe. Callers should pass an already-captured (and already-redacted)
proof excerpt; this only classifies, it never fetches.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.rules import SECRET_RULES

# The high-confidence secret classes worth naming as "disclosed sensitive data", mapped to a plain
# label. Only these rule_ids from SECRET_RULES are consulted (their patterns/gates are reused as-is);
# the noisier heuristic rules (generic password assignment, dotenv) are intentionally left out so a
# severity-raising claim is only ever made on an unambiguous secret.
# NOTE ON secret.openai-key: its shared pattern `sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}` allows
# INTERIOR HYPHENS, which is fine when scanning SOURCE (`apiKey = "sk-..."`) but on an arbitrary
# disclosed body it false-matches ordinary kebab-case slugs/SKUs ("sk-mens-running-shoes-2024-ltd").
# So the OpenAI class is handled by a body-specific STRICT regex below (continuous run, no kebab
# word-breaks) instead of the shared rule — a real key is a continuous high-entropy string.
_SENSITIVE_SECRET_LABELS = {
    "secret.aws-access-key-id": "an AWS access key ID",
    "secret.aws-secret-access-key": "an AWS secret access key",
    "secret.github-pat": "a GitHub access token",
    "secret.slack-bot-token": "a Slack token",
    "secret.stripe-key": "a Stripe secret key",
    "secret.google-api-key": "a Google API key",
    "secret.anthropic-key": "an Anthropic API key",
    "secret.private-key-pem": "a private key (PEM)",
}
# A JWT by shape (two base64url segments each opening with the tell-tale ``eyJ`` = base64 of ``{"``,
# plus a signature). Matched DIRECTLY here — the secret.jwt rule runs exposure-triage that is too
# restrictive for "the disclosed body contains a session token"; the ``eyJ.eyJ.`` structure is
# JWT-specific enough to be a confident, low-FP signal on its own.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
# OpenAI key, body-strict: `sk-` + optional `proj-`, then a CONTINUOUS 20+ alnum/underscore run with
# NO further hyphens — a real key is continuous, whereas a false-positive slug ("sk-mens-running-...")
# is kebab-cased. This is stricter than the shared source-scanning rule on purpose (see note above).
_OPENAI_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_]{20,}\b")
# An email address — high-signal PII in a disclosure, though not a "secret". Anchored with a plausible
# TLD so it doesn't fire on every ``user@host`` fragment.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
# Role/functional local-parts that are almost always the SITE'S OWN public contact address (footer
# mailto:, support links) — not exfiltrated victim PII. Excluded so an email claim means real PII.
_ROLE_LOCALPARTS = frozenset({
    "support", "sales", "info", "contact", "admin", "noreply", "no-reply", "help", "hello",
    "team", "office", "press", "media", "billing", "abuse", "security", "privacy", "legal", "careers",
})

_MAX_LABELS = 8


def _has_nonrole_email(text: str) -> bool:
    """True only if an email whose local-part is NOT a generic role account appears — so "email
    address(es)" is claimed for plausibly-personal PII, not the site's own support@ footer address."""
    for m in _EMAIL_RE.finditer(text):
        local = m.group(0).split("@", 1)[0].lower()
        if local not in _ROLE_LOCALPARTS:
            return True
    return False


def classify(text: str) -> list[str]:
    """Return de-duplicated plain labels for the high-confidence sensitive data present in ``text``
    (a captured, redacted proof body). Empty when nothing high-confidence is found."""
    text = text or ""
    if not text:
        return []
    labels: list[str] = []
    seen: set[str] = set()

    def add(label: str) -> None:
        if label and label not in seen:
            seen.add(label)
            labels.append(label)

    for rule in SECRET_RULES:
        label = _SENSITIVE_SECRET_LABELS.get(getattr(rule, "rule_id", ""))
        if not label:
            continue
        try:
            hits = list(rule.scan(path="proof-body", text=text))  # reuse the rule's exact pattern + gates
        except Exception:  # noqa: BLE001 - classification is best-effort, never raise into a report
            hits = []
        if hits:
            add(label)
        if len(labels) >= _MAX_LABELS:
            return labels
    if _JWT_RE.search(text):
        add("a JWT (session/bearer token)")
    if _OPENAI_RE.search(text):  # body-strict OpenAI key (not the hyphen-loose shared rule)
        add("an OpenAI API key")
    if _has_nonrole_email(text):
        add("email address(es)")
    return labels[:_MAX_LABELS]


def summarize(text: str) -> str:
    """A human phrase naming the disclosed sensitive data ("a JWT (session/bearer token) and email
    address(es)"), or '' when nothing high-confidence is present."""
    labels = classify(text)
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    return ", ".join(labels[:-1]) + " and " + labels[-1]
