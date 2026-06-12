"""Secret / credential detection.

Targets the hardcoded keys, tokens, and PEM blocks that get committed
by accident or planted as a backdoor. Patterns are deliberately tight:
each one matches a known vendor's key shape, not a generic high-entropy
string, so the false-positive rate is low and findings are explainable
("AWS access key" vs. "looks random").

Ported and extended from the GreyNOC Aegis secret extractor.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_PEM_FLAGS = re.MULTILINE | re.DOTALL

RULES = (
    RegexRule(
        rule_id="secret.aws-access-key-id",
        title="AWS access key ID",
        description="A literal AWS access key was committed to source.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Rotate the key, remove it from history (BFG / git-filter-repo), and move to a secrets manager.",
        pattern=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.aws-secret-access-key",
        title="AWS secret access key",
        description="Looks like an AWS secret access key (40 base64 chars) tied to an aws_secret_access_key assignment.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Rotate the key, scrub history, switch to IAM roles or a secrets manager.",
        pattern=r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\b[\"' :=]+[A-Za-z0-9/+=]{40}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.github-pat",
        title="GitHub personal access token",
        description="ghp_, gho_, ghu_, ghs_, or ghr_ token prefixes appear in source.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Revoke the token in GitHub settings, scrub history, use a short-lived OAuth or GitHub App instead.",
        pattern=r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.slack-bot-token",
        title="Slack bot token",
        description="A Slack xoxb / xoxa / xoxp token is hardcoded.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Revoke the token in api.slack.com, scrub history, store in a secrets manager.",
        pattern=r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.stripe-key",
        title="Stripe live or test secret key",
        description="A Stripe secret key (sk_live_ / sk_test_) is hardcoded.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Roll the key in the Stripe dashboard, scrub history, load it from environment.",
        pattern=r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.google-api-key",
        title="Google API key",
        description="A Google Cloud API key (AIza...) is hardcoded.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="secret",
        remediation="Restrict or rotate the key in Google Cloud Console; keys with no referrer restriction are usable from anywhere.",
        pattern=r"\bAIza[0-9A-Za-z\-_]{35}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.openai-key",
        title="OpenAI API key",
        description="An OpenAI sk-... key is hardcoded.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Revoke the key on platform.openai.com, scrub history, load via env var or secret store.",
        pattern=r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
        line_must_contain=("sk-",),
        unique=True,
    ),
    RegexRule(
        rule_id="secret.anthropic-key",
        title="Anthropic API key",
        description="An Anthropic sk-ant-... key is hardcoded.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Revoke the key in the Anthropic console, scrub history, load via env var or secret store.",
        pattern=r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.jwt",
        title="JWT in source",
        description="A literal JWT (three base64url segments separated by dots) is committed.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="secret",
        remediation="Treat any committed JWT as compromised. Revoke it on the auth server.",
        pattern=r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.private-key-pem",
        title="Private key block",
        description="A PEM-encoded private key block (RSA/EC/OpenSSH/PGP/DSA) is committed.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Rotate the key pair, scrub history, store the private half outside the repo.",
        pattern=r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----",
        flags=_PEM_FLAGS,
        unique=True,
    ),
    RegexRule(
        rule_id="secret.generic-password-assignment",
        title="Hardcoded password / secret assignment",
        description="A variable named password / passwd / secret is assigned a quoted literal.",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        category="secret",
        remediation="Load credentials from environment, a secrets manager, or an OS keyring.",
        pattern=(
            r"(?im)^\s*[\"']?(?:password|passwd|pwd|secret|api[_\-]?key|token|access[_\-]?token)"
            r"[\"']?\s*[:=]\s*[\"'][A-Za-z0-9!@#$%^&*()_+=\-]{6,}[\"']"
        ),
        line_must_not_contain=("example", "placeholder", "your-", "<", "FAKE", "fake", "REDACTED"),
        unique=True,
    ),
    RegexRule(
        rule_id="secret.dotenv-committed",
        title=".env-style key=value file in repo",
        description="A file matching .env contains key=value pairs with secret-looking values.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="secret",
        remediation="Move the file out of the repo, add `.env` to .gitignore, distribute via a secrets channel.",
        pattern=r"(?im)^[A-Z][A-Z0-9_]{2,}\s*=\s*[A-Za-z0-9_+/=\-]{10,}\s*$",
        path_globs=("*.env", "**/.env", "**/.env.*"),
        unique=True,
        line_must_not_contain=("example", "EXAMPLE", "your-", "<", "FAKE", "fake"),
    ),
)
