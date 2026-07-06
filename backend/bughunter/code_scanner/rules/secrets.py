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
from collections.abc import Iterable
from dataclasses import dataclass

from bughunter.code_scanner.jwt_exposure import classify_jwt_exposure
from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.model import Finding
from bughunter.code_scanner.rules.base import RegexRule, Rule, _line_span, _snippet_around

_PEM_FLAGS = re.MULTILINE | re.DOTALL
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}\b")


@dataclass(frozen=True)
class JwtExposureRule(Rule):
    """Claim-aware JWT rule.

    Static scans cannot prove replay, so identity/session JWTs are held back
    until a caller supplies replay evidence through the classifier. The rule
    only emits when decoded claim values contain concrete secret material.
    """

    def scan(self, *, path: str, text: str) -> Iterable[Finding]:
        seen: set[tuple[str, str]] = set()
        for match in _JWT_RE.finditer(text):
            token = match.group(0)
            key = (path, token)
            if key in seen:
                continue
            seen.add(key)
            classification = classify_jwt_exposure(token)
            if classification is None or classification.finding is not True:
                continue
            line_start, line_end = _line_span(text, match)
            secret_kinds = ", ".join(sorted({hit.kind for hit in classification.secret_hits}))
            if classification.role == "embedded_secret":
                title = "Secret value embedded in JWT claim"
                description = (
                    "A JWT claim value contains concrete secret material"
                    f"{f' ({secret_kinds})' if secret_kinds else ''}. OAuth scope names were excluded from scanning."
                )
                remediation = "Remove the secret value from the token, rotate the exposed secret, and issue tokens by reference."
            else:
                title = "Confirmed replayable JWT"
                description = classification.impact or "JWT replay was confirmed."
                remediation = "Revoke the token and ensure public client-side flow tokens cannot authenticate users."
            yield Finding(
                rule_id=f"{self.rule_id}.embedded-secret" if classification.role == "embedded_secret" else self.rule_id,
                title=title,
                description=description,
                severity=Severity(classification.severity),
                confidence=Confidence.HIGH,
                category=self.category,
                file_path=path,
                line_start=line_start,
                line_end=line_end,
                snippet=_snippet_around(text, match),
                remediation=remediation,
            )

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
        rule_id="secret.gitlab-pat",
        title="GitLab personal/project access token",
        description="A GitLab access token (glpat-...) is hardcoded.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Revoke the token in GitLab (Settings → Access Tokens), scrub history, use a short-lived CI token instead.",
        pattern=r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.npm-token",
        title="npm access token",
        description="An npm access token (npm_...) is hardcoded.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Revoke the token on npmjs.com (Access Tokens), scrub history, use a granular/automation token from a secret store.",
        pattern=r"\bnpm_[A-Za-z0-9]{36}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.sendgrid-key",
        title="SendGrid API key",
        description="A SendGrid API key (SG.xxx.yyy) is hardcoded.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Revoke the key in the SendGrid dashboard (Settings → API Keys), scrub history, load it from a secret store.",
        pattern=r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.digitalocean-token",
        title="DigitalOcean personal access token",
        description="A DigitalOcean access token (dop_v1_...) is hardcoded.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Revoke the token in the DigitalOcean control panel (API → Tokens), scrub history, use a scoped token from a secret store.",
        pattern=r"\bdop_v1_[a-f0-9]{64}\b",
        unique=True,
    ),
    RegexRule(
        rule_id="secret.gcp-service-account",
        title="GCP service-account key (JSON)",
        description="A Google Cloud service-account key file (type=service_account with a private_key) is committed.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Delete and rotate the key in the GCP console (IAM → Service Accounts → Keys), scrub history, use Workload Identity instead.",
        # Match the whole FLAT JSON object (service-account keys have no nested braces) that carries both
        # the service_account type and an inline private_key PEM — captured verbatim so the liveness
        # validator can parse client_email + private_key from it. (?s) so it spans the multi-line JSON.
        pattern=r'(?s)\{[^{}]*"type"\s*:\s*"service_account"[^{}]*"private_key"\s*:\s*"-----BEGIN[^{}]*\}',
        unique=True,
    ),
    RegexRule(
        # A Google/Firebase AIza key is a browser-embeddable PUBLIC client key by default — it is DESIGNED
        # to ship in web/app source and to identify its project. Detecting one is NOT proof of a secret or
        # a vulnerability, so this rule stays INFO; only strict classification (bughunter.secret_classification)
        # may escalate it, and only with real proof of unauthorized access/impact (an open Firebase data
        # store, or demonstrated unrestricted paid-API abuse). Never High from the pattern alone.
        rule_id="secret.google-api-key",
        title="Google/Firebase API key (public client key by default)",
        description="A Google/Firebase API key (AIza...) appears in source. These are browser-safe public "
                    "client keys by design — reportable only with proof of unauthorized access or impact.",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        category="secret",
        remediation="Confirm the key's HTTP-referrer / API / app restrictions. It is only a finding if it is "
                    "unrestricted AND grants unauthorized access (e.g. an open Firebase data store or paid-API abuse).",
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
        # (?!ant-): an Anthropic 'sk-ant-...' key must NOT also match the OpenAI rule, or it would be
        # double-detected and validated against the wrong issuer (api.openai.com) — see secret.anthropic-key.
        pattern=r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
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
    JwtExposureRule(
        rule_id="secret.jwt",
        title="JWT in source",
        description="A JWT was parsed and classified from its claims before exposure triage.",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        category="secret",
        remediation="Only report JWTs as credentials after replay is confirmed or a real secret value is present.",
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
        pattern=r"(?im)^[A-Z][A-Z0-9_]{2,}[^\S\n]*=[^\S\n]*[A-Za-z0-9_+/=\-]{10,}[^\S\n]*$",
        path_globs=("*.env", "**/.env", "**/.env.*"),
        unique=True,
        line_must_not_contain=("example", "EXAMPLE", "your-", "<", "FAKE", "fake"),
    ),
)
