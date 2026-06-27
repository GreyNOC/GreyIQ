"""Weak-JWT source sinks (alg:none, short HMAC secret, signature verification off).

Static signals that a JWT implementation is forgeable: accepting the `none`
algorithm, signing/verifying with a tiny hardcoded HMAC secret, or disabling
signature verification. We flag the code SINK; HIGH severity, MEDIUM/LOW confidence.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    (
        "jwt.alg-none",
        "JWT 'none' algorithm accepted",
        "Allowing alg:'none' (or listing it among accepted algorithms) lets an attacker forge an unsigned token.",
        Severity.HIGH, Confidence.MEDIUM, "jwt",
        "Pin a single asymmetric/HMAC algorithm; never include 'none' in the accepted-algorithms list.",
        (),
        r"(?i)alg(?:orithm)?s?\s*[=:]\s*\[?\s*[\"']none[\"']",
    ),
    (
        "jwt.verify-disabled",
        "JWT signature verification disabled",
        "verify_signature=False / verify=false skips signature checks, so any token is accepted.",
        Severity.HIGH, Confidence.MEDIUM, "jwt",
        "Always verify the signature; never set verify=False / verify_signature=False in production.",
        (),
        r"(?i)verify(?:_signature)?[\"']?\s*[=:]\s*(?:false|0)\b",
    ),
    (
        "jwt.short-hmac-secret",
        "JWT signed with a short hardcoded HMAC secret",
        "A short literal HMAC key (<=15 chars) is brute-forceable, letting an attacker forge tokens.",
        Severity.HIGH, Confidence.LOW, "jwt",
        "Use a long, random, secret-stored signing key (32+ bytes); never hardcode a short secret.",
        ("python", "javascript", "typescript", "go"),
        r"\bjwt\s*\.\s*(?:encode|sign)\s*\([^)]*,\s*[\"'][^\"']{1,15}[\"']",
    ),
]


RULES = tuple(
    RegexRule(
        rule_id=rid, title=title, description=desc, severity=sev, confidence=conf,
        category=cat, remediation=remed, languages=langs, pattern=pat, flags=re.MULTILINE,
    )
    for rid, title, desc, sev, conf, cat, remed, langs, pat in _RULES_RAW
)
