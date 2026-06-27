"""Insecure-deserialization sink primitives (PHP / Ruby / Java).

Deserializing attacker-controlled bytes with an unsafe API is a path to RCE. The
Python pickle/marshal/yaml sinks are already covered by the eval_exec pack (category
'injection'); this pack adds the non-Python deserialization sinks. We flag the SINK,
not a proven flow: HIGH severity, confidence LOW for bare sinks and MEDIUM where the
regex binds a request source.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    # ---------- PHP ----------
    (
        "php.unserialize-superglobal",
        "PHP unserialize() on a request superglobal",
        "unserialize($_GET/$_POST/...) instantiates attacker-chosen classes — a PHP object-injection / RCE sink.",
        Severity.HIGH, Confidence.MEDIUM, "deserialization",
        "Use json_decode for untrusted input, or unserialize with an allowed_classes allowlist.",
        ("php",),
        r"\bunserialize\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST|COOKIE)\b",
    ),
    # ---------- Ruby ----------
    (
        "rb.marshal-load",
        "Ruby Marshal.load / YAML.load",
        "Marshal.load and YAML.load reconstruct arbitrary Ruby objects; unsafe on untrusted input.",
        Severity.HIGH, Confidence.LOW, "deserialization",
        "Use JSON.parse for untrusted data, or YAML.safe_load with a permitted-class list.",
        ("ruby",),
        r"\b(?:Marshal\.load|YAML\.load)\s*\(",
    ),
    # ---------- Java ----------
    (
        "java.objectinputstream-readobject",
        "Java ObjectInputStream.readObject",
        "Native Java deserialization (readObject) of untrusted streams is a classic RCE gadget-chain sink.",
        Severity.HIGH, Confidence.LOW, "deserialization",
        "Avoid native serialization for untrusted data; use JSON with a hardened parser, or an allowlist ObjectInputFilter.",
        ("java",),
        r"\bObjectInputStream\b[^;]*\.\s*readObject\s*\(",
    ),
]


RULES = tuple(
    RegexRule(
        rule_id=rid, title=title, description=desc, severity=sev, confidence=conf,
        category=cat, remediation=remed, languages=langs, pattern=pat, flags=re.MULTILINE,
    )
    for rid, title, desc, sev, conf, cat, remed, langs, pat in _RULES_RAW
)
