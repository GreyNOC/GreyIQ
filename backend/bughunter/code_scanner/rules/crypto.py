"""Weak-crypto / unsafe-crypto rules.

We flag the universal anti-patterns: weak hashes used for auth,
deprecated ciphers (DES, ECB), insecure RNGs used for keys / tokens,
hardcoded IVs or salts, and constant-time-failure patterns. The
findings are highlighted as "primitive misuse" rather than "broken
algorithm" — the right fix depends on the call context.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

RULES = (
    RegexRule(
        rule_id="crypto.md5-for-auth",
        title="MD5 used for authentication / integrity",
        description=(
            "MD5 is broken for collision resistance. Using it for password hashing, "
            "signatures, or integrity checks is a known weakness."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="crypto",
        remediation="Use SHA-256 for integrity, bcrypt / scrypt / argon2id for passwords, HMAC-SHA256 for keyed MACs.",
        pattern=r"\bmd5\s*\(|hashlib\.md5\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="crypto.sha1-for-auth",
        title="SHA-1 used for authentication / integrity",
        description="SHA-1 is deprecated for security uses. Migrate to SHA-256 or stronger.",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        category="crypto",
        remediation="Use SHA-256 or SHA-3 for integrity and signatures.",
        pattern=r"\bsha1\s*\(|hashlib\.sha1\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="crypto.des",
        title="DES / 3DES cipher in use",
        description=(
            "DES is 56-bit and brute-forceable; 3DES is being retired (NIST SP 800-131A). "
            "Both are unsuitable for new code."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="crypto",
        remediation="Use AES-256-GCM or ChaCha20-Poly1305.",
        pattern=r"\bDES(?:ede)?\b|Cipher\.getInstance\s*\(\s*[\"'](?:DES|DESede|3DES)",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="crypto.ecb-mode",
        title="Cipher used in ECB mode",
        description=(
            "ECB mode leaks plaintext structure (identical plaintext blocks become identical "
            "ciphertext blocks)."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="crypto",
        remediation=(
            "Use AES-GCM for authenticated encryption. If you must use CBC, use a fresh random "
            "IV per message and a separate MAC."
        ),
        pattern=r"\bAES\.MODE_ECB\b|Cipher\.getInstance\s*\(\s*[\"'][^\"']*\bECB\b",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="crypto.weak-random-for-keys",
        title="Weak RNG used for security-sensitive randomness",
        description=(
            "random.* (Python) and Math.random() (JS) are PRNGs seeded from observable state. "
            "They must not produce key material, session ids, or tokens."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="crypto",
        remediation=(
            "Use secrets.token_bytes / token_urlsafe / token_hex (Python) or "
            "crypto.randomBytes / crypto.getRandomValues (Node / Web)."
        ),
        pattern=r"(?:^|[^a-zA-Z_])random\.(?:random|randint|randrange|choice)\s*\(|Math\.random\s*\(\s*\)",
        flags=re.MULTILINE,
        line_must_contain=("key", "token", "secret", "nonce", "iv", "password", "salt", "session"),
    ),
    RegexRule(
        rule_id="crypto.hardcoded-iv-or-salt",
        title="Hardcoded IV / salt",
        description="A constant IV or salt makes encryption deterministic — attackers learn from repeated ciphertexts.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="crypto",
        remediation="Generate a fresh random IV / salt per message; store it alongside the ciphertext.",
        pattern=r"(?:iv|salt|nonce)\s*=\s*[\"'][A-Za-z0-9+/=]{6,}[\"']",
        flags=re.IGNORECASE | re.MULTILINE,
    ),
    RegexRule(
        rule_id="crypto.string-compare-for-mac",
        title="Non-constant-time comparison of a token / HMAC",
        description="Plain == on tokens / HMACs leaks timing information. Use a constant-time comparator.",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        category="crypto",
        remediation="Use hmac.compare_digest (Python), crypto.timingSafeEqual (Node), MessageDigest.isEqual (Java).",
        pattern=r"(?:^|[^A-Za-z0-9_])(?:hmac|token|signature|mac|hash)\s*==\s*[\"']",
        flags=re.IGNORECASE | re.MULTILINE,
    ),
)
