"""Suspicious network primitives.

A backdoor's exfil channel is one of: a raw socket, an HTTPS POST to
an attacker-controlled host, or a DNS-tunnelling pattern. These rules
flag the universal call shapes; the analyst still has to verify the
destination is malicious.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    # ---------- Python ----------
    (
        "py.reverse-shell-socket",
        "Python reverse-shell primitive (socket + dup2 + sh)",
        "Classic reverse-shell shape: open a socket, redirect stdio (os.dup2 0/1/2), then call /bin/sh. This is rarely a coincidence in production code.",
        Severity.CRITICAL,
        Confidence.HIGH,
        "backdoor",
        "Treat the file as compromised. Investigate commit history, rotate any deployed credentials, force-rebuild from a clean ref.",
        ("python",),
        (),
        r"socket\.socket\s*\([\s\S]{0,200}?os\s*\.\s*dup2\s*\([\s\S]{0,200}?(?:sh|bash)",
    ),
    (
        "py.bind-on-all-interfaces",
        "Python socket bound to 0.0.0.0",
        "Binding a service to 0.0.0.0 exposes it on every interface. Combined with a missing auth check it's a backdoor surface.",
        Severity.LOW,
        Confidence.MEDIUM,
        "network",
        "Bind to 127.0.0.1 when the listener should be local; firewall non-loopback bindings explicitly.",
        ("python",),
        (),
        r"\.bind\s*\(\s*\(\s*[\"']0\.0\.0\.0[\"']",
    ),
    (
        "py.requests-verify-false",
        "Python requests call with verify=False",
        "TLS verification is disabled — the connection accepts any cert. Standard MITM hole.",
        Severity.MEDIUM,
        Confidence.HIGH,
        "network",
        "Remove verify=False. If you have a self-signed cert, pass its path via verify=\"/path/to/ca.pem\".",
        ("python",),
        (),
        r"\brequests\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\([^)]*verify\s*=\s*False",
    ),
    (
        "py.urllib-no-cert-verify",
        "Python urllib SSL context with verify_mode=CERT_NONE",
        "ssl.create_default_context with verify_mode = ssl.CERT_NONE disables certificate validation entirely.",
        Severity.MEDIUM,
        Confidence.HIGH,
        "network",
        "Use ssl.create_default_context() with verify_mode=ssl.CERT_REQUIRED (the default).",
        ("python",),
        (),
        r"verify_mode\s*=\s*ssl\.CERT_NONE",
    ),
    # ---------- JavaScript / TypeScript ----------
    (
        "js.tls-reject-unauthorized-false",
        "Node TLS / fetch with rejectUnauthorized: false",
        "rejectUnauthorized: false disables certificate validation. Every request is MITM-able.",
        Severity.MEDIUM,
        Confidence.HIGH,
        "network",
        "Remove rejectUnauthorized: false; trust the system CA or pin the issuing cert.",
        ("javascript", "typescript"),
        (),
        r"rejectUnauthorized\s*:\s*false",
    ),
    (
        "js.suspicious-fetch-base64",
        "JS fetch to a base64-decoded URL",
        "fetch(atob(\"...\")) or fetch(Buffer.from(\"...\", \"base64\").toString()) is a common obfuscation trick to hide a callback domain from grep.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "obfuscation",
        "Decode the base64 string and verify the destination. If unknown, treat as a backdoor.",
        ("javascript", "typescript"),
        (),
        r"fetch\s*\(\s*(?:atob\s*\(|Buffer\.from\s*\([^)]*[\"']base64[\"'])",
    ),
    # ---------- Cross-language: outbound to suspicious destinations ----------
    (
        "any.dns-tunnel-shape",
        "Long encoded label as a subdomain — possible DNS tunnel",
        "DNS exfil tunnels encode payloads as long, high-entropy subdomain labels under an attacker domain.",
        Severity.MEDIUM,
        Confidence.LOW,
        "obfuscation",
        "Inspect the destination. Long base32/64 labels under an unfamiliar parent domain are rarely benign in production code.",
        (),
        (),
        r"\b[A-Za-z0-9]{32,}\.(?:[a-z0-9\-]{2,}\.){0,3}[a-z]{2,}\b",
    ),
    (
        "any.pastebin-callback",
        "URL pointing at pastebin / hastebin / 0bin / transfer.sh / ngrok",
        "Live malware drops, beacon configs, and exfil channels disproportionately use ephemeral paste / tunnel services. Worth a second look in production code.",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "network",
        "Confirm whether the destination is legitimate; if not, treat as a backdoor.",
        (),
        (),
        r"https?://(?:pastebin\.com|paste\.ee|hastebin\.com|0bin\.net|transfer\.sh|[\w-]+\.ngrok\.io|[\w-]+\.ngrok-free\.app|requestbin\.com)/\S+",
    ),
    (
        "any.discord-webhook-url",
        "Discord webhook URL in source",
        "Discord webhooks are popular exfil channels: they're free, unauthenticated, and rarely blocked.",
        Severity.HIGH,
        Confidence.HIGH,
        "backdoor",
        "Remove the webhook and rotate it. Audit what the code POSTs.",
        (),
        (),
        r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
    ),
    (
        "any.telegram-bot-url",
        "Telegram bot API endpoint in source",
        "Telegram bot endpoints are a common malware C2 / exfil channel; they tunnel through HTTPS to TLS-pinned hosts.",
        Severity.HIGH,
        Confidence.HIGH,
        "backdoor",
        "Confirm whether the bot is a legitimate notification channel; if not, revoke the bot token via @BotFather and rotate.",
        (),
        (),
        r"https?://api\.telegram\.org/bot\d+:[A-Za-z0-9_\-]+",
    ),
]


RULES = tuple(
    RegexRule(
        rule_id=rid,
        title=title,
        description=desc,
        severity=sev,
        confidence=conf,
        category=cat,
        remediation=remed,
        languages=langs,
        path_globs=globs,
        pattern=pat,
        flags=re.MULTILINE,
        unique=True,
    )
    for rid, title, desc, sev, conf, cat, remed, langs, globs, pat in _RULES_RAW
)
