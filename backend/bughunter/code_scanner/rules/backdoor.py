"""Backdoor heuristics.

These are the patterns specifically associated with planted backdoors:
magic auth-bypass strings, hidden admin / debug routes, env-var
triggers, obfuscated callbacks (base64 / hex / chr-concatenation), and
imports of suspicious encoding-helper modules right next to a network
call. Each finding is high signal but low specificity — read the file
in context before acting.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

RULES = (
    RegexRule(
        rule_id="backdoor.magic-auth-bypass",
        title="Hardcoded auth-bypass on a magic value",
        description=(
            "An `if password == \"magic\" return True` shape is a common backdoor primitive: a "
            "specific input grants admin without going through the real auth path."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        category="backdoor",
        remediation="Remove the bypass. If you need a service account, issue a real credential through the standard auth flow.",
        pattern=(
            r"(?im)(?:if|elif)\s+[\w.\[\]'\"]*?(?:password|secret|token|api[_\-]?key|auth)"
            r"[\w.\[\]'\"]*?\s*(?:==|===)\s*[\"'][^\"']{4,40}[\"']"
        ),
    ),
    RegexRule(
        rule_id="backdoor.return-true-skip-check",
        title="Bypass branch that returns True / 200 without checking input",
        description=(
            "An if-branch that short-circuits an auth check with `return True` (or HTTP 200) "
            "based on a debug / dev / admin flag is a classic planted bypass."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="backdoor",
        remediation="Remove the flag-based bypass. Use a separate dev-only auth implementation behind a build flag.",
        pattern=(
            r"(?im)if\s+[\w.\[\]\"']*(?:debug|dev|admin|test|backdoor|secret_key)[\w.\[\]\"']*\s*:\s*$"
            r"[\s\S]{0,200}?return\s+True\b"
        ),
    ),
    RegexRule(
        rule_id="backdoor.env-var-trigger",
        title="Env-var-triggered code execution path",
        description=(
            "Reading an obscurely named environment variable and dispatching code through "
            "eval / exec / os.system based on its value is a common implant trigger."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="backdoor",
        remediation="Configuration should not be executable. Replace with a flag that picks among hardcoded handlers.",
        pattern=(
            r"(?:os\.environ\.get|os\.getenv|process\.env\.\w+)\s*\([\s\S]{0,200}?(?:eval|exec|"
            r"os\.system|subprocess\.\w+\s*\([^)]*shell\s*=\s*True)"
        ),
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="backdoor.base64-decoded-source",
        title="A large base64 blob is being decoded and executed",
        description=(
            "A multi-kilobyte base64 string passed through base64.b64decode / atob and then "
            "executed (eval, exec, Function, vm.run) is a code-hiding pattern."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="backdoor",
        remediation="Decode the blob, treat it as a sandboxed inspection target, and reject any path that re-executes it.",
        pattern=(
            r"(?:base64\.b64decode|atob|Buffer\.from\s*\([^)]*[\"']base64[\"'])\s*\([\s\S]{0,2000}?"
            r"(?:eval|exec|Function|vm\s*\.\s*run\w+)"
        ),
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="backdoor.chr-concatenation-string",
        title="String built from chr() / String.fromCharCode() concatenation",
        description=(
            "Strings assembled from a long chain of chr(...) / String.fromCharCode(...) calls "
            "are typically obfuscated payloads — there's no other reason to write code that way."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="obfuscation",
        remediation="Decode the chain to see what it spells; treat malicious strings as backdoors.",
        pattern=r"(?:chr\(\d+\)\s*\+\s*){4,}chr\(\d+\)|(?:String\.fromCharCode\(\d+\)\s*\+\s*){4,}",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="backdoor.hidden-route-debug",
        title="Hidden debug / admin route in a web framework",
        description=(
            "An undocumented endpoint named /debug, /admin/shell, /__exec, /_test, or similar "
            "is a planted backdoor candidate; these routes commonly accept commands or "
            "dump credentials."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="backdoor",
        remediation="Confirm the route is intentional and gated behind real auth; if it executes input, remove it.",
        pattern=(
            r"(?:@app\.(?:route|get|post)|router\.(?:get|post)|app\.(?:get|post))\s*\(\s*[\"']"
            r"/(?:debug|admin/shell|__exec|_admin|_test|backdoor|hidden)[\"' ]"
        ),
        flags=re.MULTILINE | re.IGNORECASE,
    ),
    RegexRule(
        rule_id="backdoor.pickle-load-from-network",
        title="pickle.loads on data sourced from the network",
        description=(
            "pickle.loads(requests.get(...).content) and similar one-liners are the simplest "
            "remote-code-execution backdoor in Python."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="backdoor",
        remediation="Never feed network data to pickle. Use JSON or a typed schema.",
        pattern=(
            r"pickle\.loads?\s*\(\s*(?:requests\.\w+\s*\(|urlopen\s*\(|http\w*\s*\.\s*get\s*\(|"
            r"socket\s*\.\s*recv\b)"
        ),
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="backdoor.suspicious-dynamic-attr-on-import",
        title="getattr / setattr applied to importlib result with dynamic name",
        description=(
            "Dynamic attribute resolution against an imported module is a common loader-shim "
            "in malware: it lets the runtime name vary while the disk source looks innocuous."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        category="backdoor",
        remediation="Hardcode the dispatch table.",
        pattern=r"getattr\s*\(\s*importlib\.\w+\s*\([^)]*\)\s*,\s*[\w_]+\)",
        flags=re.MULTILINE,
    ),
)
