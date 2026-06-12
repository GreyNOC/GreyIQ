"""Command injection primitives.

These are unsafe shell-out APIs that become a backdoor or RCE the
moment any attacker-influenced data reaches the argument. We flag the
sink, not the data flow — that's a tradeoff for a fast static check
that catches real bugs.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    # ---------- Python ----------
    (
        "py.subprocess-shell-true",
        "Python subprocess.* with shell=True",
        "subprocess.run / call / Popen with shell=True passes the command through /bin/sh, making string concatenation a command-injection sink.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Pass an argv list with shell=False (the default). If you really need a shell, sanitize via shlex.quote.",
        ("python",),
        (),
        r"subprocess\s*\.\s*(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True",
    ),
    (
        "py.os-system",
        "Python os.system / os.popen",
        "os.system and os.popen pass their argument to /bin/sh -c without sanitization.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Switch to subprocess.run([...], shell=False) with an argv list.",
        ("python",),
        (),
        r"\bos\s*\.\s*(?:system|popen)\s*\(",
    ),
    (
        "py.commands-getoutput",
        "Python commands.getoutput / getstatusoutput",
        "commands.getoutput executes its argument via /bin/sh; the module is legacy and unsafe.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Use subprocess.run with shell=False.",
        ("python",),
        (),
        r"\bcommands\s*\.\s*get(?:status)?output\s*\(",
    ),
    # ---------- JavaScript / TypeScript ----------
    (
        "js.child-process-exec",
        "Node child_process.exec / execSync",
        "child_process.exec runs its argument through /bin/sh. String concatenation with user input is RCE.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Switch to child_process.spawn / execFile with an argv array.",
        ("javascript", "typescript"),
        (),
        r"(?:child_process|cp)\s*\.\s*exec(?:Sync)?\s*\(",
    ),
    (
        "js.shelljs-exec",
        "shelljs.exec call",
        "shelljs.exec is a thin wrapper over child_process.exec with the same shell-string risk.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Use shelljs.exec with an argv array, or move to native child_process.spawn.",
        ("javascript", "typescript"),
        (),
        r"\bshelljs?\s*\.\s*exec\s*\(",
    ),
    # ---------- Go ----------
    (
        "go.exec-command-string",
        "Go exec.Command with /bin/sh -c constructed string",
        "exec.Command(\"sh\", \"-c\", concat(...)) is the canonical Go command-injection sink.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Pass each argv element separately: exec.Command(\"git\", \"clone\", url).",
        ("go",),
        (),
        r"exec\.Command\s*\(\s*\"(?:sh|bash|cmd|powershell)\"[^)]*\)",
    ),
    # ---------- Ruby ----------
    (
        "rb.kernel-system",
        "Ruby Kernel#system / `backticks` with interpolation",
        "Ruby's system / `...` run their argument through /bin/sh when given a single string.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "injection",
        "Pass each argument separately: system(\"git\", \"clone\", url).",
        ("ruby",),
        (),
        r"(?:^|[^.\w])(?:system|exec|`)\s*\(?\s*[\"'].*#\{",
    ),
    # ---------- Shell ----------
    (
        "sh.curl-pipe-shell",
        "Pipe a remote download straight into a shell",
        "curl | sh and wget -O- | bash run arbitrary code from the network with no integrity check.",
        Severity.CRITICAL,
        Confidence.HIGH,
        "supply-chain",
        "Download to a file, pin the SHA256, verify it, then execute.",
        ("shell",),
        (),
        r"(?:curl|wget)[^\n;|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ksh|python|node|perl)\b",
    ),
    (
        "sh.eval-on-variable",
        "Shell eval on an expanded variable",
        "eval \"$x\" turns variable content into shell code; combined with anything user-influenced this is RCE.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Replace with positional arguments or arrays. Avoid eval in shell entirely.",
        ("shell",),
        (),
        r"\beval\s+[\"']?\$\{?\w+",
    ),
    # ---------- C / C++ ----------
    (
        "c.system-call",
        "C/C++ system() call with constructed string",
        "system() runs its argument through /bin/sh. Concatenated strings reaching system() are command injection.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "injection",
        "Use execvp / posix_spawn with an argv array instead.",
        ("c", "cpp"),
        (),
        r"(?<!\w)system\s*\(",
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
    )
    for rid, title, desc, sev, conf, cat, remed, langs, globs, pat in _RULES_RAW
)
