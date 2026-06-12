"""Eval / exec / dynamic code construction sinks.

These are the primitives most backdoors are built on. Findings here
are high signal even on their own — the actual exploitability depends
on whether attacker-controlled data reaches the sink, which we can't
prove statically. The remediation always reads "audit the data flow".
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    # ---------- Python ----------
    (
        "py.eval-on-input",
        "Python eval() / exec() on a dynamic argument",
        "eval(...) and exec(...) execute arbitrary Python; any path from user input to the argument is RCE.",
        Severity.CRITICAL,
        Confidence.HIGH,
        "injection",
        "Replace with a typed parser (json.loads, ast.literal_eval) or a constrained DSL.",
        ("python",),
        (),
        r"\b(?:eval|exec)\s*\(",
    ),
    (
        "py.pickle-loads",
        "Python pickle.loads / cPickle.loads on untrusted bytes",
        "pickle deserialization is equivalent to running attacker-supplied code. Any pickled bytes from the network or disk that an attacker can influence is RCE.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Use json / msgpack / a typed schema. If pickle is non-negotiable, verify integrity with HMAC + read-only keys.",
        ("python",),
        (),
        r"\bpickle\s*\.\s*loads?\s*\(|\bcPickle\s*\.\s*loads?\s*\(",
    ),
    (
        "py.yaml-unsafe-load",
        "Python yaml.load without SafeLoader",
        "yaml.load(...) without an explicit SafeLoader instantiates Python objects from the YAML stream. CVE-2017-18342 family.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Use yaml.safe_load or pass Loader=yaml.SafeLoader explicitly.",
        ("python",),
        (),
        r"\byaml\s*\.\s*load\s*\([^)]*(?<!SafeLoader)\s*\)",
    ),
    (
        "py.marshal-loads",
        "Python marshal.loads on untrusted bytes",
        "marshal is even more unsafe than pickle: tampered marshal data can crash the interpreter or execute arbitrary code.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "injection",
        "Marshal is for cross-Python-version internal use; never load attacker-influenced marshal bytes.",
        ("python",),
        (),
        r"\bmarshal\s*\.\s*loads?\s*\(",
    ),
    (
        "py.dynamic-import",
        "Python __import__ / importlib.import_module with a dynamic name",
        "Dynamically resolved imports are a common backdoor primitive (load a module path the attacker controls, then call its entrypoint).",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "injection",
        "Hardcode the allowed module set or use a registry of known-good handlers.",
        ("python",),
        (),
        r"(?<!\w)(?:__import__|importlib\s*\.\s*import_module)\s*\(",
    ),
    # ---------- JavaScript / TypeScript ----------
    (
        "js.eval",
        "JavaScript eval() call",
        "eval(...) and the Function(...) constructor execute arbitrary JavaScript. Source data flowing into either is RCE.",
        Severity.CRITICAL,
        Confidence.HIGH,
        "injection",
        "Replace with JSON.parse / structured handlers. Remove eval() entirely if at all possible.",
        ("javascript", "typescript"),
        (),
        r"(?<![\w.])eval\s*\(",
    ),
    (
        "js.function-constructor",
        "JavaScript new Function(...) constructor",
        "new Function(\"...\") compiles its string argument as JavaScript. Same RCE risk as eval.",
        Severity.CRITICAL,
        Confidence.HIGH,
        "injection",
        "Use a real parser or a constrained DSL, not Function(\"...\").",
        ("javascript", "typescript"),
        (),
        r"new\s+Function\s*\(",
    ),
    (
        "js.settimeout-string",
        "setTimeout / setInterval with a string body",
        "Passing a string body to setTimeout / setInterval is equivalent to eval().",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Pass a function reference, not a string of code.",
        ("javascript", "typescript"),
        (),
        r"set(?:Timeout|Interval)\s*\(\s*[\"'`]",
    ),
    (
        "js.vm-run-untrusted",
        "Node vm.runInNewContext / runInThisContext / runInContext on dynamic source",
        "vm.run* APIs evaluate JavaScript source. Without strict sandboxing they're equivalent to eval; sandboxing in vm is shallow.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Use a real sandbox (isolated-vm, a process boundary) and never let attacker source reach run*.",
        ("javascript", "typescript"),
        (),
        r"\bvm\s*\.\s*runIn(?:NewContext|ThisContext|Context)\s*\(",
    ),
    # ---------- Java / Kotlin ----------
    (
        "jvm.scriptengine-eval",
        "JVM ScriptEngine.eval() — server-side script execution",
        "ScriptEngine.eval(...) executes JavaScript / Groovy / etc.; any user input reaching the script is RCE.",
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Pre-compile only known scripts; reject any dynamic source.",
        ("java", "kotlin"),
        (),
        r"\bScriptEngine\b[\s\S]{0,40}?\.\s*eval\s*\(",
    ),
    (
        "jvm.runtime-exec",
        "Runtime.getRuntime().exec(...) — JVM shell-out",
        "Runtime.exec is the JVM equivalent of subprocess; calling it with concatenated input is command injection.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "injection",
        "Use ProcessBuilder with an argv list; never pass concatenated strings to exec.",
        ("java", "kotlin"),
        (),
        r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
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
