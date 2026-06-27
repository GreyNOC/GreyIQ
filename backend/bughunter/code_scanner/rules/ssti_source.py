"""Server-side template-injection (SSTI) source sinks.

Building a template from a string that includes untrusted input — Jinja2's
render_template_string / Template(user_input), or string-formatting into a template —
lets an attacker reach the template engine and, on many engines, RCE. We flag the
SINK; HIGH severity, MEDIUM/LOW confidence (sink-not-flow). Complements the active
{{7*7}} SSTI confirmation for URL targets.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    # ---------- Python (Jinja2 / Flask) ----------
    (
        "py.render-template-string-format",
        "Jinja2 render_template_string built from input",
        "render_template_string() given an f-string / concatenated / .format()-built template injects untrusted text into the engine.",
        Severity.HIGH, Confidence.MEDIUM, "ssti",
        "Render a fixed template file and pass user data as context variables; never build the template string from input.",
        ("python",),
        r"\brender_template_string\s*\(\s*[fF]?[\"'].*(?:\{|['\"]\s*\+|\.format\s*\()",
    ),
    (
        "py.jinja-template-variable",
        "Jinja2/Mako Template() constructed from a variable",
        "Template(user_value) compiles an attacker-controlled template — a direct SSTI sink.",
        Severity.HIGH, Confidence.LOW, "ssti",
        "Compile only fixed template strings; pass user input as render context, not as the template.",
        ("python",),
        r"\bTemplate\s*\(\s*(?![\"'])[A-Za-z_]\w*\s*\)",
    ),
    # ---------- JavaScript / TypeScript (Handlebars / EJS / Pug) ----------
    (
        "js.template-compile-variable",
        "Handlebars/EJS/Pug compiled from a variable",
        "Handlebars.compile/ejs.render/pug.compile on a request-derived template string is SSTI.",
        Severity.HIGH, Confidence.LOW, "ssti",
        "Compile only static templates; pass user input as data, never as the template source.",
        ("javascript", "typescript"),
        r"\b(?:Handlebars\s*\.\s*compile|ejs\s*\.\s*render|pug\s*\.\s*compile)\s*\(\s*(?![\"'`])[A-Za-z_$]",
    ),
]


RULES = tuple(
    RegexRule(
        rule_id=rid, title=title, description=desc, severity=sev, confidence=conf,
        category=cat, remediation=remed, languages=langs, pattern=pat, flags=re.MULTILINE,
    )
    for rid, title, desc, sev, conf, cat, remed, langs, pat in _RULES_RAW
)
