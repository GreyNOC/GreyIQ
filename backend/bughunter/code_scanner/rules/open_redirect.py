"""Open-redirect sink primitives.

Redirecting to a destination taken straight from the request (a `?next=`/`?url=`
parameter) lets an attacker bounce victims to a phishing/credential-harvest page —
the canonical open-redirect sink (CWE-601). We flag the SINK where the redirect
target is request-derived; HIGH severity, MEDIUM confidence.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    # ---------- Python (Flask / Werkzeug / Django) ----------
    (
        "py.flask-redirect-request",
        "Flask redirect() to a request value",
        "redirect(request.args/values/form[...]) sends the user wherever the request says — an open redirect.",
        Severity.HIGH, Confidence.MEDIUM, "open_redirect",
        "Allowlist redirect targets (relative paths or a fixed host set); reject absolute/off-host URLs.",
        ("python",),
        r"\bredirect\s*\(\s*request\s*\.\s*(?:args|values|form|GET|POST)\b",
    ),
    (
        "py.django-redirect-request",
        "Django HttpResponseRedirect to a request value",
        "HttpResponseRedirect(request.GET/POST[...]) redirects to an attacker-supplied URL.",
        Severity.HIGH, Confidence.MEDIUM, "open_redirect",
        "Use url_has_allowed_host_and_scheme() (Django) before redirecting to any request-supplied target.",
        ("python",),
        r"\b(?:HttpResponseRedirect|redirect)\s*\(\s*request\s*\.\s*(?:GET|POST)\b",
    ),
    # ---------- JavaScript / TypeScript (Express) ----------
    (
        "js.express-redirect-request",
        "Express res.redirect() to a request value",
        "res.redirect(req.query/params/body[...]) follows an attacker-controlled URL — open redirect.",
        Severity.HIGH, Confidence.MEDIUM, "open_redirect",
        "Validate the target against an allowlist of paths/hosts; never redirect to a raw request value.",
        ("javascript", "typescript"),
        r"\bres\s*\.\s*redirect\s*\(\s*req\s*\.\s*(?:query|params|body)\b",
    ),
    (
        "js.location-assign-request",
        "Client-side location set from a URL parameter",
        "location = / location.assign(new URLSearchParams(...).get(...)) is a DOM-based open redirect.",
        Severity.HIGH, Confidence.LOW, "open_redirect",
        "Validate the destination is a same-origin relative path before assigning to location.",
        ("javascript", "typescript"),
        r"location\s*(?:\.\s*(?:assign|replace)\s*\(|\s*=)\s*[^;]*(?:URLSearchParams|location\.search|\.query|getParameter)",
    ),
]


RULES = tuple(
    RegexRule(
        rule_id=rid, title=title, description=desc, severity=sev, confidence=conf,
        category=cat, remediation=remed, languages=langs, pattern=pat, flags=re.MULTILINE,
    )
    for rid, title, desc, sev, conf, cat, remed, langs, pat in _RULES_RAW
)
