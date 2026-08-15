"""Attack-chain engine — links individual clues into an ordered, multi-step attack.

A single finding answers "what is broken here". This module answers the question a
triager actually pays for: **"what can an attacker DO with everything we found?"**

It is a forward-chaining capability planner, not a pair matcher. The model is:

    capability  — what the attacker HOLDS at a point in the chain
                  (``exec.browser-script``, ``read.session-token``, ``identity.admin``…)
    clue        — a typed observation that can ENABLE a step: a finding, or a
                  sub-finding-grade signal (a session cookie missing HttpOnly, an
                  auth-looking field name, a reachable metadata service…)
    technique   — ``requires`` capabilities + an enabling clue -> ``grants`` capabilities
    chain       — an ordered path from an entry capability to a terminal IMPACT

This is why sub-finding signals matter and why GreyIQ no longer reports cookie flags
as standalone findings. "Cookie missing HttpOnly" is not a vulnerability; it is the
difference between "XSS runs script" and "XSS takes the account". The flag only earns
a place in the report when a chain actually consumes it — and then it is reported as
the escalation step it really is, attached to the finding it escalates.

HONESTY INVARIANTS (the house rule: reproducible or it didn't happen)
--------------------------------------------------------------------
* This module NEVER promotes anything to confirmed. A step is ``proven`` only when
  ``investigator.has_confirming_artifact`` — which delegates to the single confirm
  authority in ``report`` — already accepted that finding's evidence. Signals are
  never proof; they can only ever mark a step ``projected``.
* A chain is ``proven`` only when EVERY step is proven. One projected link makes the
  whole chain ``partial`` at best. Chain confidence is the WEAKEST link, never a mean:
  averaging is how a chain of two 50s renders as a confident 50 when it is really a
  guess resting on a guess.
* A projected chain's confidence is capped below the supported band, exactly like an
  unproven hypothesis in the cortex, so a long speculative chain can never out-rank a
  short proven one.

Pure stdlib, deterministic, bounded, and total (never raises) — it runs at report time
on a finished hunt, so an exception here would discard completed work.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from bughunter import investigator

ALGORITHM_VERSION = "attack-chain-v1"

# Bounds — this runs inside a hunt, so every dimension is capped.
_MAX_CHAINS = 12
_MAX_DEPTH = 6
_MAX_CLUES = 400
_MAX_EXPANSIONS = 20000
_MAX_PATHS_PER_IMPACT = 2

# Mirrors investigator's unproven ceiling: a projected chain must stay a lead.
_PROJECTED_CEILING = 54

# --------------------------------------------------------------------------------------
# Capability vocabulary
# --------------------------------------------------------------------------------------
# Entry points an attacker starts from. Each chain declares which one it assumes.
#
# Deliberately only two, and both universally available. A network-adjacent attacker is NOT
# an entry point here: making it one meant "session cookie without Secure" composed into an
# account-takeover chain on its own, on every HTTPS site with a non-Secure session cookie —
# which is the exact unconditional cookie noise this engine exists to stop, wearing a chain
# as a disguise. A network position must be EARNED from observed evidence (mixed content, a
# reachable plaintext endpoint) via `net.mitm-position`.
_ENTRIES: dict[str, str] = {
    "entry.unauthenticated": "an unauthenticated internet attacker",
    "entry.low-priv-account": "an attacker holding their own low-privilege account",
}

# Terminal impacts, with the business-impact weight the chain is ranked by.
_IMPACTS: dict[str, tuple[int, str]] = {
    "exec.server-code": (100, "Remote code execution on the target's infrastructure"),
    "identity.admin": (96, "Administrative account or privilege takeover"),
    "cred.cloud": (92, "Cloud control-plane credential compromise"),
    "identity.other-user": (86, "Takeover of another user's account"),
    "write.other-object": (78, "Unauthorized modification of another tenant's data"),
    "read.other-object": (70, "Unauthorized read of another tenant's data"),
    "disclose.sensitive-data": (62, "Disclosure of sensitive data to an unauthorized actor"),
    "read.server-file": (60, "Unauthorized read of server-side files"),
    "net.internal": (52, "Reachability of internal-only network services"),
}

_CAPABILITY_LABELS: dict[str, str] = {
    "act.as-victim-session": "ride the victim's authenticated session",
    "cred.cloud": "hold cloud control-plane credentials",
    "cred.service": "hold a service/API credential",
    "disclose.identifier": "know real object identifiers or hidden paths",
    "disclose.sensitive-data": "read sensitive data they should not",
    "egress.oob": "prove server-side egress to a controlled collaborator",
    "exec.browser-script": "execute script in the application's browser origin",
    "exec.server-code": "execute code server-side",
    "identity.admin": "act as an administrator",
    "identity.other-user": "act as another user",
    "net.internal": "reach internal-only network services",
    "net.mitm-position": "observe or modify the victim's plaintext traffic",
    "read.other-object": "read another tenant's objects",
    "read.server-file": "read server-side files",
    "read.server-side-response": "read the server's own outbound responses",
    "read.session-token": "read the victim's session token",
    "read.source-or-config": "read application source or configuration",
    "takeover.subdomain": "control a hostname inside the target's cookie/CORS trust boundary",
    "write.other-object": "modify another tenant's objects",
    **{key: value for key, value in _ENTRIES.items()},
}


# --------------------------------------------------------------------------------------
# Technique table — the actual attacker knowledge
# --------------------------------------------------------------------------------------
# Each row: requires (ALL must be held) + a clue matching `clue` -> grants.
#   clue kinds: ("class", <class_id>)  -> a finding of that vulnerability class
#               ("signal", <signal>)   -> a sub-finding observation (see collect_signals)
#               None                   -> no clue needed; a pure capability transition
# `weight` biases which path is preferred when several reach the same impact.
_TECHNIQUES: tuple[dict[str, Any], ...] = (
    # --- Browser-side escalation. This is where the cookie flags earn their keep. -------
    {
        "id": "xss-execution",
        "title": "Reflected/stored input reaches a browser sink",
        "requires": (),
        "clue": ("class", "xss"),
        "grants": ("exec.browser-script",),
        "weight": 8,
        "action": "Capture execution in a real browser context with a harmless marker, plus a safely-encoded control value.",
    },
    {
        "id": "prototype-pollution-gadget",
        "title": "Prototype pollution reaches a script gadget",
        "requires": (),
        "clue": ("class", "prototype-pollution"),
        "grants": ("exec.browser-script",),
        "weight": 4,
        "action": "Prove the polluted property reaches a specific sink and capture execution plus a clean-object control.",
    },
    {
        "id": "xss-steals-session-cookie",
        "title": "Script reads the session cookie (no HttpOnly)",
        "requires": ("exec.browser-script",),
        "clue": ("signal", "cookie.session-no-httponly"),
        "grants": ("read.session-token",),
        "weight": 9,
        "action": "From the proven script context, read document.cookie in a TEST account and capture the session name only — never exfiltrate a real user's token.",
        "note": "The missing HttpOnly flag is what turns script execution into token theft; on its own it is not a vulnerability.",
    },
    {
        "id": "xss-rides-session",
        "title": "Script performs authenticated actions in the victim's session",
        "requires": ("exec.browser-script",),
        "clue": None,
        "grants": ("act.as-victim-session",),
        "weight": 6,
        "action": "From the proven script context, issue one same-origin credentialed request in a test account and capture the authenticated response.",
    },
    {
        "id": "session-token-to-identity",
        "title": "Replay the stolen session token as the victim",
        "requires": ("read.session-token",),
        "clue": None,
        "grants": ("identity.other-user",),
        "weight": 8,
        "action": "Replay the captured token from a clean client against an identity endpoint and capture the victim-identity response plus a no-token control.",
    },
    {
        "id": "session-ride-to-write",
        "title": "Ride the session into a state-changing action",
        "requires": ("act.as-victim-session",),
        "clue": ("class", "csrf"),
        "grants": ("write.other-object",),
        "weight": 6,
        "action": "Capture the cross-site state change in a victim test session and the unchanged control request.",
    },
    {
        "id": "admin-viewed-sink",
        "title": "Stored payload renders in an administrative view",
        "requires": ("exec.browser-script",),
        "clue": ("signal", "sink.admin-rendered"),
        "grants": ("identity.admin",),
        "weight": 7,
        "action": "Show the stored value reaching the privileged view with a harmless marker; do not execute privileged actions without explicit engagement approval.",
    },
    # --- CSRF / SameSite --------------------------------------------------------------
    {
        "id": "csrf-cross-site-post",
        "title": "Cross-site request rides the session (no SameSite)",
        "requires": (),
        "clue": ("signal", "cookie.session-no-samesite"),
        "grants": ("act.as-victim-session",),
        "weight": 5,
        "action": "Prove a cross-site request is actually accepted with the cookie attached, and capture a control showing the action fails without it.",
        "note": "A session cookie without SameSite is only a finding once a state-changing endpoint is shown to accept the cross-site request.",
    },
    # --- Network position: this is what a missing Secure flag actually buys ------------
    {
        "id": "mixed-content-downgrade",
        "title": "Mixed content forces a plaintext request",
        "requires": (),
        "clue": ("signal", "transport.mixed-content"),
        "grants": ("net.mitm-position",),
        "weight": 3,
        "action": "Capture the plaintext subresource request the HTTPS page actually issues.",
    },
    {
        "id": "plaintext-endpoint-reachable",
        "title": "An in-scope endpoint is served over plaintext HTTP",
        "requires": (),
        "clue": ("signal", "transport.plaintext-endpoint"),
        "grants": ("net.mitm-position",),
        "weight": 3,
        "action": "Capture the plaintext request/response and confirm it is not immediately redirected to HTTPS with HSTS.",
    },
    {
        "id": "cleartext-session-exposure",
        "title": "Session cookie is transmitted over the observed cleartext channel",
        "requires": ("net.mitm-position",),
        "clue": ("signal", "cookie.session-no-secure"),
        "grants": ("read.session-token",),
        "weight": 4,
        "action": "Show the cookie is actually sent on the plaintext request, not merely that the Secure flag is absent.",
        "note": "Needs a network-adjacent attacker AND a genuinely reachable plaintext path; most programs close the flag alone as informational.",
    },
    # --- Subdomain takeover inside the cookie/CORS trust boundary ----------------------
    {
        "id": "subdomain-takeover",
        "title": "Claim a dangling subdomain",
        "requires": (),
        "clue": ("class", "subdomain-takeover"),
        "grants": ("takeover.subdomain",),
        "weight": 7,
        "action": "Claim the dangling target only if the program's rules permit it, serve a benign proof file, and capture it.",
    },
    {
        "id": "takeover-reads-domain-cookie",
        "title": "Controlled subdomain receives the domain-scoped session cookie",
        "requires": ("takeover.subdomain",),
        "clue": ("signal", "cookie.session-domain-scoped"),
        "grants": ("read.session-token",),
        "weight": 8,
        "action": "From the controlled hostname, capture that the parent-domain cookie is actually sent to it; a __Host- prefixed cookie would not be.",
        "note": "A domain-scoped session cookie is only interesting once some hostname in that scope is attacker-controlled.",
    },
    # --- Access control / IDOR --------------------------------------------------------
    {
        "id": "disclosure-yields-identifiers",
        "title": "Disclosure leaks real object identifiers or hidden paths",
        "requires": (),
        "clue": ("class", "disclosure"),
        "grants": ("disclose.identifier",),
        "weight": 5,
        "action": "Capture the exact disclosed identifier or path returned to an unauthorized actor, with secrets redacted.",
    },
    {
        "id": "identifier-to-object-read",
        "title": "Replay a disclosed identifier across the authorization boundary",
        "requires": ("disclose.identifier",),
        "clue": ("class", "access-control"),
        "grants": ("read.other-object",),
        "weight": 8,
        "action": "Use only already-disclosed identifiers, replay across two test roles you own, and capture the authorized-vs-unauthorized response differential.",
    },
    {
        "id": "direct-object-read",
        "title": "Object reference is accepted across the authorization boundary",
        "requires": ("entry.low-priv-account",),
        "clue": ("class", "access-control"),
        "grants": ("read.other-object",),
        "weight": 7,
        "action": "Replay the same object as a lower-privilege actor you control and capture the authorized-vs-unauthorized differential.",
    },
    {
        "id": "object-read-to-write",
        "title": "The same broken boundary accepts a write",
        "requires": ("read.other-object",),
        "clue": ("signal", "endpoint.state-changing"),
        "grants": ("write.other-object",),
        "weight": 6,
        "action": "Only against an object you own in a second test tenant: capture the accepted write and the rejected control.",
    },
    {
        "id": "graphql-field-authorization",
        "title": "GraphQL exposes an object/field past the REST boundary",
        "requires": (),
        "clue": ("class", "graphql"),
        "grants": ("read.other-object",),
        "weight": 6,
        "action": "Replay the same query across two test roles and capture object- and field-level response differences.",
    },
    {
        "id": "mass-assignment-privesc",
        "title": "A role-like field is accepted on a user-controlled write",
        "requires": ("entry.low-priv-account",),
        "clue": ("signal", "field.role-like"),
        "grants": ("identity.admin",),
        "weight": 7,
        "action": "On an account you own, submit the role-like field and capture the server ECHOING the elevated value back plus a control request without it.",
    },
    {
        "id": "object-write-to-admin",
        "title": "Cross-tenant write reaches a privileged record",
        "requires": ("write.other-object",),
        "clue": ("signal", "field.role-like"),
        "grants": ("identity.admin",),
        "weight": 5,
        "action": "Demonstrate on your own second tenant only; capture the privilege change and its control.",
    },
    # --- Credentials / tokens ---------------------------------------------------------
    {
        "id": "exposed-credential",
        "title": "A usable credential is exposed",
        "requires": (),
        "clue": ("class", "secrets"),
        "grants": ("cred.service",),
        "weight": 8,
        "action": "Validate the credential with the least-privileged issuer call, record its scope, and never place the raw value in the report.",
    },
    {
        "id": "credential-to-cloud",
        "title": "The exposed credential is a cloud control-plane key",
        "requires": ("cred.service",),
        "clue": ("signal", "credential.cloud-provider"),
        "grants": ("cred.cloud",),
        "weight": 8,
        "action": "Make one read-only identity call (e.g. a caller-identity lookup) to establish scope; do not enumerate or touch resources.",
    },
    {
        "id": "credential-to-admin",
        "title": "The credential carries privileged scope",
        "requires": ("cred.service",),
        "clue": ("signal", "credential.privileged-scope"),
        "grants": ("identity.admin",),
        "weight": 6,
        "action": "Establish scope with the least-privileged call that proves privilege, and stop there.",
    },
    {
        "id": "jwt-forgery",
        "title": "Token verification can be bypassed or forged",
        "requires": (),
        "clue": ("class", "jwt"),
        "grants": ("identity.other-user",),
        "weight": 7,
        "action": "Replay the altered token successfully against a test account and capture the rejected control token.",
    },
    {
        "id": "jwt-forgery-to-admin",
        "title": "The forged token carries a privileged claim",
        "requires": ("identity.other-user",),
        "clue": ("signal", "token.role-claim"),
        "grants": ("identity.admin",),
        "weight": 5,
        "action": "Forge only into an account you own; capture the privileged response and the rejected control.",
    },
    # --- Server-side request / parser primitives --------------------------------------
    {
        "id": "server-side-request",
        "title": "The server fetches an attacker-controlled destination",
        "requires": (),
        "clue": ("class", "ssrf"),
        "grants": ("net.internal", "read.server-side-response"),
        "weight": 9,
        "action": "Capture an authorized callback or an internal-response differential tied uniquely to the tested request.",
    },
    {
        "id": "xxe-as-request-primitive",
        "title": "External entity resolution acts as a request primitive",
        "requires": (),
        "clue": ("class", "xxe"),
        "grants": ("net.internal", "read.server-file"),
        "weight": 8,
        "action": "Capture a unique authorized callback for each primitive and a parser-configuration control.",
    },
    {
        "id": "oob-confirms-blind",
        "title": "Out-of-band callback confirms a blind primitive",
        "requires": ("net.internal",),
        "clue": ("signal", "proof.oob-callback"),
        "grants": ("egress.oob",),
        "weight": 6,
        "action": "Tie the callback token uniquely to the one request that produced it.",
    },
    {
        "id": "internal-to-metadata",
        "title": "The internal pivot reaches the cloud metadata service",
        "requires": ("net.internal",),
        "clue": ("signal", "infra.cloud-hosted"),
        "grants": ("cred.cloud",),
        "weight": 8,
        "action": "Use the metadata-safe control the program allows and capture a target-bound response differential; do NOT retrieve live credential material unless the program explicitly permits it.",
    },
    {
        "id": "file-read-to-config",
        "title": "File read reaches application configuration",
        "requires": ("read.server-file",),
        "clue": None,
        "grants": ("read.source-or-config",),
        "weight": 6,
        "action": "Capture an allowed read outside the intended root and a benign in-root control.",
    },
    {
        "id": "path-traversal-read",
        "title": "Path traversal escapes the intended root",
        "requires": (),
        "clue": ("class", "path-traversal"),
        "grants": ("read.server-file",),
        "weight": 7,
        "action": "Capture an allowed file read outside the intended root and a benign in-root control.",
    },
    {
        "id": "config-yields-credential",
        "title": "Configuration exposes a credential",
        "requires": ("read.source-or-config",),
        "clue": None,
        "grants": ("cred.service",),
        "weight": 6,
        "action": "Identify the credential type and validate it with the least-privileged issuer call; never store the raw value.",
    },
    # --- Direct server execution ------------------------------------------------------
    {
        "id": "template-injection",
        "title": "Template expression is evaluated server-side",
        "requires": (),
        "clue": ("class", "ssti"),
        "grants": ("exec.server-code",),
        "weight": 9,
        "action": "Capture a harmless deterministic expression result and a literal-text control.",
    },
    {
        "id": "command-injection",
        "title": "Input reaches a command interpreter",
        "requires": (),
        "clue": ("class", "rce"),
        "grants": ("exec.server-code",),
        "weight": 10,
        "action": "Capture a harmless unique execution marker and a control request without the injected input.",
    },
    {
        "id": "deserialization-execution",
        "title": "Untrusted data is deserialized",
        "requires": (),
        "clue": ("class", "deserialization"),
        "grants": ("exec.server-code",),
        "weight": 9,
        "action": "Use a benign, non-destructive gadget that only proves evaluation, and capture a control payload that is rejected.",
    },
    {
        "id": "upload-to-execution",
        "title": "Uploaded file is served from an executable path",
        "requires": (),
        "clue": ("class", "file-upload"),
        "grants": ("exec.server-code",),
        "weight": 8,
        "action": "Upload an inert marker file, capture it being executed/served, and remove it; never upload a working shell.",
    },
    {
        "id": "sql-injection-read",
        "title": "SQL injection returns database content",
        "requires": (),
        "clue": ("class", "sqli"),
        "grants": ("disclose.sensitive-data",),
        "weight": 9,
        "action": "Capture a stable true/false or error differential attributable to the input, without modifying data.",
    },
    {
        "id": "nosql-injection-read",
        "title": "NoSQL injection alters the query's meaning",
        "requires": (),
        "clue": ("class", "nosqli"),
        "grants": ("disclose.sensitive-data",),
        "weight": 7,
        "action": "Capture a stable operator-injection differential without modifying data.",
    },
    # --- Cross-origin / redirect ------------------------------------------------------
    {
        "id": "credentialed-cross-origin-read",
        "title": "An attacker origin can read authenticated responses",
        "requires": (),
        "clue": ("class", "cors"),
        "grants": ("disclose.sensitive-data",),
        "weight": 7,
        "action": "Run a browser PoC against an authenticated test account and capture the readable sensitive response plus a disallowed-origin control.",
    },
    {
        "id": "cross-origin-reads-token",
        "title": "The cross-origin response carries the session token",
        "requires": ("disclose.sensitive-data",),
        "clue": ("signal", "response.token-in-body"),
        "grants": ("read.session-token",),
        "weight": 6,
        "action": "Capture the token-bearing field in the cross-origin readable response from a test account.",
    },
    {
        "id": "auth-flow-redirect",
        "title": "An auth flow redirects off-origin with state attached",
        "requires": (),
        "clue": ("class", "redirect"),
        "grants": ("disclose.identifier",),
        "weight": 4,
        "action": "Walk the affected auth flow end to end and capture whether sensitive state reaches the off-origin destination.",
    },
    {
        "id": "redirect-leaks-token",
        "title": "The redirect carries a token to the attacker origin",
        "requires": ("disclose.identifier",),
        "clue": ("signal", "flow.auth-redirect"),
        "grants": ("read.session-token",),
        "weight": 7,
        "action": "Capture the token actually arriving at a destination you control, using a test account only.",
    },
    {
        "id": "request-smuggling-hijack",
        "title": "Desynchronized request captures another user's request",
        "requires": (),
        "clue": ("class", "request-smuggling"),
        "grants": ("read.session-token",),
        "weight": 8,
        "action": "Capture the desync with a benign marker request; stop before capturing any real user's traffic.",
    },
)

# Signals whose ONLY job is to escalate a step. Reporting them standalone is noise —
# this is the demotion list the web scanner and digest feed.
ESCALATION_ONLY_SIGNALS = frozenset({
    "cookie.session-no-httponly",
    "cookie.session-no-samesite",
    "cookie.session-no-secure",
    "cookie.session-domain-scoped",
})

_SIGNAL_LABELS: dict[str, str] = {
    "cookie.session-no-httponly": "session cookie readable by JavaScript (no HttpOnly)",
    "cookie.session-no-samesite": "session cookie sent cross-site (no SameSite)",
    "cookie.session-no-secure": "session cookie sent over cleartext (no Secure)",
    "cookie.session-domain-scoped": "session cookie scoped to the parent domain (not __Host-)",
    "credential.cloud-provider": "the exposed credential belongs to a cloud provider",
    "credential.privileged-scope": "the exposed credential carries privileged scope",
    "endpoint.state-changing": "a state-changing endpoint was observed",
    "field.role-like": "a role/privilege-like field name is accepted",
    "flow.auth-redirect": "the redirect sits inside an authentication flow",
    "infra.cloud-hosted": "the target is cloud-hosted (metadata service plausible)",
    "proof.oob-callback": "an out-of-band callback was captured",
    "response.token-in-body": "a token-like field appears in a response body",
    "sink.admin-rendered": "stored input is rendered in an administrative view",
    "transport.mixed-content": "an HTTPS page loads a plaintext subresource",
    "transport.plaintext-endpoint": "an in-scope endpoint is reachable over plaintext HTTP",
    "token.role-claim": "the token carries a role/privilege claim",
}

# --------------------------------------------------------------------------------------
# Signal extraction
# --------------------------------------------------------------------------------------
_SESSION_COOKIE_RE = re.compile(
    r"(sess|sid\b|auth|jwt|login|remember|identity|account)", re.IGNORECASE
)
# Cookies that LOOK session-ish but are not the session, and whose flag "gaps" are by design.
# A double-submit CSRF token cookie MUST be readable by JavaScript — that is the entire
# pattern — so treating a missing HttpOnly on it as a token-theft step fabricated an
# account-takeover chain out of a correct implementation. Checked before the match above.
_NOT_SESSION_COOKIE_RE = re.compile(r"(csrf|xsrf|_token\b|antiforgery)", re.IGNORECASE)
_ROLE_FIELD_RE = re.compile(
    r"^(is_?admin|admin|role|roles|is_?staff|is_?superuser|permission|permissions|scope|scopes"
    r"|privilege|privileges|is_?verified|account_?type|user_?type|group|groups|tier|plan)$",
    re.IGNORECASE,
)
_TOKEN_FIELD_RE = re.compile(
    r"(access_?token|id_?token|refresh_?token|session|api_?key|secret|bearer|jwt)", re.IGNORECASE
)
_STATE_CHANGING_RE = re.compile(
    r"(create|update|delete|remove|edit|set|add|invite|transfer|upload|change|reset|revoke|grant)",
    re.IGNORECASE,
)
_CLOUD_HOST_RE = re.compile(
    r"(amazonaws\.com|azurewebsites\.net|cloudapp\.azure\.com|googleusercontent\.com"
    r"|appspot\.com|herokuapp\.com|cloudfront\.net|run\.app|azure\.com|gcp\.)",
    re.IGNORECASE,
)
_CLOUD_CRED_RE = re.compile(r"(aws|amazon|azure|gcp|google[_-]?cloud|s3|iam|sigv4)", re.IGNORECASE)
_PRIVILEGED_SCOPE_RE = re.compile(r"(admin|write|full|owner|root|\*|superuser)", re.IGNORECASE)
_AUTH_FLOW_RE = re.compile(
    r"(login|logout|signin|sign-in|oauth|sso|saml|callback|authorize|reset|invite|verify|confirm)",
    re.IGNORECASE,
)


def _text(value: Any, limit: int = 400) -> str:
    return str(value or "").strip()[:limit]


def _signal(kind: str, subject: str, why: str, *, source: str = "", ref: str = "") -> dict[str, Any]:
    return {
        "kind": kind,
        "subject": _text(subject, 300),
        "why": _text(why, 300),
        "source": _text(source, 60),
        "ref": _text(ref, 40),
        "escalation_only": kind in ESCALATION_ONLY_SIGNALS,
    }


def cookie_signals(cookies: Any, url: str = "") -> list[dict[str, Any]]:
    """Turn raw ``Set-Cookie`` headers into escalation signals.

    This replaces the standalone ``web.cookie-*`` findings. A flag gap is recorded ONLY
    for a session-looking cookie (a preference cookie without HttpOnly is noise), and
    only ever as a signal — it becomes reportable when a chain consumes it.
    Cookie NAMES only; a value can carry the session token itself.
    """
    out: list[dict[str, Any]] = []
    if not isinstance(cookies, (list, tuple)):
        return out
    is_https = str(url or "").lower().startswith("https://")
    for raw in list(cookies)[:40]:
        cookie = str(raw or "")
        # Parse ATTRIBUTES rather than substring-searching the whole header. A cookie whose
        # VALUE happens to contain "httponly"/"secure"/"domain=" (attacker-influenceable, and
        # base64 blobs contain most things) otherwise silently suppressed its own flag gap.
        parts = cookie.split(";")
        name = parts[0].split("=", 1)[0].strip()
        if not name or _NOT_SESSION_COOKIE_RE.search(name) or not _SESSION_COOKIE_RE.search(name):
            continue
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            key, _, value = part.partition("=")
            attrs[key.strip().lower()] = value.strip()
        # Only the flag facts — never the value.
        if "httponly" not in attrs:
            out.append(_signal("cookie.session-no-httponly", url,
                               f"session cookie '{name}' is readable by JavaScript", source="set-cookie"))
        # SameSite=None is not "has SameSite" — it is the explicit opt-IN to cross-site
        # sending, i.e. exactly the condition the CSRF step needs. Treating its presence as
        # protection inverted the check on the one value that matters.
        samesite = attrs.get("samesite", "").lower()
        if "samesite" not in attrs:
            out.append(_signal("cookie.session-no-samesite", url,
                               f"session cookie '{name}' has no SameSite attribute", source="set-cookie"))
        elif samesite == "none":
            out.append(_signal("cookie.session-no-samesite", url,
                               f"session cookie '{name}' sets SameSite=None (sent cross-site)",
                               source="set-cookie"))
        if is_https and "secure" not in attrs:
            out.append(_signal("cookie.session-no-secure", url,
                               f"session cookie '{name}' may be sent over cleartext", source="set-cookie"))
        if "domain" in attrs and not name.lower().startswith("__host-"):
            out.append(_signal("cookie.session-domain-scoped", url,
                               f"session cookie '{name}' is scoped to the parent domain", source="set-cookie"))
    return out


def collect_signals(
    *,
    findings: list[dict[str, Any]] | None = None,
    response_digest: dict[str, Any] | None = None,
    surface: dict[str, Any] | None = None,
    extra: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Gather every sub-finding clue the chain engine can use. Never raises.

    Each family is guarded INDEPENDENTLY. A single over-broad try around everything meant one
    malformed sub-field — and these come from target-derived, partly model-influenced data —
    aborted every later family and still returned success, so a hunt could silently lose most
    of its chain graph with nothing anywhere saying so.
    """
    out: list[dict[str, Any]] = []

    def _family(fn: Any) -> None:
        try:
            fn()
        except Exception:  # noqa: BLE001 - one bad family must not cost the others
            pass

    def _extra_signals() -> None:
        for item in extra or []:
            if isinstance(item, dict) and item.get("kind"):
                out.append(_signal(str(item.get("kind")), item.get("subject") or "",
                                   item.get("why") or "", source=item.get("source") or "",
                                   ref=item.get("ref") or ""))

    digest = response_digest if isinstance(response_digest, dict) else {}

    def _digest_cookies() -> None:
        # The digest already extracts cookie flag gaps for the brain prompt; reuse them so
        # the chain engine sees the same facts even when the raw Set-Cookie list is gone.
        for gap in digest.get("cookie_flag_gaps") or []:
            if not isinstance(gap, dict):
                continue
            name = _text(gap.get("cookie"), 120)
            missing = gap.get("missing") if isinstance(gap.get("missing"), list) else []
            for flag in missing:
                kind = {
                    "HttpOnly": "cookie.session-no-httponly",
                    "SameSite": "cookie.session-no-samesite",
                    "Secure": "cookie.session-no-secure",
                }.get(str(flag))
                if kind:
                    out.append(_signal(kind, "", f"session cookie '{name}' is missing {flag}",
                                       source="response-digest"))

    def _digest_names() -> None:
        for name in [*(digest.get("interesting_names") or []), *(digest.get("form_fields") or [])][:200]:
            label = _text(name, 80)
            if _ROLE_FIELD_RE.match(label):
                out.append(_signal("field.role-like", label,
                                   f"a role-like field '{label}' is present in the request/response shape",
                                   source="response-digest"))
        # response.token-in-body means what it says: the name came from a RESPONSE BODY. It was
        # also being emitted from form_fields (a request shape) and interesting_names (a mixed
        # bag), so a login form's own "token" input claimed a token appeared in a response —
        # and fed the cross-origin token-read step on that basis. json_keys is the only one of
        # the three the digest builds from the parsed response body.
        for name in (digest.get("json_keys") or [])[:200]:
            label = _text(name, 80)
            if _ROLE_FIELD_RE.match(label):
                out.append(_signal("field.role-like", label,
                                   f"a role-like field '{label}' is present in the response body",
                                   source="response-digest"))
            elif _TOKEN_FIELD_RE.search(label):
                out.append(_signal("response.token-in-body", label,
                                   f"a token-like field '{label}' appears in the response body",
                                   source="response-digest"))
        # NOTE: no `token.role-claim` signal is derived from the digest. The digest decodes a
        # JWT's HEADER only — never the payload — so the presence of an `alg` says a JWT is in
        # use and nothing whatsoever about a role/privilege claim inside it. Emitting it here
        # let any JWT-using site escalate a chain's heading to administrative takeover on no
        # evidence at all. The signal stays in the vocabulary for a producer that can actually
        # observe a role claim; nothing fabricates it.

    surface_obj = surface if isinstance(surface, dict) else {}

    def _surface_endpoints() -> None:
        endpoints = surface_obj.get("endpoints") if isinstance(surface_obj.get("endpoints"), list) else []
        for endpoint in endpoints[:200]:
            url = _text(endpoint, 400)
            if url.lower().startswith("http://"):
                out.append(_signal("transport.plaintext-endpoint", url,
                                   "the endpoint was observed on plaintext HTTP", source="recon"))
            if _STATE_CHANGING_RE.search(url):
                out.append(_signal("endpoint.state-changing", url,
                                   "the path name indicates a state-changing operation", source="recon"))
            if _AUTH_FLOW_RE.search(url):
                out.append(_signal("flow.auth-redirect", url,
                                   "the endpoint sits inside an authentication flow", source="recon"))
            if _CLOUD_HOST_RE.search(url):
                out.append(_signal("infra.cloud-hosted", url,
                                   "the host resolves to a cloud provider surface", source="recon"))

    def _surface_forms() -> None:
        for form in surface_obj.get("forms") or []:
            if not isinstance(form, dict):
                continue
            if _text(form.get("method"), 10).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                out.append(_signal("endpoint.state-changing", _text(form.get("action"), 300),
                                   "an HTML form submits with a state-changing method", source="recon"))
            for field in form.get("params") or []:
                if _ROLE_FIELD_RE.match(_text(field, 80)):
                    out.append(_signal("field.role-like", _text(field, 80),
                                       f"a role-like form field '{_text(field, 80)}' is submitted",
                                       source="recon"))
    def _surface_tech() -> None:
        for tech in surface_obj.get("tech") or []:
            if _CLOUD_HOST_RE.search(_text(tech, 120)):
                out.append(_signal("infra.cloud-hosted", _text(tech, 120),
                                   "a cloud platform was fingerprinted", source="recon"))

    def _finding_signals() -> None:
        for finding in findings or []:
            if not isinstance(finding, dict):
                continue
            ref = _text(finding.get("ref"), 40)
            haystack = " ".join(
                _text(finding.get(key), 300)
                for key in ("title", "rule_id", "location", "file_path", "snippet", "secret_type")
            )
            if _CLOUD_CRED_RE.search(haystack) and investigator.normalize_class(finding) == "secrets":
                out.append(_signal("credential.cloud-provider", _text(finding.get("location"), 300),
                                   "the exposed credential looks like a cloud provider key",
                                   source="finding", ref=ref))
            # ``scopes`` (plural) is the key every validator in credential_validation actually
            # writes; the singular ``scope`` and a top-level ``credential_scope`` exist nowhere
            # in the repo, so this read matched nothing and the privileged-scope step could
            # never fire on a real validated credential.
            credential = finding.get("_credential_proof") if isinstance(finding.get("_credential_proof"), dict) else {}
            scope = _text(credential.get("scopes") or credential.get("principal"), 200)
            if scope and _PRIVILEGED_SCOPE_RE.search(scope):
                out.append(_signal("credential.privileged-scope", scope,
                                   "the validated credential reports privileged scope",
                                   source="finding", ref=ref))
            proof = finding.get("_active_proof") if isinstance(finding.get("_active_proof"), dict) else {}
            if _text(proof.get("callback_id") or proof.get("interaction_id"), 200):
                out.append(_signal("proof.oob-callback", _text(finding.get("location"), 300),
                                   "an out-of-band callback was captured for this finding",
                                   source="finding", ref=ref))
            if "mixed-content" in _text(finding.get("rule_id"), 120).lower():
                out.append(_signal("transport.mixed-content", _text(finding.get("location"), 300),
                                   "an HTTPS page loads a plaintext subresource", source="finding", ref=ref))
            # NOTE: no `sink.admin-rendered` signal is derived here. Establishing that a stored
            # value renders in an ADMINISTRATIVE view requires authenticated admin access GreyIQ
            # does not have, so there is no honest way to observe it from a hunt; the previous
            # code read `stored_context`/`sink_context`, keys no producer in the repo writes.
            # The `admin-viewed-sink` technique stays in the table for a producer that can
            # genuinely observe this, and simply never fires until one exists.

    for family in (_extra_signals, _digest_cookies, _digest_names,
                   _surface_endpoints, _surface_forms, _surface_tech, _finding_signals):
        _family(family)

    # Deduplicate on (kind, subject) preserving first-seen order for determinism.
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for item in out:
        key = (item["kind"], item["subject"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique[:_MAX_CLUES]


# --------------------------------------------------------------------------------------
# Chain construction
# --------------------------------------------------------------------------------------
def _host_of(location: str) -> str:
    try:
        parsed = urlparse(location)
    except ValueError:
        return ""
    if parsed.hostname:
        return parsed.hostname.lower()
    normalized = re.sub(r"^[a-z][a-z0-9+.-]*:", "", str(location or "").strip(), flags=re.IGNORECASE)
    normalized = normalized.replace("\\", "/").strip("/")
    return normalized.split("/", 1)[0].lower()


def _finding_clue(finding: dict[str, Any], plan: dict[str, Any], index: int) -> dict[str, Any]:
    """Normalize one finding into a clue with its PROVEN state taken from the confirm gate."""
    ref = _text(finding.get("ref"), 40) or f"F{index}"
    try:
        proven = bool(investigator.has_confirming_artifact(finding, plan))
    except Exception:  # noqa: BLE001 - a gate error must never break the chain build
        proven = False
    return {
        "ref": ref,
        "class_id": investigator.normalize_class(finding),
        "title": _text(finding.get("title") or finding.get("rule_id") or "Finding", 240),
        "location": _text(finding.get("location") or finding.get("file_path"), 400),
        "severity": _text(finding.get("severity"), 20).lower() or "info",
        "proven": proven,
    }


def _step_confidence(proven: bool) -> int:
    """A proven step is worth real confidence; an unproven evidence-backed step is a lead."""
    return 82 if proven else 34


def _build_graph(
    clues_by_class: dict[str, list[dict[str, Any]]],
    signals_by_kind: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Instantiate every technique whose enabling clue is actually present."""
    edges: list[dict[str, Any]] = []
    for technique in _TECHNIQUES:
        clue_spec = technique.get("clue")
        if clue_spec is None:
            edges.append({"technique": technique, "clue": None, "signal": None, "proven": False})
            continue
        kind, key = clue_spec
        if kind == "class":
            for clue in clues_by_class.get(key, [])[:3]:
                edges.append({"technique": technique, "clue": clue, "signal": None,
                              "proven": bool(clue["proven"])})
        else:
            # ONE edge per signal kind. A second instance of the same kind produces a chain
            # with identical steps, title and impact — the report printed the same attack
            # twice because the two edges had different indices and so survived the path
            # dedupe. Extra instances add nothing: the technique text is per-kind.
            for signal in signals_by_kind.get(key, [])[:1]:
                # A signal is an OBSERVATION, never proof. This is the invariant that keeps a
                # cookie flag from ever reading as a confirmed step.
                edges.append({"technique": technique, "clue": None, "signal": signal, "proven": False})
    return edges


def _signal_provenance_ok(witness: list[dict[str, Any]]) -> bool:
    """Reject a chain that escalates one finding using an observation about another.

    Most signals are host-wide (a cookie flag, a form field) and carry no ``ref``. The ones
    that DO — "this credential is a cloud key", "this finding got an OOB callback" — describe
    one specific finding, and pairing them with a step built from a different finding invents
    a composition nobody observed: with two exposed secrets, the chain could take finding A's
    credential step and finding B's "it's a cloud key" observation and report cloud compromise.
    """
    refs = {step["clue"]["ref"] for step in witness if step["clue"]}
    for step in witness:
        signal = step["signal"]
        signal_ref = _text(signal.get("ref"), 40) if signal else ""
        if signal_ref and signal_ref not in refs:
            return False
    return True


def _prune_path(path: list[dict[str, Any]], impact: str, entry: str) -> list[dict[str, Any]]:
    """Keep only the steps that actually DERIVE ``impact`` — the minimal witness.

    Without this, a DFS path is a transcript of everything the walk happened to pick up on
    the way, so a chain ending in account takeover could carry an unrelated SQLi step it
    never used. A chain that lists a step the attack does not need is a chain a triager
    stops trusting, so relevance is enforced structurally rather than hoped for.
    """
    needed = {impact}
    kept: list[dict[str, Any]] = []
    for step in reversed(path):
        grants = step["technique"]["grants"]
        if any(cap in needed for cap in grants):
            kept.append(step)
            for cap in grants:
                needed.discard(cap)
            for cap in step["technique"]["requires"]:
                if cap != entry:
                    needed.add(cap)
    kept.reverse()
    return kept


def _enumerate_paths(edges: list[dict[str, Any]], entry: str) -> list[tuple[list[dict[str, Any]], str]]:
    """Bounded DFS from ``entry`` over capability space, collecting minimal witnesses for
    every terminal impact reached. Deterministic: edges are explored in table order."""
    found: list[tuple[list[dict[str, Any]], str]] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()
    budget = [_MAX_EXPANSIONS]

    def record(path: list[dict[str, Any]], grants: tuple[str, ...]) -> None:
        for cap in grants:
            if cap not in _IMPACTS:
                continue
            witness = _prune_path(path, cap, entry)
            if not witness or not _signal_provenance_ok(witness):
                continue
            key = (cap, tuple(step["index"] for step in witness))
            if key in seen:
                continue
            seen.add(key)
            found.append((witness, cap))

    def walk(held: frozenset[str], used: tuple[int, ...], path: list[dict[str, Any]]) -> None:
        if budget[0] <= 0 or len(path) >= _MAX_DEPTH:
            return
        for index, edge in enumerate(edges):
            if budget[0] <= 0:
                return
            if index in used:
                continue
            technique = edge["technique"]
            if not all(cap in held for cap in technique["requires"]):
                continue
            grants = technique["grants"]
            if all(cap in held for cap in grants):
                continue  # adds nothing — skip rather than pad the chain
            budget[0] -= 1
            step = {**edge, "index": index}
            new_path = path + [step]
            record(new_path, grants)
            walk(held | set(grants), used + (index,), new_path)

    walk(frozenset({entry}), (), [])
    return found


def _score_path(path: list[dict[str, Any]], impact: str) -> tuple[int, int, str]:
    """Return (chain_score, confidence, status). Confidence is the WEAKEST link."""
    # Only EVIDENCE-bearing steps set the confidence. A pure capability transition
    # ("replay the token you now hold as the victim") is a logical consequence, not a
    # separate claim — scoring it like a speculative step made every chain containing one
    # rank below chains that simply had fewer inference steps, which is backwards.
    confidences = [_step_confidence(step["proven"]) for step in path
                   if step["clue"] is not None or step["signal"] is not None]
    confidence = min(confidences) if confidences else 24
    proven_count = sum(1 for step in path if step["proven"])
    if proven_count == len(path) and path:
        status = "proven"
    elif proven_count:
        status = "partial"
    else:
        status = "projected"
    if status != "proven":
        # A chain that is not fully proven must not reach the supported band, exactly like an
        # unproven hypothesis. Otherwise a five-step guess out-ranks a one-step captured bug.
        confidence = min(confidence, _PROJECTED_CEILING)
    impact_weight = _IMPACTS.get(impact, (40, ""))[0]
    technique_weight = sum(step["technique"].get("weight", 4) for step in path)
    # Prefer: real impact, actually proven, then short over long (a 2-step chain is a better
    # report than a 5-step one reaching the same place), then technique quality.
    score = int(impact_weight * 1.4 + proven_count * 24 + technique_weight - len(path) * 6)
    if any("net.mitm-position" in step["technique"]["grants"] for step in path):
        # The chain needs the attacker sitting on the victim's network. Real, but a much
        # higher bar than a remote request, and most programs price it accordingly.
        score -= 20
    # Two findings on the same host are far likelier to compose than two on hosts that may
    # not even share a session, so a chain that hops hosts is ranked below one that doesn't.
    hosts = {_host_of(step["clue"]["location"]) for step in path if step["clue"]} - {""}
    if len(hosts) > 1:
        score -= 12 * (len(hosts) - 1)
        confidence = max(0, confidence - 6)
    return max(0, score), max(0, min(99, confidence)), status


def _narrate(entry: str, path: list[dict[str, Any]]) -> str:
    """One plain-English sentence a triager can read without decoding the graph."""
    parts = [f"Starting as {_ENTRIES.get(entry, entry)}"]
    for step in path:
        grants = [cap for cap in step["technique"]["grants"]]
        label = _CAPABILITY_LABELS.get(grants[0], grants[0]) if grants else ""
        verb = "proven" if step["proven"] else "projected"
        parts.append(f"{step['technique']['title'].lower()} ({verb}) to {label}")
    return " → ".join(parts) + "."


def build_attack_chains(
    findings: list[dict[str, Any]] | None,
    attack_plans: dict[str, Any] | None = None,
    *,
    signals: list[dict[str, Any]] | None = None,
    surface: dict[str, Any] | None = None,
    response_digest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ordered, multi-step attack chains from findings plus sub-finding clues.

    Returns ``{algorithm, chains, signals_used, metrics}``. Total: any internal error
    degrades to an empty result rather than breaking the caller.
    """
    try:
        raw_findings = [f for f in (findings or []) if isinstance(f, dict)][:_MAX_CLUES]
        plans = attack_plans if isinstance(attack_plans, dict) else {}
        all_signals = signals if isinstance(signals, list) else collect_signals(
            findings=raw_findings, response_digest=response_digest, surface=surface,
        )

        clues_by_class: dict[str, list[dict[str, Any]]] = {}
        for index, finding in enumerate(raw_findings, 1):
            plan = plans.get(_text(finding.get("ref"), 40))
            clue = _finding_clue(finding, plan if isinstance(plan, dict) else {}, index)
            clues_by_class.setdefault(clue["class_id"], []).append(clue)
        # A proven clue should drive the chain when several of a class exist.
        for rows in clues_by_class.values():
            rows.sort(key=lambda row: (row["proven"], row["severity"] in {"critical", "high"}), reverse=True)

        signals_by_kind: dict[str, list[dict[str, Any]]] = {}
        for signal in all_signals:
            if isinstance(signal, dict) and signal.get("kind"):
                signals_by_kind.setdefault(str(signal["kind"]), []).append(signal)

        edges = _build_graph(clues_by_class, signals_by_kind)

        # Identical step sequences surface under every entry that can reach them, because a
        # path requiring nothing is walkable from all three. Report each attack ONCE, under
        # the entry that demands least of the attacker — a chain an unauthenticated stranger
        # can run is that chain's true severity, and listing the same steps again as
        # "…but with an account" is padding, not a second finding.
        best_by_path: dict[tuple[str, tuple[int, ...]], dict[str, Any]] = {}
        for entry in _ENTRIES:  # dict order == ascending attacker prerequisite
            for path, impact in _enumerate_paths(edges, entry):
                key = (impact, tuple(step["index"] for step in path))
                if key in best_by_path:
                    continue
                score, confidence, status = _score_path(path, impact)
                best_by_path[key] = {
                    "entry": entry, "path": path, "score": score,
                    "confidence": confidence, "status": status, "impact": impact,
                }
        candidates = list(best_by_path.values())

        # Keep the best few paths per impact so the report shows distinct attacks, not
        # twelve permutations of the same one.
        by_impact: dict[str, list[dict[str, Any]]] = {}
        for candidate in sorted(candidates, key=lambda row: (row["score"], -len(row["path"])), reverse=True):
            bucket = by_impact.setdefault(candidate["impact"], [])
            if len(bucket) < _MAX_PATHS_PER_IMPACT:
                bucket.append(candidate)
        selected = sorted(
            (c for bucket in by_impact.values() for c in bucket),
            key=lambda row: (row["status"] == "proven", row["score"]), reverse=True,
        )[:_MAX_CHAINS]

        chains: list[dict[str, Any]] = []
        # Track the signal OBJECTS a chain used, by identity. Collecting kinds and then
        # re-filtering the full signal list by kind reported every same-kind sibling as
        # "consumed" — on a multi-host span that meant listing a cookie gap from a host no
        # chain touched, which is exactly the noise the consumed-only filter exists to remove.
        used_signal_ids: set[int] = set()
        for position, candidate in enumerate(selected, 1):
            steps: list[dict[str, Any]] = []
            refs: list[str] = []
            for number, step in enumerate(candidate["path"], 1):
                technique = step["technique"]
                clue = step["clue"]
                signal = step["signal"]
                if clue:
                    refs.append(clue["ref"])
                if signal:
                    used_signal_ids.add(id(signal))
                steps.append({
                    "n": number,
                    "technique_id": technique["id"],
                    "title": technique["title"],
                    "requires": [_CAPABILITY_LABELS.get(cap, cap) for cap in technique["requires"]],
                    "grants": [_CAPABILITY_LABELS.get(cap, cap) for cap in technique["grants"]],
                    "evidence_ref": clue["ref"] if clue else "",
                    "evidence_title": clue["title"] if clue else "",
                    "signal": str(signal.get("kind")) if signal else "",
                    "signal_why": _text(signal.get("why"), 300) if signal else "",
                    "proven": bool(step["proven"]),
                    "state": "proven" if step["proven"] else "projected",
                    "next_action": technique.get("action", ""),
                    "note": technique.get("note", ""),
                })
            impact_weight, impact_label = _IMPACTS.get(candidate["impact"], (0, candidate["impact"]))
            unproven = [step for step in steps if not step["proven"]]
            chains.append({
                "id": f"AC{position}",
                "title": f"{_ENTRIES[candidate['entry']].capitalize()} → {impact_label.lower()}",
                "entry": candidate["entry"],
                "entry_label": _ENTRIES[candidate["entry"]],
                "impact": candidate["impact"],
                "impact_label": impact_label,
                "impact_weight": impact_weight,
                "status": candidate["status"],
                "confidence_score": candidate["confidence"],
                "priority_score": candidate["score"],
                "step_count": len(steps),
                "proven_steps": sum(1 for step in steps if step["proven"]),
                "refs": list(dict.fromkeys(refs)),
                "steps": steps,
                "narrative": _narrate(candidate["entry"], candidate["path"]),
                # The single most useful line: what to do next to close the chain.
                "next_action": (unproven[0]["next_action"] if unproven
                                else "Every step is backed by a captured artifact — package the chain as one report."),
                "blocking_step": unproven[0]["n"] if unproven else 0,
            })

        # Only the signals a chain actually consumed are worth surfacing; the rest stay noise.
        consumed = [s for s in all_signals if id(s) in used_signal_ids]
        return {
            "algorithm": ALGORITHM_VERSION,
            "chains": chains,
            "signals_used": consumed,
            "signals_collected": len(all_signals),
            "metrics": {
                "chains": len(chains),
                "proven_chains": sum(1 for chain in chains if chain["status"] == "proven"),
                "partial_chains": sum(1 for chain in chains if chain["status"] == "partial"),
                "max_impact": chains[0]["impact_label"] if chains else "",
                "signals_consumed": len(consumed),
            },
        }
    except Exception:  # noqa: BLE001 - the chain layer is advisory; a hunt must still report
        return {"algorithm": ALGORITHM_VERSION, "chains": [], "signals_used": [],
                "signals_collected": 0, "metrics": {"chains": 0, "proven_chains": 0,
                                                    "partial_chains": 0, "max_impact": "",
                                                    "signals_consumed": 0}}


def escalation_notes_by_ref(chain_result: dict[str, Any] | None) -> dict[str, list[str]]:
    """Per-finding escalation notes: 'this finding is step N of chain AC1'.

    This is how a demoted signal gets back into the report — attached to the finding it
    escalates, instead of sitting in the findings list as its own Low.
    """
    notes: dict[str, list[str]] = {}
    result = chain_result if isinstance(chain_result, dict) else {}
    for chain in result.get("chains") or []:
        if not isinstance(chain, dict):
            continue
        for step in chain.get("steps") or []:
            if not isinstance(step, dict):
                continue
            ref = _text(step.get("evidence_ref"), 40)
            if not ref:
                continue
            line = (f"Step {step.get('n')} of chain {chain.get('id')} "
                    f"({chain.get('title')}, {chain.get('status')}): {step.get('title')}.")
            notes.setdefault(ref, []).append(line)
    return notes
