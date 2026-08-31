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
* An observation is bound to WHERE it was made. A signal carries the host it was seen on,
  and it may only escalate a chain whose findings sit inside the same registrable domain.
  Without that, a campaign — which pools every target's signals into one graph — composed
  one company's cookie flag gap into another company's account takeover, and the rendered
  step named no host, so the report read as though both facts came from the same site.
* An observation is bound to WHICH finding it describes, by the finding's CONTENT and not
  by its display ref. Refs are renumbered when a campaign pools findings (F1 -> C7), so a
  ref-keyed signal silently stopped matching the finding it belonged to the moment it
  crossed a hunt boundary — deleting every credential chain a span existed to build.

Pure stdlib, deterministic, bounded, and total (never raises) — it runs at report time
on a finished hunt, so an exception here would discard completed work.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from bughunter import investigator
from bughunter.registrable_domain import registrable_domain

ALGORITHM_VERSION = "attack-chain-v2"

# Bounds — this runs inside a hunt, so every dimension is capped.
_MAX_CHAINS = 12
_MAX_DEPTH = 6
_MAX_CLUES = 400
_MAX_EXPANSIONS = 20000
_MAX_PATHS_PER_IMPACT = 2
# Signal-only paths cite no finding, so the cortex routes them to the probe queue rather
# than the report. They get their OWN budget: sharing the per-impact bucket meant a lead
# nobody can report evicted a chain built on captured evidence, and conversely a hunt with
# two anchored chains lost the mass-assignment probe the planner consumes.
_MAX_PROBE_PATHS_PER_IMPACT = 1
# A ref-carrying signal describes ONE finding, so one edge per distinct finding is needed
# — but the count is otherwise unbounded (a hunt can produce dozens of secrets findings),
# and edges multiply the DFS. Host-wide signals all share the empty key and collapse to one.
_MAX_SIGNAL_EDGES_PER_KIND = 4
# Recon-derived families are re-derivable and enormous (four rows per crawled URL); they
# must never be able to consume the whole clue budget ahead of evidence-bearing families.
_MAX_RECON_SIGNALS_PER_KIND = 8

# Mirrors investigator's unproven ceiling: a projected chain must stay a lead.
_PROJECTED_CEILING = 54

# Selection must rank by proof band FIRST, everywhere. The per-impact bucket used to rank
# on score alone and the final sort on (proven, score), so the bucket threw a fully proven
# chain away before the proven-first sort could ever see it.
_STATUS_RANK = {"proven": 2, "partial": 1, "projected": 0}

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
# `requires_proven` (optional) refuses the row unless the confirm gate accepted the clue's
#   evidence. Normal rows fire on an unproven clue and produce a PROJECTED step, which is the
#   engine's way of saying "this is the hypothesis to prove". That is wrong when the finding is
#   itself a NEGATIVE observation: a bucket that answered 403/AccessDenied is evidence it does
#   NOT read anonymously, so narrating it as "reads anonymously (projected)" contradicts what was
#   seen rather than proposing a next step.
# `clue_category` (optional, class clues only) narrows a row to findings whose scanner
#   CATEGORY matches, and simultaneously EXCLUDES those findings from the unnarrowed row
#   for the same class. It exists because the reporting layer deliberately folds some
#   categories into a broader class — a deserialization sink is reported AS rce, with
#   rce's CWE and platform weakness mapping — which is right for the report and wrong for
#   the chain ladder, where the step text should name what was actually found.
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
        # The strongest cloud evidence the engine can capture — an anonymously listable
        # bucket, an open Firebase store — contributed NOTHING to any chain, because the
        # `cloud-exposure` class hint that makes the finding legible in the report also took
        # it out of the `disclosure` bucket that fed the identifier ladder.
        "id": "public-cloud-store-anonymous-read",
        "title": "A cloud bucket or data store reads anonymously",
        "requires": (),
        "clue": ("class", "cloud-exposure"),
        # The bucket check stamps this class on all three of its outcomes, including
        # "referenced but denied anonymous listing (403)" and "referenced, not probed". Those are
        # observations that the store is NOT open, so they must not instantiate this step at all.
        "requires_proven": True,
        "grants": ("disclose.identifier", "disclose.sensitive-data"),
        "weight": 7,
        "action": "Capture the anonymous listing plus one non-sensitive object read, with a locked-bucket/authenticated 403 control; never download third-party data.",
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
        "id": "graphql-schema-disclosure",
        "title": "GraphQL reveals its schema (operations, types, hidden fields)",
        "requires": (),
        "clue": ("class", "graphql"),
        "grants": ("disclose.identifier",),
        "weight": 6,
        "action": "Replay the same query across two test roles and capture object- and field-level response differences.",
        "note": "Introspection and field suggestions disclose the schema; they are a lead for BOLA/BFLA, not an observation that any boundary was crossed.",
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
    # NOTE: there is no `oob-confirms-blind` row. A captured out-of-band callback models
    # PROOF STRENGTH, not a new attacker capability, and this engine has no corroboration
    # concept — so the row granted a capability (`egress.oob`) that no technique required
    # and no impact listed, which meant `_prune_path` dropped the step from every witness it
    # appeared in. It was unreachable output that still cost an edge. The callback already
    # earns its keep through the confirm gate, which marks the SSRF/XXE step `proven`.
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
        # The reporting layer folds category `deserialization` into class `rce` (that is the
        # right call for the platform weakness mapping and a unit test pins it), so this row
        # could never match on a `deserialization` class id — the chain simply narrated a
        # deserialization sink as "input reaches a command interpreter". Match the reported
        # class and discriminate on the category the scanner actually recorded.
        "clue": ("class", "rce"),
        "clue_category": "deserialization",
        "grants": ("exec.server-code",),
        "weight": 9,
        "action": "Use a benign, non-destructive gadget that only proves evaluation, and capture a control payload that is rejected.",
    },
    {
        "id": "upload-to-execution",
        "title": "Uploaded file is served from an executable path",
        "requires": (),
        "clue": ("signal", "sink.upload-executed"),
        "grants": ("exec.server-code",),
        "weight": 8,
        "action": "Upload an inert marker file, capture it being executed/served, and remove it; never upload a working shell.",
        "note": "An accepted upload is not execution; only the uploaded file being EXECUTED by the server is.",
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
    "sink.upload-executed": "an uploaded file was observed being executed by the server",
    "transport.mixed-content": "an HTTPS page loads a plaintext subresource",
    "transport.plaintext-endpoint": "an in-scope endpoint is reachable over plaintext HTTP",
    "token.role-claim": "the token carries a role/privilege claim",
}

# --------------------------------------------------------------------------------------
# Signal extraction
# --------------------------------------------------------------------------------------
_SESSION_COOKIE_RE = re.compile(
    r"(sess|sid\b|auth|jwt|login|remember|identity|account)"
    # Anchored bearer-token cookie names. These ARE the session on a standard SPA, and the
    # old exclusion below rejected every one of them, so the engine's flagship chain
    # (confirmed XSS + missing HttpOnly -> account takeover) never fired on those targets.
    # Anchored, never a bare `token` substring: `consent_token`/`recaptcha_token` are not
    # the session, and asserting they are is how a fabricated takeover gets manufactured.
    r"|^(access|id|refresh|bearer)[_\-]?token$|^token$",
    re.IGNORECASE,
)
# Cookies that LOOK session-ish but are not the session, and whose flag "gaps" are by design.
# A double-submit CSRF token cookie MUST be readable by JavaScript — that is the entire
# pattern — so treating a missing HttpOnly on it as a token-theft step fabricated an
# account-takeover chain out of a correct implementation. Checked before the match above.
#
# Scoped to anti-forgery names only. The previous bare `_token\b` alternative also swallowed
# `auth_token`, `session_token`, `remember_token` (Devise's literal remember-me cookie) and
# `id_token`, so on those targets the engine produced no chain at all — the opposite failure,
# and just as silent.
_NOT_SESSION_COOKIE_RE = re.compile(
    r"(?:^|[_\-.])(csrf|xsrf|antiforgery)"
    r"|(?:csrf|xsrf|anti[_\-]?forgery|request[_\-]?verification|authenticity)[_\-]?token",
    re.IGNORECASE,
)


def is_session_cookie_name(name: Any) -> bool:
    """True when ``name`` is a session-bearing cookie whose flag gaps are worth a signal.

    Exported because the chain engine has TWO producers of the ``cookie.session-*`` family:
    the raw ``Set-Cookie`` parser here and the response digest, which builds its own auth-cookie
    list on a deliberately wider pattern (it feeds a reasoning prompt, where a CSRF cookie is
    useful context). The digest path did not re-apply this gate, so the exact cookie the raw
    path is documented and tested to reject arrived through the second door and fabricated the
    takeover chain anyway. One gate, both doors.
    """
    label = _text(name, 120)
    if not label or _NOT_SESSION_COOKIE_RE.search(label):
        return False
    return bool(_SESSION_COOKIE_RE.search(label))
_ROLE_FIELD_RE = re.compile(
    r"^(is_?admin|admin|role|roles|is_?staff|is_?superuser|permission|permissions|scope|scopes"
    r"|privilege|privileges|is_?verified|account_?type|user_?type|group|groups|tier|plan)$",
    re.IGNORECASE,
)
_TOKEN_FIELD_RE = re.compile(
    r"(access_?token|id_?token|refresh_?token|session|api_?key|secret|bearer|jwt)", re.IGNORECASE
)
# NOTE: there is no path-name regex for `endpoint.state-changing` any more. It was an
# unanchored alternation run over the WHOLE endpoint URL, so `set` matched inside `/assets/`,
# `add` inside `/address`, and `edit` inside `/credit` — meaning essentially every target
# emitted the signal, and it is the sole enabling clue for the step that promotes
# "read another tenant's data" to "MODIFY another tenant's data". Anchoring it on path
# segments does not fix the category error: `/news/change-log` and `/pricing/add-ons` are
# read-only pages whose names still match. A path NAME is not an observation of a write.
# `_surface_forms` — an actually observed POST/PUT/PATCH/DELETE method — is now the only
# producer of this signal kind, which is the same reasoning that deleted `token.role-claim`
# and `sink.admin-rendered` below.
_CLOUD_HOST_RE = re.compile(
    r"(amazonaws\.com|azurewebsites\.net|cloudapp\.azure\.com|googleusercontent\.com"
    r"|appspot\.com|herokuapp\.com|cloudfront\.net|run\.app|azure\.com|gcp\.)",
    re.IGNORECASE,
)
_CLOUD_CRED_RE = re.compile(r"(aws|amazon|azure|gcp|google[_-]?cloud|s3|iam|sigv4)", re.IGNORECASE)
_PRIVILEGED_SCOPE_RE = re.compile(r"(admin|write|full|owner|root|\*|superuser)", re.IGNORECASE)
# Segment-anchored and applied to the PATH only. Unanchored over the whole URL, `reset`
# matched `/static/css/reset.css` and `sso` matched any host containing those letters, so a
# stylesheet was enough to carry an unproven open-redirect lead all the way to an
# account-takeover chain. The boundaries also keep `/order/confirmation` and
# `/team/invited-speakers` out, which a bare word-boundary would not.
_AUTH_FLOW_RE = re.compile(
    r"(?:^|[/_.\-])(login|logout|signin|sign-in|oauth|sso|saml|callback|authorize"
    r"|reset|invite|verify|confirm)(?:$|[/_.\-])",
    re.IGNORECASE,
)
# A static asset is never an authentication endpoint: a stylesheet named `reset.css` is not a
# password-reset flow, and a script bundle carries every route name in the application, so a
# match inside one describes the bundle's contents rather than this endpoint's role. Recon
# already drops most of these before they reach the surface, so this is defence in depth for
# callers that build a surface some other way.
_STATIC_ASSET_RE = re.compile(
    r"\.(?:js|mjs|cjs|json|map|css|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot)$",
    re.IGNORECASE,
)


def _text(value: Any, limit: int = 400) -> str:
    return str(value or "").strip()[:limit]


def _absolute_host(value: Any) -> str:
    """The host of an ABSOLUTE http(s) URL, or "" for anything else.

    Deliberately strict, and deliberately not ``_host_of``. Most signal subjects are not URLs
    at all — a field name (``is_admin``), a scope string (``admin,write``), a fingerprinted
    tech name, a relative form action (``/update``) — and a lenient parser happily reports
    ``is_admin`` and ``admin,write`` as hostnames, which then both fabricate cross-host
    penalties and delete valid same-host chains.
    """
    subject = _text(value, 400)
    try:
        parsed = urlparse(subject)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    return (parsed.hostname or "").lower()


def finding_key(finding: dict[str, Any]) -> str:
    """A stable identity for a finding, derived from its CONTENT rather than its display ref.

    Display refs are renumbered every time findings are pooled — a hunt's ``F1`` becomes a
    campaign's ``C7`` and then a span's ``C31`` — while the signals derived from that hunt kept
    the ``F1`` they were stamped with. ``_signal_provenance_ok`` then found no clue with that
    ref and discarded every witness using the signal, so the four finding-scoped signal kinds
    (a credential being a cloud key, a captured callback) were silently dead in exactly the
    cross-target graph a campaign exists to build. Keying on content survives every re-key,
    and it cannot be remapped wrongly across hops the way a ref chain can.

    Mirrors ``ledger.dedup_key``'s components deliberately (class + rule + digit-normalized
    location) but is computed locally: this module stays pure and importing the ledger store
    for one hash would couple the chain layer to persistence.
    """
    location = _text(finding.get("location") or finding.get("file_path"), 400)
    normalized = re.sub(r"\d+", "N", location).lower()
    raw = f"{investigator.normalize_class(finding)}|{_text(finding.get('rule_id'), 120)}|{normalized}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:20]


def _signal(kind: str, subject: str, why: str, *, source: str = "", ref: str = "",
            host: str = "", fkey: str = "") -> dict[str, Any]:
    return {
        "kind": kind,
        "subject": _text(subject, 300),
        "why": _text(why, 300),
        "source": _text(source, 60),
        "ref": _text(ref, 40),
        # WHERE the observation was made. A cookie flag gap belongs to the host that set the
        # cookie; composing it into an attack on a different company's host — which is exactly
        # what a pooled campaign graph did — asserts a step that is physically impossible
        # there. Falls back to the subject when the caller does not name a host, because for
        # the URL-subject families the subject IS the observation site.
        "host": _text(host, 200).lower() or _absolute_host(subject),
        # WHICH finding the observation describes, ref-independently. Empty for host-wide
        # observations, which describe the site rather than any one finding.
        "finding_key": _text(fkey, 40),
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
        if not is_session_cookie_name(name):
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
                # Carried-in signals keep their own provenance. `host` and `finding_key` are
                # what let a pooled campaign signal still say WHERE it was seen and WHICH
                # finding it belongs to after that finding has been renumbered.
                out.append(_signal(str(item.get("kind")), item.get("subject") or "",
                                   item.get("why") or "", source=item.get("source") or "",
                                   ref=item.get("ref") or "", host=item.get("host") or "",
                                   fkey=item.get("finding_key") or ""))

    digest = response_digest if isinstance(response_digest, dict) else {}
    # `origin` is what `digest_builder` records for exactly this purpose. Without it every
    # digest-derived signal was stamped with an empty host, which made the host binding below a
    # no-op for the entire family — the same door the cookie gate was reopened through once.
    digest_host = _absolute_host(digest.get("origin") or digest.get("final_url") or digest.get("url"))

    def _digest_cookies() -> None:
        # The digest already extracts cookie flag gaps for the brain prompt; reuse them so
        # the chain engine sees the same facts even when the raw Set-Cookie list is gone.
        #
        # The digest builds its auth-cookie list on a deliberately WIDER pattern than the raw
        # parser does — it includes csrf/xsrf, which is useful context in a reasoning prompt
        # and is exactly the cookie `cookie_signals` is documented and tested to refuse. Two
        # producers of one signal family means the gate has to be applied at BOTH doors: a
        # correct Django double-submit `csrftoken` reached the graph through this one and
        # fabricated an account-takeover chain out of a correct implementation.
        for gap in digest.get("cookie_flag_gaps") or []:
            if not isinstance(gap, dict):
                continue
            name = _text(gap.get("cookie"), 120)
            if not is_session_cookie_name(name):
                continue
            missing = gap.get("missing") if isinstance(gap.get("missing"), list) else []
            for flag in missing:
                kind = {
                    "HttpOnly": "cookie.session-no-httponly",
                    "SameSite": "cookie.session-no-samesite",
                    "Secure": "cookie.session-no-secure",
                }.get(str(flag))
                if kind:
                    out.append(_signal(kind, "", f"session cookie '{name}' is missing {flag}",
                                       source="response-digest", host=digest_host))

    def _digest_names() -> None:
        for name in [*(digest.get("interesting_names") or []), *(digest.get("form_fields") or [])][:200]:
            label = _text(name, 80)
            if _ROLE_FIELD_RE.match(label):
                out.append(_signal("field.role-like", label,
                                   f"a role-like field '{label}' is present in the request/response shape",
                                   source="response-digest", host=digest_host))
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
                                   source="response-digest", host=digest_host))
            elif _TOKEN_FIELD_RE.search(label):
                out.append(_signal("response.token-in-body", label,
                                   f"a token-like field '{label}' appears in the response body",
                                   source="response-digest", host=digest_host))
        # NOTE: no `token.role-claim` signal is derived from the digest. The digest decodes a
        # JWT's HEADER only — never the payload — so the presence of an `alg` says a JWT is in
        # use and nothing whatsoever about a role/privilege claim inside it. Emitting it here
        # let any JWT-using site escalate a chain's heading to administrative takeover on no
        # evidence at all. The signal stays in the vocabulary for a producer that can actually
        # observe a role claim; nothing fabricates it.

    surface_obj = surface if isinstance(surface, dict) else {}

    # The recon families are re-derivable and enormous — a crawl yields hundreds of URLs and
    # each can emit several rows — while `_build_graph` uses only the FIRST host-wide signal of
    # each kind. Everything past that is provably dead weight that was crowding evidence-bearing
    # signals out of the clue budget, so cap each kind at the producer.
    recon_emitted: dict[str, int] = {}

    def _recon(kind: str, subject: str, why: str) -> None:
        if recon_emitted.get(kind, 0) >= _MAX_RECON_SIGNALS_PER_KIND:
            return
        recon_emitted[kind] = recon_emitted.get(kind, 0) + 1
        out.append(_signal(kind, subject, why, source="recon"))

    def _surface_endpoints() -> None:
        endpoints = surface_obj.get("endpoints") if isinstance(surface_obj.get("endpoints"), list) else []
        for endpoint in endpoints[:200]:
            url = _text(endpoint, 400)
            try:
                path = urlparse(url).path or ""
            except ValueError:
                continue
            if url.lower().startswith("http://"):
                _recon("transport.plaintext-endpoint", url,
                       "the endpoint was observed on plaintext HTTP")
            if _AUTH_FLOW_RE.search(path) and not _STATIC_ASSET_RE.search(path):
                _recon("flow.auth-redirect", url,
                       "the endpoint path sits inside an authentication flow")
            if _CLOUD_HOST_RE.search(_absolute_host(url)):
                _recon("infra.cloud-hosted", url,
                       "the host resolves to a cloud provider surface")

    def _surface_forms() -> None:
        for form in surface_obj.get("forms") or []:
            if not isinstance(form, dict):
                continue
            # An OBSERVED state-changing method — the only honest producer of this kind.
            if _text(form.get("method"), 10).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                _recon("endpoint.state-changing", _text(form.get("action"), 300),
                       "an HTML form submits with a state-changing method")
            for field in form.get("params") or []:
                if _ROLE_FIELD_RE.match(_text(field, 80)):
                    _recon("field.role-like", _text(field, 80),
                           f"a role-like form field '{_text(field, 80)}' is submitted")

    def _surface_tech() -> None:
        for tech in surface_obj.get("tech") or []:
            if _CLOUD_HOST_RE.search(_text(tech, 120)):
                _recon("infra.cloud-hosted", _text(tech, 120), "a cloud platform was fingerprinted")

    def _finding_signals() -> None:
        for finding in findings or []:
            if not isinstance(finding, dict):
                continue
            ref = _text(finding.get("ref"), 40)
            # The ref is the DISPLAY name and is renumbered whenever findings are pooled; the
            # key is the identity that survives that. Both travel: the ref keeps the report's
            # cross-references readable, the key is what provenance is actually checked on.
            fkey = finding_key(finding)
            location = _text(finding.get("location") or finding.get("file_path"), 300)
            host = _absolute_host(location)
            haystack = " ".join(
                _text(finding.get(key), 300)
                for key in ("title", "rule_id", "location", "file_path", "snippet", "secret_type")
            )
            if _CLOUD_CRED_RE.search(haystack) and investigator.normalize_class(finding) == "secrets":
                out.append(_signal("credential.cloud-provider", location,
                                   "the exposed credential looks like a cloud provider key",
                                   source="finding", ref=ref, host=host, fkey=fkey))
            # ``scopes`` (plural) is the key every validator in credential_validation actually
            # writes; the singular ``scope`` and a top-level ``credential_scope`` exist nowhere
            # in the repo, so this read matched nothing and the privileged-scope step could
            # never fire on a real validated credential.
            credential = finding.get("_credential_proof") if isinstance(finding.get("_credential_proof"), dict) else {}
            scope = _text(credential.get("scopes") or credential.get("principal"), 200)
            if scope and _PRIVILEGED_SCOPE_RE.search(scope):
                out.append(_signal("credential.privileged-scope", scope,
                                   "the validated credential reports privileged scope",
                                   source="finding", ref=ref, host=host, fkey=fkey))
            proof = finding.get("_active_proof") if isinstance(finding.get("_active_proof"), dict) else {}
            if _text(proof.get("callback_id") or proof.get("interaction_id"), 200):
                out.append(_signal("proof.oob-callback", location,
                                   "an out-of-band callback was captured for this finding",
                                   source="finding", ref=ref, host=host, fkey=fkey))
            if "mixed-content" in _text(finding.get("rule_id"), 120).lower():
                # Host-wide, so no ref/key: it is a transport fact about the PAGE, not an
                # observation that escalates the mixed-content finding itself. Stamped with a
                # finding identity it was unusable — the consuming technique takes no class
                # clue, so no witness could ever cite that finding, and provenance discarded
                # every path containing the step. The whole branch was dead.
                out.append(_signal("transport.mixed-content", location,
                                   "an HTTPS page loads a plaintext subresource",
                                   source="finding", host=host))
            # An anonymously readable bucket or data store is itself the evidence that the target
            # runs on that cloud, which is what the metadata-pivot step needs. Host-wide (no
            # ref/key): it describes the infrastructure, not this one finding.
            #
            # Gated on the CONFIRM GATE and on having a real host. The bucket check emits the same
            # class for a reference it was never allowed to probe (empty url), and that produced a
            # host-less signal claiming a cloud surface was "confirmed" — which then unlocked the
            # cloud-metadata pivot on any SSRF, on no observation at all.
            if investigator.normalize_class(finding) == "cloud-exposure" and host:
                try:
                    cloud_proven = bool(investigator.has_confirming_artifact(finding, {}))
                except Exception:  # noqa: BLE001 - a gate error must never break collection
                    cloud_proven = False
                if cloud_proven:
                    out.append(_signal("infra.cloud-hosted", location,
                                       "an anonymously readable cloud store was captured on this host",
                                       source="finding", host=host))
            # NOTE: no `sink.admin-rendered` signal is derived here. Establishing that a stored
            # value renders in an ADMINISTRATIVE view requires authenticated admin access GreyIQ
            # does not have, so there is no honest way to observe it from a hunt; the previous
            # code read `stored_context`/`sink_context`, keys no producer in the repo writes.
            # The `admin-viewed-sink` technique stays in the table for a producer that can
            # genuinely observe this, and simply never fires until one exists.

    # Evidence-bearing families FIRST. The list is hard-truncated at `_MAX_CLUES` below, and
    # the recon families alone can fill it on a real crawl — so with findings last, a large
    # surface silently deleted every ref-carrying, impact-bearing signal the engine has.
    # `_finding_signals` must also precede `_extra_signals`: at span/portfolio scale the pooled
    # `extra` list on its own can exceed the cap.
    for family in (_finding_signals, _digest_cookies, _digest_names,
                   _extra_signals, _surface_endpoints, _surface_forms, _surface_tech):
        _family(family)

    # Deduplicate preserving first-seen order for determinism. `ref` and `finding_key` are part
    # of the key: two findings at the same location each get their own "this credential is a
    # cloud key" observation, and collapsing them on (kind, subject) deleted the second
    # finding's — which then had no signal edge and lost its entire chain.
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for item in out:
        key = (item["kind"], item["subject"], item["ref"], item["finding_key"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    if len(unique) <= _MAX_CLUES:
        return unique
    # Over budget: reserve half the slots for finding-derived rows rather than letting a big
    # crawl decide by arrival order which evidence survives. Re-emit in the original order so
    # the output stays byte-stable for a given input.
    derived = [item for item in unique if item["source"] == "finding"]
    rest = [item for item in unique if item["source"] != "finding"]
    keep_derived = derived[:max(_MAX_CLUES // 2, _MAX_CLUES - len(rest))]
    keep_rest = rest[:_MAX_CLUES - len(keep_derived)]
    kept = {id(item) for item in keep_derived} | {id(item) for item in keep_rest}
    return [item for item in unique if id(item) in kept]


# --------------------------------------------------------------------------------------
# Chain construction
# --------------------------------------------------------------------------------------
def _host_of(location: str) -> str:
    """The HOST a clue sits on, or "" when the location is not a URL at all.

    A code-scanner finding's location is a repository-relative FILE PATH. Splitting one on "/"
    and calling the first segment a host made ``backend/app/views.py`` and ``frontend/src/api.js``
    — the same repo, the same target, the same commit — look like two unrelated internet hosts,
    so every multi-finding chain in a code audit was charged the cross-host penalty that exists
    to say "these two may not even share a session". Non-URLs return "" and are excluded from
    the host set by the ``- {""}`` in ``_score_path``.
    """
    try:
        return (urlparse(location).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _same_trust_boundary(left: str, right: str) -> bool:
    """True when two hosts plausibly share a session and a CORS/cookie trust boundary.

    Sibling subdomains of one registrable domain DO share domain-scoped cookies — that is the
    whole premise of the subdomain-takeover technique, and the composition a campaign exists to
    surface. Scoring them like unrelated vendors evicted the one genuinely cross-target chain a
    span found.

    IP literals are compared EXACTLY. ``registrable_domain`` is a last-two-labels heuristic, so
    it maps ``1.2.3.4`` and ``9.8.3.4`` both to ``3.4``: reducing IPs through it would silently
    merge two unrelated hosts that happen to share their last two octets, trading the old
    over-penalty for a new false-merge. ``scan_auth`` guards its own registrable-domain check
    the same way.
    """
    if not left or not right:
        return False
    if left == right:
        return True
    if _is_ip(left) or _is_ip(right):
        return False
    left_site = registrable_domain(left)
    right_site = registrable_domain(right)
    return bool(left_site) and left_site == right_site


def _finding_clue(finding: dict[str, Any], plan: dict[str, Any], index: int) -> dict[str, Any]:
    """Normalize one finding into a clue with its PROVEN state taken from the confirm gate."""
    ref = _text(finding.get("ref"), 40) or f"F{index}"
    try:
        proven = bool(investigator.has_confirming_artifact(finding, plan))
    except Exception:  # noqa: BLE001 - a gate error must never break the chain build
        proven = False
    location = _text(finding.get("location") or finding.get("file_path"), 400)
    return {
        "ref": ref,
        "key": finding_key(finding),
        "class_id": investigator.normalize_class(finding),
        # The scanner category the finding was recorded under. Carried because the reporting
        # layer folds several categories into one class (deserialization -> rce), so the class
        # alone cannot tell the ladder which technique actually describes what was found.
        "category": _text(finding.get("category"), 80).lower(),
        "title": _text(finding.get("title") or finding.get("rule_id") or "Finding", 240),
        "location": location,
        "host": _host_of(location),
        "severity": _text(finding.get("severity"), 20).lower() or "info",
        "proven": proven,
    }


def _step_confidence(proven: bool) -> int:
    """A proven step is worth real confidence; an unproven evidence-backed step is a lead."""
    return 82 if proven else 34


_MAX_CLUES_PER_CLASS = 3


def _build_graph(
    clues_by_class: dict[str, list[dict[str, Any]]],
    signals_by_kind: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Instantiate every technique whose enabling clue is actually present."""
    # A category-narrowed row claims its findings exclusively: without this the generic row for
    # the same class fires on them too, so one deserialization sink produced both "untrusted
    # data is deserialized" and "input reaches a command interpreter" for the same impact.
    claimed_categories: dict[str, set[str]] = {}
    for technique in _TECHNIQUES:
        spec = technique.get("clue")
        category = technique.get("clue_category")
        if category and spec and spec[0] == "class":
            claimed_categories.setdefault(spec[1], set()).add(str(category))

    # A ref-carrying signal ("this credential is a cloud key") is only ever USABLE by a chain
    # that also contains that finding's own clue — `_signal_provenance_ok` rejects the witness
    # otherwise. So a clue a signal names must survive the per-class cap below, or the impact it
    # unlocks disappears because of how many UNRELATED findings of the same class the hunt
    # happened to produce.
    pinned_keys = {
        _text(signal.get("finding_key"), 40)
        for rows in signals_by_kind.values() for signal in rows
        if _text(signal.get("finding_key"), 40)
    }

    def _clues_for(class_id: str) -> list[dict[str, Any]]:
        rows = clues_by_class.get(class_id, [])
        if len(rows) <= _MAX_CLUES_PER_CLASS:
            return rows
        pinned = [row for row in rows if row["key"] in pinned_keys]
        others = [row for row in rows if row["key"] not in pinned_keys]
        # The cap still bounds the edge set (the DFS multiplies over it); pinning only changes
        # WHICH clues fill it, never how many.
        return (pinned + others)[:max(_MAX_CLUES_PER_CLASS, len(pinned))]

    known_keys = {clue["key"] for rows in clues_by_class.values() for clue in rows}

    edges: list[dict[str, Any]] = []
    for technique in _TECHNIQUES:
        clue_spec = technique.get("clue")
        if clue_spec is None:
            edges.append({"technique": technique, "clue": None, "signal": None, "proven": False})
            continue
        kind, key = clue_spec
        if kind == "class":
            wanted = technique.get("clue_category")
            excluded = claimed_categories.get(key, set()) if not wanted else set()
            for clue in _clues_for(key):
                if wanted and clue["category"] != str(wanted):
                    continue
                if clue["category"] in excluded:
                    continue
                if technique.get("requires_proven") and not clue["proven"]:
                    continue
                edges.append({"technique": technique, "clue": clue, "signal": None,
                              "proven": bool(clue["proven"])})
        else:
            # ONE edge per distinct FINDING the signal describes. A single edge per kind was
            # right for host-wide observations — a second instance produces a chain with
            # identical steps, title and impact, which the report printed twice — but wrong for
            # the finding-scoped kinds: with two exposed secrets, only the first finding's
            # "it's a cloud key" observation existed as an edge, so the second finding's chain
            # was rejected by provenance and vanished. Host-wide signals all carry the empty
            # key and still collapse to exactly one edge.
            rows = signals_by_kind.get(key, [])
            # Prefer a signal attached to a PROVEN clue, so the strongest chain is the one that
            # survives the per-kind bound below.
            proven_keys = {clue["key"] for rows_ in clues_by_class.values()
                           for clue in rows_ if clue["proven"]}
            rows = sorted(rows, key=lambda row: _text(row.get("finding_key"), 40) in proven_keys,
                          reverse=True)
            seen_keys: set[str] = set()
            for signal in rows:
                signal_key = _text(signal.get("finding_key"), 40)
                if signal_key and signal_key not in known_keys:
                    continue  # can never pass provenance; the edge would only burn DFS budget
                if signal_key in seen_keys:
                    continue
                seen_keys.add(signal_key)
                # A signal is an OBSERVATION, never proof. This is the invariant that keeps a
                # cookie flag from ever reading as a confirmed step.
                edges.append({"technique": technique, "clue": None, "signal": signal, "proven": False})
                if len(seen_keys) >= _MAX_SIGNAL_EDGES_PER_KIND:
                    break
    return edges


def _signal_provenance_ok(witness: list[dict[str, Any]]) -> bool:
    """Reject a chain that composes an observation with evidence it does not belong to.

    Two independent bindings, because there are two ways to invent a composition nobody saw.

    WHICH FINDING. Most signals are host-wide (a cookie flag, a form field) and describe no
    single finding. The ones that DO — "this credential is a cloud key", "this finding got an
    OOB callback" — are matched on the finding's CONTENT key, not its display ref: refs are
    renumbered whenever findings are pooled, so a ref-keyed check silently rejected every
    cross-target witness and deleted the credential chains a campaign exists to build.

    WHICH HOST. A cookie flag gap belongs to the host that set the cookie. Pooled into one
    graph — which is exactly what a portfolio run does — an unrelated program's missing
    HttpOnly composed into this program's confirmed XSS and reported an account takeover whose
    second step is physically impossible on the target (its session cookie IS HttpOnly), with
    nothing in the rendered step naming the other host. Sibling subdomains are NOT rejected:
    a domain-scoped cookie observed on ``www`` genuinely does reach a claimed ``old`` sibling,
    and that composition is the campaign's whole payoff.
    """
    keys = {step["clue"]["key"] for step in witness if step["clue"]}
    hosts = {step["clue"]["host"] for step in witness if step["clue"]} - {""}
    for step in witness:
        signal = step["signal"]
        if not signal:
            continue
        signal_key = _text(signal.get("finding_key"), 40)
        if signal_key and signal_key not in keys:
            return False
        signal_host = _text(signal.get("host"), 200)
        if signal_host and hosts and not any(
            _same_trust_boundary(signal_host, host) for host in hosts
        ):
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
    """Bounded search from ``entry`` over capability space, collecting minimal witnesses for
    every terminal impact reached. Deterministic: edges are explored in table order.

    ITERATIVE DEEPENING, not a plain DFS. A complete search of a routine 13-class hunt needs
    ~2M expansions against a 20k budget, and a depth-first walk with one shared counter spends
    the entire allowance inside the FIRST edge's subtree — instrumented, the set of root edges
    ever expanded was literally ``[0]``. Every witness whose edges sit late in the technique
    table was lost, so the output was biased by table position rather than by chain quality.
    Splitting the budget per root does NOT fix it (measured: byte-identical output), because
    the bias is recursive — each root's share is consumed by its own first child in turn.

    Deepening by length matches how the engine ranks anyway: `_score_path` prefers short
    witnesses, so exhausting depth 1 before depth 2 spends the budget on the chains most
    likely to be reported. The budget is shared across rounds, never reset, so total work stays
    bounded and the result stays deterministic.
    """
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

    def walk(held: frozenset[str], used: tuple[int, ...], path: list[dict[str, Any]],
             limit: int = _MAX_DEPTH) -> None:
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
            # Only the frontier is recorded: shallower paths were already recorded by earlier
            # rounds, and `seen` dedupes, so this just avoids redundant `_prune_path` work.
            record(new_path, grants)
            walk(held | set(grants), used + (index,), new_path, limit)

    walk(frozenset({entry}), (), [], _MAX_DEPTH)
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
    # Signal hosts count too: an observation made somewhere else is exactly as much of a hop as
    # a finding made somewhere else, and leaving them out is how a pooled cookie gap from an
    # unrelated program scored identically to a same-host one.
    hosts = {step["clue"]["host"] for step in path if step["clue"]}
    hosts |= {_text(step["signal"].get("host"), 200) for step in path if step["signal"]}
    hosts -= {""}
    # Sibling subdomains of one registrable domain share domain-scoped cookies and a CORS
    # boundary, so the "may not even share a session" premise simply does not apply to them —
    # and penalizing them evicted the one real cross-target chain a span produced.
    sites: list[str] = []
    for host in sorted(hosts):
        if not any(_same_trust_boundary(host, other) for other in sites):
            sites.append(host)
    if len(sites) > 1:
        score -= 12 * (len(sites) - 1)
        confidence = max(0, confidence - 6)
    return max(0, score), max(0, min(99, confidence)), status


def _narrate(entry: str, path: list[dict[str, Any]], impact: str) -> str:
    """One plain-English sentence a triager can read without decoding the graph.

    Names the capability the chain actually CONSUMED, not the first entry of the technique's
    grants tuple. Two techniques grant two capabilities each (XXE and SSRF both grant
    ``net.internal`` alongside a read primitive), so a chain resting on the second grant
    narrated the one it never used — and the cortex copies this sentence verbatim into the
    chain's ``why``, which is what the report prints.
    """
    parts = [f"Starting as {_ENTRIES.get(entry, entry)}"]
    for position, step in enumerate(path):
        grants = list(step["technique"]["grants"])
        following = path[position + 1]["technique"]["requires"] if position + 1 < len(path) else ()
        used = next((cap for cap in grants if cap in following or cap == impact), "")
        label = _CAPABILITY_LABELS.get(used or (grants[0] if grants else ""),
                                       used or (grants[0] if grants else ""))
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
        #
        # Three corrections live in this block, all of them things that silently threw away the
        # best chain:
        #  * The bucket key must be a SUPERSET of the final ranking key. Ranking the bucket on
        #    score alone meant a fully proven chain was discarded here, before the proven-first
        #    sort below could ever see it — the two keys had drifted apart, which is the defect.
        #  * Two candidates with the same technique sequence for the same impact are the same
        #    attack. Distinctness was keyed on edge indices, so N findings of one class produced
        #    N identical ladders that each took a slot. (Keyed per IMPACT, not globally: one
        #    technique tuple legitimately reaches two impacts — an XXE grants both a file read
        #    and internal reach — and a global dedupe would delete a real impact.)
        #  * A path citing no finding is a probe lead the cortex routes away from the report, so
        #    it gets its OWN budget instead of evicting a chain built on captured evidence.
        def _rank(row: dict[str, Any]) -> tuple[int, int, int]:
            return (_STATUS_RANK.get(row["status"], 0), row["score"], -len(row["path"]))

        by_impact: dict[str, list[dict[str, Any]]] = {}
        probes_by_impact: dict[str, list[dict[str, Any]]] = {}
        shapes: set[tuple[str, tuple[str, ...]]] = set()
        for candidate in sorted(candidates, key=_rank, reverse=True):
            shape = (candidate["impact"],
                     tuple(step["technique"]["id"] for step in candidate["path"]))
            if shape in shapes:
                continue
            shapes.add(shape)
            anchored = any(step["clue"] for step in candidate["path"])
            table = by_impact if anchored else probes_by_impact
            cap = _MAX_PATHS_PER_IMPACT if anchored else _MAX_PROBE_PATHS_PER_IMPACT
            bucket = table.setdefault(candidate["impact"], [])
            if len(bucket) < cap:
                bucket.append(candidate)
        selected = sorted(
            [c for bucket in by_impact.values() for c in bucket]
            + [c for bucket in probes_by_impact.values() for c in bucket],
            key=_rank, reverse=True,
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
                    # The raw capability ids alongside the prose. A consumer that has to REASON
                    # about what a blocked step was waiting for needs the id — matching on the
                    # human label would break the moment the label is reworded.
                    "grants_ids": list(technique["grants"]),
                    "requires_ids": list(technique["requires"]),
                    "evidence_ref": clue["ref"] if clue else "",
                    "evidence_title": clue["title"] if clue else "",
                    # WHERE the cited finding was observed. A consumer that has to decide whether a
                    # proof still holds needs the endpoint, and matching a URL against the finding's
                    # human-readable TITLE — which is what the step used to expose — never matches.
                    "evidence_location": clue["location"] if clue else "",
                    "signal": str(signal.get("kind")) if signal else "",
                    "signal_why": _text(signal.get("why"), 300) if signal else "",
                    # WHERE the observation was made. The rendered step used to carry only the
                    # kind and the prose, so a reader could not tell that a cookie flag gap had
                    # been seen on a different host from the finding it escalates — the one
                    # fact needed to catch a bad composition by reading the report.
                    "signal_host": _text(signal.get("host"), 200) if signal else "",
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
                "narrative": _narrate(candidate["entry"], candidate["path"], candidate["impact"]),
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
