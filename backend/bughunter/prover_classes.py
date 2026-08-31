"""The vuln-class vocabulary the deterministic prover can actually CONFIRM — one source of truth.

Every check in ``active_verify_service.verify_active``'s ``checks`` list is tagged with the normalized
class it proves, and that tag is the ONLY currency the planning layer has: a per-endpoint class
ranking is fed to ``_apply_class_priority``, which reorders (never adds/removes) those checks so the
shared request budget is spent where a real bug is most likely. A class the planner can name but the
prover cannot confirm is wasted budget; a class the prover CAN confirm but the planner cannot name is
invisible recall — the hunt never steers toward it at all.

WHY THIS MODULE EXISTS: that vocabulary was hardcoded in three places that drifted apart. The prover
grew jwt / graphql / debug / websocket / sensitive / cloud-exposure / csrf / clickjacking checks, but
``hunt_brain.ACTIVE_CLASSES`` still listed 10 canonical names, an inline gate inside
``hunt_brain._validate_plan`` re-listed a fourth subset by hand, and ``offline_hunt._ACTIVE_CLASSES``
listed 10 again. The result was a silent recall hole in the path the operator runs MOST — the offline,
no-LLM hunt — because the offline planner could not even propose the eight newer classes, and any
brain that did propose them had its suggestion dropped by the gate. Three hand-synced lists is a
latent drift bug by construction, so the fix is to name the set once, here, and let
``backend/test_active_verify_service.py`` mechanically re-derive the prover's real tags with ``ast``
and fail the suite the moment a new check introduces a tag this set doesn't carry.

SAFETY: widening the vocabulary cannot damage precision. These names only ever REORDER existing,
already-gated checks — ``_apply_class_priority`` is pure reorder, the prover self-gates scope and SSRF
on every request, and a finding is still promoted to 'confirmed' only by an observed-vs-control
differential the check captures itself. A wider vocabulary raises recall and can, at worst, spend a
little budget on a class that doesn't confirm on this target.

Stdlib-only and dependency-free ON PURPOSE: ``active_verify_service`` is heavy (it pulls the HTTP
stack, the impact model, and the redaction layer), and ``hunt_brain``/``offline_hunt`` must stay
importable without it. Both sides import THIS module instead, so there is no cycle and no cost.
"""

from __future__ import annotations

# The canonical class tags carried by the prover's ``checks`` list. Kept as a frozenset because it is
# consulted as a membership test on every planner suggestion and must never be mutated at runtime.
# ORDER IS NOT MEANINGFUL here — the prover owns check order; this set only answers "can we prove it?".
PROVER_CLASSES: frozenset[str] = frozenset({
    "clickjacking",     # _check_clickjacking          — framing headers on the landing response
    "csrf",             # _check_csrf                  — unprotected state-changing form
    "jwt",              # _check_jwt_alg_none / _alg_confusion / _weak_secret
    "graphql",          # _check_graphql_introspection / _field_suggestions
    "cors",             # _check_cors                  — cross-origin credentialed read
    "redirect",         # _check_open_redirect
    "host-header",      # _check_host_header
    "xss",              # _check_reflected_xss / _reflected_xss_context
    "ssti",             # _check_ssti                  — benign arithmetic echo
    "rce",              # _check_rce_command_injection / _check_time_rce (opt-in)
    "sqli",             # _check_error_sqli / _bool_sqli / _check_time_sqli (opt-in)
    "nosqli",           # _check_nosqli
    "crlf",             # _check_crlf
    "cloud-exposure",   # _check_open_bucket           — scope-gated, GET-only
    "sensitive",        # _check_sensitive_paths       — .git/.env at the site root
    "debug",            # _check_debug_endpoints       — actuator/jolokia heapdump/env
    "websocket",        # _check_cswsh                 — one benign RFC-6455 handshake
    "path-traversal",   # _check_path_traversal
})

# Spelling variants a brain (or an operator typing a class into a hunt config) may emit, folded onto
# the canonical tag BEFORE the allowlist test. This is a convenience layer only: an alias can never
# introduce a class the prover cannot confirm, because every VALUE here is a member of
# PROVER_CLASSES. Keys are written already-normalized (lowercase, dashes) — the callers that use this
# table lowercase and fold whitespace/underscores to dashes first, so "OS Command_Injection" and
# "os-command-injection" both land on the same key.
CLASS_ALIASES: dict[str, str] = {
    "open-redirect": "redirect",
    "command-injection": "rce",
    "os-command-injection": "rce",
    "lfi": "path-traversal",
    "local-file-inclusion": "path-traversal",
    "directory-traversal": "path-traversal",
    "file-inclusion": "path-traversal",
    "sql-injection": "sqli",
    "no-sqli": "nosqli",
    "nosql-injection": "nosqli",
    "template-injection": "ssti",
    "cswsh": "websocket",       # the CSWSH check's own literature name
    "ssjs": "nosqli",           # server-side JS injection lands on the NoSQL operator probe
}
