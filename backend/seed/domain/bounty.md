# Bug bounty — operator playbook

**Authorized testing only.** Everything here assumes a program you are enrolled in,
inside its published scope: named hosts, allowed paths and asset types, allowed test
accounts, allowed methods, automation and rate limits, and its OOB/collaborator rules.
Re-cut from `seed/greyiq_bug_bounty_knowledge.txt` so the offline chat brain and the
training corpus say the same thing.

## The operator loop
<!-- triggers: operator loop, where do i start, bug bounty process, methodology -->
Bug bounty work is authorized testing only. Treat every automated result as a lead until
a clean proof artifact exists, and separate confirmed evidence from likely hypotheses
from the next safe check.

1. Read the scope and exclusions first. Record allowed hosts, paths, asset types, test accounts, automation limits, rate limits, OOB/collaborator rules, and report eligibility.
2. Map the surface before testing deeply: routes, forms, query params, JSON fields, JS bundle endpoints, API docs, mobile endpoints, auth flows, redirects, upload/import/render features, webhooks, GraphQL, and cloud storage references.
3. Prioritize high-value classes: broken access control, auth/session flaws, injection/RCE/SSTI/SQLi/NoSQLi, SSRF, exposed live secrets, cloud exposure, request smuggling, and business logic. Low-value hardening is useful only if it chains to real impact.
4. Prove one root cause at a time. Capture the exact request, the exact response, the role/account used, the negative control, and the before/after state.
5. Write one report per root cause. Lead with impact, show the smallest reproduction, redact secrets, name the affected asset, include a concrete fix, and state limitations.

## Proof of impact standard
<!-- triggers: proof of impact, negative control, observed vs control, is this confirmed -->
A bounty finding is strongest when it has an observed-vs-control artifact.

- **Observed result** means the unauthorized read, write, redirect, code-execution marker, file read, cross-origin read, forged-token acceptance, or state change actually happened.
- **Control result** means the same request with the expected role, object, input, origin, or invalid credential did NOT produce the effect.
- If either side is missing, call it a **candidate** and name the exact artifact to capture next. GreyIQ's own prover uses the same rule: no differential, no confirmation.

## Triage order
<!-- triggers: triage, severity, how bad is, priority order -->
Severity is decided by impact, not by how exotic the bug is.

- **Critical/high first**: RCE, command injection, SSTI to RCE, SQLi with data access, auth bypass, account takeover, cross-tenant access, live production secrets, cloud metadata credential reach, writable public storage, request smuggling with hijack/poisoning.
- **Medium often needs a chain**: reflected XSS without account impact, CORS without credentialed sensitive data, open redirect outside auth, missing headers, weak CSP, information disclosure without sensitive data.
- **Low/info is usually hardening** unless it unlocks a chain: headers, version disclosure, verbose errors, weak cookie posture without an exploitable flow.

## Access control and IDOR
<!-- triggers: idor, access control, bola, two accounts, cross-tenant -->
Find object identifiers in URLs, JSON bodies, GraphQL variables, file paths, invoice/order/user/team IDs, UUIDs, slugs, and exports.

- Use two accounts when the program allows it. First prove Account A can access its own object.
- Then replay as Account B with only the object id changed. A strong report shows Account B receives Account A's data or performs Account A's action.
- Include both account roles, both request/response pairs, the exact changed identifier, and the data class exposed.
- If only status codes differ without a data or action impact, keep hunting — that is a candidate, not a finding.

## BFLA and admin function access
<!-- triggers: bfla, admin function, function level authorization, privilege escalation -->
Function-level authorization is a different bug from object-level (IDOR).

- Map privileged actions: admin user update, invite, role change, billing, export, impersonation, audit logs, feature flags, internal tools.
- Replay the privileged request with a normal user token. Try method confusion only within scope.
- A strong proof shows the normal user performed or reached a function reserved for a higher role.

## Authentication and session
<!-- triggers: auth flaw, session, password reset, oauth, account takeover, mfa -->
Cookie flags alone are rarely enough without impact — look for a server-side effect.

- Prioritize password reset, OAuth/OIDC, SSO, magic links, invite acceptance, email change, MFA setup, logout, refresh tokens, remember-me tokens, and session fixation.
- Proof needs a server-side effect: token reuse, a reset link accepted twice, login as another account, a session still valid after logout, MFA bypass, or OAuth token/code leakage.

## Secrets and credential exposure
<!-- triggers: leaked secret, api key, credential exposure, blast radius -->
A revoked or test key is usually not reportable unless the program accepts historical exposure.

- Classify the secret by provider and key type.
- Validate liveness with ONE benign read-only request to the credential issuer, only when the program allows it.
- Redact the value in the report. Determine production vs staging, scopes, project/account, authorized domains, and blast radius.
- Check git history for the same secret if you have source access.

## Report checklist
<!-- triggers: write the report, bounty report, report template, report checklist, how to report, submission -->
One report per root cause, impact first.

- **Title**: bug class + endpoint/parameter/root cause.
- **Summary**: one or two sentences, impact first.
- **Scope**: target, program, account roles, and authorization notes.
- **Reproduction**: exact numbered steps, request method/path/headers/body, and only the minimum payload.
- **Proof**: observed result, control result, evidence excerpt or screenshot, and limitations.
- **Impact**: data/action affected, attacker capability, affected users/tenants, business risk, and why it is eligible.
- **Remediation**: server-side authorization, parameterization, allow-listing, secret rotation, token invalidation, storage policy, or workflow-invariant enforcement.
- **Attachments**: raw HTTP, screenshot, redacted issuer response, collaborator token, or PoC HTML only when needed.

## What should I do next
<!-- triggers: what next, what should i do next, stuck, next step -->
The answer depends only on which artifact you are missing.

- If scope is unclear: confirm scope and exclusions first.
- If there is no target surface yet: map routes, forms, params, JS bundles, API docs, and auth flows first.
- If there are candidate findings: confirm the highest-impact one with observed-vs-control proof.
- If there is a confirmed finding: package one root-cause report with exact repro, proof, impact, and fix.
