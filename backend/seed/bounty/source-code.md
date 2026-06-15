# Playbook: Source-code audit

**Authorized testing only** — review code you own or are authorized to assess.
The static scanner flags candidate sinks; you confirm reachability from
untrusted input.

## What the automated pass covers
- Command injection and `eval`/`exec` on dynamic input
- Hardcoded secrets / credentials
- Weak cryptography
- Vulnerable / risky dependencies
- Risky CI/CD workflows
- Backdoor / suspicious-network patterns

## How to confirm a finding
1. Identify the **source** of data reaching the flagged sink: HTTP request,
   environment, CLI arg, file contents, deserialized object.
2. Trace the path — is there sanitization, parameterization, or an allow-list
   between source and sink? If not, it's likely real.
3. Build the smallest input that proves control (a benign marker first).

## Classes to prioritize
- **RCE / injection** (CWE-78/94) — shell, eval, template, deserialization sinks.
- **SQLi** (CWE-89) — string-built queries; prefer parameterized queries as the fix.
- **Secrets** (CWE-798) — confirm live, check git history, rotate.
- **SSRF** (CWE-918) — server-side fetchers taking attacker URLs.

## Writing the report
Cite file:line, show the tainted data flow (source → sink), give a PoC input,
state impact, and recommend the concrete fix (parameterize, sanitize, drop the
dangerous API, move the secret to a vault).
