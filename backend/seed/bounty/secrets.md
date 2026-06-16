# Playbook: Secrets & credential exposure

**Authorized testing only.** Confirming a secret is live means testing it
against its own service — do that only when it's in scope.

## What the automated pass covers
- Hardcoded API keys, tokens, and private keys in source (static)
- Secrets leaked in served HTML/JS and source maps (passive web)

## How to triage a candidate secret
1. **Classify** it (provider, key type) from its prefix/format.
2. **Validate** it is live with a single low-impact, read-only call to the
   matching service — in scope only. A revoked/test key is not reportable.
3. **Scope the blast radius** — what does it access? Production or staging?
4. If you have source access, **check git history** — the secret often lives in
   old commits even after being removed from HEAD.

## Writing the report
Redact the secret in the body (show the prefix + length), state where it was
found (URL or file:line, and commit if applicable), what it grants, and proof it
is live without dumping sensitive data. Recommend immediate rotation + moving the
secret to a secrets manager and adding a pre-commit/secret-scan gate.
