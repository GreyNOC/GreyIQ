# Playbook: Cloud storage, debug endpoints & sensitive-file exposure

**Authorized testing only.** Every check below is a single read-only GET
against an in-scope host — confirm a finding, then stop; never write, delete,
or enumerate beyond what's needed to prove exposure.

## What the automated pass covers
- Exposed cloud storage (S3/GCS/Azure buckets and Firebase projects) referenced in HTML/JS/configs
- `.git`/`.env`/backup/config files served at the site root (gated against a non-existent-path control, so an app that 200s everything can't false-positive)
- Debug/management endpoints (actuator, jolokia, heapdump, env) that leak config, secrets, or a remote-code path
- Missing `X-Frame-Options`/`frame-ancestors` (clickjacking candidate)

## High-value classes to hunt by hand
- **Cloud storage exposure** — find referenced buckets/blobs in page source, JS bundles, and configs; test public list/read/write. Where an SSRF exists, check reach to the cloud metadata endpoint (`169.254.169.254`) for credentials — in scope only.
- **Sensitive file exposure** — beyond `.git`/`.env`: `.git` directory listing (clone the whole history via `git-dumper`-style fetches, in scope only), `.DS_Store`/`.svn`, IDE/editor swap files, and backup extensions (`.bak`, `.old`, `.sql`) next to real source paths.
- **Debug/management endpoints** — actuator/jolokia-style endpoints can leak env vars and secrets (disclosure) or expose a JMX/`env`-write path to remote code (rce) depending on what's reachable; classify by what you can actually demonstrate, not the endpoint's name alone.
- **Clickjacking** — a missing frame-ancestors/X-Frame-Options header is only a candidate; it becomes reportable once you build a minimal framing page and show a real sensitive action (not just page content) is clickable through the overlay.

## Bounty triage notes
- Redact everything except the minimum needed to prove exposure — a `.env` or cloud-credential capture should show shape/prefix, never the full secret, in the report body.
- If a bucket is writable, prove it with a benign, clearly-marked object and remove it after — never overwrite or delete existing content.
- A `.git` exposure is often worth more than the files at HEAD: check history for secrets already rotated out of the current tree.
- Clickjacking is the lowest-severity class here; only worth a full report when it reaches a genuinely sensitive action (funds transfer, credential change, account takeover) rather than a cosmetic page.

## Writing the report
State exactly what was fetched (path, status, the smallest excerpt that proves
the signature) and what a non-existent control path returned for comparison.
For a bucket or debug endpoint, name the concrete data class exposed and its
production/staging blast radius, not just "misconfigured."
