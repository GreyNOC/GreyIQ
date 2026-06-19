# Playbook: Web application

**Authorized testing only.** Stay inside the program's scope (domains, paths,
accounts). All automated checks here are passive (one GET); anything active is a
manual step you perform within scope.

## What the automated pass covers
- Missing/weak security headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy)
- Insecure cookies (missing Secure / HttpOnly)
- Mixed content on HTTPS pages
- Secrets leaked in served HTML/JS
- Dangerous client-side sinks (`innerHTML`, `document.write`, `eval`, `dangerouslySetInnerHTML`)
- Software/version + error/stack + source-map disclosure

## High-value classes to hunt by hand
- **XSS** — trace reflected and stored input to each DOM sink; confirm execution (not just rendering); note any CSP that blocks it.
- **Access control / IDOR** — replay requests as a second, lower-privileged account and swap object identifiers.
- **SSRF** — any "fetch by URL" feature (webhooks, import, render) is a candidate; use a collaborator host.
- **Auth/session** — cookie flags, token entropy/expiry, session fixation, reset-token reuse, login rate-limiting.
- **CSRF** — state-changing requests lacking anti-CSRF tokens or SameSite protection.

## Bounty triage notes
- **CORS** - credentialed APIs that reflect arbitrary `Origin` values or trust attacker-controlled subdomains.
- **Open redirect** - `next`, `returnUrl`, `callback`, `continue`, and OAuth redirect parameters.
- **File upload** - extension/MIME bypass, direct object access, stored XSS, parser/previewer abuse, archive traversal.
- **Business logic** - workflow skips, replay, duplicate coupons, race-sensitive actions, quota resets, and role transitions.
- Confirm whether the issue is policy-eligible before investing in a polished report.
- Prefer one root cause per report; mention related hardening findings as supporting evidence.
- Capture account roles, exact request/response pairs, and before/after state changes.
- For browser issues, preserve console/network evidence from the live pass when it adds proof.

## Writing the report
For each confirmed bug: a precise URL + request, the exact payload, the observed
vs. expected behavior, a minimal PoC, the realistic impact, and a concrete fix.
Lead with the highest severity. Chain low-severity findings where they combine
into something worse (e.g. disclosure + IDOR).
