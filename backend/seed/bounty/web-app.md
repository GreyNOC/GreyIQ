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

## Writing the report
For each confirmed bug: a precise URL + request, the exact payload, the observed
vs. expected behavior, a minimal PoC, the realistic impact, and a concrete fix.
Lead with the highest severity. Chain low-severity findings where they combine
into something worse (e.g. disclosure + IDOR).
