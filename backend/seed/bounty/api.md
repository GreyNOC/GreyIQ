# Playbook: API endpoint

**Authorized testing only.** Most API bugs require authenticated, manual
testing — the automated pass is a passive GET that only sees transport and
disclosure issues. The real value is the structured checklist below.

## What the automated pass covers
- Transport + security headers on the endpoint
- Verbose error bodies / stack traces (disclosure)
- Secrets accidentally returned in a response

## High-value classes to hunt by hand
- **Broken object-level auth (BOLA / IDOR)** — for each object id, replay the request as a different, lower-privileged token and confirm you still get the object.
- **Broken function-level auth** — call admin/internal operations with a normal token; try undocumented verbs (PUT/DELETE/PATCH).
- **Mass assignment** — add unexpected fields (e.g. `"role":"admin"`, `"isVerified":true`) to JSON bodies.
- **Injection** — parameters reaching queries/commands; a SQL error in a response is a strong SQLi lead.
- **SSRF** — server-side URL fetchers; rate-limiting and resource exhaustion gaps.

## Evidence that makes API reports stronger
- **CORS** - credentialed endpoints that trust arbitrary origins or wildcard subdomains.
- **Business logic** - replay, idempotency, state-machine bypass, quota reset, coupon/credit duplication.
- Include the exact method, path, query, headers that matter, and JSON body.
- Name both account roles/tokens used for authorization comparisons.
- Show the minimal changed field or identifier between allowed and unauthorized requests.
- Preserve response status, response body excerpt, and resulting object/account state.

## Writing the report
Capture the exact request (method, path, headers, body) and the response that
proves the issue, plus the token/role context. Show the minimal diff between an
authorized and unauthorized request. State the data exposed and the fix
(server-side authorization check, allow-list, schema).
