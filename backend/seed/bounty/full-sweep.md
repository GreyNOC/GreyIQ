# Playbook: Full sweep

**Authorized testing only.** A broad first pass to map the target before you
focus. GreyIQ picks the right scanner for the target (static for code/repos,
passive web for URLs) and reports every class it finds.

## Use it as a map
1. Run the sweep, then read the findings table top-down by severity.
2. Pick the single highest-impact class present and switch to a **focused hunt**
   (re-run with that vuln class selected) for deeper, class-specific guidance.
3. Look for **chains**: an info disclosure + an access-control gap, or exposed
   secret + reachable admin endpoint, is often worth more than either alone.

## Class quick-reference
- **RCE / injection** — highest priority; trace input to sink.
- **Secrets** — validate live, scope blast radius.
- **XSS** — confirm execution at a DOM sink.
- **SSRF** — server-side URL fetchers.
- **Access control / IDOR** — swap identifiers across accounts.
- **Auth/session** — cookie flags, token handling, rate-limiting.

## Extra sweep leads
- **CSRF / CORS / redirects** - browser-trust issues; strongest when they expose authenticated actions or data.
- **File upload / business logic** - often manual-only; prove state change, storage impact, or workflow bypass.
- **Supply chain** - dependency, CI, install-hook, and artifact risks; prove reachability to builds or secrets.

## Writing the report
One report, severity-ordered. For each issue: where, evidence, reproduction,
impact, fix. Call out chains explicitly. Submit the most severe, confirmed bug
first.
