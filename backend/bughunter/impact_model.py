"""GreyIQ BugHunter — deterministic impact + proof-of-impact model.

The report already has a high-quality proof-of-impact *renderer* (report.py), but
historically only the optional LLM brain ever fed it — so a fully offline run
showed an empty Impact line and a "not captured yet" proof block. This module is
the missing **deterministic producer**: a per-class table that gives every
finding a concrete impact narrative (attacker capability -> affected asset ->
business impact), a finding-specific **proof obligation** (the exact artifact the
operator must capture to PROVE the impact for a submission), and a CVSS v3.1 base
vector + computed base score so severity is justified rather than asserted.

Pure / dependency-free / frozen-safe: constant data + a self-contained CVSS v3.1
base-score calculation. No network, no LLM. The brain still enriches on top; this
just guarantees the report is strong with nothing configured.

A static/passive scanner cannot exploit a target, so nothing here claims a bug is
"confirmed" — every deterministic proof block is a *candidate* whose obligation
tells the operator precisely what to capture to make it provable.
"""

from __future__ import annotations

import math
from typing import Any

# --- Per-class impact model. Keys cover every VULN_CLASSES id and every
# _CATEGORY_LABELS id in bounty.py (a unit test asserts full coverage). Each entry:
#   attacker_capability : who can do what
#   affected_asset      : the data / action / privilege at stake
#   business_impact     : the realistic worst-case consequence
#   proof_obligation    : the EXACT artifact to capture to prove impact (the key field)
#   cvss_vector         : CVSS v3.1 base vector (estimated — a static tool can't measure all metrics)
IMPACT_MODEL: dict[str, dict[str, str]] = {
    "rce": {
        "attacker_capability": "An attacker who controls the flagged input runs arbitrary commands or code on the server.",
        "affected_asset": "the application server and everything it can reach (data, secrets, internal network).",
        "business_impact": "full server compromise, data theft, lateral movement, and persistence.",
        "proof_obligation": "Capture a benign marker proving code execution — e.g. the response or out-of-band callback showing the output of `echo greyiq$((6*7))` (=> greyiq42) or a time-based delay — without running any real payload.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "secrets": {
        "attacker_capability": "Anyone who can read the exposed location uses the leaked credential.",
        "affected_asset": "whatever the key/token authenticates to (API, cloud account, database, third-party service).",
        "business_impact": "unauthorized access to the backing service, billing abuse, or pivot to further data.",
        "proof_obligation": "Confirm the secret is live by making ONE benign authenticated read against the matching service (in scope) and capture the request + the success response — then state the blast radius. Redact the secret itself.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    },
    "xss": {
        "attacker_capability": "An attacker injects script that executes in another user's authenticated browser session.",
        "affected_asset": "victim sessions, cookies, CSRF tokens, and any action the victim can take.",
        "business_impact": "session/account takeover, credential theft, or unauthorized actions as the victim.",
        "proof_obligation": "Capture the request with a unique marker payload and the rendered response (or a screenshot) showing it EXECUTES, not just reflects — e.g. a `prompt(document.domain)` firing, plus the cookie/CSP context.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "ssrf": {
        "attacker_capability": "An attacker makes the server issue requests to attacker-chosen internal or cloud-metadata hosts.",
        "affected_asset": "internal services, cloud metadata credentials, and otherwise-unreachable endpoints.",
        "business_impact": "internal recon, credential theft from metadata, and pivoting behind the firewall.",
        "proof_obligation": "Point the parameter at a collaborator host you control and capture the inbound request proving the server connected out; if reachable, capture one in-scope internal response (e.g. metadata) as proof of reach.",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
    },
    "access-control": {
        "attacker_capability": "An authenticated low-privilege user reads or changes objects owned by other users by swapping an identifier.",
        "affected_asset": "other tenants'/users' records or actions (orders, profiles, files, admin functions).",
        "business_impact": "cross-tenant data disclosure or unauthorized state change (IDOR/BOLA, broken access control).",
        "proof_obligation": "As account B, replay the request with account A's object id and capture the HTTP 200 + response body showing A's data; capture the negative control (403/empty) for an id B does own, plus both account roles.",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    },
    "auth": {
        "attacker_capability": "An attacker defeats authentication or session handling (fixation, weak token, missing invalidation).",
        "affected_asset": "user sessions and accounts, including the account-recovery path.",
        "business_impact": "account takeover or authentication bypass.",
        "proof_obligation": "Capture the full request/response sequence proving the weakness — e.g. a session that stays valid after logout, a reused reset token, or a forged/predicted token accepted as valid.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "sqli": {
        "attacker_capability": "An attacker injects SQL into a query through the flagged parameter.",
        "affected_asset": "the entire database reachable by the query's role.",
        "business_impact": "mass data disclosure, authentication bypass, or data tampering.",
        "proof_obligation": "Capture a boolean- or time-based differential proving injection (e.g. `1 AND SLEEP(5)` delaying the response vs a control) — do NOT dump data; one row count or DB-version banner is sufficient proof.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "csrf": {
        "attacker_capability": "An attacker tricks an authenticated victim's browser into making a state-changing request.",
        "affected_asset": "any state-changing action lacking an anti-CSRF token (email/password change, transfers, invites).",
        "business_impact": "unauthorized actions performed as the victim (account/email/password change).",
        "proof_obligation": "Build a minimal cross-site HTML/fetch PoC and capture the before/after server state proving the victim's action changed without their intent, plus the absence of a validated anti-CSRF token.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    },
    "cors": {
        "attacker_capability": "An attacker page reads authenticated responses cross-origin because the API reflects/trusts its Origin.",
        "affected_asset": "authenticated API responses (profile, tokens, account data).",
        "business_impact": "cross-origin theft of authenticated data leading to account compromise.",
        "proof_obligation": "Capture the response showing `Access-Control-Allow-Origin: <attacker>` with `Allow-Credentials: true`, plus a PoC from an untrusted origin that actually READS sensitive authenticated data.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    },
    "redirect": {
        "attacker_capability": "An attacker supplies a redirect parameter that sends users to an external site.",
        "affected_asset": "users following links, and any token passed through the redirect (OAuth code, reset token).",
        "business_impact": "credential phishing, OAuth token leak, or account-takeover chains.",
        "proof_obligation": "Capture the request showing an absolute external URL accepted by the redirect parameter (especially after login/OAuth/reset), and note any token that travels to the attacker host.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "file-upload": {
        "attacker_capability": "An attacker uploads or retrieves a file that bypasses type/path/storage controls.",
        "affected_asset": "the web/file server, stored content, and other users' downloads.",
        "business_impact": "remote code execution (webshell), stored XSS, or arbitrary file read/overwrite.",
        "proof_obligation": "Capture the upload request + the response/URL proving the dangerous file was accepted and is reachable/executed (e.g. a benign `.php`/SVG that runs), or a path-traversal write/read of an out-of-scope path stopped at proof.",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    },
    "business-logic": {
        "attacker_capability": "An attacker abuses a workflow by skipping, repeating, or reordering server-side steps.",
        "affected_asset": "the business invariant (price, quota, balance, role, coupon, vote).",
        "business_impact": "financial loss, privilege gain, or quota/limit bypass.",
        "proof_obligation": "Capture the request sequence and the before/after state proving the invariant broke (e.g. negative quantity accepted, a coupon reused, balance increased) with the unauthorized value clearly shown.",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    },
    "supply-chain": {
        "attacker_capability": "An attacker controls a dependency, install hook, or CI step in the build path.",
        "affected_asset": "the build pipeline, release artifacts, and any secret the build can read.",
        "business_impact": "compromised releases shipped to users, or theft of deploy/release secrets.",
        "proof_obligation": "Show the vulnerable package/workflow is reachable in the DEPLOYED build path (lockfile + import/usage), and identify the exact exploitable version/permission — link to the advisory rather than running an exploit.",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "ssti": {
        "attacker_capability": "An attacker injects template syntax that the server evaluates.",
        "affected_asset": "server-side context and, in most engines, file read or code execution.",
        "business_impact": "remote code execution or sensitive file/configuration disclosure.",
        "proof_obligation": "Capture the request with an arithmetic probe per engine (e.g. `${7*7}` / `{{7*7}}`) and the response rendering `49`, identifying the engine — stop at expression evaluation, before any file-read/RCE payload.",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    },
    "xxe": {
        "attacker_capability": "An attacker submits XML whose external entities the parser resolves.",
        "affected_asset": "local files readable by the service and internal hosts (SSRF via entities).",
        "business_impact": "local file disclosure (e.g. /etc/passwd, config/secrets) or internal SSRF.",
        "proof_obligation": "Capture the request with a benign external entity pointing at a collaborator you control and the inbound hit proving resolution; if files resolve, capture one in-scope, non-sensitive file as proof and stop.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "nosqli": {
        "attacker_capability": "An attacker injects operator syntax into a NoSQL query parameter.",
        "affected_asset": "the document store and the authentication/filter logic that queries it.",
        "business_impact": "authentication bypass or unauthorized data retrieval.",
        "proof_obligation": "Capture the baseline vs operator-injection requests (e.g. `{\"$ne\":null}`) and the responses proving an auth bypass or a changed result set — one differential is enough; do not bulk-extract.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    },
    "jwt": {
        "attacker_capability": "An attacker forges or downgrades a JWT the server accepts (alg:none, key confusion, weak secret, kid injection).",
        "affected_asset": "any identity/role/scope the token asserts.",
        "business_impact": "authentication bypass or privilege escalation to another user/admin.",
        "proof_obligation": "Capture the original token, the forged token (e.g. role swapped / alg:none / cracked HS secret), and the authenticated response the server returns for the forged token proving it is accepted.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "graphql": {
        "attacker_capability": "An attacker reaches hidden queries/mutations or missing field-level authorization.",
        "affected_asset": "objects and mutations another role should not access; rate limits via batching.",
        "business_impact": "BOLA/BFLA data disclosure or unauthorized mutations, or limit bypass via aliasing.",
        "proof_obligation": "Capture an introspection or field-auth request as a lower-privileged role and the response returning another role's object/mutation result that the UI does not expose.",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    },
    "prototype-pollution": {
        "attacker_capability": "An attacker pollutes Object.prototype via attacker-controlled keys merged into an object.",
        "affected_asset": "global object behavior and any gadget that reads polluted properties.",
        "business_impact": "depends on the gadget — XSS, auth/logic bypass, or RCE in Node.",
        "proof_obligation": "Capture the request injecting `__proto__`/`constructor.prototype` and proof a polluted property appears on a fresh object, THEN demonstrate the concrete downstream gadget (pollution alone is informational).",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
    },
    "race-condition": {
        "attacker_capability": "An attacker fires concurrent requests to a single-use or limit-enforcing action.",
        "affected_asset": "the enforced limit (coupon, withdrawal, vote, invite, 2FA attempt).",
        "business_impact": "double-spend, limit bypass, or financial loss.",
        "proof_obligation": "Capture the concurrent request burst (single-packet / last-byte sync) and the before/after state proving the invariant broke (e.g. one coupon redeemed N times), with the request count needed.",
        "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
    },
    "request-smuggling": {
        "attacker_capability": "An attacker desyncs a front-end/back-end chain with conflicting length/encoding headers.",
        "affected_asset": "other users' requests/responses, caches, and access controls at the proxy.",
        "business_impact": "request hijacking, cache poisoning, or control bypass affecting other users.",
        "proof_obligation": "Capture a SELF-CONTAINED desync proof (your own next request captured/prefixed) with the timing differential — never a payload that affects other users' traffic.",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },
    "subdomain-takeover": {
        "attacker_capability": "An attacker claims a third-party resource a dangling DNS record still points at.",
        "affected_asset": "the subdomain itself, plus cookies/OAuth scoped to the parent domain.",
        "business_impact": "content/phishing on a trusted subdomain, session capture, or OAuth allow-list bypass.",
        "proof_obligation": "Capture the dangling CNAME -> unclaimed-service fingerprint, then claim the resource and serve a benign marker page proving control — never host real content.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "cloud-exposure": {
        "attacker_capability": "Anyone reaches a misconfigured public bucket/blob or cloud metadata endpoint.",
        "affected_asset": "stored objects (backups, user data, source) or instance credentials.",
        "business_impact": "data disclosure or theft of cloud credentials enabling account takeover.",
        "proof_obligation": "Capture the unauthenticated list/read response for one non-sensitive object (and the public-write test result if applicable), naming the exact bucket/permission and the data class exposed.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    # --- _CATEGORY_LABELS ids (crypto / dependency / network / ci / headers /
    # mixed_content / disclosure) get a model too, so no finding renders empty. ---
    "crypto": {
        "attacker_capability": "An attacker exploits weak or misused cryptography (broken cipher, predictable keys, no integrity).",
        "affected_asset": "data confidentiality/integrity protected by the weak primitive.",
        "business_impact": "decryption, forgery, or tampering of protected data.",
        "proof_obligation": "Demonstrate the weakness concretely — e.g. recover or predict a value, or show data accepted without integrity — and tie it to the specific algorithm/usage flagged.",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "dependency": {
        "attacker_capability": "An attacker exploits a known-vulnerable version of a bundled dependency.",
        "affected_asset": "whatever the vulnerable component handles in the deployed app.",
        "business_impact": "depends on the CVE — ranges from DoS to RCE if the vulnerable path is reachable.",
        "proof_obligation": "Show the vulnerable version is shipped (lockfile) AND the vulnerable code path is reachable in the deployed app; cite the advisory/CVE rather than weaponizing it.",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
    },
    "network": {
        "attacker_capability": "A network-positioned attacker exploits weak transport (no/invalid TLS, downgrade).",
        "affected_asset": "data in transit and the integrity of the connection.",
        "business_impact": "interception or tampering of traffic (MITM).",
        "proof_obligation": "Capture the transport weakness — e.g. cleartext sensitive data, an invalid/expired certificate accepted, or a downgrade — with the exact endpoint and observed handshake.",
        "cvss_vector": "AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "ci": {
        "attacker_capability": "An attacker abuses an over-permissioned or injectable CI/CD workflow.",
        "affected_asset": "build runners, repository write access, and CI secrets.",
        "business_impact": "secret exfiltration, malicious build injection, or repo compromise.",
        "proof_obligation": "Show the exact workflow step that is injectable or over-permissioned (e.g. unpinned action with write token, untrusted input in `run:`) and the secret/permission it exposes — do not trigger it maliciously.",
        "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N",
    },
    "headers": {
        "attacker_capability": "A missing/weak security header removes a browser-side defense.",
        "affected_asset": "users of the page (defense-in-depth against XSS, clickjacking, sniffing).",
        "business_impact": "increases exploitability of other bugs; rarely impactful on its own.",
        "proof_obligation": "Capture the response showing the missing/weak header, and — to make it report-worthy — demonstrate the concrete attack it enables (e.g. a clickjacking PoC for missing X-Frame-Options).",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },
    "mixed_content": {
        "attacker_capability": "A network attacker tampers with sub-resources loaded over http on an https page.",
        "affected_asset": "scripts/styles/resources injected into the secure page.",
        "business_impact": "script injection / page tampering via MITM of the insecure resource.",
        "proof_obligation": "Capture the https page referencing an http:// sub-resource (the exact tag) and note that a network attacker can replace it; demonstrate injection if a script is loaded insecurely.",
        "cvss_vector": "AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "disclosure": {
        "attacker_capability": "Anyone reading the response obtains information the app should not reveal.",
        "affected_asset": "internal paths, versions, stack traces, or source maps aiding further attacks.",
        "business_impact": "reconnaissance that lowers the cost of other attacks; sometimes direct data leak.",
        "proof_obligation": "Capture the exact response disclosing the information (stack trace, version, internal path, source map) and explain the concrete follow-on it enables.",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
}

_GENERIC_MODEL: dict[str, str] = {
    "attacker_capability": "An attacker exploits the flagged weakness from untrusted input.",
    "affected_asset": "the data or action the vulnerable code path controls.",
    "business_impact": "depends on reachability — confirm the affected asset within scope.",
    "proof_obligation": "Capture the request and the response/state proving a real security effect (data exposed, privilege gained, or state changed), with a negative control.",
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
}

# --- Per-class REMEDIATION (one concrete, verifiable fix) + REFERENCES (authoritative
# links a triager trusts). These are the report's "fix" + "references" floor: present
# on EVERY finding even with no brain and no per-rule remediation. Constant text, no
# network. A unit test asserts both are present for every class id.
_CS = "https://cheatsheetseries.owasp.org/cheatsheets"
_CWE = "https://cwe.mitre.org/data/definitions"

_REMEDIATION: dict[str, str] = {
    "rce": "Never pass untrusted input to a shell/eval/deserializer. Use argv arrays (shell=False), safe parsers, and an allowlist; drop privileges on the worker.",
    "secrets": "Revoke and rotate the exposed credential immediately, remove it from the served asset/source, and load secrets from a secret manager / env at runtime — never commit or ship them.",
    "xss": "Context-encode all output (HTML/attr/JS/URL), prefer a framework's auto-escaping, set a strict Content-Security-Policy, and validate input on the server.",
    "ssrf": "Allowlist the destination host + scheme before fetching, resolve and reject private/link-local/metadata IPs, and disable following redirects to internal addresses.",
    "access-control": "Enforce a server-side authorization check that the authenticated principal owns/may access the requested object on every request; never rely on client-supplied ids or UI hiding.",
    "auth": "Set Secure/HttpOnly/SameSite on session cookies, use high-entropy tokens with server-side expiry/rotation, rate-limit auth endpoints, and invalidate sessions on logout/reset.",
    "sqli": "Use parameterized queries / prepared statements for every query; never build SQL by string formatting. Apply least-privilege DB roles.",
    "csrf": "Require an unpredictable per-session anti-CSRF token (or SameSite=strict cookies) on every state-changing request and verify it server-side.",
    "cors": "Reflect Origin only from an explicit allowlist, never combine `Access-Control-Allow-Origin: *`/reflected with `Allow-Credentials: true`, and never trust `null`.",
    "redirect": "Allowlist redirect targets (relative paths or a fixed host set); validate with a host/scheme check (e.g. url_has_allowed_host_and_scheme) and reject off-host URLs.",
    "file-upload": "Validate type by content (not extension), store outside the web root with non-executable permissions and random names, and serve via a controlled handler.",
    "business-logic": "Enforce the intended workflow and invariants server-side (ownership, quantity/price, state transitions); never trust client-asserted steps or amounts.",
    "supply-chain": "Pin and integrity-verify dependencies (lockfile + hashes), build from a clean source, and never pipe a remote download straight into a shell.",
    "ssti": "Render fixed template files and pass user input as context variables; never build the template string from input. Sandbox the engine where supported.",
    "xxe": "Disable DTDs and external-entity resolution on the XML parser (or use defusedxml); reject documents containing a DOCTYPE for untrusted input.",
    "nosqli": "Use typed query builders / parameterized operators, validate that user input is the expected scalar type, and reject query-operator objects (`$ne`, `$where`).",
    "jwt": "Pin a single strong algorithm (reject `none`), always verify the signature with a long random key, and validate iss/aud/exp; never accept HS/RS key confusion.",
    "graphql": "Disable introspection in production, enforce per-field authorization, and add query depth/complexity limits and rate limiting.",
    "prototype-pollution": "Reject `__proto__`/`constructor`/`prototype` keys when merging/cloning untrusted objects; use Map or a null-prototype object and a vetted merge utility.",
    "race-condition": "Make the critical section atomic (DB transaction + row lock, unique constraint, or idempotency key) so concurrent requests can't double-spend the operation.",
    "request-smuggling": "Normalize and reject ambiguous Content-Length/Transfer-Encoding combinations at the front-end proxy; use HTTP/2 to the backend and a single conformant parser.",
    "subdomain-takeover": "Remove dangling DNS records that point at unclaimed third-party services; verify ownership before pointing a record and monitor for unresolved targets.",
    "cloud-exposure": "Make the bucket/resource private, enforce block-public-access, scope IAM to least privilege, and require auth on every object.",
    "crypto": "Use a vetted library with a modern algorithm (AES-GCM, SHA-256+, Argon2/bcrypt for passwords), random IVs/salts, and never a hardcoded key.",
    "dependency": "Upgrade the vulnerable package to a fixed version (or backport the patch), and add automated dependency scanning to CI.",
    "network": "Use TLS for all transport, validate certificates, and bind services to least-exposed interfaces with authentication.",
    "ci": "Pin actions/images by digest, scope tokens to least privilege, never echo secrets, and require review for workflow changes from forks.",
    "headers": "Add the missing security response headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy) at the app or edge.",
    "mixed_content": "Serve every sub-resource over HTTPS and add `upgrade-insecure-requests` to the CSP so no asset loads over http on a secure page.",
    "disclosure": "Remove the verbose error/stack/version disclosure from responses, return generic errors to clients, and log details server-side only.",
}

_REFERENCES: dict[str, list[str]] = {
    "rce": [f"{_CS}/OS_Command_Injection_Defense_Cheat_Sheet.html", f"{_CWE}/78.html"],
    "secrets": [f"{_CS}/Secrets_Management_Cheat_Sheet.html", f"{_CWE}/798.html"],
    "xss": [f"{_CS}/Cross_Site_Scripting_Prevention_Cheat_Sheet.html", f"{_CWE}/79.html", "https://portswigger.net/web-security/cross-site-scripting"],
    "ssrf": [f"{_CS}/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html", f"{_CWE}/918.html", "https://portswigger.net/web-security/ssrf"],
    "access-control": [f"{_CS}/Access_Control_Cheat_Sheet.html", f"{_CWE}/639.html", "https://portswigger.net/web-security/access-control/idor"],
    "auth": [f"{_CS}/Session_Management_Cheat_Sheet.html", f"{_CWE}/384.html"],
    "sqli": [f"{_CS}/SQL_Injection_Prevention_Cheat_Sheet.html", f"{_CWE}/89.html", "https://portswigger.net/web-security/sql-injection"],
    "csrf": [f"{_CS}/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html", f"{_CWE}/352.html"],
    "cors": [f"{_CS}/HTML5_Security_Cheat_Sheet.html", f"{_CWE}/942.html", "https://portswigger.net/web-security/cors"],
    "redirect": [f"{_CS}/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html", f"{_CWE}/601.html"],
    "file-upload": [f"{_CS}/File_Upload_Cheat_Sheet.html", f"{_CWE}/434.html"],
    "business-logic": ["https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability", f"{_CWE}/840.html"],
    "supply-chain": [f"{_CS}/Vulnerable_Dependency_Management_Cheat_Sheet.html", f"{_CWE}/1357.html"],
    "ssti": ["https://portswigger.net/web-security/server-side-template-injection", f"{_CWE}/1336.html"],
    "xxe": [f"{_CS}/XML_External_Entity_Prevention_Cheat_Sheet.html", f"{_CWE}/611.html", "https://portswigger.net/web-security/xxe"],
    "nosqli": [f"{_CS}/Injection_Prevention_Cheat_Sheet.html", f"{_CWE}/943.html", "https://portswigger.net/web-security/nosql-injection"],
    "jwt": [f"{_CS}/JSON_Web_Token_for_Java_Cheat_Sheet.html", f"{_CWE}/347.html", "https://portswigger.net/web-security/jwt"],
    "graphql": [f"{_CS}/GraphQL_Cheat_Sheet.html", f"{_CWE}/200.html"],
    "prototype-pollution": ["https://portswigger.net/web-security/prototype-pollution", f"{_CWE}/1321.html"],
    "race-condition": ["https://portswigger.net/web-security/race-conditions", f"{_CWE}/362.html"],
    "request-smuggling": ["https://portswigger.net/web-security/request-smuggling", f"{_CWE}/444.html"],
    "subdomain-takeover": ["https://owasp.org/www-community/Subdomain_Takeover", f"{_CWE}/350.html"],
    "cloud-exposure": [f"{_CS}/Secrets_Management_Cheat_Sheet.html", f"{_CWE}/200.html"],
    "crypto": [f"{_CS}/Cryptographic_Storage_Cheat_Sheet.html", f"{_CWE}/327.html"],
    "dependency": [f"{_CS}/Vulnerable_Dependency_Management_Cheat_Sheet.html", f"{_CWE}/1395.html"],
    "network": [f"{_CS}/Transport_Layer_Security_Cheat_Sheet.html", f"{_CWE}/319.html"],
    "ci": ["https://docs.github.com/actions/security-guides/security-hardening-for-github-actions", f"{_CWE}/1395.html"],
    "headers": [f"{_CS}/HTTP_Security_Response_Headers_Cheat_Sheet.html", f"{_CWE}/693.html"],
    "mixed_content": [f"{_CS}/HTTP_Security_Response_Headers_Cheat_Sheet.html", f"{_CWE}/319.html"],
    "disclosure": [f"{_CS}/Error_Handling_Cheat_Sheet.html", f"{_CWE}/200.html"],
}

_GENERIC_REMEDIATION = "Validate and sanitize untrusted input at the trust boundary, enforce the relevant control server-side, and confirm the fix with the captured proof artifact."
_GENERIC_REFERENCES = ["https://owasp.org/www-project-top-ten/", f"{_CWE}/710.html"]


def remediation_for_class(class_id: str) -> str:
    """A concrete, verifiable fix sentence for the class (always non-empty)."""
    return _REMEDIATION.get(str(class_id or ""), _GENERIC_REMEDIATION)


def references_for_class(class_id: str) -> list[str]:
    """2-3 authoritative https:// references for the class (always non-empty)."""
    return list(_REFERENCES.get(str(class_id or ""), _GENERIC_REFERENCES))


# --- Bugcrowd VRT (Vulnerability Rating Taxonomy) category, alongside the HackerOne
# severity rating, so a report carries both platforms' language. Estimated — '' for a
# class with no clean VRT mapping (the report only renders the row when non-empty).
_BUGCROWD_VRT: dict[str, str] = {
    "rce": "server_security_misconfiguration.remote_code_execution_rce",
    "xss": "cross_site_scripting_xss.stored",
    "sqli": "server_side_injection.sql_injection",
    "ssrf": "server_side_injection.server_side_request_forgery_ssrf",
    "ssti": "server_side_injection.server_side_template_injection_ssti",
    "xxe": "server_side_injection.xml_external_entity_injection_xxe",
    "access-control": "broken_access_control_bac.insecure_direct_object_reference_idor",
    "auth": "broken_authentication_and_session_management",
    "csrf": "broken_authentication_and_session_management.cross_site_request_forgery_csrf",
    "redirect": "unvalidated_redirects_and_forwards.open_redirect",
    "cors": "server_security_misconfiguration.cors_misconfiguration",
    "secrets": "sensitive_data_exposure.disclosure_of_secrets",
    "jwt": "broken_authentication_and_session_management.authentication_bypass",
    "file-upload": "unrestricted_file_upload",
    "graphql": "server_security_misconfiguration.misconfigured_dns",
    "deserialization": "server_side_injection.remote_code_execution_rce",
    "nosqli": "server_side_injection.nosql_injection",
    "headers": "server_security_misconfiguration.security_headers",
    "disclosure": "sensitive_data_exposure.disclosure_of_known_vulnerabilities",
}


def bugcrowd_vrt(class_id: str) -> str:
    """The Bugcrowd VRT category for a class, or '' if there is no clean mapping."""
    return _BUGCROWD_VRT.get(str(class_id or ""), "")

# --- CVSS v3.1 base-score metric weights (spec section 7.4). ---
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # scope changed
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _parse_vector(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in str(vector or "").split("/"):
        if ":" in part:
            key, _, val = part.partition(":")
            metrics[key.strip().upper()] = val.strip().upper()
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 roundup: smallest 1-decimal number >= value (integer-arithmetic form)."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss_base_score(vector: str) -> dict[str, Any]:
    """Compute the CVSS v3.1 base score + qualitative severity from a base vector.
    Returns {score, severity, vector}. On a malformed vector, score is 0.0."""
    m = _parse_vector(vector)
    try:
        scope_changed = m.get("S") == "C"
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        ui = _UI[m["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return {"score": 0.0, "severity": "None", "vector": str(vector or "")}

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        score = _roundup(min(impact + exploitability, 10.0))
    return {"score": round(score, 1), "severity": cvss_severity(score), "vector": str(vector or "")}


def cvss_severity(score: float) -> str:
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def impact_for_class(class_id: str) -> dict[str, str]:
    """The impact-model entry for a class id (falls back to a generic model)."""
    return IMPACT_MODEL.get(str(class_id or ""), _GENERIC_MODEL)


def cvss_for_class(class_id: str) -> dict[str, Any]:
    """{vector, score, severity, justification, estimated} for a class id. The
    severity is 'estimated' because a static/passive scan can't measure every metric."""
    model = impact_for_class(class_id)
    vector = model["cvss_vector"]
    scored = cvss_base_score(vector)
    return {
        "vector": vector,
        "base_score": scored["score"],
        "base_severity": scored["severity"],
        "estimated": True,
        "justification": (
            f"{model['attacker_capability']} {model['business_impact'].capitalize()} "
            "Vector is an estimate for a static/passive finding; confirm the real metrics on the live target."
        ),
    }
