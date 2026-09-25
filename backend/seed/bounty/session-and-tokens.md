# Playbook: Sessions, tokens & real-time channels

**Authorized testing only.** Stay inside the program's scope (domains, paths,
accounts). Token and session checks below are read-only and self-scoped —
they inspect and replay a token you already hold, never someone else's.

## What the automated pass covers
- JWT `alg:none`, disabled/absent signature verification, weak/short HMAC secrets
- WebSocket handshakes that trust a cross-origin `Origin` (CSWSH)
- Session cookie flags (`Secure` / `HttpOnly` / `SameSite`)

## High-value classes to hunt by hand
- **JWT / token forgery** — decode the token; check `alg`/`kid`/`iss`/`exp` and whether the signature is actually verified server-side. Try `alg:none`, RS/HS key confusion (sign with the public key as the HMAC secret), and `kid` injection (path traversal or SQLi into the key lookup).
- **Privilege via claims** — swap `sub`/`role`/`scope`/`aud` and confirm only with a token the server still accepts as valid; a decoded-but-rejected token proves nothing.
- **WebSocket hijacking (CSWSH)** — find `ws://`/`wss://` literals or `new WebSocket(...)` targets; confirm the handshake completes (101) while carrying an attacker-controlled `Origin`, then prove a cross-site page can read authenticated data from the socket.
- **Session lifecycle** — fixation (session id unchanged across login), reset-token reuse or lack of expiry, and whether logout/refresh actually invalidates the session server-side rather than just clearing the client cookie.
- **Login/2FA rate-limiting** — brute-force and credential-stuffing gaps on the endpoints that mint or verify a token.

## Bounty triage notes
- A candidate secret/JWT is a lead, not a finding: prove the server still honors a token you forged or replayed before reporting a bypass, not just that you decoded one.
- Chain a token weakness with an IDOR/BFLA check — a forgeable `role` claim is far more valuable when it also reaches an admin-only endpoint.
- For CSWSH, capture the handshake response headers as proof; a working attack still needs a same-run PoC page, so keep the header-only case labeled a candidate until that PoC exists.
- Note the token's blast radius (one account vs. every account sharing a secret) before scoring severity.

## Writing the report
Show the exact token (redacted signature), the forged/replayed variant, and the
server response proving it was accepted. For CSWSH, include the handshake
request/response and the PoC page. Lead with what the forged claim or hijacked
socket lets the attacker actually do, not just that verification is weak.
