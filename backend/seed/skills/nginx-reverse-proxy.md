---
name: nginx-reverse-proxy
description: Create or repair an Nginx reverse proxy for localhost app services
when: nginx, reverse proxy, proxy_pass, certbot, tls, ssl, websocket, domain, server block
---
Use this playbook when the task asks for Nginx, reverse proxying, TLS, Certbot,
domains, or exposing a localhost app through HTTP/HTTPS.

1. Inspect before editing:
   - Identify the local app ports from source/config/docs.
   - Check whether the app needs WebSocket or streaming headers.
   - Check for existing Nginx snippets, deploy docs, or PM2 configs.
2. Plan safely:
   - Do not guess the real domain. Use a placeholder such as `example.com` only when documenting.
   - Proxy to `http://127.0.0.1:<port>` by default.
   - Keep backend services private unless the user asks for direct exposure.
3. Generate the server block:
   - Use `proxy_pass` to the detected localhost port.
   - Include `Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto` headers.
   - Add WebSocket headers (`Upgrade` and `Connection`) when the app uses sockets, live reload, streaming, or realtime APIs.
   - Keep client body size, cache, and timeout settings minimal unless the repo needs them.
4. TLS and Certbot:
   - Document Certbot commands, but do not invent email addresses or domains.
   - Keep HTTP-to-HTTPS redirects as an optional step when TLS is configured.
5. Verification:
   - Include `sudo nginx -t`.
   - Include `sudo systemctl reload nginx`.
   - Include local and external curl checks.
6. Rollback:
   - Disable the site symlink or restore the previous Nginx config.
   - Reload Nginx after rollback.
   - Keep PM2/app rollback separate from Nginx rollback.
