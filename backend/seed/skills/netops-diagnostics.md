---
name: netops-diagnostics
description: Triage network, connectivity, DNS, port, and TLS-certificate problems for a service
when: network, connectivity, connection, unreachable, timeout, latency, dns, resolve, port, firewall, tls, ssl, certificate, cert, expired, handshake, 502, 503, 504, gateway, upstream, outage, downtime, health check, ping, endpoint, reachable
---
Use this playbook for network/NOC triage: a service is unreachable, slow, returning
gateway errors, has DNS problems, or a TLS certificate is failing or expiring. Gather
facts with the read-only `net_probe` tool before drawing any conclusion — never guess
the cause.

1. Pin down the target first:
   - Get the exact host(s), port(s), and URL(s) from the user, source, config, or deploy docs (DEPLOY.md, nginx configs, ecosystem.config.*, .env.example).
   - Note what "working" should look like (expected status, port, response time) so you can tell healthy from broken.
   - Do not invent hostnames, domains, IPs, or credentials.

2. Work the layers in order with `net_probe`, stopping at the first layer that breaks:
   - DNS: `net_probe action=dns target=<host>`. No records or a resolution failure means the problem is name resolution, not the app.
   - Reachability: `net_probe action=tcp target=<host> port=<port>`. OPEN = listening; REFUSED = host up but nothing on that port; TIMEOUT = firewall/route/host down.
   - Response: `net_probe action=http target=<url>`. Read the status, redirect chain, timing, and `server`/`location` headers. 502/503/504 point at the upstream/app, not the proxy edge.
   - Certificate: `net_probe action=tls target=<host> port=443`. Check validity, the days-until-expiry, and that the SANs cover the hostname. "did NOT validate" names the exact fault (expired, self-signed, hostname mismatch).

3. Localize the fault from the layer that failed:
   - DNS fails → registrar/DNS record/resolver, or a typo'd host.
   - TCP refused/timeout → service not running, wrong port, or a firewall/security-group rule.
   - HTTP 5xx with TCP open → the app or upstream is unhealthy (check logs/process next).
   - TLS invalid/expiring → certificate renewal or chain/SAN problem.

4. Confirm locally when commands are enabled (otherwise skip and report what net_probe found):
   - Is the process up and bound? e.g. `pm2 status`, or check the listener (`ss -ltnp` / `netstat -ano`).
   - Tail recent logs for the failing service rather than restarting blindly.
   - Re-probe with `net_probe` after any change to confirm the layer now passes.

5. Report and remediate safely:
   - State the failing layer, the evidence (the net_probe output), and the most likely cause.
   - Propose the smallest fix first (restart a process, renew a cert, open one port, correct one DNS record). Do not make broad firewall or DNS changes on a guess.
   - Never disable TLS verification or expose a private service to fix a symptom.

6. Rollback and escalation:
   - Record the exact change made so it can be reverted (config diff, prior cert, prior record value).
   - If a fix needs privileged or destructive commands, or touches shared DNS/firewall state, explain the step and let the user run it rather than guessing.
