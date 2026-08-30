# GreyIQ BugHunter — Operator's Guide

This is the practical walkthrough for the Hunt cockpit: **Program → Hunt → Reports**. It
assumes you already have GreyIQ running (see the main [README](../README.md) for install/run).
Everything in this guide is also reachable in the app itself — each tab has a collapsible
**walkthrough** panel (a `<details>` block near the top) carrying the same content inline,
and a first-time launch opens a short guided tour automatically (reopen it anytime with the
**🧭 Guide me** button in the top bar).

## Before anything else: authorization

GreyIQ is built for **authorized testing only** — your own assets, an engagement you're
contracted for, or a bug-bounty program you're enrolled in. Every active probe requires
you to tick an authorization checkbox *and* name the exact host in **Scope**; both are
enforced server-side, fail-closed. A host you never named in Scope is never touched, no
matter what the UI lets you type into Target. Nothing here authorizes you to test anything
— that authorization has to already exist before you open the app.

## 1. Program setup

The **Program** tab (first tab in the cockpit) is where a bug-bounty program's identity
and scope live. One saved program feeds three things: the launch rail's **Program** picker
(autofills Target/Scope for a hunt), the **Operator** tab's autonomous scheduling, and — once
you set up SSRF/OOB testing — the Access-control tab's collaborator panel.

A program record has: a name, an optional HackerOne team handle, a **structured scope**
table (one row per in-scope/out-of-scope asset), optional program-provided source repository
links, an `oob_allowed` flag, and free-text notes.

### Getting a program and scope in — four ways

**Start from a repository link.** At the top of the Program tab, paste one or more public
HTTPS repository-root links and click **Create draft program →**. GreyIQ validates the same
GitHub, GitLab, Bitbucket, Codeberg, and SourceHut roots accepted by the source scanner,
derives a program name from the repository owner, and opens the existing review form with
**Clone and adversarially scan** already selected. The new record is inactive, disabled for
autonomous scheduling, and has no web scope until you review and save it. Issue, blob, tree,
pull-request, credential-bearing, and non-allowlisted URLs are rejected.

The optional **Enrich from forge (read-only)** checkbox is off by default. On the explicit
create click, it makes at most one unauthenticated GET per repository to GitHub's public API
(`api.github.com`) or GitLab's public API (`gitlab.com`); other forges are skipped. A returned
description is added to Notes. Homepage/web domains appear only as **unticked** suggested
scope rows with a reminder to confirm authorization. They are never written into the draft's
scope by the backend and never become in-scope unless you deliberately tick **In scope** and
save. Failures are best-effort and do not prevent the local draft from being created.

**Fetch from HackerOne (API).** If you have a HackerOne API username + token saved (see
[HackerOne credentials](#hackerone-credentials) below), enter the program's team handle and
click **Fetch scope from HackerOne**. GreyIQ calls HackerOne's own hacker API —
`GET /v1/hackers/programs/{handle}` for the program's name/policy, then
`GET /v1/hackers/programs/{handle}/structured_scopes` (paginated) for every scope entry —
using HTTP Basic auth with the same credentials you already entered. This is one of the
small, documented set of calls that can reach a host other than your target, and it only
fires on this explicit click — never automatically or in the background.

Many programs restrict structured-scope visibility to invited or paid researchers, so a
403/404 here is common and is *not* a bug — GreyIQ tells you plainly and points at the CSV
fallback instead of failing silently.

- Your **API token**: hackerone.com → Settings → **API Token** (this is a token, not your
  account password).
- Your **API username**: shown right next to the token on that same settings page.
- The **program handle**: the segment right after `hackerone.com/` in the program's URL
  (e.g. `hackerone.com/acme` → handle is `acme`).

**Import a CSV, or paste a table.** No API access to that program's scope? Copy the scope
table straight off the program's HackerOne page (or export it if the program offers that),
and paste it — or upload the file — into the **Import targets** box, with kind set to
**HackerOne scope CSV/paste**. GreyIQ recognizes the real column names HackerOne uses
(`asset_identifier`/`identifier`, `asset_type`, `eligible_for_submission`,
`eligible_for_bounty`, `instruction`, `max_severity`) case-insensitively, so it keeps every
column instead of collapsing the row to a single URL. If it doesn't recognize any header at
all, it falls back to treating each cell as a bare in-scope identifier — still useful for a
plain list of hosts.

**Type it by hand.** Click **+ Add scope row** and fill in an identifier — that's the only
required field. Everything else (asset type, bounty eligibility, severity cap, instructions)
is optional metadata.

**Add a program-provided source repository.** Paste each public HTTPS repository-root link
into **Program-provided source repositories**, then explicitly enable **Clone and adversarially
scan**. HackerOne/CSV imports that contain supported GitHub, GitLab, Bitbucket, Codeberg, or
SourceHut repository roots are detected and copied into this review list, but cloning remains
off until you opt in. Issue, pull-request, blob, and tree pages are not accepted as repositories.
Private-repository credentials are intentionally not accepted in repository URLs.

### Review before you hunt

Whichever way scope arrived, review the table before saving:

- Untick **In scope** on any row you don't want probed. This is an **exclusion filter
  only** — unticking a row never expands what GreyIQ is allowed to touch; it only narrows it.
- Forge-enriched host suggestions start unticked. Check the program's published policy and
  confirm you are authorized to test a host before ticking **In scope**; the suggestion alone
  grants no authorization.
- A program with **no** in-scope rows (and no hand-typed Scope text) can never be marked
  active — this is the same fail-closed gate the launch rail and Operator already use, just
  applied one level up: an empty structured scope can't silently become "active everywhere."
- Click **Save program**.
- For a source-code hunt, click **Hunt repository** on the saved program or pick the repository
  from the launch rail's Target suggestions. GreyIQ makes a depth-1, single-branch temporary
  clone, scans the whole eligible code tree with the adversarial static rule set, sends the
  resulting leads through the configured hunt brain for red-team reproduction/impact planning,
  performs the normal authorized credential-validation and reporting stages, then removes the clone.

### HackerOne credentials

Saved once, in the **Submissions** tab's "HackerOne API" bar: your team handle, API
username, and API token. The token field is write-only — GreyIQ never reads it back to the
UI once saved. These same credentials power both the read-only scope import described above
and the (separately gated) HackerOne report submission described in
[Reports & submission](#4-reports--submission).

## 2. SSRF / OOB setup, per program

Blind SSRF (and blind XXE) can't be proven by looking at the response — the target fetches
a URL you control, out of band, and you watch for the callback. GreyIQ's detection engine
for this already exists in the **Access-control** tab's OOB panel; the Program tab just
removes the friction of setting it up per program:

1. **Confirm the policy allows it.** Some bounty programs explicitly forbid interacting
   with third-party/out-of-network infrastructure during testing. Read the program's policy,
   then tick **"This program's policy allows out-of-band / collaborator testing"** on its
   Program-setup form. This isn't cosmetic — clicking "Set up SSRF/OOB →" on a program that
   hasn't confirmed this asks you to double check before continuing.
2. **Set up a collaborator once** (global, not per-program) in the Access-control tab's OOB
   panel: a collaborator base URL + secret. See that panel's own walkthrough for the
   one-time setup.
3. **Jump over with scope pre-filled.** Click **"Set up SSRF/OOB →"** on a saved program's
   row — it carries that program's scope straight into the Access-control tab's Scope box, so
   you don't retype it.
4. **Mint a callback + probe.** In the OOB panel, mint a callback URL, then run the
   blind-SSRF probe against a candidate endpoint. GreyIQ injects the callback into likely
   parameters and polls for a hit, with a same-run negative control before anything is ever
   marked confirmed.

Common places SSRF sinks hide, worth trying first: webhook/callback URL fields, "import a
file from a link" features, avatar or link/thumbnail proxies, PDF/screenshot-export tools
that "render this URL," and any parameter that already looks like a URL (`redirect`, `next`,
`return_to`, `source`, …).

## 3. Running a hunt

Three ways to actually run the engine, all reading the same Target/Scope from the launch
rail (which the Program picker can autofill):

- **Single hunt** — one target, one profile (Web app / API / Source-code / Secrets / Full
  sweep), optional vuln-class focus. A supported public repository URL is automatically routed
  to the remote-clone source scanner. The fastest way to check one asset. Start here.
- **Full campaign** — recon-crawls the target first (robots/sitemap/security.txt,
  same-origin links, served-JS mining), then hunts every discovered URL, dedupes and ranks
  findings, and (in **Deep** mode) auto-captures a screenshot + writes a research dossier
  for every confirmed lead.
- **Autonomous operator** (Operator tab) — works your whole **portfolio** of programs
  unattended on a schedule: recon → hunt → prove → dedup → report, repeated per program at
  its configured interval. Auto-submit is off by default and, when armed, is gated by
  confirmed-proof + non-duplicate + a per-program daily cap — review-only until you
  explicitly arm it, and the kill switch stops it immediately.

All three default to **passive-only**. Ticking **"Test for proof of impact (active)"** turns
on benign, in-scope-only active probes that can mark a finding **Confirmed** instead of just
flagged; it (and every other active/opt-in mode — deep SQLi, live browser pass, deep
auto-work) still only ever fires against a host actually named in Scope.

### Passive OSINT campaigns (local CLI)

The shipped `gn` command can build a domain evidence ledger before you spend any request
budget on the target:

```text
gn osint example.com
gn osint example.com --json
gn osint example.com --hunt --scope "*.example.com" --active -y
gn campaign https://example.com --scope "*.example.com" --osint -y
```

`gn osint` queries public indexes, not the investigated website: crt.sh + Cert Spotter for
certificate history, then Google + Cloudflare DNS-over-HTTPS for current resolution. Every
claim carries its provider IDs and retrieval time. Exact agreement from two independent
providers is **verified**; one-source DNS facts stay **observed**; CT-only hostnames stay
**historical**. The report and complete JSON ledger land under `runtime/osint/` by default.

`--hunt` is a deliberate handoff, not automatic authorization. It requires explicit Scope and
`-y`, includes only hosts independently present in current public DNS, withholds private or
reserved answers, and then routes the targets through the same bounded campaign and per-request
scope checks described above. Use `--max-hosts` to control the DNS-validation budget (25 by
default, hard-capped at 100). `gn campaign --osint` is the lighter alternative: it opts the
existing recon crawl into crt.sh seeding while retaining the normal page and request caps.

The OSINT input checks are format and boundary checks, not organization filtering: commercial,
nonprofit, and non-U.S. domains are accepted. Entity-specific policy restrictions are limited to
explicitly selected U.S. federal VDP profiles (currently NASA); a `.gov` domain or organization name
does not silently activate a profile. Authorization, scope, private-address, rate, and evidence gates
remain universal because they prevent false attribution and out-of-scope traffic.

## 4. Reading results

The **Findings** board shows every finding with a proof-status pill:

- **Confirmed** — GreyIQ proved it with an actual benign probe (a real differential, a real
  out-of-band callback, a real timing signature) — not a pattern match.
- **Candidate** — a plausible lead the passive/static side surfaced, not yet actively proven.

Click any row for the evidence pane: the captured request/response, the differential that
proved it, CVSS, CWE/OWASP mapping, remediation guidance, and (when available) a proof
screenshot.

## 5. Reports & submission

Confirmed (and reportable candidate) findings appear in the **Submissions** tab:

- **Copy report** / **Download .md** — a self-contained, submission-ready Markdown package,
  reshaped per platform (HackerOne, YesWeHack, Bugcrowd, Intigriti, **HackenProof** — pick the
  format at the top of the tab). HackenProof's format leads with Target + Vulnerability category
  and uses its four-band Critical–Low severity (web/mobile and smart-contract classes).
- **Submit to HackerOne** — the one place GreyIQ pushes a report over the network on your
  behalf. It's hard-gated: only enabled once proof status is Confirmed *and* your HackerOne
  creds are saved, requires an explicit confirmation dialog, and the server independently
  re-checks the confirmed status (a forged client request can't push an unproven finding).
  Every other platform — including HackenProof — is **export-only**: HackenProof publishes no
  researcher API for scope, submission, or metrics (its programmatic surface is a triage-side
  MCP server, not a hunter API), so GreyIQ formats the report and you submit it on the
  platform's own dashboard.
- **Download everything (.zip)** — the whole engagement folder (reports, JSON sidecars,
  screenshots, per-finding packages) as one archive.

## Safety model, summarized

- **Scope-bound, fail-closed everywhere.** A host not named in Scope (or, now, a program's
  own in-scope structured-scope table) is never probed — this is checked server-side on
  every request, including every redirect hop, not just trusted from the UI.
- **GET-only by default.** Active checks default to safe, idempotent, benign requests. A
  few opt-in checks (time-based SQLi, blind XXE/stored-XSS auto-send) can send a single
  bounded non-GET request, always explicitly opted into per-call.
- **Egress is deliberately narrow.** Everything talks to your authorized target, except:
  the HackerOne report submission (`api.hackerone.com`, write, hard-gated, manual), the
  HackerOne scope import described above (`api.hackerone.com`, read-only, manual), optional
  repo-draft enrichment (`api.github.com` or `gitlab.com`, unauthenticated read-only, one GET
  per repository, explicit click only), an
  optional certificate-transparency lookup for subdomain seeding (`crt.sh`, read-only), the
  explicit local OSINT command (`crt.sh`, Cert Spotter, Google DNS, and Cloudflare DNS;
  read-only public-index queries), and
  polling your own OOB collaborator server (a host you configured). Nothing else leaves the
  machine.
- **Nothing auto-submits without you arming it.** The Operator's auto-submit is
  quadruple-gated (explicitly armed + per-program opt-in + server-recomputed confirmed proof
  + a daily cap), and the kill switch stops the whole loop immediately.
