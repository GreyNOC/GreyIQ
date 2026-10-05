# Changelog

Notable changes to GreyIQ.

## v4.7.0 - Hugging Face GGUF models in the local brain

- Import compatible Hugging Face GGUF repositories into GreyIQ's local Ollama model library.
- Select an imported model as the local coding brain for chat and agent work. Model retrieval is
  operator initiated, and inference runs through the local Ollama runtime.

## v4.6.0 - the investigation queue, in the app

### The lead queue is readable in the cockpit, and reachable at all

The **Download leads (.md)** button shipped in v4.2.1 was documented as being in the Hunt cockpit.
It was not. It lives in the AI Studio surface (`#panelSecurity`, inside `.app-shell`), and
`body[data-app-mode="hunt"] .app-shell { display: none }` with `appMode: "hunt"` as the default -
so an operator who works in the cockpit, which is where a hunt is actually launched, could not
reach it at all. README and CHANGELOG both asserted otherwise; both are corrected.

The cockpit's export row now carries a **Leads** button that renders the queue *in the app*: each
lead with its status, severity, confidence, the gaps still open, anything the engine says
contradicts it, which chains it participates in, and - the line an operator actually acts on - the
exact artifact that would confirm it. Untested chain leads render in their own section, labelled as
probes rather than results. The same panel still downloads the Markdown brief.

`export_leads` now returns the structured `report` alongside `markdown`. It was already building
that object and discarding it, which is why the in-app operator had a file download and no way to
READ the queue while the CLI had `--json`. This cannot widen what crosses the API boundary: the
brief is *rendered from* this same object, so anything reachable in `report` was already reachable
in `markdown` - and the redaction tests now assert against both.

No `/api/bounty/investigate` route was added. The endpoint half already exists as
`POST /api/bounty/leads`, and "investigate" is this codebase's established name for the per-finding
active re-probe drawer (`/api/bounty/finding/reverify`); a second route by that name would leave
two differently-shaped endpoints called the same thing.

## v4.5.0 - YesWeHack becomes a place you set a program up from, not just a report format

YesWeHack has been in the platform registry since the report formats landed, but only as an output
shape: you could render a finding for its form, and that was the whole relationship. Setting the
program up was still manual - retype the scope, retype the exclusions, and find the user-agent tag
the program requires somewhere in its rules. This release makes it a source. `From YesWeHack` in the
program wizard (and `Fetch scope from YesWeHack` in the form) pulls the program from
`api.yeswehack.com` and fills in the record.

**No credential is needed for a public program, and that is the default.** Verified against the live
API, not assumed: `GET /programs?page=N` and `GET /programs/{slug}` both answer 200 unauthenticated,
so the Submissions bar starts at *anonymous - public programs only* and the common case needs no
secret at all. Sign-in exists for private/invited programs and exchanges email+password (plus TOTP)
for a session token via `POST /login` / `POST /account/totp`; only the returned token is stored - the
password is never written to the secrets file, never logged, and never read back. A Personal Access
Token (`X-AUTH-TOKEN`) works too, for the manager-role accounts YesWeHack issues them to. The fetcher
carries the same posture as the HackerOne one: host-pinned, redirects captured rather than followed
so a credential cannot hop off-host, bounded reads, and a retry policy that never retries a
deterministic 401/403/404.

One fetch fills scope, out-of-scope, rules of engagement, qualifying and non-qualifying classes, the
per-tier reward grid, test-account instructions, VPN and source-IP constraints - and the marker.
**The marker is the part that makes the import worth having.** Most YesWeHack programs require a
per-program tag on the User-Agent of every request so they can attribute the traffic; GreyIQ already
had exactly that field (`portfolio.user_agent_suffix`, appended verbatim by
`web_ingest.set_ua_suffix`), so the import writes the program's own value straight into it and an
imported program is in-policy without further setup. A re-fetch never overwrites a marker or Notes
the operator has edited.

**An adversarial review caught a scope-safety bug before this shipped, and it is worth recording
because the tests had certified the broken behaviour.** YesWeHack's out-of-scope list is free text
that mixes real host patterns with prose, so the importer classified each line and stored the
host-shaped ones as exclusions. The classifier accepted `https://shop.acme.example/checkout` and
`api.acme.example:8443` - but both scope matchers (`campaign._target_host_excluded` and the
equivalent check in `active_verify_service`) parse the *candidate* host and compare the exclusion
token **verbatim**. A URL- or port-shaped token therefore matched nothing: the host stayed huntable
while the UI reported the exclusion as captured. Three of four exclusions in the reproduction were
inert, and the test suite asserted those two forms were "enforceable", so 54 green tests locked it
in. The fix normalises each line to the bare host token the matchers actually honour, at the
importer, where the data arrives - and the regression test now runs end-to-end through
`portfolio._normalize` into the real matcher rather than asserting on the classifier alone.

Two smaller decisions came out of the same review. **Exclusions are budgeted before in-scope rows**:
when the 500-entry cap has to drop something, losing an in-scope row costs an opportunity, while
losing an out-of-scope row would leave a forbidden host looking merely un-listed - so the cap now
drops in the direction that hunts less. And **a prose exclusion is never dropped silently**: a rule
the host matcher cannot enforce is surfaced in the fetch result and in Notes, because a count that
implied every exclusion was captured is worse than no count.

YesWeHack stays **export-only**. There is no researcher report-creation endpoint in YesWeHack's own
client or its Burp extension, so nothing here claims a submit path that does not exist; the one-click
API submit remains HackerOne-only and YesWeHack reports are filed on the platform.

This release also carries the **v4.4.1 changelog entry, which was published as a tag but never merged
to main** - `git diff v4.4.1 origin/main` was the version bump and that entry, and nothing else. The
entry is restored below so the history does not skip a shipped version.

**Six one-directional wiring gaps, where the engine computed something real and nothing collected
it.** This whole class is invisible at runtime: a response field the client never reads looks exactly
like a field the server never sent, and a route with no caller looks exactly like a route nobody
needs. Nothing errors, nothing logs, and the capability simply is not there.

Two were values thrown away on arrival. **`get_report_ready` rebuilds a runnable `replay.sh` and a
`findings.har`** for the finding being readied - from its captured crafted request, deliberately
without the confirmed-only filter the bundle path applies, because this is a preview of a finding
still being assembled. Both ride that one response and are never stored in the ledger, so the Report
Center dropped them and a history finding had no reproduction artifact at all. It now keeps them on
the record and offers each as a download, but only when it has one: the server returns `""`/`null`
when nothing was reconstructable, and an unconditional menu item would hand a triager an empty file
and call it a reproduction. **`/prove` returns the captured request/response artifact per result**
(`_compact_active` has carried `proof_evidence` since the Prove flow was built), and every call site
kept the observed/control prose and discarded the artifact. For a finding proven from the cached run
that was survivable - the engine persists the same artifact server-side - but a finding re-proven
from *history* has no cached run to read it back from, so the concrete headers a triager asks for
were gone. All three prove sites now fold it onto the finding and the campaign drawer's report sends
it. The selection also moved to the *class-matched* confirmed result - the one
`_persist_proof_of_impact` picks server-side - so the artifact belongs to the finding it is attached
to, rather than to whichever check happened to confirm first at the same URL.

Four were routes with nothing on the other end. **`/api/bounty/finding/restore`** existed while both
delete sites discarded the `dedup_key` the dismiss response returns - and that key is the only handle
on the suppression a delete records, because the server derives it when the caller has none. An
accidental delete was therefore permanent. Both sites keep it now and offer *Undo delete*, honestly:
restore is idempotent, so the bar distinguishes "restored" from "there was nothing to restore", and
it says that restoring lifts the suppression for future hunts rather than putting the row back on the
in-memory board. **`/api/oob/poll`** existed while *Mint callback URL* handed the operator a token
nothing could check; the blind provers poll their own tokens internally, but a payload pasted by hand
had no read-back at all. The OOB panel gets a poll control that Mint pre-fills. Worth more than it
was, now that the collaborator config reaches every hunt path and the four blind provers actually
run.

**`/api/workspace/rollback` was the orphan, but the wired route was the bug.** `/api/agent/undo`
wrote the pre-run text back over whatever was on disk, with no way to tell "still exactly what the
run wrote" from "the user has been working in this file for an hour since" - so an undo destroyed
work the agent had never touched. `workspace.rollback_changes` has always refused that case and
documented refusing it; the snapshot route had no fingerprint to refuse it with. The snapshot now
carries the sha256 of what the run last wrote, and restore skips any file matching neither that nor
the pre-run text, reporting it per-file instead of overwriting it. A file already put back one at a
time is not a conflict, and a snapshot written before the fingerprint existed still restores exactly
as it did. The same payload was also dropping `content_unavailable`, so the existing guard against
blanking a file whose original could not be read had never once fired in the real pipeline - its test
hand-built the entry the serializer omitted. The orphaned route is wired where it belongs: per-file
*Revert* in the Changes panel, the conservative sibling of an all-or-nothing undo.

**`/api/bounty/stored-xss-beacon` was unwireable by construction, and the fix is server-side.** It
took the OOB collaborator base and secret as *request* fields while `oob_config_status` returns only
`has_secret`, never the secret - so no client could ever fill them in, and making one able to would
mean weakening the boundary that keeps the secret server-side. Instead the route now reads the saved
config exactly as `oob-ssrf`, `oob-xxe`, mint and poll do, the two fields are gone from the request
model, and a client that sends them is ignored. With the secret never leaving the server, the panel
gets a form.

`backend/test_route_wiring_contracts.py` pins each seam in both directions - the client reads the
field, *and* every field the route returns is read by something, with the three deliberate exceptions
named and justified - because a producer with no consumer and a consumer with no producer fail
identically and silently. It also carries a register of the `/api` routes the app still does not
call, each with the reason, so a new orphan fails the gate rather than quietly never shipping - and
the register fails just as loudly when a route on it *becomes* wired, so it can only shrink by
someone looking at it. Every fix was verified non-vacuous by reverting it and watching its test go
red.

**And `npm run check` could not run in a Claude Code worktree at all.** `scripts/check-syntax.py`
matched its skip list against the *absolute* path's `.parts`, which carry every ancestor directory
name - so a checkout that merely LIVES under a directory named `.claude` / `dist` / `build` /
`release` / `runtime` skipped every file in itself, found zero modules, and exited on its own "the
walk is broken" guard. Every Claude Code worktree is `.claude/worktrees/<name>`, so the gate worked
in CI and refused to start on the machine doing the work. Matching relative to the repo root fixes
it and gives the same semantics as `check-syntax.mjs`, whose walk descends from the root and was
never affected; 305 modules compile clean where the gate previously would not begin. Two tests in
`test_ci_gate.py` had copied the same comparison and failed the same way, and the new test for it
runs the gate's real walk rather than asserting on its source - a source assertion would have passed
throughout.

## v4.4.1 - the shipped runtime moves to Electron 44.3.0

No GreyIQ source changed in this release. `git diff v4.4.0..HEAD` touches `package.json` and
`package-lock.json` and nothing else: the whole content is the Electron devDependency moving 44.0.0
to 44.3.0 (#175). That is still a change to what ships, which is why it gets a version rather than a
silent rebuild - electron-builder bundles the Electron runtime into both the portable and the
installer, so the binary a user runs is not the one v4.4.0 produced.

What the runtime gained across 44.1.0, 44.2.0 and 44.3.0:

- **Chromium 152.0.7977.65 to 152.0.7977.78, Node.js 24.19.0 to 24.20.0**, plus backported fixes from
  upstream Chromium, V8, ANGLE and Skia. This is the browser engine the cockpit renders in and the
  Node the main process runs on, so it is the part of the bump that carries the most weight.
- **An ASAR integrity violation now exits with code 1 instead of an access violation on Windows**
  (electron#53455). GreyIQ ships asar-packed, so this is the tamper-detection path failing as
  designed rather than crashing ambiguously.
- **No main-process crash after a large volume of renderer IPC** (electron#53417), and none when a
  file dialog is opened on a window that is closing at the same time (electron#53583). Both are
  reachable from ordinary cockpit use.

Most of the renderer hardening in 44.3.0 does not change GreyIQ's posture, and this entry does not
claim it: the window runs `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`,
`webSecurity: true` (`electron/main.cjs:519`) and enables no `<webview>`, so the `<webview>` popup
and `nodeIntegrationInWorker` subframe fixes have no surface here. The AppX/MSIX WebGPU/SwiftShader
fix in 44.1.0 does not apply either - GreyIQ ships portable and NSIS, not MSIX.

`npm audit` reports six advisories (one critical, five high). None reach the artifact: the production
dependency tree is empty, every advisory is transitive under `app-builder-lib` or `@electron/get`,
and `build.files` packages only `electron/**/*` and `package.json`. That is build-machine exposure,
not shipped exposure, and it is recorded here so the distinction is on the record rather than
assumed.

## v4.4.0 - hunting what an unauthenticated attacker actually gets

A QA/QC pass over the hunt engine, its technique and its reporting, aimed at the two classes the
operator is judged on and the position a bounty hunt actually starts from: account takeover and
remote code execution, with no session. Two things came out of it. The engine could only ever prove
the *talkative* half of each class — the bug that echoes something back — and several checks it
already owned were unreachable in the hunt it runs most: one because it needed a credential the hunt
does not have, the rest because the request budget ran out before the suite reached them. Nothing
here relaxes an evidence rule:
`report._has_captured_artifact` remains the only thing that can call anything confirmed, and every
new probe is scope-bound, SSRF-guarded and governed exactly like the existing ones.

**The suite could not fit in its own budget, and position alone decided who starved.** Against a
one-parameter URL the landing fetch plus CORS, the three redirect probes and the three host-header
probes spend ten requests between them; the ceiling was twelve. Whatever was ordered last therefore
fired zero probes -- and what was ordered last included the only CRITICAL check in the suite. Two
fixes were tried and discarded before the right one, and both failures are worth recording.
Reordering the check up the list only MOVES the starvation: it starved reflected XSS instead, which
the end-to-end suite caught within a minute. A reserved one-parameter slot -- registering the check
twice, once early and once for the remaining parameters -- was worse, because one endpoint could then
report the same class twice: two CRITICAL findings for one bug, which is exactly what a triager
penalises. It also quietly took the two requests the fixed-budget re-verify path needed to reach XSS,
so a reproducible finding was scored unstable and its submission kept rendering "candidate".

The budget was the problem, so the budget is what changed -- MEASURED rather than estimated. A full
sweep costs 62 requests against a one-parameter URL, 90 against three, and 99 with the opt-in timing
probes on, so the per-pass default is 160. The per-host bucket has to hold not one pass but the whole
fan-out, since a hunt runs up to four ranked endpoints on one host through the SAME process-wide
bucket; it is 700. The refill rate moved with it: at the old 0.5/s a bucket that size took 23 minutes
to recover, and the shared governor lives as long as the process, so the next hunt against that host
would have drawn on a dead bucket. At 1.0/s it is still half the send rate the inter-request floor
permits, so the ceiling keeps binding. The opt-in iterative loop went to 400 for a related reason:
turn 0 deliberately takes the whole remaining allowance, so a total sized at one pass would have let
it take everything and the "iterative" loop would have degenerated into a single pass.

Politeness is unchanged where it matters, and still ENFORCED rather than promised: the 500 ms
inter-request floor and the token bucket are what bound a hunt, neither is relaxed for a real target,
and the out-of-band provers now draw on that same shared bucket instead of each opening a private one
-- the ceiling the settings called "process-wide" was really that number once per prover.

**Blind OS command injection now confirms out of band.** The prover could confirm command injection
two ways, and both need the target to hand something back: an echoed `$(expr 111 + 111)`, or a
response the injected `sleep` delays. Real unauthenticated RCE routinely does neither — the command
runs in a worker, a queue consumer or a log pipeline, and the HTTP response is a fast, identical 200.
`oob_service.confirm_blind_rce` closes that with the mechanism the collaborator already provides for
SSRF and XXE: a shell-wrapped callback URL, and a recorded hit as proof that request data reached a
command interpreter. It probes parameters *and* the three request headers that reach a shell without
any parameter having to exist, each header carrying its own token so a hit names the exact one.

The second control is the part that matters. The fresh-token control blind SSRF relies on proves only
that the callback happened *because of this probe* — not that a shell made it. An application that
fetches any URL it finds in a parameter (an unfurler, a webhook validator, a plain SSRF) calls home
for the wrapped value too, and reporting that as a CRITICAL RCE would be a fabricated severity. So
every probe is paired with a matched control on its own fresh token: the same callback URL as a bare
value, no shell metacharacters, sent *first* so it has had at least as long to land. If the bare
control is fetched as well the result is `url-fetch` and the operator is pointed at the blind-SSRF
prover; only a hit on the wrapped token with a silent bare control confirms execution. The payload is
also built to a budget rather than assumed to fit — `MAX_URL_LENGTH` rejects an over-long URL inside
`_Http.fetch`, and the sweep treats that as "skip this parameter", so a long collaborator hostname
would have disabled the whole probe in silence.

**JWT `jku`/`x5u` key-source injection is now provable, unauthenticated.** The three JWT checks all
attack the key the server already holds — forge `alg:none`, re-use the public key as an HMAC secret,
crack a weak secret offline. None covered the fourth and most direct route to takeover: telling the
verifier *where to get the key*. A server that resolves a key set named by the token it is verifying
will validate a token signed with the attacker's own key, which is any identity it likes.
`confirm_jwt_key_injection` repoints the header at a collaborator URL, carries the payload and
signature over verbatim, and treats the fetch as the finding. It is invisible in band by construction
— a server that fetches the URL and then rejects the token answers exactly like one that never
fetched — so out of band is the only place it is observable. The token used is the one the
application hands an *anonymous* visitor, which is what makes it a no-session probe; a target that
issues none is a clean no-op. It is scored for the fetch it proved (7.5) and not the takeover it
implies, with the remaining step named in the plan rather than assumed.

**A discovered token is replayed on the transport it arrived on.** `_extract_jwt_token` looks in
Set-Cookie first, and rightly so -- a cookie a site sets is its own session rather than something
echoed into a page -- but it returns the bare value, so every caller replayed it as
`Authorization: Bearer`. Against a cookie-session application that header is read by nothing, and the
cost differs per check while being bad in all of them: the forged token never reaches the verifier,
the corrupted-signature control comes back 200 because the server never looked at it, and the check
bails. The jku/x5u probe reported a clean "no callback" on a target that may well be vulnerable.

For the weak-secret check it was worse than a miss. Gating the discovered-token path on server
acceptance -- the fix that stops a docs sample being called a confirmed forgery -- only settles
anything if the forgery actually reaches the verifier, so a bearer replay turned that gate into a
false NEGATIVE on cookie sessions: a genuine weak-secret takeover stuck at candidate, unsubmittable.
`served_token_carrier` now returns the transport alongside the token, the cookie case rebuilds the
original Cookie header with every crumb the response set and swaps only the JWT one, and all four JWT
checks plus the out-of-band key-source probe take it. A token found in a body or a response header is
a bearer token and still replays as one.

**What separates command execution from an app that merely fetches URLs.** The blind-RCE probe's
entire severity rests on a matched control: the same callback URL, sent as a BARE value, must stay
silent. The first draft adjudicated that control with a single zero-delay read at the instant the
probe's hit appeared, while the probe itself had been given four reads across eight seconds. The
asymmetry ran the wrong way -- the probe value carries one callback per shell context and the control
carries one in total, so against any async fetcher the probe lands inside its window and the control
lands just after the single read it was granted. A 200 ms race decided a CVSS 9.8. The control now
gets the probe's full polling budget, and a FRESH bare control is re-sent and polled as well, which
also covers an app that only services the second request from a new IP and a fleet where the control
happened to land on a node without the fetcher. Either control answering means no RCE is claimed.

The callback's User-Agent is read now, too. The payload only ever runs curl or wget, so a hit whose
UA names an application HTTP client is evidence against the shell claim and downgrades it; an absent
or unrecognised UA still confirms, because the bare-URL control is the primary control and an egress
proxy may rewrite the header. That gate is deliberately local to this prover -- blind SSRF, XXE and
the JWT key-source probe are all *supposed* to be answered by an application client. And a sweep
where every token failed its pre-probe control now reports `not-probed` rather than `no-callback`:
nothing was sent, so "no callback observed" would be a false negative wearing the costume of a clean
result.

**A self-signed token is now tested without any infrastructure at all.** The jku/x5u probe above
needs a collaborator, and plenty of hunts run without one configured — so the same idea is also
covered in the ordinary pass, for the case where the attacker does not have to host anything: the key
travels *inside* the token. `_check_jwt_jwk_embedded` mints an RSA keypair, embeds the public half in
the forged token's `jwk` header, signs with the private half, and a verifier that trusts the embedded
key validates it. It reuses the alg:none scaffold exactly — the real token authenticates, a
corrupted-signature copy is REJECTED (so the server does verify, and a server that verifies nothing is
never credited to this check), and the self-signed copy is ACCEPTED with the same authenticated body.
The claims are carried over byte for byte: what is proven is that an attacker-chosen key is trusted,
never a privilege granted to ourselves.

**The politeness floor no longer applies to loopback.** Seating the full suite made every local E2E
pass spend up to 99 requests at the 500 ms inter-request floor, which turned one module of the test
suite from 67 s into 236 s. That floor exists to be gentle with somebody else's server — a target, a staging
box, a third party — and the machine the process is already running on is none of those. The token
bucket, which is the part that actually bounds what a host absorbs, is unchanged for every host
including loopback; only the pacing is dropped, and only where there is nobody to pace for. Matched as
a full dotted-quad, not a `127.` prefix, because `127.example.com` is a name anyone can register and a
pacing exemption should never be something an attacker can name for themselves.

**Three checks that could not fire, and two taxonomies that disagreed with themselves.**

- The offline HMAC crack reached its token only through an operator credential, so
  `_check_jwt_weak_secret` returned `None` before doing anything in every unauthenticated hunt — the
  exact hunt where an app handing an anonymous visitor an HS256 guest token signed with `secret` is
  worth catching, and where the crack costs zero requests. It now reads the token the target itself
  handed back, like its two siblings. Its live corroboration had to be tightened to match: on that
  path the baseline is not automatically authenticated, so a public page answering 200 to any
  `Authorization` header was narrated as the server accepting a forged token. A body-match gate alone
  did not fix it either: on a wholly public endpoint the two responses are identical precisely BECAUSE
  the server ignored both tokens, so it reported "was accepted, body match 100%" about a server that
  never looked. It now takes the same corrupted-signature control its two siblings take -- the copy
  with a broken signature must be REJECTED before any acceptance is narrated. The finding itself was
  always confirmed by the offline crack; it was the corroboration that was fabricated.

  Reaching a served token also changed what the finding may CLAIM. Cracking a string proves how that
  string was signed, never that this application trusts it -- and a docs page showing an example token
  cracks identically, because jwt.io's own sample is signed with `your-256-bit-secret`, which sits in
  the weak-secret list. So an operator-supplied credential, a live session by construction, stays
  confirmed on the crypto alone, while a token read out of the target's own response is a CANDIDATE
  until the server is shown to honour a token forged with that secret.
- The command-injection probe `break`ed its parameter loop on a transient network error while its own
  control `continue`d, so one reset on the first candidate discarded every remaining candidate.
- Nine classes name two CWEs because one rarely covers a class, and taxonomy routing read only the
  first. A program that enables CWE-94 but not CWE-78 matched nothing for a *confirmed* RCE, so the
  report filed with no machine-readable weakness and landed in the triage backlog. Both mapping
  functions now try each id in order, primary first.
- Bugcrowd's VRT parented RCE under Server Security Misconfiguration while the same file's other row
  and `taxonomy._CWE_TO_VRT` both put it under Server-Side Injection. That entry is the primary source
  for a Bugcrowd submission, so every RCE the engine filed there carried the wrong category.
- The one debug endpoint classed `rce` reported confirmed CRITICAL code execution on reachability
  alone. Unauthenticated Jolokia is a genuine critical and keeps its severity, but the check proves an
  exposed management port, not a running command, and the proof now says so — reporting reachability
  as demonstrated execution is the exact over-claim the evidence rule exists to prevent.

## v4.3.0 - the engine acts on what it worked out

GreyIQ has always been good at reaching a conclusion and bad at using it. Three places computed
exactly what should happen next and then wrote it into a report instead of doing it, and one loop
that was supposed to learn between turns had been reading the wrong input all along. This release is
about closing those edges. Nothing here relaxes an evidence rule: `report._has_captured_artifact` is
still the only thing that can call anything confirmed, every new probe goes through the same
scope-, SSRF- and governor-gated prover, and the two new request-spending behaviours are opt-in.

**The iterative loop was observing the wrong thing.** `meta['digest']` is built from a fetch of the
landing page, and the loop probes one URL, so the structure it re-read every turn was byte-identical
after the first. The deterministic re-planner's whole termination argument is "continue only when the
latest observation carries structure no earlier one did", so it fired immediately, and the LLM
re-planner was handed the same page three times. The loop could not see the error its own probe had
just raised, which meant the best it could do was reschedule the scan it had already run.
`digest_builder.build_probe_digest` now turns a differential pass into structure: the error families
the probes themselves provoked, which classes answered without confirming, and which are settled.
That is the only part of an observation that differs between turns against one URL. Both re-planners
read it, and the rules the LLM prompt has always stated in prose now execute deterministically -- an
error family a *probe* triggered promotes its injection class, and a class that answered but did not
confirm is promoted as the closest thing the pass produced to a lead. A confirmed class is never
re-promoted; that ground is settled.

**A steered turn now probes the hypothesis instead of the suite.** `class_priority` only ever
REORDERED the ~25 checks, so a turn that wanted "sqli on one new parameter" re-paid for clickjacking,
csrf, three JWT probes, two GraphQL probes, CORS, redirect, host-header and the rest -- extra turns
were largely a recomputation of turn 0. `verify_active` gains `only_classes`, which restricts. Turn 0
still runs the suite in full so recall is established before anything narrows, and the restriction
fails open twice over. Two limits on it are load-bearing and worth stating: a turn driven by new
*parameter* names is never restricted, because `class_priority` is an ordered ranking rather than a
membership set and an ordinary ranking can be entirely param-blind; and the restriction never
subtracts already-confirmed classes, because those ids come from the finding's impact vocabulary
while the filter matches check-suite tags, and the two collide on shared names.

**The cortex reasons about what to test, not only what was found.** It mapped each finding to exactly
one hypothesis and ranked by expected payoff, so a near-certain low outranked a maximally-uncertain
lead gating three chains -- while the lead brief promised to "favour the test that eliminates the most
hypothesis space" and nothing computed it. Ranking now includes expected information gain
(uncertainty, peaking at 50/100 and zero at either pole, times the chains resting on the lead), and it
steers leads only, because ranking captured evidence by how little is left to learn about it would
sink it in the queue. Alongside that: `build_probe_plan` states per unproven lead and per blocked
chain the exact `(endpoint, class)` that would change the verdict, restricted to classes the prover
can confirm and to locations already observed; `project_if_confirmed` names the chains a given lead
would complete; and a synthesis pass derives the theory a pile of individually-unremarkable rows
hides -- three routes sharing one weakness on one property is a control missing at the framework
layer, not three coincidences. Derived rows are routed to the probe queue, which already means "worth
testing" and never "found".

**One bounded re-plan wave now runs inside the hunt** (`GREYIQ_HUNT_REPLAN`, default off). After the
first active pass the cortex can name the unresolved lead worth chasing across *every* scanner's
findings, not just the seed URL the loop probes. The wave re-probes the top few through the same
prover, class-restricted, capped at three endpoints and eight requests, and stops on rate-limiting.
It sits before classification, attack planning and the QA gate, so what it captures flows through the
normal pipeline -- placing it after the final graph would have been easier and quietly wrong, since
those findings would have skipped every downgrade-only QA step the report depends on.

**The campaign path stops being the one mode that never learns.** Campaigns are how GreyIQ runs
unattended, and they had no cross-run memory at all. `run_bounty_hunt`'s drift and
negative-knowledge steering sit behind `extra_params is None and class_priority is None`, and a
campaign always supplies both — so every per-URL hunt skipped that branch, *and* the snapshot and
miss-recording at the end of it. The mode that hunts the same targets most often was re-testing
ground it had already proved inert and never noticing what had changed. It now reads cooled
`(endpoint, class)` pairs and downranks them, diffs its surface against the last run and hunts what
moved first, and writes both memories back. Recon is asked for observations (no extra request — the
shapes were already in memory and discarded).

Three honesty guards came with it, each of which the direct-hunt path already had and the first
draft of this did not. A miss is only learned from a campaign that finished its fan-out *and* whose
every per-URL active pass ran clean — a prover that was rate-limited or cut short never reached the
tail of its plan, so those pairs were not tested. Confirmations are banked unfiltered as they are
observed, because `consolidated` is later narrowed by dismissals and the VDP policy and deduped
across URLs on a location that collapses digits anywhere; without that a pair the prover *confirmed*
could be written down as a miss and eventually cool a route the engine has proved. And the drift
baseline records only *observed* parameter names, never the brain's hypotheses — a hypothesis is by
construction a name the target did not serve, so storing it would make the next run diff one run's
guesses against another's and report changes the site never made.

**A campaign's early targets now inform its later ones.** The fan-out ran one frozen plan against
every URL, so whatever the first target proved could not change where the budget went on the fifth —
a parallel repetition of a single guess rather than a sequence that learns. A class confirmed on one
URL now moves to the front of the priority for the URLs not yet hunted on the same registrable
domain. Same-property only, additive, ordering-only.

**A matched advisory now aims the prober.** The known-CVE fingerprint ran *after* every URL had been
hunted and produced only candidate findings — the richest targeting signal the engine derives,
arriving too late to influence a single request. It now runs before the fan-out (the same one GET,
just earlier, and its findings are still consolidated from that same result) and maps each matched
advisory's CWE to the class the prover can confirm for it, so an outdated jQuery is a concrete reason
to try reflected XSS on this host. The map is deliberately partial: ReDoS, prototype pollution and
SSRF have no prover check, so they are left out rather than mapped to something adjacent — steering
budget at a class that cannot confirm is waste dressed up as intelligence.

**Two thirds of what `gn train-brain` learns finally reaches a hunt.** The trainer distils a class
ranker, a parameter-name table and idor/privileged selectors, and promotes all three into
`hunt_ranker.json` -- but `Ranker.suggest_params` and `Ranker.select` had no caller outside the tests.
The offline planner now asks the learned table for parameter names first (the curated list still
follows, so recall cannot drop) and ORs the trained selectors into the access-control candidates, so a
program whose confirmed IDORs never matched the hand-written hints can teach the engine what its own
object endpoints look like. Endpoint *selection* under the probe cap stays rule-owned, as the ranker
seam's contract promises.

Three candidate optimisations were examined and deliberately not taken. Sharing one request budget
across the active fan-out looked like it was restoring a per-hunt ceiling, but the process-wide
per-host governor is the real ceiling and already binds; sharing would only let the first target
starve the rest. Caching repeated GETs in `_Http` would have broken the opt-in time-based probes,
which confirm on response *duration* -- a cached baseline returns instantly and could manufacture a
false confirmation. And reserving a share of the budget for the loop's steered turns is
self-defeating as the engine stands: `_Http` raises the same `_RateLimited` when a call exhausts its
own allotment as when the host governor throttles, so hitting the reduced cap is precisely what
makes the loop stop and strand the reserve -- while also cutting the tail of the check suite on the
only turn allowed to run it unrestricted. Turn 0 keeps the full budget until those two conditions
are distinguishable.

## v4.2.3 - the lead brief honours its own filters

`gn leads --brief` rendered every chain probe regardless of the filters it was given, and could not
select one at all:

- `--brief --status confirmed` still emitted every `untested` probe.
- `--brief --ref CP1` reported *"No leads found"* for a probe sitting in the queue, because `ref` was
  matched against findings only and probes carry their own id namespace (`CP*` / `CR*`).

Both are fixed. `_cmd_leads` applies the same predicate to `chain_probes` — it works on a probe
unchanged, since a probe carries `status`, has no `report_ready`, and has no confidence score, so a
`--min-confidence` floor correctly excludes an untested lead. `render_lead_brief` selects `ref` across
both collections, and `_render_probes` now takes the **already-selected** list instead of re-reading
`queue["chain_probes"]` — that second part is the structural fix, because re-reading the raw queue let
the brief contradict whatever filter it was handed no matter what the caller did upstream.

Introduced by the chain-probe section added in v4.2.2: a second lead type reached the brief without
the filtering being extended to it.

## v4.2.2 - three more review fixes

- **A credential in a non-URL target no longer reaches the download filename.** A source hunt names a
  local folder, so `urlparse(...).hostname` is empty and the filename fell back to the raw target -
  and the slugger only rewrites punctuation, so `ghp_...` survived it intact. The target is now
  scrubbed before slugging (a hostname is unaffected; a path stays recognisable).
- **The lead brief now includes untested chain probes.** `render_lead_brief` rendered only hypotheses
  and proven chains, so the brief was not the whole investigation queue it advertises. On a hunt whose
  findings are all inert, the signal-only and drift-reopened (`CR*`) leads can be the ONLY actionable
  rows in the file. They render in their own section, explicitly labelled as probes to run rather than
  results, with the `blocked_runs` age shown so a lead the surface may have just unblocked is visible.
- **A site-wide control loss re-enables every cooled pair.** `surface_drift._collapse` folds a
  host-wide change into ONE delta whose subject is prose (`"3 endpoint(s)"`), not a URL, so keying it
  as an endpoint produced an unmatched string. The `header.security-removed` / `cookie.flag-lost`
  triggers added in v4.2.1 therefore appeared to work while being inert in exactly the collapsed case
  - a protection coming off across the whole surface, the strongest reason to re-probe there is. A
  non-URL subject is now read as the host-wide change it is (`ALL_ENDPOINTS`), and suppression is
  skipped for that run. Erring toward probing more is the correct direction here: a false re-enable
  costs a little budget, a false suppression silently removes coverage.

## v4.2.1 - download the hunt's leads, and four review fixes

### Download leads (.md)

A **Download leads (.md)** button renders the finished hunt's whole investigation queue as ONE
Markdown brief - every lead with its evidence state, the contradictions against it, and the exact
artifact that would confirm it - ready to hand to an analyst or paste to a model. It is the in-app
face of `gn leads --brief`, built through the same redaction-safe bridge, and the new
`/api/bounty/leads` route resolves the sidecar from the **cached run id only**, so no
client-supplied path is ever read.

> **Correction (v4.6.0):** this entry originally said the button was in the Hunt cockpit beside
> *Copy report*. It was not — it shipped in the AI Studio surface, which is `display: none` in the
> cockpit's default hunt mode, so a cockpit-only operator could not reach it. v4.6.0 puts the queue
> in the cockpit for real, as a rendered view rather than only a download.

### Review fixes

- **Negative knowledge no longer learns from a truncated run.** The prover walks `probe_priority` in
  order and stops when its request budget is gone, so on a partial run the tail of the plan was never
  probed. Recording those as misses conflated "never executed" with "executed and inert" and would
  have systematically cooled exactly the endpoints that never got a fair chance. `record_hunt` now
  takes `complete` (default **False**) and records misses only when the run errored nowhere, was in
  scope, and was neither rate-limited nor skipped. Confirmations are still recorded either way -
  they only ever grant immunity.
- **The lead export no longer leaks operator-supplied metadata.** A hunt started against a signed URL
  or a callback carrying `?token=...` put that value verbatim into `target`/`scope`/`path`, which the
  JSON queue and the model-bound brief both rendered. All three now go through the scrubber like
  every other field. (Reproduced, then pinned by test.)
- **Proof equality is decided on the whole value, not a 2 kB prefix.** A full HTTP/HTML capture
  routinely shares thousands of characters of boilerplate before the record that differs, so the old
  prefix window could call a REAL differential identical and silently downgrade a confirmed finding
  to candidate.
- **`gn leads --brief` now honours `--status` / `--min-confidence`.** Filtering moved ahead of the
  render branch; it previously applied only to the JSON and terminal output.

## v4.2.0 - negative knowledge: the hunt stops re-testing inert ground

A hunt's probe budget is hard-capped (`offline_hunt._MAX_PRIORITY`) - the prover walks a ranked
`probe_priority` list in order and stops when the budget runs out. On a **re-scan** of a program that
budget was re-spent on the same `(endpoint, class)` pairs that were probed and produced nothing last
time, crowding out surface that had never been looked at. The engine had no memory of what did NOT
work.

New `bughunter/negative_knowledge.py` gives it one. A planned `(endpoint, class)` that did not
confirm is recorded as a **miss**; on the next run the cooled pairs are downranked so the budget
flows to fresh surface instead.

- **Endpoint-scoped, not class-scoped.** This deliberately complements
  `brain_techniques.learned_hunt_priors` (which nudges a whole vulnerability CLASS down after
  repeated misses program-wide) rather than duplicating it: a class that is dead on `/login` stays
  fully hunted on every other route. Endpoints are keyed `host/path` with numeric, hex and UUID
  segments collapsed, so `/order/1001` and `/order/2999` share one memory.
- **It cannot blind the hunt.** Every safeguard is tested: a pair needs 2 misses before it is even
  eligible; anything **ever confirmed is immunized permanently**; misses **decay after 45 days** and
  earn a fresh probe; a pair is **re-enabled the instant `surface_drift` reports its endpoint
  changed** (the "unless new evidence changes the situation" clause); suppression only **downranks**
  within an endpoint, dropping a row only when *every* class on it is cooled; and
  `GREYIQ_NO_NEGATIVE_KNOWLEDGE=1` turns the whole layer off.
- **Honest by construction.** A miss is derived only from the same `(plan, outcomes)` pair the hunt
  trace already records - no finer signal is invented than the engine actually observed. Recording
  and suppression are both best-effort and fail-closed, so this bookkeeping can never break a hunt.

## v4.1.0 - evidence integrity, and the lead bridge to Claude

Three changes that make GreyIQ better at *reasoning through* a hunt, not just recording one — and
close a real correctness hole on the path to a live submission.

### The confirm authority stops accepting a non-differential as proof

`report._has_captured_artifact` — the single "is there a real captured artifact?" gate the whole
engine defers to — accepted any proof whose `observed_result` and `control_result` were both merely
**non-empty**. It never checked the two actually **differ**. The investigation cortex, meanwhile,
was already flagging an identical observed/control pair as a *blocking* `non-differential-control`
contradiction. So one report could render `proof_status: confirmed` for a finding its own
Investigation section called `contradicted` — and because `submission.submit_to_hackerone` hard-gates
on exactly that `confirmed` status, a finding **with no established differential could pass the
HackerOne auto-submit gate**. Demonstrated by execution, not inspection.

- One shared predicate now decides it: `report.proof_is_non_differential` (normalize both sides —
  bounded, whitespace-collapsed, case-folded — then require they differ), used by BOTH the confirm
  gate and the cortex's `_same_observed_and_control`, so the two authorities can never part again.
- The check lives ONLY in the gate's final observed/control branch: the credential, JWT-replay and
  secret-hit confirmation routes are independent and are never vetoed by a stray identical pair.
- An identical pair is not a *failed* differential — an EMPTY pair (the honest default of every
  static/deterministic plan) still reads as "nothing captured", never as "identical", so the entire
  source-scanning profile (a static SQLi is Critical from its class template alone) is untouched.
- The API-side mirrors (`has_differential` on the client-proof overlay, `has_poi` in
  `get_report_ready`) and the client POI dot in `public/app.js` share the same normalized-difference
  test, so the badge, the VDP gate, and the rendered `proof_status` can no longer disagree.

### QAQC gate: class-general claim-integrity checks

`report.qa_validate_report` only ever fired on `cors`/`disclosure` findings. It now records two
**informational, every-class** checks — "do observed and control actually differ?" and "does a
claimed `confirmed` proof have a captured artifact?" — surfacing in the report's audit section the
silent `candidate` downgrade the renderer already applied. Gated on what a finding *claims*, never on
artifact *absence*, so a static lead (which claims nothing) is never touched.

### `gn leads` — hand a hunt's investigation queue to an analyst or a Claude brain

A finished hunt's evidence graph — ranked hypotheses, ordered attack chains, untested chain probes,
contradictions, and the exact proof obligation for each lead — previously lived only *inside* a
rendered report. The new `bughunter.leads` module and `gn leads <path>` command export it as a
stable, **redaction-safe** lead queue (`greyiq-lead-queue-v1`): each lead carries its own evidence
state, the contradictions that cite it, and the chains it participates in, inline. `--json` emits the
machine queue; `--brief` renders a Markdown investigation brief wrapped as untrusted data, ready to
hand to a configured Claude brain; `--status` / `--ref` / `--min-confidence` filter it; and a
directory argument sweeps a whole engagement's `targets/` tree.

- Built from a strict field **allowlist**, never a denylist over the raw finding — `build_json`
  serializes findings wholesale, so a denylist would leak `source_text`, `screenshot_path`, the
  `_credential_proof` carrier, or any raw field added later. Every free-text field is scrubbed with
  `redact_text`, `apply_secret_classification` is re-run on the loaded copy, and response bodies are
  never emitted (only the safe `sensitive_data_labels`). A planted credential in six different raw
  carriers is proven, by test, to reach neither the queue nor the brief.


## v4.0.0 - the Burp-style redesign, and the subsystem that never shipped

Two pieces of work were orphaned by the same collision on 2026-08-01, when the remote TACNOC
v2.6.0 release landed in the middle of a session. The session stashed its in-progress redesign to
merge cleanly, renumbered its own release v2.6.0 -> v2.7.0 to resolve the version clash, and ended
before finishing either. `main` then shipped a *different* v2.7.0, so the clash repeated silently.
Five releases went out without either piece. This release lands both.

### The visual redesign

Rebuilt on Burp Suite Professional: neutral charcoal greys carry the interface and ONE saturated
orange carries every interactive or selected signal. **Dark is the default** (#1c1f23 window,
#26292d panels, #ff6633); light is the option, and darkens the accent to #bf4508 so text on it
still clears AA. Semantic status (ok / warn / danger) stays separate from the accent so a
"running" state can never be misread as "healthy".

- **Square edges everywhere** - all 169 `border-radius` sites are 0, pills and status dots
  included. The `--radius-*` tokens remain (at 0) so a stray reference still resolves square.
- **Flat** - no gradients, no glows, no blurred drop shadows, no frosted translucency. Every
  surface that carried a shadow already had a 1px border, which is what separates it now. Focus
  becomes a crisp 2px accent ring.
- **One design, whole product** - the standalone PoC page that ships to platforms and the
  attack-plan map PNG inside the submission bundle wear the same palette. The map stays
  document-light, because a triager reads it as a document.
- **Contrast was measured in the running app, not assumed.** A new `--on-accent` token carries the
  ink for any saturated fill, because no single value works in both themes: white on #ff6633 is
  2.8:1, and charcoal ink on the light accent is ~4.0:1. Fixed along the way: dark `--coral` was
  failing both as a chip fill and as panel text; "Delete this bot" was danger-red *on* the orange
  button it inherits from (1.31:1); and a dark-theme override was beating the accent fill on
  background only, leaving dark ink on a dark wash at 1.13:1. Both themes, both app modes and all
  eight cockpit views now report zero contrast failures and zero non-zero radii.

### The offline brains, recovered

86 files and ~18k lines that five releases never saw. GreyIQ's no-brain path is what the shipped
build actually runs - `greyiq-backend.spec` hard-excludes PyTorch, so TinyGPT is not importable in
a release install. This makes that path a real agent across every domain we work in: hunting, red
team, wardriving, coding, and web apps. See `docs/offline-brains.md`.

#### Offline chat answers from curated playbooks instead of a canned sentence
- **The shipped app's offline chat was one hardcoded platitude.** With torch absent, `get_engine()`
  raised, `chat()` fell into its exception handler, and every message returned `fallback_reply` —
  the same sentence, forever. New **`solin_domain.py`** is a torch-free, stdlib-only extractive
  answerer over curated packs (`seed/domain/{bounty,webapp,redteam,wardrive,coding}.md`, 73 cards),
  routed **before** the engine and retried in the exception handler.
- It **quotes, never generates**: replies are a contiguous slice of a pack file plus a fixed opener
  and a `Source:` line. A test asserts the excerpt is a verbatim substring of its card — the
  mechanical guarantee that a 0.8M-parameter char model is not writing security advice.
- `webapp.md` is generated from `bughunter.bounty.VULN_CLASSES`, so chat and reports cannot drift.
- Bare class names (`SSRF`, `idor`, `prototype pollution`) reach the class explainer; tool questions
  reach the bundled catalog; greetings and off-domain questions fall through untouched.

#### Wardriving / RF survey analysis (new)
- **`gn wardrive <export>` and `wardrive -y <path>` in chat** — read-only posture assessment and
  rogue-AP triage over surveys you already captured: airodump-ng CSV, WiGLE CSV, Kismet netxml,
  Kismet CSV (alias-mapped), and Windows `netsh wlan show networks mode=bssid`. Four formats
  normalize onto one vocabulary and merge by BSSID.
- Findings for WEP/WPA1-TKIP/open networks, evil-twin and rogue-AP candidates, WPS, PMF, hidden and
  default SSIDs, probe-request (PNL) exposure, non-randomized client MACs, and channel congestion.
- **No transmission, ever** — no monitor-mode control, no handshake capture, no cracking, not even
  in remediation text. Enforced by a source-scan test over the package's own imports. `-y/--authorize`
  is required on both surfaces; a chat message is never authorization on its own.
- **"Undetermined" is a first-class answer.** Capability facts carry provenance and are discarded if
  the observing format cannot see them, so an airodump-only survey yields **zero** WPS and **zero**
  PMF findings and says why — rendered above the findings so it can never read as a clean bill of
  health. Merge order can never change a verdict, and a finding cites the export that observed the
  fact, not the merge survivor.

#### The offline hunt brain
- **Class vocabulary 10 → 18**, derived from the prover's own check list via new
  `bughunter/prover_classes.py`. `jwt`, `graphql`, `debug`, `websocket`, `sensitive`,
  `cloud-exposure`, `csrf`, and `clickjacking` were structurally unreachable from the no-brain path;
  a test parses the prover's source with `ast` so the two can never drift again.
- **Learned ranker (distillation Phases 1–3)** — `hunt_features.py`, `hunt_model.py`, and
  `gn train-brain` train a pure-stdlib logistic ranker on your own `hunt_traces.jsonl`, and promote
  it **only if it beats the hand-tuned rules on a held-out split**. GreyIQ ships no pre-trained
  weights; `gn train-brain --show` states how many more rows are needed. The ranker may only
  *permute* an endpoint's existing candidates — a non-permutation is discarded.
- **The probe-priority cap no longer evicts high-signal endpoints.** The 20-row cap now ranks by
  class signal before truncating instead of keeping the first 20 discovered.
- **The deterministic offline re-plan loop** (`GREYIQ_HUNT_LOOP_OFFLINE`, opt-in) refines a plan from
  observed structure — JSON keys, form fields, error family, JWT shape, cookie flags — with no LLM.

#### The offline coder
- **It can now edit existing code**, not only create files: AST-validated ops (`add_import`,
  anchored insert, function wrap) in new `edit_ops.py`, applied through the agent's `ToolBox` so
  every write stays snapshotted and undoable. A Python result that does not re-parse leaves the file
  untouched. New `offline_repair.py` adds a bounded deterministic verify→repair loop.
- **28 new templates** for the stack we actually use — FastAPI, Flask, Express, pytest/unittest,
  Docker, docker-compose, GitHub Actions, CodeQL, Dependabot, pre-commit, nginx, systemd, PM2,
  Makefile, PowerShell/Pester — plus hunt-scope, detection-rule, and finding-report scaffolds.
  The regex if-chain became a declarative recipe registry.
- A test now iterates **every** recipe and asserts it fires on a phrasing from its own advertised
  label (9/36 were failing, including every framework route recipe and every dotted config filename).

#### Fixes
- **Seven `gn` verbs never ran in the shipped exe.** `platforms`, `bundle`, `takeover`, `cve`,
  `idor`, `bfla`, and `idor-probe` were registered in the parser but missing from the hand-maintained
  `CLI_COMMANDS` tuple, so `run_frozen.py` booted the API server instead of running them.
  `CLI_COMMANDS` is now derived from the parser and cannot drift.
- **Selecting the deterministic coder silently blinded the hunt.** `offline`/`deterministic` are real
  coder providers, so `coder_enabled()` was True for them — but they have no chat completion, so
  every LLM-prompt gate took the LLM branch into a guaranteed error and lost its offline fallback.
  New `coder.reasoning_brain_enabled()` draws the distinction; `hunt_brain.plan_hunt` returned an
  empty plan and `hunt_loop` started then died at turn 0.
- Offline chat no longer answers off-domain questions with a security playbook (an out-of-vocabulary
  token was scored *below* ordinary filler, inverting coverage; thresholds retuned against a
  measured 64-question fixture rather than by feel).
- A UTF-8 BOM no longer drops an entire airodump capture; a junction cycle no longer aborts a survey;
  one corrupt template no longer disables the whole offline coder; and the RF report no longer tells
  operators their English Windows is "localized" or points them at a runtime OUI override that was
  never wired up.

### Reconciling five releases of drift

The recovered branch forked before v2.7.0, so the merge was combines rather than picks: `hunt_loop`
keeps main's chain-aware steering *and* the branch's structural offline re-plan; `gn_cli` takes the
derived `CLI_COMMANDS`; `offline_coder` takes the recipe registry with main's bounded authorized
HTTP traffic client ported into it as a row. `_load_snippet` now states which seed wins - an
explicit `seed_dir` is authoritative, so a corrupt template disables that recipe instead of being
silently healed from the source tree and offered by a build that cannot render it.
`seed/domain/webapp.md` is generated from `bughunter.bounty.VULN_CLASSES` and was regenerated: v3.0.0
added `path-traversal`, and the drift guard caught it.

- electron 43.4.1 -> 44.0.0.

### Branding

The app wears the GreyNOC owl. It replaces the orb on the window/taskbar icon, the Windows
executable and the NSIS installer, and it replaces the globe *inside* the app -- boot splash,
chat header, cockpit sidebar, and the idle dashboard hero. In-app it is a traced SVG painted as a
CSS mask filled with `currentColor`, so one asset is legible on the charcoal sidebar and the light
one alike; an `<img>` cannot inherit `currentColor` and would have had to pick a theme and lose
contrast in the other. The `.ico` carries seven real frames so Windows picks per context. The boot
splash was also still painted in the pre-v4 blue-greys -- they are hardcoded rather than tokenised,
so the palette sweep never reached the first screen the app shows.

### What an adversarial review caught before release

Twenty claims were raised against this diff by independent finders and put to a three-skeptic
refutation panel; twelve survived and are fixed here. The ones worth naming:

- **The radius sweep ate three tokens.** The bulk rewrite matched the literal text
  `border-radius: var(--radius-card)` inside the very comment documenting the token, and ran past
  the comment's terminator to the next semicolon -- deleting `--radius-card` and sealing
  `--radius-pill`, `--radius` and `--glow` inside an unterminated comment. Invisible, because an
  undefined `var()` makes `border-radius` invalid-at-computed-value, which falls back to 0.
- **A path-traversal refusal was silently defeated** in the ported traffic-client recipe: an
  `or <default>` swallowed `_safe_rel`'s rejection, so a request naming `../../evil.py` wrote the
  default file instead of refusing. Half that recipe's trigger had also been dropped in the port.
- **Avatar initials broke for every pre-v4 bot.** Bot colours are persisted, so existing users kept
  the old dark palette under v4's new dark ink. Ink is now derived per bot from its own luminance.
- **The primary CTA failed in its default state** at 3.4:1, and the learned hunt ranker had
  train/serve feature skew that made its whole `form:*` namespace unreachable at inference.

- Also folded in from `main` while this was in flight: an unclosed snapshot file handle in
  `surface_drift`, and review fixes to the chat and `gn wardrive` output.

Suite: **2583 tests**, 3 skipped, green.

## v3.0.1 - chain-engine QAQC, observation provenance, surface-drift engine

A whole-subsystem audit of the attack-chain engine (71 adversarial agents; 49 defects confirmed
after refutation, 10 claims refuted and dropped) plus a new engine that gives the hunt a memory.

### Fabrications closed — the engine claimed things nobody observed

Each of these produced a **confirmed, report-ready** claim on evidence that did not support it.

- **A read-only file disclosure was reported as a PROVEN remote code execution.**
  `_check_path_traversal` tagged its finding `file-upload` (the 5th positional argument of
  `_finding` is the class hint), so the chain engine's upload-to-execution technique fired and
  produced `unauthenticated attacker → remote code execution`, status `proven`, with "package the
  chain as one report" as the next action. The finding also carried CWE-434 and an RCE-shaped
  CVSS vector for a confidentiality-only bug. The producer now tags `path-traversal` — a class
  that had **no producer at all**, which is why the honest `path-traversal-read → read.server-file`
  ladder was dead code — and it gains its own `VULN_CLASSES`, impact-model, remediation and
  reference entries. The technique now additionally requires an observed execution signal, so a
  future class re-tag cannot mint a terminal impact on its own.
- **GraphQL introspection was reported as a confirmed cross-tenant data read.** Schema disclosure
  observes no boundary being crossed, so it now grants only `disclose.identifier` — a lead for
  BOLA/BFLA, which is what the check's own docstring always called it. Paired with a real
  access-control finding it still reaches the object-read impact.
- **A correct CSRF implementation produced an account-takeover chain.** The chain engine refuses
  double-submit cookies (`csrftoken` MUST be JS-readable — that is the pattern), but the response
  digest builds its auth-cookie list on a deliberately wider pattern and fed the same signal
  family through a second, ungated door. One gate now guards both.
- **A stylesheet made an open-redirect lead into an account takeover.** `_AUTH_FLOW_RE` was an
  unanchored alternation run over the whole URL, so `reset` matched `/static/css/reset.css`. It is
  now segment-anchored, applied to the path only, and static assets are skipped.
- **Every site inflated "read another tenant's data" into "modify another tenant's data."**
  `set` matched inside `/assets/`, `add` inside `/address`, `edit` inside `/credit`. A path *name*
  is not an observation of a write, and anchoring does not rescue it (`/news/change-log`,
  `/pricing/add-ons`), so the heuristic is gone: an observed `POST`/`PUT`/`PATCH`/`DELETE` form
  method is now the only producer of that signal.
- **The attack-plan map stamped "✓ CONFIRMED" on any finding**, filled its "observed" box with a
  hardcoded sentence, and silently dropped the negative-control stage when none was captured —
  and that PNG ships inside the platform submission package. The map now delegates to the single
  confirm authority, renders `CANDIDATE — NOT YET CONFIRMED` with what remains to prove, and never
  omits the control stage.

### An observation is now bound to where it was made and what it describes

- **Cross-program contamination.** A campaign pools every target's signals into one graph, and a
  signal carried no host — so one company's missing `HttpOnly` composed into another company's
  confirmed XSS and was reported as an account takeover whose second step is *physically
  impossible* on that target, with nothing in the rendered step naming the other host. Signals now
  carry their observation host and may only escalate a chain inside the same registrable domain.
  Sibling subdomains are deliberately exempt — domain-scoped cookies really do cross them, and
  that composition is the campaign's whole payoff — and IP literals are compared exactly, never
  through the registrable-domain heuristic.
- **Ref renumbering silently deleted every credential chain a campaign existed to build.** Display
  refs are renumbered when findings are pooled (`F1` → `C7` → `C31`) while the signals kept the ref
  they were stamped with, so provenance matched nothing and discarded every cross-target witness.
  Provenance is now keyed on a content-derived finding identity that survives every re-key.
- Rendered chain steps now name the host an observation came from — the one fact a reader needs to
  catch a bad composition by reading the report.

### The search stopped being biased by table position

- `_enumerate_paths` shared one expansion budget across a depth-first walk, so the **first edge's
  subtree consumed the entire allowance** — instrumented on a routine 13-class hunt, the set of
  root edges ever expanded was literally `[0]`, and every witness whose techniques sat late in the
  table was lost. Splitting the budget per root does not fix it (measured: byte-identical output),
  because the bias is recursive. It now uses **iterative deepening**, which also matches how the
  engine ranks: short witnesses score higher, so the budget goes to the chains most likely to be
  reported.
- A **fully proven chain was discarded before the proven-first sort could see it**: the per-impact
  bucket ranked on score alone while the final sort ranked on proof. Both keys now rank by proof
  band first.
- Two candidates with the same technique sequence for one impact are the same attack, and were
  each taking a report slot; signal-only paths (which the cortex routes to the probe queue, not the
  report) were evicting chains built on captured evidence. Both fixed, the latter with its own
  budget so the planner still gets its leads.
- A **code-scanner file path was parsed as a hostname** (`backend/app/views.py` → host `backend`),
  so every multi-finding chain in a code audit paid the cross-host penalty that exists to say
  "these two may not even share a session".

### Coverage gaps closed

- Confirmed **cloud-exposure** findings (an anonymously listable bucket, an open Firebase store —
  the strongest cloud evidence the engine can capture) contributed **nothing** to any chain: the
  class hint that makes them legible in the report also took them out of the disclosure bucket
  that feeds the identifier ladder. They now have their own technique.
- **GraphQL introspection from the API-discovery path** was tagged `info-disclosure`, a class id no
  technique consumes and no alias mapped — while the active detector reported the identical
  vulnerability as `graphql`. Pure spelling drift; the producers now agree, with an alias kept for
  stored ledger rows.
- A **deserialization sink narrated itself as command injection**, because the reporting layer
  folds that category into class `rce` (correctly, for the platform weakness mapping). Techniques
  can now discriminate on the scanner category without changing the reported class.
- The `oob-confirms-blind` technique granted a capability no technique required and no impact
  listed, so the step was pruned out of every witness it appeared in — unreachable output that
  still cost an edge. Removed; a captured callback already earns `proven` through the confirm gate.

### Downgraded chains stopped inviting submissions

A chain whose every *step* captured an artifact, but whose cited *finding* the cortex would not
call confirmed, kept the engine's "every step is backed by a captured artifact — package the chain
as one report" as its closing line and in the action plan. The guard covered only the `blocked`
case. Both readiness paths now respect the downgrade. Cortex chain ids also moved to `AC*`: a
campaign refs its pooled findings `C1..Cn`, so a span report printed "chain C1 cites C1", naming
two unrelated things in one sentence.

### New: the surface-drift engine (`bughunter/surface_drift.py`)

Every other engine reasons about **one moment**; `OperatorLoop` re-runs campaigns on a cadence and
each cycle starts blind. So GreyIQ could not notice the highest-signal event in bug bounty:
**something changed**.

- Fingerprints each crawled URL's response **shape** from responses recon *already fetched* and
  currently discards, diffs each run against the last, and turns the deltas into ranked probe
  targets, a "What changed" phase in the action plan, and a **Surface drift** report section.
- **Re-opens blocked attack chains across time** — the payoff. `build_attack_chains` computes which
  step a chain is stuck on and which capability it was waiting for, then throws it away, so run N
  re-derives and re-blocks the identical chain even when run N's surface just started leaking
  exactly what it needed. Chains are keyed by *shape* (impact + technique ids), never by the
  rendered id, which is reassigned at every render.
- **Zero new requests, structurally**: the module issues no HTTP at all, so it has no method, host
  or URL of its own and the scope gate, SSRF guard, governor and request budget are untouched by
  construction. A contract test scans the source for every egress symbol.
- Honesty invariants, all contract-tested: a delta is never a finding and emits **no chain signal**
  (a statement that something *changed* is not a statement that anything is exploitable); a
  re-opened chain is a probe with `status: untested` that never inherits prior confidence; a first
  run reports `first-observation`, never "no changes detected"; a baseline covering less than half
  this run's surface is **refused rather than diffed**; absence is never evidence of a fix; decay is
  monotone; shapes are names, never values.
- Two things the naive version gets wrong, both found by driving a live target rather than by
  tests: hashing the body makes every run report that everything changed (it hashes the digest's
  name-only structure instead), and a site-wide change emitted one row per URL (a single dropped
  CSP header produced eighteen identical rows that buried the real changes; site-wide changes now
  collapse to one).

### Also

- The hunt loop's chain steering was dead: its own target URL was rejected by the plan allowlist
  whenever recon dropped the seed, and `_chain_focus` sliced the top 3 chains *before* filtering out
  the fully-proven ones — so on a productive hunt the steering window was always full of chains with
  nothing left to chase. The no-progress guard also never compared class priorities, so a model
  answering with the same JSON every turn re-ran byte-identical probes; and loop coverage reported
  only the final turn's request count.
- Chain context now travels with the submission body. `report_formats.render_finding` — the renderer
  that actually produces `vulnerability_information` for every platform — never rendered it, and the
  run cache dropped `investigation` before it got there, so the file pasted into HackerOne priced a
  finding as isolated while the report priced it as step 1 of an account takeover.
- The per-finding "Chain role" line dropped the step's own proven/projected marker, so a finding
  whose step was purely projected inherited another finding's credibility.
- A confirmed non-`_active_proof` route (JWT replay, live credential) left the plan's proof status
  stale at `candidate`, so the cortex recorded a contradiction against a finding the report
  confirmed.
- `digest_builder` was a stale twin of the hardened cookie parser: it substring-scanned the whole
  `Set-Cookie` header including the value, and treated `SameSite=None` — the explicit opt-*in* to
  cross-site sending — as protection.
- Test suite 2017 → 2100+, including contract tests for four documented invariants that were pinned
  so loosely that deleting the guard they describe left the suite green.

### Merged from main — OSINT harness, and a dependency CVE cleared

This release also carries the work that landed on `main` while the audit ran:

- Added a local-first `gn osint` campaign engine. It queries two certificate-transparency
  indexes and two independent DNS-over-HTTPS resolvers, retains timestamped source provenance
  for every claim, labels single-source and historical observations honestly, and writes a
  Markdown evidence brief plus a machine-readable JSON ledger.
- `gn osint <domain> --hunt --scope <scope> -y` hands only two-resolver, public-DNS-verified
  hosts to the existing bounded multi-target BugHunter campaign. OSINT never grants scope;
  authorization and the normal per-request scope checks remain mandatory. `gn campaign
  --osint` also exposes the existing opt-in CT recon expansion directly from the local CLI.
- The offline Workbench coder can scaffold a local authorized HTTP/C2 traffic simulator. It is
  deliberately transport-only: finite request count, bounded bodies/timeouts, attributable User-
  Agent, strict TLS with private-CA/mTLS options, no redirects, and no command polling, response
  execution, persistence, evasion, or TLS-disable switch.
- `cryptography` moves to `>=50.0,<51.0`, clearing **CVE-2026-69247** — the previous
  `<50.0` upper bound was itself what blocked the fix. Electron moves 43.2.0 -> 43.4.1.

## v2.9.0 - attack-chain engine, cookie findings demoted

### Attack-chain engine
- New `bughunter/attack_chain.py`: a forward-chaining **capability planner** that links
  findings and sub-finding clues into **ordered, multi-step attack chains**. It models what an
  attacker *holds* at each point (`exec.browser-script`, `read.session-token`,
  `identity.admin`, `net.internal`…), which technique each clue enables, and what that step
  grants — so the report answers "what can an attacker do with everything we found", not just
  "what is broken here". Every recorded path is reduced to its **minimal witness**, so a chain
  never lists a finding the attack does not actually use.
- This replaces the cortex's static class-pair recipe table, which could only say "these two
  classes co-occur" — it could not order the steps, state what the attacker holds between
  them, or use a clue that is not a finding at all.
- The engine **cannot confirm anything**. A step is `proven` only when the single confirm
  authority (`report._has_captured_artifact`, via `investigator.has_confirming_artifact`)
  already accepted that finding's evidence; a chain is `proven` only when *every* step is;
  confidence is the **weakest link**, never a mean (averaging is how a proven step carries an
  unproven one); and a not-fully-proven chain stays capped below the supported band so a long
  speculative chain can never out-rank a short captured one.
- A chain citing **no** finding is not a result — it is routed to `chain_probes` and rendered
  as "chain leads worth testing", keeping unobserved structure out of the findings narrative.
- Reports gain an **Attack chains** section: per chain, the attacker's starting position, the
  ordered step ladder (step, evidence, proven/projected, what it grants), and the one action
  that would close it. Guided next steps now name the blocking step of each open chain.

### Cookie flags are no longer findings
- **`web.cookie-insecure` and `web.cookie-no-httponly` are gone.** A missing
  `HttpOnly`/`Secure`/`SameSite` flag describes no attacker capability on its own — there is
  nothing to reproduce and nothing to impact — and it is the single largest source of
  auto-closed informational noise in a bounty queue.
- What a flag actually changes is the severity of *something else*, so the flags are now
  emitted as escalation **signals** and consumed by the chain engine: no `HttpOnly` is the
  step that turns a confirmed XSS into account takeover; no `SameSite` is what makes a CSRF
  request arrive with the session attached; a `Domain`-scoped (non-`__Host-`) session cookie
  is what makes a confirmed subdomain takeover reach the session. They reach the report only
  as a numbered step of a chain a real finding anchors, carrying that finding's proof and an
  explicit note that the flag alone is not a vulnerability. Only signals a chain actually
  consumed are surfaced.
- Net effect on a boring HTTPS site with sloppy cookie flags and nothing else broken: **no
  output at all**. With a confirmed XSS on the same site: one account-takeover chain in which
  the missing `HttpOnly` is step 2.
- A network-adjacent attacker is deliberately **not** a chain entry point. Making it one meant
  "session cookie without `Secure`" composed into an account-takeover chain by itself on every
  HTTPS site — the same unconditional cookie noise wearing a chain as a disguise. A network
  position must now be earned from observed evidence (mixed content, or a reachable
  plaintext endpoint).
- Signals carry cookie **names and flag facts only**, never a cookie value.

### The engines now chain together
- **Campaigns and portfolios build cross-target chains.** Per-target hunts each chained within
  one host; the roll-up runs the cortex over the pooled, re-keyed findings, so a chain whose
  steps live on different hosts becomes visible for the first time — a claimable subdomain on
  one host plus a parent-domain session cookie on another is an account takeover neither
  single-target hunt can see. `SPAN.md`/`PORTFOLIO.md` print only the genuinely cross-host
  chains, since same-host ones are already in that target's own report. Per-target proof
  verdicts are re-attached before the graph is built, or every finding a hunt confirmed would
  re-enter the roll-up as an unproven lead.
- **The iterative hunt loop is chain-aware**: each turn is told which chains are one captured
  artifact away from real impact, and aims the remaining request budget at closing one rather
  than at whatever class looks locally interesting.
- The coding agent's `investigate_code` brief renders the same ordered ladder.
- Passing `signals` to `build_investigation` now **merges** with surface- and digest-derived
  clues instead of replacing them; treating them as a replacement silently dropped half the
  chain graph the moment a caller supplied one.

## v2.8.0 - investigation cortex, removable brain keys

### Investigation cortex
- Added a deterministic, evidence-grounded investigation cortex shared by the coding
  agent, hunt planner/loop, and bounty reports. It calibrates confidence from typed
  artifacts, ranks proof-gathering hypotheses, flags contradictory evidence, and
  correlates bounded attack-chain leads without allowing model prose to confirm a bug.
- Agent mode gains the read-only `investigate_code` tool. It runs the existing static
  scanner within the workspace, returns ranked root-cause leads and next proof
  obligations, and explicitly strips raw credential values before results can reach a
  configured remote model.
- Hunt plans now carry an explicit evidence-required hypothesis queue, and iterative
  hunts return a final investigation snapshot alongside their request-budget metadata.
- Markdown reports gain an Investigation intelligence decision brief; JSON sidecars and
  the hunt API return the same complete machine-readable graph.
- New contract tests cover false confirmation from prose, non-differential controls,
  public-key severity inflation, chain correlation, report serialization, and coding-
  agent credential isolation.
- **The cortex no longer decides what counts as confirmation.** Pre-release adversarial
  review found it re-deriving the confirm rule instead of using the engine's authority, and
  the two had drifted: a passive web `proof_evidence` (request line + response status,
  which every header/cookie/disclosure finding carries) counted as a confirming artifact
  here but is deliberately refused by `report._has_captured_artifact`, because it proves a
  GET happened, not impact. A configured brain — or prompt-injected text echoed through one
  — could pair a claimed `status: confirmed` with one passive GET and make the delivered
  report print "confirmed / report-ready / 90-of-100" for a Low missing-header finding whose
  canonical proof status in the same report still read `candidate`. That is exactly the
  fabrication the gate exists to prevent. `investigator.has_confirming_artifact` now
  delegates to the single authority; an unbacked claim raises a blocking
  `confirmation-without-artifact` contradiction instead of a confirmation, and without an
  accepted artifact calibrated confidence is capped below the `supported` band (a
  missing-header finding scored 86/100 and read "supported" on the strength of a GET).
- Liveness alone no longer validates a credential: a live Google/Firebase **public client
  key** answering its own issuer is that key's expected behaviour, and was scoring an
  Informational finding at 98/100. It now requires the same strict classification the
  report gate requires, and a public key claimed as confirmed raises the classification
  conflict — which previously keyed off a severity the classifier forces down to info/low,
  so it could never fire on the mainline path.
- A malformed authority in a finding's location (`https://host]/x`, `http://[foo]/x`) raised
  out of `urlparse` at report-writing time and would have discarded a **completed** hunt's
  report; scope extraction now fails closed. A non-finite `score` from a model reply no
  longer empties the probe queue, and a synthesized hypothesis ref can no longer collide
  with an explicit one.
- The read-only claim for `investigate_code` is now asserted against the filesystem — a full
  run must leave the workspace byte-identical — and workspace escape is tested directly,
  replacing assertions that only read the tool's own description back.
- The graph is built from the same filtered finding set as the report body and JSON sidecar,
  so the ranked hypothesis queue can no longer cite an `F<n>` that was dropped as a
  false-positive secret or an unconfirmed JWT candidate and appears nowhere else.
- An iterative hunt returns two graphs — the loop's provisional snapshot and the
  authoritative one built at report time — so both now carry `stage` and `authoritative`
  markers instead of being indistinguishable in the same API response.
- A second adversarial pass over that fix found the confirm gate closed but the fix carrying
  its own costs, now also fixed. Unproven confidence is **rescaled** into the lead range
  rather than clipped at its ceiling: clipping gave every unproven lead the identical score,
  which flattened the ranked hypothesis queue into input order and ranked a missing header
  level with a captured stack trace — in the one situation ("nothing is confirmed yet, what
  do I chase?") the queue exists to answer.
- The chain layer honours the same rule as the node layer. A chain of pure leads was averaging
  its nodes and adding a same-scope bonus to land at `supported / 59`, above the ceiling none
  of its nodes could reach; it is now `candidate` and capped. A malformed URL no longer
  collapses to its scheme in scope extraction, which had handed unrelated findings a shared
  bogus "scope" and with it that bonus.
- Confirmation is read from the **same** proof carrier the gate is applied to, in the report's
  own precedence order, so a bare `confirmed` on one carrier cannot borrow a differential
  sitting on another. The cortex also reads the report's full proof vocabulary
  (`verified`/`proven`/`reproduced`), which it previously ignored — the mirror of the same
  drift, in the under-reporting direction.

### A stored brain API key can finally be removed
- A blank `api_key` in an update means "keep the stored one" — the UI never receives the
  key back, so without that rule saving any other brain setting would wipe it. That
  overload left **no way to express deletion**: the delete branch of the secrets store was
  unreachable for coder providers, so removing a key meant hand-editing
  `runtime/secrets.json`.
- An explicit `clear_api_key` sentinel in the provider block is that path. It is a command,
  not a setting (never stored), it is scoped to the provider that asked, and it **outranks
  an `api_key` sent alongside it** so a contradictory update fails safe — visibly no key
  beats silently keeping one the operator asked to delete. False-ish string flags
  (`"false"`, `"0"`, `"off"`) are read as "no", so a stringified flag cannot delete a key
  by accident.
- The brain panel grows a **Clear saved key** control, shown only once a key is actually
  stored and confirmed before it fires. Clearing refreshes just the key state, so it does
  not snap the provider dropdown back or discard unsaved field edits.

### Frontend assets stay grep-visible
- A single raw control byte makes ripgrep and grep classify a file as binary and skip it
  silently. `public/app.js` had picked up a raw NUL as a cache-key separator, which blinded
  every content search and grep-driven audit over the 11.8k-line frontend — git itself had
  the blob marked `-text`. A regression test now asserts `app.js`, `index.html` and
  `styles.css` carry no raw control bytes beyond tab/LF/CR and decode as UTF-8.

## v2.7.0 - per-brain reasoning, structured output, and an identity on the wire

### Brains
- **Per-brain reasoning profiles** (`backend/brain_profiles.py`). Every brain previously shared one
  model, one effort level and one token budget, so the hunt planner - which decides where an entire
  engagement points its probe budget - reasoned exactly as hard as the one-line impact narrator that
  runs once per finding. Profiles give `xhigh` to the hunt planner, the strategy dossier and the
  Workbench agent, and a deliberately cheap budget to the per-finding narrator. A profile is a
  DEFAULT, not an override: an explicit operator setting always wins, and any historical shipped
  default counts as "unset" so an upgraded install is never left pairing raised effort with the old
  ceiling.
- **Structured outputs.** The four JSON brains no longer scrape their reply out of model prose with
  three divergent parsers - a caller sets a JSON schema and the reply is constrained to match. The
  hunt planner's vulnerability-class enum is derived from `ACTIVE_CLASSES`, so the schema cannot
  drift from what the differential prover can actually confirm. This is a SHAPE guarantee only:
  every validator and the `brain_safety` sanitizer still own the untrusted content, and
  non-Anthropic providers keep the prose-scraping fallback unchanged.
- **Prompt caching** on the system prompt. The hunt planner alone re-sends up to 56k characters of
  technique playbooks per run; that prefix is now a cache breakpoint.
- Default model is now `claude-opus-5`, and `max_tokens` moves 8192 -> 16000 because that ceiling
  covers thinking as well as the reply.
- **A truncated or refused turn now raises instead of returning a partial string.** Returning a
  half-written attack plan or a clipped JSON object as a success was the worst available outcome.
- The **Workbench agent** had no effort or thinking configuration at all - the most agentic brain in
  the product ran on bare API defaults. It now matches the rest.
- The **strategy/research dossier had no system prompt**, so deep target research was being done by
  a model still told it was a coding assistant.
- The 400 fallback is now a ladder that drops one capability per rejection, so a model that rejects
  caching no longer also loses adaptive thinking. Effort is sent independently of thinking.

### Identity on the wire
- The default User-Agent read `GreyNOC-Slop-Detection/0.1` - a **different GreyNOC product** - so
  every in-scope request was misattributed. It is now derived from the single `_version` source, as
  is the web-scan UA that had drifted to `/0.1`.
- **All four headless-browser contexts that reach a target now send it.** They sent Chromium's own
  UA, so proof screenshots, the stored-XSS render, the live scan and the research-account login
  carried no researcher identity and no program marker. The local SVG rasterizer is deliberately
  excluded - it aborts every request and never touches the network.
- **A global researcher marker** (e.g. `h1-greynoc`) now rides every in-scope request, with a
  settings field, plus a per-run tag on the hunt form. `campaign.run_campaign` was previously the
  only setter in the entire product, so an ad-hoc hunt, a re-verify or a prover run identified
  nobody. Both fragments are control-character stripped and length-capped; the per-program suffix
  keeps its verbatim-append contract.

## v2.6.1 - honest brain failures, CVE-2026-69247

### Security
- `cryptography` moves to 50.x for **CVE-2026-69247**. The previous `<50.0` ceiling pinned the
  build to vulnerable 49.0.0 and failed the CI `pip-audit` gate on every run. `cryptography` is a
  bundled release dependency (RSA/RS256 signing that proves a leaked GCP service-account key is
  live), so the vulnerable copy was shipping inside the portable exe and the installer, not just
  failing CI. Verified: the hazmat primitives in use are unchanged, `test_credential_validation`
  53 passed, full suite identical on 50.0.0, `pip-audit -r requirements.txt` clean.

### Fixed
- A configured-but-failing Claude brain is no longer misreported as an absent one. The hunt's
  report enrichment returned the same "unused" result for both "nothing configured" and "Claude
  rejected the API key", so an auth failure, timeout, or 429 was announced to the operator as
  *"brain enrichment skipped (no brain configured)"* - pointing at the wrong problem. `_ask_brain`
  now records why it failed and the progress line distinguishes the two cases. The reason reaches
  only the live progress stream: `report.build_json` builds its brain block from an explicit
  allowlist, so it cannot enter a delivered report.
- The Workbench agent loop caught `anthropic.AuthenticationError` in its generic handler, so a
  rejected or expired key surfaced as a raw SDK 401 repr. It now raises the same actionable
  "Claude rejected the API key (authentication failed)" message the chat path already used, and
  gives `APIStatusError` the same treatment.

### Tests
- First coverage for the Anthropic provider path, which previously had none: the request shape
  (adaptive thinking plus `output_config.effort`, the 400-retry that drops them for older models,
  and that `temperature`/`top_p`/`top_k` are never sent - those return 400 on Opus 4.7+), the
  API-key round-trip including preserve-on-blank-resave and redaction to `has_api_key`, and the
  failure-reporting split. Suite 1877 -> 1893 passed.
## v2.6.0 - TACNOC launcher, shared brain techniques

Merges the `GreyNOC/AddTACNOC` line onto the v2.5.0 release. That branch was cut before
the v2.5.0 whole-app QAQC pass and self-labelled 2.5.2; this release carries both, so the
version moves to 2.6.0 rather than reusing a number from a line that never shipped.

### TACNOC
- The cockpit topbar gains a **TACNOC** action that opens the companion TACNOC
  (GreyNOC Belcher) intercepting-proxy workbench in its own hardened Electron process,
  keeping TACNOC's contextBridge and secret-store boundary intact.
- Discovery runs entirely in the main process: an explicit `GREYIQ_TACNOC_PATH` override,
  then bundled/installed/development layouts. No renderer-controlled path or command-line
  argument crosses IPC.
- Browser-only mode says so plainly instead of failing silently.
- `docs/tacnoc-integration.md` records the accepted design for making TACNOC a *baked-in*
  feature — headless project export for evidence plus a control channel where GreyIQ
  serves and TACNOC dials out — along with the at-rest crypto split that constrains it,
  and what was rejected and why. The launcher in this release is the first step, not the
  destination.

### Shared brain techniques
- New `backend/brain_techniques.py`: technique retrieval and outcome learning shared by the
  code and hunt brains. Stores are local, append-only JSONL, bounded, and secret-redacted;
  learning is best-effort and can never break a run.
- Reasoning stays separate from authority — a technique can suggest a procedure but cannot
  expand scope, manufacture proof, or execute a network action. Hunt suggestions still pass
  the scope-gated differential prover; code changes still pass the workspace sandbox and
  verification gate.
- Seed techniques: `adaptive-attack-chains` (evidence-gated chaining that learns from both
  confirmations and clean controls) and `frontier-code-workflow` (plan → evidence → change
  → verify → reflect).

### Security and hygiene
- **Removed a TACNOC engagement project from version control.**
  `Tiffanys-Co.gnbproj/{belcher.db,ca.pem,secrets.enc.json}` had been committed; that
  directory holds a project CA private key and data-encryption key, and its database stores
  host/URL/method metadata in cleartext. It is untracked and `*.gnbproj/` / `*.tacnocproj/`
  are now ignored. The commit that added it was never pushed, so the material never left
  the build machine — treat that project's CA as burned and regenerate it regardless.
- New `backend/test_electron_security.py` and `backend/test_tacnoc_launcher.py` lock the
  launcher's IPC contract: command selection stays in the main process, the renderer never
  supplies an executable or arguments, and the child is spawned with `stdio: 'ignore'`.
- `public/app.js` no longer contains a raw NUL byte (it had been written as a literal
  control character in a `.join()` delimiter instead of `\u0000`). Runtime behaviour is
  byte-identical, but `grep`/`ripgrep` classified the whole 11.6k-line file as binary and
  silently skipped it — every content search over the main frontend file returned nothing.

## v2.5.0 - whole-app QAQC: platform-aware reporting, cockpit & Workbench polish

A whole-app quality pass driven by a fan-out UX audit: 23 verified, user-facing defects
found and fixed across the bug-bounty cockpit, program setup, security panels, and the AI
Studio Workbench, plus the report/export flow made platform-aware end to end. Every fix is
locked in by a static frontend contract test.

### Report format now follows the program's platform (was silently HackerOne)
- Picking a saved program sets the export format from its platform, and a reload re-derives it
  from the restored program — so a Bugcrowd/YesWeHack/Intigriti/HackenProof program no longer
  silently exports a **HackerOne-shaped** report. A one-off run falls back to the HackerOne
  generic framing.
- **Export-only platforms get an export call-to-action, not a dead button.** For any non-HackerOne
  format (which has no researcher submit API here), the full-report and submission-row "Submit to
  HackerOne" control is replaced by "export above, then file on {platform}'s dashboard" — the
  action that actually works. HackerOne remains the only live-API submit.
- The findings-detail pane now shows which platform format its Copy/Download produce, so a report
  can't be handed to the wrong program by surprise.
- The submit gate reason references the **Submissions tab's** credentials bar (it was shared with
  the Report Center, where "the credentials bar below" pointed at nothing).

### Cockpit navigation, board, and tour
- The nav tab is now labelled **Program** to match the page heading, guide, and tour (was
  "Overview", the lone outlier a new user couldn't find).
- The live board is titled by run kind — **Hunt / Campaign / Portfolio dashboard** — so a plain
  single hunt isn't mislabelled "Campaign dashboard", with a note that a single hunt streams its
  findings when it completes.
- The **Single hunt** segment re-opens its live board when a run exists, mirroring Full campaign —
  no more one-way trip away from a running single hunt.
- The **Set up SSRF/OOB →** shortcut scrolls straight to (and focuses) the OOB panel instead of
  dropping you at the top of a six-form page.
- The guided tour's step titles no longer carry numbers that fought the "Step N of 8" counter, and
  the coding-brain step names the actual **Studio ↗** button instead of a phantom "Studio side".
- The Findings board's empty state points to the Report Center (findings are in-memory per session
  but durable in the ledger), so an empty board doesn't read as data loss.
- The new-program **HackerOne scope import** pre-checks for saved API credentials and offers a
  one-click jump to save them, instead of dead-ending on a fetch that can't work.

### Program setup and security panels
- Program **Save/Update** now checks the server result: a validation rejection is reported instead
  of a false "Saved." (both the Program-tab and Operator-tab editors).
- The two program editors now cross-link — scheduling/activation/auto-submit live on the Operator
  tab; structured scope/platform/account-access/IDOR/OOB live on the Program tab.
- The Pentest/OSINT **toolkit** and **bounty-profile** panels explain themselves when the local
  service is down (was a blank void), and a hunt won't POST an empty profile.
- The portfolio **Select all** toggle keeps an honest label (flips to "Deselect all" when
  everything is selected).
- Switching to a **one-off target** clears the previously-picked program's target, so a "fresh"
  one-off run can't silently reuse the prior program's host.

### AI Studio Workbench
- Enter is ignored while an IME candidate is composing (CJK), so confirming a candidate no longer
  sends a half-composed message.
- The workspace file tree skips redundant re-renders (a signature cache) — the ~600 ms poll during
  a streaming agent run no longer churns the DOM or steals focus from a browsed node — and the file
  search is debounced.
- Opening a file restores tree focus for keyboard/AT users, and the file-tree filter is session-only
  (a persisted filter no longer came back with an empty search box after reload).

### Coding brain and hunt engine (QA/QC)
- OpenAI-compatible coding-brain and agent requests now adapt through multiple sequential parameter
  incompatibilities (token-limit spelling and temperature) with bounded loop protection, so routed
  gateways no longer fail after fixing only the first rejected field.
- Direct active hunts retain per-endpoint veteran/brain priorities instead of flattening every route
  into one global budget order, and now apply stored learned priors on the standalone path as
  campaigns already did.
- Offline hunt plans use deterministic cold-start ordering, treat unseen learned classes as neutral
  rather than zero, and skip malformed model class rows without discarding later valid guidance.

## v2.4.1 - fix new-program wizard, all platforms selectable

- **Fix the new-program wizard rendering.** The v2.4.0 wizard reused CSS class names already
  owned by other components, so it inherited a `position: fixed` overlay and floated over the
  Hunt-setup sidebar instead of rendering in the main column. Three class-name collisions are
  now namespaced: the wizard container (`.ck-wizard` → `.ck-progwiz`, which the guided tour
  owns as a fixed overlay), the empty state (`.ck-empty` → `.ck-prog-empty`), and the repo
  preflight verdict (`.ck-preflight` → `.ck-rpf`, distinct from the submission-readiness panel).
- **Every report-format platform is selectable in the flow.** The program platform selector is
  now built from the platform registry (HackerOne, YesWeHack, Bugcrowd, Intigriti, HackenProof,
  plus Other/manual) instead of a hardcoded subset, and it preserves whichever platform an
  existing program is tagged with.

## v2.4.0 - gentle Program setup, repository preflight, HackenProof platform

### Program setup redesigned into a gentle, one-step-at-a-time flow
- The Program tab now rests as a calm list with a single **New program** button, and opens a
  guided **Start → Identify → Scope & save** wizard (pick how you start: repo link, HackerOne,
  or manual). The scattered repo-link bar, VDP-preset bar, and always-on giant form are gone;
  advanced fields (out-of-band, research accounts, IDOR pairs) are tucked under one disclosure.

### Repository preflight — no more doomed hunts
- A repository target is now checked for reachability **before** a hunt commits to it, via
  `git ls-remote` against the allowlisted forge (`POST /api/repos/preflight`). A typo'd, private,
  or missing repo is caught up front with an actionable message instead of failing deep in the
  clone. Clone failures no longer leak the local temp path or raw git plumbing to the UI. The
  launch-time check is best-effort: only a definitive negative (bad URL, not found, private)
  blocks a hunt — a transient/slow forge never refuses a run the operator asked for.

### HackenProof report-format platform (export-only)
- Adds **HackenProof** as a fifth submission format (web3: exchanges, protocols, smart contracts):
  its four-band Critical–Low severity and Target + Vulnerability category framing, an AI summary
  voice, a program platform selector, and a readiness checklist matching HackenProof's own form
  (no CWE requirement). HackenProof publishes no researcher API for scope/submission/metrics, so
  like YesWeHack/Bugcrowd/Intigriti it is export-only — GreyIQ formats the report and you submit
  it on the platform's dashboard.

## v2.3.0 - repository-link program onboarding

- Adds **Start from a repo link** to the Program tab: one or more validated public forge
  repository roots create an inactive, autonomous-operator-disabled draft in the existing
  review form, with cloning selected but repository scope deferred until the first Save.
- Adds optional, explicit **Enrich from forge (read-only)** metadata for GitHub and GitLab:
  one unauthenticated GET per repository, bounded and non-redirecting. Descriptions enrich
  Notes; homepage/web domains are returned only as unticked suggestions and never authorize scope.
- Keeps repeat creation idempotent and non-destructive by merging repository roots and notes
  without resetting established program scope, credentials, or operator settings.
- Documents the fixed forge API egress allowlist and adds regression coverage for invalid
  forge pages/credentials, zero-network Tier 1, candidate-host isolation, route dispatch,
  first-Save finalization, and frontend review-only affordances.
- Preserves acronym/mixed-case owner handles in the derived program name (OWASP/GitLab are
  kept verbatim instead of being flattened to "Owasp"/"Gitlab"), and documents the
  non-destructive idempotency-key collision behavior inline.

## v2.2.1 - release packaging correction

- Reissues the unchanged, fully validated v2.2.0 code as correctly versioned v2.2.1 Windows
  artifacts after GitHub's immutable-release policy prevented correction of asset filename casing.
- No hunt-engine, proof, reporting, submission, or cockpit behavior changed from v2.2.0.

## v2.2.0 - veteran hunt intelligence and professional cockpit

This release strengthens GreyIQ's complete finding lifecycle: deciding what to test, discovering
hidden attack surface, validating proof without overclaiming, packaging triager-ready evidence,
and operating the hunt through a focused professional workflow. Existing authorization, scope,
budget, VDP-policy, and submit gates remain enforced.

### Veteran hunt planning and source-map recon
- A deterministic offline planner ranks differential checks per endpoint from observed routes,
  parameters, forms, APIs, authentication signals, and stack semantics, so constrained request
  budgets reach likely high-impact classes without requiring an LLM.
- Ordered class priorities remain an actual ranking; duplicate-class checks and the safety-tuned
  unranked tail keep stable ordering.
- Recon inspects explicitly referenced, in-scope external source maps for hidden endpoints,
  parameters, sibling hosts, and redacted secrets, with pre/post-redirect scope gates and hard
  request, map, source-file, and content limits.

### Submission-proof QA/QC hardening
- Findings reach **Confirmed** only through an engine-trusted validator or a captured
  positive-vs-control differential. HTTP-looking notes and generic screenshots cannot overstate
  proof of impact or exploitability.
- Proof obligations are redacted with the other proof fields, preventing credentials echoed by a
  model or operator note from leaking into exported reports.
- Per-finding packages copy every referenced screenshot, preserve colliding basenames, omit broken
  links after failed copies, and namespace same-named evidence in engagement ZIPs.
- Test discovery is restricted to GreyIQ's backend suite so cached repositories and packaged
  dependencies cannot pollute local QA runs.

### Professional cockpit workflow
- The launch rail follows a clear Target/Scope -> Strategy -> Authorize/Launch flow with a dedicated
  scroll region, readiness guidance, and a clear non-overlapping launch action.
- Single-hunt, campaign, and portfolio modes show only relevant controls; portfolio runs cannot
  expose or reuse a single target's shared session credentials.
- Navigation, run modes, sortable findings, finding rows, and empty-state handoffs publish keyboard
  and assistive-technology semantics.
- The cockpit scales to phone widths: navigation compacts, structured scope rows stack, wide tables
  scroll within their panels, and page-level horizontal overflow is prevented.

### Maintenance
- Local HTTP fixtures now close their listener sockets deterministically, eliminating the remaining
  `ResourceWarning` noise from the QA suite.

## v2.1.0 — program repository hunts

A program's scope is rarely just its running app — bounty programs increasingly publish their
**source** too. This release lets a hunt cover that source alongside the live surface, as an
explicit, bounded, safe-by-default opt-in. Everything below is additive; the anti-overclaim
honesty invariants and the unbypassable submit gate are unchanged.

### Opt-in source-code hunts on a program's public repositories
- **Per-program opt-in** — a program can now carry `repository_urls` (public HTTPS repository
  roots) plus a `clone_repositories` flag that **defaults off**. Nothing is cloned until an
  operator explicitly turns it on and selects the repositories in the Program tab.
- **Repository-root only, strictly validated** — `is_supported_remote_git_url` accepts only a
  forge-allowlisted, public HTTPS **repository root**. Issue / pull-request / blob / tree / commit
  and other in-repository forge *pages* are rejected as non-clone targets, as are URLs carrying
  embedded credentials, a query, or a fragment. GitLab nested-group and sourcehut (`~user`)
  shapes are handled explicitly.
- **Additive to the existing scope, still bounded** — opted-in repositories join `seed_targets`
  (which still take precedence over derived web assets) so a program can hunt its **app and its
  source in the same span / portfolio / operator cycle**. Fan-out stays bounded
  (`_MAX_REPOSITORIES = 25`); a repository root imported as a structured-scope asset is never
  fetched as a web page — it is hunted only through the explicit opt-in.
- **Correct scanner routing** — target-kind inference now detects a cloneable repository *before*
  the generic http(s) branch (the old ordering classified every forge URL as a web page, leaving
  the remote-git scanner unreachable), and the hunt log honestly narrates the shallow single-branch
  clone and the adversarial source scan. `git_metadata` now rides along in scanner results.
- **Docs** — README security notes and the User Guide describe the opt-in shallow-clone-into-temp,
  scan, and remove-after flow, and the forge repository-root URL requirement.

### Maintenance
- Dev toolchain: bumped `electron` 43.0.0 → 43.1.0 (dev dependency; #145).

## v2.0.0 — the submission-ready release

A major version focused on the last mile: taking a confirmed finding **straight to HackerOne
(or any service)** and shipping a **POC bundle that contains every bit of evidence** — plus
matching leaps in the coding agent and the hunt's confirmation honesty. Everything below is
additive; the anti-overclaim honesty invariants (downgrade-only QA gate, captured-artifact
gating of "confirmed", VDP-policy withholding, and the unbypassable submit gate) are unchanged.

### Report straight to HackerOne — routed, field-perfect, one submit
The HackerOne API submit used to send five flat text attributes; a filed report landed with no
machine-readable weakness, no asset selected, and no evidence attached. It now files a **routed**
report behind the exact same hard gate (explicit confirm + server-recomputed
`proof_status == "confirmed"` + perms-store creds):
- **CWE → HackerOne weakness_id** — matched against the program's own enabled weakness list
  (`hackerone_import.fetch_weaknesses`, matched by `taxonomy.match_weakness_id`; no fragile
  hardcoded ids). The report lands weakness-set and routable.
- **In-scope asset routing** — the finding's host is matched to the program's imported
  `structured_scope_id` (now captured on import + persisted), so the H1 form's required Asset
  field is filled. An operator can override it from the new **asset picker**.
- **Evidence rides along** — proof screenshots, the attack-plan map, the request/response
  transcripts, `replay.sh`, and `findings.har` are uploaded as report **attachments**
  (best-effort and honestly reported — an upload failure never fails the submit; the files stay
  in the downloadable bundle).
- **Submission preflight** (`/api/bounty/finding/preflight`) — a per-platform required-field
  checklist (H1: asset+weakness; Bugcrowd: VRT+priority; Intigriti/YWH: endpoint+CVSS), a
  **probable-duplicate scan** against the program's disclosed reports (duplicate is the #1
  rejection reason), and the attachment count — all before you file.
- **CWE → Bugcrowd VRT** — a curated `taxonomy.cwe_to_vrt` map auto-fills the Bugcrowd
  submission's Bug-Type field instead of the old "(map to the closest VRT category)" placeholder.

### POC bundle — every bit of evidence, navigable and reproducible
- **`INDEX.md`** — a triager-facing "start here" map in every bundle: the finding table, what
  each artifact is, how to verify the chain of custody, and how to reproduce. Fingerprinted into
  the SHA-256 manifest like every other artifact.
- **Single-hunt parity** — a single finding's "Download bundle" now also ships the
  machine-replayable `replay.sh` + `findings.har` (previously campaign-only).
- **Runnable negative control** — `replay.sh` now annotates each request with the
  observed-vs-control differential, so a triager reproduces the *differential the report claims*,
  not just the positive request.

### Coding agent — robust multi-site edits
- **`multi_edit`** — apply several find/replace edits to one file atomically (all succeed and the
  file is written once, or the batch aborts with the file untouched), routed through the same
  snapshot/rollback machinery as every write.
- **`edit_file` `replace_all`** — replace every occurrence instead of requiring a unique match,
  retiring the top real-task failure mode of brittle single edits.

### Hunt — reproduction-stability
- **Stability re-verify** — the operator-triggered re-verify can now re-run the same scope-gated,
  budget-bounded, benign probe up to 3× and report how consistently each finding re-confirms
  (`stability: {passes, of, stable}`). A flaky WAF/timing false-positive won't confirm every pass.

### Deferred to a later 2.x (documented, not shipped)
Multi-platform *direct* submit transport (only HackerOne has a researcher create-report API),
autonomous mass-assignment/two-account-IDOR proving in the campaign loop (write-bearing — needs
live-target verification before it runs unattended), and agent `ask_user` suspend/resume.

## v1.8.8

### Desktop app + installer branded with the GreyNOC orb icon
The Windows portable/NSIS installer and the Linux AppImage previously shipped the stock Electron
icon — electron-builder found no icon in its build resources (`build/`) and the app window set none.
This release wires the **GreyNOC orb** everywhere a desktop build surfaces an icon (packaging/branding
only — no behavior changes):
- **Windows** — `build/icon.ico` (7 embedded sizes, 16→256px) becomes the portable exe, the
  `Setup.exe` installer, the uninstaller, the installed app exe, and the Start Menu + Desktop shortcut
  icons (nsis `installerIcon` / `uninstallerIcon` / `installerHeaderIcon`).
- **Linux** — `build/icon.png` (512×512) becomes the AppImage icon.
- **Runtime window** — `BrowserWindow` now sets a platform-aware `icon` (`electron/icon.{ico,png}`,
  bundled via the existing `electron/**/*` files glob), so the window, taskbar/dock, and `electron .`
  dev runs all show the orb. On packaged Windows the taskbar uses the exe's embedded icon.
- **Tooling** — `.gitignore` allow-lists `build/icon.{ico,png}` past the `build/*` rule;
  `.gitattributes` marks `*.ico` / `*.png` binary so EOL normalization can't corrupt them.

## v1.8.7

### Detection expansion — confirmed WebSocket cross-site hijacking (CSWSH)
Completes the safe detection additions with a new **active-confirmed** check (still no
exploitation/payloads/C2/evasion — the offensive core stays declined):
- **WebSocket CSWSH detector** — for a WebSocket endpoint (surfaced by the v1.8.5 miner), the active
  pass now sends **one benign RFC-6455 handshake** — a GET carrying the `Upgrade`/`Sec-WebSocket-*`
  headers and a reserved attacker (cross-site) `Origin` marker. **No WebSocket frame is ever sent and
  no body is read**, so a server holding the socket open never blocks the scan. It confirms *only* when
  the server returns `101 Switching Protocols` **and** a `Sec-WebSocket-Accept` equal to
  `base64(SHA1(the key we sent + the RFC-6455 GUID))` — that accept token is the offline-computable
  **cryptographic negative control**, so an unconditional/proxy 101 or a soft-404 can't produce a false
  positive. Reported as class `websocket` (CWE-284, low severity) with a browser-PoC follow-up
  checklist and a full impact model. The check is **path-gated** — it only spends a request on a
  WebSocket-shaped endpoint (`/ws`, `/socket.io`, `/cable`, …) or one whose landing response announced
  an upgrade (`426`/`Upgrade: websocket`), and runs late in the active pass, so it never preempts the
  request budget the high-value XSS/RCE/SQLi checks depend on. Registered in `bounty.VULN_CLASSES` and
  `impact_model` (impact narrative, remediation, references).

## v1.8.6

### Detection expansion — GraphQL operation surfacing + opt-in CT recon
Continuing the safe, benign-probe detection additions (still no exploitation/payloads/C2/evasion):
- **GraphQL operations surfaced** — introspection already fetched every type's fields, but the parser
  discarded them. It now names the actual **query and mutation operations** the schema exposes (e.g.
  `users`, `adminReport`, `deleteUser`) in the finding's disclosed-schema evidence, and folds those
  operation names into the probe surface as candidate leads — no extra request. Still candidate-grade.
- **Certificate-transparency recon (opt-in)** — a new `recon_osint_enabled` setting
  (`GREYIQ_RECON_OSINT`, **off by default**) seeds in-scope sibling hosts from the public CT logs
  (crt.sh) that no link or JS exposed. crt.sh is queried, never the target, and every returned host is
  scope-gated before it becomes a crawl target — so it only widens discovery *within* your scope.

## v1.8.5

### Detection expansion — WebSocket surface + more CVE fingerprints
Inspired by external tooling but rebuilt GreyIQ-native and kept strictly to the safe, authorized,
benign-probe model (no exploitation, payloads, C2, or evasion — those were deliberately excluded):
- **WebSocket endpoint discovery** — the served-JS miner now extracts `ws://`/`wss://` endpoints
  (explicit literals + `new WebSocket(...)` targets, relative ones resolved to the base host), each
  scope-gated like every other discovered host. Surfaced as a real-time-surface inventory (an
  endpoint's existence is not itself a finding).
- **More component CVEs** — added Prism and Marked to the passive front-end fingerprint/CVE table, plus
  jQuery CVE-2020-11022, so more outdated-dependency leads surface (candidate-grade, via `cve_service`).

## v1.8.4

### Offline coder — learns from real runs (Phase 1, move 5)
The Workbench now **distills** what the strong brains do into a corpus the offline coder can grow from:
every **successful, verify-passing** agent run driven by a real brain (Claude/Ollama) is recorded to an
append-only `edit_traces.jsonl` — the request intent, provider, selected skills, and the *structural
shape* of the diff (which files, what operation, size deltas). It records **structure only** (never file
content or a diff body), secret-redacted and fail-closed, and only real-brain verified runs (an offline
run is already a template). This is the coding sibling of the shipped bug-hunt `hunt_trace`; a later
mining step will cluster these shapes into new `seed/snippets/` templates so the offline path replays —
offline, at low compute — edit patterns a strong brain performed online. See
[docs/offline-coder-strategy.md](docs/offline-coder-strategy.md).

## v1.8.3

### Offline coder — retrieval-augmented, repo-specific scaffolds (Phase 1, move 3)
The deterministic offline coder now reads the repo to make its scaffolds fit the project instead of
emitting a generic snippet:
- **Framework-aware tests** — "add a test for `foo`" produces a **pytest** stub in a pytest repo
  (detected from `conftest.py` / `pytest.ini` / the dependency manifests) and a **unittest** stub
  otherwise; `repomap.search_repo` locates the target symbol so the stub's TODO points at the real file.
- **Stack-gated templates** — "add a route `/path`" scaffolds a Flask route **only** in a Flask repo;
  otherwise it honestly defers to a configured brain (and names the closest matching skill playbook).
- **New scaffolds** — "add a dockerfile" and "set up a CI workflow" generate a `Dockerfile` and a
  GitHub Actions workflow (with the test command matched to the repo's runner).
- Templates live in a new bundled `seed/snippets/` library (`{{slot}}` markers filled from the request
  + retrieval); a built-in fallback keeps it working in a stripped environment. Every generated file
  still flows through the snapshotted, verify-gated toolbox. See
  [docs/offline-coder-strategy.md](docs/offline-coder-strategy.md).

## v1.8.2

### Workbench agent — QA/QC hardening (the real Ollama/Claude code path)
From an audit of the code-writing path, six defects fixed (each with a regression test):
- **Prompt-injection surface closed** — repo-derived context (a hostile `package.json`'s script
  names, the repo map) is now framed as untrusted **data** in the agent's system prompt, not as
  trusted instructions.
- **Undo survives a mid-run failure** — a run that fails partway now still attaches (and persists) its
  rollback snapshot, so partial edits stay one-click undoable.
- **Rollback never destroys data** — a pre-existing file whose content couldn't be captured is left
  untouched (not deleted or blanked); `undo` keeps the snapshot when a restore hits an error so you
  can retry.
- **One agent run per workspace** — concurrent runs are rejected instead of racing on files and
  clobbering each other's snapshot.
- **All tool output is trust-wrapped** — `run_command` / `net_probe` results cross the same
  untrusted-data boundary as file reads.

### Offline coder — honest degradation instead of garbage (Phase 1)
The tiny offline model **cannot** write code (64-character context, no code in its training data), so:
- **Offline chat no longer fakes it** — a code-writing request with no brain configured now returns an
  honest "configure a Local (Ollama) or Claude brain and use the Workbench agent" message instead of
  emitting mangled output the quality gate would discard anyway.
- **A new deterministic offline coder** (`offline_coder.py`) gives no-brain agent runs a real
  fallback: it scaffolds test stubs and new files from templates through the agent's normal
  (snapshotted, verify-gated) toolbox, and honestly defers novel logic to a configured brain — rather
  than dead-ending. See [docs/offline-coder-strategy.md](docs/offline-coder-strategy.md) for the full
  plan (retrieval, verify→repair, and distilling real Claude/Ollama runs into reusable templates).

## v1.8.1

### Whole-app QA/QC — 33 verified defect fixes
A multi-agent QA/QC audit of the v1.8.0 codebase surfaced 35 adversarially-verified defects in
GreyIQ's own code; this release fixes 33, each with a regression test. (Two low-severity findings —
`redact_text` has no email pattern — were assessed as intended: a captured non-role email is the
proof-of-impact a CORS/sensitive-data finding must show, and secrets in it are still redacted.)

- **Auto-submit throttle honored** — `max_submits_per_day = 0` now actually pauses filing (was
  silently coerced to 3).
- **No dropped confirmations** — a passive *candidate* lead no longer marks itself "reported", so a
  later `--active` run's confirmed, payable finding is packaged instead of skipped as "already
  reported"; concurrent span targets can't double-package the same finding.
- **Crash hardening** — a crafted JWT/JWKS or deeply-nested JSON from a target can no longer
  `RecursionError`-crash the active pass, recon, the ledger, the OOB poller, or the API (now a clean
  400/skip).
- **Scope integrity** — GraphQL and OpenAPI discovery re-gate the post-redirect `final_url` (no false
  finding / leaked params from a rebound out-of-scope host).
- **Credential accuracy** — a live AWS key hitting STS clock-skew/throttling is reported inconclusive,
  not "dead".
- **Honest severity** — the pre-export QA "downgrade-only" cap now actually lowers the exported
  severity (no over-claim), and re-keys its audit refs after renumbering.
- **DNS-rebinding closed** — a Host-header allowlist blocks a rebound origin from stealing the
  loopback session token and driving `/api/*`.
- **Rate-limit correctness** — the per-host spacing no longer collapses under concurrent callers, and
  passive recon draws from a **separate** per-host token pool so a crawl can't starve the active prover.
- **Redaction** — JWTs are fully redacted (no longer truncated at the first dot); the hunt-trace log
  redacts its target field; plus smaller report/scanner/desktop/UI correctness fixes.

## v1.8.0

### Offline-brain distillation — Phase 0: hunt-trace training corpus
- **Every URL hunt is now recorded** to an append-only `hunt_traces.jsonl` under the runtime dir: the recon
  surface, the plan the brain produced from it, and what actually confirmed. This is the training corpus for
  a future learned, fully-offline hunt ranker that sharpens `offline_hunt.py` from real confirmations
  (see [docs/offline-hunt-brain-distillation.md](docs/offline-hunt-brain-distillation.md)).
- Wired into **both** hunt paths — the campaign engine and the standalone `run_bounty_hunt` (guarded so a
  campaign's per-URL sub-hunt never double-logs). New `hunt_trace.training_examples` lazily joins the ledger
  by `dedup_key` to backfill each finding's final stage/bounty, so a bounty landing weeks later is reflected
  without rewriting the log.
- **Privacy-preserving and safe by construction:** every stored URL runs through `redact_text` (secret values
  in `?token=`/`AKIA…`/`eyJ…` stripped; numeric/UUID path segments kept), fields are capped, the append is
  torn-line-durable, and a trace write is fail-closed — it can never break a hunt. It sits behind the
  unchanged plan-validation + prover gate, so it only ever records.
- **Visible via `gn traces`** (and `--json`): hunts logged, programs, outcome rows, confirmed rows.

### Whole-app QAQC hardening (precision + safety)
- **Active-prover confirm oracles.** A reflected `<svg/onload>` inside RCDATA/raw-text/HTML-comment context is
  now treated as inert (not a confirm-grade injection); the blind SQLi/RCE timing margin is clamped below a
  timeout-reduced delay so a real blind injection isn't silently missed.
- **JWT forgery is proven by a body differential** — a forged/`alg:none` token confirms a bypass only when it
  unlocks the *same authenticated content* the real token returns (a bare 2xx public page is no longer a
  false CRITICAL), plus an RS→HMAC algorithm-confusion control.
- **Recon re-gates the post-redirect `final_url`** — an in-scope `<script src>` that 302s to a public
  out-of-scope host is no longer mined (the fetch guard is SSRF-only, not scope).
- **API discovery** resolves/skips braced server-variable/template URLs, so a `{version}` URL is never handed
  to the prover.
- **Credential validation** keeps a Firebase project *number* out of the slug `project_id`, and leaves AWS
  `ASIA` temporary credentials inconclusive (no session token) rather than false-marking a live one dead.
- **One process-wide host rate governor** (`rate_limit.shared_governor`) so concurrent span/portfolio hunts on
  a host share a single token bucket — WAF/ban and avoid-DoS-policy safety.
- **RecursionError hardening** against hostile deeply-nested JSON, and redaction↔classify parity for keyed
  session/CSRF/OAuth/bearer values.
- **Backend log rotation** — the desktop app's backend log rolls to a single `.1` backup past 5 MB instead of
  growing unbounded.

## v1.7.0

### GreyNOC-minimalist UI — cool-grey NOC console
- **The whole app is restyled as a flat, monochrome instrument panel.** The warm off-white ground
  with teal + coral + violet + amber accents is replaced by cool neutral greys with a single
  desaturated steel signal (`#3a5560` light / `#8ea8ae` dark) used only for what's interactive —
  active nav, focus, and primary actions. Because the change is a retune of the shared design tokens
  in `public/styles.css`, it re-themes the cockpit, Report Center, and Studio together.
- **Color now means state.** Semantic status is kept separate and muted (up = green, warn = amber,
  down/critical = red); the engine-up service pill is green rather than the accent hue.
- **Flat and quiet.** Every decorative gradient (backgrounds, logo, card sheens) and glow (globe
  drop-shadows, status-dot halo, boot splash) is gone; hardcoded accent tints now follow the token.
  Card radius tightened to 9px, pills reserved for status chips. Dark remains the default theme.

## v1.6.0

### Report Center — honest POC readiness + no malformed replay artifacts
- **The "Get report ready" POC flag now reflects a real runnable reproduction.** It was hard-coded
  true, so every finding's POC dot read green regardless of whether a runnable artifact existed —
  unlike POI (observed-vs-control differential) and POE (captured request/response). `has_poc` now
  means a `replay.sh`/`findings.har` was rebuilt from a captured crafted request, or an
  operator/brain-supplied PoC is present. The report still always carries deterministic reproduction
  steps; those are guidance, not proof, so they no longer light the flag on their own. The
  not-yet-readied Report Center preview dot mirrors the same rule, so it never flips green→red the
  moment you click "Get report ready".
- **Stop emitting malformed `replay.sh` / `findings.har` for multi-step findings.** The artifact
  builders accepted any `request_line` whose token after the method merely started with `http`, so
  producers that emit a multi-step / placeholder *description* — mass-assignment/BFLA, broken-session,
  blind-XXE, stored-XSS, GraphQL introspection — were turned into unrunnable curls (a URL argument
  full of spaces and prose) and shipped into the campaign download bundle. A shared
  `bounty._single_url_target()` gate now requires a single absolute-URL target (no whitespace, no
  isolated `...` truncation ellipsis), so those produce no artifact. Genuinely runnable single-URL
  lines — including path-traversal payloads whose `....` dot runs are real, and inline XSS payloads —
  still replay.

## v1.5.0

### Session issuer-binding (authenticated-scan hardening) + dead-code removal
- **A reused research-account session is never replayed off its issuer.** A multi-target span logs
  into the program's research account once (at host `L`) and reuses that session for every in-scope
  target `T`. Because a session bound to `T` makes the same-site check `same_site(T, T)` trivially
  true, `L`'s login cookie was being attached to in-scope targets on **other registrable domains**
  that never issued it. The session now carries its **issuing host**, and `scan_auth.build_auth`
  attaches it to a target only when the target shares the issuer's registrable domain
  (`same_registrable_site` — registrable-domain wide, so a `login.acme.com` session still covers
  sibling `app.acme.com`, but strict across a domain boundary and across shared-hosting suffixes
  like `herokuapp.com`). Off the issuer's domain the target is hunted unauthenticated. Enforced at
  `run_bounty_hunt` and the reused-session access-control probes (IDOR/BFLA/mass-assignment/session).
  Impact was bounded (the operator's own session, in-scope hosts only), but it violated the stated
  "tokens are never replayed off their own issuer" invariant.
- **Dead-code removal (deletion-only).** Removed confirmed-unused backend code — `code_scanner/llm.py`
  and `sarif.py`, the unused `ledger` helpers, and the retired `web_ingest.fetch_website_text` cluster —
  each grep-verified dead with no importers or tests.

## v1.4.0

### Evidence-based CORS severity + sensitive-data capture engine (anti-overclaim)
- **CORS is no longer auto-High.** A reflected attacker `Origin` + `Access-Control-Allow-Credentials: true`
  now confirms a **server-side header misconfiguration** but is graded by evidence: **Medium** only when an
  authenticated endpoint returned a real 2xx body, **Low/Info** on a 404/403/204/redirect/unauthenticated/
  empty response. **High** requires a browser-hosted PoC that reads sensitive victim data cross-origin
  (`cross_origin_read_confirmed`) — the active prover reads same-site (curl-equivalent) and never claims it.
- **CVSS never asserts `C:H` without proof.** The CORS class vector dropped from `S:C/C:H` (High) to a
  `C:L` Low ceiling; the active prover attaches a per-finding evidence-based vector (Low/Medium) that is
  honored on confirmation instead of the old static class vector.
- **Sensitive-data capture engine.** `sensitive_data.classify` now also names CSRF/anti-forgery tokens,
  session identifiers, and OAuth/bearer tokens (classified on the **raw** body before redaction). When a
  captured readable body contains sensitive data it is saved, **redacted**, to a separate
  `evidence/sensitive-data/<ref>-sensitive-data.txt` in the PoC download and named on the report.
- **Honest wording.** Same-site captures are labelled "same-site (curl-equivalent) read; browser
  cross-origin read not yet proven" instead of "Demonstrated cross-origin read / attacker page exfiltrates".
- **Pre-export QA gate.** `report.qa_validate_report` runs before export and applies downgrade-only
  corrections (cap unproven High CORS to Medium, cap 404/redirect-only to Low, strip `C:H` with no sensitive
  read), surfaced in a new **"Pre-export QA (evidence vs claim)"** report section and the JSON `qa` block.
- See [docs/cors-report-logic.md](docs/cors-report-logic.md) for the full decision tree, severity/confidence
  rules, wording, QA checklist, and a rewritten honest 404-CORS example.

## v1.3.0

### Resizable sidebar + pick the target from a program's scope
- The left **sidebar is now resizable** — drag the divider at its right edge (or focus it and use the
  arrow keys; Shift for larger steps). The width is clamped to a sensible range, persists across
  reloads, and collapses out of the way on the mobile stacked layout.
- Once you pick a program, the **Target field becomes a dropdown of that program's in-scope targets**,
  so you choose from scope instead of typing (e.g. a program scoped to `tiktok.com` lists it directly).
  An **Other target…** option reveals the free-text input for anything off-list. The chosen scope target
  is preserved across reloads, and every run/report still reads the same underlying value.

## v1.2.0

### Program-first launch flow
- The sidebar **Hunt setup** is now a guided, program-first flow: **Program** is step 1 (an accented
  picker at the top), and the rest of the form (**Target & scope**, **Options**, Run) stays hidden until
  you pick a saved program — which auto-fills target + scope — or choose the new **One-off target** option
  to enter your own. The top bar shows a read-only Program indicator mirroring the choice.
- A hand-typed one-off target now persists across reloads (the setup no longer collapses back to step 1),
  and clearing the target to retype no longer yanks focus or hides the form.

### QA/QC pass — reliability, layout, and accessibility fixes
- **Report Center table** scrolls horizontally instead of clipping its right-hand columns (incl. the
  Actions button + kebab) off-screen on narrow viewports.
- The row **kebab menu** is now `position: fixed` and flips upward near the bottom of the list, so its
  items are never clipped by the scroll container; it closes on Escape (returning focus) and on scroll,
  and exposes `role="menu"`/`menuitem`.
- **Accessibility:** the run-type control exposes its selection via `aria-pressed` (not colour alone);
  popup triggers initialise `aria-expanded`.
- **Robustness:** the Saved-views loader guards against a corrupt (non-array) localStorage value; the
  per-finding status overlay is pruned on delete (bounded growth) without wiping a sibling finding's
  status; removed dead `.ck-rail` / `.ck-nav-5` CSS left over from the pre-redesign cockpit.

## v1.1.0

### Redesigned bug-bounty cockpit — sidebar + top-bar shell, Report Center as a data board
- The Hunt cockpit is rebuilt around a persistent **left sidebar** (glowing GreyNOC-IQ globe brand,
  single-column icon navigation, a collapsible **Hunt setup** panel that holds the launch form, and an
  Operator footer) and a slim **top bar** (Program picker + run-type control on the left; engine status,
  Guide me, Studio, theme, and an operator avatar on the right).
- The **Report Center** is now a proper board: five stat cards (Report ready / Confirmed / Submitted /
  Paid / Total findings), a filter toolbar (search + severity + proof + status + sort + **Saved views**),
  and a paginated table — **Severity · Title · Target · Status · Proof · Last updated · Actions** — at 25
  findings per page, with a per-row **Open report** / **Get report ready** action and a "…" overflow menu
  (copy / download .md / re-ready).
- New per-finding **Status** column (Confirmed / Candidate / Missing proof / Submitted / Paid) and a
  **Last updated** timestamp; **Saved views** persist filter presets locally; the search box keeps focus
  and keystrokes across a live refresh.
- One consistent dark design across every view: unified stat cards, filled severity pills (LOW now reads
  green), and the same card/table look everywhere. Responsive down to mobile. Design and layout only —
  every hunt, campaign, filter, theme, drawer, and report action behaves exactly as before.

## v1.0.0

### Global Report Center + live event stream
- A durable, app-wide **Report Center** over the cross-run finding ledger: every finding across every
  program, each with a **Get report ready** action that assembles proof-of-concept, proof-of-impact, and
  proof-of-evidence into a submission-ready report that stays synced and survives restarts.
- An app-wide **live event stream** (a lightweight ~2s poll — no SSE, so the API token header and CSP
  stay intact) that updates the cockpit as findings confirm or reports ready anywhere, with an
  auto-reconnect banner + amber engine pill when the local engine is briefly unreachable.
- Report assembly reports its own capped `proof_status`, so a forged confirm (observed result with no
  control) honestly caps to *candidate* instead of inflating to *confirmed*.

## v0.99.0

### Strict secret classification — stop over-reporting public API keys
- BugHunter no longer reports a **public frontend API key** (Google/Firebase `AIza…`, OAuth client id,
  Google Analytics / GTM id, Firebase web config, CDN/endpoint URL) as a **confirmed secret** or
  **High/Medium** severity without proof. A value appearing in page source is not a vulnerability, and a
  regex match is not a secret. A live Firebase browser key (a `getProjectConfig` 200) is the *expected*
  behaviour of a public key — not an exploit.
- Every exposed-key finding is now classified as one of **confirmed_secret** (a real, privileged secret
  proven usable — a validator-backed live server token, a committed private key / service-account JSON /
  `.env`, or a proven-open Firebase data store), **public_client_key** (browser-safe, informational),
  **candidate_unverified** (a regex match with no validation — not reportable yet), or **false_positive**
  (dead/revoked or a placeholder, hidden). Only a confirmed_secret may be Medium+.
- Findings carry structured **evidence fields** (classification, proof present/required, validation
  method, request/response evidence, impact proven, reportability, redacted secret) and the report says
  plainly when something is **"Informational only"** or **"Not reportable yet"** and exactly what proof
  is missing (domain/API restriction, unauthorized access, Firebase rules, billing abuse).
- Reports and the JSON output now **redact secrets everywhere** — the full key is never printed (only a
  safe prefix…suffix), including in the credential PoC and the structured findings sidecar.
- Applied on every surface: hunts, campaigns, the standalone web scan, the on-demand "View full report",
  and both the remote triage prompt and the offline local summary. Genuinely validated server tokens and
  real Firebase data-store exposure still confirm and keep their severity.

### Single hunt now runs on the live dashboard
- A **single Hunt** now drives the same **live dashboard** a full campaign does — you can watch it work
  instead of staring at a compact text log. The target appears as a work unit (queued → running → done),
  the activity log streams every step live, and its findings + severity tiles roll up on the dashboard,
  with the same click-to-investigate drawer (re-verify, "View full report") a campaign target has.
- Removed the old separate launch-rail progress log; both a single hunt and a campaign share one
  dashboard, and the empty state now invites a single Hunt, a Full campaign, or a Portfolio hunt.

## v0.97.0

### NASA mode — hunt strictly within a program's Vulnerability Disclosure Policy
- New **VDP policy profiles** bind a saved program to a published program's rules of engagement, so the
  full engine runs but only inside that program's authorized scope and reporting guidelines. The first
  profile is **NASA VDP** ("NASA mode"): its in-scope registered domains (nasa.gov, usgeo.gov, globe.gov,
  nspires.nasaprs.com, nsc.nasa.gov), the endpoints it won't accept (e.g. `/wp-json/wp/v2/users`,
  `xmlrpc.php`), the classes it rejects (non-sensitive clickjacking, missing-best-practice), **confirmed
  findings only** (NASA rejects automated-scan output without a demonstration of exploitability), and
  **no DoS / rate / spam** (time-based and deep probing are forced off for the program).
- One click in Program setup — **"Set up NASA VDP (NASA mode)"** — creates the program pre-scoped and
  policy-locked; the program row shows a **policy-locked** badge. A profile only ever *narrows* what is
  probed and reported; it authorizes nothing the engine's own scope/SSRF gates don't already, and it
  can never widen scope.
- Findings the policy won't accept are **withheld transparently** (an excluded endpoint, a rejected
  class, or anything without a captured proof of exploit under confirmed-only), and the count is shown
  in the run log — never silently dropped. Endpoints: `GET /api/operator/vdp-profiles`,
  `POST /api/operator/programs/preset`.
- The policy is enforced at **every delivery surface**, not just the campaign summary: the on-demand
  report builder (the "View full report" button on the live dashboard and in history) re-applies the
  program's rules, so a withheld finding can't be turned into a submittable report. Manual single-target
  runs against a policy-bound program apply its policy just like span runs do. Re-running the one-click
  preset is **non-destructive** — it never re-widens a scope you narrowed (e.g. down to a NASA test
  host); a profile can only ever narrow.

## v0.96.0

### Confirms sessions that stay valid after logout
- A new check proves a **session isn't destroyed on logout** — so a stolen or leaked session (from a
  proxy log, a shared device, an XSS exfil) keeps working even after the victim logs out. Give it an
  endpoint that shows your account's data, the logout endpoint, and that account's session: the engine
  confirms it end-to-end by authenticating, verifying an anonymous request is denied (so the endpoint
  is genuinely session-gated), logging out, then replaying the **same** session and showing it still
  returns your authenticated content. If logout properly kills the session, it's reported as enforced.
- Uses only your own session and your own logout; GET-only reads. Available in the access-control panel
  beside the IDOR, BFLA, and mass-assignment checks, and at `POST /api/bounty/session-invalidation`.

## v0.95.0

### Confirms mass assignment → privilege escalation
- A new check proves **mass assignment**: when an app lets a normal user set a field they should never
  control — like `is_admin`, `is_verified`, or `is_staff` — by just including it in an update request.
  Give it a JSON object your test account owns (e.g. `/api/users/me`) and that account's session, and
  the engine confirms it end-to-end: it reads the object, sends a client update flipping the privilege
  flag on, re-reads to prove the change actually persisted, and checks that an empty update *doesn't*
  flip it (so the escalation is genuinely caused by the value you set) — then **restores the flag**, so
  the test is benign and reversible.
- Only ever touches the object you own, stays in scope, flips a single boolean and puts it back, and
  attaches your session same-site only. Available from the access-control panel next to the IDOR and
  BFLA checks, and at `POST /api/bounty/mass-assignment`.

## v0.94.0

### Confirms JWT algorithm-confusion (RS256→HS256) token forgery
- Some servers verify their login tokens (JWTs) with a **public** key but can be tricked into treating
  a token as if it used a shared-secret algorithm — which lets anyone forge a valid token using that
  public key, and impersonate any user. The engine now **proves** this end-to-end and on its own: it
  fetches the target's own public key, forges a token with it, and confirms **critical** only when the
  forged token is accepted *and* a tampered-signature token is rejected (so the forgery working can
  only mean the bug is real — no false positives).
- Runs automatically on a token you supply or one the app itself hands out — no setup. GET-only, and it
  only ever sends the forged token back to the same in-scope target.
- Also sharpened the tamper-signature control used by both this and the existing "unsigned token"
  (`alg:none`) check, so it no longer occasionally misses a real bug.

## v0.93.0

### Confirms exposed database dumps and config backups
- The engine now proves a served **backup / database-dump / config-backup** the same rigorous way it
  already proves an exposed `.git`, `.env`, or `.aws/credentials`: it fetches the file and confirms
  only when the response carries the file's unmistakable contents (a real SQL dump header, secret
  key/value lines, or WordPress `DB_PASSWORD` definitions) **and** a non-existent control path does
  not — so a page that merely mentions those strings never triggers it. New: `/backup.sql`,
  `/dump.sql`, `/.env.bak`, `/.env.local`, and `/wp-config.php.bak`. GET-only, no false positives.

## v0.92.0

### Attack-plan map button on the full report
- The "View full report" page now has an **Attack plan map** button that renders the graphical attack
  map for any confirmed finding on demand — including a finding you opened from history — and shows it
  inline with a Download button. Once rendered, the `.png` is embedded in the report and included in
  the POC download alongside the screenshot. Built from the finding's own captured proof (no re-scan),
  and it simply reports an error if the renderer isn't available.

## v0.91.0

### A graphical attack-plan map in every proof download
- Confirmed findings now come with a **visual map of the attack** — a `.png` that lays out the exact
  flow the engine used to prove the bug: the actor, the crafted request, the observed tell, the
  negative control that rules out a false positive, and the confirmed impact. It's the picture that
  goes with the text reproduction steps, and it lands right next to the proof screenshot in the POC
  download and is embedded in the submission report.
- It's an **option** (on by default) — a toggle on the hunt launch panel — so you can turn it off if
  you don't want it.
- Built entirely from the finding's own captured data (no extra requests), rendered by the same
  bundled browser used for screenshots. Any secret in the proof text is redacted just like everywhere
  else, and if the renderer isn't available the map is simply skipped — the hunt is never affected.

## v0.90.0

### Catches GraphQL schema leaks even when introspection is off
- GraphQL servers often disable introspection but still hand out the schema field-by-field through
  error "suggestions" — ask for a field that doesn't exist and the server replies *Did you mean
  "<a real field>"?*. The engine now confirms this: it sends one harmless query naming an
  unguessable nonexistent field and, if the server suggests a real one back, records the disclosure.
  It's proven only when the response is a genuine GraphQL validation error about the exact field we
  sent (so ordinary "did you mean to POST?" gateway messages never trigger it), and it never changes
  any data.

## v0.89.0

### The hunt now reads the response and reasons like an analyst
- The engine already fetched each response in full but only ever looked at a 200-character slice of it.
  Now it builds a **response digest** from what it already has — the JSON field names an endpoint
  returns, the (including hidden) form fields, which security headers are missing, weak session-cookie
  flags, the JWT algorithm in play, and a shortlist of the *interesting* names it saw (`owner_id`,
  `is_admin`, `price`, a token). It extracts names and shapes only — never a value.
- That structure feeds the AI in two places: the iterative probe loop now steers its checks at **this**
  target's real weak spots instead of guessing parameter names blindly, and every report's
  "what to try next" section now carries **concrete, target-specific leads** grounded in what was
  actually seen — "the response exposes `owner_id`, test it for IDOR", "there's an `is_admin` field,
  try mass-assignment", "the token uses HS256, check for signing-key weaknesses". These are leads to
  pursue by hand — they're never counted as confirmed findings.

### Forged-token (alg:none) check now runs on tokens the app hands out
- The signature-bypass (JWT `alg:none`) check previously only ran when you supplied a session token.
  Now, if the target itself returns a JWT (in a cookie, the page, or a header), the engine tests **that**
  token for the bypass — proving the app accepts an unsigned copy of its own token — even when you
  gave it no credentials. It stays a confirmed finding only via the same strict proof as before
  (the real token works, a corrupted-signature copy is rejected, and the unsigned copy is accepted).

## v0.88.0

### Stored XSS you can prove *executes* — via an out-of-band beacon
- Stored XSS was already confirmed when the injected payload appeared unescaped in the page source. New
  in this release: a stronger, dynamic confirmation that catches stored XSS which only appears after the
  browser renders the page (DOM/JavaScript-built content a plain source fetch misses).
- With an out-of-band collaborator configured, the engine injects a harmless `<img src=…your
  collaborator…>` beacon into the stored field, renders the view page in a real headless browser, and
  treats it as confirmed only when your collaborator records the beacon firing for a fresh,
  previously-silent token. If the app escaped the input, the image renders as inert text and nothing
  fires — so there's no false positive. A crawler/preview-bot callback is downgraded to a candidate.
- Benign and safe: the beacon does nothing but request your own collaborator (no data read, no session
  theft); the view and inject URLs are scope-bound and SSRF-guarded, every request the render makes is
  filtered so it can never reach an internal host, your session is attached only to same-site requests
  (never leaked to a cross-origin host the page references), and it's fully opt-in. Available as an
  assisted mode (get the payloads, submit them yourself, then re-render) or an auto mode.

## v0.87.0

### Every confirmed finding now ships a runnable proof of exploit
- Alongside the screenshot, each confirmed finding now exports the exact benign request that proved it:
  a copy-paste **`replay.sh`** (one `curl` per finding) and a **`findings.har`** you can import into Burp
  or browser devtools. Both land in the campaign folder and the downloadable evidence bundle. They carry
  only the crafted request — never a response body or another user's data — and any secret riding in a
  request URL or header is redacted.

### More leaked cloud keys get *proven* live — now AWS and GCP too
- The engine already proved leaked GitHub/Slack/Stripe/OpenAI/Anthropic/Google/GitLab/npm/SendGrid/
  DigitalOcean keys are live. It now covers the two highest-value cloud key types:
  - **AWS access keys** — validated with a signed `sts:GetCallerIdentity` call that returns only the
    key's own account/identity (no resource is read). The engine pairs a leaked access-key ID with its
    secret from the same file to sign the check.
  - **GCP service-account keys** — validated by minting a short-lived token at Google's own token
    endpoint; the token proves the key authenticates and is never used to read anything. A malicious
    key file can't redirect the check anywhere but Google.
- Both contact only the credential's own issuer, never your target, and a dead or revoked key stays a
  candidate.

### More things the engine can confirm are exposed
- New always-on checks (each proven by a distinctive signature plus a control, so they can't
  false-positive): a served **`.aws/credentials`** file, a served **`.npmrc`** with a registry auth
  token (including private registries on a port or path), an unauthenticated **Elasticsearch** `_cat`
  API, and **WordPress** REST user enumeration.
- **Blind XXE** confirmation now runs automatically during a hunt when you've configured an out-of-band
  collaborator — the same benign, callback-only technique already used for blind SSRF.

## v0.86.0

### Confirmed findings keep their proof after a restart
- When the engine confirms a finding during a hunt, it captures the exact proof — the request it sent,
  the response, and the observed-vs-control difference that proves the bug. For findings confirmed by
  the active pass (reflected XSS, SQL injection, CORS, open redirect, and the like), that captured
  difference was being shown live but not saved to the finding's durable history. If you closed and
  reopened the app and rebuilt the report from history, a genuinely-confirmed finding could come back
  with an empty proof section.
- Now that observed-vs-control difference is persisted with every confirmed finding, so a report
  rebuilt at any later time still carries the concrete, reproducible proof that earned the "confirmed"
  status. (Findings still can't be over-promoted — the status is decided separately from the stored
  evidence.)

## v0.85.0

### Broken-admin-function checks now fire on every admin path the scan finds
- When you've configured a second (admin) account, the engine's dual-account **BFLA** check — does a
  low-privilege account reach an admin-only function? — used to run only on endpoints the AI flagged.
  Now it also runs, deterministically, on any endpoint the crawl finds whose path looks like a
  privileged function (`/admin`, `/internal`, `/manage`, `/settings`, role/permission/config/audit
  routes) — so it fires even with no AI configured, or when the AI missed one.
- This only widens what's *checked*, never what's *confirmed*: the three-session admin/user/anonymous
  differential still owns every confirmation, and a path that turns out to be public (the anonymous
  request isn't denied) is a harmless no-op.

## v0.84.0

### More leaked keys now get *proven* live — not just flagged
- The engine already confirmed leaked GitHub, Slack, Stripe, OpenAI, Anthropic, and Google/Firebase
  keys by sending one benign, read-only request to the key's **own** issuer. That proof now covers four
  more of the highest-value token types: **GitLab** personal/project tokens (`glpat-…`), **npm** tokens
  (`npm_…`), **SendGrid** keys (`SG.…`), and **DigitalOcean** tokens (`dop_v1_…`).
- When one of these turns up in source, the engine reads only the token's own issuer to prove it
  authenticates and to name what it controls (the GitLab/npm/DigitalOcean account, or the SendGrid
  key's scopes) — never touching the target, never mutating anything, and never following a redirect
  that could replay the token elsewhere. A live key becomes a **confirmed** finding with a runnable,
  copy-pasteable proof; a dead or revoked one stays a candidate. Detection uses each vendor's
  unmistakable prefix, so the false-positive rate stays at zero.

## v0.83.0

### Cross-tenant IDOR — the engine now proves one account can read another's data
- Building on the two-account setup, you can now list **object-URL pairs** on a program: an object your
  *first* account owns and a *different* object your *second* account owns. During an active hunt the
  engine runs the dual-session **IDOR / BOLA** check on each pair — it reads your first account's object
  as your *second* account and confirms the bug only when the second account receives the first
  account's specific object (distinct from its own data). A properly-scoped app returns the second
  account's own data or a 403, so this can't false-positive on a shared or static page.
- The pairs are **always operator-supplied** — the engine never guesses which object belongs to which
  account (guessing would corrupt the ownership control and invent findings). The captured proof is the
  differential only (statuses + similarity ratios), never the other user's data. GET-only, in scope,
  and fail-closed: no pairs, no second account, or any error simply skips the check.

### Fixed: authenticated hunting was silently off in Portfolio Hunt
- Running a **Portfolio Hunt** (many programs at once) was ignoring each program's saved research
  account, so every program hunted logged-*out* — which also meant the dual-account BFLA and cross-tenant
  IDOR checks never ran there. Portfolio Hunt now logs into each program's own account just like a
  single-program run, so authenticated findings (and the two-account proofs) work in every run mode.

## v0.82.0

### Dual-account testing — the engine now proves admin-only functions aren't really admin-only
- You can now give a program a **second, higher-privilege research account** (an admin/manager role you
  also control) alongside your regular one. When both are set, the engine runs a **broken function-level
  authorization (BFLA)** check: it takes an admin-only function the AI flagged, requests it as your
  *low-privilege* account, and confirms the bug only when that account gets the same admin response
  *and* an anonymous request is denied — so the endpoint is genuinely privilege-gated, yet the
  under-privileged user reached it.
- The proof carries only the differential (response sizes, status codes, the anonymous control's
  denial) — never the privileged page's body. Everything stays benign and GET-only, in scope, and
  fails closed: no admin account, no session, or any error simply skips the check.
- The AI only *selects* which admin function to test; the engine's three-session differential is what
  confirms it. Both accounts' passwords and cookies are stored locally, sent only to the program's own
  login page, and never shown again after saving.

### Every evidence bundle now ships a chain-of-custody manifest
- Downloaded evidence zips now include an **integrity manifest**: `EVIDENCE-MANIFEST.json` (the tool,
  version, time, and a SHA-256 + size for every artifact) and `MANIFEST.sha256` in the standard
  `sha256sum -c` format. After unzipping, a triager runs `sha256sum -c MANIFEST.sha256` (macOS:
  `shasum -a 256 -c`) and a matching digest proves every proof file — request/response transcripts,
  the JSON sidecar, the screenshots — is byte-for-byte unaltered. That's what turns a pile of captured
  files into verifiable evidence.

### UI polish
- Cockpit navigation marks the current view for screen readers (`aria-current`), the live hunt log is
  quieter, and the nav grid is evenly spaced.

## v0.81.0

### Offline hunts are now steered — and they learn
- When no cloud AI (Claude/Ollama) is configured, the hunt used to run with no targeting at all. Now a
  built-in offline engine reads the mapped surface and points the checks where bugs actually live: the
  parameters that take a URL (for SSRF), the ones that reflect input (for XSS), object endpoints worth
  an IDOR check (`/order/1042`, UUID paths), and — per endpoint — the vulnerability classes its path,
  parameters, and technology stack imply (a Flask/Jinja app gets template-injection first, a
  download/file endpoint gets path-traversal, and so on).
- It **learns from your hunting**: the classes a program has actually rewarded before are tried first,
  so the offline hunt sharpens itself the more you use it.
- Fully offline, private, and safe — it only ever *names* parameters and picks which check to run; the
  engine does the probing, stays in scope, and confirms the result.

## v0.80.2

### Hardening pass — the AI can never overstate a finding, and the exploit proof is always recorded
- **The AI can never mark a finding "confirmed."** Only the engine's own captured exploit (its
  request-vs-control differential, a live-credential read, etc.) can confirm a finding — AI wording can
  no longer make an unproven finding read as proven, and every AI-written line in a report is now
  scrubbed of secrets and screened for tampering before it can appear.
- **The actual exploit proof is always recorded.** Confirming a finding after the fact now keeps the
  real captured request/response (not just a summary), the injected header that proves an open-redirect
  or header-injection bug is preserved, and re-checking a Firebase key also records the open
  database/storage exposure — so every report carries the concrete, reproducible proof.
- The live campaign view now shows that captured proof (and the plain-English impact line) inline,
  instead of only a status badge.

## v0.80.1

### The AI can now drive the hunt as a loop (opt-in)
- A new **iterative hunt loop**: instead of the AI reasoning once before the hunt and going quiet, it
  now probes, **reads what came back**, and decides what to try next — the reactive "second look" that
  turns near-misses (a parameter that reflected but was encoded, a stack trace that points at template
  injection, an oddly-named redirect parameter) into real findings.
- It stays strictly bounded: the AI only ever names parameters and picks which check to run — the
  engine does the probing, stays in scope, and confirms the result — and the whole loop can never use
  more requests than a single normal hunt. Off by default; enable with `GREYIQ_HUNT_LOOP_ENABLED=1`.

## v0.80.0

### The AI writes the impact and the report — from the real proof only
- **AI impact statement.** Every finding the engine *confirms* now carries an AI-written impact /
  blast-radius sentence — the concrete "so-what" a triager rewards ("an unauthenticated attacker page
  reads any logged-in user's orders and email") — written **only** from the captured proof. It can
  never change what was proven: it's a descriptive line the proof gate ignores, so it can't turn an
  unconfirmed finding into a confirmed one.
- **AI-written submission summary.** The opening Description of a submission is now written by the AI
  in the destination platform's voice (HackerOne / Bugcrowd), grounded in the finding and its captured
  proof — replacing the generic one-size-fits-all text that gets reports rejected. Every evidence and
  proof section still renders exactly as before.
- Both are secret-redacted and screened for tampering before they can appear, and the engine falls
  back to its own wording whenever the AI is unavailable.

### The AI aims the XSS and SSRF checks
- The AI reads a target's endpoints and points the **SSRF** probe at the parameters that actually take
  a URL here (`image_url`, `webhook`, `feed`, `avatar_url`, …) and the **XSS** checks at the parameters
  that reflect input — the target-specific surface the generic defaults miss. It only ever *names* a
  parameter; the engine supplies the test and confirms the result, so this finds more without ever
  reporting something unproven.

## v0.79.0

### The AI now helps find an entire bug class it missed before
- **Autonomous IDOR / broken object-level authorization.** When a program has an account configured
  and the active pass is on, the AI reads the discovered endpoints, picks the ones that address a
  specific object by id, and the engine runs its single-session IDOR probe on them **as your logged-in
  research account** — surfacing "this object id can be walked to a neighbour's data" leads the hunt
  produced none of before. Reported as candidates (a single session can't prove cross-tenant on its
  own), pointing at the dual-account confirm. The AI only ever *selects* an already-in-scope endpoint;
  the engine does the probing, stays in scope, and owns the verdict.
- **Safer AI-written text.** Every piece of text the AI contributes to a report is now secret-redacted
  and screened for prompt-injection before it can appear, and dropped entirely if it looks tampered —
  so nothing an AI echoes from a scanned page can mislead a triager.

## v0.78.2

### OpenAI hosted model compatibility
- OpenAI/ChatGPT requests now omit custom `temperature` for newer hosted models that only accept the provider default, fixing HTTP 400 errors like `Unsupported value: 'temperature' does not support 0.2 with this model`.
- The OpenAI-compatible retry path now also strips `temperature` once when a gateway reports it unsupported, while local OpenAI-compatible servers keep the configured temperature.

## v0.78.1

### Proof artifacts, bigger findings, and ChatGPT API compatibility
- Reports now include **Proof of concept**, **Proof of impact**, and **Proof of exploitability** sections for confirmed findings, with captured request/response or screenshot evidence carried into downloads.
- The active proof engine now detects more high-impact exposed management/debug surfaces, including phpinfo, Go expvar/pprof, Spring logfiles, Docker Registry catalogs, Kubernetes namespace lists, and Apache server-status, guarded by root-only probes and catch-all controls.
- OpenAI/ChatGPT-hosted model requests now use `max_completion_tokens` where required, keep `max_tokens` for local OpenAI-compatible servers, and retry once with the alternate field when a gateway reports an unsupported token parameter.

## v0.78.0

### API-key access proof on demand
- Source API-key findings now have a separate **Test API key access** action. It sends one
  read-only request to the key's own allowlisted issuer, records what the key can access, and
  keeps the secret redacted in the returned artifact.
- The captured API response and access summary are saved as `api-key-access.txt` / `.json` in
  the PoC download folder and are also included in the engagement bundle under `evidence/`.
- Live API-key tests update the cached proof plan so the full report can carry the fresh issuer
  request/response proof without asking the operator to reproduce it manually.

## v0.77.0

### Confirmed source API proofs are now report-ready
- Confirmed source/API credential findings now carry the one benign issuer validation into the main
  PoC and proof-of-impact blocks: redacted authenticated-read request, issuer success response, and
  blast radius are generated automatically from the validation result.
- Reports render those proof artifacts anywhere the proof-of-impact section appears, while keeping
  the secret itself redacted outside the sensitive credential block.
- Guided next steps now treat already-confirmed proofs as review-ready artifacts instead of asking the
  operator or submitter to prove the same impact again.

## v0.76.0

### Hunt programs the way they require — logged in, with your research account
- A program can now carry its **hunting requirements**. Give a program your authorized **research-account
  email + password** and its **login URL**, and the engine logs in through the program's own login page
  (via the bundled browser) and hunts as that authenticated user — reaching everything behind the login.
  A pasted **session cookie** works as a fallback when a login form is CAPTCHA/SSO-heavy.
- Programs that require a **user-agent tag** on your traffic (common on HackerOne/YesWeHack — e.g.
  `-BugBounty-<program>-31337`) get it appended to **every in-scope request** automatically.
- Credentials are stored locally and used only against the program's own login page (scope- and
  SSRF-guarded, fails closed). The password and session cookie are **never shown again** after saving,
  and the required tag can never inject a header. Set it all in the Program form's new
  **"Account access & hunting requirements"** section.

### A finding confirmed during a hunt now reads confirmed in its report
- Clicking a finding during a campaign and opening **View full report** now shows it as **Confirmed**
  with its captured proof (the observed-vs-control differential + request/response evidence) — instead
  of "Candidate / validate before submission" — with no manual re-verify needed. A genuinely
  unconfirmed finding still reads candidate.

## v0.75.0

### Proof of impact now updates the submission report
- After **Create/Get proof of impact** (or the one-click **Prepare full report**) confirms a finding,
  the captured request/response differential is now persisted onto the run — so the submission report,
  the downloadable `.md`, and the HackerOne submit gate all render the finding as **Confirmed** with its
  observed-vs-control proof, instead of still reading "Candidate / unverified".
- Previously only the finding's status *badge* flipped to Confirmed while every rebuilt report kept
  showing the candidate proof-obligation text, because the gathered proof was never written back to the
  cached run the canonical report is built from.
- The proof is only promoted when the active check confirms the finding's **own class** (an unrelated
  confirmation at the same URL never flips it), and a client-supplied status still can't reach Confirmed
  without a real negative control.

### Stronger proof on every confirmed finding
- A **proof screenshot** is now captured for *every* actively-confirmed finding (previously deep-mode
  only) and ships in its submission package — a visual PoC of the vulnerable behaviour that speeds and
  raises triage acceptance. Scope-gated and bounded; degrades cleanly when a browser engine is absent.
- Data-disclosure findings (CORS cross-origin read, IDOR, exposed-file/dump) now **name the sensitive
  data actually disclosed** — "the disclosed content includes a JWT (session/bearer token) and email
  address(es)" — the concrete impact that lifts a finding from Low to High. Detection is deliberately
  conservative (high-confidence secrets + JWTs + personal emails only; credit-card/phone/password
  heuristics and the site's own public role addresses are excluded so the claim is never over-stated),
  and it is shown only for disclosure findings, never for an injection finding's own payload effect.

## v0.74.0

### Every leaked API key is now proven, not just detected
- **OpenAI & Anthropic keys** are validated with one benign, read-only request to their own issuer
  (`GET /v1/models` — the public model catalog, never account data): a live key is confirmed and the
  models it can spend credits on are named; a dead/revoked key is marked not-live.
- **Stripe keys** are validated by probing a deliberately **non-existent** customer, so a live key
  returns a 404 ("no such customer") and a dead key returns 401 — liveness is read from the status
  code alone and **no account data is ever read**. Live-mode vs test-mode is called out.
- This joins the existing Firebase / GitHub / Slack liveness checks, so every API-key class the
  scanner detects (except AWS, which needs the paired secret) ships as a **proven** finding with the
  exact **request sent** and **HTTP return code** shown in the report.

### Safer credential handling
- Credential validation never follows redirects, so a found token can only ever be sent to its own
  allowlisted issuer — it can never be replayed to a redirect target. (Also hardens the existing
  Firebase / GitHub / Slack checks.)
- An Anthropic `sk-ant-…` key is no longer mis-detected as an OpenAI key, so it is only ever validated
  against Anthropic.
- The report's "no account data was read" statement now appears only for the checks where it is
  literally true, and is omitted for the checks that read and display the account/workspace/project.

## v0.73.0

### Finds more, proves more
- **Context-aware reflected XSS** — a new check that catches JavaScript-string `</script>` breakouts
  and double-quoted-attribute `"` breakouts the element-content check structurally misses. It confirms
  only when the breakout character reflects **un-encoded** *and* the reflection physically sits inside
  a `<script>` element or a double-quoted attribute (verified from the surrounding syntax), so an
  encoded or non-executable reflection is never flagged.
- **Live-validated GitHub & Slack tokens** — a leaked GitHub personal-access-token or Slack token is
  now proven live by one benign, read-only request to its **own issuer** (never the target), naming
  the account/workspace and the scopes it grants, with a runnable proof-of-concept — turning a
  detection-only leak into a proven finding, the same way Firebase keys already are.
- **Deeper SQL injection** — error-based SQLi now also tries double-quote and backslash quote-breaks
  (the MySQL/MSSQL string contexts a single quote misses), keeping the database-error-banner-only
  confirmation; boolean-blind SQLi now confirms the **inverse polarity** (endpoints whose default
  response is the FALSE result) with every stability and reproduction guard intact; and each injection
  check probes one more discovered parameter.
- **Tech-stack steering** — the technology fingerprint's per-class hints (Flask/Django/Next → template
  injection, PHP/WordPress/ASP.NET → command injection, Angular → XSS, GraphQL → introspection) now
  reorder the active checks alongside the reasoning layer's per-endpoint priorities, so the request
  budget is spent on the classes the observed stack actually implies. Pure reordering — it never
  creates a finding, only changes the order they run in.

### Proof that reaches the report
- An end-to-end guarantee that every confirmed finding's proof-of-concept (reproduction steps + a
  runnable command), proof-of-impact, and the exact **request sent + HTTP return code** render on
  every report surface — the campaign report, the per-finding file, all four platform submissions,
  and the JSON sidecar.

## v0.72.0

### The hunt sees more, and reasons about where to strike
- **All-knowing recon (within scope)** — discovery now crawls the surface it mines, not just the
  landing page: endpoints and in-scope sibling hosts pulled from served JS, inline `<script>`/config
  blobs, and HTML comments, plus the full sitemap-index + robots `Sitemap:` inventory. `<form>`
  action targets, OIDC/OAuth `.well-known` auth endpoints, and OpenAPI/Swagger specs (JSON **and**
  YAML, templated paths instantiated, Swagger-UI spec URLs scraped) join the probe surface. Every new
  host/URL passes the same fail-closed scope gate before it is ever fetched.
- **Reasoning-steered hunting** — the model now reads the mapped surface and (a) proposes the
  target-specific parameter names the heuristics miss and (b) prioritizes the vuln class most likely
  to hit each endpoint, which reorders the active checks so the request budget is spent where a real
  bug is most likely. The model never emits a finding: a hypothesis is reported only when the
  deterministic differential prover independently confirms it — recall up, precision unchanged. Fully
  scope-gated, prompt-injection-hardened, and fail-closed to today's behavior when no brain is set.

### Proof of impact that survives triage
- Confirmed findings now capture the **actual vulnerable behavior in the live response**: the
  shell-evaluated result for OS command injection, the reflected host for host-header injection, the
  NoSQL error text, the injected header for CRLF, the authenticated body a forged `alg:none` JWT
  unlocked, the real `Location` for open redirect, and the disclosed schema for GraphQL introspection.
  IDOR/BFLA carry the size differential without ever embedding another user's data.
- **Leaked Google/Firebase API key** — a runnable `curl` proof-of-concept (a benign, read-only call
  to Google's issuer, never the target) plus the captured issuer response proving the key is live and
  what it grants; an open Firebase Storage bucket now lists the real object names an attacker can
  enumerate.
- Missing-HSTS and exposed-source-map findings now carry captured proof, and a static finding's
  multi-line span renders as a range.

## v0.71.0

### More money-classes found, and proof that survives triage
- **Open Firebase exposure** — a live leaked Firebase key now leads straight into an unauthenticated
  read check of the project's **Realtime Database** (via a shallow read that returns only top-level
  key names, never the data) and **Cloud Storage** bucket. An open store is a confirmed,
  VRP-eligible finding.
- **Blind SSRF, automatically** — when a collaborator is configured, an active hunt runs the
  out-of-band SSRF probe itself: a fresh, unguessable callback token (the reproducible "sheriff
  flag") per parameter, confirmed only when a hit appears after the probe. Crawler/preview bots stay
  candidate.
- **Chrome extension analysis** — scans a browser-extension `manifest.json` for access-to-all-sites
  permissions, `unsafe-eval` CSP, an `externally_connectable` open to any site, and high-privilege
  permissions (no false positives on web-app manifests).
- **Proof of impact that shows the real response** — confirmed reflected-XSS / SSTI / SQLi findings
  now include the server's **actual response excerpt** with the payload's effect (reflected /
  evaluated / DB error), not just a description — the concrete evidence a triager accepts.

### Whole-app QAQC hardening
Fixed a batch of audited defects: the backend version is now single-sourced with a CI parity gate;
deleting a program cascades to all its findings (High/Critical kept in a History archive); two
prompt-injection vectors (workspace skills, README-derived memory) fenced as untrusted; the DNS
resolver validates transaction id + question (spoof-proof) and net_probe pins DNS against rebinding;
per-cookie CSRF SameSite; a confirmed finding's severity always comes from the deterministic CVSS
(never an attacker-influenceable brain vector); submissions record before the network round-trip
(no duplicate HackerOne filings); and the real reward amount is recorded to the pipeline.

## v0.70.0

### Finds more criticals & RCE — and proves them
New actively-confirmed critical checks, each with a control differential and adversarially vetted
against false positives (findings must be legit):
- **OS command injection** — a benign `$(expr 111+111)` shell-substitution echo confirms code
  execution without running any real command.
- **Blind OS command injection** (opt-in) — a `sleep` timing differential with a *matched-
  metacharacter* control, so a WAF that tarpits on `$(` can't produce a false positive.
- **Unauthenticated debug/management endpoints** — Spring Boot actuator **heap dump** (every
  in-memory secret) / env / index and **Jolokia** JMX (a path to RCE), confirmed by the product's
  own signature plus a catch-all control.
- **SSTI → RCE** escalation gadgets per engine, and the live-scan **uncaught JavaScript exception**
  finding is now triaged into code-evaluation / prototype-pollution / DOM-sink leads.

### Leaked API keys that HackerOne accepts
A found **Firebase / Google API key** is now validated and reported to spec: the exact file, line,
and **variable name**; a benign read-only check against the key's own issuer that proves it is
**live** and names the **Firebase project** and authorized domains it grants; and the **actual key**
shown un-redacted (with a review-before-sharing warning) so you can paste it straight into the
report. A live key reads as Confirmed.

### Delete a program, everywhere
Deleting a program now cascades across the whole app and deletes its findings — **High/Critical
findings are kept** in a History "Archived" subcategory, the rest are removed.

## v0.69.0

### Every confirmed finding now ships a real proof of concept
The proof-of-concept engine used to write a concrete reproduction only for CORS — every other
class fell back to a generic `curl <url>`. Now **every actively-confirmed finding** carries:
the *exact* crafted request GreyIQ used to confirm it, rebuilt as a copy-paste `curl`; the
confirming evidence as the demonstration; a class-specific escalation step; and — for the
browser-exploitable classes — a **runnable PoC page** (reflected-XSS, open-redirect, CSRF,
clickjacking). A JWT weak-secret finding gets a **forged-token PoC** built from the recovered
secret. Host-header / CRLF findings get escalation guidance instead of a misleading open-URL
PoC.

### Findings that show the data, not just the flaw
The disclosure/read checks (path traversal, exposed `.git`/`.env`, GraphQL introspection) now
capture a redacted excerpt of the **actual retrieved content** and render it under a
"Demonstrated impact — data disclosed" heading — the same "show the real data" treatment that
made CORS reports submittable, now across the board.

### Cleaner PoC formatting + staged report actions
HTML PoCs are fenced as ` ```html ` so a reviewer recognizes them as code, and the report's
reproduction origin always matches the finding (a subdomain-trust finding uses an attacker
subdomain, not an unrelated origin). The report panel gains a staged **Prove → Package →
Submit** action pipeline.

## v0.68.0

### CORS reports HackerOne stops rejecting
HackerOne kept flagging our CORS reports for *"No CORS headers shown in proof; missing concrete
reproduction steps and demonstration of vulnerability."* All three are now closed:

- **The CORS headers are shown, plainly.** The reconstructed response now prints
  `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` as **separate header lines**
  instead of one combined value. And on-demand reports (a history/board finding opened from the
  full-report panel) used to drop the captured request/response entirely — so they showed *no* CORS
  headers at all; that evidence is now carried through.
- **Concrete, copy-pasteable reproduction.** Instead of a generic `curl` with no `Origin`, a CORS
  report now gives the exact request —
  `curl -i -H 'Origin: <attacker>' -H 'Cookie: <your session>' '<url>'` — the ACAO/ACAC headers to
  look for, and a **runnable HTML PoC** (a credentialed `fetch(..., {credentials:'include'})`) as the
  report's Proof of concept.
- **The read is demonstrated.** On an **authenticated** scan the probe carries your same-site
  session, so the response body it reads back is the very data an attacker origin could steal. The
  report shows it under **Demonstrated cross-origin read**, with the observation stating the attacker
  origin READ it. Unauthenticated scans still report the misconfiguration but claim no read
  (fail-closed) — so scan while logged in to capture the demonstration.

## v0.67.3

### The request/response/source proof as text
Capturing a finding's screenshot now also saves the **plain-text** proof — the request line, the
full request and response headers, and the served response body (where a secret/disclosure
actually lives) — the same content as the proof-sheet image, but copy-pasteable. It's added to the
one-click POC zip as **response-source.txt** and to each finding's "Download everything" bundle
under **evidence/**, so you can paste the exact HTTP exchange straight into a submission.

## v0.67.2

### Copy the proof of impact straight into your submission
The full-report panel has a **Copy proof of impact** button that copies, as plain text you can
paste into a report: the proof of impact, the numbered steps to reproduce, the captured
request/response, and the actual sensitive data read. The one-click POC zip also now includes a
**steps-and-evidence.txt** with the same content. It only labels a captured response body as
"sensitive data read" — a bare matched header is shown as evidence, never overstated as a data
read.

## v0.67.1

### CORS reports that HackerOne accepts
A CORS finding now demonstrates the **actual cross-origin read of sensitive data**, not just the
reflected header — the exact thing HackerOne's review kept flagging as ineligible. GreyIQ's CORS
probe already carries your session, so on an **authenticated** scan the response it gets back is
the very data an attacker page would read; the report's proof of impact now shows it ("a
cross-origin request carrying the victim's session returned the authenticated response … that the
reflected ACAO + Allow-Credentials let the attacker origin READ", with the data). Scan the target
while logged in (Scan behind a login, or the new **Get proof of impact** button) to capture it; an
unauthenticated scan still flags the misconfiguration but tells you to re-run authenticated.

It also now catches a **substring / prefix-trust** ACL — one that trusts any origin merely
*containing* the target host (e.g. `https://target.attacker.com`) — with the control/probe origins
built from the target's real scheme and port so `http://` sites are covered too.

### Better proof, fewer weak screenshots
- Every finding's report now has an always-available **Get proof of impact** button that actively
  re-probes the finding in scope and captures the live request/response + screenshot — it works
  for a finding opened from history too.
- A rendered-page screenshot that is just an app error page ("Something went wrong"), a loading
  skeleton, or near-blank is no longer attached when the real **response-source** proof is
  present — such a shot only weakened the report.
- Broadened the confirm-grade SQL error signatures (DB2, Oracle, SQL Server, PostgreSQL/Npgsql).

## v0.67.0

### The engine finds more real bugs
Six new or expanded active checks, each fired only against a target you named in scope and gated
by a same-run negative control (or a self-certifying signal), so they add coverage without adding
false positives:

- **Weak JWT signing secret.** When your session token is HS256/384/512, GreyIQ recovers a
  weak/guessable signing secret **offline** (by matching HMAC against the token's own signature)
  and confirms account takeover — a critical finding, at zero request cost until a match.
- **Path traversal / local file read.** Proves a file-read by returning one well-known system
  file (`/etc/passwd`, `win.ini`), gated by the file's signature plus a benign-value control.
- **GraphQL introspection.** Confirms schema disclosure on GraphQL endpoints.
- **Exposed `.git` / `.env`.** Flags a served source repository or secrets file, gated so a
  single-page app that answers 200 to everything can't trigger it.
- **Host-header injection now also probes `X-Forwarded-Host`** — the reverse-proxy shape behind
  most password-reset poisoning, which a plain Host probe misses.
- **Template injection now probes four engines** in one request (`{{7*7}}`, `${7*7}`, `<%=7*7%>`,
  `#{7*7}`), so it catches Freemarker/EL, ERB/EJS and Thymeleaf, not just Jinja/Twig.

### Reports HackerOne accepts
- A CORS report now carries **CWE-284** end-to-end even for a finding opened from history —
  previously the weakness was blank and HackerOne inferred CWE-16.
- The one-click POC zip now includes a runnable **`poc.html`**. For a CORS finding it's a real
  proof-of-concept page: served from an origin you control and opened while logged in to the
  target, it performs a credentialed cross-origin fetch and displays the authenticated response
  — the working cross-origin-read PoC HackerOne asks for. Nothing runs until you click.

## v0.66.2

### Proof screenshots that actually prove it
A screenshot of a rendered page shows nothing for a finding whose evidence lives in the served
response — a secret in the page source, a missing or weak security header — the page just looks
normal. Capturing a finding now produces a **Response source (PoC)** shot: the real HTTP exchange
the browser made — the request line and headers it sent, the response status and **every**
response header, and the served response body with the matched value highlighted — the exact
proof a triager wants. The rendered page and a full-page shot come along as supporting context.

### One-click POC zip
The full-report view has a **Download POC (.zip)** button that bundles everything needed to submit
into a single archive — the report, a proof-of-concept/evidence summary, every captured screenshot
(including the response-source PoC), and a machine-readable finding record. It's built right in the
app, so it works for any finding, including one you opened from history with no active run.

## v0.66.1

### Screenshots that prove the finding — and no more re-running the hunt
Capturing a proof screenshot no longer needs the run to still be cached: a finding you opened
from history (or after the run was evicted) now screenshots from its own URL, so you never have
to re-run a whole campaign just to grab an image. Each capture also carries a proof banner with
the finding's title, location, and evidence, and outlines the matched value on the page — so the
shot proves the finding even when the page itself looks blank (a secret in source, a missing
header). You get two shots per capture (annotated evidence + full page), each downloadable, and
they stay put while you work.

### Browse straight to a full report
The Submissions queue and the "All findings" history now have a **View full report** button on
every row, so you can pull up a finding's full report (proof of impact, screenshots, submit)
while browsing — not only from a finding's drawer.

### QA/QC audit — nine fixes
A multi-agent review found and this release fixes: clicking a finding could act on the *wrong*
finding when two shared a reference (Delete/Submit now target the exact one); subdomain-takeover
and known-CVE scans no longer wipe your existing findings board; a malformed local-model response
can't crash a hunt; a report can no longer be labeled "Confirmed" without a real
observed-vs-control proof; the scan's private-host guard now covers CGNAT and IPv6-wrapped
addresses; the open-redirect check no longer false-confirms on a look-alike subdomain; and the
packaged build drops ~13.6 MB of unusable model checkpoints.

## v0.66.0

### Download just the screenshot
Every captured proof screenshot — in the finding drawer, the Submissions full-report panel, and
the active-probe result — now has a **Download screenshot** button, so you can save the image on
its own to attach to a report without exporting the whole thing.

### Proof of concept in the full report
The Submissions full-report view now shows a **Proof of concept** section, and folds it into the
copied/downloaded report. On-demand reports for a campaign or history finding previously started
from a template with an empty PoC, so their report had no PoC section — now the finding's PoC
carries through.

### Steps to reproduce always number cleanly
Reproduction steps are now numbered correctly no matter how they arrive. A brain that returned the
steps as one block of text used to render them one character per line ("1. S / 2. e / 3. n …"),
and steps that already carried their own "1." got double-numbered — both are fixed, at the source
and in every report format, so a submitted report reads as a clean 1..N list.

## v0.65.0

### Open a finding's full report — and submit from one place
Every finding's detail drawer now has a **View full report** button — on the Findings board
(after a campaign) and in the live Campaign dashboard (while it's still running). It opens the
finding on the Submissions page, where the full submission report now lives: the proof of impact,
a captured screenshot, the platform-shaped report itself, and one-click Copy / Download / Capture
screenshot / Submit to HackerOne (Submit stays gated until the finding is Confirmed). You can dig
into a finding the moment it appears mid-campaign and land on the exact report you'd file.

### Search, filter, and sort on the Submissions page
The Submissions page gained a search box (title, URL, class, CWE), severity and proof-status
filters, and sort (severity / title / most recent) — applied to both the current run's queue and
the full findings history. The history is cached client-side so search filters instantly, with a
Refresh button to reload it from the engine.

### Packaging
- The release now bundles only the newest Chromium revision Playwright needs, and installs
  Chromium in the local build — trimming the download and making proof screenshots work out of
  the box from a fresh checkout.

## v0.64.0

### Delete a finding — and it stays gone
You can now delete a finding from the Findings board or the "All findings" history. A deleted
finding is suppressed by its stable dedup key, so no future hunt, campaign, history view, funnel,
or CSV export ever surfaces it again — for a false positive or an accepted risk you don't want
re-reported. It's reversible (a restore path), and the money/stage data on an already-filed
finding is preserved. Deleting one outdated-library (known-CVE) finding on a page no longer
suppresses the other libraries found there, and the board delete removes exactly the finding you
picked (not any other row that happened to share its reference).

### Proof screenshots — and the live scan — now work in the packaged app
The release build bundles Playwright + Chromium and points it at the bundled browser, so "Capture
screenshot" and the dynamic live-app scan work out of the box, with no separate `playwright
install` on the user's machine. (Adds ~170–270 MB to the download; Linux still needs the usual
system libraries present.)

### Report accuracy
- Recon no longer leaks an HTML-encoded `&amp;` into a finding's URL and its curl proof-of-concept
  (which broke a triager's copy-paste reproduction and mis-parsed the query), while still
  preserving a raw `&` so real query parameters aren't silently dropped from the crawl.
- CORS findings now carry **CWE-284** (Improper Access Control), which HackerOne's Weakness picker
  accepts, instead of the Flash-era CWE-942.

### Hardening
- An adversarial multi-agent review of the change found and fixed four defects before release —
  including a bundled-browser launch path that never set its browser directory and a board-delete
  that could remove the wrong row.
- Tests: suppression/restore, per-library CVE-key distinctness, recon entity handling, and the
  frozen browser-path helper.

## v0.63.0

### Finding status now updates everywhere at once
A finding's status used to live in each view separately, so confirming or submitting it in one
place left the others stale. There's now one shared status model, keyed by a stable finding
identity (the same class·rule·location the ledger dedups on) and persisted across restarts.
Create-proof-of-impact (promoting a candidate to confirmed only when the active pass confirms
*that finding's own class*) and Submit now propagate immediately to the campaign dashboard, the
Findings board + detail drawer, the Submissions queue, and the "All findings" history — no more
stale "candidate" in one view while another shows "confirmed"/"submitted".

### GreyNOC globe brand mark
The GreyNOC geodesic globe is now the app's mark: a procedurally-generated geodesic-sphere SVG
(glowing edges, glassy blue core, subtle rotate/pulse, reduced-motion aware) in the cockpit +
studio headers, a boot splash while the engine starts, the campaign-dashboard idle hero, and the
favicon.

### QAQC hardening (adversarially reviewed)
- Report builder never claims **confirmed** from client-supplied proof without a real
  observed-vs-control differential (caps at candidate otherwise).
- All proof fields (method/actor/affected-asset/limitations, not just evidence/observed) are
  redacted before landing in a report — closes a secret/PII leak path.
- `GET /api/bounty/findings` history is bounded (most-recent cap + a `truncated` note; full set
  still available via CSV export).
- API/JSON responses now send `Cache-Control: no-store`.

## v0.62.0

### Portfolio Hunt — many programs, one run
A new **Portfolio** run type on the launch rail: pick several saved programs (or all) and
GreyIQ runs a full campaign on each one's own saved scope **concurrently**, merged into one
live board. Bounded & polite — the per-host rate governors stay on, and only a few programs
run at once, so a portfolio-scale hunt is fast without multiplying the request rate any single
host sees or looking like abuse. The live dashboard shows each **program** as a unit with its
own status + streamed findings; the click-to-investigate drawer (proof of impact, report) and
the Submissions reporting hub work over the combined results. Deep mode routes the AI write-ups
(reproduction, research, sharper reports) through your selected device — the GPU if set.
New `POST /api/bounty/portfolio`.

> Note: GPU accelerates the AI brain (write-ups/research), not the HTTP probing itself, which
> is network-bound and deliberately rate-limited per host. Portfolio scale comes from bounded
> concurrency across programs.

### Reports always include reproduction steps
On-demand reports (Create report, from a dashboard/history/ledger finding that isn't in the
live run cache) now always carry a real **Steps to reproduce** section + a benign `curl` repro
for web findings — built from the engine's offline attack-plan model, the same steps a full
hunt emits — with any gathered proof of impact folded in.

## v0.61.0

### Reporting hub: findings wired across the app, proof-of-impact + reports per finding
Findings used to live only in the current run (in-memory, lost on restart) while the durable
finding **ledger** — every finding from every hunt + campaign — was never surfaced. The
Submissions page is now the reporting hub:

- **All findings — history.** A durable, cross-run finding history (from the persistent
  ledger, grouped by program) alongside the current run — survives restarts. New
  `GET /api/bounty/findings`.
- **Create proof of impact** — on every candidate, in the campaign dashboard drawer and the
  submissions queue: a scope-gated active re-probe **plus a proof screenshot**, run in a
  separate track that never pauses the campaign. New `POST /api/bounty/finding/prove`.
- **Create report** — a well-authored, platform-shaped report built on demand for any
  finding (including durable-history findings not in the run cache), folding in gathered
  proof + screenshots. New `POST /api/bounty/finding/report`.
- **Engagement (special) report** — one polished document across a whole run or program
  (executive summary + severity/risk overview + every finding). New
  `POST /api/bounty/report/aggregate`.
- **Export** — all-in-one `.zip` bundle, per-report `.md`, and a CSV of every finding across
  all runs.

## v0.60.3

### Investigate findings live: sort, filter, click-to-inspect, and on-demand re-verify
The campaign dashboard's findings are now interactive while the hunt runs:

- **No more scroll-jump.** The dashboard used to fully rebuild every 1.2s poll, resetting
  the findings list to the top while you read. It now builds once and updates in place —
  lists only re-render when their contents change, with scroll position preserved.
- **Sort + filter by severity.** A controls bar sorts by severity (default) or most-recent,
  and filters to a single severity, with live per-severity counts.
- **Click a finding to investigate.** Each row opens a read-only drawer with its severity,
  class, target, location, rule, CWE, and proof status (campaigns now stream those extra
  fields).
- **On-demand re-verify — a separate engine track.** A *Re-verify this finding* button in the
  drawer actively re-probes that finding's URL right now, in parallel to the running
  campaign, and shows the fresh proof. Fail-closed: it refuses without authorization and
  refuses any out-of-scope host, and reuses the same scope-gated, SSRF-guarded active checks.
  New `POST /api/bounty/finding/reverify` endpoint backs it.

## v0.60.2

### Stop campaign button
The campaign dashboard now has a **Stop campaign** button (shown while a campaign is
running). It cooperatively cancels the run — a target in flight finishes its current URL,
any not-yet-started targets in a program span are skipped, and the campaign returns the
partial results found so far. The status pill reflects Running → Stopping… → Stopped. New
`POST /api/bounty/campaign/stop` endpoint backs it.

## v0.60.1

### Fix: campaign dashboard findings now stream per-URL, not per-completed-target
On a program span, the dashboard only counted a target's findings once the *whole* target
finished — so during a long, multi-URL target (e.g. a big program), findings showed up in
the activity log but the stat tiles and findings list stayed at 0 until the target
completed. Findings now stream to the dashboard as each URL finishes, attributed to the
named target, so counts and the findings list climb live. Single-target campaigns are
unchanged.

## v0.60.0

### Live campaign dashboard
A running campaign no longer makes you wait for the whole run to finish — findings and
per-target status now stream in and update automatically on a dedicated **Campaign**
dashboard.

- Starting a Full campaign opens the dashboard automatically. It shows an overall
  progress bar (targets complete / total), stat tiles (findings, confirmed, critical/high,
  medium, low), a per-target list with a live status dot (queued → running → done/error)
  plus each target's finding count / top severity / elapsed, and a live findings list
  (newest first, with severity, class, and proof status) — all refreshing as work
  completes. A "View all findings" jump and the full activity log are there too.
- Backend: the progress module now carries a structured per-run snapshot (work-unit status
  + streamed findings + rolled-up stats) alongside the text log; campaigns emit it per
  discovered URL (single-target) and per named target (program span, streamed from the
  concurrent workers), and `/api/bounty/progress` returns it.
- Themed and responsive (collapses to a single column on narrow windows).

## v0.59.0

### Sharper reports + a full UX/UI/robustness QAQC pass

**Hunt engine & report writing**
- **Consistent severity everywhere.** Findings are now ordered and numbered (F1, F2…)
  by the same CVSS-resolved severity used for their labels and triage, so the findings
  table, ref numbers, and the "highest priority" line can never disagree.
- **Duplicate leads are grouped.** Near-identical, artifact-less leads (same class/rule/
  title across locations) collapse into one entry with a "(+N more)" hint and an affected-
  locations list, so reports — especially campaign spans — aren't spammed with duplicates.
  Confirmed / distinct-evidence findings are never grouped.
- **Tighter executive summary** (no more analyst summary and a generic one stacked), plus
  an optional one-line **TL;DR** and a **suggested report title** from the coding brain.

**UX / UI / robustness (from a multi-agent QAQC pass)**
- Electron: recover from a backend crash *after* the UI loads (a clear "engine stopped —
  restart" page instead of a silently-dead app), a renderer-crash reload, and an actionable
  error when a packaged build's backend component is missing (vs a misleading Python error).
- The Program tab no longer shows "No programs yet" when the engine is simply unreachable —
  it says so and offers a retry.
- The autonomous operator's Stop now surfaces failures (never silently), with a guard
  against a double Start; program toggle/delete/save actions surface errors and can't
  double-submit.
- A "thinking" indicator while a chat/agent reply is in flight; report copy/download buttons
  show progress and disable during the (up to 20s) server fetch.
- A first-run wizard step on connecting a coding brain (local / Claude / OpenAI).
- Visual: the evidence chip and the confirmed-proof badge use theme tokens (were unreadable/
  low-contrast in one theme); the cockpit now stacks to a single column on narrow windows
  instead of crushing the main panel.
- Detection: the open-cloud-bucket check no longer lets an earlier access-denied bucket mask
  a later publicly-listable (high-severity) one on the same page.

## v0.58.1

### Token-first HackerOne credentials + live "Test connection"
The Submissions-tab HackerOne credential entry is now a single **API credential** box: paste
just your token, or `identifier:token` (the pair HackerOne shows together when you click
Generate API token). The server splits it into the identifier/token pair HackerOne's HTTP
Basic auth requires — a bare token keeps any already-saved identifier, so rotating a token
doesn't wipe a working username.

A new **Test connection** button probes a real authenticated HackerOne endpoint and reports
exactly what H1 returns (✓ accepted, or the reason on a 401) — turning "which username do I
use?" into a one-click, server-authoritative answer instead of guessing. HackerOne's Hacker
API has no token-only/Bearer mode (verified against its current docs — every endpoint's curl
sample is `-u "<API_USERNAME>:<API_TOKEN>"`), so the identifier is still required; this just
makes supplying and verifying it painless.

## v0.58.0

### Server security hardening, a live hunt progress log, and engine reliability/UX
A security-focused release. The server was hardened against the active scanning it now
attracts, a live progress log makes long hunts observable, and a batch of reliability,
UX, and active-security improvements landed on top — every one adversarially QA'd before
shipping.

**Security hardening**
- **Authenticated API gate**: API routes now require a session token and enforce an
  origin check, failing closed — closing the window where an unauthenticated request
  could read config or private files.
- **DNS-rebinding fix**: the SSRF guard now pins the exact DNS resolution for the
  lifetime of a request (through the real connect), closing the check-then-connect
  (TOCTOU) gap where a host could resolve to a public address at guard time and a
  private one at connect time.
- **Path containment**: an output directory can no longer be steered to write outside
  its intended root.
- Assorted lower-severity fixes: health-endpoint version leak, a blocking file send, and
  a code-router secret exposure.

**Live hunt progress log**
- Hunts and campaigns now stream a live activity log (backend `progress` module +
  polling frontend panel), so a multi-minute run is observable instead of opaque.

**Engine reliability, UX, and active-security enhancements**
- Bounded retry-with-backoff for transient network failures across active-verify,
  page-fetch, and HackerOne API calls — a real server response (HTTPError / non-retryable
  status) still fails on the first attempt, and the per-hunt request budget and per-host
  rate governor are spent exactly once per logical fetch no matter how many low-level
  attempts it takes.
- Completion alerts: a tab-title badge and a native OS notification when a hunt finishes
  or a finding auto-submits while the tab is hidden.
- A pipeline funnel visualization and a one-click CSV ledger export on the Learn tab, for
  spreadsheet tracking / income reporting.
- Bounded concurrency for multi-target campaign spans (several targets hunted at once),
  with results aggregated back in original target order so report numbering stays
  deterministic.
- A new active check that confirms whether a target accepts a forged, unsigned
  (`alg:none`) copy of the operator's own JWT as authenticated — strictly opt-in (only
  when the operator supplied a real JWT-shaped credential) and gated on a
  negative-signature control so a finding is only raised when it's specifically
  attributable to `alg:none`.
- A missing lock around the learning store's read-modify-write was fixed (it was the odd
  one out versus the ledger and portfolio stores).

Both the security hardening and the enhancement batch were put through a multi-agent
adversarial QA/QC pass with independent refutation voting; every confirmed finding was
fixed, tested, and re-verified before merge.

## v0.57.5

### Expanded HackerOne integration: program enrichment, hacktivity recon, own activity, status sync
GreyIQ's HackerOne integration previously only fetched a program's scope and submitted
reports. Every endpoint below was verified against HackerOne's real, official Hacker API
docs before building against it.

- **Program enrichment**: fetching a program's scope now also captures real program
  signals — offers bounties, fast payments, Gold Standard Safe Harbor, open scope, and
  your own track record on that program — shown as badges on the Program tab. There is
  no structured bounty-table endpoint anywhere in HackerOne's API (confirmed, not
  guessed), so this surfaces the real flags instead of a guessed reward table.
- **Hacktivity reconnaissance**: a "Recent hacktivity" panel per program showing what
  vulnerability classes are actually getting disclosed/paid there.
- **My HackerOne activity**: an on-demand panel (Submissions tab) for your own report
  statuses and earnings/balance.
- **Report-status sync**: a bounded, manually-triggered action (Operator tab) that polls
  every locally "submitted" finding's real HackerOne status, advances the pipeline to
  "paid" on a real reward, and records the outcome to the learning store — closing a
  loop that previously required manually running `gn learn`.
- Fixed a real gap found along the way: manually submitting a finding never registered
  it in the local ledger (only the autonomous operator's auto-submit path did), so its
  HackerOne report id was never tracked for status sync. Now registered at submit time
  regardless of how the finding was discovered.

Every new call is manually triggered (button click), never automatic/background, using
the same stored API credentials — no new secret, no new trust boundary.

## v0.57.4

### Proof-of-impact CVSS confidence, and no more self-identifying in submitted reports
- Actively confirmed findings (dual-session IDOR/BFLA, blind SSRF/XXE via collaborator,
  stored XSS, subdomain takeover, and any active-verify check folded into a hunt) now
  carry a CVSS marked "confirmed" — with a justification tied to the real captured
  differential — instead of always claiming a static-template estimate even once real
  evidence backs the score. The confirmed flag can never disagree with the proof-of-impact
  status shown next to it, since both are gated by the same evidence check.
- Submitted report bodies (the actual content pasted or pushed into a HackerOne/Bugcrowd/
  YesWeHack/Intigriti report) no longer self-identify as "GreyIQ BugHunter" by default.
  A new per-program toggle in the Program tab ("This program's terms require disclosing
  automated-tool assistance") lets you opt back in with a neutral disclosure line for the
  rare program whose rules require it. Local-only reports and JSON metadata (never
  transmitted to a platform) are unaffected.

## v0.57.3

### Full campaign: span a program's entire scope, not just one Target
Reported live: previously a campaign only ever crawled from the single Target field,
discovering in-scope hosts opportunistically via links — a program's dozens of named
assets (seed targets, or a HackerOne-imported structured scope) were never actually
hunted unless linked from that one starting page.

- A "Hunt this program's entire scope (N targets)" toggle on Full campaign, shown once
  a program with more than one derivable target is selected, defaulting on. Runs one
  full campaign per in-scope target (from seed targets, or every eligible row in the
  program's structured scope — HackerOne-imported wildcards are stripped to a concrete
  apex) and merges them into one findings board.
- The autonomous operator now derives targets the same way, so a HackerOne-imported
  program (no hand-typed seed targets) is no longer silently skipped by scheduled runs.
- **Fixed a real folder-collision bug** surfaced while building this: two campaigns for
  the same program within the same second produced the identical output folder name and
  silently clobbered each other's on-disk artifacts. Closed for the existing
  single-target and operator paths too, not just the new span mode.

879 tests green (+11). Live-verified end-to-end against a real 2-seed-target program.

## v0.57.2

### Fixed: launch-rail Program picker not updating on Operator-tab changes
Reported live: adding, editing, enabling/disabling, or deleting a program from the
**Operator** tab never refreshed the launch rail's `#ckActiveProgram` picker — only the
**Program** tab's own save/render did, even though both tabs edit the same saved-program
list. A program changed via Operator stayed invisible in the picker until the user
happened to revisit the Program tab.

- All 5 program-mutation call sites (create/edit + enable/disable toggle + delete, from
  either tab) now refresh the picker immediately through one shared helper.
- Deleting the currently-selected active program (from either tab) now correctly clears
  the selection instead of leaving a dangling reference.

## v0.57.1

### Fixed: CSV identifier column shadowed by asset_type
Reported live right after v0.57.0 shipped: pasting a real HackerOne scope export
(`identifier,asset_type,...` columns) into the Program tab's importer with kind=`csv`
produced "Nothing parsed" — the bare `"asset"` column hint matched `asset_type` (an enum
column, never a dotted host) before the real `identifier` column was ever considered, the
same collision class already fixed for the HackerOne-specific parser in v0.57.0.

- `_pick_column` (the generic CSV parser) now prefers an exact header match over a
  substring one, and `"identifier"` is now a recognized column hint.
- `kind="auto"` now recognizes a HackerOne-shaped header and routes to the richer
  structured-scope parser automatically instead of flattening it to a bare host list —
  an explicit kind selection is never overridden.
- The Program tab's importer no longer dead-ends when a plain CSV/Burp/HAR parse
  succeeds but carries no structured scope — it now synthesizes bare-identifier rows so
  the "Add" button always appears when there's something to add.

858 tests green (+5).

## v0.57.0

### Program setup: HackerOne scope import (API + CSV) and a guided first-run flow
Promotes "Program" to a first-class object with its own cockpit tab, so a bug-bounty
program's scope, HackerOne handle, and SSRF/OOB posture are set up once and reused
everywhere — the launch rail's active-program picker, the Operator tab's autonomous
scheduling, and a program-specific SSRF setup shortcut.

**New:**
- **Program tab** (first in the cockpit nav): a structured-scope table (identifier,
  asset type, eligibility, severity, instructions) editable by hand, imported from a
  CSV/paste, or pulled live from HackerOne's own hacker API
  (`GET /v1/hackers/programs/{handle}/structured_scopes`, reusing the API credentials
  already saved for submission — the first read-only call in the engine to a fixed,
  non-target host, gated to a single explicit button click).
- **Active-program picker** on the launch rail: selecting a saved program autofills
  Target/Scope for a hunt, instead of retyping scope every run.
- **Program-specific SSRF/OOB setup**: a policy-gate reminder plus a one-click jump to
  the Access-control tab's OOB/collaborator panel with scope pre-filled, and a checklist
  of common SSRF injection points.
- **Guided first-run wizard**: a 7-step tour that drives the real cockpit UI (not a
  simulation), shown automatically on a clean install and reopenable via a
  "🧭 Guide me" button in the top bar.
- `docs/USER_GUIDE.md`: the first user-facing operator's guide — program setup, SSRF
  setup, running a hunt, and reports/submission.

**Fixed (found during an adversarial QA pass on the above before shipping):**
- A real SSRF/credential-exfiltration path in the HackerOne import: pagination followed
  the API's `links.next` with no host validation, and the default HTTP client silently
  follows redirects while re-forwarding the Basic-auth token. Every fetched URL is now
  pinned to `api.hackerone.com`, and redirects are refused rather than followed.
- Editing a program's structured-scope table didn't propagate to the fields the scanner
  and operator actually read (`scope_text`/`in_scope_hosts`/`out_of_scope_hosts`) —
  removing a host silently left it still in scope, adding one silently left it never
  hunted.
- Editing a program via the Operator tab's compact form silently wiped the new
  structured-scope table, `oob_allowed`, and notes back to empty.
- A HackerOne CSV column-matching collision (`asset_type` shadowing `asset_identifier`
  when listed first) that discarded every real hostname.

853 tests green (+50).

## v0.56.0

### QAQC pass, part 4 — closing the test-coverage backlog
The 50-agent QAQC audit that drove v0.53.0–v0.55.0 also produced a list of ~60
test-coverage gaps (code paths with no dedicated test) alongside the confirmed faults.
This release closes that backlog, plus one real bug it surfaced along the way.

**Fixed:**
- `report.py`'s JWT-replay check crashed (`AttributeError`) whenever a `jwt_exposure`
  field arrived as something other than a dict (a corrupted run cache or an unexpected
  upstream shape) — it now degrades to "unconfirmed" instead of taking down the whole
  report render for every JWT-credential finding.

**New dedicated coverage (previously untested or thinly tested):**
- The full SSRF/egress-guard surface (`_guard_url`, redirect re-guarding, settings env
  parsing, same-site session binding) and the API's auth/CORS/path-traversal boundary,
  driven through a real in-process ASGI harness.
- Response-consumption isolation (byte cap, cookies, charset) and the sensitive-path
  validators (`git config`, `.env`, actuator, etc.), including governor-exhaustion
  fail-closed behavior.
- `operator`/`ledger`/`portfolio`/`rate_limit`: lifecycle methods, the supervisor loop's
  kill-switch and idle-wait (run against a real background thread), and EV pay-factor
  edge cases that previously had zero coverage.
- `triage.py` (zero coverage before this) and the remaining `ranking`/`campaign` gaps,
  including severity roll-ups and "Ready to submit" rendering.
- `access_control`, `api_discovery`, and `oob_service`: cross-origin OpenAPI scope
  filtering, two-ID IDOR probing, and OOB sweep resilience to a transient poll failure.
- `submission.py`'s HackerOne submit (success path, HTTP/URL-error decoding, screenshot
  co-location and basename-collision behavior) and `report.py`'s Markdown-escaping /
  `build_json` dropped-finding handling — previously only the refusal gates were tested.
- `bundle.py`'s archive-size-cap and per-file-size-skip branches.
- `live_scan_service.py` (the Playwright dynamic-scan engine) had **no test file at
  all** — now covered end-to-end via a fake `playwright.sync_api` injected into
  `sys.modules`, driving the real event-handling, per-request SSRF route guard, and
  capture-cap-overflow code, plus the risk-scoring bands.
- `recon.discover`'s three kill switches (page cap, per-campaign request budget, BFS
  depth) against a real local multi-page server, and the per-host governor throttle
  `_safe_fetch` defers to.
- `recon_js.mine_js`'s `fetch`/`axios`/`.open` call-target regex, every extraction cap,
  and redirected-`base_url` scoping.
- The vendored DNS resolver's compressed-name reader against hostile input (pointer
  cycles, pointer-to-self, out-of-range/forward pointers, unterminated names) — none of
  it can hang or crash, only degrade to a partial/empty name.
- `active_verify_service`'s Host-header confirmed (Location-reflection) branch, the
  per-hunt request budget's `_RateLimited` propagation (independent of the per-host
  governor), and direct tests of `_with_operator`/`_norm_len`.

803 tests green (+278), including two previously-zero-coverage modules
(`live_scan_service.py`, `triage.py`) and one previously-zero-coverage security
boundary (`greyiq_api.py`'s auth/CORS/traversal handling via a real ASGI harness).

## v0.55.0

### QAQC pass, part 3 — all 16 low-severity + 4 plausible faults fixed
Completes the QAQC hardening pass started in v0.53.0/v0.54.0: every remaining confirmed
and plausible finding from the original 50-agent audit is now fixed, with regression
tests (most verified to actually catch the original bug by reverting the fix and
confirming the test fails).

**Active verification / cloud / redirect:**
- GCS and Azure cloud buckets can now confirm as publicly listable (previously only
  S3 ever did) — each provider gets its correct listing query and response-shape check.
- A protocol-relative open-redirect (`Location: //evil/`) is now detected — it was
  silently mis-parsed and missed entirely.
- A redirect chain ending in an error response now re-validates the final URL and
  closes the response (was leaking a socket/fd on every 404/500).
- An IDN (internationalized) target's session now binds in punycode, matching the form
  every actual request is compared against — before, the session silently never attached.

**Resilience to corrupted/hand-edited state:**
- A corrupted learning store (non-numeric `rewarded`/`noise`/`bounty_total`) no longer
  aborts a campaign mid-run.
- A non-numeric `max_pages`/`interval_minutes`/`max_submits_per_day` no longer crashes
  `upsert_program` (the CLI / a hand-edited `portfolio.json` aren't Pydantic-shielded
  like the HTTP API).
- The operator supervisor thread no longer dies on a timezone-naive `next_run_at`.
- An invalid-UTF-8 request body now returns a clean 400 instead of a 500.

**Correctness / consistency:**
- The campaign report no longer lists an already-reported (duplicate) confirmed finding
  under "Ready to submit" with no package — it's now excluded or annotated.
- `next_steps`' ranking and submission-phase counts now agree with the report/H1 rating
  on the same finding (both resolve severity through the CVSS-aware single source of
  truth) instead of mis-tiering it.
- `recon` no longer mines params/fingerprints from a page a redirect landed on OUT of
  scope.
- A 422 validation error no longer reflects the submitted payload values (or pydantic's
  internal error-doc URLs) back to the client — only the failing field names + a
  generic reason.
- Concurrent `/api/*` calls against the same cached run (e.g. screenshot + research)
  no longer race on an unlocked read-modify-write of the shared run state.
- The vendored DNS resolver's query encoder no longer corrupts the packet for a label
  over 63 bytes (a malformed host or an IDNA expansion) — the declared length now
  always matches what's actually appended.

**Cockpit:**
- The Findings tab now re-renders when you switch to it (findings added by a standalone
  tool like IDOR/CVE/takeover used to sit invisible until an unrelated action).
- The Findings board now shows standalone-tool findings even when no hunt has run yet,
  and its summary strip (risk/severity counts) is now derived fresh from the current
  findings instead of a stale cached hunt result.
- The column sort-direction arrow now points the right way (was inverted).
- A non-JSON-object error body no longer crashes `apiFetch` with an opaque
  "Cannot read properties of null" instead of the real HTTP status.

525 tests green (+36), including new dedicated coverage for `scan_service.py`,
`next_steps.py`, the API's request/validation/concurrency handling, and the recon
scope-bleed regression — all previously untested.

## v0.54.0

### QAQC pass, part 2 — the 8 medium-severity faults
Continues the v0.53.0 safety-hardening pass: the medium-severity faults the 50-agent QAQC
audit confirmed (one, the screenshot SSRF-via-redirect, was already closed by v0.53.0's
redirect re-guard — same root cause, two audit groups).

- **New shared `registrable_domain` helper** (public-suffix-aware, no external data — a
  small built-in set of common ccSLDs like `co.uk` and multi-tenant PaaS hosts like
  `herokuapp.com`/`github.io`). Fixes two real bugs at once:
  - **Scope authorization**: a bare platform suffix typed into free-text scope (e.g.
    `herokuapp.com`, copied from a program description) no longer authorizes every
    unrelated tenant under that shared host — only a real, owned apex
    (`myapp.herokuapp.com`) does. The same protection now covers multi-label ccSLDs.
  - **Cross-program memory contamination**: `learning.program_key` no longer collapses
    `foo.co.uk` and `bar.co.uk` into one shared `co.uk` learning/ledger bucket.
  - Also applied to `recon_js`'s same-apex host filtering.
- **Blank-valued query parameters are no longer dropped** from the active prover's probe
  candidate list (`?id=&q=x` now tests `id` too, not just `q`).
- **`run_web_scan`'s "never raises" contract now actually holds**: a truncated/short-closed
  response body (`http.client.IncompleteRead`, e.g. a server that drops the connection
  mid-chunk) is caught and returned as a clean `{"ok": false, ...}` instead of crashing
  the scan.
- **OOB collaborator polling no longer crashes** on a non-object JSON response (a
  misconfigured tunnel/proxy or load-balancer error page rendered as JSON).
- **The operator supervisor thread no longer dies** on a timezone-naive `next_run_at`
  (e.g. a hand-edited `portfolio.json`) — one malformed program no longer stops every
  program from being scheduled.
- **Blind-SSRF/XXE confirm no longer wipes the Submissions queue**: they now merge into
  the existing findings list (matching the IDOR/BFLA/stored-XSS panels) instead of
  replacing it wholesale, so a prior confirmed finding survives running a follow-up OOB
  check.

489 tests green (+18).

## v0.53.0

### Safety hardening — 7 fail-open faults fixed (QAQC pass)
A 50-agent fault-hunt + adversarial-verification pass over the whole codebase confirmed 31
real faults; the 7 high-severity ones are fixed here. Several share one root cause:
**redirects and sub-resources weren't re-checked against the scope/SSRF gate** — only the
initial URL was.

- **Deep mode now reports honestly.** `deep=True` already silently enabled the active pass
  (incl. the opt-in time-based SQLi SLEEP probe) via `time_based`, but the campaign report
  recorded `active: off`. It now derives one honest `effective_active = active or
  time_based or deep` for both the probe and the report.
- **Stored-XSS auto-send no longer leaks the session off-host.** The view-host session is
  now attached to the inject-URL POST only when it's same-site (`scan_auth.auth_headers_for`)
  — the inject URL can legitimately be a different in-scope host than the view URL.
- **Operator auto-submit no longer dead-locks itself.** It gated on `ledger.is_duplicate`
  (stage ≥ reported), but building a local submission package marks a finding "reported"
  in the same cycle — so armed auto-submit could never actually file anything. It now uses
  a new `ledger.is_submitted` (stage ≥ submitted); only a real prior submission blocks a
  re-file.
- **Screenshot capture re-guards every redirect/sub-resource** (not just the initial URL)
  against the SSRF/private-host/port guard, and discards the capture if the final page
  left scope.
- **The "confirmed" proof gate no longer trusts a bare explicit status.** A
  `proof_of_impact.status: "confirmed"` from a brain (possibly hallucinating, or echoing a
  scanned page's prompt injection) now requires a real captured artifact — concretely, the
  `observed_result` + `control_result` differential pair every active-prover check actually
  produces — before it can flip a finding to confirmed (and through the auto-submit gate).
- **The live (Playwright) scanner re-guards every redirect/sub-resource** the same way.
- **Submissions/research/screenshot now key off the finding's OWN run**, not whatever ran
  most recently — fixes submitting/copying the wrong report after running a follow-up tool
  (IDOR/BFLA/stored-XSS/takeover/CVE) on top of an earlier hunt's findings.

A new `web_scan_service.playwright_request_allowed` helper centralizes the redirect/
sub-resource re-guard so screenshot capture and the live scanner share one tested
implementation.

471 tests green (+12).

## v0.52.0

### Operator — import targets from CSV, Burp Suite XML, or HAR
The "Add / update a program" form gains an **Import targets** panel: paste or load a CSV of
hosts/URLs, a Burp Suite items/sitemap **XML** export, or a **HAR** capture, and fold the
result into the program's seed targets and scope.

- One parser ([target_ingest.py](backend/bughunter/target_ingest.py), pure / no-network /
  stdlib-only) normalizes all three into deduped **targets** (full URLs — query params
  preserved so the active prover mines them) and **hosts** (for scope), and surfaces the
  discovered param names.
- **Fail-closed**: parsing never probes and never auto-adds a host to scope — you review the
  result and click "Add to seed targets" / "Add hosts to scope". XML carrying a
  DOCTYPE/ENTITY declaration is refused (entity-expansion / XXE guard); input is byte- and
  count-capped.
- Wired: `POST /api/bounty/ingest-targets`.

458 tests green (+15).

## v0.51.0

### Cockpit — in-app walkthroughs on the dense panels
Every dense cockpit panel now carries a collapsible **walkthrough** that explains its
prerequisites and the recommended order of operations — grounded in exactly what each tool
does, and fail-closed safety notes included.

- **Access control** (IDOR/BOLA · discovery probe · BFLA), the **Operator**, the **Surface**
  tab (subdomain takeover + CVE fingerprinting), and the main **hunt** form each get a
  "How this works — walkthrough" panel with prerequisites, a numbered flow, and a safety line.
- One reusable, declarative component (`ckWalkthrough` + a per-panel spec) drives them, so the
  pattern is trivial to drop onto future panels. Each remembers its own open/closed state; the
  hunt form's starts collapsed (it's the primary, frequently-used form), the rest start open.

443 tests green (UI-only change).

## v0.50.0

### BugHunter — screenshots resolve scope at capture time (edit-and-recapture)
The **Capture screenshot** button was checking the scope FROZEN into a finding's cached run,
so adding a host to scope *afterward* never took effect — the capture kept failing the
fail-closed gate until you re-ran the whole hunt.

- The screenshot endpoint now resolves scope at **capture time** by unioning three
  operator-supplied sources: the cached run's own scope, the **live program's current
  `scope_text`** (so editing + saving an Operator program's scope takes effect WITHOUT
  re-running the hunt), and an optional **scope override from the request** — the cockpit's
  current Scope box, now sent by the Capture button. Add the host, click capture again; no
  re-run needed.
- The union only ever **widens** to hosts you explicitly named: `host_in_active_scope` (plus
  the SSRF / URL guard) still runs against the union and still fails closed, so an unnamed
  host is refused exactly as before.

443 tests green (+8), including ALLOW-direction tests that drive the real scope gate end-to-end.

## v0.49.0

### Operator — edit existing programs
You can now **edit** a program in the operator, not just enable/disable or delete it.

- Each program row gets an **Edit** button that loads it into the form (name, scope, seed
  targets, HackerOne handle, interval, daily cap, and all toggles pre-filled). Saving **updates
  that program in place** (it carries the id) instead of creating a duplicate, and preserves the
  fields the form doesn't expose (enabled state, recon depth). A **Cancel** backs out of editing.

435 tests green.

## v0.48.0

### Phase C complete — DNS CNAME correlation for takeover (vendored mini-resolver)
The last Phase C item: a minimal DNS-over-UDP CNAME resolver (stdlib `socket` only,
frozen-safe — no dnspython), wired into the subdomain-takeover scan.

- For each in-scope resolved subdomain, GreyIQ resolves its CNAME chain and correlates it with
  known-takeoverable services (GitHub Pages, S3, Heroku, Fastly, Azure, Netlify, …). A CNAME to
  such a service **enriches** a confirmed takeover (stronger proof), and a **dangling CNAME with
  no body fingerprint** is surfaced as a medium **candidate** (the resource may be claimable)
  for the operator to verify.
- Bounded (max 40 lookups, short timeout); the lookup goes to a public resolver (the external
  DNS the OS already uses), never the target. Best-effort — any failure falls back cleanly.

435 tests green (+10). This completes the Phase C plan.

## v0.47.0

### Phase C — stored (persistent) XSS confirmation (assisted + opt-in send)
Confirms a marker payload SUBMITTED on one request and RENDERED UNESCAPED on a DIFFERENT
view page — true stored XSS, distinct from the reflected check.

- **Assisted (default, GET-only):** GreyIQ mints a unique marker payload; submit it via your
  own tooling, then GreyIQ GETs the view URL and confirms whether the raw executable tag
  rendered.
- **Auto (opt-in `send`):** GreyIQ POSTs the payload into the field at the inject URL — a
  guarded, scope-bound, no-redirect form POST (the engine's second non-GET egress, like the
  XXE `send`) — after checking a fresh marker is absent first (negative control).
- Confirmed **only** when our unique marker payload appears RAW in the view page (escaped ->
  not confirmed; absent -> not stored), so the proof embeds only our marker. Wired:
  `POST /api/bounty/stored-xss` + a cockpit "Stored XSS" panel; a confirmed render caches a run.

425 tests green (+9). With this, the active Phase C list is complete (only takeover CNAME
correlation remains — it needs a DNS library not in the frozen build).

## v0.46.0

### Phase C — IDOR discovery probe (single-session id mutation)
Auto-discovers IDOR candidates so the dual-session confirm has something to point at:

- `run_idor_probe` mutates the numeric ids in a URL — **path segments and query values,
  including a URL carrying two ids** — and flags when a neighbouring id returns a DISTINCT
  valid object (same template, different data) with the same session: a likely missing
  per-object authorization.
- **Candidate-grade and honest:** one session can't prove the neighbour belongs to another
  tenant, so it explicitly points to the dual-session IDOR confirm. The neighbour body is
  never embedded (proof is the differential). Identical/denied/different-page neighbours are
  reported as enforced.
- Wired: `POST /api/bounty/idor-probe`, `gn idor-probe <url> -y`, and a probe form in the
  cockpit access-control view. A candidate caches as a run (the submit gate still refuses it).

416 tests green (+7).

## v0.45.0

### Phase C — CSRF (missing anti-CSRF token, candidate-grade)
A new passive check in the active suite: a **state-changing POST form served with no
anti-CSRF token**.

- Honest tiering — modern browsers default cookies to `SameSite=Lax`, which already blocks
  cross-site POST, so a missing token alone is rarely exploitable. A tokenless POST form whose
  session cookie is explicitly `SameSite=None` is a **medium** candidate; if a Lax/Strict
  cookie is observed it's **skipped** (protected); otherwise a **low** candidate the operator
  verifies (the limitation is stated in the finding).
- Skips forms that carry a token field (csrf/xsrf/authenticity_token/…) or a page-wide
  `<meta name="csrf-token">`. GET-only, passive form inspection. Maps to the CSRF class.

409 tests green (+6).

## v0.44.0

### Phase C — certificate-transparency subdomain seeding (takeover)
Subdomain-takeover enumeration now seeds from certificate-transparency logs (crt.sh) — the
highest-yield source of real subdomains the wordlist misses.

- Queries crt.sh for the apex's issued certs (OSINT — it queries the public CT logs, **never
  the target**), parses + de-duplicates the hostnames under the apex (wildcards stripped), and
  folds them into the candidate set alongside the wordlist + recon-discovered hosts.
  Best-effort: any failure or out-of-apex name is dropped and enumeration falls back cleanly.
- This is the engine's first **external (non-target) egress**, by explicit operator opt-in.
  The per-host fetch + takeover confirmation stay scope-bound, GET-only, and SSRF-guarded.

403 tests green (+4).

## v0.43.0

### Phase C — NoSQL injection (error-based, confirm-grade)
A new active check that finds NoSQL injection, added to the active suite (so it runs in every
active hunt/campaign):

- Sends a parameter as a NoSQL **operator object** (`param` → `{$ne: ...}`); a NoSQL backend
  error banner that appears **only** for the operator (not the scalar control) confirms the
  injection point — e.g. Mongoose casting `{$ne:...}` to a typed field (CastError). High
  precision, mirroring the trusted SQL-error check.
- Only **unambiguous** Mongo / Mongoose / BSON / PyMongo / Couchbase banners count; a generic
  stack trace never confirms, and a page that always shows the banner fails the negative
  control. Maps to the existing NoSQLi class (CWE-943, A03:2021 Injection).

399 tests green (+4).

## v0.42.0

### Phase C — BFLA (broken function-level authorization)
Confirms a privilege-escalation class with the same proven dual-session machinery as IDOR,
GET-only:

- A **three-session differential** (admin / low-privilege user / anonymous): confirms only
  when the low-privilege user's response ~matches the **admin** response **and** an anonymous
  request is denied/different — so the endpoint is genuinely access-controlled, not a public
  page. Otherwise reported honestly as `enforced` or a `candidate`.
- The privileged body is **never embedded** — the proof is the differential only (statuses +
  similarity ratios), exactly like IDOR.
- Wired everywhere: `POST /api/bounty/bfla`, `gn bfla <url> -y` (high-/low-priv sessions), and
  a BFLA panel in the cockpit access-control view. A confirmed bypass caches as a run.

395 tests green (+7).

## v0.41.0

### Phase C — API surface discovery (OpenAPI/Swagger + GraphQL)
Recon now maps the machine-readable API surface, multiplying what every active check reaches:

- Fetches the common **OpenAPI/Swagger** spec locations (`/openapi.json`, `/swagger.json`,
  `/v3/api-docs`, …), parses OpenAPI 3.x **and** Swagger 2.0, and feeds the concrete GET
  endpoints + declared parameter names into the prover's surface. A public spec is treated as
  surface expansion, **not** a finding (it's often intentional).
- Probes the common **GraphQL** routes with a GET introspection query; if the schema comes
  back, introspection-enabled is added as a **candidate** finding (type/field evidence + an
  inline plan). It runs inside the campaign, so the operator surfaces it automatically.
- GET-only, scope-gated (fail-closed), SSRF-guarded, and budget-shared with recon.

388 tests green (+10).

## v0.40.0

### Blind XXE over OOB (assisted + opt-in auto-send)
Confirms blind XML External Entity (XXE) injection out of band — the XML parser resolving an
attacker-supplied external entity makes a request to your collaborator, proving the bug
**without exfiltrating any file** (the entity only fetches the callback).

- **Assisted (default, GET-only):** GreyIQ mints a token and hands you ready payload variants
  (classic, parameter-entity, SVG, SOAP) with the callback embedded; deliver one to an XML
  endpoint, then re-poll the token to confirm.
- **Auto (opt-in `send`):** GreyIQ POSTs the benign payload itself — its first and only
  non-GET egress, gated, scope-bound, SSRF-guarded, no-redirect. Same negative-control +
  crawler-UA hardening as the SSRF path.
- Wired: `POST /api/bounty/oob-xxe` and a "blind XXE" panel in the cockpit OOB section.
  Confirmed/candidate hits cache as runs (report / bundle / submit); the hard submit gate
  still only auto-files confirmed findings.
- **DNS OOB channel — deferred.** A DNS channel needs an authoritative DNS server logging
  queries, which the phone-behind-an-HTTP-Cloudflare-tunnel collaborator can't host (tunnels
  carry HTTP, not UDP:53). Revisit with a small VPS or a delegated domain running a logging
  resolver.

378 tests green (+8), plus a no-network end-to-end smoke (auto-send confirms + caches a run;
assisted returns the payload kit without sending).

## v0.39.0

### Wider known-CVE coverage — more libraries + CMS detection
The outdated-component check now fingerprints more of the front-end stack:

- Added **jQuery UI** (with a guard so it's never confused with jQuery core), **Axios**,
  **Underscore.js**, and **Mustache.js** to the curated CVE table, plus **WordPress core**
  via the `<meta generator>` tag and an `X-Powered-By` header.
- `detect_components` is now header- and meta-aware (it reads response headers and the
  generator tag, not just the body).
- Server-software banner versions (`Server:`, `X-Powered-By:` nginx/Apache/PHP) are
  **deliberately not** mapped to CVEs — version-alone is low-signal and routinely rejected,
  which would be a false positive against the engine's confirm-grade promise. Only products
  with a clean version and a real, accepted CVE are matched.

370 tests green (+5).

## v0.38.0

### Known-CVE detection now runs inside every campaign (passive earnings)
The outdated-component check (v0.37.0) is now part of the campaign pipeline — so the
autonomous operator surfaces it automatically on every program it runs, with no separate step.

- After recon, a single scope-bound, SSRF-guarded GET of the target fingerprints its
  front-end libraries; each outdated component with known CVEs is folded into the campaign as
  a **candidate** finding (one per library), carrying its own attack plan, CVSS, EPSS-style
  score, and KEV flag. It shows on the cockpit's findings board, in `CAMPAIGN.md`, and in the
  downloadable bundle.
- Honest as ever: candidates, never "confirmed" — the hard submit gate still refuses to
  auto-file them. Scope defaults to the target's own host when a campaign is run without an
  explicit scope (matching recon), and the pass is best-effort (never breaks a campaign).

365 tests green (+1).

## v0.37.0

### New earner — known-CVE / outdated-component detection (Phase B)
A new passive check that finds a class programs pay for: outdated front-end libraries with
published CVEs.

- Fingerprints the **versions** of jQuery, Lodash, Bootstrap, Moment, AngularJS, Handlebars,
  and DOMPurify from script `src` filenames and the libraries' own version banners (with a
  guard so `jquery-ui` / `jquery-migrate` don't masquerade as jQuery core), then maps each
  detected version to a curated, offline table of real CVEs whose fix is in a higher version
  — each with its CVSS, CWE, an estimated EPSS-style exploit-likelihood, and a KEV flag for
  prioritisation.
- **Honest tiering:** results are version-fingerprint *candidates*, not claimed exploits.
  They cache as runs so you can export the outdated-component report / bundle, but the hard
  submit gate refuses to auto-file a candidate — it recomputes proof status server-side and
  only CONFIRMED findings can be auto-submitted.
- Wired everywhere: `POST /api/bounty/cve`, `gn cve <url> -y`, and a "Known-CVE components"
  panel on the cockpit's Surface view. GET-only, scope-bound (fail-closed), SSRF-guarded.

364 tests green (+15), plus a no-network end-to-end smoke proving the candidate path caches a
run and the submit gate refuses it.

## v0.36.0

### QA hardening round 3 — confirm-route robustness + one severity source of truth
The audit's architecture items, landed:

- **No more opaque 500s on the confirm routes.** The IDOR / takeover / OOB-SSRF routes now
  share one `_persist_finding_run` tail (build ctx → render → write `.md` **+ `.json`** →
  cache the run) instead of three drifting ~30-line copies, and each is wrapped so an
  unexpected service/render exception returns a structured `{ok: false, error}` the cockpit
  can show (the full traceback is logged server-side). The OOB route — which silently
  skipped its JSON evidence sidecar — now writes one like the others.
- **A finding's severity can no longer disagree across outputs.** A single
  `resolve_severity()` (CVSS-preferred, then the raw scanner label) is the source of truth,
  resolved once at confirm time and written back onto the finding — so the cockpit toast,
  the default report's table/detail/triage, the per-platform report, and the HackerOne
  `severity_rating` always show the same word.
- **PoC screenshots embed on every report surface**, not just the per-platform package —
  the default report (`build_markdown` + `build_finding_markdown`) now renders the captured
  screenshot too (by basename, with the not-auto-redacted caveat).

349 tests green (+10), plus a live end-to-end smoke of the refactored confirm path.

## v0.35.0

### QA hardening round 2 — boolean-SQLi precision + the safety-critical tests
Continuing the audit-driven hardening:

- **Boolean-blind SQLi** now rejects an *infrastructure* differential: the TRUE/FALSE
  divergence must be two clean **200s with no SQL-error banner** (a WAF/error block page of
  a different length no longer confirms), and must **reproduce on a second pass** before it
  confirms.
- Added targeted tests for the two **most safety-critical functions, previously untested**:
  the SSRF/URL policy (`web_ingest._enforce_url_policy` — refuses non-http schemes, embedded
  credentials, non-standard ports, and private/loopback/link-local/cloud-metadata IPs) and
  the archive **zip-slip / tar-slip** guard (rejects traversal, absolute, and null-byte
  member names).

339 tests green (+14).

## v0.34.0

### QA hardening — fewer false positives, accurate severity (engine-wide audit)
A multi-agent QA/QC audit of the whole engine drove a round of precision fixes so a
"confirmed" finding stays trustworthy:

- **Subdomain takeover:** removed two generic-404-grade fingerprints (Webflow, Heroku
  "There's nothing here, yet.") that fire on normal sites, and now require an **error
  (4xx/5xx) response** — a normal 200 page that merely *quotes* an "unclaimed" phrase no
  longer confirms. Added **wildcard-DNS detection** (a catch-all record no longer makes
  every label "resolve"), and reconciled the finding severity with its CVSS (high).
- **OOB blind SSRF:** added a **pre-probe negative control** (the fresh, unguessable token
  must be empty), confirm only on the token going 0→1 after the probe, **downgrade
  callbacks from social unfurlers / search crawlers to a candidate** (generic HTTP-library
  UAs, which a real SSRF backend uses, stay confirmed), and make a transient collaborator-
  poll error non-fatal across params.
- **Host-header injection:** a Host reflected only into the **response body** (common and
  usually harmless) is now a low **candidate** with a proof obligation; only a Host
  reflected into the **Location header** stays confirmed.
- **Report taxonomy:** corrected the GraphQL Bugcrowd VRT (was a DNS-misconfig category)
  and the XSS VRT (over-asserted "stored" → "reflected").

325 tests green (4 new regression tests).

## v0.33.0

### Confirm blind bugs out-of-band (OOB collaborator)
GreyIQ can now **confirm blind, out-of-band vulnerabilities** — blind SSRF above all —
using your own OOB collaborator (e.g. the greynoc-chat `/oob` receiver running on your
phone). It mints a unique callback URL, injects it into the target's server-side-fetch
parameters, sends a benign GET probe, then polls your collaborator for an inbound hit: a
recorded callback **proves** the target reached out of band, where nothing reflects in its
own response.

- New **Out-of-band** panel in the cockpit's Access-control tab: configure your collaborator
  (URL + secret, write-only), auto-confirm blind SSRF against a target, or **mint a callback
  URL** to paste into a manual XXE / blind-XSS payload.
- `POST /api/bounty/oob-ssrf` (a confirmed hit is cached as a run, so the per-platform
  report / screenshot / research / bundle / submit all work on it), plus `/api/oob/config`,
  `/api/oob/mint`, `/api/oob/poll`.
- Scope-bound + SSRF-guarded target probes; the collaborator secret lives in GreyIQ's
  secrets store and is never embedded. Pairs with the new greynoc-chat OOB receiver.

## v0.32.0

### Subdomain enumeration + takeover — more surface, a high-value easy win
GreyIQ now maps more of the attack surface and confirms **dangling subdomain takeovers** —
a DNS record still pointing at a deleted third-party resource (GitHub Pages, S3, Heroku,
Fastly, Shopify, …) that an attacker can claim to serve content on the target's own
subdomain.

Give it an in-scope apex; it enumerates subdomains from a bounded label wordlist (resolved
via DNS — no external API) plus any hosts recon already found, fetches each resolving,
in-scope host **GET-only through the same SSRF/private-host guard**, and confirms a takeover
only on a **strong, service-specific "unclaimed" fingerprint** (curated to unique signatures
so a normal page or a plain 404 never matches). No resource is ever claimed.

A confirmed takeover is a first-class finding: a **Subdomain takeover** form in the cockpit's
Surface tab, `gn takeover example.com -s example.com -y`, and `POST /api/bounty/takeover` —
all flowing into the per-platform report, screenshot, research, downloadable bundle, and the
hard-gated submit.

## v0.31.0

### Confirm IDOR / broken access control — the #1 paying class
GreyIQ can now **prove** IDOR/BOLA (broken access control), the highest-value bug class
and the one a single-session scanner can't touch because it needs two accounts. You supply
**two of your own authorized test accounts** and one object URL each; the engine runs a
GET-only, scope-bound, three-request differential:

- account A reads A's object (ground truth),
- account B reads B's own object (control — proves B's session is valid),
- account B reads **A's** object (the attack).

It confirms a cross-tenant read only when B's response to A's object is ~identical to A's
own **and** matches A clearly more than it matches B's own object — so a real IDOR is told
apart from a properly-scoped endpoint or a shared/static page (no false "confirmed").

Crucially, the captured proof is the **differential only** (statuses + similarity ratios) —
the other user's data is **never shown, stored, or written into the report**. Each session
is attached same-site only, so neither credential ever leaves the target host.

A confirmed IDOR becomes a first-class finding: a new **Access control** cockpit tab,
`gn idor <A-url> <B-url> --a-cookie ... --b-cookie ... -y`, and `POST /api/bounty/idor` —
all flowing into the per-platform report, screenshot, research dossier, downloadable
bundle, and the hard-gated HackerOne submit.

## v0.30.0

### Deep mode runs unattended — the operator works leads aggressively on a schedule
The autonomous operator can now run programs in **deep mode**. Add a program with **Deep
auto-work** on (a new toggle in the operator program form, `gn operator add --deep`, or
`deep: true` on `POST /api/operator/programs`) and each scheduled cycle runs the campaign
aggressively: proof-of-impact + time-based blind SQLi, then a screenshot and a researched
dossier for every confirmed lead — all written into the engagement folder, hands-off.

Same safety model: deep is **fail-closed** (a program with no scope can't be deep, exactly
like active/live), deep **implies proof-of-impact** (a deep program is always active), and
it adds **no new egress** — it reuses the operator's existing scope-bound campaign and the
unchanged, hard-gated auto-submit path (armed + per-program opt-in + server-confirmed +
ledger-dedup + per-day throttle).

## v0.29.0

### Work the lead end to end — research, prove, and download the whole engagement
GreyIQ can now take a lead all the way to a submittable result and hand you the entire
engagement as one download.

- **Research each lead (your brain, your choice).** A new **Research this lead** action
  writes a research dossier per finding — what the bug is here, why it matters, an ordered
  plan to confirm it, exploitation notes, variants to try, and references. It uses the
  **brain you plug in** (Claude / ChatGPT / local Ollama) and makes **no internet calls**;
  with no brain configured it still produces a complete deterministic dossier. (`POST
  /api/bounty/research`.)

- **Screenshot the exploit.** A new **Capture screenshot** action drives a headless
  browser to a finding's proof-of-concept URL and saves a PNG that's embedded in the
  report and the submission package. Opt-in, scope-bound and SSRF-guarded, and clearly
  flagged as **not auto-redacted — review before you submit** (an image can't be scrubbed
  the way text evidence is). Needs Playwright (`pip install playwright && python -m
  playwright install chromium`); degrades cleanly when absent. (`POST
  /api/bounty/screenshot`.)

- **Deep mode — commit to the plan automatically.** A new **Deep auto-work** toggle (and
  `gn campaign --deep`) implies proof-of-impact + time-based blind SQLi, then for each
  *confirmed* lead auto-captures a screenshot and writes a researched dossier into the
  engagement folder. Still GET-only, scope-bound, and bounded.

- **Download everything (.zip).** A new **Download everything** button (and `gn bundle
  <folder>`, `POST /api/bounty/bundle`) packages the whole engagement — reports,
  per-platform submission packages, captured evidence, screenshots, research dossiers,
  and JSON — into a single .zip you can submit from.

## v0.28.0

### Choose your reporting format — HackerOne, YesWeHack, Bugcrowd, Intigriti
Submission reports can now be shaped for the destination platform. The **same finding —
and the same gathered evidence —** is reframed with each platform's own conventions:

- **HackerOne** — Weakness (CWE) + severity rating; Summary / Steps / Supporting material / Impact.
- **YesWeHack** — Bug type (CWE) + CVSS vector; Description / Steps / PoC / Impact / Remediation.
- **Bugcrowd** — VRT-led with a P1–P5 priority; Description / Steps / PoC / Impact / Remediation.
- **Intigriti** — Type (OWASP/CWE) + CVSS; Description / Endpoint / PoC / Impact / Recommended fix.

Pick the format in the Hunt cockpit's **Submissions** tab (a new selector). **Copy report**
and **Download .md** produce the chosen platform's layout, and the gathered evidence — the
captured request/response, matched values, `Set-Cookie`, and code/response excerpt — is
always included when the finding carries it. The one-click API submit still files to
HackerOne (the only wired platform API); use Copy/Download to file on the others.

On the CLI, `gn platforms` lists the formats and `gn campaign --platform <id>` writes the
submission packages in that format. New `GET /api/bounty/platforms`. The report framing is
done by a new `report_formats` module that re-shapes `report.py`'s output per platform
without changing what the HackerOne API submit sends.

## v0.27.0

### Find more — discovered parameters now feed the active prover
The active verification checks (reflected XSS, SSTI, error/boolean/time-based SQL
injection, open redirect, CRLF) used to inject only into parameters that were already
present in a URL's query string. Recon mined parameter names from the target's own
JavaScript — but the campaign discarded them, so an endpoint discovered without a query
string (for example `/search` with no `?q=`) was never probed for the parameters it
actually takes.

Now the parameter names recon discovers are threaded into every parameter-keyed active
check. Coverage is strictly wider with **no extra requests on already-parametered URLs**:
the URL's own parameters are tried first and the discovered names only fill the slots a
URL leaves empty (capped per check), so a param-less endpoint that previously tested
nothing now probes its real parameters. The SQL-injection checks still refuse to invent
an injection point — they act only on a parameter the URL carries or that recon actually
found.

Recon also mines more parameter sources: HTML form fields (`input`/`select`/`textarea`/
`button` names) on every crawled page, plus the query-string parameter names of every
discovered URL (so a parameter seen on one endpoint is tried against a param-less
sibling). The safety envelope is unchanged — GET-only, scope-bound and fail-closed,
marker-plus-negative-control confirmation, and a per-host/per-hunt request budget; every
discovered name is validated and capped before it is ever used as a probe key.

## v0.23.0

### Much smaller download + faster first launch — Ollama is now on-demand
Ollama (the local-model runtime) was **~1.4 GB — about 86% of the portable** — and
the bug-hunting engine and the Claude/OpenAI brains never use it. It is **no longer
bundled**: the portable/installer drop to roughly **~250 MB**, and the first-launch
unpack shrinks accordingly (on top of the v0.15.0 boot-time fix).

Ollama is now **downloaded on demand** to a writable `userData` dir the first time the
operator actually selects the **local** model in the Brain settings — reusing the same
proven download/extract path the AMD/ROCm runtime already used. The renderer triggers
it via a new `greyiq:ensure-ollama` IPC; nothing downloads at boot, and a system-
installed Ollama (already serving on the port) is used directly. NVIDIA GPUs still work
on the downloaded base runner; AMD/ROCm is still fetched on first run. Removed the now-
redundant Ollama bundling step from the Windows + Linux release CI (also relieving the
Linux runner's disk pressure).

## v0.22.0

### Headless operator — run the loop with no GUI (`gn operator`)
The autonomous operator is now drivable from the terminal, so it can run on a server,
a VPS, or a phone:
- `gn operator add --name acme --scope "*.acme.com" --targets https://acme.com [--active] [--auto-submit --handle <team>]`
- `gn operator list` / `remove <id>` / `pipeline` (the money funnel)
- `gn operator run -y [--once] [--allow-submit]` — runs the unattended loop (continuous
  with a live event stream + Ctrl-C kill switch, or `--once` for a single pass).

It builds the loop's callables directly over the torch-free engine, so the submit path
goes through the **same** hard-gated `submit_to_hackerone` (confirm + server-recomputed
`proof_status=='confirmed'` + the creds the desktop app stored). `run` requires an
explicit `-y/--authorize`; auto-submission stays off unless `--allow-submit` is passed
**and** the program opted in **and** has a HackerOne handle.

## v0.21.0

### Surface expansion — find far more, still in scope
Recon now mines the real attack surface, not just the landing page:
- **Served-JS mining** (`recon_js.py`) — pulls in-scope API **endpoints**, query-param
  **names**, same-apex **hosts**, and (already-**redacted**) leaked **secrets** out of
  bundled JavaScript. Discovered endpoints become hunt targets (so the active prover's
  XSS/SQLi/redirect/CRLF checks get real parameters to bite on), and JS secrets are
  folded into the campaign findings.
- **In-scope cross-host discovery** — recon now follows hosts the program scope allows
  (a wildcard like `*.acme.com`), gated by the **same fail-closed
  `host_in_active_scope`** the active prover uses. Every new host is checked **before**
  it's fetched; out-of-scope hosts are counted, never fetched.
- **Tech fingerprinting** (`fingerprint.py`) — names the stack from already-fetched
  headers/cookies/body and emits advisory hints (e.g. Django → emphasize SSTI/SQLi).
  Advisory only: it reorders which already-gated checks run, never enables one.

### Safety
A new **global per-campaign request budget** (default 40) bounds total fetches — the
kill switch for host fan-out under a wildcard scope, on top of the per-host governor.
Served-JS mining is bounded (≤8 bundles), secrets are redacted inside `recon_js`
before they leave it, and the SSRF/private-host/port guard runs on every fetch. No new
deps; pure stdlib.

## v0.20.0

### Report polish — land more reports
- **Clickable CWE / OWASP references.** Every `CWE-<n>` becomes a link to its MITRE
  page (compound `CWE-639 / CWE-284` handled) and each `Axx:2021` OWASP token links to
  its Top-10 category page, in both the per-finding report and the main report.
- **Bugcrowd VRT alongside the HackerOne rating.** Each finding carries an estimated
  Bugcrowd VRT category (`impact_model.bugcrowd_vrt`), rendered in the report header
  and included in the submission package — so a report speaks both platforms' language.
- **Evidence-completeness score.** The submission-readiness checklist and a new
  machine-readable `completeness` map ({score, max, missing}) now share one predicate
  list (they can't drift), with two added evidence-grade checks (a captured request/PoC
  artifact, a negative control). It's **advisory only** — never a submit precondition;
  the submit gate stays confirm + confirmed proof + creds.

## v0.19.0

### The autonomous operator — run the whole bounty loop unattended
Point GreyIQ at a **portfolio of programs** and it runs the money loop on a schedule
without hand-holding: recon → hunt → prove → consolidate → **dedup across runs** →
rank by expected value → submission packages → (only when explicitly armed) **file
confirmed findings**, then reschedule and move on. A new **Operator** tab in the
cockpit is the control panel: program management, a live activity log, the kill
switch, and a money pipeline funnel (discovered → confirmed → reported → submitted →
paid, with $ per program).

New modules, all pure/frozen-safe (stdlib + the existing stores):
- **`portfolio.py`** — the program list (`RUNTIME_DIR/portfolio.json`): scope, seed
  targets, cadence, and **fail-closed** automation flags (active/live/auto_submit all
  default OFF; an empty scope or missing HackerOne handle forces auto-submit off).
- **`ledger.py`** — a persistent finding ledger keyed by a stable dedup key
  (`class|rule|digit-normalized-location`). It powers **cross-run dedup** (a re-run
  never re-reports — or re-files — a finding it already reported) and the pipeline
  funnel. `stage='confirmed'` is set *only* when the server-truth `proof_status` is
  confirmed, so the funnel can't inflate the submit-eligible pool.
- **`ranking.py`** — expected-value ordering (`severity × learned prior × confirmed
  weight × program-pay factor`, every factor bounded), with **confirmed as the
  outermost sort key** so a confirmed finding never sinks below a lead.
- **`operator.py`** — the unattended loop: a background supervisor that runs due,
  enabled programs sequentially, a stop-event **kill switch** checked between every
  program and before every submit, and the run-cycle that hunts each target and
  (when armed) auto-files.

Campaign consolidation now ranks by EV and records every finding in the ledger,
skipping a submission package for anything already reported in a prior run.

### Safety (unattended automation, done right)
Auto-submission is **quadruple-gated** and optimizes for high signal, never volume:
the loop must be started with **arm auto-submit** *and* the program must opt in *and*
the finding must be server-recomputed **confirmed** *and* not already
reported/submitted (ledger dedup) *and* within the program's daily cap. The operator
adds **zero new network/scanning code** — it calls the same `run_campaign` (recon
stays same-origin, active probing stays scope-bound and fail-closed) and the same
**unbypassable** `submit_to_hackerone` gate (confirm + server-recomputed
`proof_status=='confirmed'` + real creds). Starting it requires an explicit
authorization confirmation.

New API: `GET/POST /api/operator/programs`, `/programs/delete`, `/start` (authorized +
arm), `/stop` (kill switch), `/events`, `GET /api/operator/pipeline`. +13 tests
covering the dedup, throttle, fail-closed scope, and "review-only never submits"
invariants.

## v0.18.0

### Prove more — three new GET-only active confirmations (more submittable findings)
More leads become **Confirmed** (the bar for filing), all inside the existing
double-gated, scope-bound, negative-control, budgeted active envelope:
- **Boolean-based blind SQLi** — an `AND '1'='1'` vs `AND '1'='2'` differential that
  reads **one boolean bit** and extracts no data. Confirms only when two unmodified
  baselines are near-identical (the page is stable enough to differentiate — its own
  negative control) AND the TRUE branch tracks the baseline while the FALSE branch
  diverges materially; a flapping/dynamic page or an ignored parameter degrades to
  no-finding rather than over-claiming. No timing, no `SLEEP`, no `UNION`.
- **CRLF / response-header injection** — injects an encoded CRLF + a benign custom
  header marker into a parameter and confirms only when the server **splits it into a
  real response header** equal to the marker AND a control without the CRLF does not.
- **Two more CORS confirmations** — `Origin: null` trusted with credentials, and an
  arbitrary **subdomain** Origin reflected with credentials — each gated by a distinct
  negative control so the reflection is proven attacker-driven.

All GET-only with benign markers; every "confirmed" is backed by a same-run control.

## v0.17.0

### Find more — five declared-but-empty vuln classes now detect
Static sink rule packs take five bounty classes that previously found *nothing*
(only a manual checklist) to real findings, each classified accurately with CWE/OWASP:
- **Open redirect** (`open_redirect` → `redirect`): Flask/Django/Express redirect to a
  request value, and DOM-based `location` from a URL param.
- **SSTI source** (`ssti`): Jinja2 `render_template_string` built from input,
  `Template(var)`, Handlebars/EJS/Pug compiled from a variable — complements the
  active `{{7*7}}` confirmation.
- **XXE** (`xxe`): lxml/stdlib/PHP/Java XML parsers without entity/DTD hardening
  (suppressed when a hardened-parser token is on the line).
- **Weak JWT** (`jwt`): `alg:none`, signature verification disabled, short hardcoded
  HMAC secret.
- **Insecure deserialization** (`deserialization` → `rce`): PHP `unserialize($_GET)`,
  Ruby `Marshal.load`, Java `ObjectInputStream.readObject` (Python pickle/yaml/marshal
  were already covered by the eval/exec pack).

All sink-only, HIGH severity with honest LOW/MEDIUM confidence, pure-regex and
frozen-safe; safe forms (parameterized, hardened-parser, constant target) don't match.

### Report — every finding is submission-grade
- **Remediation + references floor.** Every vuln class now carries a concrete,
  verifiable fix sentence and 2–3 authoritative links (OWASP cheat sheet + CWE +
  PortSwigger). A fully offline run now renders a **Remediation** and a **References**
  section on every finding (previously present only on some scanner rules / when the
  brain was configured), and the submission-readiness "concrete fix" checkbox now
  passes. New `impact_model.remediation_for_class` / `references_for_class`.

New tests: the five sink packs (positive + negative-control per pack, no rule_id
collisions, accurate classification) and the remediation/references coverage +
offline-report rendering.

## v0.16.0

### After-testing workflow — submit a report straight from the app
The cockpit's Submissions tab is now a real worklist: after a run you can get the
**canonical** server-built report per finding, export it, and file a confirmed
finding to HackerOne — without leaving the app.

- **Canonical packages, not client drafts.** A new `POST /api/bounty/submission`
  rebuilds the exact `build_finding_markdown`/`build_submission` package the CLI and
  campaign use (title, severity rating, CWE, CVSS, steps, proof, remediation), keyed
  by a `run_id` the scan/campaign response now returns (bounded in-memory run cache —
  no re-scan). The detail drawer and Submissions queue **Copy report** / **Download
  .md** now use this canonical output, falling back to the offline draft only if the
  run was evicted.
- **File to HackerOne, hard-gated.** A new `POST /api/bounty/submit` calls the
  existing `submit_to_hackerone`, which **refuses unless** an explicit confirm, a
  **server-recomputed `proof_status == "confirmed"`**, and real credentials are all
  present — a forged client request can't push a non-confirmed finding. The cockpit's
  **Submit to HackerOne** button is disabled until a finding is Confirmed *and* creds
  are configured (a UI mirror of the gate, never a replacement), and asks for an
  explicit confirmation naming the team + finding before it fires.
- **Credentials in the perms-restricted secrets store.** `GET/POST
  /api/bounty/hackerone/creds` store the team handle + API username/token alongside
  the provider keys (atomic, private file); the status endpoint returns only
  `has_token` — the token is **never echoed** back to the browser.
- A successful submit records the outcome to the learning store (`status: submitted`)
  and marks the finding submitted in the queue, closing the run → submit → learn loop.

New tests: canonical package build, the server-authoritative submit gate (refuses
non-confirmed even with creds + confirm), creds round-trip (token never leaked), and
the bounded run cache.

## v0.15.0

### Much faster startup — the portable opens in a fraction of the time
Profiling the double-click → window path found two avoidable costs, both fixed:

- **PyTorch dropped from the packaged binary (~1.2 GB → gone).** Torch was 86% of the
  1.4 GB payload and the bug-hunting engine never uses it — it only powered the
  offline TinyGPT chat brain and the Train tab (both now in the demoted Studio). The
  portable download and the **one-time first-launch unpack shrink ~6×** (the old
  fresh-run unpack was measured at ~200 s). The Ollama/Claude coding brain and every
  bug-bounty feature are unaffected; the offline local model degrades to a clear
  "local model unavailable" message in the packaged app (still available from source,
  and re-bundlable via the build spec).
- **Torch + pandas are no longer imported at boot.** The backend imported the
  torch-backed local-model runtime (`solin_core`, ~3.9 s) and document ingestion
  (`pytesseract`→`pandas`, ~1.4 s) at module load, before it could answer
  `/api/health` — the gate the desktop window blocks on. Both are now imported
  **lazily on first actual use**, cutting the API's import time from **~6.0 s to
  ~0.65 s on every launch**. `/api/status` still reports local-model availability via
  a cheap `find_spec` probe (no torch import).

New regression tests pin both invariants (no torch/pandas on the boot path; the
service boots and degrades gracefully when torch is absent — the frozen condition).

## v0.14.0

### Bug-bounty cockpit — the app is now bug-bounty-first
GreyIQ opens into a dedicated **Hunt cockpit** instead of the AI-studio chat. The
studio (chat, coding brain, training, Workbench) is preserved behind a single
**Studio ↗** toggle (a **◀ Hunt** button returns) — nothing was removed, the
default surface just changed.

The cockpit is a full bug-bounty workflow built directly on the engine:
- **Launch rail** — one form for a **Single hunt** or a **Full campaign**: target,
  scope/program, profile + focus class (hunt) or program handle + recon depth
  (campaign), and prominent safety switches (**Test for proof of impact**, dynamic
  Playwright pass, and a required **authorized** toggle). Authorization and active
  scoping stay enforced server-side, fail-closed.
- **Findings board** — the center stage: a sortable, filterable table (severity ·
  class/CWE · **proof-status pill** confirmed/candidate/missing · finding · location
  · CVSS), with a run-summary strip (risk, severity counts, an active-verification
  armed/disarmed chip) and filter chips (All / Confirmed / by severity).
- **Finding detail drawer** — click any finding for the full proof pane: numbered
  reproduction steps, the captured proof-of-impact (observed / control / evidence),
  the **“To confirm” obligation** for unproven leads, CVSS vector, impact,
  remediation, and a one-click **Copy submission draft**.
- **Surface** — the recon map for a campaign (discovered URLs + robots/sitemap/
  security.txt sources). **Submissions** — a confirmed-first draft queue.
  **Learn** — the per-program stats dashboard with an inline *record-outcome* form,
  so the learning loop closes without dropping to the CLI.

Every dynamic node is built DOM-only (`createElement`/`textContent`, never
`innerHTML`) so scanner- and brain-derived finding text can't inject markup.

### API
- `run_campaign` now also returns a compact structured payload (campaign-global
  finding refs + proof/CVSS maps + a `surface` block + severity counts + risk) so
  the cockpit renders one board for campaigns exactly like single hunts.

## v0.13.0

A whole-engine QA/QC pass (multi-agent audit of the find → prove → report
pipeline, every recommendation adversarially verified against the code) plus the
API surface the upcoming bug-bounty cockpit needs.

### Find — close real blind spots
- **Static SQL-injection sink pack.** A new `sqli` rule pack flags queries built by
  string-formatting (f-string / `%` / `+` / `.format` / template literal) handed to
  a DB `execute`/`query` across Python, Node, Go, Django, and PHP — HIGH severity,
  MEDIUM confidence. Parameterized calls and constant SQL do not match. The `sqli`
  bounty class now maps to real findings instead of an empty manual checklist.
- **Static SSRF sink pack.** A new `ssrf` rule pack flags server-side fetches of a
  non-literal URL (`requests`/`httpx`/`urlopen`, `axios`/`fetch`, Go `http.Get`,
  PHP) — HIGH severity, LOW confidence (the first argument is often a benign
  constant, so these are honest leads, not confirmed bugs). The `ssrf` class now
  produces findings.
- **Sensitive-path probe.** A hunt's web scan now probes a short, **constant**
  wordlist of well-known exposed paths (`/.git/config`, `/.git/HEAD`, `/.env`,
  `/.svn/entries`, `/server-status`, `/actuator/health`, swagger/openapi,
  `/.DS_Store`) and **content-validates** every hit — an SPA that returns its 200
  HTML shell for unknown paths is never flagged. Same-origin, GET-only through the
  existing SSRF/redirect guard, governor-throttled, redacted evidence, and **off by
  default** for the bare passive `/api/scan/web` (a quick scan stays a single GET).

### Prove — one more confirmation, fuller artifacts
- **Active SSTI check.** A new opt-in active check confirms server-side template
  injection with a benign `{{7*7}}` → `49` differential against a literal-string
  negative control (a coincidental "49" can't confirm — the marker must be evaluated
  adjacent to it). GET-only, inside the existing double-gated, scope-bound,
  budgeted active envelope.
- **Captured request header + raw HTTP repro block.** Active proofs now render the
  crafted `Origin:`/`Host:` request header (previously captured but silently
  dropped) and a copy-pasteable fenced `http` request→response block reconstructed
  purely from the already-redacted captured fields — the single most convincing
  artifact for a triager.

### Report
- **curl reproduction step.** The deterministic attack plan for a passive web
  finding now leads with a benign `curl -sSiL <url> | head -n 40` (shell-escaped) so
  an offline report still hands the operator a one-line repro. Source-code findings
  are unchanged.

### API — make the engine reachable from the browser
- **Structured findings on `/api/bounty/scan`.** The scan response now includes the
  per-finding `findings`, `attack_plans`, `proof_of_impact`, `cvss`, `class_counts`,
  and submission/retest checklists it already computed (and previously threw away),
  so a GUI can render a findings board + proof pane without re-parsing the markdown.
  Additive; redacted/scope-filtered exactly like the on-disk sidecar.
- **`POST /api/bounty/campaign`, `POST /api/bounty/learn`, `GET /api/bounty/stats`** —
  the end-to-end campaign and the learning loop are now reachable over the API
  (previously CLI-only), authorization still fails closed server-side.

### Fixed
- **Learning priors no longer self-corrupt on re-scan.** `learned_priors` now drives
  the reward-rate denominator off *adjudicated* outcomes (rewarded + duplicate/N-A)
  only — a weekly campaign auto-logging the same confirmed finding as "submitted" no
  longer dilutes an earned prior back toward neutral.

## v0.12.0

### Added
- **`gn campaign` — run the whole bounty end-to-end.** One command takes a target
  through the full bounty: **recon** maps the surface (a bounded, same-origin,
  depth/page-capped crawl plus passive recon of `robots.txt`, `sitemap.xml`, and
  `/.well-known/security.txt`), then the engine **hunts every discovered URL**
  (scan + optional `--active` proof of impact), **consolidates and ranks** the
  findings (deduped across the surface; ranked by severity × learned program priors
  × CVSS × confirmed-proof), and emits a **`CAMPAIGN.md` index plus a
  submission-ready package per reportable finding** under `submissions/`. Gated on
  `-y/--authorize`; `--active` captures proof, `--live` adds the dynamic Playwright
  pass, `--max-pages` caps discovery. Works on both URL targets (recon-crawled) and
  local repo/folder targets (single source-code hunt). Recon reuses the passive
  scanner's SSRF/private-host/port guard on **every** fetch (input URL, each redirect
  hop, and the final URL), is GET-only, same-origin-only, and rate-limited by the
  shared per-host governor.
- **Learn from the bounty.** A local, deterministic feedback loop: `gn learn -c
  <class> --status <accepted|resolved|duplicate|informative|not-applicable|triaged|
  submitted|spam> [--bounty N] [--program H | --target URL]` records a finding's
  outcome, and `gn stats [--program H | --target URL]` shows what the engine has
  learned per program. Outcomes build a per-program, per-class memory that sharpens
  the **next** campaign — classes a program has paid out for get a priority boost,
  classes that are consistently duplicate/N-A get a penalty — and the campaign report
  surfaces this "program intelligence" so the operator focuses where the program
  actually rewards. Pure JSON store under the runtime dir; no network, no ML.
- **Submission packaging.** Every reportable finding is exported as a HackerOne-shaped
  package (title, severity rating, CWE, impact, and the self-contained
  `vulnerability_information` body). Pushing to the HackerOne API is a separate,
  **hard-gated** action — it refuses unless given an explicit confirmation, a
  **confirmed** proof status, and real credentials, and is the only path that touches
  the network.

### Fixed
- **Windows long-path safety (`MAX_PATH`).** A deep install dir plus the campaign's
  nested `campaign-…/targets/` layout could push a report path past Windows' 260-char
  limit, surfacing as a misleading "file not found" on write (and a silently empty
  read). All report/submission/campaign reads and writes now route through a
  long-path-safe helper that transparently retries over the `\\?\` extended-length
  prefix on Windows. New `bughunter/fsutil.py`.
- The `gn` CLI now forces UTF-8 (with graceful fallback) on stdout/stderr so help text
  and output never crash on a `cp1252` Windows console.

## v0.11.1

_(The v0.11.0 release tag was consumed by GitHub's immutable-releases feature and
could not carry the binaries, so this re-tag also folds in the `gn` CLI.)_

### Added
- **`gn` — a short bug-bounty CLI.** Drive the same engine from the terminal:
  `gn hunt <url|repo> -y [-p profile] [-c class] [-s "scope"] [--active] [--live]`,
  plus `gn scan`, `gn profiles`, `gn classes`, and `gn tools <class…>`. A hunt is
  gated on `-y/--authorize`; `--active` runs the proof-of-impact testing. Torch-free
  and frozen-safe — the shipped backend binary doubles as the CLI
  (`greyiq-backend hunt …`), and `gn`/`gn.cmd` wrap it for source checkouts
  (`npm run gn -- …`).
- The Security tab's active option is now labelled **"Test for proof of impact"** to
  make the capture-the-proof workflow discoverable.
- **Active verification — prove findings, don't just flag them.** A new opt-in layer
  turns provable leads into *confirmed* findings with a captured request/response. For
  a URL target, ticking **Active verification** fires at most one benign
  GET/HEAD/OPTIONS per check to prove: reflected XSS (unescaped, HTML-context, with a
  no-marker control), CORS Origin reflection with credentials, open redirect
  (off-origin `Location` captured, never followed), host-header reflection, error-based
  SQL injection (a single quote eliciting a real **SQL** error banner), and clickjacking
  framability (a candidate with a PoC obligation). Each confirmed check writes a
  `status: confirmed` proof — backed by a same-run **negative control** — into the
  proof-of-impact slot, so the report renders "Confirmed" with the artifact in hand.
  Safety: strictly double-gated (active + authorized + URL), **scope-bound and
  fail-closed** (a host you didn't name in Scope is never probed — exact/suffix host
  matching, not substring), reuses the passive scanner's SSRF/private-host/port guard
  on every request, never follows redirects off-host, GET/HEAD/OPTIONS-only with benign
  markers, a per-host token-bucket plus a per-hunt request budget, and every artifact
  redacted. Default OFF. New `active_verify_service.py` + `rate_limit.py`; env knobs
  `GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST`, `GREYIQ_ACTIVE_MIN_INTERVAL_MS`,
  `GREYIQ_ACTIVE_SCAN_ALLOWLIST`.

## v0.10.0

### Added
- **Proof of impact, built in.** Every bug-bounty finding now ships a real impact
  model — attacker capability → affected asset → business impact — plus a
  **finding-specific proof obligation** (the exact artifact to capture to *prove* the
  impact for a submission) and an estimated **CVSS v3.1 vector with a computed base
  score** (the calculator is verified against NVD reference scores). This is
  deterministic and works fully offline; the LLM brain enriches it rather than being
  the only source — previously the proof-of-impact renderer sat empty on every offline
  run. New `impact_model.py`; `cvss` / `proof_obligation` fields in the report Markdown
  and JSON.
- **Captured passive proof for web findings.** Header/cookie/version/mixed-content/
  error findings now carry the exact request line, response status, and offending
  header/Set-Cookie value as redacted `proof_evidence`, so the report shows what
  produced each finding.
- BugHunter proof-of-impact report sections and readiness checks so impact claims
  require concrete evidence (confirmed/candidate/missing, with method, actor, observed
  result, control result, affected asset, and limitations).

### Fixed (whole-app QA/QC audit)
- **Stronger honesty on proof status.** A finding is marked "confirmed" only with a
  real captured artifact (authenticated replay, live secret, or a response carrying an
  HTTP status) — concrete-sounding LLM prose alone, or passive web evidence ("a GET
  returned 200"), can no longer flip an unproven lead to submission-ready.
- **Secret-leak redaction holes closed:** a truncated PEM private key (END marker
  clipped) and credentials on a whitespace-collapsed `.env`-style line are now
  redacted; live-scan runtime evidence is redacted before it reaches the report.
- BugHunter JWT exposure triage suppresses OAuth flow-token false positives, gates
  session-impact reporting on replay confirmation, and uses CWE-200; web-scan secret
  evidence is redacted before report generation.
- **SSRF hardening:** the agent's `net_probe` refuses cloud-metadata / link-local
  targets (including via HTTP redirect) while still allowing legitimate loopback/
  private ops diagnostics.
- **Agent engine:** the destructive-command denylist now catches `rm -r -f` with split
  flags; ranged file reads are memory-bounded yet can still page through a large file;
  `grep`/`find_code` output goes through the untrusted-data boundary; rollback removes
  directories the run created.
- **Reliability:** atomic writes for the secrets store, runtime config, and project
  memory (no torn files, no world-readable window); the API no longer reflects raw
  exception text on a 500; Electron shows the error page instead of a stuck spinner on a
  boot failure and reaps the backend/Ollama process tree on quit; assorted
  scanner-accuracy and unbounded-growth fixes (yaml.load detection, minified-file skip,
  repo-map walk, BPE cache, live-capture caps).

## v0.9.9

### Fixed
- **Empty "Bounty type" dropdown when the backend is late.** The Security panel's
  selectors (bounty type, focus class, toolkit) were populated once at boot and gated
  on the local API being reachable at that instant — so if the API lagged the UI (the
  packaged build unpacking on first launch, or the PM2/phone split where the Node UI
  serves before the Python API), the dropdowns stayed blank with no retry. They now
  (re)load whenever the Security panel is shown and the moment the service becomes
  reachable, via an idempotent `ensureSecurityData()`.

## v0.9.8

### Added
- **Guided next steps for the bounty hunt.** Every hunt now ends with an ordered,
  prioritized operator action plan — "what do I do now?" answered as numbered steps
  grouped into phases (*stabilize coverage → confirm findings → hunt by hand → chain &
  escalate → expand coverage → prepare submission → retest*). Each confirmation step is
  emitted highest-impact first (severity, confidence, **and intrinsic class value**
  weighted), names the opening reproduction move, and points at the single best tool
  from the curated toolkit. The plan is deterministic (works fully offline) and, when a
  brain is configured, folds in target-specific analyst leads. It renders as a clean,
  color-coded checklist in the UI (the full Markdown report is one click away) and ships
  in the report's Markdown and JSON, plus a new `next_steps` field on the scan response.
- **10 modern high-bounty vuln classes.** The focus taxonomy nearly doubles with
  server-side template injection (SSTI), XXE, NoSQL injection, JWT forgery/weakness,
  GraphQL abuse, prototype pollution, race conditions / TOCTOU, HTTP request smuggling,
  subdomain takeover, and exposed cloud storage/metadata — each with CWE/OWASP mapping,
  a sharp 3-step hunt checklist, curated tool recommendations, and chain leads (e.g.
  *SSRF + cloud-exposure → metadata credentials*). They flow into the web-app, API, and
  source-code profiles and the full sweep.
- **Coverage & gaps summary.** The report and UI now state what the pass actually
  covered and — more importantly — what it structurally could not (no dynamic pass, no
  authenticated testing, git history unscanned, partial on scanner error), so the
  operator knows where the blind spots are before trusting a low finding count.

### Changed
- **Runs without PyTorch — bug-hunting goes anywhere.** The local TinyGPT brain is the
  only component that needs PyTorch; its import is now lazily guarded, so the backend
  boots even where torch is absent or won't load (e.g. an ARM phone running the API
  under PM2/Termux). The bug-hunting engine and the Claude API brain are entirely
  torch-free and stay fully functional; local-model train/infer is cleanly gated off
  with a clear message, and `status` reports `local_model_available`.
- **Honest agent completion status.** A run now reports an explicit `completed` /
  `verified` / `outstanding` triple instead of implying success by default: it only
  claims "done" when the model finished on its own *and* its changed files verified
  clean. Hitting the step limit runs a final verify, names exactly what is still
  outstanding (unverified files, remaining work), and tells you a re-run will continue
  from the current state. The Workbench surfaces a ✓/⚠ completion line accordingly.

## v0.9.7

### Added
- **Task templates.** A row of one-click starter workflows sits above the composer —
  *Review project, Explain repo, Create README, Fix failing tests, Find security
  risks, Package for release,* and *Issue / PR plan*. Each one prefills the composer
  (you review and send it) and enables Agent mode where the task needs to read or edit
  files; *Find security risks* runs BugHunter's code scanner on your workspace.
- **Project memory & source cards.** A new **Project** tab (the Workbench's default
  view) shows what GreyIQ knows about the current workspace as source cards — purpose,
  tech stack, run commands, and key files, derived by a one-click **Scan project**
  (stack/run/files are detected offline; the one-line purpose uses your brain) — plus
  your own preferences, constraints, and open tasks. The agent is handed this memory at
  the start of every run, and it persists per workspace.
- **Guided "Plan → Change → Verify → Explain" workflow.** A new first tab in the
  Workbench presents every agent run as four ordered stages: the up-front plan the
  agent is told to follow, the files it changed, the verification result (pass/fail),
  and a plain-language summary — with quick links into the Changes and Verify tabs.
- **One-click rollback.** Each agent run snapshots the pre-edit state of every file it
  touches; **Undo last agent run** restores them exactly and removes files the run
  created. The snapshot is kept per workspace and survives an app restart.
- **Security trust labels.** Files are scanned for prompt-injection: the Workbench
  preview shows a per-file trust label ("trusted local file" → "prompt-injection risk"
  with the matched signals), and when the agent reads a risky file its contents are
  handed to the model inside an explicit untrusted-DATA boundary — so an embedded
  "ignore your instructions / use write_file / exfiltrate secrets" is treated as data to
  report, not a command to follow. An agent run shows a Trust-check note for any flagged
  reads, and the agent bar shows whether shell commands require approval. This brings the
  agent red-team's injection thinking into the daily UI.

### Changed
- `scan` / `bughunt` chat commands now always run the BugHunter scanner, even when
  Agent mode is on (previously they were routed to the agent).

## v0.9.6

### Changed
- **Dark mode is now the default.** New installs and the browser fallback open in
  dark. An explicit theme choice (via the header toggle) is remembered and always
  wins; users who never picked — including those with a stale light preference from
  the old default — now open in dark.

## v0.9.5

### Added
- **Delete personalities and local models.** A "Delete this bot" button in the bot
  editor removes a personality along with its chat history, learned memory, and
  backend AI core (always keeping at least one). The Coding brain panel now lists
  installed Ollama models with a **Remove** button to free their disk space.

## v0.9.4

### Added
- **Out-of-the-box GPU acceleration for the local model (Ollama).** NVIDIA (CUDA)
  is bundled and used automatically. AMD (ROCm) is auto-provisioned on first run:
  when an AMD GPU is detected, GreyIQ downloads Ollama's ROCm runtime (~1 GB,
  one-time) and overlays it on a writable copy of the bundled runtime. Any failure
  falls back to the bundled runtime, so GPU setup can never break the app.
- A **"Local model GPU: …"** status line in the Coding brain panel (desktop) showing
  the detected GPU vendor and the active runtime (CUDA/ROCm), or CPU.

### Fixed
- Restored the bundled **CUDA** runner on Linux. A prior release pruned it to fit
  GitHub's 2 GiB asset cap, which disabled NVIDIA acceleration; the CPU-only torch
  wheel already keeps assets small, so the prune was unnecessary.

### Docs
- Clarified GPU support in the README and the package description.

## v0.9.3

### Added
- **Pentest & OSINT Toolkit** — a curated, queryable catalog of 172 tools across 10
  categories (from [awesome-pentest](https://github.com/enaqx/awesome-pentest),
  CC-BY 4.0, and [awesome-osint](https://github.com/jivoi/awesome-osint), MIT),
  mapped to BugHunter's vuln classes, surfaced in a browsable panel, in BugHunter
  "Recommended tooling", and via an agent skill.

### Fixed (release CI, Linux)
- Ollama's Linux asset moved to `.tar.zst`; download/extract updated (was a 404).
- Free ~30 GB on the runner before the build (was "No space left on device").
- CPU-only torch + slimmer bundle so release assets stay under GitHub's 2 GiB
  per-asset limit.

## v0.9.2
- Workbench: collapsible, readable file tree.

## v0.9.1
- QA/QC: fixed BugHunter vuln-class mapping and assorted cleanups.

## v0.9.0
- Agent security red-team; Workbench slide-to-dock; GreyNOC-IQ rename.
