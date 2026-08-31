# Attack-chain engine

`backend/bughunter/attack_chain.py`

A single finding answers *"what is broken here?"*. The chain engine answers the question a
triager actually pays for: **"what can an attacker do with everything we found?"**

It is a forward-chaining capability planner, not a pair matcher.

## Model

| Concept | Meaning |
|---|---|
| **capability** | What the attacker *holds* at a point in the chain — `exec.browser-script`, `read.session-token`, `identity.admin`, `net.internal`… |
| **clue** | A typed observation that can enable a step: a **finding**, or a sub-finding **signal** |
| **technique** | `requires` capabilities + an enabling clue → `grants` capabilities |
| **chain** | An ordered path from an entry capability to a terminal **impact** |

Entry points are deliberately only two — `entry.unauthenticated` and
`entry.low-priv-account` — and both are universally available. A network-adjacent position
is **not** an entry; it must be earned from observed evidence (mixed content, a reachable
plaintext endpoint) via `net.mitm-position`. See "Why cookie flags are not findings" below
for why that distinction matters.

The search is a bounded **iterative-deepening** walk over capability space. Every recorded
path is reduced to its **minimal witness** for the impact it reaches: a step that does not
contribute is dropped, so a chain never lists an unrelated finding it happened to walk past.

Deepening rather than a plain DFS, because the two are not equivalent under a budget. A
complete search of a routine 13-class hunt needs roughly two million expansions against a
20,000 budget, and a depth-first walk sharing one counter spends the entire allowance inside
the *first* edge's subtree — instrumented, the set of root edges ever expanded was literally
`[0]`. Every witness whose techniques sit late in the table was lost, so the output was
biased by table position rather than by chain quality. Splitting the budget per root does not
fix it (measured: byte-identical output), because the bias is recursive: each root's share is
consumed by its own first child in turn. Deepening by length also matches how the engine
ranks anyway — short witnesses score higher — so the budget goes to the chains most likely
to be reported.

## Provenance: an observation is bound to where and to what

Two bindings, because there are two ways to invent a composition nobody saw.

**Which host.** Every signal records the host it was observed on, and it may only escalate a
chain whose findings sit inside the same registrable domain. Without this, a campaign — which
pools every target's signals into one graph — composed one company's missing `HttpOnly` into
another company's confirmed XSS and reported an account takeover whose second step is
physically impossible on that target, because its session cookie *is* `HttpOnly`. Sibling
subdomains are deliberately *not* rejected and carry no cross-host penalty: domain-scoped
cookies really do cross them, and that composition is the campaign's entire payoff. IP
literals are compared exactly, never through the registrable-domain heuristic, which would
otherwise merge `1.2.3.4` and `9.8.3.4`.

**Which finding.** Signals that describe one specific finding are matched on the finding's
*content*, not its display ref. Refs are renumbered every time findings are pooled (a hunt's
`F1` becomes a campaign's `C7`, then a span's `C31`) while the signal keeps the ref it was
stamped with, so a ref-keyed check silently discarded every cross-target witness — the
credential chains a span exists to build were dead in exactly the graph that needed them.

## Why cookie flags are not findings

GreyIQ does not report `Cookie missing HttpOnly` / `Secure` / `SameSite` as findings.

A flag gap describes no attacker capability on its own. There is nothing to reproduce and
nothing to impact, which is why these are the largest single source of auto-closed
informational noise in a bounty queue. What a flag actually changes is **the severity of
something else**:

| Flag gap | The step it enables | Needs |
|---|---|---|
| no `HttpOnly` | script execution → session-token theft | a confirmed XSS |
| no `SameSite` (or `SameSite=None`) | cross-site request arrives with the session attached | a state-changing endpoint |
| no `Secure` | session token exposed on an observed cleartext channel | mixed content or a reachable `http://` endpoint |
| `Domain`-scoped (not `__Host-`) | a controlled sibling host receives the session cookie | a confirmed subdomain takeover |

`SameSite=None` counts as *no* SameSite: it is the explicit opt-in to cross-site sending, not
protection. Flags are read from parsed cookie **attributes**, never by substring-searching the
header, so a cookie whose value contains `secure` cannot suppress its own gap. CSRF
double-submit cookies (`csrftoken`, `XSRF-TOKEN`, …) are excluded entirely — they *must* be
readable by JavaScript, so scoring their missing `HttpOnly` as token theft would fabricate a
takeover chain out of a correct implementation.

So the scanner emits them as **signals** (`attack_chain.cookie_signals`), and they reach the
report only as a numbered step of a chain that a real finding anchors — carrying that
finding's proof and an explicit note that the flag alone is not a vulnerability. Only
signals a chain actually consumed are surfaced; the rest stay silent.

Signals carry cookie **names and flag facts only**, never a cookie value.

The net effect on a boring HTTPS site with sloppy cookie flags and nothing else broken:
**zero output**. On the same site with a confirmed XSS: one account-takeover chain, in which
the missing `HttpOnly` is step 2.

## Honesty invariants

The engine's value is entirely in refusing to overstate. All of these are enforced by
contract tests in `backend/test_attack_chain.py`:

- **The engine never confirms anything.** A step is `proven` only when
  `investigator.has_confirming_artifact` — which delegates to the single confirm authority
  in `report` — already accepted that finding's evidence.
- **A signal can never make a step proven.** Signals are observations, not evidence.
- **A chain is `proven` only when every step is.** One projected link caps it at `partial`.
- **Confidence is the weakest link, never a mean.** Averaging is how a proven step carries
  an unproven one.
- **A not-fully-proven chain is capped below the supported band**, so a long speculative
  chain can never out-rank a short captured one.
- **A chain citing no finding is not a chain**, it is a probe lead. Those are routed to
  `investigation.chain_probes` and rendered as "chain leads worth testing", never as results.
- **Cross-host chains rank below same-host chains** — two findings on unrelated hosts may
  not share a session at all.
- Pure capability transitions ("replay the token you now hold") are logical consequences, so
  they do not set confidence — but they are also never marked proven. A consequence of that:
  **a chain containing an inference step cannot reach `proven`**, and stays `partial` until
  someone captures that step's artifact too. That is deliberate — "you could replay the token"
  is not the same as having replayed it — and it is why `proven` is normally reached by short
  chains whose every step is a confirmed finding.
- **A chain never reads stronger than the findings it cites.** The chain layer asks "did every
  step capture an artifact?" and the cortex asks "is this finding's evidence sound?"; a finding
  can pass the first and fail the second, so the chain status is clamped to the weakest cited
  hypothesis. A chain resting on a contradicted finding is `blocked` and is never described as
  submittable, whatever its step states say.
- **A signal carrying a finding ref can only escalate a chain citing that finding.** With two
  exposed secrets, the chain must not pair the first finding's credential step with the second
  finding's "this one is a cloud key" observation.
- **Nothing fabricates a signal it cannot observe.** Three signals in the vocabulary
  (`token.role-claim`, `sink.admin-rendered`, `sink.upload-executed`) have no honest producer
  today — the response digest decodes a JWT header only, proving a stored value renders in an
  *administrative* view needs admin access GreyIQ does not have, and nothing observes an
  uploaded file being executed. They are left unemitted rather than guessed, so the techniques
  consuming them simply never fire.
- **A path name is not an observation.** `endpoint.state-changing` is emitted only from an
  actually observed `POST`/`PUT`/`PATCH`/`DELETE` form method. The old path-name heuristic was
  an unanchored alternation over the whole URL, so `set` matched inside `/assets/` and `add`
  inside `/address` — meaning essentially every target emitted the one clue that promotes
  "read another tenant's data" to "*modify* another tenant's data". Anchoring does not rescue
  it: `/news/change-log` and `/pricing/add-ons` are read-only pages whose names still match.
- **A terminal impact is never minted from a class label alone.** A confirmed path traversal
  was class-tagged `file-upload`, which fired the upload-to-execution technique and reported a
  *proven* remote code execution from a read-only file disclosure. The producer was corrected,
  and the technique now requires an observed `sink.upload-executed` signal, so a future class
  re-tag cannot mint an impact by itself. Likewise, GraphQL introspection grants only
  `disclose.identifier` — it discloses a schema and observes no boundary being crossed, so it
  is a lead for BOLA/BFLA rather than a cross-tenant read.

The module is pure stdlib, deterministic, bounded on every dimension, and total: it runs at
report time on a finished hunt, so it degrades to an empty result rather than raising.

## Where it is wired

| Surface | What it gets |
|---|---|
| `web_scan_service` | emits cookie signals instead of cookie findings |
| `bounty` (single hunt) | collects signals from scanners + recon surface + response digest |
| `investigator` | builds the chains; splits report chains from probe leads |
| `report` | the **Attack chains** section — ordered step ladder per chain |
| `next_steps` | "close chain AC1" actions naming the blocking step |
| `hunt_loop` | chain-aware steering: the next turn chases the blocked step |
| `campaign` / portfolio | **cross-target** chains — findings on different hosts in one graph |
| `agent` (`investigate_code`) | the ladder in the coding agent's evidence brief |

Cross-target chaining is the campaign's payoff: a claimable subdomain on one host plus a
parent-domain session cookie on another is an account takeover that neither single-target
hunt can see, because neither host holds both halves.
