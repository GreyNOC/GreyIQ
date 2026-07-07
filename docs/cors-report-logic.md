# CORS Reporting Logic — Evidence-Based Severity, Confidence & Wording

This document is the reference for how GreyIQ now decides CORS severity, confidence, and
wording, and how it separates **confirmed evidence** from **possible impact**. It is the
design behind the code in:

- [`backend/bughunter/active_verify_service.py`](../backend/bughunter/active_verify_service.py) — `_check_cors`, `_cors_read_impact`, `_cors_cvss`
- [`backend/bughunter/sensitive_data.py`](../backend/bughunter/sensitive_data.py) — the sensitive-data capture/classification engine
- [`backend/bughunter/impact_model.py`](../backend/bughunter/impact_model.py) — the CORS impact narrative + CVSS ceiling
- [`backend/bughunter/report.py`](../backend/bughunter/report.py) — `qa_validate_report` (pre-export QA gate) + CORS wording
- [`backend/bughunter/bounty.py`](../backend/bughunter/bounty.py) — `_write_sensitive_data_files` + QA-gate wiring

## The three levels of proof (never conflate them)

| Level | What it proves | How GreyIQ can capture it |
|---|---|---|
| **Confirmed misconfiguration** | The server reflects an arbitrary Origin **and** returns `Access-Control-Allow-Credentials: true`. | curl / a single benign GET with a marker `Origin` + a negative-control Origin. This is a **server-side header behaviour** fact. |
| **Confirmed exploitability** | A **real browser**, on an **attacker-controlled origin**, using the **victim's credentials**, read the cross-origin response body. | A hosted browser PoC. curl/same-site does **not** prove this (no SameSite/CORS/preflight enforcement). |
| **Confirmed sensitive impact** | The readable response actually contains user-specific/sensitive authenticated data (email, profile, account IDs, private JSON, CSRF tokens, session material). | The `sensitive_data` classifier naming real data classes in the captured body. |

> **curl proves headers. A browser proves exploitability. Named sensitive data proves impact.**
> A report may only claim each level that its evidence actually reached.

---

## A. Corrected decision tree for CORS report generation

```
_check_cors(url):
  probe   = GET url  with Origin: https://attacker-marker.example   (+ operator session if authenticated scan)
  control = GET url  with Origin: <the site's own origin>

  ── Is the attacker Origin reflected (ACAO == attacker) AND ACAC: true
     AND the control Origin is reflected DIFFERENTLY (dynamic, attacker-driven)? ──
   │
   ├─ NO ─▶ Is the attacker Origin reflected but ACAC != true?
   │        ├─ YES ▶ LOW / candidate  "reflects arbitrary Origin (no credentials)"
   │        └─ NO  ▶ try variant checks (Origin: null, arbitrary-subdomain, substring/prefix trust)
   │                 · each variant confirms only against a control differential
   │                 · none match ▶ no finding
   │
   └─ YES ─▶  MISCONFIGURATION CONFIRMED (server-side header behaviour).
              Now grade the *demonstrated impact* → _cors_read_impact(probe):

              ── Authenticated scan AND 2xx AND a real (>= 8 byte) body captured? ──
               │
               ├─ NO ─▶ tier = LOW
               │        · non-2xx (404/403/204/redirect), unauthenticated, or empty body
               │        · proof labelled: "server-side CORS header behaviour confirmed;
               │          sensitive cross-origin read NOT demonstrated"
               │        · CVSS = _cors_cvss("low")  (C:L, AC:H → Low, never C:H)
               │
               └─ YES ▶ tier = MEDIUM
                        · capture body as read_data (raw → redacted once by _finding)
                        · classify RAW body → sensitive_data_labels (JWT / session / CSRF / OAuth / email…)
                        · proof labelled: "same-site (curl-equivalent) read; browser cross-origin
                          read NOT yet proven"
                        · CVSS = _cors_cvss("medium")  (C:L, S:U → Medium, never C:H)

              ── HIGH is NOT reachable from this engine alone. ──
              High requires cross_origin_read_confirmed = True, set only when a browser-hosted
              PoC on an attacker origin actually read sensitive victim data cross-origin.

  ── Final pass: qa_validate_report() re-checks every claim vs evidence and applies
     downgrade-only corrections before export (see section E). ──
```

---

## B. Updated severity rules

| Severity | Condition | CVSS ceiling |
|---|---|---|
| **High** | **Only** when a browser PoC on an attacker origin read **sensitive authenticated victim data** cross-origin (`cross_origin_read_confirmed`). | `C:H` allowed |
| **Medium** | Arbitrary-Origin reflection **+** `Allow-Credentials: true` confirmed on an **authenticated endpoint** that returned a real 2xx body — sensitive cross-origin read not yet browser-proven. | `C:L` (no `C:H`) |
| **Low / Info** | Misconfiguration confirmed only on a **404 / 403 / 204 / redirect / logout / health-check / static / public** response, an unauthenticated scan, or an empty body. | `C:L`, `AC:H` → Low |

Hard rule: **never emit `C:H` in the CVSS vector unless sensitive confidentiality impact is proven.**
The default modelled CORS vector is `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` (Low); the active
prover overrides it per-finding with the tier vector above.

---

## C. Updated confidence rules

| Confidence | Evidence |
|---|---|
| **High** | Request/response evidence **and** a browser PoC showing an actual readable **sensitive** authenticated body read cross-origin. |
| **Medium** | Strong header evidence of a dangerous misconfiguration (reflected Origin + credentials on an authenticated endpoint), impact not fully proven. |
| **Low** | Evidence is incomplete/ambiguous/unauthenticated, or from passive/static scanning only. |

Confidence tracks the **weakest** unproven link: header-only ⇒ Medium at best; add a same-site
sensitive read ⇒ still Medium (browser step missing); add the browser cross-origin read ⇒ High.

---

## D. Safer report template wording

**Avoid** (unless the evidence proves it): "An attacker can steal account data." · "Account
compromise is possible." · "Profile, tokens, and account data are exposed." · "Exploitability
confirmed." · "Sensitive data theft confirmed." · "High severity confirmed."

**Use instead:**

- "The server reflects arbitrary `Origin` values while also allowing credentials."
- "This satisfies the browser CORS header requirement for credentialed cross-origin reads."
- "The tested endpoint returned HTTP 404, so sensitive data exposure is not confirmed from this evidence alone."
- "If the same CORS policy is applied to authenticated data endpoints, an attacker-controlled page may be able to read victim-specific responses."
- "Browser-based proof is required to confirm exploitability and sensitive impact."
- (same-site capture) "Requested with the tool's own session (a same-site, curl-equivalent read), the endpoint returned an authenticated body. The confirmed CORS headers **would** let an attacker-controlled origin read a response like this; a browser cross-origin read has not yet been proven."
- (sensitive data present) "**Sensitive data present in the captured response:** … A browser-hosted PoC that reads this cross-origin would confirm an attacker can obtain it; until then this establishes the data at risk, not a completed theft."

---

## E. Final pre-export QA checklist (`report.qa_validate_report`)

Runs on every finding before export; applies **downgrade-only** corrections (never raises severity):

1. **Claims sensitive-data exposure / `C:H`?** → require named sensitive data in the readable response; else strip `C:H` (recompute score).
2. **Claims browser exploitability / High CORS?** → require a browser-hosted PoC (`cross_origin_read_confirmed`); else cap to **Medium**.
3. **Response is 404/403/204/redirect and no sensitive read?** → cap demonstrated impact to **Low**.
4. **CORS evidence is curl-only?** → label it as **server-side header behaviour**, not browser exploitability.
5. **CVSS aligned with evidence?** → no `C:H` without proven sensitive confidentiality impact.

Every correction is recorded in the report's **"Pre-export QA (evidence vs claim)"** section and in
the JSON sidecar (`qa.issues`) so a triager can audit exactly why a severity reads the way it does.

---

## F. Code-level logic (pseudocode)

```python
def grade_cors(probe, control, authenticated):
    reflects_marker = probe.acao == ATTACKER_ORIGIN
    credentialed    = probe.acac == "true"
    dynamic         = control.acao != probe.acao        # reflection is attacker-driven, not static

    if not (reflects_marker and credentialed and dynamic):
        if reflects_marker and not credentialed:
            return Finding(sev="low", status="candidate",
                           note="reflects arbitrary Origin but no Allow-Credentials")
        return None  # (or a variant check: null / subdomain / substring)

    # Misconfiguration CONFIRMED (server-side header behaviour).
    body = probe.body
    if authenticated and 200 <= probe.status < 300 and len(body.strip()) >= 8:
        labels = sensitive_data.classify(body)          # classify RAW body, before redaction
        tier   = "medium"                               # authenticated endpoint; browser read still unproven
        read_data = body[:1500]                         # captured for the PoC + sensitive-data file
    else:
        tier   = "low"                                  # 404/redirect/unauth/empty → no read demonstrated
        labels, read_data = [], None

    return Finding(
        sev=tier,                                       # NEVER "high" here — that needs a browser PoC
        status="confirmed",                             # the misconfiguration is confirmed
        cvss=cors_cvss(tier),                           # C:L ceiling; never C:H
        proof_evidence={"read_data": read_data, "sensitive_data_labels": "; ".join(labels)},
        wording=honest_cors_wording(tier, labels, probe.status),
    )

# Final gate before export — downgrade-only:
def qa_validate(finding, plan):
    if finding.cls == "cors" and severity(finding) >= HIGH and not finding.cross_origin_read_confirmed:
        cap(finding, plan, "medium", "no browser cross-origin PoC read sensitive data")
    if finding.cls in {"cors", "disclosure"} and status(finding) in NON_SENSITIVE and not sensitive(finding):
        cap(finding, plan, "low", "endpoint returned 404/redirect with no sensitive read")
    if finding.cls in {"cors", "disclosure"} and has_metric(plan.cvss, "C", "H") and not sensitive(finding):
        set_metric(plan.cvss, "C", "L")                 # boundary-aware: never corrupts AC:H
```

Sensitive-data capture engine (`sensitive_data.classify`) names, high-confidence only:
AWS/GitHub/Slack/Stripe/Anthropic/OpenAI keys, PEM private keys, JWTs, **CSRF/anti-forgery
tokens, session identifiers, OAuth access/refresh tokens, bearer tokens**, and non-role email
PII. Classify the **raw** body before redaction (redaction rewrites tokens to markers the
classifier can no longer match). Captured data is saved, **redacted**, to a separate
`evidence/sensitive-data/<ref>-sensitive-data.txt` in the PoC download and named on the report.

---

## G. Rewritten example — the honest 404 CORS report

**Evidence:** GET to the endpoint · `Origin: https://attacker-marker.example` · **HTTP 404** ·
`Access-Control-Allow-Origin` reflects the attacker origin · `Access-Control-Allow-Credentials: true`.

---

### CORS: server reflects arbitrary Origin with credentials — **Low** (misconfiguration confirmed)

**Severity:** Low · **Confidence:** Medium
**CVSS v3.1:** `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` — 3.1 Low *(no `C:H`: no sensitive data was read)*

**Summary.** The server reflects an arbitrary `Origin` value in `Access-Control-Allow-Origin`
while also returning `Access-Control-Allow-Credentials: true`. This satisfies the browser CORS
header requirement for credentialed cross-origin reads. On the tested endpoint this is a
**confirmed server-side header misconfiguration**.

**What is confirmed (server-side header behaviour).**
```http
GET /api/whoami HTTP/1.1
Origin: https://attacker-marker.example

HTTP/1.1 404 Not Found
Access-Control-Allow-Origin: https://attacker-marker.example
Access-Control-Allow-Credentials: true
```
A negative control with a different `Origin` was reflected differently, proving the reflection is
attacker-driven (dynamic), not a static value.

**What is NOT confirmed.** The tested endpoint returned **HTTP 404**, so **no sensitive data
exposure, account compromise, token theft, or cross-origin read is demonstrated by this evidence
alone.** The captured result is the CORS *header behaviour* only — verified with a curl-level
request, which does not enforce the browser's SameSite/CORS/credential rules and therefore does
**not** prove browser exploitability.

**Possible impact (unproven).** If the **same CORS policy is applied to an authenticated data
endpoint**, an attacker-controlled page may be able to read victim-specific responses cross-origin.
The real-world impact depends entirely on which endpoints share this policy and what they return.

**To confirm exploitability and sensitive impact (proof obligation).** Host a PoC on an
attacker-controlled origin and capture the **sensitive authenticated response body** it reads with
the victim's credentials against an endpoint that returns user-specific data. Browser-based proof
is required to raise this above Low.

**Remediation.** Reflect `Origin` only from an explicit allowlist; never combine reflected/`*`
`Access-Control-Allow-Origin` with `Allow-Credentials: true`; never trust `null`.

---

This report is honest: it states exactly what the evidence proves (a header misconfiguration on a
404), refuses to assert High severity or data theft, names the concrete next step, and stays
strict enough for a triager to trust.
