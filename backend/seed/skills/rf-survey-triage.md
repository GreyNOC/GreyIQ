---
name: rf-survey-triage
description: Triage a wireless/RF survey export (airodump-ng, WiGLE, Kismet, netsh) into a defensive posture assessment, and explain what a given capture format can and cannot prove
when: wifi, wi-fi, wlan, 802.11, wireless, ssid, bssid, rogue ap, evil twin, wardriving, wardrive, kismet, airodump, wigle, wps, wep, wpa2, wpa3, pmf, 802.11w, rf survey, access point, netsh wlan, who is on my wifi, hidden ssid, probe request, oui, mac randomization
---
GreyIQ ships **`gn wardrive`** — a read-only analyzer for survey EXPORT files the operator
already captured. It never transmits, never joins a network, never captures key material.
Point it at a file or a folder:

```
gn wardrive ./capture/ -y --out rf-report.md
gn wardrive survey.csv -y --json
gn wardrive walk.netxml -y --authorized inventory.json --min-severity medium
```

`-y/--authorize` is required: a survey records other people's networks and client devices,
so the operator asserts the capture is theirs and the site is in scope.

## The one thing to get right: what the format can actually prove

This is the most common way a wireless assessment goes wrong. Each export format records a
different subset of the beacon, and a finding is only as honest as its source.

| format | WPS | PMF (802.11w) | signal |
| --- | --- | --- | --- |
| airodump-ng CSV | **never** | **never** | dBm |
| WiGLE CSV | yes | yes (`MFPR`/`MFPC`) | dBm |
| Kismet `.netxml` | usually | **never** | dBm |
| Kismet CSV export | sometimes | **never** | dBm |
| `netsh wlan` (Windows) | **never** | **never** | percentage only |

So: **an airodump-only survey produces zero WPS findings and zero PMF findings.** That is
not "WPS is off everywhere" — it is "this capture cannot see WPS". GreyIQ reports it in an
explicit *Undetermined* section instead of raising a finding, because a confidently wrong
"PMF missing" line in a client deliverable is worse than an honest "not determinable". If
you need those facts, re-capture with Kismet or a WiGLE export.

Same discipline on signal: netsh gives a driver-computed **percentage**, never a dBm.
GreyIQ records the percentage and leaves dBm undetermined rather than converting it, because
a converted percentage is a fabricated measurement.

## What it looks for

- **Encryption** — WEP (critical), open (high; downgraded to info when the SSID matches a
  curated guest/hotspot pattern), WPA1/TKIP (high), mixed CCMP+TKIP (medium), and WPA3
  **transition mode** (medium) where SAE and PSK share a BSS so a client can still be
  steered onto the WPA2 path.
- **WPS enabled** (high) — only from a format that reports it.
- **802.11w absent** (medium) — only when the export demonstrably reports MFP elsewhere.
- **Evil twin / SSID impersonation** — one SSID whose BSSIDs disagree with each other.
  The false-positive control is the point: legitimate multi-AP and band-steering
  deployments put one SSID on many BSSIDs, so a **same-vendor, same-encryption group is
  never flagged**. Scoring only counts divergence — different encryption for one SSID
  (strongest), a locally-administered BSSID, a different hardware vendor (only when both
  OUIs are actually in the table).
- **Unmanaged / soft AP** — a locally-administered BSSID, or SoC/dev-board silicon
  (Espressif, Raspberry Pi) beaconing where AP hardware is expected.
- **Rogue AP** — requires `--authorized inventory.json`. Without an inventory there is no
  such thing as a rogue AP and GreyIQ does not claim one.
- **Factory-default SSID** — usually means unchanged admin credentials too.
- **Client exposure** — a device's Preferred Network List leaked in probe requests, and
  clients running with MAC randomization off.

## Answering RF questions

- *"Is my wifi secure?"* — ask which tool produced the capture first; the answer changes
  what can be said. Then read the encryption mix and the Undetermined section together.
- *"Is there a rogue AP?"* — not answerable without an AP inventory. Ask for one.
- *"Why is the same SSID on six BSSIDs?"* — almost always a normal multi-AP or band-steered
  deployment. Look for disagreement between them, not for the count.
- *"Can you crack / capture / test the passphrase?"* — no. GreyIQ's wardrive path is
  read-only analysis of an export. Offensive wireless work is out of scope for this tool.
