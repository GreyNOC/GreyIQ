# Wardriving / RF survey — read-only export analysis

**GreyIQ's wardrive support is READ-ONLY analysis of capture exports YOU supply.** It never
transmits, never associates, never deauthenticates, never injects, and never cracks a key or
handshake. The radio work happens in your own capture tool, under your own authorization, on
your own network or an engagement whose ROE names RF testing; GreyIQ only reads the file
afterwards. Nothing in this pack is a step toward attacking a network you do not own.

## What GreyIQ actually does with a survey
<!-- triggers: wardrive, wardriving, rf survey, wireless survey, what can greyiq do with wifi -->
The pipeline is: your export in, one normalized model, an analysis report out.

- You capture with your own tool and export a file. GreyIQ parses that file — it never touches a radio.
- Four incompatible export formats are normalized onto one vocabulary so the analysis reasons over facts instead of over whichever tool recorded them: airodump-ng CSV, WiGLE CSV, Kismet netxml, and Windows `netsh wlan show networks`.
- Encryption collapses onto `open` / `wep` / `wpa` / `wpa2` / `wpa3` / `wpa2-wpa3` / `owe`, plus a cipher and an auth mode.
- The output is a posture report over the estate you surveyed. It is analysis, not an attack plan.

## Unknown is not "clean"
<!-- triggers: unknown, wps unknown, missing field, tri-state, is it secure -->
The single most important rule in reading a survey.

- WPS and PMF are TRI-STATE on purpose: "the format cannot tell us" is a different fact from "the format reports it and it is off". airodump, for example, never records WPS at all.
- An absent fact is reported as **unknown** and never as a passing grade. A finding is never raised on an unknown.
- If you need the missing fact, re-capture with a tool whose format records it — do not infer it.
- A truncated capture (the survey was stopped mid-write) yields empty/unknown values rather than an error; treat its gaps as unknown too.

## Authorization for the capture itself
<!-- triggers: is wardriving legal, authorization, permission, am i allowed -->
GreyIQ reads the file; you own the legality of how it was made.

- Passive observation of beacon frames on your own estate, or on an engagement whose signed ROE explicitly names RF/wireless testing, is the intended use.
- Association, deauthentication, injection, evil-twin/rogue-AP staging, and handshake capture for cracking are NOT part of GreyIQ's scope and are not supported here.
- Client (station) records in an export identify devices and their probe history — that is personal data. Handle it under the engagement's data-handling terms and redact it in any report.
- Keep the capture's provenance with the file: who captured, when, where, with what tool, under which authorization.

## Reading the posture report
<!-- triggers: read the report, survey findings, open network, wep, wpa2, posture -->
What the normalized facts are actually telling you.

- **Open / OWE** — an open SSID carries no link-layer confidentiality; OWE gives opportunistic encryption but no authentication. Note which of the two the export actually reported.
- **WEP** — broken as a confidentiality control; treat any WEP SSID on the estate as an inventory finding to remediate.
- **WPA / WPA2-PSK** — check for a shared PSK across the estate and for guest/corporate separation. The export cannot tell you the PSK's strength; do not guess.
- **WPA2/WPA3 transition mode** — reported as `wpa2-wpa3`; it is a downgrade surface, and whether PMF is required is the deciding fact. If PMF is unknown, say unknown.
- **WPS enabled** — an inventory finding worth remediating where the format actually reports it.

## Turning a survey into a deliverable
<!-- triggers: survey report, deliverable, inventory, remediation -->
Same evidence discipline as every other GreyIQ report.

- Lead with the inventory: how many SSIDs/BSSIDs, on which bands and channels, with which normalized encryption values, and how many fields came back unknown.
- Raise one finding per remediable fact (open SSID, WEP, WPS on, transition mode without PMF), each with the exact source rows it came from.
- Never state a conclusion the export cannot support — no key strength, no client behaviour you did not observe, no coverage claim outside the survey path.
- Recommend the control change and the re-survey that would verify it.
