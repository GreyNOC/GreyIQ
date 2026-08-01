"""Wardrive — the RF posture analyzer: parsed survey in, defensive findings out.

Structured exactly like ``offline_hunt.offline_plan``: curated tables at the top, small
pure predicates, one public entry point (:func:`analyze_survey`). No model, no network, no
radio. Every verdict is a deterministic function of rows the operator already captured, so
re-running the same export produces byte-identical findings — "reproducible or it didn't
happen", made mechanical.

THE UNDETERMINED CONTRACT is the reason this module exists in its current shape. A survey
export is not a scan; it is a recording made by a tool that chose what to write down. Three
rules follow, and they are the release-blocking part of this package:

  1. A detector fires only on a POSITIVE observation. ``_f_wps`` needs ``wps is True``;
     ``_f_pmf`` needs ``pmf == "disabled"``. ``None``/``""`` mean the export could not tell
     us and produce NOTHING — not a finding, and equally not a clean bill of health.
  2. What could not be determined is reported, loudly, in ``result["undetermined"]``, and
     deliberately NOT as findings. airodump-ng CSV carries neither WPS state nor RSN
     capability bits, so an airodump-only survey yields exactly zero WPS findings and zero
     PMF findings and one undetermined row per fact naming the format limitation and the
     capture that would resolve it. A "PMF missing" line derived from a format that cannot
     observe PMF would be confidently wrong in a client deliverable.
  3. What was INFERRED rather than observed is separated into ``result["inferences"]`` and
     labelled as inference. WPA3-SAE mandates 802.11w, so a WPA3-SAE BSS almost certainly
     has PMF required — but this export did not say so, and the difference matters.

Every finding therefore carries a ``verification_obligation``: the analyzer never touched
the medium, it read a file, so a finding is an OBSERVATION plus what to capture to confirm
it. That is the ``impact_model`` posture applied one level weaker, which is correct here.

SAFETY ENVELOPE: read-only analysis of operator-supplied exports. Nothing in this module
transmits, associates, injects, captures key material, or recovers a passphrase, and no
remediation text suggests doing so. Findings describe DEFENSIVE posture and how to fix it.

Finding dicts copy ``takeover_service._build_finding`` field-for-field so they render
through the existing report machinery unchanged, plus the two fields this package requires:
``evidence`` (the VERBATIM source token the verdict came from) and ``source_format``.
"""

from __future__ import annotations

from typing import Any

from bughunter.wardrive import oui
from bughunter.wardrive.model import (
    NON_OVERLAPPING_24,
    AccessPoint,
    CapabilityFact,
    Station,
    Survey,
    encryption_rank,
    format_can_observe,
    is_locally_administered,
    normalize_mac,
)

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_OWASP_MISCONFIG = "A05:2021 Security Misconfiguration"
_OWASP_CRYPTO = "A02:2021 Cryptographic Failures"

_REF_80211 = "https://standards.ieee.org/ieee/802.11/7028/"
_REF_WPA3 = "https://www.wi-fi.org/discover-wi-fi/security"
_REF_NIST_1B = "https://csrc.nist.gov/publications/detail/sp/800-153/final"

# How many dB of spread inside one SSID group counts as an outlier radio rather than
# ordinary distance. Chosen wide on purpose: a real multi-AP floor plan easily spans 30 dB,
# so a narrower threshold would flag every healthy deployment.
_SIGNAL_OUTLIER_DB = 35

# Bound the report. A city-scale WiGLE export has tens of thousands of open networks and a
# deliverable with 40 000 findings is unreadable; the cap is reported, never silent.
_DEFAULT_CAP = 200


def _location(ap_or_station: Any) -> str:
    """Where a finding lives: the export path plus the identity fragment. Mirrors the URL +
    fragment shape ``takeover_service`` uses so existing renderers need no special case."""
    path = getattr(ap_or_station, "source_path", "") or "<survey>"
    # A Station ALSO has a `bssid` (the AP it associated to), so the identity has to come
    # from the record type, not from whichever attribute happens to exist first — otherwise
    # a client finding cites the access point's address under a `mac=` label.
    if isinstance(ap_or_station, AccessPoint):
        key, ident = "bssid", ap_or_station.bssid
    else:
        key, ident = "mac", getattr(ap_or_station, "mac", "")
    return f"{path}#{key}={ident}" if ident else path


def _build_rf_finding(*, rule_id: str, title: str, severity: str, confidence: str,
                      class_id: str, class_name: str, cwe: str, owasp: str,
                      subject: Any, evidence: str, matched_value: str, remediation: str,
                      verification_obligation: str, references: list[str] | None = None,
                      category: str = "wireless",
                      provenance: CapabilityFact | None = None) -> dict[str, Any]:
    """One finding, in the codebase's standard shape.

    ``evidence`` is the VERBATIM token from the export — the raw ``Privacy``/``AuthMode``/
    ``Authentication`` string, the SSID as broadcast, the BSSID as written. It is quoted
    rather than paraphrased so a reader can grep the export and land on the same bytes,
    which is the whole basis on which this analyzer is allowed to assert anything.

    ``provenance`` is the :class:`~bughunter.wardrive.model.CapabilityFact` the verdict came
    from, and when it is supplied EVERY citation field — ``location``, ``file_path``,
    ``line_start``/``line_end``, ``snippet``, ``source_format`` and the proof's
    ``request_line`` — is taken from THE FACT rather than from ``subject``. ``subject`` is
    the merged record, whose own provenance belongs to whichever export was seen first; for
    WPS and PMF that is routinely a format the fact could not have come from, and citing it
    told the reader to grep an airodump-ng row to verify a WPS claim.
    """
    severity = severity if severity in _SEVERITIES else "info"
    if provenance is not None:
        path = provenance.source_path or "<survey>"
        ident = getattr(subject, "bssid", "") or ""
        location = f"{path}#bssid={ident}" if ident else path
        row = int(provenance.source_row or 0) or 1
        snippet = str(provenance.raw_line or "")[:400]
        source_format = str(provenance.observed_by or "") or "unknown"
    else:
        location = _location(subject)
        row = int(getattr(subject, "source_row", 0) or 0) or 1
        snippet = str(getattr(subject, "raw_line", "") or "")[:400]
        source_format = str(getattr(subject, "source", "") or "unknown")
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "location": location,
        "file_path": location,
        "line_start": row,
        "line_end": row,
        "class_id": class_id,
        "class_name": class_name,
        "cwe": cwe,
        "owasp": owasp,
        "references": list(references or [_REF_80211]),
        "vrt": "",
        "remediation": remediation,
        "snippet": snippet,
        "evidence": str(evidence or "")[:400],
        "source_format": source_format,
        "verification_obligation": verification_obligation,
        "proof_evidence": {
            "request_line": snippet,
            "response_status": "passive survey export (no frame was transmitted)",
            "matched_value": matched_value,
        },
    }


def _capability_fact(ap: AccessPoint, fact: str) -> CapabilityFact | None:
    """The WPS/PMF fact behind ``ap``, but only when a format that CAN observe that
    capability recorded it.

    Fail-closed by design: no fact (or a fact from a format the capability is structurally
    absent from) means the analyzer has nothing it is entitled to assert, so the detector
    stays silent and the BSS remains in ``result["undetermined"]``. The model already
    enforces this when a fact is attached; repeating it here means no future call path can
    route around it and land a WPS or PMF claim on an airodump-ng / netsh citation."""
    held = getattr(ap, f"{fact}_fact", None)
    if held is None or not isinstance(held, CapabilityFact):
        return None
    if not format_can_observe(held.observed_by, fact):
        return None
    return held


# --- crypto posture ---------------------------------------------------------------


def _f_weak_crypto(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Encryption posture per BSS, ordered weakest-first by ``model.encryption_rank``."""
    findings: list[dict[str, Any]] = []
    patterns = ctx["ssid_patterns"]
    for ap in aps:
        kind, label = oui.classify_ssid(ap.ssid, patterns)
        raw = ap.raw_privacy or ap.encryption
        if ap.encryption == "wep":
            findings.append(_build_rf_finding(
                rule_id="wardrive.wep", title=f"WEP in use on {ap.label()}",
                severity="critical", confidence="high",
                class_id="weak-wireless-crypto", class_name="Broken wireless encryption",
                cwe="CWE-327 Use of a Broken or Risky Cryptographic Algorithm", owasp=_OWASP_CRYPTO,
                subject=ap, evidence=raw,
                matched_value=f"{ap.bssid} advertises WEP ({raw})",
                remediation=("Retire WEP entirely. WEP's RC4/IV construction is broken and its keys are "
                             "recoverable from ordinary traffic. Move the BSS to WPA2-CCMP at minimum and "
                             "WPA3-SAE where the client fleet supports it; if a legacy device forces WEP, "
                             "put it on an isolated VLAN with no route to production."),
                verification_obligation=("Confirm against a live beacon (Kismet or a pcap) that this BSSID "
                                         "still advertises WEP; this reading comes from a survey export, not "
                                         "from a current observation."),
                references=[_REF_80211, _REF_WPA3]))
        elif ap.encryption == "open":
            if kind == "guest":
                findings.append(_build_rf_finding(
                    rule_id="wardrive.open-network-guest",
                    title=f"Open network by design: {ap.label()} ({label})",
                    severity="info", confidence="high",
                    class_id="open-wireless", class_name="Unencrypted wireless network",
                    cwe="CWE-319 Cleartext Transmission of Sensitive Information", owasp=_OWASP_CRYPTO,
                    subject=ap, evidence=ap.ssid or raw,
                    matched_value=f"{ap.bssid} is open and matches the curated guest/hotspot pattern {label!r}",
                    remediation=("Recorded as informational because the SSID matches a known guest/public "
                                 "hotspot pattern, i.e. the openness is intentional. Confirm the guest BSS is "
                                 "isolated from internal VLANs and consider OWE so guest traffic is encrypted "
                                 "without a shared passphrase."),
                    verification_obligation=("Verify with the network owner that this SSID really is the "
                                             "intended guest network before treating the openness as accepted."),
                    references=[_REF_WPA3]))
            else:
                findings.append(_build_rf_finding(
                    rule_id="wardrive.open-network", title=f"Unencrypted network: {ap.label()}",
                    severity="high", confidence="high",
                    class_id="open-wireless", class_name="Unencrypted wireless network",
                    cwe="CWE-319 Cleartext Transmission of Sensitive Information", owasp=_OWASP_CRYPTO,
                    subject=ap, evidence=raw,
                    matched_value=f"{ap.bssid} advertises no link-layer encryption ({raw})",
                    remediation=("Enable WPA2-CCMP or WPA3-SAE. If the BSS must stay passphrase-free (a public "
                                 "or captive-portal network), use OWE so the link is still encrypted, and "
                                 "isolate it from internal VLANs."),
                    verification_obligation=("Re-observe the beacon to confirm the BSS is still open; a survey "
                                             "export is a snapshot of the moment it was captured.")))
        elif ap.encryption == "owe":
            findings.append(_build_rf_finding(
                rule_id="wardrive.owe-unauthenticated", title=f"OWE (unauthenticated encryption): {ap.label()}",
                severity="low", confidence="medium",
                class_id="open-wireless", class_name="Unauthenticated wireless network",
                cwe="CWE-319 Cleartext Transmission of Sensitive Information", owasp=_OWASP_CRYPTO,
                subject=ap, evidence=raw,
                matched_value=f"{ap.bssid} uses OWE: traffic is encrypted but the AP is not authenticated",
                remediation=("OWE is the correct choice for a passphrase-free network and is a large "
                             "improvement over an open BSS, but it authenticates nothing, so a client cannot "
                             "tell this AP from another advertising the same SSID. Where the clients are "
                             "managed, prefer WPA3-SAE or 802.1X so the AP itself is authenticated."),
                verification_obligation="Confirm from a beacon capture whether OWE transition mode is also enabled.",
                references=[_REF_WPA3]))
        elif ap.encryption == "wpa" or ap.cipher == "tkip":
            findings.append(_build_rf_finding(
                rule_id="wardrive.wpa1-tkip", title=f"WPA1/TKIP in use on {ap.label()}",
                severity="high", confidence="high",
                class_id="weak-wireless-crypto", class_name="Deprecated wireless encryption",
                cwe="CWE-327 Use of a Broken or Risky Cryptographic Algorithm", owasp=_OWASP_CRYPTO,
                subject=ap, evidence=raw,
                matched_value=f"{ap.bssid} advertises WPA1/TKIP ({raw})",
                remediation=("Disable TKIP and WPA1. TKIP is deprecated by the 802.11 standard, caps the BSS "
                             "at legacy rates, and its integrity check is weak. Move to CCMP-only WPA2 or "
                             "WPA3-SAE."),
                verification_obligation="Re-observe the beacon's RSN/WPA information elements to confirm TKIP is still offered."))
        elif ap.encryption == "wpa2-wpa3":
            findings.append(_build_rf_finding(
                rule_id="wardrive.wpa3-transition", title=f"WPA3 transition mode on {ap.label()}",
                severity="medium", confidence="medium",
                class_id="wireless-downgrade", class_name="Wireless downgrade exposure",
                cwe="CWE-757 Selection of Less-Secure Algorithm During Negotiation", owasp=_OWASP_CRYPTO,
                subject=ap, evidence=raw,
                matched_value=f"{ap.bssid} advertises SAE and PSK on one BSS ({raw})",
                remediation=("Transition mode advertises WPA3-SAE and WPA2-PSK on the same BSS, so a client "
                             "can still be steered onto the WPA2-PSK path and the passphrase remains exposed "
                             "to offline guessing. Once the client fleet supports SAE, move this SSID to "
                             "WPA3-only; until then keep the passphrase long and random."),
                verification_obligation=("Confirm from the RSN element which AKM suites are actually offered, and "
                                         "check whether the site's clients negotiate SAE in practice."),
                references=[_REF_WPA3]))
        if _mixed_cipher(ap):
            findings.append(_build_rf_finding(
                rule_id="wardrive.mixed-cipher", title=f"Mixed CCMP+TKIP cipher suite on {ap.label()}",
                severity="medium", confidence="medium",
                class_id="weak-wireless-crypto", class_name="Mixed wireless cipher suite",
                cwe="CWE-327 Use of a Broken or Risky Cryptographic Algorithm", owasp=_OWASP_CRYPTO,
                subject=ap, evidence=raw,
                matched_value=f"{ap.bssid} offers both CCMP and TKIP ({raw})",
                remediation=("Offering TKIP alongside CCMP keeps the deprecated cipher reachable for any client "
                             "that asks for it, and forces the group key down to TKIP. Set the BSS to CCMP-only."),
                verification_obligation="Confirm the pairwise and GROUP cipher suites from the RSN element; a group TKIP key weakens every client."))
    return findings


def _mixed_cipher(ap: AccessPoint) -> bool:
    """Both CCMP and TKIP present in the verbatim privacy blob. Read off the RAW token
    rather than the normalized cipher, because normalization keeps only the strongest."""
    blob = (ap.raw_privacy or "").upper()
    return ("CCMP" in blob or "AES" in blob) and "TKIP" in blob


# --- WPS / PMF: the two tri-state facts -------------------------------------------


def _f_wps(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """WPS findings, and ONLY from a positive observation.

    ``ap.wps is None`` means the export cannot say — airodump-ng and netsh never report WPS
    at all — and produces nothing here. It is counted into ``undetermined`` instead, so the
    report says "undetermined for N BSS" rather than the confidently wrong "WPS off"."""
    findings: list[dict[str, Any]] = []
    for ap in aps:
        if ap.wps is not True:
            continue
        fact = _capability_fact(ap, "wps")
        if fact is None:
            continue  # nothing observable to cite - the BSS stays undetermined instead
        findings.append(_build_rf_finding(
            rule_id="wardrive.wps-enabled", title=f"WPS enabled on {ap.label()}",
            severity="high", confidence="high",
            class_id="wireless-wps", class_name="WPS enabled",
            cwe="CWE-1391 Use of Weak Credential", owasp=_OWASP_MISCONFIG,
            # Evidence AND location AND snippet come from the fact, so the export the
            # finding points a reader at is the one that actually observed the element.
            subject=ap, provenance=fact, evidence=fact.evidence or "WPS",
            matched_value=(f"{ap.bssid} advertises WPS ({fact.evidence or 'WPS element present'}), "
                           f"{'observed directly in' if fact.basis == 'direct' else 'recorded by'} "
                           f"{fact.observed_by} at {fact.source_path or '<text>'} row {fact.source_row}"),
            remediation=("Disable WPS on this AP. The WPS external-registrar PIN is an eight-digit shared "
                         "secret validated in two halves, which collapses its strength far below the WPA2 "
                         "passphrase it protects, and many implementations expose a static PIN printed on "
                         "the case. Onboard devices with a QR code or a provisioning profile instead."),
            verification_obligation=("Confirm from the AP's own configuration that WPS is enabled; the beacon's "
                                     "WPS element is advertised by some models even when registration is off.")))
    return findings


def _f_pmf(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """PMF (802.11w management-frame protection) findings — the honesty case.

    PMF lives in the RSN Capability bits. airodump-ng CSV, netsh and Kismet's netxml do not
    export them, so ``ap.pmf`` is ``""`` for every BSS from those formats and this detector
    returns NOTHING for them, by construction. It fires only on ``"disabled"``, which the
    parsers set solely when the export demonstrably reports MFP for other rows in the same
    file (see ``parsers._apply_capability_evidence``) — a determination reproducible from
    the export alone.

    TWO conditions, not one: the value must be ``"disabled"`` AND a format that can observe
    PMF must have produced it. Without the second, a merged record could hold a value no
    export in the survey was capable of supplying, and the finding would cite whichever file
    happened to create the record."""
    findings: list[dict[str, Any]] = []
    for ap in aps:
        if ap.pmf != "disabled":
            continue
        if ap.encryption not in ("wpa2", "wpa2-wpa3", "wpa3"):
            continue  # PMF is an RSN feature; asserting it about WEP or an open BSS is meaningless
        fact = _capability_fact(ap, "pmf")
        if fact is None:
            continue  # no export that can see PMF observed this BSS - it stays undetermined
        findings.append(_build_rf_finding(
            rule_id="wardrive.pmf-absent", title=f"802.11w management-frame protection not advertised on {ap.label()}",
            severity="medium", confidence="medium",
            class_id="wireless-mfp", class_name="Management-frame protection absent",
            cwe="CWE-940 Improper Verification of Source of a Communication Channel", owasp=_OWASP_MISCONFIG,
            # Same provenance rule as WPS: quote the token, the file and the line from the
            # export that could see PMF - and say which file that was, because the claim
            # "other rows in the same export carry the marker" is about THAT file only.
            subject=ap, provenance=fact,
            evidence=fact.evidence or "no MFPC/MFPR capability",
            # The "other rows carry the marker" clause is the file-level INFERENCE's own
            # justification, so it is stated only when that is where the verdict came from.
            # Printing it under any other basis would assert a fact about the cited export
            # that this verdict never rested on.
            matched_value=(f"{ap.bssid} advertises {ap.encryption.upper()} without MFPC/MFPR "
                           f"({fact.evidence}) in {fact.source_path or fact.observed_by} row "
                           f"{fact.source_row}"
                           + (", while other rows in that same export do carry those markers"
                              if fact.basis == "inferred" else "")),
            remediation=("Enable 802.11w. Without it the BSS's management frames are unauthenticated, so a "
                         "nearby radio can forge disconnect frames and interrupt clients at will, and the "
                         "resulting reconnections make the network far easier to impersonate. Set PMF to "
                         "capable across the estate and to required on any SSID whose clients all support it "
                         "(WPA3-SAE mandates it)."),
            verification_obligation=("Read the RSN Capability bits from a beacon capture for this BSSID to confirm "
                                     "MFPC/MFPR are clear; this verdict is derived from the export's own markers, "
                                     "not from the capability field itself."),
            references=[_REF_80211, _REF_NIST_1B]))
    return findings


# --- identity: evil twin, rogue, soft AP ------------------------------------------


def _f_evil_twin(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """The flagship detector: one SSID advertised by BSSIDs that disagree about themselves.

    THE FALSE-POSITIVE CONTROL IS THE HARD PART, and it is stated in the finding text as
    well as enforced here. A legitimate multi-AP or band-steering deployment puts the SAME
    SSID on many BSSIDs by design — that is not a defect and must never be flagged. So a
    same-vendor, same-encryption group scores ZERO and produces nothing at all, no matter
    how many BSSIDs it has.

    Only DIVERGENCE scores, and only divergence we can actually observe:

      * different encryption for one SSID  — STRONGEST. A client that has the passphrase
        will still associate to the open or weaker twin.
      * different hardware vendor          — STRONG, but ONLY when both OUIs are in the
        curated table. ``oui.same_vendor`` returns None for an unknown prefix and an
        unknown is not evidence of anything.
      * a locally-administered BSSID       — STRONG. Vendor hardware burns in a globally
        unique address; a software-assigned one means a soft AP.
      * a >35 dB signal outlier            — WEAK, and never sufficient alone.

    2+ strong => high. 1 strong => medium CANDIDATE. 0 strong => nothing.
    """
    table = ctx["oui_table"]
    findings: list[dict[str, Any]] = []
    groups: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        if ap.ssid and not ap.hidden:
            groups.setdefault(ap.ssid, []).append(ap)
    for ssid in sorted(groups):
        members = sorted(groups[ssid], key=lambda a: a.bssid)
        if len(members) < 2:
            continue
        encryptions = sorted({m.encryption for m in members})
        strong: list[str] = []
        weak: list[str] = []
        if len(encryptions) > 1:
            strong.append(f"the same SSID is advertised with DIFFERENT encryption: {', '.join(encryptions)}")
        soft = [m.bssid for m in members if is_locally_administered(m.bssid)]
        if soft:
            strong.append(f"locally-administered (software-assigned) BSSID(s): {', '.join(sorted(soft))}")
        vendors = {m.bssid: oui.vendor_for(m.bssid, table) for m in members}
        known = sorted({v for v in vendors.values() if v})
        undetermined_vendors = [b for b, v in sorted(vendors.items()) if not v]
        if len(known) > 1:
            strong.append(f"different hardware vendors for one SSID: {', '.join(known)}")
        signals = [m.signal_dbm for m in members if m.signal_dbm is not None]
        if len(signals) > 1 and (max(signals) - min(signals)) >= _SIGNAL_OUTLIER_DB:
            weak.append(f"{max(signals) - min(signals)} dB spread between the strongest and weakest BSSID")
        if not strong:
            continue
        severity = "high" if len(strong) >= 2 else "medium"
        confidence = "medium" if len(strong) >= 2 else "low"
        title = (f"Possible evil twin on SSID {ssid!r}" if severity == "high"
                 else f"Evil-twin CANDIDATE on SSID {ssid!r}")
        anchor = members[0]
        reasons = strong + weak
        caveat = ""
        if undetermined_vendors:
            caveat = (f" Vendor is UNDETERMINED for {len(undetermined_vendors)} BSSID(s) "
                      f"({', '.join(undetermined_vendors[:4])}) - they are outside GreyIQ's curated OUI "
                      f"subset, so no vendor divergence was counted for them.")
        findings.append(_build_rf_finding(
            rule_id="wardrive.evil-twin", title=title,
            severity=severity, confidence=confidence,
            class_id="wireless-impersonation", class_name="SSID impersonation / evil twin",
            cwe="CWE-290 Authentication Bypass by Spoofing / CWE-940", owasp=_OWASP_MISCONFIG,
            subject=anchor,
            evidence=", ".join(f"{m.bssid}={m.raw_privacy or m.encryption}" for m in members)[:400],
            matched_value=f"{len(members)} BSSIDs advertise {ssid!r}: " + "; ".join(reasons),
            remediation=("Identify every BSSID advertising this SSID against the site's AP inventory and remove "
                         "or reconfigure the ones that do not belong. FALSE-POSITIVE CONTROL: a legitimate "
                         "multi-AP or band-steering deployment advertises one SSID from many BSSIDs, which is "
                         "why a same-vendor, same-encryption group is deliberately NOT flagged - this group was "
                         "flagged because its members disagree with each other. Enabling 802.11w and 802.1X, or "
                         "WPA3-SAE, makes impersonating this SSID materially harder." + caveat),
            verification_obligation=("Walk the site and match each BSSID to physical hardware, or check the WLAN "
                                     "controller's AP list. A survey export cannot distinguish an unmanaged AP "
                                     "from an attacker's - only the inventory can."),
            references=[_REF_80211, _REF_WPA3]))
    return findings


def _f_rogue_ap(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Rogue-AP verdicts, which require an AUTHORIZED INVENTORY to be meaningful.

    Without ``--authorized`` there is no such thing as a rogue AP — every network in a
    survey is somebody's, and calling a neighbour's router "rogue" is a fabrication. With
    an inventory, the sharp case is an SSID the operator owns being advertised by a BSSID
    they do not."""
    inventory = ctx["authorized"]
    if not inventory:
        return []
    known_bssids = inventory["bssids"]
    known_ssids = inventory["ssids"]
    findings: list[dict[str, Any]] = []
    for ap in aps:
        if ap.bssid in known_bssids:
            continue
        if ap.ssid and ap.ssid.lower() in known_ssids:
            findings.append(_build_rf_finding(
                rule_id="wardrive.rogue-ap",
                title=f"Unlisted BSSID advertising the authorized SSID {ap.ssid!r}",
                severity="high", confidence="medium",
                class_id="wireless-impersonation", class_name="Unauthorized access point",
                cwe="CWE-290 Authentication Bypass by Spoofing", owasp=_OWASP_MISCONFIG,
                subject=ap, evidence=ap.ssid,
                matched_value=(f"{ap.bssid} advertises {ap.ssid!r}, which the supplied inventory lists as "
                               f"authorized, but this BSSID is not in the inventory"),
                remediation=("Locate this radio and account for it. Either it is a managed AP missing from the "
                             "inventory - fix the inventory - or it is an unmanaged or hostile radio "
                             "impersonating a network your clients trust, and it must be removed."),
                verification_obligation=("Confirm against the WLAN controller and the physical site walk before "
                                         "treating this as hostile; an out-of-date inventory produces exactly "
                                         "this finding.")))
    return findings


def _f_soft_ap(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """A BSS beaconing from a locally-administered address, or from SoC/dev-board silicon.

    Neither is a defect on its own — a phone hotspot is not an attack — but in a MANAGED RF
    environment both are unmanaged infrastructure inside the perimeter, and the dev-board
    case is the highest-signal cheap indicator there is: a beaconing Espressif or Raspberry
    Pi radio in a corporate space is almost never part of the WLAN design."""
    table = ctx["oui_table"]
    patterns = ctx["ssid_patterns"]
    findings: list[dict[str, Any]] = []
    for ap in aps:
        klass = oui.vendor_class(ap.bssid, table)
        kind, label = oui.classify_ssid(ap.ssid, patterns)
        # `token` is the byte string the verdict was READ FROM, chosen by the branch that
        # produced it rather than by the vendor class. Keying it on `klass != "unknown"`
        # quoted the BSSID for an SSID-derived verdict, so a curated Cisco enterprise-AP OUI
        # could be printed as the evidence for "this is a soft AP" - a token that argues
        # against the claim it is filed under.
        if klass == "soft-ap":
            basis = "the BSSID's locally-administered bit is set (software-assigned, not vendor-burned)"
            token = ap.bssid
        elif klass == "soc-devboard":
            vendor = oui.vendor_for(ap.bssid, table) or "an SoC/dev-board vendor"
            basis = f"the BSSID belongs to {vendor}, a SoC/dev-board OUI rather than AP hardware"
            token = ap.bssid
        elif kind == "soft-ap":
            basis = f"the SSID matches the curated soft-AP pattern {label!r}"
            token = ap.ssid or ap.bssid
        else:
            continue
        findings.append(_build_rf_finding(
            rule_id="wardrive.soft-ap", title=f"Unmanaged / soft access point: {ap.label()}",
            severity="medium", confidence="low",
            class_id="wireless-unmanaged-ap", class_name="Unmanaged access point",
            cwe="CWE-1188 Initialization of a Resource with an Insecure Default", owasp=_OWASP_MISCONFIG,
            subject=ap, evidence=token,
            matched_value=f"{ap.bssid} ({ap.label()}): {basis}",
            remediation=("Account for this radio. In a managed RF environment a soft AP, phone hotspot or "
                         "dev board bridges an unmanaged device onto whatever it is attached to and sits "
                         "outside the WLAN's monitoring and policy. If it is sanctioned, add it to the AP "
                         "inventory; if not, remove it and cover the case in policy."),
            verification_obligation=("Attribute the radio to a physical device before acting - a passing "
                                     "phone hotspot and a permanently installed bridge look identical in a "
                                     "survey export.")))
    return findings


# --- configuration hygiene --------------------------------------------------------


def _f_default_ssid(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    patterns = ctx["ssid_patterns"]
    findings: list[dict[str, Any]] = []
    for ap in aps:
        kind, label = oui.classify_ssid(ap.ssid, patterns)
        if kind != "factory":
            continue
        findings.append(_build_rf_finding(
            rule_id="wardrive.default-ssid", title=f"Factory-default SSID still broadcast: {ap.ssid!r}",
            severity="medium", confidence="medium",
            class_id="wireless-default-config", class_name="Factory-default wireless configuration",
            cwe="CWE-1392 Use of Default Credentials / CWE-1188", owasp=_OWASP_MISCONFIG,
            subject=ap, evidence=ap.ssid,
            matched_value=f"{ap.bssid} broadcasts {ap.ssid!r}, matching the curated pattern {label!r}",
            remediation=("Change the SSID and, far more importantly, audit everything else the vendor shipped: "
                         "an unchanged SSID very often means an unchanged admin password, an unchanged "
                         "management interface and an unchanged onboarding PIN. It also fingerprints the exact "
                         "model to anyone in radio range."),
            verification_obligation=("Confirm the device is actually running vendor-default configuration - an "
                                     "SSID left at default does not by itself prove the credentials were.")))
    return findings


def _f_hidden_ssid(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    hidden = [ap for ap in aps if ap.hidden]
    if not hidden:
        return []
    anchor = hidden[0]
    return [_build_rf_finding(
        rule_id="wardrive.hidden-ssid", title=f"{len(hidden)} BSS suppress the SSID in beacons",
        severity="info", confidence="high",
        class_id="wireless-obscurity", class_name="SSID cloaking",
        cwe="CWE-656 Reliance on Security Through Obscurity", owasp=_OWASP_MISCONFIG,
        subject=anchor, evidence=", ".join(ap.bssid for ap in hidden[:12]),
        matched_value=f"{len(hidden)} BSS broadcast an empty SSID element: {', '.join(ap.bssid for ap in hidden[:8])}",
        remediation=("Informational. Hiding the SSID adds no meaningful protection - the name is still carried "
                     "in association and probe frames - and it pushes managed clients into broadcasting the "
                     "network name wherever they go, which enlarges their exposure rather than reducing it. "
                     "Spend the effort on WPA3-SAE and 802.11w instead."),
        verification_obligation="No further capture needed; this is a configuration observation, not a defect claim.")]


def _f_channel_health(aps: list[AccessPoint], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """2.4 GHz BSS parked on an overlapping channel. Availability hygiene rather than a
    security defect, so it is INFO and it says so."""
    overlapping = [ap for ap in aps
                   if ap.band == "2.4GHz" and ap.channel is not None and ap.channel not in NON_OVERLAPPING_24]
    if not overlapping:
        return []
    anchor = overlapping[0]
    channels = sorted({ap.channel for ap in overlapping if ap.channel is not None})
    return [_build_rf_finding(
        rule_id="wardrive.channel-overlap",
        title=f"{len(overlapping)} 2.4 GHz BSS on overlapping channels",
        severity="info", confidence="high", category="wireless-availability",
        class_id="wireless-rf-health", class_name="RF channel planning",
        cwe="CWE-400 Uncontrolled Resource Consumption", owasp=_OWASP_MISCONFIG,
        subject=anchor, evidence=", ".join(str(c) for c in channels),
        matched_value=(f"channels {', '.join(str(c) for c in channels)} overlap the non-overlapping set "
                       f"{NON_OVERLAPPING_24}"),
        remediation=("Availability hygiene, not a security defect. Under 20 MHz spacing only channels 1, 6 and "
                     "11 do not overlap in 2.4 GHz; anything else raises the noise floor for every network "
                     "nearby, including yours. Move these BSS onto 1/6/11 or onto 5 GHz."),
        verification_obligation="None - this is read directly off the channel numbers in the export.")]


# --- client-side exposure ---------------------------------------------------------


def _f_probe_exposure(stations: list[Station], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """A client's Preferred Network List, leaked in its probe requests.

    This is the most useful client-side artifact in a survey export: a device that names
    networks it has joined before is broadcasting a travel history, and any radio nearby can
    answer with a matching SSID. Reported as an exposure to REMEDIATE on the client, never
    with any suggestion of exploiting it."""
    findings: list[dict[str, Any]] = []
    for station in sorted(stations, key=lambda s: (-len(s.probes), s.mac)):
        named = [p for p in station.probes if p]
        if not named:
            continue
        severity = "medium" if len(named) >= 3 else "low"
        findings.append(_build_rf_finding(
            rule_id="wardrive.probe-exposure",
            title=f"Client {station.mac} broadcasts {len(named)} network name(s) in probe requests",
            severity=severity, confidence="high", category="wireless-client",
            class_id="wireless-pnl-exposure", class_name="Preferred Network List exposure",
            cwe="CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", owasp=_OWASP_MISCONFIG,
            subject=station, evidence=", ".join(named[:12]),
            matched_value=f"{station.mac} probed for: {', '.join(named[:12])}",
            remediation=("On the client: remove stale saved networks, and turn off auto-join for any network "
                         "that is not a managed corporate SSID. A device that names its saved networks in "
                         "probe requests reveals where it has been and lets any AP in range present itself as "
                         "one of them. Hidden SSIDs make this worse, because the client must name them to "
                         "find them at all - prefer broadcast SSIDs with strong authentication."),
            verification_obligation=("Attribute the MAC to a device before reporting it as an individual's "
                                     "exposure; modern clients randomize per network and the same handset can "
                                     "appear as several MACs in one export.")))
    return findings


def _f_trackable_client(stations: list[Station], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Clients probing from a GLOBALLY unique (burned-in) MAC, i.e. with MAC randomization
    off. Modern clients randomize precisely so a passive observer cannot track them across
    surveys; one that does not is trackable by anyone within range."""
    trackable = [s for s in stations if s.mac and not s.randomized]
    if not trackable:
        return []
    anchor = sorted(trackable, key=lambda s: s.mac)[0]
    return [_build_rf_finding(
        rule_id="wardrive.trackable-client",
        title=f"{len(trackable)} client(s) use a non-randomized (trackable) MAC",
        severity="low", confidence="medium", category="wireless-client",
        class_id="wireless-client-privacy", class_name="Client MAC trackability",
        cwe="CWE-359 Exposure of Private Personal Information", owasp=_OWASP_MISCONFIG,
        subject=anchor, evidence=", ".join(sorted(s.mac for s in trackable)[:12]),
        matched_value=f"{len(trackable)} client MAC(s) have the locally-administered bit clear, so they are burned-in and stable",
        remediation=("Enable MAC randomization in the client OS's Wi-Fi settings (it is the default on current "
                     "Android, iOS and Windows). A stable burned-in address lets any passive receiver correlate "
                     "the same device across locations and days."),
        verification_obligation=("Some devices randomize per SSID but not while associated; confirm on the "
                                 "device rather than from the export alone."))]


# --- undetermined bookkeeping -----------------------------------------------------


def _undetermined(aps: list[AccessPoint], survey: Survey,
                  table: dict[str, tuple[str, str]]) -> list[dict[str, Any]]:
    """What this survey COULD NOT determine, with the reason and the capture that fixes it.

    This is the deliberate counterweight to the detectors' positive-observation rule: the
    facts that produced no finding because they could not be observed are reported here so
    the deliverable can never be read as a clean bill of health."""
    rows: list[dict[str, Any]] = []
    formats = sorted({str(src.get("format") or "") for src in survey.sources if src.get("format")})
    fmt_list = ", ".join(formats) or "unknown"

    def fmt_of(subset: list[AccessPoint]) -> str:
        return ", ".join(sorted({ap.source for ap in subset if ap.source})) or fmt_list

    wps_unknown = [ap for ap in aps if ap.wps is None]
    if wps_unknown:
        rows.append({
            "fact": "wps", "ap_count": len(wps_unknown), "formats": fmt_of(wps_unknown),
            # Accurate for all three ways a BSS lands here, because the ledger is the one
            # place the deliverable states WHY nothing was claimed: the format cannot carry
            # the fact, no export in the survey emitted the marker at all, or the row naming
            # this BSS had an empty capability field and so observed nothing about it.
            "reason": ("no export in this survey observed WPS for these BSS - airodump-ng and netsh never "
                       "report it, no WPS marker appeared anywhere in the other exports, or the row naming "
                       "the BSS carried no capability field"),
            "resolved_by": "a Kismet capture or a WiGLE export, which do record the WPS information element",
            "not_a_finding": "no WPS finding was raised for these BSS, and none of them is known to have WPS off",
        })
    pmf_unknown = [ap for ap in aps if not ap.pmf and ap.encryption in ("wpa2", "wpa2-wpa3", "wpa3")]
    if pmf_unknown:
        rows.append({
            "fact": "pmf", "ap_count": len(pmf_unknown), "formats": fmt_of(pmf_unknown),
            "reason": ("no export in this survey observed the RSN Capability bits these BSS would carry 802.11w "
                       "in: airodump-ng CSV, netsh and Kismet netxml cannot express them at all, and where "
                       "WiGLE could, the AuthMode either carried no MFP marker anywhere in that export or was "
                       "empty for this BSS (an empty field records nothing, not absence)"),
            "resolved_by": "a beacon pcap, or a WiGLE export whose AuthMode carries the MFPR/MFPC markers",
            "not_a_finding": "no 'PMF missing' finding was raised for these BSS - the export cannot observe it",
        })
    sig_unknown = [ap for ap in aps if ap.signal_dbm is None]
    if sig_unknown:
        rows.append({
            "fact": "signal_dbm", "ap_count": len(sig_unknown), "formats": fmt_of(sig_unknown),
            "reason": ("the export gave a driver-computed percentage or the no-signal sentinel instead of a "
                       "measured dBm"),
            "resolved_by": "any capture that records dBm (airodump-ng, Kismet, WiGLE)",
            "not_a_finding": "signal-based proximity reasoning was skipped for these BSS rather than estimated",
        })
    enc_unknown = [ap for ap in aps if ap.encryption == "unknown"]
    if enc_unknown:
        rows.append({
            "fact": "encryption", "ap_count": len(enc_unknown), "formats": fmt_of(enc_unknown),
            "reason": "no privacy token could be decoded from the export row (truncated capture, or localized labels)",
            "resolved_by": "re-export the capture, or re-run netsh on an English-locale shell",
            "not_a_finding": "these BSS were NOT treated as open; unknown is not open",
        })
    vendor_unknown = [ap for ap in aps if not oui.vendor_for(ap.bssid, table)]
    if vendor_unknown:
        rows.append({
            "fact": "vendor", "ap_count": len(vendor_unknown), "formats": fmt_of(vendor_unknown),
            "reason": "the BSSID prefix is outside GreyIQ's curated OUI subset (which is not the full IEEE registry)",
            "resolved_by": "add the prefix to <runtime>/rf/oui.tsv",
            "not_a_finding": "no vendor divergence was scored for these BSSIDs in evil-twin triage",
        })
    return rows


def _inferences(aps: list[AccessPoint]) -> list[dict[str, Any]]:
    """Facts we believe but did NOT observe, kept strictly out of ``findings``."""
    rows: list[dict[str, Any]] = []
    for ap in sorted(aps, key=lambda a: a.bssid):
        if ap.encryption == "wpa3" and ap.auth == "sae" and not ap.pmf:
            rows.append({
                "bssid": ap.bssid, "fact": "pmf", "value": "required", "basis": "INFERRED",
                "detail": ("WPA3-SAE mandates 802.11w, so PMF is almost certainly required on this BSS - but "
                           "this export does not carry the RSN Capability bits, so it was NOT observed."),
                "source_format": ap.source,
            })
    return rows


# --- public entry -----------------------------------------------------------------

_AP_DETECTORS = (_f_weak_crypto, _f_wps, _f_pmf, _f_evil_twin, _f_rogue_ap, _f_soft_ap,
                 _f_default_ssid, _f_hidden_ssid, _f_channel_health)
_STATION_DETECTORS = (_f_probe_exposure, _f_trackable_client)


def _normalize_inventory(authorized: Any) -> dict[str, set[str]] | None:
    """Accept an inventory as ``{"bssids": [...], "ssids": [...]}`` or as a bare list of
    BSSIDs. Anything unusable becomes None — "no inventory" — rather than a partial one, so
    a malformed file can never turn every AP on the street into a rogue."""
    if not authorized:
        return None
    bssids: set[str] = set()
    ssids: set[str] = set()
    if isinstance(authorized, dict):
        entries = authorized.get("bssids") or authorized.get("aps") or []
        for value in entries if isinstance(entries, (list, tuple, set)) else []:
            # An entry may be a bare BSSID string or a {"bssid": …, "ssid": …} record. Anything
            # else (a number, a nested list from a hand-edited file) contributes nothing rather
            # than raising - this runs BEFORE the per-detector guard, so it must be total.
            if isinstance(value, dict):
                mac = normalize_mac(value.get("bssid", ""))
                if str(value.get("ssid") or "").strip():
                    ssids.add(str(value["ssid"]).strip().lower())
            elif isinstance(value, str):
                mac = normalize_mac(value)
            else:
                continue
            if mac:
                bssids.add(mac)
        names = authorized.get("ssids") or []
        for value in names if isinstance(names, (list, tuple, set)) else []:
            if isinstance(value, str) and value.strip():
                ssids.add(value.strip().lower())
    elif isinstance(authorized, (list, tuple, set)):
        for value in authorized:
            mac = normalize_mac(value) if isinstance(value, str) else ""
            if mac:
                bssids.add(mac)
    if not bssids and not ssids:
        return None
    return {"bssids": bssids, "ssids": ssids}


def analyze_survey(survey: Survey, *, authorized: Any = None, seed_dir: Any = None,
                   runtime_dir: Any = None, cap: int = _DEFAULT_CAP) -> dict[str, Any]:
    """Analyze a parsed :class:`Survey` and return the assessment result.

    ``{ok, error, source_formats, sources, stats, findings, undetermined, inferences,
    warnings, oui_table, capped}``. Total: any detector that raises costs its own findings
    and nothing else, because an assessment that dies on one malformed row is worth less
    than one that reports the other 3 000."""
    if survey is None:
        return {"ok": False, "error": "no survey supplied", "findings": [], "undetermined": [],
                "inferences": [], "warnings": [], "stats": {}, "sources": [], "source_formats": [],
                "oui_table": {}, "capped": False}
    aps = survey.ap_list()
    stations = survey.station_list()
    ctx: dict[str, Any] = {
        "oui_table": oui.load_oui_table(seed_dir, runtime_dir),
        "ssid_patterns": oui.load_ssid_patterns(seed_dir, runtime_dir),
        "authorized": _normalize_inventory(authorized),
    }
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for detector in _AP_DETECTORS:
        try:
            findings.extend(detector(aps, ctx))
        except Exception as exc:  # noqa: BLE001 - one detector must never cost the whole assessment
            errors.append(f"{detector.__name__} failed ({type(exc).__name__}: {exc})")
    for detector in _STATION_DETECTORS:
        try:
            findings.extend(detector(stations, ctx))
        except Exception as exc:  # noqa: BLE001 - same contract on the client-side detectors
            errors.append(f"{detector.__name__} failed ({type(exc).__name__}: {exc})")
    # Deterministic ordering with explicit keys - never set iteration, because these findings
    # are read side by side with a previous run's during a retest.
    findings.sort(key=lambda f: (-_SEVERITY_RANK.get(f.get("severity", "info"), 0),
                                 str(f.get("rule_id", "")), str(f.get("location", ""))))
    capped = len(findings) > cap
    if capped:
        findings = findings[:cap]
    warnings = list(survey.warnings) + errors
    if capped:
        warnings.append(f"finding list truncated to the {cap} highest-severity entries.")
    return {
        "ok": True,
        "error": "",
        "source_formats": sorted({str(src.get("format") or "") for src in survey.sources if src.get("format")}),
        "sources": list(survey.sources),
        "stats": _stats(aps, stations, findings),
        "findings": findings,
        "undetermined": _undetermined(aps, survey, ctx["oui_table"]),
        "inferences": _inferences(aps),
        "warnings": warnings,
        "oui_table": oui.table_info(seed_dir, runtime_dir),
        "capped": capped,
    }


def _stats(aps: list[AccessPoint], stations: list[Station], findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_encryption: dict[str, int] = {}
    by_band: dict[str, int] = {}
    for ap in aps:
        by_encryption[ap.encryption] = by_encryption.get(ap.encryption, 0) + 1
        by_band[ap.band or "unknown"] = by_band.get(ap.band or "unknown", 0) + 1
    by_severity = {sev: 0 for sev in _SEVERITIES}
    for finding in findings:
        sev = str(finding.get("severity") or "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "access_points": len(aps),
        "stations": len(stations),
        "hidden": sum(1 for ap in aps if ap.hidden),
        "enterprise": sum(1 for ap in aps if ap.enterprise),
        "weakest_encryption": min((ap.encryption for ap in aps), key=encryption_rank, default=""),
        "by_encryption": dict(sorted(by_encryption.items(), key=lambda kv: (encryption_rank(kv[0]), kv[0]))),
        "by_band": dict(sorted(by_band.items())),
        "by_severity": by_severity,
        "findings": len(findings),
        "clients_with_probes": sum(1 for s in stations if s.probes),
    }
