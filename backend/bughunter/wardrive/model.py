"""Wardrive / RF survey — the data model and the normalization that makes four
incompatible export formats comparable.

Every wireless survey tool spells the same facts differently: airodump-ng writes
``WPA2 CCMP PSK`` across three columns, WiGLE writes ``[WPA2-PSK-CCMP][WPS][ESS]``
in one, Kismet's netxml writes ``<encryption>WPA+PSK</encryption>`` repeated once
per element, and Windows ``netsh`` writes ``Authentication : WPA2-Personal`` /
``Encryption : CCMP``. :func:`normalize_privacy` collapses all of them onto ONE
vocabulary (``open``/``wep``/``wpa``/``wpa2``/``wpa3``/``wpa2-wpa3``/``owe``) plus a
cipher, an auth mode, and a tri-state WPS flag, so the analyzer reasons over facts
rather than over the tool that happened to record them.

The tri-state matters and is deliberate: ``wps=None`` means *this format cannot tell
us* (airodump never reports WPS), which is different from ``wps=False`` (*the format
reports WPS and it is off*). The analyzer never raises a finding on an unknown — an
absent fact is reported as unknown, never as a clean bill of health. Same for
:attr:`AccessPoint.pmf`, which only WiGLE can supply.

A BARE TRI-STATE IS NOT ENOUGH once two exports of the same walk are merged, and that
is what :class:`CapabilityFact` exists for. Each WPS/PMF value carries WHICH export
observed it, whether it was observed DIRECTLY (a verbatim ``[MFPR]`` / ``<wps>`` token)
or INFERRED from file-level absence, and the exact path/row/bytes it came from. Three
rules fall out of that and all three are release-blocking:

  1. A direct observation always beats an inference, no matter which file was parsed
     first. Before facts carried a basis, ``add_ap``'s fill-if-blank merge let a file-1
     inference ("no MFP token anywhere in this export") permanently outrank a file-2
     ``[MFPR]``, and the analyzer then asserted the opposite of data it had parsed.
  2. Merge order can never change a verdict: :func:`choose_capability_fact` is a total
     order over (basis, value, path, row), so ``a`` then ``b`` and ``b`` then ``a``
     select the same fact.
  3. A fact may only be attached by a format that can actually observe it
     (:data:`CAPABILITY_SUPPORT`). An airodump-ng CSV carries no RSN capability bits, so
     a PMF value can never land on a record via an airodump row — and because the
     finding quotes the FACT's provenance rather than the merged record's, it can never
     cite an airodump line as the source of a PMF verdict either.

Pure / dependency-free / frozen-safe: stdlib only, no I/O. Every function is total —
malformed input yields empty/unknown values rather than raising, because a survey
export is operator-supplied data that may be truncated mid-capture.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# --- MAC / BSSID -----------------------------------------------------------------

_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-]?[0-9a-f]{2}){5}$", re.IGNORECASE)
_NON_HEX = re.compile(r"[^0-9a-f]")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def normalize_mac(value: Any) -> str:
    """Canonical lowercase colon-separated MAC, or '' if ``value`` isn't one.

    Accepts ``AA:BB:CC:DD:EE:FF``, ``aa-bb-cc-dd-ee-ff``, ``AABBCCDDEEFF`` and the
    ``(not associated)`` placeholder airodump writes for unassociated clients (→ '')."""
    raw = str(value or "").strip()
    if not raw or not _MAC_RE.match(raw):
        return ""
    hexed = _NON_HEX.sub("", raw.lower())
    if len(hexed) != 12:
        return ""
    return ":".join(hexed[i:i + 2] for i in range(0, 12, 2))


def oui_prefix(mac: str) -> str:
    """The 24-bit OUI prefix (``aa:bb:cc``) of a normalized MAC, or ''."""
    mac = normalize_mac(mac)
    return mac[:8] if mac else ""


def is_locally_administered(mac: str) -> bool:
    """True when the MAC's locally-administered bit is set — i.e. it is a RANDOMIZED /
    software-assigned address rather than a burned-in vendor address.

    Modern phones randomize their probe-request MAC per network precisely so a passive
    observer can't track them across surveys. A client seen with a GLOBALLY unique
    (burned-in) address is therefore trackable, which is what the analyzer flags."""
    mac = normalize_mac(mac)
    if not mac:
        return False
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return False
    return bool(first & 0b10)


def is_multicast(mac: str) -> bool:
    """True for a group/broadcast address (least-significant bit of octet 0 set)."""
    mac = normalize_mac(mac)
    if not mac:
        return False
    try:
        return bool(int(mac[:2], 16) & 0b1)
    except ValueError:
        return False


# --- Channel / band --------------------------------------------------------------

# The non-overlapping 2.4 GHz channels under 20 MHz spacing (US/ETSI common set).
NON_OVERLAPPING_24 = (1, 6, 11)


def band_for_channel(channel: int | None) -> str:
    """The band a channel number belongs to. 6 GHz and 2.4 GHz both use low channel
    numbers, so a bare channel number is ambiguous above the 2.4 GHz range only —
    we resolve 1-14 as 2.4 GHz, 32-177 as 5 GHz, and leave anything else ''."""
    if channel is None:
        return ""
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    return ""


def parse_channel(value: Any) -> int | None:
    """First integer in ``value`` as a channel number, or None. Tolerates ``' 6'``,
    ``'6,-1'`` (airodump writes -1 for an unknown channel), ``'36 (5 GHz)'``."""
    match = re.search(r"-?\d+", str(value or ""))
    if not match:
        return None
    try:
        channel = int(match.group(0))
    except ValueError:
        return None
    return channel if channel > 0 else None


def parse_signal(value: Any) -> int | None:
    """Signal strength in dBm. Accepts a raw dBm int (``-67``), airodump's ``Power``
    column, and a Windows ``netsh`` percentage (``84%``), which is mapped onto dBm with
    the standard wlanapi linear rule (0% = -100 dBm, 100% = -50 dBm). Returns None when
    the value is absent or the ``-1`` airodump writes for "never received a frame"."""
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("%"):
        try:
            pct = max(0, min(100, int(float(raw[:-1]))))
        except ValueError:
            return None
        return int(round(pct / 2.0 - 100))
    match = re.search(r"-?\d+", raw)
    if not match:
        return None
    try:
        dbm = int(match.group(0))
    except ValueError:
        return None
    if dbm in (0, -1):  # airodump's "unknown power" sentinels
        return None
    return dbm if dbm < 0 else -dbm


# --- Privacy / encryption normalization ------------------------------------------

#: The normalized encryption vocabulary, WEAKEST FIRST. The analyzer orders severity by
#: this index, so adding a scheme here is the single place that decides how bad it is.
ENCRYPTION_ORDER = ("open", "wep", "wpa", "wpa2", "wpa2-wpa3", "wpa3", "owe", "unknown")

_WEAKNESS_RANK = {
    "wep": 0,
    "open": 1,
    "wpa": 2,
    "wpa2": 3,
    "wpa2-wpa3": 4,
    "owe": 5,
    "wpa3": 6,
    "unknown": 7,
}


def encryption_rank(encryption: str) -> int:
    """Sort key: lower == weaker. Unknown sorts last so it never displaces a real defect."""
    return _WEAKNESS_RANK.get(str(encryption or "unknown").lower(), 7)


def normalize_privacy(raw: Any, cipher_hint: Any = "", auth_hint: Any = "") -> dict[str, Any]:
    """Collapse any tool's privacy/auth/cipher spelling onto the shared vocabulary.

    ``raw`` is the primary privacy blob (airodump ``Privacy``, WiGLE ``AuthMode``,
    Kismet ``encryption`` values joined, netsh ``Authentication``). ``cipher_hint`` /
    ``auth_hint`` carry the extra columns airodump and netsh split out.

    Returns ``{encryption, cipher, auth, wps, enterprise, raw}`` where ``wps`` is
    tri-state (True / False / None-for-unknown) and every string is lowercase.

    The order of the checks below is load-bearing: WPA3/SAE is tested before WPA2
    because a transition-mode AP advertises BOTH, and WEP is tested before "wpa"
    because ``WPA`` never appears in a WEP blob but ``WEP`` can appear alongside
    nothing else. ``unknown`` is returned only when the blob carries no privacy token
    at all — never as a silent stand-in for "open"."""
    blob = " ".join(str(p or "") for p in (raw, cipher_hint, auth_hint)).upper()
    primary = str(raw or "").upper()

    # WPS is only knowable when the format says so. WiGLE puts a literal [WPS] element in
    # AuthMode; Kismet netxml exposes a <wps> element. Absent => None (unknown), NOT False.
    # The NEGATIVE spellings are tested FIRST and this order is load-bearing: every one of
    # them ("NO_WPS", "WPS=0", "WPS: disabled") CONTAINS the substring "WPS", so testing the
    # bare substring first made the negative branch unreachable and turned bytes that say
    # WPS is off into a positive "WPS enabled" verdict — asserting the opposite of the token
    # it quotes as evidence.
    wps: bool | None = None
    if re.search(r"\bNO[_\- ]?WPS\b|WPS\s*[:=]\s*(0|OFF|FALSE|DISABLED|NO)\b", blob):
        wps = False
    elif "WPS" in blob:
        wps = True

    cipher = ""
    for token, name in (("GCMP", "gcmp"), ("CCMP", "ccmp"), ("AES", "ccmp"), ("TKIP", "tkip"), ("WEP", "wep")):
        if token in blob:
            cipher = name
            break

    auth = ""
    enterprise = False
    if re.search(r"\bSAE\b", blob):
        auth = "sae"
    elif re.search(r"\bEAP\b|ENTERPRISE|802\.1X|8021X|MGT\b", blob):
        auth = "eap"
        enterprise = True
    elif re.search(r"\bPSK\b|PERSONAL", blob):
        auth = "psk"
    elif re.search(r"\bOWE\b", blob):
        auth = "owe"

    has_wpa3 = bool(re.search(r"WPA3|\bSAE\b", blob))
    has_wpa2 = bool(re.search(r"WPA2|RSN", blob))
    # A bare "WPA" that is not WPA2/WPA3 is the original 2003 TKIP-era scheme.
    has_wpa1 = bool(re.search(r"\bWPA\b", blob)) and not has_wpa2 and not has_wpa3
    has_wep = bool(re.search(r"\bWEP\b", blob))
    has_owe = bool(re.search(r"\bOWE\b", blob))
    # airodump writes "OPN"; WiGLE writes a bare "[ESS]" with no cipher element; netsh
    # writes "Open"; Kismet writes "None". Each means an unencrypted, unauthenticated BSS.
    has_open = bool(re.search(r"\bOPN\b|\bOPEN\b|\bNONE\b", primary)) or (
        primary.replace(" ", "") in ("[ESS]", "[IBSS]", "[ESS][WPS]")
    )

    if has_wpa3 and has_wpa2:
        encryption = "wpa2-wpa3"  # transition mode
    elif has_wpa3:
        encryption = "wpa3"
    elif has_owe and not has_wpa2:
        encryption = "owe"
    elif has_wpa2:
        encryption = "wpa2"
    elif has_wpa1:
        encryption = "wpa"
    elif has_wep:
        encryption = "wep"
    elif has_open:
        encryption = "open"
    else:
        encryption = "unknown"

    if encryption in ("wep",):
        cipher = cipher or "wep"
    if encryption == "open":
        cipher, auth = "", auth or "open"

    return {
        "encryption": encryption,
        "cipher": cipher,
        "auth": auth,
        "wps": wps,
        "enterprise": enterprise,
        "raw": str(raw or "").strip()[:120],
    }


# --- Capability provenance --------------------------------------------------------

#: Which export format can OBSERVE which capability, as ``fmt -> (wps, pmf)``. This is the
#: machine-readable form of the table in ``parsers``' module docstring and it is enforced,
#: not merely documented: :meth:`AccessPoint.apply_capability_fact` DISCARDS a fact whose
#: observing format cannot see it, so no code path can attach (or later quote) a PMF value
#: that came through a format carrying no RSN capability bits. Unknown format => (False,
#: False), i.e. fail closed: a value we cannot attribute to a format that could have seen
#: it is not a value we are allowed to assert.
CAPABILITY_SUPPORT: dict[str, tuple[bool, bool]] = {
    "airodump-csv": (False, False),   # no WPS column (that is `wash`), no RSN capability bits
    "wigle-csv": (True, True),        # AuthMode carries [WPS] and [MFPR]/[MFPC]
    "kismet-netxml": (True, False),   # <wps> element only; netxml has no capability bits
    "kismet-csv": (True, False),      # a dedicated `wps` column on some builds only
    "netsh-text": (False, False),     # neither
}

#: Basis strength. A DIRECT observation (a verbatim token in an export) outranks an
#: INFERENCE (this file demonstrably emits the marker and this row lacks it), which in turn
#: outranks an UNATTRIBUTED value (a record hand-built without provenance).
_BASIS_RANK = {"direct": 3, "inferred": 2, "unattributed": 1}

#: PMF strength, used only to break a tie between two DIRECT observations that disagree, so
#: the winner is a function of the facts and never of the order the files were parsed in.
_PMF_RANK = {"required": 3, "optional": 2, "disabled": 1, "": 0}


def format_can_observe(fmt: Any, fact: str) -> bool:
    """Whether export format ``fmt`` can observe ``fact`` (``"wps"`` / ``"pmf"``)."""
    support = CAPABILITY_SUPPORT.get(str(fmt or "").strip().lower())
    if support is None:
        return False  # fail closed - an unrecognized format has no demonstrated capability
    return support[0] if fact == "wps" else support[1] if fact == "pmf" else False


@dataclass(frozen=True)
class CapabilityFact:
    """One WPS/PMF observation together with the provenance OF THAT FACT.

    Kept separate from the :class:`AccessPoint` it lands on because after a cross-format
    merge the record's own ``source_path``/``source_row``/``raw_line`` belong to whichever
    export was seen FIRST, which is routinely not the export that could observe WPS or PMF.
    A finding that quoted the record instead of the fact would tell a reader to grep an
    airodump-ng row to verify a WPS claim — bytes that by construction say nothing about
    WPS. Every field here is what the analyzer cites."""

    fact: str            # "wps" | "pmf"
    value: Any           # bool for wps, one of ""/"disabled"/"optional"/"required" for pmf
    basis: str           # "direct" | "inferred" | "unattributed"
    observed_by: str     # the export FORMAT that observed it
    evidence: str = ""   # the verbatim token the verdict was read from
    source_path: str = ""
    source_row: int = 0
    raw_line: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact": self.fact, "value": self.value, "basis": self.basis,
            "observed_by": self.observed_by, "evidence": self.evidence,
            "source_path": self.source_path, "source_row": self.source_row,
            "raw_line": self.raw_line,
        }


def _fact_value_rank(fact: CapabilityFact) -> int:
    """Order two SAME-BASIS facts that disagree, deterministically.

    WPS: a positive observation wins — some export verbatim carried the element, and that
    reading stays reproducible from the bytes the finding quotes. PMF: the strongest
    advertised state wins. Neither rule consults arrival order, which is the point."""
    if fact.fact == "wps":
        return 1 if fact.value is True else 0
    return _PMF_RANK.get(str(fact.value or ""), 0)


def choose_capability_fact(a: CapabilityFact | None, b: CapabilityFact | None) -> CapabilityFact | None:
    """The winner of two observations of the same capability — a TOTAL ORDER, so merging
    ``a`` then ``b`` and ``b`` then ``a`` select the same fact and the deliverable cannot
    depend on the order ``sorted()`` happened to hand the exports to the parser."""
    if a is None:
        return b
    if b is None:
        return a
    key_a = (_BASIS_RANK.get(a.basis, 0), _fact_value_rank(a))
    key_b = (_BASIS_RANK.get(b.basis, 0), _fact_value_rank(b))
    if key_a != key_b:
        return a if key_a > key_b else b
    # Fully tied (same basis, same value): pick by provenance so the citation is stable. The
    # key covers every field a finding quotes, so two facts can only tie when quoting either
    # of them produces the same deliverable.
    tie_a = (str(a.observed_by), str(a.source_path), int(a.source_row or 0), str(a.evidence))
    tie_b = (str(b.observed_by), str(b.source_path), int(b.source_row or 0), str(b.evidence))
    return a if tie_a <= tie_b else b


def facts_conflict(a: CapabilityFact | None, b: CapabilityFact | None) -> bool:
    """True when two DIRECT observations of the same capability disagree. Reported as a
    warning rather than resolved silently: two exports of the same site really can have
    seen different states, and the operator is entitled to know which one the finding cites."""
    return bool(a and b and a.basis == "direct" and b.basis == "direct" and a.value != b.value)


# --- Records ---------------------------------------------------------------------


@dataclass
class AccessPoint:
    """One BSS observed in a survey. ``bssid`` is the identity; two records with the
    same BSSID from different files are merged by :meth:`Survey.add_ap`."""

    bssid: str
    ssid: str = ""
    hidden: bool = False
    channel: int | None = None
    band: str = ""
    encryption: str = "unknown"
    cipher: str = ""
    auth: str = ""
    wps: bool | None = None
    pmf: str = ""  # "" unknown | "required" | "optional" | "disabled"
    enterprise: bool = False
    signal_dbm: int | None = None
    # Windows ``netsh`` reports a driver-computed QUALITY PERCENTAGE, not a measured dBm.
    # It gets its OWN field rather than being pushed through :func:`parse_signal`'s
    # percentage branch, because converting it would invent a precision the capture never
    # had — an assessment must not print "-58 dBm" when the tool only ever said "84%".
    signal_pct: int | None = None
    vendor: str = ""
    beacons: int = 0
    first_seen: str = ""
    last_seen: str = ""
    raw_privacy: str = ""
    # The verbatim token that decided :attr:`wps` / :attr:`pmf`, kept SEPARATE from
    # ``raw_privacy``. When one BSS is seen in two exports the record is merged, and the
    # format that could observe WPS/PMF is usually NOT the one that supplied ``raw_privacy``
    # — quoting the wrong file's blob as the evidence for a WPS finding would break the
    # promise that every finding cites the bytes it was actually derived from.
    capability_evidence: str = ""
    # The provenance OF the WPS / PMF value above: which export observed it, directly or by
    # inference, and the exact bytes. ``wps``/``pmf`` are kept in lockstep with these by
    # :meth:`apply_capability_fact` and are never written by any other path, so
    # "value present" and "we can say where it came from" are the same statement.
    wps_fact: CapabilityFact | None = None
    pmf_fact: CapabilityFact | None = None
    source: str = ""
    # Provenance, so every finding can cite the exact line it was decoded from rather than
    # asserting a fact with no traceable origin (the no-fabrication rule made mechanical).
    source_path: str = ""
    source_row: int = 0  # 1-indexed line/record number inside the export
    raw_line: str = ""  # the verbatim export line this record came from

    def __post_init__(self) -> None:
        """Reconcile the bare tri-states with their facts, in both directions.

        Every parser in this package supplies facts. A record built by hand (a test, or a
        caller written before facts existed) may set ``wps``/``pmf`` alone; rather than
        silently trusting a value with no traceable origin, we attach an UNATTRIBUTED fact
        naming the record's own source, which then goes through exactly the same
        observability check as everything else — so a hand-built airodump record claiming
        PMF loses the claim instead of smuggling it into a deliverable."""
        for name in ("wps", "pmf"):
            fact = getattr(self, f"{name}_fact")
            value = getattr(self, name)
            if fact is None and (value is not None if name == "wps" else bool(value)):
                fact = CapabilityFact(
                    fact=name, value=value, basis="unattributed", observed_by=self.source,
                    evidence=self.capability_evidence or self.raw_privacy,
                    source_path=self.source_path, source_row=self.source_row,
                    raw_line=self.raw_line)
            setattr(self, f"{name}_fact", None)
            setattr(self, name, None if name == "wps" else "")
            self.apply_capability_fact(fact)

    def apply_capability_fact(self, fact: CapabilityFact | None) -> bool:
        """Attach ``fact`` and mirror its value onto the flat ``wps``/``pmf`` field.

        Returns whether it was attached. A fact whose observing format cannot see this
        capability (:data:`CAPABILITY_SUPPORT`) is DROPPED and the field stays undetermined
        — the single choke point that keeps a structurally impossible observation out of
        both the record and every finding derived from it."""
        if fact is None or fact.fact not in ("wps", "pmf"):
            return False
        if not format_can_observe(fact.observed_by, fact.fact):
            return False
        if fact.fact == "wps":
            self.wps_fact = fact
            self.wps = fact.value if isinstance(fact.value, bool) else None
        else:
            self.pmf_fact = fact
            self.pmf = str(fact.value or "")
        self.capability_evidence = self._capability_evidence()
        return True

    def merge_capability_fact(self, fact: CapabilityFact | None) -> bool:
        """Attach ``fact`` only if it wins :func:`choose_capability_fact` against the one
        already held. Used by both the cross-file merge and the file-level inference, so an
        inference can never displace a direct observation regardless of arrival order."""
        if fact is None:
            return False
        current = self.wps_fact if fact.fact == "wps" else self.pmf_fact if fact.fact == "pmf" else None
        winner = choose_capability_fact(current, fact)
        if winner is current:
            return False
        return self.apply_capability_fact(winner)

    def _capability_evidence(self) -> str:
        """The token shown as the record's capability evidence: the strongest fact's own
        bytes. Derived rather than stored first-writer-wins, which used to let a format that
        observed NEITHER capability claim the slot and get quoted by both findings."""
        best = max((f for f in (self.wps_fact, self.pmf_fact) if f and f.evidence),
                   key=lambda f: (_BASIS_RANK.get(f.basis, 0), f.fact == "wps"), default=None)
        return best.evidence[:400] if best else ""

    def label(self) -> str:
        """Human identity for a report line: the SSID when there is one, else the BSSID."""
        return self.ssid or (f"<hidden {self.bssid}>" if self.bssid else "<unknown>")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid, "ssid": self.ssid, "hidden": self.hidden,
            "channel": self.channel, "band": self.band, "encryption": self.encryption,
            "cipher": self.cipher, "auth": self.auth, "wps": self.wps, "pmf": self.pmf,
            "enterprise": self.enterprise, "signal_dbm": self.signal_dbm,
            "signal_pct": self.signal_pct,
            "vendor": self.vendor, "beacons": self.beacons,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "raw_privacy": self.raw_privacy, "capability_evidence": self.capability_evidence,
            # Serialized so a JSON consumer can answer "which export said so, and how?" for
            # every WPS/PMF value without re-reading the exports.
            "wps_fact": self.wps_fact.to_dict() if self.wps_fact else None,
            "pmf_fact": self.pmf_fact.to_dict() if self.pmf_fact else None,
            "source": self.source,
            "source_path": self.source_path, "source_row": self.source_row,
            "raw_line": self.raw_line,
        }


@dataclass
class Station:
    """One client observed in a survey, with its probe list (the Preferred Network
    List leak — the single most useful client-side artifact in a survey export)."""

    mac: str
    bssid: str = ""  # associated AP, "" when unassociated
    probes: list[str] = field(default_factory=list)
    signal_dbm: int | None = None
    packets: int = 0
    vendor: str = ""
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    source_path: str = ""
    source_row: int = 0
    raw_line: str = ""

    @property
    def randomized(self) -> bool:
        return is_locally_administered(self.mac)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac, "bssid": self.bssid, "probes": list(self.probes),
            "signal_dbm": self.signal_dbm, "packets": self.packets, "vendor": self.vendor,
            "randomized": self.randomized, "first_seen": self.first_seen,
            "last_seen": self.last_seen, "source": self.source,
            "source_path": self.source_path, "source_row": self.source_row,
            "raw_line": self.raw_line,
        }


@dataclass
class Survey:
    """A parsed survey: every AP and station across every supplied export file.

    Merging is by identity (BSSID / station MAC) so the same network seen in an
    airodump CSV *and* a WiGLE CSV becomes one record whose fields are filled from
    whichever source knew them — :meth:`add_ap` only ever fills a blank field or
    upgrades a value the merge rules consider strictly more informative."""

    aps: dict[str, AccessPoint] = field(default_factory=dict)
    stations: dict[str, Station] = field(default_factory=dict)
    sources: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_ap(self, ap: AccessPoint) -> None:
        bssid = normalize_mac(ap.bssid)
        if not bssid:
            return
        ap.bssid = bssid
        if not ap.band:
            ap.band = band_for_channel(ap.channel)
        existing = self.aps.get(bssid)
        if existing is None:
            self.aps[bssid] = ap
            return
        # Merge: prefer a real SSID over a blank/hidden one, a KNOWN encryption over
        # "unknown", and the strongest signal seen.
        if ap.ssid and not existing.ssid:
            existing.ssid, existing.hidden = ap.ssid, False
        if existing.encryption == "unknown" and ap.encryption != "unknown":
            existing.encryption = ap.encryption
            existing.raw_privacy = existing.raw_privacy or ap.raw_privacy
        # NOTE: "wps", "pmf" and "capability_evidence" are deliberately NOT in this
        # fill-if-blank list. Filling them by arrival order is what let an inferred absence
        # written by the first file outrank a verbatim [MFPR] in the second, and let a
        # format that can observe neither claim the evidence slot. They go through
        # merge_capability_fact below, which is order-independent by construction.
        for attr in ("cipher", "auth", "vendor", "band", "first_seen", "last_seen",
                     "raw_privacy", "source_path", "raw_line"):
            if not getattr(existing, attr) and getattr(ap, attr):
                setattr(existing, attr, getattr(ap, attr))
        if existing.channel is None and ap.channel is not None:
            existing.channel = ap.channel
            existing.band = existing.band or band_for_channel(ap.channel)
        for name in ("wps", "pmf"):
            incoming = getattr(ap, f"{name}_fact")
            held = getattr(existing, f"{name}_fact")
            # Capped: a city-scale merge of two 200k-row walks could otherwise append one
            # warning per BSS and bury every other parse note in the deliverable.
            if facts_conflict(held, incoming) and len(self.warnings) < 500:
                winner = choose_capability_fact(held, incoming)
                loser = incoming if winner is held else held
                self.warnings.append(
                    f"{bssid}: exports disagree about {name.upper()} - {winner.observed_by} "
                    f"({winner.source_path or '<text>'} row {winner.source_row}) observed "
                    f"{winner.value!r} and {loser.observed_by} ({loser.source_path or '<text>'} "
                    f"row {loser.source_row}) observed {loser.value!r}; the finding cites the "
                    f"former. Both readings are real - the state may have changed between captures.")
            existing.merge_capability_fact(incoming)
        if not existing.source_row and ap.source_row:
            existing.source_row = ap.source_row
        existing.enterprise = existing.enterprise or ap.enterprise
        existing.beacons = max(existing.beacons, ap.beacons)
        if ap.signal_dbm is not None and (existing.signal_dbm is None or ap.signal_dbm > existing.signal_dbm):
            existing.signal_dbm = ap.signal_dbm
        if ap.signal_pct is not None and (existing.signal_pct is None or ap.signal_pct > existing.signal_pct):
            existing.signal_pct = ap.signal_pct
        if ap.source and ap.source not in existing.source:
            existing.source = f"{existing.source}, {ap.source}" if existing.source else ap.source

    def add_station(self, station: Station) -> None:
        mac = normalize_mac(station.mac)
        if not mac:
            return
        station.mac = mac
        station.bssid = normalize_mac(station.bssid)
        existing = self.stations.get(mac)
        if existing is None:
            self.stations[mac] = station
            return
        for probe in station.probes:
            if probe and probe not in existing.probes:
                existing.probes.append(probe)
        if not existing.bssid and station.bssid:
            existing.bssid = station.bssid
        for attr in ("vendor", "first_seen", "last_seen", "source_path", "raw_line"):
            if not getattr(existing, attr) and getattr(station, attr):
                setattr(existing, attr, getattr(station, attr))
        if not existing.source_row and station.source_row:
            existing.source_row = station.source_row
        existing.packets = max(existing.packets, station.packets)
        if station.signal_dbm is not None and (existing.signal_dbm is None or station.signal_dbm > existing.signal_dbm):
            existing.signal_dbm = station.signal_dbm
        if station.source and station.source not in existing.source:
            existing.source = f"{existing.source}, {station.source}" if existing.source else station.source

    def ap_list(self) -> list[AccessPoint]:
        """APs in a stable, deterministic order: weakest encryption first, then BSSID."""
        return sorted(self.aps.values(), key=lambda a: (encryption_rank(a.encryption), a.bssid))

    def station_list(self) -> list[Station]:
        return sorted(self.stations.values(), key=lambda s: s.mac)

    def to_dict(self) -> dict[str, Any]:
        return {
            "aps": [a.to_dict() for a in self.ap_list()],
            "stations": [s.to_dict() for s in self.station_list()],
            "sources": list(self.sources),
            "warnings": list(self.warnings),
        }
