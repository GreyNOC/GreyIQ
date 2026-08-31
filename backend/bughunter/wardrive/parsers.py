"""Wardrive — parsers for the survey EXPORT formats an operator already captured.

Nothing here touches a radio. Every function in this module takes TEXT that a survey tool
already wrote to disk under the operator's own authorization and turns it into the shared
:class:`~bughunter.wardrive.model.Survey`. No socket, no subprocess, no monitor-mode
toggle, no frame injection — the package's entire input surface is files.

Every parser is TOTAL: a truncated capture (the normal case — a survey ends when the
operator stops walking, mid-line) yields the rows it could decode plus a WARNING naming
what it could not, and never raises. A parser that raised would throw away the 4 000 good
rows in front of the corrupt one.

WHAT EACH FORMAT CAN AND CANNOT TELL US — this table is the whole point of the module,
because a finding is only as honest as the format it came from:

======================  ========  ========  ==============  =====================
format                  WPS       PMF       signal          parser confidence
======================  ========  ========  ==============  =====================
airodump-ng CSV         NEVER     NEVER     dBm             HIGH - stable since 1.x
WiGLE CSV               yes       yes       dBm (RSSI)      HIGH - header-bound
Kismet .netxml          usually   NEVER     dBm             HIGH - stable schema
Kismet CSV export       maybe     NEVER     dBm             MEDIUM - schema varies
netsh wlan (Windows)    NEVER     NEVER     percentage      MEDIUM - localized labels
======================  ========  ========  ==============  =====================

"NEVER" is load-bearing. airodump-ng writes no WPS column (that is ``wash``) and no RSN
capability bits, so an airodump-only survey MUST yield ``wps=None`` / ``pmf=""`` on every
BSS and therefore zero WPS findings and zero PMF findings. Reporting "PMF missing" from a
capture that structurally cannot report PMF would be a confidently wrong line in an
assessment deliverable — the exact failure the GreyNOC no-fabrication rule exists to
prevent. Undetermined is a first-class answer here, not a gap to be filled in.

Where a format CAN report a fact, absence still is not automatically a negative. WiGLE and
Kismet both emit their WPS/PMF markers only on the networks that have them, so a bare
per-row absence is ambiguous between "off" and "this exporter build never emits it".
:func:`_apply_capability_evidence` resolves that with FILE-LEVEL evidence, which is
reproducible from the export alone: if the marker appears anywhere in the file the exporter
demonstrably emits it, so its absence on another row is a real observation (``False`` /
``"disabled"``); if it appears nowhere the whole file stays undetermined and says so.

That inference has TWO preconditions, and both are enforced per row rather than per file:

  * the row must itself carry a capability RECORD the marker could have appeared in. A
    WiGLE row whose ``AuthMode`` cell is empty — routine in a truncated or torn export —
    recorded nothing at all, so its absence of ``[MFPC]`` is not an observation and the BSS
    stays UNDETERMINED. Turning a missing field into "PMF disabled" is fabrication.
  * the inference is attached as an INFERRED :class:`~bughunter.wardrive.model.CapabilityFact`
    carrying THIS row's path/line/bytes, so it can never outrank a direct observation from
    another export and a finding built on it quotes the row it was actually derived from.

Confidence per format is stated above and repeated in each parser's docstring. Kismet's CSV
export in particular has changed column names across releases, so it is mapped through an
ALIAS table rather than a pretended-known schema, and every column it could not map is
recorded as a warning instead of silently dropped.

Pure stdlib (``csv``, ``re``, ``xml.etree.ElementTree``, ``pathlib``), frozen-safe.
"""

from __future__ import annotations

import csv
import io
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bughunter.wardrive.model import (
    AccessPoint,
    CapabilityFact,
    Station,
    Survey,
    band_for_channel,
    normalize_mac,
    normalize_privacy,
    parse_channel,
    parse_signal,
)

#: Every format id this module can produce. Also the ``source_format`` stamped on findings.
FORMATS: tuple[str, ...] = ("airodump-csv", "wigle-csv", "kismet-netxml", "kismet-csv", "netsh-text")

#: Extensions walked when a DIRECTORY is handed to :func:`load_survey`.
SURVEY_EXTENSIONS: tuple[str, ...] = (".csv", ".netxml", ".xml", ".txt", ".log")

# Caps. A WiGLE export can be hundreds of thousands of rows and a survey is an interactive
# command; these bound worst-case work without truncating any realistic capture silently
# (truncation always emits a warning).
_MAX_ROWS = 200_000
_MAX_BYTES = 64_000_000
_MAX_PROBES = 32
_RAW_CLIP = 400  # verbatim evidence line length carried into findings

_HIDDEN_SSID_JUNK = re.compile(r"^[\x00\s]*$")

#: How deep the directory walk descends, and how a junction/symlink cycle is broken. Both
#: are Windows realities, not hypotheticals: ``Path.rglob`` follows a directory JUNCTION
#: (only true symlinks are skipped), so ``capture\sub\back -> capture`` descends until the
#: path passes MAX_PATH and raises ``FileNotFoundError`` out of the whole survey.
_MAX_WALK_DEPTH = 24
#: And how many directories it visits at all. A survey is an interactive command; a walk of
#: an entire archive volume is bounded and REPORTED rather than left to run for minutes.
_MAX_WALK_DIRS = 20_000

_BOM = "﻿"


# --- shared helpers ---------------------------------------------------------------


def _strip_bom(value: Any) -> str:
    """Text with a leading UTF-8 BOM removed.

    A BOM is what Windows tools actually emit: Excel, Notepad, ``Out-File -Encoding
    utf8BOM`` and a PowerShell concatenation of split captures all prepend U+FEFF. Python's
    ``str.strip()`` does NOT treat it as whitespace, so an un-stripped BOM makes airodump's
    ``BSSID`` section header read as ``"﻿bssid"``: the header is never recognized, every
    AP row is skipped as headerless, and a CRITICAL WEP finding silently disappears from the
    assessment while the station section still parses. Stripping happens in the parsers as
    well as in :func:`_read_export`, because text also arrives through
    :func:`parse_survey_text` from callers that did their own reading."""
    body = str(value or "")
    return body[1:] if body.startswith(_BOM) else body


@dataclass
class _RowCapability:
    """What ONE row of ONE export said about WPS/PMF, before any cross-file merging.

    The file-level inference in :func:`_apply_capability_evidence` reads these rather than
    the merged :class:`AccessPoint` records. That distinction is the whole fix for two
    fabrications: the merged record may have been created by a format that cannot observe
    the capability at all, and a row whose capability cell was EMPTY recorded nothing, so
    neither may be turned into a negative verdict."""

    bssid: str
    source_path: str
    source_row: int
    raw_line: str
    #: The verbatim capability record on this row, per fact. "" means the exporter wrote
    #: nothing here, which is UNDETERMINED and never "off".
    wps_token: str = ""
    pmf_token: str = ""
    #: Whether this row already carries a DIRECT observation (so no inference applies).
    wps_direct: bool = False
    pmf_direct: bool = False


def _clean_ssid(value: Any) -> tuple[str, bool]:
    """``(ssid, looks_hidden)``. airodump writes a run of NUL bytes for a cloaked ESSID and
    Kismet writes an empty ``<essid>``; both mean "the beacon carried no SSID", which is a
    DIFFERENT fact from an SSID that is genuinely the empty string. NULs are stripped so
    they never reach a report, and the emptiness is returned separately."""
    raw = str(value or "")
    if _HIDDEN_SSID_JUNK.match(raw):
        return "", True
    return raw.replace("\x00", "").strip(), False


def _clip(value: Any) -> str:
    return str(value or "").strip()[:_RAW_CLIP]


def _int_or_zero(value: Any) -> int:
    match = re.search(r"\d+", str(value or ""))
    try:
        return int(match.group(0)) if match else 0
    except ValueError:
        return 0


def _track(survey: Survey, ap: AccessPoint, aps: dict[str, AccessPoint], *,
           capability: _RowCapability | None = None,
           rows: list[_RowCapability] | None = None) -> None:
    """Add ``ap`` to the survey and remember the CANONICAL record for it.

    :meth:`Survey.add_ap` merges by BSSID, so when the same BSS appears in two exports the
    object that survives is the FIRST one and the new record is folded into it and dropped.
    File-level capability resolution has to reach the survivor — resolving WPS on a
    discarded duplicate would silently lose the one fact the second format contributed —
    but it must carry THIS row's provenance with it, which is what ``capability`` records.

    ``aps`` is keyed by BSSID rather than being a list: a WiGLE city walk runs to hundreds of
    thousands of rows, and de-duplicating against a list once per row is quadratic — measured
    at 56 s for 60 000 rows before this was a dict, and 1.4 s after."""
    survey.add_ap(ap)
    canonical = survey.aps.get(ap.bssid)
    if canonical is None:
        return
    if capability is not None and rows is not None:
        rows.append(capability)
    aps.setdefault(canonical.bssid, canonical)


def _apply_capability_evidence(survey: Survey, aps: dict[str, AccessPoint],
                               rows: list[_RowCapability], fmt: str, *,
                               wps_seen: bool, pmf_seen: bool) -> None:
    """Resolve per-row ABSENCE of a WPS/PMF marker into either a negative observation or a
    documented undetermined, using evidence from the file as a whole.

    A tool that emits ``[WPS]`` only on WPS networks makes a bare absence ambiguous: the AP
    might not do WPS, or this exporter build might never write the token. The disambiguator
    is reproducible from the export itself — if the marker appears on ANY row, the exporter
    demonstrably emits it, so absence elsewhere is a genuine observation. If it appears on
    NO row we keep ``None``/``""`` and warn, because concluding "WPS off everywhere" from a
    file that never mentions WPS is exactly the fabrication this package refuses to commit.

    Two guards make that sound rather than merely plausible, and both were fabrications
    before they existed:

      * the inference is applied per ROW, only where that row carried a capability record
        (``*_token``). A row whose capability cell was empty observed nothing; it stays
        undetermined instead of being read as a negative.
      * it is attached as an INFERRED fact carrying that row's own path/line/bytes, via
        ``merge_capability_fact``, so a DIRECT observation of the same BSS in any other
        export — parsed before or after — always wins.
    """
    if not aps:
        return
    for fact_name, seen, marker in (("wps", wps_seen, "WPS marker"),
                                    ("pmf", pmf_seen, "802.11w/MFP marker")):
        if not seen:
            survey.warnings.append(
                f"{fmt}: no {marker} appears anywhere in this export, so {fact_name.upper()} is "
                f"UNDETERMINED for all {len(aps)} BSS - not reported as "
                f"{'disabled' if fact_name == 'wps' else 'absent'}.")
            continue
        value: Any = False if fact_name == "wps" else "disabled"
        silent = 0
        for row in rows:
            token = row.wps_token if fact_name == "wps" else row.pmf_token
            if getattr(row, f"{fact_name}_direct"):
                continue
            if not token:
                silent += 1  # the exporter wrote no capability record on this row
                continue
            ap = survey.aps.get(row.bssid)
            if ap is None:
                continue
            ap.merge_capability_fact(CapabilityFact(
                fact=fact_name, value=value, basis="inferred", observed_by=fmt,
                evidence=token[:_RAW_CLIP], source_path=row.source_path,
                source_row=row.source_row, raw_line=row.raw_line))
        if silent:
            survey.warnings.append(
                f"{fmt}: {silent} row(s) carry no capability field at all (empty or truncated), so "
                f"{fact_name.upper()} stays UNDETERMINED for them - a missing field is not a negative "
                f"observation.")


def _no_capability_warning(survey: Survey, fmt: str, tool: str, count: int) -> None:
    """The airodump/netsh case: the format carries NO WPS and NO RSN capability bits at all,
    so both facts stay undetermined for structural reasons rather than evidentiary ones."""
    if not count:
        return
    survey.warnings.append(
        f"{fmt}: {tool} exports carry neither WPS state nor RSN capability bits, so WPS and PMF "
        f"(802.11w) are UNDETERMINED for all {count} BSS. Re-capture with Kismet or a WiGLE "
        f"export to determine them.")


# --- format detection -------------------------------------------------------------


def detect_format(text: str, *, filename: str = "") -> str:
    """Best-effort format id for ``text``, or ``""`` when nothing matches.

    Content first, filename only as a tiebreaker: operators rename exports constantly, and
    a ``.csv`` can be any of three different formats here.

    The BOM is stripped before anything is matched. Without that an airodump export saved
    by a Windows tool misses the ``^\\s*BSSID\\s*,`` anchor (``\\s`` does not match U+FEFF)
    while ``_kismet_csv_header`` — which normalizes the BOM away — still claims the file, so
    every finding from it would be stamped with the wrong ``source_format``."""
    head = _strip_bom(text)[:8000]
    stripped = head.lstrip()
    if stripped.startswith("WigleWifi") or re.search(r"^WigleWifi-[\d.]+,", head, re.MULTILINE):
        return "wigle-csv"
    if "<detection-run" in head or "<wireless-network" in head:
        return "kismet-netxml"
    if re.search(r"^\s*BSSID\s*,\s*First time seen", head, re.MULTILINE):
        return "airodump-csv"
    if re.search(r"^\s*Station MAC\s*,", head, re.MULTILINE):
        return "airodump-csv"
    if re.search(r"^\s*(SSID|BSSID)\s+\d+\s*:", head, re.MULTILINE):
        return "netsh-text"
    first_line = head.splitlines()[0].lower() if head.splitlines() else ""
    columns = [_norm_col(col) for col in first_line.split(",")] if "," in first_line else []
    # A WiGLE export whose banner line was stripped still has WiGLE's own header. Recognize it
    # explicitly: `authmode` belongs to no other format, and the Kismet alias table would
    # otherwise claim the file and then silently read no encryption from it.
    if "authmode" in columns and "mac" in columns:
        return "wigle-csv"
    if columns and _kismet_csv_header(first_line.split(",")):
        return "kismet-csv"
    suffix = Path(str(filename or "")).suffix.lower()
    if suffix in (".netxml", ".xml") and "<" in head:
        return "kismet-netxml"
    return ""


# --- airodump-ng CSV --------------------------------------------------------------

# airodump's section-1 header. Bound by NAME (the column set has grown over releases) with
# ONE structural exception documented in parse_airodump_csv: the ESSID column.
_AIRODUMP_AP_KEYS = {
    "bssid": "bssid", "first time seen": "first_seen", "last time seen": "last_seen",
    "channel": "channel", "privacy": "privacy", "cipher": "cipher",
    "authentication": "auth", "power": "power", "# beacons": "beacons",
    "id-length": "id_length", "essid": "essid", "key": "key",
}
_AIRODUMP_ST_KEYS = {
    "station mac": "mac", "first time seen": "first_seen", "last time seen": "last_seen",
    "power": "power", "# packets": "packets", "bssid": "bssid", "probed essids": "probes",
}


def parse_airodump_csv(text: str, *, source_path: str = "", survey: Survey | None = None,
                       max_rows: int = _MAX_ROWS) -> Survey:
    """airodump-ng ``-w … --output-format csv``. Parser confidence HIGH.

    Four real correctness traps, each handled explicitly:

    * TWO sections separated by a blank line — access points, then stations. The station
      section is found by its ``Station MAC`` header, not by counting blank lines, because a
      capture interrupted mid-write can contain stray blank lines.
    * Every cell is space-padded after the comma, so each is stripped.
    * ``Power = -1`` is the "never received a frame from this BSS" SENTINEL, not -1 dBm.
      :func:`model.parse_signal` maps it to ``None``; reporting -1 dBm would invent a
      near-perfect signal from a record that means the opposite.
    * airodump does NOT quote, so an SSID containing a comma spills across columns. The
      ESSID is therefore bound by POSITION FROM THE END (``Key`` is always last) and the
      spilled cells are re-joined RAW — joining stripped cells would eat the space in
      ``"My, Net"``. Same for a station's comma-separated ``Probed ESSIDs``.

    Hidden networks come from ``ID-length == 0``, which is the beacon's actual SSID-element
    length, NOT from a blank ESSID — a blank ESSID also happens when airodump simply has not
    heard a beacon yet, and calling that "hidden" would be a guess.

    WPS and PMF are structurally absent from this format; both stay undetermined.
    """
    survey = survey or Survey()
    lines = _strip_bom(text).splitlines()
    ap_header: list[str] | None = None
    st_header: list[str] | None = None
    aps: dict[str, AccessPoint] = {}
    rows = 0
    for index, line in enumerate(lines, start=1):
        if rows >= max_rows:
            survey.warnings.append(f"airodump-csv: stopped at the {max_rows}-row cap; the export is longer.")
            break
        if not line.strip():
            continue
        cells = line.split(",")
        first = cells[0].strip().lower()
        if first == "bssid" and len(cells) > 3:
            ap_header, st_header = [c.strip().lower() for c in cells], None
            continue
        if first == "station mac":
            st_header, ap_header = [c.strip().lower() for c in cells], None
            continue
        if ap_header is not None:
            ap = _airodump_ap_row(cells, ap_header, index, line, source_path)
            if ap is not None:
                _track(survey, ap, aps)
                rows += 1
        elif st_header is not None:
            station = _airodump_station_row(cells, st_header, index, line, source_path)
            if station is not None:
                survey.add_station(station)
                rows += 1
        elif normalize_mac(first):
            survey.warnings.append(
                f"airodump-csv: row {index} carries a MAC but no section header preceded it "
                f"(truncated export?); row skipped.")
    if ap_header is None and st_header is None and not aps:
        survey.warnings.append("airodump-csv: no 'BSSID,' or 'Station MAC,' header found; nothing parsed.")
    _no_capability_warning(survey, "airodump-csv", "airodump-ng", len(aps))
    survey.sources.append({"path": source_path, "format": "airodump-csv",
                           "aps": len(aps), "rows": rows,
                           "reports_wps": False, "reports_pmf": False})
    return survey


def _airodump_ap_row(cells: list[str], header: list[str], index: int, line: str,
                     source_path: str) -> AccessPoint | None:
    idx = {name: pos for pos, name in enumerate(header)}
    def cell(key: str) -> str:
        pos = idx.get(key)
        return cells[pos].strip() if pos is not None and pos < len(cells) else ""

    bssid = normalize_mac(cell("bssid"))
    if not bssid:
        return None
    # ESSID by position-from-the-end: header ... ID-length, ESSID, Key. Anything between the
    # ESSID column and the trailing Key column belongs to the ESSID (unquoted comma spill).
    essid_pos, tail = idx.get("essid"), len(header) - 1 - idx.get("essid", len(header) - 1)
    if essid_pos is None:
        essid_raw = ""
    elif len(cells) > essid_pos:
        end = max(essid_pos + 1, len(cells) - tail)
        essid_raw = ",".join(cells[essid_pos:end])
    else:
        essid_raw = ""
    ssid, blank = _clean_ssid(essid_raw)
    id_length = cell("id-length")
    # ID-length is authoritative for cloaking; a blank ESSID with no ID-length column is
    # only "hidden" when there is nothing else to go on, and we say so via the raw line.
    hidden = (id_length == "0") if id_length else blank
    privacy = normalize_privacy(cell("privacy"), cell("cipher"), cell("authentication"))
    channel = parse_channel(cell("channel"))
    return AccessPoint(
        bssid=bssid, ssid="" if hidden else ssid, hidden=hidden,
        channel=channel, band=band_for_channel(channel),
        encryption=privacy["encryption"], cipher=privacy["cipher"], auth=privacy["auth"],
        wps=None, pmf="", enterprise=bool(privacy["enterprise"]),
        signal_dbm=parse_signal(cell("power")),
        beacons=_int_or_zero(cell("# beacons")),
        first_seen=cell("first time seen"), last_seen=cell("last time seen"),
        raw_privacy=" ".join(p for p in (cell("privacy"), cell("cipher"), cell("authentication")) if p),
        source="airodump-csv", source_path=source_path, source_row=index, raw_line=_clip(line),
    )


def _airodump_station_row(cells: list[str], header: list[str], index: int, line: str,
                          source_path: str) -> Station | None:
    idx = {name: pos for pos, name in enumerate(header)}
    def cell(key: str) -> str:
        pos = idx.get(key)
        return cells[pos].strip() if pos is not None and pos < len(cells) else ""

    mac = normalize_mac(cell("station mac"))
    if not mac:
        return None
    probes_pos = idx.get("probed essids")
    probe_blob = ",".join(cells[probes_pos:]) if probes_pos is not None and len(cells) > probes_pos else ""
    probes: list[str] = []
    for candidate in probe_blob.split(","):
        name = candidate.replace("\x00", "").strip()
        if name and name not in probes:
            probes.append(name)
        if len(probes) >= _MAX_PROBES:
            break
    return Station(
        mac=mac, bssid=normalize_mac(cell("bssid")), probes=probes,
        signal_dbm=parse_signal(cell("power")), packets=_int_or_zero(cell("# packets")),
        first_seen=cell("first time seen"), last_seen=cell("last time seen"),
        source="airodump-csv", source_path=source_path, source_row=index, raw_line=_clip(line),
    )


# --- WiGLE CSV --------------------------------------------------------------------

_WIGLE_MFPR = re.compile(r"\[MFPR\]", re.IGNORECASE)
_WIGLE_MFPC = re.compile(r"\[MFPC\]", re.IGNORECASE)
_WIGLE_WPS = re.compile(r"\[WPS", re.IGNORECASE)


def parse_wigle_authmode(token: str) -> dict[str, Any]:
    """Decode a WiGLE ``AuthMode`` capability string, e.g. ``[WPA2-PSK-CCMP][WPS][ESS]`` or
    ``[RSN-SAE-CCMP][MFPR][MFPC][ESS]``. Parser confidence HIGH.

    It is the richest privacy field any of these formats carries and the ONLY one that can
    express PMF: ``MFPR`` = management-frame protection REQUIRED, ``MFPC`` = CAPABLE.
    Per-row absence is left as ``""`` here — it is only resolved against file-level evidence
    by :func:`_apply_capability_evidence`, because a single row cannot distinguish "this AP
    does not do PMF" from "this exporter build does not write MFP tokens"."""
    raw = str(token or "")
    privacy = normalize_privacy(raw)
    # WiGLE/Android name the RSN information element itself "RSN", which the shared
    # normalizer reads as a WPA2 marker - correct for every other format, but here it turns
    # a PURE WPA3 network ("[RSN-SAE-CCMP]") into a false "transition mode" verdict and thus
    # into a fabricated downgrade finding. Android's capability string is structured, so the
    # AKM list resolves it exactly: transition mode is PSK *and* SAE, nothing less.
    akm = raw.upper()
    has_sae = "SAE" in akm
    has_psk = "PSK" in akm
    if has_sae:
        privacy["encryption"] = "wpa2-wpa3" if has_psk else "wpa3"
    if _WIGLE_MFPR.search(raw):
        pmf = "required"
    elif _WIGLE_MFPC.search(raw):
        pmf = "optional"
    else:
        pmf = ""
    privacy["pmf"] = pmf
    privacy["wps"] = True if _WIGLE_WPS.search(raw) else None
    return privacy


def parse_wigle_csv(text: str, *, source_path: str = "", survey: Survey | None = None,
                    max_rows: int = _MAX_ROWS) -> Survey:
    """A WiGLE WiFi Android export. Parser confidence HIGH.

    Line 1 is a PRE-header (``WigleWifi-1.4,appRelease=…``) and line 2 is the real header;
    newer app releases append columns, so every field is bound BY HEADER NAME and never by
    index. Non-``WIFI`` rows (``BT``, ``BLE``, ``GSM``, cell towers) are filtered out — they
    are real observations but not 802.11 and would corrupt the AP statistics.

    Properly quoted, so the ``csv`` module handles an SSID containing a comma.

    GPS columns are read but deliberately NOT surfaced in findings: a report that pins a
    resident's home network to a lat/lon is a privacy harm the assessment does not need.
    """
    survey = survey or Survey()
    body = _strip_bom(text)
    lines = body.splitlines()
    if not lines:
        survey.warnings.append("wigle-csv: empty export.")
        survey.sources.append({"path": source_path, "format": "wigle-csv", "aps": 0, "rows": 0,
                               "reports_wps": True, "reports_pmf": True})
        return survey
    pre_header = lines[0] if lines[0].lstrip().startswith("WigleWifi") else ""
    if pre_header:
        survey.warnings.append(f"wigle-csv: exporter banner {_clip(pre_header)!r}")
        lines = lines[1:]
    reader = csv.reader(io.StringIO("\n".join(lines)))
    try:
        header = [str(c).strip().lower() for c in next(reader)]
    except StopIteration:
        survey.warnings.append("wigle-csv: pre-header present but no column header followed (truncated export).")
        survey.sources.append({"path": source_path, "format": "wigle-csv", "aps": 0, "rows": 0,
                               "reports_wps": True, "reports_pmf": True})
        return survey
    idx = {name: pos for pos, name in enumerate(header)}
    if "mac" not in idx:
        survey.warnings.append(f"wigle-csv: header has no 'MAC' column ({', '.join(header[:12])}); nothing parsed.")
        survey.sources.append({"path": source_path, "format": "wigle-csv", "aps": 0, "rows": 0,
                               "reports_wps": True, "reports_pmf": True})
        return survey
    aps: dict[str, AccessPoint] = {}
    capabilities: list[_RowCapability] = []
    rows = 0
    wps_seen = pmf_seen = False
    # +2: the pre-header line and the header line, so source_row is the real 1-indexed file line.
    offset = 2 if pre_header else 1
    row_number = offset
    while True:
        row_number += 1
        try:
            cells = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:  # a torn final line in an interrupted export
            survey.warnings.append(f"wigle-csv: row {row_number} unreadable ({exc}); stopped there.")
            break
        if rows >= max_rows:
            survey.warnings.append(f"wigle-csv: stopped at the {max_rows}-row cap; the export is longer.")
            break
        def cell(key: str) -> str:
            pos = idx.get(key)
            return str(cells[pos]).strip() if pos is not None and pos < len(cells) else ""

        if (cell("type") or "WIFI").upper() != "WIFI":
            continue
        bssid = normalize_mac(cell("mac"))
        if not bssid:
            continue
        auth_raw = cell("authmode")
        privacy = parse_wigle_authmode(auth_raw)
        wps_seen = wps_seen or privacy["wps"] is True
        pmf_seen = pmf_seen or bool(privacy["pmf"])
        ssid, blank = _clean_ssid(cell("ssid"))
        channel = parse_channel(cell("channel")) or parse_channel(cell("frequency"))
        raw_line = _clip(",".join(str(c) for c in cells))
        # Facts, not bare values: the AuthMode cell IS the observation, so it travels with
        # the verdict. An EMPTY cell yields no fact at all - a torn or short row recorded
        # nothing, and "nothing recorded" is undetermined, never "capability absent".
        wps_fact = (CapabilityFact(fact="wps", value=True, basis="direct", observed_by="wigle-csv",
                                   evidence=_clip(auth_raw), source_path=source_path,
                                   source_row=row_number, raw_line=raw_line)
                    if privacy["wps"] is True else None)
        pmf_fact = (CapabilityFact(fact="pmf", value=privacy["pmf"], basis="direct",
                                   observed_by="wigle-csv", evidence=_clip(auth_raw),
                                   source_path=source_path, source_row=row_number, raw_line=raw_line)
                    if privacy["pmf"] else None)
        ap = AccessPoint(
            bssid=bssid, ssid=ssid, hidden=blank or not ssid,
            channel=channel, band=band_for_channel(channel),
            encryption=privacy["encryption"], cipher=privacy["cipher"], auth=privacy["auth"],
            wps_fact=wps_fact, pmf_fact=pmf_fact, enterprise=bool(privacy["enterprise"]),
            signal_dbm=parse_signal(cell("rssi")),
            first_seen=cell("firstseen"), last_seen=cell("lastseen") or cell("firstseen"),
            raw_privacy=_clip(auth_raw),
            source="wigle-csv", source_path=source_path, source_row=row_number,
            raw_line=raw_line,
        )
        _track(survey, ap, aps, rows=capabilities, capability=_RowCapability(
            bssid=ap.bssid, source_path=source_path, source_row=row_number, raw_line=raw_line,
            wps_token=_clip(auth_raw), pmf_token=_clip(auth_raw),
            wps_direct=wps_fact is not None, pmf_direct=pmf_fact is not None))
        rows += 1
    _apply_capability_evidence(survey, aps, capabilities, "wigle-csv",
                               wps_seen=wps_seen, pmf_seen=pmf_seen)
    survey.sources.append({"path": source_path, "format": "wigle-csv", "aps": len(aps), "rows": rows,
                           "reports_wps": wps_seen, "reports_pmf": pmf_seen})
    return survey


# --- Kismet .netxml ---------------------------------------------------------------


def parse_kismet_netxml(text: str, *, source_path: str = "", survey: Survey | None = None,
                        max_rows: int = _MAX_ROWS) -> Survey:
    """Kismet's legacy ``.netxml`` export. Parser confidence HIGH — the schema has been
    stable across Kismet releases far longer than the CSV export has.

    A survey export is UNTRUSTED input (it came off someone's SD card), so a ``DOCTYPE`` is
    REJECTED outright rather than parsed: stdlib's expat expands internal entities, which is
    the billion-laughs / entity-expansion surface. Blocking the declaration removes it
    entirely and costs nothing, because Kismet never writes one.

    ``<wps>`` is present on newer Kismet builds and is the only WPS source in this format.
    There are NO RSN capability bits in netxml, so PMF stays undetermined for every BSS.
    """
    survey = survey or Survey()
    body = _strip_bom(text)
    if re.search(r"<!DOCTYPE", body, re.IGNORECASE):
        survey.warnings.append(
            "kismet-netxml: export declares a DOCTYPE; refused (entity expansion is an untrusted-input "
            "risk and Kismet never writes one). Nothing parsed.")
        survey.sources.append({"path": source_path, "format": "kismet-netxml", "aps": 0, "rows": 0,
                               "reports_wps": False, "reports_pmf": False})
        return survey
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        # Truncated captures are the norm: recover the complete <wireless-network> blocks and
        # report the rest, instead of discarding a whole walk because the tool was Ctrl-C'd.
        recovered = _recover_netxml(body)
        if recovered is None:
            survey.warnings.append(f"kismet-netxml: unparseable XML ({exc}); nothing parsed.")
            survey.sources.append({"path": source_path, "format": "kismet-netxml", "aps": 0, "rows": 0,
                                   "reports_wps": False, "reports_pmf": False})
            return survey
        survey.warnings.append(
            f"kismet-netxml: XML truncated ({exc}); recovered the complete <wireless-network> blocks only.")
        root = recovered
    version = str(root.get("kismet-version") or "").strip()
    if version:
        survey.warnings.append(f"kismet-netxml: produced by Kismet {version}.")
    aps: dict[str, AccessPoint] = {}
    capabilities: list[_RowCapability] = []
    wps_seen = False
    rows = 0
    for order, network in enumerate(root.iter("wireless-network"), start=1):
        if rows >= max_rows:
            survey.warnings.append(f"kismet-netxml: stopped at the {max_rows}-row cap.")
            break
        ap, saw_wps = _netxml_network(network, order, source_path)
        if ap is None:
            continue
        wps_seen = wps_seen or saw_wps
        # The reassembled <SSID> block is the WPS capability record: <wps> would have sat
        # inside it, so its absence there is an observation once the file proves the
        # exporter writes the element. It is NOT a PMF record - netxml carries no RSN
        # capability bits at all, which is why no pmf_token is offered here. Passing this
        # line as generic "capability evidence" is what used to let a netxml fragment be
        # quoted as the proof of a PMF verdict decided by a WiGLE row in another file.
        _track(survey, ap, aps, rows=capabilities, capability=_RowCapability(
            bssid=ap.bssid, source_path=source_path, source_row=order, raw_line=ap.raw_line,
            wps_token=ap.raw_line, wps_direct=saw_wps))
        rows += 1
        for client_order, client in enumerate(network.iter("wireless-client"), start=1):
            station = _netxml_client(client, ap.bssid, order * 1000 + client_order, source_path)
            if station is not None:
                survey.add_station(station)
    if not aps:
        survey.warnings.append("kismet-netxml: no <wireless-network> elements decoded.")
    _apply_capability_evidence(survey, aps, capabilities, "kismet-netxml",
                               wps_seen=wps_seen, pmf_seen=False)
    survey.sources.append({"path": source_path, "format": "kismet-netxml", "aps": len(aps), "rows": rows,
                           "reports_wps": wps_seen, "reports_pmf": False})
    return survey


def _resolve_kismet_generation(privacy: dict[str, Any]) -> dict[str, Any]:
    """Kismet's legacy vocabulary has no WPA2 token — it writes ``WPA`` for BOTH generations
    and distinguishes them only by the CIPHER (``WPA+TKIP`` vs ``WPA+AES-CCM``).

    Taken literally, a perfectly ordinary WPA2-CCMP network therefore decodes as ``wpa`` and
    earns a HIGH "WPA1/TKIP in use" finding it does not deserve. CCMP is defined by RSN
    (802.11i), so a CCMP-bearing BSS is WPA2 or better — this is decoding the format's own
    shorthand, not guessing. A TKIP-only BSS stays ``wpa``, which is the genuine WPA1 case.
    """
    if privacy.get("encryption") == "wpa" and privacy.get("cipher") in ("ccmp", "gcmp"):
        privacy = dict(privacy)
        privacy["encryption"] = "wpa2"
    return privacy


def _recover_netxml(body: str) -> ET.Element | None:
    """Wrap the COMPLETE ``<wireless-network>…</wireless-network>`` blocks of a truncated
    document in a synthetic root. Returns None when nothing complete survives."""
    blocks = re.findall(r"<wireless-network\b.*?</wireless-network>", body, re.DOTALL)
    if not blocks:
        return None
    try:
        return ET.fromstring("<detection-run>" + "".join(blocks) + "</detection-run>")
    except ET.ParseError:
        return None


def _netxml_text(node: ET.Element | None, tag: str) -> str:
    if node is None:
        return ""
    child = node.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _netxml_network(network: ET.Element, order: int, source_path: str) -> tuple[AccessPoint | None, bool]:
    bssid = normalize_mac(_netxml_text(network, "BSSID"))
    if not bssid:
        return None, False
    ssid_node = network.find("SSID")
    essid_node = ssid_node.find("essid") if ssid_node is not None else None
    ssid, blank = _clean_ssid(essid_node.text if essid_node is not None else "")
    cloaked = str(essid_node.get("cloaked") if essid_node is not None else "").strip().lower() == "true"
    enc_tokens = [(node.text or "").strip() for node in (ssid_node.iter("encryption") if ssid_node is not None else [])]
    enc_tokens = [tok for tok in enc_tokens if tok]
    privacy = _resolve_kismet_generation(normalize_privacy(" ".join(enc_tokens) or "None"))
    wps_raw = _netxml_text(ssid_node, "wps") if ssid_node is not None else ""
    saw_wps = bool(wps_raw)
    wps: bool | None = None
    if wps_raw:
        wps = wps_raw.strip().lower() not in ("no", "0", "false", "off", "unconfigured", "none")
    channel = parse_channel(_netxml_text(network, "channel"))
    snr = network.find("snr-info")
    signal = parse_signal(_netxml_text(snr, "max_signal_dbm")) if snr is not None else None
    # Reassembled from the source ELEMENTS rather than paraphrased, so the evidence a
    # finding quotes is greppable in the operator's own .netxml.
    raw_line = _clip("<BSSID>{}</BSSID>{}{}".format(
        bssid,
        "".join(f"<encryption>{tok}</encryption>" for tok in enc_tokens),
        f"<wps>{wps_raw}</wps>" if wps_raw else ""))
    # The <wps> element is a DIRECT observation and is recorded as one, so it outranks any
    # other export's file-level inference no matter which file was parsed first. PMF gets no
    # fact here at any confidence: netxml carries no RSN capability bits.
    wps_fact = (CapabilityFact(fact="wps", value=bool(wps), basis="direct",
                               observed_by="kismet-netxml",
                               evidence=_clip(f"<wps>{wps_raw}</wps>"), source_path=source_path,
                               source_row=order, raw_line=raw_line)
                if wps is not None else None)
    ap = AccessPoint(
        bssid=bssid, ssid="" if cloaked else ssid, hidden=cloaked or blank,
        channel=channel, band=band_for_channel(channel),
        encryption=privacy["encryption"], cipher=privacy["cipher"], auth=privacy["auth"],
        wps_fact=wps_fact, pmf="", enterprise=bool(privacy["enterprise"]),
        signal_dbm=signal, vendor=_netxml_text(network, "manuf"),
        first_seen=str(network.get("first-time") or "").strip(),
        last_seen=str(network.get("last-time") or "").strip(),
        raw_privacy=_clip(", ".join(enc_tokens)),
        source="kismet-netxml", source_path=source_path, source_row=order,
        raw_line=raw_line,
    )
    return ap, saw_wps


def _netxml_client(client: ET.Element, bssid: str, order: int, source_path: str) -> Station | None:
    mac = normalize_mac(_netxml_text(client, "client-mac"))
    if not mac:
        return None
    probes: list[str] = []
    for ssid_node in client.iter("SSID"):
        for essid in ssid_node.iter("essid"):
            name, _ = _clean_ssid(essid.text)
            if name and name not in probes:
                probes.append(name)
            if len(probes) >= _MAX_PROBES:
                break
    snr = client.find("snr-info")
    return Station(
        mac=mac, bssid=bssid, probes=probes,
        signal_dbm=parse_signal(_netxml_text(snr, "max_signal_dbm")) if snr is not None else None,
        packets=_int_or_zero(_netxml_text(client, "packets")),
        first_seen=str(client.get("first-time") or "").strip(),
        last_seen=str(client.get("last-time") or "").strip(),
        source="kismet-netxml", source_path=source_path, source_row=order,
        raw_line=_clip(f"<wireless-client> client-mac={mac} probes={'|'.join(probes)}"),
    )


# --- Kismet CSV (alias-driven) ----------------------------------------------------

# Kismet's CSV/device export has changed column NAMES across releases (and again between
# `kismet_csv`, `kismetdb_dump_devices` and the newer `kismet.device.base.*` dotted keys), so
# the parser maps ALIASES to fields instead of pretending to know one schema. Anything it
# cannot map is reported as a warning rather than dropped in silence — an unmapped column is
# information the operator has and the analyzer does not, and they deserve to know that.
_KISMET_ALIASES: dict[str, tuple[str, ...]] = {
    "bssid": ("bssid", "mac", "macaddr", "devmac", "device", "kismetdevicebasemacaddr"),
    "ssid": ("ssid", "essid", "networkname", "name", "kismetdevicebasename",
             "dot11devicelastbeaconedssid", "dot11deviceadvertisedssidmapssid"),
    "channel": ("channel", "chan", "kismetdevicebasechannel"),
    "frequency": ("frequency", "freq", "freqmhz", "kismetdevicebasefrequency"),
    "encryption": ("encryption", "crypt", "cryptstring", "privacy", "encryptionstring",
                   "dot11deviceadvertisedssidcryptstring"),
    "signal": ("signal", "signaldbm", "bestsignaldbm", "rssi", "maxsignaldbm",
               "kismetdevicebasesignalmaxsignal", "kismetdevicebasesignallastsignal"),
    "vendor": ("manuf", "manufacturer", "vendor", "kismetdevicebasemanuf"),
    "first_seen": ("firsttime", "firstseen", "first", "kismetdevicebasefirsttime"),
    "last_seen": ("lasttime", "lastseen", "last", "kismetdevicebaselasttime"),
    "packets": ("packets", "packetstotal", "numpackets", "kismetdevicebasepackets"),
    "type": ("type", "phyname", "phy", "kismetdevicebasephyname", "kismetdevicebasetype"),
    "wps": ("wps", "wpsstate", "dot11deviceadvertisedssidwps", "wpsversion"),
    "bssidref": ("lastbssid", "apmac", "associatedbssid"),
}
_KISMET_REQUIRED = ("bssid",)


def _norm_col(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _kismet_csv_header(header: list[str]) -> dict[str, int] | None:
    """Map a header row onto field names via :data:`_KISMET_ALIASES`, or None when it does
    not look like a Kismet device export at all."""
    normalized = [_norm_col(col) for col in header]
    mapping: dict[str, int] = {}
    for field, aliases in _KISMET_ALIASES.items():
        for pos, col in enumerate(normalized):
            if col in aliases and field not in mapping:
                mapping[field] = pos
    if any(field not in mapping for field in _KISMET_REQUIRED):
        return None
    if "encryption" not in mapping and "ssid" not in mapping:
        return None
    return mapping


def parse_kismet_csv(text: str, *, source_path: str = "", survey: Survey | None = None,
                     max_rows: int = _MAX_ROWS) -> Survey:
    """A Kismet CSV/device export. Parser confidence MEDIUM, and that is stated in the
    report rather than hidden: the column set differs between Kismet releases and between
    the several exporters Kismet ships, so binding to one fixed schema would silently
    mis-parse half the exports in the wild.

    Columns are mapped through :data:`_KISMET_ALIASES` and every column that could NOT be
    mapped is recorded as a warning, so an operator can see exactly which fields the
    analyzer ignored instead of assuming it read everything.

    Kismet CSV carries no RSN capability bits, so PMF is undetermined; WPS is present in
    some exports and resolved against file-level evidence.
    """
    survey = survey or Survey()
    reader = csv.reader(io.StringIO(_strip_bom(text)))
    try:
        header = [str(c) for c in next(reader)]
    except StopIteration:
        survey.warnings.append("kismet-csv: empty export.")
        survey.sources.append({"path": source_path, "format": "kismet-csv", "aps": 0, "rows": 0,
                               "reports_wps": False, "reports_pmf": False})
        return survey
    mapping = _kismet_csv_header(header)
    if mapping is None:
        survey.warnings.append(
            f"kismet-csv: header does not map to any known Kismet schema "
            f"({', '.join(h.strip() for h in header[:12])}); nothing parsed.")
        survey.sources.append({"path": source_path, "format": "kismet-csv", "aps": 0, "rows": 0,
                               "reports_wps": False, "reports_pmf": False})
        return survey
    mapped_positions = set(mapping.values())
    unmapped = [header[pos].strip() for pos in range(len(header)) if pos not in mapped_positions and header[pos].strip()]
    if unmapped:
        survey.warnings.append(
            f"kismet-csv: {len(unmapped)} column(s) could not be mapped to a known field and were "
            f"ignored: {', '.join(unmapped[:20])}. Kismet's CSV schema varies by release; parser "
            f"confidence for this format is MEDIUM.")
    aps: dict[str, AccessPoint] = {}
    capabilities: list[_RowCapability] = []
    wps_seen = False
    rows = 0
    row_number = 1
    while True:
        row_number += 1
        try:
            cells = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            survey.warnings.append(f"kismet-csv: row {row_number} unreadable ({exc}); stopped there.")
            break
        if rows >= max_rows:
            survey.warnings.append(f"kismet-csv: stopped at the {max_rows}-row cap; the export is longer.")
            break
        def cell(key: str) -> str:
            pos = mapping.get(key)
            return str(cells[pos]).strip() if pos is not None and pos < len(cells) else ""

        phy = cell("type").lower()
        if phy and "802.11" not in phy and "wifi" not in phy and "wi-fi" not in phy and "dot11" not in phy:
            continue
        bssid = normalize_mac(cell("bssid"))
        if not bssid:
            continue
        enc_raw = cell("encryption")
        privacy = _resolve_kismet_generation(normalize_privacy(enc_raw))
        # WPS comes ONLY from the dedicated column, exactly as the netxml parser takes it
        # only from the <wps> element. normalize_privacy's substring scan of the crypt
        # string is discarded here: a Kismet Encryption cell reading "RSN{PSK,CCMP} WPS"
        # made this parser assert WPS with no capability evidence to cite, and the finding
        # then quoted whatever privacy blob another export had contributed.
        wps_raw = cell("wps")
        wps_fact = None
        if wps_raw:
            wps_seen = True
            wps_fact = CapabilityFact(
                fact="wps",
                value=wps_raw.strip().lower() not in ("0", "no", "false", "off", "none", "unconfigured"),
                # The VERBATIM cell, not a `wps=<value>` label built around it: the evidence
                # field promises bytes a reader can grep the export for and land on.
                basis="direct", observed_by="kismet-csv", evidence=_clip(wps_raw),
                source_path=source_path, source_row=row_number,
                raw_line=_clip(",".join(str(c) for c in cells)))
        ssid, blank = _clean_ssid(cell("ssid"))
        channel = parse_channel(cell("channel")) or parse_channel(cell("frequency"))
        raw_line = _clip(",".join(str(c) for c in cells))
        ap = AccessPoint(
            bssid=bssid, ssid=ssid, hidden=blank or not ssid,
            channel=channel, band=band_for_channel(channel),
            encryption=privacy["encryption"], cipher=privacy["cipher"], auth=privacy["auth"],
            wps_fact=wps_fact, pmf="", enterprise=bool(privacy["enterprise"]),
            signal_dbm=parse_signal(cell("signal")), vendor=cell("vendor"),
            beacons=_int_or_zero(cell("packets")),
            first_seen=cell("first_seen"), last_seen=cell("last_seen"),
            raw_privacy=_clip(enc_raw),
            source="kismet-csv", source_path=source_path, source_row=row_number,
            raw_line=raw_line,
        )
        _track(survey, ap, aps, rows=capabilities, capability=_RowCapability(
            bssid=ap.bssid, source_path=source_path, source_row=row_number, raw_line=raw_line,
            wps_token=_clip(wps_raw), wps_direct=wps_fact is not None))
        rows += 1
    _apply_capability_evidence(survey, aps, capabilities, "kismet-csv",
                               wps_seen=wps_seen, pmf_seen=False)
    survey.sources.append({"path": source_path, "format": "kismet-csv", "aps": len(aps), "rows": rows,
                           "reports_wps": wps_seen, "reports_pmf": False,
                           "unmapped_columns": unmapped})
    return survey


# --- netsh wlan show networks mode=bssid ------------------------------------------

_NETSH_SSID_RE = re.compile(r"^SSID\s+(\d+)$", re.IGNORECASE)
_NETSH_BSSID_RE = re.compile(r"^BSSID\s+(\d+)$", re.IGNORECASE)
# netsh appends a unit to several labels ("Basic rates (Mbps)"), and the unit is not part of
# the field's identity. Stripped before lookup so a build that adds or drops the suffix does
# not read as an unknown - and therefore cannot be mistaken for evidence of localization.
_NETSH_UNIT_SUFFIX = re.compile(r"\s*\([^)]*\)\s*$")
# The English labels. On a localized Windows every one of these is translated, which is why
# an unrecognized label produces a WARNING naming it instead of a silently empty AP record.
_NETSH_LABELS = {
    "network type": "network_type", "authentication": "auth", "encryption": "cipher",
    "signal": "signal", "radio type": "radio", "band": "band", "channel": "channel",
    "basic transfer rates": "rates", "other rates": "rates", "basic rates": "rates",
    "supported rates": "rates",
}
# English labels current Windows 11 emits that carry NO field this analyzer reads. They are
# recognized on purpose: every one of them was reported as an unknown label on an ordinary
# English Windows 11 box, and the parser then told the operator their own machine "looks
# like a LOCALIZED (non-English) Windows" - a claim about their system that nothing in the
# input supports, carried verbatim into the written deliverable.
_NETSH_IGNORED_LABELS = (
    "bss load", "connected stations", "channel utilization", "medium available capacity",
    "qos mscs supported", "qos map supported", "qos", "mesh", "802.11 features",
    "network based on", "physical layer",
)
#: The labels whose absence is what a localized capture actually looks like. If NONE of
#: these were recognized, the export's own semantics were unreadable - the only evidence of
#: localization this parser can honestly cite.
_NETSH_CORE_LABELS = ("authentication", "encryption", "network type", "radio type")
_NETSH_STRUCTURAL = ("interface name", "there are", "ssid", "bssid")


def parse_netsh_text(text: str, *, source_path: str = "", survey: Survey | None = None,
                     max_rows: int = _MAX_ROWS) -> Survey:
    """Windows ``netsh wlan show networks mode=bssid``. Parser confidence MEDIUM.

    Indentation-structured, one ``SSID <n>`` block per network with nested ``BSSID <n>``
    blocks. Three traps:

    * A hidden network renders as ``SSID 3 : `` with an EMPTY value — that is real, not a
      parse failure.
    * ``Authentication`` values are Windows-localized PRODUCT names (``WPA2-Personal``,
      ``WPA3-SAE``, ``Open``, ``OWE``), not IEEE tokens; ``normalize_privacy`` maps them.
    * On a non-English Windows every LABEL is translated too. Structure is recovered from the
      ordinal prefixes ``SSID <n>`` / ``BSSID <n>``, which are not translated, so the access
      points are still found; unrecognized labels are collected into a warning so the
      operator learns encryption was undetermined rather than seeing a confident "open".

    ``Signal`` is a driver-computed PERCENTAGE. It populates ``signal_pct`` and leaves
    ``signal_dbm`` as None: a percentage converted to dBm is a fabricated measurement.

    netsh reports no WPS and no RSN capability bits, so both stay undetermined.
    """
    survey = survey or Survey()
    aps: dict[str, AccessPoint] = {}
    current_ssid, current_hidden = "", False
    # netsh nests TWO scopes and they carry different fields. Authentication / Encryption /
    # Network type belong to the SSID block and are printed BEFORE the first BSSID; Signal /
    # Radio type / Band / Channel belong to each BSSID block. Reading everything into the
    # BSSID scope loses the encryption of every network in the file - and an AP whose
    # encryption silently reads as unknown is one step away from being reported as open.
    ssid_meta: dict[str, Any] = {}
    pending: dict[str, Any] = {}
    pending_row, pending_raw = 0, ""
    unknown_labels: list[str] = []
    english_labels: set[str] = set()
    lines = _strip_bom(text).splitlines()

    def flush() -> None:
        nonlocal pending, pending_row, pending_raw
        bssid = normalize_mac(pending.get("bssid", ""))
        if bssid:
            def field(key: str) -> Any:
                # BSSID scope wins where a value exists; otherwise inherit the SSID block.
                return pending.get(key) if pending.get(key) else ssid_meta.get(key)

            privacy = normalize_privacy(field("auth") or "", field("cipher") or "")
            channel = parse_channel(field("channel"))
            signal_raw = str(field("signal") or "").strip()
            pct = None
            if signal_raw.endswith("%"):
                try:
                    pct = max(0, min(100, int(float(signal_raw[:-1]))))
                except ValueError:
                    pct = None
            ap = AccessPoint(
                bssid=bssid, ssid="" if current_hidden else current_ssid, hidden=current_hidden,
                channel=channel, band=band_for_channel(channel) or str(field("band") or "").strip(),
                encryption=privacy["encryption"], cipher=privacy["cipher"], auth=privacy["auth"],
                wps=None, pmf="", enterprise=bool(privacy["enterprise"]),
                signal_dbm=None, signal_pct=pct,
                raw_privacy=" / ".join(p for p in (str(field("auth") or ""), str(field("cipher") or "")) if p),
                source="netsh-text", source_path=source_path, source_row=pending_row,
                raw_line=_clip(pending_raw),
            )
            _track(survey, ap, aps)
        pending, pending_row, pending_raw = {}, 0, ""

    for index, line in enumerate(lines, start=1):
        if len(aps) >= max_rows:
            survey.warnings.append(f"netsh-text: stopped at the {max_rows}-row cap.")
            break
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        label, value = label.strip(), value.strip()
        low = label.lower()
        ssid_match = _NETSH_SSID_RE.match(label)
        if ssid_match:
            flush()
            ssid_meta = {}
            current_ssid, blank = _clean_ssid(value)
            current_hidden = blank or not current_ssid
            continue
        bssid_match = _NETSH_BSSID_RE.match(label)
        if bssid_match:
            flush()
            pending = {"bssid": value}
            pending_row, pending_raw = index, line
            continue
        base = _NETSH_UNIT_SUFFIX.sub("", low).strip()
        key = _NETSH_LABELS.get(base)
        if key is not None:
            english_labels.add(base)
        else:
            if base in _NETSH_IGNORED_LABELS or any(
                    base.startswith(prefix) for prefix in _NETSH_IGNORED_LABELS):
                english_labels.add(base)  # recognized English, just not a field we read
                continue
            if any(low.startswith(prefix) for prefix in _NETSH_STRUCTURAL):
                if low.startswith(("interface name", "there are")):
                    english_labels.add(base)
                continue
            if label and label not in unknown_labels and len(unknown_labels) < 24:
                unknown_labels.append(label)
            continue
        if pending:
            pending[key] = value
            pending_raw = f"{pending_raw} | {line.strip()}"[:_RAW_CLIP]
        else:
            ssid_meta[key] = value
    flush()

    if unknown_labels:
        # The localization verdict must be EVIDENCED, not assumed. An unknown label on its own
        # proves nothing: current Windows 11 emits Bss Load / QoS / rate lines this analyzer
        # has no field for, on an entirely English capture. What a localized export actually
        # looks like is that NONE of the core labels decoded - and that is what is tested.
        # Claiming "your Windows is non-English" from an unread QoS line is a statement about
        # the operator's machine that the input cannot support, and it was written straight
        # into the client deliverable.
        core_seen = sorted(label for label in english_labels if label in _NETSH_CORE_LABELS)
        if core_seen:
            survey.warnings.append(
                f"netsh-text: {len(unknown_labels)} label(s) carry no field this analyzer reads and "
                f"were skipped: {', '.join(unknown_labels[:8])}. The core English labels "
                f"({', '.join(core_seen)}) WERE recognized, so this is NOT evidence of a localized "
                f"Windows - netsh's field set varies by Windows build and driver. Nothing was "
                f"inferred from the skipped lines.")
        else:
            survey.warnings.append(
                f"netsh-text: {len(unknown_labels)} label(s) were not recognized AND none of the core "
                f"English labels ({', '.join(_NETSH_CORE_LABELS)}) appeared, which is consistent with a "
                f"LOCALIZED (non-English) Windows: {', '.join(unknown_labels[:8])}. Access points were "
                f"still recovered from the untranslated 'SSID <n>' / 'BSSID <n>' structure, but any field "
                f"behind an unrecognized label is UNDETERMINED, not absent.")
    if not aps:
        survey.warnings.append("netsh-text: no 'BSSID <n> :' block found; nothing parsed.")
    _no_capability_warning(survey, "netsh-text", "netsh wlan", len(aps))
    if aps:
        survey.warnings.append(
            f"netsh-text: signal is a driver-computed PERCENTAGE, so signal_dbm is undetermined for all "
            f"{len(aps)} BSS (converting a percentage to dBm would fabricate a measurement).")
    survey.sources.append({"path": source_path, "format": "netsh-text", "aps": len(aps), "rows": len(aps),
                           "reports_wps": False, "reports_pmf": False})
    return survey


# --- dispatch ---------------------------------------------------------------------

_PARSERS = {
    "airodump-csv": parse_airodump_csv,
    "wigle-csv": parse_wigle_csv,
    "kismet-netxml": parse_kismet_netxml,
    "kismet-csv": parse_kismet_csv,
    "netsh-text": parse_netsh_text,
}


def parse_survey_text(text: str, *, fmt: str = "auto", source_path: str = "",
                      survey: Survey | None = None, max_rows: int = _MAX_ROWS) -> Survey:
    """Parse one export's TEXT into ``survey`` (created when omitted). Unknown format ->
    a warning and an unchanged survey; never a raise."""
    survey = survey or Survey()
    text = _strip_bom(text)
    resolved = str(fmt or "auto").strip().lower()
    if resolved in ("", "auto"):
        resolved = detect_format(text, filename=source_path)
    parser = _PARSERS.get(resolved)
    if parser is None:
        survey.warnings.append(
            f"{source_path or '<text>'}: format not recognized (expected one of {', '.join(FORMATS)}); skipped.")
        return survey
    try:
        return parser(text, source_path=source_path, survey=survey, max_rows=max_rows)
    except Exception as exc:  # noqa: BLE001 - a malformed export must degrade to a warning,
        # never abort a survey that may hold thousands of good rows from other files.
        survey.warnings.append(f"{source_path or '<text>'}: {resolved} parser failed ({type(exc).__name__}: {exc}).")
        return survey


def _read_export(path: Path) -> tuple[str, str]:
    """``(text, warning)`` for one export file. Survey tools write latin-1 and cp1252 SSIDs
    routinely, so decoding is lossy-but-total rather than strict.

    ``utf-8-sig`` rather than ``utf-8``: a capture re-saved by any Windows tool carries a
    BOM, and an un-stripped BOM silently costs the whole airodump AP section."""
    try:
        if path.stat().st_size > _MAX_BYTES:
            return "", f"{path}: larger than the {_MAX_BYTES // 1_000_000} MB cap; skipped."
        return path.read_text(encoding="utf-8-sig", errors="replace"), ""
    except OSError as exc:
        return "", f"{path}: unreadable ({exc})."
    except Exception as exc:  # noqa: BLE001 - one bad file must not stop the other exports
        return "", f"{path}: unreadable ({type(exc).__name__}: {exc})."


def _walk_exports(root: Path, survey: Survey) -> list[Path]:
    """Every survey export under ``root``, sorted, with the walk itself made total.

    ``Path.rglob`` is not usable here on the package's primary platform. It FOLLOWS a
    Windows directory junction (only true symlinks are skipped) and catches only
    ``PermissionError``, so an ordinary ``capture\\sub\\back -> capture`` junction makes it
    descend until the path exceeds MAX_PATH and then raises ``FileNotFoundError`` out of
    :func:`load_survey` — discarding an entire assessment over a subtree that held no
    exports, in flat contradiction of this module's "one bad file must not stop the other
    exports" contract. The same crash needs no junction at all: any archive subtree deeper
    than MAX_PATH does it.

    So the walk is explicit: cycles are broken by REAL path (``realpath`` resolves
    junctions), depth is capped, and an unreadable directory costs that subtree and a
    warning rather than the survey."""
    found: list[Path] = []
    seen: set[str] = set()
    notes = 0
    stack: list[tuple[Path, int]] = [(root, 0)]

    def note(message: str) -> None:
        # Capped, because a pathological tree (an archive of thousands of junctioned session
        # folders) would otherwise bury every parser note in the deliverable under skips.
        nonlocal notes
        notes += 1
        if notes <= 20:
            survey.warnings.append(message)
        elif notes == 21:
            survey.warnings.append(f"{root}: further directory-walk notes suppressed.")

    while stack:
        if len(seen) >= _MAX_WALK_DIRS:
            note(f"{root}: stopped after {_MAX_WALK_DIRS} directories; the tree is larger.")
            break
        directory, depth = stack.pop()
        try:
            real = os.path.realpath(str(directory))
        except OSError:  # a path the OS refuses to resolve is a subtree we skip, not a crash
            continue
        if real in seen:
            note(f"{directory}: skipped - it resolves to {real}, already walked (directory "
                 f"junction or symlink cycle).")
            continue
        seen.add(real)
        if depth > _MAX_WALK_DEPTH:
            note(f"{directory}: deeper than the {_MAX_WALK_DEPTH}-level walk cap; not descended.")
            continue
        try:
            with os.scandir(directory) as scan:
                entries = sorted(scan, key=lambda entry: entry.name)
        except OSError as exc:
            note(f"{directory}: subtree skipped ({exc}); other exports still read.")
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append((Path(entry.path), depth + 1))
                elif entry.is_file() and Path(entry.name).suffix.lower() in SURVEY_EXTENSIONS:
                    found.append(Path(entry.path))
            except OSError:  # noqa: PERF203 - one unstatable entry must not cost the directory
                continue
    return sorted(found)


def load_survey(paths: Any, *, fmt: str = "auto", max_rows: int = _MAX_ROWS,
                max_files: int = 200) -> Survey:
    """Parse every export in ``paths`` (a path, or an iterable of paths) into ONE survey.

    A DIRECTORY is walked for :data:`SURVEY_EXTENSIONS`, sorted, so ``gn wardrive ./capture/``
    picks up the airodump CSV and the netxml the same run produced and merges them by BSSID —
    which is how a WPS/PMF fact that only one of the two formats carries reaches the analyzer.
    Deterministic ordering throughout: a survey re-run over the same files must be identical.
    """
    survey = Survey()
    candidates: list[Path] = []
    raw_paths = paths if isinstance(paths, (list, tuple, set)) else [paths]
    for raw in raw_paths:
        path = Path(str(raw))
        try:
            is_dir = path.is_dir()
        except OSError:
            is_dir = False
        if is_dir:
            found = _walk_exports(path, survey)
            if not found:
                survey.warnings.append(f"{path}: directory holds no {'/'.join(SURVEY_EXTENSIONS)} export.")
            candidates.extend(found)
        else:
            candidates.append(path)
    if len(candidates) > max_files:
        survey.warnings.append(f"{len(candidates)} exports found; only the first {max_files} were read.")
        candidates = candidates[:max_files]
    for path in candidates:
        text, warning = _read_export(path)
        if warning:
            survey.warnings.append(warning)
            continue
        parse_survey_text(text, fmt=fmt, source_path=str(path), survey=survey, max_rows=max_rows)
    if not survey.sources:
        survey.warnings.append("no survey export was parsed.")
    return survey
