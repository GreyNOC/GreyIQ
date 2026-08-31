"""Wardrive / RF survey — parser fidelity, the tri-state honesty rule, and the read-only envelope.

The load-bearing tests here are not the round-trips. They are:

  * SAFETY — this package's own source must contain no socket, no subprocess, no HTTP client
    and no offensive wireless tooling. The envelope is enforced by scanning the code, because
    a docstring promise is not an invariant.
  * UNDETERMINED vs ABSENT — an airodump-ng capture carries no WPS state and no RSN
    capability bits, so an airodump-only survey must emit ZERO WPS findings and ZERO PMF
    findings and report both as undetermined instead. Emitting "PMF missing" from a format
    that cannot observe PMF would be a confidently wrong line in a client deliverable.
  * EVIL-TWIN FALSE-POSITIVE CONTROL — a legitimate band-steered deployment puts one SSID on
    many BSSIDs; a same-vendor, same-encryption group must produce nothing at all.

Fixtures are inline and realistic (real column sets, real space padding, real quirks), so a
parser regression fails here rather than on an operator's capture.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as core_report  # noqa: E402
from bughunter.wardrive import analyze as wd_analyze  # noqa: E402
from bughunter.wardrive import cli as wd_cli  # noqa: E402
from bughunter.wardrive import oui as wd_oui  # noqa: E402
from bughunter.wardrive import parsers  # noqa: E402
from bughunter.wardrive import report as wd_report  # noqa: E402

WARDRIVE_DIR = BACKEND_DIR / "bughunter" / "wardrive"

# --- fixtures ---------------------------------------------------------------------

AIRODUMP_CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication,"
    " Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
    "00:0B:85:AA:BB:01, 2026-07-30 10:00:00, 2026-07-30 10:05:00,   6,  195, WPA2, CCMP, PSK,"
    " -42,      120,        0,   0.  0.  0.  0,   8, CorpWiFi, \r\n"
    "24:0A:C4:11:22:33, 2026-07-30 10:00:10, 2026-07-30 10:05:10,  11,  130, OPN,  ,   ,"
    "  -1,       40,        0,   0.  0.  0.  0,  10, FreeCoffee, \r\n"
    "00:14:6C:DE:AD:02, 2026-07-30 10:01:00, 2026-07-30 10:06:00,   1,   54, WEP , WEP ,   ,"
    " -70,       33,       12,   0.  0.  0.  0,   0, , \r\n"
    "14:CC:20:00:00:03, 2026-07-30 10:02:00, 2026-07-30 10:07:00,   6,  195, WPA2, CCMP TKIP, PSK,"
    " -55,       90,        0,   0.  0.  0.  0,  11, Lab, Net, \r\n"
    "\r\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
    "00:1E:C2:AA:00:01, 2026-07-30 10:00:05, 2026-07-30 10:05:05,  -55,       12,"
    " 00:0B:85:AA:BB:01, CorpWiFi,Home Net,Airport Free WiFi\r\n"
    "02:11:22:33:44:55, 2026-07-30 10:00:07, 2026-07-30 10:05:07,   -1,        3,"
    " (not associated),  \r\n"
)

WIGLE_CSV = (
    "WigleWifi-1.6,appRelease=2.72,model=Pixel 7,release=14,device=panther,display=UQ1A,"
    "board=panther,brand=google\n"
    "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,"
    "AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type\n"
    "00:0B:85:AA:BB:01,CorpWiFi,[WPA2-PSK-CCMP][ESS],2026-07-30 10:00:00,6,2437,-42,"
    "37.0,-122.0,10,5,,,WIFI\n"
    "6C:F3:7F:00:00:02,CorpWiFi-Secure,[RSN-SAE-CCMP][MFPR][MFPC][ESS],2026-07-30 10:00:05,"
    "36,5180,-51,37.0,-122.0,10,5,,,WIFI\n"
    "14:CC:20:00:00:03,\"Home, Sweet Home\",[WPA2-PSK-CCMP][WPS][ESS],2026-07-30 10:00:09,"
    "11,2462,-66,37.0,-122.0,10,5,,,WIFI\n"
    "AA:BB:CC:DD:EE:FF,SomeBeacon,[BLE],2026-07-30 10:00:11,0,0,-80,37.0,-122.0,10,5,,,BLE\n"
)

KISMET_NETXML = """<?xml version="1.0" encoding="ISO-8859-1"?>
<detection-run kismet-version="2022.02.R1" start-time="Thu Jul 30 10:00:00 2026">
 <wireless-network number="1" type="infrastructure" first-time="Thu Jul 30 10:00:00 2026"
                   last-time="Thu Jul 30 10:05:00 2026">
  <SSID first-time="Thu Jul 30 10:00:00 2026" last-time="Thu Jul 30 10:05:00 2026">
   <type>Beacon</type>
   <encryption>WPA+PSK</encryption>
   <encryption>WPA+AES-CCM</encryption>
   <essid cloaked="false">CorpWiFi</essid>
   <wps>Configured</wps>
  </SSID>
  <BSSID>00:0B:85:AA:BB:01</BSSID>
  <manuf>Cisco Systems</manuf>
  <channel>6</channel>
  <snr-info><max_signal_dbm>-42</max_signal_dbm></snr-info>
  <wireless-client number="1" type="established">
   <client-mac>00:1E:C2:AA:00:01</client-mac>
   <SSID><essid cloaked="false">CorpWiFi</essid></SSID>
   <snr-info><max_signal_dbm>-55</max_signal_dbm></snr-info>
  </wireless-client>
 </wireless-network>
 <wireless-network number="2" type="infrastructure" first-time="Thu Jul 30 10:01:00 2026"
                   last-time="Thu Jul 30 10:06:00 2026">
  <SSID first-time="Thu Jul 30 10:01:00 2026" last-time="Thu Jul 30 10:06:00 2026">
   <type>Beacon</type>
   <encryption>None</encryption>
   <essid cloaked="true"></essid>
  </SSID>
  <BSSID>24:0A:C4:11:22:33</BSSID>
  <channel>11</channel>
  <snr-info><max_signal_dbm>-70</max_signal_dbm></snr-info>
 </wireless-network>
</detection-run>
"""

KISMET_CSV = (
    "kismet.device.base.macaddr,kismet.device.base.name,kismet.device.base.phyname,"
    "kismet.device.base.channel,dot11.device.advertised_ssid.crypt_string,"
    "kismet.device.base.signal.last_signal,kismet.device.base.manuf,"
    "kismet.device.base.mod_time,kismet.device.base.seenby\n"
    "00:0B:85:AA:BB:01,CorpWiFi,IEEE802.11,6,WPA2-PSK-CCMP,-42,Cisco Systems,1234,wlan0mon\n"
    "24:0A:C4:11:22:33,FreeCoffee,IEEE802.11,11,Open,-70,Espressif Inc.,1234,wlan0mon\n"
    "11:22:33:44:55:66,SomeBluetooth,Bluetooth,0,,-80,,1234,hci0\n"
)

NETSH_TEXT = """Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : CorpWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:0b:85:aa:bb:01
         Signal             : 84%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 36
    BSSID 2                 : 00:0b:85:aa:bb:02
         Signal             : 61%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 24:0a:c4:11:22:33
         Signal             : 42%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 11
"""

NETSH_TEXT_DE = """Schnittstellenname : WLAN
Es sind 1 Netzwerke derzeit sichtbar.

SSID 1 : Firmennetz
    Netzwerktyp             : Infrastruktur
    Authentifizierung       : WPA2-Personal
    Verschluesselung        : CCMP
    BSSID 1                 : 00:0b:85:aa:bb:01
         Signal             : 90%
         Funktyp            : 802.11n
         Kanal              : 6
"""


# --- cross-format merge fixtures ---------------------------------------------------
# One BSS (aa:bb:cc:00:00:01 / CorpNet) captured by several tools on the same walk, which
# is the workflow `load_survey` advertises. Each pair below is deliberately built so that
# exactly ONE of the two files can observe the capability under test.

MERGE_BSSID = "aa:bb:cc:00:00:01"

AIRODUMP_ONE = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication,"
    " Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
    "AA:BB:CC:00:00:01, 2026-01-01 10:00:00, 2026-01-01 10:05:00,  6,  130, WPA2, CCMP, PSK,"
    " -55,      40,        0,   0.  0.  0.  0,   7, CorpNet, \n"
)

# CorpNet's AuthMode cell is EMPTY - WiGLE writes this whenever it never captured the
# capability string, and any torn/short row produces the same thing. A DIFFERENT BSS in the
# same file carries [MFPC][WPS], so the file demonstrably emits both markers.
WIGLE_EMPTY_AUTHMODE = (
    "WigleWifi-1.4,appRelease=2.53\n"
    "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,"
    "AltitudeMeters,AccuracyMeters,Type\n"
    "AA:BB:CC:00:00:01,CorpNet,,2026-01-01 10:00:00,6,-55,0,0,0,0,WIFI\n"
    "AA:BB:CC:00:00:02,OtherNet,[WPA2-PSK-CCMP][MFPC][WPS][ESS],2026-01-01 10:00:00,6,-60,0,0,0,0,WIFI\n"
)

# The same BSS with a REAL AuthMode that lacks the MFP markers: a genuine negative once the
# file proves the exporter writes them.
WIGLE_NO_MFP = (
    "WigleWifi-1.4,appRelease=2.53\n"
    "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,"
    "AltitudeMeters,AccuracyMeters,Type\n"
    "AA:BB:CC:00:00:01,CorpNet,[WPA2-PSK-CCMP][ESS],2026-01-01 10:00:00,6,-55,0,0,0,0,WIFI\n"
    "AA:BB:CC:00:00:02,OtherNet,[WPA2-PSK-CCMP][MFPC][ESS],2026-01-01 10:00:00,6,-60,0,0,0,0,WIFI\n"
)

NETXML_ONE_WPS = """<?xml version="1.0"?>
<detection-run kismet-version="2022.02.R1">
 <wireless-network number="1">
  <SSID><encryption>WPA+PSK</encryption><encryption>AES-CCM</encryption>
   <essid cloaked="false">CorpNet</essid><wps>Configured</wps></SSID>
  <BSSID>AA:BB:CC:00:00:01</BSSID><channel>6</channel>
 </wireless-network>
</detection-run>
"""

# A real Kismet CSV schema variant with NO `wps` column, whose Encryption cell happens to
# contain the substring "WPS". Nothing here observes WPS state.
KISMET_CSV_NO_WPS_COLUMN = (
    "BSSID,SSID,Encryption,Channel,Type\n"
    'AA:BB:CC:00:00:01,CorpNet,"RSN{PSK,CCMP} WPS",6,Wi-Fi\n'
)

# The same export WITH the dedicated column, which is the only thing kismet-csv may read
# WPS from.
KISMET_CSV_WPS_COLUMN = (
    "BSSID,SSID,Encryption,Channel,Type,WPS\n"
    "AA:BB:CC:00:00:01,CorpNet,RSN{PSK|CCMP},6,Wi-Fi,Configured\n"
)

# Two WiGLE walks of one site. Day 1 stamps dd:03 by file-level inference (dd:04 carries the
# markers); day 2 observes [MFPR][WPS] on dd:03 verbatim.
WIGLE_WALK_DAY1 = (
    "WigleWifi-1.4,appRelease=2.53\n"
    "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,"
    "AltitudeMeters,AccuracyMeters,Type\n"
    "00:AA:BB:CC:DD:03,ShopAP,[WPA2-PSK-CCMP][ESS],2026-01-01 10:00:00,6,-55,0,0,0,0,WIFI\n"
    "00:AA:BB:CC:DD:04,OtherAP,[WPA2-PSK-CCMP][MFPC][WPS][ESS],2026-01-01 10:00:00,6,-60,0,0,0,0,WIFI\n"
)
WIGLE_WALK_DAY2 = (
    "WigleWifi-1.4,appRelease=2.53\n"
    "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,"
    "AltitudeMeters,AccuracyMeters,Type\n"
    "00:AA:BB:CC:DD:03,ShopAP,[WPA2-PSK-CCMP][MFPR][MFPC][WPS][ESS],2026-01-02 10:00:00,6,-40,0,0,0,0,WIFI\n"
)

# Real `netsh wlan show networks mode=bssid` output from an English Windows 11 box. Every
# label below was captured from the shipping OS; eight of them were unknown to the parser.
NETSH_WIN11_ENGLISH = """Interface name : Wi-Fi
There are 1 networks currently visible.

SSID 1 : CorpWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:0b:85:aa:bb:01
         Signal             : 100%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 48
         Bss Load           :
              Connected Stations       : 3
              Channel Utilization      : 20 (7 %)
              Medium Available Capacity: 20 (61224 usec)
         QoS MSCS Supported : No
         QoS Map Supported  : Yes
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54
"""


def _ap(survey, bssid):
    return survey.aps[bssid]


def _rules(result) -> list[str]:
    return sorted(f["rule_id"] for f in result["findings"])


def _write_dir(tmp: str, files: dict[str, str]) -> Path:
    root = Path(tmp)
    for name, body in files.items():
        (root / name).write_text(body, encoding="utf-8")
    return root


# --- safety envelope ---------------------------------------------------------------


class SafetyEnvelopeTests(unittest.TestCase):
    """The read-only envelope, enforced by scanning the package's own source."""

    def _sources(self) -> dict[str, str]:
        return {p.name: p.read_text(encoding="utf-8") for p in sorted(WARDRIVE_DIR.glob("*.py"))}

    def test_package_has_no_network_or_process_capability(self) -> None:
        banned = ("import socket", "socket.socket", "import subprocess", "subprocess.",
                  "urllib.request", "import requests", "http.client", "os.system", "os.popen",
                  "import scapy", "pyshark")
        for name, text in self._sources().items():
            for token in banned:
                self.assertNotIn(token, text, f"{name} must not reference {token!r} - the wardrive package "
                                              f"is read-only analysis of operator-supplied export files")

    def test_package_names_no_offensive_wireless_capability(self) -> None:
        banned = ("pmkid", "deauth", "aireplay", "aircrack", "hashcat", "handshake capture",
                  "wps pin brute", "reaver", "bully", "mdk3", "mdk4", "wifite")
        for name, text in self._sources().items():
            low = text.lower()
            for token in banned:
                self.assertNotIn(token, low, f"{name} must not reference {token!r}")

    def test_seed_skill_declares_the_read_only_scope(self) -> None:
        skill = (BACKEND_DIR / "seed" / "skills" / "rf-survey-triage.md").read_text(encoding="utf-8")
        self.assertIn("when:", skill)
        for keyword in ("wifi", "bssid", "evil twin", "kismet", "airodump", "wigle", "netsh wlan"):
            self.assertIn(keyword, skill)
        self.assertIn("read-only", skill.lower())


# --- airodump ----------------------------------------------------------------------


class AirodumpParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="walk-01.csv")

    def test_detects_and_parses_both_sections(self) -> None:
        self.assertEqual(parsers.detect_format(AIRODUMP_CSV, filename="walk-01.csv"), "airodump-csv")
        self.assertEqual(len(self.survey.aps), 4)
        self.assertEqual(len(self.survey.stations), 2)

    def test_power_minus_one_is_no_signal_not_minus_one_dbm(self) -> None:
        """airodump writes Power=-1 for 'never received a frame'. Reporting -1 dBm would
        invent a near-perfect signal from a row that means the opposite."""
        self.assertIsNone(_ap(self.survey, "24:0a:c4:11:22:33").signal_dbm)
        self.assertEqual(_ap(self.survey, "00:0b:85:aa:bb:01").signal_dbm, -42)

    def test_id_length_zero_is_hidden_not_open(self) -> None:
        wep = _ap(self.survey, "00:14:6c:de:ad:02")
        self.assertTrue(wep.hidden)
        self.assertEqual(wep.encryption, "wep")  # a blank ESSID must never read as "open"

    def test_unquoted_comma_in_essid_is_reassembled(self) -> None:
        self.assertEqual(_ap(self.survey, "14:cc:20:00:00:03").ssid, "Lab, Net")

    def test_station_probe_list_is_reassembled(self) -> None:
        station = self.survey.stations["00:1e:c2:aa:00:01"]
        self.assertEqual(station.probes, ["CorpWiFi", "Home Net", "Airport Free WiFi"])
        self.assertEqual(station.bssid, "00:0b:85:aa:bb:01")

    def test_not_associated_station_has_no_bssid(self) -> None:
        station = self.survey.stations["02:11:22:33:44:55"]
        self.assertEqual(station.bssid, "")
        self.assertTrue(station.randomized)

    def test_every_record_carries_its_source_row_and_raw_line(self) -> None:
        for ap in self.survey.ap_list():
            self.assertGreater(ap.source_row, 0)
            self.assertIn(ap.bssid.replace(":", "").upper()[:6], ap.raw_line.replace(":", "").upper())
            self.assertEqual(ap.source_path, "walk-01.csv")

    def test_mixed_cipher_is_preserved_in_the_raw_privacy_blob(self) -> None:
        lab = _ap(self.survey, "14:cc:20:00:00:03")
        self.assertIn("TKIP", lab.raw_privacy)
        self.assertEqual(lab.cipher, "ccmp")  # normalized keeps the strongest


class AirodumpTriStateTests(unittest.TestCase):
    """THE RELEASE BLOCKER: undetermined is not the same fact as absent."""

    def setUp(self) -> None:
        self.survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="walk-01.csv")
        self.result = wd_analyze.analyze_survey(self.survey)

    def test_airodump_leaves_wps_and_pmf_undetermined_on_every_ap(self) -> None:
        for ap in self.survey.ap_list():
            self.assertIsNone(ap.wps, f"{ap.bssid}: airodump cannot report WPS, so it must stay None")
            self.assertEqual(ap.pmf, "", f"{ap.bssid}: airodump cannot report PMF, so it must stay ''")

    def test_airodump_only_survey_emits_zero_wps_and_zero_pmf_findings(self) -> None:
        rule_ids = [f["rule_id"] for f in self.result["findings"]]
        self.assertEqual([r for r in rule_ids if "wps" in r], [])
        self.assertEqual([r for r in rule_ids if "pmf" in r], [])

    def test_the_undetermined_ledger_names_both_facts_and_the_capture_that_resolves_them(self) -> None:
        facts = {row["fact"]: row for row in self.result["undetermined"]}
        self.assertIn("wps", facts)
        self.assertIn("pmf", facts)
        self.assertEqual(facts["wps"]["ap_count"], 4)
        self.assertIn("kismet", facts["wps"]["resolved_by"].lower())
        self.assertIn("not_a_finding", facts["pmf"])

    def test_the_source_declares_it_cannot_report_wps_or_pmf(self) -> None:
        source = self.survey.sources[0]
        self.assertEqual(source["format"], "airodump-csv")
        self.assertFalse(source["reports_wps"])
        self.assertFalse(source["reports_pmf"])
        self.assertTrue(any("UNDETERMINED" in w for w in self.survey.warnings))


# --- WiGLE -------------------------------------------------------------------------


class WigleParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.survey = parsers.parse_wigle_csv(WIGLE_CSV, source_path="wigle.csv")

    def test_pre_header_then_real_header_and_wifi_only(self) -> None:
        self.assertEqual(parsers.detect_format(WIGLE_CSV, filename="wigle.csv"), "wigle-csv")
        self.assertEqual(len(self.survey.aps), 3)  # the BLE row is filtered out
        self.assertNotIn("aa:bb:cc:dd:ee:ff", self.survey.aps)

    def test_mfpr_becomes_pmf_required(self) -> None:
        sae = _ap(self.survey, "6c:f3:7f:00:00:02")
        self.assertEqual(sae.pmf, "required")
        self.assertEqual(sae.encryption, "wpa3")
        self.assertEqual(sae.auth, "sae")

    def test_wps_bracket_is_a_positive_observation(self) -> None:
        self.assertIs(_ap(self.survey, "14:cc:20:00:00:03").wps, True)

    def test_file_level_evidence_turns_absence_into_a_negative_observation(self) -> None:
        """WiGLE emits [WPS]/[MFPC] only where present, so a bare absence is ambiguous. When
        the marker appears SOMEWHERE in the file the exporter demonstrably writes it, which
        makes its absence elsewhere a real observation - reproducible from the export alone."""
        self.assertIs(_ap(self.survey, "00:0b:85:aa:bb:01").wps, False)
        self.assertEqual(_ap(self.survey, "00:0b:85:aa:bb:01").pmf, "disabled")

    def test_quoted_ssid_with_a_comma_survives(self) -> None:
        self.assertEqual(_ap(self.survey, "14:cc:20:00:00:03").ssid, "Home, Sweet Home")

    def test_wigle_survey_does_emit_wps_and_pmf_findings(self) -> None:
        """The mirror image of the airodump case: a format that CAN report these facts must
        actually produce the findings, or the tri-state rule would just be silence."""
        result = wd_analyze.analyze_survey(self.survey)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("wardrive.wps-enabled", rule_ids)
        self.assertIn("wardrive.pmf-absent", rule_ids)

    def test_pmf_finding_is_not_raised_for_the_wpa3_sae_bss(self) -> None:
        result = wd_analyze.analyze_survey(self.survey)
        pmf = [f for f in result["findings"] if f["rule_id"] == "wardrive.pmf-absent"]
        self.assertNotIn("6c:f3:7f:00:00:02", " ".join(f["location"] for f in pmf))


class WigleAuthModeTests(unittest.TestCase):
    def test_decodes_the_capability_brackets(self) -> None:
        cases = {
            "[WPA2-PSK-CCMP][ESS]": ("wpa2", "ccmp", "psk", "", None),
            "[RSN-SAE-CCMP][MFPR][MFPC][ESS]": ("wpa3", "ccmp", "sae", "required", None),
            "[WPA2-PSK-CCMP][MFPC][ESS]": ("wpa2", "ccmp", "psk", "optional", None),
            "[WPA2-PSK-CCMP][WPS][ESS]": ("wpa2", "ccmp", "psk", "", True),
            "[WEP][ESS]": ("wep", "wep", "", "", None),
            "[ESS]": ("open", "", "open", "", None),
        }
        for token, (enc, cipher, auth, pmf, wps) in cases.items():
            with self.subTest(token=token):
                parsed = parsers.parse_wigle_authmode(token)
                self.assertEqual(parsed["encryption"], enc)
                self.assertEqual(parsed["cipher"], cipher)
                self.assertEqual(parsed["auth"], auth)
                self.assertEqual(parsed["pmf"], pmf)
                self.assertIs(parsed["wps"], wps)


# --- Kismet ------------------------------------------------------------------------


class KismetNetxmlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.survey = parsers.parse_kismet_netxml(KISMET_NETXML, source_path="walk.netxml")

    def test_round_trip(self) -> None:
        self.assertEqual(parsers.detect_format(KISMET_NETXML, filename="walk.netxml"), "kismet-netxml")
        self.assertEqual(len(self.survey.aps), 2)
        corp = _ap(self.survey, "00:0b:85:aa:bb:01")
        self.assertEqual(corp.ssid, "CorpWiFi")
        self.assertEqual(corp.signal_dbm, -42)
        self.assertEqual(corp.vendor, "Cisco Systems")

    def test_wpa_plus_aes_ccm_is_wpa2_not_a_wpa1_finding(self) -> None:
        """Kismet's legacy netxml has NO WPA2 token - it writes `WPA` for both generations and
        separates them by cipher. Read literally, `WPA+AES-CCM` (an ordinary WPA2-CCMP network)
        decodes as WPA1 and earns a HIGH 'WPA1/TKIP in use' finding it does not deserve."""
        corp = _ap(self.survey, "00:0b:85:aa:bb:01")
        self.assertEqual(corp.encryption, "wpa2")
        self.assertEqual(corp.cipher, "ccmp")
        rule_ids = [f["rule_id"] for f in wd_analyze.analyze_survey(self.survey)["findings"]]
        self.assertNotIn("wardrive.wpa1-tkip", rule_ids)

    def test_a_tkip_only_network_is_still_wpa1(self) -> None:
        tkip = KISMET_NETXML.replace("<encryption>WPA+AES-CCM</encryption>",
                                     "<encryption>WPA+TKIP</encryption>")
        survey = parsers.parse_kismet_netxml(tkip, source_path="walk.netxml")
        self.assertEqual(_ap(survey, "00:0b:85:aa:bb:01").encryption, "wpa")
        rule_ids = [f["rule_id"] for f in wd_analyze.analyze_survey(survey)["findings"]]
        self.assertIn("wardrive.wpa1-tkip", rule_ids)

    def test_cloaked_essid_is_hidden(self) -> None:
        self.assertTrue(_ap(self.survey, "24:0a:c4:11:22:33").hidden)

    def test_wps_element_is_observed_and_its_absence_resolved_by_file_evidence(self) -> None:
        self.assertIs(_ap(self.survey, "00:0b:85:aa:bb:01").wps, True)
        self.assertIs(_ap(self.survey, "24:0a:c4:11:22:33").wps, False)

    def test_netxml_never_reports_pmf(self) -> None:
        for ap in self.survey.ap_list():
            self.assertEqual(ap.pmf, "")
        self.assertFalse(self.survey.sources[0]["reports_pmf"])

    def test_client_becomes_a_station_with_its_probe(self) -> None:
        station = self.survey.stations["00:1e:c2:aa:00:01"]
        self.assertEqual(station.bssid, "00:0b:85:aa:bb:01")
        self.assertEqual(station.probes, ["CorpWiFi"])

    def test_doctype_is_refused(self) -> None:
        hostile = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaa">]>'
                   "<detection-run><wireless-network><BSSID>00:0B:85:AA:BB:01</BSSID>"
                   "</wireless-network></detection-run>")
        survey = parsers.parse_kismet_netxml(hostile, source_path="hostile.netxml")
        self.assertEqual(len(survey.aps), 0)
        self.assertTrue(any("DOCTYPE" in w for w in survey.warnings))

    def test_truncated_document_recovers_the_complete_blocks(self) -> None:
        truncated = KISMET_NETXML[:KISMET_NETXML.index('<wireless-network number="2"') + 200]
        survey = parsers.parse_kismet_netxml(truncated, source_path="cut.netxml")
        self.assertEqual(len(survey.aps), 1)
        self.assertTrue(any("truncated" in w.lower() for w in survey.warnings))


class KismetCsvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.survey = parsers.parse_kismet_csv(KISMET_CSV, source_path="devices.csv")

    def test_alias_driven_column_mapping(self) -> None:
        """Kismet's CSV column names differ between releases, so the parser maps ALIASES
        rather than pretending to know one schema."""
        self.assertEqual(len(self.survey.aps), 2)  # the Bluetooth row is filtered by phyname
        corp = _ap(self.survey, "00:0b:85:aa:bb:01")
        self.assertEqual(corp.ssid, "CorpWiFi")
        self.assertEqual(corp.encryption, "wpa2")
        self.assertEqual(corp.signal_dbm, -42)
        self.assertEqual(corp.vendor, "Cisco Systems")

    def test_unmapped_columns_are_reported_not_silently_dropped(self) -> None:
        note = [w for w in self.survey.warnings if "could not be mapped" in w]
        self.assertTrue(note, self.survey.warnings)
        self.assertIn("seenby", note[0])
        self.assertIn("MEDIUM", note[0])
        self.assertIn("kismet.device.base.seenby", self.survey.sources[0]["unmapped_columns"])

    def test_unknown_schema_yields_a_warning_not_a_wrong_parse(self) -> None:
        survey = parsers.parse_kismet_csv("alpha,beta,gamma\n1,2,3\n", source_path="mystery.csv")
        self.assertEqual(len(survey.aps), 0)
        self.assertTrue(any("does not map" in w for w in survey.warnings))


# --- netsh -------------------------------------------------------------------------


class NetshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.survey = parsers.parse_netsh_text(NETSH_TEXT, source_path="netsh.txt")

    def test_round_trip_with_nested_bssid_blocks(self) -> None:
        self.assertEqual(parsers.detect_format(NETSH_TEXT, filename="netsh.txt"), "netsh-text")
        self.assertEqual(len(self.survey.aps), 3)
        self.assertEqual(_ap(self.survey, "00:0b:85:aa:bb:01").ssid, "CorpWiFi")
        self.assertEqual(_ap(self.survey, "00:0b:85:aa:bb:02").ssid, "CorpWiFi")
        self.assertEqual(_ap(self.survey, "00:0b:85:aa:bb:01").channel, 36)

    def test_percentage_signal_never_becomes_a_fabricated_dbm(self) -> None:
        corp = _ap(self.survey, "00:0b:85:aa:bb:01")
        self.assertEqual(corp.signal_pct, 84)
        self.assertIsNone(corp.signal_dbm)
        self.assertTrue(any("PERCENTAGE" in w for w in self.survey.warnings))

    def test_empty_ssid_value_is_a_hidden_network(self) -> None:
        self.assertTrue(_ap(self.survey, "24:0a:c4:11:22:33").hidden)
        self.assertEqual(_ap(self.survey, "24:0a:c4:11:22:33").encryption, "open")

    def test_netsh_reports_neither_wps_nor_pmf(self) -> None:
        for ap in self.survey.ap_list():
            self.assertIsNone(ap.wps)
            self.assertEqual(ap.pmf, "")
        result = wd_analyze.analyze_survey(self.survey)
        self.assertEqual([f for f in result["findings"] if "pmf" in f["rule_id"]], [])

    def test_localized_windows_yields_access_points_plus_a_warning_not_zero(self) -> None:
        """On a non-English Windows every LABEL is translated but the 'SSID <n>' / 'BSSID <n>'
        structure is not. Silently returning zero APs would be the worst outcome; a confident
        'open' would be worse still."""
        survey = parsers.parse_netsh_text(NETSH_TEXT_DE, source_path="netsh-de.txt")
        self.assertEqual(len(survey.aps), 1)
        ap = _ap(survey, "00:0b:85:aa:bb:01")
        self.assertEqual(ap.encryption, "unknown")
        self.assertEqual(ap.signal_pct, 90)
        localized = [w for w in survey.warnings if "not recognized" in w]
        self.assertTrue(localized, survey.warnings)
        self.assertIn("Authentifizierung", localized[0])
        facts = {row["fact"] for row in wd_analyze.analyze_survey(survey)["undetermined"]}
        self.assertIn("encryption", facts)

    def test_unknown_encryption_is_never_reported_as_open(self) -> None:
        survey = parsers.parse_netsh_text(NETSH_TEXT_DE, source_path="netsh-de.txt")
        rule_ids = [f["rule_id"] for f in wd_analyze.analyze_survey(survey)["findings"]]
        self.assertNotIn("wardrive.open-network", rule_ids)


# --- detectors ---------------------------------------------------------------------


class EvilTwinTests(unittest.TestCase):
    """The false-positive control is the whole detector."""

    def _survey(self, rows: list[tuple[str, str, str]]):
        from bughunter.wardrive.model import AccessPoint, Survey

        survey = Survey()
        for index, (bssid, ssid, privacy) in enumerate(rows, start=1):
            from bughunter.wardrive.model import normalize_privacy

            parsed = normalize_privacy(privacy)
            survey.add_ap(AccessPoint(
                bssid=bssid, ssid=ssid, channel=6, band="2.4GHz",
                encryption=parsed["encryption"], cipher=parsed["cipher"], auth=parsed["auth"],
                signal_dbm=-50, raw_privacy=privacy, source="airodump-csv",
                source_path="x.csv", source_row=index, raw_line=f"{bssid}, {ssid}, {privacy}"))
        return survey

    def test_band_steered_same_vendor_same_encryption_deployment_is_not_flagged(self) -> None:
        survey = self._survey([
            ("24:A4:3C:00:00:01", "CorpWiFi", "WPA2 CCMP PSK"),
            ("24:A4:3C:00:00:02", "CorpWiFi", "WPA2 CCMP PSK"),
            ("24:A4:3C:00:00:03", "CorpWiFi", "WPA2 CCMP PSK"),
            ("24:A4:3C:00:00:04", "CorpWiFi", "WPA2 CCMP PSK"),
        ])
        rule_ids = [f["rule_id"] for f in wd_analyze.analyze_survey(survey)["findings"]]
        self.assertNotIn("wardrive.evil-twin", rule_ids)

    def test_one_open_bssid_from_a_different_vendor_is_a_high_candidate(self) -> None:
        survey = self._survey([
            ("24:A4:3C:00:00:01", "CorpWiFi", "WPA2 CCMP PSK"),
            ("24:A4:3C:00:00:02", "CorpWiFi", "WPA2 CCMP PSK"),
            ("24:0A:C4:99:99:99", "CorpWiFi", "OPN"),
        ])
        twins = [f for f in wd_analyze.analyze_survey(survey)["findings"]
                 if f["rule_id"] == "wardrive.evil-twin"]
        self.assertEqual(len(twins), 1)
        self.assertEqual(twins[0]["severity"], "high")
        self.assertIn("DIFFERENT encryption", twins[0]["proof_evidence"]["matched_value"])
        self.assertIn("FALSE-POSITIVE CONTROL", twins[0]["remediation"])

    def test_a_locally_administered_twin_alone_is_only_a_medium_candidate(self) -> None:
        survey = self._survey([
            ("24:A4:3C:00:00:01", "CorpWiFi", "WPA2 CCMP PSK"),
            ("02:A4:3C:00:00:02", "CorpWiFi", "WPA2 CCMP PSK"),
        ])
        twins = [f for f in wd_analyze.analyze_survey(survey)["findings"]
                 if f["rule_id"] == "wardrive.evil-twin"]
        self.assertEqual(len(twins), 1)
        self.assertEqual(twins[0]["severity"], "medium")

    def test_undetermined_vendors_are_not_counted_as_divergence(self) -> None:
        # Both prefixes are outside the curated table AND globally administered, so there is
        # no observable divergence at all - an unknown vendor is not evidence of anything.
        survey = self._survey([
            ("00:AB:C0:00:00:01", "CorpWiFi", "WPA2 CCMP PSK"),
            ("00:AB:C4:00:00:02", "CorpWiFi", "WPA2 CCMP PSK"),
        ])
        rule_ids = [f["rule_id"] for f in wd_analyze.analyze_survey(survey)["findings"]]
        self.assertNotIn("wardrive.evil-twin", rule_ids)


class RogueApTests(unittest.TestCase):
    def test_no_inventory_means_no_rogue_verdict(self) -> None:
        survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="w.csv")
        rule_ids = [f["rule_id"] for f in wd_analyze.analyze_survey(survey)["findings"]]
        self.assertNotIn("wardrive.rogue-ap", rule_ids)

    def test_unlisted_bssid_on_an_authorized_ssid_is_high(self) -> None:
        survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="w.csv")
        inventory = {"bssids": ["00:0B:85:AA:BB:01"], "ssids": ["CorpWiFi", "Lab, Net"]}
        result = wd_analyze.analyze_survey(survey, authorized=inventory)
        rogue = [f for f in result["findings"] if f["rule_id"] == "wardrive.rogue-ap"]
        self.assertEqual(len(rogue), 1)
        self.assertEqual(rogue[0]["severity"], "high")
        self.assertIn("14:cc:20:00:00:03", rogue[0]["location"])

    def test_a_malformed_inventory_does_not_turn_the_street_into_rogues(self) -> None:
        survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="w.csv")
        for bad in ({"bssids": [], "ssids": []}, {"nonsense": 1}, [], "", None,
                    {"bssids": 7}, {"bssids": [1, None, ["nested"]], "ssids": [2]},
                    {"aps": [{"no_bssid": "x"}]}, 42):
            with self.subTest(inventory=bad):
                result = wd_analyze.analyze_survey(survey, authorized=bad)
                self.assertEqual([f for f in result["findings"] if f["rule_id"] == "wardrive.rogue-ap"], [])


class FindingShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="walk-01.csv")
        parsers.parse_wigle_csv(WIGLE_CSV, source_path="wigle.csv", survey=survey)
        parsers.parse_netsh_text(NETSH_TEXT, source_path="netsh.txt", survey=survey)
        self.result = wd_analyze.analyze_survey(survey)

    def test_every_severity_is_one_the_core_report_can_render(self) -> None:
        for finding in self.result["findings"]:
            self.assertIn(finding["severity"], core_report._SEVERITY_ORDER,
                          f"{finding['rule_id']} would sort as unknown and print uncolored")

    def test_every_finding_cites_verbatim_evidence_its_format_and_its_source_row(self) -> None:
        self.assertTrue(self.result["findings"])
        for finding in self.result["findings"]:
            self.assertTrue(finding["evidence"], f"{finding['rule_id']} carries no evidence token")
            for fmt in str(finding["source_format"]).split(", "):  # a merged BSS names every source
                self.assertIn(fmt, parsers.FORMATS)
            self.assertGreaterEqual(finding["line_start"], 1)
            self.assertTrue(finding["rule_id"].startswith("wardrive."))
            self.assertTrue(finding["verification_obligation"])
            self.assertTrue(finding["cwe"])

    def test_findings_are_deterministically_ordered(self) -> None:
        again = wd_analyze.analyze_survey(self._rebuild())
        self.assertEqual([(f["rule_id"], f["location"]) for f in self.result["findings"]],
                         [(f["rule_id"], f["location"]) for f in again["findings"]])

    def _rebuild(self):
        survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="walk-01.csv")
        parsers.parse_wigle_csv(WIGLE_CSV, source_path="wigle.csv", survey=survey)
        parsers.parse_netsh_text(NETSH_TEXT, source_path="netsh.txt", survey=survey)
        return survey

    def test_merging_across_formats_fills_a_fact_only_one_format_knew(self) -> None:
        """The airodump row for 00:0b:85:aa:bb:01 cannot say anything about WPS; the WiGLE
        row for the same BSSID can. Identity merging is what carries that across."""
        survey = self._rebuild()
        self.assertIs(survey.aps["00:0b:85:aa:bb:01"].wps, False)
        self.assertEqual(survey.aps["00:0b:85:aa:bb:01"].pmf, "disabled")

    def test_a_merged_finding_quotes_the_export_that_could_see_the_fact(self) -> None:
        """A BSS first seen in an airodump CSV and later in a WiGLE export keeps airodump's
        privacy blob as raw_privacy - a token that by construction says NOTHING about WPS.
        The WPS/PMF findings must quote WiGLE's AuthMode instead, or the evidence field would
        point at bytes that cannot support the claim."""
        survey = self._rebuild()
        merged = survey.aps["14:cc:20:00:00:03"]
        self.assertIn("TKIP", merged.raw_privacy)          # airodump supplied this
        self.assertIn("[WPS]", merged.capability_evidence)  # WiGLE supplied this
        result = wd_analyze.analyze_survey(survey)
        wps = [f for f in result["findings"]
               if f["rule_id"] == "wardrive.wps-enabled" and "14:cc:20" in f["location"]]
        self.assertEqual(len(wps), 1)
        self.assertIn("[WPS]", wps[0]["evidence"])
        self.assertNotIn("TKIP", wps[0]["evidence"])

    def test_wpa3_pmf_is_an_inference_and_stays_out_of_findings(self) -> None:
        survey = parsers.parse_wigle_csv(
            WIGLE_CSV.replace("[RSN-SAE-CCMP][MFPR][MFPC][ESS]", "[RSN-SAE-CCMP][ESS]")
                     .replace("[WPA2-PSK-CCMP][WPS][ESS]", "[WPA2-PSK-CCMP][ESS]"),
            source_path="wigle.csv")
        result = wd_analyze.analyze_survey(survey)
        inferred = [row for row in result["inferences"] if row["bssid"] == "6c:f3:7f:00:00:02"]
        self.assertEqual(len(inferred), 1)
        self.assertEqual(inferred[0]["value"], "required")
        self.assertEqual(inferred[0]["basis"], "INFERRED")
        self.assertNotIn("6c:f3:7f:00:00:02", " ".join(f["location"] for f in result["findings"]
                                                       if f["rule_id"] == "wardrive.pmf-absent"))


class ClientExposureTests(unittest.TestCase):
    def test_probe_list_is_reported_as_a_client_exposure(self) -> None:
        survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="w.csv")
        probes = [f for f in wd_analyze.analyze_survey(survey)["findings"]
                  if f["rule_id"] == "wardrive.probe-exposure"]
        self.assertEqual(len(probes), 1)
        self.assertIn("Airport Free WiFi", probes[0]["evidence"])
        self.assertEqual(probes[0]["severity"], "medium")  # 3 named networks

    def test_non_randomized_client_is_flagged_as_trackable(self) -> None:
        survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="w.csv")
        trackable = [f for f in wd_analyze.analyze_survey(survey)["findings"]
                     if f["rule_id"] == "wardrive.trackable-client"]
        self.assertEqual(len(trackable), 1)
        self.assertIn("00:1e:c2:aa:00:01", trackable[0]["evidence"])
        self.assertNotIn("02:11:22:33:44:55", trackable[0]["evidence"])


# --- capability provenance ----------------------------------------------------------


class CapabilityProvenanceTests(unittest.TestCase):
    """THE cross-format release blocker: a WPS/PMF verdict, its evidence, its file, its line
    and its snippet must all come from an export that could actually OBSERVE that capability.

    Before capability facts carried their own provenance, a merged record kept the FIRST
    file's path/row/raw_line while a LATER file supplied the value, and the file-level
    "absence" inference was stamped onto the canonical record regardless of which format had
    created it. A directory holding an airodump-ng CSV and a WiGLE CSV of the same walk then
    produced a medium `802.11w not advertised` finding located at an airodump row, quoting
    airodump's `WPA2 CCMP PSK` blob as its evidence - printed directly above the same run's
    note that airodump "carr[ies] neither WPS state nor RSN capability bits". Every test
    here is that class of fabrication, and every one is checked in BOTH merge orders because
    the bug's other half was that the answer depended on filename sort order."""

    def _survey_for(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp:
            root = _write_dir(tmp, files)
            return parsers.load_survey([str(root)])

    def _both_merge_orders(self, a: tuple[str, str], b: tuple[str, str]):
        """The same two exports parsed in both orders (``load_survey`` walks ``sorted()``)."""
        for first, second in ((a, b), (b, a)):
            files = {f"01-{first[0]}": first[1], f"02-{second[0]}": second[1]}
            yield f"{first[0]} then {second[0]}", self._survey_for(files)

    def _pairs(self):
        return (
            (("airodump.csv", AIRODUMP_ONE), ("wigle.csv", WIGLE_EMPTY_AUTHMODE)),
            (("airodump.csv", AIRODUMP_ONE), ("wigle.csv", WIGLE_NO_MFP)),
            (("airodump.csv", AIRODUMP_ONE), ("kismet.netxml", NETXML_ONE_WPS)),
            (("airodump.csv", AIRODUMP_ONE), ("kismet.csv", KISMET_CSV_NO_WPS_COLUMN)),
            (("airodump.csv", AIRODUMP_ONE), ("kismet.csv", KISMET_CSV_WPS_COLUMN)),
            (("kismet.netxml", NETXML_ONE_WPS), ("wigle.csv", WIGLE_NO_MFP)),
            (("netsh.txt", NETSH_TEXT), ("wigle.csv", WIGLE_NO_MFP)),
        )

    def _assert_citations_are_observable(self, survey, result) -> None:
        from bughunter.wardrive.model import format_can_observe

        fmt_of_path = {str(src.get("path")): str(src.get("format")) for src in survey.sources}
        for finding in result["findings"]:
            fact = {"wardrive.wps-enabled": "wps", "wardrive.pmf-absent": "pmf"}.get(finding["rule_id"])
            if not fact:
                continue
            cited_format = finding["source_format"]
            self.assertTrue(
                format_can_observe(cited_format, fact),
                f"{finding['rule_id']} is stamped source_format={cited_format!r}, a format that "
                f"cannot observe {fact.upper()}: {finding['evidence']!r}")
            cited_path = finding["location"].split("#")[0]
            self.assertEqual(
                fmt_of_path.get(cited_path), cited_format,
                f"{finding['rule_id']} cites {cited_path!r}, which was not parsed as "
                f"{cited_format!r} - a reader grepping it lands on unrelated bytes")
            # The evidence must be bytes of the line it is filed under: "grep the export and
            # land on the same bytes" is the basis on which the analyzer asserts anything.
            self.assertIn(finding["evidence"], finding["snippet"] or finding["evidence"],
                          f"{finding['rule_id']}: the quoted evidence {finding['evidence']!r} does "
                          f"not appear in the quoted line {finding['snippet']!r}")

    def test_a_wps_or_pmf_finding_only_ever_cites_an_export_that_can_observe_it(self) -> None:
        for a, b in self._pairs():
            for order, survey in self._both_merge_orders(a, b):
                with self.subTest(pair=f"{a[0]}+{b[0]}", order=order):
                    self._assert_citations_are_observable(survey, wd_analyze.analyze_survey(survey))

    def test_an_empty_capability_cell_never_becomes_a_negative_verdict(self) -> None:
        """A WiGLE row whose AuthMode cell is empty - the routine shape of a torn or
        truncated export - recorded NOTHING about that BSS. Reading it as "PMF disabled"
        because a different row in the file carried [MFPC] invents a determination, drops the
        BSS out of the undetermined ledger, and (after a merge) cites another file's row as
        the proof."""
        for order, survey in self._both_merge_orders(("airodump.csv", AIRODUMP_ONE),
                                                     ("wigle.csv", WIGLE_EMPTY_AUTHMODE)):
            with self.subTest(order=order):
                ap = _ap(survey, MERGE_BSSID)
                self.assertIsNone(ap.wps, "an empty AuthMode cell observed nothing about WPS")
                self.assertEqual(ap.pmf, "", "an empty AuthMode cell observed nothing about PMF")
                self.assertIsNone(ap.pmf_fact)
                result = wd_analyze.analyze_survey(survey)
                # The sibling BSS in the same file DOES carry [MFPC][WPS] and is expected to
                # produce findings; the subject BSS, whose own cell was empty, must not.
                self.assertEqual([f["rule_id"] for f in result["findings"]
                                  if MERGE_BSSID in f["location"]
                                  and ("wps" in f["rule_id"] or "pmf" in f["rule_id"])], [])
                facts = {row["fact"] for row in result["undetermined"]}
                self.assertIn("pmf", facts, "the honest undetermined row must survive")
                self.assertIn("wps", facts)

    def test_merge_order_never_changes_a_verdict(self) -> None:
        """Filename sort order decided WPS and PMF before this: `walk-day1` then `walk-day2`
        gave wps=False, the reverse gave wps=True, from the same two files."""
        for a, b in self._pairs() + ((("day1.csv", WIGLE_WALK_DAY1), ("day2.csv", WIGLE_WALK_DAY2)),):
            verdicts = []
            for order, survey in self._both_merge_orders(a, b):
                result = wd_analyze.analyze_survey(survey)
                verdicts.append((order, {b: (ap.wps, ap.pmf) for b, ap in sorted(survey.aps.items())},
                                 _rules(result),
                                 sorted((f["rule_id"], f["evidence"]) for f in result["findings"])))
            with self.subTest(pair=f"{a[0]}+{b[0]}"):
                self.assertEqual(verdicts[0][1], verdicts[1][1],
                                 f"{verdicts[0][0]} and {verdicts[1][0]} disagree about the facts")
                self.assertEqual(verdicts[0][2], verdicts[1][2], "the findings depend on merge order")
                self.assertEqual(verdicts[0][3], verdicts[1][3], "the evidence depends on merge order")

    def test_a_direct_mfpr_observation_outranks_an_earlier_inferred_absence(self) -> None:
        """`_apply_capability_evidence` turns a per-row absence into `pmf="disabled"`, which is
        an INFERENCE. A second export carrying [MFPR] verbatim for the same BSSID is a DIRECT
        observation and must win regardless of which file was parsed first - the old
        fill-if-blank merge kept the inference and emitted a finding asserting the opposite of
        data the same survey had parsed."""
        for order, survey in self._both_merge_orders(("day1.csv", WIGLE_WALK_DAY1),
                                                     ("day2.csv", WIGLE_WALK_DAY2)):
            with self.subTest(order=order):
                ap = _ap(survey, "00:aa:bb:cc:dd:03")
                self.assertEqual(ap.pmf, "required")
                self.assertEqual(ap.pmf_fact.basis, "direct")
                self.assertIn("[MFPR]", ap.pmf_fact.evidence)
                result = wd_analyze.analyze_survey(survey)
                pmf = [f for f in result["findings"] if f["rule_id"] == "wardrive.pmf-absent"]
                self.assertEqual([f["location"] for f in pmf if "dd:03" in f["location"]], [])

    def test_a_direct_wps_token_outranks_an_earlier_inferred_false(self) -> None:
        """Same inversion on WPS, with a second consequence: `report._tri(False)` prints the
        inventory row as **disabled**, a positive assertion the export contradicts."""
        for order, survey in self._both_merge_orders(("day1.csv", WIGLE_WALK_DAY1),
                                                     ("day2.csv", WIGLE_WALK_DAY2)):
            with self.subTest(order=order):
                ap = _ap(survey, "00:aa:bb:cc:dd:03")
                self.assertIs(ap.wps, True)
                self.assertEqual(ap.wps_fact.basis, "direct")
                result = wd_analyze.analyze_survey(survey)
                wps = [f for f in result["findings"]
                       if f["rule_id"] == "wardrive.wps-enabled" and "dd:03" in f["location"]]
                self.assertEqual(len(wps), 1, "the observed [WPS] must reach the findings")
                self.assertIn("[WPS]", wps[0]["evidence"])
                markdown = wd_report.build_rf_markdown(
                    result, ctx={"access_points": [a.to_dict() for a in survey.ap_list()]})
                row = [line for line in markdown.splitlines() if "00:aa:bb:cc:dd:03" in line]
                self.assertTrue(row)
                self.assertNotIn("| disabled |", row[0],
                                 "the inventory prints 'disabled' for a BSS the export says has WPS on")

    def test_kismet_csv_takes_wps_only_from_the_dedicated_column(self) -> None:
        """A Kismet Encryption cell reading `RSN{PSK,CCMP} WPS` is not a WPS observation - the
        schema variant has no WPS column at all, the source row reports `reports_wps: false`,
        and the parser had no capability token to cite, so the HIGH finding it raised quoted
        whatever privacy blob another export had contributed."""
        survey = self._survey_for({"01-airodump.csv": AIRODUMP_ONE,
                                   "03-kismet.csv": KISMET_CSV_NO_WPS_COLUMN})
        ap = _ap(survey, MERGE_BSSID)
        self.assertIsNone(ap.wps)
        self.assertIsNone(ap.wps_fact)
        result = wd_analyze.analyze_survey(survey)
        self.assertEqual([r for r in _rules(result) if "wps" in r], [])
        self.assertIn("wps", {row["fact"] for row in result["undetermined"]})
        self.assertFalse(any(src["reports_wps"] for src in survey.sources))

    def test_a_wps_column_is_still_read_and_is_attributed_to_kismet_csv(self) -> None:
        """The mirror image: where the export DOES carry the column the fact must land, with
        kismet-csv named as the observer."""
        survey = parsers.parse_kismet_csv(KISMET_CSV_WPS_COLUMN, source_path="devices.csv")
        ap = _ap(survey, MERGE_BSSID)
        self.assertIs(ap.wps, True)
        self.assertEqual(ap.wps_fact.observed_by, "kismet-csv")
        self.assertEqual(ap.wps_fact.evidence, "Configured")
        self.assertIn(ap.wps_fact.evidence, ap.wps_fact.raw_line, "evidence must be verbatim bytes")

    def test_a_negative_wps_spelling_is_never_read_as_a_positive(self) -> None:
        """`NO_WPS`, `WPS=0` and `WPS: disabled` all CONTAIN the substring "WPS"; the bare
        substring test ran first, so the negative branch was unreachable and bytes saying WPS
        is off produced a HIGH "WPS enabled" finding quoting those very bytes."""
        for blob in ("WPA2-PSK NO_WPS", "WPA2 PSK WPS=0", "WPA2 PSK WPS: disabled",
                     "WPA2-PSK no-wps", "WPA2-PSK NO WPS"):
            with self.subTest(blob=blob):
                self.assertIs(parsers.normalize_privacy(blob)["wps"], False)
        self.assertIs(parsers.normalize_privacy("WPA2-PSK WPS")["wps"], True)

    def test_kismet_netxml_never_supplies_pmf_evidence(self) -> None:
        """netxml carries no RSN capability bits at all, so it must not claim the capability
        slot: it used to pass its whole record as generic capability evidence, first-writer
        wins, and a PMF verdict decided by a WiGLE AuthMode was then reported quoting an XML
        fragment that contains no MFP marker of any kind."""
        for order, survey in self._both_merge_orders(("kismet.netxml", NETXML_ONE_WPS),
                                                     ("wigle.csv", WIGLE_NO_MFP)):
            with self.subTest(order=order):
                ap = _ap(survey, MERGE_BSSID)
                self.assertEqual(ap.pmf, "disabled")
                self.assertEqual(ap.pmf_fact.observed_by, "wigle-csv")
                self.assertNotIn("<encryption>", ap.pmf_fact.evidence)
                result = wd_analyze.analyze_survey(survey)
                pmf = [f for f in result["findings"] if f["rule_id"] == "wardrive.pmf-absent"]
                self.assertEqual(len(pmf), 1)
                self.assertEqual(pmf[0]["source_format"], "wigle-csv")
                self.assertIn("[WPA2-PSK-CCMP][ESS]", pmf[0]["evidence"])
                self.assertNotIn("<BSSID>", pmf[0]["snippet"])

    def test_the_finding_line_and_snippet_belong_to_the_observing_export(self) -> None:
        """`_build_rf_finding` took snippet/location/line_start from the merged record, so a
        WPS finding told the reader to verify it at line 2 of an airodump-ng CSV."""
        survey = self._survey_for({"01-air.csv": AIRODUMP_ONE, "02-kismet.netxml": NETXML_ONE_WPS})
        result = wd_analyze.analyze_survey(survey)
        wps = [f for f in result["findings"] if f["rule_id"] == "wardrive.wps-enabled"]
        self.assertEqual(len(wps), 1)
        self.assertTrue(wps[0]["location"].split("#")[0].endswith("02-kismet.netxml"))
        self.assertEqual(wps[0]["file_path"], wps[0]["location"])
        self.assertIn("<wps>", wps[0]["snippet"])
        self.assertIn("<wps>", wps[0]["proof_evidence"]["request_line"])
        self.assertNotIn("CCMP, PSK", wps[0]["snippet"])

    def test_a_capability_value_from_a_format_that_cannot_observe_it_is_dropped(self) -> None:
        """The choke point, tested directly: a record that claims PMF while naming a format
        with no RSN capability bits keeps NO value at all. Fail closed - an unattributable
        value is not one this package is allowed to assert."""
        from bughunter.wardrive.model import AccessPoint

        ap = AccessPoint(bssid="aa:bb:cc:00:00:01", encryption="wpa2", pmf="disabled", wps=True,
                         source="airodump-csv", source_path="w.csv", source_row=2, raw_line="x")
        self.assertEqual(ap.pmf, "")
        self.assertIsNone(ap.pmf_fact)
        self.assertIsNone(ap.wps)
        self.assertIsNone(ap.wps_fact)
        wigle = AccessPoint(bssid="aa:bb:cc:00:00:01", encryption="wpa2", pmf="disabled",
                            source="wigle-csv", source_path="w.csv", source_row=3, raw_line="y")
        self.assertEqual(wigle.pmf, "disabled")  # a format that CAN observe keeps it

    def test_two_disagreeing_direct_observations_are_reported_not_silently_resolved(self) -> None:
        """Two exports of the same site can honestly disagree (the state changed between
        captures). The winner is deterministic, and the operator is told which reading the
        finding cites rather than the loser vanishing."""
        netxml_off = NETXML_ONE_WPS.replace("<wps>Configured</wps>", "<wps>No</wps>")
        for order, survey in self._both_merge_orders(("kismet.netxml", netxml_off),
                                                     ("wigle.csv", WIGLE_EMPTY_AUTHMODE.replace(
                                                         "AA:BB:CC:00:00:01,CorpNet,,",
                                                         "AA:BB:CC:00:00:01,CorpNet,[WPA2-PSK-CCMP][WPS][ESS],"))):
            with self.subTest(order=order):
                ap = _ap(survey, MERGE_BSSID)
                self.assertIs(ap.wps, True)
                self.assertEqual(ap.wps_fact.observed_by, "wigle-csv")
                self.assertTrue(any("disagree about WPS" in w for w in survey.warnings),
                                survey.warnings)


class SoftApEvidenceTests(unittest.TestCase):
    """`evidence` is defined as the verbatim token THE VERDICT came from."""

    def _finding(self, bssid: str, ssid: str):
        from bughunter.wardrive.model import AccessPoint, Survey

        survey = Survey()
        survey.add_ap(AccessPoint(bssid=bssid, ssid=ssid, encryption="wpa2", cipher="ccmp",
                                  raw_privacy="WPA2 CCMP PSK", source="airodump-csv",
                                  source_path="walk.csv", source_row=2,
                                  raw_line=f"{bssid}, ..., WPA2, CCMP, PSK, ..., {ssid},"))
        soft = [f for f in wd_analyze.analyze_survey(survey)["findings"]
                if f["rule_id"] == "wardrive.soft-ap"]
        self.assertEqual(len(soft), 1, ssid)
        return soft[0]

    def test_an_ssid_derived_verdict_quotes_the_ssid_not_a_curated_enterprise_oui(self) -> None:
        """A Cisco OUI is evidence AGAINST a soft-AP claim, yet it was quoted as the proof of
        one: the guard tested the vendor class rather than which branch produced the verdict,
        and every class except `unknown` took the BSSID branch."""
        finding = self._finding("00:0B:85:11:22:33", "iPhone")  # Cisco Systems / enterprise-ap
        self.assertIn("the SSID matches", finding["proof_evidence"]["matched_value"])
        self.assertEqual(finding["evidence"], "iPhone")
        self.assertNotEqual(finding["evidence"], "00:0b:85:11:22:33")

    def test_a_bssid_derived_verdict_still_quotes_the_bssid(self) -> None:
        finding = self._finding("02:0B:85:11:22:33", "PlainName")  # locally administered
        self.assertIn("locally-administered", finding["proof_evidence"]["matched_value"])
        self.assertEqual(finding["evidence"], "02:0b:85:11:22:33")


class ByteOrderMarkTests(unittest.TestCase):
    """A UTF-8 BOM is what Windows tools actually emit (Excel, Notepad, `Out-File -Encoding
    utf8BOM`, a PowerShell concat of split captures). U+FEFF is not whitespace to
    `str.strip()`, so an un-stripped BOM made airodump's `BSSID,` section header unmatchable:
    every AP row was skipped as headerless while the station section still parsed, and a
    CRITICAL WEP finding disappeared from the assessment."""

    def test_a_bom_does_not_cost_the_airodump_access_point_section(self) -> None:
        plain = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="walk-01.csv")
        bommed = parsers.parse_airodump_csv("﻿" + AIRODUMP_CSV, source_path="walk-01.csv")
        self.assertEqual(len(bommed.aps), len(plain.aps))
        self.assertEqual(len(bommed.aps), 4)
        self.assertEqual(_rules(wd_analyze.analyze_survey(bommed)),
                         _rules(wd_analyze.analyze_survey(plain)))
        self.assertIn("wardrive.wep", _rules(wd_analyze.analyze_survey(bommed)))

    def test_a_bom_does_not_mis_route_format_detection(self) -> None:
        for fmt, text in (("airodump-csv", AIRODUMP_CSV), ("wigle-csv", WIGLE_CSV),
                          ("kismet-netxml", KISMET_NETXML), ("kismet-csv", KISMET_CSV),
                          ("netsh-text", NETSH_TEXT)):
            with self.subTest(fmt=fmt):
                self.assertEqual(parsers.detect_format("﻿" + text, filename="x.csv"), fmt)
                survey = parsers.parse_survey_text("﻿" + text, source_path="x.csv")
                self.assertEqual(survey.sources[0]["format"], fmt)
                self.assertTrue(survey.aps)

    def test_a_bom_prefixed_file_read_from_disk_parses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "walk-01.csv"
            path.write_text(AIRODUMP_CSV, encoding="utf-8-sig")
            # The reader itself must hand on BOM-free text, so a caller that bypasses the
            # parsers' own guard still sees the same bytes the export claims to contain.
            text, warning = parsers._read_export(path)
            self.assertEqual(warning, "")
            self.assertFalse(text.startswith("﻿"), "_read_export must decode the BOM away")
            survey = parsers.load_survey([str(path)])
            self.assertEqual(len(survey.aps), 4)


class NetshLabelTests(unittest.TestCase):
    """The localization claim is a statement about the OPERATOR'S MACHINE, so it needs
    evidence. Current Windows 11 emits Bss Load / QoS / rate labels the table had never
    heard of, and every one of them was turned into "this looks like a LOCALIZED
    (non-English) Windows" - written into the client deliverable, on an English capture."""

    def test_current_windows_11_labels_are_recognized_and_no_localization_is_claimed(self) -> None:
        survey = parsers.parse_netsh_text(NETSH_WIN11_ENGLISH, source_path="netsh.txt")
        self.assertEqual(len(survey.aps), 1)
        ap = _ap(survey, "00:0b:85:aa:bb:01")
        self.assertEqual(ap.encryption, "wpa2")
        self.assertEqual(ap.channel, 48)
        notes = " | ".join(survey.warnings)
        for label in ("Bss Load", "Connected Stations", "Channel Utilization",
                      "Medium Available Capacity", "QoS MSCS Supported", "QoS Map Supported",
                      "Basic rates", "Other rates"):
            self.assertNotIn(label, notes,
                             f"{label!r} is ordinary English Windows 11 output, not an unknown label")
        self.assertNotIn("LOCALIZED", notes, "an English Windows 11 capture is not localized")
        self.assertNotIn("not recognized", notes)
        report = wd_report.build_rf_markdown(wd_analyze.analyze_survey(survey))
        self.assertNotIn("LOCALIZED", report)

    def test_a_unit_suffix_on_a_rate_label_is_not_an_unknown_label(self) -> None:
        for label in ("Basic rates (Mbps)", "Other rates (Mbps)", "Basic transfer rates (Mbps)"):
            with self.subTest(label=label):
                text = NETSH_TEXT.replace("         Radio type         : 802.11ac",
                                          f"         {label}         : 6 12 24")
                survey = parsers.parse_netsh_text(text, source_path="netsh.txt")
                self.assertFalse([w for w in survey.warnings if "not recognized" in w], survey.warnings)

    def test_a_genuinely_localized_capture_is_still_called_out(self) -> None:
        """The other half of the honesty rule: when NONE of the core English labels decoded,
        the export really is unreadable and saying so is an observation, not a guess."""
        survey = parsers.parse_netsh_text(NETSH_TEXT_DE, source_path="netsh-de.txt")
        localized = [w for w in survey.warnings if "LOCALIZED" in w]
        self.assertTrue(localized, survey.warnings)
        self.assertIn("Authentifizierung", localized[0])
        self.assertIn("none of the core English labels", localized[0])

    def test_an_unknown_label_alongside_english_ones_is_reported_without_a_locale_claim(self) -> None:
        text = NETSH_TEXT.replace("         Band               : 5 GHz",
                                  "         Sproingle Factor   : 7")
        survey = parsers.parse_netsh_text(text, source_path="netsh.txt")
        note = [w for w in survey.warnings if "Sproingle Factor" in w]
        self.assertTrue(note, survey.warnings)
        self.assertNotIn("LOCALIZED", note[0])
        self.assertIn("NOT evidence of a localized Windows", note[0])


class SurveyWalkTests(unittest.TestCase):
    """`load_survey`'s contract is "one bad file must not stop the other exports". The
    directory walk was the one part of it with no guard: `Path.rglob` FOLLOWS a Windows
    directory junction (only true symlinks are skipped) and lets `FileNotFoundError` escape
    once the path passes MAX_PATH, so a junction cycle - or any archive subtree deeper than
    MAX_PATH - discarded the whole assessment including files sitting at short paths."""

    def test_a_junction_cycle_does_not_abort_the_survey(self) -> None:
        if os.name != "nt":
            self.skipTest("directory junctions are a Windows construct")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture"
            (root / "sub").mkdir(parents=True)
            (root / "walk-01.csv").write_text(AIRODUMP_CSV, encoding="utf-8")
            link = root / "sub" / "back"
            made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(root)],
                                  capture_output=True, text=True, timeout=60)
            if made.returncode != 0 or not link.exists():
                self.skipTest(f"could not create a junction: {made.stdout}{made.stderr}")
            try:
                survey = parsers.load_survey([str(root)])
                self.assertEqual(len(survey.aps), 4, "the readable export must still be parsed")
                self.assertEqual([Path(s["path"]).name for s in survey.sources], ["walk-01.csv"])
                self.assertTrue(any("junction" in w for w in survey.warnings), survey.warnings)
                self.assertTrue(wd_analyze.analyze_survey(survey)["ok"])
            finally:
                # Remove the junction itself, never its target: rmtree descends junctions.
                os.rmdir(link)

    def test_an_unreadable_subtree_costs_that_subtree_and_nothing_else(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture"
            root.mkdir()
            (root / "walk-01.csv").write_text(AIRODUMP_CSV, encoding="utf-8")
            (root / "archive").mkdir()

            class _ExplodingOs:
                """Only the parsers module's own `os` name is rebound, so nothing else in the
                process sees this. WinError 3 is what a past-MAX_PATH subtree really raises."""

                path = os.path

                @staticmethod
                def scandir(target):
                    if str(target).endswith("archive"):
                        raise OSError(3, "The system cannot find the path specified")
                    return os.scandir(target)

            parsers.os = _ExplodingOs  # type: ignore[assignment]
            try:
                survey = parsers.load_survey([str(root)])
            finally:
                parsers.os = os  # type: ignore[assignment]
            self.assertEqual(len(survey.aps), 4)
            self.assertTrue(any("subtree skipped" in w for w in survey.warnings), survey.warnings)

    def test_the_walk_depth_cap_is_reported_never_silent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "c"
            root.mkdir()
            (root / "walk-01.csv").write_text(AIRODUMP_CSV, encoding="utf-8")
            deep = root
            for _ in range(parsers._MAX_WALK_DEPTH + 2):
                deep = deep / "d"
            deep.mkdir(parents=True)
            (deep / "buried.csv").write_text(AIRODUMP_CSV, encoding="utf-8")
            survey = parsers.load_survey([str(root)])
            self.assertEqual([Path(s["path"]).name for s in survey.sources], ["walk-01.csv"])
            self.assertTrue(any("walk cap" in w for w in survey.warnings), survey.warnings)


class RuntimeTableWiringTests(unittest.TestCase):
    """`<runtime>/rf/oui.tsv` is tier 2 of the documented three-tier design, and the report
    prints "add the prefix to <runtime>/rf/oui.tsv" as the remediation for every undetermined
    vendor - while `_cmd_wardrive` passed neither seed_dir nor runtime_dir, so the file was
    never read. A deliverable must not hand the client a step that provably does nothing."""

    AIRODUMP_UNKNOWN_VENDOR = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication,"
        " Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "40:B0:34:11:22:33, 2026-01-01 10:00:00, 2026-01-01 10:05:00,  6,  130, WPA2, CCMP, PSK,"
        " -55,      40,        0,   0.  0.  0.  0,   6, SiteAP, \n"
    )

    def test_the_command_passes_the_seed_and_runtime_dirs_to_the_analyzer(self) -> None:
        import gn_cli

        captured: dict[str, object] = {}
        real = wd_analyze.analyze_survey

        def spy(survey, **kwargs):
            captured.update(kwargs)
            return real(survey, **kwargs)

        parser = argparse.ArgumentParser(prog="gn")
        sub = parser.add_subparsers(dest="command")
        wd_cli.register_cli(sub)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "walk.csv"
            path.write_text(AIRODUMP_CSV, encoding="utf-8")
            args = parser.parse_args(["wardrive", str(path), "-y"])
            wd_analyze.analyze_survey = spy  # type: ignore[assignment]
            try:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(args.func(args), 0)
            finally:
                wd_analyze.analyze_survey = real  # type: ignore[assignment]
        self.assertEqual(captured.get("seed_dir"), gn_cli.SEED_DIR)
        self.assertEqual(captured.get("runtime_dir"), gn_cli.RUNTIME_DIR)

    def test_the_operator_oui_override_changes_the_verdict_end_to_end(self) -> None:
        """Through the shipped command, with the operator table in the documented place."""
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / "capture-01.csv"
            capture.write_text(self.AIRODUMP_UNKNOWN_VENDOR, encoding="utf-8")
            runtime = Path(tmp) / "rt" / "rf"
            runtime.mkdir(parents=True)
            (runtime / "oui.tsv").write_text("40b034\tHewlett Packard\tenterprise-ap\n",
                                             encoding="utf-8")
            env = dict(os.environ, GREYIQ_RUNTIME_DIR=str(Path(tmp) / "rt"))
            out = subprocess.run([sys.executable, "-B", "gn_cli.py", "wardrive", str(capture),
                                  "-y", "--json"],
                                 cwd=str(BACKEND_DIR), capture_output=True, text=True,
                                 timeout=300, env=env)
            self.assertEqual(out.returncode, 0, out.stderr)
            payload = json.loads(out.stdout)
            self.assertIn(str(runtime / "oui.tsv"), payload["oui_table"]["files"])
            self.assertEqual([row for row in payload["undetermined"] if row["fact"] == "vendor"], [])


# --- degradation -------------------------------------------------------------------


class DegradationTests(unittest.TestCase):
    def test_every_parser_survives_a_truncated_or_corrupt_export(self) -> None:
        corrupt = {
            "airodump-csv": AIRODUMP_CSV[:180],
            "wigle-csv": WIGLE_CSV[:120],
            "kismet-netxml": KISMET_NETXML[:120],
            "kismet-csv": KISMET_CSV[:70],
            "netsh-text": NETSH_TEXT[:90],
        }
        for fmt, text in corrupt.items():
            with self.subTest(fmt=fmt):
                survey = parsers.parse_survey_text(text, fmt=fmt, source_path=f"cut.{fmt}")
                self.assertTrue(survey.warnings, f"{fmt} produced no parse note for a truncated export")
                self.assertTrue(wd_analyze.analyze_survey(survey)["ok"])

    def test_binary_garbage_is_a_warning_not_a_raise(self) -> None:
        for fmt in parsers.FORMATS:
            with self.subTest(fmt=fmt):
                survey = parsers.parse_survey_text("\x00\xff\x01 not a survey at all", fmt=fmt)
                self.assertEqual(len(survey.aps), 0)

    def test_unrecognized_format_is_skipped_with_a_note(self) -> None:
        survey = parsers.parse_survey_text("hello world", fmt="auto", source_path="notes.txt")
        self.assertTrue(any("not recognized" in w for w in survey.warnings))
        self.assertEqual(len(survey.aps), 0)

    def test_a_missing_oui_table_degrades_to_vendor_none_everywhere(self) -> None:
        """Absent data must behave exactly as before the table existed: less knowledge,
        never a crash and never a fabricated vendor."""
        with tempfile.TemporaryDirectory() as tmp:
            empty_seed = Path(tmp) / "seed"
            empty_seed.mkdir()
            table = wd_oui.load_oui_table(empty_seed)
            self.assertEqual(table, {})
            self.assertIsNone(wd_oui.vendor_for("00:0b:85:aa:bb:01", table))
            self.assertEqual(wd_oui.vendor_class("00:0b:85:aa:bb:01", table), "unknown")
            self.assertEqual(wd_oui.vendor_class("02:0b:85:aa:bb:01", table), "soft-ap")  # tier 3 still works
            self.assertIsNone(wd_oui.same_vendor("00:0b:85:aa:bb:01", "24:a4:3c:00:00:01", table))
            survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="w.csv")
            result = wd_analyze.analyze_survey(survey, seed_dir=empty_seed)
            self.assertTrue(result["ok"])
            self.assertEqual(result["oui_table"]["entries"], 0)
            self.assertEqual(result["oui_table"]["vintage"], "unavailable")

    def test_a_missing_ssid_pattern_table_degrades_to_no_opinion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty_seed = Path(tmp) / "seed"
            empty_seed.mkdir()
            self.assertEqual(wd_oui.load_ssid_patterns(empty_seed), ())
            self.assertEqual(wd_oui.classify_ssid("linksys", ()), ("", ""))

    def test_a_city_scale_export_parses_in_linear_time(self) -> None:
        """Performance REGRESSION guard, not a micro-benchmark. A WiGLE city walk is
        hundreds of thousands of rows; de-duplicating each parsed record against a LIST once
        per row is quadratic and took 56 s for 60 000 rows before the tracker became a dict
        keyed by BSSID (0.8 s after). The bound below is ~25x above the linear time and ~2x
        below the quadratic time, so it fails loudly on a reintroduced O(n^2) without being
        flaky on a loaded machine."""
        import time

        rows = ["WigleWifi-1.6,appRelease=2.72,model=x,release=14,device=d,display=u,board=b,brand=g",
                "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,"
                "AltitudeMeters,AccuracyMeters,Type"]
        for i in range(30_000):
            mac = ":".join(f"{b:02x}" for b in (0x24, 0xA4, 0x3C, i >> 16 & 255, i >> 8 & 255, i & 255))
            rows.append(f"{mac},Net{i % 900},[WPA2-PSK-CCMP][ESS],2026-07-30 10:00:00,6,-55,"
                        f"37,-122,10,5,WIFI")
        started = time.perf_counter()
        survey = parsers.parse_wigle_csv("\n".join(rows), source_path="city.csv")
        elapsed = time.perf_counter() - started
        self.assertEqual(len(survey.aps), 30_000)
        self.assertLess(elapsed, 10.0, f"parsing 30k rows took {elapsed:.1f}s - O(n^2) regression?")

    def test_the_finding_cap_is_reported_never_silent(self) -> None:
        from bughunter.wardrive.model import AccessPoint, Survey

        survey = Survey()
        for i in range(300):
            survey.add_ap(AccessPoint(bssid=f"00:ab:c0:00:{i // 256:02x}:{i % 256:02x}",
                                      ssid=f"Open{i}", encryption="open", raw_privacy="OPN",
                                      source="airodump-csv", source_row=i + 1, raw_line="x"))
        result = wd_analyze.analyze_survey(survey, cap=50)
        self.assertEqual(len(result["findings"]), 50)
        self.assertTrue(result["capped"])
        self.assertTrue(any("truncated" in w for w in result["warnings"]))

    def test_analyze_survey_tolerates_no_survey(self) -> None:
        result = wd_analyze.analyze_survey(None)
        self.assertFalse(result["ok"])
        self.assertEqual(result["findings"], [])


class OuiTableTests(unittest.TestCase):
    def test_seed_table_loads_and_classifies(self) -> None:
        table = wd_oui.load_oui_table()
        self.assertGreater(len(table), 50)
        self.assertEqual(wd_oui.vendor_class("24:0a:c4:11:22:33", table), "soc-devboard")
        self.assertEqual(wd_oui.vendor_class("00:0b:85:aa:bb:01", table), "enterprise-ap")
        self.assertEqual(wd_oui.vendor_for("14:cc:20:00:00:03", table), "TP-Link Technologies")

    def test_locally_administered_beats_the_table(self) -> None:
        self.assertEqual(wd_oui.vendor_class("02:0b:85:00:00:01"), "soft-ap")

    def test_runtime_table_merges_over_the_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime" / "rf"
            runtime.mkdir(parents=True)
            (runtime.parent / "rf" / "oui.tsv").write_text(
                "# operator table\n000b85\tSite Standard AP\tenterprise-ap\n", encoding="utf-8")
            table = wd_oui.load_oui_table(runtime_dir=Path(tmp) / "runtime")
            self.assertEqual(wd_oui.vendor_for("00:0b:85:aa:bb:01", table), "Site Standard AP")

    def test_ssid_pattern_anchors(self) -> None:
        patterns = wd_oui.load_ssid_patterns()
        self.assertEqual(wd_oui.classify_ssid("NETGEAR42", patterns)[0], "factory")
        self.assertEqual(wd_oui.classify_ssid("Acme-Guest", patterns)[0], "guest")
        self.assertEqual(wd_oui.classify_ssid("ESP_A1B2C3", patterns)[0], "soft-ap")
        self.assertEqual(wd_oui.classify_ssid("A Perfectly Normal Name", patterns), ("", ""))

    def test_a_guest_ssid_downgrades_the_open_network_finding(self) -> None:
        from bughunter.wardrive.model import AccessPoint, Survey

        survey = Survey()
        survey.add_ap(AccessPoint(bssid="24:A4:3C:00:00:07", ssid="Acme-Guest", encryption="open",
                                  raw_privacy="OPN", source="airodump-csv", source_row=2,
                                  raw_line="24:A4:3C:00:00:07, ..., OPN, ..., Acme-Guest,"))
        findings = {f["rule_id"]: f for f in wd_analyze.analyze_survey(survey)["findings"]}
        self.assertIn("wardrive.open-network-guest", findings)
        self.assertEqual(findings["wardrive.open-network-guest"]["severity"], "info")
        self.assertNotIn("wardrive.open-network", findings)


# --- report ------------------------------------------------------------------------


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.survey = parsers.parse_airodump_csv(AIRODUMP_CSV, source_path="walk-01.csv")
        self.result = wd_analyze.analyze_survey(self.survey)

    def test_header_states_the_findings_come_from_a_passive_export(self) -> None:
        markdown = wd_report.build_rf_markdown(self.result)
        self.assertIn("PASSIVE survey export", markdown)
        self.assertIn("No frame was transmitted", markdown)

    def test_undetermined_section_precedes_the_findings(self) -> None:
        markdown = wd_report.build_rf_markdown(self.result)
        self.assertLess(markdown.index("## Undetermined"), markdown.index("## Findings"))
        self.assertIn("is **not** evidence the control is present", markdown)

    def test_tri_state_renders_as_three_distinct_words(self) -> None:
        """An airodump BSS must print WPS/PMF as `undetermined` in the inventory table.
        Rendering None as "no" is the same fabrication as raising the finding would be."""
        markdown = wd_report.build_rf_markdown(
            self.result, ctx={"access_points": [ap.to_dict() for ap in self.survey.ap_list()]})
        self.assertIn("| undetermined | undetermined |", markdown)
        self.assertNotIn("| disabled | disabled |", markdown)

    def test_ssid_markup_cannot_restructure_the_report(self) -> None:
        from bughunter.wardrive.model import AccessPoint, Survey

        survey = Survey()
        survey.add_ap(AccessPoint(bssid="24:A4:3C:00:00:09", ssid="evil|row`code`</td>",
                                  encryption="open", raw_privacy="OPN", source="airodump-csv",
                                  source_row=2, raw_line="x"))
        markdown = wd_report.build_rf_markdown(
            wd_analyze.analyze_survey(survey),
            ctx={"access_points": [ap.to_dict() for ap in survey.ap_list()]})
        self.assertNotIn("evil|row", markdown)
        self.assertIn("evil\\|row", markdown)

    def test_write_rf_report_lands_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "deep" / "nested" / "rf-report.md"
            written = wd_report.write_rf_report(out, self.result)
            self.assertTrue(Path(written).exists())
            self.assertIn("# RF survey", Path(written).read_text(encoding="utf-8"))


# --- CLI ---------------------------------------------------------------------------


class CliTests(unittest.TestCase):
    def _parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="gn")
        sub = parser.add_subparsers(dest="command")
        wd_cli.register_cli(sub)
        return parser

    def test_registers_the_verb(self) -> None:
        args = self._parser().parse_args(["wardrive", "x.csv", "-y"])
        self.assertTrue(callable(args.func))
        self.assertTrue(args.authorize)

    def test_authorize_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "walk.csv"
            path.write_text(AIRODUMP_CSV, encoding="utf-8")
            args = self._parser().parse_args(["wardrive", str(path)])
            buf, errbuf = io.StringIO(), io.StringIO()
            with redirect_stdout(buf), redirect_stderr(errbuf):
                code = args.func(args)
            self.assertEqual(code, 2)
            self.assertIn("--authorize", errbuf.getvalue())

    def test_json_smoke_over_a_directory_of_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture"
            root.mkdir()
            (root / "walk-01.csv").write_text(AIRODUMP_CSV, encoding="utf-8")
            (root / "walk.netxml").write_text(KISMET_NETXML, encoding="utf-8")
            args = self._parser().parse_args(["wardrive", str(root), "-y", "--json"])
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = args.func(args)
            self.assertEqual(code, 0)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["ok"])
            self.assertEqual(sorted(payload["source_formats"]), ["airodump-csv", "kismet-netxml"])
            self.assertTrue(payload["survey"]["aps"])

    def test_report_and_min_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "walk.csv"
            path.write_text(AIRODUMP_CSV, encoding="utf-8")
            out = Path(tmp) / "rf.md"
            args = self._parser().parse_args(
                ["wardrive", str(path), "-y", "--min-severity", "critical", "--out", str(out)])
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                code = args.func(args)
            self.assertEqual(code, 0)
            self.assertTrue(out.exists())
            printed = buf.getvalue()
            self.assertIn("WEP", printed)  # the only critical
            self.assertNotIn("Unencrypted network", printed)

    def test_written_report_is_dated_and_names_the_scope(self) -> None:
        """A deliverable with no date and no scope line is not an assessment artifact."""
        import os

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "walk.csv"
            path.write_text(AIRODUMP_CSV, encoding="utf-8")
            out = Path(tmp) / "rf.md"
            os.environ["GREYIQ_REPORT_TIMESTAMP"] = "2026-08-01T00:00:00+00:00"
            self.addCleanup(os.environ.pop, "GREYIQ_REPORT_TIMESTAMP", None)
            args = self._parser().parse_args(["wardrive", str(path), "-y", "--out", str(out)])
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(args.func(args), 0)
            markdown = out.read_text(encoding="utf-8")
            self.assertIn("2026-08-01T00:00:00+00:00", markdown)
            self.assertIn(str(path), markdown)

    def test_missing_export_is_an_error_not_a_traceback(self) -> None:
        args = self._parser().parse_args(["wardrive", "definitely-not-here.csv", "-y"])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(args.func(args), 2)

    def test_registration_does_not_import_the_engine(self) -> None:
        """gn_cli builds its parser on every startup, so registering this verb must not drag
        the parsers/analyzer/renderer onto the boot path."""
        script = (
            "import sys, argparse\n"
            f"sys.path.insert(0, {str(BACKEND_DIR)!r})\n"
            "import bughunter.wardrive.cli as c\n"
            "p = argparse.ArgumentParser(); c.register_cli(p.add_subparsers())\n"
            "print(','.join(sorted(m for m in sys.modules if m.startswith('bughunter.wardrive.'))))\n"
        )
        out = subprocess.run([sys.executable, "-B", "-c", script], capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        loaded = set(filter(None, out.stdout.strip().split(",")))
        for heavy in ("bughunter.wardrive.parsers", "bughunter.wardrive.analyze",
                      "bughunter.wardrive.report", "bughunter.wardrive.oui"):
            self.assertNotIn(heavy, loaded, f"{heavy} must not be imported at registration time")


if __name__ == "__main__":
    unittest.main()
