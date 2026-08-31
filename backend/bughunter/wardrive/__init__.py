"""GreyIQ wardrive — read-only RF survey analysis for authorized site assessments.

WHAT THIS PACKAGE IS. An operator walks a site with airodump-ng, Kismet, the WiGLE app or
just ``netsh wlan show networks mode=bssid`` and ends up with export files. This package
reads those files and turns them into a defensive posture assessment: encryption weakness,
WPS exposure, 802.11w state, factory-default configuration, evil-twin / unmanaged-AP triage,
and the client-side Preferred-Network-List leak. It is deterministic structured prediction
over a parsed table — rules from day one, no model, no learning loop, nothing to train.

WHAT THIS PACKAGE IS NOT, and the boundary is absolute. There is no socket, no subprocess
invoking a wireless tool, no monitor-mode control, no frame transmission of any kind, no
key-material capture, no passphrase recovery, and no WiGLE API call. The entire input
surface is FILES THE OPERATOR ALREADY HAS. ``test_wardrive.py`` enforces this by scanning
this package's own source. The remediation text is likewise defensive only: it says how to
fix a posture, never how to exercise it.

THE RULE THAT SHAPES EVERY MODULE HERE is the tri-state. ``wps=None`` and ``pmf=""`` mean
*this export format cannot tell us*, which is a completely different fact from *the format
reported it and it is off*. airodump-ng CSV carries neither WPS state nor RSN capability
bits, so an airodump-only survey yields ZERO WPS findings and ZERO PMF findings — and says
so in an explicit ``undetermined`` section rather than implying a clean bill of health. A
confidently wrong "PMF missing" line in a client deliverable is worse than an honest
"not determinable from this capture format", and that is the GreyNOC no-fabrication rule
("reproducible or it didn't happen") applied to RF.

Layout:
  ``model``    normalization + the AccessPoint/Station/Survey records (identity merging)
  ``parsers``  airodump-ng CSV, WiGLE CSV, Kismet netxml, Kismet CSV, netsh text
  ``oui``      curated OUI vendor attribution + SSID-pattern tables, offline
  ``analyze``  the detectors, the undetermined ledger, and the inference ledger
  ``report``   Markdown rendering of the assessment
  ``cli``      the ``gn wardrive`` verb, registered through gn_cli's plugin hook

Stdlib only, frozen-safe: ``build/greyiq-backend.spec`` collects all of ``bughunter``, so
this package ships in the frozen backend with no spec change.
"""

from __future__ import annotations

from bughunter.wardrive.model import (
    ENCRYPTION_ORDER,
    NON_OVERLAPPING_24,
    AccessPoint,
    Station,
    Survey,
    band_for_channel,
    encryption_rank,
    is_locally_administered,
    is_multicast,
    normalize_mac,
    normalize_privacy,
    oui_prefix,
    parse_channel,
    parse_signal,
)

__all__ = [
    "ENCRYPTION_ORDER",
    "NON_OVERLAPPING_24",
    "AccessPoint",
    "Station",
    "Survey",
    "analyze_survey",
    "band_for_channel",
    "build_rf_markdown",
    "classify_ssid",
    "detect_format",
    "encryption_rank",
    "is_locally_administered",
    "is_multicast",
    "load_survey",
    "normalize_mac",
    "normalize_privacy",
    "oui_prefix",
    "parse_channel",
    "parse_signal",
    "vendor_for",
]


def __getattr__(name: str):
    """Re-export the engine LAZILY.

    ``gn_cli`` imports ``bughunter.wardrive.cli`` on every startup to register the verb, and
    that import walks this ``__init__``. Eagerly pulling in the parsers, the analyzer and
    the renderer here would put ``csv``/``xml``/the whole detector table on the CLI's boot
    path for every command — the same boot-latency rule that makes each ``_cmd_*`` import
    its engine inside the function body. The names below therefore resolve on first use."""
    if name in ("analyze_survey",):
        from bughunter.wardrive.analyze import analyze_survey

        return analyze_survey
    if name in ("load_survey", "detect_format"):
        from bughunter.wardrive import parsers

        return getattr(parsers, name)
    if name in ("vendor_for", "classify_ssid"):
        from bughunter.wardrive import oui

        return getattr(oui, name)
    if name in ("build_rf_markdown", "write_rf_report"):
        from bughunter.wardrive import report

        return getattr(report, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
