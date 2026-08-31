"""Wardrive — OUI vendor attribution and SSID-pattern lookup, three tiers deep.

Rogue-AP triage is mostly a vendor question: an SSID advertised by a Cisco radio and
by an Espressif dev board is the same string carrying two completely different stories.
This module answers "who made the radio" from curated LOCAL tables — never a network
lookup, because the whole package is offline by construction.

Three tiers, in order of how much they can be trusted:

  1. ``seed/rf/oui.tsv`` — a hand-curated MA-L subset scoped to prefixes that change a
     verdict (enterprise AP vendors, retail/ISP CPE, SoC/dev-board makers, handset
     radios). Deliberately NOT the full ~35k-row IEEE registry: the value is in the
     classification, not the coverage, exactly as ``takeover_service._FINGERPRINTS``
     carries curated signatures rather than every public wordlist entry.
  2. ``<runtime>/rf/oui.tsv`` — an optional operator-maintained table MERGED OVER the
     seed, so a site with unusual kit can teach the analyzer without a code change.
  3. :func:`model.is_locally_administered` — zero bytes, no table, always correct. The
     locally-administered bit is the soft-AP / hostapd / phone-hotspot signature and it
     works on every address whether or not any table has heard of it. When the tables
     are missing entirely this tier still carries the rogue-AP detector.

THE HONESTY CONTRACT, and the reason :func:`vendor_for` returns ``None`` rather than a
string: an absent prefix means "not in GreyIQ's curated subset", NOT "unknown vendor"
and never "suspicious". :func:`table_info` surfaces the table's vintage and row count so
the report can attribute an unknown-vendor verdict to table age instead of stating it as
fact. A missing/corrupt table degrades to an EMPTY table — every caller keeps working and
simply learns less, which is the required "absent data behaves exactly as before".

Pure stdlib, no I/O beyond reading the two seed files, module-cached by resolved path +
mtime so tests can point at a tempdir without poisoning the process cache.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any

from bughunter.wardrive.model import is_locally_administered, oui_prefix

_OUI_FILE = "oui.tsv"
_SSID_FILE = "default_ssids.txt"
_RF_SUBDIR = "rf"

# Bound what a hand-edited or operator-supplied table can cost us. A malformed multi-GB
# file must not be able to hang a survey; it is truncated and reported, never streamed.
_MAX_ROWS = 60_000
_MAX_BYTES = 8_000_000

_VENDOR_CLASSES = ("enterprise-ap", "consumer-ap", "soc-devboard", "mobile", "network-gear")
_SSID_KINDS = ("factory", "soft-ap", "guest")

_LOCK = threading.Lock()
_OUI_CACHE: dict[tuple[Any, ...], dict[str, tuple[str, str]]] = {}
_SSID_CACHE: dict[tuple[Any, ...], tuple[tuple[str, str, str], ...]] = {}


def default_seed_dir() -> Path:
    """Where ``seed/`` lives, resolved the same way ``gn_cli`` resolves it so a frozen
    build and a dev checkout agree. Never raises — a wrong guess just yields no table."""
    if getattr(sys, "frozen", False):
        bundle = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        return bundle / "seed"
    # .../backend/bughunter/wardrive/oui.py -> .../backend/seed
    return Path(__file__).resolve().parents[2] / "seed"


def _rf_files(seed_dir: Any, runtime_dir: Any, name: str) -> list[Path]:
    """Seed table first, operator runtime table second — later entries WIN the merge."""
    bases: list[Path] = []
    seed = Path(seed_dir) if seed_dir else default_seed_dir()
    bases.append(seed / _RF_SUBDIR)
    if runtime_dir:
        bases.append(Path(runtime_dir) / _RF_SUBDIR)
    return [base / name for base in bases]


def _cache_key(paths: list[Path]) -> tuple[Any, ...]:
    """Path + mtime + size, so an edited table is picked up but a repeated survey in the
    same process pays the parse cost once."""
    key: list[Any] = []
    for path in paths:
        try:
            stat = path.stat()
            key.append((str(path), int(stat.st_mtime_ns), int(stat.st_size)))
        except OSError:
            key.append((str(path), 0, 0))
    return tuple(key)


def _read_rows(path: Path) -> list[list[str]]:
    """Tab-separated, ``#``-commented rows from ``path``. Total: any read problem
    (absent, locked by OneDrive, a directory, undecodable bytes) yields ``[]``."""
    try:
        if path.stat().st_size > _MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:  # absent / locked / not a file - the documented degraded path
        return []
    except Exception:  # noqa: BLE001 - a table read must NEVER break a survey
        return []
    rows: list[list[str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rows.append([cell.strip() for cell in line.split("\t")])
        if len(rows) >= _MAX_ROWS:
            break
    return rows


def load_oui_table(seed_dir: Any = None, runtime_dir: Any = None) -> dict[str, tuple[str, str]]:
    """``{"aabbcc": (vendor, vendor_class)}`` merged seed-then-runtime, ``{}`` on failure.

    Rows with an unrecognized class are kept with class ``"unknown"`` rather than dropped:
    an operator table that says "this prefix is Foo Corp" is still useful even if the third
    column is misspelled."""
    paths = _rf_files(seed_dir, runtime_dir, _OUI_FILE)
    key = _cache_key(paths)
    with _LOCK:
        cached = _OUI_CACHE.get(key)
    if cached is not None:
        return cached
    table: dict[str, tuple[str, str]] = {}
    for path in paths:
        for row in _read_rows(path):
            if len(row) < 2:
                continue
            prefix = "".join(ch for ch in row[0].lower() if ch in "0123456789abcdef")
            vendor = row[1].strip()
            if len(prefix) != 6 or not vendor:
                continue
            klass = row[2].strip().lower() if len(row) > 2 else ""
            table[prefix] = (vendor, klass if klass in _VENDOR_CLASSES else "unknown")
    with _LOCK:
        _OUI_CACHE[key] = table
    return table


def oui_key(bssid: str) -> str:
    """``aabbcc`` lookup key for a MAC, or '' when ``bssid`` is not a MAC."""
    prefix = oui_prefix(bssid)
    return prefix.replace(":", "") if prefix else ""


def vendor_for(bssid: str, table: dict[str, tuple[str, str]] | None = None) -> str | None:
    """Vendor name for ``bssid``, or ``None`` when the prefix is not in the curated subset.

    ``None`` is deliberately NOT the string "unknown": callers must be able to tell
    "we looked and there is no entry" apart from a vendor literally named unknown, and
    the report must be able to say the table simply does not cover this prefix."""
    entry = (table if table is not None else load_oui_table()).get(oui_key(bssid))
    return entry[0] if entry else None


def vendor_class(bssid: str, table: dict[str, tuple[str, str]] | None = None) -> str:
    """Verdict-relevant class for ``bssid``: one of :data:`_VENDOR_CLASSES`, ``"soft-ap"``
    for a locally-administered address, or ``"unknown"``.

    The locally-administered check runs FIRST and beats the table on purpose: a randomized
    or software-assigned BSSID tells you how the radio is being operated, which matters
    more for rogue triage than which silicon happens to sit underneath it."""
    if is_locally_administered(bssid):
        return "soft-ap"
    entry = (table if table is not None else load_oui_table()).get(oui_key(bssid))
    return entry[1] if entry else "unknown"


def same_vendor(bssid_a: str, bssid_b: str, table: dict[str, tuple[str, str]] | None = None) -> bool | None:
    """Whether two BSSIDs come from the same vendor. ``None`` == UNDETERMINED, i.e. at
    least one prefix is outside the curated table, so the evil-twin detector must not
    count a vendor divergence it cannot actually observe."""
    key_a, key_b = oui_key(bssid_a), oui_key(bssid_b)
    if not key_a or not key_b:
        return None
    if key_a == key_b:
        return True
    lookup = table if table is not None else load_oui_table()
    ent_a, ent_b = lookup.get(key_a), lookup.get(key_b)
    if ent_a is None or ent_b is None:
        return None
    return ent_a[0] == ent_b[0]


def table_info(seed_dir: Any = None, runtime_dir: Any = None) -> dict[str, Any]:
    """Provenance for the report: how many prefixes we know and where they came from.
    Printed next to every unknown-vendor verdict so table age is attributable."""
    paths = _rf_files(seed_dir, runtime_dir, _OUI_FILE)
    table = load_oui_table(seed_dir, runtime_dir)
    present = [str(p) for p in paths if p.exists()]
    return {
        "entries": len(table),
        "files": present,
        "missing": [str(p) for p in paths if str(p) not in present],
        "vintage": "2026-07 (curated MA-L subset)" if table else "unavailable",
    }


# --- SSID patterns ---------------------------------------------------------------


def load_ssid_patterns(seed_dir: Any = None, runtime_dir: Any = None) -> tuple[tuple[str, str, str], ...]:
    """``((pattern, label, kind), ...)`` from ``seed/rf/default_ssids.txt``, longest
    pattern first so the most specific rule wins. ``()`` when the file is absent."""
    paths = _rf_files(seed_dir, runtime_dir, _SSID_FILE)
    key = _cache_key(paths)
    with _LOCK:
        cached = _SSID_CACHE.get(key)
    if cached is not None:
        return cached
    merged: dict[str, tuple[str, str, str]] = {}
    for path in paths:
        for row in _read_rows(path):
            if len(row) < 3:
                continue
            pattern, label, kind = row[0].strip().lower(), row[1].strip(), row[2].strip().lower()
            if not pattern or kind not in _SSID_KINDS:
                continue
            merged[pattern] = (pattern, label, kind)
    patterns = tuple(sorted(merged.values(), key=lambda item: (-len(item[0]), item[0])))
    with _LOCK:
        _SSID_CACHE[key] = patterns
    return patterns


def _pattern_matches(pattern: str, ssid_low: str) -> bool:
    """``*`` is a wildcard ANCHOR, not a glob: leading ``*`` = suffix match, trailing
    ``*`` = prefix match, both = substring, neither = exact. Deliberately not fnmatch —
    an SSID is arbitrary operator data and must never be interpreted as a pattern."""
    lead, trail = pattern.startswith("*"), pattern.endswith("*")
    core = pattern.strip("*")
    if not core:
        return False
    if lead and trail:
        return core in ssid_low
    if lead:
        return ssid_low.endswith(core)
    if trail:
        return ssid_low.startswith(core)
    return ssid_low == core


def classify_ssid(ssid: str, patterns: tuple[tuple[str, str, str], ...] | None = None) -> tuple[str, str]:
    """``(kind, label)`` for an SSID — ``("", "")`` when no curated pattern matches.

    ``kind`` drives two different decisions: ``factory`` raises a finding, ``guest``
    SUPPRESSES one (an open guest network is a design decision, not a defect), and
    ``soft-ap`` feeds rogue triage. No match means no opinion, never "safe"."""
    ssid_low = str(ssid or "").strip().lower()
    if not ssid_low:
        return "", ""
    for pattern, label, kind in (patterns if patterns is not None else load_ssid_patterns()):
        if _pattern_matches(pattern, ssid_low):
            return kind, label
    return "", ""


def reset_cache() -> None:
    """Drop the memoized tables. For tests that rewrite a table under the same path
    inside one mtime tick; production never needs it."""
    with _LOCK:
        _OUI_CACHE.clear()
        _SSID_CACHE.clear()
