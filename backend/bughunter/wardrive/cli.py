"""Wardrive — the ``gn wardrive`` verb, registered through gn_cli's plugin hook.

``gn_cli._VERB_PLUGINS`` already names ``bughunter.wardrive.cli``, so this module owns its
own subcommand and gn_cli needs no edit. That hook has one hard rule: REGISTRATION MUST
STAY IMPORT-LIGHT. :func:`register_cli` runs on every ``import gn_cli`` — including
``run_frozen.py``'s dispatch path and ``test_boot_no_torch.py`` — so nothing here imports
the parsers, the analyzer or the renderer at module scope. :func:`_cmd_wardrive` imports
them inside its body, exactly like every ``_cmd_*`` in gn_cli.

``-y/--authorize`` is REQUIRED, matching ``gn hunt``. The analysis itself is read-only, but
a wireless survey export is a recording of other people's networks and of client devices
that never consented to being in it. The flag is the operator asserting that the capture
was made under their own authorization and that the assessment is for the site that owns
those networks — the same assertion the rest of the CLI demands before it touches anything
belonging to somebody else.
"""

from __future__ import annotations

import argparse
from typing import Any

_MIN_SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_HELP = ("analyze a wifi survey EXPORT you already captured (airodump-ng / WiGLE / Kismet / netsh) - "
         "read-only RF posture + rogue-AP triage; never transmits")


def register_cli(sub: Any) -> None:
    """Add ``gn wardrive`` to the parser. Import-light by contract — no engine imports here."""
    wd = sub.add_parser("wardrive", help=_HELP)
    wd.add_argument("export", nargs="+",
                    help="survey export file(s); a DIRECTORY is walked for .csv/.netxml/.xml/.txt exports")
    wd.add_argument("--format", dest="fmt", default="auto",
                    choices=("auto", "airodump-csv", "wigle-csv", "kismet-netxml", "kismet-csv", "netsh-text"),
                    help="force an export format instead of detecting it (default: auto)")
    wd.add_argument("--authorized", default="",
                    help="authorized-AP inventory JSON ({\"bssids\": [...], \"ssids\": [...]}); "
                         "without it no rogue-AP verdict is possible and none is claimed")
    wd.add_argument("--min-severity", dest="min_severity", default="info", choices=_MIN_SEVERITIES,
                    help="hide findings below this severity in the printed output (default: info)")
    wd.add_argument("--out", default="", help="write the markdown report to this path")
    wd.add_argument("--json", action="store_true", help="print the machine-readable result")
    wd.add_argument("-y", "--authorize", action="store_true",
                    help="confirm the capture was made under YOUR authorization and the site is in scope (required)")
    wd.set_defaults(func=_cmd_wardrive)


def _cmd_wardrive(args: argparse.Namespace) -> int:
    # Engine imports live INSIDE the command body: see the module docstring's boot-latency rule.
    import json
    import os
    import sys
    from datetime import UTC, datetime
    from pathlib import Path

    from bughunter.wardrive import analyze as analyze_mod
    from bughunter.wardrive import parsers, report

    def err(message: str) -> int:
        print(f"gn: {message}", file=sys.stderr)
        return 2

    if not getattr(args, "authorize", False):
        return err("a survey export records other people's networks and client devices - pass -y/--authorize "
                   "to confirm the capture is yours and the site is in scope.")

    targets = [str(p) for p in (args.export if isinstance(args.export, list) else [args.export])]
    missing = [p for p in targets if not Path(p).exists()]
    if missing:
        return err(f"export not found: {', '.join(missing)}")

    authorized: Any = None
    if getattr(args, "authorized", ""):
        try:
            authorized = json.loads(Path(args.authorized).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return err(f"could not read the authorized-AP inventory {args.authorized}: {exc}")

    survey = parsers.load_survey(targets, fmt=getattr(args, "fmt", "auto") or "auto")
    seed_dir, runtime_dir = _table_dirs()
    result = analyze_mod.analyze_survey(survey, authorized=authorized,
                                        seed_dir=seed_dir, runtime_dir=runtime_dir)
    if not result.get("ok"):
        return err(str(result.get("error") or "analysis failed"))

    ap_dicts = [ap.to_dict() for ap in survey.ap_list()]
    if getattr(args, "json", False):
        payload = dict(result)
        payload["survey"] = survey.to_dict()
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human(result, min_severity=str(getattr(args, "min_severity", "info") or "info"))

    out = str(getattr(args, "out", "") or "")
    if out:
        ctx = {
            "title": "RF survey — wireless posture assessment",
            "scope": ", ".join(targets),
            # An assessment deliverable without a date is worth less; the env override exists
            # so a test can pin it and diff two reports byte for byte.
            "generated": os.getenv("GREYIQ_REPORT_TIMESTAMP") or datetime.now(UTC).isoformat(timespec="seconds"),
            "version": _greyiq_version(),
            "access_points": ap_dicts,
        }
        try:
            written = report.write_rf_report(out, result, ctx=ctx)
        except OSError as exc:
            return err(f"could not write the report to {out}: {exc}")
        print(f"report: {written}")
    return 0


def _table_dirs() -> tuple[Any, Any]:
    """``(seed_dir, runtime_dir)`` for the OUI / SSID tables, from gn_cli's own resolution.

    Without this the operator table is DEAD CODE in the shipped product: ``analyze_survey``
    defaults both to None, ``oui._rf_files`` then never builds the ``<runtime>/rf`` base, and
    tier 2 of the three-tier design is unreachable — while the report keeps printing "add the
    prefix to <runtime>/rf/oui.tsv" as the remediation for every undetermined vendor. That is
    a deliverable instructing the client to perform a step that provably does nothing.

    Imported INSIDE the function (gn_cli owns ``GREYIQ_RUNTIME_DIR`` resolution and importing
    it at module scope would break this module's registration-is-import-light contract), and
    guarded: driven straight from a test there may be no gn_cli on the path, which costs the
    operator override for that run and never the assessment."""
    try:
        from gn_cli import RUNTIME_DIR, SEED_DIR  # type: ignore[attr-defined]

        return SEED_DIR, RUNTIME_DIR
    except Exception:  # noqa: BLE001 - a table-path lookup must never fail the survey
        return None, None


def _greyiq_version() -> str:
    """The shipped version for the report header. Absent (module driven straight from a
    test, or an odd sys.path) costs a header line, never the report."""
    try:
        from _version import VERSION

        return str(VERSION)
    except Exception:  # noqa: BLE001 - a version lookup must never fail a written report
        return ""


def _print_human(result: dict[str, Any], *, min_severity: str) -> None:
    """Terminal summary. Severity colouring reuses gn_cli's palette so `gn wardrive` looks
    like the rest of the CLI; if gn_cli is unavailable (the module driven directly from a
    test) the output degrades to plain text rather than failing."""
    try:
        from gn_cli import _c, _SEV_COLOR  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - colour is cosmetic; never let it break the command
        _SEV_COLOR = {}

        def _c(text: str, _code: str) -> str:
            return text

    stats = result.get("stats") or {}
    floor = _SEVERITY_RANK.get(str(min_severity or "info").lower(), 0)
    print(f"formats: {', '.join(result.get('source_formats') or ['none'])}  "
          f"access points: {int(stats.get('access_points') or 0)}  "
          f"clients: {int(stats.get('stations') or 0)}")
    shown = 0
    for finding in result.get("findings") or []:
        severity = str(finding.get("severity") or "info").lower()
        if _SEVERITY_RANK.get(severity, 0) < floor:
            continue
        shown += 1
        tag = _c(f"[{severity}]", _SEV_COLOR.get(severity, "0"))
        print(f"  {tag} {finding.get('title', '')}")
        print(f"      {finding.get('location', '')}  evidence: {str(finding.get('evidence') or '')[:120]}")
    if not shown:
        print("  no findings at or above this severity.")
    undetermined = result.get("undetermined") or []
    if undetermined:
        print("undetermined (the export cannot tell us; absence of a finding is NOT a clean bill of health):")
        for row in undetermined:
            print(f"  {row.get('fact')}: {row.get('ap_count')} BSS - {row.get('reason')}")
    for warning in (result.get("warnings") or [])[:12]:
        print(f"  note: {warning}")
