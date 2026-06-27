"""GreyIQ ``gn`` — drive the bug-bounty engine from the terminal.

Short, scriptable commands over the same engine the desktop app uses:

    gn hunt https://example.com -s "acme — *.example.com" --active -y
    gn hunt ./path/to/repo -p source-code -y
    gn scan https://example.com
    gn profiles | gn classes | gn tools xss ssrf

Torch-free and frozen-safe: it imports only the bughunter engine (the scanners,
the impact/proof model, the active verifier), so it runs anywhere the scanners
run — including a phone — without the ML stack. The frozen backend exe dispatches
here when given a subcommand (see run_frozen.py), so the shipped binary is also
the CLI.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# --- Resolve seed/runtime dirs exactly like greyiq_api (frozen vs dev). ---
if getattr(sys, "frozen", False):
    _BUNDLE = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    BACKEND_DIR, PROJECT_ROOT, SEED_DIR = _BUNDLE, _BUNDLE, _BUNDLE / "seed"
else:
    BACKEND_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT, SEED_DIR = BACKEND_DIR.parent, BACKEND_DIR / "seed"
RUNTIME_DIR = Path(os.getenv("GREYIQ_RUNTIME_DIR", PROJECT_ROOT / "runtime")).resolve()

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from _version import VERSION  # noqa: E402

# These are the CLI verbs run_frozen.py recognizes to dispatch here.
CLI_COMMANDS = ("hunt", "scan", "profiles", "classes", "tools", "version", "gn")

_SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.getenv("NO_COLOR") is None and os.getenv("TERM") != "dumb"


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _color_enabled() else text


def _err(message: str) -> int:
    print(_c(f"gn: {message}", "31"), file=sys.stderr)
    return 2


def _load_coder_config(use_brain: bool) -> dict:
    """Deterministic by default. With --brain, load the configured brain from the
    runtime config (merging the perms-restricted secrets store), mirroring the API."""
    if not use_brain:
        return {}
    try:
        payload = json.loads((RUNTIME_DIR / "solin_runtime_config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    coder_cfg = payload.get("coder") if isinstance(payload, dict) else {}
    coder_cfg = dict(coder_cfg) if isinstance(coder_cfg, dict) else {}
    try:
        secrets = json.loads((RUNTIME_DIR / "secrets.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        secrets = {}
    if isinstance(secrets, dict):
        for provider in ("anthropic", "openai", "local"):
            key = secrets.get(provider)
            if not key:
                continue
            block = coder_cfg.get(provider)
            if isinstance(block, dict):
                block["api_key"] = key
            else:
                coder_cfg[provider] = {"api_key": key}
    return coder_cfg


def _cmd_hunt(args: argparse.Namespace) -> int:
    from bughunter.bounty import run_bounty_hunt

    if not args.authorize:
        return _err("a hunt tests a live/owned target — pass -y/--authorize to confirm you're authorized and in scope.")
    out_dir = args.out or str(RUNTIME_DIR / "reports")
    result = run_bounty_hunt(
        args.target,
        args.profile,
        args.vuln_class,
        out_dir,
        args.scope or "",
        True,  # authorized — gated by --authorize above
        _load_coder_config(args.brain),
        default_reports_dir=RUNTIME_DIR / "reports",
        seed_dir=SEED_DIR,
        runtime_dir=RUNTIME_DIR,
        version=VERSION,
        run_live=args.live,
        active=args.active,
        per_finding=args.per_finding,
    )
    if not result.get("ok"):
        return _err(result.get("error", "the hunt could not run."))
    if args.json:
        result.pop("report_markdown", None)  # the file holds the full report
        print(json.dumps(result, indent=2, default=str))
        return 0
    _print_hunt_summary(result)
    return 0


def _print_hunt_summary(result: dict) -> None:
    counts = result.get("severity_counts") or {}
    risk = str(result.get("risk", "unknown")).upper()
    risk_code = {"CRITICAL": "1;31", "HIGH": "31", "MODERATE": "33", "LOW": "36", "CLEAN": "32"}.get(risk, "0")
    print(f"\n{_c('GreyIQ hunt', '1')} — {result.get('target', '')}")
    print(f"Profile: {result.get('profile', '')}   Scanners: {', '.join(result.get('scanners_run') or []) or 'none'}")
    sev = " ".join(f"{counts.get(k, 0)}{k[0].upper()}" for k in ("critical", "high", "medium", "low", "info"))
    print(f"Risk: {_c(risk, risk_code)} (score {result.get('score', 0)})   Findings: {result.get('finding_count', 0)}  [{sev}]")
    verified = result.get("active_verified_classes") or []
    if verified:
        print(_c(f"Actively confirmed (captured proof): {', '.join(verified)}", "32"))
    elif result.get("active_authorization", {}).get("in_scope") is False and result.get("active_authorization", {}).get("skipped_reason"):
        print(_c("Active verification skipped — " + result["active_authorization"]["skipped_reason"], "33"))
    errors = result.get("scan_errors") or []
    if errors:
        print(_c(f"⚠ {len(errors)} scanner(s) failed — results are partial.", "33"))
    paths = result.get("per_finding_paths") or []
    extra = f"  (+{len(paths)} per-finding file(s))" if paths else ""
    print(f"Report: {result.get('report_path', '')}  (+ JSON sidecar){extra}")
    print(f"Next: {_c('open the report', '2')} for guided next steps, proof obligations, and CVSS per finding.\n")


def _cmd_scan(args: argparse.Namespace) -> int:
    from bughunter.chat_commands import _code_target_type, _looks_like_path, _looks_like_url
    from bughunter.scan_service import run_code_scan
    from bughunter.triage import summarize_findings
    from bughunter.web_scan_service import run_web_scan

    target = args.target.strip()
    if _looks_like_url(target):
        result = run_web_scan(target)
    elif _looks_like_path(target):
        result = run_code_scan(target, _code_target_type(target))
    else:
        return _err("couldn't tell if that's a URL or a path. Use a full http(s):// URL or a folder/repo path.")
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0
    print(summarize_findings(result))
    return 0 if result.get("ok") else 1


def _cmd_profiles(args: argparse.Namespace) -> int:
    from bughunter.bounty import list_profiles

    data = list_profiles()
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(_c("Hunt profiles:", "1"))
    for profile in data["profiles"]:
        kinds = ", ".join(profile.get("kinds") or [])
        print(f"  {_c(profile['id'], '36'):<28} {profile['name']}  ({kinds})")
        print(f"      {profile['description']}")
    return 0


def _cmd_classes(args: argparse.Namespace) -> int:
    from bughunter.bounty import list_profiles

    classes = list_profiles()["classes"]
    if args.json:
        print(json.dumps(classes, indent=2))
        return 0
    print(_c(f"Vuln classes ({len(classes)}):", "1"))
    for cls in classes:
        print(f"  {_c(cls['id'], '36'):<28} {cls['name']}")
    return 0


def _cmd_tools(args: argparse.Namespace) -> int:
    from bughunter import toolkit as toolkit_lib

    if args.classes:
        tools = toolkit_lib.recommended_tools(args.classes, SEED_DIR, RUNTIME_DIR, limit=args.limit)
        if not tools:
            return _err(f"no curated tools mapped to: {', '.join(args.classes)}")
        if args.json:
            print(json.dumps(tools, indent=2))
            return 0
        print(_c(f"Tools for {', '.join(args.classes)}:", "1"))
        for tool in tools:
            print(f"  {_c(tool.get('name', ''), '36'):<24} {tool.get('description', '')}")
            print(f"      {tool.get('url', '')}")
        return 0
    payload = toolkit_lib.catalog_payload(SEED_DIR, RUNTIME_DIR)
    print(f"{payload.get('count', 0)} curated tools. Pass a class id (see `gn classes`), e.g. `gn tools xss ssrf`.")
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"GreyIQ gn {VERSION}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gn",
        description="GreyIQ bug-bounty CLI — hunt, scan, and prove findings from the terminal.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"GreyIQ gn {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    hunt = sub.add_parser("hunt", help="run a bounty hunt against a URL or repo/folder")
    hunt.add_argument("target", help="https:// URL, repo URL, or local path")
    hunt.add_argument("-p", "--profile", default="full-sweep", help="hunt profile (default: full-sweep; see `gn profiles`)")
    hunt.add_argument("-c", "--class", dest="vuln_class", default=None, help="focus vuln class (see `gn classes`)")
    hunt.add_argument("-s", "--scope", default="", help="program/scope notes (name the host here to allow active checks)")
    hunt.add_argument("--active", action="store_true", help="active verification: send benign probes to PROVE findings (URL targets)")
    hunt.add_argument("--live", action="store_true", help="dynamic Playwright browser pass (URL targets)")
    hunt.add_argument("--brain", action="store_true", help="use the configured LLM brain to enrich (default: deterministic)")
    hunt.add_argument("-o", "--out", default=None, help="report output folder (default: runtime/reports)")
    hunt.add_argument("--per-finding", action="store_true", help="also write one submission-ready file per finding")
    hunt.add_argument("-y", "--authorize", action="store_true", help="confirm you are AUTHORIZED to test the target (required)")
    hunt.add_argument("--json", action="store_true", help="print the machine-readable result")
    hunt.set_defaults(func=_cmd_hunt)

    scan = sub.add_parser("scan", help="quick code/web scan with a triage summary")
    scan.add_argument("target", help="https:// URL or local path")
    scan.add_argument("--json", action="store_true", help="print the raw scan result")
    scan.set_defaults(func=_cmd_scan)

    profiles = sub.add_parser("profiles", help="list hunt profiles")
    profiles.add_argument("--json", action="store_true")
    profiles.set_defaults(func=_cmd_profiles)

    classes = sub.add_parser("classes", help="list vuln classes")
    classes.add_argument("--json", action="store_true")
    classes.set_defaults(func=_cmd_classes)

    tools = sub.add_parser("tools", help="recommended tools for one or more vuln classes")
    tools.add_argument("classes", nargs="*", help="class ids, e.g. xss ssrf")
    tools.add_argument("--limit", type=int, default=12)
    tools.add_argument("--json", action="store_true")
    tools.set_defaults(func=_cmd_tools)

    version = sub.add_parser("version", help="print the version")
    version.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "gn":  # tolerate `greyiq-backend.exe gn hunt ...`
        argv = argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return _err("interrupted.")
    except Exception as exc:  # noqa: BLE001 - the CLI must report, not traceback-dump
        return _err(f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
