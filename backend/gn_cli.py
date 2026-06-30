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

# Windows consoles default to cp1252; degrade gracefully instead of crashing on
# any non-encodable char in output or argparse help (e.g. an em-dash).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError, OSError):
        pass

# These are the CLI verbs run_frozen.py recognizes to dispatch here.
CLI_COMMANDS = ("hunt", "campaign", "scan", "learn", "stats", "operator", "profiles", "classes", "tools", "version", "gn")

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
        active=args.active or getattr(args, "time_based", False) or getattr(args, "deep", False),  # --time-based/--deep imply --active
        time_based=getattr(args, "time_based", False),
        auth={"cookie": getattr(args, "cookie", "") or "", "headers": getattr(args, "header", None) or []},
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


def _cmd_campaign(args: argparse.Namespace) -> int:
    from bughunter.campaign import run_campaign

    if not args.authorize:
        return _err("a campaign tests a live/owned target end-to-end — pass -y/--authorize to confirm scope.")
    result = run_campaign(
        args.target,
        scope=args.scope or "",
        authorized=True,
        coder_cfg=_load_coder_config(args.brain),
        default_reports_dir=RUNTIME_DIR / "reports",
        seed_dir=SEED_DIR,
        runtime_dir=RUNTIME_DIR,
        version=VERSION,
        active=args.active or getattr(args, "time_based", False) or getattr(args, "deep", False),  # --time-based/--deep imply --active
        time_based=getattr(args, "time_based", False),
        auth={"cookie": getattr(args, "cookie", "") or "", "headers": getattr(args, "header", None) or []},
        live=args.live,
        program=args.program,
        max_pages=args.max_pages,
        platform=getattr(args, "platform", "hackerone") or "hackerone",
        deep=getattr(args, "deep", False),
        on_progress=(lambda m: print(_c(f"  - {m}", "2"))) if not args.json else None,
    )
    if not result.get("ok"):
        return _err(result.get("error", "the campaign could not run."))
    if args.json:
        result.pop("report_markdown", None)
        print(json.dumps(result, indent=2, default=str))
        return 0
    print(f"\n{_c('GreyIQ campaign', '1')} — {result.get('program', '')}")
    print(f"Surface: {result.get('urls_scanned', 0)}/{result.get('urls_discovered', 0)} target(s)   "
          f"Findings: {result.get('finding_count', 0)}   {_c(str(result.get('confirmed_count', 0)) + ' confirmed', '32')}")
    subs = result.get("submission_paths") or []
    print(f"Submission packages: {len(subs)}   Report: {result.get('campaign_path', '')}")
    if result.get("confirmed_count"):
        print(_c("Confirmed findings are submission-ready under submissions/. Record outcomes with `gn learn`.", "32"))
    return 0


def _cmd_learn(args: argparse.Namespace) -> int:
    from bughunter import learning

    try:
        prog = learning.record_outcome(
            RUNTIME_DIR, program=args.program, target=args.target or "", class_id=args.vuln_class,
            title=args.title or "", status=args.status, bounty=args.bounty, severity=args.severity or "", notes=args.notes or "",
        )
    except ValueError as exc:
        return _err(str(exc))
    key = learning.program_key(args.program, args.target or "")
    print(_c(f"Recorded: {args.vuln_class} -> {args.status}" + (f" (${args.bounty:g})" if args.bounty else "") + f"  [program: {key}]", "32"))
    print(f"Program totals — submitted: {sum(s['submitted'] for s in prog['class_stats'].values())}, "
          f"rewarded: {sum(s['rewarded'] for s in prog['class_stats'].values())}, "
          f"bounty: ${sum(s['bounty_total'] for s in prog['class_stats'].values()):g}")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    from bughunter import learning

    data = learning.program_summary(RUNTIME_DIR, args.program, args.target or "")
    if args.json:
        print(json.dumps(data, indent=2, default=str))
        return 0
    if "programs" in data:  # all programs
        progs = data["programs"]
        if not progs:
            print("No bounty outcomes recorded yet. After you submit, run `gn learn` to teach the engine.")
            return 0
        print(_c("Bounty learning — by program:", "1"))
        for key, summary in sorted(progs.items(), key=lambda kv: -kv[1]["bounty_total"]):
            print(f"  {_c(key, '36'):<28} submitted {summary['submitted']}, rewarded {summary['rewarded']}, ${summary['bounty_total']:g}")
        print("\nRun `gn stats --program <key>` for the class breakdown.")
        return 0
    print(_c(f"Program: {data['program']}", "1"))
    print(f"  submitted {data['submitted']}, rewarded {data['rewarded']}, bounty ${data['bounty_total']:g}")
    if data.get("class_stats"):
        print("  class breakdown (by bounty):")
        for cls, s in data["class_stats"].items():
            print(f"    {_c(cls, '36'):<26} sub {s['submitted']}, rewarded {s['rewarded']}, noise {s['noise']}, ${s['bounty_total']:g}")
    intel = learning.program_intelligence(RUNTIME_DIR, args.program, args.target or "")
    if intel:
        print(_c("  what pays here:", "32"))
        for note in intel:
            print(f"    - {note}")
    return 0


def _operator_callables(coder_cfg: dict):
    """Build the operator's run_campaign_fn + submit_fn directly over the torch-free
    bughunter engine (no API). The submit path goes through the SAME hard-gated
    submission.submit_to_hackerone (confirm + proof_status=='confirmed' + creds)."""
    from datetime import UTC, datetime

    from bughunter import campaign as campaign_mod
    from bughunter import submission as submission_mod

    last: dict = {}

    def run_campaign_fn(target, *, scope, program, active, live, deep=False, max_pages=12):
        result = campaign_mod.run_campaign(
            target, scope=scope, authorized=True, coder_cfg=coder_cfg,
            default_reports_dir=RUNTIME_DIR / "reports", seed_dir=SEED_DIR, runtime_dir=RUNTIME_DIR,
            version=VERSION, active=active, live=live, deep=deep, program=program, max_pages=max_pages,
        )
        last["result"], last["target"], last["scope"] = result, target, scope
        return result

    def submit_fn(_run_id, ref):
        result = last.get("result") or {}
        finding = next((f for f in (result.get("findings") or []) if f.get("ref") == ref), None)
        if finding is None:
            return {"ok": False, "error": "finding not found in the last run"}
        ctx = {
            "tool": "GreyIQ BugHunter", "version": VERSION,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            "target": last.get("target", ""), "scope": last.get("scope", ""),
            "attack_plans": result.get("attack_plans") or {},
        }
        package = submission_mod.build_submission(ctx, finding)
        if package is None:
            return {"ok": False, "error": "finding is not reportable"}
        handle, username, token = _hackerone_creds()
        try:
            return {"ok": True, **submission_mod.submit_to_hackerone(
                package, team_handle=handle, api_username=username, api_token=token, confirm=True)}
        except submission_mod.SubmissionError as exc:
            return {"ok": False, "error": str(exc)}

    return run_campaign_fn, submit_fn


def _hackerone_creds() -> tuple[str, str, str]:
    """Read the HackerOne creds the desktop app stored in the shared secrets file."""
    try:
        secrets = json.loads((RUNTIME_DIR / "secrets.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        secrets = {}
    if not isinstance(secrets, dict):
        secrets = {}
    return (str(secrets.get("hackerone.team_handle", "")), str(secrets.get("hackerone.api_username", "")),
            str(secrets.get("hackerone.api_token", "")))


def _cmd_operator(args: argparse.Namespace) -> int:
    from bughunter import operator as operator_mod
    from bughunter import portfolio

    rt = str(RUNTIME_DIR)
    action = getattr(args, "op_action", None)

    if action == "list" or action is None:
        progs = portfolio.list_programs(rt)
        if not progs:
            print("No programs yet. Add one: gn operator add --name acme --scope '*.acme.com' --targets https://acme.com")
            return 0
        print(_c(f"Portfolio ({len(progs)} program(s)):", "1"))
        for p in progs:
            flags = " ".join(f for f, on in (("active", p["active"]), ("live", p["live"]), ("deep", p.get("deep")),
                                             ("auto-submit", p["auto_submit"]), ("enabled", p["enabled"])) if on) or "disabled"
            print(f"  {_c(p['id'], '36'):<24} {p['name']}  [{flags}]  scope: {p['scope_text'] or '(none)'}  "
                  f"targets: {len(p['seed_targets'])}  every {p['interval_minutes']}m")
        return 0

    if action == "add":
        prog = portfolio.upsert_program(rt, {
            "name": args.name, "scope_text": args.scope, "seed_targets": args.targets or [],
            "platform": "hackerone" if args.handle else "manual", "platform_handle": args.handle or "",
            "active": args.active, "live": args.live, "deep": getattr(args, "deep", False), "auto_submit": args.auto_submit,
            "interval_minutes": args.interval, "max_submits_per_day": args.max_submits, "max_pages": args.max_pages,
        })
        warn = "" if (not args.auto_submit or prog["auto_submit"]) else _c("  (auto-submit ignored — needs a HackerOne handle + non-empty scope)", "33")
        print(_c(f"Saved program: {prog['id']}", "32") + warn)
        return 0

    if action == "remove":
        ok = portfolio.remove_program(rt, args.id)
        return 0 if ok else _err(f"no such program: {args.id}")

    if action == "pipeline":
        from bughunter import ledger
        f = ledger.funnel(rt).get("portfolio", {})
        st = f.get("stages", {})
        print(_c("Money pipeline (portfolio):", "1"))
        print(f"  discovered {st.get('discovered',0)}  confirmed {st.get('confirmed',0)}  reported {st.get('reported',0)}  "
              f"submitted {st.get('submitted',0)}  paid {st.get('paid',0)}   {_c('$'+str(f.get('bounty_total',0)),'32')}")
        return 0

    if action == "run":
        if not args.authorize:
            return _err("the operator runs live campaigns — pass -y/--authorize to confirm you're authorized on every enabled program.")
        run_campaign_fn, submit_fn = _operator_callables(_load_coder_config(args.brain))
        loop = operator_mod.OperatorLoop(rt, run_campaign_fn=run_campaign_fn, submit_fn=submit_fn)
        if args.allow_submit:
            print(_c("AUTO-SUBMIT ARMED — confirmed, non-duplicate findings will be filed (per-program opt-in + daily cap apply).", "1;31"))
        if args.once:
            progs = [p for p in portfolio.list_programs(rt) if p.get("enabled")]
            if not progs:
                return _err("no enabled programs to run.")
            for p in progs:
                print(_c(f"· cycle: {p['id']}", "2"))
                submit = submit_fn if (args.allow_submit and p.get("auto_submit")) else None
                summary = operator_mod.run_program_cycle(rt, p, run_campaign_fn=run_campaign_fn, submit_fn=submit,
                                                         on_event=lambda m: print(_c(f"    {m}", "2")))
                print(f"  {p['id']}: {summary['findings']} findings, {summary['confirmed']} confirmed, {summary['submitted']} submitted")
            return 0
        # Continuous: run the loop, stream events, Ctrl+C to stop.
        loop.start(allow_submit=args.allow_submit)
        print(_c("Operator running — Ctrl+C to stop.", "1"))
        seen = 0
        try:
            import time
            while loop.running:
                tail = loop.event_tail(after=seen)
                for ev in tail["events"]:
                    print(f"  {_c(ev['at'][11:19], '2')}  {ev['message']}")
                seen = tail["count"]
                time.sleep(2)
        except KeyboardInterrupt:
            loop.stop()
            print(_c("\nKill switch — stopping…", "33"))
        return 0

    return _err(f"unknown operator action: {action}")


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


def _cmd_takeover(args: argparse.Namespace) -> int:
    from bughunter import takeover_service as tk

    if not args.authorize:
        return _err("subdomain enumeration touches in-scope hosts only — pass -y/--authorize to confirm scope.")
    res = tk.scan_subdomain_takeover(args.target, scope=args.scope or "")
    if not res.get("ok"):
        return _err(res.get("error", "could not run the scan."))
    print(f"{_c('Subdomain scan', '1')} — apex {res.get('apex')}: {len(res.get('resolved') or [])} resolving in-scope host(s)")
    findings = res.get("findings") or []
    if not findings:
        print("  no dangling-service takeovers found.")
        return 0
    for f in findings:
        print(_c(f"  TAKEOVER: {f['title']}", "32"))
        print(f"    {f['proof_evidence']['matched_value']}")
    if args.json:
        print(json.dumps(res, indent=2, default=str))
    return 0


def _cmd_idor(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime
    from pathlib import Path

    from bughunter import access_control_service as ac
    from bughunter import report_formats

    if not args.authorize:
        return _err("IDOR testing uses your two authorized test sessions against an in-scope host — pass -y/--authorize.")
    res = ac.run_idor_check(
        args.url_a, args.url_b,
        account_a={"cookie": args.a_cookie or "", "headers": args.a_header or []},
        account_b={"cookie": args.b_cookie or "", "headers": args.b_header or []},
        scope=args.scope or "",
    )
    if not res.get("ok"):
        return _err(res["error"])
    status = res["status"]
    if status != "confirmed":
        print(_c(f"IDOR not confirmed ({status}).", "33"))
        print(f"  {res.get('reason', '')}")
        if res.get("detail"):
            print(f"  detail: {res['detail']}")
        return 0
    finding = res["finding"]; finding.setdefault("ref", "F1"); plan = res["attack_plan"]
    ctx = {"tool": "GreyIQ BugHunter", "version": VERSION,
           "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
           "target": args.url_a, "scope": args.scope or "", "attack_plans": {"F1": plan}}
    md = report_formats.render_finding(ctx, finding, report_formats.normalize_platform(args.platform))
    print(_c("IDOR / broken access control CONFIRMED", "32") + f" at {finding['title']}")
    print(f"  differential: {res.get('detail')}")
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out = args.out or str(RUNTIME_DIR / "reports" / f"idor-{stamp}.md")
    try:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(md, encoding="utf-8")
        print(f"  report: {out}")
    except OSError as exc:
        print(_c(f"  (could not write report: {exc})", "33"))
    return 0


def _cmd_bundle(args: argparse.Namespace) -> int:
    from pathlib import Path

    from bughunter import bundle

    src = str(args.path or "").strip()
    if not src or not Path(src).is_dir():
        return _err(f"not a folder: {src or '(none)'} — point this at an engagement/campaign output directory.")
    out = args.out or (src.rstrip("/\\") + ".zip")
    res = bundle.bundle_directory(src, out)
    if not res.get("ok"):
        return _err(res.get("error", "could not build the bundle."))
    print(f"{_c('Bundle written', '1')}: {res['path']}")
    print(f"  {res['file_count']} file(s), {res.get('zip_bytes', 0)} bytes"
          + (f", {len(res['skipped'])} skipped" if res.get("skipped") else ""))
    return 0


def _cmd_platforms(args: argparse.Namespace) -> int:
    from bughunter import report_formats

    platforms = report_formats.list_platforms()
    if args.json:
        print(json.dumps({"platforms": platforms, "default": report_formats.DEFAULT_PLATFORM}, indent=2))
        return 0
    print(_c("Report formats (use --platform <id> on a campaign):", "1"))
    for p in platforms:
        default = "  (default)" if p["id"] == report_formats.DEFAULT_PLATFORM else ""
        print(f"  {_c(p['id'], '36'):<28} {p['name']}{default}")
        print(f"      {p['blurb']}")
    return 0


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
    hunt.add_argument("--time-based", dest="time_based", action="store_true",
                      help="opt-in: add the bounded-SLEEP blind-SQLi probe (implies --active; off by default — it executes a fixed SLEEP)")
    hunt.add_argument("--cookie", default="", help="scan behind a login: a Cookie header value, sent to the target host + subdomains ONLY")
    hunt.add_argument("--header", action="append", metavar="'Name: value'",
                      help="extra auth header (repeatable), e.g. --header 'Authorization: Bearer ...'; sent same-site only")
    hunt.add_argument("--live", action="store_true", help="dynamic Playwright browser pass (URL targets)")
    hunt.add_argument("--brain", action="store_true", help="use the configured LLM brain to enrich (default: deterministic)")
    hunt.add_argument("-o", "--out", default=None, help="report output folder (default: runtime/reports)")
    hunt.add_argument("--per-finding", action="store_true", help="also write one submission-ready file per finding")
    hunt.add_argument("-y", "--authorize", action="store_true", help="confirm you are AUTHORIZED to test the target (required)")
    hunt.add_argument("--json", action="store_true", help="print the machine-readable result")
    hunt.set_defaults(func=_cmd_hunt)

    camp = sub.add_parser("campaign", help="end-to-end: recon -> hunt every URL -> prove -> submission packages -> learn")
    camp.add_argument("target", help="https:// URL (recon-crawled) or repo/folder path")
    camp.add_argument("-s", "--scope", default="", help="program/scope notes (name the host to allow active checks)")
    camp.add_argument("--program", default=None, help="program handle for the learning store (default: target domain)")
    camp.add_argument("--active", action="store_true", help="capture proof of impact on each URL (recommended)")
    camp.add_argument("--time-based", dest="time_based", action="store_true",
                      help="opt-in: add the bounded-SLEEP blind-SQLi probe per URL (implies --active; off by default)")
    camp.add_argument("--cookie", default="", help="scan behind a login: a Cookie header value, sent to in-scope hosts + subdomains ONLY")
    camp.add_argument("--header", action="append", metavar="'Name: value'",
                      help="extra auth header (repeatable), e.g. --header 'Authorization: Bearer ...'; sent same-site only")
    camp.add_argument("--live", action="store_true", help="dynamic Playwright pass per URL")
    camp.add_argument("--brain", action="store_true", help="use the configured LLM brain to enrich")
    camp.add_argument("--max-pages", type=int, default=12, help="recon discovery cap (default 12)")
    camp.add_argument("--platform", default="hackerone",
                      help="report format for the submission packages: hackerone | yeswehack | bugcrowd | intigriti (see `gn platforms`)")
    camp.add_argument("--deep", action="store_true",
                      help="aggressive: implies --active + time-based blind SQLi, and auto-captures a screenshot + writes a brain-researched dossier for each confirmed lead")
    camp.add_argument("-y", "--authorize", action="store_true", help="confirm you are AUTHORIZED + in scope (required)")
    camp.add_argument("--json", action="store_true")
    camp.set_defaults(func=_cmd_campaign)

    learn = sub.add_parser("learn", help="record a finding's bounty outcome (teaches the engine)")
    learn.add_argument("-c", "--class", dest="vuln_class", required=True, help="vuln class id (see `gn classes`)")
    learn.add_argument("--status", required=True, help="accepted | resolved | duplicate | informative | not-applicable | triaged | submitted | spam")
    learn.add_argument("--program", default=None, help="program handle (default: derived from --target)")
    learn.add_argument("--target", default="", help="target URL/host (used to derive the program if no handle)")
    learn.add_argument("--bounty", type=float, default=0.0, help="bounty amount, if any")
    learn.add_argument("--severity", default="", help="severity, e.g. high")
    learn.add_argument("--title", default="", help="short finding title")
    learn.add_argument("--notes", default="", help="free-text notes")
    learn.set_defaults(func=_cmd_learn)

    stats = sub.add_parser("stats", help="show what the engine has learned per program")
    stats.add_argument("--program", default=None, help="a program handle (omit for all programs)")
    stats.add_argument("--target", default="", help="a target URL/host (derives the program)")
    stats.add_argument("--json", action="store_true")
    stats.set_defaults(func=_cmd_stats)

    op = sub.add_parser("operator", help="autonomous operator — run a portfolio of programs unattended")
    op.set_defaults(func=_cmd_operator, op_action=None)
    opsub = op.add_subparsers(dest="op_action", metavar="<action>")
    opsub.add_parser("list", help="list portfolio programs").set_defaults(func=_cmd_operator)
    opa = opsub.add_parser("add", help="add or update a program")
    opa.add_argument("--name", required=True)
    opa.add_argument("--scope", required=True, help="scope hosts/wildcards (the fail-closed active gate)")
    opa.add_argument("--targets", nargs="+", default=[], help="seed target URLs (each in scope)")
    opa.add_argument("--handle", default="", help="HackerOne team handle (required to auto-submit)")
    opa.add_argument("--interval", type=int, default=1440, help="re-run cadence in minutes (default 1440)")
    opa.add_argument("--max-submits", dest="max_submits", type=int, default=3, help="max auto-submits/day (default 3)")
    opa.add_argument("--max-pages", dest="max_pages", type=int, default=12)
    opa.add_argument("--active", action="store_true", help="capture proof of impact")
    opa.add_argument("--live", action="store_true", help="dynamic Playwright pass")
    opa.add_argument("--deep", action="store_true",
                     help="aggressive auto-work (implies --active): time-based SQLi + a screenshot + a researched dossier per confirmed lead")
    opa.add_argument("--auto-submit", dest="auto_submit", action="store_true", help="opt this program into auto-submission")
    opa.set_defaults(func=_cmd_operator)
    opr = opsub.add_parser("remove", help="remove a program")
    opr.add_argument("id")
    opr.set_defaults(func=_cmd_operator)
    oprun = opsub.add_parser("run", help="run the operator loop")
    oprun.add_argument("--once", action="store_true", help="run each due program one cycle, then exit")
    oprun.add_argument("--allow-submit", dest="allow_submit", action="store_true", help="ARM auto-submission (per-program opt-in still applies)")
    oprun.add_argument("--brain", action="store_true", help="use the configured LLM brain to enrich")
    oprun.add_argument("-y", "--authorize", action="store_true", help="confirm you're AUTHORIZED on every enabled program (required)")
    oprun.set_defaults(func=_cmd_operator)
    opp = opsub.add_parser("pipeline", help="show the money pipeline funnel")
    opp.set_defaults(func=_cmd_operator)

    scan = sub.add_parser("scan", help="quick code/web scan with a triage summary")
    scan.add_argument("target", help="https:// URL or local path")
    scan.add_argument("--json", action="store_true", help="print the raw scan result")
    scan.set_defaults(func=_cmd_scan)

    profiles = sub.add_parser("profiles", help="list hunt profiles")
    profiles.add_argument("--json", action="store_true")
    profiles.set_defaults(func=_cmd_profiles)

    platforms = sub.add_parser("platforms", help="list report formats (HackerOne, YesWeHack, Bugcrowd, Intigriti)")
    platforms.add_argument("--json", action="store_true")
    platforms.set_defaults(func=_cmd_platforms)

    bundle = sub.add_parser("bundle", help="zip an engagement folder (reports + evidence + screenshots) for download")
    bundle.add_argument("path", help="the engagement/campaign output folder to zip")
    bundle.add_argument("-o", "--out", default=None, help="output .zip path (default: <folder>.zip)")
    bundle.set_defaults(func=_cmd_bundle)

    takeover = sub.add_parser("takeover", help="enumerate subdomains of an apex and confirm dangling subdomain takeovers")
    takeover.add_argument("target", help="apex/host to enumerate (e.g. example.com)")
    takeover.add_argument("-s", "--scope", default="", help="scope (name the apex/wildcard to allow testing)")
    takeover.add_argument("--json", action="store_true")
    takeover.add_argument("-y", "--authorize", action="store_true", help="confirm the apex is in scope (required)")
    takeover.set_defaults(func=_cmd_takeover)

    idor = sub.add_parser("idor", help="confirm IDOR / broken access control with TWO of your authorized test accounts")
    idor.add_argument("url_a", help="account A's object URL (e.g. https://app/api/order/1001)")
    idor.add_argument("url_b", help="account B's OWN object URL on the same host (a DIFFERENT object B owns)")
    idor.add_argument("--a-cookie", dest="a_cookie", default="", help="account A's Cookie header value")
    idor.add_argument("--a-header", dest="a_header", action="append", metavar="'Name: value'", help="account A auth header (repeatable)")
    idor.add_argument("--b-cookie", dest="b_cookie", default="", help="account B's Cookie header value")
    idor.add_argument("--b-header", dest="b_header", action="append", metavar="'Name: value'", help="account B auth header (repeatable)")
    idor.add_argument("-s", "--scope", default="", help="scope (name the host to allow active testing)")
    idor.add_argument("--platform", default="hackerone", help="report format (see `gn platforms`)")
    idor.add_argument("-o", "--out", default=None, help="report output path")
    idor.add_argument("-y", "--authorize", action="store_true", help="confirm you OWN both test accounts and are in scope (required)")
    idor.set_defaults(func=_cmd_idor)

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
