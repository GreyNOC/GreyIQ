"""GreyIQ ``gn`` — drive the bug-bounty engine from the terminal.

Short, scriptable commands over the same engine the desktop app uses:

    gn hunt https://example.com -s "example.com" --active -y
    gn hunt ./path/to/repo -p source-code -y
    gn scan https://example.com --scope example.com -y
    gn scan ./path/to/repo
    gn osint example.com
    gn osint example.com --hunt -s "*.example.com" -y
    gn profiles | gn classes | gn tools xss ssrf

Torch-free and frozen-safe: it imports only the bughunter engine (the scanners,
the impact/proof model, the active verifier), so it runs anywhere the scanners
run — including a phone — without the ML stack. The frozen backend exe dispatches
here when given a subcommand (see run_frozen.py), so the shipped binary is also
the CLI.

Two structural rules make that dual-purpose binary safe to extend:

  * A verb owned by another module registers ITSELF through ``_VERB_PLUGINS``
    (see :func:`_register_plugin_verbs`) instead of being hand-wired here, so
    adding a command touches exactly one file — the module that implements it.
  * ``CLI_COMMANDS`` is DERIVED from :func:`build_parser`, never hand-listed.
    The hand-listed tuple had silently drifted: ``platforms``, ``bundle``,
    ``takeover``, ``cve``, ``idor``, ``bfla`` and ``idor-probe`` were all
    registered on the parser but missing from it, so ``run_frozen.py``'s
    dispatch test failed and the shipped exe booted the API SERVER instead of
    running those commands. Deriving the set makes that drift unrepresentable.

Both rules cost a parser build at import time, which is only cheap because every
``_cmd_*`` imports its engine INSIDE the function body (see ``_cmd_traces`` /
``_cmd_scan``). Registration must stay import-light or ``test_boot_no_torch.py``
and CLI startup latency both regress — that convention binds plugins too.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# --- Resolve seed/runtime dirs exactly like greyiq_api (frozen vs dev). ---
if getattr(sys, "frozen", False):
    _BUNDLE = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    BACKEND_DIR, PROJECT_ROOT, SEED_DIR = _BUNDLE, _BUNDLE, _BUNDLE / "seed"
else:
    BACKEND_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT, SEED_DIR = BACKEND_DIR.parent, BACKEND_DIR / "seed"


def _resolve_runtime_dir(project_root: Path) -> Path:
    """Keep frozen Linux CLI data outside the read-only application bundle."""
    explicit = os.getenv("GREYIQ_RUNTIME_DIR")
    if explicit is not None:
        return Path(explicit).resolve()
    if getattr(sys, "frozen", False) and sys.platform == "linux":
        xdg_home = os.getenv("XDG_DATA_HOME")
        data_home = Path(xdg_home) if xdg_home else Path.home() / ".local" / "share"
        if not data_home.is_absolute():
            data_home = Path.home() / ".local" / "share"
        return (data_home / "greyiq" / "runtime").resolve()
    return (project_root / "runtime").resolve()


RUNTIME_DIR = _resolve_runtime_dir(PROJECT_ROOT)

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

# Verbs run_frozen.py dispatches on that have NO subparser of their own. "gn" is the bare
# alias prefix (`greyiq-backend.exe gn hunt ...`), stripped by main() before parsing.
_ALWAYS_DISPATCH: tuple[str, ...] = ("gn",)

# Modules that own their own `gn` verb. Each exposes `register_cli(sub) -> None`, which calls
# sub.add_parser(...) + set_defaults(func=...). Imported LAZILY by build_parser() and
# fail-closed: a module that does not exist yet (or fails to import, or raises while
# registering) is simply skipped, so the CLI always builds. A plugin MUST keep its module
# import light — it runs on every `import gn_cli`, and pulling torch/pandas in at
# registration time would break test_boot_no_torch.py and CLI startup. Import the engine
# inside the command function, exactly like the _cmd_* handlers below.
_VERB_PLUGINS: tuple[str, ...] = ("bughunter.hunt_train", "coder_train",
                                  "bughunter.wardrive.cli", "edit_mine")

_SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def _color_enabled() -> bool:
    # The stdout half of the pair documented on ``gn_fx.enabled``. ``TERM=dumb`` wins here too,
    # and it is normalised before comparing: the bare ``!= "dumb"`` let ``TERM=DUMB`` and a
    # trailing space through, while gn_fx lower()s and strip()s, so one shell could get colour
    # and no motion from the same request. An empty TERM still keeps colour here: one SGR code
    # needs no terminfo entry, where the cursor control gn_fx uses is the stricter ask.
    return (sys.stdout.isatty() and os.getenv("NO_COLOR") is None
            and str(os.getenv("TERM") or "").strip().lower() != "dumb")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _color_enabled() else text


def _pad(text: str, code: str, width: int) -> str:
    """Colour ``text`` and pad it to ``width`` VISIBLE characters.

    Every column in this file used to be written ``f"{_c(name, '36'):<28}"``, which pads the
    ANSI-WRAPPED string — so with colour on, the nine invisible bytes of the escape sequence were
    counted as content and every column was nine characters short. `gn classes`, `gn profiles`,
    `gn tools`, `gn stats` and the operator listing all rendered as a ragged mess on a real terminal
    and looked perfect in the tests, which capture through StringIO and so never colour at all.
    Pad on the plain text, then wrap.
    """
    body = str(text)
    filler = " " * max(0, int(width) - len(body))
    return _c(body, code) + filler


def _fx(args: argparse.Namespace, title: str) -> Any:
    """The live animated status line for a long verb — see ``gn_fx``.

    Inert (not one byte written) unless stderr is a terminal a human is watching, and never under
    ``--json`` even on a terminal: a caller redirecting stdout to a file is still a machine consumer
    and the phase lines would confuse a log. ``--no-fx`` and ``GN_NO_FX=1`` both turn it off.
    """
    import gn_fx

    off = bool(getattr(args, "no_fx", False)) or bool(getattr(args, "json", False))
    return gn_fx.scanner(title, active=False if off else None)


def _progress(args: argparse.Namespace, fx: Any) -> Any:
    """The ``on_progress`` sink the engines take.

    Three modes, in priority order: nothing under ``--json`` (stdout must stay one parseable
    document); the live line when a human is watching stderr; otherwise the historical dim stdout
    line, byte-identical to what this printed before the animation existed — which is what a pipe,
    a CI log and the whole test suite get.
    """
    import gn_fx

    if getattr(args, "json", False):
        return None
    return gn_fx.progress_sink(fx, fallback=(lambda m: print(_c(f"  - {m}", "2"))))


def _fx_report(fx: Any, result: dict) -> None:
    """Flash the live line once per CONFIRMED finding, in its own severity colour.

    Confirmed only, and read from the engine's own proof status rather than the severity field: the
    whole point of this program is that a candidate is not a finding, so a passive header lead must
    not flash Critical across the operator's terminal. A run that confirms nothing leaves the line
    showing the phase and nothing else, which is the honest outcome.
    """
    if fx is None or not getattr(fx, "active", False):
        return
    try:
        for finding in (result.get("findings") or []):
            if not isinstance(finding, dict):
                continue
            status = str(finding.get("proof_status") or (finding.get("proof_of_impact") or {}).get("status") or "")
            if status.strip().lower() != "confirmed":
                continue
            fx.hit(str(finding.get("severity") or "info"), str(finding.get("title") or ""))
    except Exception:  # noqa: BLE001 - a decoration must never break a completed hunt
        pass


def _err(message: str) -> int:
    print(_c(f"gn: {message}", "31"), file=sys.stderr)
    return 2


def _ensure_dir(path: Path | str) -> Path:
    """Create an output directory THIS PROGRAM chose, parents and all, idempotently.

    A clean checkout has no ``runtime/``. The API server makes it at boot
    (``greyiq_api``: ``RUNTIME_DIR.mkdir(parents=True)``) and nothing on the CLI path ever did, so
    the first `gn hunt` on a fresh clone died inside ``bounty._resolve_output_dir`` — which calls
    ``mkdir(parents=False)`` — with a bare ``FileNotFoundError`` naming a reports directory the
    operator had not asked for and could not place. The same hole swallowed `gn osint`, `gn bfla`
    and `gn idor` whenever ``GREYIQ_RUNTIME_DIR`` pointed somewhere not yet created.

    Only for paths this program chose (``RUNTIME_DIR`` and its subdirectories). A directory the
    OPERATOR named with ``-o`` is handed to the engine untouched: ``bounty._resolve_output_dir``
    deliberately refuses to conjure a brand-new multi-level tree at an arbitrary path, and
    pre-creating it here would quietly defeat that containment guard from the outside.

    Total. An unwritable path is returned unchanged so the verb fails at the write, with the real
    error about the real file, instead of here with a second error about a directory.
    """
    target = Path(path)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return target


def _reports_dir() -> Path:
    """``runtime/reports``, created on demand — the default every report-writing verb falls back to."""
    return _ensure_dir(RUNTIME_DIR / "reports")


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


def _oob_config() -> tuple[str, str]:
    """The operator's OOB collaborator (url, secret) from the runtime secrets store.

    Same file and same keys ``greyiq_api._oob_config`` reads, so a collaborator configured in the
    desktop app is honoured by the CLI too. Without this, ``gn hunt`` and ``gn campaign`` had the four
    out-of-band provers -- blind SSRF, blind XXE, blind RCE and JWT key-URL injection -- permanently
    disabled, because run_bounty_hunt gates each one on a configured collaborator. Read directly
    rather than through greyiq_api so the CLI keeps its import-light, torch-free startup.

    Total: an unreadable or malformed store means "no collaborator", which disables the provers —
    exactly the behaviour before this existed. It never invents one.
    """
    try:
        stored = json.loads((RUNTIME_DIR / "secrets.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ("", "")
    if not isinstance(stored, dict):
        return ("", "")
    base = str(stored.get("oob.collaborator_url") or "").strip()
    secret = str(stored.get("oob.secret") or "").strip()
    # Both or neither: a base with no secret cannot mint a token, and the provers require both.
    return (base, secret) if base and secret else ("", "")


#: One sentence, one place. `gn hunt` and `gn dash` gate on the same thing and must refuse in the
#: same words: an operator who learns the wording from one verb and gets a different sentence from
#: the other has been told there are two different rules.
_HUNT_AUTHORIZE = ("a hunt tests a live/owned target — pass -y/--authorize to confirm you're "
                   "authorized and in scope.")


#: The depth variables, in one place because `hunt` and `dash` must register the SAME set (a test
#: pins dash's namespace as a superset of hunt's) and `/help -v` renders this exact table.
#: Every row names the real setting it moves and what bounds the extra spend — a flag whose
#: "effect" is behaviour the engine already performs unconditionally is not a flag, it is a lie,
#: and several candidates were dropped for exactly that.
DEPTH_VARIABLES: tuple[dict[str, str], ...] = (
    {"flag": "-Th, --theorize", "knob": "hunt_loop_enabled + hunt_loop_offline_enabled",
     "means": "iterative theorize -> probe -> re-plan on the seed URL",
     "bound": "<=400 requests total, <=6 turns, stops early on no progress",
     "note": "implies --active. Trades the 4-endpoint fan-out for depth on ONE url."},
    {"flag": "-Tn, --turns N", "knob": "hunt_loop_max_iters",
     "means": "how many theorize turns -Th may take, 1-6",
     "bound": "clamped to 1..6; the 400-request budget still binds first",
     "note": "no effect without -Th. Default 3."},
    {"flag": "-Ch, --chain", "knob": "hunt_replan_enabled",
     "means": "after the active pass, re-probe the step that blocks the best chain",
     "bound": "<=3 endpoints, <=3 classes, <=8 requests, once",
     "note": "implies --active. One bounded wave, not a second hunt."},
    {"flag": "-v, --variables", "knob": "(help only)",
     "means": "print this table",
     "bound": "no engine call, no requests",
     "note": "`/help -v` in the cockpit, `gn hunt --variables` in a shell."},
)


def variables_lines() -> list[str]:
    """``/help -v`` and ``gn hunt --variables``: the depth table with its real knobs and bounds."""
    lines = ["hunt depth variables", ""]
    for row in DEPTH_VARIABLES:
        lines.append(f"  {row['flag']:<18} {row['means']}")
        lines.append(f"  {'':<18}   engine knob : {row['knob']}")
        lines.append(f"  {'':<18}   bounded by  : {row['bound']}")
        lines.append(f"  {'':<18}   {row['note']}")
        lines.append("")
    lines.extend([
        "  Stop is honoured between turns and before the chain wave - a turn already in flight",
        "  finishes first, exactly as `stop` promises everywhere else.",
        "",
        "  Theorizing and chaining NEVER promote a theory to a finding: only a captured artifact",
        "  confirms. More depth buys more tested leads, not more claimed bugs.",
    ])
    return lines


def _register_depth_flags(parser: argparse.ArgumentParser) -> None:
    """The same four options on `hunt` and `dash`. Short forms are case-sensitive on purpose:
    -Th/-Tn/-Ch read as words, and argparse would otherwise collide -t with --time-based."""
    parser.add_argument("-Th", "--theorize", action="store_true",
                        help="iterative theorize -> probe -> re-plan on the seed URL "
                             "(implies --active; <=400 requests, <=6 turns)")
    parser.add_argument("-Tn", "--turns", type=int, default=None, metavar="N",
                        help="how many theorize turns -Th may take, 1-6 (default 3)")
    parser.add_argument("-Ch", "--chain", action="store_true",
                        help="after the active pass, re-probe the step blocking the best chain "
                             "(implies --active; <=3 endpoints, <=8 requests)")
    parser.add_argument("-v", "--variables", action="store_true",
                        help="print the depth-variable table and exit")


def depth_refusal(args: argparse.Namespace) -> str:
    """``""`` when the depth flags are coherent, else why they are not.

    ``-Tn`` moves ``hunt_loop_max_iters``, which the engine reads ONLY when the loop is on. Without
    ``-Th`` the hunt therefore succeeds while silently ignoring the depth that was asked for, and an
    operator reads a normal-looking summary as the result of a deeper experiment. The cockpit's
    ``/hunt`` already refuses this exact pair; the shell path must agree, or the same command means
    two different things depending on where it was typed.
    """
    if getattr(args, "turns", None) is not None and not getattr(args, "theorize", False):
        return ("-Tn/--turns only has an effect with -Th/--theorize (it sets the loop's iteration "
                "count, and the loop is off) - add -Th, or drop -Tn.")
    return ""


def depth_settings(args: argparse.Namespace) -> Any:
    """The ``settings`` object for this hunt, or None when no depth flag was passed.

    Returns None rather than a default-valued copy so an untouched hunt keeps taking the engine's
    own ``get_settings()`` — handing down a snapshot taken at parse time would silently freeze any
    env var the engine would otherwise re-read.
    """
    import dataclasses

    from bughunter.active_verify_service import get_settings

    theorize = bool(getattr(args, "theorize", False))
    chain = bool(getattr(args, "chain", False))
    turns = getattr(args, "turns", None)
    if not (theorize or chain or turns is not None):
        return None
    changes: dict[str, Any] = {}
    if theorize:
        # BOTH, or the loop enables and then dies at turn 0: without a reasoning brain the planner
        # returns an empty done=True plan unless the offline half is on too (hunt_loop.py).
        changes["hunt_loop_enabled"] = True
        changes["hunt_loop_offline_enabled"] = True
    if chain:
        changes["hunt_replan_enabled"] = True
    if turns is not None:
        # The same clamp settings.py applies to the env var. hunt_loop reads this back with no
        # clamp of its own, so an unclamped 9999 here would be honoured as 9999 turns.
        changes["hunt_loop_max_iters"] = max(1, min(int(turns), 6))
    return dataclasses.replace(get_settings(), **changes)


def _cmd_hunt(args: argparse.Namespace) -> int:
    from bughunter.bounty import run_bounty_hunt

    if getattr(args, "variables", False):
        for line in variables_lines():
            print(line)
        return 0
    refusal = depth_refusal(args)
    if refusal:
        return _err(refusal)
    if not args.authorize:
        return _err(_HUNT_AUTHORIZE)
    reports = _reports_dir()
    out_dir = args.out or str(reports)
    # A direct hunt used to pass no on_progress at ALL, so nothing printed between the command and the
    # summary -- minutes of silence in which a working hunt and a hung one look identical.
    fx = _fx(args, args.target)
    with fx:
        fx.phase("starting hunt")
        result = run_bounty_hunt(
            args.target,
            args.profile,
            args.vuln_class,
            out_dir,
            args.scope or "",
            True,  # authorized — gated by --authorize above
            _load_coder_config(args.brain),
            default_reports_dir=reports,
            seed_dir=SEED_DIR,
            runtime_dir=RUNTIME_DIR,
            version=VERSION,
            run_live=args.live,
            # -Th/-Ch imply --active for the same reason --time-based does: both branches live
            # inside `if (active or time_based) and authorized and kind == "url"`, so without it
            # the flag would be accepted and then quietly do nothing.
            active=(args.active or getattr(args, "time_based", False) or getattr(args, "deep", False)
                    or getattr(args, "theorize", False) or getattr(args, "chain", False)),
            time_based=getattr(args, "time_based", False),
            auth={"cookie": getattr(args, "cookie", "") or "", "headers": getattr(args, "header", None) or []},
            per_finding=args.per_finding,
            on_progress=_progress(args, fx),
            settings=depth_settings(args),
            oob_base=_oob_config()[0], oob_secret=_oob_config()[1],
        )
        _fx_report(fx, result)
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
    fx = _fx(args, args.target)
    with fx:
        fx.phase("starting campaign")
        result = run_campaign(
            args.target,
            scope=args.scope or "",
            authorized=True,
            coder_cfg=_load_coder_config(args.brain),
            default_reports_dir=_reports_dir(),
            seed_dir=SEED_DIR,
            runtime_dir=RUNTIME_DIR,
            version=VERSION,
            active=args.active or getattr(args, "time_based", False) or getattr(args, "deep", False),  # --time-based/--deep imply --active
            time_based=getattr(args, "time_based", False),
            auth={"cookie": getattr(args, "cookie", "") or "", "headers": getattr(args, "header", None) or []},
            live=args.live,
            program=args.program,
            max_pages=args.max_pages,
            osint=getattr(args, "osint", False),
            platform=getattr(args, "platform", "hackerone") or "hackerone",
            deep=getattr(args, "deep", False),
            on_progress=_progress(args, fx),
            oob_base=_oob_config()[0], oob_secret=_oob_config()[1],
        )
        _fx_report(fx, result)
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


def _cmd_osint(args: argparse.Namespace) -> int:
    """Run passive evidence collection; optionally hand DNS-verified hosts to BugHunter."""
    from bughunter import osint as osint_engine

    if args.hunt and not args.authorize:
        return _err("--hunt opens live targets — pass -y/--authorize to confirm you are authorized and in scope.")
    if args.hunt and not str(args.scope or "").strip():
        return _err("--hunt requires explicit --scope; OSINT discovery never grants authorization.")
    if args.active and not args.hunt:
        return _err("--active is valid only with --hunt.")

    # Started, not `with`-wrapped: this function has five early `return _err(...)` exits below, and
    # gn_fx.stop_all() in main()'s finally clears the line on every one of them.
    fx = _fx(args, args.target)
    fx.start()
    fx.phase("passive OSINT collection")
    result = osint_engine.run_campaign(
        args.target,
        output_dir=args.out or _ensure_dir(RUNTIME_DIR / "osint"),
        max_hosts=args.max_hosts,
        timeout=args.timeout,
    )
    hunt_result: dict | None = None
    if args.hunt:
        targets = list(result.get("hunt_targets") or [])
        if not targets:
            return _err(
                "no hosts met the two-resolver DNS verification gate; review the OSINT report "
                f"at {result.get('report_path', '')}"
            )
        from bughunter.active_verify_service import host_in_active_scope
        from bughunter.settings import get_settings

        scope_settings = get_settings()
        targets = [
            target for target in targets
            if host_in_active_scope(urlparse(str(target)).hostname or "", args.scope, scope_settings)
        ]
        if not targets:
            return _err(
                "no DNS-verified OSINT hosts are within the explicit --scope; "
                "OSINT discovery never expands authorization."
            )
        from bughunter.campaign import run_campaign_over_targets

        hunt_result = run_campaign_over_targets(
            targets,
            scope=args.scope,
            authorized=True,
            coder_cfg=_load_coder_config(args.brain),
            default_reports_dir=_reports_dir(),
            seed_dir=SEED_DIR,
            runtime_dir=RUNTIME_DIR,
            version=VERSION,
            active=args.active,
            live=args.live,
            program=args.program or result.get("apex"),
            max_pages=args.max_pages,
            platform=args.platform,
            on_progress=_progress(args, fx),
        )
        if not hunt_result.get("ok"):
            return _err(hunt_result.get("error", "the verified-host hunt could not run."))
        _fx_report(fx, hunt_result)

    fx.stop()
    if args.json:
        payload = dict(result)
        if hunt_result is not None:
            payload["hunt"] = hunt_result
        print(json.dumps(payload, indent=2, default=str))
        return 1 if result.get("status") == "failed" else 0

    summary = result.get("summary") or {}
    state = str(result.get("status") or "unknown").upper()
    print(f"\n{_c('GreyIQ OSINT', '1')} — {result.get('domain', '')}  [{state}]")
    print(
        f"Assets: {summary.get('assets_total', 0)} observed   "
        f"{_c(str(summary.get('hunt_eligible', 0)) + ' DNS-verified', '32')}   "
        f"Claims: {summary.get('claims_verified', 0)} verified / {summary.get('claims_observed', 0)} observed"
    )
    print(f"Evidence report: {result.get('report_path', '')}  (+ JSON sidecar)")
    if hunt_result is not None:
        print(
            f"Bug Hunt: {hunt_result.get('targets_hunted', 0)} target(s), "
            f"{hunt_result.get('finding_count', 0)} finding(s), "
            f"{hunt_result.get('confirmed_count', 0)} confirmed — {hunt_result.get('campaign_path', '')}"
        )
    elif summary.get("hunt_eligible"):
        print("Next: add `--hunt --scope <program-scope> -y` to campaign against verified hosts only.")
    return 1 if result.get("status") == "failed" else 0


def _cmd_learn(args: argparse.Namespace) -> int:
    from bughunter import learning

    try:
        prog = learning.record_outcome(
            RUNTIME_DIR, program=args.program, target=args.target or "", class_id=args.vuln_class,
            title=args.title or "", status=args.status, bounty=args.bounty, severity=args.severity or "", notes=args.notes or "",
            finding_id=getattr(args, "finding_id", "") or "",
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
            print(f"  {_pad(key, '36', 28)} submitted {summary['submitted']}, rewarded {summary['rewarded']}, ${summary['bounty_total']:g}")
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


def _cmd_traces(args: argparse.Namespace) -> int:
    from bughunter import hunt_trace

    stats = hunt_trace.trace_stats(RUNTIME_DIR)
    if args.json:
        print(json.dumps(stats, indent=2, default=str))
        return 0
    if not stats["hunts"]:
        print("No hunt traces recorded yet. Run a URL hunt or campaign; each one appends to the "
              "offline-brain training corpus (hunt_traces.jsonl).")
        return 0
    print(_c("Hunt trace corpus (offline-brain distillation):", "1"))
    print(f"  {stats['hunts']} hunt(s) across {stats['programs']} program(s)")
    print(f"  {stats['outcome_rows']} outcome row(s), {_c(str(stats['confirmed_rows']) + ' confirmed', '32')}")
    print("\nThis is the local training data for a learned offline hunt ranker (see "
          "docs/offline-hunt-brain-distillation.md). Nothing here leaves your machine.")
    return 0


_LEAD_STATUS_COLOR = {
    "confirmed": "32", "supported": "36", "candidate": "33",
    "contradicted": "1;31", "report-now": "32",
}


def _cmd_leads(args: argparse.Namespace) -> int:
    """Export a finished hunt's ranked investigation queue — the lead bridge.

    Reads a hunt's JSON sidecar (or sweeps an engagement directory) and emits the cortex's
    hypotheses, chains, contradictions, and proof obligations as a redaction-safe queue an
    analyst — or a configured Claude brain — can work lead by lead."""
    from bughunter import leads as leads_lib

    report = leads_lib.build_lead_report(args.path)

    # Filter FIRST, so every renderer below sees the same queue. --brief used to return before this,
    # which silently ignored --status/--min-confidence on exactly the output most likely to be handed
    # to an analyst. Filtering happens on the projected queue (never the raw sidecar), so a filtered
    # export keeps the same shape as an unfiltered one — just fewer leads.
    if args.ref or args.status or args.min_confidence is not None:
        def _keep(row: dict) -> bool:
            return ((not args.ref or row.get("id") == args.ref)
                    and (not args.status or _lead_matches_status(row, args.status))
                    and (args.min_confidence is None or _lead_confidence(row) >= args.min_confidence))

        for queue in report.get("hunts", []):
            queue["leads"] = [lead for lead in queue.get("leads", []) if _keep(lead)]
            # Chain probes are a second, id-namespaced lead type (CP*/CR*) that the brief renders,
            # so the SAME filters have to reach them — otherwise `--status confirmed` still emitted
            # every `untested` probe. The predicate works unchanged on a probe: it carries `status`,
            # has no `report_ready`, and has no confidence score, so a `--min-confidence` floor
            # correctly excludes an untested lead.
            queue["chain_probes"] = [p for p in queue.get("chain_probes", []) if _keep(p)]

    if args.brief:
        # A Markdown investigation brief, wrapped as untrusted data — ready to hand to a model.
        print(leads_lib.render_lead_brief(report, ref=args.ref, wrap=not args.no_wrap))
        return 0

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    hunts = report.get("hunts") or []
    if not hunts:
        found = report.get("source", {}).get("sidecars", 0)
        if found:
            return _err(f"no GreyIQ hunt sidecar with an investigation graph under {args.path}.")
        return _err(f"no hunt report found at {args.path} — pass a bounty-*.json sidecar or an engagement folder.")
    for queue in hunts:
        _print_lead_queue(queue)
    return 0


def _lead_confidence(lead: dict) -> int:
    try:
        return int(lead.get("confidence_score") or 0)
    except (TypeError, ValueError):
        return 0


def _lead_matches_status(lead: dict, status: str) -> bool:
    want = status.strip().lower()
    if want in {"report-ready", "ready"}:
        return bool(lead.get("report_ready"))
    return str(lead.get("status") or "").lower() == want


def _print_lead_queue(queue: dict) -> None:
    hunt = queue.get("hunt") or {}
    metrics = queue.get("metrics") or {}
    print(f"\n{_c('GreyIQ leads', '1')} — {hunt.get('target') or '(unknown target)'}")
    verdict = queue.get("verdict") or ""
    if verdict:
        print(f"Verdict: {verdict}")
    print(
        f"Leads: {metrics.get('hypotheses', len(queue.get('leads') or []))}  "
        f"{_c(str(metrics.get('confirmed', 0)) + ' confirmed', '32')}  "
        f"{metrics.get('supported', 0)} supported  {metrics.get('contradictions', 0)} contradiction(s)  "
        f"{metrics.get('attack_chains', 0)} chain(s)"
    )
    leads = queue.get("leads") or []
    if not leads:
        print("  (no leads at this depth)")
        return
    for lead in leads:
        status = str(lead.get("status") or "")
        color = _LEAD_STATUS_COLOR.get(status, "0")
        rank = lead.get("rank")
        tag = _c(f"[{lead.get('id')}]", "1")
        print(f"  {tag} {lead.get('title') or 'Lead'}")
        print(
            f"      {_c(status, color)} · {lead.get('confidence_band')} confidence "
            f"({lead.get('confidence_score')}) · {lead.get('class_id')}/{lead.get('severity')}"
            + (f" · rank {rank}" if rank else "")
            + ("  · report-ready" if lead.get("report_ready") else "")
        )
        for con in lead.get("contradictions") or []:
            if con.get("blocking"):
                print(_c(f"      ⚠ blocking: {con.get('message')}", "1;31"))
        if lead.get("proof_obligation"):
            print(f"      → to confirm: {lead['proof_obligation']}")
        if lead.get("in_chains"):
            print(f"      chains: {', '.join(lead['in_chains'])}")
    print(f"\n  {_c('gn leads', '2')} <path> --brief   for a Claude-ready investigation brief; "
          f"{_c('--json', '2')} for the machine queue.\n")


def _operator_campaign_fn(coder_cfg: dict):
    """Build the portfolio scheduler's campaign callable over the bughunter engine."""
    from bughunter import campaign as campaign_mod
    from bughunter import portfolio as portfolio_mod
    from bughunter import progress as progress_mod
    from coder import unattended_config

    safe_brain = unattended_config(coder_cfg)

    def run_campaign_fn(target, *, scope, program, active, live, deep=False, max_pages=12,
                        run_id=""):
        if run_id:
            progress_mod.start_run(run_id)
        saved = portfolio_mod.get_program(RUNTIME_DIR, program) or {}
        result = campaign_mod.run_campaign(
            target, scope=scope, authorized=True, coder_cfg=safe_brain,
            default_reports_dir=_reports_dir(), seed_dir=SEED_DIR, runtime_dir=RUNTIME_DIR,
            version=VERSION, active=active, live=live, deep=deep, program=program, max_pages=max_pages,
            progress_run_id=run_id or None,
            user_agent_suffix=str(saved.get("user_agent_suffix") or ""),
            policy_profile=str(saved.get("policy_profile") or ""),
            excluded_hosts=tuple(str(host) for host in (saved.get("out_of_scope_hosts") or [])),
            disclose_automation=bool(saved.get("disclose_automation")),
        )
        return result

    return run_campaign_fn


def _read_operator_grants(path: str) -> list[dict]:
    """Read a bounded, local grant manifest; the operator validates its contents."""
    grant_path = Path(path).expanduser()
    if not grant_path.is_file() or grant_path.stat().st_size > 256 * 1024:
        raise ValueError("grant file is missing or exceeds 256 KiB")
    try:
        payload = json.loads(grant_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"could not read the grant file: {exc}") from exc
    grants = payload.get("grants") if isinstance(payload, dict) else payload
    if not isinstance(grants, list):
        raise ValueError("grant file must contain a JSON list or an object with a grants list")
    return grants


def _cmd_operator(args: argparse.Namespace) -> int:
    from bughunter import operator as operator_mod
    from bughunter import portfolio

    # The portfolio, the ledger and the operator's state all land under the runtime dir; the verb
    # writes on nearly every action, so it is created up front rather than at each write site.
    rt = str(_ensure_dir(RUNTIME_DIR))
    action = getattr(args, "op_action", None)

    if action == "list" or action is None:
        progs = portfolio.list_programs(rt)
        if not progs:
            print("No programs yet. Add one: gn operator add --name acme --scope '*.acme.com' --targets https://acme.com")
            return 0
        print(_c(f"Portfolio ({len(progs)} program(s)):", "1"))
        for p in progs:
            flags = " ".join(f for f, on in (("active", p["active"]), ("live", p["live"]), ("deep", p.get("deep")),
                                             ("enabled", p["enabled"])) if on) or "disabled"
            print(f"  {_pad(p['id'], '36', 24)} {p['name']}  [{flags}]  scope: {p['scope_text'] or '(none)'}  "
                  f"targets: {len(p['seed_targets'])}  every {p['interval_minutes']}m")
        return 0

    if action == "add":
        prog = portfolio.upsert_program(rt, {
            "name": args.name, "scope_text": args.scope, "seed_targets": args.targets or [],
            "platform": "hackerone" if args.handle else "manual", "platform_handle": args.handle or "",
            "active": args.active, "live": args.live, "deep": getattr(args, "deep", False),
            "interval_minutes": args.interval, "max_submits_per_day": args.max_submits, "max_pages": args.max_pages,
        })
        warn = _c("  (automatic submission is disabled)", "33") if args.auto_submit else ""
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
        if args.allow_submit:
            return _err("automatic submission is disabled; review findings and submit manually.")
        if args.once:
            return _err("--once is unavailable until it can use the same grant and audit controls; use the Operator tab or continuous run with --grant-file")
        if not args.grant_file:
            return _err("pass --grant-file with a current authorization and policy record for every enabled program")
        try:
            grants = _read_operator_grants(args.grant_file)
        except (OSError, ValueError) as exc:
            return _err(str(exc))
        run_campaign_fn = _operator_campaign_fn(_load_coder_config(args.brain))
        loop = operator_mod.OperatorLoop(rt, run_campaign_fn=run_campaign_fn)
        # Continuous: run the loop, stream events, Ctrl+C to stop.
        try:
            loop.start(grants=grants)
        except (ValueError, OSError) as exc:
            return _err(str(exc))
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
        finally:
            # The supervisor is a daemon thread. Wait for its audit and lease
            # cleanup before the CLI process can exit (also on poll errors).
            if loop.running and not loop.stop_event.is_set():
                loop.stop()
            if loop._thread is not None:
                loop._thread.join()
        return 0

    return _err(f"unknown operator action: {action}")


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from terminal_dashboard import run_dashboard

    return run_dashboard(RUNTIME_DIR, port=args.port, interval=args.interval, version=VERSION)


def _cmd_scan(args: argparse.Namespace) -> int:
    from bughunter.chat_commands import (
        _code_target_type, _looks_like_path, _looks_like_url,
        validate_scoped_network_target,
    )
    from bughunter.code_scanner.sources.git_remote import is_supported_remote_git_url
    from bughunter.scan_service import run_code_scan
    from bughunter.triage import summarize_findings
    from bughunter.web_scan_service import run_web_scan

    target = args.target.strip()
    lowered = target.lower()
    remote_repo = is_supported_remote_git_url(target) or (
        lowered.startswith(("http://", "https://", "ssh://", "git@"))
        and (lowered.rstrip("/").endswith(".git") or lowered.startswith(("ssh://", "git@")))
    )
    if remote_repo:
        gate = validate_scoped_network_target("code", target, args.scope, args.authorize)
        if not gate["ok"]:
            return _err(str(gate["error"]))
        result = run_code_scan(target, "git_remote")
    elif _looks_like_url(target):
        gate = validate_scoped_network_target("web", target, args.scope, args.authorize)
        if not gate["ok"]:
            return _err(str(gate["error"]))
        result = run_web_scan(target, scope_host=str(gate["scope_host"]))
    elif _looks_like_path(target):
        target_type = _code_target_type(target)
        if target_type == "git_remote":
            gate = validate_scoped_network_target("code", target, args.scope, args.authorize)
            if not gate["ok"]:
                return _err(str(gate["error"]))
        result = run_code_scan(target, target_type)
    else:
        return _err("couldn't tell if that's a URL or a path. Use a full http(s):// URL or a folder/repo path.")
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("ok") else 1
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


def _cmd_cve(args: argparse.Namespace) -> int:
    from bughunter import cve_service as cv

    if not args.authorize:
        return _err("fetching the target to fingerprint its components touches an in-scope host — pass -y/--authorize.")
    res = cv.scan_known_cves(args.target, scope=args.scope or "")
    if not res.get("ok"):
        return _err(res.get("error", "could not run the scan."))
    comps = res.get("components") or []
    print(f"{_c('Known-CVE scan', '1')} — {res.get('host')}: {len(comps)} fingerprinted component(s)")
    findings = res.get("findings") or []
    if not findings:
        print("  no outdated components with known CVEs found.")
        if args.json:
            print(json.dumps(res, indent=2, default=str))
        return 0
    for f in findings:
        print(_c(f"  OUTDATED: {f['title']}", "33"))
        for ln in f.get("_cve_summary_lines", []):
            print(f"    - {ln}")
    if args.json:
        print(json.dumps(res, indent=2, default=str))
    return 0


def _cmd_bfla(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime
    from pathlib import Path

    from bughunter import access_control_service as ac
    from bughunter import report_formats

    if not args.authorize:
        return _err("BFLA testing uses your high- and low-privilege test sessions against an in-scope host — pass -y/--authorize.")
    res = ac.run_bfla_check(
        args.priv_url,
        admin_account={"cookie": args.admin_cookie or "", "headers": args.admin_header or []},
        user_account={"cookie": args.user_cookie or "", "headers": args.user_header or []},
        scope=args.scope or "",
    )
    if not res.get("ok"):
        return _err(res["error"])
    status = res["status"]
    if status != "confirmed":
        print(_c(f"BFLA not confirmed ({status}).", "33"))
        print(f"  {res.get('reason', '')}")
        if res.get("detail"):
            print(f"  detail: {res['detail']}")
        return 0
    finding = res["finding"]; finding.setdefault("ref", "F1"); plan = res["attack_plan"]
    ctx = {"tool": "GreyIQ BugHunter", "version": VERSION,
           "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
           "target": args.priv_url, "scope": args.scope or "", "attack_plans": {"F1": plan}}
    md = report_formats.render_finding(ctx, finding, report_formats.normalize_platform(args.platform))
    print(_c("BFLA / broken function-level authorization CONFIRMED", "32") + f" at {finding['title']}")
    print(f"  differential: {res.get('detail')}")
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out = args.out or str(_reports_dir() / f"bfla-{stamp}.md")
    try:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(md, encoding="utf-8")
        print(f"  report: {out}")
    except OSError as exc:
        print(_c(f"  (could not write report: {exc})", "33"))
    return 0


def _cmd_idor_probe(args: argparse.Namespace) -> int:
    from bughunter import access_control_service as ac

    if not args.authorize:
        return _err("the probe reads YOUR object with your session against an in-scope host — pass -y/--authorize.")
    res = ac.run_idor_probe(
        args.url, account={"cookie": args.cookie or "", "headers": args.header or []}, scope=args.scope or "")
    if not res.get("ok"):
        return _err(res["error"])
    status = res["status"]
    if status != "candidate" or "finding" not in res:
        print(_c(f"No IDOR signal ({status}).", "33"))
        print(f"  {res.get('reason', '')}")
        return 0
    print(_c("Possible IDOR (single-session id mutation) — CANDIDATE", "33") + f": {res['finding']['title']}")
    print(f"  {res['detail'].get('original')}  ->  {res['detail'].get('mutated')}")
    print(f"  a neighbouring id returned a distinct object (similarity {res['detail'].get('ratio_neighbour_vs_original')}).")
    print("  Confirm cross-tenant with: gn idor <A's object> <B's object> --a-cookie ... --b-cookie ... -y")
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
    out = args.out or str(_reports_dir() / f"idor-{stamp}.md")
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
    res = bundle.bundle_directory(src, out, meta={"tool": "GreyIQ BugHunter", "version": VERSION})
    if not res.get("ok"):
        return _err(res.get("error", "could not build the bundle."))
    print(f"{_c('Bundle written', '1')}: {res['path']}")
    print(f"  {res['file_count']} file(s), {res.get('zip_bytes', 0)} bytes"
          + (f", {len(res['skipped'])} skipped" if res.get("skipped") else ""))
    if res.get("manifest"):
        print(f"  evidence integrity manifest: {', '.join(res['manifest'])} "
              f"(verify with: sha256sum -c MANIFEST.sha256)")
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
        print(f"  {_pad(p['id'], '36', 28)} {p['name']}{default}")
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
        print(f"  {_pad(profile['id'], '36', 28)} {profile['name']}  ({kinds})")
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
        print(f"  {_pad(cls['id'], '36', 28)} {cls['name']}")
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
            print(f"  {_pad(tool.get('name', ''), '36', 24)} {tool.get('description', '')}")
            print(f"      {tool.get('url', '')}")
        return 0
    payload = toolkit_lib.catalog_payload(SEED_DIR, RUNTIME_DIR)
    print(f"{payload.get('count', 0)} curated tools. Pass a class id (see `gn classes`), e.g. `gn tools xss ssrf`.")
    return 0


def _cmd_fx(args: argparse.Namespace) -> int:
    """`gn fx` — draw the live status line for a few seconds, so a terminal can be checked without
    committing to a real hunt. Exits 2 with an explanation when motion is not appropriate here."""
    import gn_fx

    return gn_fx.demo(getattr(args, "seconds", 6.0))


def _dash_subcommand(argv: list[str], sink: Any = None) -> tuple[int, str]:
    """Run one real ``gn`` verb typed into the dashboard pane; hand back ``(exit code, output)``.

    The body lives in ``gn_dash`` because it owns what the pane needs around the call — the refusal
    vocabulary and the ``OutputTail`` the OUTPUT pane reads WHILE a slow verb is still writing — and
    a second copy here is exactly the hand-maintained duplicate that made ``CLI_COMMANDS`` wrong for
    seven verbs. This name exists so the wiring reads in one direction: ``_cmd_dash`` hands the
    dashboard a CLI-owned dispatcher, rather than the dashboard reaching back for one.
    """
    import gn_dash

    return gn_dash._dash_subcommand(argv, sink)  # noqa: SLF001 - one feature, three modules


def _dash_hunt(args: argparse.Namespace, run_id: str, into: dict) -> int:
    """The hunt ``gn dash <target>`` watches, as the callable ``gn_dash.run`` drives on its worker.

    The same engine call ``_cmd_hunt`` makes, with two differences, both forced by the terminal now
    belonging to the renderer:

      * Progress goes to ``bughunter.progress``, not ``gn_fx``. A status line written onto a screen
        the dashboard is row-diffing punches a hole in the frame that never repairs, and the store
        is where the panels read from anyway — the same store the API route writes, so a
        dash-launched hunt and an app-launched one produce identical snapshots.
      * ``should_stop`` is wired to the flag the pane's ``stop`` verb sets. Without it that verb
        would set something nothing reads, and the ``STOPPING`` pill would be a lie on screen.

    The result is stashed in ``into`` instead of returned, so ``_cmd_dash`` can print the ordinary
    hunt summary onto the RESTORED terminal: the report path is the one thing the operator still
    needs after the panels are gone, and it would otherwise die with the alternate screen.
    """
    from bughunter import progress as bounty_progress
    from bughunter.bounty import run_bounty_hunt

    import gn_dash

    target = str(args.target)
    reports = _reports_dir()
    # Register the single work unit exactly as the API route does, or the TARGETS panel stays empty
    # through a run that is working and the header reads 0/0 for its whole life.
    bounty_progress.start_run(run_id)
    bounty_progress.set_targets(run_id, [target])
    bounty_progress.mark_target(run_id, target, "running")
    result = run_bounty_hunt(
        target,
        args.profile,
        args.vuln_class,
        args.out or str(reports),
        args.scope or "",
        True,  # authorized — gated by --authorize in _cmd_dash, before the screen is entered
        _load_coder_config(args.brain),
        default_reports_dir=reports,
        seed_dir=SEED_DIR,
        runtime_dir=RUNTIME_DIR,
        version=VERSION,
        run_live=args.live,
        active=(args.active or getattr(args, "time_based", False) or getattr(args, "deep", False)
                or getattr(args, "theorize", False) or getattr(args, "chain", False)),
        time_based=getattr(args, "time_based", False),
        auth={"cookie": getattr(args, "cookie", "") or "", "headers": getattr(args, "header", None) or []},
        per_finding=args.per_finding,
        on_progress=bounty_progress.sink(run_id),
        should_stop=(lambda rid=run_id: bounty_progress.is_stopped(rid)),
        settings=depth_settings(args),
        oob_base=_oob_config()[0], oob_secret=_oob_config()[1],
    )
    gn_dash.stream_result(run_id, target, result)
    into["result"] = result
    return 0 if result.get("ok") else 2


def _dash_source(args: argparse.Namespace) -> Any:
    """The ``--attach`` source, discovering the run id when the operator did not name one.

    Run ids are minted by whoever launched the run (``crypto.randomUUID()`` in the desktop app) and
    written down nowhere, so requiring ``--run-id`` would make ``--attach`` unusable by the operator
    who is most likely to want it. The picker takes the newest run that has NOT been asked to stop;
    ``progress.list_runs`` cannot report "finished", so this deliberately does not pretend to skip
    completed runs — it skips the one signal that is real.
    """
    import gn_dash

    host = str(getattr(args, "host", "") or "127.0.0.1")
    port = getattr(args, "port", None)
    token = str(getattr(args, "token", "") or "")
    run_id = str(getattr(args, "run_id", "") or "").strip()
    probe = gn_dash.AttachedSource(run_id, host=host, port=port, token=token)
    if run_id:
        return probe
    live = [row for row in probe.list_runs() if not row.get("stopped")]
    if not live:
        raise gn_dash.SourceError(
            "the backend is holding no un-stopped run to attach to — start one in the app, or pass "
            "--run-id.", fatal=True)
    chosen = live[0]
    # probe.port, so naming the run does not cost a second 8766..8845 walk.
    return gn_dash.AttachedSource(str(chosen.get("run_id") or ""), host=host, port=probe.port,
                                  token=token, label=str(chosen.get("target") or ""))


def _cmd_dash_home(args: argparse.Namespace) -> int:
    """`gn dash --home` (what `GreyNOC Start` runs) — the idle cockpit, and the loop around it.

    The cockpit itself starts nothing. It hands back what the operator asked for in
    ``source.pending`` and this relaunches ``_cmd_dash`` in the real mode. ``/quit`` leaves no
    pending action, which is how it ends.

    It does NOT come back to home afterwards, tempting as a resident shell is. ``_cmd_dash`` prints
    the hunt summary onto the restored terminal on its way out, and the report path in it is the one
    thing the operator still needs once the panels are gone — re-entering the alternate screen would
    wipe it. Handing the terminal back is worth more than staying resident.

    Relaunching rather than swapping the source under the running poller is deliberate: the poller
    owns a socket and a thread, and tearing those down underneath a repaint to graft a new source on
    buys nothing an operator can see, at the cost of the one race this module has stayed free of.
    """
    import gn_dash
    import gn_tui

    refusal = gn_tui.refusal()
    if refusal:
        # No hunt to fall back to here, so — like --attach — it says why instead of doing nothing.
        return _err(refusal)
    small = gn_dash.size_refusal(gn_tui.terminal_size(sys.stdout))
    if small:
        return _err(small)
    if getattr(args, "braille", False):
        os.environ["GN_DASH_GLYPHS"] = "braille"

    source = gn_dash.HomeSource()
    code = gn_dash.run(source, run_subcommand=_dash_subcommand,
                       refresh_hz=getattr(args, "refresh", 4.0))
    pending = getattr(source, "pending", None)
    if not isinstance(pending, dict):
        return code
    action = str(pending.get("action") or "")
    # A FRESH namespace: mutating `args` would leave --home set, and _cmd_dash would recurse
    # straight back into this function.
    nxt = argparse.Namespace(**vars(args))
    nxt.home = False
    if action == "hunt":
        nxt.target, nxt.attach = str(pending.get("target") or ""), False
        # The cockpit demanded -y before it recorded the ask; this carries that consent through
        # rather than re-asking on a terminal the operator has already answered on.
        nxt.authorize = True
        # The depth variables the operator typed after the target. Only the three the cockpit
        # parses are read, by name, so nothing else in `pending` can reach the namespace.
        depth = pending.get("depth")
        if isinstance(depth, dict):
            nxt.theorize = bool(depth.get("theorize"))
            nxt.chain = bool(depth.get("chain"))
            turns = depth.get("turns")
            nxt.turns = int(turns) if isinstance(turns, int) else None
    elif action == "attach":
        nxt.target, nxt.attach, nxt.authorize = "", True, False
    else:
        return code
    return _cmd_dash(nxt)


def _cmd_dash(args: argparse.Namespace) -> int:
    """`gn dash` — the full-screen cockpit over a hunt this process runs, or one it attaches to.

    The dash namespace is a strict SUPERSET of ``hunt``'s, which is what lets every degradation be a
    one-line delegation to :func:`_cmd_hunt` instead of a second hunt path that can drift: ``--json``,
    a redirected stdout, ``NO_COLOR``, ``TERM=dumb``, ``GN_NO_FX``, ``GN_NO_DASH``, a pipe on stdin.
    All of them run the identical hunt and print the identical summary, byte for byte. A test pins
    the superset property, because the day it stops holding the delegation starts raising
    ``AttributeError`` on a namespace instead of hunting.

    A terminal that is merely TOO SMALL refuses rather than delegating. That asymmetry is deliberate:
    a redirected stream means nobody is watching and a hunt is what was wanted, while a 40-column
    window means somebody IS watching and asked for panels — running the hunt silently instead would
    be a different command from the one they typed.

    ``import gn_dash`` is inside the function and unguarded, exactly as ``_cmd_fx`` imports gn_fx: at
    module scope it would put the renderer and gn_sysmon's ctypes probe on the startup path of every
    `gn version`, and wrapped in a try/except it would be invisible to PyInstaller's analysis — the
    verb would work in dev and vanish from the frozen exe.
    """
    from uuid import uuid4

    import gn_dash
    import gn_tui

    if getattr(args, "self_test", False):
        return gn_dash.self_test()

    # Before the home branch AND before the alternate screen: a refusal printed into a screen that
    # is about to be discarded is a refusal the operator never sees.
    refusal = depth_refusal(args)
    if refusal:
        return _err(refusal)

    if bool(getattr(args, "home", False)):
        return _cmd_dash_home(args)

    attach = bool(getattr(args, "attach", False))
    target = str(getattr(args, "target", "") or "").strip()
    if attach and target:
        return _err("--attach watches a run the backend is already holding; it takes no target.")
    if not attach and not target:
        return _err("`gn dash` needs a target to hunt, or --attach to watch a run already in flight.")
    if args.json:
        if attach:
            return _err("--attach needs an interactive terminal; POST /api/bounty/progress directly "
                        "for a machine feed.")
        return _cmd_hunt(args)

    refusal = gn_tui.refusal()
    if refusal:
        # Attaching has no hunt to fall back to, so it must say why instead of doing nothing.
        return _err(refusal) if attach else _cmd_hunt(args)
    small = gn_dash.size_refusal(gn_tui.terminal_size(sys.stdout))
    if small:
        return _err(small)
    if not attach and not args.authorize:
        # Before the alternate screen: a refusal printed into a screen that is about to be discarded
        # is a refusal the operator never sees.
        return _err(_HUNT_AUTHORIZE)
    if getattr(args, "braille", False):
        # Written into the environment rather than passed down, so the flag reaches gn_tui.tier()
        # through the same door GN_DASH_GLYPHS does and there is exactly one place glyphs get
        # chosen. Assignment, not setdefault: an argument typed on this command outranks the shell
        # it was typed in. Set only once every refusal is behind us, so a delegated `gn hunt` never
        # inherits an environment this verb edited on its way out.
        os.environ["GN_DASH_GLYPHS"] = "braille"

    holder: dict = {}
    try:
        if attach:
            source, launch = _dash_source(args), None
        else:
            run_id = str(getattr(args, "run_id", "") or "").strip() or f"gn-dash-{uuid4().hex[:12]}"
            source = gn_dash.LocalSource(run_id, target)

            def launch() -> int:  # type: ignore[misc]
                return _dash_hunt(args, run_id, holder)

        code = gn_dash.run(source, run_subcommand=_dash_subcommand, launch=launch,
                           refresh_hz=getattr(args, "refresh", 4.0))
    except gn_dash.SourceError as exc:
        return _err(exc.message)

    result = holder.get("result")
    if isinstance(result, dict) and not result.get("ok"):
        return _err(result.get("error", "the hunt could not run."))
    if isinstance(result, dict):
        _print_hunt_summary(result)
    return code


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"GreyIQ gn {VERSION}")
    return 0


def _register_plugin_verbs(sub: argparse._SubParsersAction) -> None:
    """Let each module in ``_VERB_PLUGINS`` add its own subcommand.

    Deliberately total: a plugin that is absent (the module ships in a later release),
    unimportable (a broken optional dependency), or that raises inside ``register_cli``
    is SKIPPED, never propagated. build_parser() is on the import path of both the CLI
    and run_frozen.py's dispatch test, so a single bad optional module must never be
    able to stop `gn` from parsing `gn hunt` — losing one verb is recoverable, a CLI
    that cannot build is not.
    """
    import importlib

    for mod_name in _VERB_PLUGINS:
        try:
            register = getattr(importlib.import_module(mod_name), "register_cli", None)
        except Exception:  # noqa: BLE001 - a missing/broken plugin must never break the CLI
            continue
        if not callable(register):
            continue
        try:
            register(sub)
        except Exception:  # noqa: BLE001 - same contract: a bad registration costs one verb, not the CLI
            continue
def _cli_launcher() -> tuple[Path, str]:
    """Return the launcher users can add to PATH for this source or frozen build."""
    if getattr(sys, "frozen", False):
        binary = Path(sys.executable).resolve()
        if sys.platform == "linux":
            portable = binary.parent.parent / "greyiq-cli"
            if portable.is_file() and os.access(portable, os.X_OK):
                return portable, "greyiq-cli"
            debian = Path("/usr/bin/greyiq-cli")
            if debian.is_file() and os.access(debian, os.X_OK):
                return debian, "greyiq-cli"
        return binary, binary.name
    launcher = PROJECT_ROOT / ("gn.cmd" if os.name == "nt" else "gn")
    return launcher.resolve(), "gn"


def _cmd_path(_args: argparse.Namespace) -> int:
    """Show current data path and a copyable command for exposing this CLI."""
    launcher, command = _cli_launcher()
    print(f"CLI launcher: {launcher}")
    print(f"Runtime data: {RUNTIME_DIR}")
    found = shutil.which(command)
    # Windows command lookup also searches the current directory, which does not
    # make the command available after the user changes directories. Require the
    # discovered launcher (or a symlink to it) to live in an actual PATH entry.
    path_dirs = {
        os.path.normcase(str(Path(os.path.expandvars(entry.strip('"'))).resolve()))
        for entry in os.getenv("PATH", "").split(os.pathsep)
        if entry.strip('"') and Path(os.path.expandvars(entry.strip('"'))).is_absolute()
    }
    on_path = bool(
        found and Path(found).is_absolute()
        and Path(found).resolve() == launcher.resolve()
        and os.path.normcase(str(Path(found).parent.resolve())) in path_dirs
    )
    if on_path:
        print(f"{command} is already on PATH. Try: {command} dashboard")
    elif os.name == "nt":
        directory = str(launcher.parent).replace("'", "''")
        quoted_launcher = str(launcher).replace("'", "''")
        print(f"Run now: & '{quoted_launcher}' dashboard")
        print("PowerShell, current session: ")
        print(f"$env:Path = '{directory};' + $env:Path")
        print("For future sessions, add that directory to your user PATH in Windows Environment Variables.")
    else:
        export = f'export PATH={shlex.quote(str(launcher.parent))}:"$PATH"'
        print(f"Run now: {shlex.quote(str(launcher))} dashboard")
        print(f"Current shell: {export}")
        print("For future shells, add that export line to ~/.profile (or your shell startup file).")
    if os.name == "nt":
        print("Optional data override before launch: $env:GREYIQ_RUNTIME_DIR = 'C:\\path\\to\\runtime'")
    else:
        print('Optional data override before launch: export GREYIQ_RUNTIME_DIR="/absolute/path/to/runtime"')
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
    hunt.add_argument("-s", "--scope", default="", help="explicit exact hosts or *.domain grants for URL hunts")
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
    hunt.add_argument("--no-fx", action="store_true",
                       help="no live animated status line (also: GN_NO_FX=1, NO_COLOR, or a non-tty)")
    _register_depth_flags(hunt)
    hunt.set_defaults(func=_cmd_hunt)

    camp = sub.add_parser("campaign", help="end-to-end: recon -> hunt every URL -> prove -> submission packages -> learn")
    camp.add_argument("target", help="https:// URL (recon-crawled) or repo/folder path")
    camp.add_argument("-s", "--scope", default="", help="explicit exact hosts or *.domain grants for URL hunts")
    camp.add_argument("--program", default=None, help="program handle for the learning store (default: target domain)")
    camp.add_argument("--active", action="store_true", help="capture proof of impact on each URL (recommended)")
    camp.add_argument("--time-based", dest="time_based", action="store_true",
                      help="opt-in: add the bounded-SLEEP blind-SQLi probe per URL (implies --active; off by default)")
    camp.add_argument("--cookie", default="", help="scan behind a login: a Cookie header value, sent to in-scope hosts + subdomains ONLY")
    camp.add_argument("--header", action="append", metavar="'Name: value'",
                      help="extra auth header (repeatable), e.g. --header 'Authorization: Bearer ...'; sent same-site only")
    camp.add_argument("--live", action="store_true", help="dynamic Playwright pass per URL")
    camp.add_argument("--brain", action="store_true", help="use the configured LLM brain to enrich")
    camp.add_argument("--osint", action="store_true",
                      help="opt in to passive certificate-transparency seeding before recon (third-party lookup)")
    camp.add_argument("--max-pages", type=int, default=12, help="recon discovery cap (default 12)")
    camp.add_argument("--platform", default="hackerone",
                      help="report format for the submission packages: hackerone | yeswehack | bugcrowd | intigriti (see `gn platforms`)")
    camp.add_argument("--deep", action="store_true",
                      help="aggressive: implies --active + time-based blind SQLi, and auto-captures a screenshot + writes a brain-researched dossier for each confirmed lead")
    camp.add_argument("-y", "--authorize", action="store_true", help="confirm you are AUTHORIZED + in scope (required)")
    camp.add_argument("--json", action="store_true")
    camp.add_argument("--no-fx", action="store_true",
                       help="no live animated status line (also: GN_NO_FX=1, NO_COLOR, or a non-tty)")
    camp.set_defaults(func=_cmd_campaign)

    osint = sub.add_parser("osint", help="passive multi-source domain research with evidence provenance")
    osint.add_argument("target", help="public domain or absolute URL")
    osint.add_argument("--max-hosts", type=int, default=25,
                       help="maximum CT candidates to validate through both DNS providers (1-100; default 25)")
    osint.add_argument("--timeout", type=float, default=10.0, help="per-provider timeout in seconds (default 10)")
    osint.add_argument("-o", "--out", default=None, help="evidence output root (default: runtime/osint)")
    osint.add_argument("--hunt", action="store_true",
                       help="hand only two-resolver DNS-verified hosts to a BugHunter campaign")
    osint.add_argument("-s", "--scope", default="",
                       help="explicit program scope required with --hunt; OSINT never grants scope")
    osint.add_argument("--program", default=None, help="program handle for the optional BugHunter campaign")
    osint.add_argument("--active", action="store_true", help="capture proof of impact during --hunt")
    osint.add_argument("--live", action="store_true", help="dynamic Playwright pass during --hunt")
    osint.add_argument("--brain", action="store_true", help="use the configured brain during --hunt only")
    osint.add_argument("--max-pages", type=int, default=12, help="per-host recon cap during --hunt")
    osint.add_argument("--platform", default="hackerone",
                       help="submission export format for --hunt (default: hackerone)")
    osint.add_argument("-y", "--authorize", action="store_true",
                       help="confirm authorization for --hunt (not required for passive OSINT)")
    osint.add_argument("--json", action="store_true", help="print the machine-readable campaign result")
    osint.add_argument("--no-fx", action="store_true",
                       help="no live animated status line (also: GN_NO_FX=1, NO_COLOR, or a non-tty)")
    osint.set_defaults(func=_cmd_osint)

    learn = sub.add_parser("learn", help="record a finding's bounty outcome (teaches the engine)")
    learn.add_argument("-c", "--class", dest="vuln_class", required=True, help="vuln class id (see `gn classes`)")
    learn.add_argument("--status", required=True, help="accepted | resolved | duplicate | informative | not-applicable | triaged | submitted | spam")
    learn.add_argument("--program", default=None, help="program handle (default: derived from --target)")
    learn.add_argument("--target", default="", help="target URL/host (used to derive the program if no handle)")
    learn.add_argument("--bounty", type=float, default=0.0, help="bounty amount, if any")
    learn.add_argument("--severity", default="", help="severity, e.g. high")
    learn.add_argument("--title", default="", help="short finding title")
    learn.add_argument("--notes", default="", help="free-text notes")
    learn.add_argument("--finding-id", default="", help="stable report ID; updates the same report on retries/status changes")
    learn.set_defaults(func=_cmd_learn)

    stats = sub.add_parser("stats", help="show what the engine has learned per program")
    stats.add_argument("--program", default=None, help="a program handle (omit for all programs)")
    stats.add_argument("--target", default="", help="a target URL/host (derives the program)")
    stats.add_argument("--json", action="store_true")
    stats.set_defaults(func=_cmd_stats)

    traces = sub.add_parser("traces", help="show the offline-brain training corpus (hunt_traces.jsonl) recorded from your hunts")
    traces.add_argument("--json", action="store_true")
    traces.set_defaults(func=_cmd_traces)

    leads = sub.add_parser("leads", help="export a finished hunt's ranked investigation queue (leads, chains, proof obligations) for an analyst or a Claude brain to work")
    leads.add_argument("path", help="a bounty-*.json hunt sidecar, or an engagement folder to sweep")
    leads.add_argument("--json", action="store_true", help="emit the machine-readable lead queue (greyiq-lead-queue-v1)")
    leads.add_argument("--brief", action="store_true", help="render a Markdown investigation brief, wrapped as untrusted data, ready to hand to a model")
    leads.add_argument("--no-wrap", action="store_true", help="with --brief, omit the untrusted-data wrapper (human reading only)")
    leads.add_argument("--ref", default=None, help="show only this lead ref (e.g. H3)")
    leads.add_argument("--status", default=None, help="filter by status: confirmed|supported|candidate|contradicted|report-ready")
    leads.add_argument("--min-confidence", type=int, default=None, dest="min_confidence", help="only leads with confidence_score >= N")
    leads.set_defaults(func=_cmd_leads)

    op = sub.add_parser("operator", help="schedule portfolio hunts for human review")
    op.set_defaults(func=_cmd_operator, op_action=None)
    opsub = op.add_subparsers(dest="op_action", metavar="<action>")
    opsub.add_parser("list", help="list portfolio programs").set_defaults(func=_cmd_operator)
    opa = opsub.add_parser("add", help="add or update a program")
    opa.add_argument("--name", required=True)
    opa.add_argument("--scope", required=True, help="scope hosts/wildcards (the fail-closed active gate)")
    opa.add_argument("--targets", nargs="+", default=[], help="seed target URLs (each in scope)")
    opa.add_argument("--handle", default="", help="HackerOne team handle for report routing")
    opa.add_argument("--interval", type=int, default=1440, help="re-run cadence in minutes (default 1440)")
    opa.add_argument("--max-submits", dest="max_submits", type=int, default=3, help="legacy stored setting; automatic submission is disabled")
    opa.add_argument("--max-pages", dest="max_pages", type=int, default=12)
    opa.add_argument("--active", action="store_true", help="capture proof of impact")
    opa.add_argument("--live", action="store_true", help="dynamic Playwright pass")
    opa.add_argument("--deep", action="store_true",
                     help="aggressive auto-work (implies --active): time-based SQLi + a screenshot + a researched dossier per confirmed lead")
    opa.add_argument("--auto-submit", dest="auto_submit", action="store_true", help="legacy flag; automatic submission is disabled")
    opa.set_defaults(func=_cmd_operator)
    opr = opsub.add_parser("remove", help="remove a program")
    opr.add_argument("id")
    opr.set_defaults(func=_cmd_operator)
    oprun = opsub.add_parser("run", help="run the operator loop")
    oprun.add_argument("--once", action="store_true", help="reserved; currently refused until guarded one-shot auditing is available")
    oprun.add_argument("--grant-file", default="", help="JSON grants for every enabled program, including policy source and expiry")
    oprun.add_argument("--allow-submit", dest="allow_submit", action="store_true", help="legacy flag; refused because automatic submission is disabled")
    oprun.add_argument("--brain", action="store_true", help="use the configured LLM brain to enrich")
    oprun.add_argument("-y", "--authorize", action="store_true", help="confirm you're AUTHORIZED on every enabled program (required)")
    oprun.set_defaults(func=_cmd_operator)
    opp = opsub.add_parser("pipeline", help="show the money pipeline funnel")
    opp.set_defaults(func=_cmd_operator)

    dashboard = sub.add_parser("dashboard", help="read-only live terminal dashboard for local health and reports")
    dashboard.add_argument("--port", type=int, default=8766, help="local backend health port (default: 8766)")
    dashboard.add_argument("--interval", type=float, default=2.0, help="refresh seconds, 0.2-60 (default: 2)")
    dashboard.set_defaults(func=_cmd_dashboard)

    path = sub.add_parser("path", help="show the CLI PATH setup command and runtime data directory")
    path.set_defaults(func=_cmd_path)

    scan = sub.add_parser("scan", help="quick code/web scan; network targets require -y and exact --scope")
    scan.add_argument("target", help="HTTP(S) URL or local path (remote Git currently unavailable)")
    scan.add_argument("-s", "--scope", default="", help="exact host for web; exact HTTPS repository-root URL for remote code (no wildcard)")
    scan.add_argument("-y", "--authorize", action="store_true", help="confirm the network target is authorized and in scope (required for web and remote repository scans)")
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

    cvescan = sub.add_parser("cve", help="fingerprint a page's front-end libraries and flag outdated components with known CVEs")
    cvescan.add_argument("target", help="URL/host to fetch and fingerprint (e.g. https://app.example.com)")
    cvescan.add_argument("-s", "--scope", default="", help="scope (name the host/wildcard to allow testing)")
    cvescan.add_argument("--json", action="store_true")
    cvescan.add_argument("-y", "--authorize", action="store_true", help="confirm the host is in scope (required)")
    cvescan.set_defaults(func=_cmd_cve)

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

    bfla = sub.add_parser("bfla", help="confirm broken function-level authz with your high- and low-privilege test accounts")
    bfla.add_argument("priv_url", help="the privileged/admin endpoint to test (e.g. https://app/admin/users)")
    bfla.add_argument("--admin-cookie", dest="admin_cookie", default="", help="high-privilege account's Cookie header value")
    bfla.add_argument("--admin-header", dest="admin_header", action="append", metavar="'Name: value'", help="high-priv auth header (repeatable)")
    bfla.add_argument("--user-cookie", dest="user_cookie", default="", help="low-privilege account's Cookie header value")
    bfla.add_argument("--user-header", dest="user_header", action="append", metavar="'Name: value'", help="low-priv auth header (repeatable)")
    bfla.add_argument("-s", "--scope", default="", help="scope (name the host to allow active testing)")
    bfla.add_argument("--platform", default="hackerone", help="report format (see `gn platforms`)")
    bfla.add_argument("-o", "--out", default=None, help="report output path")
    bfla.add_argument("-y", "--authorize", action="store_true", help="confirm you OWN both test accounts and are in scope (required)")
    bfla.set_defaults(func=_cmd_bfla)

    iprobe = sub.add_parser("idor-probe", help="single-session IDOR discovery: mutate a URL's numeric ids and flag neighbouring objects")
    iprobe.add_argument("url", help="one authenticated object URL with a numeric id (path or query)")
    iprobe.add_argument("--cookie", default="", help="your session Cookie header value")
    iprobe.add_argument("--header", action="append", metavar="'Name: value'", help="auth header (repeatable)")
    iprobe.add_argument("-s", "--scope", default="", help="scope (name the host to allow active testing)")
    iprobe.add_argument("-y", "--authorize", action="store_true", help="confirm you own the account and are in scope (required)")
    iprobe.set_defaults(func=_cmd_idor_probe)

    classes = sub.add_parser("classes", help="list vuln classes")
    classes.add_argument("--json", action="store_true")
    classes.set_defaults(func=_cmd_classes)

    tools = sub.add_parser("tools", help="recommended tools for one or more vuln classes")
    tools.add_argument("classes", nargs="*", help="class ids, e.g. xss ssrf")
    tools.add_argument("--limit", type=int, default=12)
    tools.add_argument("--json", action="store_true")
    tools.set_defaults(func=_cmd_tools)

    fxdemo = sub.add_parser("fx", help="preview the live status animation in this terminal")
    fxdemo.add_argument("--seconds", type=float, default=6.0, help="how long to run the preview")
    fxdemo.set_defaults(func=_cmd_fx)

    # A CORE verb, registered here beside `fx` and never through _VERB_PLUGINS: that loader is
    # fail-closed (see _register_plugin_verbs), so a dashboard that failed to import would silently
    # cost the verb and `gn dash` would fall through run_frozen's dispatch and boot the API server.
    # Every option `hunt` defines is repeated here on purpose — the namespace has to be a strict
    # superset for the --json / non-tty delegation to _cmd_hunt to be total.
    dash = sub.add_parser("dash", help="full-screen cockpit: run a hunt, or attach to one, with live panels")
    dash.add_argument("target", nargs="?", default="", help="https:// URL, repo URL, or local path (omit with --attach)")
    dash.add_argument("-p", "--profile", default="full-sweep", help="hunt profile (default: full-sweep; see `gn profiles`)")
    dash.add_argument("-c", "--class", dest="vuln_class", default=None, help="focus vuln class (see `gn classes`)")
    dash.add_argument("-s", "--scope", default="", help="program/scope notes (name the host here to allow active checks)")
    dash.add_argument("--active", action="store_true", help="active verification: send benign probes to PROVE findings (URL targets)")
    dash.add_argument("--time-based", dest="time_based", action="store_true",
                      help="opt-in: add the bounded-SLEEP blind-SQLi probe (implies --active)")
    dash.add_argument("--cookie", default="", help="scan behind a login: a Cookie header value, sent to the target host + subdomains ONLY")
    dash.add_argument("--header", action="append", metavar="'Name: value'",
                      help="extra auth header (repeatable); sent same-site only")
    dash.add_argument("--live", action="store_true", help="dynamic Playwright browser pass (URL targets)")
    dash.add_argument("--brain", action="store_true", help="use the configured LLM brain to enrich (default: deterministic)")
    dash.add_argument("-o", "--out", default=None, help="report output folder (default: runtime/reports)")
    dash.add_argument("--per-finding", action="store_true", help="also write one submission-ready file per finding")
    dash.add_argument("-y", "--authorize", action="store_true", help="confirm you are AUTHORIZED to test the target (required to hunt)")
    dash.add_argument("--json", action="store_true", help="no dashboard: run the hunt and print the machine-readable result")
    dash.add_argument("--no-fx", action="store_true",
                      help="no live animation; with a redirected stream this runs exactly like `gn hunt`")
    dash.add_argument("--home", action="store_true",
                      help="open the idle HOME cockpit with nothing running; drive it with /hunt, "
                           "/attach, /usage (this is what `GreyNOC Start` runs)")
    dash.add_argument("--attach", action="store_true",
                      help="watch a run the local backend is already holding instead of starting one")
    dash.add_argument("--run-id", dest="run_id", default="",
                      help="the run to watch with --attach (default: the newest un-stopped run)")
    dash.add_argument("--host", default="127.0.0.1", help="--attach host; loopback only (127.0.0.1, ::1, localhost)")
    dash.add_argument("--port", type=int, default=None, help="--attach port (default: $GREYIQ_PORT, else probe 8766-8845)")
    dash.add_argument("--token", default="", help="--attach session token (default: $GREYIQ_SESSION_TOKEN, else runtime/session.token)")
    dash.add_argument("--refresh", type=float, default=4.0, help="repaints per second, clamped to 0.5-20 (default 4)")
    dash.add_argument("--braille", action="store_true",
                      help="braille sparklines — off by default because the encode probe cannot see whether your FONT has U+28xx (also: GN_DASH_GLYPHS=braille|rich|box|ascii)")
    dash.add_argument("--self-test", dest="self_test", action="store_true",
                      help="draw one frame, tear it down, and report the glyph tier, key reader, console VT state, size and host counters")
    _register_depth_flags(dash)
    dash.set_defaults(func=_cmd_dash)

    version = sub.add_parser("version", help="print the version")
    version.set_defaults(func=_cmd_version)

    _register_plugin_verbs(sub)  # LAST: plugin verbs are additive and must not shadow a core verb
    # Record the registered verb set on the parser so CLI_COMMANDS can be derived from it
    # rather than hand-maintained (see the module docstring for the drift this fixes).
    parser.set_defaults(_verbs=tuple(sorted(sub.choices)))
    return parser


def cli_commands() -> tuple[str, ...]:
    """The verbs run_frozen.py dispatches to this CLI, derived from build_parser().

    Fail-closed to the empty set on any parser failure: dispatch must never depend on a
    plugin. An empty result degrades the frozen exe to API-server mode (its behaviour
    before a CLI existed) rather than crashing the binary at startup.
    """
    try:
        verbs = tuple(build_parser().get_default("_verbs") or ())
    except Exception:  # noqa: BLE001 - dispatch must never depend on a plugin
        verbs = ()
    return tuple(sorted(set(verbs) | set(_ALWAYS_DISPATCH)))


# Module-level for run_frozen.py, which reads `gn_cli.CLI_COMMANDS` at dispatch time.
# Must stay defined AFTER build_parser() so the derivation can run at import.
CLI_COMMANDS: tuple[str, ...] = cli_commands()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "gn":  # tolerate `greyiq-backend.exe gn hunt ...`
        argv = argv[1:]
    # `--variables` is answered BEFORE parse_args, because `hunt`'s target is a required positional
    # and argparse enforces that first: `gn hunt --variables` would otherwise exit 2 demanding a
    # target for a flag that describes flags and runs nothing. Scoped to the verbs that own the
    # table so it cannot shadow another verb's -v.
    if argv and argv[0] in ("hunt", "dash") and {"-v", "--variables"} & set(argv[1:]):
        for line in variables_lines():
            print(line)
        return 0
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
    finally:
        # Clear any live status line before the shell prompt comes back, on EVERY exit: a clean
        # return, an early `return _err(...)`, a Ctrl-C, or an engine exception. Without this a
        # half-drawn frame is the last thing on the operator's terminal, and on Ctrl-C the cursor is
        # left mid-line. Guarded because a missing or broken decoration must never change the exit
        # code the operator's script reads.
        try:
            import gn_fx

            gn_fx.stop_all()
        except Exception:  # noqa: BLE001
            pass
        # And give the whole terminal back, for the same reason and with the same guard. A separate
        # registry from gn_fx's on purpose (see gn_tui._LIVE): a pane command calls gn_fx.stop_all()
        # because the verb it ran started a Scanner, and that must not tear down the dashboard the
        # operator is looking at. gn_dash.run unwinds its own ExitStack first, so on a normal exit
        # this finds nothing left to do — it is here for the paths that skipped that unwind, where a
        # live alternate screen would otherwise swallow the message main() just printed.
        #
        # Looked up in sys.modules rather than imported: nothing can be holding the terminal if the
        # module that takes it was never loaded, and importing it here would put ctypes/termios on
        # the exit path of every `gn version`.
        try:
            tui = sys.modules.get("gn_tui")
            if tui is not None:
                tui.teardown_all()
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    # `python backend/gn_cli.py …` (which is what `npm run gn` does) loads this file as __main__,
    # so `sys.modules["gn_cli"]` is absent — and two modules look for RUNTIME_DIR exactly there
    # rather than importing this one: gn_dash.runtime_dirs, which is how `--attach` finds
    # session.token, and gn_sysmon._runtime_dir, which is how the system strip knows WHICH volume
    # its disk percentage is about. Neither may import gn_cli (it reconfigures stdout/stderr at
    # import, and a sampler is not allowed to have opinions about the caller's streams), so the
    # alias is published here instead. setdefault, never assignment: if a real `gn_cli` is already
    # imported, that one is the module those lookups should see.
    sys.modules.setdefault("gn_cli", sys.modules[__name__])
    raise SystemExit(main())
