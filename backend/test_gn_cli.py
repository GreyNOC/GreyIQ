"""Tests for the `gn` bug-bounty CLI."""
from __future__ import annotations

import argparse
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_cli  # noqa: E402


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = gn_cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class GnCliTests(unittest.TestCase):
    def test_version_and_help(self) -> None:
        code, out, _ = _run(["version"])
        self.assertEqual(code, 0)
        self.assertIn(gn_cli.VERSION, out)
        # No args prints help, exit 0.
        self.assertEqual(_run([])[0], 0)

    def test_profiles_classes_tools(self) -> None:
        self.assertEqual(_run(["profiles"])[0], 0)
        code, out, _ = _run(["classes"])
        self.assertEqual(code, 0)
        self.assertIn("ssti", out)
        code, out, _ = _run(["tools", "xss"])
        self.assertEqual(code, 0)
        self.assertEqual(_run(["tools", "no-such-class"])[0], 2)  # nothing mapped -> error

    def test_hunt_requires_authorization(self) -> None:
        code, _, err = _run(["hunt", str(BACKEND_DIR / "bughunter"), "-p", "source-code"])
        self.assertEqual(code, 2)
        self.assertIn("authorize", err.lower())

    def test_hunt_runs_deterministically_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "src"
            target.mkdir()
            (target / "leak.py").write_text("AWS_KEY = 'AKIA" + "A" * 16 + "'\n", encoding="utf-8")
            out_dir = Path(tmp) / "reports"
            code, out, _ = _run(["hunt", str(target), "-p", "source-code", "-y", "-o", str(out_dir)])
            self.assertEqual(code, 0)
            self.assertIn("GreyIQ hunt", out)
            self.assertTrue(list(out_dir.glob("*.md")), "a markdown report should be written")

    def test_hunt_json_output(self) -> None:
        import json
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = _run(["hunt", str(BACKEND_DIR / "bughunter" / "settings.py"), "-p", "source-code", "-y", "-o", tmp, "--json"])
            # settings.py is a file; the code profile accepts a path. Result is JSON.
            self.assertEqual(code, 0)
            doc = json.loads(out)
            self.assertIn("risk", doc)
            self.assertNotIn("report_markdown", doc)  # trimmed from JSON (it's in the file)

    def test_cli_commands_match_dispatch_list(self) -> None:
        # run_frozen dispatches on gn_cli.CLI_COMMANDS. It is DERIVED from the parser, so
        # the two can never drift -- assert the exact identity, not a subset.
        self.assertEqual(
            set(gn_cli.CLI_COMMANDS),
            set(gn_cli.build_parser().get_default("_verbs")) | {"gn"},
        )

    def test_every_registered_verb_is_dispatchable(self) -> None:
        # Regression for the shipped-exe dispatch bug: these seven were registered in
        # build_parser() but absent from the hand-written CLI_COMMANDS tuple, so
        # `greyiq-backend.exe takeover ...` fell through and booted the API server.
        for verb in ("hunt", "campaign", "osint", "scan", "learn", "stats", "traces", "operator",
                     "profiles", "classes", "tools", "version",
                     "platforms", "bundle", "takeover", "cve", "idor", "bfla", "idor-probe"):
            self.assertIn(verb, gn_cli.CLI_COMMANDS)

    def test_osint_hunt_requires_authorization_and_scope_before_lookup(self) -> None:
        with mock.patch("bughunter.osint.run_campaign") as run:
            code, _, err = _run(["osint", "example.com", "--hunt"])
            self.assertEqual(code, 2)
            self.assertIn("authorize", err.lower())
            run.assert_not_called()

            code, _, err = _run(["osint", "example.com", "--hunt", "-y"])
            self.assertEqual(code, 2)
            self.assertIn("scope", err.lower())
            run.assert_not_called()

    def test_osint_cli_prints_passive_campaign_summary(self) -> None:
        payload = {
            "status": "complete", "domain": "example.com", "report_path": "OSINT.md",
            "summary": {"assets_total": 2, "hunt_eligible": 1, "claims_verified": 3, "claims_observed": 2},
        }
        with mock.patch("bughunter.osint.run_campaign", return_value=payload) as run:
            code, out, err = _run(["osint", "example.com"])
        self.assertEqual(code, 0)
        self.assertNotIn("gn:", err)
        self.assertIn("GreyIQ OSINT", out)
        self.assertIn("DNS-verified", out)
        run.assert_called_once()

    def test_osint_hunt_filters_verified_hosts_through_explicit_scope(self) -> None:
        payload = {
            "status": "complete", "domain": "example.com", "apex": "example.com",
            "report_path": "OSINT.md", "summary": {},
            "hunt_targets": ["https://api.example.com/", "https://admin.example.com/"],
        }
        hunt_payload = {"ok": True}
        with mock.patch("bughunter.osint.run_campaign", return_value=payload), \
             mock.patch("bughunter.campaign.run_campaign_over_targets", return_value=hunt_payload) as hunt:
            code, _, err = _run([
                "osint", "example.com", "--hunt", "--scope", "api.example.com", "-y", "--json",
            ])

        self.assertEqual(code, 0)
        self.assertNotIn("gn:", err)
        self.assertEqual(hunt.call_args.args[0], ["https://api.example.com/"])

    def test_traces_command_reports_corpus(self) -> None:
        import json

        from bughunter import hunt_trace
        with tempfile.TemporaryDirectory() as tmp:
            original = gn_cli.RUNTIME_DIR
            gn_cli.RUNTIME_DIR = Path(tmp)
            try:
                # Empty corpus: friendly nudge, exit 0.
                code, out, _ = _run(["traces"])
                self.assertEqual(code, 0)
                self.assertIn("No hunt traces", out)
                # Record one trace, then the corpus readout reflects it.
                hunt_trace.record_trace(
                    Path(tmp), program="demo", target="https://app.example.com/",
                    surface={"endpoints": ["https://app.example.com/search"], "params": ["q"], "tech": ["flask"], "forms": []},
                    plan={"provider": "offline", "probe_priority": [{"endpoint": "https://app.example.com/search", "classes": ["xss"]}]},
                    outcomes=[{"endpoint": "https://app.example.com/search", "class": "xss", "proof_status": "confirmed", "dedup_key": "k1"}])
                code, out, _ = _run(["traces"])
                self.assertEqual(code, 0)
                self.assertIn("1 hunt(s)", out)
                self.assertIn("1 confirmed", out)
                code, out, _ = _run(["traces", "--json"])
                self.assertEqual(code, 0)
                doc = json.loads(out)
                self.assertEqual(doc["hunts"], 1)
                self.assertEqual(doc["confirmed_rows"], 1)
            finally:
                gn_cli.RUNTIME_DIR = original

    def test_learn_and_stats_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original = gn_cli.RUNTIME_DIR
            gn_cli.RUNTIME_DIR = Path(tmp)
            try:
                code, out, _ = _run(["learn", "-c", "xss", "--status", "accepted",
                                     "--target", "https://shop.example.com", "--bounty", "500"])
                self.assertEqual(code, 0)
                self.assertIn("Recorded", out)
                # Unknown status is rejected with a usage error.
                self.assertEqual(_run(["learn", "-c", "xss", "--status", "banana", "--program", "p"])[0], 2)
                # Stats for the derived program shows the class breakdown.
                code, out, _ = _run(["stats", "--target", "https://shop.example.com"])
                self.assertEqual(code, 0)
                self.assertIn("xss", out)
                self.assertIn("500", out)
                # Stats across all programs.
                self.assertEqual(_run(["stats"])[0], 0)
            finally:
                gn_cli.RUNTIME_DIR = original

    def test_campaign_requires_authorization(self) -> None:
        code, _, err = _run(["campaign", str(BACKEND_DIR / "bughunter")])
        self.assertEqual(code, 2)
        self.assertIn("authorize", err.lower())

    def test_campaign_osint_flag_reaches_engine(self) -> None:
        payload = {
            "ok": True, "program": "demo", "urls_scanned": 0, "urls_discovered": 0,
            "finding_count": 0, "confirmed_count": 0, "submission_paths": [],
        }
        with mock.patch("bughunter.campaign.run_campaign", return_value=payload) as run:
            code, _, err = _run(["campaign", "https://example.com", "--osint", "-y", "--json"])
        # Other browser tests can finalize an un-awaited Playwright future while stderr is redirected
        # here on Windows; the CLI contract is its exit code + engine call, not ambient GC warnings.
        self.assertEqual(code, 0)
        self.assertNotIn("gn:", err)
        self.assertTrue(run.call_args.kwargs["osint"])

    def test_operator_cli_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original = gn_cli.RUNTIME_DIR
            gn_cli.RUNTIME_DIR = Path(tmp)
            try:
                # Add a program, list it, show the (empty) pipeline.
                self.assertEqual(_run(["operator", "add", "--name", "Acme", "--scope", "*.acme.com",
                                       "--targets", "https://acme.com", "--handle", "acme", "--active"])[0], 0)
                code, out, _ = _run(["operator", "list"])
                self.assertEqual(code, 0)
                self.assertIn("acme", out)
                self.assertEqual(_run(["operator", "pipeline"])[0], 0)
                # run is gated on -y/--authorize (it fires live campaigns).
                code, _, err = _run(["operator", "run"])
                self.assertEqual(code, 2)
                self.assertIn("authorize", err.lower())
                # auto-submit without a handle is dropped fail-closed.
                _run(["operator", "add", "--name", "NoHandle", "--scope", "x.com", "--auto-submit"])
                self.assertEqual(_run(["operator", "remove", "acme"])[0], 0)
            finally:
                gn_cli.RUNTIME_DIR = original


_PLUGIN_MODULES = ("gn_stub_ok_plugin", "gn_stub_broken_plugin", "gn_stub_raising_plugin")

_STUB_OK = """\
def register_cli(sub):
    p = sub.add_parser("gn-stub-verb", help="a stub verb registered by a plugin")
    p.set_defaults(func=lambda _args: 0)
"""
_STUB_BROKEN = "raise RuntimeError('this plugin is broken at import time')\n"
_STUB_RAISING = """\
def register_cli(sub):
    raise ValueError('this plugin blows up while registering')
"""


class VerbPluginHookTests(unittest.TestCase):
    """The self-registering verb hook must be TOTAL: every plugin failure mode costs at most
    that one verb, never the CLI. That is the whole point — several modules can each drop a
    verb in without any one of them being able to stop `gn hunt` from parsing."""

    def _with_plugins(self, tmp: str, names: tuple[str, ...]) -> None:
        """Write the stub modules into tmp, put it on sys.path, and point the hook at them."""
        import importlib

        (Path(tmp) / "gn_stub_ok_plugin.py").write_text(_STUB_OK, encoding="utf-8")
        (Path(tmp) / "gn_stub_broken_plugin.py").write_text(_STUB_BROKEN, encoding="utf-8")
        (Path(tmp) / "gn_stub_raising_plugin.py").write_text(_STUB_RAISING, encoding="utf-8")
        sys.path.insert(0, tmp)
        importlib.invalidate_caches()  # tmp is brand new; the path finder caches directory listings
        original = gn_cli._VERB_PLUGINS
        gn_cli._VERB_PLUGINS = names
        self.addCleanup(setattr, gn_cli, "_VERB_PLUGINS", original)
        self.addCleanup(lambda: sys.path.remove(tmp) if tmp in sys.path else None)
        self.addCleanup(lambda: [sys.modules.pop(m, None) for m in _PLUGIN_MODULES])

    def test_absent_and_broken_plugins_are_skipped(self) -> None:
        # This is today's real state: none of bughunter.hunt_train / bughunter.wardrive.cli
        # / edit_mine exist yet, and the CLI has to build anyway.
        with tempfile.TemporaryDirectory() as tmp:
            self._with_plugins(tmp, ("gn_no_such_module_at_all", "gn_stub_broken_plugin",
                                     "gn_stub_raising_plugin"))
            verbs = gn_cli.build_parser().get_default("_verbs")
            self.assertIn("hunt", verbs)
            self.assertIn("version", verbs)
            self.assertNotIn("gn-stub-verb", verbs)  # nothing half-registered
            self.assertEqual(_run(["version"])[0], 0)  # and it still actually dispatches

    def test_shipped_plugin_names_do_not_break_the_cli_today(self) -> None:
        # Guard the REAL tuple, not a stub: whatever _VERB_PLUGINS currently names, the
        # parser must build and every core verb must survive.
        verbs = gn_cli.build_parser().get_default("_verbs")
        for verb in ("hunt", "campaign", "scan", "version"):
            self.assertIn(verb, verbs)

    def test_plugin_registered_verb_reaches_cli_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._with_plugins(tmp, ("gn_stub_ok_plugin", "gn_stub_broken_plugin"))
            self.assertIn("gn-stub-verb", gn_cli.build_parser().get_default("_verbs"))
            # cli_commands() re-derives, so a plugin verb is dispatchable by the frozen exe
            # without anyone editing a hardcoded list.
            commands = gn_cli.cli_commands()
            self.assertIn("gn-stub-verb", commands)
            self.assertIn("gn", commands)
            self.assertIn("hunt", commands)
            self.assertEqual(_run(["gn-stub-verb"])[0], 0)

    def test_cli_commands_falls_back_to_bare_alias_if_the_parser_dies(self) -> None:
        # Fail-closed contract: dispatch never depends on a plugin. If build_parser itself
        # cannot run, cli_commands() degrades to the always-dispatch set instead of raising
        # at import time (which would make the frozen exe unstartable).
        original = gn_cli.build_parser
        gn_cli.build_parser = lambda: (_ for _ in ()).throw(RuntimeError("parser exploded"))
        try:
            self.assertEqual(gn_cli.cli_commands(), ("gn",))
        finally:
            gn_cli.build_parser = original


class VerbPluginsAreFrozenSafeTests(unittest.TestCase):
    """Every ``_VERB_PLUGINS`` module must be force-included in the PyInstaller spec.

    The plugin loader resolves these by NAME through importlib and is fail-closed, so an
    ImportError silently DROPS the verb — it does not error. In the frozen exe a dropped
    verb falls through ``run_frozen``'s dispatch test and boots the API server instead,
    which reads to a user as "the feature was never built".

    This is not hypothetical: ``collect_submodules("bughunter")`` returns
    ``bughunter.wardrive.cli`` and ``bughunter.hunt_train`` at spec-eval time, yet neither
    reached the first v2.6.0 bundle, so ``gn wardrive`` and ``gn train-brain`` worked
    perfectly from source and were missing from the shipped binary. A broad package sweep
    must never be trusted to carry a DYNAMIC entry point."""

    @staticmethod
    def _spec_plugin_modules() -> list[str]:
        """Run the spec's own ``_verb_plugin_modules`` helper — testing the real code, not
        a re-implementation of it, so the two cannot diverge."""
        import ast
        import os

        spec_src = (BACKEND_DIR.parent / "build" / "greyiq-backend.spec").read_text(encoding="utf-8")
        ast.parse(spec_src)  # the spec must stay syntactically valid Python
        start = spec_src.index("def _verb_plugin_modules")
        end = spec_src.index("for _plugin in")
        namespace: dict = {"os": os, "BACKEND": str(BACKEND_DIR)}
        exec(spec_src[start:end], namespace)  # noqa: S102 - our own spec file, not user input
        return list(namespace["_verb_plugin_modules"]())

    def test_the_spec_parses_the_real_verb_plugins_tuple(self) -> None:
        self.assertEqual(self._spec_plugin_modules(), list(gn_cli._VERB_PLUGINS))

    def test_every_shipped_plugin_module_is_force_included(self) -> None:
        import os

        parsed = self._spec_plugin_modules()
        for module_name in gn_cli._VERB_PLUGINS:
            rel = os.path.join(str(BACKEND_DIR), *module_name.split("."))
            on_disk = os.path.isfile(rel + ".py") or os.path.isfile(os.path.join(rel, "__init__.py"))
            if not on_disk:
                continue  # a not-yet-landed plugin is tolerated by the loader and by the spec
            self.assertIn(module_name, parsed,
                          f"{module_name} exists but the spec would not force-include it — "
                          "it would vanish from the frozen exe")

    def test_a_registered_plugin_verb_is_dispatchable(self) -> None:
        """Whatever the plugins actually registered must be reachable through the frozen
        dispatch predicate (``argv[0] in gn_cli.CLI_COMMANDS``), not just present in help."""
        registered = set(gn_cli.build_parser().get_default("_verbs") or ())
        for verb in ("wardrive", "train-brain"):
            if verb in registered:
                self.assertIn(verb, gn_cli.CLI_COMMANDS)


class DashVerbTests(unittest.TestCase):
    """``gn dash`` — registration, the superset property, and every degradation path.

    The superset test is the load-bearing one. Every way the dashboard can decline (``--json``, a
    redirected stream, ``NO_COLOR``, ``GN_NO_DASH``, a pipe on stdin) is a one-line delegation to
    ``_cmd_hunt`` with the SAME namespace, so the moment ``hunt`` grows an option ``dash`` does not
    have, that delegation stops hunting and starts raising ``AttributeError``.
    """

    @staticmethod
    def _dests(verb: str) -> set[str]:
        parser = gn_cli.build_parser()
        action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))  # noqa: SLF001
        return {act.dest for act in action.choices[verb]._actions} - {"help"}  # noqa: SLF001

    def test_dash_is_registered_as_a_core_verb_and_dispatchable(self) -> None:
        # Not via _VERB_PLUGINS: that loader is fail-closed, so a dashboard that failed to import
        # would silently cost the verb and `greyiq-backend.exe dash` would boot the API server.
        self.assertIn("dash", gn_cli.CLI_COMMANDS)
        parsed = gn_cli.build_parser().parse_args(["dash", "https://t.example", "-y"])
        self.assertIs(parsed.func, gn_cli._cmd_dash)

    def test_the_dash_namespace_is_a_strict_superset_of_hunts(self) -> None:
        missing = self._dests("hunt") - self._dests("dash")
        self.assertEqual(missing, set(),
                         "every `hunt` option must exist on `dash` — the --json and non-tty paths "
                         "hand the dash namespace straight to _cmd_hunt")
        self.assertTrue(self._dests("dash") - self._dests("hunt"),
                        "…and `dash` is expected to add its own (--attach, --self-test, …)")

    def test_json_delegates_to_the_real_hunt_with_the_same_namespace(self) -> None:
        with mock.patch.object(gn_cli, "_cmd_hunt", return_value=0) as hunt:
            code = gn_cli._cmd_dash(gn_cli.build_parser().parse_args(
                ["dash", "https://t.example", "-y", "--json"]))
        self.assertEqual(code, 0)
        hunt.assert_called_once()
        self.assertEqual(hunt.call_args[0][0].target, "https://t.example")

    def test_a_redirected_stream_runs_the_plain_hunt_and_writes_no_escape_sequence(self) -> None:
        # test_gn_fx's "a non-terminal gets not one byte", extended to the whole screen: the
        # alt-screen enter sequence must never reach a captured stream.
        with mock.patch.object(gn_cli, "_cmd_hunt", return_value=0) as hunt:
            code, out, err = _run(["dash", str(BACKEND_DIR / "bughunter"), "-p", "source-code", "-y"])
        self.assertEqual(code, 0)
        hunt.assert_called_once()
        self.assertNotIn("\033[?1049h", out + err)

    def test_attach_refuses_a_machine_feed_instead_of_silently_hunting(self) -> None:
        # There is no hunt to fall back to here, and delegating would start one against a target
        # the operator did not name.
        code, _, err = _run(["dash", "--attach", "--json"])
        self.assertEqual(code, 2)
        self.assertIn("/api/bounty/progress", err)

    def test_attach_and_a_target_are_refused_together(self) -> None:
        code, _, err = _run(["dash", "--attach", "https://t.example"])
        self.assertEqual(code, 2)
        self.assertIn("takes no target", err)

    def test_dash_needs_a_target_or_attach(self) -> None:
        code, _, err = _run(["dash"])
        self.assertEqual(code, 2)
        self.assertIn("--attach", err)

    def test_authorization_is_refused_in_hunts_own_words(self) -> None:
        # Same sentence from both verbs: two wordings read as two rules.
        _, _, dash_err = _run(["dash", str(BACKEND_DIR / "bughunter"), "-p", "source-code"])
        _, _, hunt_err = _run(["hunt", str(BACKEND_DIR / "bughunter"), "-p", "source-code"])
        self.assertEqual(dash_err, hunt_err)
        self.assertIn(gn_cli._HUNT_AUTHORIZE, dash_err)

    def test_self_test_reports_its_picks_even_when_it_cannot_draw(self) -> None:
        # The gn fx lesson: a verb that prints nothing is indistinguishable from a broken one. Off
        # a terminal it still names the tier, the size and WHY it refused, and exits 2.
        code, out, _ = _run(["dash", "--self-test"])
        self.assertEqual(code, 2)
        for expected in ("gn dash self-test", "glyph tier", "terminal size", "host counters",
                         "refused"):
            self.assertIn(expected, out)


class DashHomeTests(unittest.TestCase):
    """``gn dash --home`` — the idle cockpit and the relaunch handoff `GreyNOC Start` depends on."""

    def _args(self, *extra: str) -> argparse.Namespace:
        return gn_cli.build_parser().parse_args(["dash", "--home", *extra])

    def test_home_is_registered_and_routes_to_the_home_driver(self) -> None:
        self.assertTrue(self._args().home)
        with mock.patch.object(gn_cli, "_cmd_dash_home", return_value=0) as home:
            gn_cli._cmd_dash(self._args())
        home.assert_called_once()

    def test_quitting_home_launches_nothing(self) -> None:
        # /quit leaves no pending action; the driver must not relaunch anything.
        with mock.patch.object(gn_cli, "_dash_subcommand"), \
             mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.size_refusal", return_value=""), \
             mock.patch("gn_dash.run", return_value=0) as run, \
             mock.patch.object(gn_cli, "_cmd_dash") as dash:
            code = gn_cli._cmd_dash_home(self._args())
        self.assertEqual(code, 0)
        run.assert_called_once()
        dash.assert_not_called()

    def test_hunt_relaunches_with_the_target_and_carries_the_consent(self) -> None:
        def _run(source: object, **_kw: object) -> int:
            source.pending = {"action": "hunt", "target": "https://t.example"}  # type: ignore[attr-defined]
            return 0

        with mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.size_refusal", return_value=""), \
             mock.patch("gn_dash.run", side_effect=_run), \
             mock.patch.object(gn_cli, "_cmd_dash", return_value=7) as dash:
            code = gn_cli._cmd_dash_home(self._args())
        self.assertEqual(code, 7)
        nxt = dash.call_args[0][0]
        self.assertEqual(nxt.target, "https://t.example")
        self.assertTrue(nxt.authorize, "the cockpit demanded -y; that consent must carry through")
        self.assertFalse(nxt.attach)
        self.assertFalse(nxt.home, "leaving --home set would recurse straight back into the driver")

    def test_attach_relaunches_in_attach_mode_with_no_target_and_no_consent(self) -> None:
        def _run(source: object, **_kw: object) -> int:
            source.pending = {"action": "attach"}  # type: ignore[attr-defined]
            return 0

        with mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.size_refusal", return_value=""), \
             mock.patch("gn_dash.run", side_effect=_run), \
             mock.patch.object(gn_cli, "_cmd_dash", return_value=0) as dash:
            gn_cli._cmd_dash_home(self._args())
        nxt = dash.call_args[0][0]
        self.assertTrue(nxt.attach)
        self.assertEqual(nxt.target, "")
        self.assertFalse(nxt.authorize, "attaching watches someone else's run; it authorizes nothing")
        self.assertFalse(nxt.home)

    def test_an_unknown_pending_action_launches_nothing(self) -> None:
        def _run(source: object, **_kw: object) -> int:
            source.pending = {"action": "sudo-rm-rf"}  # type: ignore[attr-defined]
            return 0

        with mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.size_refusal", return_value=""), \
             mock.patch("gn_dash.run", side_effect=_run), \
             mock.patch.object(gn_cli, "_cmd_dash") as dash:
            gn_cli._cmd_dash_home(self._args())
        dash.assert_not_called()

    def test_the_relaunch_namespace_carries_every_field_the_hunt_path_reads(self) -> None:
        # _dash_hunt reads these straight off the namespace; a missing one is an AttributeError
        # in the middle of a live hunt rather than a refusal up front.
        def _run(source: object, **_kw: object) -> int:
            source.pending = {"action": "hunt", "target": "https://t.example"}  # type: ignore[attr-defined]
            return 0

        with mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.size_refusal", return_value=""), \
             mock.patch("gn_dash.run", side_effect=_run), \
             mock.patch.object(gn_cli, "_cmd_dash", return_value=0) as dash:
            gn_cli._cmd_dash_home(self._args())
        nxt = dash.call_args[0][0]
        for field in ("profile", "vuln_class", "out", "scope", "brain", "live", "active",
                      "time_based", "per_finding", "cookie", "header", "json", "refresh"):
            self.assertTrue(hasattr(nxt, field), f"_dash_hunt reads {field} off this namespace")

    def test_a_non_tty_refuses_instead_of_silently_hunting(self) -> None:
        # Unlike `gn dash <target>`, home has no target to fall back to, so it must say why.
        code, _out, err = _run(["dash", "--home"])
        self.assertEqual(code, 2)
        self.assertIn("terminal", err.lower())


class DepthVariableTests(unittest.TestCase):
    """The -Th/-Tn/-Ch depth flags: each must move a REAL setting, or it is a lie."""

    def _settings(self, *flags: str) -> object:
        args = gn_cli.build_parser().parse_args(["hunt", "https://t.example", "-y", *flags])
        return gn_cli.depth_settings(args)

    def test_no_depth_flag_leaves_the_engine_on_its_own_settings(self) -> None:
        # None, not a snapshot: handing down a parse-time copy would freeze any env var the engine
        # would otherwise re-read.
        self.assertIsNone(self._settings())

    def test_theorize_enables_BOTH_halves_of_the_loop(self) -> None:
        # hunt_loop_enabled alone makes the planner return an empty done=True plan with no brain,
        # so the loop would switch on and die at turn 0 - a flag that appears to work and does not.
        s = self._settings("-Th")
        self.assertTrue(s.hunt_loop_enabled)
        self.assertTrue(s.hunt_loop_offline_enabled)
        self.assertFalse(s.hunt_replan_enabled, "-Th must not silently turn on the chain wave")

    def test_chain_enables_the_replan_wave_only(self) -> None:
        s = self._settings("-Ch")
        self.assertTrue(s.hunt_replan_enabled)
        self.assertFalse(s.hunt_loop_enabled)

    def test_turns_is_clamped_exactly_as_the_env_var_is(self) -> None:
        # hunt_loop reads this back with NO clamp of its own, so an unclamped 9999 would be
        # honoured as 9999 turns against a live host.
        self.assertEqual(self._settings("-Th", "-Tn", "5").hunt_loop_max_iters, 5)
        self.assertEqual(self._settings("-Th", "-Tn", "99").hunt_loop_max_iters, 6)
        self.assertEqual(self._settings("-Th", "-Tn", "0").hunt_loop_max_iters, 1)
        self.assertEqual(self._settings("-Th", "-Tn", "-7").hunt_loop_max_iters, 1)

    def test_the_flags_are_registered_on_both_hunt_and_dash(self) -> None:
        # A test already pins dash's namespace as a superset of hunt's; this pins that these
        # specific four are on both, so `/hunt ... -Th` can relaunch through the dash namespace.
        for verb in ("hunt", "dash"):
            dests = DashVerbTests._dests(verb)
            for flag in ("theorize", "chain", "turns", "variables"):
                self.assertIn(flag, dests, f"{flag} missing from `{verb}`")

    def test_a_depth_flag_implies_active_or_it_would_do_nothing(self) -> None:
        # Both branches live inside `if (active or time_based) and authorized and kind == "url"`.
        captured: dict = {}

        def _fake(*a: object, **kw: object) -> dict:
            captured.update(kw)
            return {"ok": True, "findings": [], "report_path": "", "target": "https://t.example"}

        for flag in ("-Th", "-Ch"):
            captured.clear()
            with mock.patch("bughunter.bounty.run_bounty_hunt", _fake), \
                 contextlib.redirect_stdout(io.StringIO()):
                gn_cli._cmd_hunt(gn_cli.build_parser().parse_args(
                    ["hunt", "https://t.example", "-y", flag]))
            self.assertTrue(captured.get("active"), f"{flag} must imply --active")
            self.assertIsNotNone(captured.get("settings"), f"{flag} must hand down a settings object")

    def test_variables_prints_the_table_without_needing_a_target(self) -> None:
        # `hunt`'s target is a required positional, so this is answered before parse_args.
        for argv in (["hunt", "--variables"], ["hunt", "-v"], ["dash", "-v"]):
            with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()) as out:
                code = gn_cli.main(argv)
            self.assertEqual(code, 0)
            self.assertIn("hunt depth variables", out.getvalue())

    def test_every_row_names_its_engine_knob_and_its_bound(self) -> None:
        text = "\n".join(gn_cli.variables_lines())
        for row in gn_cli.DEPTH_VARIABLES:
            self.assertIn(row["flag"], text)
            self.assertIn(row["knob"], text)
            self.assertIn(row["bound"], text)
        self.assertIn("only a captured artifact", text.lower().replace("NEVER", "never"),
                      "the table must say depth buys tested leads, not claimed bugs")


class DashIsFrozenSafeTests(unittest.TestCase):
    """The three cockpit modules must be force-included in the PyInstaller spec.

    ``gn_cli`` imports ``gn_dash`` inside ``_cmd_dash`` (unguarded, exactly as ``_cmd_fx`` imports
    ``gn_fx``) to keep the renderer off every other verb's startup path — which is precisely the
    function-level import PyInstaller's static analysis cannot see. They are NOT ``_VERB_PLUGINS``,
    so the fail-closed loader and the test above never look at them: without the spec line the verb
    parses in the shipped exe and then dies on the import, and nothing else here would notice."""

    @staticmethod
    def _spec_optional_modules() -> list[str]:
        """The literal tuple the spec's ``for _opt in (...)`` loop walks — read from the real spec
        with ast, not re-typed here, so a rename on either side fails this test."""
        import ast

        spec_src = (BACKEND_DIR.parent / "build" / "greyiq-backend.spec").read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(spec_src)):
            if isinstance(node, ast.For) and getattr(node.target, "id", "") == "_opt":
                return [str(name) for name in ast.literal_eval(node.iter)]
        return []

    def test_the_cockpit_modules_are_force_included(self) -> None:
        optional = self._spec_optional_modules()
        for module_name in ("gn_dash", "gn_tui", "gn_sysmon"):
            with self.subTest(module=module_name):
                self.assertTrue((BACKEND_DIR / f"{module_name}.py").is_file(),
                                f"{module_name} must be a FLAT module — the spec's isfile guard "
                                "does not match a package, so a package would silently not ship")
                self.assertIn(module_name, optional,
                              f"{module_name} exists but the spec would not force-include it — "
                              "`gn dash` would work in dev and die on import in the frozen exe")


class AutoPathCreationTests(unittest.TestCase):
    """The CLI creates the directories it chose, and only those.

    A clean checkout has no ``runtime/``: the API server makes it at boot and nothing on the CLI
    path ever did, so the first `gn hunt` on a fresh clone died inside
    ``bounty._resolve_output_dir`` — ``mkdir(parents=False)`` — with a bare ``FileNotFoundError``
    naming a reports directory the operator had never asked for. The containment guard on a
    caller-supplied ``-o`` is deliberately NOT relaxed by any of this.
    """

    def test_ensure_dir_creates_parents_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b" / "c"
            self.assertEqual(gn_cli._ensure_dir(deep), deep)
            self.assertTrue(deep.is_dir())
            self.assertEqual(gn_cli._ensure_dir(deep), deep)  # second call is a no-op, not an error
            self.assertTrue(deep.is_dir())

    def test_ensure_dir_is_total_when_the_path_cannot_exist(self) -> None:
        # Total by design: the verb must fail at its write, with the real error about the real
        # file, rather than here with a second error about a directory.
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "a-file"
            blocker.write_text("not a directory", encoding="utf-8")
            target = blocker / "under-a-file"
            self.assertEqual(gn_cli._ensure_dir(target), target)
            self.assertFalse(target.exists())

    def test_a_hunt_creates_its_reports_tree_on_a_fresh_runtime_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "never-created" / "runtime"
            target = Path(tmp) / "src"
            target.mkdir()
            (target / "leak.py").write_text("AWS_KEY = 'AKIA" + "A" * 16 + "'\n", encoding="utf-8")
            with mock.patch.object(gn_cli, "RUNTIME_DIR", runtime):
                code, out, err = _run(["hunt", str(target), "-p", "source-code", "-y"])
            self.assertEqual(code, 0, err)
            self.assertIn("GreyIQ hunt", out)
            self.assertTrue(list((runtime / "reports").glob("*.md")),
                            "the report has to land somewhere the operator was told about")

    def test_an_operator_named_out_dir_is_still_not_auto_vivified(self) -> None:
        # The CLI must not pre-create the operator's -o path: doing so would defeat
        # bounty._resolve_output_dir's containment guard from the outside. A multi-level path is
        # refused there and the run lands in the (created) default instead.
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            requested = Path(tmp) / "no-1" / "no-2" / "no-3"
            target = Path(tmp) / "src"
            target.mkdir()
            (target / "clean.py").write_text("x = 1\n", encoding="utf-8")
            with mock.patch.object(gn_cli, "RUNTIME_DIR", runtime):
                code, _, err = _run(["hunt", str(target), "-p", "source-code", "-y", "-o", str(requested)])
            self.assertEqual(code, 0, err)
            self.assertFalse((Path(tmp) / "no-1").exists())
            self.assertTrue((runtime / "reports").is_dir())

    def test_the_osint_evidence_root_is_created_before_the_engine_is_called(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "fresh" / "runtime"
            payload = {"ok": True, "apex": "t.example", "hunt_targets": [],
                       "report_path": "", "assets": [], "claims": [], "sources": []}
            with mock.patch.object(gn_cli, "RUNTIME_DIR", runtime), \
                 mock.patch("bughunter.osint.run_campaign", return_value=payload) as run:
                code, _, err = _run(["osint", "t.example", "--json"])
            self.assertEqual(code, 0, err)
            self.assertEqual(Path(run.call_args.kwargs["output_dir"]), runtime / "osint")
            self.assertTrue((runtime / "osint").is_dir())


if __name__ == "__main__":
    unittest.main()
