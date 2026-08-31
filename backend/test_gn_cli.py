"""Tests for the `gn` bug-bounty CLI."""
from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
