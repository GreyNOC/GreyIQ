"""Tests for the `gn` bug-bounty CLI."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
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

    def test_path_command_prints_copyable_setup_without_changing_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="GreyIQ CLI ") as tmp:
            launcher = Path(tmp) / "greyiq-cli"
            before = dict(gn_cli.os.environ)
            with mock.patch.object(gn_cli, "_cli_launcher", return_value=(launcher, "greyiq-cli")), \
                 mock.patch.object(gn_cli.shutil, "which", return_value=None):
                code, out, err = _run(["path"])
            self.assertEqual(code, 0, err)
            self.assertIn(str(launcher), out)
            self.assertIn(str(gn_cli.RUNTIME_DIR), out)
            self.assertIn("GREYIQ_RUNTIME_DIR", out)
            self.assertIn("PATH", out)
            if gn_cli.os.name == "nt":
                self.assertIn("$env:Path", out)
            else:
                self.assertIn("export PATH=", out)
                self.assertIn("'", out, "a launcher directory with spaces must be shell-quoted")
            self.assertEqual(dict(gn_cli.os.environ), before)

    def test_path_command_does_not_confuse_current_directory_with_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="GreyIQ CLI ") as tmp:
            launcher = Path(tmp) / "greyiq-cli"
            # Windows command lookup searches the current directory even when
            # it is absent from PATH. That is not a persistent CLI install.
            with mock.patch.object(gn_cli, "_cli_launcher", return_value=(launcher, "greyiq-cli")), \
                 mock.patch.object(gn_cli.shutil, "which", return_value=str(launcher)), \
                 mock.patch.dict(gn_cli.os.environ, {"PATH": str(launcher.parent.parent)}):
                code, out, err = _run(["path"])
            self.assertEqual(code, 0, err)
            self.assertNotIn("already on PATH", out)

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
                     "dashboard", "path", "leads", "profiles", "classes", "tools", "version",
                     "platforms", "bundle", "takeover", "cve", "idor", "bfla", "idor-probe",
                     "setup", "settings", "output"):
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

    def test_learn_finding_id_updates_one_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original = gn_cli.RUNTIME_DIR
            gn_cli.RUNTIME_DIR = Path(tmp)
            try:
                for status in ("submitted", "accepted", "accepted"):
                    code, _, err = _run(["learn", "-c", "xss", "--status", status,
                                         "--program", "acme", "--finding-id", "h1:42"])
                    self.assertEqual(code, 0, err)
                code, out, err = _run(["stats", "--program", "acme", "--json"])
                self.assertEqual(code, 0, err)
                stats = json.loads(out)
                self.assertEqual(stats["findings"], 1)
                self.assertEqual(stats["rewarded"], 1)
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
                with mock.patch("bughunter.campaign.run_campaign") as run:
                    code, _, err = _run(["operator", "run", "--once", "-y", "--allow-submit"])
                self.assertEqual(code, 2)
                self.assertIn("automatic submission is disabled", err.lower())
                run.assert_not_called()
                with mock.patch("bughunter.campaign.run_campaign") as run:
                    code, _, err = _run(["operator", "run", "--once", "-y"])
                self.assertEqual(code, 2)
                self.assertIn("--once is unavailable", err)
                run.assert_not_called()
                code, _, err = _run(["operator", "run", "-y"])
                self.assertEqual(code, 2)
                self.assertIn("--grant-file", err)
                grant_path = Path(tmp) / "operator-grants.json"
                grants = [{"program_id": "acme", "authorization_ref": "engagement-1"}]
                grant_path.write_text(json.dumps({"grants": grants}), encoding="utf-8")
                with mock.patch("bughunter.operator.OperatorLoop") as loop_type:
                    loop_type.return_value.running = False
                    code, _, _ = _run(["operator", "run", "-y", "--grant-file", str(grant_path)])
                self.assertEqual(code, 0)
                loop_type.return_value.start.assert_called_once_with(grants=grants)
                # Legacy program flag is accepted but normalized off.
                _run(["operator", "add", "--name", "NoHandle", "--scope", "x.com", "--auto-submit"])
                self.assertEqual(_run(["operator", "remove", "acme"])[0], 0)
            finally:
                gn_cli.RUNTIME_DIR = original

    def test_operator_ctrl_c_waits_for_stopped_audit_before_returning(self) -> None:
        from bughunter import operator as operator_mod, portfolio

        with tempfile.TemporaryDirectory() as tmp:
            portfolio.upsert_program(tmp, {
                "id": "example", "name": "Example", "scope_text": "example.com",
                "seed_targets": ["https://example.com"],
            })
            now = datetime.now(UTC)
            grant_path = Path(tmp) / "grants.json"
            grant_path.write_text(json.dumps([{
                "program_id": "example", "authorization_ref": "test engagement",
                "policy_source": "https://example.com/policy", "policy_checked_at": now.isoformat(),
                "expires_at": (now + timedelta(days=1)).isoformat(), "max_cycles": 1,
            }]), encoding="utf-8")

            campaign_entered = threading.Event()
            release_campaign = threading.Event()
            cli_done = threading.Event()
            loops = []
            results = []
            real_loop_type = operator_mod.OperatorLoop

            def run_campaign(*args, **kwargs):
                campaign_entered.set()
                release_campaign.wait(timeout=10)
                return {"ok": True, "findings": [], "proof_of_impact": {}}

            def loop_factory(*args, **kwargs):
                loop = real_loop_type(*args, **kwargs)

                def interrupt_during_poll(*, after=0):
                    if not campaign_entered.wait(timeout=5):
                        raise AssertionError("the campaign never started")
                    raise KeyboardInterrupt

                loop.event_tail = interrupt_during_poll
                loops.append(loop)
                return loop

            def run_cli():
                try:
                    results.append(_run(["operator", "run", "-y", "--grant-file", str(grant_path)]))
                finally:
                    cli_done.set()

            with mock.patch.object(gn_cli, "RUNTIME_DIR", Path(tmp)), \
                 mock.patch.object(gn_cli, "_operator_campaign_fn", return_value=run_campaign), \
                 mock.patch.object(operator_mod, "OperatorLoop", side_effect=loop_factory):
                cli_thread = threading.Thread(target=run_cli)
                cli_thread.start()
                try:
                    self.assertTrue(campaign_entered.wait(timeout=5))
                    self.assertTrue(loops[0].stop_event.wait(timeout=5))
                    self.assertFalse(cli_done.wait(timeout=0.25),
                                     "the CLI returned while the campaign and audit were still running")
                finally:
                    release_campaign.set()
                    cli_thread.join(timeout=10)
                    for loop in loops:
                        if loop._thread is not None and loop._thread.is_alive():
                            loop.stop()
                            loop._thread.join(timeout=10)

            self.assertFalse(cli_thread.is_alive())
            self.assertEqual(results[0][0], 0)
            self.assertIn("Kill switch", results[0][1])
            self.assertFalse(loops[0].running)
            self.assertIsNone(loops[0]._lease_fd)
            audit = Path(tmp, "operator_authorization_audit.jsonl").read_text(encoding="utf-8")
            self.assertEqual([json.loads(line)["event"] for line in audit.splitlines()],
                             ["armed", "cycle_started", "cycle_finished", "stopped"])

    def test_operator_cli_cloud_brain_is_disabled(self) -> None:
        run_fn = gn_cli._operator_campaign_fn({"enabled": True, "provider": "openai"})
        saved = {"user_agent_suffix": " -Policy-Marker", "policy_profile": "example",
                 "out_of_scope_hosts": ["excluded.example.com"], "disclose_automation": True}
        with mock.patch("bughunter.portfolio.get_program", return_value=saved), \
                mock.patch("bughunter.campaign.run_campaign", return_value={"ok": False}) as run:
            run_fn("https://example.com", scope="example.com", program="p",
                   active=False, live=False)
        self.assertEqual(run.call_args.kwargs["coder_cfg"], {"enabled": False, "provider": "off"})
        self.assertEqual(run.call_args.kwargs["user_agent_suffix"], " -Policy-Marker")
        self.assertEqual(run.call_args.kwargs["policy_profile"], "example")
        self.assertEqual(run.call_args.kwargs["excluded_hosts"], ("excluded.example.com",))
        self.assertTrue(run.call_args.kwargs["disclose_automation"])

    def test_operator_campaign_forwards_saved_account_to_engine(self) -> None:
        run_fn = gn_cli._operator_campaign_fn({"enabled": False})
        access = {"cookie": "session=stale", "email": "researcher@example.com",
                  "password": "stored-secret", "login_url": "https://app.example.com/login"}
        saved = {"account_access": access, "out_of_scope_hosts": []}
        with mock.patch("bughunter.portfolio.get_program", return_value=saved), \
             mock.patch("bughunter.campaign.run_campaign", return_value={"ok": True}) as run:
            run_fn("https://app.example.com/one", scope="*.example.com",
                   program="p", active=False, live=False)

        run.assert_called_once()
        self.assertIs(run.call_args.kwargs["account_access"], access)
        self.assertEqual(access["cookie"], "session=stale")


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

    def test_bare_dash_opens_the_board_rather_than_refusing(self) -> None:
        # It used to refuse ("name a target, or --attach"), which made the one verb you reach for
        # on a fresh terminal the one that needed a run to exist first.
        with mock.patch.object(gn_cli, "_cmd_dash_board", return_value=0) as board:
            code = gn_cli._cmd_dash(gn_cli.build_parser().parse_args(["dash"]))
        self.assertEqual(code, 0)
        board.assert_called_once()

    def test_board_and_another_view_are_refused_together(self) -> None:
        for extra in (["--panels"], ["--attach"], ["https://t.example"]):
            with self.subTest(extra=extra):
                code, _, err = _run(["dash", "--board", *extra])
                self.assertEqual(code, 2)
                self.assertIn("--board is the IDLE dash", err)

    def test_the_board_refuses_a_machine_feed_instead_of_silently_hunting(self) -> None:
        code, _, err = _run(["dash", "--json"])
        self.assertEqual(code, 2)
        self.assertIn("no run to serialize", err)

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


class _Tty(io.StringIO):
    """A stream that claims to be a terminal, for the paths that only run when one is."""

    def isatty(self) -> bool:
        return True


@contextlib.contextmanager
def _terminal(answers: list[str]):
    """Run with stdin/stdout that look like a terminal, answering input() from `answers`.

    The prompts land on ``out.prompts``: a real ``input()`` writes its prompt to the terminal, so
    without that a test cannot see the one line that carries the question.
    """
    replies = iter(answers)
    out = _Tty()
    out.prompts = []  # type: ignore[attr-defined]

    def _input(prompt: str = "") -> str:
        out.prompts.append(str(prompt))  # type: ignore[attr-defined]
        return next(replies)

    with mock.patch("sys.stdout", out), mock.patch("sys.stdin", _Tty()), \
         mock.patch("builtins.input", _input):
        yield out


class _ProfileCase(unittest.TestCase):
    """A CLI with its own runtime directory, so no test can read or write the real profile."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="gn-profile-")
        self.runtime = Path(self._tmp.name)
        self._saved = gn_cli.RUNTIME_DIR
        gn_cli.RUNTIME_DIR = self.runtime
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        gn_cli.RUNTIME_DIR = self._saved
        self._tmp.cleanup()

    def args(self, *argv: str) -> argparse.Namespace:
        return gn_cli.build_parser().parse_args(list(argv))

    def set(self, key: str, value: str) -> None:
        self.assertEqual(_run(["settings", "set", key, value])[0], 0)


class SettingsVerbTests(_ProfileCase):
    """`gn setup`, `gn settings`, `gn output` — the profile as an operator drives it."""

    def test_setup_defaults_writes_a_profile_without_asking(self) -> None:
        with mock.patch("builtins.input", side_effect=AssertionError("must not ask")):
            code, out, err = _run(["setup", "--defaults"])
        self.assertEqual(code, 0, err)
        self.assertTrue(gn_cli.RUNTIME_DIR.joinpath("operator_profile.json").is_file())
        self.assertIn("tinygpt", out)
        self.assertIn("learning: on", out)

    def test_setup_records_the_answers_it_was_given(self) -> None:
        with _terminal(["greynoc", "local", "off", "api", "on", str(self.runtime / "reports")]):
            code = gn_cli.main(["setup"])
        self.assertEqual(code, 0)
        import gn_profile

        profile = gn_profile.load(self.runtime)
        self.assertEqual(profile.get("operator.handle"), "greynoc")
        self.assertEqual(profile.get("bot"), "local")
        self.assertIs(profile.get("learning"), False)
        self.assertEqual(profile.get("hunt.profile"), "api")
        self.assertIs(profile.get("hunt.active"), True)

    def test_setup_writes_nothing_when_an_answer_is_refused(self) -> None:
        with _terminal(["", "skynet"]), contextlib.redirect_stderr(io.StringIO()) as err:
            code = gn_cli.main(["setup"])
        self.assertEqual(code, 2)
        self.assertIn("nothing was written", err.getvalue())
        self.assertFalse(gn_cli.RUNTIME_DIR.joinpath("operator_profile.json").exists())

    def test_setup_on_an_existing_profile_shows_it_instead_of_overwriting(self) -> None:
        _run(["setup", "--defaults"])
        self.set("bot", "off")
        with mock.patch("builtins.input", side_effect=AssertionError("must not ask")):
            code, out, _err = _run(["setup"])
        self.assertEqual(code, 0)
        self.assertIn("already written", out)
        self.assertEqual(_run(["settings", "get", "bot"])[1].strip(), "off")

    def test_setup_with_no_terminal_says_what_it_needs_instead_of_answering_itself(self) -> None:
        # A pipe, or a dash pane: writing the defaults there would be this verb answering its own
        # questions on the operator's behalf and saving the result.
        code, _out, err = _run(["setup"])
        self.assertEqual(code, 2)
        self.assertIn("--defaults", err)
        self.assertFalse(gn_cli.RUNTIME_DIR.joinpath("operator_profile.json").exists())

    def test_settings_lists_every_setting_and_the_commands_that_change_them(self) -> None:
        import gn_profile

        code, out, _err = _run(["settings"])
        self.assertEqual(code, 0)
        for item in gn_profile.SETTINGS:
            self.assertIn(item.key, out)
        self.assertIn("gn settings set", out)
        self.assertIn("gn output", out)
        self.assertIn("gn setup", out, "with no profile it must name the way to write one")

    def test_get_prints_a_bare_value_for_a_script_to_read(self) -> None:
        self.assertEqual(_run(["settings", "get", "bot"])[1], "tinygpt\n")
        self.set("learning", "off")
        self.assertEqual(_run(["settings", "get", "learning"])[1], "off\n")

    def test_set_saves_immediately_and_survives_the_process(self) -> None:
        code, out, _err = _run(["settings", "set", "hunt.profile", "api"])
        self.assertEqual(code, 0)
        self.assertIn("operator_profile.json", out, "it says where it wrote")
        self.assertEqual(_run(["settings", "get", "hunt.profile"])[1].strip(), "api")

    def test_an_unknown_key_or_value_is_refused_and_nothing_is_written(self) -> None:
        for argv, expected in ((["settings", "set", "authorize", "true"], "no setting called"),
                               (["settings", "set", "always_authorize", "1"], "no setting called"),
                               (["settings", "set", "bot", "gpt5"], "tinygpt"),
                               (["settings", "set", "learning", "sometimes"], "on or off"),
                               (["settings", "get", "authorize"], "no setting called"),
                               (["settings", "unset", "authorize"], "no setting called")):
            with self.subTest(argv=argv):
                code, _out, err = _run(argv)
                self.assertEqual(code, 2)
                self.assertIn(expected, err)
        self.assertFalse(gn_cli.RUNTIME_DIR.joinpath("operator_profile.json").exists())

    def test_unset_returns_a_setting_to_its_default(self) -> None:
        self.set("bot", "off")
        code, out, _err = _run(["settings", "unset", "bot"])
        self.assertEqual(code, 0)
        self.assertIn("tinygpt", out)
        self.assertEqual(_run(["settings", "get", "bot"])[1].strip(), "tinygpt")

    def test_path_prints_where_the_profile_lives(self) -> None:
        code, out, _err = _run(["settings", "path"])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), str(self.runtime / "operator_profile.json"))

    def test_output_sets_a_folder_for_one_target_and_lists_it(self) -> None:
        folder = str(self.runtime / "acme")
        code, out, err = _run(["output", "-s", "https://acme.example/app", "--path", folder])
        self.assertEqual(code, 0, err)
        self.assertIn("acme.example", out)
        code, out, _err = _run(["output"])
        self.assertEqual(code, 0)
        self.assertIn(folder, out)

    def test_output_with_no_scope_sets_the_default_folder(self) -> None:
        folder = str(self.runtime / "all")
        self.assertEqual(_run(["output", "--path", folder])[0], 0)
        self.assertEqual(_run(["settings", "get", "output.dir"])[1].strip(), folder)

    def test_output_clear_drops_one_entry(self) -> None:
        _run(["output", "-s", "acme.example", "--path", str(self.runtime / "acme")])
        code, out, _err = _run(["output", "-s", "acme.example", "--clear"])
        self.assertEqual(code, 0)
        self.assertIn("cleared", out)
        self.assertNotIn("acme.example", _run(["output"])[1])

    def test_output_lists_runtime_reports_when_nothing_is_set(self) -> None:
        code, out, _err = _run(["output"])
        self.assertEqual(code, 0)
        self.assertIn("runtime/reports", out)


class ProfileDrivesTheVerbsTests(_ProfileCase):
    """The profile fills what the command line did not say — and nothing else."""

    def test_the_saved_posture_reaches_a_hunt_that_named_none_of_it(self) -> None:
        self.set("hunt.profile", "api")
        self.set("hunt.active", "on")
        self.set("hunt.brain", "on")
        self.set("hunt.per_finding", "on")
        self.assertEqual(_run(["output", "--path", str(self.runtime / "r")])[0], 0)
        args = self.args("hunt", "https://acme.example", "-y")
        gn_cli._from_profile(args, targets=(args.target,))
        self.assertEqual(args.profile, "api")
        self.assertTrue(args.active)
        self.assertTrue(args.brain)
        self.assertTrue(args.per_finding)
        self.assertEqual(args.out, str(self.runtime / "r"))

    def test_a_flag_the_operator_typed_always_wins(self) -> None:
        self.set("hunt.profile", "api")
        args = self.args("hunt", "https://acme.example", "-y", "-p", "secrets",
                         "-o", str(self.runtime / "typed"))
        gn_cli._from_profile(args, targets=(args.target,))
        self.assertEqual(args.profile, "secrets")
        self.assertEqual(args.out, str(self.runtime / "typed"))

    def test_no_setting_can_turn_an_armed_flag_off(self) -> None:
        # There is no "hunt.active off" that disarms --active: the profile fills blanks only.
        self.set("hunt.active", "off")
        args = self.args("hunt", "https://acme.example", "-y", "--active")
        gn_cli._from_profile(args, targets=(args.target,))
        self.assertTrue(args.active)

    def test_no_setting_can_authorize_a_hunt(self) -> None:
        import gn_profile

        # Even a profile file that was hand-edited to carry one.
        gn_profile.profile_path(self.runtime).write_text(
            json.dumps({"settings": {"authorize": True, "hunt.active": True}}), encoding="utf-8")
        args = self.args("hunt", "https://acme.example")
        gn_cli._from_profile(args, targets=(args.target,))
        self.assertFalse(args.authorize, "a file on disk cannot assert authorization")
        code, _out, err = _run(["hunt", "https://acme.example", "--json"])
        self.assertEqual(code, 2)
        self.assertIn(gn_cli._HUNT_AUTHORIZE, err)

    def test_prompting_off_in_the_profile_means_no_prompt(self) -> None:
        self.set("hunt.prompt", "off")
        args = self.args("hunt", "https://acme.example", "-y")
        gn_cli._from_profile(args, targets=(args.target,))
        self.assertTrue(args.no_prompt)

    def test_the_per_target_folder_beats_the_default_one(self) -> None:
        _run(["output", "--path", str(self.runtime / "all")])
        _run(["output", "-s", "acme.example", "--path", str(self.runtime / "acme")])
        args = self.args("hunt", "https://app.acme.example", "-y")
        gn_cli._from_profile(args, targets=(args.target,))
        self.assertEqual(args.out, str(self.runtime / "acme"))

    def test_a_first_run_hints_once_and_hunts_anyway(self) -> None:
        # A CLI that refuses to work until a wizard is answered cannot be driven from a script.
        with mock.patch.object(gn_cli, "_cmd_hunt", wraps=gn_cli._cmd_hunt), \
             mock.patch("bughunter.bounty.run_bounty_hunt",
                        return_value={"ok": True, "findings": [], "severity_counts": {},
                                      "report_path": "r.md"}):
            code, _out, err = _run(["hunt", "https://acme.example", "-y", "--no-fx"])
        self.assertEqual(code, 0, err)


class TerminalAttestationTests(_ProfileCase):
    """``-y``, or the same question asked at a terminal. Never a file, never a setting."""

    def test_yes_at_the_terminal_is_the_attestation(self) -> None:
        args = self.args("hunt", "https://acme.example")
        with _terminal(["y"]) as out:
            self.assertTrue(gn_cli._confirm_authorization(args, args.target))
        self.assertTrue(args.authorize)
        self.assertIn("acme.example", out.getvalue(), "the question names the target")
        self.assertIn("AUTHORIZED", "".join(out.prompts), "and asks for the attestation by name")

    def test_anything_but_yes_is_a_refusal(self) -> None:
        for answer in ("", "n", "no", "maybe", "sure", "Y E S", "ok"):
            with self.subTest(answer=answer):
                args = self.args("hunt", "https://acme.example")
                with _terminal([answer]):
                    self.assertFalse(gn_cli._confirm_authorization(args, args.target))
                self.assertFalse(args.authorize)
        args = self.args("hunt", "https://acme.example")
        with _terminal(["YES"]):
            self.assertTrue(gn_cli._confirm_authorization(args, args.target), "case is not the test")

    def test_eof_and_ctrl_c_are_refusals(self) -> None:
        for raised in (EOFError, KeyboardInterrupt):
            with self.subTest(raised=raised.__name__):
                args = self.args("hunt", "https://acme.example")
                with mock.patch("sys.stdout", _Tty()), mock.patch("sys.stdin", _Tty()), \
                     mock.patch("builtins.input", side_effect=raised):
                    self.assertFalse(gn_cli._confirm_authorization(args, args.target))

    def test_nobody_is_asked_when_nobody_is_there(self) -> None:
        for extra in ([], ["--json"], ["--no-prompt"]):
            with self.subTest(extra=extra):
                args = self.args("hunt", "https://acme.example", *extra)
                with mock.patch("builtins.input", side_effect=AssertionError("must not ask")):
                    self.assertFalse(gn_cli._confirm_authorization(args, args.target))

    def test_y_on_the_command_line_asks_nothing(self) -> None:
        args = self.args("hunt", "https://acme.example", "-y")
        with mock.patch("builtins.input", side_effect=AssertionError("must not ask")):
            self.assertTrue(gn_cli._confirm_authorization(args, args.target))

    def test_the_attestation_also_carries_the_scope(self) -> None:
        # Answering the question is the same act as typing -y, so it scopes the target too.
        args = self.args("hunt", "https://acme.example")
        with _terminal(["yes"]):
            gn_cli._confirm_authorization(args, args.target)
        self.assertEqual(gn_cli._authorized_scope(args, args.target), "acme.example")


class AutoScopeFormTests(_ProfileCase):
    """`gn auto hunt -s acme.example` — the one-line hunt, with no directory involved."""

    def test_a_scope_becomes_the_plan_a_directory_would_have(self) -> None:
        code, out, err = _run(["auto", "hunt", "-s", "greynoc.com", "--dry-run"])
        self.assertEqual(code, 0, err)
        self.assertIn("https://greynoc.com", out)
        self.assertIn("--scope", out)
        self.assertIn("dry run", out)

    def test_the_bare_word_hunt_is_accepted_because_it_reads_like_a_sentence(self) -> None:
        for argv in (["auto", "hunt", "-s", "greynoc.com", "--dry-run"],
                     ["auto", "-s", "greynoc.com", "--dry-run"]):
            with self.subTest(argv=argv):
                code, out, _err = _run(argv)
                self.assertEqual(code, 0)
                self.assertIn("https://greynoc.com", out)

    def test_hunt_without_a_scope_names_both_forms(self) -> None:
        code, _out, err = _run(["auto", "hunt"])
        self.assertEqual(code, 2)
        self.assertIn("-s acme.example", err)
        self.assertIn("gn auto <path>", err)

    def test_a_scope_and_a_directory_together_are_refused(self) -> None:
        code, _out, err = _run(["auto", str(BACKEND_DIR), "-s", "greynoc.com"])
        self.assertEqual(code, 2)
        self.assertIn("not both", err)

    def test_a_real_folder_called_hunt_is_still_a_folder(self) -> None:
        (self.runtime / "hunt").mkdir()
        here = os.getcwd()
        os.chdir(self.runtime)
        try:
            code, out, _err = _run(["auto", "hunt", "--dry-run"])
        finally:
            os.chdir(here)
        self.assertEqual(code, 2, "an empty folder has nothing to hunt")
        self.assertNotIn("needs a scope", out)

    def test_a_scope_hunt_is_passive_until_something_arms_it(self) -> None:
        code, out, _err = _run(["auto", "hunt", "-s", "greynoc.com", "--dry-run"])
        self.assertIn("passive only", out)
        self.set("hunt.active", "on")
        code, out, _err = _run(["auto", "hunt", "-s", "greynoc.com", "--dry-run"])
        self.assertIn("ACTIVE", out)
        code, out, _err = _run(["auto", "hunt", "-s", "greynoc.com", "--dry-run", "--passive"])
        self.assertIn("passive only", out, "--passive wins over the profile")

    def test_active_cannot_be_armed_without_a_scope_to_bind_it(self) -> None:
        # An empty scope makes host_in_active_scope refuse every host, so "ACTIVE" there would be
        # a posture line that sends no probes.
        with mock.patch("bughunter.hunt_dir.from_scope") as planner:
            planner.return_value = __import__("bughunter.hunt_dir", fromlist=["HuntPlan"]).HuntPlan(
                ok=True, targets=["https://acme.example"], scope_text="", name="acme")
            code, out, _err = _run(["auto", "-s", "acme.example", "--dry-run", "--active"])
        self.assertEqual(code, 0)
        self.assertIn("passive only", out)

    def test_a_scope_hunt_still_needs_the_attestation(self) -> None:
        code, _out, err = _run(["auto", "hunt", "-s", "greynoc.com"])
        self.assertEqual(code, 2)
        self.assertIn("-y/--authorize", err)


class AuthorizeCarriesScopeTests(unittest.TestCase):
    """``-y`` is sudo for the thing you pointed at: it puts that target in scope.

    Every verb here used to make the operator say it twice — `gn hunt https://acme.example -y -s
    acme.example` — and refuse the run for forgetting the second half. These pin the three bounds
    that make the shortcut safe: no -y, no widening; additive and exact; only the named target.
    """

    def _args(self, *argv: str) -> argparse.Namespace:
        return gn_cli.build_parser().parse_args(list(argv))

    def test_y_puts_the_target_in_scope(self) -> None:
        args = self._args("hunt", "https://acme.example", "-y")
        self.assertEqual(gn_cli._authorized_scope(args, args.target), "acme.example")

    def test_without_y_nothing_is_added(self) -> None:
        # The flag IS the attestation. A scope that widened without it would be this program
        # asserting an authorization nobody gave.
        args = self._args("hunt", "https://acme.example")
        self.assertEqual(gn_cli._authorized_scope(args, args.target), "")
        args = self._args("hunt", "https://acme.example", "-s", "other.example")
        self.assertEqual(gn_cli._authorized_scope(args, args.target), "other.example")

    def test_the_operators_own_scope_is_kept_and_added_to_never_rewritten(self) -> None:
        args = self._args("hunt", "https://acme.example", "-y", "-s", "*.corp.example other.example")
        scope = gn_cli._authorized_scope(args, args.target)
        self.assertTrue(scope.startswith("*.corp.example other.example"))
        self.assertIn("acme.example", scope.split())

    def test_a_target_already_named_is_not_named_twice(self) -> None:
        for typed in ("acme.example", "ACME.example", "other.example acme.example"):
            with self.subTest(typed=typed):
                args = self._args("hunt", "https://acme.example", "-y", "-s", typed)
                self.assertEqual(gn_cli._authorized_scope(args, args.target), typed)

    def test_nothing_is_added_for_a_target_that_needs_no_scope(self) -> None:
        for target in (".", "./repo", "not a url"):
            with self.subTest(target=target):
                args = self._args("hunt", target, "-y", "-p", "source-code")
                self.assertEqual(gn_cli._authorized_scope(args, args.target), "")

    def test_a_wildcard_is_never_derived(self) -> None:
        args = self._args("hunt", "https://sub.acme.example", "-y")
        self.assertEqual(gn_cli._authorized_scope(args, args.target), "sub.acme.example")

    def test_two_targets_each_grant_only_themselves(self) -> None:
        args = self._args("idor", "https://acme.example/a", "https://acme.example/b", "-y")
        self.assertEqual(gn_cli._authorized_scope(args, args.url_a, args.url_b), "acme.example")
        args = self._args("idor", "https://a.example/x", "https://b.example/y", "-y")
        self.assertEqual(gn_cli._authorized_scope(args, args.url_a, args.url_b).split(),
                         ["a.example", "b.example"])

    def test_the_hunt_passes_the_derived_scope_to_the_engine_and_the_board(self) -> None:
        captured: dict = {}

        def _hunt(*a: object, **kw: object) -> dict:
            captured["scope"] = a[4]
            return {"ok": True, "findings": [], "severity_counts": {}, "report_path": "r.md"}

        with mock.patch("bughunter.bounty.run_bounty_hunt", side_effect=_hunt), \
             mock.patch.object(gn_cli, "_fx") as fx:
            code = gn_cli._cmd_hunt(self._args("hunt", "https://acme.example", "-y", "--no-fx"))
        self.assertEqual(code, 0)
        self.assertEqual(captured["scope"], "acme.example",
                         "the engine reads permission out of the scope text")
        self.assertEqual(fx.call_args.kwargs["scope"], "acme.example",
                         "the board states the scope the run is actually bound by")

    def test_scan_fills_the_scope_it_was_not_given_without_joining_one_it_was(self) -> None:
        # Its gate takes exactly ONE exact grant, so this verb substitutes rather than appends.
        with mock.patch("bughunter.chat_commands.validate_scoped_network_target",
                        return_value={"ok": True, "scope_host": "acme.example"}) as gate, \
             mock.patch("bughunter.web_scan_service.run_web_scan",
                        return_value={"ok": True, "findings": []}), \
             mock.patch("bughunter.triage.summarize_findings", return_value=""):
            gn_cli._cmd_scan(self._args("scan", "https://acme.example", "-y"))
            self.assertEqual(gate.call_args.args[2], "acme.example")
            gn_cli._cmd_scan(self._args("scan", "https://acme.example", "-y",
                                        "-s", "acme.example"))
            self.assertEqual(gate.call_args.args[2], "acme.example")


class DashBoardTests(unittest.TestCase):
    """``gn dash`` — the resident threat board, and what each of its asks relaunches."""

    def _args(self, *extra: str) -> argparse.Namespace:
        return gn_cli.build_parser().parse_args(["dash", *extra])

    def _board(self, ask: object) -> tuple[int, dict]:
        """Run the driver with one ask coming back from the board, then a quit."""
        asks = [ask, None]
        calls: dict = {}

        def _run_board(**kw: object) -> object:
            calls["kw"] = kw
            return asks.pop(0)

        with mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.board_refusal", return_value=""), \
             mock.patch("gn_dash.run_board", side_effect=_run_board), \
             mock.patch.object(gn_cli, "_dash_board_again", return_value=False), \
             mock.patch.object(gn_cli, "_cmd_hunt", return_value=0) as hunt, \
             mock.patch.object(gn_cli, "_cmd_dash", return_value=0) as dash:
            code = gn_cli._cmd_dash_board(self._args())
        calls["hunt"], calls["dash"] = hunt, dash
        return code, calls

    def test_quitting_the_board_launches_nothing(self) -> None:
        code, calls = self._board(None)
        self.assertEqual(code, 0)
        calls["hunt"].assert_not_called()
        calls["dash"].assert_not_called()

    def test_a_hunt_runs_the_real_verb_with_the_consent_and_depth_the_board_took(self) -> None:
        # _cmd_hunt, NOT _cmd_dash: the hunt must draw its own live board (the arcs are the
        # engine's) and leave its summary on a restored terminal.
        code, calls = self._board({"action": "hunt", "target": "https://t.example",
                                   "depth": {"theorize": True, "turns": 3}})
        self.assertEqual(code, 0)
        calls["dash"].assert_not_called()
        nxt = calls["hunt"].call_args[0][0]
        self.assertEqual(nxt.target, "https://t.example")
        self.assertTrue(nxt.authorize, "the board demanded -y; that consent must carry through")
        self.assertTrue(nxt.theorize)
        self.assertEqual(nxt.turns, 3)
        self.assertFalse(nxt.attach)
        for flag in ("board", "home", "panels"):
            self.assertFalse(getattr(nxt, flag), f"leaving --{flag} set would recurse")

    def test_a_hunt_returns_to_standby_until_the_operator_says_otherwise(self) -> None:
        asks = [{"action": "hunt", "target": "https://t.example", "depth": {}},
                {"action": "hunt", "target": "https://t.example", "depth": {}}, None]
        again = [True, False]
        with mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.board_refusal", return_value=""), \
             mock.patch("gn_dash.run_board", side_effect=lambda **_kw: asks.pop(0)), \
             mock.patch.object(gn_cli, "_dash_board_again", side_effect=lambda: again.pop(0)), \
             mock.patch.object(gn_cli, "_cmd_hunt", return_value=0) as hunt:
            code = gn_cli._cmd_dash_board(self._args())
        self.assertEqual(code, 0)
        self.assertEqual(hunt.call_count, 2, "ENTER brings the board back; q leaves")

    def test_attach_and_panels_hand_over_to_the_cockpit(self) -> None:
        for ask, expected in (({"action": "attach"}, {"attach": True, "target": ""}),
                              ({"action": "panels"}, {"panels": True})):
            with self.subTest(ask=ask):
                code, calls = self._board(ask)
                self.assertEqual(code, 0)
                calls["hunt"].assert_not_called()
                nxt = calls["dash"].call_args[0][0]
                for field, value in expected.items():
                    self.assertEqual(getattr(nxt, field), value)

    def test_an_unknown_ask_launches_nothing(self) -> None:
        code, calls = self._board({"action": "sudo-rm-rf"})
        self.assertEqual(code, 0)
        calls["hunt"].assert_not_called()
        calls["dash"].assert_not_called()

    def test_the_scope_the_operator_declared_is_what_the_board_states(self) -> None:
        # The board prints it beside "AUTHORIZED SCOPE ONLY"; it may only ever be the operator's
        # own words, never a target standing in for them.
        with mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.board_refusal", return_value=""), \
             mock.patch("gn_dash.run_board", return_value=None) as run_board:
            gn_cli._cmd_dash_board(gn_cli.build_parser().parse_args(
                ["dash", "-s", "*.acme.example"]))
        self.assertEqual(run_board.call_args.kwargs["scope"], "*.acme.example")

    def test_a_terminal_that_will_not_take_the_board_says_so(self) -> None:
        with mock.patch("gn_tui.refusal", return_value=""), \
             mock.patch("gn_dash.board_refusal", return_value="too small, it says"), \
             mock.patch("gn_dash.run_board") as run_board:
            code, _out, err = _run(["dash"])
        self.assertEqual(code, 2)
        self.assertIn("too small, it says", err)
        run_board.assert_not_called()

    def test_a_non_tty_refuses_instead_of_silently_hunting(self) -> None:
        code, _out, err = _run(["dash"])
        self.assertEqual(code, 2)
        self.assertIn("terminal", err.lower())

    def test_returning_to_standby_is_the_default_answer_and_q_is_not(self) -> None:
        for typed, expected in (("", True), ("\n", True), ("q", False), ("Q", False),
                                ("quit", False), ("yes", True)):
            with self.subTest(typed=typed), mock.patch("builtins.input", return_value=typed):
                self.assertIs(gn_cli._dash_board_again(), expected)
        with mock.patch("builtins.input", side_effect=EOFError):
            self.assertFalse(gn_cli._dash_board_again(), "a piped stdin has nobody to ask")


class DashHomeTests(unittest.TestCase):
    """``gn dash --panels`` — the idle cockpit and the relaunch handoff `GreyNOC Start` depends on."""

    def _args(self, *extra: str) -> argparse.Namespace:
        return gn_cli.build_parser().parse_args(["dash", "--panels", *extra])

    def test_the_older_home_spelling_still_opens_the_panels(self) -> None:
        self.assertTrue(gn_cli.build_parser().parse_args(["dash", "--home"]).home)
        with mock.patch.object(gn_cli, "_cmd_dash_home", return_value=0) as home:
            gn_cli._cmd_dash(gn_cli.build_parser().parse_args(["dash", "--home"]))
        home.assert_called_once()

    def test_panels_is_registered_and_routes_to_the_home_driver(self) -> None:
        self.assertTrue(self._args().panels)
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

    def test_turns_without_theorize_is_refused_on_the_shell_path_too(self) -> None:
        # -Tn alone sets hunt_loop_max_iters while the loop stays off, so the hunt would succeed
        # while silently ignoring the depth asked for. The cockpit already refuses this pair; the
        # same command must not mean two different things depending on where it was typed.
        for verb in ("hunt", "dash"):
            with self.subTest(verb=verb):
                args = gn_cli.build_parser().parse_args(
                    [verb, "https://t.example", "-y", "-Tn", "5"])
                self.assertIn("only has an effect with -Th", gn_cli.depth_refusal(args))

    def test_turns_with_theorize_is_accepted(self) -> None:
        args = gn_cli.build_parser().parse_args(
            ["hunt", "https://t.example", "-y", "-Th", "-Tn", "5"])
        self.assertEqual(gn_cli.depth_refusal(args), "")

    def test_the_shell_refuses_before_running_the_hunt_at_all(self) -> None:
        with mock.patch("bughunter.bounty.run_bounty_hunt") as hunt, \
             contextlib.redirect_stderr(io.StringIO()) as err:
            code = gn_cli._cmd_hunt(gn_cli.build_parser().parse_args(
                ["hunt", "https://t.example", "-y", "-Tn", "5"]))
        self.assertEqual(code, 2)
        hunt.assert_not_called()
        self.assertIn("-Tn", err.getvalue())

    def test_dash_refuses_before_entering_the_alternate_screen(self) -> None:
        # A refusal printed into a screen about to be discarded is one the operator never sees.
        with mock.patch("gn_dash.run") as run, mock.patch.object(gn_cli, "_cmd_dash_home") as home, \
             contextlib.redirect_stderr(io.StringIO()) as err:
            code = gn_cli._cmd_dash(gn_cli.build_parser().parse_args(
                ["dash", "--home", "-Tn", "5"]))
        self.assertEqual(code, 2)
        run.assert_not_called()
        home.assert_not_called()
        self.assertIn("-Tn", err.getvalue())

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


class OobCredsTests(unittest.TestCase):
    """`_oob_creds` reads the collaborator the desktop app already stored.

    The app's OOB panel writes `oob.collaborator_url` + `oob.secret` into the shared
    secrets file (`save_oob_config`). A terminal-driven hunt must read that SAME place —
    a second config location is how one of them ends up stale.
    """

    def _with_secrets(self, payload):
        import json as _json
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        if payload is not None:
            (root / "secrets.json").write_text(_json.dumps(payload), encoding="utf-8")
        orig = gn_cli.RUNTIME_DIR
        gn_cli.RUNTIME_DIR = root
        self.addCleanup(lambda: setattr(gn_cli, "RUNTIME_DIR", orig))
        return gn_cli._oob_creds()

    def test_reads_the_configured_collaborator(self) -> None:
        base, secret = self._with_secrets({
            "oob.collaborator_url": "https://chat.example", "oob.secret": "s" * 32})
        self.assertEqual(base, "https://chat.example")
        self.assertEqual(secret, "s" * 32)

    def test_absent_or_malformed_secrets_are_empty_not_an_error(self) -> None:
        """A hunt must not fail because no collaborator was ever configured."""
        for payload in (None, {}, {"oob.collaborator_url": ""}, []):
            with self.subTest(payload=payload):
                self.assertEqual(self._with_secrets(payload), ("", ""))

    def test_values_are_trimmed(self) -> None:
        base, secret = self._with_secrets({
            "oob.collaborator_url": "  https://chat.example  ", "oob.secret": "  tok  "})
        self.assertEqual((base, secret), ("https://chat.example", "tok"))


class AutoSchedulesItsOwnCycleTests(unittest.TestCase):
    """`gn auto` hunts one cycle itself, so it must record that cycle's schedule.

    ``operator.run_program_cycle`` deliberately does not stamp: the loop's ``_run_one``
    owns that, so a guard halt can leave the program due on purpose. Nothing else was
    stamping the directly-invoked cycle, so ``next_run_at`` stayed unset, ``_is_due`` read
    it as "never run", and the very next scheduler pass re-hunted the same targets at once.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="gn-auto-sched-")
        self.root = Path(self._tmp.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.hunt = self.root / "repo"
        (self.hunt / ".greyiq").mkdir(parents=True)
        (self.hunt / ".greyiq" / "targets.txt").write_text(
            "https://app.example.com\n", encoding="utf-8")
        self._orig_runtime = gn_cli.RUNTIME_DIR
        gn_cli.RUNTIME_DIR = self.runtime
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(lambda: setattr(gn_cli, "RUNTIME_DIR", self._orig_runtime))

    def _run_auto(self, extra: list[str] | None = None) -> tuple[int, str]:
        """`gn auto --once` with the hunt and the brain stubbed out: no network, no model."""
        summary = {"program": "", "targets_run": 1, "findings": 0, "confirmed": 0,
                   "submitted": 0, "errors": [], "stopped": False, "stop_reason": ""}
        from bughunter import operator as operator_mod
        with mock.patch.object(gn_cli, "_operator_campaign_fn", return_value=lambda *a, **k: {}), \
             mock.patch.object(gn_cli, "_operator_sync_fn", return_value=None), \
             mock.patch.object(operator_mod, "run_program_cycle", return_value=summary):
            return _run(["auto", str(self.hunt), "-y", "--once", *(extra or [])])[:2]

    def test_the_cycle_is_stamped_so_the_scheduler_does_not_rerun_it(self) -> None:
        from bughunter import operator as operator_mod
        from bughunter import portfolio

        code, _ = self._run_auto()
        self.assertEqual(code, 0)

        programs = portfolio.list_programs(self.runtime)
        self.assertEqual(len(programs), 1, programs)
        program = programs[0]
        self.assertTrue(program.get("last_run_at"), "the cycle that ran was not recorded")
        self.assertTrue(program.get("next_run_at"), "no next_run_at: the program reads as never run")

        # The invariant that actually matters: the scheduler must not consider it due.
        loop = operator_mod.OperatorLoop(str(self.runtime), run_campaign_fn=lambda *a, **k: {})
        self.assertFalse(loop._is_due(program),
                         "a just-hunted program is still due, so the loop re-hunts it immediately")

    def test_the_stamp_honours_the_directory_interval(self) -> None:
        from bughunter import portfolio

        code, _ = self._run_auto(["--interval", "30"])
        self.assertEqual(code, 0)
        program = portfolio.list_programs(self.runtime)[0]
        self.assertEqual(int(program.get("interval_minutes")), 30)
        due_at = datetime.fromisoformat(str(program["next_run_at"]))
        delta = due_at - datetime.now(UTC)
        self.assertGreater(delta, timedelta(minutes=25))
        self.assertLess(delta, timedelta(minutes=35))
