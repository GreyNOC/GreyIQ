"""Picking a bot has to change the HUNT, and that is the whole reason the registry exists.

Before this, ``bot`` was a setting the studio displayed and nothing honoured: the panel said
``bot anthropic`` while ``hunt_brain`` ran on whatever the desktop app had last written into
``solin_runtime_config.json``. That is the same shape of defect the ``learning`` switch had — a
control that reads as honoured and is not — and ``LearningOptOutTests`` in test_gn_cli pins the
other half of it.

So these tests follow the selection all the way to the config the planner is handed:

  * ``gn bot use X`` then ``--brain`` must produce X's provider and model.
  * The key still comes from the perms-restricted secrets store and must survive the overlay.
  * A local-only or ``off`` bot must leave the hunt deterministic, which is a real posture and not
    a failure.
  * Without ``--brain`` nothing is loaded at all, bot or no bot.
  * A bot store that will not load must cost the operator their SELECTION, never their hunt.
  * ``gn bot`` is registered on the CLI and stays import-light, like every other verb plugin.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_bots  # noqa: E402
import gn_cli  # noqa: E402
import gn_profile  # noqa: E402


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = gn_cli.main(argv)
    return (code, out.getvalue(), err.getvalue())


class _Tty(io.StringIO):
    """A stream that claims to be a terminal, so `gn setup` asks its questions."""

    def isatty(self) -> bool:
        return True


@contextmanager
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

    err = io.StringIO()
    with mock.patch("sys.stdout", out), mock.patch("sys.stdin", _Tty()),          mock.patch("builtins.input", _input), redirect_stderr(err):
        yield (out, err)


class _RuntimeCase(unittest.TestCase):
    """A CLI with its own runtime directory, so no test can read or write the real store."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="gn-bots-")
        self.runtime = Path(self._tmp.name)
        self._saved = gn_cli.RUNTIME_DIR
        gn_cli.RUNTIME_DIR = self.runtime
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        gn_cli.RUNTIME_DIR = self._saved
        self._tmp.cleanup()

    def write_runtime_config(self, **coder_block: object) -> None:
        self.runtime.joinpath("solin_runtime_config.json").write_text(
            json.dumps({"coder": coder_block}), encoding="utf-8")

    def write_secret(self, provider: str, key: str) -> None:
        self.runtime.joinpath("secrets.json").write_text(
            json.dumps({provider: key}), encoding="utf-8")


class SelectionReachesTheHuntTests(_RuntimeCase):
    def test_the_live_bot_decides_the_provider_and_model_the_planner_gets(self) -> None:
        self.write_runtime_config(enabled=False, provider="openai",
                                  openai={"model": "gpt-4o"},
                                  anthropic={"model": "an-old-one"})
        self.write_secret("anthropic", "sk-SECRET")
        self.assertEqual(_run(["bot", "new", "scout", "--provider", "anthropic",
                               "--model", "claude-opus-5"])[0], 0)
        self.assertEqual(_run(["bot", "use", "scout"])[0], 0)
        config = gn_cli._load_coder_config(True)
        self.assertTrue(config["enabled"])
        self.assertEqual(config["provider"], "anthropic")
        self.assertEqual(config["anthropic"]["model"], "claude-opus-5")
        self.assertEqual(config["anthropic"]["api_key"], "sk-SECRET",
                         "the key comes from the secrets store and must survive the overlay")

    def test_switching_the_bot_switches_what_the_next_hunt_plans_with(self) -> None:
        self.write_runtime_config(enabled=True, provider="anthropic",
                                  anthropic={"model": "claude-opus-5"},
                                  local={"model": "qwen2.5-coder:14b"})
        _run(["bot", "new", "qwen", "--provider", "local", "--model", "qwen3:32b"])
        _run(["bot", "use", "qwen"])
        config = gn_cli._load_coder_config(True)
        self.assertEqual(config["provider"], "local")
        self.assertEqual(config["local"]["model"], "qwen3:32b")
        _run(["bot", "use", "anthropic"])
        config = gn_cli._load_coder_config(True)
        self.assertEqual(config["provider"], "anthropic")

    def test_a_local_only_or_off_bot_leaves_the_hunt_deterministic(self) -> None:
        self.write_runtime_config(enabled=True, provider="anthropic",
                                  anthropic={"model": "claude-opus-5"})
        for name in ("tinygpt", "off"):
            with self.subTest(bot=name):
                _run(["bot", "use", name])
                self.assertEqual(gn_cli._load_coder_config(True), {},
                                 "a bot that does not send prompts off the machine must not be "
                                 "able to hand the planner a hosted brain")

    def test_without_the_brain_flag_nothing_is_loaded_at_all(self) -> None:
        self.write_runtime_config(enabled=True, provider="anthropic",
                                  anthropic={"model": "claude-opus-5"})
        _run(["bot", "use", "anthropic"])
        self.assertEqual(gn_cli._load_coder_config(False), {},
                         "deterministic by default is unchanged: a bot is a selection, not a "
                         "decision to spend an API budget")

    def test_a_corrupt_store_still_honours_a_builtin_selection(self) -> None:
        """A store that will not parse loses the DEFINITIONS, not the selection.

        ``gn_bots.load`` is total and merges the built-ins regardless, so an operator who picked
        one of them keeps their brain and gets the file's error reported elsewhere.
        """
        self.write_runtime_config(enabled=False, provider="openai", openai={"model": "gpt-4o"},
                                  anthropic={"model": "claude-opus-5"})
        _run(["bot", "use", "anthropic"])
        gn_bots.store_path(self.runtime).write_text("{not json", encoding="utf-8")
        config = gn_cli._load_coder_config(True)
        self.assertEqual(config["provider"], "anthropic")
        self.assertTrue(gn_bots.load(self.runtime).error, "and the store says why it is broken")

    def test_a_corrupt_store_that_loses_a_CUSTOM_bot_falls_back_locally(self) -> None:
        """The safe direction. A missing definition must not become a different hosted brain.

        Substituting whatever ``solin_runtime_config.json`` happened to say would send the
        operator's prompts to a provider they did not pick — so an unresolvable selection is the
        local default, which means a deterministic hunt.
        """
        self.write_runtime_config(enabled=True, provider="openai", openai={"model": "gpt-4o"})
        _run(["bot", "new", "my-claude", "--provider", "anthropic", "--model", "claude-opus-5"])
        _run(["bot", "use", "my-claude"])
        gn_bots.store_path(self.runtime).write_text("{not json", encoding="utf-8")
        self.assertEqual(gn_cli._load_coder_config(True), {})

    def test_a_bot_the_profile_names_but_the_store_lost_falls_back_locally(self) -> None:
        self.write_runtime_config(enabled=True, provider="anthropic",
                                  anthropic={"model": "claude-opus-5"})
        profile, error = gn_profile.set_value(gn_profile.load(self.runtime), "bot", "deleted-bot")
        self.assertEqual(error, "")
        gn_profile.save(self.runtime, profile)
        self.assertEqual(gn_cli._load_coder_config(True), {},
                         "an unresolvable selection resolves to the local default, which means "
                         "deterministic — never to whatever the config happened to say")

    def test_asking_for_a_brain_and_not_getting_one_is_said_out_loud(self) -> None:
        """`--brain` is a request, and a request that quietly does nothing is the whole defect.

        tinygpt, off, offline and an inert clone all resolve to no reasoning brain. That is a real
        posture - the hunt runs its bounded offline planner - but an operator who typed --brain
        and gets it without a word has been told nothing.
        """
        self.write_runtime_config(enabled=True, provider="anthropic",
                                  anthropic={"model": "claude-opus-5"})
        for name in ("tinygpt", "off", "offline"):
            with self.subTest(bot=name):
                _run(["bot", "use", name])
                gn_cli._BRAIN_REPORTED = False
                err = io.StringIO()
                with redirect_stderr(err):
                    config = gn_cli._load_coder_config(True)
                import coder

                self.assertFalse(coder.reasoning_brain_enabled(config),
                                 "offline produces a config and still cannot plan")
                self.assertIn("--brain", err.getvalue())
                self.assertIn(name, err.getvalue())
                self.assertIn("gn bot ls", err.getvalue(), "and how to pick another")

    def test_a_bot_that_IS_a_brain_says_nothing(self) -> None:
        self.write_runtime_config(enabled=True, provider="anthropic",
                                  anthropic={"model": "claude-opus-5"})
        _run(["bot", "new", "q", "--provider", "local", "--model", "qwen3:32b"])
        _run(["bot", "use", "q"])
        gn_cli._BRAIN_REPORTED = False
        err = io.StringIO()
        with redirect_stderr(err):
            gn_cli._load_coder_config(True)
        self.assertEqual(err.getvalue(), "")

    def test_nothing_is_said_without_the_flag_at_all(self) -> None:
        _run(["bot", "use", "off"])
        gn_cli._BRAIN_REPORTED = False
        err = io.StringIO()
        with redirect_stderr(err):
            gn_cli._load_coder_config(False)
        self.assertEqual(err.getvalue(), "", "deterministic by default is not a surprise")

    def test_an_unresolvable_selection_is_reported_too(self) -> None:
        profile, _error = gn_profile.set_value(gn_profile.load(self.runtime), "bot", "deleted-bot")
        gn_profile.save(self.runtime, profile)
        gn_cli._BRAIN_REPORTED = False
        err = io.StringIO()
        with redirect_stderr(err):
            gn_cli._load_coder_config(True)
        self.assertIn("deleted-bot", err.getvalue())
        self.assertIn("not in the store", err.getvalue())

    def test_the_hunt_verbs_all_read_the_same_loader(self) -> None:
        source = Path(BACKEND_DIR, "gn_cli.py").read_text(encoding="utf-8")
        self.assertNotIn('payload.get("coder")', source.replace(
            source[source.index("def _load_coder_config"):source.index("def _oob_config")], ""),
            "every verb must reach the brain through _load_coder_config, which is where the bot "
            "overlay is applied; a second reader would silently ignore the selection")


class SettingsAndBotUseAgreeTests(_RuntimeCase):
    def test_both_doors_write_the_same_place_and_refuse_the_same_way(self) -> None:
        _run(["bot", "new", "scout", "--provider", "local", "--model", "qwen3:32b"])
        self.assertEqual(_run(["settings", "set", "bot", "scout"])[0], 0)
        self.assertEqual(gn_profile.load(self.runtime).get("bot"), "scout")
        self.assertEqual(gn_bots.active(self.runtime)[0].id, "scout")
        code, _out, err = _run(["settings", "set", "bot", "skynet"])
        self.assertEqual(code, 2)
        self.assertIn("no bot called", err)
        code, _out, err = _run(["bot", "use", "skynet"])
        self.assertEqual(code, 2)
        self.assertIn("no bot called", err)
        self.assertEqual(gn_profile.load(self.runtime).get("bot"), "scout", "unchanged")

    def test_setup_refuses_a_bot_that_does_not_exist_and_writes_nothing(self) -> None:
        with _terminal(["", "skynet"]) as (_out, err):
            code = gn_cli.main(["setup"])
        self.assertEqual(code, 2)
        self.assertIn("nothing was written", err.getvalue())
        self.assertIn("no bot called", err.getvalue())
        self.assertFalse(gn_profile.profile_path(self.runtime).exists())

    def test_setup_offers_the_bots_that_exist(self) -> None:
        _run(["bot", "new", "scout", "--provider", "local", "--model", "qwen3:32b"])
        with _terminal([""] * 12) as (out, _err):
            code = gn_cli.main(["setup"])
        self.assertEqual(code, 0)
        bot_prompt = next(line for line in out.prompts if line.strip().startswith("Bot"))
        self.assertIn("scout", bot_prompt, "the wizard lists the operator's own bots, not five "
                                           "hardcoded provider names")
        self.assertIn("tinygpt", bot_prompt)


class VerbRegistrationTests(_RuntimeCase):
    def test_gn_bot_is_registered_with_every_action_it_documents(self) -> None:
        parser = gn_cli.build_parser()
        self.assertIn("bot", gn_cli.CLI_COMMANDS)
        for action in ("ls", "show", "use", "new", "set", "rm", "clone", "reset", "teach",
                       "forget", "train", "fields", "hf"):
            with self.subTest(action=action):
                args = parser.parse_args(["bot", action] + _sample_args(action))
                self.assertTrue(callable(args.func))

    def test_a_bare_gn_bot_lists_them_rather_than_printing_help(self) -> None:
        code, out, _err = _run(["bot"])
        self.assertEqual(code, 0)
        self.assertIn("tinygpt", out)
        self.assertIn("* = live", out)

    def test_the_verb_plugin_stays_import_light(self) -> None:
        """``register_cli`` runs on every ``import gn_cli``, so it may not pull the ML stack in.

        ``test_boot_no_torch`` enforces the whole boot path; this pins the one import this module
        adds, because a plugin that imports its engine at registration time is the way that
        guarantee has been broken before.
        """
        source = Path(BACKEND_DIR, "gn_bots.py").read_text(encoding="utf-8")
        head = source[: source.index("# --- the gn verb")]
        for banned in ("import torch", "import coder", "import hf_gguf_import",
                       "from bughunter", "import numpy"):
            with self.subTest(banned=banned):
                self.assertNotIn(f"\n{banned}", head,
                                 "the registry is on the hunt path and must stay stdlib-only")


    def test_the_hugging_face_plug_in_is_reachable_in_a_frozen_build(self) -> None:
        """``gn_bot_hf`` is not a verb plugin, so the spec does not force-include it by name.

        What carries it into the bundle is that both call sites use a plain ``import gn_bot_hf``
        statement, which PyInstaller's module graph follows even inside a function body. An
        ``importlib.import_module`` by string would be invisible to it and the verb would be
        present, dispatchable, and broken only in the shipped exe — the exact failure
        ``VerbPluginsAreFrozenSafeTests`` was written for.
        """
        for module in ("gn_bots.py", "gn_studio.py"):
            source = Path(BACKEND_DIR, module).read_text(encoding="utf-8")
            with self.subTest(module=module):
                self.assertIn("import gn_bot_hf", source)
                self.assertNotIn('import_module("gn_bot_hf")', source)
        self.assertTrue(Path(BACKEND_DIR, "gn_bot_hf.py").is_file())


def _sample_args(action: str) -> list[str]:
    needs_name = {"show": [], "use": ["x"], "new": ["x"], "rm": ["x"], "clone": ["x"],
                  "reset": ["x"], "forget": ["x", "all"], "train": [], "fields": [], "ls": []}
    if action == "set":
        return ["x", "model", "y"]
    if action == "teach":
        return ["x", "a", "lesson"]
    if action == "hf":
        return ["owner/repo"]
    return needs_name.get(action, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
