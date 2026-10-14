"""Plugging a Hugging Face bot in means fetching a stranger's work, so the risks are:

  * **Running it.** An agent repository is somebody else's Python and somebody else's prompts. It is
    cloned by ``hf_agent_clone`` (pinned, digest-verified) and registered **inert**: nothing may
    turn that off, and ``coder_overlay`` builds no config for it.
  * **Treating one kind as the other.** Weights become a runnable local bot; an agent does not. The
    decision is made from what the Hub serves, and a models repository with no GGUF falls through
    to the clone path WITH that said out loud.
  * **Claiming a model works.** An imported model is probed for chat and tool calls, and the bot's
    note and the report say exactly what the probe found — never that it is ready because it
    downloaded.
  * **Fetching on the wrong trigger.** Every network call is behind an explicit verb; nothing here
    runs from a listing or a repaint.

The network is not exercised here: ``coder``, ``hf_gguf_import`` and ``hf_agent_clone`` are the
seams, and each is replaced. What is pinned is the orchestration and what the operator is told.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import gn_bot_hf  # noqa: E402
import gn_bots  # noqa: E402


class ReferenceTests(unittest.TestCase):
    def test_a_space_is_always_an_agent(self) -> None:
        for reference in ("spaces/owner/name", "hf.co/spaces/owner/name",
                          "https://huggingface.co/spaces/owner/name"):
            with self.subTest(reference=reference):
                self.assertTrue(gn_bot_hf.looks_like_agent(reference))

    def test_a_model_reference_is_not(self) -> None:
        for reference in ("owner/name-GGUF", "hf.co/owner/name",
                          "https://huggingface.co/owner/name"):
            with self.subTest(reference=reference):
                self.assertFalse(gn_bot_hf.looks_like_agent(reference))

    def test_a_bare_owner_repo_is_read_as_the_hub_because_the_verb_said_so(self) -> None:
        self.assertEqual(gn_bot_hf._hf_prefixed("owner/name"), "hf.co/owner/name")
        self.assertEqual(gn_bot_hf._hf_prefixed("hf.co/owner/name"), "hf.co/owner/name")
        self.assertEqual(gn_bot_hf._hf_prefixed("https://huggingface.co/o/n"),
                         "https://huggingface.co/o/n")

    def test_the_endpoint_comes_from_the_operators_own_config(self) -> None:
        with TemporaryDirectory() as tmp:
            host, base = gn_bot_hf.ollama_endpoint(Path(tmp))
            self.assertEqual(base, coder.CODER_DEFAULTS["local"]["base_url"])
            Path(tmp, "solin_runtime_config.json").write_text(
                '{"coder": {"local": {"base_url": "http://127.0.0.1:11500/v1"}}}',
                encoding="utf-8")
            host, base = gn_bot_hf.ollama_endpoint(Path(tmp))
        self.assertEqual(base, "http://127.0.0.1:11500/v1")
        self.assertEqual(host, "http://127.0.0.1:11500",
                         "an operator who moved Ollama gets their own endpoint, not the default")


class _Seam:
    """The three modules ``gn_bot_hf`` reaches through, replaced for one call."""

    def __init__(self, **coder_attrs: object) -> None:
        self.coder = mock.MagicMock()
        self.coder.CoderError = coder.CoderError
        self.coder.CODER_DEFAULTS = coder.CODER_DEFAULTS
        self.coder.ollama_host = coder.ollama_host
        self.coder.normalize_huggingface_model_ref = coder.normalize_huggingface_model_ref
        self.coder.model_installed.return_value = False
        self.coder.ollama_list_models.return_value = ["hf.co/u/r:Q4_K_M"]
        self.coder.ollama_probe_readiness.return_value = {"chat_ready": True, "tool_ready": True}
        for key, value in coder_attrs.items():
            setattr(self.coder, key, value)
        self.clone = mock.MagicMock()
        self.clone.AgentCloneError = type("AgentCloneError", (RuntimeError,), {})
        self.clone.clone_agent.return_value = {
            "slug": "first-agent", "name": "First agent", "layout": "smolagents",
            "origin": {"repo_id": "spaces/owner/name", "revision": "a" * 40},
            "tools": [{"name": "web_search"}, {"name": "get_time"}],
            "path": "/runtime/agents/first-agent",
        }
        self.gguf = mock.MagicMock()
        self.gguf.import_sharded_hf_model.return_value = "hf.co/u/r:Q4_K_M-sharded"

    def __enter__(self):
        self._patch = mock.patch.dict(sys.modules, {
            "coder": self.coder, "hf_agent_clone": self.clone, "hf_gguf_import": self.gguf})
        self._patch.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._patch.stop()


class ModelImportTests(unittest.TestCase):
    def test_a_model_becomes_a_runnable_local_bot_pinned_to_the_imported_alias(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            # The pull "installs" it, so the post-pull check sees it.
            seam.coder.model_installed.side_effect = [False, True]
            result = gn_bot_hf.plug_model(tmp, "unsloth/Qwen2.5-Coder-GGUF", alias="qwen")
            bot = gn_bots.load(tmp).get(result["bot"])
        self.assertEqual(result["kind"], "model")
        self.assertTrue(result["runnable"])
        self.assertEqual(bot.provider, "local")
        self.assertEqual(bot.model, "hf.co/unsloth/Qwen2.5-Coder-GGUF")
        self.assertEqual(bot.source, "huggingface")
        self.assertEqual(bot.origin["kind"], "gguf")
        self.assertFalse(bot.off_machine, "an imported model runs on this machine")
        self.assertFalse(bot.inert)

    def test_the_repository_is_checked_for_gguf_before_anything_is_downloaded(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.model_installed.side_effect = [False, True]
            gn_bot_hf.plug_model(tmp, "owner/repo")
            self.assertTrue(seam.coder.check_public_hf_gguf.called)
            order = [name for name, _a, _k in seam.coder.mock_calls]
            self.assertLess(order.index("check_public_hf_gguf"), order.index("ollama_pull"))

    def test_a_sharded_repository_falls_back_to_the_verified_shard_importer(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.ollama_pull.side_effect = coder.CoderError(
                "This is a sharded GGUF repository.")
            seam.coder.model_installed.side_effect = [False, True]
            result = gn_bot_hf.plug_model(tmp, "owner/repo")
        self.assertTrue(seam.gguf.import_sharded_hf_model.called)
        self.assertEqual(result["model"], "hf.co/u/r:Q4_K_M-sharded")

    def test_a_pull_failure_that_is_not_sharding_is_raised_as_it_came(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.ollama_pull.side_effect = coder.CoderError("Ollama is not running.")
            with self.assertRaises(coder.CoderError) as caught:
                gn_bot_hf.plug_model(tmp, "owner/repo")
        self.assertIn("not running", str(caught.exception))
        self.assertFalse(seam.gguf.import_sharded_hf_model.called)

    def test_a_model_that_fails_the_chat_probe_is_not_called_ready(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.model_installed.side_effect = [False, True]
            seam.coder.ollama_probe_readiness.return_value = {
                "chat_ready": False, "tool_ready": False, "reason": "it returned no content"}
            result = gn_bot_hf.plug_model(tmp, "owner/repo")
            bot = gn_bots.load(tmp).get(result["bot"])
        self.assertFalse(result["runnable"])
        self.assertIn("failed the chat probe", bot.notes)
        report = "\n".join(gn_bot_hf.report_lines(result))
        self.assertIn("it returned no content", report)
        self.assertIn("nothing should be pointed at it yet", report)

    def test_a_chat_only_model_says_the_agent_and_planner_cannot_use_it(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.model_installed.side_effect = [False, True]
            seam.coder.ollama_probe_readiness.return_value = {
                "chat_ready": True, "tool_ready": False, "reason": "no tool calls"}
            result = gn_bot_hf.plug_model(tmp, "owner/repo")
            bot = gn_bots.load(tmp).get(result["bot"])
        self.assertTrue(result["runnable"], "it can still chat")
        self.assertIn("chat only", bot.notes)
        self.assertIn("chat only", "\n".join(gn_bot_hf.report_lines(result)))

    def test_an_already_installed_model_is_not_downloaded_again(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.model_installed.return_value = True
            seam.coder.model_installed.side_effect = None
            gn_bot_hf.plug_model(tmp, "owner/repo")
        self.assertFalse(seam.coder.ollama_pull.called)

    def test_an_import_that_ollama_claims_but_cannot_show_is_refused(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.model_installed.return_value = False
            with self.assertRaises(coder.CoderError) as caught:
                gn_bot_hf.plug_model(tmp, "owner/repo")
        self.assertIn("absent from its installed list", str(caught.exception))


class AgentCloneTests(unittest.TestCase):
    def test_a_cloned_agent_is_registered_inert_and_cannot_be_a_brain(self) -> None:
        with TemporaryDirectory() as tmp, _Seam():
            result = gn_bot_hf.plug_agent(tmp, "spaces/owner/name")
            registry = gn_bots.load(tmp)
            bot = registry.get(result["bot"])
        self.assertEqual(result["kind"], "agent")
        self.assertFalse(result["runnable"])
        self.assertTrue(bot.inert)
        self.assertEqual(bot.source, "clone")
        self.assertEqual(gn_bots.coder_overlay(bot, {"provider": "local"}), {})
        _r, changed, error = gn_bots.update(registry, bot.id, "provider", "local")
        self.assertIsNone(changed)
        self.assertIn("inert", error)

    def test_the_clone_records_where_it_came_from_and_at_which_commit(self) -> None:
        with TemporaryDirectory() as tmp, _Seam():
            result = gn_bot_hf.plug_agent(tmp, "spaces/owner/name")
            bot = gn_bots.load(tmp).get(result["bot"])
        self.assertEqual(bot.origin["repo"], "spaces/owner/name")
        self.assertEqual(bot.origin["revision"], "a" * 12)
        self.assertEqual(result["tools"], 2)
        self.assertIn("inert", "\n".join(gn_bot_hf.report_lines(result)))

    def test_cloning_is_delegated_rather_than_reimplemented(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            gn_bot_hf.plug_agent(tmp, "spaces/owner/name", alias="first")
        self.assertEqual(seam.clone.clone_agent.call_args.kwargs["alias"], "first",
                         "every safety rule about cloning a stranger's agent lives in that module")


class RoutingTests(unittest.TestCase):
    def test_a_space_goes_to_the_clone_path_without_probing_for_weights(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            result = gn_bot_hf.plug(tmp, "spaces/owner/name")
        self.assertEqual(result["kind"], "agent")
        self.assertFalse(seam.coder.check_public_hf_gguf.called)

    def test_a_models_repo_with_no_gguf_falls_through_to_the_clone_and_says_so(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.check_public_hf_gguf.side_effect = coder.CoderError(
                "This Hugging Face repository has no GGUF model file.")
            said: list[str] = []
            result = gn_bot_hf.plug(tmp, "owner/smolagent", progress=said.append)
        self.assertEqual(result["kind"], "agent")
        self.assertIn("no GGUF weights", result["fell_back"])
        self.assertTrue(any("no GGUF" in line for line in said))
        self.assertIn("no GGUF weights", "\n".join(gn_bot_hf.report_lines(result)))

    def test_model_forces_the_weights_path_and_keeps_the_refusal(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.check_public_hf_gguf.side_effect = coder.CoderError(
                "This Hugging Face repository has no GGUF model file.")
            with self.assertRaises(coder.CoderError):
                gn_bot_hf.plug(tmp, "owner/smolagent", as_model=True)
            self.assertFalse(seam.clone.clone_agent.called)

    def test_agent_forces_the_clone_path_even_for_a_weights_repo(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            result = gn_bot_hf.plug(tmp, "owner/repo-GGUF", as_agent=True)
        self.assertEqual(result["kind"], "agent")
        self.assertFalse(seam.coder.ollama_pull.called)

    def test_the_two_kind_flags_are_opposites(self) -> None:
        with TemporaryDirectory() as tmp, _Seam():
            with self.assertRaises(coder.CoderError) as caught:
                gn_bot_hf.plug(tmp, "owner/repo", as_agent=True, as_model=True)
        self.assertIn("opposites", str(caught.exception))

    def test_an_empty_reference_asks_for_one_instead_of_fetching(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            with self.assertRaises(coder.CoderError):
                gn_bot_hf.plug(tmp, "   ")
        self.assertFalse(seam.coder.check_public_hf_gguf.called)
        self.assertFalse(seam.clone.clone_agent.called)

    def test_a_name_collision_renames_rather_than_overwriting(self) -> None:
        with TemporaryDirectory() as tmp, _Seam() as seam:
            seam.coder.model_installed.side_effect = [False, True, False, True]
            first = gn_bot_hf.plug_model(tmp, "owner/repo", alias="qwen")
            second = gn_bot_hf.plug_model(tmp, "owner/repo2", alias="qwen")
        self.assertNotEqual(first["bot"], second["bot"],
                            "a second import must not silently replace the first")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
