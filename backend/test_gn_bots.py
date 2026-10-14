"""The bot registry decides what answers the operator and what plans their hunt. So the risks are:

  * **A selection that does not take effect.** This is the defect the registry exists to fix: the
    ``bot`` setting used to be displayed and ignored, so the dashboard named one brain while the
    hunt used another. ``coder_overlay`` is therefore pinned against what ``_load_coder_config``
    builds, and a selected bot must reach the hunt's config.
  * **A name that resolves to nothing, silently.** A profile may name a bot that has been deleted.
    Resolution must fall back to the local default AND say so; the writers must refuse an unknown
    name up front rather than storing it.
  * **A cloned stranger's agent becoming a brain.** ``gn bot hf`` registers a clone as ``inert``;
    nothing may turn that off, and ``coder_overlay`` must build no config for one.
  * **Leaking a key.** A bot record carries no key, and ``key_state`` reports presence only.
  * **A trained stamp nobody can reproduce.** ``mark_trained`` is the only writer of it, and it is
    called with a trainer's own result.
  * **A corrupt store stopping a hunt.** Every reader is total: a missing, malformed or
    half-refused store yields the built-ins plus a reason, never an exception.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_bots  # noqa: E402
import gn_profile  # noqa: E402


class BuiltinTests(unittest.TestCase):
    def test_a_fresh_install_has_the_shipped_bots_and_nothing_written(self) -> None:
        with TemporaryDirectory() as tmp:
            registry = gn_bots.load(tmp)
            self.assertEqual(registry.ids(), tuple(bot.id for bot in gn_bots.BUILTINS))
            self.assertFalse(registry.exists)
            self.assertFalse(gn_bots.store_path(tmp).exists(),
                             "reading must not create a store; an untouched built-in that improves "
                             "in a later version has to reach an existing install")

    def test_the_default_bot_is_local_needs_no_key_and_sends_nothing(self) -> None:
        default = gn_bots.load(TemporaryDirectory().name).get(gn_bots.DEFAULT_ID)
        self.assertIsNotNone(default)
        self.assertEqual(default.provider, "tinygpt")
        self.assertFalse(default.off_machine)
        self.assertEqual(gn_bots.coder_overlay(default, {"provider": "anthropic"}), {},
                         "the default bot means deterministic: no model, nothing sent")

    def test_no_field_can_assert_authorization(self) -> None:
        for item in gn_bots.FIELDS:
            self.assertNotIn("authoriz", item.key.lower(),
                             "a file on disk cannot assert that a human is authorized to test")
        self.assertNotIn("api_key", [item.key for item in gn_bots.FIELDS])
        self.assertNotIn("api_key", {key for bot in gn_bots.BUILTINS
                                     for key in gn_bots._to_doc(bot)},
                         "a registry that can hold a key is a registry that can leak one")

    def test_a_builtin_cannot_be_deleted_and_can_be_reset(self) -> None:
        registry = gn_bots.load("/nonexistent")
        _r, bot, error = gn_bots.delete(registry, "tinygpt")
        self.assertIsNone(bot)
        self.assertIn("built in", error)
        registry, edited, _e = gn_bots.update(registry, "local", "model", "qwen3:32b")
        self.assertEqual(edited.model, "qwen3:32b")
        registry, shipped, error = gn_bots.reset(registry, "local")
        self.assertEqual(error, "")
        self.assertEqual(shipped, gn_bots._BUILTIN_BY_ID["local"])

    def test_only_what_differs_from_a_builtin_is_written(self) -> None:
        with TemporaryDirectory() as tmp:
            registry = gn_bots.load(tmp)
            registry, _bot, _e = gn_bots.update(registry, "local", "model", "qwen3:32b")
            registry, error = gn_bots.save(tmp, registry)
            self.assertEqual(error, "")
            stored = json.loads(gn_bots.store_path(tmp).read_text(encoding="utf-8"))
            self.assertEqual([entry["id"] for entry in stored["bots"]], ["local"])
            self.assertEqual(gn_bots.load(tmp).get("local").model, "qwen3:32b")
            self.assertEqual(gn_bots.load(tmp).ids(),
                             tuple(bot.id for bot in gn_bots.BUILTINS),
                             "and the other five are still there")


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = gn_bots.load("/nonexistent/path")

    def test_create_slugs_the_name_and_keeps_what_was_typed(self) -> None:
        registry, bot, error = self.registry, None, ""
        registry, bot, error = gn_bots.create(registry, "Red Team Claude",
                                              provider="anthropic", model="claude-opus-5")
        self.assertEqual(error, "")
        self.assertEqual(bot.id, "red-team-claude")
        self.assertEqual(bot.name, "Red Team Claude")
        self.assertEqual(bot.provider, "anthropic")
        self.assertTrue(bot.created_at and bot.updated_at)

    def test_create_defaults_to_the_local_bot_not_a_hosted_one(self) -> None:
        _r, bot, _e = gn_bots.create(self.registry, "scratch")
        self.assertEqual(bot.provider, gn_bots.DEFAULT_ID)
        self.assertFalse(bot.off_machine, "one word must not create something that costs money")

    def test_a_name_that_cannot_be_an_id_is_refused(self) -> None:
        for name in ("", "   ", "!!!", "-" * 5):
            with self.subTest(name=name):
                _r, bot, error = gn_bots.create(self.registry, name)
                self.assertIsNone(bot)
                self.assertTrue(error)

    def test_a_duplicate_is_refused_and_names_the_two_ways_out(self) -> None:
        registry, _bot, _e = gn_bots.create(self.registry, "scout")
        _r, bot, error = gn_bots.create(registry, "scout")
        self.assertIsNone(bot)
        self.assertIn("clone", error)
        self.assertIn("set", error)

    def test_clone_copies_the_lessons_and_not_the_training_stamp(self) -> None:
        registry, _b, _e = gn_bots.create(self.registry, "scout", provider="anthropic")
        registry, _b, _e = gn_bots.teach(registry, "scout", "always name the endpoint")
        registry, _b, _e = gn_bots.mark_trained(registry, "scout", "hunt ranker · 40 rows")
        registry, copy, error = gn_bots.clone(registry, "scout", "scout-b")
        self.assertEqual(error, "")
        self.assertEqual(copy.lessons, ("always name the endpoint",))
        self.assertEqual(copy.trained_at, "", "a copy has not been trained — that is not its number")
        self.assertEqual(copy.train_note, "")

    def test_cloning_twice_numbers_rather_than_refusing(self) -> None:
        registry, _b, _e = gn_bots.create(self.registry, "scout")
        registry, first, _e = gn_bots.clone(registry, "scout")
        registry, second, error = gn_bots.clone(registry, "scout")
        self.assertEqual(error, "")
        self.assertNotEqual(first.id, second.id)

    def test_teach_and_forget(self) -> None:
        registry, _b, _e = gn_bots.create(self.registry, "scout")
        registry, bot, _e = gn_bots.teach(registry, "scout", "cite the endpoint")
        registry, bot, note = gn_bots.teach(registry, "scout", "cite the endpoint")
        self.assertIn("already knows", note, "a duplicate lesson is a note, not a second lesson")
        self.assertEqual(len(bot.lessons), 1)
        registry, bot, _e = gn_bots.teach(registry, "scout", "prefer read-only probes")
        self.assertEqual(len(bot.lessons), 2)
        registry, bot, _e = gn_bots.forget(registry, "scout", "1")
        self.assertEqual(bot.lessons, ("prefer read-only probes",))
        registry, bot, _e = gn_bots.forget(registry, "scout", "all")
        self.assertEqual(bot.lessons, ())
        _r, bot, error = gn_bots.forget(registry, "scout", "1")
        self.assertIsNone(bot)
        self.assertIn("not been taught", error)

    def test_lessons_are_bounded(self) -> None:
        registry, _b, _e = gn_bots.create(self.registry, "scout")
        for index in range(gn_bots.MAX_LESSONS + 10):
            registry, bot, _e = gn_bots.teach(registry, "scout", f"lesson {index}")
        self.assertEqual(len(bot.lessons), gn_bots.MAX_LESSONS)
        self.assertEqual(bot.lessons[-1], f"lesson {gn_bots.MAX_LESSONS + 9}")

    def test_a_field_this_build_does_not_know_is_refused(self) -> None:
        _r, bot, error = gn_bots.update(self.registry, "local", "authorize", "yes")
        self.assertIsNone(bot)
        self.assertIn("no bot field", error)

    def test_every_field_is_coerced_and_reports_what_it_wanted(self) -> None:
        for key, value, fragment in (("provider", "skynet", "one of"),
                                     ("temperature", "9", "0.0 and 2.0"),
                                     ("temperature", "warm", "number"),
                                     ("effort", "maximum", "one of"),
                                     ("base_url", "file:///etc", "http")):
            with self.subTest(field=key, value=value):
                _r, bot, error = gn_bots.update(self.registry, "local", key, value)
                self.assertIsNone(bot)
                self.assertIn(fragment, error)

    def test_a_control_character_cannot_reach_a_stored_field(self) -> None:
        registry, bot, error = gn_bots.update(self.registry, "local", "persona",
                                              "helpful\033[31m\nand red")
        self.assertEqual(error, "")
        self.assertNotIn("\033", bot.persona)
        self.assertNotIn("\n", bot.persona)

    def test_temperature_can_be_cleared_back_to_the_provider_default(self) -> None:
        registry, bot, _e = gn_bots.update(self.registry, "local", "temperature", "0.7")
        self.assertEqual(bot.temperature, 0.7)
        registry, bot, error = gn_bots.update(registry, "local", "temperature", "")
        self.assertEqual(error, "")
        self.assertIsNone(bot.temperature)


class FindTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = gn_bots.load("/nonexistent/path")
        registry, _b, _e = gn_bots.create(registry, "Red Team Claude", provider="anthropic")
        self.registry = registry

    def test_an_id_a_name_and_a_unique_prefix_all_find_it(self) -> None:
        for typed in ("red-team-claude", "Red Team Claude", "red", "RED-TEAM"):
            with self.subTest(typed=typed):
                bot, error = gn_bots.find(self.registry, typed)
                self.assertIsNotNone(bot, error)
                self.assertEqual(bot.id, "red-team-claude")

    def test_an_ambiguous_prefix_names_the_candidates_rather_than_picking_one(self) -> None:
        bot, error = gn_bots.find(self.registry, "o")
        self.assertIsNone(bot, "silently choosing a bot is how a prompt reaches the wrong provider")
        self.assertIn("openai", error)
        self.assertIn("offline", error)

    def test_an_unknown_name_says_how_to_list_and_how_to_make_one(self) -> None:
        bot, error = gn_bots.find(self.registry, "skynet")
        self.assertIsNone(bot)
        self.assertIn("gn bot ls", error)
        self.assertIn("gn bot new skynet", error)

    def test_an_exact_id_wins_over_a_prefix_of_another_name(self) -> None:
        registry, _b, _e = gn_bots.create(self.registry, "off-site")
        bot, error = gn_bots.find(registry, "off")
        self.assertEqual(error, "")
        self.assertEqual(bot.id, "off", "the exact id is never ambiguous")


class ResolveTests(unittest.TestCase):
    def test_a_configured_bot_that_is_gone_falls_back_and_says_so(self) -> None:
        registry = gn_bots.load("/nonexistent/path")
        bot, note = gn_bots.resolve(registry, "deleted-bot")
        self.assertEqual(bot.id, gn_bots.DEFAULT_ID)
        self.assertIn("deleted-bot", note)
        self.assertIn("not in the store", note)

    def test_nothing_configured_is_the_default_with_no_complaint(self) -> None:
        bot, note = gn_bots.resolve(gn_bots.load("/nonexistent/path"), "")
        self.assertEqual(bot.id, gn_bots.DEFAULT_ID)
        self.assertEqual(note, "")

    def test_active_reads_the_profile_and_set_active_writes_it(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertEqual(gn_bots.active(tmp)[0].id, gn_bots.DEFAULT_ID)
            registry, _bot, _e = gn_bots.create(gn_bots.load(tmp), "scout", provider="local")
            gn_bots.save(tmp, registry)
            bot, error = gn_bots.set_active(tmp, "sco")
            self.assertEqual(error, "")
            self.assertEqual(bot.id, "scout")
            self.assertEqual(gn_profile.load(tmp).get("bot"), "scout",
                             "one source of truth: the operator profile")
            self.assertEqual(gn_bots.active(tmp)[0].id, "scout")

    def test_set_active_refuses_a_bot_that_does_not_exist_and_writes_nothing(self) -> None:
        with TemporaryDirectory() as tmp:
            bot, error = gn_bots.set_active(tmp, "skynet")
            self.assertIsNone(bot)
            self.assertIn("no bot called", error)
            self.assertFalse(gn_profile.profile_path(tmp).exists())


class TotalityTests(unittest.TestCase):
    """A corrupt bot store must cost the operator their SELECTION, never their hunt."""

    def test_malformed_json_is_the_builtins_plus_a_reason(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text("{not json", encoding="utf-8")
            registry = gn_bots.load(tmp)
        self.assertEqual(registry.ids(), tuple(bot.id for bot in gn_bots.BUILTINS))
        self.assertIn("not valid JSON", registry.error)

    def test_a_refused_entry_is_reported_not_silently_dropped(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text(json.dumps({"bots": [
                {"id": "good", "provider": "local"},
                {"id": "bad", "provider": "skynet"},
                {"id": "", "provider": "local"},
                "not an object",
            ]}), encoding="utf-8")
            registry = gn_bots.load(tmp)
        self.assertIn("good", registry.ids())
        self.assertNotIn("bad", registry.ids())
        self.assertIn("bad", registry.error)
        self.assertIn("provider", registry.error,
                      "a hand-edited provider that cannot be honoured must be named, not silently "
                      "turned into the default")

    def test_a_duplicate_id_keeps_the_first_and_says_so(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text(json.dumps({"bots": [
                {"id": "twin", "provider": "local", "model": "first"},
                {"id": "twin", "provider": "local", "model": "second"},
            ]}), encoding="utf-8")
            registry = gn_bots.load(tmp)
        self.assertEqual(registry.get("twin").model, "first")
        self.assertIn("twice", registry.error)

    def test_an_unwritable_store_is_an_error_not_an_exception(self) -> None:
        registry = gn_bots.load("/nonexistent/path")
        _r, error = gn_bots.save("/nonexistent\0path", registry)
        self.assertTrue(error)

    def test_a_stored_entry_with_junk_in_a_shape_field_still_loads(self) -> None:
        """``lessons``, ``origin`` and ``source`` are shapes, not settings.

        A string where a list belongs is a broken file, not a choice the operator made, so these
        fall back quietly. The fields that carry a DECISION - provider, temperature, effort,
        base_url - are refused and reported instead; see the test below.
        """
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text(json.dumps({"bots": [
                {"id": "odd", "provider": "local", "lessons": "nope",
                 "origin": "nope", "source": "mystery"},
            ]}), encoding="utf-8")
            bot = gn_bots.load(tmp).get("odd")
        self.assertIsNotNone(bot)
        self.assertEqual(bot.lessons, ())
        self.assertEqual(bot.origin, {})
        self.assertEqual(bot.source, "operator")

    def test_a_stored_value_that_cannot_be_honoured_is_refused_and_named(self) -> None:
        for field, value in (("temperature", "hot"), ("temperature", 9.5), ("effort", "mega"),
                             ("provider", "ollama"),
                             ("base_url", "https://h/v1?api_key=sk-1")):
            with self.subTest(field=field, value=value):
                with TemporaryDirectory() as tmp:
                    gn_bots.store_path(tmp).write_text(json.dumps({"bots": [
                        {"id": "odd", "provider": "local", field: value},
                    ]}), encoding="utf-8")
                    registry = gn_bots.load(tmp)
                self.assertIsNone(registry.get("odd"),
                                  "a value quietly rewritten hides that it did not take effect")
                self.assertIn("odd", registry.error)
                self.assertNotIn("sk-1", registry.error, "and a refusal never quotes a secret")


class OverlayTests(unittest.TestCase):
    """The function that makes "change the bot" change the HUNT."""

    def setUp(self) -> None:
        self.base = {
            "enabled": False, "provider": "openai",
            "local": {"base_url": "http://127.0.0.1:11434/v1", "model": "old", "api_key": ""},
            "anthropic": {"model": "old", "api_key": "SECRET"},
        }

    def test_a_hosted_bot_sets_the_provider_the_model_and_keeps_the_key(self) -> None:
        registry, bot, _e = gn_bots.create(gn_bots.load("/nonexistent"), "scout",
                                           provider="anthropic", model="claude-opus-5")
        config = gn_bots.coder_overlay(bot, self.base)
        self.assertTrue(config["enabled"])
        self.assertEqual(config["provider"], "anthropic")
        self.assertEqual(config["anthropic"]["model"], "claude-opus-5")
        self.assertEqual(config["anthropic"]["api_key"], "SECRET",
                         "the key comes from the secrets store and must survive the overlay")

    def test_a_local_bot_carries_its_endpoint_and_sampling(self) -> None:
        registry, bot, _e = gn_bots.create(gn_bots.load("/nonexistent"), "qwen",
                                           provider="local", model="qwen3:32b",
                                           base_url="http://127.0.0.1:11500/v1")
        registry, bot, _e = gn_bots.update(registry, "qwen", "temperature", "0.4")
        config = gn_bots.coder_overlay(bot, self.base)
        self.assertEqual(config["provider"], "local")
        self.assertEqual(config["local"]["model"], "qwen3:32b")
        self.assertEqual(config["local"]["base_url"], "http://127.0.0.1:11500/v1")
        self.assertEqual(config["temperature"], 0.4)

    def test_an_on_machine_or_off_bot_is_deterministic(self) -> None:
        registry = gn_bots.load("/nonexistent")
        for name in ("tinygpt", "off"):
            with self.subTest(bot=name):
                self.assertEqual(gn_bots.coder_overlay(registry.get(name), self.base), {})

    def test_the_deterministic_coder_gets_a_config_but_no_model(self) -> None:
        config = gn_bots.coder_overlay(gn_bots.load("/nonexistent").get("offline"), self.base)
        self.assertEqual(config["provider"], "offline")
        self.assertTrue(config["enabled"])

    def test_a_persona_never_reaches_the_overlay(self) -> None:
        """A chat persona steering an engagement's probe budget is nobody's feature.

        ``hunt_brain`` overwrites ``system_prompt`` with its own, so this is belt and braces — but
        the overlay is what a future call site would reach for, and it must not carry one.
        """
        registry, bot, _e = gn_bots.create(gn_bots.load("/nonexistent"), "poet",
                                           provider="anthropic", model="claude-opus-5",
                                           persona="answer only in limericks")
        config = gn_bots.coder_overlay(bot, self.base)
        self.assertNotIn("system_prompt", config)
        self.assertNotIn("limericks", json.dumps(config))
        self.assertIn("limericks", gn_bots.system_extra(bot), "chat is where a persona belongs")

    def test_system_extra_carries_the_persona_style_and_lessons(self) -> None:
        registry, _b, _e = gn_bots.create(gn_bots.load("/nonexistent"), "scout",
                                          provider="anthropic", persona="a terse recon analyst",
                                          style="direct")
        registry, bot, _e = gn_bots.teach(registry, "scout", "always name the endpoint")
        extra = gn_bots.system_extra(bot)
        self.assertIn("a terse recon analyst", extra)
        self.assertIn("direct", extra)
        self.assertIn("always name the endpoint", extra)


class InertCloneTests(unittest.TestCase):
    def _clone(self) -> tuple[object, object]:
        registry = gn_bots.load("/nonexistent")
        bot = gn_bots.Bot(id="first-agent", provider="off", source="clone", inert=True,
                          origin={"repo": "spaces/owner/name", "revision": "abc123"})
        registry, stored, _e = gn_bots.register(registry, bot)
        return (registry, stored)

    def test_an_inert_clone_can_never_become_a_brain(self) -> None:
        registry, clone = self._clone()
        self.assertEqual(gn_bots.coder_overlay(clone, {"provider": "local"}), {})
        _r, bot, error = gn_bots.update(registry, "first-agent", "provider", "local")
        self.assertIsNone(bot, "the inert flag has to be more than advisory")
        self.assertIn("inert", error)

    def test_an_inert_clone_survives_a_save_and_reload_as_inert(self) -> None:
        with TemporaryDirectory() as tmp:
            registry, _clone = self._clone()
            gn_bots.save(tmp, registry)
            reloaded = gn_bots.load(tmp).get("first-agent")
        self.assertTrue(reloaded.inert)
        self.assertEqual(reloaded.source, "clone")
        self.assertEqual(reloaded.origin["repo"], "spaces/owner/name")

    def test_a_listing_says_inert_on_the_row(self) -> None:
        registry, _clone = self._clone()
        text = "\n".join(gn_bots.list_lines(registry, "tinygpt", None))
        self.assertIn("first-agent", text)
        self.assertIn("inert", text,
                      "a clone that looks runnable is the one misreading an operator could make")

    def test_there_is_nothing_to_train_on_a_clone(self) -> None:
        _registry, clone = self._clone()
        kind, why = gn_bots.trainer_for(clone)
        self.assertEqual(kind, "")
        self.assertIn("inert", why)


class ReadinessTests(unittest.TestCase):
    def test_a_hosted_bot_without_a_key_is_not_ready_and_the_key_is_never_shown(self) -> None:
        with TemporaryDirectory() as tmp:
            bot = gn_bots.load(tmp).get("anthropic")
            self.assertEqual(gn_bots.key_state(tmp, bot), "none")
            self.assertEqual(gn_bots.readiness(tmp, bot), "needs a key")
            Path(tmp, "secrets.json").write_text(json.dumps({"anthropic": "sk-SECRET"}),
                                                 encoding="utf-8")
            self.assertEqual(gn_bots.key_state(tmp, bot), "configured")
            self.assertEqual(gn_bots.readiness(tmp, bot), "ready")
            rendered = "\n".join(gn_bots.show_lines(bot, tmp) + gn_bots.list_lines(
                gn_bots.load(tmp), "anthropic", tmp))
            self.assertNotIn("SECRET", rendered)

    def test_a_local_bot_needs_no_key_and_a_model_is_required(self) -> None:
        with TemporaryDirectory() as tmp:
            registry, bot, _e = gn_bots.create(gn_bots.load(tmp), "bare", provider="local")
            self.assertEqual(gn_bots.key_state(tmp, bot), "not needed")
            self.assertEqual(gn_bots.readiness(tmp, bot), "needs a model")

    def test_off_machine_is_true_for_hosted_and_for_a_remote_ollama_only(self) -> None:
        registry = gn_bots.load("/nonexistent")
        self.assertTrue(registry.get("anthropic").off_machine)
        self.assertTrue(registry.get("openai").off_machine)
        self.assertFalse(registry.get("local").off_machine, "the shipped local is loopback")
        self.assertFalse(registry.get("tinygpt").off_machine)
        registry, remote, _e = gn_bots.create(registry, "remote", provider="local",
                                              model="qwen", base_url="http://10.1.2.3:11434/v1")
        self.assertTrue(remote.off_machine, "an Ollama on another host is off this machine")
        registry, host, _e = gn_bots.create(registry, "lan", provider="local",
                                            model="qwen", base_url="http://localhost:11434/v1")
        self.assertFalse(host.off_machine)


class TrainerTests(unittest.TestCase):
    def test_each_bot_names_the_trainer_it_actually_has(self) -> None:
        registry = gn_bots.load("/nonexistent")
        self.assertEqual(gn_bots.trainer_for(registry.get("tinygpt"))[0], "tiny")
        self.assertEqual(gn_bots.trainer_for(registry.get("anthropic"))[0], "hunt")
        self.assertEqual(gn_bots.trainer_for(registry.get("local"))[0], "hunt")
        self.assertEqual(gn_bots.trainer_for(registry.get("off"))[0], "")

    def test_a_trained_stamp_is_only_ever_written_with_a_run_behind_it(self) -> None:
        source = Path(BACKEND_DIR, "gn_bots.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("trained_at=_now()"), 1,
                         "mark_trained is the only writer; a stamp no run produced is exactly the "
                         "unreproducible number this program's house rule forbids")
        registry, bot, _e = gn_bots.mark_trained(gn_bots.load("/nonexistent"), "local",
                                                 "hunt ranker · 40 rows")
        self.assertTrue(bot.trained_at)
        self.assertIn("40 rows", bot.train_note)


class CliReadVersusWriteTests(unittest.TestCase):
    """`gn bot set <bot> <field>` with no value READS the field; it must not blank it.

    An empty string coerces cleanly for every text field, so an argparse default of "" made a read
    and an explicit clear the same argv — and the read won the operator's model setting.
    """

    def test_the_value_argument_has_no_empty_string_default(self) -> None:
        import argparse

        parser = argparse.ArgumentParser()
        gn_bots.register_cli(parser.add_subparsers())
        args = parser.parse_args(["bot", "set", "scout", "model"])
        self.assertIsNone(args.value, "omitted and cleared must be distinguishable")
        args = parser.parse_args(["bot", "set", "scout", "model", ""])
        self.assertEqual(args.value, "")


class RenderingTests(unittest.TestCase):
    def test_the_live_bot_is_marked_and_the_mark_is_explained(self) -> None:
        lines = gn_bots.list_lines(gn_bots.load("/nonexistent"), "local", None)
        marked = [line for line in lines if line.strip().startswith("*")]
        self.assertEqual(len(marked), 2, "one row, plus the line that explains the mark")
        self.assertIn("local", marked[0])
        self.assertIn("live", marked[1])

    def test_a_narrow_listing_is_compact_rather_than_wrapped(self) -> None:
        registry = gn_bots.load("/nonexistent")
        wide = gn_bots.list_lines(registry, "local", None)
        narrow = gn_bots.list_lines(registry, "local", None, width=40)
        self.assertLessEqual(max(len(line) for line in narrow), 40,
                             "the studio's chat pane cannot fold a table and still be one")
        self.assertGreater(max(len(line) for line in wide), max(len(line) for line in narrow))

    def test_show_lines_say_what_a_bot_is_and_what_it_was_taught(self) -> None:
        registry, _b, _e = gn_bots.create(gn_bots.load("/nonexistent"), "scout",
                                          provider="anthropic", model="claude-opus-5")
        registry, bot, _e = gn_bots.teach(registry, "scout", "cite the endpoint")
        text = "\n".join(gn_bots.show_lines(bot, None))
        self.assertIn("claude-opus-5", text)
        self.assertIn("cite the endpoint", text)
        self.assertIn("never", text, "an untrained bot says so rather than showing a blank")

    def test_the_fields_listing_says_keys_are_not_a_field(self) -> None:
        text = "\n".join(gn_bots.fields_lines())
        for item in gn_bots.FIELDS:
            self.assertIn(item.key, text)
        self.assertIn("secrets store", text)
        self.assertIn("authorization", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
