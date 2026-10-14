"""Full control over the bots, from the view the operator is looking at them in.

Every verb here is the same operation ``gn bot ...`` performs — one store, one set of rules, two
doors — so the rules themselves are pinned in ``test_gn_bots``. These tests are about the half the
studio owns:

  * **Which bot an argument-light command means.** ``/model x`` acts on the live bot, ``/bot set
    scout model x`` on a named one, and ``/bot rm`` with no name refuses rather than guessing.
  * **That a refusal reaches the operator** on the footer, with nothing written, instead of a
    traceback into the frame.
  * **That the panels show the change immediately.** A studio reporting a saved thing while
    displaying the old one is worse than one that reports nothing.
  * **Who answers a typed question, and whether you can tell afterwards.** The studio used to
    display a configured brain and never call it; it calls the LIVE bot now, so the invariants
    moved: nothing on the REPAINT path may call a model, a model's answer must be labelled as one,
    and an off-machine bot must announce itself before the first answer comes back.
  * **That a trained stamp needs a real run behind it** — a refused gate leaves none.
"""
from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_bots  # noqa: E402
import gn_profile  # noqa: E402
import gn_studio  # noqa: E402
import gn_tui  # noqa: E402

SEED = BACKEND_DIR / "seed"
NEWLINE = chr(10)


def _tier() -> dict:
    class _Stream(io.StringIO):
        encoding = "utf-8"

        def isatty(self) -> bool:
            return True

    return gn_tui.tier(_Stream())


class _StudioCase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = TemporaryDirectory()
        self.tmp = self._dir.name
        self.addCleanup(self._dir.cleanup)
        self.studio = gn_studio.Studio(runtime_dir=self.tmp, seed_dir=SEED,
                                       stream=io.StringIO(), size=(100, 26))

    def said(self) -> str:
        return NEWLINE.join(text for _who, text in self.studio.snapshot().chat)

    def bots(self) -> str:
        return NEWLINE.join(f"{row.label}={row.value}" for row in self.studio.snapshot().bots)

    def brain(self) -> str:
        return NEWLINE.join(f"{row.label}={row.value}" for row in self.studio.snapshot().brain)


class BotCommandTests(_StudioCase):
    def test_new_use_and_the_panel_marks_the_live_one(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.assertIn("created scout", self.said())
        self.assertIn("scout", gn_bots.load(self.tmp).ids())
        self.studio.submit("/use scout")
        self.assertEqual(gn_profile.load(self.tmp).get("bot"), "scout")
        self.assertEqual(self.studio.snapshot().bots[0].label, "*scout",
                         "the live bot is marked, and first: it must not move down the panel as "
                         "bots are added")
        self.assertEqual(self.studio.snapshot().bot, "scout", "and the header names it")

    def test_a_prefix_is_enough_to_switch(self) -> None:
        self.studio.submit("/new scoutmaster local qwen3:32b")
        self.studio.submit("/use scoutm")
        self.assertEqual(gn_profile.load(self.tmp).get("bot"), "scoutmaster")

    def test_an_ambiguous_prefix_refuses_and_names_the_candidates(self) -> None:
        self.studio.submit("/use o")
        self.assertIn("openai", self.studio.snapshot().message)
        self.assertIn("offline", self.studio.snapshot().message)
        self.assertEqual(gn_profile.load(self.tmp).get("bot"), "tinygpt", "nothing switched")

    def test_field_setters_without_a_name_act_on_the_live_bot(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        self.studio.submit("/model qwen3:14b")
        self.studio.submit("/persona a terse recon analyst")
        self.studio.submit("/style direct")
        bot = gn_bots.load(self.tmp).get("scout")
        self.assertEqual(bot.model, "qwen3:14b")
        self.assertEqual(bot.persona, "a terse recon analyst")
        self.assertEqual(bot.style, "direct")

    def test_a_bare_field_setter_reads_the_field_instead_of_blanking_it(self) -> None:
        """`/model` with nothing after it must not wipe the model it was about to show."""
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        self.studio.submit("/model")
        self.assertEqual(gn_bots.load(self.tmp).get("scout").model, "qwen3:32b")
        self.assertIn("scout.model = qwen3:32b", self.said())
        self.studio.submit("/bot set scout persona")
        self.assertIn("scout.persona = (blank)", self.said())

    def test_clearing_a_field_is_still_possible_and_explicit(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit('/bot set scout model ""')
        self.assertEqual(gn_bots.load(self.tmp).get("scout").model, "")

    def test_a_named_bot_wins_over_the_live_one(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/bot set scout model qwen3:8b")
        self.assertEqual(gn_bots.load(self.tmp).get("scout").model, "qwen3:8b")
        self.assertEqual(gn_profile.load(self.tmp).get("bot"), "tinygpt",
                         "editing a bot is not selecting it")

    def test_teach_and_forget_reach_the_store(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        self.studio.submit('/teach "always name the endpoint you probed"')
        self.assertEqual(gn_bots.load(self.tmp).get("scout").lessons,
                         ("always name the endpoint you probed",))
        self.studio.submit("/bot forget scout all")
        self.assertEqual(gn_bots.load(self.tmp).get("scout").lessons, ())

    def test_clone_then_delete_leaves_something_answering(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/clone scout as scout-b")
        self.assertIn("scout-b", gn_bots.load(self.tmp).ids())
        self.studio.submit("/use scout-b")
        self.studio.submit("/bot rm scout-b -y")
        self.assertNotIn("scout-b", gn_bots.load(self.tmp).ids())
        self.assertEqual(gn_profile.load(self.tmp).get("bot"), gn_bots.DEFAULT_ID,
                         "deleting the live bot must leave something answering")
        self.assertIn("tinygpt is now", self.said())

    def test_deleting_a_bot_needs_the_same_confirmation_the_cli_asks_for(self) -> None:
        """A bot's lessons are the operator's own prose and there is no undo."""
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit('/teach "cite the endpoint"')
        self.studio.submit("/bot rm scout")
        self.assertIn("scout", gn_bots.load(self.tmp).ids(), "unconfirmed, nothing is deleted")
        self.assertIn("no undo", self.said())
        self.assertIn("1 lesson", self.said(), "and it says what goes with it")
        self.studio.submit("/bot rm scout -y")
        self.assertNotIn("scout", gn_bots.load(self.tmp).ids())

    def test_a_builtin_cannot_be_deleted_from_here_either(self) -> None:
        self.studio.submit("/bot rm tinygpt -y")
        self.assertIn("built in", self.studio.snapshot().message)
        self.assertIn("tinygpt", gn_bots.load(self.tmp).ids())

    def test_every_refusal_lands_on_the_footer_and_nothing_is_written(self) -> None:
        for line in ("/new", "/use", "/use skynet", "/bot set tinygpt nonsense x",
                     "/bot set tinygpt temperature warm", "/bot forget tinygpt 4",
                     "/bot rm", "/bot reset scout", "/teach", "/bot nonsense",
                     "/new !!!", "/clone skynet"):
            with self.subTest(line=line):
                self.studio.note("")
                self.studio.submit(line)
                self.assertTrue(self.studio.snapshot().message, f"{line} said nothing")
        self.assertEqual(gn_bots.load(self.tmp).ids(),
                         tuple(bot.id for bot in gn_bots.BUILTINS))
        self.assertFalse(gn_profile.profile_path(self.tmp).exists())

    def test_the_listing_and_show_go_into_the_transcript(self) -> None:
        self.studio.submit("/new scout anthropic claude-opus-5")
        self.studio.submit("/bots")
        self.assertIn("scout", self.said())
        self.studio.submit("/bot show scout")
        self.assertIn("claude-opus-5", self.said())
        self.assertIn("needs a key", self.said(), "and it says what is missing")

    def test_show_with_no_name_is_the_live_bot(self) -> None:
        self.studio.submit("/bot show")
        self.assertIn("tinygpt", self.said())

    def test_the_fields_listing_is_reachable_from_here(self) -> None:
        self.studio.submit("/bot fields")
        self.assertIn("persona", self.said())
        self.assertIn("secrets store", self.said(), "and it says keys are not a field")

    def test_a_typo_on_a_name_only_verb_refuses_instead_of_acting_on_the_live_bot(self) -> None:
        """`/train scoutt` must not quietly train something else and report success for it."""
        self.studio.submit("/new scout local qwen3:32b")
        for line in ("/train scoutt", "/bot show scoutt", "/clone scoutt", "/bot reset scoutt"):
            with self.subTest(line=line):
                self.studio.note("")
                before = self.said()
                self.studio.submit(line)
                self.assertIn("no bot called", self.studio.snapshot().message)
                self.assertEqual(self.said(), before, "and it did not act on anything")

    def test_a_field_verb_still_falls_back_to_the_live_bot(self) -> None:
        # /bot set model x and /bot teach "..." mean the bot the operator is looking at.
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        self.studio.submit("/bot set model qwen3:8b")
        self.assertEqual(gn_bots.load(self.tmp).get("scout").model, "qwen3:8b")
        self.studio.submit("/bot teach cite the endpoint")
        self.assertEqual(gn_bots.load(self.tmp).get("scout").lessons, ("cite the endpoint",))

    def test_a_bot_the_profile_names_but_the_store_lost_is_reported(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        gn_bots.store_path(self.tmp).unlink()
        self.studio.refresh()
        self.assertIn("not in the store", self.brain())
        self.assertIn("tinygpt", self.brain(), "and it names what answers instead")


class TrainFromTheStudioTests(_StudioCase):
    def test_a_bot_with_nothing_to_train_says_so_without_running(self) -> None:
        self.studio.submit("/use off")
        self.studio.submit("/train")
        self.assertIn("nothing answers", self.said())

    def test_tinygpt_names_the_verb_rather_than_starting_torch_from_a_dashboard(self) -> None:
        self.studio.submit("/train tinygpt")
        self.assertIn("gn train-coder", self.said())

    def _fake_hunt_train(self, result: dict) -> mock._patch:
        fake = mock.MagicMock()
        fake.train.return_value = result
        return mock.patch.dict(sys.modules, {
            "bughunter": mock.MagicMock(hunt_train=fake),
            "bughunter.hunt_train": fake,
        })

    def test_training_records_only_what_the_run_produced(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        with self._fake_hunt_train({"ok": True, "rows": 42, "programs": 3}):
            self.studio.submit("/train")
        self.assertIn("trained scout", self.said())
        self.assertIn("42 rows", self.said())
        stored = gn_bots.load(self.tmp).get("scout")
        self.assertTrue(stored.trained_at)
        self.assertIn("42 rows", stored.train_note)

    def test_a_refused_gate_is_reported_as_the_gate_and_leaves_no_stamp(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        with self._fake_hunt_train({"ok": False, "reason": "19 rows; 40 needed"}):
            self.studio.submit("/train")
        self.assertIn("not trained: 19 rows; 40 needed", self.said())
        self.assertFalse(gn_bots.load(self.tmp).get("scout").trained_at,
                         "a refusal must not leave a trained stamp behind")

    def test_a_trainer_that_raises_is_a_sentence_not_a_traceback(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        fake = mock.MagicMock()
        fake.train.side_effect = RuntimeError("no corpus")
        with mock.patch.dict(sys.modules, {"bughunter": mock.MagicMock(hunt_train=fake),
                                           "bughunter.hunt_train": fake}):
            self.studio.submit("/train")
        self.assertIn("would not run", self.said())


class CompletionTests(_StudioCase):
    def test_tab_completes_the_command_the_verb_and_the_bot_name(self) -> None:
        self.studio.submit("/new scoutmaster local qwen3:32b")
        for typed, expected in (("/bot", "/bot"), ("/bots", "/bots "),
                                ("/bot u", "/bot use "),
                                ("/us", "/use "),
                                ("/use scou", "/use scoutmaster "),
                                ("/bot show scou", "/bot show scoutmaster ")):
            with self.subTest(typed=typed):
                self.studio._line.set(typed)
                self.studio.handle_key("TAB")
                self.assertEqual(self.studio._line.text, expected)

    def test_an_ambiguous_name_advances_to_the_common_prefix_and_lists(self) -> None:
        # What every shell does: two bots sharing a prefix advance the line as far as they agree
        # and then name themselves, rather than appearing to do nothing.
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/new scoutmaster local qwen3:32b")
        self.studio._line.set("/use sc")
        self.studio.handle_key("TAB")
        self.assertEqual(self.studio._line.text, "/use scout")
        said = self.studio.snapshot().message
        self.assertIn("scoutmaster", said)
        self.assertIn("scout", said)

    def test_tab_with_several_matches_lists_them_and_changes_nothing(self) -> None:
        self.studio._line.set("/use o")
        self.studio.handle_key("TAB")
        self.assertEqual(self.studio._line.text, "/use o")
        self.assertIn("openai", self.studio.snapshot().message)

    def test_tab_on_a_question_leaves_it_alone(self) -> None:
        self.studio._line.set("what is ssrf")
        self.studio.handle_key("TAB")
        self.assertEqual(self.studio._line.text, "what is ssrf")

    def test_every_completable_command_is_a_command_the_parser_knows(self) -> None:
        for name in gn_studio.commands():
            with self.subTest(command=name):
                parsed = gn_studio.parse_studio_command("/" + name)
                # A command that needs an argument still refuses without one; what must never
                # happen is "not a studio command" for something Tab just offered.
                self.assertNotIn("not a studio command", str(parsed.get("message") or ""),
                                 f"/{name} completes but the parser does not know it")


class ChatRoutingTests(_StudioCase):
    def test_a_local_bot_answers_from_the_pack_with_its_source(self) -> None:
        self.studio.submit("what is ssrf")
        said = self.said()
        self.assertIn("Server-side request forgery", said)
        self.assertIn("VULN_CLASSES", said, "quoted, with the card it was quoted from")

    def test_an_off_bot_answers_nothing_and_says_how_to_fix_that(self) -> None:
        self.studio.submit("/use off")
        self.studio.submit("what is ssrf")
        self.assertIn("nothing answers", self.said())
        self.assertIn("/use tinygpt", self.said())

    def test_pack_asks_the_pack_whichever_bot_is_live(self) -> None:
        self.studio.submit("/use off")
        self.studio.submit("/pack what is ssrf")
        self.assertIn("Server-side request forgery", self.said())

    def _fake_coder(self, **kwargs: object) -> tuple[mock._patch, mock.MagicMock]:
        fake = mock.MagicMock()
        for key, value in kwargs.items():
            setattr(fake.generate, key, value)
        return (mock.patch.dict(sys.modules, {"coder": fake}), fake)

    def test_a_model_bot_is_called_and_its_answer_is_labelled_as_a_models(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        patch, fake = self._fake_coder(return_value={"text": "Probe the webhook parameter.",
                                                     "model": "qwen3:32b", "provider": "local"})
        with patch:
            self.studio.submit("how should I test this webhook")
        said = self.said()
        self.assertIn("Probe the webhook parameter.", said)
        self.assertIn("a model's words, not the offline pack", said)
        self.assertIn("scout", said)
        config = fake.generate.call_args[0][1]
        self.assertEqual(config["provider"], "local")
        self.assertEqual(config["local"]["model"], "qwen3:32b")
        self.assertIn("reproduc", config["system_prompt"],
                      "the studio's own instruction about evidence goes to every model bot")

    def test_a_persona_and_its_lessons_reach_the_models_system_prompt(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        self.studio.submit("/persona a terse recon analyst")
        self.studio.submit('/teach "always name the endpoint you probed"')
        patch, fake = self._fake_coder(return_value={"text": "ok", "model": "qwen3:32b"})
        with patch:
            self.studio.submit("where do I start")
        prompt = fake.generate.call_args[0][1]["system_prompt"]
        self.assertIn("a terse recon analyst", prompt)
        self.assertIn("always name the endpoint you probed", prompt)

    def test_a_failed_model_call_says_so_and_falls_back_to_the_pack(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        patch, _fake = self._fake_coder(side_effect=RuntimeError("Ollama is not running"))
        with patch:
            self.studio.submit("what is ssrf")
        said = self.said()
        self.assertIn("Ollama is not running", said)
        self.assertIn("Server-side request forgery", said, "the pack still answers")
        self.assertIn("after scout failed", said, "and the label says which answered")

    def test_an_answer_that_comes_back_empty_is_not_reported_as_no_match(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        patch, _fake = self._fake_coder(return_value={"text": "", "model": "qwen3:32b"})
        with patch:
            self.studio.submit("anything")
        self.assertIn("returned nothing", self.said(),
                      "'the pack had no card' and 'the model said nothing' are different events")

    def test_a_models_answer_keeps_its_paragraphs_and_loses_its_escapes(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        patch, _fake = self._fake_coder(return_value={
            "text": "first\n\nsecond\033[31m line", "model": "qwen3:32b"})
        with patch:
            self.studio.submit("anything")
        said = self.said()
        self.assertIn("first", said)
        self.assertIn(NEWLINE, said, "an explanation is paragraphs, not a wall")
        self.assertNotIn("\033", said)
        frame = NEWLINE.join(gn_studio.render(self.studio.snapshot(), gn_tui.Size(100, 26),
                                              _tier()))
        self.assertNotIn("\033", frame)

    def test_a_model_bot_is_asked_with_the_conversation_so_far(self) -> None:
        """A chat window that forgets the previous turn is not a chat window."""
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        patch, fake = self._fake_coder(return_value={"text": "the webhook one", "model": "q"})
        with patch:
            self.studio.submit("which parameter first")
            self.studio.submit("and after that")
        messages = fake.generate.call_args[0][0]
        self.assertEqual([m["role"] for m in messages], ["user", "assistant", "user"])
        self.assertEqual(messages[0]["content"], "which parameter first")
        self.assertEqual(messages[1]["content"], "the webhook one")
        self.assertEqual(messages[2]["content"], "and after that")

    def test_switching_bots_starts_a_new_conversation(self) -> None:
        self.studio.submit("/new a local qwen3:32b")
        self.studio.submit("/new b local qwen3:32b")
        self.studio.submit("/use a")
        patch, fake = self._fake_coder(return_value={"text": "a said this", "model": "q"})
        with patch:
            self.studio.submit("first")
            self.studio.submit("/use b")
            self.studio.submit("second")
        messages = fake.generate.call_args[0][0]
        self.assertEqual([m["content"] for m in messages], ["second"],
                         "handing one model another's words back as its own is a lie that "
                         "produces strange answers")

    def test_the_pack_never_enters_a_models_context(self) -> None:
        self.studio.submit("what is ssrf")          # answered by the pack, on tinygpt
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        patch, fake = self._fake_coder(return_value={"text": "ok", "model": "q"})
        with patch:
            self.studio.submit("now you")
        messages = fake.generate.call_args[0][0]
        self.assertEqual([m["content"] for m in messages], ["now you"])

    def test_clear_takes_the_conversation_with_it(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        patch, fake = self._fake_coder(return_value={"text": "remembered", "model": "q"})
        with patch:
            self.studio.submit("first")
            self.studio.submit("/clear")
            self.studio.submit("second")
        messages = fake.generate.call_args[0][0]
        self.assertEqual([m["content"] for m in messages], ["second"],
                         "a cleared screen that the bot still remembers would mislead about what "
                         "it knows")

    def test_the_conversation_is_bounded_and_never_cut_mid_pair(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        patch, fake = self._fake_coder(return_value={"text": "ok", "model": "q"})
        with patch:
            for index in range(40):
                self.studio.submit(f"question {index}")
        messages = fake.generate.call_args[0][0]
        self.assertLessEqual(len(messages), 25)
        self.assertEqual(messages[0]["role"], "user", "a dangling user turn is rejected outright "
                                                      "by some providers")

    def test_an_off_machine_bot_announces_itself_once_before_the_first_answer(self) -> None:
        self.studio.submit("/new scout anthropic claude-opus-5")
        self.studio.submit("/use scout")
        self.assertTrue(self.studio.snapshot().off_machine)
        patch, _fake = self._fake_coder(return_value={"text": "ok", "model": "claude-opus-5"})
        with patch:
            self.studio.submit("first question")
            self.studio.submit("second question")
        said = self.said()
        self.assertIn("off this machine", said)
        self.assertEqual(said.count("keeps everything local"), 1,
                         "once per session: a warning on every turn is one nobody reads")

    def test_the_header_marks_an_off_machine_bot(self) -> None:
        self.studio.submit("/new scout anthropic claude-opus-5")
        self.studio.submit("/use scout")
        frame = NEWLINE.join(gn_studio.render(self.studio.snapshot(), gn_tui.Size(100, 26),
                                              _tier()))
        self.assertIn("bot scout->net", frame)

    def test_a_local_bot_is_not_marked_as_leaving_the_machine(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        self.assertFalse(self.studio.snapshot().off_machine)
        frame = NEWLINE.join(gn_studio.render(self.studio.snapshot(), gn_tui.Size(100, 26),
                                              _tier()))
        self.assertIn("bot scout ", frame)
        self.assertNotIn("->net", frame)

    def test_nothing_on_the_repaint_path_can_call_a_model(self) -> None:
        """The rule that survives: opening the studio spends no budget and stalls no frame.

        ``collect`` and ``render`` are what a repaint runs, and a model call from either would be a
        network round trip inside the frame loop. Driven with ``coder`` replaced by something that
        fails if it is touched at all.
        """
        self.studio.submit("/new scout anthropic claude-opus-5")
        self.studio.submit("/use scout")
        exploding = mock.MagicMock()
        exploding.generate.side_effect = AssertionError("a repaint called a model")
        with mock.patch.dict(sys.modules, {"coder": exploding}):
            for _ in range(3):
                self.studio.refresh()
                gn_studio.render(self.studio.snapshot(), gn_tui.Size(100, 26), _tier())
            gn_studio.collect(self.tmp, SEED, gn_profile.load(self.tmp))
            self.studio.submit("/bots")
            self.studio.submit("/bot show scout")
            self.studio.submit("/refresh")
        exploding.generate.assert_not_called()


class HuggingFaceFromTheStudioTests(_StudioCase):
    def test_hf_with_no_reference_explains_both_kinds_without_touching_the_network(self) -> None:
        exploding = mock.MagicMock()
        exploding.plug.side_effect = AssertionError("a help message fetched something")
        with mock.patch.dict(sys.modules, {"gn_bot_hf": exploding}):
            self.studio.submit("/hf")
        said = self.said().lower()
        self.assertIn("gguf", said)
        self.assertIn("inert", said)
        exploding.plug.assert_not_called()

    def test_a_model_that_lands_is_registered_and_reported(self) -> None:
        fake = mock.MagicMock()
        fake.plug.return_value = {"kind": "model", "bot": "qwen2.5-coder",
                                  "model": "hf.co/u/r:Q4_K_M", "chat_ready": True,
                                  "tool_ready": True, "runnable": True}
        fake.report_lines.side_effect = lambda result: ["plugged in " + result["bot"]]
        with mock.patch.dict(sys.modules, {"gn_bot_hf": fake}):
            self.studio.submit("/hf unsloth/Qwen2.5-Coder-GGUF as qwen")
        self.assertIn("plugged in qwen2.5-coder", self.said())
        self.assertEqual(fake.plug.call_args.kwargs["alias"], "qwen")

    def test_the_kind_flags_are_passed_through(self) -> None:
        fake = mock.MagicMock()
        fake.plug.return_value = {"kind": "agent", "bot": "a", "runnable": False}
        fake.report_lines.return_value = ["cloned a"]
        with mock.patch.dict(sys.modules, {"gn_bot_hf": fake}):
            self.studio.submit("/hf owner/repo --agent")
        self.assertTrue(fake.plug.call_args.kwargs["as_agent"])
        self.assertFalse(fake.plug.call_args.kwargs["as_model"])

    def test_a_refusal_from_the_hub_is_a_sentence_not_a_traceback(self) -> None:
        fake = mock.MagicMock()
        fake.plug.side_effect = RuntimeError("This Hugging Face model is private or gated.")
        with mock.patch.dict(sys.modules, {"gn_bot_hf": fake}):
            self.studio.submit("/hf owner/private")
        self.assertIn("private or gated", self.said())

    def test_progress_reaches_the_footer_while_it_runs(self) -> None:
        seen: list[str] = []

        def plug(_runtime: object, reference: str, **kwargs: object) -> dict:
            progress = kwargs["progress"]
            progress("downloading the weights 40%")
            seen.append(self.studio.snapshot().busy)
            return {"kind": "model", "bot": "x", "runnable": False}

        fake = mock.MagicMock()
        fake.plug.side_effect = plug
        fake.report_lines.return_value = ["done"]
        with mock.patch.dict(sys.modules, {"gn_bot_hf": fake}):
            self.studio.submit("/hf owner/repo")
        self.assertTrue(seen and "40%" in seen[0],
                        "a studio frozen mid-download looks broken; the footer has to say what "
                        "it is doing")
        self.assertEqual(self.studio.snapshot().busy, "", "and it clears when the job ends")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
