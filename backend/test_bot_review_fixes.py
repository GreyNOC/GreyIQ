"""Regressions for the sixteen defects the adversarial review of the bot work turned up.

One test per finding, each driving the input that produced the wrong behaviour. They live together
because they are one review's output and because the pattern repeats: almost every one of them was
a surface telling the operator something that was not true — a store that reported a bad entry and
then deleted it, a header that said the prompt stayed local while it left, a sentence claiming a
bot answers chat when nothing does.

THE REGISTRY (`gn_bots`, `gn_cli`)
  1. A refused entry survived a mutation; an unparseable store was never overwritten.
  2. Id numbering stopped collapsing, so `register` can no longer replace an existing bot.
  3. `gn setup` stores the RESOLVED bot id, not the prefix that was typed.
  4. A non-UTF-8 or absurdly nested store is a reason, not an exception.
  5. The temporary file is uniquely named.
  6. An endpoint cannot carry a credential.
  7. An exact display-name match is ambiguity-checked.
  8. A stored temperature or effort this build cannot honour is reported, not rewritten.

THE STUDIO (`gn_studio`)
  1. A `local` bot that inherits a non-loopback endpoint is marked off-machine.
  2. C1 control characters cannot reach a rendered frame.
  3. `/hf` with only flags is a sentence, not an IndexError.
  4. The BRAIN key row reads the store the key is actually in.
  5. `/use` describes what the bot it just made live actually does.
  6. `/teach <lesson>` cannot have its first word eaten as a bot name.
  7. The off-machine marker survives the narrowest supported terminal.
  8. A truncated answer says it was truncated, and the model is not fed its own truncation.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
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


class StoreNeverLosesBotsTests(unittest.TestCase):
    """Reading is lossy and ``save`` rewrites the whole file, so the two must not compose."""

    def test_an_entry_this_build_refuses_survives_a_mutation(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text(json.dumps({"bots": [
                {"id": "planner", "provider": "anthropic", "model": "claude-opus-5",
                 "persona": "mine", "lessons": ["cite the trace id"]},
                {"id": "qwen", "provider": "ollama", "model": "qwen3:32b"},
            ]}), encoding="utf-8")
            registry = gn_bots.load(tmp)
            self.assertIn("qwen", registry.error, "the refusal is still reported")
            registry, bot, error = gn_bots.create(registry, "scratch")
            self.assertEqual(error, "")
            _r, error = gn_bots.save(tmp, registry)
            self.assertEqual(error, "")
            written = json.loads(gn_bots.store_path(tmp).read_text(encoding="utf-8"))
        ids = [entry.get("id") for entry in written["bots"]]
        self.assertIn("qwen", ids, "the command that reported the bad entry used to delete it")
        self.assertIn("planner", ids)
        self.assertIn("scratch", ids)

    def test_a_store_that_cannot_be_parsed_is_never_replaced(self) -> None:
        broken = '{"bots":[{"id":"a","provider":"local"},]}'
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text(broken, encoding="utf-8")
            registry = gn_bots.load(tmp)
            self.assertFalse(registry.readable)
            registry, bot, _e = gn_bots.create(registry, "other")
            _r, error = gn_bots.save(tmp, registry)
            self.assertTrue(error, "one trailing comma used to cost every bot in the file")
            self.assertIn("nothing was changed", error)
            self.assertEqual(gn_bots.store_path(tmp).read_text(encoding="utf-8"), broken)

    def test_creating_over_a_refused_entrys_id_is_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text(json.dumps({"bots": [
                {"id": "qwen", "provider": "ollama"}]}), encoding="utf-8")
            registry = gn_bots.load(tmp)
        _r, bot, error = gn_bots.create(registry, "qwen")
        self.assertIsNone(bot, "it would put the same id in the file twice")
        self.assertIn("already exists", error)

    def test_a_normal_store_still_round_trips(self) -> None:
        with TemporaryDirectory() as tmp:
            registry, _b, _e = gn_bots.create(gn_bots.load(tmp), "scout", provider="local",
                                              model="qwen3:32b")
            _r, error = gn_bots.save(tmp, registry)
            self.assertEqual(error, "")
            self.assertEqual(gn_bots.load(tmp).get("scout").model, "qwen3:32b")


class IdNumberingTests(unittest.TestCase):
    #: What ``gn bot hf bartowski/Meta-Llama-3.1-8B-Instruct-GGUF`` derives: 31 characters, one
    #: short of the limit, so every numbered variant used to truncate back to the base.
    LONG = "meta-llama-3.1-8b-instruct-gguf"

    def test_register_renames_instead_of_replacing_an_existing_bot(self) -> None:
        registry, mine, _e = gn_bots.create(gn_bots.load("/nonexistent"), self.LONG,
                                            provider="local", model="m")
        registry, mine, _e = gn_bots.teach(registry, self.LONG, "my own lesson")
        before = len(registry.bots)
        clone = gn_bots.Bot(id=self.LONG, provider="off", inert=True, source="clone")
        registry, stored, error = gn_bots.register(registry, clone)
        self.assertEqual(error, "")
        self.assertIsNotNone(stored)
        self.assertNotEqual(stored.id, self.LONG, "an inert clone must not land on its name")
        self.assertEqual(len(registry.bots), before + 1)
        survivor = registry.get(self.LONG)
        self.assertFalse(survivor.inert, "the operator's bot is still theirs")
        self.assertEqual(survivor.lessons, ("my own lesson",))

    def test_register_refuses_when_every_name_is_taken(self) -> None:
        registry = gn_bots.load("/nonexistent")
        registry, _b, _e = gn_bots.create(registry, "x")
        for index in range(2, 100):
            registry, _b, _e = gn_bots.create(registry, gn_bots._numbered("x", index))
        _r, stored, error = gn_bots.register(registry, gn_bots.Bot(id="x", provider="local"))
        self.assertIsNone(stored, "falling through used to overwrite")
        self.assertIn("already exist", error)

    def test_clone_of_a_long_id_numbers_truthfully(self) -> None:
        registry, _b, _e = gn_bots.create(gn_bots.load("/nonexistent"), self.LONG,
                                          provider="local", model="m")
        _r, copy, error = gn_bots.clone(registry, self.LONG)
        self.assertIsNotNone(copy, error)
        self.assertNotEqual(copy.id, self.LONG)
        self.assertLessEqual(len(copy.id), gn_bots._ID_MAX)

    def test_every_numbered_id_is_a_legal_id(self) -> None:
        for base in ("a", "a" * 30, "a" * 31, "a" * 32, "bot.name_1"):
            for index in (2, 9, 10, 99):
                with self.subTest(base=base, index=index):
                    candidate = gn_bots._numbered(base, index)
                    self.assertTrue(candidate)
                    self.assertEqual(candidate, gn_bots.bot_id(candidate))
                    self.assertNotEqual(candidate, base, "it has to be a DIFFERENT id")


class UnreadableStoreTests(unittest.TestCase):
    """Every `gn bot` verb loads first, so a reader that raises leaves no way back."""

    def test_a_utf16_store_is_the_builtins_plus_a_reason(self) -> None:
        with TemporaryDirectory() as tmp:
            # What PowerShell's Out-File and Notepad's "Save as Unicode" write on this platform.
            gn_bots.store_path(tmp).write_bytes(json.dumps({"bots": []}).encode("utf-16"))
            registry = gn_bots.load(tmp)
        self.assertEqual(registry.ids(), tuple(bot.id for bot in gn_bots.BUILTINS))
        self.assertIn("not UTF-8", registry.error)
        self.assertFalse(registry.readable, "and it must not be overwritten either")

    def test_a_deeply_nested_store_is_a_reason(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text("[" * 60000 + "]" * 60000, encoding="utf-8")
            registry = gn_bots.load(tmp)
        self.assertIn("nested too deeply", registry.error)

    def test_a_utf16_secrets_store_does_not_take_the_listing_with_it(self) -> None:
        with TemporaryDirectory() as tmp:
            Path(tmp, "secrets.json").write_bytes(b"\xff\xfe{\x00")
            bot = gn_bots.load(tmp).get("anthropic")
            self.assertEqual(gn_bots.key_state(tmp, bot), "none")
            self.assertEqual(gn_bots.readiness(tmp, bot), "needs a key")
            self.assertTrue(gn_bots.list_lines(gn_bots.load(tmp), "anthropic", tmp))

    def test_the_temporary_file_is_uniquely_named(self) -> None:
        """Two shells both wrote `bots.json.tmp`: on Windows that is a Win32 error, not a race."""
        with TemporaryDirectory() as tmp:
            registry, _b, _e = gn_bots.create(gn_bots.load(tmp), "scout")
            names: list[str] = []
            real = os.replace

            def watch(src: str, dst: str) -> None:
                names.append(Path(src).name)
                real(src, dst)

            with mock.patch("os.replace", watch):
                gn_bots.save(tmp, registry)
                gn_bots.save(tmp, registry)
        self.assertEqual(len(names), 2)
        self.assertNotEqual(names[0], names[1])
        self.assertNotIn("bots.json.tmp", names)


class EndpointCannotCarryACredentialTests(unittest.TestCase):
    def test_a_query_string_or_userinfo_is_refused(self) -> None:
        for bad in ("https://api.example.com/v1?api_key=sk-live-AKIA1234567890",
                    "http://user:pass@127.0.0.1:11434/v1",
                    "https://host/v1#token=abc",
                    "https://host/v1?x=1"):
            with self.subTest(url=bad):
                _r, bot, error = gn_bots.update(gn_bots.load("/nonexistent"), "local",
                                                "base_url", bad)
                self.assertIsNone(bot, "the one module that promises it cannot hold a key")
                self.assertTrue(error)

    def test_an_ordinary_endpoint_is_still_accepted(self) -> None:
        for good in ("http://127.0.0.1:11434/v1", "https://api.openai.com/v1",
                     "http://localhost:11500", "https://host.example.com/v1/sub-path"):
            with self.subTest(url=good):
                _r, bot, error = gn_bots.update(gn_bots.load("/nonexistent"), "local",
                                                "base_url", good)
                self.assertIsNotNone(bot, error)

    def test_a_stored_credential_endpoint_is_refused_on_load_too(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_bots.store_path(tmp).write_text(json.dumps({"bots": [
                {"id": "leaky", "provider": "local", "model": "m",
                 "base_url": "https://api.example.com/v1?api_key=sk-live-1"}]}), encoding="utf-8")
            registry = gn_bots.load(tmp)
        self.assertIsNone(registry.get("leaky"), "it must not load, so nothing can print it")
        self.assertIn("leaky", registry.error)
        self.assertNotIn("sk-live-1", registry.error, "and the refusal does not quote the key")


class NameAmbiguityTests(unittest.TestCase):
    def test_two_bots_sharing_a_display_name_refuse_rather_than_pick(self) -> None:
        registry = gn_bots.load("/nonexistent")
        registry, _b, _e = gn_bots.create(registry, "test-brain", provider="local", model="m")
        registry, _b, _e = gn_bots.update(registry, "test-brain", "name", "Claude")
        bot, error = gn_bots.find(registry, "claude")
        self.assertIsNone(bot, "built-ins sort first, so this used to be the HOSTED one")
        self.assertIn("anthropic", error)
        self.assertIn("test-brain", error)

    def test_an_exact_id_still_wins_over_a_shared_display_name(self) -> None:
        registry = gn_bots.load("/nonexistent")
        registry, _b, _e = gn_bots.create(registry, "mine", provider="local", model="m")
        registry, _b, _e = gn_bots.update(registry, "mine", "name", "Claude")
        bot, error = gn_bots.find(registry, "mine")
        self.assertEqual(error, "")
        self.assertEqual(bot.id, "mine")


class StoredValueIsReportedTests(unittest.TestCase):
    def test_a_temperature_or_effort_that_cannot_be_honoured_is_named(self) -> None:
        for field, value in (("temperature", 9.5), ("temperature", "NaN"), ("effort", "ultra")):
            with self.subTest(field=field, value=value):
                with TemporaryDirectory() as tmp:
                    gn_bots.store_path(tmp).write_text(json.dumps({"bots": [
                        {"id": "hot", "provider": "local", "model": "m", field: value},
                    ]}).replace('"NaN"', "NaN"), encoding="utf-8")
                    registry = gn_bots.load(tmp)
                self.assertIsNone(registry.get("hot"))
                self.assertIn("hot", registry.error)
                self.assertIn(field, registry.error,
                              "clamping it while reporting nothing hid that it did not take effect")


class SetupStoresTheResolvedBotTests(unittest.TestCase):
    """`gn setup` is the one path that checked the bot existed AND skipped the single writer."""

    def _run_setup(self, answers: list[str], runtime: Path) -> tuple[int, str]:
        import gn_cli

        class _Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        replies = iter(answers)
        out, err = _Tty(), io.StringIO()
        saved = gn_cli.RUNTIME_DIR
        gn_cli.RUNTIME_DIR = runtime
        try:
            with mock.patch("sys.stdout", out), mock.patch("sys.stdin", _Tty()), \
                 mock.patch("builtins.input", lambda _p="": next(replies)), \
                 mock.patch("sys.stderr", err):
                code = gn_cli.main(["setup"])
        finally:
            gn_cli.RUNTIME_DIR = saved
        return (code, err.getvalue())

    def test_a_prefix_is_stored_as_the_bot_it_resolves_to(self) -> None:
        with TemporaryDirectory() as tmp:
            code, _err = self._run_setup(["", "anth", "", "", "", ""], Path(tmp))
            self.assertEqual(code, 0)
            self.assertEqual(gn_profile.load(tmp).get("bot"), "anthropic",
                             "storing 'anth' put a value in the profile nothing would honour")
            self.assertEqual(gn_bots.active(tmp)[0].id, "anthropic")
            self.assertEqual(gn_bots.active(tmp)[1], "", "and it resolves with no complaint")

    def test_a_bot_that_does_not_exist_still_writes_nothing(self) -> None:
        with TemporaryDirectory() as tmp:
            code, err = self._run_setup(["", "skynet"], Path(tmp))
            self.assertEqual(code, 2)
            self.assertIn("no bot called", err)
            self.assertFalse(gn_profile.profile_path(tmp).exists())


class _StudioCase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = TemporaryDirectory()
        self.tmp = self._dir.name
        self.addCleanup(self._dir.cleanup)
        self.studio = gn_studio.Studio(runtime_dir=self.tmp, seed_dir=SEED,
                                       stream=io.StringIO(), size=(100, 26))

    def said(self) -> str:
        return NEWLINE.join(text for _who, text in self.studio.snapshot().chat)

    def frame(self, cols: int = 100, rows: int = 26) -> str:
        return NEWLINE.join(gn_studio.render(self.studio.snapshot(), gn_tui.Size(cols, rows),
                                             _tier(), "utf-8"))

    def write_runtime_config(self, **coder: object) -> None:
        Path(self.tmp, "solin_runtime_config.json").write_text(
            json.dumps({"coder": coder}), encoding="utf-8")

    def fake_coder(self, **kwargs: object) -> tuple[object, mock.MagicMock]:
        fake = mock.MagicMock()
        for key, value in kwargs.items():
            setattr(fake.generate, key, value)
        return (mock.patch.dict(sys.modules, {"coder": fake}), fake)


class OffMachineIsResolvedTests(_StudioCase):
    """The worst thing this view can get wrong: "your question stayed here" when it did not."""

    def test_a_local_bot_inheriting_a_remote_endpoint_is_marked_everywhere(self) -> None:
        # Exactly what the desktop app writes when the operator moves Ollama to another host.
        self.write_runtime_config(enabled=True, provider="local",
                                  local={"base_url": "http://192.0.2.50:11434/v1",
                                         "model": "qwen2.5-coder:14b"})
        self.studio.submit("/new remote local qwen2.5-coder:14b")
        self.studio.submit("/use remote")
        self.assertTrue(self.studio.snapshot().off_machine,
                        "create() leaves base_url empty, so the bot's own field says nothing")
        self.assertIn("->net", self.frame())
        self.assertTrue(any(row.label == "sends" for row in self.studio.snapshot().brain))
        self.assertIn("sends off this machine", self.said())

    def test_a_loopback_bot_is_not_marked(self) -> None:
        self.write_runtime_config(enabled=True, provider="local",
                                  local={"base_url": "http://127.0.0.1:11434/v1"})
        self.studio.submit("/new nearby local qwen3:32b")
        self.studio.submit("/use nearby")
        self.assertFalse(self.studio.snapshot().off_machine)
        self.assertNotIn("->net", self.frame())

    def test_the_marker_survives_the_narrowest_supported_terminal(self) -> None:
        self.studio.submit("/use anthropic")
        for cols in (gn_studio.MIN_SIZE.cols, 74, 79, 80, 100, 200):
            with self.subTest(cols=cols):
                rows = gn_studio.render(self.studio.snapshot(), gn_tui.Size(cols, 18), _tier(),
                                        "utf-8")
                self.assertIn("->net", rows[0],
                              "the header is the only part of the frame always on screen")
                self.assertLessEqual(len(rows[0]), cols)

    def test_the_once_per_session_notice_uses_the_resolved_endpoint(self) -> None:
        self.write_runtime_config(enabled=True, provider="local",
                                  local={"base_url": "http://192.0.2.50:11434/v1"})
        self.studio.submit("/new remote local qwen3:32b")
        self.studio.submit("/use remote")
        patch, _fake = self.fake_coder(return_value={"text": "ok", "model": "q"})
        with patch:
            self.studio.submit("anything")
        self.assertIn("off this machine", self.said())


class NoEscapeReachesTheFrameTests(_StudioCase):
    def test_c1_control_characters_in_a_models_answer_are_neutralised(self) -> None:
        """U+009B is ECMA-48's CSI: on a UTF-8 terminal it can clear the operator's screen."""
        self.studio.submit("/new scout local q")
        self.studio.submit("/use scout")
        patch, _fake = self.fake_coder(return_value={
            "text": "here is the fix\u009b2J\u009b1;1H and \u009d0;pwned\u009c done", "model": "q"})
        with patch:
            self.studio.submit("how do I fix it")
        frame = self.frame()
        for char in ("\u009b", "\u009c", "\u009d", "\u0090", "\u0085"):
            with self.subTest(char=hex(ord(char))):
                self.assertNotIn(char, frame)
        self.assertNotIn("\033", frame)
        self.assertIn("here is the fix", frame, "and the text itself survives")

    def test_a_persona_cannot_carry_one_into_the_frame_either(self) -> None:
        self.studio.submit("/new scout local q")
        self.studio.submit("/use scout")
        self.studio.submit("/persona a \u009b2J analyst")
        self.studio.submit("/bot show scout")
        self.assertNotIn("\u009b", self.frame())

    def test_every_control_character_maps_to_a_space(self) -> None:
        for code in [*range(0, 32), 127, *range(128, 160)]:
            with self.subTest(code=code):
                self.assertEqual(gn_studio._plain(chr(code)), " ")
                self.assertEqual(gn_bots._text(chr(code) + "x", 10), "x")


class HfCommandDoesNotCrashTests(_StudioCase):
    def test_only_flags_is_a_sentence_not_an_indexerror(self) -> None:
        for line in ("/hf --agent", "/hf -", "/hf --use", "/bot hf --model", "/hf --agent --use"):
            with self.subTest(line=line):
                self.studio.note("")
                self.studio.submit(line)          # must not raise
                self.assertIn("reference", self.studio.snapshot().message)

    def test_the_same_through_a_keystroke_shows_the_usage_not_a_raised_key(self) -> None:
        for char in "/hf --agent":
            self.studio.handle_key(char)
        self.studio.handle_key("ENTER")
        self.assertNotIn("raised", self.studio.snapshot().message)


class BrainPanelAgreesWithRealityTests(_StudioCase):
    def test_the_key_row_reads_the_store_the_key_is_in(self) -> None:
        Path(self.tmp, "secrets.json").write_text(json.dumps({"anthropic": "sk-ant-SECRET"}),
                                                  encoding="utf-8")
        self.write_runtime_config(enabled=True, provider="anthropic",
                                  anthropic={"model": "claude-opus-5"})
        self.studio.submit("/use anthropic")
        rows = {row.label: row.value for row in self.studio.snapshot().brain}
        self.assertEqual(rows.get("key"), "configured",
                         "it read the runtime config, which never holds the key, and said none "
                         "while BOTS showed the same bot ready")
        self.assertNotIn("SECRET", self.frame(), "presence only, always")

    def test_a_bot_that_needs_no_key_says_so_rather_than_none(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        rows = {row.label: row.value for row in self.studio.snapshot().brain}
        self.assertEqual(rows.get("key"), "not needed")


class UseSaysWhatTheBotDoesTests(_StudioCase):
    def test_off_offline_and_an_inert_clone_are_not_claimed_to_answer_and_hunt(self) -> None:
        gn_bots.store_path(self.tmp).write_text(json.dumps({"bots": [
            {"id": "smolagent", "provider": "off", "inert": True, "source": "clone"}]}),
            encoding="utf-8")
        self.studio.refresh()
        for name in ("off", "offline", "smolagent"):
            with self.subTest(bot=name):
                self.studio.submit(f"/use {name}")
                said = [text for _who, text in self.studio.snapshot().chat][-1]
                self.assertNotIn("it answers here and plans the hunt", said)
                # None of the three gives the hunt planner a brain that can answer a prompt:
                # `off` and the clone resolve to {}, and `offline` is the deterministic coder,
                # which `coder.generate` refuses outright.
                import coder

                overlay = gn_bots.coder_overlay(gn_bots.load(self.tmp).get(name), {})
                self.assertFalse(coder.reasoning_brain_enabled(overlay),
                                 "none of these plans a hunt, so none may say it does")

    def test_a_runnable_bot_still_says_it_answers_and_hunts(self) -> None:
        self.studio.submit("/new scout local qwen3:32b")
        self.studio.submit("/use scout")
        self.assertIn("it answers chat and plans the hunt", self.said())

    def test_both_doors_print_the_same_sentence(self) -> None:
        """`gn bot use` and `/use` are one operation, so the claim they make is one function.

        The studio's copy was fixed first and the CLI kept printing "off is live - it answers chat
        and plans the hunt (off - nothing answers)", which contradicts itself inside one line.
        """
        source = Path(BACKEND_DIR, "gn_bots.py").read_text(encoding="utf-8")
        self.assertIn("def what_it_does", source)
        self.assertIn("what_it_does(bot)", Path(BACKEND_DIR, "gn_studio.py").read_text(
            encoding="utf-8"))
        for name in ("off", "offline", "tinygpt"):
            with self.subTest(bot=name):
                bot = gn_bots.load("/nonexistent").get(name)
                self.assertNotIn("it answers chat and plans the hunt",
                                 gn_bots.what_it_does(bot))

    def test_an_inert_clone_answers_from_the_pack_as_the_help_promises(self) -> None:
        gn_bots.store_path(self.tmp).write_text(json.dumps({"bots": [
            {"id": "smolagent", "provider": "off", "inert": True, "source": "clone"}]}),
            encoding="utf-8")
        self.studio.refresh()
        self.studio.submit("/use smolagent")
        self.studio.submit("what is ssrf")
        self.assertIn("Server-side request forgery", self.said())
        self.assertIn("cloned agents answer from", NEWLINE.join(gn_studio.help_lines()))

    def test_off_itself_still_answers_nothing(self) -> None:
        self.studio.submit("/use off")
        self.studio.submit("what is ssrf")
        self.assertIn("nothing answers", self.said())


class TeachKeepsTheWholeLessonTests(_StudioCase):
    def test_a_lesson_starting_with_a_bot_name_goes_to_the_live_bot_intact(self) -> None:
        for lesson in ("local file reads are out of scope on this program",
                       "off-by-one in the pager is in scope",
                       "openai keys in a JS bundle are reportable"):
            with self.subTest(lesson=lesson):
                self.studio.submit("/bot forget tinygpt all")
                self.studio.submit(f"/teach {lesson}")
                self.assertEqual(gn_bots.load(self.tmp).get("tinygpt").lessons, (lesson,))
                for name in ("local", "off", "openai"):
                    self.assertEqual(gn_bots.load(self.tmp).get(name).lessons, (),
                                     "the first word is a lesson, not a name")

    def test_the_two_argument_form_still_names_a_bot(self) -> None:
        self.studio.submit("/bot teach local only loopback endpoints")
        self.assertEqual(gn_bots.load(self.tmp).get("local").lessons,
                         ("only loopback endpoints",))

    def test_a_field_alias_does_not_read_a_bot_name_either(self) -> None:
        self.studio.submit("/new local-ish local q")
        self.studio.submit("/use local-ish")
        self.studio.submit("/persona local to this machine only")
        self.assertEqual(gn_bots.load(self.tmp).get("local-ish").persona,
                         "local to this machine only")


class TruncationSaysSoTests(_StudioCase):
    def test_a_cut_answer_is_marked_and_the_model_keeps_its_own_words(self) -> None:
        self.studio.submit("/new scout local q")
        self.studio.submit("/use scout")
        long = "A" * 16217
        patch, fake = self.fake_coder(return_value={"text": long, "model": "q"})
        with patch:
            self.studio.submit("explain everything")
            shown = next(text for _who, text in self.studio.snapshot().chat
                         if text.startswith("AAA"))
            self.assertIn("cut here", shown, "stopping mid-word reads as a complete answer")
            self.assertLess(len(shown), len(long))
            self.studio.submit("go on")
            history = fake.generate.call_args[0][0]
        self.assertEqual(len(history[1]["content"]), len(long),
                         "the model must not be handed the display's truncation as its own turn")

    def test_a_short_answer_is_untouched(self) -> None:
        self.studio.submit("/new scout local q")
        self.studio.submit("/use scout")
        patch, _fake = self.fake_coder(return_value={"text": "short and whole", "model": "q"})
        with patch:
            self.studio.submit("briefly")
        self.assertIn("short and whole", self.said())
        self.assertNotIn("cut here", self.said())


class LoopbackIsDecidedByParsingTests(unittest.TestCase):
    """The security review's one finding: a string test decided whether a prompt leaves the machine.

    ``_is_loopback`` ended in ``host.startswith("127.")``, applied to a value that may be a DNS
    NAME. ``http://127.0.0.1.evil.com:11434/v1`` is a registrable hostname that satisfied it, so
    every off-machine surface went quiet - the header's ``->net``, the BRAIN ``sends`` row, the
    ``/use`` line, ``gn bot show``'s endpoint note and the once-per-session transcript notice -
    while ``coder.generate`` posted the system prompt, the persona, the lessons and the whole
    conversation to that host, with the local provider's key as a bearer token.
    """

    def test_a_hostname_that_merely_starts_with_127_is_not_loopback(self) -> None:
        for url in ("http://127.0.0.1.evil.com:11434/v1", "http://127.evil.com/v1",
                    "http://127.0.0.1.attacker.test/v1", "http://localhost.evil.com/v1",
                    "http://10.1.2.3:11434/v1", "https://api.example.com/v1"):
            with self.subTest(url=url):
                self.assertFalse(gn_bots._is_loopback(url))

    def test_a_real_loopback_address_still_is(self) -> None:
        for url in ("http://127.0.0.1:11434/v1", "http://127.1.2.3:11434/v1",
                    "http://localhost:11434/v1", "http://LOCALHOST:11434", "http://[::1]:11434/v1"):
            with self.subTest(url=url):
                self.assertTrue(gn_bots._is_loopback(url))

    def test_it_agrees_with_the_helper_the_rest_of_the_project_uses(self) -> None:
        """Three other places already answer this question; a fourth answer is a bug waiting."""
        import coder

        for url in ("http://127.0.0.1.evil.com:11434/v1", "http://127.0.0.1:11434/v1",
                    "http://127.evil.com/v1", "http://localhost:11434/v1",
                    "http://10.1.2.3/v1", "https://api.openai.com/v1",
                    "http://[::1]:11434/v1", "http://127.0.0.1:99999/v1"):
            with self.subTest(url=url):
                self.assertEqual(gn_bots._is_loopback(url),
                                 coder.ollama_host_is_loopback(coder.ollama_host(url)))

    def test_every_surface_warns_for_such_a_bot(self) -> None:
        registry, bot, error = gn_bots.create(gn_bots.load("/nonexistent"), "sneaky",
                                              provider="local", model="m",
                                              base_url="http://127.0.0.1.evil.com:11434/v1")
        self.assertEqual(error, "")
        self.assertTrue(bot.off_machine)
        with TemporaryDirectory() as tmp:
            self.assertTrue(gn_bots.sends_off_machine(tmp, bot))
            shown = NEWLINE.join(gn_bots.show_lines(bot, tmp))
        self.assertIn("off this machine", shown)

    def test_a_malformed_url_fails_closed(self) -> None:
        """The job of this check is to decide whether to WARN, so the safe direction is to warn."""
        for url in ("", "   ", "not a url", "http://", "http://[oops", "http://host:port/v1"):
            with self.subTest(url=url):
                self.assertFalse(gn_bots._is_loopback(url))


class RegisteredBotsGoThroughTheReadPathTests(unittest.TestCase):
    """A Bot built from Hugging Face metadata is held to the rules a stored one is.

    ``gn_bot_hf`` constructs one directly, and a hostile ``agent.json`` name survives
    ``hf_agent_clone._one_line`` (which collapses whitespace, and ESC is not whitespace).
    """

    def test_an_escape_in_a_registered_name_or_origin_is_cleaned(self) -> None:
        csi, esc = chr(0x9B), chr(0x1B)         # ECMA-48 CSI, and ESC
        bot = gn_bots.Bot(id="cloned", provider="off", inert=True, source="clone",
                          name=f"Agent{csi}2J{esc}[31m", origin={"repo": f"o/r{csi}2J"})
        registry, stored, error = gn_bots.register(gn_bots.load("/nonexistent"), bot)
        self.assertEqual(error, "")
        for char in (csi, esc):
            with self.subTest(char=hex(ord(char))):
                self.assertNotIn(char, stored.name)
                self.assertNotIn(char, stored.origin["repo"])
        self.assertIn("Agent", stored.name, "and the readable part survives")

    def test_a_registered_bot_is_always_one_load_would_accept_back(self) -> None:
        with TemporaryDirectory() as tmp:
            registry, stored, _e = gn_bots.register(
                gn_bots.load(tmp),
                gn_bots.Bot(id="hf-model", provider="local", model="hf.co/o/r:Q4_K_M",
                            base_url="http://127.0.0.1:11434/v1", source="huggingface"))
            gn_bots.save(tmp, registry)
            reloaded = gn_bots.load(tmp)
        self.assertEqual(reloaded.error, "", "a registered bot must not be refused on the way back")
        self.assertEqual(reloaded.get("hf-model").model, "hf.co/o/r:Q4_K_M")

    def test_a_bot_that_could_not_be_stored_is_refused_not_silently_mangled(self) -> None:
        _r, stored, error = gn_bots.register(
            gn_bots.load("/nonexistent"),
            gn_bots.Bot(id="bad", provider="local",
                        base_url="https://h/v1?api_key=sk-live-1"))
        self.assertIsNone(stored)
        self.assertTrue(error)
        self.assertNotIn("sk-live-1", error)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
