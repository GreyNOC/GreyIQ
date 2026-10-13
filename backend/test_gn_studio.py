"""The studio shows what an agent IS and what it has learned, and chats. So the risks are:

  * **A number nobody can reproduce.** Every row comes from a store's own reader; a store that is
    missing, empty or unreadable must render ``--`` with the reason, never a zero — a fabricated
    zero is indistinguishable from "nothing has happened yet", and this program's house rule is
    that a number has to be reproducible from evidence.
  * **A chat that invents a security claim.** Answers are VERBATIM excerpts from the bundled pack
    (``solin_domain`` generates nothing). When nothing matches it says so instead of answering.
  * **Leaking what it is showing.** The BRAIN panel says whether a key is configured, never the key.
  * **Spending the operator's budget or bandwidth by being opened.** A configured external brain is
    displayed and never called.
  * **A frame that lies about its own shape.** ``render`` is pure and escape-free: exactly
    ``size.rows`` rows, none wider than ``size.cols``, at every reflow band — the same contract
    ``gn_dash.render`` holds, because ``gn_tui.Screen`` counts cells and colour goes on afterwards.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_profile  # noqa: E402
import gn_studio  # noqa: E402
import gn_tui  # noqa: E402

ANSI = re.compile("\033\\[[0-9;]*m")
SEED = BACKEND_DIR / "seed"


def _tier(name: str = "rich") -> dict:
    class _Stream(io.StringIO):
        encoding = "utf-8" if name == "rich" else "ascii"

        def isatty(self) -> bool:
            return True

    return gn_tui.tier(_Stream())


def _state(**kwargs: object) -> gn_studio.StudioState:
    base = dict(
        brain=(gn_studio.Row("bot", "tinygpt", "on"),),
        learning=(gn_studio.Row("corpus", "2 hunts · 9 rows"),),
        agents=(gn_studio.Row("store", "empty", "dim"),),
    )
    base.update(kwargs)
    return gn_studio.StudioState(**base)  # type: ignore[arg-type]


class PanelTests(unittest.TestCase):
    """Each row traces to a store. A store that will not answer says so."""

    def test_an_empty_runtime_reports_nothing_rather_than_zeroes(self) -> None:
        with TemporaryDirectory() as tmp:
            rows = gn_studio.learning_rows(tmp, SEED)
        text = "\n".join(f"{r.label}={r.value}" for r in rows)
        self.assertIn("outcomes=none recorded", text,
                      "'no outcomes yet' and '$0 earned' are different claims")
        self.assertIn("ranker=none yet", text)

    def test_a_store_that_raises_is_a_row_not_a_crash(self) -> None:
        with TemporaryDirectory() as tmp, \
             mock.patch.object(gn_studio, "_trace_stats", side_effect=OSError("boom")):
            rows = gn_studio.learning_rows(tmp, SEED)
        corpus = next(r for r in rows if r.label == "corpus")
        self.assertTrue(corpus.value.startswith("--"))
        self.assertEqual(corpus.tone, "off")
        self.assertIn("OSError", corpus.value)

    def test_the_real_stores_are_read_through_their_own_readers(self) -> None:
        # Not a fixture: if trace_stats changes shape, this is where it shows up.
        with TemporaryDirectory() as tmp:
            Path(tmp, "hunt_traces.jsonl").write_text(
                json.dumps({"program": "p", "target": "https://t.example",
                            "outcomes": [{"rule_id": "r", "confirmed": True}]}) + "\n",
                encoding="utf-8")
            rows = {r.label: r.value for r in gn_studio.learning_rows(tmp, SEED)}
        self.assertIn("hunts", rows["corpus"])

    def test_the_brain_panel_says_whether_a_key_exists_never_the_key(self) -> None:
        with TemporaryDirectory() as tmp:
            Path(tmp, "solin_runtime_config.json").write_text(json.dumps({
                "internet_enabled": False, "memory_learning": True,
                "coder": {"enabled": True, "provider": "anthropic",
                          "anthropic": {"model": "claude-x", "api_key": "sk-ant-SECRET"}},
            }), encoding="utf-8")
            rows = gn_studio.brain_rows(gn_profile.load(tmp), tmp)
        text = "\n".join(f"{r.label}={r.value}" for r in rows)
        self.assertIn("key=configured", text)
        self.assertNotIn("SECRET", text)
        self.assertIn("model=claude-x", text)

    def test_the_bot_comes_from_the_profile(self) -> None:
        with TemporaryDirectory() as tmp:
            profile, _error = gn_profile.set_value(gn_profile.load(tmp), "bot", "off")
            rows = gn_studio.brain_rows(profile, tmp)
        bot = next(r for r in rows if r.label == "bot")
        self.assertEqual(bot.value, "off")
        self.assertEqual(bot.tone, "off")

    def test_a_cloned_agent_is_labelled_inert(self) -> None:
        with TemporaryDirectory() as tmp:
            Path(tmp, "agents").mkdir()
            Path(tmp, "agents", "owner-name").mkdir()
            rows = gn_studio.agent_rows(tmp)
        self.assertIn("inert", rows[0].value, "a clone that looks runnable is the one misreading "
                                              "an operator could make here")

    def test_an_empty_store_names_how_to_fill_it(self) -> None:
        with TemporaryDirectory() as tmp:
            rows = gn_studio.agent_rows(tmp)
        self.assertIn("gn agent clone", rows[0].value)

    def test_collect_returns_all_three_panels_and_never_raises(self) -> None:
        panels = gn_studio.collect("/nonexistent/path/at/all", SEED, None)
        self.assertEqual(set(panels), {"brain", "learning", "agents"})
        for rows in panels.values():
            self.assertTrue(rows)


class ChatTests(unittest.TestCase):
    """Extractive only: the answer is quoted, and ``how`` says which branch quoted it."""

    def test_a_class_question_is_answered_from_the_class_table(self) -> None:
        body, how = gn_studio.answer("what is ssrf", seed_dir=SEED)
        self.assertTrue(body)
        self.assertIn("class table", how)
        self.assertIn("CWE", body)

    def test_a_playbook_question_is_quoted_with_its_source_path(self) -> None:
        body, how = gn_studio.answer("how do I prove an IDOR", seed_dir=SEED)
        self.assertTrue(body)
        self.assertIn("Source:", body, "the excerpt carries its own citation")
        self.assertTrue(how)

    def test_nothing_matching_is_said_rather_than_answered(self) -> None:
        body, how = gn_studio.answer("zzzz qqqq xxxx", seed_dir=SEED)
        self.assertEqual((body, how), ("", ""))

    def test_an_empty_question_asks_nothing(self) -> None:
        self.assertEqual(gn_studio.answer("   ", seed_dir=SEED), ("", ""))

    def test_a_pack_that_will_not_load_is_no_answer_not_a_traceback(self) -> None:
        with mock.patch("solin_domain.load_pack", side_effect=OSError("gone")), \
             mock.patch("solin_domain.detect_class_query", return_value=""), \
             mock.patch("solin_domain.looks_like_tool_request", return_value=False):
            self.assertEqual(gn_studio.answer("anything at all", seed_dir=SEED), ("", ""))

    def test_the_answer_path_never_touches_the_network_or_a_brain(self) -> None:
        # The whole argument for a chat window on a dashboard: it cannot spend an API budget.
        import urllib.request

        with mock.patch.object(urllib.request, "urlopen",
                              side_effect=AssertionError("the studio must not call out")):
            body, _how = gn_studio.answer("what is ssrf", seed_dir=SEED)
        self.assertTrue(body)


class CommandTests(unittest.TestCase):
    def test_anything_without_a_slash_is_a_question(self) -> None:
        self.assertEqual(gn_studio.parse_studio_command("what is ssrf"),
                         {"action": "ask", "text": "what is ssrf"})

    def test_the_views_and_the_housekeeping(self) -> None:
        for line, action in (("/board", "board"), ("/wopr", "board"), ("/panels", "panels"),
                             ("/cockpit", "panels"), ("/refresh", "refresh"), ("/r", "refresh"),
                             ("/clear", "clear"), ("/quit", "quit"), ("/q", "quit"),
                             ("/help", "help"), ("/?", "help")):
            with self.subTest(line=line):
                self.assertEqual(gn_studio.parse_studio_command(line)["action"], action)

    def test_ask_with_and_without_a_question(self) -> None:
        self.assertEqual(gn_studio.parse_studio_command("/ask why")["text"], "why")
        self.assertEqual(gn_studio.parse_studio_command("/ask")["action"], "error")

    def test_a_blank_line_does_nothing(self) -> None:
        self.assertEqual(gn_studio.parse_studio_command("  ")["action"], "none")

    def test_an_unknown_command_names_the_ones_that_exist(self) -> None:
        parsed = gn_studio.parse_studio_command("/hunt https://t.example -y")
        self.assertEqual(parsed["action"], "error")
        self.assertIn("/board", parsed["message"])


class RenderTests(unittest.TestCase):
    """The frame contract, at every band — the same one gn_dash.render holds."""

    def test_exactly_the_rows_and_columns_it_was_given(self) -> None:
        for cols, rows in ((72, 18), (80, 24), (104, 27), (120, 40), (200, 60), (73, 19)):
            with self.subTest(size=(cols, rows)):
                size = gn_tui.Size(cols, rows)
                frame = gn_studio.render(_state(), size, _tier())
                self.assertEqual(len(frame), rows)
                for row in frame:
                    self.assertLessEqual(len(row), cols)

    def test_no_escape_sequence_reaches_a_row(self) -> None:
        hostile = _state(chat=(("gn", "\033[2J\033[H wiped your screen"),),
                         brain=(gn_studio.Row("bot", "\033[31mred", "on"),))
        for row in gn_studio.render(hostile, gn_tui.Size(100, 26), _tier()):
            self.assertNotIn("\033", row)

    def test_below_its_floor_it_says_so_instead_of_drawing_a_wrong_studio(self) -> None:
        for cols, rows in ((40, 12), (71, 18), (72, 17)):
            with self.subTest(size=(cols, rows)):
                frame = gn_studio.render(_state(), gn_tui.Size(cols, rows), _tier())
                self.assertEqual(len(frame), rows)
                self.assertIn("studio needs", "\n".join(frame))

    def test_the_header_names_the_studio_and_the_learning_state(self) -> None:
        on = gn_studio.render(_state(learning_on=True), gn_tui.Size(100, 24), _tier())[0]
        off = gn_studio.render(_state(learning_on=False), gn_tui.Size(100, 24), _tier())[0]
        self.assertIn(gn_studio.TITLE, on)
        self.assertIn("LEARNING ON", on)
        self.assertIn("LEARNING OFF", off)

    def test_every_panel_is_titled_so_a_number_is_never_unlabelled(self) -> None:
        frame = "\n".join(gn_studio.render(_state(), gn_tui.Size(100, 26), _tier()))
        for title in ("BRAIN", "LEARNING", "AGENTS", "CHAT"):
            self.assertIn(title, frame)

    def test_a_long_value_is_elided_not_wrapped_into_the_chat(self) -> None:
        state = _state(brain=(gn_studio.Row("model", "x" * 300),))
        frame = gn_studio.render(state, gn_tui.Size(100, 24), _tier())
        self.assertTrue(any("~" in row for row in frame))
        for row in frame:
            self.assertLessEqual(len(row), 100)

    def test_the_caret_parks_on_the_input_row(self) -> None:
        size = gn_tui.Size(100, 24)
        row, column = gn_studio.cursor(_state(input_text="abc", input_caret=3), size)
        self.assertEqual(row, size.rows)
        self.assertEqual(column, 6)
        _row, column = gn_studio.cursor(_state(input_caret=9999), size)
        self.assertLessEqual(column, size.cols)

    def test_the_transcript_scrolls_without_losing_the_frame(self) -> None:
        chat = tuple(("gn", f"line {index}") for index in range(80))
        for scroll in (0, 5, 500):
            with self.subTest(scroll=scroll):
                frame = gn_studio.render(_state(chat=chat, chat_scroll=scroll),
                                         gn_tui.Size(100, 24), _tier())
                self.assertEqual(len(frame), 24)

    def test_an_empty_chat_explains_what_the_window_is_for(self) -> None:
        frame = "\n".join(gn_studio.render(_state(), gn_tui.Size(100, 26), _tier()))
        self.assertIn("ask a question", frame)
        self.assertIn("generates", frame, "it states that nothing here generates text")

    def test_the_ascii_tier_draws_a_frame_its_codec_can_write(self) -> None:
        frame = gn_studio.render(_state(), gn_tui.Size(100, 24), _tier("ascii"))
        "\n".join(frame).encode("ascii", errors="strict")

    def test_every_console_codec_gets_a_frame_it_can_actually_write(self) -> None:
        """The failure this guards is the worst one here: a row that will not encode raises inside
        ``Screen._write``, which deactivates the screen and leaves a STILL frame over a live studio.

        Driven by the codec, not the glyph tier, because the two disagree — cp437 encodes the
        box-drawing glyphs (tier ``box``) and cannot encode the em-dash that arrives inside a
        quoted playbook card.
        """
        quoted = ("**Access control** — replay as account B → confirm the data class "
                  "exposed. Don’t submit a status-code difference… · see the pack")
        state = _state(chat=(("you", "how do I prove an IDOR"), ("gn", quoted)),
                       brain=(gn_studio.Row("model", "qwen2.5‑coder:14b"),))
        for encoding in ("utf-8", "cp437", "cp1252", "ascii", "latin-1"):
            with self.subTest(encoding=encoding):
                class _Stream:
                    """`io.StringIO.encoding` is read-only, and `tier` only reads the attribute."""

                    def __init__(self, name: str) -> None:
                        self.encoding = name

                    def isatty(self) -> bool:
                        return True

                tier = gn_tui.tier(_Stream(encoding))
                frame = gn_studio.render(state, gn_tui.Size(96, 22), tier, encoding)
                "\n".join(frame).encode(encoding, errors="strict")
                for row in frame:
                    self.assertLessEqual(len(row), 96, "a replacement must not widen a row")

    def test_a_utf8_terminal_keeps_the_text_it_can_write(self) -> None:
        state = _state(chat=(("gn", "an em—dash and a · dot"),))
        frame = "\n".join(gn_studio.render(state, gn_tui.Size(96, 22), _tier(), "utf-8"))
        self.assertIn("em—dash", frame, "folding is for codecs that need it, not for everyone")


class ColorTests(unittest.TestCase):
    def test_colour_is_applied_after_render_and_changes_no_visible_width(self) -> None:
        tier = _tier()
        plain = gn_studio.render(_state(), gn_tui.Size(100, 26), tier)
        painted = gn_studio.colorize(plain, tier)
        self.assertEqual(len(plain), len(painted))
        for before, after in zip(plain, painted):
            self.assertEqual(ANSI.sub("", after), before)

    def test_disabled_colour_is_the_plain_frame(self) -> None:
        tier = _tier()
        plain = gn_studio.render(_state(), gn_tui.Size(100, 26), tier)
        self.assertEqual(gn_studio.colorize(plain, tier, enabled=False), plain)

    def test_the_ascii_tier_keeps_its_frame_plain(self) -> None:
        # "+", "-" and "|" occur in a model name and a card excerpt; tinting them colours content.
        tier = _tier("ascii")
        painted = gn_studio.colorize(gn_studio.render(_state(), gn_tui.Size(100, 24), tier), tier)
        self.assertNotIn("\033[38;5;178m|", "\n".join(painted))

    def test_an_off_value_reads_as_off_and_an_on_value_as_on(self) -> None:
        tier = _tier()
        state = _state(brain=(gn_studio.Row("key", "none", "dim"),
                              gn_studio.Row("internet", "on", "on")))
        painted = "\n".join(gn_studio.colorize(gn_studio.render(state, gn_tui.Size(100, 24), tier),
                                               tier))
        self.assertIn(f"\033[{gn_studio._SGR['off']}mnone", painted)
        self.assertIn(f"\033[{gn_studio._SGR['on']}mon", painted)

    def test_every_escape_in_a_painted_frame_is_a_complete_sequence(self) -> None:
        tier = _tier()
        joined = "\n".join(gn_studio.colorize(
            gn_studio.render(_state(chat=(("you", "what is ssrf"),)), gn_tui.Size(100, 26), tier),
            tier))
        for position, char in enumerate(joined):
            if char == "\033":
                self.assertIsNotNone(ANSI.match(joined, position),
                                     "a truncated escape reached the frame")


class _Keys:
    def __init__(self, script: list[str]) -> None:
        self.script = list(script)

    def read(self, timeout: float = 0.06) -> str | None:
        return self.script.pop(0) if self.script else "CTRL-C"


class LoopTests(unittest.TestCase):
    """The loop's decisions, driven without a terminal: every one of them is a method call."""

    def studio(self, **kwargs: object) -> gn_studio.Studio:
        return gn_studio.Studio(runtime_dir=self.tmp, seed_dir=SEED, stream=io.StringIO(),
                                size=(100, 26), **kwargs)  # type: ignore[arg-type]

    def setUp(self) -> None:
        self._dir = TemporaryDirectory()
        self.tmp = self._dir.name
        self.addCleanup(self._dir.cleanup)

    def test_a_question_is_asked_and_answered_into_the_transcript(self) -> None:
        board = self.studio(answerer=lambda text: (f"the answer to {text}", "a source"))
        board.submit("what is ssrf")
        chat = board.snapshot().chat
        self.assertEqual(chat[0], ("you", "what is ssrf"))
        self.assertIn("the answer to", chat[1][1])
        self.assertEqual(chat[2][0], "cite")
        self.assertIn("answered by: a source", chat[2][1])

    def test_an_answer_the_pack_does_not_have_says_so(self) -> None:
        board = self.studio(answerer=lambda _text: ("", ""))
        board.submit("zzz")
        self.assertIn(gn_studio.NO_MATCH, board.snapshot().chat[-1][1])

    def test_an_answerer_that_raises_costs_the_answer_not_the_studio(self) -> None:
        def _boom(_text: str) -> tuple[str, str]:
            raise RuntimeError("no")

        board = self.studio(answerer=_boom)
        with self.assertRaises(RuntimeError):
            board.submit("x")       # inline path: the error surfaces to the caller
        board = self.studio(answerer=lambda _t: ("", ""))
        board.submit("x")
        self.assertTrue(board.snapshot().chat)

    def test_the_view_commands_hand_an_ask_back_and_leave(self) -> None:
        for line, action in (("/board", "board"), ("/panels", "panels")):
            with self.subTest(line=line):
                board = self.studio()
                board.submit(line)
                self.assertTrue(board._quit.is_set())
                self.assertEqual(board._ask, {"action": action})

    def test_quit_leaves_with_no_ask(self) -> None:
        board = self.studio()
        board.submit("/quit")
        self.assertTrue(board._quit.is_set())
        self.assertIsNone(board._ask)

    def test_refresh_re_reads_the_stores(self) -> None:
        board = self.studio()
        with mock.patch.object(gn_studio, "collect", wraps=gn_studio.collect) as collect:
            board.submit("/refresh")
        collect.assert_called_once()
        self.assertIn("re-read", board.snapshot().message)

    def test_clear_empties_the_transcript_and_keeps_the_panels(self) -> None:
        board = self.studio(answerer=lambda _t: ("body", "src"))
        board.submit("hello")
        board.submit("/clear")
        state = board.snapshot()
        self.assertEqual(state.chat, ())
        self.assertTrue(state.brain, "the panels are not part of the transcript")

    def test_help_is_one_turn_not_one_per_line(self) -> None:
        board = self.studio()
        board.submit("/help")
        self.assertEqual(len(board.snapshot().chat), 1)
        self.assertIn("/refresh", board.snapshot().chat[0][1])

    def test_ctrl_c_quits_and_an_unknown_key_is_ignored(self) -> None:
        board = self.studio()
        board.handle_key("F13")
        self.assertFalse(board._quit.is_set())
        self.assertEqual(board.snapshot().input_text, "")
        board.handle_key("CTRL-C")
        self.assertTrue(board._quit.is_set())

    def test_keys_reach_the_input_line_and_enter_submits(self) -> None:
        board = self.studio(answerer=lambda _t: ("ok", "src"))
        for key in "hi":
            board.handle_key(key)
        self.assertEqual(board.snapshot().input_text, "hi")
        board.handle_key("ENTER")
        self.assertEqual(board.snapshot().input_text, "")
        self.assertEqual(board.snapshot().chat[0], ("you", "hi"))

    def test_page_keys_scroll_the_transcript(self) -> None:
        board = self.studio()
        board.handle_key("PGUP")
        self.assertEqual(board.snapshot().chat_scroll, 5)
        board.handle_key("PGDN")
        self.assertEqual(board.snapshot().chat_scroll, 0)
        board.handle_key("PGDN")
        self.assertEqual(board.snapshot().chat_scroll, 0, "it cannot scroll below the newest line")

    def test_a_key_that_raises_is_a_message_not_a_crash(self) -> None:
        board = self.studio()
        with mock.patch.object(board._line, "feed", side_effect=ValueError("bad")):
            board.handle_key("x")
        self.assertIn("ValueError", board.snapshot().message)

    def test_the_transcript_is_capped(self) -> None:
        board = self.studio(answerer=lambda _t: ("", ""))
        for index in range(gn_studio.MAX_TURNS + 20):
            board.say("gn", f"line {index}")
        self.assertLessEqual(len(board.snapshot().chat), gn_studio.MAX_TURNS)

    def test_a_console_that_will_not_take_vt_refuses_rather_than_drawing(self) -> None:
        board = self.studio(keys=_Keys(["CTRL-C"]))
        with mock.patch("gn_tui.WinConsole") as console:
            console.return_value.__enter__.return_value.vt_enabled = False
            self.assertIsNone(board.run())
        self.assertIn("VT", board._out.getvalue())


class SetupFromTheStudioTests(unittest.TestCase):
    """The studio is where an operator LOOKS at their agent's setup, so it is where they change it.

    Through ``gn_profile``, never the file: the key whitelist, the type checks and the refusal of
    anything that smells like authorization are the CLI's, and there is no second door into the
    profile.
    """

    def setUp(self) -> None:
        self._dir = TemporaryDirectory()
        self.tmp = self._dir.name
        self.addCleanup(self._dir.cleanup)
        self.studio = gn_studio.Studio(runtime_dir=self.tmp, seed_dir=SEED,
                                       stream=io.StringIO(), size=(100, 26))

    def test_set_saves_and_the_panel_shows_it_immediately(self) -> None:
        self.studio.submit("/set bot local")
        self.assertEqual(gn_profile.load(self.tmp).get("bot"), "local")
        self.assertIn("saved", self.studio.snapshot().message)
        self.assertIn("local", [r.value for r in self.studio.snapshot().brain if r.label == "bot"],
                      "a studio that reports a saved setting while showing the old one is worse "
                      "than one that reports nothing")

    def test_unset_returns_it_to_the_default(self) -> None:
        self.studio.submit("/set bot off")
        self.studio.submit("/unset bot")
        self.assertEqual(gn_profile.load(self.tmp).get("bot"), "tinygpt")

    def test_a_bad_value_is_refused_with_the_choices_named(self) -> None:
        self.studio.submit("/set bot skynet")
        self.assertIn("tinygpt", self.studio.snapshot().message)
        self.assertFalse(gn_profile.profile_path(self.tmp).exists(), "nothing was written")

    def test_no_setting_that_looks_like_authorization_can_be_set_from_here(self) -> None:
        for key in ("authorize", "always_authorize", "hunt.authorize"):
            with self.subTest(key=key):
                self.studio.submit(f"/set {key} true")
                self.assertIn("no setting called", self.studio.snapshot().message)
        self.assertFalse(gn_profile.profile_path(self.tmp).exists())

    def test_learning_off_flips_the_header(self) -> None:
        self.assertTrue(self.studio.snapshot().learning_on)
        self.studio.submit("/set learning off")
        self.assertFalse(self.studio.snapshot().learning_on)

    def test_settings_prints_the_same_table_the_cli_does(self) -> None:
        self.studio.submit("/settings")
        shown = self.studio.snapshot().chat[-1][1]
        for item in gn_profile.SETTINGS:
            self.assertIn(item.key, shown)

    def test_it_reads_the_profile_off_disk_each_time(self) -> None:
        # `gn settings set` in another shell, or the app's settings pane, may have written since.
        profile, _error = gn_profile.set_value(gn_profile.load(self.tmp), "bot", "anthropic")
        gn_profile.save(self.tmp, profile)
        self.studio.submit("/settings")
        self.assertIn("anthropic", self.studio.snapshot().chat[-1][1])

    def test_an_unwritable_profile_is_reported_not_raised(self) -> None:
        with mock.patch("gn_profile.save", return_value=(gn_profile.Profile(), "disk is full")):
            self.studio.submit("/set bot off")
        self.assertIn("disk is full", self.studio.snapshot().message)

    def test_the_hint_fits_the_narrowest_studio_it_draws_on(self) -> None:
        # The one line that lists the commands must never be the line that gets cut.
        self.assertLessEqual(len(gn_studio.HINT), gn_studio.MIN_SIZE.cols - 6)
        frame = gn_studio.render(_state(), gn_studio.MIN_SIZE, _tier())
        self.assertIn(gn_studio.HINT, "\n".join(frame))


class SizeRefusalTests(unittest.TestCase):
    def test_it_names_the_verbs_that_print_the_same_numbers(self) -> None:
        refusal = gn_studio.size_refusal(gn_tui.Size(40, 12))
        self.assertIn("40x12", refusal)
        for verb in ("gn stats", "gn traces", "gn settings"):
            self.assertIn(verb, refusal)

    def test_a_terminal_that_fits_refuses_nothing(self) -> None:
        self.assertEqual(gn_studio.size_refusal(gn_tui.Size(100, 30)), "")
        self.assertEqual(gn_studio.size_refusal(gn_studio.MIN_SIZE), "")


if __name__ == "__main__":
    unittest.main()
