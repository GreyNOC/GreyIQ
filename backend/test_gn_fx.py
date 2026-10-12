"""The live status animation must be invisible to every machine consumer, and total.

``gn_fx`` draws a moving status line for the long ``gn`` verbs. It sits in front of a security tool,
so the interesting tests are not "does it animate" but "can it ever be the reason something breaks":

  * Every ``--json`` verb promises stdout is one parseable document (``test_wardrive`` runs the real
    CLI as a subprocess and ``json.loads`` its stdout), so the frames must never touch stdout.
  * A pipe, a CI log, a redirect and this suite (which captures through ``io.StringIO``) must get
    nothing at all — not a frame, not a bare escape code.
  * A Windows cp1252 console must not be handed block-drawing characters, because ``gn_cli``'s
    ``reconfigure`` to UTF-8 is wrapped in a bare ``except`` and can fail silently.
  * Nothing in here may raise, because a raise would abort a hunt in flight.

The full-screen threat board (``gn_fx.Board``) raises the stakes on every one of those, because it
takes the ALTERNATE SCREEN: a stray byte on a redirected stream is a control sequence in someone's
log file rather than a smudged line, and a path out of the board that forgets to restore leaves the
operator staring at a frozen map with no prompt. So it is tested for all of the above plus two of
its own — the terminal is always given back, including when the stream died mid-frame, and nothing
is DRAWN that the engine did not report, which is the no-fabrication rule as a renderer.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_cli  # noqa: E402
import gn_fx  # noqa: E402

_ANSI = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


def _tty(encoding: str = "utf-8") -> io.StringIO:
    """A StringIO that claims to be a terminal with a given encoding."""

    class _Fake(io.StringIO):
        pass

    _Fake.encoding = encoding          # class attr: TextIOBase forbids assigning it per-instance
    _Fake.isatty = lambda _self: True
    return _Fake()


class OnlyForAHumanTests(unittest.TestCase):
    def setUp(self) -> None:
        for var in ("NO_COLOR", "GN_NO_FX"):
            self._restore(var)
        # CI can deliberately start with TERM=dumb, including on Windows. These
        # tests supply their own fake TTY, so make its terminal capability explicit.
        old_term = os.environ.get("TERM")
        os.environ["TERM"] = "xterm"
        self.addCleanup(lambda: os.environ.__setitem__("TERM", old_term)
                        if old_term is not None else os.environ.pop("TERM", None))

    def _restore(self, var: str) -> None:
        old = os.environ.pop(var, None)
        if old is not None:
            self.addCleanup(os.environ.__setitem__, var, old)

    def test_a_non_terminal_gets_not_one_byte(self) -> None:
        # The load-bearing case: a pipe, a file, a CI log, and every test in this suite.
        quiet = io.StringIO()
        self.assertFalse(gn_fx.enabled(quiet))
        fx = gn_fx.scanner("t", stream=quiet)
        fx.start()
        fx.phase("phase")
        fx.note("a progress line")
        fx.hit("critical", "a finding")
        time.sleep(0.15)
        fx.stop("summary")
        self.assertEqual(quiet.getvalue(), "",
                         "the animation wrote to a non-terminal, which would corrupt piped output")

    def test_counts_are_still_tracked_while_inert(self) -> None:
        # So a caller can report a digest at the end whether or not anything was drawn.
        fx = gn_fx.scanner("t", stream=io.StringIO())
        fx.hit("high")
        fx.hit("high")
        fx.hit("low")
        self.assertEqual(fx._counts, {"high": 2, "low": 1})

    def test_no_color_and_gn_no_fx_both_turn_it_off_on_a_real_terminal(self) -> None:
        stream = _tty()
        self.assertTrue(gn_fx.enabled(stream), "precondition: a utf-8 tty should be eligible")
        for var in ("NO_COLOR", "GN_NO_FX"):
            with self.subTest(env=var):
                os.environ[var] = "1"
                try:
                    self.assertFalse(gn_fx.enabled(stream), f"{var} was ignored")
                finally:
                    os.environ.pop(var, None)

    def test_term_dumb_turns_it_off(self) -> None:
        stream = _tty()
        old = os.environ.get("TERM")
        os.environ["TERM"] = "dumb"
        self.addCleanup(lambda: os.environ.__setitem__("TERM", old) if old else os.environ.pop("TERM", None))
        self.assertFalse(gn_fx.enabled(stream))

    def test_a_stream_that_cannot_answer_isatty_is_not_a_terminal(self) -> None:
        class _Hostile:
            def isatty(self):  # noqa: ANN202
                raise OSError("detached")

        self.assertFalse(gn_fx.enabled(_Hostile()))


class TermDumbWinsOnEveryPlatformTests(unittest.TestCase):
    """The precedence between ``TERM`` and the platform, pinned from either platform.

    ``test_term_dumb_turns_it_off`` above could only ever exercise the branch for the machine it
    ran on, so ``… not in {"dumb", ""} or os.name == "nt"`` passed CI (ubuntu) for a year while
    every Windows console animated straight through an explicit ``TERM=dumb``. The rule is a pure
    function of (TERM, platform), so assert the whole matrix instead of half of it.
    """

    def test_dumb_is_refused_whatever_the_platform(self) -> None:
        for os_name in ("posix", "nt"):
            for term in ("dumb", "DUMB", " dumb ", "Dumb"):
                with self.subTest(os_name=os_name, term=term):
                    self.assertFalse(gn_fx._term_allows_motion(term, os_name),
                                     "TERM=dumb is a deliberate 'no escape sequences' and must win")

    def test_an_empty_term_is_the_only_case_the_platform_decides(self) -> None:
        # Windows consoles leave TERM unset and still take ANSI; on POSIX it means no terminfo.
        for term in (None, "", "   "):
            with self.subTest(term=term):
                self.assertTrue(gn_fx._term_allows_motion(term, "nt"))
                self.assertFalse(gn_fx._term_allows_motion(term, "posix"))

    def test_a_named_terminal_is_allowed_on_both(self) -> None:
        for os_name in ("posix", "nt"):
            for term in ("xterm", "xterm-256color", "screen"):
                with self.subTest(os_name=os_name, term=term):
                    self.assertTrue(gn_fx._term_allows_motion(term, os_name))

    def test_enabled_asks_that_rule_rather_than_re_deriving_it(self) -> None:
        # The bug was a second, divergent copy of the rule inlined into enabled().
        stream = _tty()
        for var in ("NO_COLOR", "GN_NO_FX"):
            os.environ.pop(var, None)
        old = os.environ.get("TERM")
        self.addCleanup(lambda: os.environ.__setitem__("TERM", old) if old else os.environ.pop("TERM", None))
        for term in ("dumb", "DUMB", "xterm"):
            with self.subTest(term=term):
                os.environ["TERM"] = term
                self.assertEqual(gn_fx.enabled(stream), gn_fx._term_allows_motion(term, os.name))

    def test_colour_refuses_dumb_exactly_as_motion_does(self) -> None:
        # gn_fx.enabled documents itself as the mirror of this, so the pair must not disagree:
        # the bare `os.getenv("TERM") != "dumb"` here passed `DUMB` and ` dumb ` through.
        import contextlib

        class _Tty:
            def isatty(self) -> bool:
                return True

        old = os.environ.get("TERM")
        self.addCleanup(lambda: os.environ.__setitem__("TERM", old) if old else os.environ.pop("TERM", None))
        no_color = os.environ.pop("NO_COLOR", None)
        if no_color is not None:
            self.addCleanup(os.environ.__setitem__, "NO_COLOR", no_color)
        with contextlib.redirect_stdout(_Tty()):
            os.environ["TERM"] = "xterm"
            colour_on_a_terminal = gn_cli._color_enabled()
            refused: dict[str, bool] = {}
            for term in ("dumb", "DUMB", " dumb "):
                os.environ["TERM"] = term
                refused[term] = gn_cli._color_enabled()
        self.assertTrue(colour_on_a_terminal, "precondition: a named TERM on a tty should colour")
        for term, enabled in refused.items():
            with self.subTest(term=term):
                self.assertFalse(enabled, f"TERM={term!r} still coloured")


class GlyphsAreProbedNotAssumedTests(unittest.TestCase):
    def test_a_cp1252_console_gets_the_ascii_frame_set(self) -> None:
        stream = _tty("cp1252")
        self.assertIs(gn_fx._pick_frames(stream), gn_fx._FRAME_SETS[-1],
                      "a cp1252 console would render the block glyphs as '?'")

    def test_everything_written_to_a_cp1252_console_encodes_cleanly(self) -> None:
        stream = _tty("cp1252")
        fx = gn_fx.scanner("t", stream=stream, active=True)
        fx.start()
        fx.phase("active verification")
        fx.note("a progress line")
        fx.hit("critical", "a finding")
        time.sleep(0.25)
        fx.stop("done")
        body = stream.getvalue()
        self.assertTrue(body, "precondition: the animation should have drawn something")
        try:
            body.encode("cp1252")
        except UnicodeEncodeError as exc:  # pragma: no cover - the assertion is the point
            self.fail(f"cp1252 console would raise on its own output: {exc}")

    def test_the_last_frame_set_is_pure_ascii(self) -> None:
        # It is the backstop, so it must be usable on any encoding at all.
        frames = gn_fx._FRAME_SETS[-1]
        blob = "".join("".join(v) if isinstance(v, tuple) else str(v) for v in frames.values())
        blob.encode("ascii")  # raises if not

    def test_a_utf8_terminal_gets_the_rich_set(self) -> None:
        self.assertIs(gn_fx._pick_frames(_tty("utf-8")), gn_fx._FRAME_SETS[0])


class ItActuallyAnimatesTests(unittest.TestCase):
    def test_the_swimmer_moves_and_the_wake_follows_it(self) -> None:
        stream = _tty()
        fx = gn_fx.scanner("t", stream=stream, active=True)
        fx.start()
        time.sleep(0.5)
        fx.stop()
        frames = [f for f in stream.getvalue().split("\r\033[2K") if f.strip()]
        self.assertGreater(len(frames), 3, f"only {len(frames)} frames in half a second")
        positions = []
        for frame in frames:
            plain = _ANSI.sub("", frame)
            for index, char in enumerate(plain):
                if char in gn_fx._FRAME_SETS[0]["swimmer"]:
                    positions.append(index)
                    break
        self.assertGreater(len(set(positions)), 1, "the swimmer never moved")

    def test_the_swimmer_turns_around_instead_of_wrapping(self) -> None:
        # A ping-pong sweep, so it never jumps from the right edge back to the left.
        stream = _tty()
        fx = gn_fx.scanner("t", stream=stream, active=True)
        # Drive the frame counter directly rather than sleeping for a full traverse.
        swimmers = set(gn_fx._FRAME_SETS[0]["swimmer"])
        left_edge, _right_edge = gn_fx._FRAME_SETS[0]["edges"]
        seen = []
        for step in range(gn_fx._TANK_WIDTH * 4):
            fx._step = step
            tank = _ANSI.sub("", fx._tank())
            # Position WITHIN the water, so the left glass does not offset every reading.
            water_at = tank.index(left_edge) + 1
            cell = next((i for i, c in enumerate(tank[water_at:]) if c in swimmers), None)
            self.assertIsNotNone(cell, f"no swimmer in the tank at step {step}: {tank!r}")
            seen.append(cell)
        self.assertLessEqual(max(seen), gn_fx._TANK_WIDTH - 1, "the swimmer left the tank")
        self.assertGreaterEqual(min(seen), 0)
        self.assertEqual(max(seen), gn_fx._TANK_WIDTH - 1, "it never reaches the far glass")
        self.assertEqual(min(seen), 0, "it never reaches the near glass")
        # No single step may move it more than one cell — that is what wrapping looks like.
        for before, after in zip(seen, seen[1:]):
            self.assertLessEqual(abs(after - before), 1, f"jumped from {before} to {after}")

    def test_a_finding_flashes_in_its_own_severity_colour(self) -> None:
        stream = _tty()
        fx = gn_fx.scanner("t", stream=stream, active=True)
        fx.start()
        fx.hit("critical", "confirmed RCE")
        time.sleep(0.3)
        fx.stop()
        body = stream.getvalue()
        self.assertIn("CRITICAL", body)
        self.assertIn(f"\033[{gn_fx._SEV_COLOR['critical']}m", body)

    def test_the_line_is_cleared_on_stop(self) -> None:
        stream = _tty()
        fx = gn_fx.scanner("t", stream=stream, active=True)
        fx.start()
        time.sleep(0.15)
        fx.stop()
        # Whatever else it wrote, the last thing must be an erase (optionally then a summary line),
        # or the operator's next shell prompt lands on top of a half-drawn frame.
        self.assertTrue(stream.getvalue().endswith("\r\033[2K"),
                        f"stop() left content behind: {stream.getvalue()[-40:]!r}")

    def test_a_summary_survives_the_clear(self) -> None:
        stream = _tty()
        fx = gn_fx.scanner("t", stream=stream, active=True)
        fx.start()
        time.sleep(0.12)
        fx.stop("hunt complete")
        self.assertTrue(stream.getvalue().endswith("  hunt complete\n"))


class TotalityTests(unittest.TestCase):
    """Nothing here may raise, and nothing may be left running."""

    def test_stop_is_idempotent(self) -> None:
        fx = gn_fx.scanner("t", stream=_tty(), active=True)
        fx.start()
        fx.stop()
        fx.stop()
        fx.stop("and again")   # must not raise, must not re-print

    def test_a_dead_stream_mid_animation_does_not_raise(self) -> None:
        class _Breaks(io.StringIO):
            pass

        _Breaks.encoding = "utf-8"
        _Breaks.isatty = lambda _self: True
        stream = _Breaks()
        fx = gn_fx.scanner("t", stream=stream, active=True)
        fx.start()
        stream.close()          # the pipe went away — a closed pager, a killed tmux pane
        time.sleep(0.25)
        fx.stop("still fine")   # the assertion is that this returns at all

    def test_stop_all_drains_the_registry_and_is_safe_on_an_empty_one(self) -> None:
        gn_fx.stop_all()        # empty
        first, second = gn_fx.scanner("a", stream=_tty(), active=True), gn_fx.scanner("b", stream=_tty(), active=True)
        first.start()
        second.start()
        self.assertEqual(len(gn_fx._LIVE), 2)
        gn_fx.stop_all()
        self.assertEqual(gn_fx._LIVE, [], "a scanner was left running, so its thread keeps painting")

    def test_an_inert_scanner_is_never_registered(self) -> None:
        gn_fx.stop_all()
        gn_fx.scanner("t", stream=io.StringIO()).start()
        self.assertEqual(gn_fx._LIVE, [])

    def test_the_thread_is_a_daemon_so_it_cannot_hold_the_process_open(self) -> None:
        fx = gn_fx.scanner("t", stream=_tty(), active=True)
        fx.start()
        self.addCleanup(fx.stop)
        self.assertTrue(fx._thread.daemon)

    def test_an_empty_note_is_dropped_rather_than_printing_a_blank_line(self) -> None:
        stream = _tty()
        fx = gn_fx.scanner("t", stream=stream, active=True)
        fx.note("")
        fx.note("   ")
        self.assertEqual(stream.getvalue(), "")


class ProgressSinkKeepsTheOldOutputTests(unittest.TestCase):
    """Adding motion must not have changed one byte of what a pipe or a test sees."""

    def test_an_inert_scanner_hands_back_the_fallback_unchanged(self) -> None:
        calls: list[str] = []
        fallback = calls.append
        sink = gn_fx.progress_sink(gn_fx.scanner("t", stream=io.StringIO()), fallback=fallback)
        self.assertIs(sink, fallback, "the historical stdout sink was replaced on a non-terminal")
        sink("engine message")
        self.assertEqual(calls, ["engine message"])

    def test_no_scanner_at_all_hands_back_the_fallback(self) -> None:
        self.assertIsNone(gn_fx.progress_sink(None, None))
        marker = object()
        self.assertIs(gn_fx.progress_sink(None, marker), marker)

    def test_an_active_scanner_routes_the_message_to_the_live_line(self) -> None:
        stream = _tty()
        fx = gn_fx.scanner("t", stream=stream, active=True)
        fx.start()
        self.addCleanup(fx.stop)
        sink = gn_fx.progress_sink(fx, fallback=(lambda _m: self.fail("fallback used while active")))
        sink("active recon: 12 endpoints")
        self.assertIn("active recon: 12 endpoints", stream.getvalue())

    def test_json_mode_gets_no_sink_at_all(self) -> None:
        import argparse

        args = argparse.Namespace(json=True, no_fx=False)
        self.assertIsNone(gn_cli._progress(args, gn_cli._fx(args, "t")),
                          "--json must send no progress anywhere; stdout has to stay one document")


class CliIntegrationTests(unittest.TestCase):
    def test_the_long_verbs_all_accept_no_fx(self) -> None:
        parser = gn_cli.build_parser()
        for argv in (["hunt", "https://t.example", "--no-fx"],
                     ["campaign", "https://t.example", "--no-fx"],
                     ["osint", "t.example", "--no-fx"],
                     # `dash` too: its namespace is a strict superset of hunt's, and the degradation
                     # paths hand that namespace straight to _cmd_hunt, which reads no_fx.
                     ["dash", "https://t.example", "--no-fx"],
                     ["train-coder", "--no-fx"]):
            with self.subTest(verb=argv[0]):
                self.assertTrue(parser.parse_args(argv).no_fx)

    def test_no_fx_makes_the_scanner_inert_even_on_a_terminal(self) -> None:
        import argparse

        args = argparse.Namespace(json=False, no_fx=True)
        self.assertFalse(gn_cli._fx(args, "t").active)

    def test_the_fx_verb_is_registered_and_dispatchable(self) -> None:
        self.assertIn("fx", gn_cli.CLI_COMMANDS)
        parsed = gn_cli.build_parser().parse_args(["fx", "--seconds", "1"])
        self.assertIs(parsed.func, gn_cli._cmd_fx)

    def test_the_fx_verb_explains_itself_instead_of_animating_into_a_pipe(self) -> None:
        # Captured stderr is not a tty, so the demo must refuse with a reason and exit 2.
        import contextlib

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = gn_cli.main(["fx", "--seconds", "1"])
        self.assertEqual(code, 2)
        self.assertIn("terminal", err.getvalue().lower())

    def test_a_real_subprocess_writes_nothing_to_stdout_before_its_payload(self) -> None:
        # The contract test_wardrive relies on, asserted here directly for a cheap verb: stdout must
        # be exactly one JSON document, with no banner or frame ahead of it.
        proc = subprocess.run(
            [sys.executable, "-B", "gn_cli.py", "classes", "--json"],
            cwd=str(BACKEND_DIR), capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        json.loads(proc.stdout)   # raises if anything else was printed
        self.assertNotIn("\033", proc.stdout, "an escape sequence reached a redirected stdout")


class ColumnsAlignWithColourOnTests(unittest.TestCase):
    """The bug the padding helper exists for — invisible in this suite, obvious on a terminal."""

    def test_padding_counts_visible_characters_not_escape_bytes(self) -> None:
        original = gn_cli._color_enabled
        gn_cli._color_enabled = lambda: True
        self.addCleanup(lambda: setattr(gn_cli, "_color_enabled", original))

        padded = gn_cli._pad("rce", "36", 28)
        self.assertEqual(len(_ANSI.sub("", padded)), 28,
                         "the field is not 28 visible characters wide")
        # And the old expression, for the record: f-string padding measures the wrapped string, so
        # nine escape bytes were counted as content and every column came out nine short.
        old_style = f"{gn_cli._c('rce', '36'):<28}"
        self.assertEqual(len(_ANSI.sub("", old_style)), 19)

    def test_the_listings_line_up_identically_with_colour_on_and_off(self) -> None:
        import contextlib

        original = gn_cli._color_enabled

        def _columns(colour: bool, argv: list[str]) -> set[int]:
            gn_cli._color_enabled = lambda: colour
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                gn_cli.main(argv)
            starts = set()
            for line in out.getvalue().splitlines():
                # ONLY the two-column id/name rows. `gn profiles` also prints a 6-space-indented
                # description line per profile, which is prose and has no column to align.
                if not line.startswith("  ") or line.startswith("      "):
                    continue
                plain = _ANSI.sub("", line)
                parts = plain.split()
                if len(parts) > 1:
                    starts.add(plain.index(parts[1], len(parts[0]) + 2))
            return starts

        self.addCleanup(lambda: setattr(gn_cli, "_color_enabled", original))
        for argv in (["classes"], ["profiles"]):
            with self.subTest(verb=argv[0]):
                plain, coloured = _columns(False, argv), _columns(True, argv)
                self.assertEqual(len(coloured), 1, f"ragged columns with colour on: {coloured}")
                self.assertEqual(plain, coloured, "colour changed the column layout")

class TheBoardIsOnlyForAHumanTests(unittest.TestCase):
    """Everything OnlyForAHumanTests asserts about the line, asserted about the full screen.

    The board is strictly worse to leak than the line: it writes the alternate-screen escape, so a
    single stray byte on a redirected stream is a control sequence in somebody's log file, and on a
    machine consumer's stdout it would be in the middle of a JSON document.
    """

    def _pin(self, var: str, value: str | None) -> None:
        """Set (or clear) an env var for this test and ALWAYS put it back as it was.

        Unlike the pop-and-maybe-restore helper above, this restores a var that started unset by
        removing it again — which matters because these tests are the only ones in the file that
        SET ``NO_COLOR``/``GN_NO_FX`` rather than clearing them. Leaving one behind turned every
        later test in the process inert, and the symptom was a board test failing on its own
        ordering rather than on anything it asserts.
        """
        old = os.environ.get(var)
        self.addCleanup(lambda: os.environ.__setitem__(var, old) if old is not None
                        else os.environ.pop(var, None))
        if value is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = value

    def setUp(self) -> None:
        self._pin("NO_COLOR", None)
        self._pin("GN_NO_FX", None)
        # CI can deliberately start with TERM=dumb, including on Windows. These tests supply their
        # own fake TTY, so make its terminal capability explicit.
        self._pin("TERM", "xterm")
        # board_fits() asks the stream and then the environment; these fakes have no descriptor, so
        # pin a terminal big enough and let each test override it.
        self._pin("COLUMNS", "120")
        self._pin("LINES", "40")

    def _run_one(self, stream: io.StringIO) -> None:
        """Everything a hunt does to a board, against a surface that should stay silent."""
        board = gn_fx.Board("t", scope="example.com", stream=stream)
        board.start()
        board.track(["api.example.com", {"name": "sso.example.com", "severity": "high"}])
        board.launch("api.example.com")
        board.phase("active verification")
        board.log("> active recon: checking 7 discovered in-scope endpoint(s)")
        board.resolve("api.example.com", "critical", "AUTH BYPASS")
        board.hit("low", "a finding with no asset")
        board.hold(0.05)
        time.sleep(0.12)
        board.stop("summary")

    def test_a_non_terminal_gets_not_one_byte(self) -> None:
        # The load-bearing case: a pipe, a file, a CI log, and every test in this suite. An
        # alternate-screen escape here would corrupt the stream for everything downstream of it.
        quiet = io.StringIO()
        board = gn_fx.Board("t", stream=quiet)
        self.assertFalse(board.active)
        self._run_one(quiet)
        self.assertEqual(quiet.getvalue(), "",
                         "the board wrote to a non-terminal, which would corrupt piped output")

    def test_no_color_turns_the_board_off(self) -> None:
        os.environ["NO_COLOR"] = "1"
        stream = _tty()
        self._run_one(stream)
        self.assertEqual(stream.getvalue(), "")

    def test_gn_no_fx_turns_the_board_off(self) -> None:
        os.environ["GN_NO_FX"] = "1"
        stream = _tty()
        self._run_one(stream)
        self.assertEqual(stream.getvalue(), "")

    def test_term_dumb_turns_the_board_off(self) -> None:
        os.environ["TERM"] = "dumb"
        stream = _tty()
        self._run_one(stream)
        self.assertEqual(stream.getvalue(), "")

    def test_a_terminal_too_small_for_the_board_gets_no_board(self) -> None:
        os.environ["COLUMNS"], os.environ["LINES"] = "80", "20"
        self.assertFalse(gn_fx.board_fits(_tty()))
        stream = _tty()
        board = gn_fx.Board("t", stream=stream)
        self.assertFalse(board.active, "the board drew on a 80x20 terminal and would have wrapped")
        self._run_one(stream)
        self.assertEqual(stream.getvalue(), "")

    def test_a_narrow_terminal_falls_back_to_the_status_line(self) -> None:
        # The degradation that matters: a split pane still gets live feedback, just the line.
        os.environ["COLUMNS"], os.environ["LINES"] = "70", "40"
        surface = gn_fx.surface("t", scope="example.com", stream=_tty())
        self.assertIsInstance(surface, gn_fx.Scanner)
        self.assertTrue(surface.active, "a narrow terminal lost its progress feedback entirely")

    def test_a_terminal_big_enough_gets_the_board(self) -> None:
        surface = gn_fx.surface("t", scope="example.com", stream=_tty())
        self.assertIsInstance(surface, gn_fx.Board)

    def test_an_empty_scope_still_asks_for_the_board(self) -> None:
        # A hunt run without --scope has no scope to STATE, but it still has assets to plot, so
        # `scope=""` is a board with a bare footer — not a fallback to the line. Only omitting the
        # argument entirely (osint, dash, train-coder) asks for the line.
        self.assertIsInstance(gn_fx.surface("t", scope="", stream=_tty()), gn_fx.Board)

    def test_active_false_forces_the_line_whatever_the_terminal_is(self) -> None:
        # What --no-fx and --json ask for, and they must not get a board on a 200-column screen.
        surface = gn_fx.surface("t", scope="example.com", stream=_tty(), active=False)
        self.assertIsInstance(surface, gn_fx.Scanner)
        self.assertFalse(surface.active)


class TheBoardGivesTheTerminalBackTests(unittest.TestCase):
    """It takes the alternate screen. Every path out of it has to give the screen back."""

    def _board(self, stream: io.StringIO | None = None) -> tuple[gn_fx.Board, io.StringIO]:
        stream = stream if stream is not None else _tty()
        return gn_fx.Board("t", stream=stream, active=True), stream

    def test_the_alternate_screen_is_entered_and_left(self) -> None:
        board, stream = self._board()
        board.start()
        self.assertIn("\033[?1049h", stream.getvalue(), "the board never took the alternate screen")
        board.stop()
        value = stream.getvalue()
        self.assertIn("\033[?1049l", value, "the operator was left in the alternate screen")
        self.assertIn("\033[?25h", value, "the cursor was left hidden")
        self.assertIn("\033[?7h", value, "auto-wrap was left off for the next command")
        self.assertLess(value.index("\033[?1049h"), value.index("\033[?1049l"))

    def test_stop_is_idempotent_and_leaves_one_digest(self) -> None:
        board, stream = self._board()
        board.start()
        board.stop()
        first = stream.getvalue()
        board.stop()
        board.stop("and again")
        self.assertEqual(stream.getvalue(), first, "stop() printed twice")

    def test_a_dead_stream_mid_frame_still_restores_the_terminal(self) -> None:
        # The ordering this class exists for. A closed pager sets the stopped flag from the ticker
        # thread; an early return from stop() there would strand the operator in the alternate
        # buffer with a frozen map, which is the worst failure this module can have.
        board, stream = self._board()
        board.start()
        stream.close()
        time.sleep(0.15)
        board.stop("still fine")       # the assertion is that this returns at all
        self.assertTrue(board._restored)

    def test_stop_all_tears_the_board_down(self) -> None:
        # gn_cli.main's finally calls exactly this, and it is the only thing standing between an
        # early `return _err(...)` and a terminal left in the alternate screen.
        gn_fx.stop_all()
        board, stream = self._board()
        board.start()
        self.assertIn(board, gn_fx._LIVE)
        gn_fx.stop_all()
        self.assertEqual(gn_fx._LIVE, [])
        self.assertIn("\033[?1049l", stream.getvalue())

    def test_an_inert_board_is_never_registered(self) -> None:
        gn_fx.stop_all()
        gn_fx.Board("t", stream=io.StringIO()).start()
        self.assertEqual(gn_fx._LIVE, [])

    def test_the_ticker_is_a_daemon_so_it_cannot_hold_the_process_open(self) -> None:
        board, _stream = self._board()
        board.start()
        self.addCleanup(board.stop)
        self.assertTrue(board._thread.daemon)

    def test_a_stream_that_refuses_the_alternate_screen_degrades_to_inert(self) -> None:
        class _Refuses(io.StringIO):
            def write(self, _text: str) -> int:
                raise OSError("no")

        _Refuses.encoding = "utf-8"
        _Refuses.isatty = lambda _self: True
        board = gn_fx.Board("t", stream=_Refuses(), active=True)
        board.start()
        self.assertFalse(board.active, "a stream that cannot take the board was handed one anyway")
        self.assertIsNone(board._thread)
        board.stop()


class TheBoardIsTotalTests(unittest.TestCase):
    """Nothing here may raise. A raise would abort a hunt mid-flight for the sake of an animation."""

    def test_every_verb_survives_a_dead_stream(self) -> None:
        class _Breaks(io.StringIO):
            pass

        _Breaks.encoding = "utf-8"
        _Breaks.isatty = lambda _self: True
        stream = _Breaks()
        board = gn_fx.Board("t", stream=stream, active=True)
        board.start()
        stream.close()
        board.track(["api.example.com"])
        board.launch("api.example.com")
        board.resolve("api.example.com", "critical", "x")
        board.log("a line")
        board.phase("a phase")
        board.hit("high", "x")
        board.hold(0.02)
        board.stop("done")

    def test_a_non_encodable_message_does_not_stop_the_board(self) -> None:
        # bounty.py emits an em-dash or an ellipsis in nearly every message it has, and gn_cli's
        # reconfigure to UTF-8 is inside a bare except, so a cp1252 console really can reach here.
        stream = _tty("cp1252")
        board = gn_fx.Board("t", stream=stream, active=True)
        board.start()
        self.addCleanup(board.stop)
        board.log("scan complete — 4 raw finding(s)… → risk=moderate")
        board.phase("running active verification against 4 candidate(s)…")
        board.resolve("api.example.com", "high", "SSRF → CLOUD METADATA")
        board._paint_locked(1.0)
        self.assertFalse(board._stopped.is_set(), "an em-dash killed the board")
        written = stream.getvalue()
        self.assertIn("scan complete - 4 raw finding(s)...", written,
                      "the em-dash and ellipsis were not transliterated for a cp1252 console")
        written.encode("cp1252", errors="strict")   # raises if anything unencodable got through

    def test_a_non_encodable_asset_label_is_still_drawn(self) -> None:
        board = gn_fx.Board("t", stream=_tty("cp1252"), active=True)
        board.track(["xn--caf-dma.example.com", "café.example.com"])
        self.assertEqual(len(board._assets), 2)
        board._paint_locked(1.0)

    def test_garbage_handed_to_the_verbs_is_ignored_rather_than_raised(self) -> None:
        board = gn_fx.Board("t", stream=_tty(), active=True)
        board.track(None)
        board.track([None, "", {}, {"name": ""}, 7])
        board.launch("")
        board.launch(None)
        board.resolve("", "critical")
        board.resolve(None, None)
        board.log("")
        board.log(None)
        board.phase(None)
        self.assertEqual(board._assets, [], "something unnameable was put on the map")


class ThePlacementIsStableTests(unittest.TestCase):
    """An operator learns where their assets live. The map may never teleport one."""

    HOSTS = ("api.example.com", "sso.example.com", "vpn.example.com", "legacy.example.com",
             "cdn.example.com", "www.example.com", "mail.example.com", "git.example.com")

    def _placed(self, names) -> dict[str, tuple[int, int]]:
        board = gn_fx.Board("t", stream=_tty(), active=True)
        board.track(list(names))
        return {a["name"]: (a["x"], a["y"]) for a in board._assets}

    def test_the_same_host_always_lands_on_the_same_spot(self) -> None:
        self.assertEqual(self._placed(self.HOSTS), self._placed(self.HOSTS))

    def test_placement_does_not_depend_on_the_order_the_names_arrived(self) -> None:
        # A campaign discovers its URLs in whatever order recon returns them; the map must not
        # reshuffle because two of them swapped.
        forwards = self._placed(self.HOSTS)
        backwards = self._placed(reversed(self.HOSTS))
        self.assertEqual(forwards, backwards)

    def test_placement_survives_a_fresh_process(self) -> None:
        # The reason this hashes rather than calling hash(): PYTHONHASHSEED randomises str hashing
        # per process, so a seeded hash() would move every asset on every run.
        code = (
            "import sys; sys.path.insert(0, '.');"
            "import gn_fx;"
            f"print([gn_fx._hash_name(n) % len(gn_fx._SITES) for n in {self.HOSTS!r}])"
        )
        seen = set()
        for seed in ("0", "1", "12345"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            proc = subprocess.run([sys.executable, "-c", code], cwd=str(BACKEND_DIR),
                                  capture_output=True, text=True, timeout=120, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            seen.add(proc.stdout.strip())
        self.assertEqual(len(seen), 1, f"placement moved with PYTHONHASHSEED: {seen}")

    def test_two_assets_never_share_a_cell(self) -> None:
        placed = self._placed(self.HOSTS)
        self.assertEqual(len(set(placed.values())), len(placed), "two assets stacked on one cell")

    def test_every_site_is_filled_before_any_is_shared(self) -> None:
        # Linear probing, not modulo-and-hope: filling the list exactly means no collision was
        # ever resolved by stacking.
        names = [f"h{index}.example.com" for index in range(len(gn_fx._SITES))]
        placed = self._placed(names)
        self.assertEqual(sorted(placed.values()), sorted(gn_fx._SITES))

    def test_past_capacity_an_asset_is_nudged_rather_than_stacked(self) -> None:
        names = [f"h{index}.example.com" for index in range(len(gn_fx._SITES) + 6)]
        placed = self._placed(names)
        self.assertEqual(len(placed), len(names))
        for (x, y) in placed.values():
            self.assertTrue(0 <= x < gn_fx._MAP_W and 0 <= y < gn_fx._MAP_H,
                            f"a nudged asset was pushed off the map at ({x},{y})")

    def test_past_the_cap_further_assets_are_counted_not_dropped_silently(self) -> None:
        board = gn_fx.Board("t", stream=_tty(), active=True)
        board.track([f"h{index}.example.com" for index in range(gn_fx._BOARD_MAX_ASSETS + 7)])
        self.assertEqual(len(board._assets), gn_fx._BOARD_MAX_ASSETS)
        self.assertEqual(board._overflow, 7)
        board._paint_locked(1.0)
        rendered = _ANSI.sub("", "\n".join(board._grid.rows()))
        self.assertIn("(+7)", rendered, "the board stopped mentioning assets without saying so")

    def test_a_url_at_the_site_root_is_the_same_place_as_its_bare_host(self) -> None:
        # The engines name the same asset both ways: a campaign's seed is a URL, a portfolio's
        # target is a host. They must not become two markers for one thing.
        self.assertEqual(gn_fx._place_key("https://api.example.com/"), "api.example.com")
        self.assertEqual(gn_fx._place_key("https://api.example.com"), "api.example.com")
        self.assertNotEqual(gn_fx._place_key("https://api.example.com/v1"), "api.example.com")

    def test_a_label_names_the_most_specific_thing_the_engine_said(self) -> None:
        for name, expected in (("cdn.example.com", "CDN"),
                               ("https://api.example.com/", "API"),
                               ("https://api.example.com/v1/users", "USERS"),
                               ("https://api.example.com/v1/users/", "USERS"),
                               ("/srv/app/settings.py", "SETTINGS"),
                               ("example.com", "EXAMPLE")):
            with self.subTest(name=name):
                self.assertEqual(gn_fx._asset_tag(name), expected)


class DefconTracksTheWorstConfirmedSeverityTests(unittest.TestCase):
    """Not a count of arcs. On a live board a number that only counts motion is theatre."""

    def _defcon(self, board: gn_fx.Board, t: float) -> int:
        board._grid.clear()
        board._draw(t)
        rendered = _ANSI.sub("", "\n".join(board._grid.rows()))
        match = re.search(r"DEFCON (\d)", rendered)
        self.assertIsNotNone(match, rendered)
        return int(match.group(1))

    def _board(self) -> gn_fx.Board:
        return gn_fx.Board("t", stream=_tty(), active=True, clock_base=0.0)

    def _land(self, board: gn_fx.Board, name: str, severity: str) -> None:
        """Resolve an arc and seek it into the past, so the frame under test is after impact."""
        board.resolve(name, severity, severity.upper())
        board._by_name[name]["launch_at"] = 0.0
        board._by_name[name]["resolve_at"] = 0.5

    def test_nothing_confirmed_is_defcon_five(self) -> None:
        board = self._board()
        board.track(["a.example.com", "b.example.com", "c.example.com"])
        board.launch("a.example.com")
        board.launch("b.example.com")
        self.assertEqual(self._defcon(board, 9.0), 5,
                         "arcs in the air moved DEFCON with nothing confirmed")

    def test_each_severity_sets_its_own_level(self) -> None:
        for severity, expected in (("critical", 1), ("high", 2), ("medium", 3),
                                   ("low", 4), ("info", 5)):
            with self.subTest(severity=severity):
                board = self._board()
                self._land(board, "a.example.com", severity)
                self.assertEqual(self._defcon(board, 3.0), expected)

    def test_the_worst_confirmed_severity_wins_whatever_order_they_land_in(self) -> None:
        for order in (("low", "critical", "medium"), ("critical", "low", "medium")):
            with self.subTest(order=order):
                board = self._board()
                for index, severity in enumerate(order):
                    self._land(board, f"h{index}.example.com", severity)
                self.assertEqual(self._defcon(board, 3.0), 1)

    def test_a_low_landing_on_an_asset_cannot_repaint_a_critical_down(self) -> None:
        board = self._board()
        self._land(board, "a.example.com", "critical")
        self._land(board, "a.example.com", "low")
        self.assertEqual(board._by_name["a.example.com"]["severity"], "critical")
        self.assertEqual(self._defcon(board, 3.0), 1)

    def test_five_arcs_confirming_nothing_stay_at_defcon_five(self) -> None:
        # The bug the rule exists to prevent: DEFCON as `5 - len(arcs)` reads fine on a demo and
        # says DEFCON 1 over a board that has proven nothing at all.
        board = self._board()
        for index in range(5):
            board.track([f"h{index}.example.com"])
            board.launch(f"h{index}.example.com")
            board._by_name[f"h{index}.example.com"]["launch_at"] = 0.0
        self.assertEqual(self._defcon(board, 9.0), 5)

    def test_the_tally_counts_findings_while_the_map_merges_them_by_asset(self) -> None:
        # Two confirmed Highs and a Low on ONE url: one marker (painted High), but the tally and the
        # digest must say 2H 1L — the same numbers the line surface and the CLI summary report.
        board = self._board()
        for severity in ("high", "high", "low"):
            self._land(board, "https://api.example.com/fetch", severity)
        self.assertEqual(len(board._assets), 1)
        self.assertEqual(board._assets[0]["severity"], "high")
        board._grid.clear()
        board._draw(3.0)
        rendered = _ANSI.sub("", "\n".join(board._grid.rows()))
        self.assertIn("CONFIRMED  2H  1L", rendered)
        digest = _ANSI.sub("", board._digest_line())
        self.assertIn("2H  1L", digest)
        self.assertIn("1/1 asset(s) confirmed", digest)
        self.assertEqual(self._defcon(board, 3.0), 2)

    def test_the_board_and_the_line_agree_on_a_result(self) -> None:
        result = {"findings": [
            {"ref": "F1", "title": "a", "severity": "high", "location": "https://x.example.com/a",
             "proof_status": "confirmed"},
            {"ref": "F2", "title": "b", "severity": "high", "location": "https://x.example.com/a",
             "proof_status": "confirmed"},
        ]}
        board = self._board()
        gn_fx.report_result(board, result)
        line = gn_fx.scanner("t", stream=_tty(), active=True)
        gn_fx.report_result(line, result)
        self.assertEqual(gn_fx._finding_counts(board._assets), line._counts)

    def test_an_unknown_severity_is_treated_as_info_not_as_critical(self) -> None:
        board = self._board()
        self._land(board, "a.example.com", "catastrophic")
        self.assertEqual(board._by_name["a.example.com"]["severity"], "info")
        self.assertEqual(self._defcon(board, 3.0), 5)


class TheBoardDrawsWhatTheEngineSaidTests(unittest.TestCase):
    """No fabrication, as a drawing: every marker traces back to something the engine reported."""

    def _board(self) -> gn_fx.Board:
        return gn_fx.Board("t", stream=_tty(), active=True, clock_base=0.0)

    def _rendered(self, board: gn_fx.Board, t: float) -> str:
        board._grid.clear()
        board._draw(t)
        return _ANSI.sub("", "\n".join(board._grid.rows()))

    def test_a_tracked_asset_with_no_arc_is_drawn_but_not_counted_as_verified(self) -> None:
        board = self._board()
        board.track(["sso.example.com"])
        rendered = self._rendered(board, 2.0)
        self.assertIn("ASSETS 0/1", rendered)
        self.assertNotIn("SSO", rendered, "an unverified asset was labelled as if it had landed")

    def test_an_asset_verified_with_nothing_to_report_gets_no_severity_marker(self) -> None:
        board = self._board()
        board.launch("sso.example.com")
        board._by_name["sso.example.com"]["launch_at"] = 0.0
        rendered = self._rendered(board, 6.0)
        self.assertIn("ASSETS 1/1", rendered)
        self.assertIn("CONFIRMED  --", rendered)
        self.assertNotIn("SSO", rendered, "a clean asset was labelled like a confirmed finding")

    def test_a_confirmed_asset_is_labelled_and_tallied(self) -> None:
        board = self._board()
        board.resolve("sso.example.com", "critical", "AUTH BYPASS")
        board._by_name["sso.example.com"]["launch_at"] = 0.0
        board._by_name["sso.example.com"]["resolve_at"] = 0.5
        rendered = self._rendered(board, 0.9)      # inside the blink-on half
        self.assertIn("SSO", rendered)
        self.assertIn("CONFIRMED  1C", rendered)

    def test_a_label_at_the_right_limb_flips_instead_of_being_clipped(self) -> None:
        board = self._board()
        board.track(["legacy.example.com"])
        asset = board._assets[0]
        asset["x"], asset["y"] = gn_fx._MAP_W - 3, 8
        asset["severity"], asset["launch_at"], asset["resolve_at"] = "high", 0.0, 0.5
        rendered = self._rendered(board, 0.9).splitlines()
        row = next(line for line in rendered if "LEGACY" in line)
        self.assertIn("LEGACY", row)
        self.assertLess(row.index("LEGACY"), asset["x"],
                        "the label ran off the right limb instead of flipping to the left")

    def test_an_arc_animates_off_its_own_launch_time(self) -> None:
        # So a hunt that sits quiet for four minutes does not desynchronise what is in the air.
        board = self._board()
        board.launch("a.example.com")
        board._by_name["a.example.com"]["launch_at"] = 300.0
        mid_flight = self._rendered(board, 300.0 + gn_fx._FLIGHT / 2)
        landed = self._rendered(board, 300.0 + gn_fx._FLIGHT + 0.1)
        self.assertIn("ASSETS 0/1", mid_flight)
        self.assertIn("ASSETS 1/1", landed)

    def test_a_spent_trail_erodes_instead_of_burying_the_map(self) -> None:
        # The live board's one real addition to the scripted prototype: a hunt's verdict arrives
        # minutes after the arc lands, and arcs that waited for one would cover the continents.
        board = self._board()
        board.launch("a.example.com")
        board._by_name["a.example.com"]["launch_at"] = 0.0
        just_landed = self._rendered(board, gn_fx._FLIGHT + 0.05)
        long_after = self._rendered(board, gn_fx._FLIGHT + gn_fx._ERODE + 1.0)
        arc_glyphs = set(gn_fx._BOARD_UNI["arc"]) | {gn_fx._BOARD_UNI["head"]}
        self.assertTrue(any(ch in just_landed for ch in arc_glyphs))
        self.assertFalse(any(ch in long_after for ch in arc_glyphs),
                         "a spent trail was still drawn a second after it should have drained")

    def test_the_engines_phase_is_shown_verbatim(self) -> None:
        board = self._board()
        board.phase("active verification")
        self.assertIn("active verification", self._rendered(board, 1.0))

    def test_the_digest_left_behind_reports_only_what_resolved(self) -> None:
        board = self._board()
        board.track(["a.example.com", "b.example.com"])
        board.launch("a.example.com")
        self.assertIn("nothing confirmed", _ANSI.sub("", board._digest_line()))
        board.resolve("a.example.com", "high", "x")
        digest = _ANSI.sub("", board._digest_line())
        self.assertIn("DEFCON 2", digest)
        self.assertIn("1/2 asset(s) confirmed", digest)
        self.assertIn("1H", digest)

    def test_the_ascii_fallback_is_used_on_a_console_that_cannot_encode_the_glyphs(self) -> None:
        # A Windows cp1252 console must not be handed block-drawing characters: a map that renders
        # as a screen of ???? is worse than one made of colons.
        board = gn_fx.Board("t", stream=_tty("cp1252"), active=True, clock_base=0.0)
        self.assertIs(board._glyphs, gn_fx._BOARD_ASCII)
        board.resolve("a.example.com", "high", "x")
        board._by_name["a.example.com"]["launch_at"] = 0.0
        board._by_name["a.example.com"]["resolve_at"] = 0.5
        rendered = self._rendered(board, 0.9)
        rendered.encode("cp1252", errors="strict")     # raises if a block glyph got through
        self.assertIn(gn_fx._BOARD_ASCII["land"], rendered)

    def test_a_utf8_terminal_gets_the_block_glyphs(self) -> None:
        self.assertIs(gn_fx.Board("t", stream=_tty("utf-8"), active=True)._glyphs, gn_fx._BOARD_UNI)

    def test_every_frame_is_exactly_the_grid_it_promises(self) -> None:
        # One row wider or taller than the terminal was measured for and the board folds.
        board = self._board()
        board.track(["a.example.com"])
        board._grid.clear()
        board._draw(3.0)
        rows = board._grid.rows()
        self.assertEqual(len(rows), gn_fx._BOARD_ROWS)
        self.assertGreaterEqual(board._cols, gn_fx._BOARD_MIN_COLS)
        self.assertLessEqual(board._cols, gn_fx._BOARD_COLS)
        for row in rows:
            self.assertEqual(len(_ANSI.sub("", row)), board._cols)

    def test_a_frame_only_repaints_the_rows_that_changed(self) -> None:
        # A full frame is ~4 KB; at 20 fps that is enough write traffic to make the board the slow
        # part of a hunt watched over ssh.
        stream = _tty()
        board = gn_fx.Board("t", stream=stream, active=True, clock_base=0.0)
        board.track(["a.example.com"])
        board._paint_locked(1.0)
        first = len(stream.getvalue())
        stream.seek(0)
        stream.truncate()
        board._paint_locked(1.0)       # the same instant: nothing has changed
        self.assertEqual(stream.getvalue(), "", "an unchanged frame was repainted in full")
        self.assertGreater(first, 0)


class TheFeedOnlyBelievesWhatTheEnginesSayTests(unittest.TestCase):
    """The judgement call, pinned to the literal strings bughunter emits.

    These are copied from the engine source, not invented: ``bounty.py``'s opening line,
    ``campaign.py``'s per-URL loop and span prefix, ``operator.py``'s per-target cycle event. If a
    message there is reworded this suite is how we find out.
    """

    def _feed(self, *messages: str) -> gn_fx.Board:
        board = gn_fx.Board("t", stream=_tty(), active=True, clock_base=0.0)
        feed = gn_fx.BoardFeed(board)
        for message in messages:
            feed(message)
        return board

    def _flying(self, board: gn_fx.Board) -> list[str]:
        return [a["name"] for a in board._assets if a["launch_at"] is not None]

    def test_a_single_hunts_seed_target_launches(self) -> None:
        board = self._feed("hunt: https://api.example.com (profile=Web application)")
        self.assertEqual(self._flying(board), ["https://api.example.com"])

    def test_each_campaign_url_launches_as_the_engine_reaches_it(self) -> None:
        board = self._feed("recon: mapping the surface…",
                           "hunt 1/2: https://www.example.com/",
                           "hunt 2/2: https://www.example.com/login")
        self.assertEqual(self._flying(board),
                         ["https://www.example.com/", "https://www.example.com/login"])

    def test_a_portfolio_target_launches_from_the_cycle_event(self) -> None:
        board = self._feed("hunt acme-portfolio: https://sso.example.com")
        self.assertEqual(self._flying(board), ["https://sso.example.com"])

    def test_a_span_line_is_attributed_by_its_own_prefix_not_by_position(self) -> None:
        # run_campaign_over_targets runs several targets CONCURRENTLY, so lines interleave. Each
        # one carries its own target; nothing here may be attributed to whichever was "current".
        board = self._feed("[1/2 https://a.example.com] starting…",
                           "[2/2 https://b.example.com] starting…",
                           "[2/2 https://b.example.com] hunt 1/1: https://b.example.com/admin",
                           "[1/2 https://a.example.com] recon: mapping the surface…")
        self.assertEqual(self._flying(board), ["https://a.example.com", "https://b.example.com",
                                               "https://b.example.com/admin"])

    def test_a_line_about_a_target_that_is_not_a_start_tracks_it_without_an_arc(self) -> None:
        board = self._feed("[2/2 https://b.example.com] skipped — out of scope")
        self.assertEqual([a["name"] for a in board._assets], ["https://b.example.com"])
        self.assertEqual(self._flying(board), [],
                         "'the engine mentioned this' was treated as 'the engine started on it'")

    def test_prose_never_becomes_a_target(self) -> None:
        # Every one of these is a real message. The first is the trap: it matches the portfolio
        # pattern exactly and its "target" is the word SKIPPED.
        board = self._feed(
            "hunt acme-portfolio: SKIPPED — no huntable targets",
            "hunt-planner: prioritised probe classes on 5 endpoint(s) from observed semantics",
            "hunt-brain: +3 target-specific parameter name(s)",
            "hunt-loop turn 1: +2 param(s), 40 req budget left",
            "running scanner(s)…",
            "scan complete — http, tls scanner(s) ran, 4 raw finding(s), risk=moderate",
            "active recon: checking 7 discovered in-scope endpoint(s)",
            "running active verification against 4 candidate(s)…",
            "active verification complete — 1 confirmed, 2 candidate",
            "writing report…",
            "done — 4 finding(s) (moderate risk)",
            "outcome sync: 3 adjudicated outcome(s) learned",
        )
        self.assertEqual(board._assets, [], f"prose reached the map: {board._assets}")

    def test_every_message_still_reaches_the_teletype_verbatim(self) -> None:
        # Unattributable is not unreportable: the operator sees the engine's whole stream either
        # way, which is what the one-line surface already gave them — and sees it word for word,
        # because the teletype is the engine's own prose, not a paraphrase of it.
        board = self._feed("writing report…", "done — 4 finding(s) (moderate risk)")
        typed = [line[1] for line in board._lines]
        self.assertEqual(typed, ["> writing report…", "> done — 4 finding(s) (moderate risk)"])

    def test_a_repeated_message_does_not_re_fire_an_arc_already_in_the_air(self) -> None:
        # campaign.py passes its own _emit down into run_bounty_hunt, so a URL is announced twice:
        # once by the campaign loop and once by the hunt's own opening line.
        board = self._feed("hunt 1/1: https://api.example.com",
                           "hunt: https://api.example.com (profile=Web application)")
        self.assertEqual(len(board._assets), 1)
        self.assertEqual(board._assets[0]["launch_at"], board._assets[0]["launch_at"])

    def test_the_feed_never_raises_on_anything_it_is_handed(self) -> None:
        board = gn_fx.Board("t", stream=_tty(), active=True)
        feed = gn_fx.BoardFeed(board)
        for message in (None, "", "   ", "[", "[1/", "[1/2 ]", "hunt :", "hunt 1/2:",
                        "hunt " + "x" * 5000 + ": " + "y" * 5000, 7, object()):
            feed(message)      # the assertion is that none of these raise

    def test_the_feed_is_what_an_active_board_hands_the_engines(self) -> None:
        board = gn_fx.Board("t", stream=_tty(), active=True)
        self.assertIsInstance(gn_fx.progress_sink(board), gn_fx.BoardFeed)

    def test_an_inert_board_hands_back_the_historical_stdout_sink_unchanged(self) -> None:
        calls: list[str] = []
        fallback = calls.append
        sink = gn_fx.progress_sink(gn_fx.Board("t", stream=io.StringIO()), fallback=fallback)
        self.assertIs(sink, fallback, "the historical stdout sink was replaced on a pipe")
        sink("engine message")
        self.assertEqual(calls, ["engine message"])


class VerdictsLandFromTheResultTests(unittest.TestCase):
    """The engines do not stream findings to the CLI, so the arcs resolve from the result dict.

    Confirmed only, and attributed to the asset the finding itself names.
    """

    HUNT_RESULT = {
        "findings": [
            {"ref": "F1", "title": "SSRF to cloud metadata", "severity": "high",
             "location": "https://api.example.com/fetch", "proof_status": "confirmed"},
            {"ref": "F2", "title": "Missing X-Frame-Options", "severity": "medium",
             "location": "https://api.example.com/", "proof_status": "candidate"},
            {"ref": "F3", "title": "Server header", "severity": "info",
             "location": "https://api.example.com/"},
        ],
    }
    CAMPAIGN_RESULT = {
        "findings": [
            {"ref": "C1", "title": "Auth bypass", "severity": "critical",
             "source_url": "https://sso.example.com/login"},
            {"ref": "C2", "title": "Stack trace", "severity": "low",
             "source_url": "https://legacy.example.com/"},
        ],
        "proof_of_impact": {"C1": {"status": "confirmed"}, "C2": {"status": "candidate"}},
    }
    PLAN_RESULT = {
        "findings": [{"ref": "F1", "title": "CRLF injection", "severity": "medium",
                      "location": "https://api.example.com/redirect"}],
        "attack_plans": {"F1": {"proof_of_impact": {"status": "confirmed"}}},
    }

    def test_only_confirmed_findings_are_returned(self) -> None:
        self.assertEqual(gn_fx.confirmed_findings(self.HUNT_RESULT),
                         [("https://api.example.com/fetch", "high", "SSRF to cloud metadata")])

    def test_a_campaigns_status_map_is_read(self) -> None:
        self.assertEqual(gn_fx.confirmed_findings(self.CAMPAIGN_RESULT),
                         [("https://sso.example.com/login", "critical", "Auth bypass")])

    def test_a_single_hunts_attack_plan_status_is_read(self) -> None:
        self.assertEqual(gn_fx.confirmed_findings(self.PLAN_RESULT),
                         [("https://api.example.com/redirect", "medium", "CRLF injection")])

    def test_a_finding_that_names_no_asset_falls_back_to_the_verbs_target(self) -> None:
        result = {"findings": [{"ref": "F1", "title": "x", "severity": "high",
                                "proof_status": "confirmed"}]}
        self.assertEqual(gn_fx.confirmed_findings(result, default="https://t.example"),
                         [("https://t.example", "high", "x")])

    def test_a_malformed_result_returns_nothing_rather_than_raising(self) -> None:
        for result in (None, {}, {"findings": None}, {"findings": [None, 7, "x"]},
                       {"findings": [{}], "proof_of_impact": "not a dict"}):
            self.assertEqual(gn_fx.confirmed_findings(result), [])

    def test_a_confirmed_finding_lands_on_the_arc_its_url_was_launched_under(self) -> None:
        board = gn_fx.Board("t", stream=_tty(), active=True)
        gn_fx.BoardFeed(board)("hunt 1/1: https://api.example.com/fetch")
        drawn = gn_fx.report_result(board, self.HUNT_RESULT)
        self.assertEqual(drawn, 1)
        self.assertEqual(len(board._assets), 1, "the verdict created a second marker for one asset")
        self.assertEqual(board._assets[0]["severity"], "high")

    def test_a_query_string_does_not_split_one_asset_into_two(self) -> None:
        board = gn_fx.Board("t", stream=_tty(), active=True)
        board.launch("https://api.example.com/fetch")
        board.resolve("https://api.example.com/fetch?url=x", "high", "SSRF")
        self.assertEqual(len(board._assets), 1)
        self.assertEqual(board._assets[0]["severity"], "high")

    def test_an_unambiguous_host_match_lands_on_that_host(self) -> None:
        board = gn_fx.Board("t", stream=_tty(), active=True)
        board.launch("https://sso.example.com/login")
        board.resolve("sso.example.com", "critical", "Auth bypass")
        self.assertEqual(len(board._assets), 1)
        self.assertEqual(board._assets[0]["severity"], "critical")

    def test_an_ambiguous_host_is_not_guessed_at(self) -> None:
        # Two endpoints on one host and a finding that names only the host: attributing it to
        # either would put a severity on an endpoint that may not have produced it.
        board = gn_fx.Board("t", stream=_tty(), active=True)
        board.launch("https://api.example.com/a")
        board.launch("https://api.example.com/b")
        board.resolve("api.example.com", "high", "x")
        self.assertEqual(len(board._assets), 3)
        self.assertIsNone(board._by_name["https://api.example.com/a"]["severity"])
        self.assertIsNone(board._by_name["https://api.example.com/b"]["severity"])

    def test_a_verdict_for_an_asset_the_board_never_saw_still_lands(self) -> None:
        # The engine just named it, so it is real; a campaign's consolidated findings can name a
        # URL whose own per-URL line never reached this process.
        board = gn_fx.Board("t", stream=_tty(), active=True)
        self.assertEqual(gn_fx.report_result(board, self.CAMPAIGN_RESULT), 1)
        self.assertEqual([a["name"] for a in board._assets], ["https://sso.example.com/login"])

    def test_the_line_surface_still_flashes_severities_exactly_as_before(self) -> None:
        # The same rule, same entry point, on the renderer that had it first.
        fx = gn_fx.scanner("t", stream=_tty(), active=True)
        self.assertEqual(gn_fx.report_result(fx, self.HUNT_RESULT), 1)
        self.assertEqual(fx._counts, {"high": 1})

    def test_nothing_lands_on_an_inert_surface(self) -> None:
        fx = gn_fx.scanner("t", stream=io.StringIO())
        self.assertEqual(gn_fx.report_result(fx, self.HUNT_RESULT), 0)
        self.assertEqual(gn_fx.report_result(None, self.HUNT_RESULT), 0)


class TheBoardIsWiredIntoTheHuntingVerbsTests(unittest.TestCase):
    def test_the_hunting_verbs_all_accept_no_fx(self) -> None:
        parser = gn_cli.build_parser()
        for argv in (["hunt", "https://t.example", "--no-fx"],
                     ["campaign", "https://t.example", "--no-fx"],
                     ["auto", ".", "--no-fx"]):
            with self.subTest(verb=argv[0]):
                self.assertTrue(parser.parse_args(argv).no_fx)

    def test_no_fx_forces_the_line_even_on_a_terminal_big_enough_for_the_board(self) -> None:
        import argparse

        args = argparse.Namespace(json=False, no_fx=True)
        surface = gn_cli._fx(args, "t", scope="example.com")
        self.assertIsInstance(surface, gn_fx.Scanner)
        self.assertFalse(surface.active)

    def test_json_forces_the_line_too_because_stdout_must_stay_one_document(self) -> None:
        import argparse

        args = argparse.Namespace(json=True, no_fx=False)
        surface = gn_cli._fx(args, "t", scope="example.com")
        self.assertIsInstance(surface, gn_fx.Scanner)
        self.assertFalse(surface.active)
        self.assertIsNone(gn_cli._progress(args, surface))

    def test_a_verb_that_asks_for_no_scope_keeps_the_line_it_always_had(self) -> None:
        # osint, dash and train-coder: a board is for a run with assets on it. Omitting `scope`
        # and passing an EMPTY one are deliberately different asks.
        import argparse

        args = argparse.Namespace(json=False, no_fx=False)
        self.assertIsInstance(gn_cli._fx(args, "t"), gn_fx.Scanner)

    def test_the_board_states_only_a_scope_the_operator_declared(self) -> None:
        # The footer prints the scope beside "AUTHORIZED SCOPE ONLY". A target standing in for a
        # scope there would be this program asserting an authorization nobody gave it — so a hunt
        # with no --scope gets a board with no SCOPE line, not one naming the target.
        bare = gn_fx.Board("t", scope="", stream=_tty(), active=True, clock_base=0.0)
        bare._paint_locked(1.0)
        self.assertNotIn("SCOPE example", _ANSI.sub("", "\n".join(bare._grid.rows())))
        declared = gn_fx.Board("t", scope="example.com", stream=_tty(), active=True, clock_base=0.0)
        declared._paint_locked(1.0)
        self.assertIn("SCOPE example.com", _ANSI.sub("", "\n".join(declared._grid.rows())))


    def test_the_wopr_scene_is_registered_and_dispatchable(self) -> None:
        parser = gn_cli.build_parser()
        self.assertEqual(parser.parse_args(["fx", "wopr"]).scene, "wopr")
        self.assertEqual(parser.parse_args(["fx"]).scene, "line")
        self.assertIs(parser.parse_args(["fx", "wopr"]).func, gn_cli._cmd_fx)

    def test_the_wopr_scene_explains_itself_instead_of_animating_into_a_pipe(self) -> None:
        import contextlib

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = gn_cli.main(["fx", "wopr"])
        self.assertEqual(code, 2)
        self.assertIn("terminal", err.getvalue().lower())
        self.assertNotIn("\033", err.getvalue(), "an escape sequence reached a redirected stderr")

    def test_a_real_subprocess_hunt_refusal_writes_no_escape_codes_to_a_pipe(self) -> None:
        # The whole contract in one check, through the real entry point: stderr is a pipe, so not
        # one byte of board may appear on either stream.
        proc = subprocess.run(
            [sys.executable, "-B", "gn_cli.py", "hunt", "https://t.example", "--json"],
            cwd=str(BACKEND_DIR), capture_output=True, text=True, timeout=180,
        )
        self.assertNotIn("\033", proc.stdout)
        self.assertNotIn("\033", proc.stderr)
        self.assertNotIn("1049", proc.stderr, "the alternate-screen escape reached a pipe")


if __name__ == "__main__":
    unittest.main()
