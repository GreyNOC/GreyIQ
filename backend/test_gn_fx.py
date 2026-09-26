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
        os.environ.setdefault("TERM", "xterm")

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


if __name__ == "__main__":
    unittest.main()
