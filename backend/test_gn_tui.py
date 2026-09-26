"""The dashboard's terminal primitives must be invisible to every machine consumer, and must always
give the terminal back.

``gn_tui`` takes the whole screen and the keyboard. The interesting tests are therefore not "does it
draw" but "can it ever leave an operator with a broken shell, or corrupt something that was not a
terminal at all":

  * A pipe, a redirect, a CI log and this suite must get NOT ONE BYTE — especially not
    ``\\033[?1049h``, which silently swallows the rest of a redirected file into an alt screen.
  * The teardown sequence is a contract: exact bytes, exact order, one write, idempotent, and it
    never raises, because it runs in a ``finally`` and must not change the exit code.
  * CI is a single ubuntu job. Every Windows branch — the console modes, the ``getwch`` key path — is
    driven here from Linux through the ``_kernel32`` / ``_msvcrt`` seams, or it ships unexercised:
    commit ``b5f7efc`` exists solely because two Windows-only failures reached a release gate that
    structurally could not see them.
  * Nothing may raise. A raise from a decoration would abort a hunt in flight.
"""
from __future__ import annotations

import io
import os
import re
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_fx  # noqa: E402
import gn_tui  # noqa: E402

_ANSI = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


def _tty(encoding: str = "utf-8"):
    """A StringIO that claims to be a terminal, and records each write and flush separately.

    Same shape as ``test_gn_fx._tty`` (``encoding`` is a class attribute because ``TextIOBase``
    forbids assigning it per instance), plus the call log the "one write, one flush" contract needs.
    """

    class _Fake(io.StringIO):
        def __init__(self) -> None:
            super().__init__()
            self.writes: list[str] = []
            self.flushes = 0

        def write(self, text):  # noqa: ANN001, ANN202
            self.writes.append(text)
            return super().write(text)

        def flush(self) -> None:
            self.flushes += 1
            super().flush()

        def isatty(self) -> bool:
            return True

    _Fake.encoding = encoding
    return _Fake()


class _Env(unittest.TestCase):
    """A predictable environment: no opt-outs set, a named TERM, no inherited terminal size."""

    def setUp(self) -> None:
        for var in ("NO_COLOR", "GN_NO_FX", "GN_NO_DASH", "GN_DASH_GLYPHS", "COLUMNS", "LINES"):
            self.unset(var)
        self.setenv("TERM", "xterm")
        # Both ends: a leaked holder from an earlier failure must not make the next test lie.
        gn_tui.teardown_all()
        self.addCleanup(gn_tui.teardown_all)

    def unset(self, var: str) -> None:
        old = os.environ.pop(var, None)
        if old is not None:
            self.addCleanup(os.environ.__setitem__, var, old)

    def setenv(self, var: str, value: str) -> None:
        old = os.environ.get(var)
        os.environ[var] = value
        if old is None:
            self.addCleanup(lambda v=var: os.environ.pop(v, None))
        else:
            self.addCleanup(os.environ.__setitem__, var, old)

    def patch(self, obj: object, name: str, value: object) -> None:
        old = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, old)


class OnlyWhenAHumanIsWatchingTests(_Env):
    def test_a_non_terminal_gets_not_one_byte(self) -> None:
        # The load-bearing case, extended from test_gn_fx.test_a_non_terminal_gets_not_one_byte to a
        # full screen: a pipe, a file, a CI log, and every test in this suite.
        quiet = io.StringIO()
        self.assertFalse(gn_tui.enabled(quiet, quiet))
        screen = gn_tui.Screen(quiet)
        self.assertFalse(screen.active)
        screen.acquire()
        screen.frame(["a panel", "another row"])
        screen.take_resize()
        screen.frame(["changed"])
        screen.restore()
        body = quiet.getvalue()
        self.assertEqual(body, "", "the dashboard wrote to a non-terminal, which corrupts piped output")
        self.assertNotIn("\033[?1049h", body,
                         "an alt-screen switch reached a redirected stream; everything after it is lost")

    def test_enabled_asks_gn_fx_rather_than_re_deriving_the_policy(self) -> None:
        # The gn_fx bug this convention exists to prevent was a second, divergent copy of the rule.
        seen: list[object] = []

        def _fake(stream=None):  # noqa: ANN001, ANN202
            seen.append(stream)
            return False

        self.patch(gn_fx, "enabled", _fake)
        out, inp = _tty(), _tty()
        self.assertFalse(gn_tui.enabled(out, inp))
        self.assertEqual(seen, [out], "enabled() did not delegate to gn_fx.enabled on the OUT stream")

    def test_the_gn_fx_opt_outs_turn_the_dashboard_off_too(self) -> None:
        out, inp = _tty(), _tty()
        self.assertTrue(gn_tui.enabled(out, inp), "precondition: a utf-8 tty pair should be eligible")
        for var in ("NO_COLOR", "GN_NO_FX"):
            with self.subTest(env=var):
                os.environ[var] = "1"
                try:
                    self.assertFalse(gn_tui.enabled(out, inp), f"{var} was ignored")
                finally:
                    os.environ.pop(var, None)

    def test_stdin_that_is_not_a_terminal_turns_it_off(self) -> None:
        # `echo x | gn dash ...`: without this it degrades to a hunt instead of blowing up inside
        # termios.tcgetattr on a pipe.
        self.assertFalse(gn_tui.enabled(_tty(), io.StringIO()))

    def test_gn_no_dash_turns_it_off(self) -> None:
        out, inp = _tty(), _tty()
        self.assertTrue(gn_tui.enabled(out, inp))
        self.setenv("GN_NO_DASH", "1")
        self.assertFalse(gn_tui.enabled(out, inp))

    def test_gn_no_dash_accepts_exactly_the_vocabulary_gn_no_fx_does(self) -> None:
        # An operator who learned GN_NO_FX=true works must not find GN_NO_DASH=true silently ignored.
        for value in ("1", "true", "TRUE", " yes ", "on", "0", "false", "no", "", "maybe"):
            with self.subTest(value=value):
                self.setenv("GN_NO_DASH", value)
                self.setenv("GN_NO_FX", value)
                self.assertEqual(gn_tui._truthy_off("GN_NO_DASH"), gn_fx._truthy_off("GN_NO_FX"),
                                 f"the two opt-outs disagree about {value!r}")

    def test_a_stream_that_cannot_answer_isatty_is_not_a_terminal(self) -> None:
        class _Hostile:
            def isatty(self):  # noqa: ANN202
                raise OSError("detached")

        self.assertFalse(gn_tui.enabled(_Hostile(), _Hostile()))


class RefusalExplainsItselfTests(_Env):
    def test_refusal_is_empty_exactly_when_enabled(self) -> None:
        cases = (
            ("a terminal pair", _tty(), _tty(), None),
            ("stdout redirected", io.StringIO(), _tty(), None),
            ("stdin redirected", _tty(), io.StringIO(), None),
            ("GN_NO_DASH", _tty(), _tty(), ("GN_NO_DASH", "1")),
            ("NO_COLOR", _tty(), _tty(), ("NO_COLOR", "1")),
            ("GN_NO_FX", _tty(), _tty(), ("GN_NO_FX", "1")),
            ("TERM=dumb", _tty(), _tty(), ("TERM", "dumb")),
        )
        for label, out, inp, env in cases:
            with self.subTest(case=label):
                if env:
                    os.environ[env[0]] = env[1]
                try:
                    self.assertEqual(gn_tui.enabled(out, inp), gn_tui.refusal(out, inp) == "",
                                     f"{label}: refusal() and enabled() disagree")
                finally:
                    if env:
                        os.environ.pop(env[0], None)
                        if env[0] == "TERM":
                            os.environ["TERM"] = "xterm"

    def test_the_refusal_names_the_condition_the_operator_can_act_on(self) -> None:
        # `gn fx` set the precedent: a verb that silently does nothing looks broken.
        self.setenv("GN_NO_DASH", "1")
        self.assertIn("GN_NO_DASH", gn_tui.refusal(_tty(), _tty()))
        os.environ.pop("GN_NO_DASH")
        self.assertIn("stdout", gn_tui.refusal(io.StringIO(), _tty()))
        self.assertIn("stdin", gn_tui.refusal(_tty(), io.StringIO()))
        self.setenv("TERM", "dumb")
        self.assertIn("dumb", gn_tui.refusal(_tty(), _tty()))

    def test_the_refusal_is_one_sentence_with_no_gn_prefix(self) -> None:
        # _err() adds "gn: " itself; a second prefix would read "gn: gn: ...".
        message = gn_tui.refusal(io.StringIO(), io.StringIO())
        self.assertTrue(message)
        self.assertFalse(message.startswith("gn:"))
        self.assertTrue(message.endswith("."))
        self.assertNotIn("\n", message)


class TeardownContractTests(_Env):
    def _entered(self):  # noqa: ANN202
        stream = _tty()
        screen = gn_tui.Screen(stream, active=True, size=gn_tui.Size(40, 10))
        screen.acquire()
        self.addCleanup(screen.restore)
        return stream, screen

    def test_the_exact_teardown_sequence_in_order(self) -> None:
        # Spelled out rather than compared to the constant: this order IS the contract. Show the
        # cursor, reset SGR, reset the scroll region, leave the alt screen, show the cursor AGAIN
        # (leaving the alt screen restores the main screen's saved — hidden — cursor state).
        stream, screen = self._entered()
        before = len(stream.getvalue())
        screen.restore()
        self.assertEqual(stream.getvalue()[before:], "\033[?25h\033[0m\033[r\033[?1049l\033[?25h")

    def test_teardown_is_one_write_and_one_flush(self) -> None:
        # A restore delivered in pieces can be half-applied if the stream dies between them.
        stream, screen = self._entered()
        writes, flushes = len(stream.writes), stream.flushes
        screen.restore()
        self.assertEqual(len(stream.writes) - writes, 1, stream.writes[writes:])
        self.assertEqual(stream.flushes - flushes, 1)

    def test_teardown_is_idempotent(self) -> None:
        # Reachable three ways: the caller's ExitStack, gn_cli.main's finally, and atexit.
        stream, screen = self._entered()
        screen.restore()
        screen.restore()
        screen.restore()
        self.assertEqual(stream.getvalue().count("\033[?1049l"), 1,
                         "the alt screen was left more than once")

    def test_teardown_never_raises_on_a_dead_stream(self) -> None:
        stream, screen = self._entered()
        stream.close()          # a closed pager, a killed tmux pane
        screen.restore()        # the assertion is that this returns at all

    def test_a_frame_after_teardown_writes_nothing(self) -> None:
        stream, screen = self._entered()
        screen.restore()
        after = len(stream.getvalue())
        screen.frame(["late row"])
        self.assertEqual(len(stream.getvalue()), after)

    def test_teardown_all_drains_in_reverse_acquisition_order(self) -> None:
        # The screen must leave the alt screen BEFORE the key reader hands the tty back, or the
        # restored termios settings apply to a screen the operator cannot see.
        order: list[str] = []

        class _Holder:
            def __init__(self, name: str) -> None:
                self.name = name

            def restore(self) -> None:
                order.append(self.name)

        for name in ("winconsole", "keyreader", "screen"):
            gn_tui._register(_Holder(name))
        gn_tui.teardown_all()
        self.assertEqual(order, ["screen", "keyreader", "winconsole"])
        self.assertEqual(gn_tui._LIVE, [])

    def test_teardown_all_survives_a_holder_that_raises_and_is_safe_when_empty(self) -> None:
        gn_tui.teardown_all()   # empty

        class _Angry:
            def restore(self) -> None:
                raise RuntimeError("the terminal went away")

        done: list[str] = []

        class _Good:
            def restore(self) -> None:
                done.append("ok")

        gn_tui._register(_Good())
        gn_tui._register(_Angry())
        gn_tui.teardown_all()
        self.assertEqual(done, ["ok"], "one angry holder stopped the rest of the unwind")
        self.assertEqual(gn_tui._LIVE, [])

    def test_an_inert_screen_is_never_registered(self) -> None:
        gn_tui.teardown_all()
        gn_tui.Screen(io.StringIO()).acquire()
        self.assertEqual(gn_tui._LIVE, [], "an inert screen joined the teardown registry")

    def test_the_registry_is_separate_from_gn_fx(self) -> None:
        # A pane command calls gn_fx.stop_all() because the verb it ran may have started a Scanner.
        # That must not be able to tear down the dashboard the operator is looking at.
        stream, screen = self._entered()
        self.assertIn(screen, gn_tui._LIVE)
        gn_fx.stop_all()
        self.assertIn(screen, gn_tui._LIVE)
        self.assertNotIn(screen, gn_fx._LIVE)
        self.assertNotIn("\033[?1049l", stream.getvalue())


class _FakeKernel32:
    """Enough of kernel32 to drive the Windows console branch from Linux.

    Handles are deliberately above 2GB: the real ``GetStdHandle`` restype is ``c_void_p`` precisely
    because the default ``int`` restype truncates those.
    """

    def __init__(self, modes: dict, *, refuse: tuple = ()) -> None:
        self.handles = {gn_tui._STD_OUTPUT_HANDLE: 0x7FFFFFFF00,
                        gn_tui._STD_INPUT_HANDLE: 0x7FFFFFFF04}
        self.modes = {self.handles[k]: v for k, v in modes.items()}
        self.refuse = {self.handles[k] for k in refuse}
        self.sets: list[tuple[int, int]] = []

    def out(self) -> int:
        return self.handles[gn_tui._STD_OUTPUT_HANDLE]

    def inp(self) -> int:
        return self.handles[gn_tui._STD_INPUT_HANDLE]

    def GetStdHandle(self, which):  # noqa: N802, ANN001, ANN202
        return self.handles.get(which, 0)

    def GetConsoleMode(self, handle, out_ptr):  # noqa: N802, ANN001, ANN202
        if handle not in self.modes:
            return 0                      # a pipe: ERROR_INVALID_HANDLE
        out_ptr[0] = self.modes[handle]
        return 1

    def SetConsoleMode(self, handle, mode):  # noqa: N802, ANN001, ANN202
        self.sets.append((handle, int(mode)))
        if handle in self.refuse:
            return 0
        self.modes[handle] = int(mode)
        return 1


class WindowsConsoleTests(_Env):
    """Every assertion here runs on Linux CI, which is the only reason any of it is tested at all."""

    VT = gn_tui._ENABLE_VIRTUAL_TERMINAL_PROCESSING
    QUICK = gn_tui._ENABLE_QUICK_EDIT_MODE
    EXTENDED = gn_tui._ENABLE_EXTENDED_FLAGS

    def _console(self, out_mode: int, in_mode: int, *, refuse: tuple = ()) -> _FakeKernel32:
        fake = _FakeKernel32({gn_tui._STD_OUTPUT_HANDLE: out_mode,
                              gn_tui._STD_INPUT_HANDLE: in_mode}, refuse=refuse)
        self.patch(gn_tui, "_kernel32", fake)
        return fake

    def test_vt_is_turned_on_and_the_exact_mode_integer_is_restored(self) -> None:
        fake = self._console(0x0003, self.EXTENDED)
        console = gn_tui.WinConsole()
        console.acquire()
        self.assertEqual(fake.modes[fake.out()], 0x0003 | self.VT)
        self.assertEqual(console.vt_state, "enabled")
        self.assertTrue(console.vt_enabled)
        console.restore()
        self.assertEqual(fake.modes[fake.out()], 0x0003, "the original mode integer was not restored")

    def test_a_console_that_already_has_vt_is_left_untouched(self) -> None:
        fake = self._console(0x0007, self.EXTENDED)
        with gn_tui.WinConsole() as console:
            self.assertEqual(console.vt_state, "already-on")
        self.assertEqual(fake.sets, [], "SetConsoleMode was called on a console that needed nothing")
        self.assertEqual(fake.modes[fake.out()], 0x0007)

    def test_a_pipe_whose_console_mode_cannot_be_read_is_a_no_op(self) -> None:
        fake = _FakeKernel32({})            # neither handle is a console
        self.patch(gn_tui, "_kernel32", fake)
        with gn_tui.WinConsole() as console:
            self.assertEqual(console.vt_state, "no-console")
            # Unknown is not the same as no: a mintty pty has no console mode and handles ANSI fine,
            # and refusing there would break a terminal with nothing wrong with it.
            self.assertTrue(console.vt_enabled)
        self.assertEqual(fake.sets, [])

    def test_quick_edit_is_cleared_with_extended_flags_and_restored_exactly(self) -> None:
        # Quick-edit is on by default and one stray click-drag freezes ALL console output, which
        # reads as a hung dashboard. ENABLE_EXTENDED_FLAGS is what makes the clear take effect.
        original_in = 0x01F7 | self.QUICK
        fake = self._console(0x0007, original_in)
        console = gn_tui.WinConsole()
        console.acquire()
        applied = fake.modes[fake.inp()]
        self.assertFalse(applied & self.QUICK, "quick-edit was left on")
        self.assertTrue(applied & self.EXTENDED, "the clear does not take effect without EXTENDED_FLAGS")
        console.restore()
        self.assertEqual(fake.modes[fake.inp()], original_in)

    def test_an_input_console_that_needs_nothing_is_not_written_to(self) -> None:
        fake = self._console(0x0007, self.EXTENDED | 0x0001)
        gn_tui.WinConsole().acquire()
        self.assertEqual(fake.sets, [])

    def test_a_console_that_refuses_vt_reports_it_unavailable(self) -> None:
        # gn_dash then refuses to run: clear-and-home would destroy the operator's scrollback,
        # which is worse than not running.
        self._console(0x0003, self.EXTENDED, refuse=(gn_tui._STD_OUTPUT_HANDLE,))
        console = gn_tui.WinConsole().acquire()
        self.assertEqual(console.vt_state, "unavailable")
        self.assertFalse(console.vt_enabled)

    def test_the_full_handle_reaches_kernel32(self) -> None:
        fake = self._console(0x0003, self.EXTENDED)
        gn_tui.WinConsole().acquire()
        self.assertTrue(fake.sets)
        for handle, _mode in fake.sets:
            self.assertGreater(handle, 0xFFFFFFFF,
                               "a handle above 2GB was truncated on its way into SetConsoleMode")

    def test_an_invalid_handle_is_not_used(self) -> None:
        for bogus in (None, 0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            with self.subTest(handle=bogus):
                self.assertTrue(gn_tui._bad_handle(bogus))
        self.assertFalse(gn_tui._bad_handle(0x7FFFFFFF00))

    def test_a_kernel32_that_raises_is_survivable(self) -> None:
        class _Angry:
            def GetStdHandle(self, _which):  # noqa: N802, ANN202
                raise OSError("no console")

        self.patch(gn_tui, "_kernel32", _Angry())
        console = gn_tui.WinConsole().acquire()
        console.restore()

    def test_restore_is_idempotent(self) -> None:
        fake = self._console(0x0003, self.EXTENDED)
        console = gn_tui.WinConsole().acquire()
        console.restore()
        console.restore()
        console.restore()
        self.assertEqual(len([s for s in fake.sets if s[1] == 0x0003]), 1)

    def test_it_is_completely_inert_with_no_console_api(self) -> None:
        self.patch(gn_tui, "_kernel32", None)
        with gn_tui.WinConsole() as console:
            self.assertEqual(console.vt_state, "unmanaged")
            self.assertTrue(console.vt_enabled)
            self.assertEqual(gn_tui._LIVE, [], "an inert console joined the teardown registry")

    @unittest.skipUnless(os.name == "nt" and gn_tui._kernel32 is not None,
                         "the real kernel32 binding only exists on Windows")
    def test_the_real_binding_declares_a_pointer_sized_handle(self) -> None:
        import ctypes

        self.assertIs(gn_tui._kernel32.GetStdHandle.restype, ctypes.c_void_p,
                      "the default int restype truncates a console handle above 2GB")


class _FakeMsvcrt:
    """``kbhit``/``getwch`` over a scripted key sequence."""

    def __init__(self, chars) -> None:  # noqa: ANN001
        self.chars = list(chars)

    def kbhit(self) -> bool:
        return bool(self.chars)

    def getwch(self) -> str:
        return self.chars.pop(0)


class WindowsKeysTests(_Env):
    def _reader(self, chars) -> gn_tui.KeyReader:  # noqa: ANN001
        self.patch(gn_tui, "_msvcrt", _FakeMsvcrt(chars))
        reader = gn_tui.KeyReader(poll=0.001)
        self.assertEqual(reader.backend, "msvcrt")
        return reader

    def test_every_extended_key_maps_through_the_table(self) -> None:
        for code, name in gn_tui._WIN_EXTENDED.items():
            for lead in ("\x00", "\xe0"):   # both leads are real; conhost uses each for some keys
                with self.subTest(code=code, lead=lead):
                    self.assertEqual(self._reader([lead, code]).read(0.05), name)

    def test_an_unimplemented_extended_key_is_swallowed(self) -> None:
        self.assertIsNone(self._reader(["\xe0", "S"]).read(0.05))   # Delete

    def test_the_control_vocabulary(self) -> None:
        for char, name in (("\r", "ENTER"), ("\n", "ENTER"), ("\t", "TAB"),
                           ("\x08", "BACKSPACE"), ("\x1b", "ESC"), ("\x0c", "CTRL-L")):
            with self.subTest(char=repr(char)):
                self.assertEqual(self._reader([char]).read(0.05), name)

    def test_ctrl_c_arrives_as_a_key_because_getwch_delivers_it_literally(self) -> None:
        # There is no SIGINT coming on this path, so gn_dash has to see the key or the operator
        # cannot quit.
        self.assertEqual(self._reader(["\x03"]).read(0.05), "CTRL-C")

    def test_a_printable_character_comes_back_as_itself(self) -> None:
        for char in ("a", "Z", "7", " ", "-", "é"):
            with self.subTest(char=char):
                self.assertEqual(self._reader([char]).read(0.05), char)

    def test_an_unimplemented_control_character_is_dropped_not_echoed(self) -> None:
        # \x01 typed into the command line would look like a rendering bug the operator cannot delete.
        self.assertIsNone(self._reader(["\x01"]).read(0.05))

    def test_nothing_pressed_returns_none_after_the_timeout(self) -> None:
        import time

        reader = self._reader([])
        started = time.monotonic()
        self.assertIsNone(reader.read(0.05))
        self.assertGreaterEqual(time.monotonic() - started, 0.04)

    def test_a_raising_msvcrt_is_a_key_that_was_not_pressed(self) -> None:
        class _Angry:
            def kbhit(self):  # noqa: ANN202
                raise OSError("console detached")

        self.patch(gn_tui, "_msvcrt", _Angry())
        self.assertIsNone(gn_tui.KeyReader().read(0.01))

    def test_a_reader_with_no_backend_still_burns_the_timeout(self) -> None:
        # Returning immediately would turn the caller's poll loop into a spin that eats a core.
        import time

        self.patch(gn_tui, "_msvcrt", None)
        self.patch(gn_tui, "termios", None)
        reader = gn_tui.KeyReader()
        self.assertEqual(reader.backend, "none")
        started = time.monotonic()
        self.assertIsNone(reader.read(0.05))
        self.assertGreaterEqual(time.monotonic() - started, 0.04)
        reader.restore()


class _ScriptedPosixReader(gn_tui.KeyReader):
    """The real POSIX assembly logic over a scripted byte source, so it runs on Windows too.

    ``select`` and ``os.read`` on a tty are exercised for real by
    ``RealPosixKeyboardTests`` on Linux; everything ABOVE them — the escape-sequence assembly, the
    bare-Escape timeout, the UTF-8 continuation reads — is the part that has actual logic in it.
    """

    def __init__(self, script) -> None:  # noqa: ANN001
        super().__init__(stream=io.StringIO())
        self.backend = "termios"
        self.script = list(script)

    def _read_byte(self, _deadline):  # noqa: ANN001, ANN202
        return self.script.pop(0) if self.script else None


class PosixKeysTests(_Env):
    def test_every_escape_sequence_maps_through_the_table(self) -> None:
        for sequence, name in gn_tui._POSIX_KEYS.items():
            with self.subTest(sequence=sequence):
                script = [b"\x1b"] + [bytes(c, "latin-1") for c in sequence]
                self.assertEqual(_ScriptedPosixReader(script).read(0.05), name)

    def test_a_bare_escape_is_not_an_arrow_key(self) -> None:
        self.assertEqual(_ScriptedPosixReader([b"\x1b", None]).read(0.05), "ESC")

    def test_an_unrecognised_sequence_is_swallowed_not_typed_into_the_line(self) -> None:
        # "[3~" echoed literally is worse than ignoring a key we have not implemented.
        self.assertIsNone(_ScriptedPosixReader([b"\x1b", b"[", b"3", b"~"]).read(0.05))

    def test_a_runaway_sequence_terminates(self) -> None:
        self.assertIsNone(_ScriptedPosixReader([b"\x1b", b"["] + [b"1"] * 40).read(0.05))

    def test_the_control_vocabulary(self) -> None:
        for byte, name in ((b"\r", "ENTER"), (b"\n", "ENTER"), (b"\t", "TAB"),
                           (b"\x7f", "BACKSPACE"), (b"\x08", "BACKSPACE"), (b"\x03", "CTRL-C"),
                           (b"\x0c", "CTRL-L")):
            with self.subTest(byte=byte):
                self.assertEqual(_ScriptedPosixReader([byte]).read(0.05), name)

    def test_a_multibyte_character_is_assembled_from_its_bytes(self) -> None:
        # os.read(fd, 1) hands back one BYTE, so a non-ASCII target name typed into the command line
        # would otherwise arrive as undecodable fragments.
        self.assertEqual(_ScriptedPosixReader([b"\xc3", b"\xa9"]).read(0.05), "é")
        self.assertEqual(_ScriptedPosixReader([b"\xe2", b"\x80", b"\x94"]).read(0.05), "—")

    def test_a_truncated_multibyte_character_is_dropped(self) -> None:
        self.assertIsNone(_ScriptedPosixReader([b"\xc3", None]).read(0.05))

    def test_nothing_pressed_returns_none(self) -> None:
        self.assertIsNone(_ScriptedPosixReader([]).read(0.01))


@unittest.skipUnless(gn_tui.termios is not None and hasattr(os, "openpty"),
                     "the real termios path only exists on POSIX")
class RealPosixKeyboardTests(_Env):
    """cbreak against a real pty, so select/os.read/termios are exercised and not just mocked."""

    def test_cbreak_keeps_isig_so_ctrl_c_still_raises(self) -> None:
        # Raw would clear ISIG, Ctrl-C would stop raising, and gn_cli.main's KeyboardInterrupt
        # handler — the operator's way out of a running hunt — would never fire.
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        handle = io.open(slave, "rb", buffering=0, closefd=True)
        self.addCleanup(handle.close)
        reader = gn_tui.KeyReader(handle)
        self.assertEqual(reader.backend, "termios")
        reader.acquire()
        try:
            attributes = gn_tui.termios.tcgetattr(handle.fileno())
            self.assertTrue(attributes[3] & gn_tui.termios.ISIG, "cbreak was replaced by raw mode")
            self.assertFalse(attributes[3] & gn_tui.termios.ICANON, "the terminal is still line-buffered")
        finally:
            reader.restore()

    def test_the_terminal_settings_come_back_exactly(self) -> None:
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        handle = io.open(slave, "rb", buffering=0, closefd=True)
        self.addCleanup(handle.close)
        before = gn_tui.termios.tcgetattr(handle.fileno())
        reader = gn_tui.KeyReader(handle).acquire()
        reader.restore()
        reader.restore()
        self.assertEqual(gn_tui.termios.tcgetattr(handle.fileno()), before)

    def test_a_real_arrow_key_arrives_as_one_normalised_name(self) -> None:
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        handle = io.open(slave, "rb", buffering=0, closefd=True)
        self.addCleanup(handle.close)
        reader = gn_tui.KeyReader(handle).acquire()
        self.addCleanup(reader.restore)
        os.write(master, b"\x1b[Ax")
        self.assertEqual(reader.read(0.5), "UP")
        self.assertEqual(reader.read(0.5), "x")


class CommandLineTests(_Env):
    def test_typing_inserts_at_the_caret(self) -> None:
        line = gn_tui.CommandLine()
        for key in "stop":
            line.feed(key)
        self.assertEqual(line.text, "stop")
        self.assertEqual(line.cursor, 4)
        line.feed("HOME")
        line.feed("g")
        self.assertEqual(line.text, "gstop")
        self.assertEqual(line.cursor, 1)

    def test_backspace_deletes_before_the_caret_and_stops_at_the_start(self) -> None:
        line = gn_tui.CommandLine()
        line.set("gn")
        line.feed("BACKSPACE")
        line.feed("BACKSPACE")
        line.feed("BACKSPACE")
        self.assertEqual(line.text, "")
        self.assertEqual(line.cursor, 0)

    def test_the_caret_cannot_leave_the_text(self) -> None:
        line = gn_tui.CommandLine()
        line.set("ab")
        for _ in range(5):
            line.feed("RIGHT")
        self.assertEqual(line.cursor, 2)
        for _ in range(5):
            line.feed("LEFT")
        self.assertEqual(line.cursor, 0)
        line.feed("END")
        self.assertEqual(line.cursor, 2)

    def test_enter_returns_the_line_and_clears_it(self) -> None:
        line = gn_tui.CommandLine()
        line.set("leads --limit 5")
        self.assertEqual(line.feed("ENTER"), "leads --limit 5")
        self.assertEqual(line.text, "")

    def test_an_empty_enter_returns_an_empty_string_not_none(self) -> None:
        # "pressed enter on a blank line" and "nothing happened" are different events.
        self.assertEqual(gn_tui.CommandLine().feed("ENTER"), "")

    def test_history_walks_up_and_back_down_to_the_half_typed_line(self) -> None:
        line = gn_tui.CommandLine()
        line.set("stop")
        line.feed("ENTER")
        line.set("help")
        line.feed("ENTER")
        line.set("rever")
        line.feed("UP")
        self.assertEqual(line.text, "help")
        line.feed("UP")
        self.assertEqual(line.text, "stop")
        line.feed("UP")
        self.assertEqual(line.text, "stop", "walked off the top of the history")
        line.feed("DOWN")
        self.assertEqual(line.text, "help")
        line.feed("DOWN")
        self.assertEqual(line.text, "rever", "the half-typed line was lost")

    def test_history_does_not_record_blanks_or_repeats(self) -> None:
        line = gn_tui.CommandLine()
        for text in ("stop", "stop", "   ", "", "help"):
            line.set(text)
            line.feed("ENTER")
        self.assertEqual(line.history, ("stop", "help"))

    def test_history_is_bounded(self) -> None:
        line = gn_tui.CommandLine(history=3)
        for index in range(10):
            line.set(f"verb{index}")
            line.feed("ENTER")
        self.assertEqual(line.history, ("verb7", "verb8", "verb9"))

    def test_escape_clears_the_line(self) -> None:
        line = gn_tui.CommandLine()
        line.set("half a command")
        line.feed("ESC")
        self.assertEqual(line.text, "")

    def test_keys_it_does_not_own_are_ignored(self) -> None:
        # TAB is ambiguous by design (complete a verb, or switch panes) and that is gn_dash's call.
        line = gn_tui.CommandLine()
        line.set("st")
        for key in ("TAB", "CTRL-L", "CTRL-C", "PGUP", "PGDN", None, ""):
            self.assertIsNone(line.feed(key))
        self.assertEqual(line.text, "st")

    def test_render_pads_to_exactly_the_width_and_keeps_the_caret_inside_it(self) -> None:
        line = gn_tui.CommandLine()
        line.set("gn")
        rendered = line.render(10)
        self.assertEqual(len(rendered.text), 10)
        self.assertEqual(rendered.text, "gn        ")
        self.assertEqual(rendered.caret, 2)

    def test_render_scrolls_to_keep_the_caret_visible(self) -> None:
        line = gn_tui.CommandLine()
        text = "reverify https://target.example/a/very/long/path"
        line.set(text)
        rendered = line.render(12)
        self.assertEqual(len(rendered.text), 12)
        self.assertEqual(rendered.text, text[-11:] + " ", "the window did not follow the caret")
        self.assertEqual(rendered.caret, 11)
        line.feed("HOME")
        rendered = line.render(12)
        self.assertEqual(rendered.caret, 0)
        self.assertTrue(rendered.text.startswith("reverify"))

    def test_render_survives_a_nonsense_width(self) -> None:
        line = gn_tui.CommandLine()
        line.set("x")
        for width in (0, -5, None, "wide"):
            with self.subTest(width=width):
                rendered = line.render(width)
                self.assertGreaterEqual(len(rendered.text), 1)


class MeasurementTests(_Env):
    def test_the_streams_own_terminal_is_preferred_over_the_environment(self) -> None:
        # shutil reads COLUMNS/LINES and then sys.__stdout__, never the stream we draw to — and
        # stdout and stderr are redirected independently.
        self.setenv("COLUMNS", "999")
        self.setenv("LINES", "999")

        class _Sized(io.StringIO):
            def fileno(self):  # noqa: ANN202
                return 7

        self.patch(gn_tui.os, "get_terminal_size", lambda _fd: os.terminal_size((123, 45)))
        self.assertEqual(gn_tui.terminal_size(_Sized()), gn_tui.Size(123, 45))

    def test_a_stream_with_no_fileno_falls_back(self) -> None:
        # io.UnsupportedOperation subclasses both OSError and ValueError, which is why one tuple
        # covers a StringIO harness as well as a real closed fd.
        self.setenv("COLUMNS", "100")
        self.setenv("LINES", "30")
        self.assertEqual(gn_tui.terminal_size(io.StringIO()), gn_tui.Size(100, 30))

    def test_the_fallback_is_used_when_every_probe_fails(self) -> None:
        def _angry(*_args, **_kwargs):  # noqa: ANN202
            raise OSError("no terminal anywhere")

        self.patch(gn_tui.shutil, "get_terminal_size", _angry)
        self.assertEqual(gn_tui.terminal_size(io.StringIO(), gn_tui.Size(72, 20)), gn_tui.Size(72, 20))
        self.assertEqual(gn_tui.terminal_size(io.StringIO()), gn_tui.Size(80, 24))

    def test_a_nonsense_reading_is_clamped(self) -> None:
        class _Sized(io.StringIO):
            def fileno(self):  # noqa: ANN202
                return 7

        self.patch(gn_tui.os, "get_terminal_size", lambda _fd: os.terminal_size((1 << 30, 1 << 30)))
        size = gn_tui.terminal_size(_Sized())
        self.assertEqual(size, gn_tui._MAX_SIZE)

    def test_a_zero_reading_is_not_a_terminal_size(self) -> None:
        class _Sized(io.StringIO):
            def fileno(self):  # noqa: ANN202
                return 7

        self.patch(gn_tui.os, "get_terminal_size", lambda _fd: os.terminal_size((0, 0)))
        self.setenv("COLUMNS", "88")
        self.setenv("LINES", "26")
        self.assertEqual(gn_tui.terminal_size(_Sized()), gn_tui.Size(88, 26))

    def test_a_broken_fallback_cannot_be_the_reason_nothing_draws(self) -> None:
        def _angry(*_args, **_kwargs):  # noqa: ANN202
            raise OSError("no terminal anywhere")

        self.patch(gn_tui.shutil, "get_terminal_size", _angry)
        self.assertEqual(gn_tui.terminal_size(io.StringIO(), ("wide", "tall")), gn_tui.Size(80, 24))

    def test_visible_len_counts_cells_not_escape_bytes(self) -> None:
        # The gn_cli._pad lesson at screen scale: a row measured with len() wraps, and a wrapped row
        # scrolls the whole frame out from under the diff.
        row = f"\033[1;31m{'CRITICAL':<8}\033[0m \033[2m{'idor'}\033[0m"
        self.assertEqual(gn_tui.visible_len(row), 13)
        self.assertGreater(len(row), gn_tui.visible_len(row))
        self.assertEqual(gn_tui.visible_len("plain"), 5)
        self.assertEqual(gn_tui.visible_len(""), 0)

    def test_truncation_never_cuts_an_escape_sequence_in_half(self) -> None:
        row = "\033[36mabcdefghij\033[0m"
        cut = gn_tui._truncate_visible(row, 4)
        self.assertEqual(gn_tui.visible_len(cut), 4)
        self.assertEqual(_ANSI.sub("", cut), "abcd")
        self.assertTrue(cut.endswith("\033[0m"), "a truncated row left the colour on for the rest of the line")

    def test_truncation_leaves_a_short_plain_row_alone(self) -> None:
        self.assertEqual(gn_tui._truncate_visible("short", 40), "short")
        self.assertEqual(gn_tui._truncate_visible("short", 0), "")

    def test_a_newline_inside_a_row_is_neutralised(self) -> None:
        # It would scroll the frame, and every subsequent diffed row would land one line off.
        self.assertEqual(gn_tui._truncate_visible("a\nb\tc", 40), "a b c")


class SparklineTests(_Env):
    SEVEN = ("▁", "▂", "▃", "▄", "▅", "▆", "▇")
    THREE = ("░", "▒", "▓")
    FOUR = ("_", ".", ":", "|")

    def test_resolution_comes_from_the_ladder_not_from_eighths(self) -> None:
        # The box tier has THREE levels; an eighths calculation would index off the end every frame.
        for ladder in (self.SEVEN, self.THREE, self.FOUR):
            with self.subTest(levels=len(ladder)):
                drawn = gn_tui.sparkline([0, 50, 100], 3, ladder, lo=0, hi=100)
                self.assertEqual(drawn[0], ladder[0])
                self.assertEqual(drawn[-1], ladder[-1])
                self.assertTrue(set(drawn) <= set(ladder))

    def test_the_full_ladder_is_reachable(self) -> None:
        drawn = gn_tui.sparkline(list(range(7)), 7, self.SEVEN, lo=0, hi=6)
        self.assertEqual(drawn, "".join(self.SEVEN))

    def test_a_flat_series_is_drawn_flat_at_the_floor(self) -> None:
        # A sparkline shows change; with no range there is none, and inventing a mid-height bar
        # would claim a scale that does not exist. The caller labels the absolute value.
        self.assertEqual(gn_tui.sparkline([4, 4, 4, 4], 4, self.SEVEN), self.SEVEN[0] * 4)

    def test_a_single_value_does_not_claim_a_trend(self) -> None:
        drawn = gn_tui.sparkline([9], 5, self.SEVEN)
        self.assertEqual(len(drawn), 5)
        self.assertEqual(drawn, "    " + self.SEVEN[0])

    def test_the_newest_sample_is_always_the_rightmost_cell(self) -> None:
        # So "now" does not walk across the panel as history accumulates.
        drawn = gn_tui.sparkline([0, 6], 6, self.SEVEN, lo=0, hi=6)
        self.assertEqual(drawn, "    " + self.SEVEN[0] + self.SEVEN[6])

    def test_more_values_than_cells_keeps_the_most_recent(self) -> None:
        drawn = gn_tui.sparkline([6, 6, 6, 0, 0], 2, self.SEVEN, lo=0, hi=6)
        self.assertEqual(drawn, self.SEVEN[0] * 2)

    def test_a_missing_sample_is_a_gap_never_a_floor(self) -> None:
        # "the host would not tell us" and "we measured zero" are different claims.
        drawn = gn_tui.sparkline([6, None, 6], 3, self.SEVEN, lo=0, hi=6)
        self.assertEqual(drawn, f"{self.SEVEN[6]} {self.SEVEN[6]}")
        self.assertEqual(gn_tui.sparkline([float("nan"), float("inf")], 2, self.SEVEN), "  ")

    def test_explicit_bounds_win_and_out_of_range_values_clamp(self) -> None:
        drawn = gn_tui.sparkline([-50, 0, 500], 3, self.SEVEN, lo=0, hi=100)
        self.assertEqual(drawn, self.SEVEN[0] + self.SEVEN[0] + self.SEVEN[6])

    def test_an_empty_series_is_blank_at_the_right_width(self) -> None:
        self.assertEqual(gn_tui.sparkline([], 5, self.SEVEN), "     ")
        self.assertEqual(gn_tui.sparkline(None, 5, self.SEVEN), "     ")

    def test_it_never_raises_whatever_it_is_handed(self) -> None:
        for values, width, glyphs in (
            (["nonsense", object()], 4, self.SEVEN),
            ([1, 2], 0, self.SEVEN),
            ([1, 2], "wide", self.SEVEN),
            ([1, 2], 4, ()),
            ([1, 2], 4, ""),
            (object(), 4, self.SEVEN),
        ):
            with self.subTest(values=repr(values)[:20], width=width, glyphs=len(glyphs) if glyphs else 0):
                self.assertIsInstance(gn_tui.sparkline(values, width, glyphs), str)


class GlyphTierTests(_Env):
    def test_every_tier_encodes_under_the_codec_it_exists_for(self) -> None:
        # A loop, not just a check of the last tier: test_gn_fx only checks the backstop, so a
        # typo'd middle tier would slip straight through.
        for name, codec in (("rich", "utf-8"), ("box", "cp437"), ("ascii", "ascii")):
            with self.subTest(tier=name, codec=codec):
                entry = next(e for e in gn_tui._TIERS if e["name"] == name)
                gn_tui._probe_text(entry).encode(codec)   # raises if not

    def test_the_last_tier_is_pure_ascii(self) -> None:
        entry = gn_tui._TIERS[-1]
        (gn_tui._probe_text(entry) + str(entry["braille"])).encode("ascii")

    def test_the_probe_picks_the_richest_tier_the_stream_can_encode(self) -> None:
        for encoding, expected in (("utf-8", "rich"), ("cp437", "box"), ("cp850", "box"),
                                   ("cp1252", "ascii"), ("ascii", "ascii")):
            with self.subTest(encoding=encoding):
                self.assertEqual(gn_tui.tier(_tty(encoding))["name"], expected)

    def test_a_stream_with_no_encoding_at_all_still_gets_a_tier(self) -> None:
        self.assertEqual(gn_tui.tier(io.StringIO())["name"], "ascii")

    def test_braille_is_off_by_default_even_on_utf8(self) -> None:
        # gn_cli reconfigures both streams to UTF-8, so the encode probe ALWAYS says yes in a real
        # gn process — it cannot see that Consolas has no U+28xx glyphs.
        self.assertEqual(gn_tui.tier(_tty("utf-8"))["braille"], "")

    def test_braille_is_available_as_an_explicit_opt_in(self) -> None:
        self.setenv("GN_DASH_GLYPHS", "braille")
        picked = gn_tui.tier(_tty("utf-8"))
        self.assertEqual(picked["name"], "rich")
        self.assertEqual(picked["braille"], "⣿")

    def test_the_override_can_force_a_tier_down(self) -> None:
        # The real use: the codec is fine but the FONT is not, and only the operator can see that.
        self.setenv("GN_DASH_GLYPHS", "ascii")
        self.assertEqual(gn_tui.tier(_tty("utf-8"))["name"], "ascii")
        self.setenv("GN_DASH_GLYPHS", "box")
        self.assertEqual(gn_tui.tier(_tty("utf-8"))["name"], "box")

    def test_the_override_cannot_force_a_glyph_the_codec_cannot_represent(self) -> None:
        # That is not a font question, it is a UnicodeEncodeError mid-frame — a still screen.
        self.setenv("GN_DASH_GLYPHS", "rich")
        self.assertEqual(gn_tui.tier(_tty("cp437"))["name"], "box")
        self.setenv("GN_DASH_GLYPHS", "braille")
        picked = gn_tui.tier(_tty("cp437"))
        self.assertEqual(picked["name"], "box")
        self.assertEqual(picked["braille"], "")

    def test_an_unrecognised_override_falls_through_to_the_probe(self) -> None:
        self.setenv("GN_DASH_GLYPHS", "emoji")
        self.assertEqual(gn_tui.tier(_tty("utf-8"))["name"], "rich")

    def test_the_caller_gets_a_copy_it_cannot_corrupt(self) -> None:
        picked = gn_tui.tier(_tty("utf-8"))
        picked["bars"] = ("x",)
        self.assertEqual(gn_tui.tier(_tty("utf-8"))["bars"], gn_tui._TIERS[0]["bars"])

    def test_every_tier_carries_the_same_shape(self) -> None:
        for entry in gn_tui._TIERS:
            with self.subTest(tier=entry["name"]):
                self.assertEqual(len(entry["box"]), 8)
                self.assertGreaterEqual(len(entry["bars"]), 3)
                self.assertTrue(entry["dot"] and entry["tick"])


class ScreenTests(_Env):
    def _screen(self, cols: int = 40, rows: int = 6):  # noqa: ANN202
        stream = _tty()
        screen = gn_tui.Screen(stream, active=True, size=gn_tui.Size(cols, rows))
        screen.acquire()
        self.addCleanup(screen.restore)
        return stream, screen

    def test_entering_takes_the_alt_screen_and_hides_the_cursor_in_one_write(self) -> None:
        stream = _tty()
        screen = gn_tui.Screen(stream, active=True, size=gn_tui.Size(40, 6))
        screen.acquire()
        self.addCleanup(screen.restore)
        self.assertEqual(stream.writes, ["\033[?1049h\033[2J\033[H\033[?25l"])

    def test_entering_twice_is_a_no_op(self) -> None:
        stream, screen = self._screen()
        writes = len(stream.writes)
        screen.acquire()
        self.assertEqual(len(stream.writes), writes)

    def test_a_frame_is_one_write_and_one_flush(self) -> None:
        stream, screen = self._screen()
        writes, flushes = len(stream.writes), stream.flushes
        screen.frame(["one", "two", "three"])
        self.assertEqual(len(stream.writes) - writes, 1, "a frame delivered in pieces tears")
        self.assertEqual(stream.flushes - flushes, 1)

    def test_only_the_rows_that_changed_are_repainted(self) -> None:
        stream, screen = self._screen()
        screen.frame(["alpha", "beta", "gamma"])
        stream.writes.clear()
        screen.frame(["alpha", "BETA", "gamma"])
        self.assertEqual(len(stream.writes), 1)
        painted = stream.writes[0]
        self.assertIn("\033[2;1HBETA\033[K", painted)
        self.assertNotIn("alpha", painted)
        self.assertNotIn("gamma", painted)

    def test_an_unchanged_frame_writes_nothing_at_all(self) -> None:
        stream, screen = self._screen()
        screen.frame(["alpha", "beta"])
        stream.writes.clear()
        flushes = stream.flushes
        screen.frame(["alpha", "beta"])
        self.assertEqual(stream.writes, [])
        self.assertEqual(stream.flushes, flushes)

    def test_rows_that_vanish_are_cleared_rather_than_left_behind(self) -> None:
        stream, screen = self._screen()
        screen.frame(["alpha", "beta", "gamma"])
        stream.writes.clear()
        screen.frame(["alpha"])
        painted = stream.writes[0]
        self.assertIn("\033[2;1H\033[K", painted)
        self.assertIn("\033[3;1H\033[K", painted)

    def test_the_bottom_row_stops_one_cell_short(self) -> None:
        # Writing the bottom-right cell scrolls conhost by a line, which shifts every row out from
        # under the diff and leaves the frame permanently one line off.
        stream, screen = self._screen(cols=10, rows=3)
        screen.frame(["0123456789", "0123456789", "0123456789"])
        painted = "".join(stream.writes)
        self.assertIn("\033[1;1H0123456789\033[K", painted)
        self.assertIn("\033[3;1H012345678\033[K", painted)
        self.assertNotIn("\033[3;1H0123456789", painted)

    def test_a_row_longer_than_the_terminal_is_truncated_not_wrapped(self) -> None:
        stream, screen = self._screen(cols=8, rows=3)
        screen.frame(["\033[31mthis row is far too long\033[0m"])
        row = stream.writes[-1]
        body = row.split("H", 1)[1].rsplit("\033[K", 1)[0]
        self.assertEqual(gn_tui.visible_len(body), 8)

    def test_extra_rows_beyond_the_terminal_are_dropped(self) -> None:
        stream, screen = self._screen(cols=20, rows=3)
        screen.frame([f"row{index}" for index in range(10)])
        self.assertNotIn("row3", "".join(stream.writes))

    def test_the_cursor_is_parked_last(self) -> None:
        stream, screen = self._screen(cols=20, rows=4)
        screen.frame(["a", "b", "c", "> "], cursor=(4, 3))
        self.assertTrue(stream.writes[-1].endswith("\033[4;3H"))

    def test_the_cursor_is_re_parked_even_when_no_row_changed(self) -> None:
        stream, screen = self._screen(cols=20, rows=4)
        screen.frame(["a", "b", "c", "> x"], cursor=(4, 4))
        stream.writes.clear()
        screen.frame(["a", "b", "c", "> x"], cursor=(4, 5))
        self.assertEqual(stream.writes, ["\033[4;5H"])

    def test_a_resize_forces_a_full_repaint(self) -> None:
        stream, screen = self._screen(cols=20, rows=4)
        screen.frame(["a", "b"])
        self.assertFalse(screen.take_resize())
        screen._resized.set()                 # what SIGWINCH does, and nothing more
        self.assertTrue(screen.take_resize())
        stream.writes.clear()
        screen.frame(["a", "b"])
        painted = stream.writes[0]
        self.assertIn("\033[1;1Ha\033[K", painted)
        self.assertIn("\033[2;1Hb\033[K", painted)

    def test_a_resize_is_noticed_without_sigwinch(self) -> None:
        # Windows has no SIGWINCH at all, and Windows is the primary runtime target.
        stream = _tty()
        sizes = [gn_tui.Size(80, 24), gn_tui.Size(100, 30)]
        self.patch(gn_tui, "terminal_size", lambda *_a, **_k: sizes[-1])
        screen = gn_tui.Screen(stream, active=True)
        screen.acquire()
        self.addCleanup(screen.restore)
        self.assertFalse(screen.take_resize())
        sizes.append(gn_tui.Size(120, 40))
        self.assertTrue(screen.take_resize())
        self.assertEqual(screen.size(), gn_tui.Size(120, 40))

    def test_a_dead_stream_mid_frame_does_not_raise(self) -> None:
        stream, screen = self._screen()
        stream.close()          # the pipe went away
        screen.frame(["one", "two"])
        screen.frame(["three"])
        self.assertFalse(screen.active, "a dead stream should stop the drawing, not the hunt")

    def test_a_pinned_size_is_never_re_measured(self) -> None:
        def _angry(*_args, **_kwargs):  # noqa: ANN202
            raise AssertionError("a pinned screen measured the terminal")

        stream, screen = self._screen(cols=30, rows=5)
        self.patch(gn_tui, "terminal_size", _angry)
        self.assertEqual(screen.size(), gn_tui.Size(30, 5))
        self.assertFalse(screen.take_resize())


class TotalityTests(_Env):
    """Nothing here may raise, and nothing may be left holding the terminal."""

    def test_a_full_lifecycle_against_a_hostile_stream(self) -> None:
        class _Hostile(io.StringIO):
            def isatty(self) -> bool:
                return True

            def write(self, _text):  # noqa: ANN001, ANN202
                raise OSError("the terminal went away")

            def flush(self) -> None:
                raise OSError("the terminal went away")

        _Hostile.encoding = "utf-8"
        stream = _Hostile()
        screen = gn_tui.Screen(stream, active=True, size=gn_tui.Size(40, 6))
        screen.acquire()
        screen.frame(["a", "b"])
        screen.take_resize()
        screen.restore()

    def test_no_module_level_call_touches_a_real_terminal_on_import(self) -> None:
        # Importing gn_tui must be free: gn_cli imports it on a code path that may be `gn hunt`.
        self.assertEqual(gn_tui._LIVE, [])

    def test_the_teardown_string_shows_the_cursor_twice_and_ends_with_it(self) -> None:
        # Pinned separately from the byte-exact test because the reason is subtle: leaving the alt
        # screen restores the main screen's saved cursor state, which is the hidden one we left.
        self.assertEqual(gn_tui._TEARDOWN.count("\033[?25h"), 2)
        self.assertTrue(gn_tui._TEARDOWN.endswith("\033[?25h"))
        self.assertLess(gn_tui._TEARDOWN.index("\033[0m"), gn_tui._TEARDOWN.index("\033[?1049l"))


if __name__ == "__main__":
    unittest.main()
