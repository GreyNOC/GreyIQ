"""Terminal primitives for the full-screen ``gn dash`` — the half whose job is giving the terminal back.

``gn_fx`` owns one line and leaves everything else alone; its worst failure is a smear on the row the
shell prompt is about to overwrite. A dashboard takes the whole screen, the cursor and the keyboard,
so the interesting property here is not what it draws but that the operator always gets them back. A
shell left in cbreak, with the cursor hidden and the alternate screen still up, looks like a hung
machine — and the operator's fix for a hung machine is to close the window, which takes the hunt with
it. Every rule below is a failure this module exists to prevent:

  * **Nothing is drawn unless a human is watching both ends.** :func:`enabled` CALLS
    ``gn_fx.enabled(out)`` instead of re-deriving NO_COLOR/GN_NO_FX/TERM, so that policy keeps one
    home and a fix there fixes both; it then ANDs ``stdin.isatty()`` — a dashboard nobody can type
    into is a screensaver, and ``termios.tcgetattr`` on a pipe raises — and ``GN_NO_DASH``. A pipe, a
    redirect, a CI log and this suite get not one byte. Especially not ``\\033[?1049h``: an alt-screen
    switch written into a redirected file is invisible corruption of someone's output.
  * **cbreak, never raw.** Raw mode clears ISIG, so Ctrl-C stops raising and ``gn_cli.main``'s
    ``KeyboardInterrupt`` handler never runs. A dashboard that swallowed Ctrl-C would leave the
    operator no way to stop a running hunt except killing the window.
  * **Teardown is one write, idempotent, and total.** The screen half is a single string and a single
    flush, so a partially-written restore cannot exist; every write, every ``ctypes`` call and every
    ``termios`` call is individually guarded, because teardown runs in a ``finally`` and must not be
    able to change the exit code an operator's script reads. It is reachable three ways — the
    caller's ``ExitStack``, :func:`teardown_all` from ``gn_cli.main``'s ``finally``, and ``atexit`` —
    and running it three times must restore exactly once. ``os._exit`` and SIGKILL are not
    interceptable: after those the terminal stays broken, and nothing here can pretend otherwise.
  * **The Windows console is configured with ctypes, without ``ctypes.wintypes``.** ``wintypes`` is
    in the frozen bundle only because something else drags it in; it is not in the spec's
    ``hiddenimports``, so importing it here would ship in dev and vanish from the exe. ``DWORD`` is
    ``c_uint32`` and ``BOOL`` is ``c_int`` — layout-identical. ``GetStdHandle.restype`` is
    ``c_void_p`` because the default ``int`` restype truncates a handle above 2GB into garbage.
  * **Every platform branch sits behind an injectable module-level seam** (``_kernel32``,
    ``_msvcrt``, ``termios``). CI is a single ubuntu job, so a Windows-only branch that is not
    drivable from Linux ships unexercised — which is exactly how the two Windows-only failures in
    ``b5f7efc`` reached a release gate.

No panels, no telemetry, no HTTP: those are ``gn_dash``'s. This module knows about bytes, keys and
sizes, and nothing about hunting.
"""
from __future__ import annotations

import atexit
import os
import re
import shutil
import signal
import sys
import threading
import time
from typing import Any, NamedTuple, Sequence, TextIO

import gn_fx

# --- platform seams -------------------------------------------------------------------------------
# Imported here, once, and referenced through the module globals everywhere below, so a test on
# Linux can put a fake in front of the Windows path (and vice versa) without touching sys.modules.

try:  # POSIX. ``tty`` imports ``termios`` at module scope, so it MUST share this guard: split them
    import termios  # noqa: E401  # and the `import tty` line alone raises ImportError on Windows.
    import tty
except Exception:  # noqa: BLE001 - Windows, or a build without the extension
    termios = None  # type: ignore[assignment]
    tty = None  # type: ignore[assignment]

try:
    import select
except Exception:  # noqa: BLE001
    select = None  # type: ignore[assignment]

try:
    import msvcrt as _msvcrt
except Exception:  # noqa: BLE001 - every non-Windows platform
    _msvcrt = None  # type: ignore[assignment]

try:
    import ctypes
except Exception:  # noqa: BLE001 - a stripped build with no _ctypes
    ctypes = None  # type: ignore[assignment]

_STD_INPUT_HANDLE = -10
_STD_OUTPUT_HANDLE = -11
_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_ENABLE_QUICK_EDIT_MODE = 0x0040
_ENABLE_EXTENDED_FLAGS = 0x0080

#: ``DWORD``/``BOOL`` without ``ctypes.wintypes`` — see the module docstring for why that import is
#: not available to us in the frozen bundle.
_DWORD = ctypes.c_uint32 if ctypes is not None else None

_kernel32: Any = None
if ctypes is not None and os.name == "nt":
    try:
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # argtypes matter as much as restype: with none set, ctypes passes a Python int as a C int
        # and a console handle above 2GB is silently truncated to a handle that is not ours.
        _kernel32.GetStdHandle.argtypes = (ctypes.c_int,)
        _kernel32.GetStdHandle.restype = ctypes.c_void_p
        _kernel32.GetConsoleMode.argtypes = (ctypes.c_void_p, ctypes.POINTER(_DWORD))
        _kernel32.GetConsoleMode.restype = ctypes.c_int
        _kernel32.SetConsoleMode.argtypes = (ctypes.c_void_p, _DWORD)
        _kernel32.SetConsoleMode.restype = ctypes.c_int
    except Exception:  # noqa: BLE001 - no kernel32 means we simply do not manage the console
        _kernel32 = None

# --- screen bytes ---------------------------------------------------------------------------------
#: Alternate screen, cleared, cursor hidden — one write, so a half-entered screen cannot exist.
_ENTER = "\033[?1049h\033[2J\033[H\033[?25l"

#: The exact teardown sequence, in this order, as ONE write and one flush:
#: show cursor · reset SGR · reset the scroll region · leave the alt screen · show cursor AGAIN.
#: The second show is not a typo. Leaving the alt screen restores the main screen's saved cursor
#: state, which on several terminals is the hidden state we left behind when we entered — so the
#: operator gets their scrollback back with no cursor in it, which reads as a frozen shell.
_TEARDOWN = "\033[?25h\033[0m\033[r\033[?1049l\033[?25h"

_ANSI_RE = re.compile(r"\033\[[0-9;?]*[A-Za-z]")
_RESET = "\033[0m"

_WIN_POLL_SECONDS = 0.01      # a tight kbhit() spin burns a whole core for the length of a hunt
_ESCAPE_SECONDS = 0.02        # long enough to catch the rest of an arrow key, short enough that a
                              # pressed Escape does not feel stuck


class Size(NamedTuple):
    cols: int
    rows: int


_DEFAULT_SIZE = Size(80, 24)
#: A reading beyond this is not a terminal, it is a bad ioctl: every row string is built to `cols`,
#: so a nonsense value should cost a squashed frame rather than a multi-gigabyte allocation.
_MAX_SIZE = Size(2000, 1000)

# --- the teardown registry ------------------------------------------------------------------------
#: Everything holding a piece of the operator's terminal. Deliberately SEPARATE from ``gn_fx._LIVE``:
#: a pane command may call ``gn_fx.stop_all()`` because the verb it ran started a Scanner, and that
#: must not be able to tear down the dashboard the operator is looking at.
_LIVE: list[Any] = []
_LIVE_LOCK = threading.Lock()


def _register(item: Any) -> None:
    with _LIVE_LOCK:
        if item not in _LIVE:
            _LIVE.append(item)


def _deregister(item: Any) -> None:
    with _LIVE_LOCK:
        try:
            _LIVE.remove(item)
        except ValueError:
            pass


def teardown_all() -> None:
    """Restore everything still holding the terminal. Total and idempotent — safe in a ``finally``.

    Drained in REVERSE acquisition order, which is the whole point: the screen must leave the alt
    screen before the key reader hands the tty back, or the restored ``termios`` settings apply to a
    screen the operator cannot see.
    """
    with _LIVE_LOCK:
        live, _LIVE[:] = list(_LIVE), []
    for item in reversed(live):
        try:
            item.restore()
        except Exception:  # noqa: BLE001 - cleanup must not raise over the real result
            pass


atexit.register(teardown_all)


# --- policy ---------------------------------------------------------------------------------------
def _truthy_off(name: str) -> bool:
    """``GN_NO_DASH`` accepts exactly the vocabulary ``GN_NO_FX`` does (``gn_fx._truthy_off``).

    Duplicated rather than imported because it is six characters of parsing, but the two MUST stay
    in step: an operator who learned that ``GN_NO_FX=true`` works and then finds ``GN_NO_DASH=true``
    ignored has been handed a silent opt-out that does not opt out. A test pins the pair.
    """
    return str(os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _isatty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001 - a stream that cannot answer is not a terminal
        return False


def enabled(out: TextIO | None = None, inp: TextIO | None = None) -> bool:
    """Whether a full-screen dashboard is appropriate for this invocation.

    ``out`` defaults to **stdout**, not stderr: ``gn dash … > file`` has to behave exactly like
    ``gn hunt``, and the only way that holds is if the redirected stream is the one being asked.
    ``inp`` defaults to stdin, because a dashboard with no keyboard cannot be quit.

    The colour/motion half is delegated to ``gn_fx.enabled`` rather than re-derived — see the module
    docstring — so ``NO_COLOR``, ``GN_NO_FX`` and ``TERM=dumb`` turn the dashboard off for free, and
    a future correction to that rule corrects this one too.
    """
    out = sys.stdout if out is None else out
    inp = sys.stdin if inp is None else inp
    if _truthy_off("GN_NO_DASH"):
        return False
    if not _isatty(inp):
        return False
    try:
        return bool(gn_fx.enabled(out))
    except Exception:  # noqa: BLE001 - an unanswerable stream is not a terminal
        return False


def refusal(out: TextIO | None = None, inp: TextIO | None = None) -> str:
    """One sentence for ``_err()`` naming WHICH condition refused, or ``""`` when enabled.

    ``gn fx`` set the precedent (gn_fx.demo): a verb that silently does nothing is indistinguishable
    from a verb that is broken. The conditions are tested in the order an operator can act on them,
    and the sentence carries no ``gn:`` prefix because ``_err`` adds one.
    """
    out = sys.stdout if out is None else out
    inp = sys.stdin if inp is None else inp
    if _truthy_off("GN_NO_DASH"):
        return "the dashboard is turned off by GN_NO_DASH in this shell."
    if not _isatty(out):
        return "the dashboard needs a terminal on stdout, and stdout is redirected here."
    if not _isatty(inp):
        return "the dashboard needs a keyboard, and stdin is not a terminal here."
    try:
        if gn_fx.enabled(out):
            return ""
    except Exception:  # noqa: BLE001
        return "this stream could not answer whether it is a terminal."
    if os.getenv("NO_COLOR") is not None:
        return "NO_COLOR is set, and a dashboard is nothing but escape sequences."
    if _truthy_off("GN_NO_FX"):
        return "GN_NO_FX is set, which turns off the dashboard along with the status line."
    if str(os.getenv("TERM") or "").strip().lower() == "dumb":
        return "TERM=dumb asks for no escape sequences, and a dashboard cannot honour that."
    return "this terminal does not support the cursor control a dashboard needs (check TERM)."


# --- measurement ----------------------------------------------------------------------------------
def terminal_size(stream: TextIO | None = None, fallback: Sequence[int] = _DEFAULT_SIZE) -> Size:
    """The size of the terminal THIS STREAM is attached to.

    ``os.get_terminal_size(stream.fileno())`` first, deliberately not ``shutil`` first: shutil reads
    ``COLUMNS``/``LINES`` and then ``sys.__stdout__``, never the stream we are drawing to, and
    ``gn_fx.enabled`` exists precisely because stdout and stderr are redirected independently. A
    dashboard sized from the wrong stream wraps every row and scrolls its own frame away.

    ``(AttributeError, ValueError, OSError)`` is one tuple that also covers a ``StringIO`` test
    harness: ``io.UnsupportedOperation`` subclasses both ``OSError`` and ``ValueError``.
    """
    stream = sys.stdout if stream is None else stream
    try:
        low = Size(max(1, int(fallback[0])), max(1, int(fallback[1])))
    except Exception:  # noqa: BLE001 - a caller's bad fallback must not be the reason nothing draws
        low = _DEFAULT_SIZE

    def _from_stream() -> Any:
        return os.get_terminal_size(stream.fileno())

    def _from_shutil() -> Any:
        return shutil.get_terminal_size((low.cols, low.rows))

    for probe in (_from_stream, _from_shutil):
        try:
            got = probe()
            cols, rows = int(got[0]), int(got[1])
        except (AttributeError, ValueError, OSError, TypeError, IndexError):
            continue
        if cols > 0 and rows > 0:
            return Size(min(cols, _MAX_SIZE.cols), min(rows, _MAX_SIZE.rows))
    return low


def visible_len(text: str) -> int:
    """Length in cells, ignoring ANSI escapes.

    ``gn_cli._pad`` learned this the expensive way: ``f"{coloured:<28}"`` pads the escape bytes as if
    they were content, so every column came out nine characters short with colour on and perfect in
    the tests, which capture through StringIO and never colour at all. At screen scale the same
    mistake wraps a row, and a wrapped row scrolls the whole frame.

    Counts codepoints, so a double-width CJK glyph is under-counted by one cell. Nothing this module
    draws is wide; a target name that is would run one cell long per character, which is a known and
    accepted limit rather than a hidden one.
    """
    return len(_ANSI_RE.sub("", str(text)))


def _truncate_visible(text: str, limit: int) -> str:
    """Cut ``text`` to ``limit`` visible cells without cutting an escape sequence in half.

    A sequence chopped mid-flight is not a shortened row, it is literal garbage on screen (``[3` and
    the rest) plus a terminal left in whatever mode the fragment implied.
    """
    if limit <= 0:
        return ""
    if "\033" not in text and len(text) <= limit and text.isprintable():
        return text
    out: list[str] = []
    visible = 0
    index = 0
    escaped = False
    length = len(text)
    while index < length:
        match = _ANSI_RE.match(text, index)
        if match:
            out.append(match.group(0))
            escaped = True
            index = match.end()
            continue
        if visible >= limit:
            break
        char = text[index]
        # A newline or a carriage return inside a row would scroll the frame out from under the
        # row-diff, so the next repaint would draw onto the wrong lines forever.
        out.append(" " if char in "\n\r\t\v\f" else char)
        visible += 1
        index += 1
    result = "".join(out)
    if escaped and not result.endswith(_RESET):
        result += _RESET
    return result


def _sparkline(values: Sequence[Any], cells: int, glyphs: Sequence[str],
               lo: float | None, hi: float | None) -> str:
    series = list(values or ())[-cells:]
    numbers: list[float | None] = []
    for value in series:
        try:
            number = float(value)
        except (TypeError, ValueError):
            numbers.append(None)
            continue
        # NaN and infinity are not measurements; they render as a gap, never as a floor.
        numbers.append(None if (number != number or number in (float("inf"), float("-inf"))) else number)
    real = [n for n in numbers if n is not None]
    if not real:
        return " " * cells
    try:
        low = min(real) if lo is None else float(lo)
        high = max(real) if hi is None else float(hi)
    except (TypeError, ValueError):
        low, high = min(real), max(real)
    if high < low:
        low, high = high, low
    span = high - low
    top = len(glyphs) - 1
    out: list[str] = []
    for number in numbers:
        if number is None:
            out.append(" ")
        elif span <= 0:
            out.append(glyphs[0])
        else:
            index = int(round(((number - low) / span) * top))
            out.append(glyphs[max(0, min(top, index))])
    return "".join(out).rjust(cells)


def sparkline(values: Sequence[Any], width: int, glyphs: Sequence[str], *,
              lo: float | None = None, hi: float | None = None) -> str:
    """A ``width``-cell sparkline of ``values`` drawn with the ``glyphs`` ladder, low to high.

    Resolution comes from ``len(glyphs)`` — 7 blocks, 3 shades or 4 ASCII rungs depending on what the
    stream can encode — and is never hardcoded to eighths, because the ``box`` tier has three levels
    and an eighths calculation there would index off the end of the ladder every frame.

    Right-aligned: the newest sample is always the rightmost cell, so "now" does not walk across the
    panel as history accumulates. A value that is not a number (a probe that returned ``None``, a NaN)
    is a BLANK cell, never the floor glyph — a gap in the record and a measured zero are different
    claims. With no range to show (one sample, or a flat series) every cell is the floor glyph: a
    sparkline shows change, and the caller labels the absolute value beside it.
    """
    try:
        cells = max(0, int(width))
    except Exception:  # noqa: BLE001
        return ""
    if cells <= 0:
        return ""
    ladder = tuple(glyphs or ())
    if not ladder:
        return " " * cells
    try:
        return _sparkline(values, cells, ladder, lo, hi)
    except Exception:  # noqa: BLE001 - a panel decoration may never be the reason a frame dies
        return " " * cells


# --- glyph tiers ----------------------------------------------------------------------------------
#: Three tiers, probed against the live stream's encoding. ``gn_fx`` has two, and the gap between
#: them is the problem: a cp437/cp850 console encodes the box-drawing set and the ``░▒▓`` shades
#: perfectly well but has no ``▁▂▃▄▅▆▇``, and gn_fx's table drops such a console all the way to
#: ``-`` and ``|``. The ``box`` tier is that missing middle.
_TIERS: tuple[dict[str, Any], ...] = (
    {"name": "rich",  "box": ("┌", "┐", "└", "┘", "─", "│", "├", "┤"),
                      "bars": ("▁", "▂", "▃", "▄", "▅", "▆", "▇"), "braille": "⣿", "dot": "·", "tick": "●"},
    {"name": "box",   "box": ("┌", "┐", "└", "┘", "─", "│", "├", "┤"),
                      "bars": ("░", "▒", "▓"), "braille": "", "dot": ".", "tick": "*"},
    {"name": "ascii", "box": ("+", "+", "+", "+", "-", "|", "+", "+"),
                      "bars": ("_", ".", ":", "|"), "braille": "", "dot": ".", "tick": "*"},
)

_TIER_NAMES: tuple[str, ...] = tuple(str(entry["name"]) for entry in _TIERS)


def _probe_text(entry: dict[str, Any]) -> str:
    """Every glyph a tier draws by default. ``braille`` is excluded deliberately: it is opt-in, and
    including it here would drop a UTF-8 console whose codec lacks U+28xx out of the rich tier over
    a glyph it was never going to be sent."""
    parts = []
    for key in ("box", "bars", "dot", "tick"):
        value = entry.get(key)
        parts.append("".join(value) if isinstance(value, tuple) else str(value or ""))
    return "".join(parts)


def _encodable(text: str, encoding: str) -> bool:
    if not text:
        return True
    try:
        text.encode(encoding, errors="strict")
    except (UnicodeEncodeError, LookupError, TypeError):
        return False
    return True


def tier(stream: TextIO | None = None) -> dict:
    """The richest glyph tier this stream can actually encode, as a fresh dict.

    **Braille is off by default even on UTF-8.** ``gn_cli`` reconfigures both streams to UTF-8 at
    import, so the encode probe always answers yes in a real ``gn`` process — it cannot see that
    Consolas has no U+28xx glyphs. Defaulting to braille would ship a wall of empty boxes to every
    Windows operator, and the probe would report success while doing it. ``GN_DASH_GLYPHS=braille``
    is the opt-in for a terminal whose font the operator has actually checked.

    ``GN_DASH_GLYPHS=rich|box|ascii`` forces a tier, which is how an operator overrules the probe
    when the codec is fine but the FONT is not. It cannot force a tier the codec cannot represent:
    that is not a font question, it is a ``UnicodeEncodeError`` mid-frame, and the worst failure
    mode here is a still screen. An unrecognised value falls through to the probe.
    """
    stream = sys.stdout if stream is None else stream
    encoding = str(getattr(stream, "encoding", None) or "ascii")
    requested = str(os.getenv("GN_DASH_GLYPHS") or "").strip().lower()
    want_braille = requested == "braille"
    if want_braille:
        requested = "rich"

    chosen: dict[str, Any] | None = None
    if requested in _TIER_NAMES:
        chosen = next((e for e in _TIERS if e["name"] == requested and _encodable(_probe_text(e), encoding)), None)
    if chosen is None:
        chosen = next((e for e in _TIERS if _encodable(_probe_text(e), encoding)), None)
    if chosen is None:
        chosen = _TIERS[-1]

    result = dict(chosen)
    braille = str(chosen.get("braille") or "")
    result["braille"] = braille if (want_braille and braille and _encodable(braille, encoding)) else ""
    return result


# --- Windows console ------------------------------------------------------------------------------
def _bad_handle(handle: Any) -> bool:
    """``GetStdHandle`` with a ``c_void_p`` restype answers ``None`` for NULL and the UNSIGNED form
    of ``INVALID_HANDLE_VALUE`` for a process with no console, so neither ever shows up as ``-1``."""
    if handle is None:
        return True
    try:
        value = int(handle)
    except Exception:  # noqa: BLE001
        return True
    return value in (0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)


class WinConsole:
    """Probe, set and restore the Windows console modes. Completely inert off Windows.

    Two changes, both of which an operator notices only when they are missing:

      * **stdout** gets ``ENABLE_VIRTUAL_TERMINAL_PROCESSING``, and only if it is not already on.
        Without it every escape sequence is printed literally.
      * **stdin** gets ``ENABLE_QUICK_EDIT_MODE`` cleared and ``ENABLE_EXTENDED_FLAGS`` set (the
        flag is what makes the clear take effect at all). Quick-edit is on by default, and one stray
        click-drag in the console puts it into selection mode, which freezes ALL console output. The
        dashboard stops repainting, the hunt keeps running, and it reads as a hang.

    ``vt_state`` names what happened, for ``gn dash --self-test``: ``unmanaged`` (no console API
    here — POSIX, or kernel32 would not load), ``no-console`` (a pipe or a pty such as mintty: there
    is no console mode to query and ANSI is the pty's business), ``already-on``, ``enabled``, or
    ``unavailable``. ``vt_enabled`` is False ONLY for ``unavailable`` — a real console that refused.
    Unknown is not the same as no: refusing on a mintty, where ANSI works fine and there is simply no
    console behind the handle, would break a terminal that has nothing wrong with it.
    """

    def __init__(self) -> None:
        self._saved: list[tuple[Any, int]] = []
        self._restored = threading.Event()
        self.vt_state = "unmanaged"
        self.vt_enabled = True

    def __enter__(self) -> "WinConsole":
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.restore()

    def acquire(self) -> "WinConsole":
        if _kernel32 is None:
            self.vt_state, self.vt_enabled = "unmanaged", True
            return self
        self.vt_state, self.vt_enabled = "no-console", True
        _register(self)
        self._configure_output()
        self._configure_input()
        return self

    def restore(self) -> None:
        """Put back the exact mode integers we found. Idempotent, and never raises."""
        if self._restored.is_set():
            return
        self._restored.set()
        saved, self._saved = list(self._saved), []
        for handle, mode in reversed(saved):
            self._set_mode(handle, mode)
        _deregister(self)

    # --- internals ---------------------------------------------------------------------------------
    def _configure_output(self) -> None:
        handle = self._std_handle(_STD_OUTPUT_HANDLE)
        mode = self._get_mode(handle)
        if mode is None:
            return
        if mode & _ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            self.vt_state = "already-on"
            return
        if self._set_mode(handle, mode | _ENABLE_VIRTUAL_TERMINAL_PROCESSING):
            self._saved.append((handle, mode))
            self.vt_state = "enabled"
        else:
            self.vt_state, self.vt_enabled = "unavailable", False

    def _configure_input(self) -> None:
        handle = self._std_handle(_STD_INPUT_HANDLE)
        mode = self._get_mode(handle)
        if mode is None:
            return
        # ENABLE_VIRTUAL_TERMINAL_INPUT is deliberately NOT set: keys are read through msvcrt, which
        # speaks scan codes, and VT input would deliver ESC sequences that _WIN_EXTENDED cannot match.
        want = (mode & ~_ENABLE_QUICK_EDIT_MODE) | _ENABLE_EXTENDED_FLAGS
        if want == mode:
            return
        if self._set_mode(handle, want):
            self._saved.append((handle, mode))

    def _std_handle(self, which: int) -> Any:
        try:
            handle = _kernel32.GetStdHandle(which)
        except Exception:  # noqa: BLE001
            return None
        return None if _bad_handle(handle) else handle

    def _get_mode(self, handle: Any) -> int | None:
        """The console mode, or None when this handle is not a console (a pipe: ERROR_INVALID_HANDLE)."""
        if handle is None or ctypes is None or _DWORD is None:
            return None
        try:
            holder = _DWORD(0)
            if not _kernel32.GetConsoleMode(handle, ctypes.pointer(holder)):
                return None
            return int(holder.value)
        except Exception:  # noqa: BLE001
            return None

    def _set_mode(self, handle: Any, mode: int) -> bool:
        if handle is None:
            return False
        try:
            return bool(_kernel32.SetConsoleMode(handle, int(mode)))
        except Exception:  # noqa: BLE001
            return False


# --- keyboard -------------------------------------------------------------------------------------
#: Both readers normalise to this vocabulary, so ``gn_dash`` never learns which platform it is on.
_CONTROL_KEYS = {
    "\r": "ENTER", "\n": "ENTER", "\t": "TAB",
    "\x7f": "BACKSPACE", "\x08": "BACKSPACE",
    "\x03": "CTRL-C", "\x0c": "CTRL-L", "\x1b": "ESC",
}

_POSIX_KEYS = {
    "[A": "UP", "[B": "DOWN", "[C": "RIGHT", "[D": "LEFT",
    "[H": "HOME", "[F": "END",
    "[1~": "HOME", "[7~": "HOME", "[4~": "END", "[8~": "END",
    "[5~": "PGUP", "[6~": "PGDN",
    # Application cursor mode (DECCKM), which tmux and less both turn on.
    "OA": "UP", "OB": "DOWN", "OC": "RIGHT", "OD": "LEFT", "OH": "HOME", "OF": "END",
}

#: The second byte after a ``\\x00``/``\\xe0`` lead from ``getwch``.
_WIN_EXTENDED = {
    "H": "UP", "P": "DOWN", "K": "LEFT", "M": "RIGHT",
    "G": "HOME", "O": "END", "I": "PGUP", "Q": "PGDN",
}


def _normalise(char: str) -> str | None:
    """A single character as a key name, or None for a control key we do not implement.

    Unimplemented control characters are DROPPED rather than returned literally: Ctrl-A echoed into
    the command line as ``\\x01`` looks like a rendering bug and is invisible to the operator trying
    to delete it.
    """
    if char in _CONTROL_KEYS:
        return _CONTROL_KEYS[char]
    if len(char) == 1 and char < " ":
        return None
    return char or None


class KeyReader:
    """One normalised key per :meth:`read`, or None if the timeout expired.

    Backend selection is by SEAM, not by ``os.name``: ``_msvcrt`` is None on every POSIX build and
    ``termios`` is None on every Windows build, so the ordering is unambiguous in production AND a
    test can drive either branch from either platform by setting the module global. CI is
    ubuntu-only, so without that the entire Windows key path would ship having never run.

    POSIX uses **cbreak, not raw**: raw clears ISIG, Ctrl-C stops raising, and ``gn_cli.main``'s
    ``KeyboardInterrupt`` handler — the operator's way out of a running hunt — never fires.
    """

    def __init__(self, stream: TextIO | None = None, *,
                 poll: float = _WIN_POLL_SECONDS, escape_delay: float = _ESCAPE_SECONDS) -> None:
        self._stream = sys.stdin if stream is None else stream
        self._poll = max(0.001, float(poll))
        self._escape_delay = max(0.0, float(escape_delay))
        self._fd: int | None = None
        self._saved: Any = None
        self._restored = threading.Event()
        self.backend = "msvcrt" if _msvcrt is not None else ("termios" if termios is not None else "none")

    def __enter__(self) -> "KeyReader":
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.restore()

    def acquire(self) -> "KeyReader":
        if self.backend == "termios":
            try:
                self._fd = self._stream.fileno()
                self._saved = termios.tcgetattr(self._fd)
                tty.setcbreak(self._fd)
            except Exception:  # noqa: BLE001 - a stream with no usable fd simply has no reader
                self._fd, self._saved, self.backend = None, None, "none"
                return self
        if self.backend != "none":
            _register(self)
        return self

    def restore(self) -> None:
        """Hand the tty back. Idempotent, and never raises — it runs in a ``finally``."""
        if self._restored.is_set():
            return
        self._restored.set()
        saved, self._saved = self._saved, None
        if saved is not None and self._fd is not None and termios is not None:
            try:
                # TCSADRAIN, not TCSANOW: the last frame must finish going out before the line
                # discipline changes under it.
                termios.tcsetattr(self._fd, termios.TCSADRAIN, saved)
            except Exception:  # noqa: BLE001
                pass
        _deregister(self)

    def read(self, timeout: float = 0.06) -> str | None:
        try:
            deadline = time.monotonic() + max(0.0, float(timeout))
        except (TypeError, ValueError):
            deadline = time.monotonic()
        try:
            if self.backend == "msvcrt":
                return self._read_windows(deadline)
            if self.backend == "termios":
                return self._read_posix(deadline)
        except Exception:  # noqa: BLE001 - a key that cannot be read is a key that was not pressed
            return None
        # No reader at all: still burn the timeout. Returning immediately would turn the caller's
        # "poll input, then maybe repaint" loop into a spin that eats a core for the whole hunt.
        self._sleep(deadline)
        return None

    # --- internals ---------------------------------------------------------------------------------
    def _sleep(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)

    def _read_windows(self, deadline: float) -> str | None:
        while True:
            if _msvcrt.kbhit():
                char = _msvcrt.getwch()
                if char in ("\x00", "\xe0"):
                    try:
                        return _WIN_EXTENDED.get(_msvcrt.getwch())
                    except Exception:  # noqa: BLE001
                        return None
                # getwch can deliver Ctrl-C literally instead of raising, so it is mapped here and
                # gn_dash treats it as quit; there is no SIGINT coming to do it for us.
                return _normalise(char)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(self._poll, remaining))

    def _read_posix(self, deadline: float) -> str | None:
        first = self._read_byte(deadline)
        if first is None:
            return None
        if first != b"\x1b":
            return self._decode(first)
        # Separate a pressed Escape from an arrow key: ESC [ A arrives as one burst, a pressed
        # Escape has nothing behind it. Without the delay, Escape and Up are the same key.
        nxt = self._read_byte(time.monotonic() + self._escape_delay)
        if nxt is None:
            return "ESC"
        sequence = nxt.decode("latin-1")
        if sequence == "[":
            while len(sequence) < 8:
                more = self._read_byte(time.monotonic() + self._escape_delay)
                if more is None:
                    break
                char = more.decode("latin-1")
                sequence += char
                if "@" <= char <= "~":       # the CSI final byte
                    break
        elif sequence == "O":
            more = self._read_byte(time.monotonic() + self._escape_delay)
            if more is not None:
                sequence += more.decode("latin-1")
        # An unrecognised sequence is swallowed. Returning it literally would type "[3~" into the
        # operator's command line, which is worse than ignoring a key we have not implemented.
        return _POSIX_KEYS.get(sequence)

    def _read_byte(self, deadline: float) -> bytes | None:
        if self._fd is None or select is None:
            return None
        remaining = max(0.0, deadline - time.monotonic())
        try:
            ready, _, _ = select.select([self._fd], [], [], remaining)
        except Exception:  # noqa: BLE001 - an EINTR or a closed fd is "no key", not a crash
            return None
        if not ready:
            return None
        try:
            data = os.read(self._fd, 1)
        except Exception:  # noqa: BLE001
            return None
        return data or None

    def _decode(self, first: bytes) -> str | None:
        """Assemble one character, including a multibyte UTF-8 one.

        ``os.read(fd, 1)`` hands back a single BYTE, so a non-ASCII character in a target name typed
        into the command line would otherwise arrive as two or three undecodable fragments.
        """
        lead = first[0]
        if 0xC0 <= lead <= 0xDF:
            extra = 1
        elif 0xE0 <= lead <= 0xEF:
            extra = 2
        elif 0xF0 <= lead <= 0xF7:
            extra = 3
        else:
            extra = 0
        buffer = bytearray(first)
        for _ in range(extra):
            more = self._read_byte(time.monotonic() + self._escape_delay)
            if more is None:
                break
            buffer += more
        try:
            return _normalise(buffer.decode("utf-8"))
        except UnicodeDecodeError:
            return None   # a truncated or mistyped multibyte char: dropped, never echoed


# --- command line ---------------------------------------------------------------------------------
class Rendered(NamedTuple):
    text: str
    caret: int


class CommandLine:
    """The operator's input line: an edit buffer, a history and a scrolling window over it.

    Pure state — it writes nothing and knows nothing about the screen, so every behaviour here is a
    plain unit test rather than something that can only be checked by looking at a terminal.

    :meth:`feed` IGNORES keys it does not own, ``TAB`` and ``CTRL-L`` among them. Tab is ambiguous by
    design (completion when there is a partial verb, switching panes when the line is empty) and that
    is the dashboard's decision, not this buffer's — so the caller inspects the key first.
    """

    def __init__(self, *, history: int = 100) -> None:
        self._text = ""
        self._cursor = 0
        self._history: list[str] = []
        self._limit = max(0, int(history))
        self._browse: int | None = None   # position while walking history; None means the live line
        self._stash = ""                  # the half-typed line, kept while browsing

    @property
    def text(self) -> str:
        return self._text

    @property
    def cursor(self) -> int:
        return self._cursor

    @property
    def history(self) -> tuple[str, ...]:
        return tuple(self._history)

    def set(self, text: str) -> None:
        self._text = str(text or "")
        self._cursor = len(self._text)

    def clear(self) -> None:
        self._text, self._cursor, self._browse, self._stash = "", 0, None, ""

    def feed(self, key: str | None) -> str | None:
        """Apply one key. Returns the submitted line on ENTER, otherwise None.

        An empty ENTER returns ``""``, not None: "the operator pressed enter on a blank line" and
        "nothing happened" are different events, and only the caller knows whether the first one
        means anything.
        """
        if not key:
            return None
        if key == "ENTER":
            line = self._text
            self._remember(line)
            self.clear()
            return line
        if key == "BACKSPACE":
            if self._cursor > 0:
                self._text = self._text[: self._cursor - 1] + self._text[self._cursor:]
                self._cursor -= 1
            return None
        if key == "LEFT":
            self._cursor = max(0, self._cursor - 1)
            return None
        if key == "RIGHT":
            self._cursor = min(len(self._text), self._cursor + 1)
            return None
        if key == "HOME":
            self._cursor = 0
            return None
        if key == "END":
            self._cursor = len(self._text)
            return None
        if key in ("UP", "DOWN"):
            self._walk(-1 if key == "UP" else 1)
            return None
        if key == "ESC":
            self.clear()
            return None
        if len(key) == 1 and key >= " " and key != "\x7f":
            self._text = self._text[: self._cursor] + key + self._text[self._cursor:]
            self._cursor += 1
        return None

    def render(self, width: int) -> Rendered:
        """The visible window and the caret's offset within it, padded to exactly ``width`` cells.

        Returns both because the caller has to park the real cursor under the caret with
        ``\\033[{col}G``; deriving the offset separately would mean duplicating this scroll maths in
        the renderer, and the two copies would disagree the first time either changed.
        """
        try:
            cells = max(1, int(width))
        except (TypeError, ValueError):
            cells = 1
        start = max(0, self._cursor - (cells - 1))
        window = self._text[start:start + cells]
        return Rendered(window.ljust(cells), min(cells - 1, max(0, self._cursor - start)))

    # --- internals ---------------------------------------------------------------------------------
    def _remember(self, line: str) -> None:
        entry = line.strip()
        if not entry or self._limit <= 0:
            return
        if self._history and self._history[-1] == entry:
            return   # holding enter to re-run a verb should not fill the history with one command
        self._history.append(entry)
        del self._history[: max(0, len(self._history) - self._limit)]

    def _walk(self, step: int) -> None:
        if not self._history:
            return
        if self._browse is None:
            if step > 0:
                return
            self._stash = self._text
            self._browse = len(self._history) - 1
        else:
            self._browse += step
        if self._browse < 0:
            self._browse = 0
        if self._browse >= len(self._history):
            self._browse = None
            self.set(self._stash)
            self._stash = ""
            return
        self.set(self._history[self._browse])


# --- screen ---------------------------------------------------------------------------------------
class Screen:
    """The alternate screen, a row-diffed :meth:`frame`, and the teardown that gives it all back.

    Inert unless the stream is a terminal a human is watching — ``active=False`` writes not one byte,
    which is the load-bearing property: ``\\033[?1049h`` written into a redirected file silently
    swallows everything after it into a screen buffer nobody will ever see.
    """

    def __init__(self, stream: TextIO | None = None, *, active: bool | None = None,
                 size: Sequence[int] | None = None, fallback: Sequence[int] = _DEFAULT_SIZE) -> None:
        self._stream = sys.stdout if stream is None else stream
        self._active = enabled(self._stream) if active is None else bool(active)
        self._fallback = fallback
        # A pinned size skips measurement entirely — for a caller that has already measured, and so
        # that the layout tests are not at the mercy of whatever terminal the suite runs under.
        self._fixed = Size(int(size[0]), int(size[1])) if size is not None else None
        self._size = self._fixed or terminal_size(self._stream, self._fallback)
        self._last: list[str] = []
        self._cursor: tuple[int, int] | None = None
        self._entered = False
        self._restored = threading.Event()
        self._resized = threading.Event()
        self._signal: Any = None
        self._prev_winch: Any = None

    @property
    def active(self) -> bool:
        return self._active

    def __enter__(self) -> "Screen":
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.restore()

    def acquire(self) -> "Screen":
        """Enter the alt screen and hide the cursor, then take SIGWINCH. Order matters: teardown
        unwinds it in reverse, and the signal handler must be gone before the screen it refers to."""
        if not self._active or self._entered:
            return self
        self._entered = True
        _register(self)
        self._write(_ENTER)
        self._install_winch()
        return self

    def restore(self) -> None:
        """The exact teardown sequence, once, as one write and one flush. Never raises."""
        if self._restored.is_set():
            return
        self._restored.set()
        if self._entered:
            self._entered = False
            try:
                self._stream.write(_TEARDOWN)
            except Exception:  # noqa: BLE001 - a dead pipe cannot be un-broken; keep unwinding
                pass
            try:
                self._stream.flush()
            except Exception:  # noqa: BLE001
                pass
        self._restore_winch()
        self._last = []
        _deregister(self)

    def _measure(self) -> Size:
        """Measure WITHOUT storing. Separate from :meth:`size` on purpose: folding the two together
        made ``take_resize`` compare the new reading against a ``_size`` it had just overwritten, so
        it answered False through every resize and the frame stayed at the old width for good."""
        if self._fixed is not None:
            return self._fixed
        return terminal_size(self._stream, self._fallback)

    def size(self) -> Size:
        """Re-measure. Called every frame, not once at startup: a tmux pane resized mid-hunt would
        otherwise keep drawing at the old width and wrap every row until the run ended."""
        self._size = self._measure()
        return self._size

    def take_resize(self) -> bool:
        """Whether the terminal changed size since the last check, clearing the flag.

        Checks the SIGWINCH flag AND re-measures, because Windows — the primary runtime target — has
        no SIGWINCH at all, so the flag alone would make the dashboard blind to a resize on the one
        platform it is most likely to be running on. The measurement is an ioctl, cheap enough at the
        60ms input-poll rate. A change invalidates every diffed row, so the next frame repaints in
        full rather than patching rows that have moved.
        """
        changed = self._resized.is_set()
        self._resized.clear()
        current = self._measure()
        if current != self._size:
            self._size = current
            changed = True
        if changed:
            self._last = []
            self._cursor = None
        return changed

    def frame(self, rows: Sequence[str], cursor: tuple[int, int] | None = None) -> None:
        """Paint ``rows``, emitting ONLY the rows that changed, as one write and one flush.

        Repainting a whole screen at 4Hz is visibly slow over conpty or SSH and makes typing feel
        laggy; the diff is what keeps the frame cheap. One write for the same reason ``gn_fx``
        batches: a frame delivered in pieces tears.

        The row on the terminal's last line is capped one cell short. Writing the bottom-right cell
        scrolls conhost by a line, which would shift every row out from under the diff and leave the
        frame permanently one line off.
        """
        if not self._active or not self._entered:
            return
        size = self._size or _DEFAULT_SIZE
        prepared: list[str] = []
        for index in range(min(len(rows), size.rows)):
            cap = size.cols - 1 if index == size.rows - 1 else size.cols
            prepared.append(_truncate_visible(str(rows[index]), max(0, cap)))

        out: list[str] = []
        for index, row in enumerate(prepared):
            if index < len(self._last) and self._last[index] == row:
                continue
            out.append(f"\033[{index + 1};1H{row}\033[K")
        for index in range(len(prepared), len(self._last)):
            if self._last[index]:
                out.append(f"\033[{index + 1};1H\033[K")

        if out or (cursor is not None and cursor != self._cursor):
            if cursor is not None:
                out.append(f"\033[{max(1, int(cursor[0]))};{max(1, int(cursor[1]))}H")
            self._write("".join(out))
        self._last = prepared
        self._cursor = cursor

    # --- internals ---------------------------------------------------------------------------------
    def _write(self, text: str) -> None:
        if not text:
            return
        try:
            self._stream.write(text)
            self._stream.flush()
        except Exception:  # noqa: BLE001 - a closed pager or a killed pane costs the dashboard,
            self._active = False              # never the hunt running underneath it

    def _on_winch(self, _signum: int, _frame: Any) -> None:
        # A signal handler runs between bytecodes on the main thread: set a flag and nothing else.
        self._resized.set()

    def _install_winch(self) -> None:
        sig = getattr(signal, "SIGWINCH", None)
        if sig is None:
            return   # Windows: take_resize() re-measures instead
        try:
            self._prev_winch = signal.signal(sig, self._on_winch)
            self._signal = sig
        except Exception:  # noqa: BLE001 - not the main thread, or a platform that refuses
            self._prev_winch, self._signal = None, None

    def _restore_winch(self) -> None:
        sig, previous = self._signal, self._prev_winch
        self._signal, self._prev_winch = None, None
        if sig is None:
            return
        try:
            # A None previous handler means it was installed from C and cannot be reinstated;
            # SIG_DFL is the honest best effort, and leaving our own handler in place would keep
            # a reference to a torn-down screen alive for the rest of the process.
            signal.signal(sig, previous if previous is not None else signal.SIG_DFL)
        except Exception:  # noqa: BLE001
            pass
