"""Terminal motion for the long-running ``gn`` verbs — the Alpine head-unit dolphin, in a shell.

A hunt, a campaign or a training run can sit silent for a minute at a stretch. Before this, the only
signal was whatever the engine happened to emit, so a working `gn` and a hung `gn` looked identical.
This draws a live animated status line while the work runs: a glyph swimming across a bounded tank
with a fading wake, a scanline sweeping under it, and the phase the engine is actually in — and it
flashes in severity colour when a finding lands, so a Critical is visible from across the room.

It is deliberately a small, total, stdlib-only module, because it sits in front of a security tool
and must never be the reason a hunt fails or a machine-readable output is unparseable:

  * **stderr only, never stdout.** Every ``gn`` verb with a ``--json`` mode promises that stdout is
    one parseable document — ``test_wardrive`` runs the real CLI as a subprocess and
    ``json.loads`` its stdout. Animation on stdout would break that contract for every consumer,
    so the frames and the phase lines both go to stderr. ``2>/dev/null`` gives you a silent run.
  * **Only for a human.** It requires ``stderr.isatty()``, an absent ``NO_COLOR``, a ``TERM`` that
    is not ``dumb``, and no ``GN_NO_FX``. A pipe, a CI log, a redirect and the whole test suite
    (which captures through ``io.StringIO``) all get nothing — not a frame, not an escape code.
  * **Glyphs are probed, never assumed.** Windows consoles default to cp1252, and ``gn_cli``'s
    ``reconfigure`` to UTF-8 is wrapped in a bare ``except``, so it can fail silently. Every frame
    set is encode-tested against the live stream before use, with an ASCII set behind it. A box
    that renders as ``????`` is worse than a box made of dashes.
  * **Total.** Every write is guarded, the ticker thread is a daemon that only ever touches its own
    buffer, and ``stop()`` is idempotent. A raise from here would abort a hunt mid-flight, so
    nothing here raises: the worst failure mode is a still line.

The ticker runs on its own thread precisely so the thing moves during silence, which is the whole
point — the Alpine dolphin swam whether or not the track changed.

Two renderers, one vocabulary
-----------------------------
:class:`Scanner` is the one-line surface. :class:`Board` is the full-screen NORAD threat board the
operator picked: an ASCII world map with an arc per in-scope asset, a DEFCON readout and a teletype.
Both answer the same six verbs — ``phase``, ``log``/``note``, ``track``, ``launch``, ``resolve``,
``hold`` — so a verb in ``gn_cli`` speaks one vocabulary and :func:`surface` decides which renderer
the terminal in front of it can actually take (the board wants ~78x24; anything smaller gets the
line). Everything above still holds for the board, with one addition: it takes the whole screen, so
it enters the ALTERNATE buffer and restores it in a ``finally`` — and registers itself in ``_LIVE``
so ``stop_all()`` in ``gn_cli.main``'s finally gives the terminal back down every early-return path.

Nothing on the board is decoration. An arc exists because the engine named that asset, and it lands
in a severity colour because a CONFIRMED finding landed on it — never because time passed. What the
engines can and cannot tell us is written up on :class:`BoardFeed`, which is the only thing that
turns their prose into board verbs.
"""
from __future__ import annotations

import math
import os
import re
import shutil
import sys
import threading
import time
from typing import Any, Iterable, Sequence, TextIO

# --- frame sets ---------------------------------------------------------------------------------
# Each set is (swimmer, wake, tank_left, tank_right, floor, jump). Probed in order; the last is
# 7-bit ASCII and therefore always usable.
_FRAME_SETS: tuple[dict[str, Any], ...] = (
    {   # Preferred: block-and-arrow, reads as motion at any font size.
        "swimmer": ("⠶", "⠦", "⠆", "⠇", "⠋", "⠙", "⠸", "⠴"),
        "wake": ("░", "▒", "·"),
        "edges": ("▌", "▐"),
        "floor": "─",
        "jump": "◆",
        "bars": ("▁", "▂", "▃", "▄", "▅", "▆", "▇"),
    },
    {   # Fallback: latin-1-safe, still animates.
        "swimmer": ("o", "O", "o", "c", "C", "c"),
        "wake": ("~", "-", "."),
        "edges": ("|", "|"),
        "floor": "-",
        "jump": "*",
        "bars": ("_", ".", ":", "|"),
    },
)

_SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}
_TANK_WIDTH = 22
_FRAME_SECONDS = 0.09
_PHASE_CHARS = 44

#: Every surface — :class:`Scanner` or :class:`Board` — that has started and not yet stopped.
#: ``gn_cli.main`` drains this in a finally, so a verb that returns early down an error path cannot
#: leave a half-drawn line (or, far worse, a live alternate screen) on the operator's terminal —
#: which is easy to do, since the long verbs have several ``return _err(...)`` exits.
_LIVE: list[Any] = []
_LIVE_LOCK = threading.Lock()


def stop_all(summary: str = "") -> None:
    """Stop and clear every live surface. Total and idempotent — safe in a ``finally``."""
    with _LIVE_LOCK:
        live, _LIVE[:] = list(_LIVE), []
    for scanner_ in live:
        try:
            scanner_.stop(summary)
        except Exception:  # noqa: BLE001 - cleanup must not raise over the real result
            pass


def _truthy_off(name: str) -> bool:
    return str(os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _term_allows_motion(term: str | None, os_name: str) -> bool:
    """The ``TERM`` rule, as a pure function of the two inputs it actually depends on.

    Two distinct cases were once collapsed into one expression (``… not in {"dumb", ""} or
    os.name == "nt"``), and the ``or`` let Windows overrule both of them:

      * ``TERM=dumb`` is an operator explicitly asking for no escape sequences. It wins on every
        platform. Windows has no say in it — ``dumb`` is set deliberately, never by default.
      * An EMPTY ``TERM`` is the only thing the platform gets to decide. On POSIX it means no
        terminfo entry, so nothing may be assumed; on Windows it is simply the norm — cmd.exe,
        PowerShell and Windows Terminal all leave ``TERM`` unset while handling ANSI perfectly
        well — so an unset ``TERM`` there is not evidence of a dumb terminal.

    Taking the platform as an argument rather than reading ``os.name`` keeps both halves of that
    matrix testable from either platform, which is the whole reason the bug shipped: on Linux
    ``TERM=dumb`` worked, and the test that asserts it could not see the Windows branch at all.
    """
    normalized = str(term or "").strip().lower()
    if normalized == "dumb":
        return False
    return bool(normalized) or os_name == "nt"


def enabled(stream: TextIO | None = None) -> bool:
    """Whether motion is appropriate for this invocation.

    Mirrors ``gn_cli._color_enabled`` but on the stream the frames go to, because stdout and stderr
    are redirected independently: ``gn hunt … --json > out.json`` still has a human watching stderr.
    The one deliberate difference is an empty ``TERM``: colour is a single SGR code and stays on,
    while motion needs cursor control, so it wants a terminal that has named itself.
    """
    stream = stream if stream is not None else sys.stderr
    try:
        if not stream.isatty():
            return False
    except Exception:  # noqa: BLE001 - a stream that cannot answer is not a terminal
        return False
    if os.getenv("NO_COLOR") is not None or _truthy_off("GN_NO_FX"):
        return False
    return _term_allows_motion(os.getenv("TERM"), os.name)


def _pick_frames(stream: TextIO) -> dict[str, Any]:
    """The richest frame set this stream can actually encode. Never returns None."""
    encoding = (getattr(stream, "encoding", None) or "ascii")
    for frames in _FRAME_SETS:
        probe = "".join(
            "".join(value) if isinstance(value, tuple) else str(value)
            for value in frames.values()
        )
        try:
            probe.encode(encoding, errors="strict")
        except (UnicodeEncodeError, LookupError, TypeError):
            continue
        return frames
    return _FRAME_SETS[-1]


class Scanner:
    """A live status line. Use via :func:`scanner`; ``stop()`` is idempotent and always clears up."""

    def __init__(self, title: str, *, stream: TextIO | None = None, active: bool | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._active = enabled(self._stream) if active is None else bool(active)
        self._frames = _pick_frames(self._stream) if self._active else _FRAME_SETS[-1]
        self._title = str(title or "")
        self._phase = "starting"
        self._counts: dict[str, int] = {}
        self._flash: tuple[str, str] | None = None   # (severity, text) shown for a few frames
        self._flash_left = 0
        self._step = 0
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread: threading.Thread | None = None

    # --- public API ------------------------------------------------------------------------------
    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> "Scanner":
        if not self._active or self._thread is not None:
            return self
        self._thread = threading.Thread(target=self._run, name="gn-fx", daemon=True)
        self._thread.start()
        with _LIVE_LOCK:
            _LIVE.append(self)
        return self

    def phase(self, text: str) -> None:
        """Replace the phase shown beside the tank. Cheap; call it as often as the engine emits."""
        with self._lock:
            self._phase = str(text or "").strip()

    def note(self, text: str) -> None:
        """Print one scrolling line ABOVE the live line, keeping the animation in place below it.

        This is where an engine's progress messages go when motion is on. With motion off the caller
        prints them itself, unchanged — so a pipe, a CI log and the test suite see exactly the output
        they saw before this module existed.
        """
        clean = str(text or "").rstrip()
        if not clean:
            return
        if not self._active:
            return
        with self._lock:
            self._erase()
            self._write(f"  {self._dim(clean)}\n")
            self._paint_locked()

    def hit(self, severity: str, text: str = "") -> None:
        """A finding landed. Counts it and flashes the line in that severity's colour."""
        key = str(severity or "info").strip().lower()
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + 1
            if self._active:
                self._flash = (key, str(text or "").strip())
                self._flash_left = 9

    # --- the shared surface vocabulary ----------------------------------------------------------
    # The board's four map verbs, answered by the line renderer so a `gn` verb never has to ask
    # which surface it got. A Scanner has no map, so three of them are honest no-ops; `resolve` is
    # the exception — it is only ever called for a CONFIRMED finding, which is exactly what `hit`
    # already means here, so the line keeps flashing severities as it always did.
    def track(self, assets: Iterable[Any]) -> None:
        """No-op: there is no map on a one-line surface."""

    def launch(self, name: str) -> None:
        """No-op: an arc needs a map."""

    def resolve(self, name: str, severity: str, label: str = "") -> None:
        """A confirmed finding landed on ``name``. The line flashes its severity; the name is the
        board's business."""
        self.hit(severity, label)

    def log(self, text: str, color: str | None = None) -> None:
        """One scrolling line, as :meth:`note`. ``color`` is the board's teletype paint, unused here."""
        self.note(text)

    def hold(self, seconds: float) -> None:
        """No-op: the line has no final frame worth pausing on."""

    def stop(self, summary: str = "") -> None:
        """Stop the ticker, clear the live line, and optionally leave one final line behind."""
        if self._stopped.is_set():
            return
        self._stopped.set()
        with _LIVE_LOCK:
            if self in _LIVE:
                _LIVE.remove(self)
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=1.0)
        if not self._active:
            return
        with self._lock:
            self._erase()
            if summary:
                self._write(f"  {summary}\n")
            self._flush()

    # --- context manager -------------------------------------------------------------------------
    def __enter__(self) -> "Scanner":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # --- internals -------------------------------------------------------------------------------
    def _run(self) -> None:
        # Total by construction: a terminal that vanishes mid-run (a closed pipe, a resized tmux
        # pane) must cost the animation, never the hunt running on the main thread.
        while not self._stopped.is_set():
            try:
                with self._lock:
                    self._step += 1
                    if self._flash_left:
                        self._flash_left -= 1
                        if not self._flash_left:
                            self._flash = None
                    self._paint_locked()
            except Exception:  # noqa: BLE001
                return
            self._stopped.wait(_FRAME_SECONDS)

    def _write(self, text: str) -> None:
        try:
            self._stream.write(text)
        except Exception:  # noqa: BLE001 - a dead stream ends the animation, not the run
            self._stopped.set()

    def _flush(self) -> None:
        try:
            self._stream.flush()
        except Exception:  # noqa: BLE001
            self._stopped.set()

    def _erase(self) -> None:
        self._write("\r\033[2K")

    def _dim(self, text: str) -> str:
        return f"\033[2m{text}\033[0m"

    def _tank(self) -> str:
        """The swimmer, its fading wake, and a scanline sweeping the floor."""
        frames = self._frames
        swimmers: tuple[str, ...] = frames["swimmer"]
        wake: tuple[str, ...] = frames["wake"]
        span = max(1, _TANK_WIDTH - 1)
        # Ping-pong so it turns around at the glass rather than wrapping.
        cycle = self._step % (span * 2)
        head = cycle if cycle < span else (span * 2 - cycle)
        forward = cycle < span

        cells = [" "] * _TANK_WIDTH
        for depth, glyph in enumerate(wake):
            trail = head - (depth + 1) if forward else head + (depth + 1)
            if 0 <= trail < _TANK_WIDTH:
                cells[trail] = glyph
        cells[head] = swimmers[self._step % len(swimmers)]

        water = "".join(cells)
        left, right = frames["edges"]
        # The scanline: one brighter cell walking the floor at a different rate, so the two motions
        # beat against each other instead of marching in lockstep.
        floor_cells = [frames["floor"]] * _TANK_WIDTH
        floor_cells[(self._step * 2) % _TANK_WIDTH] = frames["jump"]
        floor = "".join(floor_cells)
        return (f"\033[36m{left}\033[0m\033[1;36m{water}\033[0m\033[36m{right}\033[0m"
                f"  \033[2m{floor}\033[0m")

    def _digest(self) -> str:
        """Running finding counts, each in its own severity colour — C/H/M/L/I."""
        if not self._counts:
            return ""
        parts = []
        for key in ("critical", "high", "medium", "low", "info"):
            count = self._counts.get(key)
            if count:
                parts.append(f"\033[{_SEV_COLOR[key]}m{count}{key[0].upper()}\033[0m")
        return "  " + " ".join(parts) if parts else ""

    def _paint_locked(self) -> None:
        """Draw the live line. Caller holds the lock."""
        if self._flash is not None:
            severity, text = self._flash
            code = _SEV_COLOR.get(severity, "1")
            label = severity.upper()
            body = f" {text}" if text else ""
            # Blink the label by alternating reverse-video on consecutive frames.
            reverse = "\033[7m" if self._step % 2 else ""
            self._erase()
            self._write(f"  {reverse}\033[{code}m{label}\033[0m\033[{code}m{body}\033[0m")
            self._flush()
            return
        phase = self._phase
        if len(phase) > _PHASE_CHARS:
            phase = phase[: _PHASE_CHARS - 1] + "…" if self._frames is _FRAME_SETS[0] else phase[: _PHASE_CHARS]
        self._erase()
        self._write(f"  {self._tank()}  \033[2m{phase}\033[0m{self._digest()}")
        self._flush()


def scanner(title: str, *, stream: TextIO | None = None, active: bool | None = None) -> Scanner:
    """A :class:`Scanner` for ``with`` use. Inert unless stderr is a terminal a human is watching."""
    return Scanner(title, stream=stream, active=active)


def progress_sink(fx: Any = None, fallback: Any = None) -> Any:
    """Turn a live surface into the ``on_progress(message)`` callable the engines already take.

    With motion on, a message updates the live phase AND scrolls above the tank — or, on the
    full-screen surface, is parsed for the assets it names and typed onto the board's teletype (see
    :class:`BoardFeed`). With motion off (a pipe, ``--json``, CI, the test suite) this returns
    ``fallback`` untouched, so every existing caller keeps byte-identical output. That split is why
    adding motion could not regress any of the stdout literals the CLI tests pin.
    """
    if fx is None or not fx.active:
        return fallback
    if isinstance(fx, Board):
        return BoardFeed(fx)

    def _sink(message: str) -> None:
        text = str(message or "").strip()
        if not text:
            return
        fx.phase(text)
        fx.note(text)

    return _sink


def demo(seconds: float = 6.0, stream: TextIO | None = None) -> int:
    """``gn fx`` — show the thing, so a terminal can be checked without starting a hunt."""
    target = stream if stream is not None else sys.stderr
    if not enabled(target):
        print("gn: motion needs a terminal (stderr is redirected, NO_COLOR is set, or GN_NO_FX is on).",
              file=sys.stderr)
        return 2
    phases = ("resolving scope", "passive recon", "ranking endpoints", "active verification",
              "capturing differential proof", "building the report")
    started = time.monotonic()
    with scanner("demo", stream=target) as fx:
        index = 0
        while time.monotonic() - started < max(0.5, float(seconds)):
            fx.phase(phases[index % len(phases)])
            fx.note(f"{phases[index % len(phases)]}…")
            if index == 3:
                fx.hit("critical", "this is what a confirmed Critical looks like")
            time.sleep(max(0.5, float(seconds)) / len(phases))
            index += 1
        fx.stop("demo complete — this is what a live hunt looks like.")
    return 0


# =================================================================================================
# The threat board
# =================================================================================================
# ``scripts/fx_gallery.py`` is where this was prototyped and chosen, as the scripted ``Wopr``
# scene; everything below that decides how the board LOOKS is taken from it value for value — the
# 72x17 equirectangular map, the land spans, the glyph set, the xterm-256 severity codes, the 1.7s
# flight, the 0.9s erode, the impact ring, the blink rate and the 62 cps teletype — so the demo an
# operator picked from and the board a hunt draws are recognisably the same board. The gallery
# stays a prototype (a pure function of time over hard-coded targets); this is the live one, and it
# is the only renderer that ships, so where the two disagree THIS file is the model.
#
# A sibling renderer for the web was built alongside it and then cut — the ask was the terminal.
# Two of its decisions were not in the gallery and are kept here, because they are what a LIVE
# board needs and a scripted one does not: DEFCON read off the worst CONFIRMED severity rather than
# off a count of arcs, and placement by hashing an unknown asset's name onto a curated site list
# (see ``_SITES``) rather than hard-coded coordinates.
_BOARD_COLS, _BOARD_ROWS = 78, 24
_MAP_W, _MAP_H = 72, 17
#: The narrowest terminal the board will draw on. 78 is the grid it WANTS — the box centred with a
#: couple of columns either side — but the box itself is only ``_MAP_W + 2`` wide, so insisting on
#: 78 refused the board on a 74-column terminal purely for the margin. Found by running it: the
#: Terminal panel beside this app is 74 columns. Below this the map would have to be clipped to
#: fit, and a world map with Asia cut off is not a threat board.
_BOARD_MIN_COLS = _MAP_W + 2
_FLIGHT = 1.7            # seconds an arc is in the air
_ERODE = 0.9             # seconds for a spent trail to drain into its target
_BOARD_FPS = 20.0
_BOARD_ORIGIN = (12, 4)

# Inclusive land spans on the 72x17 grid: a continent is a number to nudge rather than a column to
# count. The same table as ``_LAND_SPANS`` in scripts/fx_gallery.py.
_LAND_SPANS: dict[int, tuple[tuple[int, int], ...]] = {
    0:  ((25, 30), (46, 62)),
    1:  ((7, 12), (14, 25), (26, 31), (35, 40), (41, 65)),
    2:  ((8, 24), (27, 30), (34, 34), (36, 39), (40, 66)),
    3:  ((9, 23), (32, 40), (41, 67)),
    4:  ((10, 22), (32, 39), (41, 66), (67, 68)),
    5:  ((11, 21), (31, 34), (37, 45), (52, 64), (66, 67)),
    6:  ((12, 19), (30, 44), (47, 52), (54, 63)),
    7:  ((14, 18), (30, 44), (48, 52), (55, 60)),
    8:  ((16, 19), (30, 41), (49, 52), (56, 61)),
    9:  ((19, 23), (29, 42), (57, 62)),
    10: ((20, 26), (31, 41), (58, 64)),
    11: ((20, 27), (32, 40), (59, 63)),
    12: ((20, 26), (32, 39), (61, 68)),
    13: ((21, 26), (33, 38), (60, 69)),
    14: ((21, 25), (34, 37), (62, 68)),
    15: ((22, 24), (70, 71)),
    16: ((22, 23),),
}

#: Sites an asset can be placed on: hand-picked, spread across the continents, none on top of the
#: node. Hashing over every land cell instead looks principled and isn't — the northern landmass
#: holds most of the cells, so three assets in a row land in Siberia on top of each other. A
#: curated list is what makes an unseen set of hostnames lay out like a map.
_SITES: tuple[tuple[int, int], ...] = (
    (14, 3), (18, 5), (13, 7), (22, 10), (24, 12), (23, 14),
    (28, 1), (33, 2), (35, 4), (38, 3), (41, 6), (33, 8),
    (36, 10), (35, 12), (45, 2), (50, 3), (50, 7), (55, 5),
    (57, 8), (58, 11), (62, 4), (65, 6), (64, 12), (67, 13), (70, 15),
)

#: How many assets the board will place. Past this the map is unreadable, so further names are
#: COUNTED and shown as ``(+n)`` beside the asset tally rather than silently dropped — a board that
#: quietly stopped mentioning targets the engine is hunting would be the one lie this module cannot
#: afford. Two per site: the nudge in :meth:`Board.track` tolerates that much crowding.
_BOARD_MAX_ASSETS = 2 * len(_SITES)

_BOARD_UNI = {
    "edges": ("│", "│"),
    "corners": ("┌", "┐", "└", "┘"),
    "tees": ("├", "┤"),
    "hbar": "─",
    "land": "▒",
    "arc": ("●", "▪", "·"),
    "head": "◉",
    "blip": "◆",
    "ring": "○",
    "cursor": "█",
}
_BOARD_ASCII = {
    "edges": ("|", "|"),
    "corners": ("+", "+", "+", "+"),
    "tees": ("+", "+"),
    "hbar": "-",
    "land": ":",
    "arc": ("*", "+", "."),
    "head": "@",
    "blip": "#",
    "ring": "o",
    "cursor": "_",
}

_BOARD_SEV = {
    "critical": "1;38;5;196",
    "high": "38;5;202",
    "medium": "38;5;214",
    "low": "38;5;228",
    "info": "38;5;109",
}
_SEV_ORDER = ("critical", "high", "medium", "low", "info")
#: DEFCON is the WORST confirmed severity, never a count of arcs. On a live board a number that
#: only counts motion is theatre, and this one has to survive an operator asking what it means.
_DEFCON_FOR = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}

# Alternate screen + hidden cursor + auto-wrap off, so a full-width frame cannot scroll the view and
# the operator's scrollback survives the board untouched. Restored in the reverse order.
_TERM_ENTER = "\033[?1049h\033[?25l\033[?7l"
_TERM_LEAVE = "\033[?7h\033[?25h\033[?1049l"

#: Characters a cp1252 console cannot encode but that the engines really do emit (bounty.py is full
#: of em-dashes and ellipses). Transliterated rather than dropped: ``gn_cli`` reconfigures the
#: streams to UTF-8 with ``errors="replace"`` inside a bare ``except``, so when that reconfigure
#: fails this is the difference between a readable teletype and a row of question marks.
_TRANSLITERATE = {
    "—": "-", "–": "-", "…": "...", "·": ".",
    "→": "->", "←": "<-", "’": "'", "‘": "'",
    "“": '"', "”": '"', "×": "x", "•": "*",
    "≥": ">=", "≤": "<=",
}


def _glyph_probe(glyphs: dict[str, Any]) -> str:
    """Every character a glyph set would draw, as one string to encode-test the stream with."""
    return "".join(
        "".join(value) if isinstance(value, (tuple, list)) else str(value)
        for value in glyphs.values()
    )


def _enable_vt(stream: TextIO) -> None:
    """Ask a legacy Windows console to interpret ANSI. No-op elsewhere, never raises."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11 if stream is sys.stdout else -12)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # noqa: BLE001 - a console that will not answer just gets no escapes
        pass


def _terminal_size(stream: TextIO | None = None) -> tuple[int, int]:
    """(columns, lines) for the terminal the board would draw on.

    The board lives on STDERR, which is redirected independently of stdout, so it asks that
    descriptor first; ``shutil.get_terminal_size`` reads ``COLUMNS``/``LINES`` and then stdout,
    which is the wrong file on ``gn hunt … --json > out.json``. Falls back to 80x24 — the
    historical safe assumption for a terminal that will not describe itself.
    """
    stream = stream if stream is not None else sys.stderr
    try:
        size = os.get_terminal_size(stream.fileno())
        if size.columns > 0 and size.lines > 0:
            return int(size.columns), int(size.lines)
    except Exception:  # noqa: BLE001 - not every stream has a usable descriptor
        pass
    try:
        size = shutil.get_terminal_size((80, 24))
        return int(size.columns), int(size.lines)
    except Exception:  # noqa: BLE001
        return 80, 24


def board_fits(stream: TextIO | None = None) -> bool:
    """Whether this terminal is big enough for the board. Anything smaller gets the Scanner.

    ``_BOARD_MIN_COLS`` x ``_BOARD_ROWS`` and no smaller: below that the map has to be clipped, and
    a world map with Asia cut off is not a threat board.

    Checked once, when the surface is chosen, and never again per frame. A resize mid-hunt is
    therefore not noticed — which is safe rather than lucky, because the board turns auto-wrap OFF
    (``_TERM_ENTER``): a row wider than the terminal is truncated at the margin, not folded onto
    the next line, so a shrunk window costs the right-hand columns of the map and nothing else.
    Swapping renderers underneath a running hunt would cost considerably more.
    """
    cols, rows = _terminal_size(stream)
    return cols >= _BOARD_MIN_COLS and rows >= _BOARD_ROWS


# --- arithmetic shared with the other two surfaces -----------------------------------------------
def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return low if value < low else high if value > high else value


def _ease_out(x: float) -> float:
    x = _clamp(x)
    return 1.0 - (1.0 - x) * (1.0 - x)


def _typed(text: str, elapsed: float, cps: float = 62.0) -> str:
    """How much of ``text`` a teletype running at ``cps`` has printed after ``elapsed`` seconds."""
    if elapsed <= 0:
        return ""
    return text[: int(elapsed * cps)]


def _bezier(p0: tuple[float, float], p1: tuple[float, float], p2: tuple[float, float],
            s: float) -> tuple[float, float]:
    inv = 1.0 - s
    return (inv * inv * p0[0] + 2 * inv * s * p1[0] + s * s * p2[0],
            inv * inv * p0[1] + 2 * inv * s * p1[1] + s * s * p2[1])


def _hash_name(name: str) -> int:
    """A stable 32-bit digest of an asset's name, used to choose its site on the map.

    Stable is the whole requirement: an operator learns where their assets live, so the same host
    has to land on the same patch of world on every run, in every process, for ever — which rules
    out ``hash()`` (``PYTHONHASHSEED`` randomises it per process) and anything that depends on the
    order the names arrived in. Same mixer as ``Scene.hashed`` in scripts/fx_gallery.py.
    """
    acc = 0x9E3779B9
    for ch in str(name):
        acc = (acc * 1664525 + ord(ch) * 1013904223 + 0x9E37) & 0xFFFFFFFF
        acc ^= acc >> 15
    return acc


def _split_unit(name: str) -> tuple[str, str]:
    """``(host, path)`` for whatever the engine called an asset, without importing urllib.

    The engines name four shapes of thing: a URL, a bare hostname, a filesystem path (a
    source-code hunt) and a repository URL. Only the first two have a host, and only the first two
    are what the canvas renderer is ever handed, so this stays deliberately small — anything it
    cannot split is used whole, which is the conservative outcome everywhere it is called.
    """
    text = str(name or "").strip()
    rest = text.split("://", 1)[1] if "://" in text else text
    rest = rest.split("#", 1)[0].split("?", 1)[0]
    if "://" not in text and ("\\" in rest or (os.name == "nt" and ":" in rest[:3])):
        return "", text            # a Windows path: the drive colon is not a port
    host, slash, path = rest.partition("/")
    host = host.rsplit("@", 1)[-1]          # strip userinfo
    if host.startswith("["):                # [::1]:8080
        host = host.split("]", 1)[0] + "]"
    elif ":" in host:
        host = host.split(":", 1)[0]
    if "." not in host and not host.startswith("[") and host.lower() != "localhost":
        return "", text            # not a host at all — a bare path, a label, a program name
    return host.lower(), (slash + path)


def _place_key(name: str) -> str:
    """What :meth:`Board.track` hashes to choose a site.

    A URL whose path is empty or ``/`` hashes as its bare HOSTNAME, so ``https://api.example.com/``
    and ``api.example.com`` are one place on the map rather than two — the engines genuinely name
    the same asset both ways (a campaign's seed is a URL, a portfolio's target is a host). Anything
    more specific hashes whole, so two endpoints on one host are two places.
    """
    host, path = _split_unit(name)
    if host and path.strip("/") == "":
        return host
    return str(name or "").strip()


def _asset_tag(name: str) -> str:
    """The <=9 character label drawn beside a blip.

    A bare hostname shows its first DNS label, which is what the gallery's hard-coded targets do
    (``cdn.example.com`` -> ``CDN``). The other shapes the engines name reduce to the most specific
    thing that identifies them: an endpoint becomes its last path segment (``/v1/users`` ->
    ``USERS``), because on a campaign every URL shares one host and a column of identical ``API``
    labels would say nothing at all.
    """
    text = str(name or "").strip()
    host, path = _split_unit(text)
    segments = [part for part in path.split("/") if part]
    if segments:
        return _short(segments[-1])
    if host:
        return _short(host.split(".")[0])
    tail = text.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return _short(tail or text)


def _short(text: str) -> str:
    """Nine characters, and never a dangling dot: ``settings.py`` truncates to ``SETTINGS.``, which
    reads as a rendering fault rather than as a filename."""
    return str(text).upper()[:9].rstrip(".")


class _Grid:
    """A character grid with a per-cell SGR code, rendered as rows with colour runs merged.

    Merging runs matters: a naive per-cell escape makes one 78x24 frame ~20 KB, and at 20 fps that
    is enough write traffic to make the board itself the slow part over ssh.
    """

    __slots__ = ("w", "h", "_ch", "_co")

    def __init__(self, width: int, height: int) -> None:
        self.w, self.h = max(1, int(width)), max(1, int(height))
        self._ch = [[" "] * self.w for _ in range(self.h)]
        self._co: list[list[str | None]] = [[None] * self.w for _ in range(self.h)]

    def clear(self) -> None:
        for y in range(self.h):
            chars, colors = self._ch[y], self._co[y]
            for x in range(self.w):
                chars[x] = " "
                colors[x] = None

    def put(self, x: float, y: float, ch: str, color: str | None = None) -> None:
        x, y = int(round(x)), int(round(y))
        if 0 <= x < self.w and 0 <= y < self.h and ch:
            self._ch[y][x] = ch[0]
            self._co[y][x] = color

    def text(self, x: int, y: int, text: str, color: str | None = None) -> None:
        for index, ch in enumerate(str(text)):
            self.put(x + index, y, ch, color)

    def rows(self) -> list[str]:
        out: list[str] = []
        for y in range(self.h):
            chars, colors = self._ch[y], self._co[y]
            parts: list[str] = []
            run: list[str] = []
            current = colors[0]
            for x in range(self.w):
                if colors[x] != current:
                    parts.append(f"\033[{current}m{''.join(run)}\033[0m" if current else "".join(run))
                    run = []
                    current = colors[x]
                run.append(chars[x])
            parts.append(f"\033[{current}m{''.join(run)}\033[0m" if current else "".join(run))
            out.append("".join(parts))
        return out


_LAND_ROWS: tuple[str, ...] = tuple(
    "".join(
        "#" if any(x0 <= x <= x1 for x0, x1 in _LAND_SPANS.get(y, ())) else " "
        for x in range(_MAP_W)
    )
    for y in range(_MAP_H)
)


def _finding_counts(assets: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Confirmed findings by severity across ``assets`` — per FINDING, not per asset.

    Several confirmed findings on one URL are common, and the marker for that URL rightly shows
    only the worst of them. The tally must not: counting assets reported ``1H`` for a result
    holding two confirmed Highs, while the line surface and the CLI summary said ``2H``.
    """
    counts: dict[str, int] = {}
    for asset in assets:
        for severity in asset.get("findings") or ([asset["severity"]] if asset.get("severity") else []):
            counts[severity] = counts.get(severity, 0) + 1
    return counts


class Board:
    """The full-screen threat board, driven by what the engine is actually doing.

    Live feed: :meth:`track` puts the in-scope assets on the map as unlit crosses, :meth:`launch`
    sends an arc because an asset entered verification, :meth:`resolve` lands it in a severity
    colour because a CONFIRMED finding landed on it, :meth:`log` types one line of the engine's own
    prose along the bottom, and :meth:`phase` names the stage. Nothing animates that was not pushed
    in, and nothing is coloured by a severity the engine has not reported.

    Every arc is a pure function of ``now() - its own launch time``, never of a frame counter, so a
    dropped frame costs nothing, a hunt that sits quiet for four minutes does not desynchronise what
    is left in the air, and nothing accumulates drift over a run that lasts hours.

    One thing a live board needs that the scripted prototype did not: a trail erodes once its
    FLIGHT is over, whether or not a verdict has arrived. In the gallery impact and verdict are the
    same instant, so eroding on impact was the same thing; here the verdict arrives minutes later
    (see :class:`BoardFeed`), and arcs that waited for one would sit fully drawn across the map for
    the whole run and bury the continents the board exists to show. Landed-but-unresolved therefore
    reads as a pulsing dim cross: the arc arrived, the verdict has not.

    Totality is the same contract as :class:`Scanner`, with the terminal added. It takes the whole
    screen, so :meth:`stop` gives the screen back in a ``finally`` and is idempotent even when the
    ticker thread has already given up on a dead stream — the one ordering that matters, since
    returning early from ``stop`` there would strand the operator in the alternate buffer.
    """

    def __init__(self, title: str, *, scope: str = "", stream: TextIO | None = None,
                 active: bool | None = None, footer: str = "", clock_base: float | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._active = (enabled(self._stream) and board_fits(self._stream)) if active is None else bool(active)
        self._encoding = (getattr(self._stream, "encoding", None) or "ascii")
        self._glyphs = _BOARD_UNI if self._encodable(_glyph_probe(_BOARD_UNI)) else _BOARD_ASCII
        self._title = self._clean(title or "GREYNOC // WOPR-IQ")
        self._scope = self._clean(scope)
        self._footer = self._clean(footer or "AUTHORIZED SCOPE ONLY  ::  READ-ONLY PROOF")
        #: None = the real UTC clock, which is what a live hunt gets: a board reporting a time the
        #: machine is not at would be a small lie in the one place this program cannot afford them.
        #: :func:`board_demo` passes the gallery's scripted base instead, so its frames reproduce.
        self._clock_base = clock_base
        # The grid is as close to _BOARD_COLS as this terminal allows, never narrower than the
        # box itself: fixed for the life of the board, so the arithmetic below cannot shift
        # underneath a frame, and measured once rather than per frame for the same reason.
        self._cols = min(max(_terminal_size(self._stream)[0], _BOARD_MIN_COLS), _BOARD_COLS)
        self._grid = _Grid(self._cols, _BOARD_ROWS)
        self._assets: list[dict[str, Any]] = []
        self._by_name: dict[str, dict[str, Any]] = {}
        self._taken: set[int] = set()
        self._overflow = 0
        self._lines: list[tuple[float, str, str]] = []   # (at, text, sgr)
        self._phase = ""
        self._started = time.monotonic()
        self._left, self._top = 0, 0
        self._last_rows: list[str] = []
        self._entered = False
        self._restored = False
        self._done = False
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread: threading.Thread | None = None

    # --- public API ------------------------------------------------------------------------------
    @property
    def active(self) -> bool:
        return self._active

    def now(self) -> float:
        return time.monotonic() - self._started

    def start(self) -> "Board":
        """Take the screen and start painting. Degrades to inert if the terminal will not take it."""
        if not self._active or self._thread is not None:
            return self
        cols, rows = _terminal_size(self._stream)
        self._left = max(0, (cols - self._cols) // 2)
        self._top = max(0, (rows - _BOARD_ROWS) // 2)
        _enable_vt(self._stream)
        try:
            self._stream.write(_TERM_ENTER)
            self._stream.flush()
        except Exception:  # noqa: BLE001 - a stream that cannot take the board gets no board
            self._active = False
            return self
        self._entered = True
        self._started = time.monotonic()
        self._thread = threading.Thread(target=self._run, name="gn-fx-board", daemon=True)
        self._thread.start()
        with _LIVE_LOCK:
            _LIVE.append(self)
        return self

    def track(self, assets: Iterable[Any]) -> None:
        """Put assets on the map. Accepts names, or ``{"name":…, "severity":…, "label":…}``.

        Linear probing off the name's own hash: the same host always lands on the same site, and a
        second host never lands on top of the first. Past the site list the placement is nudged by
        a cell rather than stacked; past ``_BOARD_MAX_ASSETS`` the name is counted into the
        overflow shown beside the tally.
        """
        try:
            items = list(assets or ())
        except TypeError:  # noqa: BLE001 - a caller handing us a non-iterable loses the arc, not the hunt
            return
        with self._lock:
            for raw in items:
                # str or {"name": …}; anything else is dropped rather than reached into, because an
                # engine handing this a surprise must cost an arc and nothing more.
                fields = raw if isinstance(raw, dict) else {}
                name = str(raw if isinstance(raw, str) else fields.get("name") or "").strip()
                if not name or name in self._by_name:
                    continue
                if len(self._assets) >= _BOARD_MAX_ASSETS:
                    self._overflow += 1
                    continue
                digest = _hash_name(_place_key(name))
                slot = digest % len(_SITES)
                for _probe in range(len(_SITES)):
                    if slot not in self._taken:
                        break
                    slot = (slot + 1) % len(_SITES)
                crowded = slot in self._taken      # more assets than sites: nudge rather than stack
                self._taken.add(slot)
                spot = _SITES[slot]
                severity = str(fields.get("severity") or "").strip().lower() or None
                label = self._clean(fields.get("label") or "")
                asset = {
                    "name": name,
                    "tag": _asset_tag(name),
                    "x": spot[0] + ((digest % 3) - 1 if crowded else 0),
                    "y": spot[1] + (((digest >> 3) % 3) - 1 if crowded else 0),
                    "severity": severity if severity in _BOARD_SEV else None,
                    "label": label,
                    "launch_at": None,
                    "resolve_at": None,
                    # One entry per CONFIRMED finding that landed here. The marker merges them
                    # (worst severity wins); the tally and the digest count every one of them.
                    "findings": [],
                }
                self._assets.append(asset)
                self._by_name[name] = asset

    def launch(self, name: str) -> None:
        """An asset has entered verification: send the arc. Idempotent — the first call wins, so a
        repeated engine message cannot re-fire an arc already in the air."""
        clean = str(name or "").strip()
        if not clean:
            return
        self.track([clean])
        with self._lock:
            asset = self._by_name.get(clean)
            if asset is not None and asset["launch_at"] is None:
                asset["launch_at"] = self.now()

    def resolve(self, name: str, severity: str, label: str = "") -> None:
        """A CONFIRMED finding landed on ``name``. The arc impacts and the marker starts blinking.

        Attribution is conservative, in the order a finding's own fields become less specific: the
        exact name the arc was launched under, then the same URL without its query or trailing
        slash, then — only when it is unambiguous — the single tracked asset on that hostname.
        Failing all three the asset is new, which is honest: the engine just named it.
        """
        clean = str(name or "").strip()
        if not clean:
            return
        key = str(severity or "").strip().lower()
        key = key if key in _BOARD_SEV else "info"
        with self._lock:
            asset = self._match_locked(clean)
        if asset is None:
            self.track([clean])
            with self._lock:
                asset = self._by_name.get(clean)
        if asset is None:
            return
        with self._lock:
            now = self.now()
            if asset["launch_at"] is None:
                asset["launch_at"] = now          # resolved without a prior launch
            # Worst severity wins: several confirmed findings can land on one asset, and a Low
            # arriving after a Critical must not repaint the marker down.
            asset["findings"].append(key)
            current = asset["severity"]
            if current is None or _DEFCON_FOR.get(key, 5) < _DEFCON_FOR.get(current, 5):
                asset["severity"] = key
                asset["label"] = self._clean(label) or asset["label"]
            if asset["resolve_at"] is None:
                asset["resolve_at"] = max(now, asset["launch_at"] + _FLIGHT)

    def log(self, text: str, color: str | None = None) -> None:
        """One teletype line. Typed out at the bottom of the board; the previous one greys above it."""
        clean = self._clean(text)
        if not clean:
            return
        with self._lock:
            self._lines.append((self.now(), clean, color or "38;5;214"))
            del self._lines[:-24]

    def note(self, text: str, color: str | None = None) -> None:
        """:meth:`log`, under the name the one-line surface uses."""
        self.log(text, color)

    def phase(self, text: str) -> None:
        """Name the stage the engine is in. Shown on the status bar under the map."""
        clean = self._clean(text)
        with self._lock:
            self._phase = clean

    def hit(self, severity: str, text: str = "") -> None:
        """A finding landed but nothing said where. Typed into the log; no arc moves, because an arc
        without an asset would be the board inventing a target."""
        key = str(severity or "info").strip().lower()
        self.log(f"> {text or key.upper()}  ::  CONFIRMED  ::  {key.upper()}",
                 _BOARD_SEV.get(key, "38;5;214"))

    def hold(self, seconds: float) -> None:
        """Keep painting for a moment longer.

        The verdicts arrive at the END of a hunt (see :class:`BoardFeed`), so without this the
        impact rings, the severity markers and the DEFCON drop are all drawn into a board that is
        torn down in the same breath. Returns immediately once stopped, so Ctrl-C is not delayed.
        """
        if not self._active or self._stopped.is_set():
            return
        self._stopped.wait(max(0.0, float(seconds)))

    def stop(self, summary: str = "") -> None:
        """Stop painting, give the screen back, and leave one line of what the board showed.

        Idempotent, and the restore is NOT conditional on the ticker still being alive: a dead
        stream sets ``_stopped`` from the thread, and an early return here would leave the operator
        in the alternate buffer looking at a frozen map.
        """
        if self._done:
            return
        self._done = True
        self._stopped.set()
        with _LIVE_LOCK:
            if self in _LIVE:
                _LIVE.remove(self)
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=1.0)
        try:
            self._restore()
        finally:
            if self._active:
                line = self._clean(summary) or self._digest_line()
                if line:
                    self._write(f"  {line}\n")
                    self._flush()

    # --- context manager -------------------------------------------------------------------------
    def __enter__(self) -> "Board":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # --- internals -------------------------------------------------------------------------------
    def _encodable(self, text: str) -> bool:
        try:
            text.encode(self._encoding, errors="strict")
        except (UnicodeEncodeError, LookupError, TypeError):
            return False
        return True

    def _clean(self, text: Any) -> str:
        """Engine prose, reduced to something this stream can certainly write.

        A board that goes still on an em-dash would be worse than one that prints a hyphen, and
        ``bounty.py`` emits em-dashes and ellipses in almost every message it has.
        """
        body = str(text or "").strip()
        if not body:
            return ""
        if not self._encodable(body):
            body = "".join(_TRANSLITERATE.get(ch, ch) for ch in body)
        if not self._encodable(body):
            body = "".join(ch if self._encodable(ch) else "?" for ch in body)
        return body

    def _match_locked(self, name: str) -> dict[str, Any] | None:
        """The tracked asset ``name`` belongs to, or None. Caller holds the lock."""
        hit = self._by_name.get(name)
        if hit is not None:
            return hit

        def _normal(value: str) -> str:
            host, path = _split_unit(value)
            return f"{host}{path.rstrip('/')}" if host else value.rstrip("/")

        wanted = _normal(name)
        for asset in self._assets:
            if _normal(asset["name"]) == wanted:
                return asset
        host, _path = _split_unit(name)
        if host:
            on_host = [a for a in self._assets if _split_unit(a["name"])[0] == host]
            if len(on_host) == 1:
                return on_host[0]
        return None

    def _run(self) -> None:
        # Total by construction: a terminal that vanishes mid-run (a closed pipe, a killed tmux
        # pane) must cost the board, never the hunt running on the main thread.
        interval = 1.0 / _BOARD_FPS
        while not self._stopped.is_set():
            try:
                with self._lock:
                    self._paint_locked(self.now())
            except Exception:  # noqa: BLE001
                return
            self._stopped.wait(interval)

    def _write(self, text: str) -> None:
        try:
            self._stream.write(text)
        except Exception:  # noqa: BLE001 - a dead stream ends the board, not the run
            self._stopped.set()

    def _flush(self) -> None:
        try:
            self._stream.flush()
        except Exception:  # noqa: BLE001
            self._stopped.set()

    def _restore(self) -> None:
        """Give the terminal back. Total and idempotent; safe from any thread, at any point."""
        if self._restored or not self._entered:
            self._restored = True
            return
        self._restored = True
        try:
            self._stream.write(_TERM_LEAVE)
            self._stream.flush()
        except Exception:  # noqa: BLE001 - nothing left to do for a stream that has gone away
            pass

    def _digest_line(self) -> str:
        """One line of what the board actually showed, left on the restored screen.

        Built only from arcs that RESOLVED, so it cannot report a severity the engine never
        confirmed. A run that confirms nothing says so.
        """
        resolved = [a for a in self._assets if a["resolve_at"] is not None and a["severity"]]
        counts = _finding_counts(resolved)
        if not self._assets:
            return ""
        tally = "  ".join(f"{counts[sev]}{sev[0].upper()}" for sev in _SEV_ORDER if counts.get(sev))
        defcon = min((_DEFCON_FOR.get(a["severity"], 5) for a in resolved), default=5)
        total = len(self._assets) + self._overflow
        return (f"\033[2mthreat board: DEFCON {defcon}  ::  {len(resolved)}/{total} asset(s) "
                f"confirmed  ::  {tally or 'nothing confirmed'}\033[0m")

    # --- draw ------------------------------------------------------------------------------------
    def _paint_locked(self, t: float) -> None:
        """Draw one frame. Caller holds the lock."""
        self._grid.clear()
        self._draw(t)
        rows = self._grid.rows()
        # Every row positioned absolutely rather than written as a block: with auto-wrap off a
        # 78-column row on an exactly-78-column terminal is already at the edge, and one stray
        # newline at the bottom-right cell is how a frame scrolls the view it is drawn in.
        #
        # And only the rows that CHANGED. A full frame is ~4 KB once colour runs are merged, which
        # at 20 fps is ~85 KB/s — fine locally, and enough to make the board itself the slow part of
        # a hunt watched over ssh. Most rows are identical between frames (the map only changes
        # where the CRT sweep and the arcs are), so this is usually a few hundred bytes.
        previous = self._last_rows
        painted = [
            f"\033[{self._top + index + 1};{self._left + 1}H{row}"
            for index, row in enumerate(rows)
            if index >= len(previous) or previous[index] != row
        ]
        self._last_rows = rows
        if painted:
            self._write("".join(painted))
            self._flush()

    def _draw(self, t: float) -> None:
        grid, glyphs = self._grid, self._glyphs
        chrome, dim = "38;5;178", "38;5;58"
        box_w = min(self._cols, _MAP_W + 2)
        box_x = max(0, (self._cols - box_w) // 2)
        map_h = min(_MAP_H, max(6, _BOARD_ROWS - 6))
        box_h = map_h + 5
        box_y = max(0, (_BOARD_ROWS - box_h) // 2)
        self._frame_box(box_x, box_y, box_w, box_h, chrome)

        resolved = [a for a in self._assets
                    if a["resolve_at"] is not None and t >= a["resolve_at"] and a["severity"]]
        counts = _finding_counts(resolved)
        defcon = min((_DEFCON_FOR.get(a["severity"] or "info", 5) for a in resolved), default=5)

        # --- header -------------------------------------------------------------------------------
        grid.text(box_x + 2, box_y, f" {self._title} ", "1;38;5;214")
        label = f" DEFCON {defcon} "
        grid.text(box_x + box_w - 13 - len(label), box_y, label,
                  "1;7;38;5;196" if defcon <= 2 else "1;38;5;214")
        grid.text(box_x + box_w - 12, box_y, f" {self._clock(t)} ", chrome)

        # --- map ----------------------------------------------------------------------------------
        mx, my = box_x + 1, box_y + 1
        sweep = int((t * 7.0) % (map_h + 6)) - 3      # a CRT band walking down the board
        for y in range(map_h):
            lit = y == sweep
            for x, cell in enumerate(_LAND_ROWS[y][: box_w - 2]):
                if cell == "#":
                    grid.put(mx + x, my + y, glyphs["land"], "38;5;108" if lit else "38;5;23")
                elif lit:
                    grid.put(mx + x, my + y, glyphs["hbar"], "38;5;236")

        # Everything below plots in MAP coordinates and is clipped to the map interior: an impact
        # ring near the right-hand limb reaches ~7 columns past its target, which is enough to punch
        # a hole through the frame if it is allowed to draw there.
        def plot(px: float, py: float, glyph: str, color: str) -> None:
            rx, ry = int(round(px)), int(round(py))
            if 0 <= rx <= box_w - 3 and 0 <= ry < map_h:
                grid.put(mx + rx, my + ry, glyph, color)

        def plot_text(px: int, py: int, text: str, color: str) -> None:
            for offset, ch in enumerate(text):
                plot(px + offset, py, ch, color)

        origin = (float(_BOARD_ORIGIN[0]), float(_BOARD_ORIGIN[1]))
        for asset in self._assets:
            launch_at = asset["launch_at"]
            ax, ay = float(asset["x"]), float(asset["y"])
            if launch_at is None:
                plot(ax, ay, "+", dim)                 # in scope, not yet reached
                continue
            progress = _clamp((t - launch_at) / _FLIGHT)
            if progress <= 0.0:
                plot(ax, ay, "+", dim)
                continue
            resolve_at = asset["resolve_at"]
            landed = resolve_at is not None and t >= resolve_at
            paint = _BOARD_SEV.get(asset["severity"] or "", "38;5;214")
            lift = 3.0 + abs(ax - origin[0]) / 11.0
            control = ((origin[0] + ax) / 2.0, min(origin[1], ay) - lift)
            # The trail drains once the arc has arrived, verdict or not: five permanent arcs across
            # a 72-column board bury the continents, and the board is the point.
            erode_from = resolve_at if landed else (launch_at + _FLIGHT)
            erode = _clamp((t - erode_from) / _ERODE) if progress >= 1.0 else 0.0
            steps = 130
            # ``erode >= 1`` means the trail is fully drained, and the loop below must then draw
            # none of it. ``s < erode`` alone does not say that: the last step is s == 1.0 exactly,
            # which is never < 1.0, so a fully eroded arc kept painting its white HEAD glyph onto
            # the target cell — visible as a bright dot sitting where a severity marker belongs,
            # on every other frame of the marker's own blink.
            for step in range(int(progress * steps) + 1) if erode < 1.0 else ():
                s = step / steps
                if s < erode:
                    continue
                px, py = _bezier(origin, control, (ax, ay), s)
                age = progress - s
                if age < 0.015:
                    glyph, color = glyphs["head"], "1;38;5;231"
                elif age < 0.10:
                    glyph, color = glyphs["arc"][0], "1;38;5;214"
                elif age < 0.30:
                    glyph, color = glyphs["arc"][1], "38;5;208"
                else:
                    glyph, color = glyphs["arc"][2], "38;5;94"
                plot(px, py, glyph, color)
            if not landed:
                # In flight, or arrived and awaiting a verdict: a cross, not a severity marker.
                # Nothing on this board may be coloured by a severity the engine has not reported.
                plot(ax, ay, "+", dim if progress < 1.0
                     else ("38;5;244" if int(t * 1.7) % 2 else "38;5;240"))
                continue
            since = t - resolve_at
            if since < 0.55:
                radius = 1.0 + _ease_out(since / 0.55) * 2.6
                for deg in range(0, 360, 24):
                    rad = math.radians(deg)
                    plot(ax + math.cos(rad) * radius * 2.0, ay + math.sin(rad) * radius,
                         glyphs["ring"], "1;38;5;231" if since < 0.2 else paint)
            if int(t * 2.6) % 2 == 0 or since < 0.55:
                plot(ax, ay, glyphs["blip"], paint)
                tag = asset["tag"]
                # Near the right limb the label would be clipped mid-word, so it flips sides.
                at = int(ax) + 2 if int(ax) + 2 + len(tag) <= box_w - 3 else int(ax) - 1 - len(tag)
                plot_text(at, int(ay), tag, paint)
        plot_text(_BOARD_ORIGIN[0] - 7, _BOARD_ORIGIN[1] - 1, "GREYNOC", "38;5;51")
        plot(_BOARD_ORIGIN[0], _BOARD_ORIGIN[1], glyphs["blip"], "1;38;5;51")

        # --- status bar ---------------------------------------------------------------------------
        bar_y = box_y + map_h + 1
        self._crossrule(box_x, bar_y, box_w, chrome)
        tally = "  ".join(f"{counts[sev]}{sev[0].upper()}" for sev in _SEV_ORDER if counts.get(sev))
        left = f" CONFIRMED  {tally or '--'} "
        grid.text(box_x + 2, bar_y, left, chrome)
        verified = sum(1 for a in self._assets
                       if a["launch_at"] is not None and t >= a["launch_at"] + _FLIGHT)
        extra = f" (+{self._overflow})" if self._overflow else ""
        right = f" ASSETS {verified}/{len(self._assets)}{extra} "
        grid.text(box_x + box_w - 2 - len(right), bar_y, right, chrome)
        # The engine's own phase, in the gap between the two tallies. The gallery has no phase
        # because no engine talks to it — this is the one thing here the prototype never had.
        gap_from = box_x + 3 + len(left)
        gap_to = box_x + box_w - 3 - len(right)
        if self._phase and gap_to - gap_from >= 8:
            phase = self._phase[: gap_to - gap_from]
            grid.text(gap_from + max(0, (gap_to - gap_from - len(phase)) // 2), bar_y,
                      phase, "38;5;101")

        # --- teletype, scrolling the way paper does: the line being typed is the bottom one -------
        shown = [line for line in self._lines if line[0] <= t]
        if len(shown) > 1:
            grid.text(box_x + 2, bar_y + 1, shown[-2][1][: box_w - 5], "38;5;240")
        if shown:
            when, text, color = shown[-1]
            typed = _typed(text, t - when, 62.0)
            grid.text(box_x + 2, bar_y + 2, typed[: box_w - 5], color)
            if int(t * 3) % 2 == 0:
                grid.put(box_x + 2 + min(len(typed), box_w - 6), bar_y + 2,
                         self._glyphs["cursor"], color)
        # No rule drawn here: _frame_box already laid the bottom edge WITH its corners, and ruling
        # over it replaced them with straight bar, so the box read as cut open at both bottom
        # corners. The footer text goes straight onto that edge.
        # The standing statement is the part that may not be cut — it is what the board is
        # claiming about its own authority — so a scope too long for the remaining columns is
        # elided instead. Seen on a 74-column terminal, where " SCOPE example.com :: " was enough
        # to truncate READ-ONLY PROOF to "REA".
        room = box_w - 4
        footer = f" {self._footer} "
        if self._scope:
            spare = room - len(footer) - len("SCOPE   ::  ")
            scope = self._scope if len(self._scope) <= spare else self._scope[: max(0, spare - 1)] + "~"
            if spare > 3:
                footer = f" SCOPE {scope}  ::  {self._footer} "
        grid.text(box_x + 2, box_y + box_h - 1, footer[:room], dim)

    def _clock(self, t: float) -> str:
        if self._clock_base is None:
            return time.strftime("%H:%M:%S", time.gmtime())
        secs = int(self._clock_base + t)
        return f"{secs // 3600 % 24:02d}:{secs // 60 % 60:02d}:{secs % 60:02d}"

    def _hrule(self, x: int, y: int, w: int, color: str) -> None:
        for index in range(w):
            self._grid.put(x + index, y, self._glyphs["hbar"], color)

    def _crossrule(self, x: int, y: int, w: int, color: str) -> None:
        """A divider INSIDE the box, tee'd into both side edges rather than written over them."""
        left, right = self._glyphs["tees"]
        self._hrule(x + 1, y, w - 2, color)
        self._grid.put(x, y, left, color)
        self._grid.put(x + w - 1, y, right, color)

    def _frame_box(self, x: int, y: int, w: int, h: int, color: str) -> None:
        tl, tr, bl, br = self._glyphs["corners"]
        left, right = self._glyphs["edges"]
        self._hrule(x, y, w, color)
        self._hrule(x, y + h - 1, w, color)
        for row in range(1, h - 1):
            self._grid.put(x, y + row, left, color)
            self._grid.put(x + w - 1, y + row, right, color)
        self._grid.put(x, y, tl, color)
        self._grid.put(x + w - 1, y, tr, color)
        self._grid.put(x, y + h - 1, bl, color)
        self._grid.put(x + w - 1, y + h - 1, br, color)


# --- what the engines actually tell us -----------------------------------------------------------
# The board wants two events per asset: it entered verification, and a finding landed on it. The
# engines give us one and a half, and this is the whole of it — read before changing any of it:
#
#   LAUNCHES are real and live. Four messages name an asset at the moment its hunt begins:
#     * ``bounty.py``       ``hunt: {target} (profile={name})``   — a single hunt's seed target
#     * ``campaign.py``     ``hunt {i}/{n}: {url}``               — each crawled URL, as it starts
#     * ``campaign.py``     ``[{i}/{n} {target}] starting…``      — each span target, as it starts
#     * ``operator.py``     ``hunt {program}: {target}``          — each portfolio target (on_event)
#   The span/portfolio prefix is parsed first and then the inner message, because those paths run
#   several targets CONCURRENTLY: each line carries its own target, so no line has to be attributed
#   by guessing which one is "current", and nothing is attributed by position. There is deliberately
#   no notion of a current unit here — a line this cannot attribute becomes a log line and nothing
#   else moves.
#
#   FINDINGS DO NOT STREAM. Nothing reaches ``on_progress`` that carries a severity and a host.
#   ``bounty.py`` emits the active pass as counts (``active verification complete — 1 confirmed``)
#   and ``campaign.py`` streams the structured per-URL findings to ``bughunter.progress`` — an
#   in-memory ring the API/UI polls, which the CLI is not on. Nor does the per-endpoint fan-out in
#   ``bounty.py`` name the endpoints it sweeps; it emits their COUNT
#   (``active recon: checking 7 discovered in-scope endpoint(s)``) and nothing else.
#   So arcs RESOLVE FROM THE RESULT DICT, at the end, through :meth:`BoardFeed.report` — whose
#   findings carry ``source_url``/``location``, a severity and a proof status, which is everything
#   the marker needs and nothing it has to infer. A campaign's arcs therefore fly and land live,
#   one per URL as the engine reaches it, and then all light up together when the verdicts arrive.
#
# The alternative was to add per-finding emits to bughunter and have the board look continuous.
# That would be a real event at a real moment, but it is a change to the engine's output contract
# for every consumer — made to improve an animation — and it is not needed to tell the truth. The
# board says what it knows when it knows it, and :meth:`Board.hold` buys the verdicts a second and
# a half on screen so the operator sees them land.

#: ``[{index}/{total} {target}] {message}`` — the per-target prefix the span and portfolio paths put
#: on every line (campaign.py's ``_target_emit``/``_p_emit``). Stripped first; the remainder is then
#: matched against the launch patterns, since a span line is ``[1/3 host] hunt 1/4: url``.
_FEED_PREFIX = re.compile(r"^\[\s*\d+\s*/\s*\d+\s+(\S+)\s*\]\s*(.*)$")
#: ``hunt {index}/{total}: {url}`` — campaign.py's per-URL loop.
_FEED_URL = re.compile(r"^hunt\s+\d+\s*/\s*\d+\s*:\s*(\S+)\s*$")
#: ``hunt: {target} (profile={name})`` — bounty.py's opening line for one hunt.
_FEED_SEED = re.compile(r"^hunt:\s+(\S+)\s+\(profile=")
#: ``hunt {program_id}: {target}`` — operator.py's per-target cycle event. Deliberately narrow:
#: ``hunt-planner:``, ``hunt-brain:`` and ``hunt-loop turn 1:`` must not match, and the one other
#: message in this shape (``hunt {pid}: SKIPPED — no huntable targets``) is rejected by
#: :func:`_looks_like_asset` rather than by listing the words it is not.
_FEED_PROGRAM = re.compile(r"^hunt\s+[^\s:/]+\s*:\s*(\S+)\s*$")


def _looks_like_asset(token: str) -> bool:
    """Whether a token the engine printed is plausibly a thing that can be hunted.

    The gate that keeps prose off the map. ``hunt {pid}: SKIPPED — no huntable targets`` matches the
    program pattern perfectly and its "target" is the word SKIPPED; an asset has a scheme, a dot or
    a separator, and a bare English word has none of the three. Conservative on purpose: a missed
    arc costs an animation, a wrong one puts a target on a threat board that was never touched.
    """
    text = str(token or "").strip().strip(",;")
    if not text or len(text) > 400:
        return False
    if "://" in text:
        return True
    if "." in text.strip("."):
        return True
    return "/" in text or "\\" in text


def confirmed_findings(result: Any, default: str = "") -> list[tuple[str, str, str]]:
    """``(asset, severity, title)`` for every CONFIRMED finding in a finished result dict.

    Confirmed only, and read from the engine's own proof status rather than the severity field: the
    whole point of this program is that a candidate is not a finding, so a passive header lead must
    not light up a Critical marker on a threat board. A run that confirms nothing returns nothing,
    which is the honest outcome and the one the board draws as DEFCON 5.

    Four places carry that status, because four code paths set it: on the finding (a campaign's
    ``proof_status``, an active-confirmed hunt finding's own), in the result's ``proof_of_impact``
    map keyed by ref (campaign), in the attack plan for that ref (a single hunt), or inline on the
    finding. All four are consulted; none is invented.
    """
    out: list[tuple[str, str, str]] = []
    try:
        findings = (result or {}).get("findings") or []
        proof = (result or {}).get("proof_of_impact") or {}
        plans = (result or {}).get("attack_plans") or {}
    except Exception:  # noqa: BLE001 - a result this module cannot read is not a reason to raise
        return out

    def _status_of(mapping: Any, ref: Any) -> str:
        entry = mapping.get(ref) if isinstance(mapping, dict) else None
        return str((entry or {}).get("status") or "") if isinstance(entry, dict) else ""

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        ref = finding.get("ref")
        inline = finding.get("proof_of_impact")
        candidates = (
            str(finding.get("proof_status") or ""),
            _status_of(proof, ref),
            _status_of((plans.get(ref) or {}) if isinstance(plans, dict) else {}, "proof_of_impact"),
            str((inline or {}).get("status") or "") if isinstance(inline, dict) else "",
        )
        if not any(value.strip().lower() == "confirmed" for value in candidates):
            continue
        asset = str(finding.get("source_url") or finding.get("location") or default or "").strip()
        severity = str(finding.get("severity") or "info").strip().lower()
        out.append((asset, severity, str(finding.get("title") or "")))
    return out


class BoardFeed:
    """The engines' prose, turned into board verbs. Usable directly as ``on_progress``/``on_event``.

    The counterpart of :func:`progress_sink` for the full-screen surface, and the only place that
    knows anything about what the engines say. See the block comment above for the whole of what
    they report and when — in particular, why :meth:`report` exists at all.
    """

    def __init__(self, board: "Board") -> None:
        self._board = board

    def __call__(self, message: str) -> None:
        """One progress line. Total: a sink must never break the hunt feeding it."""
        try:
            self._feed(str(message or ""))
        except Exception:  # noqa: BLE001 - an unparseable message costs an arc, never the run
            pass

    def _feed(self, message: str) -> None:
        text = message.strip()
        if not text:
            return
        unit, body = "", text
        prefix = _FEED_PREFIX.match(text)
        if prefix:
            unit, body = prefix.group(1).strip(), prefix.group(2).strip()

        launched = ""
        for pattern in (_FEED_URL, _FEED_SEED, _FEED_PROGRAM):
            hit = pattern.match(body)
            if hit and _looks_like_asset(hit.group(1)):
                launched = hit.group(1).strip()
                break
        # The span's own per-target start, which carries no inner launch line of its own.
        if not launched and unit and body.lower().startswith("starting") and _looks_like_asset(unit):
            launched = unit

        if launched:
            self._board.launch(launched)
        elif unit and _looks_like_asset(unit):
            # A line about a target whose arc has not been triggered by anything: put it on the map
            # as an unlit cross, since the engine has named it as in scope, but do not fly an arc —
            # "the engine mentioned this" is not "the engine started verifying this".
            self._board.track([unit])
        self._board.phase(body or text)
        self._board.log(f"> {text}")

    def report(self, result: Any, default: str = "") -> int:
        """Land the arcs for a finished result dict. Returns how many confirmed findings it drew.

        ``default`` is the asset to attribute a finding that names none of its own — the verb's own
        target, which is the one thing the CLI knows for certain about a result it just received.
        """
        drawn = 0
        try:
            for asset, severity, title in confirmed_findings(result, default=default):
                if not asset:
                    self._board.hit(severity, title)      # confirmed, but attributable to nothing
                    continue
                self._board.resolve(asset, severity, title)
                self._board.log(f"> {title or severity.upper()}  ::  CONFIRMED  ::  {severity.upper()}",
                                _BOARD_SEV.get(severity, "38;5;214"))
                drawn += 1
        except Exception:  # noqa: BLE001 - a decoration must never break a completed hunt
            pass
        return drawn


def report_result(fx: Any, result: Any, default: str = "") -> int:
    """Land every CONFIRMED finding in a finished result dict on whichever surface is live.

    The counterpart of :func:`progress_sink` for the end of a run, and the one place the
    confirmed-only rule is written down (see :func:`confirmed_findings` for why it is confirmed
    only). On the board each finding lands its asset's arc in that severity's colour; on the line
    each one flashes it, exactly as it did before the board existed. Returns how many landed, so a
    caller can decide whether the final frame is worth pausing on.
    """
    if fx is None or not getattr(fx, "active", False):
        return 0
    if isinstance(fx, Board):
        return BoardFeed(fx).report(result, default=default)
    drawn = 0
    try:
        for asset, severity, title in confirmed_findings(result, default=default):
            fx.resolve(asset, severity, title)
            drawn += 1
    except Exception:  # noqa: BLE001 - a decoration must never break a completed hunt
        pass
    return drawn


def board(title: str, *, scope: str = "", stream: TextIO | None = None,
          active: bool | None = None) -> Board:
    """A :class:`Board` for ``with`` use. Inert unless a human is watching a terminal big enough."""
    return Board(title, scope=scope, stream=stream, active=active)


def surface(title: str, *, scope: str = "", stream: TextIO | None = None,
            active: bool | None = None) -> Any:
    """The richest live surface this terminal can take: the threat board, else the status line.

    The board needs ~78x24 and the whole screen. A narrower terminal, a split pane, ``NO_COLOR``, a
    pipe — anything the board cannot have — falls back to the one-line :class:`Scanner`, which has
    the same vocabulary, so a caller never asks which one it got. ``active=False`` forces the inert
    line, which is what ``--no-fx`` and ``--json`` ask for.
    """
    if active is False:
        return scanner(title, stream=stream, active=False)
    target = stream if stream is not None else sys.stderr
    if enabled(target) and board_fits(target):
        return board(title, scope=scope, stream=target, active=active)
    return scanner(title, stream=stream, active=active)


#: The scripted sequence, ordered so DEFCON descends honestly: each finding is worse than the one
#: before it. ``example.com`` is RFC 2606 example space — the demo flies five attack arcs at these
#: hosts, and a domain somebody actually owns has no business being on the receiving end.
_BOARD_DEMO: tuple[tuple[str, str, str, float], ...] = (
    ("cdn.example.com", "info", "CACHE KEY NORMALISATION", 1.2),
    ("legacy.example.com", "low", "STACK TRACE DISCLOSURE", 2.8),
    ("vpn.example.com", "medium", "IKE FINGERPRINT LEAK", 4.4),
    ("api.example.com", "high", "SSRF -> CLOUD METADATA", 6.0),
    ("sso.example.com", "critical", "AUTH BYPASS -> ADMIN", 7.6),
)
_BOARD_DEMO_CLOCK = 2 * 3600 + 17 * 60 + 9     # the gallery's scripted clock, for reproducible stills


def board_demo(stream: TextIO | None = None) -> int:
    """``gn fx wopr`` — run the board's demo sequence, so a terminal can be checked without a hunt.

    The same five hosts, severities, labels and timings the gallery plays, driven through the LIVE
    feed rather than as a function of time: this exercises ``track``/``launch``/``resolve``/``log``
    exactly as a hunt does, so what it proves about this terminal is what a hunt will do on it.
    Says SIMULATION in its own footer, and the hosts are example space, because a board that looks
    like a hunt must never be mistakable for one that happened.
    """
    target = stream if stream is not None else sys.stderr
    if not enabled(target):
        print("gn: motion needs a terminal (stderr is redirected, NO_COLOR is set, or GN_NO_FX is on).",
              file=sys.stderr)
        return 2
    if not board_fits(target):
        cols, rows = _terminal_size(target)
        print(f"gn: the threat board needs a {_BOARD_MIN_COLS}x{_BOARD_ROWS} terminal; this one is "
              f"{cols}x{rows}. `gn fx` draws the one-line status animation instead.", file=sys.stderr)
        return 2
    live = Board("GREYNOC // WOPR-IQ", scope="example.com", stream=target,
                 footer="SIMULATION  ::  READ-ONLY PROOF",
                 clock_base=float(_BOARD_DEMO_CLOCK))
    with live:
        live.track([name for name, _s, _l, _at in _BOARD_DEMO])
        live.log("> WOPR-IQ ONLINE  ::  SCOPE example.com  ::  AUTHORIZATION ON FILE")
        live.phase("scripted demo")
        pending = [(at, name, severity, label) for name, severity, label, at in _BOARD_DEMO]
        events: list[tuple[float, str, Any]] = []
        for at, name, severity, label in pending:
            events.append((at, "launch", (name,)))
            events.append((at + _FLIGHT, "resolve", (name, severity, label)))
        events.sort(key=lambda row: row[0])
        for at, kind, payload in events:
            wait = at - live.now()
            if wait > 0:
                live.hold(wait)
            if kind == "launch":
                live.launch(payload[0])
                live.log(f"> PLOTTING TRAJECTORY  {payload[0]}")
                live.phase("active verification")
            else:
                name, severity, label = payload
                live.resolve(name, severity, label)
                live.log(f"> {label}  ::  CONFIRMED  ::  {severity.upper()}",
                         _BOARD_SEV.get(severity, "38;5;214"))
        live.log("> 5 OF 5 ARCS RESOLVED  ::  PROOF CHAIN COMPLETE  ::  NO FABRICATION",
                 _BOARD_SEV["critical"])
        live.phase("demo complete")
        live.hold(3.0)
    return 0
