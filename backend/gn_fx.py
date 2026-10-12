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
"""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, TextIO

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

#: Every scanner that has started and not yet stopped. ``gn_cli.main`` drains this in a finally, so a
#: verb that returns early down an error path cannot leave a half-drawn line on the operator's
#: terminal — which is easy to do, since the long verbs have several ``return _err(...)`` exits.
_LIVE: list["Scanner"] = []
_LIVE_LOCK = threading.Lock()


def stop_all(summary: str = "") -> None:
    """Stop and clear every live scanner. Total and idempotent — safe in a ``finally``."""
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


def progress_sink(fx: Scanner | None, fallback: Any = None) -> Any:
    """Turn a Scanner into the ``on_progress(message)`` callable the engines already take.

    With motion on, a message updates the live phase AND scrolls above the tank. With motion off
    (a pipe, ``--json``, CI, the test suite) this returns ``fallback`` untouched, so every existing
    caller keeps byte-identical output. That split is why adding motion could not regress any of the
    stdout literals the CLI tests pin.
    """
    if fx is None or not fx.active:
        return fallback

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
