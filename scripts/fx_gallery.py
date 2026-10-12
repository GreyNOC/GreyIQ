#!/usr/bin/env python3
"""Three 90s-movie terminal renderings for GreyIQ, side by side so one can be chosen.

    python scripts/fx_gallery.py all                 # play all three, in order
    python scripts/fx_gallery.py wopr                # NORAD threat board (WarGames, 1983)
    python scripts/fx_gallery.py cryptlock           # decryption cascade (Sneakers / The Matrix)
    python scripts/fx_gallery.py wireframe           # rotating wireframe scope (Hackers, 1995)
    python scripts/fx_gallery.py wopr --capture 4    # still frames, no cursor control, for review

This is a prototype gallery, not yet wired into ``gn``. It is deliberately stdlib-only and every
scene is a PURE FUNCTION OF TIME -- ``draw(canvas, t)`` with no frame-to-frame state. That buys
three things: ``--capture`` can seek to any instant for review or a CI snapshot, a dropped frame
never desynchronises the animation, and whichever direction wins ports to the landing page as the
same arithmetic driven by ``requestAnimationFrame`` instead of ``time.monotonic``.

Like ``backend/gn_fx.py``, it refuses to draw where no human is watching, probes its glyphs against
the live stream's encoding before using them (a Windows cp1252 console gets the ASCII set rather
than a screen of ``?``), and restores the terminal in a ``finally``.
"""
from __future__ import annotations

import argparse
import math
import os
import shutil
import sys
import time
from typing import Any, Sequence, TextIO

RESET = "\033[0m"
# Alternate screen + hidden cursor + auto-wrap off, so a full-width frame cannot scroll the view
# and the operator's scrollback survives the animation untouched.
TERM_ENTER = "\033[?1049h\033[?25l\033[?7l"
TERM_LEAVE = "\033[?7h\033[?25h\033[?1049l"


# --- terminal plumbing ---------------------------------------------------------------------------
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


def _encodable(text: str, stream: TextIO) -> bool:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        text.encode(encoding, errors="strict")
    except (UnicodeEncodeError, LookupError, TypeError):
        return False
    return True


def pick_glyphs(preferred: dict[str, Any], fallback: dict[str, Any], stream: TextIO) -> dict[str, Any]:
    """The richer glyph set if this stream can encode all of it; the ASCII one otherwise."""
    probe = "".join(
        "".join(value) if isinstance(value, (tuple, list)) else str(value)
        for value in preferred.values()
    )
    return preferred if _encodable(probe, stream) else fallback


# --- canvas --------------------------------------------------------------------------------------
class Canvas:
    """A character grid with a per-cell SGR code, rendered as one string with colour runs merged.

    Merging runs matters: a naive per-cell escape makes an 80x24 frame ~20 KB, and at 20 fps that
    is enough write traffic to make the animation itself the slow part over ssh.
    """

    def __init__(self, width: int, height: int, *, color: bool = True) -> None:
        self.w = max(1, int(width))
        self.h = max(1, int(height))
        self.color = bool(color)
        self._ch = [[" "] * self.w for _ in range(self.h)]
        self._co: list[list[str | None]] = [[None] * self.w for _ in range(self.h)]

    def clear(self) -> None:
        for y in range(self.h):
            chars, colors = self._ch[y], self._co[y]
            for x in range(self.w):
                chars[x] = " "
                colors[x] = None

    def put(self, x: int, y: int, ch: str, color: str | None = None) -> None:
        x, y = int(x), int(y)
        if 0 <= x < self.w and 0 <= y < self.h and ch:
            self._ch[y][x] = ch[0]
            self._co[y][x] = color

    def blank(self, x: int, y: int) -> bool:
        x, y = int(x), int(y)
        if 0 <= x < self.w and 0 <= y < self.h:
            return self._ch[y][x] == " "
        return False

    def text(self, x: int, y: int, text: str, color: str | None = None) -> None:
        for index, ch in enumerate(str(text)):
            self.put(x + index, y, ch, color)

    def center(self, y: int, text: str, color: str | None = None, *, within: int = 0) -> None:
        span = within or self.w
        self.text(max(0, (span - len(text)) // 2), y, text, color)

    def rows(self) -> list[str]:
        out: list[str] = []
        for y in range(self.h):
            chars, colors = self._ch[y], self._co[y]
            if not self.color:
                out.append("".join(chars))
                continue
            parts: list[str] = []
            run: list[str] = []
            current: str | None = colors[0]
            for x in range(self.w):
                if colors[x] != current:
                    parts.append(f"\033[{current}m{''.join(run)}{RESET}" if current else "".join(run))
                    run = []
                    current = colors[x]
                run.append(chars[x])
            parts.append(f"\033[{current}m{''.join(run)}{RESET}" if current else "".join(run))
            out.append("".join(parts))
        return out


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return low if value < low else high if value > high else value


def ease_out(x: float) -> float:
    x = clamp(x)
    return 1.0 - (1.0 - x) * (1.0 - x)


def typed(text: str, elapsed: float, cps: float = 55.0) -> str:
    """How much of ``text`` a teletype running at ``cps`` has printed after ``elapsed`` seconds."""
    if elapsed <= 0:
        return ""
    return text[: int(elapsed * cps)]


# --- scene base ----------------------------------------------------------------------------------
class Scene:
    key = ""
    title = ""
    pitch = ""
    duration = 12.0

    def __init__(self, width: int, height: int, *, stream: TextIO, color: bool, seed: int) -> None:
        self.w, self.h = width, height
        self.stream = stream
        self.color = color
        self.seed = seed

    def draw(self, canvas: Canvas, t: float) -> None:  # pragma: no cover - subclasses draw
        raise NotImplementedError

    # Deterministic noise, so every frame is reproducible from (t, seed) alone -- which is what
    # makes --capture a real snapshot rather than a lucky one.
    def hashed(self, *values: int) -> int:
        acc = 0x9E3779B9 ^ (self.seed & 0xFFFFFFFF)
        for value in values:
            acc = (acc * 1664525 + (int(value) & 0xFFFFFFFF) * 1013904223 + 0x9E37) & 0xFFFFFFFF
            acc ^= acc >> 15
        return acc

    def pick(self, options: Sequence[str], *values: int) -> str:
        return options[self.hashed(*values) % len(options)]


# --- shared chrome -------------------------------------------------------------------------------
class Chrome:
    """Box drawing against a Canvas with one glyph set, shared by the scenes that need a frame."""

    def __init__(self, canvas: Canvas, glyphs: dict[str, Any]) -> None:
        self.c = canvas
        self.g = glyphs

    def hrule(self, x: int, y: int, w: int, color: str) -> None:
        for index in range(w):
            self.c.put(x + index, y, self.g["hbar"], color)

    def frame(self, x: int, y: int, w: int, h: int, color: str) -> None:
        tl, tr, bl, br = self.g["corners"]
        left, right = self.g["edges"]
        self.hrule(x, y, w, color)
        self.hrule(x, y + h - 1, w, color)
        for row in range(1, h - 1):
            self.c.put(x, y + row, left, color)
            self.c.put(x + w - 1, y + row, right, color)
        self.c.put(x, y, tl, color)
        self.c.put(x + w - 1, y, tr, color)
        self.c.put(x, y + h - 1, bl, color)
        self.c.put(x + w - 1, y + h - 1, br, color)


_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_PAINT = {
    "critical": "1;38;5;196",
    "high": "38;5;202",
    "medium": "38;5;214",
    "low": "38;5;228",
    "info": "38;5;109",
}


# =================================================================================================
# 1. WOPR -- the NORAD threat board
# =================================================================================================
# Land as inclusive spans on a 72x17 equirectangular grid. Spans rather than 72-char string
# literals because a continent is then a number to nudge, not a column to count.
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
_MAP_W, _MAP_H = 72, 17

# name, map x, map y, severity, launch second, what the arc resolved into
_WOPR_TARGETS: tuple[tuple[str, int, int, str, float, str], ...] = (
    ("api.example.com",    36,  4, "high",     1.4, "SSRF -> CLOUD METADATA"),
    ("sso.example.com",    23, 11, "critical", 3.0, "AUTH BYPASS -> ADMIN"),
    ("vpn.example.com",    59,  6, "medium",   4.6, "IKE FINGERPRINT LEAK"),
    ("legacy.example.com", 34,  8, "low",      6.2, "STACK TRACE DISCLOSURE"),
    ("cdn.example.com",    65, 13, "info",     7.8, "CACHE KEY NORMALISATION"),
)
_WOPR_ORIGIN = (12, 4)
_FLIGHT = 1.7

_WOPR_UNI = {
    "edges": ("│", "│"),
    "corners": ("┌", "┐", "└", "┘"),
    "hbar": "─",
    "land": "▒",
    "arc": ("●", "▪", "·"),
    "head": "◉",
    "blip": "◆",
    "ring": "○",
    "cursor": "█",
}
_WOPR_ASCII = {
    "edges": ("|", "|"),
    "corners": ("+", "+", "+", "+"),
    "hbar": "-",
    "land": ":",
    "arc": ("*", "+", "."),
    "head": "@",
    "blip": "#",
    "ring": "o",
    "cursor": "_",
}


class Wopr(Scene):
    key = "wopr"
    title = "WOPR  --  the threat board"
    pitch = "arcs fly from the node to every in-scope asset; DEFCON falls as each proof lands"
    duration = 13.0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.g = pick_glyphs(_WOPR_UNI, _WOPR_ASCII, self.stream)
        self.land = self._land_rows()
        self.beats = self._beats()

    @staticmethod
    def _land_rows() -> list[str]:
        rows: list[str] = []
        for y in range(_MAP_H):
            cells = [" "] * _MAP_W
            for x0, x1 in _LAND_SPANS.get(y, ()):
                for x in range(max(0, x0), min(_MAP_W - 1, x1) + 1):
                    cells[x] = "#"
            rows.append("".join(cells))
        return rows

    @staticmethod
    def _beats() -> list[tuple[float, str, str]]:
        """(when, text, colour) for the teletype -- the whole run scripted up front."""
        amber, hot = "38;5;214", "1;38;5;196"
        out: list[tuple[float, str, str]] = [
            (0.1, "> WOPR-IQ ONLINE  ::  SCOPE example.com  ::  AUTHORIZATION ON FILE", amber),
        ]
        for name, _x, _y, severity, launch, label in _WOPR_TARGETS:
            out.append((launch, f"> PLOTTING TRAJECTORY  {name}", amber))
            paint = hot if severity in ("critical", "high") else amber
            out.append((launch + _FLIGHT + 0.05,
                        f"> {label}  ::  CONFIRMED  ::  {severity.upper()}", paint))
        out.append((_WOPR_TARGETS[-1][4] + _FLIGHT + 1.0,
                    "> 5 OF 5 ARCS RESOLVED  ::  PROOF CHAIN COMPLETE  ::  NO FABRICATION", hot))
        return out

    @staticmethod
    def _bezier(p0: tuple[float, float], p1: tuple[float, float], p2: tuple[float, float],
                s: float) -> tuple[float, float]:
        inv = 1.0 - s
        return (inv * inv * p0[0] + 2 * inv * s * p1[0] + s * s * p2[0],
                inv * inv * p0[1] + 2 * inv * s * p1[1] + s * s * p2[1])

    def draw(self, canvas: Canvas, t: float) -> None:
        g = self.g
        chrome, dim = "38;5;178", "38;5;58"
        box = Chrome(canvas, g)

        box_w = min(canvas.w, _MAP_W + 2)
        box_x = max(0, (canvas.w - box_w) // 2)
        map_h = min(_MAP_H, max(6, canvas.h - 6))
        box_h = map_h + 5
        box_y = max(0, (canvas.h - box_h) // 2)
        box.frame(box_x, box_y, box_w, box_h, chrome)

        resolved = [tgt for tgt in _WOPR_TARGETS if t >= tgt[4] + _FLIGHT]
        counts: dict[str, int] = {}
        for _n, _x, _y, severity, _l, _lab in resolved:
            counts[severity] = counts.get(severity, 0) + 1
        # DEFCON is the worst CONFIRMED severity (critical 1 ... nothing 5), the same rule the live
        # board in backend/gn_fx.py applies. Counting resolved arcs instead reads fine on a demo
        # that happens to confirm them worst-last, and then says DEFCON 4 over a confirmed HIGH.
        defcon = min((_SEV_ORDER.index(tgt[3]) + 1 for tgt in resolved), default=5)

        # --- header -------------------------------------------------------------------------------
        canvas.text(box_x + 2, box_y, " GREYNOC // WOPR-IQ ", "1;38;5;214")
        label = f" DEFCON {defcon} "
        canvas.text(box_x + box_w - 13 - len(label), box_y, label,
                    "1;7;38;5;196" if defcon <= 2 else "1;38;5;214")
        clock = time.strftime("%H:%M:%S", time.gmtime(2 * 3600 + 17 * 60 + 9 + t))
        canvas.text(box_x + box_w - 12, box_y, f" {clock} ", chrome)

        # --- map ----------------------------------------------------------------------------------
        mx, my = box_x + 1, box_y + 1
        sweep = int((t * 7.0) % (map_h + 6)) - 3   # a CRT band walking down the board
        for y in range(map_h):
            lit = y == sweep
            for x, cell in enumerate(self.land[y][: box_w - 2]):
                if cell == "#":
                    canvas.put(mx + x, my + y, g["land"], "38;5;108" if lit else "38;5;23")
                elif lit:
                    canvas.put(mx + x, my + y, g["hbar"], "38;5;236")

        # --- the node and its arcs ----------------------------------------------------------------
        # Everything below plots in MAP coordinates and is clipped to the map interior. An impact
        # ring near the right-hand limb reaches ~7 columns past its target, which is enough to punch
        # a hole through the frame if it is allowed to draw there.
        def plot(x: float, y: float, glyph: str, color: str) -> None:
            if 0 <= round(x) <= box_w - 3 and 0 <= round(y) < map_h:
                canvas.put(mx + round(x), my + round(y), glyph, color)

        def plot_text(x: int, y: int, text: str, color: str) -> None:
            for offset, ch in enumerate(text):
                plot(x + offset, y, ch, color)

        origin = (float(_WOPR_ORIGIN[0]), float(_WOPR_ORIGIN[1]))
        for name, tx, ty, severity, launch, _label in _WOPR_TARGETS:
            progress = clamp((t - launch) / _FLIGHT)
            paint = _SEV_PAINT[severity]
            if progress <= 0.0:
                plot(tx, ty, "+", dim)
                continue
            lift = 3.0 + abs(tx - origin[0]) / 11.0
            control = ((origin[0] + tx) / 2.0, min(origin[1], ty) - lift)
            steps = 130
            # After impact the trail drains into the target rather than persisting: five permanent
            # arcs across a 72-column board bury the continents, and the board is the point.
            erode = clamp((t - (launch + _FLIGHT)) / 0.9) if progress >= 1.0 else 0.0
            for step in range(int(progress * steps) + 1):
                s = step / steps
                if s < erode:
                    continue
                px, py = self._bezier(origin, control, (float(tx), float(ty)), s)
                age = progress - s
                if age < 0.015:
                    glyph, color = g["head"], "1;38;5;231"
                elif age < 0.10:
                    glyph, color = g["arc"][0], "1;38;5;214"
                elif age < 0.30:
                    glyph, color = g["arc"][1], "38;5;208"
                else:
                    glyph, color = g["arc"][2], "38;5;94"
                plot(px, py, glyph, color)
            if progress < 1.0:
                plot(tx, ty, "+", dim)
                continue
            # Impact ring, then a marker that keeps blinking in its severity colour.
            since = t - (launch + _FLIGHT)
            if since < 0.55:
                radius = 1.0 + ease_out(since / 0.55) * 2.6
                for deg in range(0, 360, 24):
                    rad = math.radians(deg)
                    plot(tx + math.cos(rad) * radius * 2.0, ty + math.sin(rad) * radius,
                         g["ring"], "1;38;5;231" if since < 0.2 else paint)
            if int(t * 2.6) % 2 == 0 or since < 0.55:
                plot(tx, ty, g["blip"], paint)
                plot_text(tx + 2, ty, name.split(".")[0].upper()[:9], paint)
        plot_text(_WOPR_ORIGIN[0] - 7, _WOPR_ORIGIN[1] - 1, "GREYNOC", "38;5;51")
        plot(_WOPR_ORIGIN[0], _WOPR_ORIGIN[1], g["blip"], "1;38;5;51")

        # --- footer -------------------------------------------------------------------------------
        bar_y = box_y + map_h + 1
        box.hrule(box_x, bar_y, box_w, chrome)
        tally = "  ".join(f"{counts[sev]}{sev[0].upper()}" for sev in _SEV_ORDER if counts.get(sev))
        canvas.text(box_x + 2, bar_y, f" CONFIRMED  {tally or '--'} ", chrome)
        assets = f" ASSETS {len(resolved)}/{len(_WOPR_TARGETS)} "
        canvas.text(box_x + box_w - 2 - len(assets), bar_y, assets, chrome)

        # Teletype, scrolling the way paper does: the line being typed is the bottom one.
        history = [beat for beat in self.beats if beat[0] <= t]
        if len(history) > 1:
            canvas.text(box_x + 2, bar_y + 1, history[-2][1][: box_w - 5], "38;5;240")
        if history:
            when, text, paint = history[-1]
            shown = typed(text, t - when, 62.0)
            canvas.text(box_x + 2, bar_y + 2, shown[: box_w - 5], paint)
            if int(t * 3) % 2 == 0:
                canvas.put(box_x + 2 + min(len(shown), box_w - 6), bar_y + 2, g["cursor"], paint)
        box.hrule(box_x, box_y + box_h - 1, box_w, chrome)
        canvas.text(box_x + 2, box_y + box_h - 1,
                    " SIMULATION  ::  AUTHORIZED SCOPE ONLY  ::  READ-ONLY PROOF ", dim)


# =================================================================================================
# 2. CRYPTLOCK -- the decryption cascade
# =================================================================================================
_BLOCK_FONT = {
    "G": ("#####", "#    ", "#  ##", "#   #", "#####"),
    "R": ("#### ", "#   #", "#### ", "#  # ", "#   #"),
    "E": ("#####", "#    ", "#### ", "#    ", "#####"),
    "Y": ("#   #", "#   #", " ### ", "  #  ", "  #  "),
    "I": ("#####", "  #  ", "  #  ", "  #  ", "#####"),
    "Q": (" ### ", "#   #", "# # #", "#  # ", " ## #"),
}
_WORD = "GREYIQ"

# No katakana, however much it wants to be in a Matrix homage: U+30A2 and friends are East Asian
# Wide, so a terminal spends TWO cells on them and every glyph to the right of one shears out of
# the grid. Everything here is narrow -- hex, operators, and the two shade blocks.
_RAIN_UNI = {
    "ink": "█",
    "glyphs": ("0", "1", "7", "3", "9", "F", "A", "E", "D", "§", "±", "¬",
               "»", "«", "▒", "░", "$", "%", "&", "*", "=", "<", ">", "/"),
    "bar": "▒",
}
_RAIN_ASCII = {
    "ink": "#",
    "glyphs": ("0", "1", "7", "3", "9", "F", "A", "E", "D", "$", "%", "&", "*", "+", "=",
               "<", ">", "/", "\\", "|", "!", "?", "#", "~"),
    "bar": ":",
}

# The decryption log down the left -- true to what GreyIQ actually negotiates.
_CRYPT_LOG = (
    (1.0, "ML-KEM-768 ENCAPSULATION", "OK"),
    (1.9, "X25519MLKEM768 HYBRID HANDSHAKE", "OK"),
    (2.8, "LEDGER SIGNATURE  ML-DSA-65", "OK"),
    (3.7, "EVIDENCE CHAIN  SHA-256", "SEALED"),
    (4.6, "EGRESS SOCKETS", "NONE"),
)
_LOCK_START = 2.2
_LOCK_SPREAD = 0.055


class Cryptlock(Scene):
    key = "cryptlock"
    title = "CRYPTLOCK  --  the decryption cascade"
    pitch = "glyph rain resolves character by character into the mark; the log seals underneath"
    duration = 12.0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.g = pick_glyphs(_RAIN_UNI, _RAIN_ASCII, self.stream)
        self.banner = self._banner()
        # When the last cell locks -- everything after is timed off this, not a second constant.
        self.locked_at = max(self._lock_time(x, y) for x, y in self.banner) + 0.35

    @staticmethod
    def _banner() -> list[tuple[int, int]]:
        cells: list[tuple[int, int]] = []
        for index, letter in enumerate(_WORD):
            rows = _BLOCK_FONT[letter]
            for y, row in enumerate(rows):
                for x, cell in enumerate(row):
                    if cell == "#":
                        cells.append((index * 6 + x, y))
        return cells

    def _lock_time(self, x: int, y: int) -> float:
        return _LOCK_START + x * _LOCK_SPREAD + (self.hashed(x, y, 7) % 55) / 100.0

    def draw(self, canvas: Canvas, t: float) -> None:
        g = self.g
        glyphs = g["glyphs"]
        banner_w = len(_WORD) * 6 - 1
        bx = max(0, (canvas.w - banner_w) // 2)
        by = max(1, canvas.h // 2 - 5)
        # Rain thins out once the mark is locked, so the final frame is readable rather than busy.
        thinning = clamp((t - self.locked_at) / 2.2)
        # A quiet zone over the mark and its subtitle. The rain still falls through it, at the
        # darkest shade only -- a hard black rectangle would read as a hole punched in the screen,
        # while rain at full brightness fills the counters of the letters with noise.
        quiet = (bx - 2, by - 1, bx + banner_w + 1, by + 10)

        # --- rain ---------------------------------------------------------------------------------
        for x in range(canvas.w):
            if thinning and (self.hashed(x, 9) % 100) < thinning * 82:
                continue
            speed = 7.0 + (self.hashed(x, 1) % 170) / 10.0
            trail = 5 + self.hashed(x, 3) % 14
            phase = (self.hashed(x, 2) % 1000) / 1000.0 * (canvas.h + trail)
            head = (t * speed + phase) % (canvas.h + trail + 6)
            for depth in range(trail):
                y = int(head) - depth
                if not (0 <= y < canvas.h):
                    continue
                glyph = glyphs[self.hashed(x, y, int(t * 13)) % len(glyphs)]
                if quiet[0] <= x <= quiet[2] and quiet[1] <= y <= quiet[3]:
                    color = "38;5;22"
                elif depth == 0:
                    color = "1;38;5;231"
                elif depth < 2:
                    color = "1;38;5;82"
                elif depth < 5:
                    color = "38;5;40"
                elif depth < 9:
                    color = "38;5;28"
                else:
                    color = "38;5;22"
                canvas.put(x, y, glyph, color)

        # --- the mark resolving -------------------------------------------------------------------
        if t >= 0.75:
            for x, y in self.banner:
                lock = self._lock_time(x, y)
                px, py = bx + x, by + y
                if t < lock:
                    canvas.put(px, py, glyphs[self.hashed(x, y, int(t * 22)) % len(glyphs)],
                               "38;5;46")
                elif t < lock + 0.14:
                    canvas.put(px, py, g["ink"], "1;38;5;231")
                else:
                    canvas.put(px, py, g["ink"], "1;38;5;46")

        # --- subtitle and seal --------------------------------------------------------------------
        sub_y = by + 6
        if t > self.locked_at:
            sub = typed("L O C A L - F I R S T   I N T E L L I G E N C E", t - self.locked_at, 26.0)
            canvas.center(sub_y, sub, "1;38;5;48")
        if t > self.locked_at + 1.0:
            canvas.center(sub_y + 1, "GREYNOC // OPERATIONS", "38;5;30")
        if t > self.locked_at + 1.8 and int(t * 2.2) % 2 == 0:
            canvas.center(sub_y + 3, "  ACCESS GRANTED  ::  KEYS NEVER LEAVE THE BOX  ",
                          "1;7;38;5;46")

        # --- the log ------------------------------------------------------------------------------
        log_x, log_y = 2, canvas.h - len(_CRYPT_LOG) - 1
        for index, (when, line, verdict) in enumerate(_CRYPT_LOG):
            if t < when:
                continue
            dots = 38 - len(line)
            full = f"{line} {g['bar'] * max(2, dots)}"
            shown = typed(full, t - when, 70.0)
            # Blank the whole row first: a rain glyph landing in the gap before OK reads as a typo.
            canvas.text(log_x, log_y + index, " " * (len(full) + len(verdict) + 3))
            canvas.text(log_x, log_y + index, shown, "38;5;35")
            if len(shown) >= len(full):
                canvas.text(log_x + len(full) + 1, log_y + index, verdict, "1;38;5;82")


# =================================================================================================
# 3. WIREFRAME -- the rotating scope
# =================================================================================================
_NODES: tuple[tuple[str, float, float, str], ...] = (
    ("api.example.com",     48.0,  10.0, "high"),
    ("sso.example.com",    -23.0, -46.0, "critical"),
    ("vpn.example.com",      35.0, 139.0, "medium"),
    ("legacy.example.com",   6.0,  12.0, "low"),
    ("cdn.example.com",    -33.0, 151.0, "info"),
)
_LOCK_EVERY = 2.0
_LOCK_FIRST = 2.4

_WIRE_UNI = {
    "edges": ("│", "│"),
    "corners": ("┌", "┐", "└", "┘"),
    "hbar": "─",
    "far": "·",
    "mid": "•",
    "near": "●",
    "node": "◆",
    "bracket": ("┌", "┐", "└", "┘"),
    "leader": "─",
    "fill": "█",
    "empty": "░",
}
_WIRE_ASCII = {
    "edges": ("|", "|"),
    "corners": ("+", "+", "+", "+"),
    "hbar": "-",
    "far": ".",
    "mid": "o",
    "near": "O",
    "node": "#",
    "bracket": ("[", "]", "[", "]"),
    "leader": "-",
    "fill": "#",
    "empty": ".",
}


class Wireframe(Scene):
    key = "wireframe"
    title = "WIREFRAME  --  the rotating scope"
    pitch = "a wireframe globe turns, blips surface, the reticle locks each asset in turn"
    duration = 13.0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.g = pick_glyphs(_WIRE_UNI, _WIRE_ASCII, self.stream)

    @staticmethod
    def _project(lat_deg: float, lon_deg: float, yaw: float, tilt: float
                 ) -> tuple[float, float, float]:
        """Unit sphere -> screen-space unit coords plus depth, after yaw and a fixed tilt."""
        lat, lon = math.radians(lat_deg), math.radians(lon_deg) + yaw
        cos_lat = math.cos(lat)
        x = cos_lat * math.cos(lon)
        y = math.sin(lat)
        z = cos_lat * math.sin(lon)
        y2 = y * math.cos(tilt) - z * math.sin(tilt)
        z2 = y * math.sin(tilt) + z * math.cos(tilt)
        return x, y2, z2

    def draw(self, canvas: Canvas, t: float) -> None:
        g = self.g
        box = Chrome(canvas, g)
        cyan, dim = "38;5;44", "38;5;23"

        panel_w = 30 if canvas.w >= 74 else 0
        globe_w = canvas.w - panel_w
        cx = globe_w // 2
        cy = canvas.h // 2
        ry = max(4, min((canvas.h - 7) // 2, 9))
        rx = max(6, min(ry * 2, globe_w // 2 - 3))
        yaw = t * 0.55
        tilt = 0.38
        sweep = int((t * 6.0) % (canvas.h + 4)) - 2

        # --- globe: back hemisphere first, so the front overdraws it ------------------------------
        # Coarse on purpose. Parallels every 20 degrees with a dense longitude step fill every cell
        # of a 40x19 ellipse, and a solid ball of glyphs stops reading as a wireframe at all --
        # 30/45 leaves black between the lines, which is what makes it look like line art.
        points: list[tuple[float, float, float, bool]] = []
        for lat in range(-60, 61, 30):                       # parallels
            for lon in range(0, 360, 4):
                x, y, z = self._project(lat, lon, yaw, tilt)
                points.append((x, y, z, lat == 0))
        for lon in range(0, 360, 45):                        # meridians
            for lat in range(-88, 89, 3):
                x, y, z = self._project(lat, lon, yaw, tilt)
                points.append((x, y, z, lon == 0))
        points.sort(key=lambda p: p[2])
        for x, y, z, spine in points:
            sx, sy = cx + x * rx, cy - y * ry
            # A five-stop depth ramp, not three: with one flat colour over everything facing us the
            # sphere renders as a disc of identical dots and loses its roundness entirely.
            if z < -0.35:
                glyph, color = g["far"], "38;5;236"
            elif z < -0.05:
                glyph, color = g["far"], "38;5;238"
            elif z < 0.25:
                glyph, color = g["mid"], dim
            elif z < 0.60:
                glyph, color = g["mid"], "38;5;37"
            else:
                glyph, color = g["near"], cyan
            if spine and z >= -0.05:
                color = "1;38;5;51"
            if round(sy) == sweep and z >= -0.05:
                color = "1;38;5;159"
            canvas.put(round(sx), round(sy), glyph, color)

        # The limb, drawn last so nothing overdraws it. Under orthographic projection a sphere's
        # silhouette is the same ellipse at every rotation, so it costs one loop -- and it is what
        # turns a cloud of lat/lon dots into something the eye reads as round.
        for deg in range(0, 360, 3):
            rad = math.radians(deg)
            canvas.put(round(cx + math.cos(rad) * rx), round(cy + math.sin(rad) * ry),
                       g["mid"], "1;38;5;45")

        # --- blips, and the reticle working through them -------------------------------------------
        locked_index = int((t - _LOCK_FIRST) / _LOCK_EVERY) if t >= _LOCK_FIRST else -1
        locked_index = min(locked_index, len(_NODES) - 1)
        for index, (name, lat, lon, severity) in enumerate(_NODES):
            x, y, z = self._project(lat, lon, yaw, tilt)
            if z < 0.0:
                continue
            sx, sy = round(cx + x * rx), round(cy - y * ry)
            paint = _SEV_PAINT[severity]
            found = index <= locked_index
            if found or int(t * 3) % 2 == 0:
                canvas.put(sx, sy, g["node"], paint if found else "38;5;244")
            if index != locked_index:
                continue
            # The lock: four corners closing in, then a leader line out to the panel row.
            since = t - (_LOCK_FIRST + index * _LOCK_EVERY)
            spread = 6.0 - ease_out(since / 0.45) * 4.0
            tl, tr, bl, br = g["bracket"]
            flash = "1;38;5;231" if since < 0.18 else paint
            canvas.put(sx - round(spread), sy - 1, tl, flash)
            canvas.put(sx + round(spread), sy - 1, tr, flash)
            canvas.put(sx - round(spread), sy + 1, bl, flash)
            canvas.put(sx + round(spread), sy + 1, br, flash)
            if since > 0.5 and panel_w:
                # Leader out from the limb of the globe, not from the reticle: a line drawn across
                # the sphere reads as a crack in it.
                for lx in range(cx + rx + 1, globe_w + 1):
                    if canvas.blank(lx, sy):
                        canvas.put(lx, sy, g["leader"], "38;5;238")
                canvas.text(sx + 2, sy - 2, name[: max(0, globe_w - sx - 3)], paint)

        # --- panel ---------------------------------------------------------------------------------
        if panel_w:
            px = globe_w
            box.frame(px, 0, panel_w, canvas.h, "38;5;31")
            canvas.text(px + 2, 0, " SCOPE ", "1;38;5;51")
            canvas.text(px + 2, 2, "example.com", "1;38;5;195")
            canvas.text(px + 2, 3, "authorization  ON FILE", "38;5;44")
            canvas.text(px + 2, 5, "kem   ML-KEM-768", "38;5;44")
            canvas.text(px + 2, 6, "sig   ML-DSA-65", "38;5;44")
            canvas.text(px + 2, 7, "group X25519MLKEM768", "38;5;44")

            mapped = clamp(t / (self.duration - 2.0))
            width = panel_w - 12
            filled = int(mapped * width)
            canvas.text(px + 2, 9, "SURFACE", "38;5;31")
            canvas.text(px + 10, 9, g["fill"] * filled + g["empty"] * (width - filled),
                        "1;38;5;51")
            canvas.text(px + 2, 10, f"{int(mapped * 100):3d}%  {len(_NODES)} ASSETS", "38;5;44")

            box.hrule(px, 11, panel_w, "38;5;31")
            canvas.text(px + 2, 11, " NODES ", "1;38;5;51")
            for index, (name, _lat, _lon, severity) in enumerate(_NODES):
                row = 13 + index
                if row >= canvas.h - 3:
                    break
                found = index <= locked_index
                paint = _SEV_PAINT[severity] if found else "38;5;240"
                canvas.put(px + 2, row, g["node"] if found else g["empty"], paint)
                canvas.text(px + 4, row, name.split(".")[0][:11].ljust(11), paint)
                canvas.text(px + 16, row, (severity[:4].upper() if found else "----"), paint)

        # --- stamp ---------------------------------------------------------------------------------
        done = _LOCK_FIRST + (len(_NODES) - 1) * _LOCK_EVERY + 1.0
        if t < done:
            if locked_index >= 0 and int(t * 3.2) % 2 == 0:
                canvas.text(2, canvas.h - 2, "  TARGET LOCKED  ", "1;7;38;5;196")
        else:
            canvas.text(2, canvas.h - 2, "  AUTHORIZATION VERIFIED  ::  READ-ONLY PROOF  ",
                        "1;7;38;5;51")
        canvas.text(2, 1, f"GREYIQ // SCOPE ORBIT   yaw {math.degrees(yaw) % 360:5.1f}", "38;5;30")


SCENES: dict[str, type[Scene]] = {
    "wopr": Wopr,
    "cryptlock": Cryptlock,
    "wireframe": Wireframe,
}


# --- driver --------------------------------------------------------------------------------------
def play(scene: Scene, *, fps: float, stream: TextIO) -> None:
    canvas = Canvas(scene.w, scene.h, color=scene.color)
    _enable_vt(stream)
    stream.write(TERM_ENTER)
    stream.flush()
    started = time.monotonic()
    interval = 1.0 / max(1.0, fps)
    try:
        while True:
            elapsed = time.monotonic() - started
            if elapsed >= scene.duration:
                break
            canvas.clear()
            scene.draw(canvas, elapsed)
            stream.write("\033[H" + "\r\n".join(canvas.rows()))
            stream.flush()
            time.sleep(max(0.0, interval - (time.monotonic() - started - elapsed)))
    except KeyboardInterrupt:
        pass
    finally:
        stream.write(TERM_LEAVE)
        stream.flush()


def capture(scene: Scene, frames: int, stream: TextIO) -> None:
    canvas = Canvas(scene.w, scene.h, color=scene.color)
    for index in range(frames):
        t = scene.duration * (index + 0.5) / frames
        canvas.clear()
        scene.draw(canvas, t)
        print(f"--- {scene.key} frame {index + 1}/{frames}  t={t:.2f}s "
              f"{'-' * max(0, scene.w - 34)}", file=stream)
        print("\n".join(canvas.rows()), file=stream)
        print("", file=stream)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fx_gallery",
        description="Three 90s-movie terminal renderings for GreyIQ.")
    parser.add_argument("scene", nargs="?", default="all",
                        choices=("all", *SCENES), help="which rendering to play (default: all)")
    parser.add_argument("--seconds", type=float, default=0.0,
                        help="override each scene's duration")
    parser.add_argument("--fps", type=float, default=20.0, help="frame rate (default: 20)")
    parser.add_argument("--capture", type=int, default=0, metavar="N",
                        help="print N still frames instead of animating")
    parser.add_argument("--no-color", action="store_true", help="drop every SGR code")
    parser.add_argument("--width", type=int, default=0, help="override terminal width")
    parser.add_argument("--height", type=int, default=0, help="override terminal height")
    parser.add_argument("--seed", type=int, default=1337, help="noise seed")
    args = parser.parse_args(list(argv) if argv is not None else None)

    stream = sys.stdout
    size = shutil.get_terminal_size((80, 24))
    width = args.width or size.columns
    height = args.height or size.lines
    # One row in hand: writing the bottom-right cell of a terminal is where wrap bugs live.
    height = max(14, height - 1)
    width = max(40, width)
    color = not args.no_color

    keys = list(SCENES) if args.scene == "all" else [args.scene]
    if not args.capture and not stream.isatty():
        print("fx_gallery: needs a terminal to animate -- try --capture 3.", file=sys.stderr)
        return 2

    for key in keys:
        scene = SCENES[key](width, height, stream=stream, color=color, seed=args.seed)
        if args.seconds:
            scene.duration = float(args.seconds)
        if args.capture:
            capture(scene, args.capture, stream)
            continue
        play(scene, fps=args.fps, stream=stream)
        print(f"  {scene.title}\n    {scene.pitch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
