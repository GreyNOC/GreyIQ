"""The ``gn dash`` cockpit — panels, run sources and the refresh loop.

``gn_tui`` owns the terminal and ``gn_sysmon`` owns the host counters; this module owns everything
that is about a hunt. It sits in front of a security tool and draws over a run that is probing
somebody else's production host, so the rules below are not style — each one is a failure this
module exists to prevent:

  * **One dict shape, no adapter layer.** :meth:`LocalSource.poll` returns the identical dict
    ``greyiq_api.bounty_progress`` produces over HTTP (``events`` / ``count`` / ``snapshot``), so
    :func:`render` never learns which mode it is in. The alternative — a renderer that branches on
    the source — is two layouts that drift, and the one that drifts is always the one the operator
    is not looking at while the other is being tested.
  * **:func:`render` is pure.** State in, rows out: no clock, no I/O, no globals. "Now" arrives as
    ``DashState.now_epoch`` precisely so a time-series bucket is reproducible in a test rather than
    something that can only be checked by staring at a terminal.
  * **No escape sequences in a row.** Every row is plain text, and every non-ASCII character in one
    comes from the tier dict ``gn_tui.tier()`` probed against the live stream. A glyph the stream
    cannot encode raises inside ``Screen._write``, which deactivates the screen — the operator is
    then left looking at a frozen frame while the hunt runs on, which is the worst failure this
    dashboard has. For the same reason every string that reaches a row is run through :func:`_plain`:
    a target name or a finding title is attacker-influenced text, and an ``\\033[2J`` inside one
    would otherwise let a target repaint the operator's screen.
  * **Never overstate.** A metric the host would not give us renders ``--`` and never ``0`` — zero is
    a claim. The request rate is derived from governor deltas, so it is labelled ``est``. At 400
    findings the stream is capped (``progress._MAX_FINDINGS_PER_RUN``) and the panel says ``(cap)``,
    because a flatlined series that is really a truncation is a lie told in a chart. ``stop`` reports
    ``stopping`` and never ``stopped``: the engine checks the flag between probes, so the honest
    latency is "after the current step".
  * **Attached mode says what it does not know.** No governor and no probe rate are exposed over
    HTTP, so those panels read ``n/a - local only``; a lost backend freezes the last good snapshot
    behind a ``stale`` badge and a ``NO BACKEND`` pill. Clearing the panels to zeros would read as
    "nothing found", which is a different claim from "we lost contact".
  * **The token goes nowhere until the port has proved it is GreyIQ.** Port discovery walks
    8766..8845 carrying no credential, and a port must clear two token-free checks before it is
    trusted: ``GET /api/health`` answering ``{"status": "ok"}``, AND an unauthenticated POST to a
    gated route being refused with GreyIQ's own ``missing or invalid session token``. Health alone
    is not enough — it is deliberately unfingerprintable, so accepting it meant another user who
    bound a lower port first would be handed ``X-GreyIQ-Token`` by the walk. A discovery loop that
    sprays a credential at every local listener is a leak looking for one.

Nothing here may raise into a hunt: the poller, the command worker and the sampler are all wrapped,
and :func:`render` itself degrades to an honest one-line error frame rather than taking the loop down.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import shlex
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Protocol, Sequence

import gn_sysmon
import gn_tui
from gn_tui import Size

# --- sizes and clocks -------------------------------------------------------------------------------
#: Below this the layout is a lie rather than a squeeze, so the dashboard refuses (see §6): one
#: honest line beats a broken frame the operator has to decode.
MIN_SIZE = Size(60, 18)
#: The width at which the top band gets a third column and the log pane grows into the rate rows.
WIDE_COLS = 120
#: Below this the band stacks instead of splitting.
NARROW_COLS = 80
#: The tallest the target band grows on a very tall terminal; the rest of the surplus goes to the log.
_MAX_BAND = 24

_MESSAGE_SECONDS = 6.0
#: ``progress._MAX_FINDINGS_PER_RUN``. Duplicated rather than imported: the renderer must label the
#: cap even in attached mode, where the engine module may not be importable at all.
FINDINGS_CAP = 400
_MAX_EVENTS = 500          # mirrors progress._MAX_LINES_PER_RUN; the store will not give us more
_MAX_OUTPUT_LINES = 400
_MAX_HISTORY = 240         # sparkline samples kept per series (a minute at 4Hz is 240)

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEV_LABELS = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}
PROOFS: tuple[str, ...] = ("confirmed", "candidate", "missing")
#: What "this work unit is no longer queued or running" means. ``skipped`` is in here and is NOT in
#: ``stats.targets_done`` (progress.py) — see :func:`completion`.
DONE_STATUSES: frozenset[str] = frozenset({"done", "error", "skipped"})
TARGET_STATUSES: tuple[str, ...] = ("queued", "running", "done", "error", "skipped")

#: Exactly what ``stop`` promises, and no more. The first ``should_stop`` check in a hunt lands after
#: the scanner pass and the recon crawl, so a stop can take a full active pass to take effect.
STOP_WORDING = "stopping - after the current step (bounty.py checks between probes)"
DASH_REFUSAL = "`dash` cannot be run from inside the dashboard."
HUNT_REFUSAL = ("a hunt is already on screen; a second one would evict this run from the progress "
                "store (_MAX_RUNS=8).")
BUSY_REFUSAL = "one pane command at a time ({busy} is still running)."
NO_GOVERNOR = "probe rate / host buckets: n/a - local only (no HTTP exposure)"

#: Status marks. Chosen by TIER NAME rather than probed, because the tier probe only proves what that
#: tier's own glyph set encodes: a cp437 console takes the box drawings and the shades but has no
#: U+2713/U+25B8, so every non-rich tier gets the ASCII marks.
_MARKS_RICH = {"queued": "·", "running": "▸", "done": "✓", "error": "✗",
               "skipped": "⊘"}
_MARKS_ASCII = {"queued": ".", "running": ">", "done": "+", "error": "!", "skipped": "~"}

#: Control characters (and ESC with them) become spaces before a row is built — see the module
#: docstring: finding titles and target names are attacker-influenced text.
_CTRL_TABLE = {index: " " for index in range(32)}
_CTRL_TABLE[127] = " "

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
#: Electron's ``findFreePort(8766)`` walks 80 ports; discovery has to cover the same ground.
_PORT_BASE, _PORT_SPAN = 8766, 80
_TOKEN_HEADER = "X-GreyIQ-Token"
# The token-free identity probe. Any /api/* path except /api/health is gated, and the gate answers
# an unauthenticated request with 403 and exactly this body (greyiq_api). Being refused in GreyIQ's
# own words is what identifies the backend BEFORE the token is ever sent; /api/bounty/runs is chosen
# because it is read-only and field-free, so even a hypothetical unrefused POST changes nothing.
_GATE_PROBE_PATH = "/api/bounty/runs"
_GATE_REFUSAL = "missing or invalid session token"

ACCESS_KEY_MESSAGE = ("the backend requires GREYIQ_ACCESS_KEY; set it in this shell and reattach.")
STALE_TOKEN_MESSAGE = ("the backend restarted - its session token was regenerated; reattach.")
NO_TOKEN_MESSAGE = ("couldn't find session.token - pass --token, or set GREYIQ_RUNTIME_DIR to the one "
                    "the app uses.")


# --- plain data ---------------------------------------------------------------------------------
@dataclass
class DashState:
    """Everything :func:`render` needs, and nothing it does not — plain data, copied out under the
    loop's lock so the renderer never touches a live buffer while the poller is writing to it.

    ``now_epoch``/``started_epoch`` are here rather than read from the clock inside the renderer:
    that is what makes the severity time-series deterministic in a test.
    """

    label: str = ""
    mode: str = "local"                 # "local" | "attached"
    run_id: str = ""
    status: str = "RUNNING"             # RUNNING STOPPING DONE STALE NO BACKEND EVICTED
    phase: str = ""
    elapsed: float = 0.0
    stale_for: float | None = None
    started_epoch: float | None = None
    now_epoch: float | None = None
    snapshot: dict[str, Any] = field(default_factory=dict)
    events: tuple[dict[str, Any], ...] = ()
    governor: tuple[dict[str, Any], ...] = ()
    rate: float | None = None
    rate_history: tuple[float | None, ...] = ()
    cpu_history: tuple[float | None, ...] = ()
    sysmon: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    output: tuple[str, ...] = ()
    tab: str = "log"                    # which of LOG/OUTPUT the bottom pane shows
    focus: str = "log"                  # "log" | "output" | "targets" - what PgUp/PgDn scrolls
    unread_output: bool = False
    target_scroll: int = 0
    pane_scroll: int = 0
    input_text: str = ""
    input_caret: int = 0
    busy: str = ""                      # the in-flight pane command, or ""
    capabilities: frozenset[str] = frozenset()


@dataclass(frozen=True)
class VerbSpec:
    """One operator verb. ``needs`` is the capability token ``source.capabilities()`` must carry, so
    an unavailable verb is greyed out BY DATA — "attached" genuinely offers a different set from
    "in-process" rather than offering one that fails when pressed."""

    name: str
    hook: str
    args: str = ""
    needs: str = ""
    help: str = ""
    latency: str = ""
    aliases: tuple[str, ...] = ()
    immediate: bool = False             # runs on the main thread; everything else goes to the worker


@dataclass(frozen=True)
class ParsedCommand:
    """The result of reading one input line. ``kind`` is ``empty`` | ``verb`` | ``subcommand`` |
    ``refused``; ``error`` carries the refusal sentence and is empty otherwise."""

    kind: str
    name: str = ""
    args: tuple[str, ...] = ()
    verb: VerbSpec | None = None
    error: str = ""


class SourceError(Exception):
    """A source could not answer. ``fatal`` means reattaching will not help (a missing access key),
    ``status`` is the pill to show. Raised only out of :meth:`RunSource.poll` and the control verbs,
    and always caught by the loop — a lost backend costs a badge, never the dashboard."""

    def __init__(self, message: str, *, status: str = "NO BACKEND", fatal: bool = False) -> None:
        super().__init__(message)
        self.message = str(message)
        self.status = str(status)
        self.fatal = bool(fatal)


class RunSource(Protocol):
    """What the loop needs from a run, in either mode.

    ``governor``/``reverify`` are part of the protocol rather than duck-typed extras so that dispatch
    stays data-driven: the capability set decides whether a verb is offered, and the method is always
    there to call. An attached source answers ``()`` for ``governor`` AND withholds the ``governor``
    capability, so the panel prints ``n/a`` instead of an empty list — those are different claims.
    """

    def poll(self, after: int) -> dict: ...
    def capabilities(self) -> frozenset[str]: ...
    def stop(self) -> tuple[bool, str]: ...
    def label(self) -> str: ...
    def governor(self) -> tuple[dict[str, Any], ...]: ...
    def reverify(self, ref: str) -> tuple[bool, str]: ...


# --- text safety --------------------------------------------------------------------------------
def _plain(text: Any) -> str:
    """One row's worth of text with every control character (ESC included) turned into a space.

    Target names, finding titles and engine log lines all reach a row, and all three are influenced
    by the host being tested. An escape sequence smuggled through one of them would move the cursor,
    clear the screen or set a colour the diffed frame never resets. Translating instead of stripping
    keeps the width honest: the remaining ``[2J`` is visible junk, which is a bug an operator can
    see, rather than an invisible one that repaints their terminal.
    """
    return str(text).translate(_CTRL_TABLE)


def _cut(text: Any, limit: int) -> str:
    """``text`` clipped to ``limit`` cells. Plain by construction — this module emits no ANSI, which
    is why a plain slice is safe here where ``gn_tui`` needs escape-aware truncation."""
    if limit <= 0:
        return ""
    return _plain(text)[:limit]


def _cell(text: Any, width: int) -> str:
    """One panel cell, exactly ``width`` cells wide."""
    if width <= 0:
        return ""
    return _cut(text, width).ljust(width)


def _elide(text: Any, width: int) -> str:
    """Middle-elide to ``width`` cells. Middle, not tail: two long URLs on the same host differ in
    their last path segment far more often than in their first, so a tail cut makes distinct work
    units render identically."""
    body = _plain(text)
    if width <= 0:
        return ""
    if len(body) <= width:
        return body
    if width <= 3:
        return body[:width]
    head = (width - 2) // 2
    tail = width - 2 - head
    return body[:head] + ".." + (body[len(body) - tail:] if tail else "")


def _clock(seconds: float | None) -> str:
    """``MM:SS`` under an hour, ``H:MM:SS`` over it. ``--:--`` when there is no clock yet."""
    try:
        total = int(max(0.0, float(seconds or 0.0)))
    except (TypeError, ValueError):
        return "--:--"
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"


def _pct(value: Any) -> str:
    """A percentage cell, or ``--`` when the probe would not answer. Never ``0%``: a host that will
    not report its CPU and a host that is idle are different facts."""
    try:
        if value is None:
            return "--"
        return f"{int(round(float(value)))}%"
    except (TypeError, ValueError):
        return "--"


# --- derived metrics ----------------------------------------------------------------------------
def _iso_epoch(stamp: Any) -> float | None:
    text = str(stamp or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def completion(snapshot: dict[str, Any] | None) -> tuple[int, int]:
    """``(finished, total)`` work units, **counting ``skipped``**.

    Deliberately not ``stats.targets_done``: that counts ``done`` and ``error`` only (progress.py),
    while a stopped campaign marks every remaining unit ``skipped``. Using the built-in stat would
    park the header counter permanently below 100% on every stopped run — the exact moment the
    operator is watching the counter to see whether the stop took.
    """
    targets = (snapshot or {}).get("targets")
    if not isinstance(targets, list):
        return (0, 0)
    finished = sum(1 for t in targets if isinstance(t, dict) and str(t.get("status") or "") in DONE_STATUSES)
    return (finished, len(targets))


def proof_counts(findings: Sequence[Any] | None) -> dict[str, int]:
    """``confirmed`` / ``candidate`` / ``missing``, counted from the findings themselves.

    ``findings_total - confirmed_total`` is NOT a candidate count — it folds in every ``missing``,
    i.e. every lead the active prover looked at and could not stand up. Presenting those as
    candidates would inflate the one number this program exists to keep honest.
    """
    counts = {name: 0 for name in PROOFS}
    for finding in findings or ():
        if not isinstance(finding, dict):
            continue
        proof = str(finding.get("proof") or "").strip().lower()
        if proof in counts:
            counts[proof] += 1
    return counts


def severity_counts(findings: Sequence[Any] | None) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings or ():
        if not isinstance(finding, dict):
            continue
        sev = str(finding.get("severity") or "info").strip().lower()
        counts[sev if sev in counts else "info"] += 1
    return counts


def target_severity(findings: Sequence[Any] | None) -> dict[str, dict[str, int]]:
    """Per-work-unit severity breakdown, derived from the findings list.

    The target record itself carries only ``findings``/``confirmed``/``top_severity``
    (progress.set_targets), so the C/H/M/L/I column has to be rolled up here. It is derived from the
    same capped stream the panel labels ``(cap)``, so past 400 findings it stops moving with the
    rest of the panel rather than disagreeing with it.
    """
    rolled: dict[str, dict[str, int]] = {}
    for finding in findings or ():
        if not isinstance(finding, dict):
            continue
        name = str(finding.get("target") or "")
        sev = str(finding.get("severity") or "info").strip().lower()
        row = rolled.setdefault(name, {key: 0 for key in SEVERITIES})
        row[sev if sev in row else "info"] += 1
    return rolled


def severity_series(findings: Sequence[Any] | None, buckets: int, *,
                    start: float | None = None, end: float | None = None) -> dict[str, tuple[int, ...]]:
    """Findings per severity per time bucket, ``buckets`` wide.

    Bucket width is ``max(1s, span / buckets)`` recomputed by the caller every frame, so the series
    always fills the panel however long the run has been going. One second is the floor because the
    ``at`` stamps are ISO timestamps, and a bucket finer than the stamp resolution would draw noise
    as structure.
    """
    width = max(1, int(buckets or 1))
    stamps: list[tuple[float, str]] = []
    for finding in findings or ():
        if not isinstance(finding, dict):
            continue
        when = _iso_epoch(finding.get("at"))
        if when is None:
            continue
        sev = str(finding.get("severity") or "info").strip().lower()
        stamps.append((when, sev if sev in SEVERITIES else "info"))
    series: dict[str, list[int]] = {name: [0] * width for name in SEVERITIES}
    if not stamps:
        return {name: tuple(values) for name, values in series.items()}
    low = min(when for when, _ in stamps) if start is None else float(start)
    high = max(when for when, _ in stamps) if end is None else float(end)
    if high < low:
        low, high = high, low
    bucket = max(1.0, (high - low) / width)
    for when, sev in stamps:
        index = int((when - low) / bucket)
        series[sev][max(0, min(width - 1, index))] += 1
    return {name: tuple(values) for name, values in series.items()}


def probe_rate(previous: Sequence[dict[str, Any]] | None, current: Sequence[dict[str, Any]] | None,
               elapsed: float, *, refill_per_s: float = 1.0) -> float | None:
    """Requests per second, ESTIMATED from per-host token-bucket deltas.

    Nothing in the engine counts requests over time: ``_Http.sent`` is per-instance and is surfaced
    once, at return. The governor buckets are the only live signal, so the spend between two samples
    is ``(tokens_before - tokens_after) + refill_per_s * dt`` — the refill term added back because
    the bucket was filling while it drained.

    It is an estimate and is labelled ``est`` on the panel: ``remaining()`` truncates to ``int``, so
    each host contributes up to a token of quantisation noise per sample. Returns ``None`` — which
    renders ``--`` — when there is no basis to divide (no elapsed time, or no host seen in both
    samples); a host that only appears in the newer sample has no baseline and is skipped rather
    than counted as a full bucket's worth of spend.
    """
    try:
        window = float(elapsed)
    except (TypeError, ValueError):
        return None
    if window <= 0:
        return None
    before = {(str(row.get("pool")), str(row.get("host"))): row for row in (previous or ())
              if isinstance(row, dict)}
    spent = 0.0
    seen = False
    for row in current or ():
        if not isinstance(row, dict):
            continue
        key = (str(row.get("pool")), str(row.get("host")))
        old = before.get(key)
        if old is None:
            continue
        try:
            drop = float(old.get("tokens", 0)) - float(row.get("tokens", 0))
        except (TypeError, ValueError):
            continue
        seen = True
        spent += drop + refill_per_s * window
    if not seen:
        return None
    return max(0.0, spent / window)


# --- layout -------------------------------------------------------------------------------------
def _plan_rows(rows: int, *, wide: bool, narrow: bool) -> dict[str, Any]:
    """How many rows each region gets, as a strict drop priority.

    The chrome — header, message line, input line — is never dropped: without the input line the
    dashboard cannot be quit, and without the message line a refused command fails silently. What
    gives, in order, is the rate body, then the system strip (which merges into the message line),
    then the target band, then the log pane. That order is the plan's, and it is the order of how
    much an operator loses: the rate panel is a decoration over a number that is also in the log.
    """
    chrome = 3
    strip = True
    band = 8
    rate = 0 if wide else (2 if narrow else 5)
    log = 12 if wide else 7
    total = chrome + 1 + band + rate + log
    if rows > total:
        extra = rows - total
        grow = min(extra // 2, max(0, _MAX_BAND - band))
        band += grow
        log += extra - grow
    else:
        deficit = total - rows
        floors = (("rate", 2), ("strip", 0), ("band", 3), ("log", 3))
        sizes = {"rate": rate, "band": band, "log": log}
        for name, floor in floors:
            if deficit <= 0:
                break
            if name == "strip":
                if strip:
                    strip = False
                    deficit -= 1
                continue
            give = min(deficit, max(0, sizes[name] - floor))
            sizes[name] -= give
            deficit -= give
        rate, band, log = sizes["rate"], sizes["band"], sizes["log"]
    return {"band": band, "rate": rate, "log": log, "strip": strip}


def _plan_cols(cols: int) -> tuple[int, ...]:
    """Cell widths for the top band, one entry per column.

    Three bands: stacked under 80, two columns to 120, three above it (the rate panel moves into the
    band and frees its rows for the log). Widths always satisfy ``sum + len + 1 == cols``, which is
    what makes every assembled row exactly ``cols`` wide with its borders.
    """
    inner = max(1, cols - 2)
    if cols >= WIDE_COLS:
        left = max(8, (inner * 40) // 100)
        middle = max(8, (inner * 35) // 100)
        right = inner - left - middle - 2
        if right >= 8:
            return (left, middle, right)
    if cols >= NARROW_COLS:
        left = inner // 2
        return (left, inner - left - 1)
    return (inner,)


def _row(cells: Sequence[str], widths: Sequence[int], vertical: str) -> str:
    return vertical + vertical.join(_cell(text, width) for text, width in zip(cells, widths)) + vertical


def _pad_block(rows: Sequence[str], height: int) -> list[str]:
    out = [str(row) for row in rows[:height]]
    out.extend("" for _ in range(height - len(out)))
    return out


# --- panels -------------------------------------------------------------------------------------
def _marks(tier: dict) -> dict[str, str]:
    return _MARKS_RICH if str(tier.get("name")) == "rich" else _MARKS_ASCII


def _gauge(fraction: float, width: int, tier: dict) -> str:
    """A horizontal fill bar built from the tier's own glyphs: the top of the ``bars`` ladder for
    filled, the tier's ``dot`` for empty. No ``U+2588``/``U+2591`` literals — neither is in any
    tier's probe text, so using them would mean drawing a glyph the stream was never tested for."""
    cells = max(0, int(width))
    if cells <= 0:
        return ""
    bars = tuple(tier.get("bars") or ("#",))
    filled = bars[-1]
    empty = str(tier.get("dot") or ".")
    try:
        ratio = max(0.0, min(1.0, float(fraction)))
    except (TypeError, ValueError):
        ratio = 0.0
    count = int(round(ratio * cells))
    return filled * count + empty * (cells - count)


def _header_row(state: DashState, size: Size, tier: dict) -> str:
    """``| gn dash . target . local . 04:12 . RUNNING ------------ 2/7 |``

    The status pill and the completion counter survive every squeeze; what gives, in order, is the
    stale badge, the clock, the mode word, and finally the label, which is middle-elided. A header
    that dropped the pill to keep a long URL would hide the one word the operator is scanning for.
    """
    box = tuple(tier.get("box") or ("+", "+", "+", "+", "-", "|", "+", "+"))
    separator = f" {tier.get('dot') or '.'} "
    done, total = completion(state.snapshot)
    right = f" {done}/{total} {box[1]}"
    label = state.label or state.run_id or "(no run)"

    tail = [state.mode, _clock(state.elapsed), state.status]
    if state.stale_for:
        tail.append(f"stale {int(state.stale_for)}s")
    options = [tail, tail[:3], [tail[0], tail[2]], [tail[2]]]
    for index, parts in enumerate(options):
        fixed = f"{box[0]} " + separator.join(["gn dash", "", *parts]) + " "
        room = size.cols - len(right) - len(fixed)
        if room < 6 and index < len(options) - 1:
            continue
        left = f"{box[0]} " + separator.join(["gn dash", _elide(label, max(1, room)), *parts]) + " "
        return _cut(left + box[4] * max(0, size.cols - len(left) - len(right)) + right, size.cols)
    return _cut(f"{box[0]} gn dash {state.status}", size.cols)


def _separator_row(title: str, size: Size, tier: dict) -> str:
    box = tuple(tier.get("box") or ("+", "+", "+", "+", "-", "|", "+", "+"))
    left = f"{box[6]}{box[4]} {title} "
    return _cut(left + box[4] * max(0, size.cols - len(left) - 1) + box[7], size.cols)


def _targets_title(state: DashState, width: int, tier: dict) -> str:
    done, total = completion(state.snapshot)
    mark = str(tier.get("tick") or "*") if state.focus == "targets" else ""
    return f" TARGETS{mark}  status  {done}/{total} done"[:max(0, width)]


def _findings_title(state: DashState, width: int, _tier: dict) -> str:
    return " FINDINGS  by severity over time"[:max(0, width)]


def _rate_title(_state: DashState, width: int, _tier: dict) -> str:
    return " RATE  host buckets"[:max(0, width)]


def _target_rows(state: DashState, height: int, width: int, tier: dict) -> list[str]:
    """One row per work unit: mark, name, the C/H/M/L/I roll-up and the confirmed count.

    There is no per-target phase column and no per-target elapsed column, and neither is an
    oversight: the engine records neither (phase is free text in the log, ``elapsed_s`` has no
    production caller). A column that is blank on every real run is worse than no column, because it
    reads as "nothing happened here".
    """
    if height <= 0:
        return []
    snapshot = state.snapshot or {}
    targets = [t for t in (snapshot.get("targets") or []) if isinstance(t, dict)]
    marks = _marks(tier)
    tick = str(tier.get("tick") or "*")
    if not targets:
        return _pad_block([" no work units registered yet"], height)
    scroll = max(0, min(int(state.target_scroll or 0), max(0, len(targets) - height)))
    # The overflow marker costs a row, so it is counted BEFORE the window is cut: a panel that says
    # "+3 more" while hiding four has miscounted the one thing the row exists to report.
    remaining = len(targets) - scroll
    hidden = remaining - (height - 1) if remaining > height else 0
    window = targets[scroll:scroll + (height - 1 if hidden else height)]
    by_target = target_severity(snapshot.get("findings"))
    rows: list[str] = []
    for record in window:
        name = str(record.get("target") or "")
        status = str(record.get("status") or "")
        mark = marks.get(status, "?")
        counts = by_target.get(name) or {}
        sev = "/".join(str(counts.get(key, 0)) for key in SEVERITIES)
        confirmed = int(record.get("confirmed") or 0)
        conf = f"{tick}{confirmed}" if confirmed else ""
        room = width - 3 - len(sev) - len(conf) - 2
        if room < 10:                      # too narrow for the roll-up: the name is what matters
            sev = ""
            room = width - 3 - len(conf) - 1
        if room < 8:
            conf = ""
            room = width - 3
        parts = [" ", mark, " ", _elide(name, max(1, room))]
        line = "".join(parts)
        trailer = " ".join(piece for piece in (sev, conf) if piece)
        if trailer:
            line = line.ljust(max(0, width - len(trailer) - 1)) + " " + trailer
        rows.append(line)
    if hidden:
        rows.append(f" ... +{hidden} more")
    return _pad_block(rows, height)


def _findings_rows(state: DashState, height: int, width: int, tier: dict) -> list[str]:
    """Five severity sparklines over time, then the proof breakdown and the total.

    The summary lines are the ones that survive a squeeze: a sparkline shows change, but
    ``confirmed 2 / candidate 9 / missing 31`` is the claim the operator acts on.
    """
    if height <= 0:
        return []
    snapshot = state.snapshot or {}
    findings = [f for f in (snapshot.get("findings") or []) if isinstance(f, dict)]
    proofs = proof_counts(findings)
    total = len(findings)
    capped = " (cap)" if total >= FINDINGS_CAP else ""
    summary = (f" confirmed {proofs['confirmed']} {tier.get('dot') or '.'} "
               f"candidate {proofs['candidate']} {tier.get('dot') or '.'} missing {proofs['missing']}")
    totals = f" total {total}{capped}"
    if height == 1:
        return [_cut(f" {total} found{capped}, {proofs['confirmed']} confirmed", width)]

    spark_rows = max(0, height - 2)
    cells = max(1, width - 12)
    counts = severity_counts(findings)
    series = severity_series(findings, cells, start=state.started_epoch, end=state.now_epoch)
    bars = tuple(tier.get("bars") or ("#",))
    body: list[str] = []
    for name in SEVERITIES[:spark_rows]:
        # An empty bucket is a GAP, not a floor: ``gn_tui.sparkline`` draws None as a blank cell and
        # the floor glyph for the lowest value present, so a row of zeroes would otherwise draw a
        # continuous low bar that reads as "a steady trickle of criticals". ``lo=0`` anchors the
        # scale at zero so one finding in a quiet run is not shown at the same height as ten.
        values = [count or None for count in series.get(name, ())]
        line = gn_tui.sparkline(values, cells, bars, lo=0)
        body.append(f" {_SEV_LABELS[name]:<4} {line} {counts.get(name, 0):>3}")
    body.append(summary)
    body.append(totals)
    return _pad_block(body, height)


def _rate_rows(state: DashState, height: int, width: int, tier: dict) -> list[str]:
    """Probe rate and per-host token buckets — the real, live ceiling a hunt runs into.

    Labelled "host bucket", never "budget": the per-pass request budget is not exposed anywhere the
    dashboard can read, and naming this after it would attach a number to a claim it does not make.
    """
    if height <= 0:
        return []
    if "governor" not in state.capabilities:
        return _pad_block([" " + NO_GOVERNOR], height)
    rows = [row for row in (state.governor or ()) if isinstance(row, dict)]
    rate = "--" if state.rate is None else f"~{state.rate:.1f}/s"
    spark_cells = max(0, min(20, width - 34))
    spark = gn_tui.sparkline(state.rate_history, spark_cells, tuple(tier.get("bars") or ("#",))) if spark_cells else ""
    # "est" is never dropped, however narrow the column gets: it is the part of the label that keeps
    # a derived number from reading as a measured one. "local" is, because the panel is only ever
    # drawn at all when the source is local.
    label = "(est, local)" if width >= 40 else "(est)"
    body = [f" probe rate {rate} {label} {spark}".rstrip()]
    if height == 1:
        if rows:
            busiest = min(rows, key=lambda row: _int(row.get("tokens")))
            body[0] = (f" probe rate {rate} (est) {_plain(busiest.get('host'))} "
                       f"{_int(busiest.get('tokens'))}/{_int(busiest.get('capacity'))}")
        return _pad_block(body, height)
    if not rows:
        body.append(" host buckets: none yet - a bucket appears once a host has been throttled")
        return _pad_block(body, height)
    for row in sorted(rows, key=lambda row: _int(row.get("tokens")))[:max(0, height - 1)]:
        host = _plain(row.get("host") or "?")
        tokens, capacity = _int(row.get("tokens")), max(1, _int(row.get("capacity")))
        counter = f"{tokens}/{capacity}"
        name_room = max(8, min(28, width - len(counter) - 16))
        gauge = _gauge(tokens / capacity, max(4, width - name_room - len(counter) - 4), tier)
        body.append(f" {_elide(host, name_room):<{name_room}} {gauge} {counter}")
    return _pad_block(body, height)


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _pane_rows(state: DashState, height: int, width: int, _tier: dict) -> list[str]:
    """The LOG or OUTPUT tail, scrolled. ``pane_scroll`` counts rows back from the newest line, so
    zero means "following", which is what an operator watching a live hunt wants by default."""
    if height <= 0:
        return []
    if state.tab == "output":
        lines = [str(line) for line in (state.output or ())]
        if not lines:
            lines = ["no pane command has run yet - type a `gn` verb below, or `help`"]
    else:
        lines = []
        for event in (state.events or ()):
            if not isinstance(event, dict):
                continue
            stamp = str(event.get("at") or "")[11:19]
            lines.append(f"{stamp}  {event.get('message', '')}" if stamp else str(event.get("message", "")))
        if not lines:
            lines = ["waiting for the first progress line..."]
    scroll = max(0, min(int(state.pane_scroll or 0), max(0, len(lines) - height)))
    end = len(lines) - scroll
    window = lines[max(0, end - height):end]
    return _pad_block([" " + line for line in window], height)


def _strip_text(state: DashState, tier: dict) -> str:
    """cpu / mem / disk, each ``--`` when its probe would not answer.

    The CPU sparkline is drawn on an ABSOLUTE 0-100 scale, not auto-ranged: auto-ranging turns the
    one-percent jitter of an idle box into a mountain range, and the strip exists to answer "is this
    machine the reason the hunt is slow", which only an absolute scale can answer at a glance.
    """
    sysmon = state.sysmon or {}
    bars = tuple(tier.get("bars") or ("#",))
    spark = gn_tui.sparkline(state.cpu_history, 6, bars, lo=0, hi=100) if state.cpu_history else ""
    disk_path = str(sysmon.get("disk_path") or "")
    name = os.path.basename(disk_path.rstrip("\\/")) or disk_path or "disk"
    cpu = " ".join(part for part in ("cpu", spark, _pct(sysmon.get("cpu_percent"))) if part)
    return (f"{cpu}  mem {_pct(sysmon.get('mem_percent'))}  "
            f"disk {_pct(sysmon.get('disk_percent'))} ({_elide(name, 18)})")


def _bottom_row(state: DashState, size: Size, tier: dict) -> str:
    box = tuple(tier.get("box") or ("+", "+", "+", "+", "-", "|", "+", "+"))
    left = f"{box[2]} {_strip_text(state, tier)} "
    return _cut(left + box[4] * max(0, size.cols - len(left) - 1) + box[3], size.cols)


def _message_row(state: DashState, size: Size, tier: dict, *, strip: bool) -> str:
    """The last command result, or — when there is none — the run's current phase.

    The phase belongs here rather than in the header: there is no per-target phase in the engine
    (only free text in the log), so what exists is ONE run-level line, and at 80 columns the header
    has no room for it without pushing out the status pill. It is prefixed with the tier's dot so a
    phase and a command result cannot be mistaken for each other on the same row.
    """
    text = _plain(state.message or "")
    if not text and state.phase:
        text = f"{tier.get('dot') or '.'} {_plain(state.phase)}"
    if strip:
        # The strip has lost its own row: it rides on the message line rather than disappearing,
        # because a full evidence disk is exactly the failure a cramped terminal still needs to see.
        text = f"{_strip_text(state, tier)}  {text}".rstrip()
    return _cut("  " + text, size.cols)


def _input_row(state: DashState, size: Size) -> str:
    prefix = f"[running: {state.busy}] " if state.busy else "> "
    return _cut(prefix + _plain(state.input_text or ""), size.cols)


def cursor(state: DashState, size: Size) -> tuple[int, int]:
    """Where the real cursor parks: under the caret on the input row, 1-based for ``\\033[r;cH``.
    The cursor is visible on this row only, which is why teardown re-shows it twice."""
    prefix = len(f"[running: {state.busy}] ") if state.busy else 2
    column = prefix + max(0, int(state.input_caret or 0)) + 1
    return (max(1, size.rows), max(1, min(size.cols, column)))


def _too_small(size: Size) -> list[str]:
    """One honest line, centred, and nothing else. A layout squeezed below its floor is not a
    smaller dashboard, it is a wrong one — and the operator cannot tell which.

    Three phrasings, shortest one that fits: a sentence clipped to ``terminal t`` names neither the
    problem nor the fix, which is the whole job of this row.
    """
    need, got = f"{MIN_SIZE.cols}x{MIN_SIZE.rows}", f"{size.cols}x{size.rows}"
    rows = [""] * size.rows
    if not size.rows:
        return rows
    for text in (f"terminal too small (needs {need}; this is {got})",
                 f"needs {need}, got {got}", f"{need} needed", need):
        if len(text) <= size.cols:
            rows[size.rows // 2] = text.center(size.cols).rstrip()
            return rows
    rows[size.rows // 2] = _cut(need, size.cols)
    return rows


def _panic(size: Size, exc: BaseException) -> list[str]:
    """A frame that reports its own failure rather than letting the loop die.

    A renderer exception with no handler is a still screen over a live hunt — the operator reads it
    as a finished run and walks away. One visible line naming the exception is recoverable.
    """
    rows = [""] * size.rows
    if size.rows:
        rows[0] = _cut(f"gn dash: frame error: {type(exc).__name__}: {exc}", size.cols)
    if size.rows > 1:
        rows[size.rows - 1] = _cut("> ", size.cols)
    return rows


def render(state: DashState, size: Size, tier: dict) -> list[str]:
    """The whole frame: exactly ``size.rows`` rows, none wider than ``size.cols``, no escapes.

    Pure. Everything time-dependent arrives on ``state``; everything glyph-dependent arrives on
    ``tier``. That is what lets the entire layout — every reflow band, every derived number — be a
    unit test instead of a screenshot.
    """
    try:
        size = Size(max(1, int(size[0])), max(1, int(size[1])))
    except Exception:  # noqa: BLE001 - a bad size must not be the reason nothing draws
        size = MIN_SIZE
    try:
        rows = _frame(state, size, tier)
    except Exception as exc:  # noqa: BLE001 - see _panic
        rows = _panic(size, exc)
    out = [_cut(row, size.cols) for row in rows[:size.rows]]
    out.extend("" for _ in range(size.rows - len(out)))
    return out


def _frame(state: DashState, size: Size, tier: dict) -> list[str]:
    if size.cols < MIN_SIZE.cols or size.rows < MIN_SIZE.rows:
        return _too_small(size)
    tier = tier if isinstance(tier, dict) else {}
    box = tuple(tier.get("box") or ("+", "+", "+", "+", "-", "|", "+", "+"))
    vertical = box[5]
    widths = _plan_cols(size.cols)
    wide, narrow = len(widths) == 3, len(widths) == 1
    heights = _plan_rows(size.rows, wide=wide, narrow=narrow)

    rows: list[str] = [_header_row(state, size, tier)]
    rows.extend(_band(state, heights["band"], widths, tier, vertical))
    if heights["rate"]:
        rows.append(_separator_row("RATE", size, tier))
        body = _rate_rows(state, heights["rate"] - 1, size.cols - 2, tier)
        rows.extend(_row([line], (size.cols - 2,), vertical) for line in body)
    rows.append(_separator_row(_pane_title(state, tier), size, tier))
    body = _pane_rows(state, heights["log"] - 1, size.cols - 2, tier)
    rows.extend(_row([line], (size.cols - 2,), vertical) for line in body)
    if heights["strip"]:
        rows.append(_bottom_row(state, size, tier))
    rows.append(_message_row(state, size, tier, strip=not heights["strip"]))
    rows.append(_input_row(state, size))
    return rows


def _pane_title(state: DashState, tier: dict) -> str:
    """``LOG | output`` — the SHOWN tab in capitals, the hidden one in lower case, the focused one
    marked with the tick and an unread hidden tab marked with the dot. Three signals, three glyphs
    that every tier has, and no second row spent on a tab bar."""
    tick = str(tier.get("tick") or "*")
    dot = str(tier.get("dot") or ".")
    shown = "output" if state.tab == "output" else "log"
    names = []
    for name in ("log", "output"):
        text = name.upper() if name == shown else name
        if state.focus == name:
            text += tick
        if name != shown and name == "output" and state.unread_output:
            text += dot
        names.append(text)
    return " | ".join(names)


def _band(state: DashState, height: int, widths: Sequence[int], tier: dict, vertical: str) -> list[str]:
    if height <= 0:
        return []
    if len(widths) == 1:
        width = widths[0]
        top = max(1, (height - 2) // 2)
        bottom = max(0, height - 2 - top)
        cells = ([_targets_title(state, width, tier)] + _target_rows(state, top, width, tier)
                 + [_findings_title(state, width, tier)] + _findings_rows(state, bottom, width, tier))
        return [_row([cell], widths, vertical) for cell in _pad_block(cells, height)]
    columns = [
        [_targets_title(state, widths[0], tier)] + _target_rows(state, height - 1, widths[0], tier),
        [_findings_title(state, widths[1], tier)] + _findings_rows(state, height - 1, widths[1], tier),
    ]
    if len(widths) == 3:
        columns.append([_rate_title(state, widths[2], tier)]
                       + _rate_rows(state, height - 1, widths[2], tier))
    columns = [_pad_block(column, height) for column in columns]
    return [_row([column[index] for column in columns], widths, vertical) for index in range(height)]


# --- the verb table -----------------------------------------------------------------------------
VERBS: tuple[VerbSpec, ...] = (
    VerbSpec("stop", hook="stop", needs="stop",
             help="ask the watched run to cancel", latency=STOP_WORDING),
    VerbSpec("reverify", hook="reverify", args="<ref>", needs="reverify",
             help="re-probe one finding's URL with the active verifier",
             latency="runs beside the hunt on the command worker; it cannot be cancelled"),
    VerbSpec("program list", hook="program_list", needs="programs",
             help="the portfolio, with each program's enabled flag"),
    VerbSpec("program enable", hook="program_enable", args="<id>", needs="programs",
             help="enable a program",
             latency="effective at the operator's next scheduling pass (<=15s idle tick)"),
    VerbSpec("program disable", hook="program_disable", args="<id>", needs="programs",
             help="disable a program",
             latency="effective at the operator's next scheduling pass (<=15s idle tick)"),
    VerbSpec("program now", hook="program_now", args="<id>", needs="programs",
             help="clear a program's next_run_at so it is due immediately",
             latency="effective at the operator's next scheduling pass (<=15s idle tick)"),
    VerbSpec("operator stop", hook="operator_stop", needs="operator-stop",
             help="stop the operator loop (attached backends only)",
             latency="between programs and targets; will not interrupt a campaign already running"),
    VerbSpec("help", hook="help", help="this table, in the OUTPUT pane", immediate=True),
    VerbSpec("quit", hook="quit", aliases=("q",), help="leave the dashboard", immediate=True),
)

#: Verbs that would put a second hunt into this process's progress store, evicting the run on screen.
_HUNT_VERBS = frozenset({"hunt", "campaign"})
_SELF_VERBS = frozenset({"dash", "gn"})


def _match_verb(tokens: Sequence[str]) -> tuple[VerbSpec | None, tuple[str, ...]]:
    """Longest match first, so ``operator stop`` is the verb and ``operator list`` is a subcommand."""
    for size in (2, 1):
        if len(tokens) < size:
            continue
        head = " ".join(tokens[:size]).lower()
        for spec in VERBS:
            if head == spec.name or head in spec.aliases:
                return spec, tuple(tokens[size:])
    return None, tuple(tokens)


def _cli_commands() -> tuple[str, ...]:
    """``gn_cli.CLI_COMMANDS``, or ``()`` when the CLI cannot be imported.

    Empty means "do not second-guess the verb": the pane dispatches through the real parser, so an
    unknown verb still gets argparse's own error. Refusing a verb here because the import failed
    would break every subcommand for a reason that has nothing to do with the command typed.
    """
    try:
        import gn_cli

        return tuple(gn_cli.CLI_COMMANDS)
    except Exception:  # noqa: BLE001 - the pane still works, it just stops pre-checking names
        return ()


def parse_command(line: str, *, capabilities: frozenset[str] = frozenset(),
                  watching: bool = True, commands: Sequence[str] | None = None) -> ParsedCommand:
    """Read one input line. Pure: it decides, it never acts.

    The refusals are the interesting part. ``dash`` would open a second full-screen renderer on this
    terminal. ``hunt``/``campaign``/``osint --hunt``/``operator run`` would start a second run in
    THIS process, and the progress store holds eight — so the run on screen would be evicted by the
    command the operator typed to look at it more closely. That one is lifted when we are attached,
    because then the store being filled belongs to another process entirely.
    """
    text = str(line or "").strip()
    if not text:
        return ParsedCommand("empty")
    try:
        tokens = shlex.split(text)
    except ValueError:
        return ParsedCommand("refused", error="unbalanced quotes in that line.")
    if not tokens:
        return ParsedCommand("empty")

    held = capabilities or frozenset()
    spec, args = _match_verb(tokens)
    if spec is not None:
        if spec.needs and spec.needs not in held:
            mode = "attached" if "operator-stop" in held else "in-process"
            return ParsedCommand("refused", name=spec.name, verb=spec,
                                 error=f"`{spec.name}` is not available on this run "
                                       f"({mode} mode does not offer `{spec.needs}`).")
        return ParsedCommand("verb", name=spec.name, args=args, verb=spec)

    name = tokens[0].lower()
    rest = tuple(tokens[1:])
    if name in _SELF_VERBS:
        return ParsedCommand("refused", name=name, error=DASH_REFUSAL)
    starts_hunt = (name in _HUNT_VERBS
                   or (name == "osint" and "--hunt" in rest)
                   or (name == "operator" and rest[:1] == ("run",)))
    if watching and starts_hunt:
        return ParsedCommand("refused", name=name, error=HUNT_REFUSAL)
    known = tuple(commands) if commands is not None else _cli_commands()
    if known and name not in known:
        return ParsedCommand("refused", name=name,
                             error=f"unknown command: {name}. Type `help` for what this pane accepts.")
    return ParsedCommand("subcommand", name=name, args=rest)


def help_lines(capabilities: frozenset[str]) -> list[str]:
    """The VERBS table, rendered for the OUTPUT pane, with each verb's REAL latency beside it.

    The latency column is the point. ``stop`` does not stop, it asks; ``program now`` takes effect on
    the next scheduling pass. An operator who reads "stop" and watches probes keep landing for eighty
    seconds concludes the tool is broken — so the wait is written down where they will read it.
    """
    lines = ["pane commands", ""]
    for spec in VERBS:
        available = (not spec.needs) or spec.needs in (capabilities or frozenset())
        name = f"{spec.name} {spec.args}".strip()
        mark = "  " if available else "x "
        lines.append(f"{mark}{name:<22} {spec.help}")
        if spec.latency:
            lines.append(f"    {' ' * 22}{spec.latency}")
    lines.extend([
        "",
        "  any other `gn` verb runs in this pane (leads, findings, stats, scan, ...).",
        "  a pane command cannot be cancelled; one runs at a time.",
        f"  refused: {DASH_REFUSAL}",
        "  refused while watching a local run: hunt / campaign / osint --hunt / operator run.",
        "",
        "  keys: Tab cycles LOG / OUTPUT / TARGETS   PgUp,PgDn scroll the focused one",
        "        Up,Down walk the command history    Ctrl-L repaints   q quits",
        "  x = unavailable on this run (the source does not offer it).",
    ])
    return lines


# --- sources ------------------------------------------------------------------------------------
class LocalSource:
    """An in-process run, read straight out of ``bughunter.progress``.

    ``poll`` is the whole structural argument of this module: it returns ``{**tail, "snapshot": ...}``
    — byte-for-byte the dict ``greyiq_api.bounty_progress`` splats over HTTP — so the renderer cannot
    tell the two modes apart and there is no adapter to keep in step.

    The snapshot is treated as READ-ONLY: ``progress.snapshot`` copies targets with ``dict(t)`` but
    findings shallowly, so every finding dict (and its nested proof detail) is shared with the live
    buffer the engine is still writing to.
    """

    def __init__(self, run_id: str, label: str = "", *, progress: Any = None, governor: Any = None) -> None:
        self._run_id = str(run_id or "")
        self._label = str(label or "")
        self._progress = progress
        self._governor = governor

    # --- RunSource ---------------------------------------------------------------------------------
    def poll(self, after: int = 0) -> dict:
        progress = self._progress_module()
        if progress is None:
            raise SourceError("the progress store is not importable in this process.", fatal=True)
        return {**progress.tail(self._run_id, int(after or 0)),
                "snapshot": progress.snapshot(self._run_id)}

    def capabilities(self) -> frozenset[str]:
        return frozenset({"stop", "reverify", "programs", "governor"})

    def stop(self) -> tuple[bool, str]:
        progress = self._progress_module()
        if progress is None:
            return (False, "the progress store is not importable in this process.")
        progress.request_stop(self._run_id)
        return (True, STOP_WORDING)

    def label(self) -> str:
        return self._label or self._run_id

    def governor(self) -> tuple[dict[str, Any], ...]:
        module = self._governor_module()
        if module is None:
            return ()
        try:
            return tuple(module.governor_snapshot())
        except Exception:  # noqa: BLE001 - a readout must never be the reason a frame dies
            return ()

    def reverify(self, ref: str) -> tuple[bool, str]:
        """Re-probe one streamed finding's URL with the same scope-gated active verifier the campaign
        uses, on a bounded budget.

        Two things keep this from being a way to aim the prover at an arbitrary host. The URL comes
        from the SNAPSHOT, never from what the operator typed — the ref is only a lookup key. And the
        scope handed to ``verify_active`` is :func:`run_scope`, the hosts this run was launched
        against, NOT the finding's own host: scoping a probe by the URL it is aimed at authorizes
        every URL, and a finding's ``location`` can be a third party the recon crawl merely observed.
        ``verify_active`` then applies its own fail-closed check, and ``in_scope`` is believed rather
        than second-guessed here.
        """
        snapshot = self._snapshot()
        finding = _find_ref(snapshot, ref)
        if finding is None:
            return (False, f"no streamed finding with ref {ref!r} on this run.")
        url = str(finding.get("location") or "")
        if not url:
            return (False, f"finding {ref} has no URL to re-verify.")
        try:
            from bughunter import active_verify_service
        except Exception as exc:  # noqa: BLE001
            return (False, f"the active verifier is not importable here: {type(exc).__name__}.")
        try:
            results, meta = active_verify_service.verify_active(
                url, [], scope=run_scope(snapshot), requests_budget=16)
        except Exception as exc:  # noqa: BLE001 - a verb must not take the cockpit down
            return (False, f"re-verify failed: {type(exc).__name__}: {exc}")
        if not meta.get("in_scope"):
            return (False, f"{url} is not in this run's scope; nothing was sent.")
        confirmed = sum(1 for row in (results or []) if str(row.get("status") or "") == "confirmed")
        return (True, f"re-verified {ref}: {len(results or [])} checks, {confirmed} confirmed.")

    # --- internals ---------------------------------------------------------------------------------
    def _snapshot(self) -> dict[str, Any]:
        progress = self._progress_module()
        return progress.snapshot(self._run_id) if progress is not None else {}

    def _progress_module(self) -> Any:
        if self._progress is None:
            try:
                from bughunter import progress as module
            except Exception:  # noqa: BLE001
                return None
            self._progress = module
        return self._progress

    def _governor_module(self) -> Any:
        if self._governor is None:
            try:
                from bughunter import rate_limit as module
            except Exception:  # noqa: BLE001
                return None
            self._governor = module
        return self._governor


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    try:
        return str(urlparse(str(url)).hostname or "")
    except Exception:  # noqa: BLE001
        return ""


def run_scope(snapshot: dict[str, Any] | None) -> str:
    """The hosts this run was LAUNCHED against, as an active-scope string.

    This is what a pane-initiated re-verify is scoped by. The alternative — scoping the probe by the
    host of the URL being probed — authorizes every URL by construction, which is not a scope check
    at all. ``active_verify_service._scope_hosts`` reads exactly this shape (whitespace-separated
    dotted hosts) and does the suffix matching itself, so nothing is re-implemented here.
    """
    hosts: list[str] = []
    for target in ((snapshot or {}).get("targets") or ()):
        if not isinstance(target, dict):
            continue
        host = _host_of(target.get("target"))
        if host and host not in hosts:
            hosts.append(host)
    return " ".join(hosts)


def _find_ref(snapshot: dict[str, Any] | None, ref: str) -> dict[str, Any] | None:
    for finding in ((snapshot or {}).get("findings") or ()):
        if isinstance(finding, dict) and str(finding.get("ref") or "") == str(ref):
            return finding
    return None


def runtime_dirs() -> tuple[str, ...]:
    """Where a ``session.token`` might live, most authoritative first.

    ``gn`` defaults to ``PROJECT_ROOT/runtime``; the desktop app sets ``GREYIQ_RUNTIME_DIR`` to its
    own ``<userData>/runtime``. An operator attaching from a shell to the app's backend is the normal
    case, and those two paths are never the same, so the platform userData path is probed too rather
    than reported as "no token".
    """
    seen: list[str] = []
    for candidate in (os.getenv("GREYIQ_RUNTIME_DIR"),
                      getattr(sys.modules.get("gn_cli"), "RUNTIME_DIR", None),
                      _user_data_runtime()):
        text = str(candidate or "").strip()
        if text and text not in seen:
            seen.append(text)
    return tuple(seen)


def _user_data_runtime() -> str:
    home = os.path.expanduser("~")
    if os.name == "nt":
        base = os.getenv("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return os.path.join(base, "GreyIQ", "runtime")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "GreyIQ", "runtime")
    return os.path.join(home, ".config", "GreyIQ", "runtime")


def read_token(explicit: str = "") -> str:
    """The session token: ``--token``, then ``$GREYIQ_SESSION_TOKEN``, then each runtime dir."""
    return read_token_source(explicit)[0]


def read_token_source(explicit: str = "") -> tuple[str, str]:
    """``(token, the runtime dir it came from)``; the dir is ``""`` for ``--token``/env.

    The dir matters beyond bookkeeping. Attaching from a shell to the desktop app's backend is the
    normal case, and the two runtime dirs are never the same — that split is the whole reason
    ``runtime_dirs`` probes more than one. Whichever dir held the token is, by construction, the one
    the backend is using, so it is also the portfolio those program verbs must act on.
    """
    if explicit:
        return (str(explicit).strip(), "")
    env = str(os.getenv("GREYIQ_SESSION_TOKEN") or "").strip()
    if env:
        return (env, "")
    for directory in runtime_dirs():
        try:
            with open(os.path.join(directory, "session.token"), "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError:
            continue
        if token:
            return (token, directory)
    return ("", "")


class AttachedSource:
    """A run inside another process, over ``POST /api/bounty/progress``.

    Two rules run through everything here. **Loopback only**: the session token is embedded in the
    unauthenticated index page, so it is not authentication once the server is reachable off
    127.0.0.1 — a ``--host`` that is not loopback is refused rather than "supported with a warning".
    **No token before a probe answers**: discovery walks ports with an unauthenticated
    ``GET /api/health``, and only the port that answers is ever sent a credential.

    Failures are typed (:class:`SourceError`) rather than swallowed, because the loop shows a
    different pill for each one: a refused connection freezes the panels behind a ``stale`` badge,
    while a missing access key is fatal and says exactly which variable to set.
    """

    def __init__(self, run_id: str, *, host: str = "127.0.0.1", port: int | None = None,
                 token: str = "", timeout: float = 4.0, label: str = "") -> None:
        self._run_id = str(run_id or "")
        self._host = str(host or "127.0.0.1").strip().lower()
        if self._host not in _LOOPBACK_HOSTS:
            raise SourceError(
                f"--attach only talks to loopback ({', '.join(sorted(_LOOPBACK_HOSTS))}); "
                f"{self._host!r} is not, and session.token is not authentication off this machine.",
                fatal=True)
        self._timeout = max(0.5, float(timeout or 4.0))
        self._label = str(label or "")
        # The dir the token came from IS the backend's runtime dir, and the program verbs act on
        # that portfolio rather than this shell's — see _portfolio.
        self._token, self.runtime_dir = read_token_source(token)
        self._port = int(port) if port else None

    # --- RunSource ---------------------------------------------------------------------------------
    def poll(self, after: int = 0) -> dict:
        payload = self._post("/api/bounty/progress", {"run_id": self._run_id, "after": int(after or 0)})
        # ``ok`` is the route's transport envelope, present on every /api/* answer; it is not run
        # data. Dropping it here is what makes the two sources answer the same three keys, so the
        # renderer cannot tell them apart. This is the ONLY normalisation either source performs.
        payload.pop("ok", None)
        return payload

    def capabilities(self) -> frozenset[str]:
        # No ``governor``: nothing exposes the token buckets over HTTP, and an empty list would read
        # as "no hosts are being paced", which is a measurement we have not made.
        return frozenset({"stop", "reverify", "programs", "operator-stop"})

    def stop(self) -> tuple[bool, str]:
        self._post("/api/bounty/campaign/stop", {"run_id": self._run_id})
        return (True, STOP_WORDING)

    def label(self) -> str:
        return self._label or self._run_id

    def governor(self) -> tuple[dict[str, Any], ...]:
        return ()

    def reverify(self, ref: str) -> tuple[bool, str]:
        """Same rule as the local path: the URL comes from the snapshot and the scope is the run's
        own targets, so the route's fail-closed check has something real to refuse."""
        snapshot = self.poll(0).get("snapshot") or {}
        finding = _find_ref(snapshot, ref)
        if finding is None:
            return (False, f"no streamed finding with ref {ref!r} on this run.")
        url = str(finding.get("location") or "")
        if not url:
            return (False, f"finding {ref} has no URL to re-verify.")
        answer = self._post("/api/bounty/finding/reverify",
                            {"url": url, "authorized": True, "scope": run_scope(snapshot)})
        if not answer.get("ok", True):
            return (False, str(answer.get("error") or "the backend refused the re-verify."))
        return (True, f"re-verified {ref} on the backend.")

    def operator_stop(self) -> tuple[bool, str]:
        self._post("/api/operator/stop", {})
        return (True, "operator stopping - between programs and targets; "
                      "a campaign already running is not interrupted.")

    def list_runs(self) -> list[dict[str, Any]]:
        answer = self._post("/api/bounty/runs", {})
        runs = answer.get("runs")
        return [row for row in runs if isinstance(row, dict)] if isinstance(runs, list) else []

    # --- internals ---------------------------------------------------------------------------------
    @property
    def port(self) -> int:
        if self._port is None:
            self._port = self._discover_port()
        return self._port

    def _base(self, port: int) -> str:
        host = f"[{self._host}]" if ":" in self._host else self._host
        return f"http://{host}:{int(port)}"

    def _discover_port(self) -> int:
        """``$GREYIQ_PORT`` first, then a token-free walk of 8766..8845."""
        env = str(os.getenv("GREYIQ_PORT") or "").strip()
        if env.isdigit() and self._is_greyiq(int(env)):
            return int(env)
        for port in range(_PORT_BASE, _PORT_BASE + _PORT_SPAN):
            if self._is_greyiq(port):
                return port
        raise SourceError(
            f"no GreyIQ backend answered on {self._host}:{_PORT_BASE}-"
            f"{_PORT_BASE + _PORT_SPAN - 1}; start the app, or pass --port.", fatal=True)

    def _is_greyiq(self, port: int) -> bool:
        """Is a GreyIQ backend listening here — established WITHOUT handing over the token?

        ``/api/health`` alone cannot answer this. It is deliberately unfingerprintable, so it
        replies with a bare ``{"status": "ok"}`` — one of the most common health shapes there is.
        Accepting that as proof of identity meant the very next request sent ``X-GreyIQ-Token`` to
        whatever was listening. On a multi-user box another user can bind 8766 before GreyIQ takes
        8767, and while they cannot read the owner-only token file, the walk would have delivered
        the token to them.

        So identity needs a signal only GreyIQ produces, obtainable without authenticating. The
        token gate itself is that signal: every ``/api/*`` path except ``/api/health`` answers an
        unauthenticated request with 403 and exactly ``{"error": "missing or invalid session
        token"}``. Being REFUSED in GreyIQ's own words is the proof, and the probe that earns it
        carries no credential — a foreign listener that happens to return ``{"status":"ok"}`` does
        not also refuse a POST in those words.

        This raises the bar from "answers a common health shape" to "reproduces GreyIQ's auth gate".
        It is not a cryptographic identity check, and it is not meant to be: the session token is
        explicitly not real authentication once the server is reachable beyond loopback (see
        greyiq_api), which is why ``--attach`` refuses a non-loopback host in the first place.
        """
        return self._health_ok(port) and self._gate_ok(port)

    def _health_ok(self, port: int) -> bool:
        request = urllib.request.Request(self._base(port) + "/api/health", method="GET")
        self._apply_access_key(request)
        try:
            with urllib.request.urlopen(request, timeout=min(1.0, self._timeout)) as response:
                body = response.read(256)
        except Exception:  # noqa: BLE001 - a closed port, a foreign listener, a timeout: all "no"
            return False
        try:
            return json.loads(body.decode("utf-8", "replace")).get("status") == "ok"
        except (ValueError, AttributeError):
            return False

    def _gate_ok(self, port: int) -> bool:
        """A DELIBERATELY unauthenticated POST to a token-gated route. No token header is set."""
        request = urllib.request.Request(
            self._base(port) + _GATE_PROBE_PATH, data=b"{}", method="POST",
            headers={"Content-Type": "application/json"})
        self._apply_access_key(request)  # the access key gates the token gate; see _apply_access_key
        try:
            with urllib.request.urlopen(request, timeout=min(1.0, self._timeout)):
                return False  # answered an unauthenticated POST: not GreyIQ's gate
        except urllib.error.HTTPError as exc:
            if int(getattr(exc, "code", 0) or 0) != 403:
                return False
            try:
                body = json.loads(exc.read(256).decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                return False
            return isinstance(body, dict) and body.get("error") == _GATE_REFUSAL
        except Exception:  # noqa: BLE001
            return False

    def _apply_access_key(self, request: urllib.request.Request) -> None:
        """Add HTTP Basic auth when ``GREYIQ_ACCESS_KEY`` is set.

        That gate runs before EVERYTHING in greyiq_api — ahead of the token gate and ahead of
        ``/api/health`` — so against a backend started with an access key, a client that omits it
        gets 401 on every request including discovery. Without this the walk found no backend at
        all, and an explicit ``--port`` reported "set GREYIQ_ACCESS_KEY", naming a variable this
        client then ignored: advice that could not be followed.
        """
        key = str(os.getenv("GREYIQ_ACCESS_KEY") or "")
        if not key:
            return
        # The server takes ANY username and compares the PASSWORD against the key
        # (greyiq_api._access_key_authorized), so the key goes in the password field verbatim —
        # never split on a colon, which would silently truncate a key that contains one.
        try:
            raw = base64.b64encode(f"gn:{key}".encode("utf-8")).decode("ascii")
        except Exception:  # noqa: BLE001 - a key we cannot encode is one we cannot send
            return
        request.add_header("Authorization", "Basic " + raw)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        port = self.port
        try:
            return self._send(port, path, payload)
        except SourceError as exc:
            if exc.status != "TOKEN":
                raise
        # A 403 after a good token is the restart case: SESSION_TOKEN is minted per process and the
        # file is rewritten at boot, so a fresh read is a different token exactly when the backend
        # has restarted. Retried only when it actually changed — retrying the same rejected token
        # would double the request rate against a backend that is already refusing us.
        fresh = read_token()
        if fresh and fresh != self._token:
            self._token = fresh
            return self._send(port, path, payload)
        raise SourceError(STALE_TOKEN_MESSAGE)

    def _send(self, port: int, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._token:
            raise SourceError(NO_TOKEN_MESSAGE, fatal=True)
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._base(port) + path, data=body, method="POST",
            headers={"Content-Type": "application/json", _TOKEN_HEADER: self._token})
        self._apply_access_key(request)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise self._http_error(exc) from None
        except urllib.error.URLError as exc:
            raise SourceError(f"no answer from the backend at {self._base(port)} ({exc.reason}).") from None
        except Exception as exc:  # noqa: BLE001 - a transport we did not anticipate is still "no answer"
            raise SourceError(f"no answer from the backend at {self._base(port)} "
                              f"({type(exc).__name__}).") from None
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise SourceError(f"{self._base(port)}{path} answered something that is not JSON; "
                              f"that port is not a GreyIQ backend.", fatal=True) from None
        if not isinstance(parsed, dict):
            raise SourceError(f"{self._base(port)}{path} answered JSON that is not an object.")
        return parsed

    @staticmethod
    def _http_error(exc: urllib.error.HTTPError) -> SourceError:
        status = int(getattr(exc, "code", 0) or 0)
        try:
            challenge = str((exc.headers or {}).get("WWW-Authenticate") or "")
        except Exception:  # noqa: BLE001
            challenge = ""
        if status == 401 and challenge:
            return SourceError(ACCESS_KEY_MESSAGE, fatal=True)
        if status == 403:
            # Signalled, not reported: _post re-reads the token file once before giving up.
            return SourceError(STALE_TOKEN_MESSAGE, status="TOKEN")
        return SourceError(f"the backend answered HTTP {status} to {exc.url or 'the request'}.")


# --- pane commands ------------------------------------------------------------------------------
class OutputTail:
    """A line buffer a pane command writes into while the OUTPUT pane reads it.

    ``_dash_subcommand`` could simply return its captured text at the end, and for ``gn version``
    that would be fine. ``gn leads`` on a large ledger is not fine: the operator would watch a frozen
    pane and then get everything at once, which is indistinguishable from a hang. So the redirect
    writes HERE, under a lock, and the pane tails it.
    """

    encoding = "utf-8"

    def __init__(self, limit: int = _MAX_OUTPUT_LINES) -> None:
        self._lock = threading.Lock()
        self._lines: list[str] = []
        self._partial = ""
        self._limit = max(1, int(limit))

    def write(self, text: Any) -> int:
        body = str(text)
        with self._lock:
            self._partial += body
            if "\n" in self._partial:
                parts = self._partial.split("\n")
                self._partial = parts.pop()
                self._lines.extend(parts)
                del self._lines[: max(0, len(self._lines) - self._limit)]
        return len(body)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        # False on purpose: the verb running in here asks, and a verb that believes it is on a
        # terminal will colour its output, which would put escape sequences into the frame.
        return False

    def add(self, line: str) -> None:
        self.write(str(line) + "\n")

    def clear(self) -> None:
        with self._lock:
            self._lines, self._partial = [], ""

    def lines(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._lines + ([self._partial] if self._partial else []))

    def text(self) -> str:
        return "\n".join(self.lines())


def _dash_subcommand(argv: Sequence[str], sink: Any = None) -> tuple[int, str]:
    """Run one real ``gn`` verb and hand back ``(exit code, output)``. Never raises.

    Dispatches through ``build_parser().parse_args()`` and ``args.func(args)`` rather than
    ``gn_cli.main``: ``main`` swallows ``KeyboardInterrupt`` into an error message and calls
    ``gn_fx.stop_all()`` in its own ``finally``. We have to catch ``SystemExit`` regardless —
    ``argparse.error()`` exits 2 — so bypassing ``main`` costs nothing and removes two surprises.

    ``gn_fx.stop_all()`` is still called here, because the verb may have started a Scanner of its
    own; it drains ``gn_fx``'s registry only and cannot touch the dashboard, which registers in
    ``gn_tui``'s separate one. That separation is the entire reason there are two registries.
    """
    argv = [str(item) for item in (argv or ())]
    if argv and argv[0] in _SELF_VERBS:
        return 2, f"gn: {DASH_REFUSAL}\n"
    buffer = sink if sink is not None else io.StringIO()
    code = 0
    try:
        import gn_cli

        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            args = gn_cli.build_parser().parse_args(argv)
            code = args.func(args) if getattr(args, "func", None) else 0
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 2
    except BaseException as exc:  # noqa: BLE001 - a pane command must never kill the cockpit
        return 2, _sink_text(buffer) + f"gn: {type(exc).__name__}: {exc}\n"
    finally:
        try:
            import gn_fx

            gn_fx.stop_all()
        except Exception:  # noqa: BLE001
            pass
    return int(code or 0), _sink_text(buffer)


def _sink_text(sink: Any) -> str:
    for reader in ("getvalue", "text"):
        method = getattr(sink, reader, None)
        if callable(method):
            try:
                return str(method())
            except Exception:  # noqa: BLE001
                return ""
    return ""


def stream_result(run_id: str, target: str, result: dict[str, Any], *, progress: Any = None) -> None:
    """Roll a finished in-process hunt into the progress store, exactly as the API route does.

    ``gn dash <target>`` calls ``run_bounty_hunt`` directly, so nothing else would ever write the
    hunt's findings into the store the panels read — the FINDINGS panel would stay empty through a
    run that found things, and the work unit would sit at ``running`` forever. Mirrors
    ``GreyIQRuntime._stream_hunt_to_dashboard`` (same compact shape, same proof-status derivation)
    so a dashboard-launched hunt and an app-launched one produce identical snapshots. Never raises.
    """
    try:
        if progress is None:
            from bughunter import progress as progress_module

            progress = progress_module
        if not run_id:
            return
        if not result.get("ok", True):
            progress.mark_target(run_id, target, "error", error=str(result.get("error") or ""))
            return
        poi = result.get("proof_of_impact") or {}
        compact: list[dict[str, Any]] = []
        for finding in (result.get("findings") or []):
            if not isinstance(finding, dict):
                continue
            ref = str(finding.get("ref") or "")
            detail = poi.get(ref) or {}
            compact.append({
                "ref": ref, "title": finding.get("title"), "severity": finding.get("severity"),
                "class_name": finding.get("class_name") or finding.get("class_id"),
                "proof_status": str(detail.get("status") or "missing"),
                "location": finding.get("location") or target, "cwe": finding.get("cwe"),
                "rule_id": finding.get("rule_id"), "class_id": finding.get("class_id"),
                "proof_detail": detail, "proof_evidence": finding.get("proof_evidence") or None,
            })
        if compact:
            progress.add_findings(run_id, target, compact)
        progress.mark_target(run_id, target, "done")
    except Exception:  # noqa: BLE001 - streaming a result must never break a completed hunt
        pass


# --- the loop -----------------------------------------------------------------------------------
def supported(stream: Any = None) -> bool:
    """Whether a dashboard is appropriate here: a terminal on both ends, and at least 60x18."""
    stream = sys.stdout if stream is None else stream
    if not gn_tui.enabled(stream):
        return False
    size = gn_tui.terminal_size(stream)
    return size.cols >= MIN_SIZE.cols and size.rows >= MIN_SIZE.rows


def size_refusal(size: Size) -> str:
    """One sentence for ``_err()`` when the terminal is below the floor, or ``""``.

    Distinct from :func:`_too_small`, which is the in-frame version: this one is printed to a shell
    that was never entered, so it names the fix. ``gn dash`` on a 40-column window must refuse here
    rather than degrade to a plain hunt — the operator asked for a cockpit, and a hunt that quietly
    ran without one is a different command from the one they typed.
    """
    if size.cols >= MIN_SIZE.cols and size.rows >= MIN_SIZE.rows:
        return ""
    return (f"the dashboard needs at least {MIN_SIZE.cols}x{MIN_SIZE.rows}; this terminal is "
            f"{size.cols}x{size.rows}. Resize it, or run the hunt without `dash`.")


def self_test(stream: Any = None, inp: Any = None) -> int:
    """``gn dash --self-test`` — enter, draw one frame, give the terminal back, and report the picks.

    CI is ubuntu-only and every console this has to survive is a Windows one, so the manual matrix
    (Windows Terminal, conhost at cp437, mintty, tmux over SSH) is the only place the interesting
    failures show up — and an operator staring at a wall of empty boxes has no other way to ask the
    program what it chose. This prints the four answers that decide a frame (glyph tier, key backend,
    VT state, measured size), says which host counters answered, and proves the round trip by really
    entering the alternate screen and really giving it back.

    It prints the diagnosis even when it refuses: "why it refused" is the most useful line here, and
    a verb that prints nothing is indistinguishable from a broken one — the ``gn fx`` lesson
    (gn_fx.demo). The exit code still answers the yes/no question: 0 drew a frame, 2 did not.
    """
    out = sys.stdout if stream is None else stream
    keys = sys.stdin if inp is None else inp
    refusal = gn_tui.refusal(out, keys)
    size = gn_tui.terminal_size(out)
    glyphs = gn_tui.tier(out)
    small = size_refusal(size)

    vt_state, key_backend, drew = "not reached", "not reached", False
    if not refusal and not small:
        vt_state, key_backend, drew = _draw_one_frame(out, keys, size, glyphs)

    sample = _probe_sysmon()
    unavailable = sorted(name for name, value in sample.items() if value is None)
    lines = [
        "gn dash self-test",
        f"  terminal size   {size.cols}x{size.rows}" + (f"   ({small})" if small else ""),
        f"  glyph tier      {glyphs.get('name', '?')}"
        f"   (stream encoding {getattr(out, 'encoding', None) or 'unknown'};"
        f" braille {'on' if glyphs.get('braille') else 'off'} - GN_DASH_GLYPHS overrides)",
        f"  key reader      {key_backend}",
        f"  console VT      {vt_state}",
        f"  host counters   {'all nine answered' if not unavailable else 'unavailable: ' + ', '.join(unavailable)}"
        f"   (disk: {sample.get('disk_path') or 'unknown'})",
        f"  one frame       {'drawn and torn down' if drew else 'not drawn'}",
    ]
    if refusal:
        lines.append(f"  refused         {refusal}")
    elif small:
        lines.append(f"  refused         {small}")
    for line in lines:
        print(line)
    return 0 if drew else 2


def _draw_one_frame(out: Any, keys: Any, size: Size, glyphs: dict) -> tuple[str, str, bool]:
    """Acquire everything the loop acquires, paint one frame, unwind. Returns what was observed.

    Total on purpose: the self-test's job is to REPORT a broken terminal, so a console that raises
    on the way in has to come back as a state string rather than as a traceback on top of a screen
    that may be half entered.
    """
    vt_state, key_backend, drew = "unmanaged", "none", False
    try:
        with ExitStack() as stack:
            console = stack.enter_context(gn_tui.WinConsole())
            vt_state = console.vt_state
            if not console.vt_enabled:
                return ("unavailable - this console refused ENABLE_VIRTUAL_TERMINAL_PROCESSING",
                        key_backend, False)
            reader = stack.enter_context(gn_tui.KeyReader(keys))
            key_backend = reader.backend
            # ``active=True``, not the default probe: :func:`self_test` has already asked
            # ``gn_tui.refusal(out, keys)`` about BOTH streams, while ``Screen``'s own probe would
            # re-ask about stdin rather than the keyboard stream it was handed — so a caller driving
            # this with an explicit pair would get "enabled" from the policy and a dead screen from
            # the object. The decision is made once, above, where both ends are in scope.
            screen = stack.enter_context(gn_tui.Screen(out, active=True, size=size))
            state = DashState(label="self-test", status="DONE", now_epoch=0.0, started_epoch=0.0,
                              message="gn dash self-test - one frame, then the terminal comes back")
            screen.frame(render(state, size, glyphs), cursor(state, size))
            # Long enough to read as a frame rather than a flicker, short enough that nobody reaches
            # for Ctrl-C. The teardown below runs either way.
            time.sleep(0.6)
            drew = screen.active
    except Exception as exc:  # noqa: BLE001 - a self-test that raises has failed to do its one job
        return (f"{vt_state} (entering raised {type(exc).__name__})", key_backend, False)
    return (vt_state, key_backend, drew)


def _probe_sysmon() -> dict[str, Any]:
    """Two samples, because the CPU cell is a DELTA: one reading always reports ``None`` and would
    tell an operator their host counters are broken when they are merely new."""
    try:
        sampler = gn_sysmon.SystemSampler()
        sampler.sample()
        time.sleep(0.2)
        return dict(sampler.sample())
    except Exception:  # noqa: BLE001 - "we could not even build the sampler" is a legal answer here
        return {name: None for name in
                ("cpu_percent", "cpu_count", "mem_used", "mem_total", "mem_percent",
                 "disk_used", "disk_total", "disk_percent", "disk_path")}


class Dashboard:
    """The refresh loop: three clocks, one poller, one command slot.

    The TUI owns the MAIN thread — ``termios`` restore and ``SIGWINCH`` both belong there — which
    inverts ``gn_fx``, where the animation is the daemon and the hunt is the main thread. The hunt
    therefore runs on a daemon worker, and its exception is captured and re-raised AFTER teardown:
    without that, a hunt that died would exit 0 behind a clean screen.

    Input is polled at 60ms and the screen repaints at 4Hz — deliberately two clocks, not one.
    Polling input at the repaint rate makes every keystroke wait up to a quarter of a second, and
    repainting at the input rate pushes a whole frame out 16 times a second over conpty or SSH,
    which is worse than either. The data poll is a third clock on its own thread (250ms local,
    1000ms attached) so a slow backend costs staleness rather than a frozen keyboard.
    """

    def __init__(self, source: Any, *, run_subcommand: Callable[..., tuple[int, str]] | None = None,
                 launch: Callable[[], Any] | None = None, refresh_hz: float = 4.0,
                 allow_control: bool = True, stream: Any = None, inp: Any = None,
                 size: Sequence[int] | None = None, sampler: Any = None,
                 poll_interval: float | None = None, commands: Sequence[str] | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self._source = source
        self._run_subcommand = run_subcommand or _dash_subcommand
        self._launch = launch
        # Clamped, not defaulted: ``--refresh 0`` is an operator asking for the slowest repaint the
        # loop offers, and turning it into 4Hz because zero is falsy would silently overrule them.
        try:
            self._hz = max(0.5, min(20.0, float(refresh_hz)))
        except (TypeError, ValueError):
            self._hz = 4.0
        self._allow_control = bool(allow_control)
        self._out = sys.stdout if stream is None else stream
        self._in = sys.stdin if inp is None else inp
        self._size = size
        self._commands = commands
        self._clock = clock or time.time
        self._attached = "operator-stop" in _capabilities(source)
        self._interval = float(poll_interval if poll_interval is not None
                               else (1.0 if self._attached else 0.25))
        self._sampler = sampler

        self._lock = threading.Lock()
        self._quit = threading.Event()
        self._state = DashState(mode="attached" if self._attached else "local",
                                capabilities=_capabilities(source))
        self._events: list[dict[str, Any]] = []
        self._snapshot: dict[str, Any] = {}
        self._after = 0
        self._started = self._clock()
        self._first_data: float | None = None
        self._last_good: float | None = None
        self._had_data = False
        self._rate_history: list[float | None] = []
        self._cpu_history: list[float | None] = []
        self._governor_prev: tuple[dict[str, Any], ...] = ()
        self._governor_at: float | None = None
        self._message = ""
        self._message_at = 0.0
        self._status = "RUNNING"
        self._stop_requested = False
        self._output = OutputTail()
        self._pool: ThreadPoolExecutor | None = None
        self._future: Any = None
        self._busy = ""
        self._hunt_error: BaseException | None = None
        self._hunt_code: int | None = None
        self._line = gn_tui.CommandLine()
        self._tab = "log"
        self._focus = "log"
        self._unread = False
        self._target_scroll = 0
        self._pane_scroll = 0
        self._repaint = False

    # --- entry -------------------------------------------------------------------------------------
    def run(self) -> int:
        # Acquisition order IS the teardown contract (gn_tui): console modes, then the keyboard,
        # then the screen — unwound in reverse, so the alt screen is gone before the tty settings
        # it was drawn under are handed back.
        with ExitStack() as stack:
            console = stack.enter_context(gn_tui.WinConsole())
            if not console.vt_enabled:
                # Clear-and-home would destroy the operator's scrollback, which is worse than not
                # running at all — so this refuses instead of degrading.
                self._write_plain("gn: this console will not enable ANSI (VT) processing, and a "
                                  "dashboard cannot draw without it.\n")
                return 2
            reader = stack.enter_context(gn_tui.KeyReader(self._in))
            screen = stack.enter_context(gn_tui.Screen(self._out, size=self._size))
            self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="gn-dash-cmd")
            # Both on the stack so an exception on the way up still stops the threads: the poller
            # holds a socket and the worker may be mid-verb, and neither is a daemon we want racing
            # the terminal restore.
            stack.callback(self._pool.shutdown, wait=False)
            stack.callback(self._quit.set)
            self._start_threads()
            self._loop(screen, reader)
        if self._hunt_error is not None:
            # After the stack has unwound, so gn_cli.main prints onto a restored terminal.
            raise self._hunt_error
        return int(self._hunt_code or 0)

    # --- threads -----------------------------------------------------------------------------------
    def _start_threads(self) -> None:
        threading.Thread(target=self._poll_loop, name="gn-dash-poll", daemon=True).start()
        if self._launch is not None:
            threading.Thread(target=self._hunt_body, name="gn-dash-hunt", daemon=True).start()

    def _hunt_body(self) -> None:
        try:
            outcome = self._launch() if self._launch else None
        except BaseException as exc:  # noqa: BLE001 - captured, re-raised after teardown
            self._hunt_error = exc
            self._set_status("DONE")
            self.note(f"the hunt raised {type(exc).__name__}: {exc}")
            return
        if isinstance(outcome, int):
            self._hunt_code = outcome
        self._set_status("DONE")
        self.note("run finished - the panels are frozen on the final snapshot; q to leave")

    def _poll_loop(self) -> None:
        """Ask the source for new data forever. Daemon, and the only thread that writes the buffers.

        ONE polling thread that blocks on each request is the re-entrancy guard: the frontend polls
        this same endpoint on a timer and has to skip a tick explicitly, because a heavy campaign
        takes longer to answer than the interval. Here the next poll simply cannot start until the
        last one returns, so a slow backend costs staleness rather than a pile-up of sockets.

        A failure backs off 1s, 2s, 4s, 8s and stops there; a FATAL one returns, because a missing
        access key or a port that is not a GreyIQ backend will not fix itself, and hammering it at
        4Hz is noise in someone's log for nothing. The panels keep the last good snapshot either way.
        """
        backoff = 0.0
        while not self._quit.is_set():
            try:
                payload = self._source.poll(self._after)
            except SourceError as exc:
                self._on_source_error(exc)
                if exc.fatal:
                    return
                backoff = min(8.0, backoff * 2 if backoff else 1.0)
            except Exception as exc:  # noqa: BLE001 - a poller that dies freezes the panels silently
                self._on_source_error(SourceError(f"{type(exc).__name__}: {exc}"))
                backoff = min(8.0, backoff * 2 if backoff else 1.0)
            else:
                backoff = 0.0
                self._absorb(payload)
            self._quit.wait(self._interval + backoff)

    def _absorb(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        now = self._clock()
        snapshot = payload.get("snapshot")
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        events = [e for e in (payload.get("events") or []) if isinstance(e, dict)]
        has_data = bool(snapshot.get("targets") or snapshot.get("findings") or events
                        or payload.get("count"))
        governor = tuple(self._source.governor() or ()) if "governor" in self._state.capabilities else ()
        with self._lock:
            self._after = int(payload.get("count") or self._after)
            if events:
                self._events.extend(events)
                del self._events[: max(0, len(self._events) - _MAX_EVENTS)]
            if self._first_data is None and has_data:
                self._first_data = now
            self._last_good = now
            evicted = self._had_data and not has_data
            self._had_data = self._had_data or has_data
            self._snapshot = snapshot
            if governor or self._governor_prev:
                window = now - self._governor_at if self._governor_at else 0.0
                rate = probe_rate(self._governor_prev, governor, window)
                self._rate_history.append(rate)
                del self._rate_history[: max(0, len(self._rate_history) - _MAX_HISTORY)]
                self._governor_prev, self._governor_at = governor, now
            if evicted:
                self._status = "EVICTED"
                self._message = "this run was evicted from the progress store (_MAX_RUNS=8)"
                self._message_at = now
            elif self._status in ("NO BACKEND", "STALE"):
                self._status = "STOPPING" if self._stop_requested else "RUNNING"

    def _on_source_error(self, exc: SourceError) -> None:
        with self._lock:
            self._status = exc.status if exc.status != "TOKEN" else "NO BACKEND"
            self._message = exc.message
            self._message_at = self._clock()

    # --- state -------------------------------------------------------------------------------------
    def snapshot_state(self, size: Size) -> DashState:
        """One lock acquire, everything copied out. The renderer never sees a live buffer."""
        now = self._clock()
        sysmon = self._sample()
        with self._lock:
            snapshot = self._snapshot or {}
            stale = None
            if self._last_good is not None and self._status in ("NO BACKEND", "STALE"):
                stale = max(0.0, now - self._last_good)
            if self._message and now - self._message_at > _MESSAGE_SECONDS:
                self._message = ""
            started = self._first_data or self._started
            state = DashState(
                label=_label_of(self._source),
                mode=self._state.mode,
                run_id=getattr(self._source, "_run_id", "") or "",
                status=self._status,
                phase=_last_message(self._events),
                elapsed=max(0.0, now - started),
                stale_for=stale,
                started_epoch=started,
                now_epoch=now,
                snapshot=snapshot,
                events=tuple(self._events),
                governor=self._governor_prev,
                rate=self._rate_history[-1] if self._rate_history else None,
                rate_history=tuple(self._rate_history),
                cpu_history=tuple(self._cpu_history),
                sysmon=sysmon,
                message=self._message,
                output=self._output.lines(),
                tab=self._tab,
                focus=self._focus,
                unread_output=self._unread,
                target_scroll=self._target_scroll,
                pane_scroll=self._pane_scroll,
                busy=self._busy,
                capabilities=self._state.capabilities,
            )
        # The same prefix width ``cursor()`` counts, so the caret lands under the character the
        # operator is about to overwrite rather than one cell off it.
        prefix = len(state.busy) + 12 if state.busy else 2
        rendered = self._line.render(max(1, size.cols - prefix))
        state.input_text, state.input_caret = rendered.text.rstrip(), rendered.caret
        return state

    def _sample(self) -> dict[str, Any]:
        """One system reading, on the repaint thread. ``self._sampler`` is None until first use and
        ``False`` once retired — a probe that raised is retired for the life of the process rather
        than retried four times a second, and every cell it fed renders ``--`` from then on."""
        if self._sampler is None:
            try:
                self._sampler = gn_sysmon.SystemSampler()
            except Exception:  # noqa: BLE001 - no sampler means three "--" cells, never a crash
                self._sampler = False
        if self._sampler is False:
            return {}
        try:
            sample = self._sampler.sample()
        except Exception:  # noqa: BLE001
            self._sampler = False
            return {}
        self._cpu_history.append(sample.get("cpu_percent"))
        del self._cpu_history[: max(0, len(self._cpu_history) - _MAX_HISTORY)]
        return sample if isinstance(sample, dict) else {}

    def note(self, message: str) -> None:
        with self._lock:
            self._message = str(message)
            self._message_at = self._clock()

    def _set_status(self, status: str) -> None:
        with self._lock:
            self._status = str(status)

    # --- the loop ----------------------------------------------------------------------------------
    def _loop(self, screen: Any, reader: Any) -> None:
        period = 1.0 / self._hz
        tier = gn_tui.tier(self._out)   # probed once: the stream's encoding does not change mid-run
        next_paint = time.monotonic()
        while not self._quit.is_set():
            timeout = max(0.0, min(0.06, next_paint - time.monotonic()))
            key = reader.read(timeout) if reader is not None else None
            if key:
                self.handle_key(key)
            if self._quit.is_set():
                break
            resized = screen.take_resize()
            if resized or self._repaint or time.monotonic() >= next_paint:
                size = screen.size()
                if self._repaint:
                    # Ctrl-L means "something else wrote on my terminal". The row diff would keep
                    # every untouched row exactly as that something left it, so the frame is blanked
                    # first: two writes, on demand only, and the help text stays true.
                    self._repaint = False
                    screen.frame([""] * size.rows)
                state = self.snapshot_state(size)
                screen.frame(render(state, size, tier), cursor(state, size))
                now = time.monotonic()
                next_paint += period
                if next_paint < now:            # a slow frame must not queue up a burst of repaints
                    next_paint = now + period
            self._reap()

    # --- keys --------------------------------------------------------------------------------------
    def handle_key(self, key: str) -> None:
        """One key. Total: an unhandled key is ignored, never echoed as a control character."""
        try:
            if key == "CTRL-C":
                # Windows getwch delivers ^C literally; on POSIX cbreak keeps ISIG and a real SIGINT
                # has already raised. Either way this is the operator asking to leave.
                self._quit.set()
                return
            if key == "CTRL-L":
                self._repaint = True
                return
            if key in ("PGUP", "PGDN"):
                self._scroll(-1 if key == "PGUP" else 1)
                return
            if key == "TAB":
                # Ambiguous by design, which is why gn_tui.CommandLine refuses to own it: with an
                # empty line Tab moves between panes, with a partial verb it completes one.
                self._cycle_focus() if not self._line.text else self._complete()
                return
            submitted = self._line.feed(key)
            if submitted is not None:
                self.submit(submitted)
        except Exception as exc:  # noqa: BLE001 - a key must never take the cockpit down
            self.note(f"that key raised {type(exc).__name__}")

    def _complete(self) -> str:
        """Complete the first word from the pane verbs plus ``gn_cli.CLI_COMMANDS``.

        Only the FIRST word: completing an argument would mean guessing at a program id or a finding
        ref, and a wrong guess silently submitted against a live engagement is not worth the
        keystroke it saves. One match completes; several print the list to the message line.
        """
        text = self._line.text
        if " " in text.strip():
            return text
        prefix = text.strip().lower()
        pool = sorted({spec.name.split(" ")[0] for spec in VERBS}
                      | set(self._commands if self._commands is not None else _cli_commands()))
        matches = [name for name in pool if name.startswith(prefix)]
        if len(matches) == 1:
            self._line.set(matches[0] + " ")
        elif matches:
            self.note(" ".join(matches[:12]))
        return self._line.text

    def _cycle_focus(self) -> None:
        order = ("log", "output", "targets")
        self._focus = order[(order.index(self._focus) + 1) % len(order)] if self._focus in order else "log"
        if self._focus in ("log", "output"):
            self._tab = self._focus
            if self._focus == "output":
                self._unread = False
        self._pane_scroll = 0

    def _scroll(self, direction: int) -> None:
        step = 5 * direction
        if self._focus == "targets":
            self._target_scroll = max(0, self._target_scroll + step)
        else:
            self._pane_scroll = max(0, self._pane_scroll - step)

    # --- commands ----------------------------------------------------------------------------------
    def submit(self, line: str) -> None:
        parsed = parse_command(line, capabilities=self._state.capabilities,
                               watching=not self._attached, commands=self._commands)
        if parsed.kind == "empty":
            return
        if not self._allow_control and parsed.name not in ("quit", "help"):
            self.note("control is off for this pane (--no-control); q to leave.")
            return
        if parsed.kind == "refused":
            self.note(f"gn: {parsed.error}")
            return
        if parsed.kind == "verb" and parsed.verb is not None and parsed.verb.immediate:
            self._run_verb(parsed.verb, parsed.args)
            return
        if self._busy:
            self.note("gn: " + BUSY_REFUSAL.format(busy=self._busy))
            return
        if parsed.kind == "verb" and parsed.verb is not None:
            self._dispatch(f"{parsed.name}", lambda spec=parsed.verb, args=parsed.args: self._run_verb(spec, args))
        else:
            self._dispatch(f"gn {parsed.name}",
                           lambda argv=(parsed.name, *parsed.args): self._run_gn(list(argv)))

    def _dispatch(self, label: str, body: Callable[[], None]) -> None:
        if self._pool is None:
            body()
            return
        self._busy = label
        try:
            self._future = self._pool.submit(self._guarded, body)
        except Exception as exc:  # noqa: BLE001 - a dead pool costs the command, not the cockpit
            self._busy = ""
            self.note(f"gn: could not start {label}: {type(exc).__name__}")

    def _guarded(self, body: Callable[[], None]) -> None:
        try:
            body()
        except SourceError as exc:
            self.note(f"gn: {exc.message}")
        except Exception as exc:  # noqa: BLE001
            self.note(f"gn: {type(exc).__name__}: {exc}")

    def _reap(self) -> None:
        """Free the single command slot once the in-flight verb has returned.

        Polled from the loop rather than freed by a done-callback: the callback would run ON the
        worker thread, so the slot could be handed to a second command while the first was still
        unwinding its ``redirect_stdout``.
        """
        future = self._future
        if future is None or not future.done():
            return
        self._future = None
        self._busy = ""

    def _run_gn(self, argv: list[str]) -> None:
        self._output.clear()
        self._output.add(f"$ gn {' '.join(argv)}")
        code, _text = self._run_subcommand(argv, self._output)
        self._output.add(f"exit {code}")
        if self._tab != "output":
            self._unread = True
        self.note(f"gn {argv[0]} exited {code}" + ("" if self._tab == "output" else " - Tab for OUTPUT"))

    def _run_verb(self, spec: VerbSpec, args: Sequence[str]) -> None:
        handler = getattr(self, f"_verb_{spec.hook}", None)
        if handler is None:
            self.note(f"gn: `{spec.name}` has no handler.")
            return
        ok, message = handler(tuple(args))
        self.note(("" if ok else "gn: ") + message)

    # --- verb hooks --------------------------------------------------------------------------------
    def _verb_stop(self, _args: Sequence[str]) -> tuple[bool, str]:
        ok, message = self._source.stop()
        if ok:
            self._stop_requested = True
            self._set_status("STOPPING")
        return (ok, message)

    def _verb_reverify(self, args: Sequence[str]) -> tuple[bool, str]:
        if not args:
            return (False, "reverify needs a finding ref, e.g. `reverify F-3`.")
        return self._source.reverify(str(args[0]))

    def _verb_operator_stop(self, _args: Sequence[str]) -> tuple[bool, str]:
        handler = getattr(self._source, "operator_stop", None)
        if handler is None:
            return (False, "this source cannot stop the operator loop.")
        return handler()

    def _verb_program_list(self, _args: Sequence[str]) -> tuple[bool, str]:
        portfolio, runtime = _portfolio(self._source)
        if portfolio is None:
            return (False, "the portfolio is not readable from here.")
        self._output.clear()
        self._output.add("$ program list")
        programs = portfolio.list_programs(runtime)
        for program in programs:
            flag = "on " if program.get("enabled") else "off"
            self._output.add(f"  [{flag}] {program.get('id', '')}  {program.get('name', '')}")
        if not programs:
            self._output.add("  (no programs in this portfolio)")
        self._unread = self._tab != "output"
        return (True, f"{len(programs)} programs - Tab for OUTPUT")

    def _verb_program_enable(self, args: Sequence[str]) -> tuple[bool, str]:
        return self._set_program(args, True)

    def _verb_program_disable(self, args: Sequence[str]) -> tuple[bool, str]:
        return self._set_program(args, False)

    def _set_program(self, args: Sequence[str], enabled: bool) -> tuple[bool, str]:
        if not args:
            return (False, "that needs a program id (see `program list`).")
        portfolio, runtime = _portfolio(self._source)
        if portfolio is None:
            return (False, "the portfolio is not writable from here.")
        record = portfolio.set_enabled(runtime, str(args[0]), enabled)
        if record is None:
            return (False, f"no program with id {args[0]!r}.")
        word = "enabled" if enabled else "disabled"
        return (True, f"{args[0]} {word} - effective at the operator's next scheduling pass "
                      f"(<=15s idle tick)")

    def _verb_program_now(self, args: Sequence[str]) -> tuple[bool, str]:
        """Clear ``next_run_at`` rather than calling ``touch_run``.

        ``touch_run`` unconditionally stamps ``last_run_at = now``, which falsifies the scheduling
        history the pipeline funnel reads. ``_is_due`` treats a falsy ``next_run_at`` as due, so
        clearing it is the honest hook for "run this one next".

        The id is RESOLVED first. ``upsert_program`` creates what it cannot find, so a mistyped id
        silently minted a new default-enabled program: the dashboard answered "due now" about a
        program that had never existed, and left the typo behind in ``portfolio.json`` as a phantom
        scheduled record. ``enable``/``disable`` right above already fail closed on an unknown id
        via ``set_enabled``; this now matches them.
        """
        if not args:
            return (False, "that needs a program id (see `program list`).")
        portfolio, runtime = _portfolio(self._source)
        if portfolio is None:
            return (False, "the portfolio is not writable from here.")
        program_id = str(args[0])
        if portfolio.get_program(runtime, program_id) is None:
            return (False, f"no program with id {program_id!r}.")
        portfolio.upsert_program(runtime, {"id": program_id, "next_run_at": None})
        return (True, f"{program_id} is due now - effective at the operator's next scheduling pass "
                      f"(<=15s idle tick)")

    def _verb_help(self, _args: Sequence[str]) -> tuple[bool, str]:
        self._output.clear()
        for line in help_lines(self._state.capabilities):
            self._output.add(line)
        self._tab = "output"
        self._focus = "output"
        self._unread = False
        return (True, "help is in the OUTPUT pane")

    def _verb_quit(self, _args: Sequence[str]) -> tuple[bool, str]:
        self._quit.set()
        return (True, "leaving")

    # --- plumbing ----------------------------------------------------------------------------------
    def _write_plain(self, text: str) -> None:
        try:
            sys.stderr.write(text)
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            pass


def _capabilities(source: Any) -> frozenset[str]:
    try:
        return frozenset(source.capabilities())
    except Exception:  # noqa: BLE001 - a source that cannot answer offers nothing
        return frozenset()


def _label_of(source: Any) -> str:
    try:
        return str(source.label() or "")
    except Exception:  # noqa: BLE001
        return ""


def _last_message(events: Sequence[dict[str, Any]]) -> str:
    for event in reversed(list(events or ())):
        if isinstance(event, dict) and event.get("message"):
            return str(event["message"])
    return ""


def _portfolio(source: Any = None) -> tuple[Any, Any]:
    """``(portfolio module, runtime dir)`` — file-backed, so it works in both modes and across
    processes: the operator loop re-reads the portfolio each program cycle.

    WHICH runtime dir is the whole question in attached mode. The backend commonly runs on
    Electron's user-data runtime while this shell's ``gn_cli.RUNTIME_DIR`` is the checkout's
    ``runtime/``, and reading the shell's dir showed a different portfolio than the operator being
    watched — ``program list`` listed the wrong programs, and ``enable``/``now`` reported success
    while changing a file the running operator never reads. Token discovery already resolved the
    backend's dir (that is where ``session.token`` was found), so prefer it and fall back to the
    shell's only when attaching did not go through a file.
    """
    try:
        import gn_cli
        from bughunter import portfolio
    except Exception:  # noqa: BLE001
        return None, None
    attached = ""
    if source is not None:
        try:
            attached = str(getattr(source, "runtime_dir", "") or "")
        except Exception:  # noqa: BLE001 - a source that cannot answer is simply not attached
            attached = ""
    return portfolio, (attached or gn_cli.RUNTIME_DIR)


def run(source: Any, *, run_subcommand: Callable[..., tuple[int, str]] | None = None,
        launch: Callable[[], Any] | None = None, refresh_hz: float = 4.0,
        allow_control: bool = True, **kwargs: Any) -> int:
    """Draw the dashboard until the operator leaves. Returns the exit code the hunt produced.

    ``run_subcommand(argv, sink) -> (exit code, text)`` is how a ``gn`` verb typed into the pane gets
    run; it defaults to :func:`_dash_subcommand`, and the ``sink`` argument is not optional for a
    replacement — it is the buffer the OUTPUT pane tails while the verb is still writing.

    ``launch`` is the hunt, run on a daemon worker because the TUI owns the main thread. If it
    raised, the exception is re-raised here, AFTER the terminal has been restored, so ``gn_cli.main``
    prints ``gn: TypeError: ...`` onto a working shell rather than into an alternate screen that is
    about to be discarded — and so a hunt that died cannot exit 0 behind a clean frame.
    """
    return Dashboard(source, run_subcommand=run_subcommand, launch=launch, refresh_hz=refresh_hz,
                     allow_control=allow_control, **kwargs).run()
