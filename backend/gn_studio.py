"""The AGENT STUDIO: what your bot is set up as, what it has learned, and a chat to ask it things.

`gn studio` (also `/studio` from the threat board, and `gn dash --studio`) is the third dash view.
The board answers "what is happening to which host"; the panel cockpit answers "what is this run
doing"; this one answers the question neither can: **what is my agent, and what has it learned?**
Same amber chrome as the board, because it is the same cockpit.

WHAT IT SHOWS, and where every number comes from
------------------------------------------------
Nothing here is computed by this module. Each row is a value some other local store already keeps,
read through that store's own reader and labelled with it:

  * **BRAIN** — the operator profile (``gn_profile``) and ``runtime/solin_runtime_config.json``:
    which bot answers, the provider and model, whether a key is present (never the key), whether
    agent commands and skills are enabled, whether internet access is on.
  * **LEARNING** — ``hunt_trace.trace_stats`` (the hunt corpus), ``learning.program_summary``
    (submitted / rewarded / bounty), ``negative_knowledge`` (what it has learned not to retry),
    ``hunt_train`` (the offline ranker) and ``coder_train.corpus_status`` (the tiny model's corpus
    and whether a trained model is actually present).
  * **AGENTS** — the local Hugging Face agent store (``hf_agent_clone``), which is inert by design;
    the studio says so on the row, because a cloned agent that LOOKS runnable is the one thing an
    operator could misread here.

A store that is missing, empty or unreadable renders as ``--`` with the reason, never as a zero: a
fabricated zero is indistinguishable from "nothing has happened yet", and this program's one house
rule is that a number has to be reproducible from evidence.

THE CHAT, AND WHY IT CANNOT MAKE ANYTHING UP
--------------------------------------------
Answers come from :mod:`solin_domain` — the torch-free curated pack the shipped build already
answers from — through the same three branches ``greyiq_api._domain_brain_reply`` uses: the
vuln-class table, the tool catalog, then a VERBATIM excerpt from a bundled card with its source
path. ``solin_domain`` performs no generation of any kind, so a chat window on a security tool
cannot invent a security claim here. When nothing matches, it says nothing matched.

**A configured external brain is shown but never called.** Opening a dashboard must not send a
prompt off the machine or spend an operator's API budget as a side effect of looking at statistics,
and a local Ollama round trip inside a repaint loop would stall the frame. The BRAIN panel names
what is configured and ``/help`` points at the Workbench agent, which is where a brain is driven on
purpose.

PURE WHERE IT MATTERS
---------------------
:func:`render` is pure and escape-free — rows in, rows out, exactly ``size.rows`` of them, none
wider than ``size.cols``, no ANSI anywhere — exactly as ``gn_dash.render`` is, and for the same
three reasons: the layout counts characters, the tests assert on plain strings, and ``_plain``
strips escapes out of text this did not author. Colour goes on afterwards in :func:`colorize`.
"""
from __future__ import annotations

import json
import os
import re
import sys
import textwrap
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

import gn_tui
from gn_tui import Size

#: The studio's floor. Narrower than the board's (it has no map to draw) but wide enough for the
#: two columns; below this the layout is not a smaller studio, it is a wrong one.
MIN_SIZE = Size(72, 18)
TITLE = "GREYNOC // AGENT STUDIO"
#: One line, like the board's. The commands, since there is nowhere else to put them.
#: Kept inside the footer's room on the narrowest terminal the studio draws on (MIN_SIZE minus the
#: chrome), so the one line that lists the commands is never the line that gets cut.
HINT = "/ask <q>  /settings  /set k v  /board  /panels  /quit"
#: What the chat says when the pack has nothing. It does NOT generate an answer instead.
NO_MATCH = ("nothing in the offline pack matched that. Try a class (\"what is ssrf\"), ask for "
            "tools (\"tools for idor\"), or /help.")
#: How many chat turns are kept. A studio is not a transcript archive; the ledger and the traces
#: are where durable things live.
MAX_TURNS = 60
_MAX_FIELD = 160

#: The amber ramp the threat board draws in, so the two views read as one cockpit. 256-colour SGR,
#: applied in :func:`colorize` after the frame is laid out.
_SGR = {
    "chrome": "38;5;178",      # the box and its rules
    "title": "1;38;5;214",     # the header name
    "dim": "38;5;58",          # a footer, a disabled row
    "label": "38;5;101",       # a row label
    "value": "38;5;223",       # a row value
    "on": "38;5;108",          # something that is on, trained, present
    "off": "38;5;203",         # something that is off, missing, unreadable
    "you": "1;38;5;81",        # the operator's own chat line
    "bot": "38;5;223",         # the bot's
    "cite": "38;5;101",        # a Source: line
}


# --- state ----------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Row:
    """One ``label  value`` line in a panel, plus how the value should read.

    ``tone`` is what the COLLECTOR meant ("this is off", "this could not be read"), and it is what
    the panel tests assert on. :func:`colorize` does not read it, because by then the row is a
    plain string — ``render``'s contract — and the tone would have to be smuggled through the text
    to survive. The painter re-derives it from the rendered value instead, off the same vocabulary
    (``_ON_WORDS`` / ``_OFF_WORDS``) the collectors write.
    """

    label: str
    value: str
    tone: str = "value"        # "value" | "on" | "off" | "dim"


@dataclass
class StudioState:
    brain: tuple[Row, ...] = ()
    learning: tuple[Row, ...] = ()
    agents: tuple[Row, ...] = ()
    #: ``(who, text)`` where who is "you", "gn" or "cite".
    chat: tuple[tuple[str, str], ...] = ()
    status: str = ""
    busy: str = ""
    message: str = ""
    input_text: str = ""
    input_caret: int = 0
    chat_scroll: int = 0
    learning_on: bool = True
    bot: str = ""


def _plain(text: Any) -> str:
    """Every control character (ESC included) as a space — the same guard ``gn_dash._plain`` is.

    Card text, a model name out of a config file and a store's error string all reach a row, and
    none of them is this module's to trust with the operator's cursor.
    """
    return str(text).translate(_CTRL_TABLE)


_CTRL_TABLE = {code: " " for code in range(32)}
_CTRL_TABLE[127] = " "


def _cut(text: Any, limit: int) -> str:
    if limit <= 0:
        return ""
    return _plain(text)[:limit]


def _field(value: Any) -> str:
    text = " ".join(_plain(value).split())
    return text[:_MAX_FIELD]


#: What a limited codec gets instead. The chat quotes markdown cards full of em-dashes, arrows and
#: curly quotes, and a row that will not encode raises inside ``Screen._write`` — which deactivates
#: the screen and leaves a still frame over a live studio. ``Board._clean`` transliterates for
#: exactly this reason; this is the same list, applied to the finished frame.
_FOLD = {
    "·": ".", "—": "-", "–": "-", "→": "->", "←": "<-",
    "‘": "'", "’": "'", "“": '"', "”": '"', "…": "...",
    "•": "*", " ": " ", "─": "-", "│": "|",
}


#: ``(char, encoding) -> replacement``, because the probe below runs per character per frame.
_FOLD_CACHE: dict[tuple[str, str], str] = {}


def _encodable(text: str, encoding: str) -> bool:
    try:
        text.encode(encoding, errors="strict")
    except (UnicodeEncodeError, LookupError, TypeError, AttributeError):
        return False
    return True


def _fold(text: str, encoding: str, limit: int = 0) -> str:
    """One row, with every character this terminal's CODEC cannot write replaced.

    Driven by the encoding rather than by the glyph tier, because the two disagree: cp437 encodes
    the box-drawing glyphs fine (so the tier is ``box``, not ``ascii``) and cannot encode the
    em-dash that arrives inside a quoted playbook card. A row that will not encode raises inside
    ``Screen._write``, which deactivates the screen and leaves a still frame over a live studio —
    the worst failure this file has. ``Board._clean`` transliterates for the same reason.

    A replacement wider than one cell (``->``) would widen the row, so the result is cut back to
    ``limit`` when one is given.
    """
    if not text or not encoding or _encodable(text, encoding):
        return text
    out = []
    for ch in text:
        key = (ch, encoding)
        replacement = _FOLD_CACHE.get(key)
        if replacement is None:
            replacement = ch if _encodable(ch, encoding) else _FOLD.get(ch, "?")
            if not _encodable(replacement, encoding):
                replacement = "?"
            _FOLD_CACHE[key] = replacement
        out.append(replacement)
    folded = "".join(out)
    return folded[:limit] if limit > 0 else folded


def _elide(text: Any, width: int) -> str:
    body = _plain(text)
    if width <= 0:
        return ""
    if len(body) <= width:
        return body
    return body[: max(1, width - 1)] + "~"


# --- the three panels -----------------------------------------------------------------------------
def brain_rows(profile: Any, runtime_dir: str | Path) -> tuple[Row, ...]:
    """What answers, and with what. Read from the profile and the app's own runtime config."""
    rows: list[Row] = []
    bot = str(getattr(profile, "get", lambda _k: "")("bot") or "tinygpt")
    rows.append(Row("bot", bot, "on" if bot != "off" else "off"))
    config = _read_json(Path(runtime_dir) / "solin_runtime_config.json")
    coder = config.get("coder") if isinstance(config.get("coder"), dict) else {}
    provider = str(coder.get("provider") or "")
    if coder:
        enabled = bool(coder.get("enabled"))
        rows.append(Row("brain", f"{provider or 'unset'} · {'enabled' if enabled else 'off'}",
                        "on" if enabled else "dim"))
        block = coder.get(provider) if isinstance(coder.get(provider), dict) else {}
        model = str(block.get("model") or "")
        if model:
            rows.append(Row("model", model))
        # Presence only. A dashboard that can print a key is a dashboard that can leak one.
        rows.append(Row("key", "configured" if str(block.get("api_key") or "") else "none",
                        "on" if str(block.get("api_key") or "") else "dim"))
        agent = coder.get("agent") if isinstance(coder.get("agent"), dict) else {}
        if agent:
            rows.append(Row("agent", f"skills {_onoff(agent.get('skills_enabled'))} · "
                                     f"commands {_onoff(agent.get('allow_commands'))}",
                            "on" if agent.get("skills_enabled") else "dim"))
    else:
        rows.append(Row("brain", "no runtime config — deterministic", "dim"))
    rows.append(Row("internet", _onoff(config.get("internet_enabled")),
                    "off" if config.get("internet_enabled") else "on"))
    rows.append(Row("memory", _onoff(config.get("memory_learning", True)),
                    "on" if config.get("memory_learning", True) else "dim"))
    return tuple(rows)


def learning_rows(runtime_dir: str | Path, seed_dir: str | Path | None = None) -> tuple[Row, ...]:
    """What the engine has learned, each number from the store that keeps it."""
    rows: list[Row] = []
    traces, error = _call(lambda: _trace_stats(runtime_dir))
    if error:
        rows.append(Row("corpus", f"-- ({error})", "off"))
    else:
        rows.append(Row("corpus", f"{traces.get('hunts', 0)} hunts · "
                                  f"{traces.get('outcome_rows', 0)} rows"))
        confirmed = int(traces.get("confirmed_rows") or 0)
        rows.append(Row("confirmed", str(confirmed), "on" if confirmed else "dim"))
        rows.append(Row("programs", str(traces.get("programs", 0))))
    paid, error = _call(lambda: _bounty_totals(runtime_dir))
    if error:
        rows.append(Row("outcomes", f"-- ({error})", "off"))
    elif paid is None:
        rows.append(Row("outcomes", "none recorded — `gn learn` after a submission", "dim"))
    else:
        rows.append(Row("outcomes", f"{paid['submitted']} submitted · {paid['rewarded']} rewarded"))
        rows.append(Row("bounty", f"${paid['bounty_total']:g}",
                        "on" if paid["bounty_total"] else "dim"))
    cooled, error = _call(lambda: _cooled_count(runtime_dir))
    if error:
        rows.append(Row("not-retried", f"-- ({error})", "off"))
    else:
        rows.append(Row("not-retried", f"{cooled} endpoint/class pair(s) cooled", "dim"))
    ranker, error = _call(lambda: _ranker_state(runtime_dir))
    rows.append(Row("ranker", ranker if not error else f"-- ({error})",
                    "on" if (not error and ranker and "trained" in ranker) else "dim"))
    tiny, error = _call(lambda: _tiny_state(runtime_dir, seed_dir))
    rows.append(Row("tinygpt", tiny if not error else f"-- ({error})",
                    "on" if (not error and "model" in tiny) else "dim"))
    return tuple(rows)


def agent_rows(runtime_dir: str | Path) -> tuple[Row, ...]:
    """The local agent store. Inert by design, and the row says so."""
    clones, error = _call(lambda: _agent_store(runtime_dir))
    if error:
        return (Row("store", f"-- ({error})", "off"),)
    if not clones:
        return (Row("store", "empty — `gn agent clone <ref>` adds one (inert)", "dim"),)
    rows = [Row("store", f"{len(clones)} cloned · inert (never executed)", "on")]
    for clone in clones[:6]:
        rows.append(Row(" " + _field(clone.get("id") or "?"),
                        _field(clone.get("revision") or clone.get("repo_id") or ""), "dim"))
    if len(clones) > 6:
        rows.append(Row("", f"... +{len(clones) - 6} more", "dim"))
    return tuple(rows)


def collect(runtime_dir: str | Path, seed_dir: str | Path | None = None,
            profile: Any = None) -> dict[str, tuple[Row, ...]]:
    """Every panel, read fresh. Total — a store that will not answer renders as ``--``."""
    return {
        "brain": brain_rows(profile, runtime_dir),
        "learning": learning_rows(runtime_dir, seed_dir),
        "agents": agent_rows(runtime_dir),
    }


def _onoff(value: Any) -> str:
    return "on" if bool(value) else "off"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _call(reader: Callable[[], Any]) -> tuple[Any, str]:
    """``(value, "")`` or ``(None, "why not")``. Every store read in this module goes through here."""
    try:
        return (reader(), "")
    except Exception as exc:  # noqa: BLE001 - a store that will not answer is a row, not a crash
        return (None, type(exc).__name__)


def _trace_stats(runtime_dir: str | Path) -> dict[str, Any]:
    from bughunter import hunt_trace

    return dict(hunt_trace.trace_stats(runtime_dir) or {})


def _bounty_totals(runtime_dir: str | Path) -> dict[str, Any] | None:
    from bughunter import learning

    data = learning.program_summary(runtime_dir, None, "") or {}
    programs = data.get("programs") if isinstance(data, dict) else {}
    if not programs:
        return None
    return {
        "submitted": sum(int(p.get("submitted") or 0) for p in programs.values()),
        "rewarded": sum(int(p.get("rewarded") or 0) for p in programs.values()),
        "bounty_total": sum(float(p.get("bounty_total") or 0) for p in programs.values()),
    }


def _cooled_count(runtime_dir: str | Path) -> int:
    from bughunter import negative_knowledge

    store = Path(runtime_dir) / "bughunter_negative_knowledge.json"
    doc = _read_json(store)
    programs = doc.get("programs") if isinstance(doc.get("programs"), dict) else {}
    total = 0
    for program in programs.values():
        pairs = program.get("pairs") if isinstance(program, dict) else None
        if isinstance(pairs, dict):
            total += len(pairs)
    return total if negative_knowledge.enabled() else 0


def _ranker_state(runtime_dir: str | Path) -> str:
    """Whether the offline hunt ranker has a trained model, and when it was written."""
    for name in ("hunt_model.json", "bughunter_hunt_model.json"):
        doc = _read_json(Path(runtime_dir) / name)
        if doc:
            stamp = str(doc.get("trained_at") or doc.get("updated_at") or "")[:10]
            rows = doc.get("rows") or doc.get("dataset_rows") or ""
            return f"trained {stamp or 'at an unrecorded time'}" + (f" · {rows} rows" if rows else "")
    return "none yet — rules only (`gn train-brain` after more hunts)"


def _tiny_state(runtime_dir: str | Path, seed_dir: str | Path | None) -> str:
    from coder_train import corpus_status

    status = corpus_status(Path(runtime_dir), Path(seed_dir) if seed_dir else None)
    chars = int(status.get("total_characters") or 0)
    model = str(status.get("active_model") or "")
    torch_ok = bool(status.get("torch_available"))
    size = f"{chars / 1_000_000:.1f}M chars" if chars >= 1_000_000 else f"{chars} chars"
    if model:
        return f"{size} · model present" + ("" if torch_ok else " · torch missing")
    return f"{size} · no model yet" + ("" if torch_ok else " · torch missing")


def _agent_store(runtime_dir: str | Path) -> list[dict[str, Any]]:
    """The cloned-agent index, read as data. Nothing in the store is imported or executed."""
    for name in ("agents/index.json", "agent_store/index.json", "agents.json"):
        doc = _read_json(Path(runtime_dir) / name)
        agents = doc.get("agents") if isinstance(doc.get("agents"), (list, dict)) else None
        if isinstance(agents, dict):
            return [{"id": key, **(value if isinstance(value, dict) else {})}
                    for key, value in agents.items()]
        if isinstance(agents, list):
            return [a for a in agents if isinstance(a, dict)]
    store = Path(runtime_dir) / "agents"
    if store.is_dir():
        return [{"id": child.name} for child in sorted(store.iterdir()) if child.is_dir()]
    return []


# --- the chat -------------------------------------------------------------------------------------
def answer(message: str, *, seed_dir: str | Path, runtime_dir: str | Path | None = None,
           min_score: float | None = None) -> tuple[str, str]:
    """``(body, how)`` for one question, or ``("", "")`` when nothing matched.

    The same three branches ``greyiq_api._domain_brain_reply`` takes, in the same order: the vuln
    class table, the tool catalog, then a verbatim card excerpt. ``how`` is the label the studio
    prints under the answer, so an operator can always see which of the three produced it.

    No generation anywhere on this path — see this module's docstring. Total: an import that fails
    or a card that will not compose is "nothing matched", never a traceback into the frame.
    """
    text = str(message or "").strip()
    if not text:
        return ("", "")
    try:
        import solin_domain
    except Exception:  # noqa: BLE001 - no pack, no answer
        return ("", "")
    try:
        class_id = solin_domain.detect_class_query(text)
        if class_id:
            body = solin_domain.explain_class(class_id)
            if body:
                return (body, f"class table · VULN_CLASSES[{class_id!r}]")
        if solin_domain.looks_like_tool_request(text):
            classes = solin_domain.classes_mentioned(text)
            tools = solin_domain.format_tools(
                solin_domain.recommend_tools(classes, seed_dir, runtime_dir))
            if tools:
                return (f"Tools in the bundled catalog for testing {', '.join(classes)} "
                        f"(names and links only, for authorized testing in scope):\n\n{tools}",
                        "toolkit catalog")
        pack = solin_domain.load_pack(seed_dir, runtime_dir)
        scored = solin_domain.match_cards_scored(
            text, pack, limit=3,
            min_score=solin_domain.MIN_SCORE if min_score is None else float(min_score))
        if scored:
            cards = [card for card, _score in scored]
            body = solin_domain.compose_answer(text, cards, cards[0].domain)
            if body:
                return (body, f"offline pack · {cards[0].source_path}")
    except Exception:  # noqa: BLE001
        return ("", "")
    return ("", "")


def chat_lines(turns: Sequence[tuple[str, str]], width: int) -> list[tuple[str, str]]:
    """The transcript as ``(who, line)`` rows, wrapped to ``width``. Pure."""
    out: list[tuple[str, str]] = []
    if width <= 4:
        return out
    for who, text in turns:
        prefix = "you> " if who == "you" else ("gn > " if who == "gn" else "     ")
        body = _plain(text)
        for paragraph in body.split("\n"):
            if not paragraph.strip():
                out.append((who, ""))
                continue
            wrapped = textwrap.wrap(paragraph, max(8, width - len(prefix)),
                                    break_long_words=True, break_on_hyphens=False) or [""]
            for index, line in enumerate(wrapped):
                out.append((who, (prefix if index == 0 else " " * len(prefix)) + line))
    return out


# --- render ---------------------------------------------------------------------------------------
def _panel_title(title: str, width: int, box: Sequence[str], left: str) -> str:
    head = f"{left}{box[4]} {title} "
    return _cut(head + box[4] * max(0, width - len(head)), width)


def _rows_block(rows: Sequence[Row], height: int, width: int) -> list[str]:
    """``label  value`` lines, padded to ``height``. The label column is sized to the content."""
    if height <= 0:
        return []
    body: list[str] = []
    label_width = min(11, max((len(r.label) for r in rows), default=0))
    for row in rows[:height]:
        label = _elide(row.label, label_width).ljust(label_width)
        value = _elide(row.value, max(0, width - label_width - 4))
        body.append(_cut(f" {label}  {value}", width))
    while len(body) < height:
        body.append(" " * 0)
    return body


def _too_small(size: Size) -> list[str]:
    """One honest line and nothing else, the same answer ``gn_dash`` gives below its floor."""
    text = f"the studio needs {MIN_SIZE.cols}x{MIN_SIZE.rows}; this is {size.cols}x{size.rows}"
    rows = [""] * max(0, size.rows)
    if rows:
        rows[max(0, size.rows // 2)] = _cut(text.center(max(1, size.cols)), size.cols)
    return rows


def render(state: StudioState, size: Size, tier: dict, encoding: str = "") -> list[str]:
    """One frame: exactly ``size.rows`` rows, none wider than ``size.cols``, and no escapes.

    Two columns: the three read-only panels on the left, the chat on the right. The left column is
    fixed at the width its labels need, so the chat gets every column that is left — a studio whose
    answers wrap every four words is one nobody reads.
    """
    if size.cols < MIN_SIZE.cols or size.rows < MIN_SIZE.rows:
        return _too_small(size)
    box = [str(glyph) for glyph in (tier.get("box") or ("+", "+", "+", "+", "-", "|", "+", "+"))]
    left_width = 36 if size.cols >= 96 else max(30, min(34, size.cols // 2 - 4))
    right_width = size.cols - left_width - 3
    inner_rows = size.rows - 3            # header, footer, input row

    header = _header(state, size, box)
    footer = _footer(state, size, box)
    panels = _left_column(state, inner_rows, left_width, box)
    chat = _chat_column(state, inner_rows, right_width, box)

    rows = [header]
    for index in range(inner_rows):
        cell = panels[index] if index < len(panels) else ""
        talk = chat[index] if index < len(chat) else ""
        rows.append(_cut(f"{box[5]}{cell.ljust(left_width)}{box[5]}{talk.ljust(right_width)}"
                         f"{box[5]}", size.cols))
    rows.append(footer)
    rows.append(_input_row(state, size))
    out = rows[: size.rows] + [""] * max(0, size.rows - len(rows))
    codec = encoding or ("ascii" if str(tier.get("name") or "") == "ascii" else "")
    if codec:
        out = [_fold(row, codec, size.cols) for row in out]
    return out


def _header(state: StudioState, size: Size, box: Sequence[str]) -> str:
    right = f" {'LEARNING ON' if state.learning_on else 'LEARNING OFF'} {box[4]} {_clock()} {box[1]}"
    left = f"{box[0]}{box[4]} {TITLE} "
    return _cut(left + box[4] * max(0, size.cols - len(left) - len(right)) + right, size.cols)


def _footer(state: StudioState, size: Size, box: Sequence[str]) -> str:
    note = state.busy or state.message or state.status or HINT
    left = f"{box[2]}{box[4]} {_elide(note, max(8, size.cols - 6))} "
    return _cut(left + box[4] * max(0, size.cols - len(left) - 1) + box[3], size.cols)


def _input_row(state: StudioState, size: Size) -> str:
    return _cut("> " + _plain(state.input_text), size.cols)


def cursor(state: StudioState, size: Size) -> tuple[int, int]:
    """Where the caret parks, 1-based, exactly as ``gn_dash.cursor`` does it."""
    column = 2 + max(0, int(state.input_caret or 0)) + 1
    return (max(1, size.rows), max(1, min(size.cols, column)))


def _left_column(state: StudioState, height: int, width: int,
                 box: Sequence[str] = ("+", "+", "+", "+", "-", "|", "+", "+")) -> list[str]:
    """BRAIN, LEARNING and AGENTS stacked, each taking the room its rows need."""
    sections = (("BRAIN", state.brain), ("LEARNING", state.learning), ("AGENTS", state.agents))
    rule = str(box[4])
    out: list[str] = []
    for index, (title, rows) in enumerate(sections):
        if len(out) >= height:
            break
        out.append(_cut(f" {title} " + rule * max(0, width - len(title) - 2), width))
        room = height - len(out)
        if index < len(sections) - 1:
            # Leave at least a title line for each section still to come, so the one an operator
            # is least likely to scroll to is not the one silently dropped.
            room = max(0, room - 2 * (len(sections) - index - 1))
        out.extend(_rows_block(rows, min(len(rows), room), width))
    return out[:height]


def _chat_column(state: StudioState, height: int, width: int, box: Sequence[str]) -> list[str]:
    head = _cut(" CHAT " + str(box[4]) * max(0, width - 6), width)
    body_height = max(0, height - 1)
    lines = chat_lines(state.chat, width - 1)
    if not lines:
        lines = [("gn", " ask a question, or /help for the commands"),
                 ("gn", ""),
                 ("gn", " answers are quoted from the offline pack, with a source line -"),
                 ("gn", " nothing on this path generates text")]
    scroll = max(0, min(int(state.chat_scroll or 0), max(0, len(lines) - body_height)))
    end = len(lines) - scroll
    window = lines[max(0, end - body_height):end]
    rows = [head]
    rows.extend(_cut(" " + line, width) for _who, line in window)
    while len(rows) < height:
        rows.append("")
    return rows[:height]


def _clock() -> str:
    return time.strftime("%H:%M:%S", time.gmtime())


# --- colour ---------------------------------------------------------------------------------------
_CHROME_RE = re.compile(r"[┌┐└┘─│├┤+|-]")
_LABEL_RE = re.compile(r"^([│|])( [a-z][a-z0-9._-]{0,11})( +)(\S.*)$")
_SECTION_RE = re.compile(r"^([│|]) (BRAIN|LEARNING|AGENTS|CHAT) ")
_SPEAKER_RE = re.compile(r"^([│|] )(you>|gn >)")
_SOURCE_RE = re.compile(r"((?:Source|answered by): .*)$")


def _sgr(text: str, name: str) -> str:
    code = _SGR.get(name)
    return f"\033[{code}m{text}\033[0m" if code and text else text


def colorize(rows: Sequence[str], tier: dict, *, enabled: bool = True) -> list[str]:
    """Paint the finished frame in the board's amber. Pure: rows in, rows out.

    Outside :func:`render` for the same reason ``gn_dash.colorize`` is: render's contract is plain
    rows of an exact width, the width maths counts characters, and the tests assert on strings.
    Everything painted here is anchored to a position render itself wrote — a panel edge, a label
    column, a speaker prefix — except the ``Source:`` tail, which is card text this module quoted
    and therefore already knows the shape of.
    """
    out = [str(row) for row in rows]
    if not enabled:
        return out
    ascii_frame = str(tier.get("name") or "") == "ascii"
    for index, row in enumerate(out):
        if not row:
            continue
        painted = row
        if index == 0:
            painted = painted.replace(TITLE, _sgr(TITLE, "title"), 1)
            painted = _paint_state(painted)
        section = _SECTION_RE.match(painted)
        if section:
            painted = painted.replace(f" {section.group(2)} ", f" {_sgr(section.group(2), 'title')} ", 1)
        else:
            label = _LABEL_RE.match(painted)
            if label:
                painted = (label.group(1) + _sgr(label.group(2), "label") + label.group(3)
                           + _paint_value(label.group(4)))
            speaker = _SPEAKER_RE.match(painted)
            if speaker:
                painted = painted.replace(
                    speaker.group(2), _sgr(speaker.group(2), "you" if "you" in speaker.group(2) else "bot"), 1)
            painted = _SOURCE_RE.sub(lambda m: _sgr(m.group(1), "cite"), painted)
        if not ascii_frame:
            # The ascii tier draws its frame with "+", "-" and "|", which also occur in a URL, a
            # model name and a card excerpt; tinting those would colour content.
            painted = _CHROME_RE.sub(lambda m: _sgr(m.group(0), "chrome"), painted)
        out[index] = painted
    return out


_ON_WORDS = ("on", "enabled", "configured", "present", "trained", "inert")
_OFF_WORDS = ("off", "none", "missing", "no model", "empty", "--")


def _paint_value(text: str) -> str:
    low = text.strip().lower()
    for word in _OFF_WORDS:
        if low.startswith(word):
            return _sgr(text, "off")
    for word in _ON_WORDS:
        if low.startswith(word):
            return _sgr(text, "on")
    return _sgr(text, "value")


def _paint_state(row: str) -> str:
    for word, tone in (("LEARNING ON", "on"), ("LEARNING OFF", "off")):
        if word in row:
            return row.replace(word, _sgr(word, tone), 1)
    return row


def color_enabled() -> bool:
    """``GN_DASH_COLOR=0`` turns the panels monochrome, the same opt-out the cockpit reads.

    ``NO_COLOR`` needs no check here: ``gn_tui.refusal`` refuses to open a full-screen view at all
    when it is set, so a running studio is one where colour is allowed.
    """
    return str(os.getenv("GN_DASH_COLOR") or "").strip() not in ("0", "false", "no", "off")


# --- the driver -----------------------------------------------------------------------------------
def size_refusal(size: Size) -> str:
    """One sentence for ``_err()`` when this terminal is below the floor, or ``""``."""
    if size.cols >= MIN_SIZE.cols and size.rows >= MIN_SIZE.rows:
        return ""
    return (f"the studio needs at least {MIN_SIZE.cols}x{MIN_SIZE.rows}; this terminal is "
            f"{size.cols}x{size.rows}. Resize it, or read the same numbers with `gn stats`, "
            f"`gn traces` and `gn settings`.")


def parse_studio_command(line: str) -> dict[str, Any]:
    """One line typed in the studio, resolved to an action. Pure, so it is testable.

    Anything that is not a slash command is a QUESTION — that is the whole point of a chat window,
    and a studio that made an operator type `/ask` before every sentence would be a worse one.
    """
    text = str(line or "").strip()
    if not text:
        return {"action": "none"}
    if not text.startswith("/"):
        return {"action": "ask", "text": text}
    name, _, rest = text[1:].partition(" ")
    name = name.lower()
    rest = rest.strip()
    if name in ("quit", "exit", "q"):
        return {"action": "quit"}
    if name in ("board", "wopr"):
        return {"action": "board"}
    if name in ("panels", "cockpit"):
        return {"action": "panels"}
    if name in ("refresh", "r"):
        return {"action": "refresh"}
    if name in ("clear", "cls"):
        return {"action": "clear"}
    if name in ("help", "?"):
        return {"action": "help"}
    if name == "ask":
        return {"action": "ask", "text": rest} if rest else {
            "action": "error", "message": "ask what? `/ask how do I prove an IDOR`"}
    if name in ("settings", "setup"):
        return {"action": "settings"}
    if name == "set":
        key, _, value = rest.partition(" ")
        if not key or not value.strip():
            return {"action": "error",
                    "message": "`/set <key> <value>`, e.g. `/set bot local`. /settings lists them."}
        return {"action": "set", "key": key, "value": value.strip()}
    if name == "unset":
        if not rest:
            return {"action": "error", "message": "`/unset <key>`. /settings lists them."}
        return {"action": "unset", "key": rest}
    return {"action": "error",
            "message": f"not a studio command: /{name}. {HINT}"}


def help_lines() -> list[str]:
    return [
        "Commands",
        "  <anything>      a question, answered from the offline pack with its source",
        "  /ask <question> the same thing, said explicitly",
        "  /settings       every setting, its value, and where that value came from",
        "  /set <key> <v>  change one and save it (same store `gn settings set` writes)",
        "  /unset <key>    back to its default",
        "  /refresh        re-read every store in the panels",
        "  /clear          clear the transcript",
        "  /board          the threat board;  /panels  the live panel cockpit",
        "  /quit           back to the shell",
        "",
        "The configured brain is shown, never called: opening a dashboard must not send a prompt",
        "off the machine or spend an API budget. The Workbench agent is where a brain is driven.",
    ]


class Studio:
    """The studio's loop: one key reader, one screen, one worker for answers.

    Repaints are event-driven, not a fixed animation: a key, an answer landing, a resize, or the
    clock's second changing. The board has arcs in flight and has to run at 20fps; this has a
    transcript and three tables, and a studio that repaints a still screen 20 times a second over
    ssh costs an operator their bandwidth for nothing.
    """

    def __init__(self, *, runtime_dir: str | Path, seed_dir: str | Path,
                 profile: Any = None, stream: Any = None, inp: Any = None,
                 size: Sequence[int] | None = None, keys: Any = None,
                 answerer: Callable[[str], tuple[str, str]] | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self._runtime = runtime_dir
        self._seed = seed_dir
        self._profile = profile
        self._out = sys.stdout if stream is None else stream
        self._in = sys.stdin if inp is None else inp
        self._size = size
        self._keys = keys
        self._answer = answerer or (lambda text: answer(text, seed_dir=self._seed,
                                                        runtime_dir=self._runtime))
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._state = StudioState()
        self._turns: list[tuple[str, str]] = []
        self._busy = ""
        self._message = ""
        self._pool: ThreadPoolExecutor | None = None
        self._future: Any = None
        self._line = gn_tui.CommandLine()
        self._scroll = 0
        self._ask: dict[str, Any] | None = None
        self._quit = threading.Event()
        self._repaint = True
        self.refresh()

    # --- state ---------------------------------------------------------------------------------
    def refresh(self) -> None:
        """Re-read every store. Called at open, on ``/refresh``, and after a verb that may change one."""
        panels = collect(self._runtime, self._seed, self._profile)
        learning_on = True
        if self._profile is not None:
            try:
                learning_on = bool(self._profile.get("learning"))
            except Exception:  # noqa: BLE001
                learning_on = True
        with self._lock:
            self._panels = panels
            self._learning_on = learning_on
            self._repaint = True

    def snapshot(self) -> StudioState:
        with self._lock:
            panels = getattr(self, "_panels", {})
            return StudioState(
                brain=panels.get("brain", ()), learning=panels.get("learning", ()),
                agents=panels.get("agents", ()), chat=tuple(self._turns[-MAX_TURNS:]),
                status="", busy=self._busy, message=self._message,
                input_text=self._line.text, input_caret=self._line.cursor,
                chat_scroll=self._scroll, learning_on=getattr(self, "_learning_on", True),
            )

    def say(self, who: str, text: str) -> None:
        with self._lock:
            self._turns.append((who, str(text)))
            del self._turns[: max(0, len(self._turns) - MAX_TURNS)]
            self._scroll = 0
            self._repaint = True

    def note(self, text: str) -> None:
        with self._lock:
            self._message = str(text)
            self._repaint = True

    # --- keys ----------------------------------------------------------------------------------
    def handle_key(self, key: str) -> None:
        """One key. Total: an unhandled key is ignored, never echoed as a control character."""
        try:
            if key == "CTRL-C":
                self._quit.set()
                return
            if key in ("PGUP", "PGDN"):
                with self._lock:
                    self._scroll = max(0, self._scroll + (5 if key == "PGUP" else -5))
                    self._repaint = True
                return
            if key in ("TAB", "CTRL-L"):
                with self._lock:
                    self._repaint = True
                return
            submitted = self._line.feed(key)
            with self._lock:
                self._repaint = True
            if submitted is not None:
                self.submit(submitted)
        except Exception as exc:  # noqa: BLE001 - a key must never take the studio down
            self.note(f"that key raised {type(exc).__name__}")

    def submit(self, line: str) -> None:
        parsed = parse_studio_command(line)
        action = str(parsed.get("action") or "")
        if action == "none":
            return
        if action == "quit":
            self._quit.set()
            return
        if action in ("board", "panels"):
            self._ask = {"action": action}
            self._quit.set()
            return
        if action == "refresh":
            self.refresh()
            self.note("stores re-read")
            return
        if action == "clear":
            with self._lock:
                self._turns.clear()
                self._scroll = 0
                self._repaint = True
            return
        if action == "help":
            # ONE turn, not one per line: the "gn >" prefix marks who is speaking, and repeating it
            # down the side of a help block makes the block look like nine separate answers.
            self.say("gn", "\n".join(help_lines()))
            return
        if action == "settings":
            self._show_settings()
            return
        if action in ("set", "unset"):
            self._change_setting(action, str(parsed.get("key") or ""), parsed.get("value"))
            return
        if action == "error":
            self.note(str(parsed.get("message") or ""))
            return
        if action == "ask":
            self._start_answer(str(parsed.get("text") or ""))

    # --- the setup half ------------------------------------------------------------------------
    def _show_settings(self) -> None:
        """The whole settings table, in the chat. Same renderer `gn settings` prints."""
        import gn_profile

        profile = self._reload_profile()
        self.say("gn", "\n".join(gn_profile.settings_lines(profile)))

    def _change_setting(self, action: str, key: str, value: Any) -> None:
        """``/set`` and ``/unset``, written to the same profile ``gn settings set`` writes.

        The studio is where an operator LOOKS at their agent's setup, so it is where they will try
        to change it. It writes through ``gn_profile`` rather than touching the file, so the key
        whitelist, the type checks and the refusal of anything that smells like authorization are
        the same ones the CLI enforces — there is no second door into the profile.
        """
        import gn_profile

        profile = self._reload_profile()
        if action == "set":
            profile, error = gn_profile.set_value(profile, key, value)
        else:
            profile, error = gn_profile.unset(profile, key)
        if error:
            self.note(error)
            return
        profile, error = gn_profile.save(self._runtime, profile)
        if error:
            self.note(error)
            return
        self._profile = profile
        item = gn_profile.setting(key)
        name = item.key if item else key
        self.note(f"{name} = {gn_profile.show(profile.get(name))}  (saved)")
        # The panels read the profile, so the change has to show up in them immediately — a studio
        # that reports a saved setting while still displaying the old one is worse than no report.
        self.refresh()

    def _reload_profile(self) -> Any:
        """The profile as it is ON DISK, not as it was when the studio opened.

        `gn settings set` in another shell, or the app's own settings pane, may have written since.
        """
        import gn_profile

        profile = gn_profile.load(self._runtime)
        self._profile = profile
        return profile

    def _start_answer(self, question: str) -> None:
        if self._busy:
            self.note(f"still answering: {self._busy}")
            return
        self.say("you", question)
        self._busy = "reading the pack"
        if self._pool is None:
            # No worker (a test driving submit() directly): answer inline, same code path.
            self._finish_answer(question, self._answer(question))
            return
        self._future = self._pool.submit(self._answer, question)
        self._future.add_done_callback(lambda fut, q=question: self._on_answer(q, fut))

    def _on_answer(self, question: str, future: Any) -> None:
        try:
            result = future.result()
        except Exception as exc:  # noqa: BLE001 - an answerer that raised is "nothing matched"
            result = ("", f"{type(exc).__name__}")
        self._finish_answer(question, result)

    def _finish_answer(self, _question: str, result: tuple[str, str]) -> None:
        body, how = (result if isinstance(result, tuple) else ("", ""))
        self._busy = ""
        if not body:
            self.say("gn", NO_MATCH)
            return
        self.say("gn", body)
        if how:
            # Not "Source:" — a class excerpt already ends with its own Source line, and two of
            # them under one answer reads as two citations for it.
            self.say("cite", f"answered by: {how}")

    # --- loop ----------------------------------------------------------------------------------
    def run(self) -> dict[str, Any] | None:
        """Draw until the operator leaves. Returns their ask (``/board``, ``/panels``) or None.

        Acquisition order IS the teardown contract, the same one ``gn_dash.Dashboard.run``
        documents: console modes, then the keyboard, then the screen — unwound in reverse.
        """
        with ExitStack() as stack:
            console = stack.enter_context(gn_tui.WinConsole())
            if not console.vt_enabled:
                self._write_plain("gn: this console will not enable ANSI (VT) processing, and the "
                                  "studio cannot draw without it.\n")
                return None
            reader = self._keys or stack.enter_context(gn_tui.KeyReader(self._in))
            screen = stack.enter_context(gn_tui.Screen(self._out, size=self._size))
            self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="gn-studio")
            stack.callback(self._pool.shutdown, wait=False)
            stack.callback(self._quit.set)
            self._loop(screen, reader)
        return self._ask

    def _loop(self, screen: Any, reader: Any) -> None:
        tier = gn_tui.tier(self._out)
        encoding = str(getattr(self._out, "encoding", None) or "ascii")
        last_second = ""
        while not self._quit.is_set():
            key = reader.read(0.06)
            if key:
                self.handle_key(key)
            resized = screen.take_resize()
            now = _clock()
            with self._lock:
                due = self._repaint or resized or now != last_second
                self._repaint = False
            if not due:
                continue
            last_second = now
            size = screen.size()
            state = self.snapshot()
            screen.frame(colorize(render(state, size, tier, encoding), tier,
                                  enabled=color_enabled()), cursor(state, size))

    def _write_plain(self, text: str) -> None:
        try:
            self._out.write(text)
            self._out.flush()
        except Exception:  # noqa: BLE001
            pass


def run_studio(*, runtime_dir: str | Path, seed_dir: str | Path, profile: Any = None,
               stream: Any = None, inp: Any = None, **kwargs: Any) -> dict[str, Any] | None:
    """Open the studio. Returns the operator's ask (``{"action": "board"|"panels"}``) or None."""
    return Studio(runtime_dir=runtime_dir, seed_dir=seed_dir, profile=profile,
                  stream=stream, inp=inp, **kwargs).run()
