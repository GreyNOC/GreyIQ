"""The AGENT STUDIO: your bots — make them, teach them, train them, pick one, talk to it.

`gn studio` (also `/studio` from the threat board, and `gn dash --studio`) is the third dash view.
The board answers "what is happening to which host"; the panel cockpit answers "what is this run
doing"; this one answers the question neither can: **what are my bots, and which one is working for
me?** Same amber chrome as the board, because it is the same cockpit.

FULL CONTROL OVER THE BOTS, IN ONE WORD EACH
--------------------------------------------
Every bot verb is a slash command, short enough to type without thinking about it, and each one is
the same operation ``gn bot …`` performs from the shell — one store, one set of rules, two doors::

    /bots                   every bot, the live one marked
    /use <name>             make one live: it answers chat AND plans the hunt
    /new <name> [provider] [model]
    /clone <name> [as <new>]        /bot rm <name>        /bot reset <name>
    /model <model>          point the live bot at a model      /persona <text>
    /bot set <name> <field> <value>                 /bot show <name>
    /teach <lesson>         a standing instruction it carries into every chat
    /train [<name>]         run the trainer it actually has
    /hf <ref>               plug in a Hugging Face bot

A name can be a prefix (``/use cl``), ``<field> <value>`` without a name means the live bot, and Tab
completes the command and the bot names. The point is that changing which bot hunts for you costs
one word, because an operator who has to remember a flag will keep using whichever bot they set up
first.

WHAT IT SHOWS, and where every number comes from
------------------------------------------------
Nothing here is computed by this module. Each row is a value some other local store already keeps,
read through that store's own reader and labelled with it:

  * **BOTS** — the bot registry (``gn_bots``, ``runtime/bots.json``): every bot, what it is, whether
    it could answer right now, and which one is live. A cloned Hugging Face agent is on the row as
    ``inert``, because a cloned agent that LOOKS runnable is the one thing an operator could misread
    here; the raw clone store (``hf_agent_clone``) is counted on the last row.
  * **BRAIN** — the live bot resolved against ``runtime/solin_runtime_config.json``: the provider and
    model the HUNT will use, whether a key is present (never the key), whether agent commands and
    skills are enabled, whether internet access is on.
  * **LEARNING** — ``hunt_trace.trace_stats`` (the hunt corpus), ``learning.program_summary``
    (submitted / rewarded / bounty), ``negative_knowledge`` (what it has learned not to retry),
    ``hunt_train`` (the offline ranker) and ``coder_train.corpus_status`` (the tiny model's corpus
    and whether a trained model is actually present).

A store that is missing, empty or unreadable renders as ``--`` with the reason, never as a zero: a
fabricated zero is indistinguishable from "nothing has happened yet", and this program's one house
rule is that a number has to be reproducible from evidence.

THE CHAT: WHO ANSWERS, AND WHAT THAT COSTS
------------------------------------------
**The live bot answers.** Which one that is decides where the words come from, and the line under
every answer says which it was:

  * ``tinygpt``, ``offline``, and any inert clone answer from :mod:`solin_domain` — the torch-free
    curated pack, through the same three branches ``greyiq_api._domain_brain_reply`` uses: the
    vuln-class table, the tool catalog, then a VERBATIM excerpt from a bundled card with its source
    path. ``solin_domain`` performs no generation of any kind, so on this path a chat window on a
    security tool cannot invent a security claim. When nothing matches, it says nothing matched.
    (TinyGPT's own checkpoint is not driven from here: ``solin_core`` imports torch at module scope
    and this view has to stay on the torch-free CLI path. The app and the Workbench run it.)
    ``off`` is the one bot that answers nothing at all, and says so when asked.
  * ``local``, ``anthropic`` and ``openai`` bots are CALLED, through ``coder.generate``, with the
    bot's persona, style and lessons as the system prompt. A model's answer is labelled as a model's
    answer, naming the bot, the provider and the model, because the difference between a quoted card
    and a generated sentence is the difference this program's house rule turns on.

**Opening the studio still sends nothing.** The earlier rule — a configured brain is displayed and
never called — was there so that looking at statistics could not spend an operator's API budget or
stall a repaint on a network round trip. That reasoning is about the REPAINT, and it still holds:
nothing on the collect/render path calls a model, every answer runs in the worker thread, and the
prompt leaves only when the operator typed a question. What changed is that typing one is now an
instruction, the same way ``gn learn`` is an instruction and the auto-trainer is not. The header
names the live bot and marks it ``->net`` when asking it sends the prompt off this machine, and the
first off-machine question in a session says so in the transcript before the answer comes back.
``/pack <q>`` asks the offline pack regardless of which bot is live.

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
#: chrome), so the one line that lists the commands is never the line that gets cut. The bot verbs
#: come first because they are what this view is for; ``/help`` has the rest.
HINT = "/bots  /use <b>  /new <b>  /teach <x>  /hf <ref>  /help  /quit"
#: What the chat says when the pack has nothing. It does NOT generate an answer instead.
NO_MATCH = ("nothing in the offline pack matched that. Try a class (\"what is ssrf\"), ask for "
            "tools (\"tools for idor\"), or /help.")
#: How many chat turns are kept. A studio is not a transcript archive; the ledger and the traces
#: are where durable things live.
MAX_TURNS = 60
_MAX_FIELD = 160
#: The longest answer a model bot may put in the transcript. Generous — a real explanation runs to
#: paragraphs — but bounded, because the transcript is a fixed-size ring in a terminal frame.
_MAX_ANSWER = 8000

#: What the studio tells a model bot it is, under the operator's own persona. Deliberately short and
#: about EVIDENCE: this window sits on a tool whose house rule is that a finding has to be
#: reproducible, and the one failure mode of putting a live model in it is a confident sentence
#: nobody can trace. The persona goes above this, so an operator's voice shapes the answer and this
#: shapes what counts as one.
STUDIO_SYSTEM_PROMPT = (
    "You are answering inside GreyNOC's agent studio, a terminal view of an authorized "
    "security-testing toolkit. Be direct and concrete; the operator is an experienced security "
    "engineer. Say plainly when you are not sure, and never present a guess as a finding: in this "
    "program a claim that cannot be reproduced from evidence is not a result. Do not invent "
    "command output, CVE text, scan results or bounty outcomes. Keep answers to what was asked."
)

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
    bots: tuple[Row, ...] = ()
    brain: tuple[Row, ...] = ()
    learning: tuple[Row, ...] = ()
    #: ``(who, text)`` where who is "you", "gn" or "cite".
    chat: tuple[tuple[str, str], ...] = ()
    status: str = ""
    busy: str = ""
    message: str = ""
    input_text: str = ""
    input_caret: int = 0
    chat_scroll: int = 0
    learning_on: bool = True
    #: The live bot's id, and whether asking it sends the prompt off this machine. Both are in the
    #: header: an operator must never type into a hosted brain thinking they are talking to the
    #: local one, and the header is the only part of the frame that is always on screen.
    bot: str = ""
    off_machine: bool = False


def _plain(text: Any) -> str:
    """Every control character (ESC included) as a space — the same guard ``gn_dash._plain`` is.

    Card text, a model name out of a config file and a store's error string all reach a row, and
    none of them is this module's to trust with the operator's cursor.
    """
    return str(text).translate(_CTRL_TABLE)


#: Every control character as a space: C0 (0-31), DEL, and **C1 (128-159)**. C1 is the one that
#: was missing, and the chat calling a live model is what made it reachable: U+009B is ECMA-48's
#: CSI and U+009D opens an OSC string, so on a UTF-8 terminal a model's answer containing
#: "\u009b2J" could clear or repaint the operator's screen — exactly what ``_plain`` exists to
#: prevent, and invisible to a guard that only looks for ESC. They are not whitespace, so
#: ``str.split()`` does not remove them either.
_CTRL_TABLE = {code: " " for code in range(32)}
_CTRL_TABLE[127] = " "
_CTRL_TABLE.update({code: " " for code in range(128, 160)})
#: The same set as characters, for ``_field_multiline``, which has to keep ``\n`` and so cannot use
#: ``translate``.
_CTRL_TABLE_KEYS = frozenset(chr(code) for code in _CTRL_TABLE)


def _cut(text: Any, limit: int) -> str:
    if limit <= 0:
        return ""
    return _plain(text)[:limit]


def _field(value: Any) -> str:
    text = " ".join(_plain(value).split())
    return text[:_MAX_FIELD]


def _field_multiline(value: Any) -> str:
    """A model's answer, control characters out but its PARAGRAPHS kept.

    ``_field`` collapses whitespace, which is right for a row in a panel and wrong for an answer —
    ``chat_lines`` wraps per paragraph, so flattening one here would turn an explanation into a
    wall. Newlines survive; every other control character becomes a space, exactly as elsewhere.

    A longer answer is cut, and the cut SAYS SO. An answer that stops mid-word reads as a complete
    one, which in a window whose house rule is that a claim must be traceable is the wrong kind of
    quiet — ``_elide`` and ``gn_bots._clip`` mark their cuts for the same reason.
    """
    text = str(value if value is not None else "")
    kept = "".join("\n" if ch == "\n" else (" " if ch in _CTRL_TABLE_KEYS else ch) for ch in text)
    lines = [" ".join(line.split()) for line in kept.split("\n")]
    body = "\n".join(lines).strip()
    if len(body) <= _MAX_ANSWER:
        return body
    return (body[:_MAX_ANSWER].rstrip()
            + f"\n\n[cut here: the answer ran past {_MAX_ANSWER} characters]")


def _common_prefix(names: Sequence[str]) -> str:
    """The longest string every name starts with. Pure; used by Tab completion."""
    if not names:
        return ""
    shortest = min(names, key=len)
    for index, char in enumerate(shortest):
        if any(name[index] != char for name in names):
            return shortest[:index]
    return shortest


def _field_multiline_untrimmed(value: Any) -> str:
    """The same cleaning as :func:`_field_multiline` with a far higher ceiling, for the HISTORY.

    What the model said is what it should be handed back; what fitted in the frame is a display
    concern. Still bounded — a conversation kept in memory cannot grow without limit.
    """
    text = str(value if value is not None else "")
    kept = "".join("\n" if ch == "\n" else (" " if ch in _CTRL_TABLE_KEYS else ch) for ch in text)
    lines = [" ".join(line.split()) for line in kept.split("\n")]
    return "\n".join(lines).strip()[: _MAX_ANSWER * 8]


def _result(future: Any) -> tuple[str, str]:
    """One worker future's result as ``(body, how)``. A job that raised is a sentence, never a trace."""
    try:
        value = future.result()
    except Exception as exc:  # noqa: BLE001
        return (f"that did not finish: {type(exc).__name__}", "")
    return value if isinstance(value, tuple) else (str(value), "")


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
#: How many bots fit in the BOTS panel before it says "+N more". The panel is a picker, not the
#: listing — ``/bots`` prints the whole store into the chat, where it can scroll.
_MAX_BOT_ROWS = 7


def bot_rows(runtime_dir: str | Path, profile: Any = None) -> tuple[Row, ...]:
    """Every bot, the live one marked, and what each one could do right now.

    The live bot is FIRST, whatever its position in the store: the one row an operator came here to
    read should not move down the panel as bots are added. A store that will not load renders as
    ``--`` with the reason, like every other row in this file.
    """
    registry, error = _call(lambda: _registry(runtime_dir))
    if error or registry is None:
        return (Row("store", f"-- ({error or 'unreadable'})", "off"),)
    live, note = _live_bot(runtime_dir, profile)
    live_id = live.id if live is not None else ""
    bots = list(registry.bots)
    bots.sort(key=lambda bot: (bot.id != live_id,))
    rows: list[Row] = []
    for bot in bots[:_MAX_BOT_ROWS]:
        mark = "*" if bot.id == live_id else " "
        ready = _readiness(runtime_dir, bot)
        # ``short`` rather than ``describe``: the panel's value column is 18 cells on a 100-column
        # terminal, so the clause that explains a provider would be elided away anyway — and an
        # elided explanation is worse than none. ``/bots`` and ``/bot show`` carry the full text.
        value = bot.short() + (f"  [{ready}]" if ready and ready != "ready" else "")
        tone = "on" if bot.id == live_id and ready == "ready" else (
            "off" if ready in ("needs a key", "needs a model", "off") else "dim")
        rows.append(Row(f"{mark}{bot.id}", value, tone))
    if len(bots) > _MAX_BOT_ROWS:
        rows.append(Row("", f"... +{len(bots) - _MAX_BOT_ROWS} more — /bots", "dim"))
    if note:
        rows.append(Row("note", note, "off"))
    if registry.error:
        rows.append(Row("store", registry.error, "off"))
    rows.append(clone_row(runtime_dir))
    return tuple(rows)


def clone_row(runtime_dir: str | Path) -> Row:
    """The local Hugging Face agent store, as one row. ALWAYS present, even when empty.

    Two reasons it is not dropped when the store is empty. A clone made by ``gn agent clone``
    rather than ``gn bot hf`` is not a registry entry, so without this row those clones would be
    invisible in the studio. And a row that vanishes is a store nobody can see was READ — the
    studio's whole claim is that every panel is a real reader, and ``test_gn_cli_stdlib_boot``
    checks this one answers on a bare Python.
    """
    clones, error = _call(lambda: _agent_store(runtime_dir))
    if error:
        return Row("clones", f"-- ({error})", "off")
    if not clones:
        return Row("clones", "none — `gn bot hf <ref>` or `gn agent clone <ref>` adds one", "dim")
    return Row("clones", f"{len(clones)} cloned · inert (never executed)", "dim")


def brain_rows(profile: Any, runtime_dir: str | Path) -> tuple[Row, ...]:
    """What answers, and with what: the live bot resolved against the app's own runtime config.

    The ``bot`` row is the bot's own record, not the raw setting, so a profile naming a bot that is
    not in the store says so here rather than presenting a name nothing will honour. The rows under
    it are what the HUNT will use — ``_load_coder_config`` builds the same overlay from the same two
    sources, which is what makes this panel a reading of the hunt's posture rather than a hint.
    """
    rows: list[Row] = []
    live, note = _live_bot(runtime_dir, profile)
    if live is None:
        bot = str(getattr(profile, "get", lambda _k: "")("bot") or "tinygpt")
        rows.append(Row("bot", bot, "on" if bot != "off" else "off"))
        if note:
            rows.append(Row("", note, "off"))
    else:
        # A built-in's id IS its provider, so naming both reads as a stutter ("tinygpt · tinygpt").
        label = live.describe() if live.id == live.provider else f"{live.id} · {live.describe()}"
        rows.append(Row("bot", label, "off" if live.provider == "off" or note else "on"))
        if note:
            rows.append(Row("", note, "off"))
        if _off_machine(runtime_dir, live):
            rows.append(Row("sends", "off this machine when you ask it something", "off"))
        ready = _readiness(runtime_dir, live)
        if ready and ready != "ready":
            rows.append(Row("ready", ready, "off"))
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
        agent = coder.get("agent") if isinstance(coder.get("agent"), dict) else {}
        if agent:
            rows.append(Row("agent", f"skills {_onoff(agent.get('skills_enabled'))} · "
                                     f"commands {_onoff(agent.get('allow_commands'))}",
                            "on" if agent.get("skills_enabled") else "dim"))
    else:
        rows.append(Row("brain", "no runtime config — deterministic", "dim"))
    # The key row is about the LIVE BOT and is read through gn_bots.key_state, which reads
    # runtime/secrets.json - the perms-restricted store the key actually lives in, and the one
    # _load_coder_config merges from. Reading it out of the runtime config instead said "none" on
    # a working hosted brain, on the same frame where BOTS showed that bot ready: two panels
    # disagreeing about the same fact, in the one that claims to be a reading of the hunt.
    # Presence only. A dashboard that can print a key is a dashboard that can leak one.
    if live is not None:
        state = _key_state(runtime_dir, live)
        if state:
            rows.append(Row("key", state, "on" if state == "configured" else
                            ("dim" if state == "not needed" else "off")))
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


def collect(runtime_dir: str | Path, seed_dir: str | Path | None = None,
            profile: Any = None) -> dict[str, tuple[Row, ...]]:
    """Every panel, read fresh. Total — a store that will not answer renders as ``--``.

    Nothing on this path calls a model. It is the repaint path, and the rule that opening a
    dashboard may not spend an operator's budget or stall a frame on a network round trip is a rule
    about exactly this function (see the module docstring).
    """
    return {
        "bots": bot_rows(runtime_dir, profile),
        "brain": brain_rows(profile, runtime_dir),
        "learning": learning_rows(runtime_dir, seed_dir),
    }


def _registry(runtime_dir: str | Path) -> Any:
    import gn_bots

    return gn_bots.load(runtime_dir)


def _live_bot(runtime_dir: str | Path, profile: Any = None) -> tuple[Any, str]:
    """``(the live bot, a note)`` — total, so a panel never has to guard the import itself.

    ``(None, why)`` only when the registry module itself will not load, which on a shipped build
    means something is wrong with the install rather than with the operator's store.
    """
    try:
        import gn_bots

        return gn_bots.active(runtime_dir, profile)
    except Exception as exc:  # noqa: BLE001 - a row, not a crash
        return (None, f"the bot store would not load ({type(exc).__name__})")


def _readiness(runtime_dir: str | Path, bot: Any) -> str:
    try:
        import gn_bots

        return gn_bots.readiness(runtime_dir, bot)
    except Exception:  # noqa: BLE001
        return ""


def _off_machine(runtime_dir: str | Path, bot: Any) -> bool:
    """Whether asking this bot leaves the machine, with the endpoint RESOLVED.

    Never ``bot.off_machine`` directly: that reads the bot's own fields, and a ``local`` bot with
    no endpoint of its own inherits the app's — which may be an Ollama on another host. Every
    surface in this view (the header marker, the BRAIN row, the once-per-session notice) goes
    through here so they cannot disagree with where the request actually went.
    """
    if bot is None:
        return False
    try:
        import gn_bots

        return gn_bots.sends_off_machine(runtime_dir, bot)
    except Exception:  # noqa: BLE001 - a marker is not worth a crash; the bot's own fields answer
        return bool(getattr(bot, "off_machine", False))


def _key_state(runtime_dir: str | Path, bot: Any) -> str:
    try:
        import gn_bots

        return gn_bots.key_state(runtime_dir, bot)
    except Exception:  # noqa: BLE001
        return ""


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
    """The transcript as ``(who, line)`` rows, wrapped to ``width``. Pure.

    The turn is split into lines BEFORE ``_plain`` runs, because ``_plain``'s table maps every
    control character to a space — newline included — so cleaning first and splitting after found
    nothing to split on and flowed every multi-line turn into one paragraph. That silently ruined
    the blocks this view puts in the transcript on purpose: the ``/help`` text, the settings table
    and the bot listing are columns, and a column that has been reflowed is not a table. Splitting
    first keeps the structure; each line still goes through ``_plain``, so an ESC inside card text
    or a model's answer is as dead as it ever was.
    """
    out: list[tuple[str, str]] = []
    if width <= 4:
        return out
    for who, text in turns:
        prefix = "you> " if who == "you" else ("gn > " if who == "gn" else "     ")
        # ONCE PER TURN, not once per line. The prefix marks who is speaking, so repeating it down
        # the side of a help block, a settings table or a bot listing makes one answer look like
        # nine — which is what `submit` has always said and what the flattening bug above hid.
        first = True
        for paragraph in str(text).split("\n"):
            paragraph = _plain(paragraph)
            if not paragraph.strip():
                out.append((who, ""))
                continue
            # A folded line hangs under its own indentation, not under the margin: these turns are
            # two-column tables ("  /use <bot>      make it live"), and a continuation that starts
            # back at column 0 reads as a new row of the table rather than as the rest of one.
            lead = len(paragraph) - len(paragraph.lstrip())
            wrapped = textwrap.wrap(paragraph, max(8, width - len(prefix)),
                                    subsequent_indent=" " * min(lead + 2, 12),
                                    break_long_words=True, break_on_hyphens=False) or [""]
            for line in wrapped:
                out.append((who, (prefix if first else " " * len(prefix)) + line))
                first = False
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
    # Up to 14 columns, and never more than half the panel: a bot id is a label now ("*red-team"),
    # and the old cap of 11 cut the names an operator chose themselves. Still bounded, because the
    # value has to stay readable — the full table is one `/bots` away.
    label_width = min(14, max(2, width // 2), max((len(r.label) for r in rows), default=0))
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
    """The title, the live bot, the learning switch and the clock.

    The bot is in the header because it is the one fact that changes what typing does: ``->net``
    marks a bot that sends the prompt off this machine, and an operator must be able to see that
    without scrolling a panel. It is dropped on a narrow terminal before the learning state is,
    because the panels repeat the bot and nothing repeats the learning switch.
    """
    state_part = "LEARNING ON" if state.learning_on else "LEARNING OFF"
    bot = _plain(state.bot).strip()
    marker = "->net" if state.off_machine else ""
    bot_part = f" bot {bot}{marker} {box[4]}" if bot else ""
    left = f"{box[0]}{box[4]} {TITLE} "
    # The MARKER outlives the bot's name as the terminal narrows. Dropping both together took the
    # one always-on-screen warning off the frame at every width below 80 — including the studio's
    # own 72-column floor, where MIN_SIZE says the view is supported.
    for right in (f"{bot_part} {state_part} {box[4]} {_clock()} {box[1]}",
                  f" {marker} {state_part} {box[4]} {_clock()} {box[1]}" if marker else "",
                  f" {state_part} {box[4]} {_clock()} {box[1]}",
                  f" {marker} {_clock()} {box[1]}" if marker else "",
                  f" {_clock()} {box[1]}"):
        if right and len(left) + len(right) <= size.cols:
            break
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
    """BOTS, BRAIN and LEARNING stacked, each taking the room its rows need.

    BOTS is first because it is both the answer to "which bot is working for me" and the picker the
    slash commands act on, and because the live row is the one an operator reads on every visit.
    """
    sections = (("BOTS", state.bots), ("BRAIN", state.brain), ("LEARNING", state.learning))
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
        # The empty state is where an operator learns what this view does, so it names the live bot
        # and the two commands that change it, not just "type something".
        bot = _plain(state.bot).strip() or "the live bot"
        # These are NOT wrapped — they go straight into the frame, so each one has to fit the
        # narrowest chat pane (31 columns at the studio's floor) or it is cut mid-sentence.
        lines = [("gn", f" ask {bot} a question,"),
                 ("gn", " or /help for the commands"),
                 ("gn", ""),
                 ("gn", " /bots       every bot, live one *"),
                 ("gn", " /use <bot>  make one live: it"),
                 ("gn", "             answers here and"),
                 ("gn", "             plans the hunt"),
                 ("gn", " /new <bot>  /teach <lesson>"),
                 ("gn", " /hf <ref>   a Hugging Face bot"),
                 ("gn", ""),
                 ("gn", " a local bot's answers are"),
                 ("gn", " quoted from the offline pack"),
                 ("gn", " with a source line; a model"),
                 ("gn", " bot is called, and its answer"),
                 ("gn", " is labelled as a model's")]
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
#: A row label, which is now also a bot id in a marker column: ``*tinygpt`` for the live bot and
#: `` tinygpt`` for the rest, so the ids line up whether or not colour is on. The marker is part of
#: the label, painted with it rather than read as a value, which is why this allows the second
#: leading space and why the id may be 14 wide (``_rows_block``'s cap).
_LABEL_RE = re.compile(r"^([│|])( {1,2}\*?[a-z][a-z0-9._-]{0,13})( +)(\S.*)$")
_SECTION_RE = re.compile(r"^([│|]) (BOTS|BRAIN|LEARNING|AGENTS|CHAT) ")
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
                # A label carrying the live marker is painted as "on", so the one row an operator
                # came here to find is the one that stands out. The marker still reads without
                # colour (GN_DASH_COLOR=0, or a pipe), which is why it is a character and not a hue.
                tone = "on" if label.group(2).lstrip().startswith("*") else "label"
                painted = (label.group(1) + _sgr(label.group(2), tone) + label.group(3)
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


#: ``/bot <verb>``, and the one-word aliases that make the common ones a single command. The values
#: are the verb the handler switches on, so ``/use x``, ``/bot use x`` and ``/switch x`` are one code
#: path. Claude Code's own habit: the thing you do twenty times a day gets its own slash.
_BOT_VERBS: dict[str, str] = {
    "ls": "ls", "list": "ls", "bots": "ls",
    "show": "show", "info": "show",
    "use": "use", "switch": "use", "pick": "use",
    "new": "new", "add": "new", "create": "new",
    "rm": "rm", "remove": "rm", "delete": "rm", "del": "rm",
    "clone": "clone", "copy": "clone",
    "set": "set", "edit": "set",
    "teach": "teach", "learn": "teach",
    "forget": "forget",
    "train": "train",
    "reset": "reset",
    "hf": "hf", "huggingface": "hf",
    "fields": "fields",
}

#: Top-level slashes that mean ``/bot <verb>``. ``/model`` and ``/persona`` are field setters on the
#: LIVE bot, which is what they mean in every other CLI that has them.
_BOT_ALIASES: dict[str, tuple[str, tuple[str, ...]]] = {
    "bots": ("ls", ()),
    "use": ("use", ()),
    "switch": ("use", ()),
    "new": ("new", ()),
    "clone": ("clone", ()),
    "teach": ("teach", ()),
    "train": ("train", ()),
    "hf": ("hf", ()),
    "model": ("set", ("model",)),
    "persona": ("set", ("persona",)),
    "style": ("set", ("style",)),
}

#: The aliases whose first argument is a VALUE, never a bot name, so the live bot is the target and
#: nothing may be read out of the arguments. ``/teach local file reads are out of scope`` taught
#: the bot called ``local`` a lesson with its first word missing.
#:
#: ``/clone`` and ``/train`` are deliberately NOT here: a bot name is exactly what their first
#: argument is, and forcing the live bot made ``/clone skynet`` copy the live bot under the name
#: ``skynet`` instead of refusing an unknown one.
_LIVE_ALIASES = frozenset({"teach", "model", "persona", "style"})


def _args(tail: str) -> list[str]:
    """One argument list from the rest of a command line, quotes respected.

    ``shlex`` rather than ``split()`` because a persona and a lesson are sentences:
    ``/teach "always name the endpoint you probed"`` has to arrive as one argument. A line with an
    unbalanced quote is split on whitespace instead of refused — an operator who typed one quote is
    mid-sentence, not making a mistake worth a refusal.
    """
    text = str(tail or "").strip()
    if not text:
        return []
    import shlex

    try:
        # Empty tokens are KEPT: shlex only produces one from an explicit `""`, which is how an
        # operator says "clear this field" (`/bot set scout model ""`). Filtering them made that
        # impossible — the quotes vanished and the command read as a bare field name.
        return shlex.split(text)
    except ValueError:
        return text.split()


def parse_studio_command(line: str) -> dict[str, Any]:
    """One line typed in the studio, resolved to an action. Pure, so it is testable.

    Anything that is not a slash command is a QUESTION for the live bot — that is the whole point of
    a chat window, and a studio that made an operator type `/ask` before every sentence would be a
    worse one.

    The bot verbs come back as ``{"action": "bot", "verb": ..., "args": [...]}`` with the arguments
    UNRESOLVED. Deliberate: whether ``/bot set model x`` means "the live bot's model" or "the bot
    called model" is a question about the store, and this function does not read stores — the
    handler does, which keeps the parser a table of shapes and keeps the shapes a unit test.
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
    if name == "bot":
        verb, _, tail = rest.partition(" ")
        verb = verb.strip().lower()
        if not verb:
            return {"action": "bot", "verb": "ls", "args": []}
        resolved = _BOT_VERBS.get(verb)
        if resolved is None:
            return {"action": "error",
                    "message": f"not a bot verb: {verb}. "
                               f"/bot ls use new rm clone set teach forget train reset hf fields"}
        return {"action": "bot", "verb": resolved, "args": _args(tail)}
    if name in _BOT_ALIASES:
        verb, prefix = _BOT_ALIASES[name]
        # ``live`` means "the live bot, and do not read a name out of the arguments" — see
        # _LIVE_ALIASES. `/bot teach <bot> <lesson>` is how a bot is named instead.
        return {"action": "bot", "verb": verb, "args": [*prefix, *_args(rest)],
                "live": name in _LIVE_ALIASES}
    if name == "pack":
        return ({"action": "ask", "text": rest, "pack": True} if rest else
                {"action": "error", "message": "`/pack <question>` asks the offline pack directly."})
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
            "message": f"not a studio command: /{name}. /help, or: "
                       + " ".join("/" + command for command in commands())}


#: Every slash the studio answers to, for Tab completion and for the "not a command" message.
#: Derived from the tables above so a verb added there is completable for free.
def commands() -> tuple[str, ...]:
    fixed = ("ask", "pack", "help", "settings", "set", "unset", "refresh", "clear",
             "board", "panels", "quit", "bot")
    return tuple(sorted(set(fixed) | set(_BOT_ALIASES)))


def help_lines() -> list[str]:
    """The commands, two columns, every line inside the narrowest chat pane the studio draws.

    Wrapped text in a help block reads as a paragraph that lost its shape, and this one is a table:
    the lines are kept under :data:`_HELP_WIDTH` so the chat column never has to fold one. A test
    pins that, because a help screen is exactly the thing nobody re-reads after editing it.
    """
    return [
        "YOUR BOTS",
        "  /bots              every bot, live one marked *",
        "  /use <bot>         make it live: answers here",
        "                     AND plans the hunt",
        "  /new <bot> [provider] [model]",
        "  /clone <bot> [as <new>]   a copy, lessons too",
        "  /bot rm <bot> -y   delete it, lessons too",
        "  /bot reset <bot>   a built-in back to shipped",
        "  /bot show [<bot>]  all of it, lessons included",
        "  /model <model>     point the live bot at a model",
        "  /persona <text>    who it is;  /style <text>",
        "  /bot set <bot> <field> <value>",
        "  /bot fields        what can be set on a bot",
        "  /teach <lesson>    a standing instruction it",
        "                     carries into every chat",
        "  /bot forget <n|all>   drop a lesson",
        "  /train [<bot>]     run the trainer it has",
        "  /hf <ref>          plug in a Hugging Face bot",
        "",
        "THE REST",
        "  <anything>         a question for the live bot",
        "  /pack <question>   ask the offline pack instead",
        "  /settings          every setting and its source",
        "  /set <key> <v>     change one and save it",
        "  /unset <key>       back to its default",
        "  /refresh           re-read every store",
        "  /clear             clear the transcript",
        "  /board  /panels    the other two views",
        "  /quit              back to the shell",
        "",
        "WHO ANSWERS",
        "  tinygpt, offline and cloned agents answer from",
        "  the bundled pack: verbatim excerpts with a",
        "  source line, nothing generated. A local,",
        "  anthropic or openai bot is CALLED, and its",
        "  answer is labelled as a model's. The header",
        "  marks a bot that sends off this machine.",
    ]


#: The widest line :func:`help_lines` may hold. Sized for the chat column on a 96-column terminal —
#: the narrowest COMMON one — rather than on the studio's 72-column floor, where nothing useful
#: would fit: below this, ``chat_lines`` folds a line under its own indentation instead.
_HELP_WIDTH = 50


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
        #: The last frame's width, for the tables ``_chat_width`` sizes. Zero until the first frame.
        self._cols = int(size[0]) if size else 0
        #: True once the operator has been told, in the transcript, that the live bot is off-machine.
        self._warned_net = False
        #: The conversation with the live MODEL bot — what it said, so it can be asked a follow-up.
        #: Reset when the bot changes or the transcript is cleared. See :meth:`_history_for`.
        self._history: list[dict[str, str]] = []
        self._history_bot = ""
        self.refresh()

    # --- state ---------------------------------------------------------------------------------
    def refresh(self) -> None:
        """Re-read every store. Called at open, on ``/refresh``, and after a verb that may change one.

        It re-reads the PROFILE as well, because the live bot is a profile value and a bot verb has
        just written it. Everything here is a local file read; nothing on this path calls a model.
        """
        self._reload_profile_quietly()
        panels = collect(self._runtime, self._seed, self._profile)
        live, _note = _live_bot(self._runtime, self._profile)
        off_machine = _off_machine(self._runtime, live)
        learning_on = True
        if self._profile is not None:
            try:
                learning_on = bool(self._profile.get("learning"))
            except Exception:  # noqa: BLE001
                learning_on = True
        with self._lock:
            self._panels = panels
            self._learning_on = learning_on
            self._live = live
            # Resolved here, once per refresh, because it needs a file read: a `local` bot with no
            # endpoint of its own inherits the app's, which may be an Ollama on another host.
            # ``snapshot`` is called per frame and must not read files.
            self._live_off_machine = off_machine
            self._repaint = True

    def _reload_profile_quietly(self) -> None:
        """The profile as it is ON DISK, swallowing a failure. ``refresh`` must never raise."""
        try:
            import gn_profile

            self._profile = gn_profile.load(self._runtime)
        except Exception:  # noqa: BLE001 - keep whatever profile we were opened with
            pass

    def live_bot(self) -> Any:
        """The live bot as of the last :meth:`refresh`, or ``None`` if the store would not load."""
        with self._lock:
            return getattr(self, "_live", None)

    def snapshot(self) -> StudioState:
        with self._lock:
            panels = getattr(self, "_panels", {})
            live = getattr(self, "_live", None)
            return StudioState(
                bots=panels.get("bots", ()), brain=panels.get("brain", ()),
                learning=panels.get("learning", ()), chat=tuple(self._turns[-MAX_TURNS:]),
                status="", busy=self._busy, message=self._message,
                input_text=self._line.text, input_caret=self._line.cursor,
                chat_scroll=self._scroll, learning_on=getattr(self, "_learning_on", True),
                bot=getattr(live, "id", "") or "",
                off_machine=bool(getattr(self, "_live_off_machine", False)),
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
            if key == "TAB":
                self._complete()
                with self._lock:
                    self._repaint = True
                return
            if key == "CTRL-L":
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
                # The model's conversation goes with it. A cleared screen that a bot still
                # remembers is the one place this view could mislead about what it knows.
                self._history, self._history_bot = [], ""
                # And the off-machine notice is re-armed: the transcript IS the record of what has
                # left this machine, so a cleared record gets the statement again.
                self._warned_net = False
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
        if action == "bot":
            self._bot_verb(str(parsed.get("verb") or ""), list(parsed.get("args") or []),
                           live=bool(parsed.get("live")))
            return
        if action == "error":
            self.note(str(parsed.get("message") or ""))
            return
        if action == "ask":
            self._start_answer(str(parsed.get("text") or ""), pack=bool(parsed.get("pack")))

    # --- completion ----------------------------------------------------------------------------
    def _complete(self) -> str:
        """Tab: complete the command, then the bot verb, then a bot name.

        Three columns deep, unlike ``gn_dash``'s first-word-only completion, and for a reason that
        does not apply there: every argument completed here is a name out of a LOCAL store this view
        already has in front of the operator, so a completion cannot guess at a program id or a
        finding ref on a live engagement. One match completes; several print the list to the footer.
        """
        text = self._line.text
        if not text.startswith("/"):
            return text
        pieces = text[1:].split(" ")
        head = pieces[0].lower()
        if len(pieces) == 1:
            return self._complete_from(commands(), head, "/")
        if head == "bot" and len(pieces) == 2:
            return self._complete_from(sorted(set(_BOT_VERBS)), pieces[1].lower(),
                                       "/bot ")
        wants_name = (head in ("use", "switch", "clone", "train")
                      or (head == "bot" and len(pieces) == 3
                          and _BOT_VERBS.get(pieces[1].lower()) in
                          ("show", "use", "rm", "clone", "set", "teach", "forget", "train", "reset")))
        if wants_name and not pieces[-1].startswith("-"):
            prefix = " ".join(["/" + pieces[0], *pieces[1:-1]]).strip()
            return self._complete_from(self._bot_names(), pieces[-1].lower(), prefix + " ")
        return text

    def _complete_from(self, pool: Sequence[str], prefix: str, head: str) -> str:
        """One match completes; several advance to their COMMON prefix and list themselves.

        The common-prefix step is what every shell does and what makes ``/bo<Tab><Tab>`` reach
        ``/bots`` in two keystrokes: without it, ``bot`` and ``bots`` cancel each other out and Tab
        looks broken on the two commands an operator uses most.
        """
        matches = [name for name in pool if name.startswith(prefix)]
        if len(matches) == 1:
            self._line.set(head + matches[0] + " ")
            return self._line.text
        if not matches:
            return self._line.text
        shared = _common_prefix(matches)
        if len(shared) > len(prefix):
            self._line.set(head + shared)
        self.note(" ".join(matches[:14]))
        return self._line.text

    def _bot_names(self) -> tuple[str, ...]:
        try:
            return _registry(self._runtime).ids()
        except Exception:  # noqa: BLE001
            return ()

    def _chat_width(self) -> int:
        """How many columns a block put in the TRANSCRIPT has, as the last frame measured it.

        A table is composed when the operator asks for it, and the terminal's width is known only
        where the frame is drawn — so ``_loop`` records it and this mirrors ``render``'s own split.
        A studio that has not drawn yet (a test calling ``submit`` directly) gets the width of the
        narrowest terminal the studio will open on, which is the safe answer: compact.
        """
        cols = int(getattr(self, "_cols", 0) or 0)
        if cols < MIN_SIZE.cols:
            cols = MIN_SIZE.cols
        left = 36 if cols >= 96 else max(30, min(34, cols // 2 - 4))
        return max(24, cols - left - 3 - 1 - 5)     # chrome, the chat's gutter, the "gn > " prefix

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

        if action == "set" and str(key or "").strip().lower() == "bot":
            # ONE writer. `/set bot x` and `/use x` are the same operation, so they take the same
            # path: the bot store is the authority on which bots exist, and a settings door that
            # skipped it could park a name in the profile that nothing will honour.
            self._bot_verb("use", [str(value or "")])
            return
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

    # --- the bots ------------------------------------------------------------------------------
    def _bot_verb(self, verb: str, args: list[str], *, live: bool = False) -> None:
        """One bot command: read the store, apply, save, re-read the panels, say what happened.

        Every mutation goes through :mod:`gn_bots` — the same functions ``gn bot …`` calls — so the
        field whitelist, the refusal to delete a built-in, the refusal to make an inert clone a
        brain and the "a trained stamp needs a real run" rule are enforced once, in one module, for
        both doors. This method owns only the two things a chat window has to decide: WHICH bot an
        argument-light command means, and what to print.
        """
        import gn_bots

        registry = gn_bots.load(self._runtime)
        if verb == "ls":
            live, note = _live_bot(self._runtime, self._profile)
            lines = gn_bots.list_lines(registry, getattr(live, "id", "") or "", self._runtime,
                                       width=self._chat_width())
            self.say("gn", "\n".join(lines + ([note] if note else [])))
            return
        if verb == "fields":
            self.say("gn", "\n".join(gn_bots.fields_lines()))
            return
        if verb == "hf":
            self._plug_huggingface(args)
            return
        if verb == "new":
            self._bot_new(registry, args)
            return
        if verb == "use":
            name = args[0] if args else ""
            if not name:
                self.note("`/use <bot>` — /bots lists them")
                return
            bot, error = gn_bots.set_active(self._runtime, name)
            if bot is None:
                self.note(error)
                return
            self.refresh()
            ready = _readiness(self._runtime, bot)
            # Only a BLOCKER is appended. "off is live: nothing answers ... - off" repeats itself,
            # and "- edits only" after a sentence that already says it does not chat reads as a
            # fault rather than the posture it is.
            extra = f" — {ready}" if gn_bots.is_blocked(ready) else ""
            sends = (" · asking it sends off this machine"
                     if _off_machine(self._runtime, bot) else "")
            self.say("gn", f"{bot.id} is live: {gn_bots.what_it_does(bot)} "
                           f"({bot.describe()}){extra}{sends}")
            return
        # Everything below names a bot, and may leave the name out to mean the live one.
        target, rest, error = self._target(registry, verb, args, live=live)
        if error:
            self.note(error)
            return
        if verb == "show":
            self.say("gn", "\n".join(gn_bots.show_lines(target, self._runtime)))
            return
        if verb == "train":
            self._train_bot(target)
            return
        if verb == "rm":
            # Same rule as `gn bot rm`: deleting a bot takes its persona and everything it was
            # taught with it, and there is no undo. The CLI demands -y; this view asked for
            # nothing, so the two doors disagreed about how destructive the same verb is.
            if "-y" not in rest and "--yes" not in rest:
                lessons = len(target.lessons)
                self.say("gn", f"/bot rm {target.id} -y deletes it"
                               + (f" and the {lessons} lesson(s) it was taught" if lessons else "")
                               + ". There is no undo.")
                return
            # Asked BEFORE the delete, and of the raw setting rather than of a resolved bot:
            # ``resolve`` is total, so the moment the bot is out of the store it answers with the
            # default and "was that one live?" can no longer be asked.
            was_live = gn_bots.configured_name(self._runtime, self._profile) == target.id
            registry, removed, error = gn_bots.delete(registry, target.id)
            if removed is None:
                self.note(error)
                return
            if not self._save(registry):
                return
            if was_live:
                # The profile still names it. Say what is answering now rather than leaving the
                # operator to find out on their next question or hunt.
                fallback, _error = gn_bots.set_active(self._runtime, gn_bots.DEFAULT_ID)
                self.say("gn", f"deleted {removed.id} — it was live, so {gn_bots.DEFAULT_ID} is now")
            else:
                self.say("gn", f"deleted {removed.id}")
            self.refresh()
            return
        if verb == "reset":
            registry, shipped, error = gn_bots.reset(registry, target.id)
            if shipped is None:
                self.note(error)
                return
            if self._save(registry):
                self.say("gn", f"{shipped.id} is back to its shipped values ({shipped.describe()})")
                self.refresh()
            return
        if verb == "clone":
            # `/clone x as y` and `/clone x y` both work: "as" is how an operator says it out loud,
            # and refusing the word would be a rule to remember for nothing.
            tail = [piece for piece in rest if piece.lower() != "as"]
            registry, copy, error = gn_bots.clone(registry, target.id, tail[0] if tail else "")
            if copy is None:
                self.note(error)
                return
            if self._save(registry):
                self.say("gn", f"cloned {target.id} to {copy.id} ({copy.describe()}) — "
                               f"{len(copy.lessons)} lesson(s) came with it, and it has not been "
                               f"trained")
                self.refresh()
            return
        if verb == "set":
            if len(rest) < 1:
                self.note("`/bot set <bot> <field> <value>` — /bot fields lists them")
                return
            if len(rest) == 1:
                # `/model` on its own READS the field. It must not write: an empty value coerces
                # cleanly to "" for every text field, so this branch used to blank the live bot's
                # model on a bare `/model` — an operator reaching for a picker losing the setting
                # they were about to look at. Clearing stays possible, and explicit: `""`.
                self._show_field(target, rest[0])
                return
            field_name, value = rest[0], " ".join(rest[1:])
            registry, updated, error = gn_bots.update(registry, target.id, field_name, value)
            if updated is None:
                self.note(error)
                return
            if self._save(registry):
                shown = getattr(updated, field_name.strip().lower(), "")
                self.say("gn", f"{updated.id}.{field_name.strip().lower()} = "
                               f"{shown if shown not in (None, '') else '(blank)'}")
                self.refresh()
            return
        if verb == "teach":
            lesson = " ".join(rest)
            registry, taught, error = gn_bots.teach(registry, target.id, lesson)
            if taught is None:
                self.note(error)
                return
            if error:                      # "already knows that one" — not a failure, not a change
                self.note(error)
                return
            if self._save(registry):
                self.say("gn", f"{taught.id} now carries {len(taught.lessons)} lesson(s) into "
                               f"every chat. /bot show {taught.id} lists them.")
                self.refresh()
            return
        if verb == "forget":
            registry, updated, error = gn_bots.forget(registry, target.id,
                                                      rest[0] if rest else "")
            if updated is None:
                self.note(error)
                return
            if self._save(registry):
                self.say("gn", f"{updated.id} now has {len(updated.lessons)} lesson(s)")
                self.refresh()
            return
        self.note(f"not a bot verb: {verb}")

    #: Verbs whose first argument can only ever be a bot name. A name that does not resolve is an
    #: ERROR for these, never a fallback to the live bot: ``/train scoutt`` must not quietly train
    #: something else and report success for it. The rest (``set``, ``teach``, ``forget``) take a
    #: field or a lesson in that position, so an unresolvable first word is the normal case there.
    _NAME_ONLY = ("rm", "reset", "clone", "show", "train")
    #: Of those, the ones that may leave the name out and mean the live bot. ``rm``, ``reset`` and
    #: ``clone`` may not: defaulting a destructive verb to whatever happens to be live is the wrong
    #: kind of convenient.
    _NAME_OPTIONAL = ("show", "train")

    def _target(self, registry: Any, verb: str, args: list[str],
                *, live: bool = False) -> tuple[Any, list[str], str]:
        """``(the bot, the remaining arguments, error)`` for a verb that names a bot.

        The ergonomics this exists for: ``/bot set model gpt-4o`` and ``/bot teach "cite the
        endpoint"`` act on the LIVE bot, because that is the bot the operator is looking at, while
        ``/bot set claude model ...`` names one. The rule is decided against the store, not guessed.

        ``live=True`` comes from a top-level alias (``/teach``, ``/model``, ``/persona``) and
        forbids reading a name out of the arguments at all, because the first argument there is a
        lesson or a value whose first word may happen to be a bot name.
        """
        import gn_bots

        bot_live, note = _live_bot(self._runtime, self._profile)
        if live:
            if bot_live is None:
                return (None, [], note or "there is no live bot to act on")
            return (bot_live, args, "")
        if verb in self._NAME_ONLY:
            if not args:
                if verb in self._NAME_OPTIONAL and bot_live is not None:
                    return (bot_live, [], "")
                return (None, [], note or f"`/bot {verb} <bot>` — /bots lists them")
            bot, why = gn_bots.find(registry, args[0])
            return (bot, args[1:], "" if bot is not None else why)
        if args:
            bot, _why = gn_bots.find(registry, args[0])
            if bot is not None:
                return (bot, args[1:], "")
        if bot_live is None:
            return (None, [], note or "there is no live bot to act on")
        return (bot_live, args, "")

    def _show_field(self, bot: Any, name: str) -> None:
        """One field's current value, and how to change it. What a bare ``/model`` means."""
        import gn_bots

        key = str(name or "").strip().lower()
        item = next((field for field in gn_bots.FIELDS if field.key == key), None)
        if item is None:
            self.note(f"no bot field called {name!r}. /bot fields lists them")
            return
        value = getattr(bot, item.key, "")
        shown = "(blank)" if value in (None, "") else value
        self.say("gn", f"{bot.id}.{item.key} = {shown}\n  {item.help}\n"
                       f"  /bot set {bot.id} {item.key} <value>")

    def _bot_new(self, registry: Any, args: list[str]) -> None:
        """``/new <name> [provider] [model]`` — positional, because that is the order it is said in."""
        import gn_bots

        if not args:
            self.note("`/new <name> [provider] [model]` — provider defaults to tinygpt (local)")
            return
        values: dict[str, Any] = {}
        if len(args) > 1:
            values["provider"] = args[1]
        if len(args) > 2:
            values["model"] = " ".join(args[2:])
        registry, bot, error = gn_bots.create(registry, args[0], **values)
        if bot is None:
            self.note(error)
            return
        if not self._save(registry):
            return
        self.say("gn", f"created {bot.id} ({bot.describe()}). `/use {bot.id}` makes it live; "
                       f"`/bot set {bot.id} persona \"...\"` gives it a voice.")
        self.refresh()

    def _save(self, registry: Any) -> bool:
        """Write the store, reporting a failure to the footer. ``False`` means nothing was saved."""
        import gn_bots

        _registry, error = gn_bots.save(self._runtime, registry)
        if error:
            self.note(error)
            return False
        return True

    def _train_bot(self, bot: Any) -> None:
        """``/train`` — run the trainer this bot actually has, and record only what it produced.

        The hunt ranker's trainer is a real pass over the trace corpus, so it goes to the worker and
        the footer says what is running. It is an INSTRUCTION, like ``gn train-brain`` — the
        ``learning`` setting gates automatic learning, not a command the operator typed.
        """
        import gn_bots

        kind, why = gn_bots.trainer_for(bot)
        if not kind:
            self.say("gn", why)
            return
        if kind == "tiny":
            self.say("gn", f"{bot.id} is the bundled TinyGPT. Its trainer needs torch and a full "
                           f"dataset pass, so it is its own verb rather than something a dashboard "
                           f"starts:\n\n  gn train-coder --status   what it would train on\n"
                           f"  gn train-coder            train it")
            return
        if self._busy:
            self.note(f"busy: {self._busy}")
            return
        self.say("you", f"/train {bot.id}")
        self._set_busy(f"training the hunt ranker for {bot.id}")
        job = lambda: self._run_hunt_training(bot)      # noqa: E731 - one expression, read as data
        if self._pool is None:
            self._finish_job(job())
            return
        self._future = self._pool.submit(job)
        self._future.add_done_callback(lambda fut: self._finish_job(_result(fut)))

    def _run_hunt_training(self, bot: Any) -> tuple[str, str]:
        """``(what to say, how)`` from a real ``hunt_train.train`` run. Never raises into the frame."""
        import gn_bots

        try:
            from bughunter import hunt_train

            result = hunt_train.train(self._runtime, seed_dir=self._seed)
        except Exception as exc:  # noqa: BLE001 - a trainer that will not run is a sentence
            return (f"the trainer would not run: {type(exc).__name__}", "")
        if not result.get("ok"):
            # A refusal is a NORMAL outcome of an honest gate (not enough rows, no improvement over
            # the incumbent), and it is reported as the gate's own reason, never as a failure.
            return (f"not trained: {result.get('reason') or 'the gate refused'}", "hunt_train gate")
        note = f"hunt ranker · {result.get('rows')} rows · {result.get('programs')} program(s)"
        registry, trained, error = gn_bots.mark_trained(gn_bots.load(self._runtime), bot.id, note)
        if trained is not None and not error:
            gn_bots.save(self._runtime, registry)
        return (f"trained {bot.id}: {note}", "hunt_train")

    def _plug_huggingface(self, args: list[str]) -> None:
        """``/hf <ref> [as <name>] [--agent|--model] [--use]`` — plug a Hugging Face bot in.

        The only command in this view that touches the network, and it is explicit: it fetches
        weights (a long download) or clones an agent at a pinned, digest-verified commit. The work
        and every safety rule belong to :mod:`gn_bot_hf`; this runs it in the worker and streams its
        progress to the footer, because a studio frozen mid-download looks broken.
        """
        if not args:
            self.say("gn", "`/hf <owner/repo>` plugs in a Hugging Face bot.\n\n"
                           "  a GGUF model repository  -> imported into your local Ollama, probed "
                           "for chat and tool calls, and registered as a runnable bot\n"
                           "  an agent or Space        -> cloned at a pinned, verified commit and "
                           "registered INERT; nothing cloned is ever imported or executed\n\n"
                           "  as <name>   what to call it      --agent / --model   say which kind\n"
                           "  --use       make it live when it lands")
            return
        if self._busy:
            self.note(f"busy: {self._busy}")
            return
        flags = {piece.lower() for piece in args if piece.startswith("-")}
        words = [piece for piece in args if piece and not piece.startswith("-")]
        if not words:
            # `/hf --agent` is a plausible typo, and it used to raise IndexError straight out of
            # submit (the footer read "that key raised IndexError") instead of showing the usage
            # block three lines above.
            self.note("`/hf <owner/repo>` — the reference comes first; /hf on its own explains it")
            return
        reference = words[0]
        alias = ""
        if len(words) > 2 and words[1].lower() == "as":
            alias = words[2]
        elif len(words) == 2:
            alias = words[1]
        self.say("you", f"/hf {' '.join(args)}")
        self._set_busy(f"fetching {reference}")
        job = lambda: self._run_plug(reference, alias, flags)    # noqa: E731
        if self._pool is None:
            self._finish_job(job())
            return
        self._future = self._pool.submit(job)
        self._future.add_done_callback(lambda fut: self._finish_job(_result(fut)))

    def _run_plug(self, reference: str, alias: str, flags: set[str]) -> tuple[str, str]:
        """The plug-in, with its progress on the footer. ``(what to say, how)``."""
        try:
            import gn_bot_hf
        except Exception as exc:  # noqa: BLE001
            return (f"the Hugging Face importer would not load: {type(exc).__name__}", "")
        try:
            result = gn_bot_hf.plug(
                self._runtime, reference, alias=alias,
                as_agent="--agent" in flags, as_model="--model" in flags,
                progress=lambda message: self._progress(f"{reference}: {message}"))
        except Exception as exc:  # noqa: BLE001 - a refusal from the Hub is a sentence, not a trace
            return (_field(exc) or type(exc).__name__, "")
        lines = gn_bot_hf.report_lines(result)
        if "--use" in flags and result.get("runnable"):
            import gn_bots

            bot, error = gn_bots.set_active(self._runtime, str(result.get("bot") or ""))
            lines.append(f"  {bot.id} is live" if bot is not None else f"  not live: {error}")
        return ("\n".join(lines), "")

    def _progress(self, message: str) -> None:
        self._set_busy(_field(message)[:120])

    def _set_busy(self, text: str) -> None:
        """What the footer says is happening, set from EITHER thread.

        One setter, under the lock, flagging a repaint: a worker reported progress while the loop
        read ``_busy`` under the lock, and a bare rebind also left the frame waiting for the
        clock's next second to show it.
        """
        with self._lock:
            self._busy = str(text)
            self._repaint = True

    def _finish_job(self, result: tuple[str, str]) -> None:
        """One worker job's result in the transcript, and the panels re-read after it."""
        body, how = (result if isinstance(result, tuple) else (str(result), ""))
        self._set_busy("")
        if body:
            self.say("gn", body)
        if how:
            self.say("cite", f"answered by: {how}")
        self.refresh()

    # --- the chat ------------------------------------------------------------------------------
    def _start_answer(self, question: str, *, pack: bool = False) -> None:
        """Ask the live bot — or the offline pack, when that is what is live or what was asked.

        This is the only path in the studio that can send a prompt off the machine, it runs only
        because the operator typed a question, and it says where the answer came from afterwards.
        See the module docstring for why that is a different thing from a repaint calling a model.
        """
        if self._busy:
            self.note(f"still answering: {self._busy}")
            return
        bot = None if pack else self.live_bot()
        runnable = bool(getattr(bot, "runnable", False))
        # `off` means off. An INERT CLONE does not: its provider is "off" because it has no brain,
        # but the help, the empty-chat panel and this module's docstring all say a cloned agent
        # answers from the bundled pack — and refusing it here made three shipped strings wrong.
        if (bot is not None and not pack and getattr(bot, "provider", "") == "off"
                and not getattr(bot, "inert", False)):
            self.say("you", question)
            self.say("gn", f"{bot.id} is off, so nothing answers. `/use tinygpt` for the offline "
                           f"pack, or `/pack {question[:40]}` to ask it just this once.")
            return
        self.say("you", question)
        if runnable and _off_machine(self._runtime, bot) and not getattr(self, "_warned_net", False):
            # Once per session, before the first answer comes back: the header carries the marker,
            # but the transcript is where an operator reads what just happened.
            self._warned_net = True
            self.say("gn", f"[{bot.id}: this question goes to {bot.provider}"
                           f"{(' · ' + bot.model) if bot.model else ''}, off this machine. "
                           f"`/use tinygpt` keeps everything local.]")
        self._set_busy(f"asking {getattr(bot, 'id', 'the pack')}" if runnable
                       else "reading the pack")
        job = (lambda: self._ask_bot(bot, question)) if runnable else (
            lambda: self._answer(question))
        if self._pool is None:
            # No worker (a test driving submit() directly): answer inline, same code path.
            self._finish_answer(question, job())
            return
        self._future = self._pool.submit(job)
        self._future.add_done_callback(lambda fut, q=question: self._on_answer(q, fut))

    def _history_for(self, bot: Any, question: str) -> list[dict[str, str]]:
        """The conversation so far with THIS bot, plus the new question.

        A chat window that forgets the previous turn is not a chat window — "and the second one?"
        has to mean something. Two rules keep it honest:

        * **Per bot.** Switching bots starts a new conversation. Handing one model another's words
          back as its own is a small lie that produces strange answers, and handing it the pack's
          verbatim card excerpts would have it believe it wrote them.
        * **Only what the bot itself said.** The pack's answers, the ``/bots`` tables and the
          footer notes live in the TRANSCRIPT, not in this list, so the model's context is exactly
          the turns it took part in.
        """
        with self._lock:
            if getattr(self, "_history_bot", "") != bot.id:
                self._history = []
                self._history_bot = bot.id
            turns = list(self._history)
        return [*turns, {"role": "user", "content": question}]

    def _remember(self, bot: Any, question: str, answer_text: str, limit: int) -> None:
        with self._lock:
            if getattr(self, "_history_bot", "") != bot.id:
                self._history, self._history_bot = [], bot.id
            self._history.append({"role": "user", "content": question})
            self._history.append({"role": "assistant", "content": answer_text})
            # Pairs, not messages: a window that cuts between a question and its answer leaves a
            # dangling user turn, which some providers reject outright.
            keep = max(2, int(limit) * 2)
            del self._history[: max(0, len(self._history) - keep)]

    def _ask_bot(self, bot: Any, question: str) -> tuple[str, str]:
        """One question to a live model bot. ``(answer, how)``; a failure is a sentence, not a trace.

        The bot's persona, style and lessons are the system prompt (``gn_bots.system_extra``), with
        the studio's own standing instruction under them: this is a security tool, so an answer that
        cannot be grounded has to say so rather than be invented. ``how`` names the bot, the provider
        and the model, because an operator reading an answer must be able to tell a generated
        sentence from a quoted card without asking.
        """
        import gn_bots

        try:
            import coder
        except Exception as exc:  # noqa: BLE001
            return ("", f"the brain would not load ({type(exc).__name__})")
        config = gn_bots.coder_overlay(bot, self._coder_config())
        persona = gn_bots.system_extra(bot)
        config["system_prompt"] = ((persona + "\n\n") if persona else "") + STUDIO_SYSTEM_PROMPT
        try:
            import brain_profiles

            brain_profiles.apply(config, "chat")
        except Exception:  # noqa: BLE001 - the profile is a default, not a requirement
            pass
        try:
            reply = coder.generate(self._history_for(bot, question), config)
        except Exception as exc:  # noqa: BLE001 - CoderError carries an operator-facing sentence
            detail = _field(exc) or type(exc).__name__
            fallback, how = self._answer(question)
            if fallback:
                return (f"[{bot.id} could not answer: {detail}]\n\n{fallback}",
                        f"the offline pack, after {bot.id} failed · {how}")
            return (f"{bot.id} could not answer: {detail}", "")
        spoken = reply.get("text") if isinstance(reply, dict) else reply
        body = _field_multiline(spoken)
        if not body:
            return ("", f"{bot.id} returned nothing")
        # The model remembers what it SAID, not what fitted on the screen. Feeding the display's
        # truncation back as its own previous turn conditions the follow-up on half a sentence.
        self._remember(bot, question, _field_multiline_untrimmed(spoken),
                       config.get("history_turns") or 12)
        model = str((reply or {}).get("model") or bot.model or "")
        return (body, f"{bot.id} · {bot.provider}{('/' + model) if model else ''} — a model's "
                      f"words, not the offline pack")

    def _coder_config(self) -> dict[str, Any]:
        """The app's own coder block with the secrets store merged — what ``_load_coder_config`` reads.

        Read here rather than imported from ``gn_cli`` so the studio does not depend on the CLI
        module it is opened BY, and so a test can drive the studio on a temporary runtime directory.
        """
        config = _read_json(Path(self._runtime) / "solin_runtime_config.json")
        block = config.get("coder") if isinstance(config.get("coder"), dict) else {}
        block = dict(block)
        secrets = _read_json(Path(self._runtime) / "secrets.json")
        for provider in ("anthropic", "openai", "local"):
            key = str(secrets.get(provider) or "")
            if not key:
                continue
            existing = block.get(provider)
            merged = dict(existing) if isinstance(existing, dict) else {}
            merged["api_key"] = key
            block[provider] = merged
        return block

    def _on_answer(self, question: str, future: Any) -> None:
        try:
            result = future.result()
        except Exception as exc:  # noqa: BLE001 - an answerer that raised is "nothing matched"
            result = ("", f"{type(exc).__name__}")
        self._finish_answer(question, result)

    def _finish_answer(self, _question: str, result: tuple[str, str]) -> None:
        body, how = (result if isinstance(result, tuple) else ("", ""))
        self._set_busy("")
        if not body:
            # An empty body with a REASON is a bot that could not answer, which is a different event
            # from the pack having no card: saying "nothing in the offline pack matched" about a
            # failed API call would send the operator looking in the wrong place.
            self.say("gn", f"no answer: {how}" if how else NO_MATCH)
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
            # Recorded for _chat_width: a table composed on the next keystroke is composed for the
            # terminal as it is NOW, resizes included.
            self._cols = size.cols
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
