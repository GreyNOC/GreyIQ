"""The BOT REGISTRY: every bot this operator has, and which one is live.

WHY THIS EXISTS
---------------
``bot`` was a five-value setting — ``tinygpt``, ``local``, ``anthropic``, ``openai``, ``off`` — that
named a PROVIDER and nothing else. Two things were wrong with that. The first is that it could not
hold a bot: an operator who runs Claude for the hunt planner and a local Qwen for chat, each with its
own model, temperature and persona, had nowhere to put the second one, let alone name it. The second
is that the setting did not take effect anywhere — ``gn_studio`` displayed it and ``_load_coder_config``
ignored it, so the dashboard said ``bot anthropic`` while the hunt used whatever the desktop app had
last written into ``solin_runtime_config.json``. A setting that reads as honoured and is not is the
same class of defect the ``learning`` switch had.

So a bot is now a RECORD, the records live in one local store, and exactly one of them is live:

  * **The definitions** live in ``runtime/bots.json`` — this module's store. A bot is a name, a
    provider, a model, a persona, a style, a temperature and a short log of what it was taught.
  * **Which one is live** stays in the operator profile (``gn_profile``'s ``bot`` setting), because
    that file is the operator's posture — the thing ``gn settings`` prints and every verb reads.
    One source of truth, and no second door into it: :func:`set_active` is the only writer, and it
    refuses a name that is not in the store.
  * **Keys are not here.** A bot says which provider it speaks to; the key for that provider stays
    in ``runtime/secrets.json`` under the perms-restricted store the desktop app and
    ``_load_coder_config`` already share. :func:`key_state` reports *presence* so a bot listing can
    say "ready" or "needs a key" without a registry that can leak one. There is no field for one,
    and the field a credential could ride in — ``base_url`` — refuses userinfo, a query and a
    fragment both from ``gn bot set`` and on load, because a stored ``?api_key=...`` would be
    printed verbatim by ``gn bot show``; the refusal itself does not quote what it rejected,
    since that error reaches a footer too.

  * **"Where does a request go" is resolved, not read off the bot.** A ``local`` bot with no
    ``base_url`` of its own inherits the app's (:func:`coder_overlay` only overwrites the one the
    bot carries), so a bot created with ``local`` and a model name will talk to whatever
    ``coder.local.base_url`` says — another host, if the operator moved Ollama. Every surface that
    tells an operator whether their prompt leaves the machine must therefore use
    :func:`sends_off_machine`, never :attr:`Bot.off_machine`.

THE SIX BUILT-IN BOTS
---------------------
``tinygpt`` (the bundled local model, no key, nothing leaves the machine) is the default and the
fallback for every unresolvable name. ``local`` is Ollama or any OpenAI-compatible endpoint,
``anthropic`` and ``openai`` are the hosted brains, ``offline`` is the deterministic template+AST
coder (it edits, it does not chat), and ``off`` is nothing answering. They are SYNTHESIZED rather
than written at first run, so a default that improves in a later version reaches an existing install
instead of being frozen into it by an upgrade — the same rule ``gn_profile`` follows. An operator can
edit a built-in (``gn bot set local model qwen2.5-coder:32b``), which stores the edited copy;
:func:`reset` drops it back to the shipped values. They cannot be deleted, because the fallback has
to exist.

WHAT A BOT CANNOT DO
--------------------
* **It cannot assert authorization.** There is no such field, for the reason ``gn_profile``'s
  docstring gives: a file on disk cannot say a human is authorized to test a target.
* **A cloned Hugging Face agent cannot become a brain.** ``gn bot hf`` registers one as ``inert``,
  :func:`coder_overlay` returns ``{}`` for it, and the listing says so on the row. A stranger's
  agent is arbitrary Python and untrusted prose (see :mod:`hf_agent_clone`); it is inventory here,
  never an executable.
* **A persona cannot reach the hunt planner.** :func:`coder_overlay` carries the provider, the model
  and the sampling knobs; the persona is handed out separately by :func:`system_extra` and used only
  on a chat path. ``hunt_brain`` sets its own system prompt, and a chat persona steering an
  engagement's probe budget is not a feature anyone asked for.

TOTAL, PURE AND STDLIB-ONLY
---------------------------
This module registers a ``gn`` verb and is imported by ``_load_coder_config`` on the hunt path, so it
stays standard-library-only and import-light, and every function is total: a missing, unreadable or
malformed store yields the built-ins rather than an exception, because a corrupt bot file must not be
able to stop a hunt. The mutators are pure — registry in, registry out — so the whole table is a unit
test, and :func:`save` is the only thing that touches the disk.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

#: The store, inside the runtime directory every other local store already lives in.
BOTS_FILE = "bots.json"
#: Bumped only for a change this file cannot read forward; :func:`load` keeps unknown versions
#: readable rather than discarding bots it does not recognise.
VERSION = 1

#: Every provider a bot may name. ``tinygpt`` is the bundled local model (``solin_core``), ``local``
#: is Ollama or any OpenAI-compatible endpoint, ``offline`` is the deterministic coder (edits, no
#: chat), ``off`` is nothing answering. The four that are not ``tinygpt``/``off`` are the ones
#: ``coder.generate`` and ``coder.coder_enabled`` already know by these names.
PROVIDERS = ("tinygpt", "local", "anthropic", "openai", "offline", "off")
#: Providers that answer by sending a prompt to a model. Everything else is on-machine or inert.
MODEL_PROVIDERS = ("local", "anthropic", "openai")
#: Providers whose key lives in ``secrets.json``. ``local`` is loopback Ollama in the default case
#: and needs none, so it is not here — :func:`key_state` says "not needed" for it.
KEYED_PROVIDERS = ("anthropic", "openai")
#: Reasoning effort levels, mirroring ``brain_profiles.EFFORT_LEVELS`` (not imported: that module is
#: for the engine's call sites and this one must stay on the import-light path).
EFFORTS = ("", "low", "medium", "high", "xhigh", "max")

#: A bot id: lowercase, short, and safe as a JSON key and a CLI argument. Deliberately narrow — an
#: id is typed at a prompt, printed in a table and compared by prefix.
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}\Z")
_ID_BAD = re.compile(r"[^a-z0-9._-]+")
_TRUE = frozenset({"1", "true", "yes", "y", "on", "enable", "enabled"})
_FALSE = frozenset({"0", "false", "no", "n", "off", "disable", "disabled"})
#: How many lessons a bot keeps. A bot is not a notebook; the oldest fall off the end.
MAX_LESSONS = 40
_MAX_LESSON = 400


@dataclass(frozen=True)
class Bot:
    """One bot. ``source`` says where it came from, which is what decides what may be done to it.

    ``inert`` is the load-bearing field: a cloned Hugging Face agent is inventory, not a brain, and
    :func:`coder_overlay` refuses to build a config for one. ``origin`` records the repository and
    pinned revision a plugged-in bot came from, so a listing can be traced back to the Hub.
    """

    id: str
    name: str = ""
    provider: str = "tinygpt"
    model: str = ""
    base_url: str = ""
    persona: str = ""
    style: str = ""
    temperature: float | None = None
    effort: str = ""
    notes: str = ""
    source: str = "operator"          # "builtin" | "operator" | "huggingface" | "clone"
    origin: dict[str, Any] = field(default_factory=dict)
    inert: bool = False
    lessons: tuple[str, ...] = ()
    created_at: str = ""
    updated_at: str = ""
    trained_at: str = ""
    train_note: str = ""

    @property
    def label(self) -> str:
        return self.name or self.id

    @property
    def runnable(self) -> bool:
        """Whether this bot can answer a free-form prompt at all."""
        return not self.inert and self.provider in MODEL_PROVIDERS

    @property
    def off_machine(self) -> bool:
        """Whether asking this bot something sends it off this computer, from ITS OWN fields.

        ``local`` is loopback in the default case but not by definition — an operator may point it
        at an Ollama on another host, and a chat window has to be able to say so.

        **A ``local`` bot with no ``base_url`` of its own inherits the app's**, so this property
        alone is not the answer for one: ``coder_overlay`` leaves the runtime config's
        ``coder.local.base_url`` in place, and if that points at another host the prompt leaves the
        machine while this says it does not. Callers that have a runtime directory must use
        :func:`sends_off_machine`, which resolves the endpoint the request will actually use.
        """
        if self.inert or self.provider not in MODEL_PROVIDERS:
            return False
        if self.provider in ("anthropic", "openai"):
            return True
        return bool(self.base_url) and not _is_loopback(self.base_url)

    def describe(self) -> str:
        """``provider · model`` — the one-line "what is this" every surface prints."""
        if self.inert:
            return f"{self.provider} · inert (never executed)"
        if self.provider == "tinygpt":
            return "tinygpt · bundled local model"
        if self.provider == "off":
            return "off · nothing answers"
        if self.provider == "offline":
            return "offline · deterministic edits, no chat"
        return f"{self.provider} · {self.model or '(model unset)'}"

    def short(self) -> str:
        """:meth:`describe` with the explanation dropped, for a narrow column.

        The studio's chat pane is half a terminal wide, and a listing that wraps every row is not a
        listing. This keeps what identifies the bot (its provider and model) and drops the clause
        that explains the provider — which the panel, ``/bot show`` and the help all still carry.
        """
        if self.inert:
            return "inert clone"
        if self.provider in ("tinygpt", "off", "offline"):
            return self.provider
        return f"{self.provider} · {self.model or '(model unset)'}"


#: The shipped bots, synthesized when the store has no entry for them. See the module docstring for
#: why they are not written at first run.
BUILTINS: tuple[Bot, ...] = (
    Bot(id="tinygpt", name="TinyGPT", provider="tinygpt", source="builtin",
        notes="the bundled local model — no key, nothing leaves the machine"),
    Bot(id="local", name="Local", provider="local", model="qwen2.5-coder:14b",
        base_url="http://127.0.0.1:11434/v1", source="builtin",
        notes="Ollama or any OpenAI-compatible endpoint on this machine"),
    Bot(id="anthropic", name="Claude", provider="anthropic", model="claude-opus-5",
        source="builtin", notes="hosted — needs a key in the secrets store"),
    Bot(id="openai", name="OpenAI", provider="openai", model="gpt-4o",
        base_url="https://api.openai.com/v1", source="builtin",
        notes="hosted — needs a key in the secrets store"),
    Bot(id="offline", name="Offline coder", provider="offline", source="builtin",
        notes="deterministic template + AST edits through the agent; it does not chat"),
    Bot(id="off", name="Off", provider="off", source="builtin",
        notes="nothing answers; every path stays deterministic"),
)

_BUILTIN_BY_ID = {bot.id: bot for bot in BUILTINS}
#: The bot every unresolvable name falls back to. It is always present and always local.
DEFAULT_ID = "tinygpt"


@dataclass(frozen=True)
class Field:
    """One settable field on a bot: what it is called, its type, and what it means."""

    key: str
    kind: str                       # "str" | "text" | "choice" | "number" | "url"
    help: str
    choices: tuple[str, ...] = ()


FIELDS: tuple[Field, ...] = (
    Field("name", "str", "what the bot is called in listings (the id never changes)"),
    Field("provider", "choice", "who answers: " + ", ".join(PROVIDERS), choices=PROVIDERS),
    Field("model", "str", "the model name the provider is asked for (`gn models` lists local ones)"),
    Field("base_url", "url", "the endpoint for local/openai-compatible providers"),
    Field("persona", "text", "who the bot is, carried into chat prompts (never into the hunt planner)"),
    Field("style", "str", "how it should answer: direct, terse, teaching, warm"),
    Field("temperature", "number", "sampling temperature, 0.0 to 2.0 (blank = the provider default)"),
    Field("effort", "choice", "how hard it may think: " + ", ".join(e for e in EFFORTS if e),
          choices=EFFORTS),
    Field("notes", "str", "a line for you, shown in `gn bot show`"),
)

_FIELD_BY_KEY = {item.key: item for item in FIELDS}


def fields_table() -> tuple[Field, ...]:
    return FIELDS


@dataclass(frozen=True)
class Registry:
    """Every bot, plus where the store is and whether it could be read.

    ``error`` is set when a store WAS there and could not be read, or when it held entries this
    module refused. The caller keeps working on the built-ins and says this, rather than presenting
    them as the operator's own bots.

    The other two fields are what keep a bad character in the file from costing the operator their
    bots. Reading is lossy by design — a refused entry is not loaded — and every mutator then does
    load, mutate, :func:`save`, which rewrites the whole file. So:

    * ``unreadable`` holds the refused entries as the RAW objects they were, and :func:`save`
      writes them back verbatim. A provider this build does not know survives a ``gn bot teach``
      on a different bot, where before it was deleted by it.
    * ``readable`` is False when the file existed and could not be parsed AT ALL, in which case
      nothing is known about its contents and :func:`save` refuses rather than replacing them.
      One trailing comma used to be enough to lose every bot and every lesson in it, reported as
      success, with no backup anywhere.
    """

    bots: tuple[Bot, ...] = ()
    path: str = ""
    exists: bool = False
    error: str = ""
    #: Entries that loaded as JSON but that this build refused, kept verbatim for :func:`save`.
    unreadable: tuple[dict[str, Any], ...] = ()
    #: False when the file is there but could not be parsed, so its contents are unknown.
    readable: bool = True

    def ids(self) -> tuple[str, ...]:
        return tuple(bot.id for bot in self.bots)

    def get(self, bot_id: str) -> Bot | None:
        name = str(bot_id or "").strip().lower()
        for bot in self.bots:
            if bot.id == name:
                return bot
        return None

    def taken(self, bot_id: str) -> bool:
        """Whether this id is in use — INCLUDING by an entry this build could not read.

        A refused entry is invisible to :meth:`get` but is still written back by :func:`save`, so
        creating a bot over its id would produce a file with the same id twice.
        """
        name = str(bot_id or "").strip().lower()
        if self.get(name) is not None:
            return True
        return any(str(entry.get("id") or "").strip().lower() == name
                   for entry in self.unreadable)


def store_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / BOTS_FILE


def slugify(value: str) -> str:
    """A bot id from whatever the operator typed. ``""`` when nothing usable is left."""
    text = _ID_BAD.sub("-", str(value or "").strip().lower()).strip("-._")
    text = re.sub(r"-{2,}", "-", text)[:32].strip("-._")
    return text if text and _ID.fullmatch(text) else ""


def bot_id(value: str) -> str:
    """The id for a name the operator typed, or ``""`` if it cannot be one."""
    text = str(value or "").strip().lower()
    return text if _ID.fullmatch(text) else slugify(text)


#: The longest a bot id may be, from :data:`_ID`. Named because the numbering below has to reserve
#: room inside it.
_ID_MAX = 32


def _numbered(base: str, index: int) -> str:
    """``base-2``, ``base-3`` ... with the BASE shortened so the suffix fits in an id.

    Without the shortening, numbering silently collapsed: ``bot_id`` re-slugifies, ``slugify``
    truncates to 32 characters and strips a trailing dash, so for a base of 31 or 32 characters
    every candidate came back as the base itself. ``clone`` then refused with a false sentence
    ("every numbered variant already exists" when none did) and ``register`` fell out of its loop
    and REPLACED the existing bot. That is reachable from ``gn bot hf`` with an ordinary repository
    name: ``bartowski/Meta-Llama-3.1-8B-Instruct-GGUF`` derives a 31-character id.
    """
    suffix = f"-{index}"
    head = str(base or "")[: max(1, _ID_MAX - len(suffix))].rstrip("-._")
    return bot_id(f"{head}{suffix}")


def _is_loopback(base_url: str) -> bool:
    """Whether this endpoint is on THIS machine, decided by parsing it — never by string shape.

    The host is parsed and the address object asked, which is what ``coder.ollama_host_is_loopback``,
    ``coder.unattended_config`` and ``coder._ollama_open`` all already do. A hand-rolled version
    here had a ``host.startswith("127.")`` branch, and that is a string test applied to a value
    that may be a DNS NAME: ``http://127.0.0.1.evil.com:11434/v1`` is a registrable hostname that
    satisfied it, so every surface that tells an operator whether their prompt leaves the machine —
    the ``->net`` header marker, the BRAIN ``sends`` row, the ``/use`` line, ``gn bot show``'s
    endpoint note and the once-per-session transcript notice — went quiet while ``coder.generate``
    posted the system prompt, the persona, the lessons and the whole conversation to that host.

    FAILS CLOSED: a name that is not an IP literal is not loopback. The job of this function is to
    decide whether to warn, so the safe direction is to warn. ``coder``'s own helper is this exact
    check but that module is not import-light, and this one is on the CLI's boot path — the same
    reason ``gn_profile._BOT_NAME`` duplicates ``gn_bots._ID``.
    """
    import ipaddress
    import urllib.parse

    try:
        parsed = urllib.parse.urlsplit(str(base_url or "").strip())
        hostname = parsed.hostname or ""
        _ = parsed.port                 # a malformed port raises here rather than later
    except ValueError:
        return False
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


#: Every control character as a space, ESC and DEL included. ``str.split()`` alone does NOT do
#: this: ESC is not whitespace, so collapsing whitespace left an escape sequence intact in a
#: persona — which ``gn bot show`` prints straight to a terminal and which goes into a model's
#: system prompt. The studio strips escapes again at render time; this is the store refusing to
#: hold one in the first place.
_CTRL = {code: " " for code in range(32)}
_CTRL[127] = " "
# C1 (128-159) too: U+009B is ECMA-48's CSI and U+009D opens an OSC string, so a persona holding
# one would repaint the terminal `gn bot show` prints to. Not whitespace, so split() leaves them.
_CTRL.update({code: " " for code in range(128, 160)})


def _text(value: Any, limit: int) -> str:
    """One field as a single line, control characters out. Every string here goes through this.

    A persona and a model name are read back into a terminal frame and into a model's prompt; a
    stored ESC or newline would be the registry's to blame, not the renderer's.
    """
    cleaned = " ".join(str(value if value is not None else "").translate(_CTRL).split())
    return cleaned[:limit]


# --- reading --------------------------------------------------------------------------------------
def _bot_from_doc(doc: Any) -> tuple[Bot | None, str]:
    """One stored entry as a :class:`Bot`, or ``(None, why not)``. Never raises."""
    if not isinstance(doc, dict):
        return (None, "an entry that is not an object")
    identifier = bot_id(doc.get("id") or doc.get("slug") or "")
    if not identifier:
        return (None, f"an entry with an unusable id ({str(doc.get('id'))[:24]!r})")
    provider = str(doc.get("provider") or "").strip().lower()
    if provider not in PROVIDERS:
        # Not dropped silently: a hand-edited provider is exactly the sort of thing an operator
        # expects to have taken effect, and a bot that quietly became tinygpt would hide it.
        return (None, f"{identifier}: provider {provider or '(blank)'!r} is not one of "
                      f"{', '.join(PROVIDERS)}")
    # A stored value this build cannot honour is REFUSED, not quietly rewritten. The argument is
    # the one the provider check above makes: an operator who hand-edited `"temperature": 9.5` or
    # `"effort": "ultra"` expects it to have taken effect, and clamping 9.5 to 2.0 (or dropping
    # the effort) while reporting nothing hides that it did not. `gn bot set` refuses the same
    # values outright, so the two doors now agree.
    temperature: float | None = None
    if doc.get("temperature") not in (None, ""):
        number, error = coerce(_FIELD_BY_KEY["temperature"], doc.get("temperature"))
        if error:
            return (None, f"{identifier}: {error}")
        temperature = number
    effort = str(doc.get("effort") or "").strip().lower()
    if effort and effort not in EFFORTS:
        return (None, f"{identifier}: effort {effort!r} is not one of "
                      f"{', '.join(level for level in EFFORTS if level)}")
    # The ENDPOINT goes through the same coercion as `gn bot set`, so a credential cannot arrive
    # by hand-editing the file either: `coerce` refuses userinfo, a query and a fragment, and
    # without this check a stored `?api_key=...` loaded fine and `gn bot show` printed it.
    base_url, error = coerce(_FIELD_BY_KEY["base_url"], doc.get("base_url"))
    if error:
        return (None, f"{identifier}: {error}")
    lessons = doc.get("lessons") if isinstance(doc.get("lessons"), list) else []
    origin = doc.get("origin") if isinstance(doc.get("origin"), dict) else {}
    source = str(doc.get("source") or "operator").strip().lower()
    return (Bot(
        id=identifier,
        name=_text(doc.get("name"), 60),
        provider=provider,
        model=_text(doc.get("model"), 120),
        base_url=base_url,
        persona=_text(doc.get("persona"), 600),
        style=_text(doc.get("style"), 80),
        temperature=temperature,
        effort=effort if effort in EFFORTS else "",
        notes=_text(doc.get("notes"), 300),
        source=source if source in ("builtin", "operator", "huggingface", "clone") else "operator",
        origin={str(k)[:40]: _text(v, 200) for k, v in list(origin.items())[:12]},
        inert=bool(doc.get("inert")),
        lessons=tuple(_text(item, _MAX_LESSON) for item in lessons[:MAX_LESSONS] if str(item).strip()),
        created_at=_text(doc.get("created_at"), 40),
        updated_at=_text(doc.get("updated_at"), 40),
        trained_at=_text(doc.get("trained_at"), 40),
        train_note=_text(doc.get("train_note"), 200),
    ), "")


def _to_doc(bot: Bot) -> dict[str, Any]:
    doc: dict[str, Any] = {"id": bot.id, "provider": bot.provider}
    for key in ("name", "model", "base_url", "persona", "style", "effort", "notes",
                "created_at", "updated_at", "trained_at", "train_note"):
        value = getattr(bot, key)
        if value:
            doc[key] = value
    if bot.temperature is not None:
        doc["temperature"] = bot.temperature
    if bot.source != "operator":
        doc["source"] = bot.source
    if bot.origin:
        doc["origin"] = dict(bot.origin)
    if bot.inert:
        doc["inert"] = True
    if bot.lessons:
        doc["lessons"] = list(bot.lessons)
    return doc


def load(runtime_dir: str | Path) -> Registry:
    """Every bot: the stored ones, then the built-ins the store did not override.

    Total. A missing store is the shipped six; an unreadable or malformed one is the shipped six
    plus an ``error`` saying why, because presenting the defaults as the operator's own choices is
    the one thing this must not do.
    """
    path = store_path(runtime_dir)
    stored: list[Bot] = []
    refused: list[str] = []
    kept: list[dict[str, Any]] = []
    exists = False
    readable = True
    error = ""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        raw = ""
    except (ValueError, RecursionError) as exc:
        # NOT just OSError. ``read_text`` raises UnicodeDecodeError (a ValueError) for a file that
        # is not UTF-8 — and on this project's primary platform that is the ordinary outcome of
        # editing the store with PowerShell's `Out-File` or Notepad's "Save as Unicode", both of
        # which write UTF-16. Every `gn bot` verb loads first, so an uncaught one left the operator
        # with no verb that worked and no way back.
        return Registry(bots=tuple(_in_order(list(BUILTINS))), path=str(path), exists=True,
                        readable=False,
                        error=f"{path.name} is not UTF-8 text ({type(exc).__name__}); "
                              f"using the built-in bots")
    if raw:
        exists = True
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            error = f"{path.name} is not valid JSON ({exc.msg}); using the built-in bots"
            doc = None
            readable = False
        except RecursionError:
            # Deeply nested JSON. A RuntimeError, so the clause above does not catch it.
            error = f"{path.name} is nested too deeply to read; using the built-in bots"
            doc = None
            readable = False
        if isinstance(doc, dict):
            entries = doc.get("bots")
            entries = entries if isinstance(entries, list) else []
            seen: set[str] = set()
            for entry in entries:
                bot, why = _bot_from_doc(entry)
                if bot is None:
                    refused.append(why)
                    # Kept VERBATIM, so saving does not delete the entry this is complaining
                    # about. See Registry.unreadable.
                    if isinstance(entry, dict):
                        kept.append(entry)
                    continue
                if bot.id in seen:
                    refused.append(f"{bot.id}: listed twice; kept the first")
                    continue
                seen.add(bot.id)
                stored.append(bot)
        elif doc is not None:
            error = f"{path.name} is not a JSON object; using the built-in bots"
            readable = False
    merged = list(stored)
    have = {bot.id for bot in merged}
    for builtin in BUILTINS:
        if builtin.id not in have:
            merged.append(builtin)
    if refused and not error:
        shown = "; ".join(refused[:3])
        extra = f" (+{len(refused) - 3} more)" if len(refused) > 3 else ""
        error = (f"{path.name}: {shown}{extra} — those entries are not loaded (and are left "
                 f"untouched)")
    return Registry(bots=tuple(_in_order(merged)), path=str(path), exists=exists, error=error,
                    unreadable=tuple(kept), readable=readable)


def _in_order(bots: Sequence[Bot]) -> list[Bot]:
    """Built-ins first in their shipped order, then everything else alphabetically.

    A listing an operator reads twice a day should not reshuffle because a file was rewritten.
    """
    order = {bot.id: index for index, bot in enumerate(BUILTINS)}
    return sorted(bots, key=lambda bot: (order.get(bot.id, len(order)), bot.id))


def save(runtime_dir: str | Path, registry: Registry) -> tuple[Registry, str]:
    """Write the store. Returns ``(registry, error)``; the error is a sentence for ``_err``.

    Only bots that DIFFER from their shipped built-in are written, for the reason the module
    docstring gives: an untouched built-in that improves in a later version should reach an existing
    install. The file is replaced atomically so a killed write cannot leave half a store behind, and
    the mode is 0600 because a persona is the operator's own prose.

    TWO REFUSALS, because reading is lossy and this rewrites the whole file:

    * **A store that could not be PARSED is never replaced.** Nothing is known about what is in it,
      and it is the only copy of the operator's personas and lessons. One trailing comma used to be
      enough to lose all of them: ``gn bot ls`` reported the broken file, and then any ordinary
      ``gn bot new`` wrote a store containing one bot and called it success.
    * **Entries this build refused are written back verbatim** (``Registry.unreadable``), so a
      hand-edited ``"provider": "ollama"`` survives a ``gn bot teach`` on a different bot. Before,
      the command that reported the problem was also the command that deleted it.

    Still single-writer: two shells mutating the store at the same time is last-write-wins, exactly
    as the operator profile is. The temporary file is uniquely named so that collision is a lost
    bot rather than a Win32 error, but nothing here locks.
    """
    path = store_path(runtime_dir)
    if registry.exists and not registry.readable:
        return (registry, f"{path} could not be read ({registry.error or 'unparseable'}), so "
                          f"nothing was changed: writing now would replace the bots in it. Fix it, "
                          f"or move it aside to start a new store.")
    keep = [bot for bot in registry.bots if _BUILTIN_BY_ID.get(bot.id) != bot]
    doc = {
        "version": VERSION,
        "updated_at": _now(),
        "bots": ([_to_doc(bot) for bot in _in_order(keep)]
                 + [dict(entry) for entry in registry.unreadable]),
    }
    handle: int | None = None
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # A UNIQUE temporary name. Two shells running `gn bot new` at once both wrote
        # `bots.json.tmp`, which on Windows is not a race that merely loses a bot: it is an access
        # denied or a sharing violation surfaced as raw Win32 text, plus a window in which one
        # process renames the file the other is still writing.
        handle, name = tempfile.mkstemp(prefix=f"{path.stem}-", suffix=".tmp",
                                        dir=str(path.parent))
        temporary = Path(name)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            handle = None               # fdopen owns the descriptor now
            stream.write(json.dumps(doc, indent=2) + "\n")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass            # a filesystem without modes is not a reason to lose the store
        os.replace(temporary, path)
        temporary = None
    except (OSError, ValueError) as exc:
        if handle is not None:
            try:
                os.close(handle)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass        # a leftover temp is a smaller problem than a save that raises
        # ValueError as well as OSError: a path Windows cannot represent at all (an embedded null,
        # a reserved name) raises that one from inside pathlib before any syscall, and a save is
        # supposed to RETURN its refusal — every caller prints it to a footer or to stderr.
        return (registry, f"could not write {path}: {exc}")
    return (replace(registry, exists=True, error=""), "")


# --- finding one ----------------------------------------------------------------------------------
def find(registry: Registry, name: str) -> tuple[Bot | None, str]:
    """One bot by id, by display name, or by a UNIQUE prefix of either. ``(None, why not)``.

    Prefix matching is the whole ergonomic point: ``gn bot use anth`` and ``/use cl`` should work,
    because an operator who has to type a name exactly will type ``gn bot ls`` first every time.
    An ambiguous prefix is an error that NAMES the candidates rather than picking one — silently
    choosing a bot is how a prompt ends up at the wrong provider.
    """
    text = str(name or "").strip().lower()
    if not text:
        return (None, "which bot? `gn bot ls` lists them.")
    exact = registry.get(text)
    if exact is not None:
        return (exact, "")
    # The DISPLAY-NAME branch is ambiguity-checked too. Nothing stops two bots sharing a name
    # (``create`` guards ids only), and built-ins sort first, so a local bot the operator called
    # "Claude" used to resolve to the hosted ``anthropic`` built-in: `/use claude` would quietly
    # make a bot live that sends prompts off the machine. Same rule as the prefix branch below.
    named = [bot for bot in registry.bots if bot.name.strip().lower() == text]
    if len(named) == 1:
        return (named[0], "")
    if named:
        return (None, _ambiguous(text, named))
    matches = [bot for bot in registry.bots
               if bot.id.startswith(text) or bot.name.strip().lower().startswith(text)]
    if len(matches) == 1:
        return (matches[0], "")
    if matches:
        return (None, _ambiguous(text, matches))
    return (None, f"no bot called {text!r}. `gn bot ls` lists them, `gn bot new {text}` makes it.")


def _ambiguous(text: str, matches: Sequence[Bot]) -> str:
    return (f"{text!r} matches {', '.join(bot.id for bot in matches[:6])} - say which one.")


def resolve(registry: Registry, name: str) -> tuple[Bot, str]:
    """The named bot, or the default plus a NOTE saying the name did not resolve.

    Never raises and never returns ``None``: every caller of this is on a path where something has
    to answer, and "the configured bot is not in the store" is a sentence to show, not a crash. The
    note is what the studio's BRAIN row and the CLI's first-run hint print.
    """
    wanted = str(name or "").strip().lower()
    if not wanted:
        return (registry.get(DEFAULT_ID) or BUILTINS[0], "")
    bot = registry.get(wanted)
    if bot is not None:
        return (bot, "")
    fallback = registry.get(DEFAULT_ID) or BUILTINS[0]
    return (fallback, f"bot {wanted!r} is not in the store — using {fallback.id}. "
                      f"`gn bot ls` lists them.")


def configured_name(runtime_dir: str | Path, profile: Any = None) -> str:
    """The RAW ``bot`` setting, before it is resolved against the store.

    Needed because :func:`resolve` is total: once a bot is deleted it answers with the default, so
    "was the bot I just deleted the live one?" cannot be asked of a resolved bot — it has already
    fallen back, and the caller would silently skip re-pointing the profile. Both ``rm`` paths ask
    this instead.
    """
    if profile is None:
        try:
            import gn_profile

            profile = gn_profile.load(runtime_dir)
        except Exception:  # noqa: BLE001
            return ""
    try:
        return str(profile.get("bot") or "")
    except Exception:  # noqa: BLE001
        return ""


def active(runtime_dir: str | Path, profile: Any = None) -> tuple[Bot, str]:
    """The live bot: whatever the operator profile names, resolved against the store.

    ``profile`` may be passed by a caller that already loaded one (the studio holds it open); when
    it is ``None`` this reads it, because a bot lookup must never depend on the caller remembering.
    """
    if profile is None:
        try:
            import gn_profile

            profile = gn_profile.load(runtime_dir)
        except Exception:  # noqa: BLE001 - an unreadable profile means the default bot
            profile = None
    wanted = ""
    if profile is not None:
        try:
            wanted = str(profile.get("bot") or "")
        except Exception:  # noqa: BLE001
            wanted = ""
    return resolve(load(runtime_dir), wanted)


def set_active(runtime_dir: str | Path, name: str) -> tuple[Bot | None, str]:
    """Make one bot live, for chat AND for the hunt. The only writer of the ``bot`` setting.

    Writes through ``gn_profile`` rather than touching the file, so the key whitelist, the type
    checks and the refusal of anything that implies authorization are the CLI's own — there is no
    second door into the profile. Refuses a name that is not in the store, which is what keeps
    ``gn settings`` from advertising a bot that does not exist.
    """
    import gn_profile

    registry = load(runtime_dir)
    bot, why = find(registry, name)
    if bot is None:
        return (None, why)
    profile = gn_profile.load(runtime_dir)
    profile, error = gn_profile.set_value(profile, "bot", bot.id)
    if error:
        return (None, error)
    profile, error = gn_profile.save(runtime_dir, profile)
    if error:
        return (None, error)
    return (bot, "")


def endpoint_for(runtime_dir: str | Path, bot: Bot) -> str:
    """The endpoint a request to this bot will ACTUALLY use, or ``""`` for a hosted/local-only bot.

    The bot's own ``base_url`` if it has one, else the app's ``coder.local.base_url`` — because
    :func:`coder_overlay` only overwrites that block's URL when the bot carries one, so an
    operator who moved Ollama to another host in the desktop app has every ``local`` bot pointing
    there whether or not the bot says so.
    """
    if bot.provider != "local" or bot.inert:
        return ""
    if bot.base_url:
        return bot.base_url
    try:
        doc = json.loads((Path(runtime_dir) / "solin_runtime_config.json").read_text(
            encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return ""
    block = doc.get("coder") if isinstance(doc, dict) else {}
    local = block.get("local") if isinstance(block, dict) else {}
    raw = local.get("base_url") if isinstance(local, dict) else None
    endpoint, error = coerce(_FIELD_BY_KEY["base_url"], raw)
    if not error:
        return endpoint
    # REFUSED: a credential, a query, a fragment or an over-long value is riding in the app's own
    # config. That field is written by ``POST /api/coder`` with no validation and was read here
    # through ``_text`` with none either, so ``http://u:sk-live-...@10.0.0.9:11434/v1`` reached
    # ``/api/bots``' ``endpoint``, ``gn bot show``, the studio's BRAIN row and the app's readiness
    # line verbatim — one field, two rules, depending only on which file it was read from. It is
    # NOT blanked: ``coder.generate`` still posts to that host, so :func:`sends_off_machine` must
    # keep the host to answer truthfully. The parts no surface may print are dropped instead.
    return _redacted_endpoint(raw)


def _redacted_endpoint(value: Any) -> str:
    """``scheme://host[:port]/path`` of a URL that failed :func:`coerce`, or ``""``.

    Userinfo, query and fragment are gone — those are where a credential travels. The host is
    kept because the request really goes there and the ``->net`` marker depends on it.
    """
    import urllib.parse

    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in ("http", "https") or not hostname:
        return ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    path = re.sub(r"[^A-Za-z0-9._~%/+-]", "", parsed.path or "")[:120]
    return f"{parsed.scheme}://{host}{f':{port}' if port else ''}{path}"


def sends_off_machine(runtime_dir: str | Path, bot: Bot) -> bool:
    """Whether asking this bot sends the prompt off this computer, endpoint resolved.

    This is the one every SURFACE must use — the studio's header marker, its BRAIN row and its
    once-per-session notice. :attr:`Bot.off_machine` answers from the bot's own fields only, which
    is False for the ordinary ``/new <name> local <model>`` bot even when the app's Ollama lives on
    another host. An operator being told their question stayed local when it did not is the worst
    thing this view can get wrong.
    """
    if bot.off_machine:
        return True
    endpoint = endpoint_for(runtime_dir, bot)
    return bool(endpoint) and not _is_loopback(endpoint)


def key_state(runtime_dir: str | Path, bot: Bot) -> str:
    """``"configured"``, ``"none"`` or ``"not needed"`` — PRESENCE, never the key.

    Reads the same ``secrets.json`` ``_load_coder_config`` merges from, so a key configured in the
    desktop app is reported here too. A surface that can print a key is a surface that can leak one.
    """
    if bot.provider not in KEYED_PROVIDERS:
        return "not needed"
    try:
        doc = json.loads((Path(runtime_dir) / "secrets.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        # ValueError covers JSONDecodeError AND the UnicodeDecodeError a non-UTF-8 secrets.json
        # raises - a UTF-16 file is what PowerShell's `Out-File` writes on this platform. An
        # uncaught one took `readiness` with it, and `gn bot ls` with that.
        return "none"
    if not isinstance(doc, dict):
        return "none"
    return "configured" if str(doc.get(bot.provider) or "").strip() else "none"


def readiness(runtime_dir: str | Path, bot: Bot) -> str:
    """One word for "could this bot answer right now", with the reason when it could not."""
    if bot.inert:
        return "inert"
    if bot.provider == "off":
        return "off"
    if bot.provider == "offline":
        return "edits only"
    if bot.provider == "tinygpt":
        return "ready"
    if not bot.model:
        return "needs a model"
    if bot.provider in KEYED_PROVIDERS and key_state(runtime_dir, bot) != "configured":
        return "needs a key"
    return "ready"


# --- mutating (pure: registry in, registry out) ---------------------------------------------------
def coerce(item: Field, value: Any) -> tuple[Any, str]:
    """One value as the field's own type, or an error naming what was expected."""
    if item.kind == "number":
        text = str(value if value is not None else "").strip()
        if text == "" or text.lower() in ("none", "default", "unset"):
            return (None, "")
        try:
            number = float(text)
        except (TypeError, ValueError):
            return (None, f"{item.key} is a number between 0.0 and 2.0 - got {value!r}")
        # `not (0 <= n <= 2)` rather than a pair of comparisons, so NaN - which JSON accepts as a
        # bare literal and which compares False against everything - is refused instead of
        # surviving as a number the panel then prints.
        if not 0.0 <= number <= 2.0:
            return (None, f"{item.key} is between 0.0 and 2.0 - got {text!r}")
        return (round(number, 3), "")
    # 600 for every kind, not 200 for the non-text ones: the per-field limit below is what
    # REFUSES an over-long value, and it can only do that if the value still is one. `notes`
    # declares 300 — in FIELDS, in the API model and in `gn bot fields` — so a 250-character note
    # was cut to 200 here and the 300 check could never fire, storing two thirds of what the
    # operator typed and reporting nothing.
    text = _text(value, 600)
    if item.kind == "choice":
        low = text.lower()
        if low not in item.choices:
            allowed = ", ".join(choice or "(blank)" for choice in item.choices)
            return (None, f"{item.key} is one of: {allowed} — got {value!r}")
        return (low, "")
    if item.kind == "url":
        if not text:
            return ("", "")
        # Refused rather than truncated. ``_text`` above has already cut the value to 200, so a
        # 326-character endpoint used to be stored as its first 200 characters with nothing said,
        # and the app then showed and used an endpoint the operator never typed.
        if len(str(value or "").strip()) > 200:
            return (None, f"{item.key} is at most 200 characters")
        # NO userinfo, query or fragment. An endpoint needs none of the three, and each one is a
        # place a credential travels: `https://api.example.com/v1?api_key=sk-live-...` used to be
        # accepted, stored in bots.json and printed verbatim by `gn bot show` and `--json` - from
        # the one module whose docstring promises it cannot hold or leak a key. `user:pass@host`
        # was worse: ``_is_loopback`` strips the userinfo, so a remote host read as on-machine.
        if not re.fullmatch(r"https?://[A-Za-z0-9._~-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~%/+-]*)?",
                            text):
            # The refusal does NOT quote the value. This is the one field a credential arrives in,
            # and the error is printed by `gn bot ls`, the studio's panels and every caller's
            # footer — a message that echoes `?api_key=sk-live-...` leaks exactly what refusing it
            # was meant to prevent.
            detail = ("it may not carry a username, password, query or fragment"
                      if any(ch in text for ch in "@?#")
                      else "write it as scheme://host[:port][/path]")
            return (None, f"{item.key} is an http(s) endpoint and {detail}")
        return (text, "")
    limit = 600 if item.kind == "text" else (120 if item.key == "model" else 80)
    if item.key in ("notes",):
        limit = 300
    if item.key == "name":
        limit = 60
    if len(text) > limit:
        return (None, f"{item.key} is at most {limit} characters")
    return (text, "")


def _put(registry: Registry, bot: Bot) -> Registry:
    bots = [existing for existing in registry.bots if existing.id != bot.id]
    bots.append(bot)
    return replace(registry, bots=tuple(_in_order(bots)))


def create(registry: Registry, name: str, **values: Any) -> tuple[Registry, Bot | None, str]:
    """A new bot. ``name`` becomes both the id (slugged) and the display name.

    Defaults to the DEFAULT bot's provider rather than to a hosted one: a bot created with one word
    should be one that answers on this machine, needs no key and costs nothing.
    """
    identifier = bot_id(name)
    if not identifier:
        return (registry, None,
                f"{name!r} cannot be a bot name. Letters, digits, dot, dash and underscore.")
    if registry.taken(identifier):
        # ``taken``, not ``get``: an entry this build refused is invisible to ``get`` but is still
        # written back by ``save``, so creating over its id would put the same id in the file twice.
        return (registry, None, f"{identifier} already exists. `gn bot clone {identifier}` copies it, "
                                f"`gn bot set {identifier} <field> <value>` edits it.")
    bot = Bot(id=identifier, name=_text(name, 60), provider=DEFAULT_ID, created_at=_now(),
              updated_at=_now())
    for key, value in values.items():
        if value in (None, ""):
            continue
        bot, error = _apply(bot, key, value)
        if error:
            return (registry, None, error)
    return (_put(registry, bot), bot, "")


def _apply(bot: Bot, key: str, value: Any) -> tuple[Bot, str]:
    item = _FIELD_BY_KEY.get(str(key or "").strip().lower())
    if item is None:
        return (bot, f"no bot field called {key!r}. `gn bot fields` lists them.")
    coerced, error = coerce(item, value)
    if error:
        return (bot, error)
    return (replace(bot, **{item.key: coerced}, updated_at=_now()), "")


def update(registry: Registry, name: str, key: str, value: Any) -> tuple[Registry, Bot | None, str]:
    """Set one field on one bot.

    An inert clone's PROVIDER cannot be changed: that field is what keeps a stranger's agent out of
    the brain path, and letting it be edited would make the inert flag advisory.
    """
    bot, why = find(registry, name)
    if bot is None:
        return (registry, None, why)
    field_key = str(key or "").strip().lower()
    if bot.inert and field_key == "provider":
        return (registry, None,
                f"{bot.id} is a cloned agent — inert by design, so it cannot become a brain. "
                f"`gn bot new <name>` makes a bot that can.")
    updated, error = _apply(bot, field_key, value)
    if error:
        return (registry, None, error)
    return (_put(registry, updated), updated, "")


def delete(registry: Registry, name: str) -> tuple[Registry, Bot | None, str]:
    """Remove one bot. A built-in cannot be deleted — the fallback has to exist."""
    bot, why = find(registry, name)
    if bot is None:
        return (registry, None, why)
    if bot.id in _BUILTIN_BY_ID:
        return (registry, None,
                f"{bot.id} is built in and cannot be deleted. `gn bot reset {bot.id}` puts it back "
                f"to its shipped values.")
    bots = tuple(existing for existing in registry.bots if existing.id != bot.id)
    return (replace(registry, bots=bots), bot, "")


def reset(registry: Registry, name: str) -> tuple[Registry, Bot | None, str]:
    """A built-in back to its shipped values."""
    bot, why = find(registry, name)
    if bot is None:
        return (registry, None, why)
    shipped = _BUILTIN_BY_ID.get(bot.id)
    if shipped is None:
        return (registry, None, f"{bot.id} is not a built-in bot, so there is nothing to reset to. "
                                f"`gn bot rm {bot.id}` deletes it.")
    return (_put(registry, shipped), shipped, "")


def clone(registry: Registry, name: str, new_name: str = "") -> tuple[Registry, Bot | None, str]:
    """Copy a bot, including what it was taught. The copy is an operator bot, never a built-in.

    What is NOT copied: the training stamp. A clone has not been trained — it inherits the lessons
    (operator prose, which is what makes a copy worth having) but claiming the parent's trained_at
    would be a number nobody could reproduce.
    """
    bot, why = find(registry, name)
    if bot is None:
        return (registry, None, why)
    wanted = str(new_name or "").strip() or f"{bot.id}-copy"
    identifier = bot_id(wanted)
    if not identifier:
        return (registry, None, f"{new_name!r} cannot be a bot name.")
    if registry.taken(identifier):
        # Auto-numbering rather than refusing: /clone twice in a row is a normal thing to do.
        for index in range(2, 100):
            candidate = _numbered(identifier, index)
            if candidate and not registry.taken(candidate):
                identifier = candidate
                break
        else:
            return (registry, None, f"{identifier} and every numbered variant already exist.")
    copy = replace(bot, id=identifier, name=_text(wanted if new_name else f"{bot.label} copy", 60),
                   source="clone" if bot.inert else "operator",
                   created_at=_now(), updated_at=_now(), trained_at="", train_note="")
    return (_put(registry, copy), copy, "")


def teach(registry: Registry, name: str, lesson: str) -> tuple[Registry, Bot | None, str]:
    """Add one operator-authored instruction to a bot.

    This is the honest half of "training" for a bot whose weights are not ours: a lesson is YOUR
    prose, carried into the bot's chat prompt by :func:`system_extra`, and visible in `gn bot show`.
    It is never presented as a trained model.
    """
    bot, why = find(registry, name)
    if bot is None:
        return (registry, None, why)
    text = _text(lesson, _MAX_LESSON)
    if not text:
        return (registry, None, f"teach {bot.id} what? `gn bot teach {bot.id} "
                                f"\"always cite the endpoint you probed\"`")
    if text in bot.lessons:
        return (registry, bot, f"{bot.id} already knows that one.")
    lessons = (*bot.lessons, text)[-MAX_LESSONS:]
    updated = replace(bot, lessons=lessons, updated_at=_now())
    return (_put(registry, updated), updated, "")


def forget(registry: Registry, name: str, which: Any) -> tuple[Registry, Bot | None, str]:
    """Drop one lesson by its 1-based number, or every lesson with ``all``."""
    bot, why = find(registry, name)
    if bot is None:
        return (registry, None, why)
    if not bot.lessons:
        return (registry, None, f"{bot.id} has not been taught anything yet.")
    text = str(which or "").strip().lower()
    if text in ("all", "*"):
        updated = replace(bot, lessons=(), updated_at=_now())
        return (_put(registry, updated), updated, "")
    try:
        index = int(text)
    except (TypeError, ValueError):
        return (registry, None, f"which lesson? 1 to {len(bot.lessons)}, or `all`.")
    if not 1 <= index <= len(bot.lessons):
        return (registry, None, f"{bot.id} has {len(bot.lessons)} lesson(s); there is no {index}.")
    lessons = tuple(item for position, item in enumerate(bot.lessons, 1) if position != index)
    updated = replace(bot, lessons=lessons, updated_at=_now())
    return (_put(registry, updated), updated, "")


def mark_trained(registry: Registry, name: str, note: str) -> tuple[Registry, Bot | None, str]:
    """Record that a REAL training run happened for this bot, and what it produced.

    Only called with a trainer's own result (``hunt_train.train``, ``coder_train``). Nothing in this
    module ever sets this on its own: a trained stamp that no run produced is exactly the
    unreproducible number this program's house rule forbids.
    """
    bot, why = find(registry, name)
    if bot is None:
        return (registry, None, why)
    updated = replace(bot, trained_at=_now(), train_note=_text(note, 200), updated_at=_now())
    return (_put(registry, updated), updated, "")


def register(registry: Registry, bot: Bot) -> tuple[Registry, Bot | None, str]:
    """Put a bot built elsewhere (a Hugging Face plug-in) into the store, renaming on collision.

    REFUSES rather than replacing when every numbered name is taken. The loop used to fall through
    with the colliding id intact, and ``_put`` then overwrote the operator's own bot — persona,
    lessons and all — while reporting success, which ``gn bot hf`` printed as "plugged in <name>".
    """
    identifier = bot.id
    if registry.taken(identifier):
        for index in range(2, 100):
            candidate = _numbered(identifier, index)
            if candidate and not registry.taken(candidate):
                identifier = candidate
                break
        else:
            return (registry, None,
                    f"{identifier} and every numbered variant already exist. Pass a name with "
                    f"--as, or remove one first.")
    stamped = replace(bot, id=identifier, created_at=bot.created_at or _now(), updated_at=_now())
    # Through the READ path, so a Bot built elsewhere is held to exactly the rules a stored one is.
    # ``gn_bot_hf`` constructs one directly from Hugging Face metadata, and a hostile ``agent.json``
    # name survives ``hf_agent_clone._one_line`` (which collapses whitespace, and ESC is not
    # whitespace). Round-tripping guarantees that whatever is registered is something ``load``
    # would accept back, rather than trusting each caller to remember ``_text``.
    cleaned, why = _bot_from_doc(_to_doc(stamped))
    if cleaned is None:
        return (registry, None, f"that bot cannot be stored: {why}")
    return (_put(registry, cleaned), cleaned, "")


# --- what a bot means to the engine ---------------------------------------------------------------
def coder_overlay(bot: Bot, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """The coder config this bot means, over whatever the runtime config already said.

    This is the function that makes "change the bot" change the HUNT. ``_load_coder_config`` reads
    ``solin_runtime_config.json`` and merges the secrets store; this then says which provider and
    model that config is actually for, so the planner runs with the bot the operator picked rather
    than with whatever the desktop app last saved.

    ``{}`` — deterministic, no model, nothing sent — for ``tinygpt``, ``off`` and any inert clone.
    ``tinygpt`` is the bundled CHAT model and not something ``coder.generate`` can be pointed at, so
    selecting it means the hunt uses its bounded offline planner. That is a real posture, not a
    failure, and ``gn bot show`` says so in those words.

    ``enabled`` is set to True for a live bot because the operator named it AND the caller asked for
    a brain (``--brain`` / ``hunt.brain``); the persona is deliberately absent — see the module
    docstring.
    """
    if bot.inert or bot.provider in ("tinygpt", "off"):
        return {}
    config: dict[str, Any] = dict(base or {})
    config["enabled"] = True
    config["provider"] = bot.provider
    if bot.temperature is not None:
        config["temperature"] = bot.temperature
    if bot.provider == "offline":
        return config
    block = config.get(bot.provider)
    block = dict(block) if isinstance(block, dict) else {}
    if bot.model:
        block["model"] = bot.model
    if bot.base_url:
        block["base_url"] = bot.base_url
    if bot.effort:
        # Honoured by the Anthropic path; harmless metadata elsewhere. brain_profiles.apply only
        # fills values left at the shipped default, so an operator's choice here still wins.
        block["effort"] = bot.effort
    config[bot.provider] = block
    return config


def system_extra(bot: Bot) -> str:
    """The bot's persona, style and lessons as a system-prompt addendum, or ``""``.

    CHAT ONLY. The hunt planner sets its own system prompt (``hunt_brain.HUNT_BRAIN_SYSTEM_PROMPT``)
    and must not be steered by a chat persona. Returned as plain text so the caller decides where it
    goes; nothing here reaches a model by itself.
    """
    parts: list[str] = []
    if bot.name:
        parts.append(f"You are {bot.name}.")
    if bot.persona:
        parts.append(bot.persona)
    if bot.style:
        parts.append(f"Answer in a {bot.style} style.")
    if bot.lessons:
        parts.append("The operator has taught you:")
        parts.extend(f"- {lesson}" for lesson in bot.lessons)
    return "\n".join(parts)


def what_it_does(bot: Bot) -> str:
    """What making THIS bot live actually means, in one clause. ONE sentence, both doors.

    "it answers chat and plans the hunt" is true of a bot with a model behind it and false of the
    other four: ``off`` answers nothing, ``offline`` edits files and ``coder.generate`` refuses it
    outright, ``tinygpt`` answers from the bundled pack, and an inert clone is inventory.
    :func:`coder_overlay` gives none of them a reasoning brain, so none of them plans a hunt.

    It lives here rather than in either caller because ``gn bot use`` and the studio's ``/use`` are
    the same operation: the studio's copy was fixed first and the CLI kept printing "off is live -
    it answers chat and plans the hunt (off - nothing answers)", which contradicts itself inside
    one line.
    """
    if bot.inert:
        return ("it answers here from the offline pack; it is an inert clone, so it never runs and "
                "the hunt uses its own offline planner")
    if bot.provider == "off":
        return "nothing answers, and the hunt stays deterministic"
    if bot.provider == "offline":
        return ("the Workbench agent edits with it; it does not chat, so questions are answered "
                "from the offline pack, and the hunt uses its own offline planner")
    if bot.provider == "tinygpt":
        return "it answers from the bundled offline pack, and the hunt uses its own offline planner"
    return "it answers chat and plans the hunt"


def trainer_for(bot: Bot) -> tuple[str, str]:
    """``(what `gn bot train` runs for this bot, why)`` — ``("", reason)`` when nothing can.

    There are exactly two real local trainers in this program, and neither of them trains a hosted
    model's weights:

      * ``hunt`` — ``hunt_train.train``, the offline hunt ranker, learned from the trace corpus.
        This is what "train the bot that hunts" means, whatever provider it chats with.
      * ``tiny`` — ``coder_train``, the bundled TinyGPT's own corpus and checkpoint.

    A hosted bot gets ``("hunt", ...)``: its ranker is ours to train even though its weights are
    not. Saying "trained" about an API model would be a claim nobody could reproduce, so
    ``gn bot train`` says which of the two it ran and `gn bot show` records only that.
    """
    if bot.inert:
        return ("", f"{bot.id} is a cloned agent — inert inventory, with nothing here to train.")
    if bot.provider == "tinygpt":
        return ("tiny", "the bundled TinyGPT's own corpus and checkpoint (`gn train-coder`)")
    if bot.provider == "off":
        return ("", f"{bot.id} is off, so nothing answers and nothing learns. `gn bot use <name>`.")
    return ("hunt", "the offline hunt ranker this bot plans with (`gn train-brain`)")


# --- rendering ------------------------------------------------------------------------------------
def list_rows(registry: Registry, active_id: str = "",
              runtime_dir: str | Path | None = None) -> tuple[tuple[str, str, str, str], ...]:
    """``(mark, id, what it is, readiness)`` per bot. Pure; the caller formats and colours it."""
    out: list[tuple[str, str, str, str]] = []
    for bot in registry.bots:
        ready = readiness(runtime_dir, bot) if runtime_dir is not None else ""
        out.append(("*" if bot.id == active_id else " ", bot.id, bot.describe(), ready))
    return tuple(out)


def list_lines(registry: Registry, active_id: str = "",
               runtime_dir: str | Path | None = None, width: int = 0) -> list[str]:
    """``gn bot ls`` / ``/bots`` — every bot, the live one marked, and what each one is.

    ``width`` is the room the caller has. A full-width terminal gets aligned columns; the studio's
    chat pane passes its own width and gets the compact form instead, because a row that wraps
    costs more legibility than the alignment buys.
    """
    rows = list_rows(registry, active_id, runtime_dir)
    if not rows:
        return ["no bots (not even the built-ins, which means the store refused to load)"]
    ids = max(len(row[1]) for row in rows)
    what = max(len(row[2]) for row in rows)
    longest = 4 + ids + what + 2 + max((len(row[3]) for row in rows), default=0)
    compact = bool(width) and longest > width
    lines = []
    for mark, identifier, describe, ready in rows:
        if compact:
            bot = registry.get(identifier)
            short = bot.short() if bot is not None else describe
            tail = f"  [{ready}]" if ready and ready != "ready" else ""
            # Cut to the budget: a row that overruns is folded by the caller, and a folded row in a
            # table reads as two bots. The full text is one `gn bot show` away.
            lines.append(_clip(f" {mark} {identifier.ljust(ids)}  {short}{tail}".rstrip(), width))
        else:
            lines.append(f" {mark} {identifier.ljust(ids)}  {describe.ljust(what)}"
                         f"{('  ' + ready) if ready else ''}".rstrip())
    lines.append("")
    # What the LIVE bot does, not what a runnable one would. This said "it answers chat and plans
    # the hunt" whatever was marked, which is false of `off` (nothing answers), `offline` (it
    # edits), `tinygpt` (the bundled pack, and the hunt's own offline planner) and an inert clone —
    # the same sentence :func:`what_it_does` exists to keep honest, printed from the one place that
    # had not been using it.
    live = registry.get(active_id) if active_id else None
    does = what_it_does(live) if live is not None else "it answers chat and plans the hunt"
    note = (f" * = live: {does}."
            + ("" if compact else " `gn bot use <name>` changes it."))
    lines.append(_clip(note, width) if compact else note)
    if registry.error:
        lines.append(_clip(f" {registry.error}", width) if compact else f" {registry.error}")
    return lines


def _clip(text: str, width: int) -> str:
    """One line inside ``width``, with a tilde where it was cut — ``gn_dash``'s own elision mark."""
    if width <= 1 or len(text) <= width:
        return text
    return text[: width - 1] + "~"


def show_lines(bot: Bot, runtime_dir: str | Path | None = None) -> list[str]:
    """One bot in full: its fields, what it was taught, where it came from, what it can do."""
    # The id, and the display name only when it differs: `gn bot show scout` printed "scout  scout".
    lines = [bot.id if bot.label == bot.id else f"{bot.id}  {bot.label}", ""]
    lines.append(f"  provider     {bot.describe()}")
    # RESOLVED, not read off the bot. A `local` bot with no base_url of its own inherits the app's
    # `coder.local.base_url`, so a bot made with just a provider and a model can be pointed at
    # another host while its own field says nothing — and this row then omitted both the
    # destination and the off-machine warning while the prompt went there. The same reason
    # :func:`sends_off_machine` exists; this was the one surface still asking the bot instead.
    resolved = endpoint_for(runtime_dir, bot) if runtime_dir is not None else ""
    off = sends_off_machine(runtime_dir, bot) if runtime_dir is not None else bot.off_machine
    shown = bot.base_url or resolved
    if shown:
        source = "" if bot.base_url else "  (from the app's coder config)"
        lines.append(f"  endpoint     {shown}{source}"
                     + ("" if not off else "   (off this machine)"))
    if bot.temperature is not None:
        lines.append(f"  temperature  {bot.temperature:g}")
    if bot.effort:
        lines.append(f"  effort       {bot.effort}")
    if bot.style:
        lines.append(f"  style        {bot.style}")
    if bot.persona:
        lines.append(f"  persona      {bot.persona}")
    if bot.notes:
        lines.append(f"  notes        {bot.notes}")
    lines.append(f"  source       {bot.source}")
    if bot.origin:
        detail = "  ".join(f"{key}={value}" for key, value in sorted(bot.origin.items()))
        lines.append(f"  origin       {detail}")
    if runtime_dir is not None:
        lines.append(f"  key          {key_state(runtime_dir, bot)}")
        lines.append(f"  ready        {readiness(runtime_dir, bot)}")
    if bot.inert:
        lines.append("  inert        nothing cloned here is ever imported or executed")
    _kind, why = trainer_for(bot)
    lines.append(f"  trains       {why}")
    if bot.trained_at:
        lines.append(f"  trained      {bot.trained_at[:19]}"
                     + (f"  {bot.train_note}" if bot.train_note else ""))
    else:
        lines.append("  trained      never (`gn bot train " + bot.id + "`)")
    if bot.lessons:
        lines.append("")
        lines.append(f"  taught ({len(bot.lessons)})")
        for index, lesson in enumerate(bot.lessons, 1):
            lines.append(f"   {index:>2}. {lesson}")
    else:
        lines.append("")
        lines.append(f"  taught       nothing yet (`gn bot teach {bot.id} \"<instruction>\"`)")
    return lines


def fields_lines() -> list[str]:
    """``gn bot fields`` — what can be set on a bot, and what each field means."""
    width = max(len(item.key) for item in FIELDS)
    lines = ["bot fields", ""]
    for item in FIELDS:
        lines.append(f"  {item.key.ljust(width)}  {item.help}")
    lines.append("")
    lines.append("  gn bot set <bot> <field> <value>")
    lines.append("")
    lines.append("  Keys are NOT a field: they live in the secrets store, and `gn bot show` reports")
    lines.append("  only whether one is present. A bot cannot carry authorization either.")
    return lines


# --- the gn verb ----------------------------------------------------------------------------------
_VERB = "bot"


def _runtime_dir() -> Path:
    import gn_cli

    return Path(gn_cli.RUNTIME_DIR)


def _fail(message: str) -> int:
    import sys

    print(f"gn: {message}", file=sys.stderr)
    return 2


def _save_and_report(runtime_dir: Path, registry: Registry, lines: Sequence[str]) -> int:
    registry, error = save(runtime_dir, registry)
    if error:
        return _fail(error)
    for line in lines:
        print(line)
    return 0


def _cmd_bot_list(args: Any) -> int:
    runtime = _runtime_dir()
    registry = load(runtime)
    live, note = active(runtime)
    if getattr(args, "json", False):
        print(json.dumps({"active": live.id, "note": note,
                          "bots": [_to_doc(bot) | {"ready": readiness(runtime, bot)}
                                   for bot in registry.bots]}, indent=2))
        return 0
    for line in list_lines(registry, live.id, runtime):
        print(line)
    if note:
        print(f" {note}")
    return 0


def _cmd_bot_show(args: Any) -> int:
    runtime = _runtime_dir()
    name = str(getattr(args, "name", "") or "")
    if not name:
        bot, _note = active(runtime)
    else:
        bot, why = find(load(runtime), name)
        if bot is None:
            return _fail(why)
    if getattr(args, "json", False):
        print(json.dumps(_to_doc(bot) | {"ready": readiness(runtime, bot),
                                         "key": key_state(runtime, bot)}, indent=2))
        return 0
    for line in show_lines(bot, runtime):
        print(line)
    return 0


def _cmd_bot_use(args: Any) -> int:
    bot, error = set_active(_runtime_dir(), str(getattr(args, "name", "") or ""))
    if bot is None:
        return _fail(error)
    print(f"{bot.id} is live: {what_it_does(bot)} ({bot.describe()})")
    if sends_off_machine(_runtime_dir(), bot):
        print("  asking it sends the prompt off this machine")
    ready = readiness(_runtime_dir(), bot)
    if ready not in ("ready", "inert"):
        print(f"  {ready}: `gn bot show {bot.id}` says what is missing")
    return 0


def _cmd_bot_new(args: Any) -> int:
    runtime = _runtime_dir()
    values = {key: getattr(args, key, None)
              for key in ("provider", "model", "base_url", "persona", "style")}
    registry, bot, error = create(load(runtime), str(getattr(args, "name", "") or ""), **values)
    if bot is None:
        return _fail(error)
    lines = [f"created {bot.id}  ({bot.describe()})"]
    if getattr(args, "use", False):
        registry, saved_error = save(runtime, registry)
        if saved_error:
            return _fail(saved_error)
        live, error = set_active(runtime, bot.id)
        if live is None:
            return _fail(error)
        lines.append(f"{bot.id} is live")
        for line in lines:
            print(line)
        return 0
    lines.append(f"  `gn bot use {bot.id}` makes it live, `gn bot set {bot.id} persona \"...\"` "
                 f"gives it a voice")
    return _save_and_report(runtime, registry, lines)


def _cmd_bot_set(args: Any) -> int:
    runtime = _runtime_dir()
    name = str(getattr(args, "name", "") or "")
    key = str(getattr(args, "field", "") or "").strip().lower()
    value = getattr(args, "value", None)
    if value is None:
        # NO value given READS the field; it does not write one. An empty string coerces cleanly
        # for every text field, so `gn bot set scout model` used to blank the model instead of
        # printing it. Clearing stays possible and explicit: `gn bot set scout model ""`.
        return _cmd_bot_get(name, key, runtime)
    registry, bot, error = update(load(runtime), name, key, value)
    if bot is None:
        return _fail(error)
    shown = getattr(bot, _FIELD_BY_KEY[key].key)
    return _save_and_report(runtime, registry,
                            [f"{bot.id}.{key} = "
                             f"{shown if shown not in (None, '') else '(blank)'}"])


def _cmd_bot_get(name: str, key: str, runtime: Path) -> int:
    """One field's current value, and what it means. What ``gn bot set <bot> <field>`` prints."""
    bot, why = find(load(runtime), name)
    if bot is None:
        return _fail(why)
    item = _FIELD_BY_KEY.get(key)
    if item is None:
        return _fail(f"no bot field called {key!r}. `gn bot fields` lists them.")
    value = getattr(bot, item.key, "")
    print(f"{bot.id}.{item.key} = {'(blank)' if value in (None, '') else value}")
    print(f"  {item.help}")
    print(f"  gn bot set {bot.id} {item.key} <value>    (\"\" clears it)")
    return 0


def _cmd_bot_rm(args: Any) -> int:
    runtime = _runtime_dir()
    registry = load(runtime)
    bot, why = find(registry, str(getattr(args, "name", "") or ""))
    if bot is None:
        return _fail(why)
    if not getattr(args, "yes", False):
        return _fail(f"this deletes the bot {bot.id} and everything it was taught. Re-run with -y.")
    was_live = configured_name(runtime) == bot.id
    registry, bot, error = delete(registry, bot.id)
    if bot is None:
        return _fail(error)
    lines = [f"deleted {bot.id}"]
    registry, save_error = save(runtime, registry)
    if save_error:
        return _fail(save_error)
    if was_live:
        # The profile still names it, so re-point it and say what is answering now rather than
        # leaving the operator to discover it on their next hunt.
        _fallback, error = set_active(runtime, DEFAULT_ID)
        lines.append(f"it was the live bot — {DEFAULT_ID} is live now"
                     if not error else f"it was the live bot, and re-pointing failed: {error}")
    for line in lines:
        print(line)
    return 0


def _cmd_bot_clone(args: Any) -> int:
    runtime = _runtime_dir()
    registry, bot, error = clone(load(runtime), str(getattr(args, "name", "") or ""),
                                 str(getattr(args, "alias", "") or ""))
    if bot is None:
        return _fail(error)
    return _save_and_report(runtime, registry,
                            [f"cloned to {bot.id}  ({bot.describe()})",
                             f"  it inherited {len(bot.lessons)} lesson(s); it has not been trained"])


def _cmd_bot_reset(args: Any) -> int:
    runtime = _runtime_dir()
    registry, bot, error = reset(load(runtime), str(getattr(args, "name", "") or ""))
    if bot is None:
        return _fail(error)
    return _save_and_report(runtime, registry, [f"{bot.id} is back to its shipped values"])


def _cmd_bot_teach(args: Any) -> int:
    runtime = _runtime_dir()
    lesson = " ".join(getattr(args, "lesson", []) or [])
    registry, bot, error = teach(load(runtime), str(getattr(args, "name", "") or ""), lesson)
    if bot is None:
        return _fail(error)
    if error:
        print(error)
        return 0
    return _save_and_report(runtime, registry,
                            [f"{bot.id} now carries {len(bot.lessons)} lesson(s) into its prompts"])


def _cmd_bot_forget(args: Any) -> int:
    runtime = _runtime_dir()
    registry, bot, error = forget(load(runtime), str(getattr(args, "name", "") or ""),
                                  getattr(args, "which", ""))
    if bot is None:
        return _fail(error)
    return _save_and_report(runtime, registry, [f"{bot.id} now has {len(bot.lessons)} lesson(s)"])


def _cmd_bot_fields(_args: Any) -> int:
    for line in fields_lines():
        print(line)
    return 0


def _cmd_bot_train(args: Any) -> int:
    """`gn bot train` — run the trainer this bot actually has, and record only what it produced."""
    runtime = _runtime_dir()
    name = str(getattr(args, "name", "") or "")
    bot = active(runtime)[0] if not name else None
    if bot is None:
        bot, why = find(load(runtime), name)
        if bot is None:
            return _fail(why)
    kind, why = trainer_for(bot)
    if not kind:
        return _fail(why)
    print(f"{bot.id}: training {why}")
    if kind == "tiny":
        print("  the TinyGPT trainer is its own verb, because it needs torch and a dataset pass:")
        print("    gn train-coder --status        what it would train on")
        print("    gn train-coder                 train it")
        return 0
    from bughunter import hunt_train

    result = hunt_train.train(runtime, seed_dir=_seed_dir(),
                              dry_run=bool(getattr(args, "dry_run", False)))
    reason = str(result.get("reason") or "")
    if not result.get("ok"):
        print(f"  not trained: {reason or 'the gate refused'}")
        return 0
    note = (f"hunt ranker · {result.get('rows')} rows · "
            f"{result.get('programs')} program(s)")
    print(f"  {note}"
          + ("  (dry run — nothing written)" if result.get("dry_run") else ""))
    if result.get("dry_run"):
        return 0
    registry, trained, error = mark_trained(load(runtime), bot.id, note)
    if trained is None:
        return _fail(error)
    return _save_and_report(runtime, registry, [f"  recorded on {bot.id}"])


def _seed_dir() -> Path | None:
    try:
        import gn_cli

        return Path(gn_cli.SEED_DIR)
    except Exception:  # noqa: BLE001
        return None


def _cmd_bot_hf(args: Any) -> int:
    """`gn bot hf <ref>` — plug a Hugging Face bot in. The work is in :mod:`gn_bot_hf`."""
    import gn_bot_hf

    return gn_bot_hf.cmd_plug(args, runtime_dir=_runtime_dir())


def register_cli(sub: Any) -> None:
    """gn_cli plugin hook. MUST stay import-light — this runs on every ``import gn_cli``."""
    parser = sub.add_parser(
        _VERB, help="your bots: make, edit, clone, teach, train, delete, and pick the live one")
    actions = parser.add_subparsers(dest="bot_command", metavar="<action>")

    for name in ("ls", "list"):
        listing = actions.add_parser(name, help="every bot, with the live one marked")
        listing.add_argument("--json", action="store_true")
        listing.set_defaults(func=_cmd_bot_list)

    show = actions.add_parser("show", help="one bot in full (default: the live one)")
    show.add_argument("name", nargs="?", default="", help="the bot (an id, a name, or a prefix)")
    show.add_argument("--json", action="store_true")
    show.set_defaults(func=_cmd_bot_show)

    use = actions.add_parser("use", help="make a bot live — it answers chat AND plans the hunt")
    use.add_argument("name", help="the bot (an id, a name, or a prefix)")
    use.set_defaults(func=_cmd_bot_use)

    new = actions.add_parser("new", help="create a bot")
    new.add_argument("name", help="what to call it (becomes its id)")
    new.add_argument("--provider", default=None, choices=PROVIDERS, help="who answers for it")
    new.add_argument("--model", default=None, help="the model name to ask that provider for")
    new.add_argument("--base-url", dest="base_url", default=None, help="endpoint for local/openai")
    new.add_argument("--persona", default=None, help="who it is, in a sentence")
    new.add_argument("--style", default=None, help="direct, terse, teaching, warm")
    new.add_argument("--use", action="store_true", help="make it live straight away")
    new.set_defaults(func=_cmd_bot_new)

    setter = actions.add_parser("set", help="change one field on a bot (no value prints it)")
    setter.add_argument("name")
    setter.add_argument("field", help="`gn bot fields` lists them")
    # None, not "": omitting the value READS the field, while an explicit "" clears it. With
    # argparse's usual empty-string default the two are the same argv and a read blanked the field.
    setter.add_argument("value", nargs="?", default=None)
    setter.set_defaults(func=_cmd_bot_set)

    for name in ("rm", "remove", "delete"):
        remove = actions.add_parser(name, help="delete a bot and what it was taught")
        remove.add_argument("name")
        remove.add_argument("-y", "--yes", action="store_true", help="confirm the deletion")
        remove.set_defaults(func=_cmd_bot_rm)

    cloner = actions.add_parser("clone", help="copy a bot, lessons included")
    cloner.add_argument("name")
    cloner.add_argument("--as", dest="alias", default="", help="what to call the copy")
    cloner.set_defaults(func=_cmd_bot_clone)

    resetter = actions.add_parser("reset", help="a built-in bot back to its shipped values")
    resetter.add_argument("name")
    resetter.set_defaults(func=_cmd_bot_reset)

    teacher = actions.add_parser("teach", help="give a bot a standing instruction it carries into chat")
    teacher.add_argument("name")
    teacher.add_argument("lesson", nargs="+", help="the instruction, in your own words")
    teacher.set_defaults(func=_cmd_bot_teach)

    forgetter = actions.add_parser("forget", help="drop one lesson (by number) or all of them")
    forgetter.add_argument("name")
    forgetter.add_argument("which", help="the lesson number from `gn bot show`, or `all`")
    forgetter.set_defaults(func=_cmd_bot_forget)

    trainer = actions.add_parser("train", help="train what this bot actually has: its hunt ranker")
    trainer.add_argument("name", nargs="?", default="", help="the bot (default: the live one)")
    trainer.add_argument("--dry-run", action="store_true", help="evaluate and report, write nothing")
    trainer.set_defaults(func=_cmd_bot_train)

    fields = actions.add_parser("fields", help="what can be set on a bot")
    fields.set_defaults(func=_cmd_bot_fields)

    plug = actions.add_parser(
        "hf", help="plug in a Hugging Face bot: a GGUF model becomes a local brain, an agent is "
                   "cloned inert")
    plug.add_argument("reference", help="owner/name, hf.co/owner/name, or spaces/owner/name "
                                        "(with an optional :quant or @revision)")
    plug.add_argument("--as", dest="alias", default="", help="what to call the bot")
    plug.add_argument("--agent", action="store_true",
                      help="clone it as an inert agent even if it has GGUF weights")
    plug.add_argument("--model", dest="as_model", action="store_true",
                      help="import it as a runnable model (refuse if it has no GGUF)")
    plug.add_argument("--use", action="store_true", help="make the new bot live when it lands")
    plug.add_argument("--json", action="store_true")
    plug.set_defaults(func=_cmd_bot_hf)

    # `gn bot` with no action lists them: the thing an operator wants 90% of the time, and the one
    # place a bare verb printing help instead would just cost them a second command.
    parser.set_defaults(func=_cmd_bot_list, bot_command="ls", json=False)
