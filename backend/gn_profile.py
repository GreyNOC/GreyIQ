"""The operator profile: the settings `gn` reads so a hunt is one line instead of twelve flags.

WHY THIS EXISTS
---------------
Every verb in this CLI took its posture from flags and nothing else, so the same six or seven
arguments were retyped on every run — profile, brain, output folder, per-finding files, platform,
whether to prompt. The flags are not wrong; repeating them is. This file holds what the operator
decided ONCE, and the verbs read it for anything they were not told on the command line.

THE ONE THING IT MAY NOT HOLD
-----------------------------
**Authorization.** A file on disk cannot assert that a human is authorized to test a target, and
this file is no more able to than ``.greyiq/hunt.json`` is (``hunt_dir``'s module docstring states
the same rule, and strips the key if a hunt file tries to set it). There is deliberately no
``authorize`` setting, no ``always_authorize``, and no key that implies one. ``-y`` on the command
line, or a human answering the confirmation at a terminal, stays the only source. ``gn settings
set`` refuses any key it does not know, which is what keeps that true as this table grows.

Secrets are not here either: API keys live in ``runtime/secrets.json`` under the perms-restricted
store the desktop app and ``_load_coder_config`` already share, so a profile can be read, printed
by ``gn settings``, diffed and pasted into a ticket without leaking one.

TOTAL AND PURE
--------------
Standard library only, no network. Every function is total: a missing, unreadable or malformed
profile yields the DEFAULTS rather than an exception, because a corrupt settings file must not be
able to stop a hunt. :func:`load` says which it got (``exists``), so a caller can tell "the
operator chose the defaults" from "there is no profile yet" — the first run depends on that
difference and nothing else does.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

#: The profile file, inside the runtime directory every other local store already lives in.
PROFILE_FILE = "operator_profile.json"
#: Bumped only for a change this file cannot read forward; :func:`load` keeps unknown versions
#: readable rather than discarding settings it does not recognise.
VERSION = 1

#: The bots that are always there. ``tinygpt`` is GreyIQ's own small local model (solin_core) and
#: the default, because it is the only one that is always present, needs no key and sends nothing
#: off the machine — the same reason every other default here is the local-first one.
#:
#: ``bot`` is no longer a CHOICE between these five, because a bot is no longer a provider: it is a
#: record in ``gn_bots``' store (a name, a provider, a model, a persona, what it was taught), and an
#: operator may have a dozen. This module therefore validates the SHAPE of a bot name and
#: ``gn_bots.set_active`` — the only writer — validates that the bot exists. See :data:`_BOT_NAME`.
BOTS = ("tinygpt", "local", "anthropic", "openai", "off")
#: Submission shapes ``report_formats.normalize_platform`` accepts.
PLATFORMS = ("hackerone", "yeswehack", "intigriti", "hackenproof", "manual")
#: Hunt profiles. Named here rather than imported so this module stays stdlib-only and the CLI's
#: boot path stays torch-free; :func:`set_value` checks against this and ``gn hunt`` still has the
#: engine's own list as the final word.
HUNT_PROFILES = ("web-app", "api", "source-code", "secrets", "full-sweep")

_TRUE = frozenset({"1", "true", "yes", "y", "on", "enable", "enabled"})
_FALSE = frozenset({"0", "false", "no", "n", "off", "disable", "disabled"})
#: A label for `gn output -s <label>`: a host, a program id, or a campaign name. Deliberately
#: narrow — it becomes a KEY in a JSON file the operator reads, not a path on disk.
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:*-]{0,126}\Z")
#: A bot name, identical to ``gn_bots._ID`` (repeated, not imported, so this module stays the
#: stdlib-only table it is). Shape only: whether the bot EXISTS is ``gn_bots``' question, and the
#: one path that can answer it — ``gn_bots.set_active`` — is the only writer of this setting.
_BOT_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}\Z")


@dataclass(frozen=True)
class Setting:
    """One setting: what it is called, what it defaults to, and what it means.

    ``ask`` is the first-run question. A setting with no ``ask`` is still settable — it is simply
    not worth stopping a new operator for, and ``gn settings`` lists every one of them.
    """

    key: str
    default: Any
    kind: str                       # "bool" | "str" | "path" | "choice" | "bot"
    help: str
    choices: tuple[str, ...] = ()
    ask: str = ""


SETTINGS: tuple[Setting, ...] = (
    Setting("operator.handle", "", "str",
            "who the reports say ran the hunt (a name, or your platform handle)",
            ask="Operator handle (blank is fine)"),
    Setting("bot", "tinygpt", "bot",
            "which bot is live — it answers chat and plans the hunt. `gn bot ls` lists them; "
            "`gn bot use <name>` is how this is set (it checks the bot exists first)",
            choices=BOTS, ask="Bot"),
    Setting("learning", True, "bool",
            "keep learning automatically from every hunt (the trace corpus, negative knowledge, "
            "the surface baseline, the auto-trainer); off writes none of them and stops a hunt "
            "consulting the negative-knowledge memory. An explicit `gn learn` or `gn train-brain` "
            "is an instruction, not automatic learning, and still runs",
            ask="Learning on"),
    Setting("hunt.profile", "full-sweep", "choice",
            "the hunt profile a run uses when -p says nothing",
            choices=HUNT_PROFILES, ask="Default hunt profile"),
    Setting("hunt.active", False, "bool",
            "arm active verification by default — benign GET/HEAD/OPTIONS proof probes, "
            "scope-bound and rate-limited (--active per run either way)",
            ask="Arm active verification by default"),
    Setting("hunt.brain", False, "bool",
            "let the brain enrich findings by default (deterministic when off)"),
    Setting("hunt.prompt", True, "bool",
            "ask at the terminal when a hunt reaches a login wall and needs a session"),
    Setting("hunt.per_finding", False, "bool",
            "also write one submission-ready file per finding"),
    Setting("output.dir", "", "path",
            "where reports go when -o says nothing (blank = runtime/reports)",
            ask="Report folder (blank = runtime/reports)"),
    Setting("platform", "hackerone", "choice",
            "the submission shape reports are written for", choices=PLATFORMS),
)

_BY_KEY = {setting.key: setting for setting in SETTINGS}


def settings_table() -> tuple[Setting, ...]:
    return SETTINGS


def setting(key: str) -> Setting | None:
    return _BY_KEY.get(str(key or "").strip().lower())


def defaults() -> dict[str, Any]:
    return {item.key: item.default for item in SETTINGS}


@dataclass(frozen=True)
class Profile:
    """What the operator decided, plus where it came from.

    ``values`` holds ONLY what was explicitly set, so :meth:`get` can say whether an answer is the
    operator's or this file's default — which is the difference between "they chose tinygpt" and
    "nobody has said". ``gn settings`` prints that distinction, and :func:`save` writes only the
    chosen half, so a default that changes in a later version reaches an existing profile instead
    of being frozen into it by a first run.
    """

    values: dict[str, Any] = field(default_factory=dict)
    output_paths: dict[str, str] = field(default_factory=dict)
    exists: bool = False
    created_at: str = ""
    path: str = ""
    #: Set when a profile WAS there but could not be read. The caller keeps working on defaults
    #: and says this, rather than silently presenting them as the operator's own choices.
    error: str = ""

    def get(self, key: str) -> Any:
        name = str(key or "").strip().lower()
        if name in self.values:
            return self.values[name]
        item = _BY_KEY.get(name)
        return item.default if item else None

    def chosen(self, key: str) -> bool:
        """Whether this came from the operator rather than from :func:`defaults`."""
        return str(key or "").strip().lower() in self.values

    def source(self, key: str) -> str:
        return "profile" if self.chosen(key) else "default"

    def all(self) -> dict[str, Any]:
        merged = defaults()
        merged.update({k: v for k, v in self.values.items() if k in _BY_KEY})
        return merged


def profile_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / PROFILE_FILE


def load(runtime_dir: str | Path) -> Profile:
    """Read the profile. Total: anything unreadable or malformed comes back as the defaults."""
    path = profile_path(runtime_dir)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return Profile(path=str(path))
    except (ValueError, RecursionError) as exc:
        # This function's contract is that ANYTHING unreadable comes back as the defaults, and
        # ``read_text`` raises UnicodeDecodeError — a ValueError, not an OSError — for a file that
        # is not UTF-8. On this project's primary platform that is the ordinary result of editing
        # the profile with PowerShell's `Out-File` or Notepad's "Save as Unicode", both of which
        # write UTF-16. Every verb loads the profile through ``_from_profile``, so an uncaught one
        # did not cost the operator their settings — it stopped the hunt.
        return Profile(path=str(path), exists=True,
                       error=f"{path.name} is not UTF-8 text ({type(exc).__name__}); "
                             f"using defaults")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return Profile(path=str(path), exists=True,
                       error=f"{path.name} is not valid JSON ({exc.msg}); using defaults")
    except RecursionError:
        return Profile(path=str(path), exists=True,
                       error=f"{path.name} is nested too deeply to read; using defaults")
    if not isinstance(doc, dict):
        return Profile(path=str(path), exists=True,
                       error=f"{path.name} is not a JSON object; using defaults")
    stored = doc.get("settings")
    stored = stored if isinstance(stored, dict) else {}
    values: dict[str, Any] = {}
    refused: list[str] = []
    for key, value in stored.items():
        item = _BY_KEY.get(str(key).strip().lower())
        if item is None:
            # An unknown key is kept OUT of the live values and out of the way: it may be a typo,
            # or a setting a newer build wrote. Either way nothing here should act on it.
            continue
        coerced, error = coerce(item, value)
        if error:
            # REPORTED, not just dropped. A hand-edited `"hunt.active": "maybe"` would otherwise
            # present the default as an ordinary default, so an operator who meant to arm active
            # probing would be told nothing and get a passive run.
            refused.append(error)
            continue
        values[item.key] = coerced
    paths = doc.get("output_paths")
    paths = paths if isinstance(paths, dict) else {}
    outputs = {str(k): str(v) for k, v in paths.items()
               if isinstance(k, str) and isinstance(v, str) and _LABEL.match(k) and v.strip()}
    note = ""
    if refused:
        shown = "; ".join(refused[:3])
        extra = f" (+{len(refused) - 3} more)" if len(refused) > 3 else ""
        note = f"{path.name}: {shown}{extra} — using the default for those"
    return Profile(values=values, output_paths=outputs, exists=True, error=note,
                   created_at=str(doc.get("created_at") or ""), path=str(path))


def save(runtime_dir: str | Path, profile: Profile) -> tuple[Profile, str]:
    """Write the profile. Returns ``(saved profile, error)``; the error is a sentence for ``_err``.

    Only the chosen half is written (see :class:`Profile`), the file is replaced atomically so a
    killed write cannot leave a half-written settings file behind, and the mode is 0600 because a
    profile carries an operator handle and local paths.
    """
    path = profile_path(runtime_dir)
    created = profile.created_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "version": VERSION,
        "created_at": created,
        "updated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "settings": {key: profile.values[key] for key in sorted(profile.values) if key in _BY_KEY},
        "output_paths": {key: profile.output_paths[key] for key in sorted(profile.output_paths)},
    }
    temporary = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass            # a filesystem without modes is not a reason to lose the settings
        os.replace(temporary, path)
    except OSError as exc:
        return (profile, f"could not write {path}: {exc}")
    return (replace(profile, exists=True, created_at=created, path=str(path)), "")


def coerce(item: Setting, value: Any) -> tuple[Any, str]:
    """One value as the setting's own type, or an error naming what was expected."""
    if item.kind == "bool":
        if isinstance(value, bool):
            return (value, "")
        text = str(value).strip().lower()
        if text in _TRUE:
            return (True, "")
        if text in _FALSE:
            return (False, "")
        return (None, f"{item.key} is on or off — got {value!r}")
    text = "" if value is None else str(value).strip()
    if item.kind == "bot":
        # SHAPE only — see _BOT_NAME. A name that is well-formed but names no bot is kept and
        # reported by whoever resolves it (``gn_bots.resolve`` returns the default plus a sentence
        # saying the configured bot is not in the store), because the alternative is a profile that
        # silently drops the operator's custom bot the first time this file is re-read.
        low = text.lower()
        if not low:
            return (None, f"{item.key} is a bot name — `gn bot ls` lists them")
        if not _BOT_NAME.fullmatch(low):
            return (None, f"{item.key} is a bot name: lowercase letters, digits, dot, dash or "
                          f"underscore, up to 32 characters — got {value!r}")
        return (low, "")
    if item.kind == "choice":
        low = text.lower()
        if low not in item.choices:
            return (None, f"{item.key} is one of: {', '.join(item.choices)} — got {value!r}")
        return (low, "")
    if item.kind == "path":
        if not text:
            return ("", "")
        try:
            return (str(Path(text).expanduser()), "")
        except (OSError, ValueError, RuntimeError):
            return (None, f"{item.key} is not a usable path: {value!r}")
    if len(text) > 200:
        return (None, f"{item.key} is at most 200 characters")
    if any(ch in text for ch in "\r\n\t"):
        return (None, f"{item.key} cannot contain line breaks or tabs")
    return (text, "")


def set_value(profile: Profile, key: str, value: Any) -> tuple[Profile, str]:
    """Set one setting. Returns ``(profile, error)``; an unknown key is refused, never stored.

    Refusing is the point: a settings file that accepts anything is a settings file where
    ``authorize = true`` looks like it did something. See this module's docstring.
    """
    name = str(key or "").strip().lower()
    item = _BY_KEY.get(name)
    if item is None:
        return (profile, f"no setting called {key!r}. `gn settings` lists them.")
    coerced, error = coerce(item, value)
    if error:
        return (profile, error)
    values = dict(profile.values)
    values[name] = coerced
    return (replace(profile, values=values), "")


def unset(profile: Profile, key: str) -> tuple[Profile, str]:
    """Drop one setting back to its default."""
    name = str(key or "").strip().lower()
    if name not in _BY_KEY:
        return (profile, f"no setting called {key!r}. `gn settings` lists them.")
    values = dict(profile.values)
    values.pop(name, None)
    return (replace(profile, values=values), "")


# --- the output folder ----------------------------------------------------------------------------
def output_label(value: str) -> str:
    """The key a target or campaign name becomes in ``output_paths``.

    A URL is reduced to its host, so ``gn output -s https://acme.example/app`` and ``-s
    acme.example`` name the same folder — an operator who types the target they hunt should not
    end up with two entries and a report in whichever one they typed that day.
    """
    text = str(value or "").strip().strip("\"'")
    if not text:
        return ""
    if "://" in text:
        from urllib.parse import urlparse

        try:
            host = urlparse(text).hostname or ""
        except ValueError:
            host = ""
        text = host or text
    text = text.rstrip("/").lower()
    return text if _LABEL.match(text) else ""


def set_output(profile: Profile, label: str, path: str) -> tuple[Profile, str]:
    """Point one target, program or campaign at its own report folder.

    An empty ``label`` sets the DEFAULT folder (``output.dir``) instead, which is what ``gn output
    --path`` with no ``-s`` means. The path is stored expanded but NOT created: the folder is made
    when a report is written (``_ensure_dir``), so a typo costs a report in the wrong place rather
    than an empty tree somewhere the operator did not look.
    """
    text = str(path or "").strip().strip("\"'")
    if not text:
        return (profile, "give a folder: `gn output -s <target> --path <folder>`.")
    try:
        resolved = str(Path(text).expanduser())
    except (OSError, ValueError, RuntimeError):
        return (profile, f"not a usable folder: {path!r}")
    if not label:
        return set_value(profile, "output.dir", resolved)
    key = output_label(label)
    if not key:
        return (profile, f"{label!r} is not a target, program or campaign name.")
    paths = dict(profile.output_paths)
    paths[key] = resolved
    return (replace(profile, output_paths=paths), "")


def clear_output(profile: Profile, label: str) -> tuple[Profile, str]:
    key = output_label(label)
    if not key:
        return (profile, f"{label!r} is not a target, program or campaign name.")
    if key not in profile.output_paths:
        return (profile, f"nothing was set for {key}.")
    paths = dict(profile.output_paths)
    paths.pop(key, None)
    return (replace(profile, output_paths=paths), "")


def output_dir_for(profile: Profile, *labels: str) -> str:
    """The folder reports for these targets go in: the most specific match, else the default.

    Checked in the order given, so a caller passes the narrowest label first (the target, then its
    program or campaign). Returns ``""`` for "nothing was set", which leaves the caller on
    ``runtime/reports`` — this never invents a path.
    """
    for label in labels:
        key = output_label(label)
        if key and key in profile.output_paths:
            return profile.output_paths[key]
        # A target also answers to its registrable domain, so `-s acme.example` covers
        # app.acme.example without an entry per subdomain.
        while key and "." in key:
            key = key.split(".", 1)[1]
            if key in profile.output_paths:
                return profile.output_paths[key]
    return str(profile.get("output.dir") or "")


# --- rendering ------------------------------------------------------------------------------------
def show(value: Any) -> str:
    """One value as the operator typed it, or would type it."""
    if isinstance(value, bool):
        return "on" if value else "off"
    text = str(value if value is not None else "")
    return text if text else "(blank)"


def settings_lines(profile: Profile) -> list[str]:
    """``gn settings`` — every setting, its value, where that value came from, and what it does."""
    width = max(len(item.key) for item in SETTINGS)
    lines = [f"settings  {profile.path or '(not written yet)'}"]
    if not profile.exists:
        lines.append("  no profile yet — these are the defaults. `gn setup` writes one.")
    if profile.error:
        lines.append(f"  {profile.error}")
    lines.append("")
    for item in SETTINGS:
        value = profile.get(item.key)
        mark = "*" if profile.chosen(item.key) else " "
        lines.append(f" {mark} {item.key.ljust(width)}  {show(value)}")
        lines.append(f"   {' ' * width}  {item.help}")
    lines.append("")
    lines.append(" * = set by you; everything else is the default.")
    if profile.output_paths:
        lines.append("")
        lines.append(" report folders")
        for key in sorted(profile.output_paths):
            lines.append(f"   {key}  ->  {profile.output_paths[key]}")
    return lines


def command_lines() -> list[str]:
    """The commands that change any of the above. Printed under ``gn settings``."""
    return [
        "",
        " commands",
        "   gn setup                        walk through the first-run questions (--defaults to skip)",
        "   gn settings                     this list",
        "   gn settings get <key>           one value",
        "   gn settings set <key> <value>   set it and save",
        "   gn settings unset <key>         back to the default",
        "   gn settings path                where the profile is written",
        "   gn output                       the report folders",
        "   gn output --path <folder>       the default report folder",
        "   gn output -s <target> --path <folder>",
        "                                   that target, program or campaign only",
        "   gn output -s <target> --clear   drop that one",
    ]


def setup_questions() -> tuple[Setting, ...]:
    """The settings ``gn setup`` asks about, in order."""
    return tuple(item for item in SETTINGS if item.ask)


def summary_lines(profile: Profile) -> list[str]:
    """The one-screen "this is your posture" block, after setup and at the top of `gn settings -v`."""
    return [f"   {item.key}: {show(profile.get(item.key))}" for item in setup_questions()]


def first_run_hint(profile: Profile) -> str:
    """One line for a verb to print when there is no profile yet, or ``""``.

    Deliberately a hint, not a gate: a CLI that refuses to work until a wizard has been answered
    is one that cannot be driven from a script, a CI job or a fresh container — and the defaults
    here are the ones a new operator would pick anyway.
    """
    if profile.exists:
        return profile.error
    return "no operator profile yet — using defaults. `gn setup` writes one (`gn settings` lists them)."


def apply_sequence(profile: Profile, pairs: Sequence[tuple[str, Any]]) -> tuple[Profile, list[str]]:
    """Set several values, collecting the refusals rather than stopping at the first."""
    errors: list[str] = []
    for key, value in pairs:
        profile, error = set_value(profile, key, value)
        if error:
            errors.append(error)
    return (profile, errors)
