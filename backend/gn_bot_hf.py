"""Plug a Hugging Face bot in: ``gn bot hf <ref>`` and the studio's ``/bot hf``.

The Hub hosts two completely different things an operator calls "a bot", and the whole point of this
module is that they do NOT get the same treatment:

  * **A GGUF model repository** is weights. It is imported into the local Ollama — Ollama's own
    ``hf.co/`` registry pull first, falling back to :mod:`hf_gguf_import`'s verified split-GGUF
    import when the repository is sharded — then PROBED for chat and tool calls, and only then
    registered as a RUNNABLE bot (provider ``local``, model = the Ollama alias). It runs on this
    machine, needs no key, and sends nothing off it.
  * **An agent repository** (a Space, or a repo with ``agent.json``) is somebody else's Python and
    somebody else's prompts. It is cloned by :mod:`hf_agent_clone` at a pinned, digest-verified
    commit and registered as an **inert** bot: ``gn_bots.coder_overlay`` returns nothing for it, it
    cannot be made a brain, and nothing cloned is ever imported or executed. The clone's prose is
    untrusted data and reaches the coding agent only through ``skills``' untrusted-data fence.

WHICH ONE A REFERENCE IS
------------------------
Decided by what the Hub actually serves, not by what the operator typed: a ``spaces/`` reference is
an agent, ``--agent`` and ``--model`` are explicit, and anything else is probed for GGUF weights
(``coder.check_public_hf_gguf``). A model repository with no GGUF file falls through to the agent
clone with a line saying that is what happened — the alternative is refusing a perfectly good
smolagents repo because it was typed without a prefix.

WHAT THIS WILL NOT DO
---------------------
* **It will not import weights over a non-loopback Ollama.** ``hf_gguf_import`` refuses it, and the
  pull path is the operator's own configured local endpoint.
* **It will not select a model that failed its probe.** A model that cannot hold a chat turn is
  registered and reported as ``needs a model``/not ready rather than silently made live, and a
  chat-capable model that fails the tool-call probe is registered with that said plainly — the
  Workbench agent needs tool calls and the hunt planner needs structured output.
* **It will not fetch anything on a ``--json`` listing or a repaint.** Every network call here is
  behind an explicit ``gn bot hf`` / ``/bot hf``.

Stdlib only (plus this project's own ``coder``, ``gn_bots``, ``hf_*`` modules), and imported LAZILY
by ``gn_bots._cmd_bot_hf`` so the CLI's boot path stays import-light.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

import gn_bots

Progress = Callable[[str], None]

#: Ollama's pull of a many-gigabyte model is not a 120-second request.
_PULL_TIMEOUT = 3600.0
#: The cache the verified split-GGUF importer stages shards in, inside the runtime directory.
_CACHE_DIRNAME = "hf-gguf-cache"


def _noop(_message: str) -> None:
    return None


def _runtime_config(runtime_dir: Path) -> dict[str, Any]:
    try:
        doc = json.loads((Path(runtime_dir) / "solin_runtime_config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def ollama_endpoint(runtime_dir: Path) -> tuple[str, str]:
    """``(native host, OpenAI-compatible base URL)`` for the operator's own local endpoint.

    Read from the same ``coder.local.base_url`` the desktop app writes, so an operator who moved
    Ollama off the default port gets their own, and falls back to the shipped default otherwise.
    """
    import coder

    config = _runtime_config(runtime_dir)
    block = config.get("coder") if isinstance(config.get("coder"), dict) else {}
    local = block.get("local") if isinstance(block.get("local"), dict) else {}
    base = str(local.get("base_url") or "").strip() or str(
        coder.CODER_DEFAULTS["local"]["base_url"])
    # Validated the way ``greyiq_api``'s model-setup worker validates it — scheme http(s), a real
    # host, no userinfo, no query or fragment, path at most "/" — rather than taken on trust from
    # a file. It raises CoderError, which both callers already print as a sentence.
    return (coder.ollama_setup_host(base), base)


def looks_like_agent(reference: str) -> bool:
    """Whether a reference NAMES a Space, which is only ever an agent repository."""
    text = str(reference or "").strip().lower()
    for prefix in ("https://", "http://", "hf.co/", "huggingface.co/"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = text.removeprefix("huggingface.co/").removeprefix("hf.co/")
    return text.startswith("spaces/")


def plug_model(runtime_dir: Path | str, reference: str, *, alias: str = "",
               progress: Progress = _noop) -> dict[str, Any]:
    """Import a Hugging Face GGUF repository into local Ollama and register it as a bot.

    Mirrors ``greyiq_api``'s model-setup worker, which is the path that is actually exercised against
    the Hub: normalise, confirm the repository is public and has GGUF weights, pull through Ollama's
    own ``hf.co/`` registry, fall back to the verified split-GGUF importer when Ollama reports a
    sharded repository, then probe chat and tool calls before saying a word about readiness.

    Returns a result dict. Raises ``coder.CoderError`` for a refusal worth showing the operator.
    """
    import coder

    runtime = Path(runtime_dir)
    target = coder.normalize_huggingface_model_ref(_hf_prefixed(reference))
    host, base_url = ollama_endpoint(runtime)
    progress(f"checking {target}")
    coder.check_public_hf_gguf(target)
    installed = coder.ollama_list_models(host)
    selected = target
    if coder.model_installed(installed, selected):
        progress("already installed")
    else:
        progress("downloading the weights (this is the long part)")
        try:
            coder.ollama_pull(host, target, timeout=_PULL_TIMEOUT,
                              progress_cb=lambda event: progress(_pull_line(event)))
        except coder.CoderError as exc:
            if "sharded gguf" not in str(exc).casefold():
                raise
            progress("sharded repository — importing each verified shard")
            selected = _import_sharded(host, target, runtime, progress)
        if not coder.model_installed(coder.ollama_list_models(host), selected):
            raise coder.CoderError(
                "Ollama reported success, but the model is absent from its installed list.")
    progress("probing chat and tool calls")
    readiness = coder.ollama_probe_readiness(host, selected)
    chat_ok = bool(readiness.get("chat_ready"))
    tool_ok = bool(readiness.get("tool_ready"))
    name = str(alias or "").strip() or selected.rsplit("/", 1)[-1].split(":", 1)[0]
    identifier = gn_bots.bot_id(name) or gn_bots.bot_id(selected.rsplit("/", 1)[-1]) or "hf-model"
    bot = gn_bots.Bot(
        id=identifier,
        name=name[:60],
        provider="local",
        model=selected,
        base_url=base_url,
        source="huggingface",
        origin={"repo": target.removeprefix("hf.co/"), "kind": "gguf", "alias": selected},
        notes=_model_note(chat_ok, tool_ok, readiness),
    )
    registry, stored, error = gn_bots.register(gn_bots.load(runtime), bot)
    if error:
        raise coder.CoderError(error)
    registry, save_error = gn_bots.save(runtime, registry)
    if save_error:
        raise coder.CoderError(save_error)
    return {
        "kind": "model",
        "bot": stored.id,
        "model": selected,
        "repo": target,
        "chat_ready": chat_ok,
        "tool_ready": tool_ok,
        "reason": str(readiness.get("reason") or ""),
        "runnable": chat_ok,
    }


def _hf_prefixed(reference: str) -> str:
    """``owner/repo`` as ``hf.co/owner/repo``, leaving a URL or an already-prefixed ref alone.

    ``normalize_huggingface_model_ref`` deliberately accepts only a URL or an ``hf.co/`` reference,
    because in the desktop app's model field a bare ``owner/repo`` could be an Ollama library name.
    Here the verb is ``bot hf``, so the operator has already said which registry they mean.
    """
    text = str(reference or "").strip()
    if not text or "://" in text or text.lower().startswith(("hf.co/", "huggingface.co/")):
        return text
    return f"hf.co/{text}"


def _pull_line(event: Any) -> str:
    if not isinstance(event, dict):
        return "downloading"
    status = str(event.get("status") or "downloading")
    total = int(event.get("total") or 0)
    done = int(event.get("completed") or 0)
    if total > 0:
        return f"{status} {min(100, int(done * 100 / total))}%"
    return status


def _import_sharded(host: str, target: str, runtime: Path, progress: Progress) -> str:
    import hf_gguf_import

    return hf_gguf_import.import_sharded_hf_model(
        host, target, runtime / _CACHE_DIRNAME,
        lambda event: progress(_pull_line(event)),
    )


def _model_note(chat_ok: bool, tool_ok: bool, readiness: dict[str, Any]) -> str:
    """What this model can actually do, in the words the probe earned — never an assumption."""
    if not chat_ok:
        return f"imported but failed the chat probe: {str(readiness.get('reason') or 'no reason given')}"
    if not tool_ok:
        return ("chat only — it failed the tool-call probe, so the Workbench agent and the hunt "
                "planner cannot use it")
    return "imported from Hugging Face; passed the chat and tool-call probes"


def plug_agent(runtime_dir: Path | str, reference: str, *, alias: str = "",
               progress: Progress = _noop) -> dict[str, Any]:
    """Clone a Hugging Face agent at a pinned, verified commit and register it as an INERT bot.

    The clone itself is :mod:`hf_agent_clone`'s work, including every safety rule that makes cloning
    a stranger's agent survivable. This adds only the registry entry, so a cloned agent appears in
    ``gn bot ls`` beside the bots that can answer — with ``inert`` on the row, which is the one thing
    an operator could otherwise misread here.
    """
    import hf_agent_clone

    runtime = Path(runtime_dir)
    manifest = hf_agent_clone.clone_agent(runtime, reference, alias=alias or None,
                                          progress=progress)
    origin = manifest.get("origin") if isinstance(manifest.get("origin"), dict) else {}
    slug = str(manifest.get("slug") or "")
    tools = manifest.get("tools") if isinstance(manifest.get("tools"), list) else []
    bot = gn_bots.Bot(
        id=gn_bots.bot_id(slug) or "hf-agent",
        name=str(manifest.get("name") or slug)[:60],
        provider="off",
        source="clone",
        inert=True,
        origin={"repo": str(origin.get("repo_id") or ""),
                "revision": str(origin.get("revision") or "")[:12],
                "kind": str(manifest.get("layout") or "agent"),
                "path": str(manifest.get("path") or "")},
        notes=f"cloned agent · {len(tools)} tool(s) · inert (never imported or executed)",
    )
    registry, stored, error = gn_bots.register(gn_bots.load(runtime), bot)
    if error:
        raise hf_agent_clone.AgentCloneError(error)
    registry, save_error = gn_bots.save(runtime, registry)
    if save_error:
        raise hf_agent_clone.AgentCloneError(save_error)
    return {
        "kind": "agent",
        "bot": stored.id,
        "repo": str(origin.get("repo_id") or ""),
        "revision": str(origin.get("revision") or ""),
        "tools": len(tools),
        "path": str(manifest.get("path") or ""),
        "runnable": False,
    }


def plug(runtime_dir: Path | str, reference: str, *, alias: str = "", as_agent: bool = False,
         as_model: bool = False, progress: Progress = _noop) -> dict[str, Any]:
    """Plug in whichever kind of bot this reference actually is. See the module docstring.

    Raises the underlying module's error (``coder.CoderError`` / ``AgentCloneError``) — both carry a
    sentence written for an operator, so the callers print them as-is.
    """
    import coder

    text = str(reference or "").strip()
    if not text:
        raise coder.CoderError("Which Hugging Face repository? e.g. "
                               "`gn bot hf unsloth/Qwen2.5-Coder-7B-Instruct-GGUF`.")
    if as_agent and as_model:
        raise coder.CoderError("--agent and --model are opposites; pass one or neither.")
    if as_agent or (looks_like_agent(text) and not as_model):
        return plug_agent(runtime_dir, text, alias=alias, progress=progress)
    try:
        return plug_model(runtime_dir, text, alias=alias, progress=progress)
    except coder.CoderError as exc:
        detail = str(exc)
        if as_model or "no GGUF model file" not in detail:
            raise
        # A models repo with no GGUF is the normal shape of a smolagents agent. Say that this is
        # what happened rather than refusing something the operator can legitimately clone.
        progress("no GGUF weights there — cloning it as an inert agent instead")
        result = plug_agent(runtime_dir, text, alias=alias, progress=progress)
        result["fell_back"] = "the repository has no GGUF weights, so it was cloned as an agent"
        return result


# --- the CLI half ---------------------------------------------------------------------------------
def cmd_plug(args: Any, *, runtime_dir: Path) -> int:
    """``gn bot hf`` — called by ``gn_bots._cmd_bot_hf``."""
    import coder
    import hf_agent_clone

    as_json = bool(getattr(args, "json", False))
    progress: Progress = _noop if as_json else (lambda message: print(f"  {message}"))
    try:
        result = plug(runtime_dir, str(getattr(args, "reference", "") or ""),
                      alias=str(getattr(args, "alias", "") or ""),
                      as_agent=bool(getattr(args, "agent", False)),
                      as_model=bool(getattr(args, "as_model", False)),
                      progress=progress)
    except (coder.CoderError, hf_agent_clone.AgentCloneError) as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail(f"the import could not write to disk: {exc}")
    if bool(getattr(args, "use", False)) and result.get("runnable"):
        bot, error = gn_bots.set_active(runtime_dir, str(result.get("bot") or ""))
        result["active"] = bool(bot)
        if bot is None:
            result["active_error"] = error
    if as_json:
        print(json.dumps(result, indent=2))
        return 0
    for line in report_lines(result):
        print(line)
    return 0


def report_lines(result: dict[str, Any]) -> list[str]:
    """What landed, in the words the probe and the clone earned. Pure, so the studio reuses it."""
    bot = str(result.get("bot") or "?")
    if result.get("fell_back"):
        lines = [str(result["fell_back"])]
    else:
        lines = []
    if str(result.get("kind")) == "model":
        lines.append(f"plugged in {bot}  (local · {result.get('model')})")
        if not result.get("chat_ready"):
            lines.append(f"  it failed the chat probe: {result.get('reason') or 'no reason given'}")
            lines.append("  it is in the store, but nothing should be pointed at it yet")
        elif not result.get("tool_ready"):
            lines.append("  chat only: it failed the tool-call probe, so the Workbench agent and "
                         "the hunt planner cannot use it")
        else:
            lines.append("  it passed the chat and tool-call probes")
    else:
        lines.append(f"cloned {bot}  ({result.get('repo')}@{str(result.get('revision') or '')[:12]}"
                     f" · {result.get('tools')} tool(s))")
        lines.append("  inert: nothing cloned is ever imported or executed, so it cannot be a brain")
        if result.get("path"):
            lines.append(f"  {result['path']}")
    if result.get("active"):
        lines.append(f"  {bot} is live")
    elif result.get("active_error"):
        lines.append(f"  it is not live: {result['active_error']}")
    elif result.get("runnable"):
        lines.append(f"  `gn bot use {bot}` makes it live")
    return lines


def _fail(message: str) -> int:
    print(f"gn: {message}", file=sys.stderr)
    return 2
