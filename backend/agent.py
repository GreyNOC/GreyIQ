"""GreyIQ coding agent — a plan -> act -> verify loop over a workspace folder.

Phase 2 of the coding bot. The brain (see coder.py) gains hands: it can read,
search, write, and edit files inside a chosen workspace, and (when enabled) run
shell commands there. Works with both Claude (native tool use) and local
Ollama / OpenAI-compatible models (OpenAI tool-calling).

Safety:
  - Every file path is resolved and confined to the workspace root (no traversal).
  - run_command is gated by `agent.allow_commands` (default off), runs in the
    workspace with a timeout, and its output is captured (never a live shell).
  - The loop is capped at `agent.max_steps` iterations.
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import coder

AGENT_DEFAULTS: dict[str, Any] = {
    "allow_commands": False,
    "max_steps": 25,
    "command_timeout_s": 60.0,
    "max_file_bytes": 100_000,
    "max_tool_output": 8_000,
}

AGENT_SYSTEM_PROMPT = (
    "You are GreyIQ, an autonomous coding agent working inside a fixed workspace "
    "folder. Use the provided tools to read, search, edit, and create files, and "
    "to run commands when that is enabled. Work in small, verifiable steps: look "
    "before you edit, make the change, then verify (re-read the file or run a "
    "test/command). All paths are relative to the workspace root. When the task is "
    "done, stop calling tools and give a short summary of what you changed and how "
    "you verified it. If something is ambiguous or risky, explain it instead of "
    "guessing."
)

# Tool definitions (provider-neutral JSON schema). Wrapped per provider below.
_TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_dir",
        "description": "List files and folders under a path in the workspace.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Relative path; defaults to '.'"}},
            "required": [],
        },
    },
    {
        "name": "read_file",
        "description": "Read a UTF-8 text file in the workspace.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Relative file path"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Create or overwrite a text file in the workspace with the given content.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "edit_file",
        "description": "Replace an exact, unique substring in a file. Fails if old_string is missing or not unique.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "old_string": {"type": "string"},
                "new_string": {"type": "string"},
            },
            "required": ["path", "old_string", "new_string"],
        },
    },
    {
        "name": "grep",
        "description": "Search workspace files for a regex pattern. Returns matching 'path:line: text'.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "path": {"type": "string", "description": "Relative dir or file to search; defaults to '.'"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "run_command",
        "description": "Run a shell command in the workspace and return its output. Only available when enabled.",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
]


class AgentError(RuntimeError):
    """An agent run failed in a way worth showing the user."""


class ToolError(Exception):
    """A tool call failed; surfaced back to the model as an error result."""


def agent_settings(coder_cfg: dict[str, Any]) -> dict[str, Any]:
    merged = dict(AGENT_DEFAULTS)
    raw = coder_cfg.get("agent") if isinstance(coder_cfg, dict) else None
    if isinstance(raw, dict):
        merged.update(raw)
    return merged


class ToolBox:
    """Workspace-confined file/command tools."""

    def __init__(self, root: Path, settings: dict[str, Any]) -> None:
        self.root = root.resolve()
        self.allow_commands = bool(settings.get("allow_commands", False))
        self.command_timeout = float(settings.get("command_timeout_s", 60.0))
        self.max_file_bytes = int(settings.get("max_file_bytes", 100_000))
        self.max_output = int(settings.get("max_tool_output", 8_000))

    def _resolve(self, rel_path: str) -> Path:
        candidate = (self.root / str(rel_path or ".")).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ToolError(f"Path '{rel_path}' is outside the workspace.")
        return candidate

    def _truncate(self, text: str) -> str:
        if len(text) > self.max_output:
            return text[: self.max_output] + f"\n... [truncated, {len(text)} chars total]"
        return text

    def run(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        """Returns (output, is_error)."""
        try:
            handler = getattr(self, f"_tool_{name}", None)
            if handler is None:
                raise ToolError(f"Unknown tool: {name}")
            return self._truncate(handler(args or {})), False
        except ToolError as exc:
            return f"Error: {exc}", True
        except Exception as exc:  # noqa: BLE001 - reported back to the model
            return f"Error: {type(exc).__name__}: {exc}", True

    def _tool_list_dir(self, args: dict[str, Any]) -> str:
        target = self._resolve(args.get("path", "."))
        if not target.exists():
            raise ToolError(f"No such path: {args.get('path', '.')}")
        if target.is_file():
            return f"{target.relative_to(self.root)} (file, {target.stat().st_size} bytes)"
        entries = []
        for child in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            rel = child.relative_to(self.root).as_posix()
            entries.append(f"{rel}/" if child.is_dir() else rel)
        return "\n".join(entries) if entries else "(empty)"

    def _tool_read_file(self, args: dict[str, Any]) -> str:
        target = self._resolve(args["path"])
        if not target.is_file():
            raise ToolError(f"Not a file: {args['path']}")
        if target.stat().st_size > self.max_file_bytes:
            raise ToolError(
                f"File is {target.stat().st_size} bytes (> {self.max_file_bytes}); read a smaller file or grep it."
            )
        return target.read_text(encoding="utf-8", errors="replace")

    def _tool_write_file(self, args: dict[str, Any]) -> str:
        target = self._resolve(args["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        content = str(args.get("content", ""))
        target.write_text(content, encoding="utf-8")
        return f"Wrote {len(content)} chars to {target.relative_to(self.root).as_posix()}"

    def _tool_edit_file(self, args: dict[str, Any]) -> str:
        target = self._resolve(args["path"])
        if not target.is_file():
            raise ToolError(f"Not a file: {args['path']}")
        old = str(args.get("old_string", ""))
        new = str(args.get("new_string", ""))
        if not old:
            raise ToolError("old_string must not be empty.")
        text = target.read_text(encoding="utf-8", errors="replace")
        count = text.count(old)
        if count == 0:
            raise ToolError("old_string was not found in the file.")
        if count > 1:
            raise ToolError(f"old_string is not unique ({count} matches); include more context.")
        target.write_text(text.replace(old, new, 1), encoding="utf-8")
        return f"Edited {target.relative_to(self.root).as_posix()}"

    def _tool_grep(self, args: dict[str, Any]) -> str:
        try:
            regex = re.compile(str(args["pattern"]))
        except re.error as exc:
            raise ToolError(f"Invalid regex: {exc}") from exc
        base = self._resolve(args.get("path", "."))
        files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        hits: list[str] = []
        for path in files:
            if any(part in {".git", "node_modules", "__pycache__"} for part in path.parts):
                continue
            try:
                if path.stat().st_size > self.max_file_bytes:
                    continue
                for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if regex.search(line):
                        hits.append(f"{path.relative_to(self.root).as_posix()}:{lineno}: {line.strip()[:200]}")
                        if len(hits) >= 200:
                            return "\n".join(hits) + "\n... [200-match limit]"
            except OSError:
                continue
        return "\n".join(hits) if hits else "(no matches)"

    def _tool_run_command(self, args: dict[str, Any]) -> str:
        if not self.allow_commands:
            raise ToolError(
                "Running commands is disabled. Enable 'Allow commands' in the agent settings to use run_command."
            )
        command = str(args.get("command", "")).strip()
        if not command:
            raise ToolError("command must not be empty.")
        try:
            proc = subprocess.run(  # noqa: S602 - intentional, workspace-scoped, user-enabled
                command,
                shell=True,
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
            )
        except subprocess.TimeoutExpired:
            raise ToolError(f"Command timed out after {self.command_timeout:.0f}s.") from None
        out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        return f"exit={proc.returncode}\n{out.strip()}"


def _anthropic_tools() -> list[dict[str, Any]]:
    return [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in _TOOLS]


def _openai_tools() -> list[dict[str, Any]]:
    return [
        {"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}}
        for t in _TOOLS
    ]


def run_agent(
    message: str,
    history: list[dict[str, str]],
    workspace: str,
    coder_cfg: dict[str, Any],
) -> dict[str, Any]:
    """Run the agent loop. Returns {text, transcript, steps, model, provider}."""
    root = Path(str(workspace or "")).expanduser()
    if not str(workspace or "").strip():
        raise AgentError("Pick a workspace folder for the agent to work in.")
    if not root.exists() or not root.is_dir():
        raise AgentError(f"Workspace is not a folder: {workspace}")

    cfg = coder.coder_config(coder_cfg)
    provider = str(cfg.get("provider", "off")).strip().lower()
    settings = agent_settings(cfg)
    toolbox = ToolBox(root, settings)

    messages: list[dict[str, Any]] = []
    for turn in (history or [])[-int(cfg.get("history_turns") or 12):]:
        if isinstance(turn, dict):
            role = str(turn.get("role") or "")
            content = str(turn.get("content") or "").strip()
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": message})
    while messages and messages[0]["role"] != "user":
        messages.pop(0)

    system_prompt = f"{AGENT_SYSTEM_PROMPT}\n\nWorkspace root: {root}\nCommands enabled: {toolbox.allow_commands}"

    if provider == "anthropic":
        return _run_anthropic(messages, system_prompt, cfg, settings, toolbox)
    if provider in ("local", "openai"):
        block = cfg["local"] if provider == "local" else cfg["openai"]
        return _run_openai(messages, system_prompt, cfg, block, settings, toolbox, provider)
    raise AgentError(
        "No coding brain is configured. Set up a brain (Local model or Claude) first — the agent needs one to think."
    )


def _run_anthropic(
    messages: list[dict[str, Any]],
    system_prompt: str,
    cfg: dict[str, Any],
    settings: dict[str, Any],
    toolbox: ToolBox,
) -> dict[str, Any]:
    block = cfg["anthropic"]
    api_key = str(block.get("api_key") or "").strip()
    if not api_key:
        raise AgentError("Claude API key is not set.")
    try:
        import anthropic
    except ImportError as exc:
        raise AgentError("The 'anthropic' package is not installed in this backend.") from exc

    client = anthropic.Anthropic(api_key=api_key, timeout=float(cfg.get("timeout_s") or 120.0))
    model = str(block.get("model") or coder.DEFAULT_ANTHROPIC_MODEL)
    tools = _anthropic_tools()
    transcript: list[dict[str, Any]] = []
    max_steps = int(settings["max_steps"])

    for _ in range(max_steps):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=int(cfg.get("max_tokens") or 8192),
                system=system_prompt,
                messages=messages,
                tools=tools,
            )
        except Exception as exc:  # noqa: BLE001
            raise AgentError(f"Claude request failed: {exc}") from exc

        text = "".join(b.text for b in response.content if getattr(b, "type", "") == "text").strip()
        tool_uses = [b for b in response.content if getattr(b, "type", "") == "tool_use"]
        if response.stop_reason != "tool_use" or not tool_uses:
            return {
                "text": text or "(done)",
                "transcript": transcript,
                "steps": len(transcript),
                "model": getattr(response, "model", model),
                "provider": "anthropic",
            }

        messages.append({"role": "assistant", "content": response.content})
        results = []
        for use in tool_uses:
            output, is_error = toolbox.run(use.name, dict(use.input or {}))
            transcript.append({"tool": use.name, "input": dict(use.input or {}), "output": output, "is_error": is_error})
            results.append(
                {"type": "tool_result", "tool_use_id": use.id, "content": output, "is_error": is_error}
            )
        messages.append({"role": "user", "content": results})

    return {
        "text": "Reached the step limit before finishing. Re-run to continue.",
        "transcript": transcript,
        "steps": len(transcript),
        "model": model,
        "provider": "anthropic",
    }


def _run_openai(
    messages: list[dict[str, Any]],
    system_prompt: str,
    cfg: dict[str, Any],
    block: dict[str, Any],
    settings: dict[str, Any],
    toolbox: ToolBox,
    provider: str,
) -> dict[str, Any]:
    base_url = str(block.get("base_url") or "").strip().rstrip("/")
    model = str(block.get("model") or "").strip()
    api_key = str(block.get("api_key") or "").strip()
    label = "Ollama" if provider == "local" else provider
    if not base_url or not model:
        raise AgentError(f"{label} base URL and model must be set.")
    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    timeout = float(cfg.get("timeout_s") or 120.0)
    tools = _openai_tools()
    convo: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}, *messages]
    transcript: list[dict[str, Any]] = []
    max_steps = int(settings["max_steps"])

    def _call(payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if api_key:
            request.add_header("Authorization", f"Bearer {api_key}")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "ignore")[:400] if hasattr(exc, "read") else ""
            raise AgentError(f"{label} HTTP {exc.code}: {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise AgentError(f"Could not reach {label} at {base_url} ({exc.reason}). Is it running?") from exc
        except Exception as exc:  # noqa: BLE001
            raise AgentError(f"{label} request failed: {exc}") from exc

    for _ in range(max_steps):
        body = _call(
            {
                "model": model,
                "messages": convo,
                "tools": tools,
                "tool_choice": "auto",
                "max_tokens": int(cfg.get("max_tokens") or 8192),
                "temperature": float(cfg.get("temperature", 0.2)),
                "stream": False,
            }
        )
        try:
            choice = body["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AgentError(f"{label} returned an unexpected response shape.") from exc

        tool_calls = choice.get("tool_calls") or []
        if not tool_calls:
            return {
                "text": str(choice.get("content") or "(done)").strip(),
                "transcript": transcript,
                "steps": len(transcript),
                "model": model,
                "provider": provider,
            }

        # Echo the assistant turn (with tool_calls) then each tool result.
        convo.append({"role": "assistant", "content": choice.get("content") or "", "tool_calls": tool_calls})
        for call in tool_calls:
            fn = call.get("function") or {}
            name = str(fn.get("name") or "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
                if not isinstance(args, dict):
                    args = {}
            except json.JSONDecodeError:
                args = {}
            output, is_error = toolbox.run(name, args)
            transcript.append({"tool": name, "input": args, "output": output, "is_error": is_error})
            convo.append({"role": "tool", "tool_call_id": call.get("id"), "content": output})

    return {
        "text": "Reached the step limit before finishing. Re-run to continue.",
        "transcript": transcript,
        "steps": len(transcript),
        "model": model,
        "provider": provider,
    }
