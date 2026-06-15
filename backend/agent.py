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
import repomap
import skills as skills_lib

AGENT_DEFAULTS: dict[str, Any] = {
    "allow_commands": False,
    "max_steps": 25,
    "command_timeout_s": 60.0,
    "max_file_bytes": 100_000,
    "max_tool_output": 8_000,
    "verify_command": "",
    "skills_enabled": True,
    "repo_map": True,
}

# Auto-run verify at most this many times when the model tries to finish with
# touched-but-unverified files.
_AUTO_VERIFY_CAP = 2

# Per-file content cap for the change payload sent to the Workbench. Beyond this
# the before/after text is clipped and a *_truncated flag is set, so a huge
# generated file can't bloat the /api/agent response.
_MAX_CHANGE_CHARS = 120_000


def _clip_change(text: str | None) -> str:
    if not text:
        return ""
    if len(text) > _MAX_CHANGE_CHARS:
        return text[:_MAX_CHANGE_CHARS] + f"\n... [truncated, {len(text)} chars total]"
    return text

AGENT_SYSTEM_PROMPT = (
    "You are GreyIQ, an autonomous coding agent working inside a fixed workspace "
    "folder. Use the provided tools to read, search, edit, and create files, and "
    "to run commands when that is enabled. Work in small, verifiable steps: look "
    "before you edit, make one focused change, then call the `verify` tool. If "
    "verify reports FAILED, fix the problem and verify again — never finish with a "
    "broken file. All paths are relative to the workspace root. If playbooks are "
    "given below, follow their steps. When the task is done and verify passes, stop "
    "calling tools and give a short summary of what you changed (file:line) and the "
    "verification result. If something is ambiguous or risky, explain it instead of "
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
        "name": "find_code",
        "description": (
            "Find where something lives by relevance. Ranks whole files across the repo by how well "
            "they match your search terms (path, symbol names, and content) and returns the best files "
            "with matching lines. Use this to locate a feature/function before reading files."
        ),
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "What to find, e.g. 'login handler' or 'parse config'"}},
            "required": ["query"],
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
    {
        "name": "verify",
        "description": (
            "Check the files you have changed. Syntax-checks touched .py/.json files and, "
            "if a verify command is configured, runs it. Returns VERIFY PASSED or FAILED. "
            "Call this after edits and before finishing."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
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
        self.verify_command = str(settings.get("verify_command") or "").strip()
        self.touched: set[str] = set()  # rel paths written/edited this run
        self.verified_ok = False  # True after a passing verify; reset on any write/edit
        # Lightweight before/after capture per touched file, for the Workbench
        # Changes/diff panel. Repeated edits to one file collapse to a single
        # entry: earliest "before", latest "after".
        self.changes: list[dict[str, Any]] = []

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

    def _mark_touched(self, target: Path) -> None:
        self.touched.add(target.relative_to(self.root).as_posix())
        self.verified_ok = False

    def _safe_read(self, target: Path) -> str | None:
        if not target.is_file():
            return None
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def _record_change(self, target: Path, operation: str, before: str | None, after: str) -> None:
        rel = target.relative_to(self.root).as_posix()
        for existing in self.changes:
            if existing["path"] == rel:
                # A later edit/write to the same file: keep the original "before",
                # update "after" to the latest content.
                existing["after"] = _clip_change(after)
                existing["after_size"] = len(after)
                existing["after_truncated"] = len(after) > _MAX_CHANGE_CHARS
                return
        self.changes.append(
            {
                "path": rel,
                "operation": operation,
                "existed": before is not None,
                "before": _clip_change(before),
                "after": _clip_change(after),
                "before_size": len(before) if before is not None else 0,
                "after_size": len(after),
                "before_truncated": before is not None and len(before) > _MAX_CHANGE_CHARS,
                "after_truncated": len(after) > _MAX_CHANGE_CHARS,
            }
        )

    def _tool_write_file(self, args: dict[str, Any]) -> str:
        target = self._resolve(args["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        content = str(args.get("content", ""))
        before = self._safe_read(target)
        target.write_text(content, encoding="utf-8")
        self._mark_touched(target)
        self._record_change(target, "write_file", before, content)
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
        new_text = text.replace(old, new, 1)
        target.write_text(new_text, encoding="utf-8")
        self._mark_touched(target)
        self._record_change(target, "edit_file", text, new_text)
        return f"Edited {target.relative_to(self.root).as_posix()}"

    def change_payload(self) -> list[dict[str, Any]]:
        """The before/after change list for the Workbench Changes panel."""
        return list(self.changes)

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

    def _tool_find_code(self, args: dict[str, Any]) -> str:
        query = str(args.get("query", "")).strip()
        if not query:
            raise ToolError("query must not be empty.")
        return repomap.search_repo(self.root, query, max_bytes=self.max_file_bytes)

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

    def _tool_verify(self, args: dict[str, Any]) -> str:
        lines: list[str] = []
        failed = False
        examined = 0
        # In-process syntax checks on touched files (frozen-safe: no python/node needed).
        for rel in sorted(self.touched):
            path = self._resolve(rel)
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix not in (".py", ".json"):
                continue
            examined += 1
            try:
                if suffix == ".py":
                    compile(path.read_text(encoding="utf-8", errors="replace"), str(path), "exec")
                else:
                    json.loads(path.read_text(encoding="utf-8", errors="replace"))
                lines.append(f"OK   {rel}")
            except (SyntaxError, ValueError) as exc:
                failed = True
                lines.append(f"FAIL {rel}: {exc}")
        # Optional project verify command (runs code, so it needs commands enabled).
        if self.verify_command:
            if not self.allow_commands:
                lines.append(f"(verify command '{self.verify_command}' set, but commands are disabled — skipped)")
            else:
                try:
                    proc = subprocess.run(  # noqa: S602 - user-configured, workspace-scoped
                        self.verify_command,
                        shell=True,
                        cwd=str(self.root),
                        capture_output=True,
                        text=True,
                        timeout=self.command_timeout,
                    )
                    cmd_out = ((proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")).strip()
                    lines.append(f"$ {self.verify_command}\nexit={proc.returncode}\n{cmd_out}")
                    if proc.returncode != 0:
                        failed = True
                except subprocess.TimeoutExpired:
                    failed = True
                    lines.append(f"verify command timed out after {self.command_timeout:.0f}s")

        if examined == 0 and not self.verify_command:
            self.verified_ok = True
            return "Nothing to verify (no .py/.json files changed; set agent.verify_command to run tests)."

        self.verified_ok = not failed
        report = ("VERIFY PASSED\n" if not failed else "VERIFY FAILED\n") + "\n".join(lines)
        if failed:
            raise ToolError(report)
        return report


def _anthropic_tools() -> list[dict[str, Any]]:
    return [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in _TOOLS]


def _openai_tools() -> list[dict[str, Any]]:
    return [
        {"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}}
        for t in _TOOLS
    ]


def _auto_verify(toolbox: "ToolBox", transcript: list[dict[str, Any]], auto_verifies: int) -> str | None:
    """When the model tries to finish with touched-but-unverified files, run verify
    once. Returns continuation feedback if verification failed (so the loop keeps
    going to fix it), or None to allow the run to finish."""
    if not toolbox.touched or toolbox.verified_ok or auto_verifies >= _AUTO_VERIFY_CAP:
        return None
    output, is_error = toolbox.run("verify", {})
    transcript.append({"tool": "verify", "input": {}, "output": output, "is_error": is_error})
    if is_error:
        return f"Automated check before finishing:\n{output}\nFix these issues, then continue."
    return None


def run_agent(
    message: str,
    history: list[dict[str, str]],
    workspace: str,
    coder_cfg: dict[str, Any],
    runtime_dir: str | Path | None = None,
    seed_dir: str | Path | None = None,
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

    # Workspace goes FIRST and prominent — it must survive context limits and be
    # unmistakable. Relative paths in every tool are relative to this folder.
    system_prompt = (
        f"WORKSPACE: you are working inside this folder:\n  {root}\n"
        f"Every file path you pass to a tool is relative to this workspace. "
        f"Commands enabled: {toolbox.allow_commands}.\n\n"
        + AGENT_SYSTEM_PROMPT
    )

    # Inject matching skill playbooks so the model follows a vetted procedure.
    if settings.get("skills_enabled", True) and runtime_dir is not None and seed_dir is not None:
        try:
            available = skills_lib.load_skills(runtime_dir, seed_dir, root)
            chosen = skills_lib.select_skills(message, available)
            block = skills_lib.skills_prompt(chosen, available)
            if block:
                system_prompt += "\n\n" + block
        except Exception:  # noqa: BLE001 - skills are best-effort, never block a run
            pass

    # Inject a compact repo map so the model is oriented from step one.
    if settings.get("repo_map", True):
        try:
            repo_map = repomap.build_repo_map(root)
            if repo_map:
                system_prompt += "\n\n" + repo_map
        except Exception:  # noqa: BLE001 - best-effort, never block a run
            pass

    if provider == "anthropic":
        result = _run_anthropic(messages, system_prompt, cfg, settings, toolbox)
    elif provider in ("local", "openai"):
        block = cfg["local"] if provider == "local" else cfg["openai"]
        result = _run_tool_loop(messages, system_prompt, cfg, block, settings, toolbox, provider)
    else:
        raise AgentError(
            "No coding brain is configured. Set up a brain (Local model or Claude) first — the agent needs one to think."
        )
    # Attach change tracking (touched files + before/after) for the Workbench.
    result["changes"] = toolbox.change_payload()
    result["touched_files"] = sorted(toolbox.touched)
    return result


_TOOL_NAMES = {t["name"] for t in _TOOLS}


def _normalize_tool_calls(raw_calls: Any) -> list[dict[str, Any]]:
    """Normalize OpenAI (args = JSON string) and Ollama-native (args = dict) tool
    calls to a uniform [{id, name, arguments: dict}]."""
    normalized: list[dict[str, Any]] = []
    for call in raw_calls or []:
        fn = call.get("function") or {}
        name = str(fn.get("name") or "").strip()
        if not name:
            continue
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args or "{}")
            except json.JSONDecodeError:
                args = {}
        if not isinstance(args, dict):
            args = {}
        normalized.append({"id": call.get("id"), "name": name, "arguments": args})
    return normalized


_TEXT_CALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>|```(?:json|tool_code)?\s*(\{.*?\})\s*```", re.DOTALL)


def _parse_text_tool_calls(text: str) -> list[dict[str, Any]]:
    """Recover tool calls that a (often local) model emitted as text instead of
    structured tool_calls — e.g. Qwen's <tool_call>{...}</tool_call> or a fenced
    JSON block. Only known tool names are accepted, so prose is never misread."""
    if not text or ("<tool_call>" not in text and "```" not in text):
        return []
    calls: list[dict[str, Any]] = []
    for match in _TEXT_CALL_RE.finditer(text):
        raw = match.group(1) or match.group(2)
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        name = obj.get("name") or obj.get("tool") or obj.get("function")
        args = obj.get("arguments") or obj.get("parameters") or obj.get("args") or {}
        if isinstance(name, str) and name in _TOOL_NAMES and isinstance(args, dict):
            calls.append({"id": None, "name": name, "arguments": args})
    return calls


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
    auto_verifies = 0

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
            feedback = _auto_verify(toolbox, transcript, auto_verifies)
            if feedback is not None:
                auto_verifies += 1
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": feedback})
                continue
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


def _run_tool_loop(
    messages: list[dict[str, Any]],
    system_prompt: str,
    cfg: dict[str, Any],
    block: dict[str, Any],
    settings: dict[str, Any],
    toolbox: ToolBox,
    provider: str,
) -> dict[str, Any]:
    """Tool-calling loop for local (Ollama native /api/chat) and OpenAI-compatible
    providers. `local` uses the native endpoint specifically so we can set the
    context window (num_ctx) — without that, the workspace + repo map fall out of
    Ollama's small default context and the model 'forgets' where it is."""
    native = provider == "local"
    label = "Ollama" if native else provider
    model = str(block.get("model") or "").strip()
    if not model:
        raise AgentError(f"{label} model is not set.")
    timeout = float(cfg.get("timeout_s") or 120.0)
    api_key = str(block.get("api_key") or "").strip()
    max_tokens = int(cfg.get("max_tokens") or 8192)
    temperature = float(cfg.get("temperature", 0.2))
    tools = _openai_tools()  # {type:function, function:{...}} — accepted by both
    convo: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}, *messages]
    transcript: list[dict[str, Any]] = []
    max_steps = int(settings["max_steps"])
    auto_verifies = 0

    if native:
        host = coder.ollama_host(block.get("base_url"))
        options = {
            "temperature": temperature,
            "num_ctx": int(block.get("num_ctx") or 16384),
            "num_predict": max_tokens,
        }
    else:
        base_url = str(block.get("base_url") or "").strip().rstrip("/")
        if not base_url:
            raise AgentError(f"{label} base URL is not set.")
        endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"

    def _chat_once() -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
        if native:
            message = coder.ollama_chat(
                host, model, convo, tools=tools, options=options, timeout=timeout, api_key=api_key
            )
            raw = {"role": "assistant", "content": message.get("content") or ""}
            if message.get("tool_calls"):
                raw["tool_calls"] = message["tool_calls"]
            return raw, str(message.get("content") or ""), _normalize_tool_calls(message.get("tool_calls"))
        payload = {
            "model": model,
            "messages": convo,
            "tools": tools,
            "tool_choice": "auto",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
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
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "ignore")[:400] if hasattr(exc, "read") else ""
            raise AgentError(f"{label} HTTP {exc.code}: {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise AgentError(f"Could not reach {label} ({exc.reason}). Is it running?") from exc
        except Exception as exc:  # noqa: BLE001
            raise AgentError(f"{label} request failed: {exc}") from exc
        try:
            message = body["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AgentError(f"{label} returned an unexpected response shape.") from exc
        return message, str(message.get("content") or ""), _normalize_tool_calls(message.get("tool_calls"))

    for _ in range(max_steps):
        raw_assistant, text, tool_calls = _chat_once()
        from_text = False
        if not tool_calls:
            recovered = _parse_text_tool_calls(text)
            if recovered:
                tool_calls, from_text = recovered, True

        if not tool_calls:
            feedback = _auto_verify(toolbox, transcript, auto_verifies)
            if feedback is not None:
                auto_verifies += 1
                convo.append({"role": "assistant", "content": text})
                convo.append({"role": "user", "content": feedback})
                continue
            return {
                "text": text.strip() or "(done)",
                "transcript": transcript,
                "steps": len(transcript),
                "model": model,
                "provider": provider,
            }

        if from_text:
            # Model emitted tool calls as text — thread results back as a plain
            # user turn (no tool_call_id to satisfy), which any server accepts.
            convo.append({"role": "assistant", "content": text})
            blobs = []
            for tc in tool_calls:
                output, is_error = toolbox.run(tc["name"], tc["arguments"])
                transcript.append({"tool": tc["name"], "input": tc["arguments"], "output": output, "is_error": is_error})
                blobs.append(f"[{tc['name']}] {output}")
            convo.append({"role": "user", "content": "Tool results:\n" + "\n\n".join(blobs)})
        else:
            convo.append(raw_assistant)
            for tc in tool_calls:
                output, is_error = toolbox.run(tc["name"], tc["arguments"])
                transcript.append({"tool": tc["name"], "input": tc["arguments"], "output": output, "is_error": is_error})
                tool_msg: dict[str, Any] = {"role": "tool", "content": output}
                if tc.get("id"):
                    tool_msg["tool_call_id"] = tc["id"]
                if native:
                    tool_msg["tool_name"] = tc["name"]
                convo.append(tool_msg)

    return {
        "text": "Reached the step limit before finishing. Re-run to continue.",
        "transcript": transcript,
        "steps": len(transcript),
        "model": model,
        "provider": provider,
    }
