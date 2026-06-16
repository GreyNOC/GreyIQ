from __future__ import annotations

import asyncio
import json
import mimetypes
import os
import shutil
import sys
import threading
import traceback
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from uuid import uuid4

import uvicorn
from pydantic import BaseModel, Field

if getattr(sys, "frozen", False):
    # PyInstaller bundle: source, public/ and seed/ are unpacked under _MEIPASS.
    # RUNTIME_DIR still comes from the environment so user data stays writable.
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    BACKEND_DIR = BUNDLE_DIR
    PROJECT_ROOT = BUNDLE_DIR
    PUBLIC_DIR = BUNDLE_DIR / "public"
    SEED_DIR = BUNDLE_DIR / "seed"
else:
    BACKEND_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT = BACKEND_DIR.parent
    PUBLIC_DIR = PROJECT_ROOT / "public"
    SEED_DIR = BACKEND_DIR / "seed"
RUNTIME_DIR = Path(os.getenv("GREYIQ_RUNTIME_DIR", PROJECT_ROOT / "runtime")).resolve()

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent as coding_agent  # noqa: E402
import coder  # noqa: E402
import workspace as workspace_fs  # noqa: E402
from ai_core.core_store import AICoreStore  # noqa: E402
from document_ingest import (  # noqa: E402
    collect_supported_files,
    ingest_source_files,
    summarize_ingest,
    supported_extensions,
)
from solin_core import SolinEngine  # noqa: E402
from training_runtime import (  # noqa: E402
    DEFAULT_EVAL_INTERVAL,
    DEFAULT_LEARNING_RATE,
    DEFAULT_MAX_ITERS,
    MAX_TRAINING_CHARS,
    TrainingSettings,
    run_training_loop,
)
from bughunter.scan_service import run_code_scan  # noqa: E402
from bughunter.web_scan_service import run_web_scan  # noqa: E402
from bughunter.live_scan_service import run_live_scan  # noqa: E402
from bughunter.triage import triage  # noqa: E402
from bughunter.chat_commands import detect_scan_command, run_scan  # noqa: E402
from bughunter.bounty import list_profiles as bounty_profiles, run_bounty_hunt, vuln_class_names  # noqa: E402
from bughunter import toolkit as toolkit_lib  # noqa: E402
from bughunter.agent_redteam import run_redteam as run_agent_redteam  # noqa: E402


APP_NAME = "GreyIQ"
VERSION = "0.9.1"
_CURRENT_SCOPE: ContextVar[dict[str, Any] | None] = ContextVar("greyiq_current_scope", default=None)
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)
_SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
)
SEED_FILES = (
    "best_model.pt",
    "solin_checkpoint.pt",
    "solin_vocab.json",
    "solin_config.json",
    "solin_inference_config.json",
    "solin_runtime_config.json",
)
SEED_DATA_FILES = (
    "greyiq_starter_knowledge.txt",
    # Native-text extract of the Manual_pdfs library, bundled so the local model
    # trains on it on first run (copied into RUNTIME_DIR/data by ensure_runtime).
    "greyiq_manual_pdfs.txt",
)
TRAINING_SOURCE_FILES = {
    "src_starter_knowledge": "greyiq_starter_knowledge.txt",
    "src_personal_choices": "greyiq_personal_choices.txt",
    "src_preferred_examples": "greyiq_preferred_examples.txt",
    "src_local_notes": "greyiq_local_notes.txt",
    "src_imported_docs": "greyiq_imported_docs.txt",
}

BUGHUNTER_CORE_ID = "core_greyiq_bughunter"
BUGHUNTER_CORE: dict[str, Any] = {
    "id": BUGHUNTER_CORE_ID,
    "name": "GreyIQ BugHunter",
    "mode": "Find, Prove, Fix",
    "type": "security_auditor",
    "description": (
        "Authorized bug and vulnerability finder for code (and, as more engines "
        "land, live apps). Runs GreyIQ's local static scanner, then explains, "
        "prioritizes, and proposes fixes - always citing file and line."
    ),
    "personality": "direct",
    "skills": [
        "code_scanning",
        "vulnerability_triage",
        "secure_code_review",
        "exploit_reasoning",
        "remediation",
        "debugging",
    ],
    "safetyMode": "open_local",
    "confidencePolicy": [
        "cite_file_and_line",
        "separate_proven_from_suspected",
        "rank_by_severity_and_exploitability",
        "give_minimal_repro_or_fix",
        "name_uncertainty",
    ],
    "responseContract": [
        "state_the_finding_and_where",
        "explain_why_it_is_exploitable",
        "rate_severity_and_confidence",
        "give_the_smallest_fix",
        "note_what_to_verify_next",
    ],
    "starterKnowledge": [
        "GreyIQ's local code scanner flags command injection, eval/exec on "
        "dynamic input, hardcoded secrets, weak crypto, vulnerable dependencies, "
        "risky CI workflows, suspicious network calls, and backdoor patterns.",
        "Only scan code you own or are explicitly authorized to review.",
        "A finding is a lead, not a verdict: confirm exploitability before "
        "calling something critical.",
    ],
    "sourceIds": [
        "src_starter_knowledge",
        "src_local_notes",
        "src_imported_docs",
    ],
}


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    bot: dict[str, Any] = Field(default_factory=dict)
    memories: list[dict[str, Any]] = Field(default_factory=list)
    history: list[dict[str, Any]] = Field(default_factory=list)
    max_new_tokens: int = Field(default=96, ge=1, le=512)
    temperature: float = Field(default=0.32, ge=0.0, le=2.0)
    auto_capture: bool = True
    mode: str | None = None


class CoderConfigRequest(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)


class AgentRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    workspace: str = Field(min_length=1, max_length=4000)
    history: list[dict[str, Any]] = Field(default_factory=list)


class WorkspaceTreeRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=4000)
    max_entries: int = Field(default=1000, ge=1, le=20000)


class WorkspaceFileRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=4000)
    path: str = Field(min_length=1, max_length=4000)


class PreferenceRequest(BaseModel):
    bot: dict[str, Any] = Field(default_factory=dict)
    preference: str | None = Field(default=None, max_length=8000)
    user: str | None = Field(default=None, max_length=8000)
    assistant: str | None = Field(default=None, max_length=8000)
    rating: str | None = Field(default=None, max_length=40)
    source_id: str | None = Field(default=None, max_length=120)
    source_name: str | None = Field(default=None, max_length=160)
    training_text: str | None = Field(default=None, max_length=200_000)


class TrainingRequest(BaseModel):
    max_iters: int = Field(default=120, ge=1, le=100_000)
    eval_interval: int = Field(default=40, ge=1, le=100_000)
    learning_rate: float = Field(default=DEFAULT_LEARNING_RATE, gt=0.0, le=1.0)
    device_preference: str = Field(default="auto", max_length=20)
    source_ids: list[str] = Field(default_factory=list)
    fresh_start: bool = False
    dataset_char_cap: int = Field(default=MAX_TRAINING_CHARS, ge=0, le=100_000_000)


class DeviceRequest(BaseModel):
    preference: str = Field(default="auto", max_length=20)


class CoreSaveRequest(BaseModel):
    core: dict[str, Any]


class ScanCodeRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4000)
    target_type: str = Field(default="path", max_length=20)
    max_files: int = Field(default=5000, ge=1, le=100_000)
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)


class WebScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class LiveScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    wait_seconds: float = Field(default=6.0, ge=0.0, le=30.0)


class BountyScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4000)
    profile: str = Field(default="full-sweep", max_length=60)
    vuln_class: str | None = Field(default=None, max_length=60)
    output_dir: str | None = Field(default=None, max_length=4000)
    scope: str = Field(default="", max_length=2000)
    authorized: bool = False
    run_live: bool = False
    per_finding: bool = False
    max_files: int = Field(default=5000, ge=1, le=100_000)


class AgentRedteamRequest(BaseModel):
    authorized: bool = False
    include_behavioral: bool = False


class TrainFolderRequest(BaseModel):
    folder: str = Field(min_length=1, max_length=4000)
    recursive: bool = True
    max_files: int = Field(default=2000, ge=1, le=20000)


class HTTPError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class OpenScreen:
    allowed: bool = True
    reason: str = ""
    category: str = ""
    refusal_message: str = ""
    requires_ack: bool = False
    audit_tag: str = ""


class OpenPolicy:
    """Permissive policy used by GreyIQ after importing the legacy engine.

    The imported model still has quality checks, memory, retrieval, and fallback
    handling. GreyIQ leaves the old policy layer unwired.
    """

    def screen_input(self, _text: str) -> OpenScreen:
        return OpenScreen()

    def screen_output(self, _text: str) -> OpenScreen:
        return OpenScreen()

    def snapshot(self) -> dict[str, Any]:
        return {"mode": "open", "policy": "unwired"}

    def system_prompt_addendum(self) -> str:
        return ""

    def set_flag(self, name: str, value: Any) -> dict[str, Any]:
        return {"mode": "open", "flag": name, "value": value}

    def set_authorization(self, _ack_text: str, _scope_note: str) -> dict[str, str]:
        return {"mode": "open", "authorization": "not_required"}

    def clear_authorization(self) -> dict[str, str]:
        return {"mode": "open", "authorization": "not_required"}

    def audit_tail(self, _lines: int = 200) -> str:
        return ""

    def capability_label(self) -> str:
        return "open local"


@dataclass
class TrainingState:
    active: bool = False
    paused: bool = False
    stop_requested: bool = False
    job_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    last_error: str = ""
    logs: list[str] = field(default_factory=list)
    runtime: dict[str, Any] = field(default_factory=lambda: {"status": "idle", "stage": "idle", "detail": ""})


class GreyIQRuntime:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.engine: SolinEngine | None = None
        self.engine_error = ""
        self.training = TrainingState()
        self.model_pull: dict[str, Any] = {
            "active": False, "model": "", "status": "", "percent": 0,
            "completed": 0, "total": 0, "done": False, "error": "",
        }
        self.store = AICoreStore(RUNTIME_DIR)
        ensure_runtime()
        self._rewrite_core_defaults()
        self._ensure_bughunter_core()

    def _rewrite_core_defaults(self) -> None:
        state = self.store.load()
        changed = False
        for core in state.get("cores", []):
            name = str(core.get("name", ""))
            if any(marker in name for marker in ("GreyNOC", "SOC", "Red Hat")):
                core.update(
                    {
                        "name": "GreyIQ Companion",
                        "mode": "Friendly Power",
                        "type": "local_companion",
                        "description": "Soft, friendly, deeply capable local AI that learns the user's preferences.",
                        "personality": "warm",
                        "skills": ["conversation", "coding", "research", "planning", "local_training"],
                        "safetyMode": "open_local",
                    }
                )
                changed = True
        for deployment in state.get("deployments", []):
            if deployment.get("channel") != "GreyIQ Chat":
                deployment["channel"] = "GreyIQ Chat"
                changed = True
        if changed:
            self.store.save(state)

    def _ensure_bughunter_core(self) -> None:
        state = self.store.load()
        if any(core.get("id") == BUGHUNTER_CORE_ID for core in state.get("cores", [])):
            return
        self.store.save_core(dict(BUGHUNTER_CORE), who="greyiq")

    def log(self, message: str) -> None:
        stamp = datetime.now(UTC).strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        with self.lock:
            self.training.logs.insert(0, line)
            del self.training.logs[80:]

    def status(self) -> dict[str, Any]:
        with self.lock:
            engine = self.engine
            model_path = getattr(engine, "model_path", None) if engine else None
            device_info = getattr(engine, "device_info", None) if engine else None
            return {
                "app": APP_NAME,
                "version": VERSION,
                "runtime_dir": str(RUNTIME_DIR),
                "engine_loaded": engine is not None,
                "engine_ready": bool(engine and engine.ready),
                "engine_error": self.engine_error,
                "model_name": model_path.name if model_path else "none",
                "model_path": str(model_path) if model_path else "",
                "device": getattr(device_info, "name", "unknown") if device_info else "unknown",
                "device_reason": getattr(device_info, "reason", "") if device_info else "",
                "summary": engine.detailed_status() if engine else "GreyIQ engine has not loaded yet.",
                "training": self.training_payload(),
                "ai_core": self.store.load(),
            }

    def training_payload(self) -> dict[str, Any]:
        return {
            "active": self.training.active,
            "paused": self.training.paused,
            "job_id": self.training.job_id,
            "started_at": self.training.started_at,
            "finished_at": self.training.finished_at,
            "last_error": self.training.last_error,
            "status": self.training.runtime,
            "recent_logs": self.training.logs[:20],
        }

    def get_engine(self) -> SolinEngine:
        with self.lock:
            if self.engine is not None:
                return self.engine
            try:
                self.engine = SolinEngine(RUNTIME_DIR, status_callback=self.log)
                self.engine.safety = OpenPolicy()
                self.engine.live_memory_learning = True
                self.engine_error = ""
                return self.engine
            except Exception as exc:
                self.engine_error = f"{exc}"
                self.log(traceback.format_exc())
                raise

    def reload_engine(self) -> None:
        with self.lock:
            self.engine = None
        self.get_engine()

    def set_device(self, preference: str) -> dict[str, Any]:
        normalized = normalize_device(preference)
        runtime_path = RUNTIME_DIR / "solin_runtime_config.json"
        payload = read_json(runtime_path, {})
        payload["device_preference"] = normalized
        write_json(runtime_path, payload)
        with self.lock:
            if self.engine is not None:
                self.engine.safety = OpenPolicy()
                self.engine.reload_with_device_preference(normalized)
                self.engine.safety = OpenPolicy()
        return self.status()

    def _code_router_config(self) -> dict[str, Any]:
        payload = read_json(RUNTIME_DIR / "solin_runtime_config.json", {})
        config = payload.get("code_router") if isinstance(payload, dict) else None
        return config if isinstance(config, dict) else {}

    def _coder_config(self) -> dict[str, Any]:
        payload = read_json(RUNTIME_DIR / "solin_runtime_config.json", {})
        config = payload.get("coder") if isinstance(payload, dict) else None
        return config if isinstance(config, dict) else {}

    def save_coder_config(self, update: dict[str, Any]) -> dict[str, Any]:
        runtime_path = RUNTIME_DIR / "solin_runtime_config.json"
        payload = read_json(runtime_path, {})
        if not isinstance(payload, dict):
            payload = {}
        payload["coder"] = coder.merge_update(payload.get("coder"), update)
        write_json(runtime_path, payload)
        return coder.public_config(payload["coder"])

    def coder_status(self) -> dict[str, Any]:
        return coder.public_config(self._coder_config())

    def coder_test(self) -> dict[str, Any]:
        try:
            result = coder.generate(
                [{"role": "user", "content": "Reply with exactly: OK"}],
                self._coder_config(),
            )
            return {"ok": True, "provider": result["provider"], "model": result["model"], "reply": result["text"][:200]}
        except coder.CoderError as exc:
            return {"ok": False, "error": str(exc)}

    def _local_brain(self) -> tuple[str, str]:
        cfg = coder.coder_config(self._coder_config())
        block = cfg.get("local") or {}
        return coder.ollama_host(block.get("base_url")), str(block.get("model") or "").strip()

    def list_local_models(self) -> dict[str, Any]:
        host, model = self._local_brain()
        try:
            installed = coder.ollama_list_models(host)
            return {
                "ok": True,
                "installed": installed,
                "configured": model,
                "present": bool(model) and coder.model_installed(installed, model),
            }
        except coder.CoderError as exc:
            return {"ok": False, "error": str(exc), "configured": model, "installed": [], "present": False}

    def model_pull_status(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.model_pull)

    def start_model_pull(self, model: str = "") -> dict[str, Any]:
        host, configured = self._local_brain()
        target = (model or configured).strip()
        if not target:
            return {"ok": False, "error": "No local model is configured."}
        with self.lock:
            if self.model_pull.get("active"):
                return {"ok": False, "error": "A model download is already in progress.", **self.model_pull}
            self.model_pull = {
                "active": True, "model": target, "status": "starting", "percent": 0,
                "completed": 0, "total": 0, "done": False, "error": "",
            }

        def worker() -> None:
            def progress(event: dict[str, Any]) -> None:
                with self.lock:
                    if event.get("status"):
                        self.model_pull["status"] = str(event["status"])
                    total = int(event.get("total") or 0)
                    completed = int(event.get("completed") or 0)
                    if total > 0:
                        self.model_pull["total"] = total
                        self.model_pull["completed"] = completed
                        self.model_pull["percent"] = min(100, int(completed * 100 / total))

            try:
                coder.ollama_pull(host, target, timeout=3600.0, progress_cb=progress)
                with self.lock:
                    self.model_pull.update({"active": False, "done": True, "status": "success", "percent": 100})
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                self.log(f"Model pull failed: {exc}")
                with self.lock:
                    self.model_pull.update({"active": False, "done": True, "error": str(exc), "status": "error"})

        threading.Thread(target=worker, name="ollama-pull", daemon=True).start()
        return {"ok": True, "active": True, "model": target}

    def run_agent(self, request: AgentRequest) -> dict[str, Any]:
        try:
            result = coding_agent.run_agent(
                request.message,
                request.history,
                request.workspace,
                self._coder_config(),
                runtime_dir=RUNTIME_DIR,
                seed_dir=SEED_DIR,
            )
            return {
                "ok": True,
                "request_id": uuid4().hex,
                "message": friendly_branding(result["text"]),
                "transcript": result["transcript"],
                "steps": result["steps"],
                "changes": result.get("changes", []),
                "touched_files": result.get("touched_files", []),
                "model_name": f"{result['provider']}:{result['model']}",
                "provider": result["provider"],
            }
        except coding_agent.AgentError as exc:
            return {
                "ok": False,
                "request_id": uuid4().hex,
                "message": str(exc),
                "transcript": [],
                "steps": 0,
                "changes": [],
                "touched_files": [],
            }

    def run_bounty(self, request: "BountyScanRequest") -> dict[str, Any]:
        return run_bounty_hunt(
            request.target,
            request.profile,
            request.vuln_class,
            request.output_dir,
            request.scope,
            request.authorized,
            self._coder_config(),
            default_reports_dir=RUNTIME_DIR / "reports",
            seed_dir=SEED_DIR,
            runtime_dir=RUNTIME_DIR,
            version=VERSION,
            run_live=request.run_live,
            max_files=request.max_files,
            per_finding=request.per_finding,
        )

    def run_agent_redteam(self, request: "AgentRedteamRequest") -> dict[str, Any]:
        return run_agent_redteam(
            None,  # red-team always writes to the runtime reports dir (no caller-chosen path)
            request.authorized,
            self._coder_config(),
            default_reports_dir=RUNTIME_DIR / "reports",
            runtime_dir=RUNTIME_DIR,
            seed_dir=SEED_DIR,
            version=VERSION,
            include_behavioral=request.include_behavioral,
        )

    def _build_coder_messages(self, request: ChatRequest, limit: int) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        for turn in (request.history or [])[-max(limit, 0):]:
            if not isinstance(turn, dict):
                continue
            role = str(turn.get("role") or "").strip()
            content = str(turn.get("content") or "").strip()
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": request.message})
        # Anthropic requires the first message to be a user turn.
        while messages and messages[0]["role"] != "user":
            messages.pop(0)
        return messages

    def _coder_system_prompt(self, request: ChatRequest, cfg: dict[str, Any]) -> str:
        base = str(cfg.get("system_prompt") or coder.DEFAULT_SYSTEM_PROMPT)
        bot = request.bot or {}
        extras: list[str] = []
        persona = str(bot.get("persona") or "").strip()
        style = str(bot.get("style") or "").strip()
        if persona:
            extras.append(f"Persona: {persona}")
        if style:
            extras.append(f"Preferred style: {style}")
        for memory in (request.memories or [])[-8:]:
            if isinstance(memory, dict) and memory.get("kind") == "preference" and memory.get("text"):
                extras.append(f"User preference: {memory['text']}")
        return base + ("\n\n" + "\n".join(extras) if extras else "")

    def _coder_reply(self, request: ChatRequest) -> dict[str, Any] | None:
        raw = self._coder_config()
        if not coder.coder_enabled(raw):
            return None
        cfg = coder.coder_config(raw)
        messages = self._build_coder_messages(request, int(cfg.get("history_turns") or 12))
        # The coding brain runs with a coding-focused system prompt; bot persona,
        # style, and stored preferences are layered on top.
        cfg = dict(cfg)
        cfg["system_prompt"] = self._coder_system_prompt(request, cfg)
        try:
            result = coder.generate(messages, cfg)
        except coder.CoderError as exc:
            self.log(f"Coding brain error: {exc}")
            return {
                "request_id": uuid4().hex,
                "message": (
                    f"The coding brain ({cfg.get('provider')}) could not respond: {exc}\n\n"
                    "Check the brain settings (provider, model, API key / server), or turn it off "
                    "to use the local fallback."
                ),
                "used_fallback": True,
                "captured_for_training": False,
                "model_name": f"coder:{cfg.get('provider')}:error",
                "device": "remote",
                "citations": [],
                "ai_core": self.store.load(),
            }
        return {
            "request_id": uuid4().hex,
            "message": friendly_branding(result["text"]),
            "used_fallback": False,
            "captured_for_training": False,
            "model_name": f"{result['provider']}:{result['model']}",
            "device": "remote" if result["provider"] == "anthropic" else "local-model",
            "citations": [],
            "ai_core": self.store.load(),
        }

    def _maybe_scan_reply(self, request: ChatRequest) -> dict[str, Any] | None:
        command = detect_scan_command(request.message)
        if command is None:
            return None
        kind, target = command
        result = run_scan(kind, target)
        triaged = triage(result, self._code_router_config())
        return {
            "request_id": uuid4().hex,
            "message": friendly_branding(triaged["summary"]),
            "used_fallback": not bool(result.get("ok")),
            "captured_for_training": False,
            "model_name": "bughunter" + ("+remote" if triaged["used_remote"] else ""),
            "device": "scanner",
            "citations": triaged["citations"],
            "ai_core": self.store.load(),
            "scan": {
                key: result.get(key)
                for key in ("ok", "scan_type", "risk", "score", "finding_count", "target")
            },
        }

    def chat(self, request: ChatRequest) -> dict[str, Any]:
        scan_reply = self._maybe_scan_reply(request)
        if scan_reply is not None:
            return scan_reply
        # A configured coding brain (local model or Claude) answers instead of the
        # tiny offline model. TinyGPT is the last-resort fallback below.
        coder_reply = self._coder_reply(request)
        if coder_reply is not None:
            return coder_reply
        try:
            engine = self.get_engine()
            engine.safety = OpenPolicy()
            seed_training_note(request)
            response, citations, diagnostics = engine.generate_reply(
                request.message,
                max_new_tokens=request.max_new_tokens,
                temperature=request.temperature,
                auto_capture=request.auto_capture,
                mode=request.mode,
            )
            response = friendly_branding(response)
            return {
                "request_id": uuid4().hex,
                "message": response,
                "used_fallback": bool(diagnostics.used_fallback),
                "captured_for_training": bool(diagnostics.captured_for_training),
                "model_name": engine.model_path.name if engine.model_path else "none",
                "device": engine.device_info.name,
                "citations": [
                    {
                        "source": match.source,
                        "score": match.score,
                        "excerpt": match.excerpt,
                    }
                    for match in citations
                ],
                "ai_core": self.store.load(),
            }
        except Exception as exc:
            self.engine_error = f"{exc}"
            self.log(traceback.format_exc())
            return {
                "request_id": uuid4().hex,
                "message": fallback_reply(request.message),
                "used_fallback": True,
                "captured_for_training": False,
                "model_name": "fallback",
                "device": "browser",
                "citations": [],
                "ai_core": self.store.load(),
                "error": str(exc),
            }

    def start_training(self, request: TrainingRequest) -> dict[str, Any]:
        with self.lock:
            if self.training.active:
                raise HTTPError(409, "Training is already active.")
            self.training = TrainingState(
                active=True,
                job_id=f"job_{uuid4().hex[:12]}",
                started_at=datetime.now(UTC).isoformat(),
                runtime={"status": "queued", "stage": "queued", "detail": "Training is queued."},
            )

        settings = TrainingSettings(
            continuous=False,
            trigger_mode="always",
            max_iters=request.max_iters,
            eval_interval=request.eval_interval,
            learning_rate=request.learning_rate,
            skip_pdf_ingest=True,
            max_cycles=1,
            device_preference=normalize_device(request.device_preference),
            source_ids=normalize_source_ids(request.source_ids),
            dataset_char_cap=request.dataset_char_cap,
            fresh_start=request.fresh_start,
        )

        def should_stop() -> bool:
            return self.training.stop_requested

        def should_pause() -> bool:
            return self.training.paused

        def on_status(status: dict[str, Any]) -> None:
            with self.lock:
                self.training.runtime = status

        def run() -> None:
            try:
                run_training_loop(
                    RUNTIME_DIR,
                    settings,
                    logger=self.log,
                    should_stop=should_stop,
                    should_pause=should_pause,
                    status_callback=on_status,
                )
                with self.lock:
                    self.training.runtime = {
                        **self.training.runtime,
                        "status": "complete",
                        "stage": "complete",
                        "detail": "Training finished.",
                    }
                    self.training.finished_at = datetime.now(UTC).isoformat()
                self.reload_engine()
            except Exception as exc:
                with self.lock:
                    self.training.last_error = str(exc)
                    self.training.runtime = {
                        **self.training.runtime,
                        "status": "error",
                        "stage": "error",
                        "detail": str(exc),
                    }
                    self.training.finished_at = datetime.now(UTC).isoformat()
                self.log(traceback.format_exc())
            finally:
                with self.lock:
                    self.training.active = False
                    self.training.stop_requested = False
                    self.training.paused = False

        threading.Thread(target=run, name="greyiq-training", daemon=True).start()
        return self.training_payload()


def normalize_device(value: str | None) -> str:
    normalized = str(value or "auto").strip().lower()
    return normalized if normalized in {"auto", "cpu", "cuda"} else "auto"


def normalize_source_ids(values: list[str] | None) -> list[str]:
    valid = set(TRAINING_SOURCE_FILES)
    seen: set[str] = set()
    selected: list[str] = []
    for value in values or []:
        source_id = str(value or "").strip()
        if source_id in valid and source_id not in seen:
            selected.append(source_id)
            seen.add(source_id)
    return selected


def source_training_file(source_id: str | None) -> str:
    clean = str(source_id or "src_local_notes").strip()
    if clean in TRAINING_SOURCE_FILES and clean != "src_starter_knowledge":
        return TRAINING_SOURCE_FILES[clean]
    safe = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in clean).strip("_")
    return f"greyiq_{safe or 'local_notes'}.txt"


def read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def default_training_text() -> str:
    lines = [
        "GreyIQ is a soft, friendly, very powerful local AI.",
        "GreyIQ answers with warmth, clarity, curiosity, and useful technical depth.",
        "GreyIQ learns from the user's preferences and keeps personal data local.",
        "GreyIQ can help with coding, planning, research, writing, troubleshooting, and creative work.",
        "When a user asks for help, GreyIQ gives the direct answer first and then the practical next step.",
        "When a user teaches a preference, GreyIQ treats it as a local training signal.",
        "A preferred GreyIQ answer is concise when the task is simple and detailed when the task is complex.",
        "GreyIQ can explain tradeoffs, inspect assumptions, and stay calm under messy technical problems.",
        "GreyIQ separates facts, assumptions, inferences, and recommendations.",
        "GreyIQ is trustworthy because it names uncertainty instead of hiding it.",
        "GreyIQ uses local notes, imported documents, and personal examples as the highest-value knowledge.",
        "GreyIQ has useful starter knowledge for software engineering, data analysis, research synthesis, writing, planning, and troubleshooting.",
        "GreyIQ answers broad questions by making a useful map: context, options, risks, recommendation, and next check.",
        "GreyIQ answers technical questions with inputs, expected outputs, failure modes, and verification steps.",
        "GreyIQ answers research questions by separating evidence from interpretation and by marking what still needs a source.",
        "GreyIQ answers personal preference questions by remembering the user's taste and adapting future responses.",
    ]
    return "\n".join(lines * 60)


def ensure_runtime() -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    (RUNTIME_DIR / "data").mkdir(parents=True, exist_ok=True)
    for name in SEED_FILES:
        src = SEED_DIR / name
        dst = RUNTIME_DIR / name
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)
    for name in SEED_DATA_FILES:
        src = SEED_DIR / name
        dst = RUNTIME_DIR / "data" / name
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)
    # Bounty: default reports folder + seed the .md playbooks (user-editable;
    # no clobber so edits survive upgrades). bounty._load_playbook falls back to
    # the bundled seed copy if a runtime copy is missing.
    (RUNTIME_DIR / "reports").mkdir(parents=True, exist_ok=True)
    seed_bounty = SEED_DIR / "bounty"
    if seed_bounty.is_dir():
        dst_bounty = RUNTIME_DIR / "bounty"
        dst_bounty.mkdir(parents=True, exist_ok=True)
        for playbook in seed_bounty.glob("*.md"):
            dst_playbook = dst_bounty / playbook.name
            if not dst_playbook.exists():
                shutil.copy2(playbook, dst_playbook)
    train_path = RUNTIME_DIR / "train.txt"
    if not train_path.exists():
        train_path.write_text(default_training_text(), encoding="utf-8")
        return

    try:
        existing = train_path.read_text(encoding="utf-8")
    except OSError:
        existing = ""
    if len(existing) < 12_000:
        train_path.write_text(f"{existing.strip()}\n\n{default_training_text()}\n", encoding="utf-8")


def friendly_branding(text: str) -> str:
    return text.replace("SOlin", "GreyIQ").replace("Solin", "GreyIQ").replace("GreyNOC", "GreyIQ")


def fallback_reply(message: str) -> str:
    words = " ".join(str(message).strip().split()[:18])
    return (
        "I can work with that. The local engine is still warming up, so here is the trustworthy first pass: "
        f"treat {words or 'the request'} as the focus, separate what we know from what we need to check, "
        "choose one useful next move, and refine from your feedback."
    )


def seed_training_note(request: ChatRequest) -> None:
    bot = request.bot or {}
    memories = request.memories or []
    lines: list[str] = []
    name = str(bot.get("name") or "GreyIQ").strip()
    persona = str(bot.get("persona") or "").strip()
    style = str(bot.get("style") or "").strip()
    if persona:
        lines.append(f"Bot {name} persona: {persona}")
    if style:
        lines.append(f"Bot {name} style: {style}")
    for memory in memories[-12:]:
        if not isinstance(memory, dict):
            continue
        if memory.get("kind") == "preference" and memory.get("text"):
            lines.append(f"User preference: {memory['text']}")
        elif memory.get("kind") == "example" and memory.get("user") and memory.get("bot"):
            lines.append(f"Preferred exchange: user={memory['user']} assistant={memory['bot']}")
    if lines:
        append_training_text("greyiq_profile.txt", "\n".join(lines))


def append_training_text(file_name: str, text: str) -> Path:
    clean = str(text or "").strip()
    if not clean:
        return RUNTIME_DIR / "data" / file_name
    path = RUNTIME_DIR / "data" / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n\n### GREYIQ TRAINING {stamp} ###\n{clean}\n")
    return path


def ingest_training_folder(request: TrainFolderRequest) -> dict[str, Any]:
    """Read a local folder and add its supported files to the training data.

    Extracts text from PDFs, images (OCR if available), DOCX, and plain-text
    files into RUNTIME_DIR/data, where the trainer reads it. Re-ingesting is
    cheap: the manifest skips files whose contents have not changed. The ingested
    text counts as "Imported Documents" (src_imported_docs) for training.
    """
    folder = Path(request.folder).expanduser()
    if not folder.exists() or not folder.is_dir():
        raise HTTPError(400, f"Not a folder: {request.folder}")

    files = collect_supported_files(folder, recursive=request.recursive)
    if not files:
        return {
            "ok": True,
            "folder": str(folder),
            "scanned": 0,
            "truncated": False,
            "summary": {"converted": 0, "unchanged": 0, "failed": 0},
            "supported_extensions": list(supported_extensions()),
            "message": "No supported files found in that folder.",
        }

    truncated = len(files) > request.max_files
    selected = files[: request.max_files]

    data_dir = RUNTIME_DIR / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    results = ingest_source_files(
        source_files=selected,
        output_folder=data_dir,
        manifest_path=RUNTIME_DIR / "pdf_manifest.json",
        method="auto",
        logger=runtime.log,
    )
    summary = summarize_ingest(results)
    added = summary.get("converted", 0) + summary.get("unchanged", 0)
    message = (
        f"Added {added} file(s) from {folder.name or folder}"
        f" ({summary.get('converted', 0)} new, {summary.get('unchanged', 0)} already current,"
        f" {summary.get('failed', 0)} skipped)."
    )
    if truncated:
        message += f" Limited to the first {request.max_files} of {len(files)} files — run again to continue."
    return {
        "ok": True,
        "folder": str(folder),
        "scanned": len(selected),
        "total_found": len(files),
        "truncated": truncated,
        "summary": summary,
        "supported_extensions": list(supported_extensions()),
        "message": message,
    }


runtime = GreyIQRuntime()


def health() -> dict[str, Any]:
    return {"status": "ok", "app": APP_NAME, "version": VERSION}


def toolkit_catalog() -> dict[str, Any]:
    """Curated Pentest Toolkit catalog (awesome-pentest, CC-BY 4.0) plus friendly
    vuln-class names so the UI can render 'maps to' badges."""
    payload = toolkit_lib.catalog_payload(SEED_DIR, RUNTIME_DIR)
    payload["vuln_classes"] = vuln_class_names()
    return payload


def preferences(request: PreferenceRequest) -> dict[str, Any]:
    bot = request.bot or {}
    bot_name = str(bot.get("name") or "GreyIQ").strip()
    chunks: list[str] = []
    target_file = "greyiq_personal_choices.txt"
    if request.preference:
        chunks.append(f"{bot_name} should prefer: {request.preference}")
    if request.user and request.assistant:
        target_file = "greyiq_preferred_examples.txt"
        chunks.append(
            f"<START_CONVO>\n<USER>\n{request.user.strip()}\n<ASSISTANT>\n{request.assistant.strip()}\n<END_CONVO>"
        )
    if request.training_text:
        target_file = source_training_file(request.source_id)
        source_name = request.source_name or request.source_id or "Training Data"
        chunks.append(f"Source: {source_name}\n{request.training_text.strip()}")
    if request.rating:
        chunks.append(f"Feedback rating: {request.rating}")
    path = append_training_text(target_file, "\n".join(chunks))
    return {"ok": True, "path": str(path), "source_id": request.source_id}


def validate_payload(model: type[BaseModel], payload: dict[str, Any]) -> BaseModel:
    try:
        validator = getattr(model, "model_validate", None)
        if validator is not None:
            return validator(payload)
        return model.parse_obj(payload)
    except Exception as exc:
        raise HTTPError(422, str(exc)) from exc


async def read_body(receive: Any) -> bytes:
    chunks: list[bytes] = []
    more_body = True
    while more_body:
        message = await receive()
        chunks.append(message.get("body", b""))
        more_body = bool(message.get("more_body", False))
    return b"".join(chunks)


async def read_json_body(receive: Any) -> dict[str, Any]:
    body = await read_body(receive)
    if not body:
        return {}
    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPError(400, f"Invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise HTTPError(422, "JSON body must be an object.")
    return payload


def _header(scope: dict[str, Any] | None, name: str) -> str:
    if not scope:
        return ""
    expected = name.lower().encode("ascii")
    for key, value in scope.get("headers", []):
        if key.lower() == expected:
            return value.decode("latin-1", errors="replace")
    return ""


def _normalize_origin(value: str) -> str:
    raw = value.strip()
    if not raw or raw == "null":
        return ""
    try:
        parsed = urlparse(raw)
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password:
        return ""
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    netloc = hostname if port is None else f"{hostname}:{port}"
    return f"{parsed.scheme}://{netloc}"


def _configured_origins() -> set[str]:
    raw = os.getenv("GREYIQ_ALLOWED_ORIGINS", "")
    return {
        normalized
        for normalized in (_normalize_origin(part) for part in raw.split(","))
        if normalized
    }


def _same_origin(scope: dict[str, Any] | None) -> str:
    host = _header(scope, "host").strip().lower()
    if not host:
        return ""
    scheme = str((scope or {}).get("scheme") or "http").lower()
    return f"{scheme}://{host}"


def _request_origin_allowed(scope: dict[str, Any] | None = None) -> bool:
    scope = scope or _CURRENT_SCOPE.get()
    origin = _header(scope, "origin")
    if not origin:
        return True
    normalized = _normalize_origin(origin)
    if not normalized:
        return False
    return normalized == _same_origin(scope) or normalized in _configured_origins()


def _cors_headers(scope: dict[str, Any] | None) -> list[tuple[bytes, bytes]]:
    origin = _header(scope, "origin")
    if not origin or not _request_origin_allowed(scope):
        return []
    normalized = _normalize_origin(origin)
    return [
        (b"access-control-allow-origin", normalized.encode("ascii")),
        (b"access-control-allow-methods", b"GET,POST,OPTIONS"),
        (b"access-control-allow-headers", b"content-type,accept"),
        (b"access-control-max-age", b"600"),
        (b"vary", b"Origin"),
    ]


def response_headers(content_type: str, content_length: int = 0) -> list[tuple[bytes, bytes]]:
    headers = [
        (b"content-type", content_type.encode("utf-8")),
        (b"content-length", str(content_length).encode("ascii")),
    ]
    if content_type.startswith("text/html"):
        headers.append((b"content-security-policy", _CSP.encode("utf-8")))
    headers.extend(_SECURITY_HEADERS)
    headers.extend(_cors_headers(_CURRENT_SCOPE.get()))
    return headers


async def send_json(send: Any, payload: Any, status_code: int = 200) -> None:
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": response_headers("application/json; charset=utf-8", len(body)),
        }
    )
    await send({"type": "http.response.body", "body": body})


async def send_file(send: Any, path: Path, status_code: int = 200) -> None:
    try:
        body = path.read_bytes()
    except OSError:
        await send_json(send, {"error": "not found"}, 404)
        return
    content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": response_headers(content_type, len(body)),
        }
    )
    await send({"type": "http.response.body", "body": body})


async def send_empty(send: Any, status_code: int = 204) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": response_headers("text/plain; charset=utf-8", 0),
        }
    )
    await send({"type": "http.response.body", "body": b""})


async def route_http(scope: dict[str, Any], receive: Any, send: Any) -> None:
    _CURRENT_SCOPE.set(scope)
    method = str(scope.get("method") or "GET").upper()
    path = str(scope.get("path") or "/")

    if method == "OPTIONS":
        if not _request_origin_allowed(scope):
            await send_json(send, {"error": "origin not allowed"}, 403)
            return
        await send_empty(send)
        return

    if not _request_origin_allowed(scope):
        await send_json(send, {"error": "origin not allowed"}, 403)
        return

    try:
        if method == "GET" and path in {"/", "/app"}:
            await send_file(send, PUBLIC_DIR / "index.html")
            return
        if method == "GET" and path == "/api/health":
            await send_json(send, health())
            return
        if method == "GET" and path == "/api/status":
            await send_json(send, await asyncio.to_thread(runtime.status))
            return
        if method == "POST" and path == "/api/chat":
            request = validate_payload(ChatRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.chat, request))
            return
        if method == "POST" and path == "/api/scan/code":
            request = validate_payload(ScanCodeRequest, await read_json_body(receive))
            await send_json(
                send,
                await asyncio.to_thread(
                    run_code_scan,
                    request.target,
                    request.target_type,
                    request.max_files,
                    tuple(request.include_globs),
                    tuple(request.exclude_globs),
                ),
            )
            return
        if method == "POST" and path == "/api/scan/web":
            request = validate_payload(WebScanRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(run_web_scan, request.url))
            return
        if method == "POST" and path == "/api/scan/live":
            request = validate_payload(LiveScanRequest, await read_json_body(receive))
            await send_json(
                send,
                await asyncio.to_thread(run_live_scan, request.url, request.wait_seconds),
            )
            return
        if method == "GET" and path == "/api/bounty/types":
            await send_json(send, bounty_profiles())
            return
        if method == "GET" and path == "/api/toolkit":
            await send_json(send, toolkit_catalog())
            return
        if method == "POST" and path == "/api/bounty/scan":
            request = validate_payload(BountyScanRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.run_bounty, request))
            return
        if method == "POST" and path == "/api/agent/redteam":
            request = validate_payload(AgentRedteamRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.run_agent_redteam, request))
            return
        if method == "GET" and path == "/api/cores":
            await send_json(send, await asyncio.to_thread(runtime.store.load))
            return
        if method == "POST" and path == "/api/cores":
            request = validate_payload(CoreSaveRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.store.save_core, request.core, who="greyiq"))
            return
        if method == "POST" and path == "/api/preferences":
            request = validate_payload(PreferenceRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(preferences, request))
            return
        if method == "POST" and path == "/api/train/start":
            request = validate_payload(TrainingRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.start_training, request))
            return
        if method == "POST" and path == "/api/train/folder":
            request = validate_payload(TrainFolderRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(ingest_training_folder, request))
            return
        if method == "GET" and path == "/api/train/status":
            await send_json(send, runtime.training_payload())
            return
        if method == "POST" and path == "/api/train/pause":
            runtime.training.paused = True
            await send_json(send, runtime.training_payload())
            return
        if method == "POST" and path == "/api/train/resume":
            runtime.training.paused = False
            await send_json(send, runtime.training_payload())
            return
        if method == "POST" and path == "/api/train/stop":
            runtime.training.stop_requested = True
            await send_json(send, runtime.training_payload())
            return
        if method == "POST" and path == "/api/runtime/device":
            request = validate_payload(DeviceRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.set_device, request.preference))
            return
        if method == "GET" and path == "/api/coder":
            await send_json(send, await asyncio.to_thread(runtime.coder_status))
            return
        if method == "POST" and path == "/api/coder":
            request = validate_payload(CoderConfigRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.save_coder_config, request.config))
            return
        if method == "POST" and path == "/api/coder/test":
            await send_json(send, await asyncio.to_thread(runtime.coder_test))
            return
        if method == "GET" and path == "/api/coder/models":
            await send_json(send, await asyncio.to_thread(runtime.list_local_models))
            return
        if method == "POST" and path == "/api/coder/pull":
            body = await read_json_body(receive)
            model = str((body or {}).get("model") or "")
            await send_json(send, await asyncio.to_thread(runtime.start_model_pull, model))
            return
        if method == "GET" and path == "/api/coder/pull":
            await send_json(send, runtime.model_pull_status())
            return
        if method == "POST" and path == "/api/agent":
            request = validate_payload(AgentRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.run_agent, request))
            return
        if method == "POST" and path == "/api/workspace/tree":
            request = validate_payload(WorkspaceTreeRequest, await read_json_body(receive))
            await send_json(
                send,
                await asyncio.to_thread(workspace_fs.list_tree, request.workspace, request.max_entries),
            )
            return
        if method == "POST" and path == "/api/workspace/file":
            request = validate_payload(WorkspaceFileRequest, await read_json_body(receive))
            await send_json(
                send,
                await asyncio.to_thread(workspace_fs.read_file, request.workspace, request.path),
            )
            return
        if path.startswith("/api/"):
            await send_json(send, {"error": "not found"}, 404)
            return

        relative_path = unquote(path.lstrip("/")) or "index.html"
        file_path = (PUBLIC_DIR / relative_path).resolve()
        try:
            file_path.relative_to(PUBLIC_DIR.resolve())
        except ValueError:
            await send_json(send, {"error": "not found"}, 404)
            return
        if file_path.exists() and file_path.is_file():
            await send_file(send, file_path)
            return
        await send_file(send, PUBLIC_DIR / "index.html")
    except HTTPError as exc:
        await send_json(send, {"detail": exc.detail}, exc.status_code)
    except Exception as exc:
        runtime.log(traceback.format_exc())
        await send_json(send, {"error": str(exc)}, 500)


async def route_lifespan(receive: Any, send: Any) -> None:
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return


class GreyIQASGI:
    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await route_lifespan(receive, send)
            return
        if scope["type"] == "http":
            await route_http(scope, receive, send)
            return
        raise RuntimeError(f"Unsupported ASGI scope: {scope['type']}")


app = GreyIQASGI()


def main() -> None:
    host = os.getenv("GREYIQ_HOST", "127.0.0.1")
    port = int(os.getenv("GREYIQ_PORT", os.getenv("PORT", "8766")))
    uvicorn.run(
        "backend.greyiq_api:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
        server_header=False,
    )


if __name__ == "__main__":
    main()
