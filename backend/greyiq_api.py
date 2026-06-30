from __future__ import annotations

import asyncio
import functools
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import shutil
import sys
import threading
import traceback
from collections import OrderedDict
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
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
# One rollback snapshot per workspace (the last agent run), keyed by a hash of the
# resolved workspace path. Powers "Undo last agent run".
SNAPSHOT_DIR = RUNTIME_DIR / "agent_snapshots"


def _snapshot_path(workspace: str) -> Path:
    try:
        key = str(Path(str(workspace or "")).expanduser().resolve())
    except (OSError, RuntimeError, ValueError):
        key = str(workspace or "")
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()
    return SNAPSHOT_DIR / f"{digest}.json"


# --- Local API hardening ---------------------------------------------------
# Cap request bodies so a local client can't exhaust memory with a huge payload.
MAX_REQUEST_BYTES = int(os.getenv("GREYIQ_MAX_REQUEST_BYTES", str(16 * 1024 * 1024)))

# Per-process session token. The backend injects it into the HTML it serves (a
# CSP-safe <meta> tag); the same-origin app echoes it back as X-GreyIQ-Token on
# every /api/* call. This blocks *other local processes* from driving the API
# over 127.0.0.1 — the Origin check alone can't, since a non-browser client can
# omit Origin. Explicitly allowlisted cross-origin frontends are exempt.
SESSION_TOKEN = secrets.token_urlsafe(32)
SESSION_TOKEN_PLACEHOLDER = "__GREYIQ_SESSION_TOKEN__"
SESSION_TOKEN_PATH = RUNTIME_DIR / "session.token"

# API keys live here (owner-only perms), separate from the general plaintext
# config, instead of inside solin_runtime_config.json.
SECRETS_PATH = RUNTIME_DIR / "secrets.json"
_SECRET_PROVIDERS = ("anthropic", "openai", "local")


# Serializes the read-modify-write of the secrets store so two concurrent provider
# writes can't drop each other's update.
_SECRETS_LOCK = threading.Lock()


def _atomic_write(path: Path, text: str, *, private: bool = False) -> None:
    """Write ``text`` to ``path`` atomically (temp file + os.replace), so a reader
    or a crash never sees a half-written file. When ``private`` the temp file is
    created with owner-only perms (0o600) BEFORE any data is written, so a secret is
    never briefly on disk world-readable (the old write-then-chmod left a window)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    replaced = False
    try:
        if private:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
        else:
            tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
        replaced = True
    finally:
        if not replaced:
            try:
                tmp.unlink()
            except OSError:
                pass


def _write_session_token() -> None:
    try:
        _atomic_write(SESSION_TOKEN_PATH, SESSION_TOKEN, private=True)
    except OSError:
        pass


def _load_secrets() -> dict[str, str]:
    try:
        data = json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
        return {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _store_secret(provider: str, api_key: str) -> None:
    with _SECRETS_LOCK:
        data = _load_secrets()
        if api_key:
            data[provider] = api_key
        else:
            data.pop(provider, None)
        try:
            _atomic_write(SECRETS_PATH, json.dumps(data), private=True)
        except OSError:
            pass


def _merge_coder_secrets(config: dict[str, Any]) -> dict[str, Any]:
    """Overlay stored API keys onto a coder config read from the main file."""
    stored = _load_secrets()
    if not stored:
        return config
    merged = json.loads(json.dumps(config)) if config else {}
    for provider in _SECRET_PROVIDERS:
        key = stored.get(provider)
        if not key:
            continue
        block = merged.get(provider)
        if isinstance(block, dict):
            block["api_key"] = key
        else:
            merged[provider] = {"api_key": key}
    return merged


def _split_coder_secrets(config: dict[str, Any]) -> dict[str, Any]:
    """Move any API keys out of a coder config into the secrets store, leaving the
    main config key-free."""
    for provider in _SECRET_PROVIDERS:
        block = config.get(provider)
        if isinstance(block, dict) and block.get("api_key"):
            _store_secret(provider, str(block["api_key"]))
            block["api_key"] = ""
    return config


def _migrate_coder_secrets() -> None:
    """One-time: pull API keys out of an existing plaintext solin_runtime_config
    into the perms-restricted secrets store."""
    runtime_path = RUNTIME_DIR / "solin_runtime_config.json"
    payload = read_json(runtime_path, {})
    coder_cfg = payload.get("coder") if isinstance(payload, dict) else None
    if not isinstance(coder_cfg, dict):
        return
    moved = False
    for provider in _SECRET_PROVIDERS:
        block = coder_cfg.get(provider)
        if isinstance(block, dict) and block.get("api_key"):
            _store_secret(provider, str(block["api_key"]))
            block["api_key"] = ""
            moved = True
    if moved:
        write_json(runtime_path, payload)


def _session_authorized(scope: dict[str, Any] | None) -> bool:
    """True if a request may call /api/*: an allowlisted cross-origin frontend, or
    a same-origin/local client presenting the session token."""
    origin = _normalize_origin(_header(scope, "origin"))
    if origin and origin in _configured_origins():
        return True
    provided = _header(scope, "x-greyiq-token").strip()
    return bool(provided) and hmac.compare_digest(provided, SESSION_TOKEN)


if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent as coding_agent  # noqa: E402
import coder  # noqa: E402
import project_memory  # noqa: E402
import workspace as workspace_fs  # noqa: E402
from ai_core.core_store import AICoreStore, DEFAULT_CORE_ID, slugify  # noqa: E402
# document_ingest pulls pytesseract -> pandas (~1.4s) and is only used by the
# folder-ingest/training endpoints, so it is imported lazily (see _document_ingest)
# to keep it off the boot path the packaged app blocks on.
from repo_ingest import ingest_repositories  # noqa: E402

# The local TinyGPT brain (solin_core / training_runtime) is the only part of the
# backend that needs PyTorch, and `import torch` alone costs ~4s. It is NOT on the
# bug-hunting or Claude-brain path, so it is imported LAZILY on first actual use
# instead of at module load — the API server answers /api/health (the gate Electron
# blocks on before showing the window) in ~1s instead of ~6s, so the packaged app
# feels far snappier. Torch absence (e.g. an ARM phone under Termux) still degrades
# to a clear message rather than crashing. See _ensure_ml_runtime / _ml_runtime_status.
SolinEngine = None  # type: ignore[assignment,misc]
TrainingSettings = None  # type: ignore[assignment,misc]
run_training_loop = None  # type: ignore[assignment]
# Mirror training_runtime's defaults so request models and settings validate without
# importing it (and thus without paying the torch import cost) at boot.
MAX_TRAINING_CHARS = 8_000_000
DEFAULT_MAX_ITERS = 1000
DEFAULT_EVAL_INTERVAL = 100
DEFAULT_LEARNING_RATE = 3e-4
_ML_RUNTIME_AVAILABLE: bool | None = None  # tri-state: None = not yet probed
_ML_RUNTIME_ERROR = ""
_ML_UNAVAILABLE_MSG = (
    "Local model runtime unavailable (PyTorch not loaded). Bug-hunting and the "
    "Claude API brain still work; local TinyGPT train/infer is disabled."
)


def _ensure_ml_runtime() -> bool:
    """Import the torch-backed TinyGPT runtime on first actual use (heavy: ~4s for
    torch), deferred out of the boot path. Returns True if available and binds the
    module-level symbols; otherwise caches a clear error. Bug-hunting and the Claude
    brain never call this."""
    global _ML_RUNTIME_AVAILABLE, _ML_RUNTIME_ERROR, SolinEngine, TrainingSettings, run_training_loop
    global MAX_TRAINING_CHARS, DEFAULT_MAX_ITERS, DEFAULT_EVAL_INTERVAL, DEFAULT_LEARNING_RATE
    if _ML_RUNTIME_AVAILABLE is not None:
        return _ML_RUNTIME_AVAILABLE
    try:
        from solin_core import SolinEngine as _Engine
        from training_runtime import (
            DEFAULT_EVAL_INTERVAL as _EI,
            DEFAULT_LEARNING_RATE as _LR,
            DEFAULT_MAX_ITERS as _MI,
            MAX_TRAINING_CHARS as _MC,
            TrainingSettings as _TS,
            run_training_loop as _RL,
        )
    except Exception as exc:  # noqa: BLE001 - torch/numpy may be missing or fail to load (DLL, ABI, ARM wheel)
        _ML_RUNTIME_AVAILABLE = False
        _ML_RUNTIME_ERROR = f"Local model runtime unavailable ({type(exc).__name__}: {exc}). " \
            "Bug-hunting and the Claude API brain still work; local TinyGPT train/infer is disabled."
        return False
    SolinEngine, TrainingSettings, run_training_loop = _Engine, _TS, _RL
    MAX_TRAINING_CHARS, DEFAULT_MAX_ITERS, DEFAULT_EVAL_INTERVAL, DEFAULT_LEARNING_RATE = _MC, _MI, _EI, _LR
    _ML_RUNTIME_AVAILABLE = True
    _ML_RUNTIME_ERROR = ""
    return True


def _ml_runtime_status() -> tuple[bool, str]:
    """Cheap availability for /api/status WITHOUT importing torch — a find_spec probe
    only, so the front-end status poll never drags torch onto a hot path. Once the
    runtime has actually been loaded, the cached result wins."""
    if _ML_RUNTIME_AVAILABLE is not None:
        return _ML_RUNTIME_AVAILABLE, _ML_RUNTIME_ERROR
    import importlib.util
    try:
        present = importlib.util.find_spec("torch") is not None
    except (ImportError, ValueError):
        present = False
    return (True, "") if present else (False, _ML_UNAVAILABLE_MSG)
from bughunter.scan_service import run_code_scan  # noqa: E402
from bughunter.web_scan_service import run_web_scan  # noqa: E402
from bughunter.live_scan_service import run_live_scan  # noqa: E402
from bughunter.triage import triage  # noqa: E402
from bughunter.chat_commands import detect_scan_command, run_scan  # noqa: E402
from bughunter.bounty import list_profiles as bounty_profiles, run_bounty_hunt, vuln_class_names  # noqa: E402
from bughunter import campaign as bounty_campaign  # noqa: E402
from bughunter import learning as bounty_learning  # noqa: E402
from bughunter import submission as bounty_submission  # noqa: E402
from bughunter import report as bounty_report  # noqa: E402
from bughunter import report_formats as bounty_formats  # noqa: E402
from bughunter import screenshot_service as bounty_screenshot  # noqa: E402
from bughunter import target_ingest as bounty_ingest  # noqa: E402
from bughunter import bundle as bounty_bundle  # noqa: E402
from bughunter import research as bounty_research  # noqa: E402
from bughunter import access_control_service as bounty_access  # noqa: E402
from bughunter import takeover_service as bounty_takeover  # noqa: E402
from bughunter import cve_service as bounty_cve  # noqa: E402
from bughunter import oob_service as bounty_oob  # noqa: E402
from bughunter import stored_xss_service as bounty_stored_xss  # noqa: E402
from bughunter import ledger as bounty_ledger  # noqa: E402
from bughunter import portfolio as bounty_portfolio  # noqa: E402
from bughunter.operator import OperatorLoop  # noqa: E402
from bughunter import toolkit as toolkit_lib  # noqa: E402
from bughunter.agent_redteam import run_redteam as run_agent_redteam  # noqa: E402


APP_NAME = "GreyIQ"
from _version import VERSION  # noqa: E402 — single source, shared with the gn CLI
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


class AgentUndoRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=4000)


class AgentEventsRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=64)
    cursor: int = Field(default=0, ge=0)


class ProjectMemoryRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=4000)


class ProjectMemorySaveRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=4000)
    facts: list[dict[str, Any]] = Field(default_factory=list)


class WorkspaceTreeRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=4000)
    max_entries: int = Field(default=1000, ge=1, le=20000)


class WorkspaceFileRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=4000)
    path: str = Field(min_length=1, max_length=4000)


class WorkspaceRollbackRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=4000)
    changes: list[dict[str, Any]] = Field(default_factory=list)


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


class RepoIngestRequest(BaseModel):
    sources: list[str] = Field(default_factory=list)
    max_total_chars: int = Field(default=4_000_000, ge=50_000, le=50_000_000)
    max_files_per_repo: int = Field(default=900, ge=10, le=10_000)


class CoreSaveRequest(BaseModel):
    core: dict[str, Any]


class DeleteCoreRequest(BaseModel):
    core_id: str = Field(min_length=1, max_length=200)


class DeleteModelRequest(BaseModel):
    model: str = Field(min_length=1, max_length=200)


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
    active: bool = False
    time_based: bool = False
    auth_cookie: str = Field(default="", max_length=8000)
    auth_headers: list[str] = Field(default_factory=list, max_length=20)
    per_finding: bool = False
    max_files: int = Field(default=5000, ge=1, le=100_000)


class CampaignRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4000)
    scope: str = Field(default="", max_length=2000)
    authorized: bool = False
    program: str | None = Field(default=None, max_length=200)
    active: bool = False
    time_based: bool = False
    auth_cookie: str = Field(default="", max_length=8000)
    auth_headers: list[str] = Field(default_factory=list, max_length=20)
    live: bool = False
    max_pages: int = Field(default=12, ge=1, le=50)
    deep: bool = False  # aggressive: time-based SQLi + auto screenshot + research per confirmed lead


class LearnRequest(BaseModel):
    class_id: str = Field(min_length=1, max_length=60)
    status: str = Field(min_length=1, max_length=40)
    program: str | None = Field(default=None, max_length=200)
    target: str = Field(default="", max_length=4000)
    bounty: float = Field(default=0.0, ge=0)
    severity: str = Field(default="", max_length=20)
    title: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=500)


class SubmissionPackageRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)
    ref: str = Field(min_length=1, max_length=40)
    platform: str = Field(default="hackerone", max_length=20)


class SubmitRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)
    ref: str = Field(min_length=1, max_length=40)
    confirm: bool = False
    platform: str = Field(default="hackerone", max_length=20)


class ScreenshotRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)
    ref: str = Field(min_length=1, max_length=40)
    full_page: bool = False
    scope: str = Field(default="", max_length=4000)   # optional extra scope (the cockpit's current Scope box), unioned with the run + live program scope at capture time


class IngestTargetsRequest(BaseModel):
    content: str = Field(default="", max_length=5_000_000)   # pasted/loaded CSV / Burp XML / HAR (module also byte-caps)
    kind: str = Field(default="auto", max_length=12)          # auto | csv | burp | har


class BundleRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)


class ResearchRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)
    ref: str = Field(min_length=1, max_length=40)


class TakeoverRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4000)   # apex/host to enumerate
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)


class CveScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4000)   # URL/host whose components to fingerprint
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)


class OobConfigRequest(BaseModel):
    collaborator_url: str = Field(default="", max_length=2000)
    secret: str = Field(default="", max_length=400)


class OobPollRequest(BaseModel):
    token: str = Field(min_length=1, max_length=64)


class OobSsrfRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4000)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)


class OobXxeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4000)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)
    send: bool = Field(default=False)               # opt-in: POST the payload (only non-GET egress)
    token: str = Field(default="", max_length=64)   # re-poll an assisted token after delivering manually


class StoredXssRequest(BaseModel):
    view_url: str = Field(min_length=1, max_length=4000)   # where the stored content renders
    inject_url: str = Field(default="", max_length=4000)   # the form endpoint (auto-send only)
    field: str = Field(default="", max_length=200)         # the field to submit into (auto-send only)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)
    send: bool = Field(default=False)               # opt-in: POST the payload into the field
    marker: str = Field(default="", max_length=64)  # re-check an assisted marker after submitting manually
    cookie: str = Field(default="", max_length=8000)
    headers: list[str] = Field(default_factory=list, max_length=20)


class IdorRequest(BaseModel):
    url_a: str = Field(min_length=1, max_length=4000)   # account A's object URL
    url_b: str = Field(min_length=1, max_length=4000)   # account B's object URL (B owns this)
    a_cookie: str = Field(default="", max_length=8000)
    a_headers: list[str] = Field(default_factory=list, max_length=20)
    b_cookie: str = Field(default="", max_length=8000)
    b_headers: list[str] = Field(default_factory=list, max_length=20)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)


class BflaRequest(BaseModel):
    priv_url: str = Field(min_length=1, max_length=4000)   # the privileged/admin endpoint to test
    admin_cookie: str = Field(default="", max_length=8000)
    admin_headers: list[str] = Field(default_factory=list, max_length=20)
    user_cookie: str = Field(default="", max_length=8000)
    user_headers: list[str] = Field(default_factory=list, max_length=20)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)


class IdorProbeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4000)   # one authenticated object URL with a numeric id
    cookie: str = Field(default="", max_length=8000)
    headers: list[str] = Field(default_factory=list, max_length=20)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)


class HackerOneCredsRequest(BaseModel):
    team_handle: str = Field(default="", max_length=200)
    api_username: str = Field(default="", max_length=200)
    api_token: str = Field(default="", max_length=400)


class ProgramUpsertRequest(BaseModel):
    id: str | None = Field(default=None, max_length=120)
    name: str = Field(default="", max_length=200)
    platform: str = Field(default="manual", max_length=20)
    platform_handle: str = Field(default="", max_length=200)
    scope_text: str = Field(default="", max_length=4000)
    in_scope_hosts: list[str] = Field(default_factory=list)
    out_of_scope_hosts: list[str] = Field(default_factory=list)
    seed_targets: list[str] = Field(default_factory=list)
    active: bool = False
    live: bool = False
    deep: bool = False
    auto_submit: bool = False
    max_pages: int = Field(default=12, ge=1, le=50)
    interval_minutes: int = Field(default=1440, ge=5, le=20160)
    max_submits_per_day: int = Field(default=3, ge=0, le=25)
    enabled: bool = True


class ProgramDeleteRequest(BaseModel):
    id: str = Field(min_length=1, max_length=120)


class OperatorStartRequest(BaseModel):
    authorized: bool = False
    allow_submit: bool = False  # ARM auto-submit (still per-program opt-in + confirmed-only + dedup'd)


class OperatorEventsRequest(BaseModel):
    after: int = Field(default=0, ge=0)


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


def _confirm_route(fn):
    """Wrap a confirm route (IDOR / takeover / OOB-SSRF) so an unexpected service or
    report-render exception returns a structured ``{ok: False, error}`` the cockpit can
    display, instead of bubbling to the generic 500 handler and failing the whole request
    opaquely. The full traceback is logged server-side; the operator sees a short reason."""
    @functools.wraps(fn)
    def wrapper(self, request):
        try:
            return fn(self, request)
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator UI, never crashes the route
            self.log(traceback.format_exc())
            return {"ok": False, "error": f"{fn.__name__} failed: {exc.__class__.__name__}: {exc}"}
    return wrapper


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
        # Live agent runs, keyed by request_id: each holds a growing event list the
        # UI polls (start_agent_run / agent_run_events) so a run streams instead of
        # blocking on one big response.
        self.agent_runs: dict[str, dict[str, Any]] = {}
        # Bounded index of recent bounty runs, keyed by run_id: holds the minimal ctx +
        # per-ref findings a submission package needs to rebuild WITHOUT re-scanning.
        # In-memory only (drop-oldest); the on-disk report/JSON sidecar is the durable
        # copy. Lets the cockpit fetch a canonical build_submission package per finding.
        self.bounty_runs: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        # The autonomous operator loop (lazy — created on first start so its callables
        # bind to this runtime's hard-gated run_campaign + submit_finding).
        self._operator: "OperatorLoop | None" = None
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
                        "mode": "Friendly Direct",
                        "type": "local_companion",
                        "description": "Friendly local AI that learns the user's preferences.",
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
            _ml_available, _ml_error = _ml_runtime_status()  # cheap probe; no torch import
            return {
                "app": APP_NAME,
                "version": VERSION,
                "runtime_dir": str(RUNTIME_DIR),
                "local_model_available": _ml_available,
                "engine_loaded": engine is not None,
                "engine_ready": bool(engine and engine.ready),
                "engine_error": self.engine_error or (_ml_error if not _ml_available else ""),
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

    def get_engine(self) -> "SolinEngine":
        with self.lock:
            if self.engine is not None:
                return self.engine
            if not _ensure_ml_runtime():  # imports torch on first use only
                self.engine_error = _ML_RUNTIME_ERROR
                raise RuntimeError(_ML_RUNTIME_ERROR)
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
        # Serialize the read-modify-write so a concurrent save_coder_config/set_device
        # can't lose this update (self.lock is a reentrant RLock).
        with self.lock:
            payload = read_json(runtime_path, {})
            if not isinstance(payload, dict):
                payload = {}
            payload["device_preference"] = normalized
            write_json(runtime_path, payload)
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
        config = config if isinstance(config, dict) else {}
        return _merge_coder_secrets(config)

    def save_coder_config(self, update: dict[str, Any]) -> dict[str, Any]:
        runtime_path = RUNTIME_DIR / "solin_runtime_config.json"
        # Serialize the read-modify-write against set_device and concurrent saves so
        # an interleaved write can't drop the device_preference or another field.
        with self.lock:
            payload = read_json(runtime_path, {})
            if not isinstance(payload, dict):
                payload = {}
            # Merge the UI update, then split API keys out into the secrets store so
            # the main config stays key-free.
            payload["coder"] = _split_coder_secrets(coder.merge_update(payload.get("coder"), update))
            write_json(runtime_path, payload)
        return coder.public_config(self._coder_config())

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

    def delete_model(self, model: str) -> dict[str, Any]:
        target = (model or "").strip()
        if not target:
            return {"ok": False, "error": "No model specified."}
        with self.lock:
            if self.model_pull.get("active") and self.model_pull.get("model") == target:
                return {"ok": False, "error": "That model is still downloading."}
        host, _ = self._local_brain()
        try:
            coder.ollama_delete(host, target)
        except coder.CoderError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "deleted": target}

    def delete_core(self, core_id: str) -> dict[str, Any]:
        try:
            ai_core = self.store.delete_core(core_id, who="greyiq")
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "core_id": core_id, "ai_core": ai_core}

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
            snapshot_meta = self._persist_snapshot(request.workspace, result.get("snapshot") or [])
            return {
                "ok": True,
                "request_id": uuid4().hex,
                "message": friendly_branding(result["text"]),
                "transcript": result["transcript"],
                "steps": result["steps"],
                "changes": result.get("changes", []),
                "touched_files": result.get("touched_files", []),
                "plan": result.get("plan", []),
                "flagged_reads": result.get("flagged_reads", []),
                "completed": result.get("completed", False),
                "verified": result.get("verified", False),
                "outstanding": result.get("outstanding", []),
                "snapshot_available": snapshot_meta["available"],
                "snapshot_count": snapshot_meta["count"],
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
                "plan": [],
                "flagged_reads": [],
                "completed": False,
                "verified": False,
                "outstanding": [],
                "snapshot_available": False,
                "snapshot_count": 0,
            }

    def start_agent_run(self, request: AgentRequest) -> dict[str, Any]:
        """Kick off an agent run in the background and return its request_id. The
        UI polls agent_run_events() for live tool-by-tool progress and, when the
        run finishes, the same result payload /api/agent would have returned."""
        request_id = uuid4().hex
        record: dict[str, Any] = {"events": [], "done": False, "result": None}
        with self.lock:
            # Bound memory: drop the oldest finished runs once a few have piled up.
            finished = [rid for rid, rec in self.agent_runs.items() if rec.get("done")]
            for rid in finished[:-3]:
                self.agent_runs.pop(rid, None)
            self.agent_runs[request_id] = record

        def on_event(event: dict[str, Any]) -> None:
            with self.lock:
                record["events"].append(event)

        def worker() -> None:
            try:
                result = coding_agent.run_agent(
                    request.message,
                    request.history,
                    request.workspace,
                    self._coder_config(),
                    runtime_dir=RUNTIME_DIR,
                    seed_dir=SEED_DIR,
                    on_event=on_event,
                )
                snapshot_meta = self._persist_snapshot(request.workspace, result.get("snapshot") or [])
                payload = {
                    "ok": True,
                    "request_id": request_id,
                    "message": friendly_branding(result["text"]),
                    "transcript": result["transcript"],
                    "steps": result["steps"],
                    "changes": result.get("changes", []),
                    "touched_files": result.get("touched_files", []),
                    "plan": result.get("plan", []),
                    "flagged_reads": result.get("flagged_reads", []),
                    "completed": result.get("completed", False),
                    "verified": result.get("verified", False),
                    "outstanding": result.get("outstanding", []),
                    "snapshot_available": snapshot_meta["available"],
                    "snapshot_count": snapshot_meta["count"],
                    "model_name": f"{result['provider']}:{result['model']}",
                    "provider": result["provider"],
                }
            except coding_agent.AgentError as exc:
                payload = {"ok": False, "request_id": request_id, "message": str(exc)}
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI, never crashes the server
                self.log(f"Agent run failed: {exc}")
                payload = {"ok": False, "request_id": request_id, "message": f"Agent error: {exc}"}
            with self.lock:
                record["result"] = payload
                record["done"] = True

        threading.Thread(target=worker, name="agent-run", daemon=True).start()
        return {"ok": True, "request_id": request_id}

    def agent_run_events(self, request_id: str, cursor: int) -> dict[str, Any]:
        """Return events for a run since `cursor`, plus the final result once done.
        Polled by the UI; unknown ids report done so a stale poll loop stops."""
        with self.lock:
            record = self.agent_runs.get(request_id)
            if record is None:
                return {"ok": False, "error": "unknown agent run", "done": True, "events": [], "cursor": cursor}
            start = max(0, int(cursor or 0))
            events = record["events"][start:]
            response: dict[str, Any] = {
                "ok": True,
                "events": events,
                "cursor": start + len(events),
                "done": bool(record["done"]),
            }
            if record["done"]:
                response["result"] = record["result"]
            return response

    def _persist_snapshot(self, workspace: str, snapshot: list[dict[str, Any]]) -> dict[str, Any]:
        """Save the run's pre-edit snapshot (one per workspace, overwriting the
        prior one) so "Undo last agent run" can restore it later. Best-effort."""
        if not snapshot:
            return {"available": False, "count": 0}
        try:
            SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
            payload = {
                "workspace": str(Path(workspace).expanduser().resolve()),
                "created_at": datetime.now(UTC).isoformat(),
                "files": snapshot,
            }
            _snapshot_path(workspace).write_text(json.dumps(payload), encoding="utf-8")
            return {"available": True, "count": len(snapshot)}
        except OSError:
            return {"available": False, "count": 0}

    def agent_snapshot(self, request: AgentUndoRequest) -> dict[str, Any]:
        """Report whether an "Undo last agent run" snapshot exists for a workspace."""
        try:
            path = _snapshot_path(request.workspace)
            if not path.is_file():
                return {"available": False, "count": 0}
            data = json.loads(path.read_text(encoding="utf-8"))
            files = data.get("files") or []
            return {
                "available": bool(files),
                "count": len(files),
                "created_at": data.get("created_at"),
                "files": [str(entry.get("path") or "") for entry in files][:200],
            }
        except (OSError, json.JSONDecodeError):
            return {"available": False, "count": 0}

    def agent_undo(self, request: AgentUndoRequest) -> dict[str, Any]:
        """Restore the workspace to its state before the last agent run, then
        consume the snapshot so the same run can't be undone twice."""
        try:
            path = _snapshot_path(request.workspace)
            if not path.is_file():
                return {"ok": False, "error": "Nothing to undo — no snapshot from a recent agent run."}
            data = json.loads(path.read_text(encoding="utf-8"))
            outcome = coding_agent.restore_snapshot(data.get("files") or [], request.workspace)
            try:
                path.unlink()
            except OSError:
                pass
            return {"ok": True, "available": False, **outcome}
        except coding_agent.AgentError as exc:
            return {"ok": False, "error": str(exc)}
        except (OSError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": f"Could not read the snapshot: {exc}"}

    def project_memory_load(self, request: ProjectMemoryRequest) -> dict[str, Any]:
        try:
            return {"ok": True, **project_memory.load(RUNTIME_DIR, request.workspace)}
        except project_memory.ProjectMemoryError as exc:
            return {"ok": False, "error": str(exc), "facts": [], "updated_at": None}

    def project_memory_save(self, request: ProjectMemorySaveRequest) -> dict[str, Any]:
        try:
            return {"ok": True, **project_memory.save(RUNTIME_DIR, request.workspace, request.facts)}
        except (project_memory.ProjectMemoryError, OSError) as exc:
            return {"ok": False, "error": str(exc), "facts": [], "updated_at": None}

    def project_scan(self, request: ProjectMemoryRequest) -> dict[str, Any]:
        try:
            return {"ok": True, **project_memory.scan(RUNTIME_DIR, request.workspace, self._coder_config())}
        except (project_memory.ProjectMemoryError, OSError) as exc:
            return {"ok": False, "error": str(exc), "facts": [], "updated_at": None}

    def run_bounty(self, request: "BountyScanRequest") -> dict[str, Any]:
        result = run_bounty_hunt(
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
            active=request.active,
            time_based=request.time_based,
            auth={"cookie": request.auth_cookie, "headers": request.auth_headers},
            max_files=request.max_files,
            per_finding=request.per_finding,
        )
        self._cache_bounty_run(result, target=request.target, scope=request.scope, program=None)
        return result

    def run_campaign(self, request: "CampaignRequest") -> dict[str, Any]:
        # authorized passes straight through — campaign.run_campaign fails closed when
        # it is False, exactly like the CLI. No default-True anywhere.
        result = bounty_campaign.run_campaign(
            request.target,
            scope=request.scope,
            authorized=request.authorized,
            coder_cfg=self._coder_config(),
            default_reports_dir=RUNTIME_DIR / "reports",
            seed_dir=SEED_DIR,
            runtime_dir=RUNTIME_DIR,
            version=VERSION,
            active=request.active,
            time_based=request.time_based,
            auth={"cookie": request.auth_cookie, "headers": request.auth_headers},
            live=request.live,
            program=request.program,
            max_pages=request.max_pages,
            deep=request.deep,
        )
        self._cache_bounty_run(result, target=request.target, scope=request.scope, program=request.program)
        return result

    # ---- After-testing / submission workflow -------------------------------------
    def _cache_bounty_run(self, result: dict[str, Any], *, target: str, scope: str, program: str | None) -> None:
        """Index a finished run by a fresh run_id so a canonical per-finding submission
        package can be rebuilt without re-scanning. Stores only the minimal ctx + the
        per-ref findings (already redacted/scope-filtered by the report layer); bounded
        drop-oldest, in-memory. Mutates ``result`` to add ``run_id``."""
        if not result.get("ok") or not result.get("findings"):
            return
        run_id = uuid4().hex
        ctx = {
            "tool": "GreyIQ BugHunter", "version": VERSION,
            "generated_at": result.get("generated_at", ""),
            "target": target, "scope": scope,
            "attack_plans": result.get("attack_plans") or {},
        }
        findings_by_ref = {str(f.get("ref")): f for f in (result.get("findings") or []) if f.get("ref")}
        # Remember where this run wrote its artifacts so the whole engagement can be
        # bundled into a downloadable .zip later (a campaign writes a self-contained
        # folder; a single hunt is gathered by explicit file list).
        artifacts = {
            "is_campaign": bool(result.get("campaign_path")),
            "output_dir": result.get("output_dir", ""),
            "report_path": result.get("report_path", ""),
            "json_path": result.get("json_path", ""),
            "campaign_path": result.get("campaign_path", ""),
            "per_finding_paths": list(result.get("per_finding_paths") or []),
            "submission_paths": list(result.get("submission_paths") or []),
        }
        with self.lock:
            self.bounty_runs[run_id] = {
                "ctx": ctx, "findings": findings_by_ref, "program": program, "target": target,
                "artifacts": artifacts,
            }
            while len(self.bounty_runs) > 16:
                self.bounty_runs.popitem(last=False)  # evict oldest
        result["run_id"] = run_id

    def _resolve_run_finding(self, run_id: str, ref: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
        with self.lock:
            run = self.bounty_runs.get(run_id)
        if not run:
            return None, None, None
        return run["ctx"], run["findings"].get(ref), run

    def ingest_targets(self, request: "IngestTargetsRequest") -> dict[str, Any]:
        """Parse an operator-supplied CSV / Burp XML / HAR export into a normalized list of
        targets + hosts. Pure / no-network. It NEVER probes and NEVER adds a host to scope —
        the operator reviews the result and chooses to apply it; the fail-closed
        host_in_active_scope gate still governs every probe."""
        return bounty_ingest.ingest(request.content, request.kind)

    def build_submission_package(self, request: "SubmissionPackageRequest") -> dict[str, Any]:
        """Return the CANONICAL server-built submission package for one finding (the
        same build_submission used by the CLI/campaign) — never a client approximation.
        Pure/no-network."""
        ctx, finding, _ = self._resolve_run_finding(request.run_id, request.ref)
        if ctx is None:
            return {"ok": False, "error": "This run is no longer cached — re-run the hunt to rebuild submission packages."}
        if finding is None:
            return {"ok": False, "error": "Unknown finding for this run."}
        platform = bounty_formats.normalize_platform(request.platform)
        package = bounty_submission.build_submission(ctx, finding, platform)
        if package is None:
            return {"ok": False, "error": "This finding is not reportable (the report rules drop it, e.g. an unconfirmed credential lead)."}
        return {"ok": True, "package": package, "platform": platform}

    def capture_screenshot(self, request: "ScreenshotRequest") -> dict[str, Any]:
        """Capture a proof screenshot of a finding's PoC URL in a headless browser and
        record it on the cached run so the report/submission embed it. OPT-IN, scope-bound
        and SSRF-guarded (in screenshot_service); Playwright-lazy (degrades cleanly). The
        image is NOT auto-redacted — the response carries a warning and the screenshot is
        NEVER auto-attached to the HackerOne API submit."""
        import base64

        ctx, finding, run = self._resolve_run_finding(request.run_id, request.ref)
        if ctx is None:
            return {"ok": False, "error": "This run is no longer cached — re-run the hunt to capture a screenshot."}
        if finding is None:
            return {"ok": False, "error": "Unknown finding for this run."}
        url = bounty_screenshot.poc_url_for_finding(finding, ctx)
        if not url:
            return {"ok": False, "error": "No proof-of-concept URL to screenshot for this finding (it has no captured request or URL location)."}
        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        out_path = RUNTIME_DIR / "screenshots" / f"{safe(request.run_id)}-{safe(request.ref)}.png"
        # Resolve the FRESHEST scope at capture time, not just the scope frozen into the
        # cached run: union (1) the run's own scope, (2) the live program's current
        # scope_text — so editing a saved program's scope takes effect WITHOUT re-running
        # the hunt — and (3) an optional scope the caller passes (the cockpit's current
        # Scope box). All three are operator-supplied authorizations; the fail-closed
        # host_in_active_scope gate still runs against the union, so this only ever WIDENS
        # to hosts the operator has explicitly named.
        scope_sources = [str(ctx.get("scope") or "")]
        program_id = str((run or {}).get("program") or "")
        if program_id:
            prog = bounty_portfolio.get_program(RUNTIME_DIR, program_id)
            if prog:
                scope_sources.append(str(prog.get("scope_text") or ""))
        if request.scope.strip():
            scope_sources.append(request.scope)
        scope = " ".join(s for s in scope_sources if s.strip())
        result = bounty_screenshot.capture_screenshot(
            url, out_path, scope=scope, authorized=True, full_page=request.full_page,
        )
        if not result.get("ok"):
            return result
        # Record on the cached finding so build_submission/report embed it by basename.
        finding["screenshot_path"] = result["path"]
        if run is not None:
            run.setdefault("screenshots", {})[request.ref] = result["path"]
        data_url = ""
        try:
            raw = Path(result["path"]).read_bytes()
            if len(raw) <= 4_000_000:  # inline preview for the cockpit; skip if huge
                data_url = "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
        except OSError:
            pass
        return {
            "ok": True, "path": result["path"], "url": result.get("url"), "final_url": result.get("final_url"),
            "title": result.get("title"), "bytes": result.get("bytes"), "warning": result.get("warning"),
            "data_url": data_url,
        }

    def research_finding(self, request: "ResearchRequest") -> dict[str, Any]:
        """Research one lead with the CONFIGURED brain (Claude/ChatGPT/local) — or a
        deterministic offline dossier when no brain is on. Writes the dossier into the
        run's research folder so it's included in the downloadable bundle. Brain-only:
        no external/internet calls."""
        ctx, finding, run = self._resolve_run_finding(request.run_id, request.ref)
        if ctx is None:
            return {"ok": False, "error": "This run is no longer cached — re-run the hunt to research it."}
        if finding is None:
            return {"ok": False, "error": "Unknown finding for this run."}
        dossier = bounty_research.build_dossier(finding, ctx, self._coder_config())
        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        out_path = RUNTIME_DIR / "research" / f"{safe(request.run_id)}-{safe(request.ref)}.md"
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(dossier["markdown"], encoding="utf-8")
            finding["research_path"] = str(out_path)
            if run is not None:
                run.setdefault("research_paths", {})[request.ref] = str(out_path)
            written = str(out_path)
        except OSError:
            written = ""
        return {
            "ok": True, "markdown": dossier["markdown"], "used_brain": dossier["used_brain"],
            "model": dossier["model"], "path": written,
        }

    def _persist_finding_run(self, *, findings: list[dict[str, Any]], plans: dict[str, Any],
                             target: str, scope: str, platform: str, slug: str, host: Any,
                             json_extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """Shared tail for the confirm routes (IDOR / takeover / OOB-SSRF): build the report
        ctx, render every finding for the chosen platform, write the ``.md`` + ``.json``
        sidecar, and cache the result as a run so every per-finding action (per-platform
        report, screenshot, research, bundle, the hard-gated submit) resolves later.

        Centralises three near-identical ~30-line tails so they can't drift, and guarantees
        the JSON evidence sidecar on every path (the OOB route previously skipped it).
        Returns the bits the caller folds into its own response shape."""
        # Resolve each finding's severity ONCE (CVSS-preferred) and write it back, so the
        # toast the cockpit shows, the cached run, the report, and the H1 rating can't
        # disagree — every later reader sees the same severity word.
        for f in findings:
            f["severity"] = bounty_report.resolve_severity(f, plans.get(f.get("ref")))
        gen = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        platform = bounty_formats.normalize_platform(platform)
        ctx = {"tool": "GreyIQ BugHunter", "version": VERSION, "generated_at": gen,
               "target": target, "scope": scope, "attack_plans": plans}
        report_md = "\n\n---\n\n".join(bounty_formats.render_finding(ctx, f, platform) for f in findings)

        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        out_dir = RUNTIME_DIR / "reports"
        md_path = out_dir / f"{slug}-{safe(host)}-{stamp}.md"
        json_path = out_dir / f"{slug}-{safe(host)}-{stamp}.json"
        payload: dict[str, Any] = {"findings": findings, "attack_plans": plans}
        if json_extra:
            payload.update(json_extra)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            md_path.write_text(report_md, encoding="utf-8")
            json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            report_path, json_out = str(md_path), str(json_path)
        except OSError:
            report_path, json_out = "", ""

        # Per-ref proof status mirrors each plan's own proof_of_impact.status (defaults to
        # confirmed for the active confirm routes; "candidate" for version-fingerprint runs
        # like known-CVE) so the cached run never overstates a candidate as confirmed. The
        # submit gate independently recomputes this from the finding/plan, so this is
        # informational — but it must still be accurate.
        result = {"ok": True, "generated_at": gen, "findings": findings, "attack_plans": plans,
                  "proof_of_impact": {ref: {"status": str(((plans.get(ref) or {}).get("proof_of_impact") or {}).get("status", "confirmed"))} for ref in plans},
                  "report_path": report_path, "json_path": json_out, "output_dir": str(out_dir)}
        self._cache_bounty_run(result, target=target, scope=scope, program=None)
        return {"run_id": result.get("run_id"), "platform": platform, "report": report_md,
                "report_path": report_path, "json_path": json_out, "generated_at": gen}

    @_confirm_route
    def scan_takeover(self, request: "TakeoverRequest") -> dict[str, Any]:
        """Enumerate subdomains of the target's apex and confirm dangling takeovers. Each
        confirmed takeover is cached as a run finding (report/screenshot/research/bundle/
        submit all work). GET-only, scope-bound, SSRF-guarded — no resource is ever claimed."""
        res = bounty_takeover.scan_subdomain_takeover(request.target, scope=request.scope)
        if not res.get("ok"):
            return res
        findings = res.get("findings") or []
        summary = {"ok": True, "apex": res.get("apex"), "resolved": res.get("resolved") or [],
                   "resolved_count": len(res.get("resolved") or []), "count": len(findings), "run_id": None,
                   "findings": [{"title": f["title"], "severity": f["severity"], "service": f.get("_takeover_service"),
                                 "location": f["location"]} for f in findings]}
        if not findings:
            return summary

        plans: dict[str, Any] = {}
        for i, f in enumerate(findings, 1):
            f["ref"] = f"F{i}"
            plans[f["ref"]] = bounty_takeover.build_plan(f)
        persisted = self._persist_finding_run(
            findings=findings, plans=plans, target=request.target, scope=request.scope,
            platform=request.platform, slug="takeover", host=res.get("apex"))
        summary["run_id"] = persisted["run_id"]
        summary["report"] = persisted["report"]
        # Rebuild the summary list AFTER persist so its severities reflect the resolved
        # (CVSS-preferred) value written back onto each finding, not the raw scanner label.
        summary["findings"] = [{"title": f["title"], "severity": f["severity"],
                                "service": f.get("_takeover_service"), "location": f["location"]} for f in findings]
        return summary

    @_confirm_route
    def scan_cve(self, request: "CveScanRequest") -> dict[str, Any]:
        """Fingerprint the target's front-end library versions and flag outdated components
        with known CVEs. These are version-fingerprint CANDIDATES (not confirmed exploits):
        each is cached as a run so the operator can export the outdated-component report /
        bundle, but the hard submit gate (which recomputes proof_status) will refuse to
        auto-file a candidate. GET-only, in-scope, SSRF-guarded."""
        res = bounty_cve.scan_known_cves(request.target, scope=request.scope)
        if not res.get("ok"):
            return res
        findings = res.get("findings") or []
        summary = {"ok": True, "host": res.get("host"), "target": res.get("target"),
                   "components": res.get("components") or [], "count": len(findings), "run_id": None,
                   "findings": [{"title": f["title"], "severity": f["severity"],
                                 "product": f.get("_cve_product"), "location": f["location"]} for f in findings]}
        if not findings:
            return summary

        plans: dict[str, Any] = {}
        for i, f in enumerate(findings, 1):
            f["ref"] = f"F{i}"
            plans[f["ref"]] = bounty_cve.build_plan(f)
        persisted = self._persist_finding_run(
            findings=findings, plans=plans, target=request.target, scope=request.scope,
            platform=request.platform, slug="cve", host=res.get("host"))
        summary["run_id"] = persisted["run_id"]
        summary["report"] = persisted["report"]
        summary["findings"] = [{"title": f["title"], "severity": f["severity"],
                                "product": f.get("_cve_product"), "location": f["location"]} for f in findings]
        return summary

    @_confirm_route
    def check_idor(self, request: "IdorRequest") -> dict[str, Any]:
        """Confirm IDOR/BOLA via a dual-session differential (the operator's two test
        accounts). On a CONFIRMED cross-tenant read, cache it as a run so every per-finding
        action (per-platform report, screenshot, research, bundle, the hard-gated submit)
        works on it. The proof is the differential only — never another user's raw data."""
        res = bounty_access.run_idor_check(
            request.url_a, request.url_b,
            account_a={"cookie": request.a_cookie, "headers": request.a_headers},
            account_b={"cookie": request.b_cookie, "headers": request.b_headers},
            scope=request.scope,
        )
        if not res.get("ok"):
            return res
        status = res["status"]
        if status != "confirmed":
            return {"ok": True, "status": status, "reason": res.get("reason", ""), "detail": res.get("detail")}

        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.url_a).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.url_a, scope=request.scope,
            platform=request.platform, slug="idor", host=host,
            json_extra={"detail": res.get("detail")})
        return {
            "ok": True, "status": "confirmed", "run_id": persisted["run_id"], "ref": "F1",
            "platform": persisted["platform"], "report": persisted["report"], "detail": res.get("detail"),
            "title": finding["title"], "severity": finding["severity"],
        }

    @_confirm_route
    def check_bfla(self, request: "BflaRequest") -> dict[str, Any]:
        """Confirm BFLA (broken function-level authorization) via a three-session differential
        (admin / low-priv user / anon). On a CONFIRMED bypass, cache it as a run so every
        per-finding action works on it. The proof is the differential only — never the
        privileged body."""
        res = bounty_access.run_bfla_check(
            request.priv_url,
            admin_account={"cookie": request.admin_cookie, "headers": request.admin_headers},
            user_account={"cookie": request.user_cookie, "headers": request.user_headers},
            scope=request.scope,
        )
        if not res.get("ok"):
            return res
        status = res["status"]
        if status != "confirmed":
            return {"ok": True, "status": status, "reason": res.get("reason", ""), "detail": res.get("detail")}

        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.priv_url).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.priv_url, scope=request.scope,
            platform=request.platform, slug="bfla", host=host,
            json_extra={"detail": res.get("detail")})
        return {
            "ok": True, "status": "confirmed", "run_id": persisted["run_id"], "ref": "F1",
            "platform": persisted["platform"], "report": persisted["report"], "detail": res.get("detail"),
            "title": finding["title"], "severity": finding["severity"],
        }

    @_confirm_route
    def check_idor_probe(self, request: "IdorProbeRequest") -> dict[str, Any]:
        """Single-session IDOR DISCOVERY: mutate the URL's numeric ids and flag a neighbouring
        distinct object as a CANDIDATE. Caches a candidate run (report/bundle work; the submit
        gate refuses a candidate). Confirm cross-tenant with the dual-session check_idor."""
        res = bounty_access.run_idor_probe(
            request.url, account={"cookie": request.cookie, "headers": request.headers}, scope=request.scope)
        if not res.get("ok"):
            return res
        if res.get("status") != "candidate" or "finding" not in res:
            return {"ok": True, "status": res.get("status"), "reason": res.get("reason", ""), "detail": res.get("detail")}

        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.url).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.url, scope=request.scope,
            platform=request.platform, slug="idor-probe", host=host, json_extra={"detail": res.get("detail")})
        return {
            "ok": True, "status": "candidate", "run_id": persisted["run_id"], "ref": "F1",
            "platform": persisted["platform"], "report": persisted["report"], "detail": res.get("detail"),
            "title": finding["title"], "severity": finding["severity"],
        }

    def export_bundle(self, request: "BundleRequest") -> dict[str, Any]:
        """Zip the whole engagement (reports, per-platform packages, evidence,
        screenshots, research dossiers, JSON) for download. A campaign's self-contained
        folder is zipped whole; a single hunt's artifacts are gathered by file list. The
        .zip is returned inline (base64) under a size cap, else by path. Local only."""
        import base64

        with self.lock:
            run = self.bounty_runs.get(request.run_id)
        if not run:
            return {"ok": False, "error": "This run is no longer cached — re-run the hunt to rebuild the bundle."}
        art = run.get("artifacts") or {}
        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        out_zip = RUNTIME_DIR / "bundles" / f"engagement-{safe(request.run_id)}.zip"
        if art.get("is_campaign") and art.get("output_dir") and Path(art["output_dir"]).is_dir():
            res = bounty_bundle.bundle_directory(art["output_dir"], out_zip)
        else:
            specs: list[tuple[str, str]] = []
            for key in ("report_path", "json_path"):
                if art.get(key):
                    specs.append((Path(art[key]).name, art[key]))
            for p in art.get("per_finding_paths") or []:
                specs.append((f"findings/{Path(p).name}", p))
            for p in art.get("submission_paths") or []:
                specs.append((f"submissions/{Path(p).name}", p))
            for p in (run.get("screenshots") or {}).values():
                specs.append((f"screenshots/{Path(p).name}", p))
            for p in (run.get("research_paths") or {}).values():
                specs.append((f"research/{Path(p).name}", p))
            res = bounty_bundle.bundle_files(specs, out_zip)
        if not res.get("ok"):
            return res
        download_b64 = ""
        zip_bytes = int(res.get("zip_bytes") or 0)
        if 0 < zip_bytes <= 20 * 1024 * 1024:  # inline for the browser; larger -> path only
            try:
                download_b64 = base64.b64encode(Path(res["path"]).read_bytes()).decode("ascii")
            except OSError:
                download_b64 = ""
        return {
            "ok": True, "path": res["path"], "filename": f"greyiq-engagement-{safe(request.run_id)[:12]}.zip",
            "zip_bytes": zip_bytes, "file_count": res.get("file_count"), "skipped": res.get("skipped") or [],
            "download_b64": download_b64, "inline": bool(download_b64),
        }

    def submit_finding(self, request: "SubmitRequest") -> dict[str, Any]:
        """File one CONFIRMED finding to HackerOne via the hard-gated submit. The gate
        lives in submission.submit_to_hackerone and is unbypassable: proof_status is
        recomputed server-side from the cached ctx, so a forged confirm can't push a
        non-confirmed finding. Creds come from the perms-restricted secrets store, never
        the request body. The ONLY path here that touches the network."""
        if bounty_formats.normalize_platform(request.platform) != "hackerone":
            return {"ok": False, "error": "Only the HackerOne API submit is wired. Export the package (Copy report / Download .md) and file it on the other platforms."}
        pkg_result = self.build_submission_package(SubmissionPackageRequest(run_id=request.run_id, ref=request.ref, platform="hackerone"))
        if not pkg_result.get("ok"):
            return pkg_result
        package = pkg_result["package"]
        handle, username, token = self._hackerone_creds()
        try:
            outcome = bounty_submission.submit_to_hackerone(
                package, team_handle=handle, api_username=username, api_token=token, confirm=request.confirm,
            )
        except bounty_submission.SubmissionError as exc:
            return {"ok": False, "error": str(exc)}
        # Record the submission to the learning store + triage so the loop closes.
        _, finding, run = self._resolve_run_finding(request.run_id, request.ref)
        if finding is not None:
            try:
                bounty_learning.record_outcome(
                    RUNTIME_DIR, program=(run or {}).get("program"), target=(run or {}).get("target", ""),
                    class_id=str(finding.get("class_id") or "other"), title=str(finding.get("title") or ""),
                    status="submitted", severity=str(finding.get("severity") or ""),
                    notes=f"HackerOne report {outcome.get('report_id', '')}",
                )
            except ValueError:
                pass
        return {"ok": True, **outcome}

    def hackerone_creds_status(self) -> dict[str, Any]:
        """Creds presence for the UI — NEVER returns the API token."""
        stored = _load_secrets()
        return {
            "ok": True,
            "team_handle": stored.get("hackerone.team_handle", ""),
            "api_username": stored.get("hackerone.api_username", ""),
            "has_token": bool(stored.get("hackerone.api_token")),
        }

    def save_hackerone_creds(self, request: "HackerOneCredsRequest") -> dict[str, Any]:
        # Empty string clears that field (matches _store_secret's pop). Stored in the
        # same perms-restricted, atomically-written secrets file as the provider keys.
        _store_secret("hackerone.team_handle", request.team_handle.strip())
        _store_secret("hackerone.api_username", request.api_username.strip())
        if request.api_token:  # never clear the token on an empty submit of the form
            _store_secret("hackerone.api_token", request.api_token.strip())
        return self.hackerone_creds_status()

    def _hackerone_creds(self) -> tuple[str, str, str]:
        stored = _load_secrets()
        return (stored.get("hackerone.team_handle", ""), stored.get("hackerone.api_username", ""), stored.get("hackerone.api_token", ""))

    # ---- OOB collaborator (out-of-band blind-bug confirmation) --------------------
    def _oob_config(self) -> tuple[str, str]:
        stored = _load_secrets()
        return (stored.get("oob.collaborator_url", ""), stored.get("oob.secret", ""))

    def oob_config_status(self) -> dict[str, Any]:
        """Collaborator config for the UI — NEVER returns the secret, only its presence."""
        url, secret = self._oob_config()
        return {"ok": True, "collaborator_url": url, "has_secret": bool(secret)}

    def save_oob_config(self, request: "OobConfigRequest") -> dict[str, Any]:
        _store_secret("oob.collaborator_url", request.collaborator_url.strip())
        if request.secret:  # don't clear the secret on an empty submit of the form
            _store_secret("oob.secret", request.secret.strip())
        return self.oob_config_status()

    def oob_mint(self) -> dict[str, Any]:
        """Mint a token + its callback URL to paste into a manual blind payload (XXE/XSS)."""
        base, secret = self._oob_config()
        if not base or not secret:
            return {"ok": False, "error": "Configure the OOB collaborator URL + secret first."}
        token = bounty_oob.mint_token()
        return {"ok": True, "token": token, "callback_url": bounty_oob.callback_url(base, token)}

    def oob_poll(self, request: "OobPollRequest") -> dict[str, Any]:
        base, secret = self._oob_config()
        return bounty_oob.poll_collaborator(base, secret, request.token)

    @_confirm_route
    def check_oob_ssrf(self, request: "OobSsrfRequest") -> dict[str, Any]:
        """Confirm blind SSRF out-of-band: inject the collaborator callback into the
        target's params, probe, and poll. A confirmed hit is cached as a run finding."""
        base, secret = self._oob_config()
        res = bounty_oob.confirm_blind_ssrf(request.url, base=base, secret=secret, scope=request.scope)
        if not res.get("ok"):
            return res
        if res.get("status") != "confirmed":
            return {"ok": True, "status": res.get("status"), "reason": res.get("reason", ""), "params_tried": res.get("params_tried", [])}

        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.url).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.url, scope=request.scope,
            platform=request.platform, slug="oob-ssrf", host=host)
        return {"ok": True, "status": "confirmed", "run_id": persisted["run_id"], "ref": "F1",
                "platform": persisted["platform"], "report": persisted["report"],
                "param": res.get("param"), "token": res.get("token"),
                "title": finding["title"], "severity": finding["severity"]}

    @_confirm_route
    def check_oob_xxe(self, request: "OobXxeRequest") -> dict[str, Any]:
        """Confirm blind XXE out-of-band. Assisted by default (mint + hand back payload
        variants to deliver, then re-poll the token); ``send=True`` opts in to GreyIQ POSTing
        the benign payload itself (the only non-GET egress). A confirmed/candidate hit is
        cached as a run finding; a 'ready'/'no-callback' result returns the payloads + token."""
        base, secret = self._oob_config()
        res = bounty_oob.confirm_blind_xxe(
            request.url, base=base, secret=secret, scope=request.scope,
            send=bool(request.send), token=(request.token or None))
        if not res.get("ok"):
            return res
        status = res.get("status")
        if status not in {"confirmed", "candidate"}:
            # ready / no-callback / send-failed: hand back the kit (payloads + token) so the
            # operator can deliver out-of-band and re-poll. Nothing is cached as a run.
            return {"ok": True, "status": status, "token": res.get("token"),
                    "payloads": res.get("payloads"), "callback_url": res.get("callback_url"),
                    "reason": res.get("reason", ""), "error": res.get("error", "")}

        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.url).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.url, scope=request.scope,
            platform=request.platform, slug="oob-xxe", host=host)
        return {"ok": True, "status": status, "run_id": persisted["run_id"], "ref": "F1",
                "platform": persisted["platform"], "report": persisted["report"], "token": res.get("token"),
                "title": finding["title"], "severity": finding["severity"]}

    @_confirm_route
    def check_stored_xss(self, request: "StoredXssRequest") -> dict[str, Any]:
        """Confirm stored XSS. Assisted by default (mint a marker payload, hand it back to
        submit, then re-check the view URL); ``send=True`` opts in to GreyIQ POSTing the payload
        into the field itself. A confirmed render caches a run; a 'ready' result returns the
        payload kit + marker."""
        res = bounty_stored_xss.confirm_stored_xss(
            view_url=request.view_url, inject_url=request.inject_url, field=request.field,
            scope=request.scope, send=bool(request.send), marker=(request.marker or None),
            cookie=request.cookie, headers=request.headers)
        if not res.get("ok"):
            return res
        if res.get("status") != "confirmed":
            return {"ok": True, "status": res.get("status"), "marker": res.get("marker"),
                    "payloads": res.get("payloads"), "reason": res.get("reason", ""), "error": res.get("error", "")}

        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.view_url).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.view_url, scope=request.scope,
            platform=request.platform, slug="stored-xss", host=host, json_extra={"detail": res.get("detail")})
        return {"ok": True, "status": "confirmed", "run_id": persisted["run_id"], "ref": "F1",
                "platform": persisted["platform"], "report": persisted["report"], "marker": res.get("marker"),
                "title": finding["title"], "severity": finding["severity"]}

    # ---- Autonomous operator ------------------------------------------------------
    def _operator_run_campaign(self, target: str, *, scope: str, program: str, active: bool, live: bool,
                               deep: bool = False, max_pages: int = 12) -> dict[str, Any]:
        """The operator's run_campaign_fn — goes through runtime.run_campaign so the
        run is cached (run_id) and the submit path can resolve it. authorized=True
        because the operator only runs after the user explicitly armed it (the start
        endpoint requires authorized); scope stays the fail-closed gate. ``deep`` carries
        the program's deep-mode flag (time-based SQLi + screenshot/research per confirmed
        lead) through unchanged."""
        return self.run_campaign(CampaignRequest(
            target=target, scope=scope, authorized=True, program=program,
            active=active, live=live, deep=deep, max_pages=max_pages,
        ))

    def _operator_submit(self, run_id: str, ref: str) -> dict[str, Any]:
        """The operator's submit_fn — the SAME hard-gated runtime.submit_finding (confirm
        + server-recomputed proof_status=='confirmed' + creds). Unforgeable by the loop."""
        return self.submit_finding(SubmitRequest(run_id=run_id, ref=ref, confirm=True, platform="hackerone"))

    def _get_operator(self) -> "OperatorLoop":
        with self.lock:
            if self._operator is None:
                self._operator = OperatorLoop(
                    str(RUNTIME_DIR),
                    run_campaign_fn=self._operator_run_campaign,
                    submit_fn=self._operator_submit,
                )
            return self._operator

    def list_programs(self) -> dict[str, Any]:
        return {"ok": True, "programs": bounty_portfolio.list_programs(RUNTIME_DIR)}

    def upsert_program(self, request: "ProgramUpsertRequest") -> dict[str, Any]:
        record = request.model_dump(exclude_none=True)
        return {"ok": True, "program": bounty_portfolio.upsert_program(RUNTIME_DIR, record)}

    def remove_program(self, program_id: str) -> dict[str, Any]:
        return {"ok": bounty_portfolio.remove_program(RUNTIME_DIR, program_id)}

    def operator_start(self, request: "OperatorStartRequest") -> dict[str, Any]:
        if not request.authorized:
            return {"ok": False, "error": "Confirm you are authorized to run the portfolio's programs (set authorized)."}
        started = self._get_operator().start(allow_submit=bool(request.allow_submit))
        return {"ok": True, "started": started, "allow_submit": bool(request.allow_submit),
                "note": "auto-submit ARMED — confirmed, non-duplicate findings will be filed within each program's daily cap." if request.allow_submit
                        else "review-only — findings are hunted and queued; nothing is auto-filed."}

    def operator_stop(self) -> dict[str, Any]:
        if self._operator is not None:
            self._operator.stop()
        return {"ok": True}

    def operator_events(self, after: int = 0) -> dict[str, Any]:
        if self._operator is None:
            return {"ok": True, "running": False, "events": [], "count": 0}
        return {"ok": True, **self._operator.event_tail(after=after)}

    def operator_pipeline(self) -> dict[str, Any]:
        return {
            "ok": True,
            "funnel": bounty_ledger.funnel(RUNTIME_DIR),
            "programs": bounty_portfolio.list_programs(RUNTIME_DIR),
            "learning": bounty_learning.program_summary(RUNTIME_DIR),
            "running": bool(self._operator and self._operator.running),
        }

    def record_outcome(self, request: "LearnRequest") -> dict[str, Any]:
        try:
            prog = bounty_learning.record_outcome(
                RUNTIME_DIR,
                program=request.program,
                target=request.target,
                class_id=request.class_id,
                title=request.title,
                status=request.status,
                bounty=request.bounty,
                severity=request.severity,
                notes=request.notes,
            )
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "program": bounty_learning.program_key(request.program, request.target), "stats": prog}

    def bounty_stats(self, program: str | None, target: str) -> dict[str, Any]:
        return {
            "ok": True,
            "summary": bounty_learning.program_summary(RUNTIME_DIR, program, target or ""),
            "intelligence": bounty_learning.program_intelligence(RUNTIME_DIR, program, target or ""),
        }

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
            core = active_core_for_request(self.store, request)
            source_ids = normalize_source_ids(core.get("sourceIds") or request.bot.get("sourceIds") or [])
            seed_training_note(request)
            response, citations, diagnostics = engine.generate_reply(
                request.message,
                max_new_tokens=request.max_new_tokens,
                temperature=request.temperature,
                auto_capture=request.auto_capture,
                mode=request.mode,
                core_contract=core,
                source_ids=source_ids,
            )
            response = friendly_branding(response)
            return {
                "request_id": uuid4().hex,
                "message": response,
                "used_fallback": bool(diagnostics.used_fallback),
                "captured_for_training": bool(diagnostics.captured_for_training),
                "confidence": diagnostics.confidence,
                "diagnostics": diagnostics_payload(
                    diagnostics,
                    citation_count=len(citations),
                    engine_ready=bool(engine.ready),
                    runtime_device=engine.device_info.name,
                ),
                "model_name": engine.model_path.name if engine.model_path else "none",
                "device": engine.device_info.name,
                "citations": [
                    {
                        "source": match.source,
                        "source_id": match.source_id,
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
                "confidence": 0.18,
                "diagnostics": {
                    "used_fallback": True,
                    "captured_for_training": False,
                    "intent": "unknown",
                    "mode": "fallback",
                    "strategy": "api_exception",
                    "confidence": 0.18,
                    "retrieval_count": 0,
                    "memory_count": 0,
                    "note_count": 0,
                    "citation_count": 0,
                    "engine_ready": False,
                    "device": "browser",
                },
                "model_name": "fallback",
                "device": "browser",
                "citations": [],
                "ai_core": self.store.load(),
                "error": str(exc),
            }

    def start_training(self, request: TrainingRequest) -> dict[str, Any]:
        if not _ensure_ml_runtime():  # imports torch on first use only
            raise HTTPError(503, _ML_RUNTIME_ERROR)
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


def core_id_for_bot(bot: dict[str, Any] | None) -> str:
    if not isinstance(bot, dict):
        return DEFAULT_CORE_ID
    explicit = str(bot.get("coreId") or bot.get("core_id") or "").strip()
    if explicit:
        return explicit
    raw_id = str(bot.get("id") or bot.get("name") or "").strip()
    if not raw_id:
        return DEFAULT_CORE_ID
    return f"core_{slugify(raw_id, 'greyiq')}"


def active_core_for_request(store: AICoreStore, request: ChatRequest) -> dict[str, Any]:
    state = store.load()
    cores = [core for core in state.get("cores", []) if isinstance(core, dict)]
    requested_id = core_id_for_bot(request.bot)
    core = next((item for item in cores if item.get("id") == requested_id), None)
    if core is None:
        deployment = next(
            (
                item
                for item in state.get("deployments", [])
                if item.get("channel") == "GreyIQ Chat"
            ),
            None,
        )
        deployed_core_id = str((deployment or {}).get("coreId") or DEFAULT_CORE_ID)
        core = next((item for item in cores if item.get("id") == deployed_core_id), None)
    return core or (cores[0] if cores else {})


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
    # Atomic: a crash or concurrent reader must never see a truncated config file.
    _atomic_write(path, json.dumps(payload, indent=2))


def default_training_text() -> str:
    lines = [
        "GreyIQ is a friendly local AI.",
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
    _write_session_token()
    _migrate_coder_secrets()
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


def diagnostics_payload(
    diagnostics: Any,
    *,
    citation_count: int,
    engine_ready: bool,
    runtime_device: str,
) -> dict[str, Any]:
    return {
        "used_fallback": bool(getattr(diagnostics, "used_fallback", False)),
        "captured_for_training": bool(getattr(diagnostics, "captured_for_training", False)),
        "intent": str(getattr(diagnostics, "intent_label", "") or "unknown"),
        "mode": str(getattr(diagnostics, "mode", "") or "default"),
        "strategy": str(getattr(diagnostics, "strategy", "") or "unknown"),
        "confidence": float(getattr(diagnostics, "confidence", 0.0) or 0.0),
        "retrieval_count": int(getattr(diagnostics, "retrieval_count", 0) or 0),
        "memory_count": int(getattr(diagnostics, "memory_count", 0) or 0),
        "note_count": int(getattr(diagnostics, "note_count", 0) or 0),
        "citation_count": int(citation_count),
        "engine_ready": bool(engine_ready),
        "device": runtime_device,
    }


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
    # Lazy: pulls pytesseract -> pandas (~1.4s). Kept off the boot path.
    from document_ingest import (
        collect_supported_files,
        ingest_source_files,
        summarize_ingest,
        supported_extensions,
    )

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
    """Curated Pentest Toolkit catalog plus friendly vuln-class names for UI badges."""
    payload = toolkit_lib.catalog_payload(SEED_DIR, RUNTIME_DIR)
    payload["vuln_classes"] = vuln_class_names()
    return payload


def normalize_rating(value: str | None) -> str:
    rating = str(value or "").strip().lower()
    if rating in {"like", "liked", "prefer", "preferred", "thumbs_up", "up"}:
        return "like"
    if rating in {"dislike", "avoid", "rejected", "thumbs_down", "down"}:
        return "dislike"
    return rating


def preference_training_entry(request: PreferenceRequest) -> tuple[str, str]:
    bot = request.bot or {}
    bot_name = str(bot.get("name") or "GreyIQ").strip()
    rating = normalize_rating(request.rating)
    chunks: list[str] = []
    target_file = "greyiq_personal_choices.txt"

    if request.preference:
        chunks.append(f"{bot_name} should prefer: {request.preference.strip()}")
    if request.user and request.assistant:
        user_text = request.user.strip()
        assistant_text = request.assistant.strip()
        if rating == "dislike":
            chunks.append(
                "\n".join(
                    [
                        f"{bot_name} should avoid this response pattern for similar requests.",
                        f"User asked: {user_text}",
                        f"Rejected response: {assistant_text}",
                    ]
                )
            )
        else:
            target_file = "greyiq_preferred_examples.txt"
            chunks.append(
                f"<START_CONVO>\n<USER>\n{user_text}\n<ASSISTANT>\n{assistant_text}\n<END_CONVO>"
            )
    if request.training_text:
        target_file = source_training_file(request.source_id)
        source_name = request.source_name or request.source_id or "Training Data"
        chunks.append(f"Source: {source_name}\n{request.training_text.strip()}")
    if rating:
        chunks.append(f"Feedback rating: {rating}")

    return target_file, "\n".join(chunk for chunk in chunks if chunk.strip())


def preferences(request: PreferenceRequest) -> dict[str, Any]:
    target_file, training_text = preference_training_entry(request)
    path = append_training_text(target_file, training_text)
    return {"ok": True, "path": str(path), "source_id": request.source_id}


def repo_ingest(request: RepoIngestRequest) -> dict[str, Any]:
    clean_sources = [source.strip() for source in request.sources if str(source or "").strip()]
    if not clean_sources:
        raise HTTPError(422, "At least one repository path or Git URL is required.")
    return ingest_repositories(
        clean_sources,
        runtime_dir=RUNTIME_DIR,
        max_total_chars=request.max_total_chars,
        max_files_per_repo=request.max_files_per_repo,
        logger=runtime.log,
    )


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
    total = 0
    more_body = True
    while more_body:
        message = await receive()
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise HTTPError(413, f"Request body too large (limit {MAX_REQUEST_BYTES} bytes).")
        chunks.append(chunk)
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
        (b"access-control-allow-headers", b"content-type,accept,x-greyiq-token"),
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


async def send_index(send: Any) -> None:
    """Serve index.html with the per-session token injected into its <meta> tag, so
    the same-origin app can authenticate its /api/* calls."""
    try:
        html = (PUBLIC_DIR / "index.html").read_text(encoding="utf-8")
    except OSError:
        await send_json(send, {"error": "not found"}, 404)
        return
    body = html.replace(SESSION_TOKEN_PLACEHOLDER, SESSION_TOKEN).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": response_headers("text/html; charset=utf-8", len(body)),
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

    # Session-token gate: /api/* (except liveness) requires the per-session token,
    # so other local processes can't drive the API over 127.0.0.1.
    if path.startswith("/api/") and path != "/api/health" and not _session_authorized(scope):
        await send_json(send, {"error": "missing or invalid session token"}, 403)
        return

    try:
        if method == "GET" and path in {"/", "/app"}:
            await send_index(send)
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
        if method == "GET" and path == "/api/bounty/platforms":
            await send_json(send, {"ok": True, "platforms": bounty_formats.list_platforms(), "default": bounty_formats.DEFAULT_PLATFORM})
            return
        if method == "GET" and path == "/api/toolkit":
            await send_json(send, toolkit_catalog())
            return
        if method == "POST" and path == "/api/bounty/scan":
            request = validate_payload(BountyScanRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.run_bounty, request))
            return
        if method == "POST" and path == "/api/bounty/campaign":
            request = validate_payload(CampaignRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.run_campaign, request))
            return
        if method == "POST" and path == "/api/bounty/learn":
            request = validate_payload(LearnRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.record_outcome, request))
            return
        if method == "GET" and path == "/api/bounty/stats":
            params = parse_qs(scope.get("query_string", b"").decode("utf-8", "replace"))
            program = (params.get("program") or [None])[0]
            target = (params.get("target") or [""])[0]
            await send_json(send, await asyncio.to_thread(runtime.bounty_stats, program, target))
            return
        if method == "POST" and path == "/api/bounty/submission":
            request = validate_payload(SubmissionPackageRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.build_submission_package, request))
            return
        if method == "POST" and path == "/api/bounty/screenshot":
            request = validate_payload(ScreenshotRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.capture_screenshot, request))
            return
        if method == "POST" and path == "/api/bounty/ingest-targets":
            request = validate_payload(IngestTargetsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.ingest_targets, request))
            return
        if method == "POST" and path == "/api/bounty/bundle":
            request = validate_payload(BundleRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.export_bundle, request))
            return
        if method == "POST" and path == "/api/bounty/research":
            request = validate_payload(ResearchRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.research_finding, request))
            return
        if method == "POST" and path == "/api/bounty/idor":
            request = validate_payload(IdorRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_idor, request))
            return
        if method == "POST" and path == "/api/bounty/bfla":
            request = validate_payload(BflaRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_bfla, request))
            return
        if method == "POST" and path == "/api/bounty/idor-probe":
            request = validate_payload(IdorProbeRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_idor_probe, request))
            return
        if method == "POST" and path == "/api/bounty/takeover":
            request = validate_payload(TakeoverRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.scan_takeover, request))
            return
        if method == "POST" and path == "/api/bounty/cve":
            request = validate_payload(CveScanRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.scan_cve, request))
            return
        if method == "GET" and path == "/api/oob/config":
            await send_json(send, await asyncio.to_thread(runtime.oob_config_status))
            return
        if method == "POST" and path == "/api/oob/config":
            request = validate_payload(OobConfigRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.save_oob_config, request))
            return
        if method == "POST" and path == "/api/oob/mint":
            await send_json(send, await asyncio.to_thread(runtime.oob_mint))
            return
        if method == "POST" and path == "/api/oob/poll":
            request = validate_payload(OobPollRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.oob_poll, request))
            return
        if method == "POST" and path == "/api/bounty/oob-ssrf":
            request = validate_payload(OobSsrfRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_oob_ssrf, request))
            return
        if method == "POST" and path == "/api/bounty/oob-xxe":
            request = validate_payload(OobXxeRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_oob_xxe, request))
            return
        if method == "POST" and path == "/api/bounty/stored-xss":
            request = validate_payload(StoredXssRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_stored_xss, request))
            return
        if method == "POST" and path == "/api/bounty/submit":
            request = validate_payload(SubmitRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.submit_finding, request))
            return
        if method == "GET" and path == "/api/bounty/hackerone/creds":
            await send_json(send, await asyncio.to_thread(runtime.hackerone_creds_status))
            return
        if method == "POST" and path == "/api/bounty/hackerone/creds":
            request = validate_payload(HackerOneCredsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.save_hackerone_creds, request))
            return
        if method == "GET" and path == "/api/operator/programs":
            await send_json(send, await asyncio.to_thread(runtime.list_programs))
            return
        if method == "POST" and path == "/api/operator/programs":
            request = validate_payload(ProgramUpsertRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.upsert_program, request))
            return
        if method == "POST" and path == "/api/operator/programs/delete":
            request = validate_payload(ProgramDeleteRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.remove_program, request.id))
            return
        if method == "POST" and path == "/api/operator/start":
            request = validate_payload(OperatorStartRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.operator_start, request))
            return
        if method == "POST" and path == "/api/operator/stop":
            await send_json(send, await asyncio.to_thread(runtime.operator_stop))
            return
        if method == "POST" and path == "/api/operator/events":
            request = validate_payload(OperatorEventsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.operator_events, request.after))
            return
        if method == "GET" and path == "/api/operator/pipeline":
            await send_json(send, await asyncio.to_thread(runtime.operator_pipeline))
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
        if method == "POST" and path == "/api/cores/delete":
            request = validate_payload(DeleteCoreRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.delete_core, request.core_id))
            return
        if method == "POST" and path == "/api/preferences":
            request = validate_payload(PreferenceRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(preferences, request))
            return
        if method == "POST" and path == "/api/repos/ingest":
            request = validate_payload(RepoIngestRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(repo_ingest, request))
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
        if method == "POST" and path == "/api/coder/delete":
            request = validate_payload(DeleteModelRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.delete_model, request.model))
            return
        if method == "POST" and path == "/api/agent":
            request = validate_payload(AgentRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.run_agent, request))
            return
        if method == "POST" and path == "/api/agent/stream":
            request = validate_payload(AgentRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.start_agent_run, request))
            return
        if method == "POST" and path == "/api/agent/events":
            request = validate_payload(AgentEventsRequest, await read_json_body(receive))
            await send_json(
                send,
                await asyncio.to_thread(runtime.agent_run_events, request.request_id, request.cursor),
            )
            return
        if method == "POST" and path == "/api/agent/snapshot":
            request = validate_payload(AgentUndoRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.agent_snapshot, request))
            return
        if method == "POST" and path == "/api/agent/undo":
            request = validate_payload(AgentUndoRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.agent_undo, request))
            return
        if method == "POST" and path == "/api/project/memory":
            request = validate_payload(ProjectMemoryRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.project_memory_load, request))
            return
        if method == "POST" and path == "/api/project/memory/save":
            request = validate_payload(ProjectMemorySaveRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.project_memory_save, request))
            return
        if method == "POST" and path == "/api/project/scan":
            request = validate_payload(ProjectMemoryRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.project_scan, request))
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
        if method == "POST" and path == "/api/workspace/rollback":
            request = validate_payload(WorkspaceRollbackRequest, await read_json_body(receive))
            await send_json(
                send,
                await asyncio.to_thread(workspace_fs.rollback_changes, request.workspace, request.changes),
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
        await send_index(send)
    except HTTPError as exc:
        await send_json(send, {"detail": exc.detail}, exc.status_code)
    except Exception:
        # Log the full traceback server-side, but never reflect raw exception text
        # (paths, internals) to the client — deliberate errors use the HTTPError path.
        runtime.log(traceback.format_exc())
        await send_json(send, {"error": "internal server error"}, 500)


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
