from __future__ import annotations

import asyncio
import base64
import binascii
import dataclasses
import functools
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import sys
import threading
import traceback
from collections import OrderedDict
from collections.abc import Iterable
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


def _resolve_runtime_dir(project_root: Path) -> Path:
    """Keep frozen Linux API data outside the read-only application bundle."""
    explicit = os.getenv("GREYIQ_RUNTIME_DIR")
    if explicit is not None:
        return Path(explicit).resolve()
    if getattr(sys, "frozen", False) and sys.platform == "linux":
        xdg_home = os.getenv("XDG_DATA_HOME")
        data_home = Path(xdg_home) if xdg_home else Path.home() / ".local" / "share"
        if not data_home.is_absolute():
            data_home = Path.home() / ".local" / "share"
        return (data_home / "greyiq" / "runtime").resolve()
    return (project_root / "runtime").resolve()


RUNTIME_DIR = _resolve_runtime_dir(PROJECT_ROOT)
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
#
# IMPORTANT: this token is NOT real authentication once the server is reachable
# beyond loopback. It is embedded in the unauthenticated index page (send_index)
# and the unauthenticated static-file fallback, both served before any /api/*
# gate ever runs — by design, since the app's own JS needs it before it can make
# its first authenticated call. Anyone who can send ONE unauthenticated GET to
# this process (trivial once it's bound beyond 127.0.0.1, e.g. behind a bare
# reverse proxy) can read the token and replay it against every /api/* route.
# GREYIQ_ACCESS_KEY (below) is the actual credential for that scenario.
SESSION_TOKEN = secrets.token_urlsafe(32)
SESSION_TOKEN_PLACEHOLDER = "__GREYIQ_SESSION_TOKEN__"
SESSION_TOKEN_PATH = RUNTIME_DIR / "session.token"

# Optional operator-configured shared secret for deployments reachable beyond
# 127.0.0.1/localhost (e.g. behind a reverse proxy on a public domain — see
# DEPLOY.md). Unset by default, which preserves today's local/Electron behavior
# exactly (no extra prompt, nothing changes for the single-user desktop case).
# When set, EVERY request — including the unauthenticated index page that
# embeds SESSION_TOKEN — must present it via HTTP Basic Auth before anything
# else is served, closing the gap where SESSION_TOKEN could be harvested
# without ever presenting a real credential.
GREYIQ_ACCESS_KEY = os.getenv("GREYIQ_ACCESS_KEY", "").strip()
# Electron and the backend share this per-launch secret only through the backend
# process environment. It never reaches the renderer or the public health route.
INTERNAL_MODEL_STORE_TOKEN = os.getenv("GREYIQ_INTERNAL_MODEL_STORE_TOKEN", "")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _is_loopback_bind(host: str) -> bool:
    return str(host or "").strip().lower() in _LOOPBACK_HOSTS


def _access_key_authorized(scope: dict[str, Any] | None) -> bool:
    """True when no GREYIQ_ACCESS_KEY is configured (the default — nothing changes
    for local/Electron use), or the request presents it via HTTP Basic Auth (any
    username, password == the key). This is the FIRST gate route_http checks, ahead
    of the session-token/origin logic, so it also protects send_index/send_file —
    the very responses that hand out SESSION_TOKEN."""
    if not GREYIQ_ACCESS_KEY:
        return True
    header = _header(scope, "authorization")
    if not header.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False
    _, _, password = decoded.partition(":")
    return hmac.compare_digest(password, GREYIQ_ACCESS_KEY)

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


def _split_coder_secrets(config: dict[str, Any], clear: Iterable[str] = ()) -> dict[str, Any]:
    """Move any API keys out of a coder config into the secrets store, leaving the
    main config key-free.

    ``clear`` names providers whose stored key the update explicitly asked to delete
    (coder.api_key_clear_requests). A blank api_key can't express that on its own: it
    means "keep the stored key", so without this the delete branch of _store_secret is
    unreachable for coder providers and a key could only be removed by hand-editing
    secrets.json."""
    to_clear = {str(name) for name in clear}
    for provider in _SECRET_PROVIDERS:
        block = config.get(provider)
        if provider in to_clear:
            _store_secret(provider, "")  # delete branch: drops the entry from secrets.json
            if isinstance(block, dict):
                block["api_key"] = ""
            continue
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


_CODE_ROUTER_SECRET_KEY = "code_router.remote_api_key"


def _migrate_code_router_secret() -> None:
    """One-time: same as _migrate_coder_secrets, but for code_router.remote_api_key
    (backend/bughunter/triage.py's remote-triage feature) -- this field lived in the
    plaintext, non-owner-restricted solin_runtime_config.json with no equivalent split
    step, unlike every coder.<provider>.api_key."""
    runtime_path = RUNTIME_DIR / "solin_runtime_config.json"
    payload = read_json(runtime_path, {})
    router_cfg = payload.get("code_router") if isinstance(payload, dict) else None
    if not isinstance(router_cfg, dict) or not router_cfg.get("remote_api_key"):
        return
    _store_secret(_CODE_ROUTER_SECRET_KEY, str(router_cfg["remote_api_key"]))
    router_cfg["remote_api_key"] = ""
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
import brain_profiles  # noqa: E402
import brain_techniques  # noqa: E402
import coding_learning_bridge  # noqa: E402
import coder  # noqa: E402
import hf_gguf_import  # noqa: E402
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
ValidationMonitorSettings = None  # type: ignore[assignment,misc]
run_training_loop = None  # type: ignore[assignment]
collect_dataset_stats = None  # type: ignore[assignment]
model_config_for = None  # type: ignore[assignment]
approx_parameter_count = None  # type: ignore[assignment]
MODEL_PRESETS: dict[str, dict[str, Any]] = {}
# Mirror training_runtime's defaults so request models and settings validate without
# importing it (and thus without paying the torch import cost) at boot.
MAX_TRAINING_CHARS = 16_000_000
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
    global ValidationMonitorSettings, collect_dataset_stats, model_config_for, approx_parameter_count, MODEL_PRESETS
    if _ML_RUNTIME_AVAILABLE is not None:
        return _ML_RUNTIME_AVAILABLE
    try:
        from solin_core import SolinEngine as _Engine
        from training_runtime import (
            DEFAULT_EVAL_INTERVAL as _EI,
            DEFAULT_LEARNING_RATE as _LR,
            DEFAULT_MAX_ITERS as _MI,
            MAX_TRAINING_CHARS as _MC,
            MODEL_PRESETS as _MP,
            TrainingSettings as _TS,
            ValidationMonitorSettings as _VMS,
            approx_parameter_count as _APC,
            collect_dataset_stats as _CDS,
            model_config_for as _MCF,
            run_training_loop as _RL,
        )
    except Exception as exc:  # noqa: BLE001 - torch/numpy may be missing or fail to load (DLL, ABI, ARM wheel)
        _ML_RUNTIME_AVAILABLE = False
        _ML_RUNTIME_ERROR = f"Local model runtime unavailable ({type(exc).__name__}: {exc}). " \
            "Bug-hunting and the Claude API brain still work; local TinyGPT train/infer is disabled."
        return False
    SolinEngine, TrainingSettings, run_training_loop = _Engine, _TS, _RL
    MAX_TRAINING_CHARS, DEFAULT_MAX_ITERS, DEFAULT_EVAL_INTERVAL, DEFAULT_LEARNING_RATE = _MC, _MI, _EI, _LR
    ValidationMonitorSettings, collect_dataset_stats = _VMS, _CDS
    model_config_for, approx_parameter_count, MODEL_PRESETS = _MCF, _APC, _MP
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
from bughunter.chat_commands import (  # noqa: E402
    detect_scan_command,
    dispatch_authorized_scan_command,
    parse_active_chat_command,
    validate_scoped_network_target,
    detect_wardrive_command,
    run_scan,
    run_wardrive,
    _looks_like_url,
    _looks_like_path,
)
# The curated offline domain brain. Stdlib-only and torch-free BY DESIGN (see its module
# docstring): the shipped build excludes torch, so this is the only thing between a frozen
# install and fallback_reply()'s single canned sentence. Safe to import at boot — it pulls
# nothing heavier than re/difflib/math/pathlib.
import solin_domain  # noqa: E402
from mcp_servers import MCPServerManager  # noqa: E402
from bughunter.bounty import list_profiles as bounty_profiles, run_bounty_hunt, vuln_class_names, _deterministic_attack_plan, cwe_for_class, owasp_for_class, build_replay_script as bounty_build_replay, build_findings_har as bounty_build_har  # noqa: E402
from bughunter import campaign as bounty_campaign  # noqa: E402
from bughunter import learning as bounty_learning  # noqa: E402
from bughunter import submission as bounty_submission  # noqa: E402
from bughunter import report as bounty_report  # noqa: E402
from bughunter import report_formats as bounty_formats  # noqa: E402
from bughunter import attack_map as bounty_attack_map  # noqa: E402
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
from bughunter import vdp_policy as bounty_vdp  # noqa: E402
from bughunter import secret_classification as bounty_secret_class  # noqa: E402
from bughunter import hackerone_import as bounty_h1_import  # noqa: E402
from bughunter import hackerone_activity as bounty_h1_activity  # noqa: E402
from bughunter import yeswehack_import as bounty_ywh_import  # noqa: E402
from bughunter import platform_programs as bounty_platform_programs  # noqa: E402
from bughunter import forge_metadata as bounty_forge_metadata  # noqa: E402
from bughunter import taxonomy as bounty_taxonomy  # noqa: E402
from bughunter import fsutil as bounty_fsutil  # noqa: E402
from bughunter import progress as bounty_progress  # noqa: E402
from bughunter import operator_guard as bounty_operator_guard  # noqa: E402
from bughunter.operator import OperatorLoop  # noqa: E402
from bughunter import toolkit as toolkit_lib  # noqa: E402
from bughunter.agent_redteam import run_redteam as run_agent_redteam  # noqa: E402
from bughunter import active_verify_service as bounty_active_verify  # noqa: E402
from bughunter import scan_auth as bounty_scan_auth  # noqa: E402
from bughunter import credential_validation as bounty_credential_validation  # noqa: E402
from bughunter import web_ingest as bounty_web_ingest  # noqa: E402
from bughunter.code_scanner.redaction import redact_text  # noqa: E402
from bughunter.code_scanner.sources import git_remote as bounty_git_remote  # noqa: E402
from bughunter.settings import get_settings as _bounty_get_settings  # noqa: E402


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
    "greyiq_coding_knowledge.txt",
    "greyiq_bug_bounty_knowledge.txt",
    # Native-text extract of the Manual_pdfs library, bundled so the local model
    # trains on it on first run (copied into RUNTIME_DIR/data by ensure_runtime).
    "greyiq_manual_pdfs.txt",
)
TRAINING_SOURCE_FILES = {
    "src_starter_knowledge": "greyiq_starter_knowledge.txt",
    "src_bug_bounty": "greyiq_bug_bounty_knowledge.txt",
    "src_verified_replay": "greyiq_verified_replay.txt",
    "src_personal_choices": "greyiq_personal_choices.txt",
    "src_preferred_examples": "greyiq_preferred_examples.txt",
    "src_local_notes": "greyiq_local_notes.txt",
    "src_imported_docs": "greyiq_imported_docs.txt",
    # Mirrors training_runtime.SOURCE_TEXT_FILES — normalize_source_ids allowlists against this dict,
    # so an id missing here is silently dropped from every request.
    "src_manuals": "greyiq_manual_pdfs.txt",
}

BUGHUNTER_CORE_ID = "core_greyiq_bughunter"
BUGHUNTER_CORE: dict[str, Any] = {
    "id": BUGHUNTER_CORE_ID,
    "_verified_replay_source_v1": True,
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
        "src_bug_bounty",
        "src_verified_replay",
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
    # The Studio's Train panel drives every field here. Anything the trainer supports but this model
    # omits is unreachable from the app — which is how ValidationMonitorSettings (patience/min_delta/
    # auto_stop/save_best_only/restore_best) and batch_size_override sat implemented-but-unusable while
    # every run was locked to patience 3 / min_delta 1e-4 / auto-stop on. test_training_api asserts that
    # every field here actually reaches TrainingSettings.
    max_iters: int = Field(default=120, ge=1, le=100_000)
    eval_interval: int = Field(default=40, ge=1, le=100_000)
    # Ceiling lowered from 1.0: a learning rate anywhere near 1.0 diverges a transformer to NaN within
    # a handful of steps. The trainer now refuses to persist a diverged run, but the sane ceiling keeps
    # an operator from wasting the run at all. 1e-2 is already 30x the 3e-4 default.
    learning_rate: float = Field(default=DEFAULT_LEARNING_RATE, gt=0.0, le=1e-2)
    device_preference: str = Field(default="auto", max_length=20)
    source_ids: list[str] = Field(default_factory=list)
    fresh_start: bool = False
    # 0 no longer means "unbounded": load_all_text reads the whole corpus into one string and
    # build_dataset materialises an int64 tensor from it, so an unbounded cap OOM-kills the backend.
    # The maximum is the documented RAM ceiling rather than an arbitrary 100M.
    dataset_char_cap: int = Field(default=MAX_TRAINING_CHARS, ge=100_000, le=MAX_TRAINING_CHARS)
    # Which architecture to train. 'compact' is the shipped checkpoint's shape, so the default RESUMES
    # and improves the model the operator already has; the bigger presets start a new lineage from
    # random weights (the previous one is archived, never overwritten in place).
    model_size: str = Field(default="compact", max_length=20)
    # 0 = size the batch from the architecture's context length (see training_runtime.batch_size_for).
    batch_size_override: int = Field(default=0, ge=0, le=512)
    # --- early-stopping / best-model monitor ---
    patience: int = Field(default=3, ge=1, le=50)
    min_delta: float = Field(default=0.0001, ge=0.0, le=1.0)
    auto_stop: bool = True
    save_best_only: bool = True
    restore_best: bool = True


class HuntBrainTrainRequest(BaseModel):
    """Train the OFFLINE HUNT ranker from local hunt traces — the hunting half of the Studio.

    This is a different brain from TinyGPT: a small, auditable linear model over the value-free
    endpoint features in hunt_features, which only ever REORDERS the prover's existing checks. It was
    reachable solely via `gn train-brain`, and its holdout/epochs/lr were not even exposed there, so
    the app could neither train nor inspect it. Promotion stays gated on beating the rules baseline on
    a held-out split — these fields tune the attempt, they cannot force a promotion."""
    dry_run: bool = False          # evaluate and report, write nothing
    min_rows: int = Field(default=200, ge=1, le=100_000)
    holdout: float = Field(default=0.2, gt=0.0, lt=1.0)
    epochs: int = Field(default=40, ge=1, le=1_000)
    lr: float = Field(default=0.1, gt=0.0, le=10.0)
    l2: float = Field(default=1e-4, ge=0.0, le=1.0)
    rng_seed: int = Field(default=1337, ge=0, le=2**31 - 1)


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
    model: str = Field(min_length=1, max_length=300)


class HuggingFaceImportRequest(BaseModel):
    reference: str = Field(min_length=1, max_length=300)


class ModelSetupRequest(BaseModel):
    model: str = Field(min_length=1, max_length=350)
    base_url: str = Field(default="", max_length=400)


class ScanCodeRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4000)
    target_type: str = Field(default="path", max_length=20)
    authorized: bool = False
    scope_repository: str = Field(default="", max_length=2048)
    max_files: int = Field(default=5000, ge=1, le=100_000)
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)


class WebScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False
    scope_host: str = Field(default="", max_length=253)


class LiveScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    wait_seconds: float = Field(default=6.0, ge=0.0, le=30.0)
    authorized: bool = False
    scope_host: str = Field(default="", max_length=253)


class BountyScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4000)
    profile: str = Field(default="full-sweep", max_length=60)
    vuln_class: str | None = Field(default=None, max_length=60)
    output_dir: str | None = Field(default=None, max_length=4000)
    scope: str = Field(default="", max_length=2000)
    authorized: bool = False
    run_live: bool = False
    active: bool = False
    external_mcp_hunt: bool = False  # separate opt-in for approved evidence-only MCP tools
    time_based: bool = False
    auth_cookie: str = Field(default="", max_length=8000)
    auth_headers: list[str] = Field(default_factory=list, max_length=20)
    per_finding: bool = False
    max_files: int = Field(default=5000, ge=1, le=100_000)
    # A per-run UA tag, for hunting a program that requires one WITHOUT saving it to the portfolio
    # (an ad-hoc/one-off target). Appended verbatim after the global researcher marker; sanitized in
    # web_ingest.set_ua_suffix, so the cap here is a bound, not the injection defense.
    user_agent_suffix: str = Field(default="", max_length=120)
    run_id: str = Field(default="", max_length=100)  # client-minted id for polling live progress


class CampaignRequest(BaseModel):
    target: str = Field(default="", max_length=4000)   # required UNLESS program_id is set (then targets are derived from the saved program)
    scope: str = Field(default="", max_length=2000)
    authorized: bool = False
    program: str | None = Field(default=None, max_length=200)
    program_id: str | None = Field(default=None, max_length=120)  # "span this program's whole scope" mode
    active_program_id: str | None = Field(default=None, max_length=120)  # the saved program bound to a single-target (non-span) cockpit run — used ONLY to look up that program's policy/scope/creds; does NOT trigger span mode (that's program_id)
    active: bool = False
    external_mcp_hunt: bool = False
    time_based: bool = False
    auth_cookie: str = Field(default="", max_length=8000)
    auth_headers: list[str] = Field(default_factory=list, max_length=20)
    live: bool = False
    max_pages: int = Field(default=12, ge=1, le=50)
    deep: bool = False  # aggressive: time-based SQLi + auto screenshot + research per confirmed lead
    attack_map: bool = True  # render a graphical attack-plan map (.png) per confirmed finding into the POC download + report
    # Per-run UA tag (see BountyScanRequest). Overrides the saved program's user_agent_suffix when
    # set, so the operator can satisfy a policy change without re-saving the program; empty (the
    # default) keeps the program's stored tag, which is the normal path.
    user_agent_suffix: str = Field(default="", max_length=120)
    run_id: str = Field(default="", max_length=100)  # client-minted id for polling live progress


class BountyProgressRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=100)
    after: int = Field(default=0, ge=0)


class BountyEventsRequest(BaseModel):
    # App-wide event stream cursor (not scoped to a run): the UI polls this so any open tab
    # reacts live to a finding confirmed / report readied / submission filed in another run.
    after: int = Field(default=0, ge=0)


class BountyRunsRequest(BaseModel):
    # Which runs this process is tracking. Deliberately FIELD-FREE: a run_id is minted by whichever
    # client launched the run, so a second client (the `gn dash --attach` shell) has no id to send
    # and nothing to filter by -- and with no field, there is nothing a caller could supply to steer
    # the route at anything but this process's own progress store. The model exists so the route
    # goes through the same validate_payload gate as every other POST rather than growing a
    # bespoke path.
    pass


class CampaignStopRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=100)


class LeadsRequest(BaseModel):
    # Download the finished hunt's investigation queue as a Markdown brief. Keyed by the cached
    # run_id ONLY — the sidecar path is resolved server-side, so no client-supplied path is read.
    run_id: str = Field(min_length=1, max_length=100)


class PortfolioRequest(BaseModel):
    # Portfolio Hunt: run a full campaign across MANY saved programs concurrently (bounded).
    program_ids: list[str] = Field(default_factory=list, max_length=50)
    all_programs: bool = False   # run every saved program (ignores program_ids)
    authorized: bool = False
    active: bool = False
    external_mcp_hunt: bool = False
    time_based: bool = False
    deep: bool = False           # GPU-brain deep AI write-ups + screenshots + research per confirmed lead
    attack_map: bool = True      # render a graphical attack-plan map (.png) per confirmed finding
    live: bool = False
    max_pages: int = Field(default=12, ge=1, le=50)
    auth_cookie: str = Field(default="", max_length=8000)
    auth_headers: list[str] = Field(default_factory=list, max_length=20)
    run_id: str = Field(default="", max_length=100)


class ReverifyRequest(BaseModel):
    # On-demand re-probe of ONE finding's URL, launched from the live dashboard's
    # investigate drawer. Runs in its own thread (parallel to any campaign) and is
    # scope-gated + SSRF-guarded exactly like the campaign's own active pass.
    url: str = Field(min_length=1, max_length=4000)
    scope: str = Field(default="", max_length=2000)
    program_id: str | None = Field(default=None, max_length=120)  # resolve the program's authoritative scope
    authorized: bool = False
    time_based: bool = False  # opt-in: allow the (executing) time-based blind-SQLi probe
    auth_cookie: str = Field(default="", max_length=8000)
    auth_headers: list[str] = Field(default_factory=list, max_length=20)
    # v2 reproduction-stability: re-run the same scope-gated probe this many times and report
    # how consistently each finding confirmed (a flaky WAF/timing false-positive won't confirm
    # every pass). 1 = the classic single probe. Capped server-side so it can't fan out.
    stability_passes: int = Field(default=1, ge=1, le=3)


class ActiveChatStatusRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=80)


class ProveRequest(BaseModel):
    # "Create proof of impact" for a candidate: active re-probe (verify_active) PLUS a proof
    # screenshot, both scope-gated. Same fail-closed posture as the campaign's active pass.
    url: str = Field(min_length=1, max_length=4000)
    scope: str = Field(default="", max_length=2000)
    program_id: str | None = Field(default=None, max_length=120)
    authorized: bool = False
    time_based: bool = False
    screenshot: bool = True
    auth_cookie: str = Field(default="", max_length=8000)
    auth_headers: list[str] = Field(default_factory=list, max_length=20)
    # When this proof-of-impact pass belongs to a cached run finding, the caller passes its
    # run_id + ref so the captured differential can be persisted back onto that run (see
    # prove_finding) — this is what makes the CANONICAL submission package, the submit gate,
    # and every rebuilt report render the finding as a confirmed proof of impact instead of
    # leaving it "candidate" even after proof was gathered.
    run_id: str = Field(default="", max_length=120)
    ref: str = Field(default="", max_length=60)


class ProofInput(BaseModel):
    status: str = Field(default="candidate", max_length=20)
    method: str = Field(default="", max_length=400)
    observed_result: str = Field(default="", max_length=6000)
    control_result: str = Field(default="", max_length=6000)
    evidence: str = Field(default="", max_length=6000)
    affected_asset: str = Field(default="", max_length=1000)
    limitations: str = Field(default="", max_length=1000)


class ProofEvidenceInput(BaseModel):
    # The engine's captured request/response artifact for a finding (the ACAO/ACAC headers
    # for CORS, the reflected marker for XSS, etc.). A history/board finding carries this from
    # its original hunt; threading it into an on-demand report is what makes the report's
    # "Supporting material / evidence" section show the concrete headers a triager demands.
    request_line: str = Field(default="", max_length=4000)
    request_header: str = Field(default="", max_length=2000)
    response_status: str = Field(default="", max_length=400)
    # The RESPONSE header IS the proof for open-redirect / CRLF / host-header findings (the injected
    # Location: / X-Greyiq-Crlf: line); without these the on-demand report drops the actual exploit
    # evidence for that whole class. set_cookie likewise for session-fixation-style proofs.
    response_header: str = Field(default="", max_length=2000)
    set_cookie: str = Field(default="", max_length=2000)
    matched_value: str = Field(default="", max_length=6000)
    read_data: str = Field(default="", max_length=8000)
    # The generic-English NAME of the sensitive data the captured body disclosed ("a JWT
    # (session/bearer token); email address(es)") — never the data itself. Carried because it is what
    # survives redaction: once read_data shows only [REDACTED_…] markers, this is the only thing left
    # that lets the rebuilt report state what was actually at risk (report._sensitive_read_captured).
    sensitive_data_labels: str = Field(default="", max_length=400)


class FindingReportRequest(BaseModel):
    # Build a well-authored report for ONE finding on demand, from the finding's own fields
    # (a ledger/dashboard finding that isn't in the in-memory run cache) plus any proof the
    # operator just gathered. Server recomputes proof_status; a client can't forge "confirmed".
    title: str = Field(default="Security finding", max_length=255)
    severity: str = Field(default="info", max_length=20)
    class_name: str = Field(default="", max_length=160)
    class_id: str = Field(default="", max_length=80)  # canonical class key → class-specific reproduction steps
    location: str = Field(default="", max_length=4000)
    cwe: str = Field(default="", max_length=40)
    rule_id: str = Field(default="", max_length=160)
    target: str = Field(default="", max_length=4000)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=40)
    description: str = Field(default="", max_length=8000)
    poc: str = Field(default="", max_length=8000)  # caller-supplied proof-of-concept outline (e.g. the brain's PoC)
    proof: ProofInput | None = None
    proof_evidence: ProofEvidenceInput | None = None  # engine-captured request/response (e.g. CORS ACAO/ACAC headers)
    screenshot_path: str = Field(default="", max_length=4000)
    policy_profile: str = Field(default="", max_length=40)  # VDP profile of the bound program (e.g. "nasa"): the report builder RE-APPLIES that program's rules here so a finding the campaign withheld can't be reconstituted into a submittable report via the dashboard/ledger "View full report" path


class FindingDismissRequest(BaseModel):
    # Delete a finding: permanently suppress it so no future hunt/campaign/history/funnel
    # surfaces it again (matched by the ledger's stable dedup key). A durable-history record
    # already carries dedup_key; a board finding sends its class_id/rule_id/location so the
    # server derives the same key the engine will compute on the next run.
    dedup_key: str = Field(default="", max_length=64)
    class_id: str = Field(default="", max_length=80)
    rule_id: str = Field(default="", max_length=160)
    location: str = Field(default="", max_length=4000)
    title: str = Field(default="", max_length=255)
    program: str | None = Field(default=None, max_length=200)
    target: str = Field(default="", max_length=4000)


class FindingRestoreRequest(BaseModel):
    # Undo a delete — the finding can surface again. Keyed by the dedup_key the delete returned.
    dedup_key: str = Field(default="", max_length=64)


class ReportReadyRequest(FindingReportRequest):
    # "Get report ready": assemble POC/POI/POE for ONE finding into a submission-ready report and
    # mark it READY in the durable ledger so the Report Center can review it. Inherits every
    # FindingReportRequest field (title/severity/class/proof/proof_evidence/screenshot_path/poc/
    # policy_profile/…) so it flows straight through build_finding_report — the single honest choke
    # point that server-recomputes proof_status. Adds only the durable-ledger coordinates.
    dedup_key: str = Field(default="", max_length=64)  # the ledger record's key (a history finding carries it)
    program: str | None = Field(default=None, max_length=200)  # its ledger bucket id
    run_id: str = Field(default="", max_length=64)  # optional: a cached-run finding
    ref: str = Field(default="", max_length=40)


class AggregateReportRequest(BaseModel):
    # The "special report": one engagement document across many findings. Either a cached
    # run (run_id — rich, with proof/plans) or a saved program (its ledger history).
    run_id: str = Field(default="", max_length=100)
    program: str | None = Field(default=None, max_length=200)
    platform: str = Field(default="hackerone", max_length=40)


class LearnRequest(BaseModel):
    class_id: str = Field(min_length=1, max_length=60)
    status: str = Field(min_length=1, max_length=40)
    program: str | None = Field(default=None, max_length=200)
    target: str = Field(default="", max_length=4000)
    bounty: float = Field(default=0.0, ge=0)
    severity: str = Field(default="", max_length=20)
    title: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=500)
    finding_id: str = Field(default="", max_length=200)


class SubmissionPackageRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)
    ref: str = Field(min_length=1, max_length=40)
    platform: str = Field(default="hackerone", max_length=20)


class SubmitRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)
    ref: str = Field(min_length=1, max_length=40)
    confirm: bool = False
    platform: str = Field(default="hackerone", max_length=20)
    # Optional operator override from the asset picker; when empty the server matches the
    # finding's host against the program's structured scope automatically.
    structured_scope_id: str = Field(default="", max_length=64)
    include_attachments: bool = True


class PreflightRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)
    ref: str = Field(min_length=1, max_length=40)
    platform: str = Field(default="hackerone", max_length=20)
    check_duplicates: bool = True


class ScreenshotRequest(BaseModel):
    # run_id/ref locate a cached run (richest: the exact PoC request URL, and the shot auto-embeds
    # on the report). Optional so a finding opened from history / an evicted run can still capture
    # from its OWN url/location — no re-hunt. When there's no cached run the url/title/location/
    # matched_value fields drive the capture + on-shot annotation.
    run_id: str = Field(default="", max_length=64)
    ref: str = Field(default="", max_length=40)
    url: str = Field(default="", max_length=4000)             # PoC/finding URL used when no run is cached
    title: str = Field(default="", max_length=255)            # finding title, overlaid on the shot
    location: str = Field(default="", max_length=4000)        # finding location, overlaid on the shot
    matched_value: str = Field(default="", max_length=2000)   # evidence to highlight + annotate
    full_page: bool = False
    scope: str = Field(default="", max_length=4000)   # optional extra scope (the cockpit's current Scope box), unioned with the run + live program scope at capture time


class AttackMapRequest(BaseModel):
    # Render the GRAPHICAL attack-plan map (.png) for a finding on demand. run_id/ref locate the cached
    # run (richest: the full attack plan + captured differential). Optional so a finding opened from
    # history / an evicted run still renders from its OWN passed proof fields — no re-hunt. Built from
    # already-captured data, no network; the PNG is returned as an inline data_url for the report page.
    run_id: str = Field(default="", max_length=64)
    ref: str = Field(default="", max_length=40)
    title: str = Field(default="", max_length=255)
    severity: str = Field(default="", max_length=16)
    class_name: str = Field(default="", max_length=120)
    location: str = Field(default="", max_length=4000)
    actor: str = Field(default="", max_length=300)
    observed_result: str = Field(default="", max_length=2000)
    control_result: str = Field(default="", max_length=2000)
    request_line: str = Field(default="", max_length=2000)
    request_header: str = Field(default="", max_length=1000)
    matched_value: str = Field(default="", max_length=2000)
    impact: str = Field(default="", max_length=1000)


class CredentialTestRequest(BaseModel):
    # Explicit, one-click source-secret validation: send the found API key only to its
    # own allowlisted issuer, record the read-only response artifact, and attach it to
    # the run so the PoC/download bundle carries the proof.
    run_id: str = Field(min_length=1, max_length=64)
    ref: str = Field(min_length=1, max_length=40)
    authorized: bool = False


class IngestTargetsRequest(BaseModel):
    content: str = Field(default="", max_length=5_000_000)   # pasted/loaded CSV / Burp XML / HAR (module also byte-caps)
    kind: str = Field(default="auto", max_length=20)          # auto | csv | burp | har | hackerone_scope


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


class StoredXssBeaconRequest(BaseModel):
    # NO base/secret here, deliberately. The collaborator URL + secret are read server-side from
    # the saved OOB config, exactly as oob-ssrf / oob-xxe / mint / poll do. They used to be request
    # fields, which made this route unreachable from the app: oob_config_status returns only
    # `has_secret`, never the secret itself, so no client could ever fill them in.
    view_url: str = Field(min_length=1, max_length=4000)   # where the stored content renders
    inject_url: str = Field(default="", max_length=4000)   # the form endpoint (auto-send only)
    field: str = Field(default="", max_length=200)         # the field to submit into (auto-send only)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)
    send: bool = Field(default=False)               # opt-in: POST the beacon into the field, then render + poll
    token: str = Field(default="", max_length=64)   # re-render/re-poll an assisted token after injecting manually
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


class MassAssignRequest(BaseModel):
    object_url: str = Field(min_length=1, max_length=4000)   # a JSON object the account OWNS (e.g. /api/users/me)
    cookie: str = Field(default="", max_length=8000)
    headers: list[str] = Field(default_factory=list, max_length=20)
    scope: str = Field(default="", max_length=2000)
    platform: str = Field(default="hackerone", max_length=20)


class SessionInvalRequest(BaseModel):
    authed_url: str = Field(min_length=1, max_length=4000)   # an endpoint that returns YOUR account content
    logout_url: str = Field(min_length=1, max_length=4000)   # the logout endpoint (same host)
    cookie: str = Field(default="", max_length=8000)
    headers: list[str] = Field(default_factory=list, max_length=20)
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
    # Token-first entry: the operator can paste a single credential — either
    # "identifier:token" (what HackerOne shows together when you Generate API token) or a
    # bare token (identifier reused from what's already stored). Split server-side into
    # the api_username/api_token pair HackerOne's Basic auth requires. Takes precedence
    # over the separate fields above when non-empty.
    api_credential: str = Field(default="", max_length=600)


class YesWeHackCredsRequest(BaseModel):
    # Shown back to the operator so they can tell which account is signed in. Never used
    # as a credential on its own.
    email: str = Field(default="", max_length=200)
    # A YesWeHack JWT (from sign-in) or a Personal Access Token. Optional by design:
    # YesWeHack serves public program scope anonymously.
    api_token: str = Field(default="", max_length=4000)
    token_kind: str = Field(default="jwt", max_length=8)  # "jwt" | "pat"
    clear_token: bool = False  # explicit "sign out" — an empty api_token alone never clears


class YesWeHackLoginRequest(BaseModel):
    email: str = Field(min_length=1, max_length=200)
    # Used for ONE POST /login exchange and never stored — only the returned JWT is
    # persisted. See yeswehack_import.login.
    password: str = Field(min_length=1, max_length=400)
    totp_code: str = Field(default="", max_length=10)


class ProgramUpsertRequest(BaseModel):
    id: str | None = Field(default=None, max_length=120)
    name: str = Field(default="", max_length=200)
    platform: str = Field(default="manual", max_length=20)
    platform_handle: str = Field(default="", max_length=200)
    scope_text: str = Field(default="", max_length=4000)
    in_scope_hosts: list[str] = Field(default_factory=list)
    out_of_scope_hosts: list[str] = Field(default_factory=list)
    seed_targets: list[str] = Field(default_factory=list)
    repository_urls: list[str] = Field(default_factory=list, max_length=25)
    clone_repositories: bool = False
    structured_scope: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    oob_allowed: bool = False
    disclose_automation: bool = False  # this program's terms require disclosing automated-tool assistance in submitted reports
    h1_program_stats: dict[str, Any] = Field(default_factory=dict)  # real signals from HackerOne's program resource (offers_bounties, fast_payments, etc.)
    ywh_program_stats: dict[str, Any] = Field(default_factory=dict)  # the same for YesWeHack (reward range, VPN/IP constraints, the required UA marker) — see yeswehack_import.fetch_program_scope
    intake_source: dict[str, Any] = Field(default_factory=dict)  # API provenance only; never grants testing authority
    notes: str = Field(default="", max_length=4000)
    account_access: dict[str, Any] = Field(default_factory=dict)  # research-account email/password/login_url/cookie — SENSITIVE (portfolio._clean_account_access bounds it; password/cookie redacted on read-back)
    admin_account_access: dict[str, Any] = Field(default_factory=dict)  # SECOND (high-privilege) research account for dual-account BFLA — same shape+redaction as account_access; the low-priv account_access is the "user" session
    idor_pairs: list[dict[str, Any]] = Field(default_factory=list, max_length=50)  # operator-supplied cross-tenant IDOR test pairs [{url_a, url_b, label}] — object URLs only, no secrets (portfolio._clean_idor_pairs bounds/dedups/caps)
    policy_profile: str = Field(default="", max_length=40)  # OPTIONAL VDP profile id (e.g. "nasa") binding this program to a program's rules of engagement (scope + excluded endpoints/classes + confirmed-only + no-DoS); validated in portfolio._normalize against bughunter.vdp_policy
    user_agent_suffix: str = Field(default="", max_length=120)    # a mandatory UA tag some programs require appended to every in-scope request
    resync_scope: bool = False  # refresh derived scope/hosts from Program-form rows; preserve explicitly entered scope_text
    remove_out_of_scope_hosts: list[str] = Field(default_factory=list, max_length=500)  # transient: explicit operator removal only; a re-fetch never clears prior exclusions
    active: bool = False
    live: bool = False
    deep: bool = False
    auto_submit: bool = False
    max_pages: int = Field(default=12, ge=1, le=50)
    interval_minutes: int = Field(default=1440, ge=5, le=20160)
    max_submits_per_day: int = Field(default=3, ge=0, le=25)
    enabled: bool = True


class ProgramFromRepoRequest(BaseModel):
    repository_urls: list[str] = Field(default_factory=list, max_length=25)
    enrich: bool = False


class RepoPreflightRequest(BaseModel):
    url: str = Field(default="", max_length=2000)


_REPO_DRAFT_PROVENANCE = (
    "Draft created from repo link(s); scope is source-only until web hosts are confirmed."
)


def _repo_owner_slug(repository_url: str) -> str:
    parsed = urlparse(repository_url)
    parts = [part for part in parsed.path.split("/") if part]
    return (parts[0].lstrip("~") if parts else "").strip()


def _display_token(token: str) -> str:
    """Titlecase a plain lowercase word, but leave acronyms (OWASP) and handles that
    already carry internal capitals (GitLab, NodeGoat) untouched, so ``str.title`` can't
    mangle them into 'Owasp'/'Gitlab'."""
    if not token or token.isupper() or token != token.lower():
        return token
    return token.capitalize()


def _program_name_from_repositories(repository_urls: list[str]) -> str:
    """Derive a display name from unique owner slugs in input order; the first repo supplies
    the name. Plain words are Titlecased while acronyms/mixed-case handles are preserved."""
    owners: list[str] = []
    seen: set[str] = set()
    for repository_url in repository_urls:
        slug = _repo_owner_slug(repository_url)
        display = " ".join(_display_token(w) for w in re.split(r"[-_.]+", slug) if w).strip()
        key = display.lower()
        if display and key not in seen:
            seen.add(key)
            owners.append(display)
    return " + ".join(owners)[:200] or "Repository Program"


def _repo_description_note(repository_url: str, description: str) -> str:
    parsed = urlparse(repository_url)
    label = parsed.path.strip("/") or (parsed.hostname or "repository")
    return f"Forge description ({label}): {description}"


def _merge_note_lines(existing_notes: str, additions: list[str]) -> str:
    lines = [line for line in str(existing_notes or "").splitlines() if line.strip()]
    known = {line.strip() for line in lines}
    for addition in additions:
        clean = str(addition or "").strip()
        if clean and clean not in known:
            known.add(clean)
            lines.append(clean)
    return "\n".join(lines)[:4000]


def _program_for_read(program: dict[str, Any]) -> dict[str, Any]:
    """Redact the research-account secrets before a program leaves the API: the UI never receives the
    stored password or session cookie in plaintext — only booleans saying whether each is set. Email,
    login/register URL, and notes are returned so the operator can see and edit them."""
    # repo_draft_pending is a storage invariant, not operator-editable data. The
    # empty scope already tells the UI this generated draft still needs review.
    program = {key: value for key, value in program.items() if key != "repo_draft_pending"}

    def _redact(acc: Any) -> dict[str, Any] | None:
        if not (isinstance(acc, dict) and acc):
            return None
        red: dict[str, Any] = {k: acc.get(k) for k in ("email", "login_url", "register_url", "notes") if acc.get(k)}
        red["password_set"] = bool(acc.get("password"))
        red["cookie_set"] = bool(acc.get("cookie"))
        return red

    red_acc = _redact(program.get("account_access"))
    if red_acc is not None:
        program = {**program, "account_access": red_acc}
    red_admin = _redact(program.get("admin_account_access"))
    if red_admin is not None:
        program = {**program, "admin_account_access": red_admin}
    return program


class ProgramDeleteRequest(BaseModel):
    id: str = Field(min_length=1, max_length=120)


class VdpPresetRequest(BaseModel):
    profile: str = Field(min_length=1, max_length=40)  # a built-in VDP policy profile id (e.g. "nasa") to create a program from


class HackerOneImportRequest(BaseModel):
    handle: str = Field(min_length=1, max_length=200)


class HackerOneHacktivityRequest(BaseModel):
    team_handle: str = Field(min_length=1, max_length=200)


class HackerOnePageRequest(BaseModel):
    page: int = Field(default=1, ge=1, le=10000)


class HackerOneReportStatusRequest(BaseModel):
    report_id: str = Field(min_length=1, max_length=32)


class HackerOneSyncRequest(BaseModel):
    limit: int = Field(default=25, ge=1, le=100)


class YesWeHackImportRequest(BaseModel):
    # A slug, or a pasted program URL the importer reduces to its last path segment.
    slug: str = Field(min_length=1, max_length=400)


class YesWeHackProgramsRequest(BaseModel):
    query: str = Field(default="", max_length=120)


class PlatformCredentialRequest(BaseModel):
    platform: str = Field(min_length=1, max_length=20)
    credential: str = Field(default="", max_length=2000)
    clear_token: bool = False


class PlatformProgramsRequest(BaseModel):
    platform: str = Field(min_length=1, max_length=20)
    query: str = Field(default="", max_length=120)
    limit: int = Field(default=100, ge=1, le=100)


class PlatformPreviewRequest(BaseModel):
    platform: str = Field(min_length=1, max_length=20)
    program_id: str = Field(min_length=1, max_length=200)


class OperatorStartRequest(BaseModel):
    authorized: bool = False
    allow_submit: bool = False  # legacy clients: explicitly refused by operator_start
    grants: list[dict[str, Any]] = Field(default_factory=list, max_length=100)


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
    # Per-eval loss points, so the Studio can draw a curve instead of showing one number at whatever
    # moment it happened to poll. Bounded: a long run must not grow this without limit, and the early
    # points are the interesting ones, so the tail is dropped rather than the head.
    history: list[dict[str, Any]] = field(default_factory=list)
    # Echo of the resolved settings this run was started with (model size, batch, monitor), so the
    # panel can show what is running rather than what the form currently holds.
    settings: dict[str, Any] = field(default_factory=dict)


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
            # Return the exception TYPE only, not str(exc): the raw message can echo a scanned
            # response body / attacker-influenced input (with secrets or an injection payload) back
            # into the operator UI. The full traceback is logged server-side for debugging.
            return {"ok": False, "error": f"{fn.__name__} failed ({exc.__class__.__name__}) — see server log for detail."}
    return wrapper


# Maps a HackerOne report's live 'state' to the learning store's outcome vocabulary
# (bughunter.learning.OUTCOMES) — only for TERMINAL states; an in-progress state (new,
# pending-program-review, triaged, needs-more-info, retesting) has no outcome yet and is
# deliberately absent here, so a sync pass never records a premature "it's over" verdict.
_H1_STATE_TO_LEARNING_OUTCOME = {
    "resolved": "resolved",
    "duplicate": "duplicate",
    "not-applicable": "not-applicable",
    "informative": "informative",
    "spam": "spam",
}


# Code-WRITING / -editing intent, for the offline honesty short-circuit (docs/offline-coder-strategy.md).
# Deliberately NARROW: it must match "write me a function" / "fix this script" / "generate a test", but
# NOT general code *discussion* ("what is an API?", "explain python") — TinyGPT can attempt prose on
# those. A tiny (well under 10M-param) char model cannot produce code, so when no brain is configured
# we say so honestly instead of spending forward passes on output the quality gate would discard anyway.
_CODEGEN_INTENT_RE = re.compile(
    r"\b(write|create|generate|implement|build|add|make|fix|refactor|edit|modify|debug|scaffold)\b"
    r"[^.?!]{0,60}\b(code|script|function|method|class|module|program|endpoint|route|component|"
    r"unit\s*test|test|regex|sql|query|dockerfile|docker\s*file|ci|pipeline|workflow|snippet|"
    r"\.py|\.js|\.ts|\.go|\.rs)\b",
    re.IGNORECASE,
)


def _looks_like_codegen_request(message: str) -> bool:
    return bool(_CODEGEN_INTENT_RE.search(str(message or "")))


def _names_concrete_target(message: str) -> bool:
    """True when the message points at a REAL host or file path the operator wants tested.

    Checked word by word, never over the whole message: ``_looks_like_path`` matches ANY
    string containing a slash, so handing it a sentence ("read/write access") would report
    a target that isn't there. When this is true the offline answer must open by admitting
    it has never seen that target — quoting a playbook at someone who named a host reads
    like analysis of that host otherwise."""
    for token in str(message or "").split():
        candidate = token.strip("\"'`(),;:!?[]<>").rstrip(".")
        if len(candidate) < 4:
            continue
        try:
            if _looks_like_url(candidate) or (_looks_like_path(candidate) and "." in candidate):
                return True
        except Exception:  # noqa: BLE001 - a target heuristic must never break a chat turn
            return False
    return False


class GreyIQRuntime:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._active_chat_runs: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        self._active_chat_running_id = ""
        # One agent run at a time per resolved workspace: concurrent runs race on the same files and
        # clobber each other's single per-workspace rollback snapshot. Keyed by resolved path; the
        # dict itself is guarded by self.lock, each value is held for a run's duration.
        self._agent_workspace_locks: dict[str, threading.Lock] = {}
        self.engine: SolinEngine | None = None
        self.engine_error = ""
        self.training = TrainingState()
        self.model_pull: dict[str, Any] = {
            "active": False, "model": "", "status": "", "percent": 0,
            "completed": 0, "total": 0, "done": False, "error": "",
        }
        self.managed_ollama_models_dir: Path | None = None
        # Live agent runs, keyed by request_id: each holds a growing event list the
        # UI polls (start_agent_run / agent_run_events) so a run streams instead of
        # blocking on one big response.
        self.agent_runs: dict[str, dict[str, Any]] = {}
        # Bounded index of recent bounty runs, keyed by run_id: holds the minimal ctx +
        # per-ref findings a submission package needs to rebuild WITHOUT re-scanning.
        # In-memory only (drop-oldest); the on-disk report/JSON sidecar is the durable
        # copy. Lets the cockpit fetch a canonical build_submission package per finding.
        self.bounty_runs: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        # The portfolio hunt scheduler (lazy — created on first start).
        self._operator: "OperatorLoop | None" = None
        self.store = AICoreStore(RUNTIME_DIR)
        ensure_runtime()
        self.mcp_servers = MCPServerManager(RUNTIME_DIR / "mcp_servers.json")
        self._rewrite_core_defaults()
        self._ensure_bughunter_core()
        # The operator's researcher UA marker is install-wide, so it must be live BEFORE the first
        # request goes out — not only after a settings save. Loaded once here from the saved config.
        self._sync_ua_marker()

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
        existing = next((core for core in state.get("cores", [])
                         if core.get("id") == BUGHUNTER_CORE_ID), None)
        if existing is not None:
            # Upgrade existing installs once, then respect later operator source edits.
            if not existing.get("_verified_replay_source_v1"):
                source_ids = list(existing.get("sourceIds") or [])
                if "src_verified_replay" not in source_ids:
                    source_ids.append("src_verified_replay")
                existing["sourceIds"] = source_ids
                existing["_verified_replay_source_v1"] = True
                self.store.save(state)
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
            # The loss curve and the settings the run is actually using — the Train panel renders both,
            # and without them an operator can only see a single instantaneous number.
            "history": list(self.training.history),
            "settings": dict(self.training.settings),
        }

    def set_training_paused(self, paused: bool) -> dict[str, Any]:
        """Pause or resume the running cycle. 409 when nothing is running, so the UI cannot show a
        paused state for a run that does not exist. The trainer checks this predicate at the top of
        every optimizer step (training_runtime._wait_while_paused)."""
        with self.lock:
            if not self.training.active:
                raise HTTPError(409, "No training run is active.")
            self.training.paused = bool(paused)
            state = "paused" if paused else "running"
            self.training.runtime = {
                **self.training.runtime,
                "detail": f"Training {state} by the operator.",
            }
        self.log(f"Training {state} by the operator.")
        return self.training_payload()

    def request_training_stop(self) -> dict[str, Any]:
        """Ask the running cycle to stop at its next step boundary; it saves a checkpoint first."""
        with self.lock:
            if not self.training.active:
                raise HTTPError(409, "No training run is active.")
            self.training.stop_requested = True
            # Stopping while paused would otherwise block forever in _wait_while_paused.
            self.training.paused = False
        self.log("Training stop requested by the operator.")
        return self.training_payload()

    def training_dataset_preview(self) -> dict[str, Any]:
        """What a run would train on, and what each model size would cost — for the Train panel.

        Answers the questions an operator has BEFORE spending a run: how much text is actually there,
        which sources it came from, whether the character cap will truncate it, and whether the corpus
        is even large enough for a longer-context preset."""
        if not _ensure_ml_runtime():
            raise HTTPError(503, _ML_RUNTIME_ERROR)
        try:
            stats = collect_dataset_stats(RUNTIME_DIR) or {}
        except Exception as exc:  # noqa: BLE001 - a preview must never 500 the panel
            return {"ok": False, "error": f"Could not read the training data: {exc}"}
        # collect_dataset_stats reports the data/ files and train.txt separately; the trainer reads both.
        total = int(stats.get("extracted_characters") or 0) + int(stats.get("root_train_characters") or 0)
        # Parameter counts scale with the vocabulary, so read the real one when it exists.
        vocab_size = 339
        try:
            vocab_doc = json.loads((RUNTIME_DIR / "solin_vocab.json").read_text(encoding="utf-8"))
            vocab_size = int(vocab_doc.get("vocab_size") or len(vocab_doc.get("stoi") or {}) or vocab_size)
        except Exception:  # noqa: BLE001 - no vocab yet on a fresh install; the default is close enough
            pass
        sizes = []
        for name, preset in (MODEL_PRESETS or {}).items():
            block = int(preset.get("block_size") or 0)
            sizes.append({
                "id": name,
                "parameters": approx_parameter_count(preset, vocab_size),
                "block_size": block,
                "n_layer": int(preset.get("n_layer") or 0),
                "n_embd": int(preset.get("n_embd") or 0),
                # Both the train and val split must exceed one context window; the split is 90/10, so
                # the validation side is the binding constraint.
                "min_chars": block * 10 + 1,
                "fits": total > block * 10,
            })
        return {
            "ok": True,
            **stats,
            "total_characters": total,
            "vocab_size": vocab_size,
            "cap": MAX_TRAINING_CHARS,
            "capped": total > MAX_TRAINING_CHARS,
            "model_sizes": sizes,
            "default_model_size": "compact",
        }

    def hunt_model_status(self) -> dict[str, Any]:
        """Which hunt ranker is ACTIVE (bundled seed vs locally trained), what it scored when it was
        promoted, and how much trace corpus exists versus how much a retrain needs. Torch-free."""
        try:
            from bughunter import hunt_train
            return {"ok": True, **hunt_train.show_status(RUNTIME_DIR, SEED_DIR, hunt_train.DEFAULT_MIN_ROWS)}
        except Exception as exc:  # noqa: BLE001 - a status read must never 500 the panel
            return {"ok": False, "error": f"Could not read the hunt model: {exc}"}

    def train_hunt_brain(self, request: "HuntBrainTrainRequest") -> dict[str, Any]:
        """Run a hunt-ranker training attempt. Returns the result dict in every case — a refusal
        (too few rows, or the trained model failed to beat the rules baseline on the holdout) is a
        normal outcome, not an error, and ``ok`` is only true when a model was actually promoted."""
        try:
            from bughunter import hunt_train
            result = hunt_train.train(
                RUNTIME_DIR,
                seed_dir=SEED_DIR,
                epochs=request.epochs,
                lr=request.lr,
                l2=request.l2,
                rng_seed=request.rng_seed,
                holdout=request.holdout,
                min_rows=request.min_rows,
                dry_run=request.dry_run,
            )
        except Exception as exc:  # noqa: BLE001 - surface the reason rather than a generic 500
            self.log(traceback.format_exc())
            return {"ok": False, "error": f"Hunt-brain training failed: {exc}"}
        self.log(f"hunt-brain training: {result.get('detail') or result.get('reason') or result}")
        return result

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
        config = dict(config) if isinstance(config, dict) else {}
        # remote_api_key is migrated out of the plaintext file on boot (see
        # _migrate_code_router_secret); overlay it back from the perms-restricted
        # secrets store here, mirroring _merge_coder_secrets' pattern for coder.*.
        stored_key = _load_secrets().get(_CODE_ROUTER_SECRET_KEY)
        if stored_key:
            config["remote_api_key"] = stored_key
        return config

    def _coder_config(self) -> dict[str, Any]:
        payload = read_json(RUNTIME_DIR / "solin_runtime_config.json", {})
        config = payload.get("coder") if isinstance(payload, dict) else None
        config = config if isinstance(config, dict) else {}
        return _merge_coder_secrets(config)

    def _sync_ua_marker(self) -> str:
        """Load the operator's saved researcher UA marker into the scan stack's global marker.

        The marker lives in the same runtime config ``/api/coder`` already round-trips (one settings
        form, one save, one file) rather than in ``bughunter.settings``, which is env-var-only and
        therefore cannot be edited from the UI. It is deliberately NOT a secret: it is a public
        attribution token a program reads in its access logs, so it stays in the plaintext config
        alongside the model name, not in the secrets store.

        Never raises: an unreadable/absent config just means "no marker", which is the shipped
        behavior, so a settings problem can never stop the engine from starting."""
        try:
            marker = str((self._coder_config() or {}).get("researcher_ua_marker") or "")
        except Exception:  # noqa: BLE001 - a bad config must not break startup
            marker = ""
        return bounty_web_ingest.set_ua_marker(marker)

    def save_coder_config(self, update: dict[str, Any]) -> dict[str, Any]:
        runtime_path = RUNTIME_DIR / "solin_runtime_config.json"
        update = dict(update or {})
        # Sanitize the researcher marker at the WRITE boundary with the same rules the scan stack
        # applies, so a control character can never reach the stored file (defense in depth:
        # set_ua_marker sanitizes again on read, and neither layer is load-bearing alone).
        if "researcher_ua_marker" in update:
            update["researcher_ua_marker"] = bounty_web_ingest.sanitize_ua_fragment(
                update["researcher_ua_marker"]).strip()
        # Serialize the read-modify-write against set_device and concurrent saves so
        # an interleaved write can't drop the device_preference or another field.
        with self.lock:
            payload = read_json(runtime_path, {})
            if not isinstance(payload, dict):
                payload = {}
            # Merge the UI update, then split API keys out into the secrets store so
            # the main config stays key-free. An explicit clear_api_key in the update
            # also deletes the stored key (a blank api_key only means "keep it").
            payload["coder"] = _split_coder_secrets(
                coder.merge_update(payload.get("coder"), update),
                clear=coder.api_key_clear_requests(update),
            )
            write_json(runtime_path, payload)
        # Apply the saved marker immediately — the operator expects the next hunt to carry it.
        self._sync_ua_marker()
        return coder.public_config(self._coder_config())

    def coder_status(self) -> dict[str, Any]:
        return coder.public_config(self._coder_config())

    def brain_status(self, workspace: str | None = None) -> dict[str, Any]:
        """Public metadata only: technique names/counts, aggregate outcomes, and guardrails."""
        root = workspace or str(PROJECT_ROOT)
        status = brain_techniques.status_snapshot(RUNTIME_DIR, SEED_DIR, root)
        try:
            from learning_engine import LearningEngine

            status["recursive_learning"] = LearningEngine(RUNTIME_DIR).status()
        except Exception:  # noqa: BLE001 - learning telemetry is advisory
            status["recursive_learning"] = {"available": False}
        return status

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

    def list_local_models(self, base_url: str | None = None) -> dict[str, Any]:
        host, model = self._local_brain()
        try:
            # An unsaved server field in Settings should show that server's
            # installed models, using the same URL validation as setup.
            if base_url is not None:
                host = coder.ollama_setup_host(base_url)
            installed = coder.ollama_list_models(host)
            return {
                "ok": True,
                "installed": installed,
                "configured": model,
                "present": bool(model) and coder.model_installed(installed, model),
            }
        except coder.CoderError as exc:
            return {"ok": False, "error": str(exc), "configured": model, "installed": [], "present": False}

    def list_public_ollama_models(self) -> dict[str, Any]:
        """Live Ollama-owned catalog for the one-click local coding brain."""
        try:
            catalog = coder.ollama_public_catalog()
            return {
                "ok": True, "source": coder.OLLAMA_CATALOG_URL,
                "fetched_at": datetime.now(UTC).isoformat(), **catalog,
            }
        except coder.CoderError as exc:
            return {
                "ok": False, "source": coder.OLLAMA_CATALOG_URL,
                "models": [], "error": str(exc),
            }

    def model_pull_status(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.model_pull)

    def set_managed_ollama_models_dir(self, value: object) -> None:
        """Accept Electron's authenticated, in-memory Ollama store update."""
        if value is None:
            models_dir = None
        elif isinstance(value, str) and 0 < len(value) <= 4000 and Path(value).is_absolute():
            models_dir = Path(value).resolve()
        else:
            raise HTTPError(422, "models_dir must be an absolute path or null.")
        with self.lock:
            self.managed_ollama_models_dir = models_dir

    def start_huggingface_import(self, reference: str) -> dict[str, Any]:
        """Import, verify, and select a public GGUF through local Ollama."""
        try:
            model = coder.normalize_huggingface_model_ref(reference)
        except coder.CoderError as exc:
            return {"ok": False, "error": str(exc)}
        # The dedicated import route must use the same readiness gate as the
        # one-click setup route. An empty URL selects loopback Ollama even when
        # the previously saved brain used a remote server.
        return self.start_model_setup(model, base_url="")

    def start_model_pull(self, model: str = "") -> dict[str, Any]:
        host, configured = self._local_brain()
        target = (model or configured).strip()
        if not target:
            return {"ok": False, "error": "No local model is configured."}
        with self.lock:
            if self.model_pull.get("active"):
                return {**self.model_pull, "ok": False, "error": "A model download is already in progress."}
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

    def start_model_setup(self, reference: str, base_url: str = "") -> dict[str, Any]:
        """Download, verify, then select a model without disrupting the active brain.

        A failed download or failed readiness probe leaves the previous provider
        and model selected. The shared pull-status endpoint reports each phase.
        """
        try:
            target, is_hf = coder.normalize_local_model_reference(reference)
        except coder.CoderError as exc:
            return {"ok": False, "error": str(exc)}
        with self.lock:
            if self.model_pull.get("active"):
                return {**self.model_pull, "ok": False, "error": "A model download is already in progress."}
            previous = self._coder_config()
            try:
                # The setup request carries the server field explicitly. An empty
                # field means the default local Ollama host, even when the saved
                # brain previously pointed at a remote server.
                host = coder.ollama_setup_host(base_url)
            except coder.CoderError as exc:
                return {"ok": False, "error": str(exc)}
            previous_selection = (
                bool(previous.get("enabled")), str(previous.get("provider") or ""),
                str((previous.get("local") or {}).get("model") or ""),
                str((previous.get("local") or {}).get("base_url") or ""),
            )
            self.model_pull = {
                "active": True, "setup": True, "model": target, "status": "checking local models",
                "percent": 0, "completed": 0, "total": 0, "done": False,
                "chat_ready": False, "tool_ready": False, "selected": False,
                "chat_only": False, "error": "",
            }

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

        def worker() -> None:
            try:
                selected_model = target
                installed = coder.ollama_list_models(host)
                if not coder.model_installed(installed, selected_model):
                    if is_hf:
                        with self.lock:
                            self.model_pull["status"] = "checking Hugging Face GGUF repository"
                        coder.check_public_hf_gguf(target)
                    with self.lock:
                        self.model_pull["status"] = "downloading model"
                    try:
                        coder.ollama_pull(host, target, timeout=3600.0, progress_cb=progress)
                    except coder.CoderError as exc:
                        if not is_hf or "sharded gguf" not in str(exc).casefold():
                            raise
                        with self.lock:
                            self.model_pull.update({
                                "status": "preparing split GGUF import", "percent": 0,
                                "completed": 0, "total": 0,
                            })
                        with self.lock:
                            managed_models_dir = getattr(self, "managed_ollama_models_dir", None)
                        # Only an Electron-verified Ollama child is tied to its
                        # reported model directory. A pre-existing server may
                        # use a different store, even on loopback.
                        models_root = managed_models_dir if host == "http://127.0.0.1:11434" else None
                        # A pre-existing Ollama server can have a different
                        # environment from GreyIQ. Even an operator-set
                        # OLLAMA_MODELS here does not prove where that server
                        # stores blobs, so use the conservative unknown-store
                        # preflight unless Electron started the managed server.
                        selected_model = hf_gguf_import.import_sharded_hf_model(
                            host, target, RUNTIME_DIR / "hf-gguf-cache", progress,
                            models_root=models_root,
                        )
                        with self.lock:
                            self.model_pull["model"] = selected_model
                    installed = coder.ollama_list_models(host)
                    if not coder.model_installed(installed, selected_model):
                        raise coder.CoderError("Ollama reported success, but the model is absent from its installed list.")
                with self.lock:
                    self.model_pull.update({"status": "checking chat and agent tool calls", "percent": 100})
                readiness = coder.ollama_probe_readiness(host, selected_model)
                with self.lock:
                    self.model_pull.update({
                        "chat_ready": bool(readiness.get("chat_ready")),
                        "tool_ready": bool(readiness.get("tool_ready")),
                    })
                if not readiness.get("chat_ready"):
                    raise coder.CoderError(str(readiness.get("reason") or "Downloaded model failed the chat check."))
                if not readiness.get("tool_ready"):
                    with self.lock:
                        self.model_pull.update({
                            "active": False, "done": True, "chat_only": True,
                            "status": "chat only; previous brain unchanged",
                            "error": str(readiness.get("reason") or "Agent tool-call check failed."),
                        })
                    return
                with self.lock:
                    current = self._coder_config()
                    current_selection = (
                        bool(current.get("enabled")), str(current.get("provider") or ""),
                        str((current.get("local") or {}).get("model") or ""),
                        str((current.get("local") or {}).get("base_url") or ""),
                    )
                    if current_selection != previous_selection:
                        self.model_pull.update({
                            "active": False, "done": True,
                            "status": "ready; brain changed during setup",
                            "error": "The model is ready, but brain settings changed during setup. Select it manually if still wanted.",
                        })
                        return
                    local_update = {"model": selected_model, "base_url": base_url.strip()}
                    self.save_coder_config({"enabled": True, "provider": "local", "local": local_update})
                    self.model_pull.update({
                        "active": False, "done": True, "selected": True,
                        "status": "ready for chat and agent tools", "percent": 100,
                    })
            except Exception as exc:  # noqa: BLE001 - report failure to the operator
                self.log(f"Model setup failed: {exc}")
                with self.lock:
                    self.model_pull.update({
                        "active": False, "done": True, "status": "error",
                        "error": str(exc),
                    })

        threading.Thread(target=worker, name="ollama-model-setup", daemon=True).start()
        return {"ok": True, "active": True, "model": target}

    def delete_model(self, model: str) -> dict[str, Any]:
        target = (model or "").strip()
        if not target:
            return {"ok": False, "error": "No model specified."}
        with self.lock:
            if self.model_pull.get("active") and self.model_pull.get("model") == target:
                return {"ok": False, "error": "That model is still downloading."}
            config = self._coder_config()
            active = str((config.get("local") or {}).get("model") or "")
            if (config.get("enabled") and config.get("provider") == "local"
                    and active and (coder.model_installed([target], active)
                                    or coder.model_installed([active], target))):
                return {"ok": False, "error": "Select another local model before removing the active brain."}
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

    def _agent_workspace_lock(self, workspace: str) -> "threading.Lock":
        """The per-resolved-workspace agent-run lock (created on first use), so only one agent run
        touches a workspace at a time — concurrent runs race on files and clobber each other's
        single rollback snapshot."""
        key = str(Path(str(workspace or "")).expanduser().resolve())
        with self.lock:
            lk = self._agent_workspace_locks.get(key)
            if lk is None:
                lk = threading.Lock()
                self._agent_workspace_locks[key] = lk
            return lk

    _AGENT_BUSY_MSG = ("An agent run is already in progress for this workspace. Wait for it to "
                       "finish (or undo it) before starting another.")

    def run_agent(self, request: AgentRequest) -> dict[str, Any]:
        ws_lock = self._agent_workspace_lock(request.workspace)
        if not ws_lock.acquire(blocking=False):
            return {"ok": False, "request_id": uuid4().hex, "message": self._AGENT_BUSY_MSG,
                    "transcript": [], "steps": 0, "changes": [], "touched_files": [], "plan": [],
                    "flagged_reads": [], "completed": False, "verified": False, "outstanding": [],
                    "snapshot_available": False, "snapshot_count": 0}
        try:
            result = coding_agent.run_agent(
                request.message,
                request.history,
                request.workspace,
                self._coder_config(),
                runtime_dir=RUNTIME_DIR,
                seed_dir=SEED_DIR,
            )
            lesson = coding_learning_bridge.learn_from_verified_run(
                RUNTIME_DIR, prompt=request.message, result=result
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
                "tinygpt_lesson": lesson,
            }
        except coding_agent.AgentError as exc:
            # A mid-run failure may have partially written files; persist the snapshot the run
            # attached so the user can still undo those partial edits.
            snap = self._persist_snapshot(request.workspace, getattr(exc, "agent_snapshot", None) or [])
            return {
                "ok": False,
                "request_id": uuid4().hex,
                "message": str(exc),
                "transcript": [],
                "steps": 0,
                "changes": getattr(exc, "agent_changes", []) or [],
                "touched_files": getattr(exc, "agent_touched", []) or [],
                "plan": [],
                "flagged_reads": [],
                "completed": False,
                "verified": False,
                "outstanding": [],
                "snapshot_available": snap["available"],
                "snapshot_count": snap["count"],
            }
        finally:
            ws_lock.release()

    def start_agent_run(self, request: AgentRequest) -> dict[str, Any]:
        """Kick off an agent run in the background and return its request_id. The
        UI polls agent_run_events() for live tool-by-tool progress and, when the
        run finishes, the same result payload /api/agent would have returned."""
        request_id = uuid4().hex
        ws_lock = self._agent_workspace_lock(request.workspace)
        if not ws_lock.acquire(blocking=False):
            return {"ok": False, "request_id": request_id, "error": self._AGENT_BUSY_MSG, "message": self._AGENT_BUSY_MSG}
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
            event_type = str(event.get("type") or "")
            message = ""
            if event_type == "plan":
                plan = [str(step)[:120] for step in (event.get("plan") or [])[:6]]
                message = f"Code brain planned {len(plan)} verified workflow step(s)"
            elif event_type == "step" and isinstance(event.get("entry"), dict):
                entry = event["entry"]
                tool = str(entry.get("tool") or "agent step")[:60]
                status = "needs adaptation" if entry.get("is_error") else "completed"
                message = f"{tool}: {status}"
            if message:
                bounty_progress.global_log("brain_dialog", {
                    "domain": "code", "stage": event_type, "run_id": request_id,
                    "message": message,
                })

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
                lesson = coding_learning_bridge.learn_from_verified_run(
                    RUNTIME_DIR, prompt=request.message, result=result
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
                    "tinygpt_lesson": lesson,
                }
            except coding_agent.AgentError as exc:
                snap = self._persist_snapshot(request.workspace, getattr(exc, "agent_snapshot", None) or [])
                payload = {"ok": False, "request_id": request_id, "message": str(exc),
                           "snapshot_available": snap["available"], "snapshot_count": snap["count"]}
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI, never crashes the server
                self.log(f"Agent run failed: {exc}")
                snap = self._persist_snapshot(request.workspace, getattr(exc, "agent_snapshot", None) or [])
                payload = {"ok": False, "request_id": request_id, "message": f"Agent error: {exc}",
                           "snapshot_available": snap["available"], "snapshot_count": snap["count"]}
            finally:
                ws_lock.release()  # free the workspace for the next run, success or failure
            passed = bool(payload.get("ok") and payload.get("completed") and payload.get("verified"))
            outcome = "completed and verified" if passed else "ended without verified completion"
            bounty_progress.global_log("brain_dialog", {
                "domain": "code", "stage": "outcome", "run_id": request_id,
                "message": f"Code workflow {outcome}; the local procedure memory was updated",
            })
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
            if outcome.get("errors"):
                # Some files couldn't be restored (e.g. a lock / permission error). KEEP the snapshot
                # so the user can retry after clearing the cause — deleting it here would strand those
                # files with no way back.
                return {"ok": False, "available": True,
                        "error": "Some files could not be restored; the snapshot was kept so you can retry.",
                        **outcome}
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
        run_id = str(request.run_id or "").strip()
        if run_id:
            bounty_progress.start_run(run_id)
            # A single hunt drives the SAME live dashboard the campaign uses: register it as one work
            # unit (queued -> running -> done/error) so its status, streamed findings, and the rolled-up
            # stat tiles render on the campaign dashboard, not only in the compact text log.
            bounty_progress.set_targets(run_id, [request.target])
            bounty_progress.mark_target(run_id, request.target, "running")
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
            external_mcp_hunt=request.external_mcp_hunt,
            mcp_manager=getattr(self, "mcp_servers", None),
            time_based=request.time_based,
            auth={"cookie": request.auth_cookie, "headers": request.auth_headers},
            max_files=request.max_files,
            per_finding=request.per_finding,
            # A one-off hunt has no saved program to carry a required UA tag, so the operator supplies
            # it per run. Carried verbatim (the program dictates its own spacing) and sanitized by
            # web_ingest.set_ua_suffix inside the hunt.
            user_agent_suffix=request.user_agent_suffix,
            on_progress=bounty_progress.sink(run_id) if run_id else None,
            # The operator's Stop button. Without this a single hunt could not hear it at all: the pill
            # flipped to "Stopped" while the active fan-out, the re-plan wave and all four OOB provers
            # kept sending. The campaign paths below already poll this same flag between their URLs.
            should_stop=(lambda rid=run_id: bounty_progress.is_stopped(rid)) if run_id else None,
            # When a collaborator is configured, an active+authorized URL hunt also runs the blind-SSRF
            # OOB probe automatically (the token is the reproducible 'sheriff flag').
            oob_base=self._oob_config()[0], oob_secret=self._oob_config()[1],
        )
        if run_id:
            self._stream_hunt_to_dashboard(run_id, request.target, result)
        self._cache_bounty_run(result, target=request.target, scope=request.scope, program=None)
        return result

    @staticmethod
    def _stream_hunt_to_dashboard(run_id: str, target: str, result: dict[str, Any]) -> None:
        """Roll a completed single hunt's findings into the live-dashboard snapshot (the same compact
        shape the campaign streams per URL) and mark its work unit done/error — so a single hunt's
        findings + status appear on the campaign dashboard exactly like a campaign target's do. The
        activity log already streams live via the on_progress sink during the hunt. Never raises."""
        try:
            if not result.get("ok", True):
                bounty_progress.mark_target(run_id, target, "error", error=str(result.get("error") or ""))
                return
            poi = result.get("proof_of_impact") or {}
            compact: list[dict[str, Any]] = []
            for f in result.get("findings") or []:
                ref = str(f.get("ref") or "")
                detail = poi.get(ref) or {}
                compact.append({
                    "ref": ref, "title": f.get("title"), "severity": f.get("severity"),
                    "class_name": f.get("class_name") or f.get("class_id"),
                    # Same proof-status derivation the campaign uses (proof_of_impact[ref].status).
                    "proof_status": str(detail.get("status") or "missing"),
                    "location": f.get("location") or target, "cwe": f.get("cwe"),
                    "rule_id": f.get("rule_id"), "class_id": f.get("class_id"),
                    # Carry the captured differential + request/response so the dashboard drawer's
                    # "View full report" renders a confirmed single-hunt finding as CONFIRMED too.
                    "proof_detail": detail, "proof_evidence": f.get("proof_evidence") or None,
                })
            if compact:
                bounty_progress.add_findings(run_id, target, compact)
            bounty_progress.mark_target(run_id, target, "done")
        except Exception:  # noqa: BLE001 - progress must never break a hunt
            pass

    def bounty_progress(self, run_id: str, after: int = 0) -> dict[str, Any]:
        # `snapshot` carries the structured campaign-dashboard state (per-target status +
        # streamed findings + rolled-up stats); `events`/`count` remain the text log.
        return {"ok": True, **bounty_progress.tail(run_id, after), "snapshot": bounty_progress.snapshot(run_id)}

    def list_bounty_runs(self) -> dict[str, Any]:
        """The runs this backend is holding live progress for, newest first — the discovery step
        for a client that did not mint the run_id itself.

        /api/bounty/progress requires a run_id (BountyProgressRequest, min_length=1) and run ids are
        minted client-side, so an operator attaching from a separate process — `gn dash --attach` —
        has no way to name the run they want to watch. Read-only: it lists, it never starts, stops
        or evicts anything. `stopped` reports that a stop was REQUESTED, not that the run has wound
        down; nothing in the store marks a run finished (see progress.list_runs).

        Named `list_bounty_runs`, not `bounty_runs`: `self.bounty_runs` is already the finished-run
        artifact cache this class keeps. Shadowing it with a method would have broken every route
        that reads that cache — and the collision is silent, because the attribute simply wins.
        """
        return {"ok": True, "runs": bounty_progress.list_runs()}

    def bounty_events(self, after: int = 0) -> dict[str, Any]:
        """The app-wide event stream — findings confirmed, reports readied, submissions filed —
        so any open tab (Campaign, Findings, Report Center) reacts live to work happening in a
        different run/program. Read-only, poll-based; the durable ledger is the system of record."""
        return {"ok": True, **bounty_progress.global_tail(after)}

    def stop_campaign(self, run_id: str) -> dict[str, Any]:
        """Cooperatively cancel a running campaign: set a stop flag the campaign loops poll
        between targets/URLs, so it winds down and its blocking request returns the partial
        results found so far. Idempotent and safe on an unknown/finished run."""
        bounty_progress.request_stop(run_id)
        return {"ok": True}

    def reverify_finding(self, request: "ReverifyRequest") -> dict[str, Any]:
        """On-demand active re-probe of ONE finding's URL — the dashboard's "investigate"
        drawer 'Re-verify' action. Runs the SAME scope-gated, SSRF-guarded active checks the
        campaign's active pass uses (``active_verify_service.verify_active``) against just this
        URL, in its own thread (so it runs in PARALLEL to a live campaign, never blocking it),
        and returns the fresh proof. Fail-closed: refuses unless authorized AND the URL's host
        is named in the effective scope. Bounded request budget so one re-verify can't fan out."""
        if not request.authorized:
            return {"ok": False, "error": "Confirm you're authorized and in scope before re-verifying (tick the authorization box on the launch rail)."}
        url = str(request.url or "").strip()
        if not url:
            return {"ok": False, "error": "This finding has no URL to re-verify."}
        if request.program_id:
            program = bounty_portfolio.get_program(RUNTIME_DIR, request.program_id)
            if program:
                scope_error = bounty_portfolio.manual_web_scope_error(program)
                if scope_error:
                    return {"ok": False, "error": scope_error}
        scope, settings, _excluded = self._active_scope_for(request.scope, request.program_id)
        auth = bounty_scan_auth.build_auth(url, cookie=request.auth_cookie, headers=request.auth_headers)
        passes = max(1, min(int(request.stability_passes or 1), 3))
        results, meta = bounty_active_verify.verify_active(
            url, [], scope=scope, settings=settings, time_based=request.time_based,
            auth=auth, requests_budget=16,
        )
        if not meta.get("in_scope"):
            return {"ok": False, "in_scope": False, "host": meta.get("host", ""),
                    "error": meta.get("skipped_reason") or "That target is not named in the current scope, so it can't be re-verified."}
        compact = [self._compact_active(r) for r in results]
        requests_used = int(meta.get("requests_used", 0))
        rate_limited = bool(meta.get("rate_limited"))
        # Reproduction-stability: re-run the SAME benign, scope-gated, budget-bounded probe up to
        # `passes-1` more times and count how often each finding re-confirmed. A finding that
        # confirms every pass is reproducibly real; one that flips is flagged as possibly flaky.
        # Keyed by (rule_id|title) so a finding is tracked across passes; best-effort — a failed
        # extra pass never fails the whole re-verify.
        if passes > 1 and compact:
            def _key(item: dict[str, Any]) -> str:
                return f"{item.get('rule_id', '')}|{item.get('title', '')}"
            confirmed_counts = {_key(c): (1 if c["status"] == "confirmed" else 0) for c in compact}
            for _ in range(passes - 1):
                try:
                    more, more_meta = bounty_active_verify.verify_active(
                        url, [], scope=scope, settings=settings, time_based=request.time_based,
                        auth=auth, requests_budget=16)
                except Exception:  # noqa: BLE001 - a flaky extra pass must not fail the base re-verify
                    break
                requests_used += int(more_meta.get("requests_used", 0))
                rate_limited = rate_limited or bool(more_meta.get("rate_limited"))
                seen = {f"{r.get('rule_id','')}|{r.get('title','')}"
                        for r in (self._compact_active(x) for x in more) if r["status"] == "confirmed"}
                for k in confirmed_counts:
                    if k in seen:
                        confirmed_counts[k] += 1
            for c in compact:
                hits = confirmed_counts.get(_key(c), 0)
                c["stability"] = {"passes": hits, "of": passes, "stable": hits == passes and c["status"] == "confirmed"}
        confirmed = sum(1 for c in compact if c["status"] == "confirmed")
        return {
            "ok": True, "host": meta.get("host", ""), "in_scope": True,
            "requests_used": requests_used, "rate_limited": rate_limited,
            "stability_passes": passes, "findings": compact, "confirmed": confirmed,
        }

    # --- Shared active-probe helpers (used by reverify + prove) --------------------
    def _active_scope_for(self, scope: str, program_id: str | None) -> tuple[str, Any, tuple[str, ...]]:
        """Resolve the freshest, authoritative active-scan scope + settings: the saved
        program's current scope_text (so editing a program's scope takes effect without
        re-running) unioned with any scope the caller passes; the program's
        out_of_scope_hosts ride on the settings so an excluded host stays fail-closed."""
        scope_parts: list[str] = []
        excluded: tuple[str, ...] = ()
        if program_id:
            program = bounty_portfolio.get_program(RUNTIME_DIR, program_id)
            if program:
                if str(program.get("scope_text") or "").strip():
                    scope_parts.append(str(program["scope_text"]))
                excluded = tuple(str(h) for h in (program.get("out_of_scope_hosts") or []))
        if str(scope or "").strip():
            scope_parts.append(str(scope))
        settings = dataclasses.replace(_bounty_get_settings(), excluded_hosts=excluded)
        return "\n".join(scope_parts), settings, excluded

    @staticmethod
    def _compact_active(r: dict[str, Any]) -> dict[str, Any]:
        """Flatten one verify_active result (with its _active_proof) into the flat shape the
        dashboard drawer + report builder consume."""
        proof = r.get("_active_proof") or {}
        return {
            "title": r.get("title", ""), "severity": r.get("severity", "info"),
            "class_hint": r.get("_active_class_hint", ""), "rule_id": r.get("rule_id", ""),
            "status": proof.get("status", ""), "method": proof.get("method", ""),
            "observed": proof.get("observed_result", ""), "control": proof.get("control_result", ""),
            "evidence": proof.get("evidence", ""), "limitations": proof.get("limitations", ""),
            "affected_asset": proof.get("affected_asset", ""),
            # The captured request/response artifact (redirect Location:, CORS ACAO/ACAC, the reflected
            # marker, read_data) — carried through so the on-demand "Prove" flow records the ACTUAL
            # exploit evidence, not just the observed/control prose.
            "proof_evidence": r.get("proof_evidence") or {},
        }

    def _capture_proof_screenshot(self, url: str, scope: str, settings: Any) -> dict[str, Any]:
        """Best-effort proof screenshot of a PoC URL (scope-gated, SSRF-guarded, Playwright-
        backed). Returns a small inline data_url for the drawer preview when the PNG is
        under 4 MB. Never raises — a screenshot failure never fails proof-of-impact."""
        safe = "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(url))[:60]
        out_path = RUNTIME_DIR / "screenshots" / f"prove-{safe}.png"
        shot = bounty_screenshot.capture_screenshot(url, out_path, scope=scope, authorized=True, settings=settings)
        if not shot.get("ok"):
            return {"ok": False, "error": str(shot.get("error") or "Screenshot could not be captured.")}
        data_url = ""
        try:
            raw = Path(shot["path"]).read_bytes()
            if len(raw) <= 4_000_000:
                data_url = "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
        except OSError:
            pass
        return {"ok": True, "path": shot.get("path", ""), "data_url": data_url,
                "warning": shot.get("warning", ""), "final_url": shot.get("final_url", "")}

    def prove_finding(self, request: "ProveRequest") -> dict[str, Any]:
        """Create proof of impact for a candidate: run the scope-gated active checks against
        the finding's URL AND capture a proof screenshot, in its own thread (parallel to any
        campaign). Fail-closed: refuses without authorization / out of scope."""
        if not request.authorized:
            return {"ok": False, "error": "Confirm you're authorized and in scope before creating proof of impact (tick the authorization box)."}
        url = str(request.url or "").strip()
        if not url:
            return {"ok": False, "error": "This finding has no URL to probe."}
        if request.program_id:
            program = bounty_portfolio.get_program(RUNTIME_DIR, request.program_id)
            if program:
                scope_error = bounty_portfolio.manual_web_scope_error(program)
                if scope_error:
                    return {"ok": False, "error": scope_error}
        scope, settings, _excluded = self._active_scope_for(request.scope, request.program_id)
        auth = bounty_scan_auth.build_auth(url, cookie=request.auth_cookie, headers=request.auth_headers)
        results, meta = bounty_active_verify.verify_active(
            url, [], scope=scope, settings=settings, time_based=request.time_based,
            auth=auth, requests_budget=16,
        )
        if not meta.get("in_scope"):
            return {"ok": False, "in_scope": False, "host": meta.get("host", ""),
                    "error": meta.get("skipped_reason") or "That target is not named in the current scope, so proof of impact can't be gathered."}
        compact = [self._compact_active(r) for r in results]
        confirmed = sum(1 for c in compact if c["status"] == "confirmed")
        out = {"ok": True, "host": meta.get("host", ""), "in_scope": True,
               "requests_used": meta.get("requests_used", 0), "rate_limited": bool(meta.get("rate_limited")),
               "findings": compact, "confirmed": confirmed, "screenshot": None}
        # Persist the captured proof-of-impact differential back onto the cached run finding
        # (when the caller named one) — the same way capture_screenshot records a screenshot on
        # the run. Without this, proof gathered here flips only the status BADGE while the
        # canonical submission package (rebuilt from the untouched cached run) keeps rendering
        # "candidate", which is exactly the report/badge disagreement the operator hits.
        if confirmed and request.run_id and request.ref:
            out["persisted"] = self._persist_proof_of_impact(request.run_id, request.ref, compact)
        if request.screenshot:
            out["screenshot"] = self._capture_proof_screenshot(url, scope, settings)
        return out

    @staticmethod
    def _proof_matches_class(class_hint: str, class_id: str) -> bool:
        """The SAME class-match rule the UI applies (ckProofMatchesFinding): an active check
        only promotes a finding when its class matches the finding's class, so a re-probe that
        confirms a DIFFERENT class at the same URL never flips THIS finding to confirmed."""
        hint = str(class_hint or "").strip().lower()
        cls = str(class_id or "").strip().lower()
        return bool(hint and cls and (hint == cls or cls in hint or hint in cls))

    def _persist_proof_of_impact(self, run_id: str, ref: str, compact: list[dict[str, Any]]) -> bool:
        """Write the captured proof-of-impact differential from an active-prover pass onto the
        cached run's attack plan for ``ref`` so the canonical submission package renders it as a
        Confirmed proof of impact. Only a class-matched, confirmed result that carries a REAL
        observed-vs-control differential is persisted — never client prose or an unrelated class
        confirmed at the same URL. Returns True when a proof was persisted."""
        ctx, finding, _run = self._resolve_run_finding(run_id, ref)
        if ctx is None or finding is None:
            return False
        class_id = str(finding.get("class_id") or finding.get("category") or "")
        best = next(
            (c for c in compact
             if c.get("status") == "confirmed"
             and str(c.get("observed") or "").strip() and str(c.get("control") or "").strip()
             and self._proof_matches_class(c.get("class_hint", ""), class_id)),
            None,
        )
        if best is None:
            return False
        fields = {
            "method": str(best.get("method") or "").strip(),
            "observed_result": str(best.get("observed") or "").strip(),
            "control_result": str(best.get("control") or "").strip(),
            "evidence": str(best.get("evidence") or "").strip(),
            "affected_asset": str(best.get("affected_asset") or "").strip(),
            "limitations": str(best.get("limitations") or "").strip(),
        }
        # Concurrent /api/* calls (and any running campaign) share these cached dicts, so the
        # read-modify-write of the plan's proof block must hold the lock — same as
        # capture_screenshot's write-back of the screenshot paths.
        with self.lock:
            plans = ctx.setdefault("attack_plans", {})
            plan = plans.get(ref)
            if not isinstance(plan, dict):
                plan = {}
                plans[ref] = plan
            poi = dict(plan.get("proof_of_impact") or {})
            poi.update({k: v for k, v in fields.items() if v})
            poi["status"] = "confirmed"
            plan["proof_of_impact"] = poi
            # Record the ACTUAL captured request/response exploit artifact on the finding (the on-demand
            # Prove flow previously kept only the observed/control prose and threw the artifact away), so
            # the submission report renders the concrete headers / reflected marker / disclosed data.
            pe = best.get("proof_evidence")
            if isinstance(pe, dict) and pe:
                finding["proof_evidence"] = pe
            # Stamp the finding too, so a finding-level proof reader agrees with the plan.
            finding["proof_status"] = "confirmed"
        return True

    def list_all_findings(self) -> dict[str, Any]:
        """The durable, cross-run finding/report history (persistent ledger) + the portfolio
        funnel — so the Submissions hub can show ALL reports across every run and program,
        surviving restarts, not just the current in-memory run. Read-only."""
        try:
            records = bounty_ledger.list_all(RUNTIME_DIR)
            funnel = bounty_ledger.funnel(RUNTIME_DIR)
            archived = bounty_ledger.list_archived(RUNTIME_DIR)
        except Exception as exc:  # noqa: BLE001 - a history read must never 500 the hub
            return {"ok": False, "error": f"Could not read the finding ledger: {exc}"}
        # `truncated` when the (capped) list is shorter than the true portfolio total, so the
        # UI can say "showing the most recent N" and point at the CSV export for everything.
        # `archived` is the history subcategory: HIGH/CRITICAL findings kept from deleted programs.
        total = int((funnel.get("portfolio") or {}).get("total") or len(records))
        ready_total = int((funnel.get("portfolio") or {}).get("ready") or 0)
        return {"ok": True, "findings": records, "funnel": funnel, "archived": archived,
                "truncated": len(records) < total, "total": total, "ready_total": ready_total}

    def dismiss_finding(self, request: "FindingDismissRequest") -> dict[str, Any]:
        """Delete a finding: record its stable dedup key in the ledger's suppression set so no
        future hunt, campaign, durable-history view, or funnel ever surfaces it again. Derives
        the key from an explicit dedup_key (a durable-history record) or the finding's
        class_id/rule_id/location (a board finding). Reversible via ``restore_finding``."""
        # The dedup key is built from class_id/rule_id/location — with none of those (and no
        # explicit key) an all-empty finding still hashes to a real-but-meaningless key that
        # suppresses nothing useful. Reject it rather than record that junk key.
        if not (request.dedup_key or request.class_id or request.rule_id or request.location):
            return {"ok": False, "error": "Not enough detail to identify the finding to delete."}
        finding = {
            "class_id": str(request.class_id or ""), "rule_id": str(request.rule_id or ""),
            "location": str(request.location or ""), "title": str(request.title or ""),
        }
        try:
            entry = bounty_ledger.dismiss(
                RUNTIME_DIR, finding=finding, dedup_key_str=str(request.dedup_key or ""),
                program=request.program, target=str(request.target or ""),
            )
        except Exception as exc:  # noqa: BLE001 - a delete must never 500 the board
            return {"ok": False, "error": f"Could not delete the finding: {exc}"}
        if not entry:
            return {"ok": False, "error": "Not enough detail to identify the finding to delete."}
        return {"ok": True, "dedup_key": entry["dedup_key"]}

    def restore_finding(self, request: "FindingRestoreRequest") -> dict[str, Any]:
        """Undo a delete — the finding can surface again. Idempotent (safe if it wasn't deleted)."""
        try:
            restored = bounty_ledger.restore(RUNTIME_DIR, str(request.dedup_key or ""))
        except Exception as exc:  # noqa: BLE001 - a restore must never 500 the board
            return {"ok": False, "error": f"Could not restore the finding: {exc}"}
        return {"ok": True, "restored": bool(restored)}

    def build_finding_report(self, request: "FindingReportRequest") -> dict[str, Any]:
        """Build a well-authored report for ONE finding on demand from its own fields (a
        ledger/dashboard finding that isn't in the in-memory run cache), folding in any proof
        the operator just gathered. Server recomputes proof_status — a client can't forge
        'confirmed'. Pure / no-network."""
        ref = "R1"
        class_id = str(request.class_id or "").strip()
        # Fill the CWE from the class when the finding arrived without one (a ledger/history
        # finding often has no cwe): otherwise the platform gets no weakness and infers a wrong
        # one — e.g. HackerOne suggesting CWE-16 for a CORS report that should be CWE-284.
        cwe = str(request.cwe or "").strip() or cwe_for_class(class_id)
        # Same reason, same fix, for the OWASP category: six renderers read finding["owasp"] -- the
        # report's finding block and summary table, and the HackerOne, Bugcrowd and Intigriti
        # submission bodies -- and this builder never set it. So a report rebuilt from a
        # ledger/history finding dropped the OWASP row the same finding showed during its original
        # hunt, on the report AND on the filed submission. FindingReportRequest carries no owasp
        # field, so the class mapping is the only source here.
        owasp = owasp_for_class(class_id)
        finding = {
            "ref": ref, "title": str(request.title or "Security finding"),
            "severity": str(request.severity or "info"), "class_name": str(request.class_name or ""),
            "class_id": class_id, "location": str(request.location or request.target or ""),
            "cwe": cwe, "owasp": owasp, "rule_id": str(request.rule_id or ""),
            "description": str(request.description or ""), "screenshot_path": str(request.screenshot_path or ""),
        }
        # Carry the engine's captured request/response artifact (a history/board finding brings
        # it from its original hunt) so BOTH the evidence section renders the concrete headers
        # (e.g. CORS ACAO/ACAC) AND the class-specific concrete reproduction below is built from
        # the real reflected Origin/headers rather than a placeholder. This is why an on-demand
        # CORS report now shows the actual CORS headers a triager rejects the report for lacking.
        if request.proof_evidence is not None:
            pe = {k: v for k, v in request.proof_evidence.model_dump().items() if str(v or "").strip()}
            if pe:
                finding["proof_evidence"] = pe
        # STRICT SECRET CLASSIFICATION on the on-demand report path too — a ledger/dashboard finding for a
        # Google/Firebase browser key (or any exposed key) is reconstructed here from client fields with no
        # classification, so without this every strict-secret gate (severity clamp, confirm authority,
        # reportability) no-ops and a public key re-inflates to High/Confirmed/reportable. Classify BEFORE
        # the attack plan + submission so the whole render pipeline sees the correct class + severity.
        bounty_secret_class.apply_secret_classification([finding])
        # Every report gets REAL reproduction steps: the engine's offline attack-plan builder
        # (class-aware steps + a benign curl repro for web findings + impact + CVSS estimate),
        # the same steps a full hunt would emit — so an on-demand report for a ledger/dashboard
        # finding is never a stub with an empty "Steps to reproduce".
        plan = _deterministic_attack_plan(finding, class_id)
        # Carry a caller-supplied proof-of-concept outline (e.g. the brain's PoC that came
        # through with a campaign/board finding) into the report — the deterministic plan
        # starts with an empty poc, so without this an on-demand report has no PoC section.
        if str(request.poc or "").strip():
            plan["poc"] = str(request.poc).strip()
        # Overlay operator-gathered proof (from Create proof of impact) onto the plan's
        # proof-of-impact block — its observed/control/evidence make the report confirmable.
        if request.proof is not None:
            p = request.proof
            # This is the ONE place arbitrary (client-supplied) proof enters the report
            # pipeline. Never let it assert 'confirmed' on prose alone: only honor a
            # confirmed status when it carries BOTH a positive observation AND a negative
            # control (the same differential the engine's active prover always supplies) —
            # otherwise cap at 'candidate'. This blocks a forged status (e.g. observed_result
            # containing an "HTTP 200" string with no control) from flipping the report to
            # confirmed. The real HackerOne submit gate is separate (server-recomputed from
            # the cached engine run), but the report must not *claim* confirmed without proof.
            status = str(p.status or "").strip().lower()
            observed = str(p.observed_result or "").strip()
            # "Differential" means both sides present AND they differ — the confirm gate's own
            # predicate (report.proof_is_non_differential), so this overlay's cap and the rendered
            # proof_status can never disagree for a pasted identical pair.
            has_differential = bool(observed and str(p.control_result or "").strip()) and not (
                bounty_report.proof_is_non_differential(
                    {"observed_result": observed, "control_result": p.control_result})
            )
            # Cap at 'candidate' for ANY incoming status that lacks a real observed-vs-control
            # differential — including an EMPTY status. Otherwise a caller reaches 'confirmed'
            # by staying silent: with no explicit status the overlay writes nothing, and the
            # renderer auto-promotes on the observed artifact alone (report._has_captured_artifact).
            # Pinning a concrete 'candidate' whenever there's an observation but no control blocks
            # that promotion, so only a genuine differential can ever read 'confirmed'.
            if not has_differential and (status == "confirmed" or observed):
                status = "candidate"
            poi = dict(plan.get("proof_of_impact") or {})
            for k, v in (("status", status), ("method", p.method), ("observed_result", p.observed_result),
                         ("control_result", p.control_result), ("evidence", p.evidence),
                         ("affected_asset", p.affected_asset), ("limitations", p.limitations)):
                if str(v or "").strip():
                    poi[k] = v
            plan["proof_of_impact"] = poi
        ctx = {
            "tool": "GreyIQ BugHunter", "version": VERSION,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            "target": str(request.target or request.location or ""), "scope": str(request.scope or ""),
            "attack_plans": {ref: plan}, "disclose_automation": False,
        }
        # VDP POLICY GATE — the on-demand report builder is the single choke point every hand-filed
        # report flows through (the live dashboard drawer and the durable ledger both POST here). The
        # campaign consolidation applies the program's VDP policy, but the live snapshot streams findings
        # PRE-filter, so without this a finding the policy withheld could be reconstituted into a
        # submittable report here. Re-apply the SAME policy: refuse to author a report for a finding on
        # an excluded endpoint, of an always-rejected class, or (confirmed-only) that isn't confirmed.
        # VDP-gate proof status: the gate must see the SAME differential-capped status the report
        # renders, NOT a fresh _has_captured_artifact() on the raw client observed_result. When the
        # caller supplies proof, a bare "HTTP 200" with no control was already capped to 'candidate'
        # above (has_differential); reusing that here stops a confirmed_only program's withhold gate
        # from being bypassed by an uncontrolled client observation (authoring a report the policy
        # requires withheld while the badge honestly reads 'candidate'). With no client proof, the
        # engine's OWN cached artifact is the trustworthy signal, so keep _has_captured_artifact there.
        if request.proof is not None:
            gate_confirmed = (status == "confirmed")  # 'status' = the capped overlay status computed above
        else:
            gate_confirmed = bounty_report._has_captured_artifact(finding, None, "")
        profile = bounty_vdp.get_profile(request.policy_profile) if request.policy_profile else None
        if profile:
            gate_item = {"proof_status": "confirmed" if gate_confirmed else "candidate", "finding": finding}
            _kept, _dropped = bounty_vdp.filter_findings([gate_item], profile)
            if not _kept:
                reason = (_dropped[0].get("reason") if _dropped else "not reportable under this program's policy")
                return {"ok": False, "withheld": True, "policy": profile.get("name"), "reason": reason,
                        "error": f"Withheld by {profile.get('name')} policy: {reason}"}
        platform = bounty_formats.normalize_platform(request.platform)
        package = bounty_submission.build_submission(ctx, finding, platform)
        if package is None:
            return {"ok": False, "error": "This finding isn't reportable (e.g. an unconfirmed credential lead)."}
        # Return the report's OWN proof_status — build_submission reads the plan's proof_of_impact
        # status, which the overlay above already capped to 'candidate' when there's no real
        # observed-vs-control differential. This is the honest value a caller/badge must trust: a bare
        # "HTTP 200" observation with no control can never read 'confirmed' here.
        return {"ok": True, "package": package, "platform": platform,
                "proof_status": str(package.get("proof_status") or "candidate")}

    def get_report_ready(self, request: "ReportReadyRequest") -> dict[str, Any]:
        """"Get report ready" for ONE finding: assemble its POC (attack-plan steps + PoC + a runnable
        replay.sh + findings.har), POI (the observed-vs-control differential) and POE (the captured
        request/response artifact + screenshot) into a submission-ready report, server-recompute
        proof_status (a client can NEVER forge 'confirmed'), persist the ready state to the durable
        ledger, and notify the app-wide stream so the Report Center updates live. Honest on absence:
        a candidate finding with no differential stays 'candidate' and its POI/POE flags read false —
        no fabricated proof."""
        # 1) Assemble the report through the single honest choke point (caps forged confirms +
        #    re-applies the program's VDP policy). Reuses build_finding_report wholesale.
        report = self.build_finding_report(request)
        if not report.get("ok"):
            return report  # withheld by policy, or not reportable — surface as-is
        package = report.get("package") or {}
        platform = report.get("platform") or bounty_formats.normalize_platform(request.platform)
        proof_status = str(report.get("proof_status") or "candidate")

        # 2) POC / POI / POE presence — honest, server-computed (never asserted by the client).
        location = str(request.location or request.target or "")
        pe = {k: v for k, v in (request.proof_evidence.model_dump().items() if request.proof_evidence is not None else [])
              if str(v or "").strip()}
        has_poe = bool(pe) or bool(str(request.screenshot_path or "").strip())
        # POI is real only with BOTH a positive observation and a negative control that DIFFER —
        # the confirm gate's own predicate, so this flag can't read "proof" while proof_status
        # reads "candidate" for the same pasted identical pair.
        has_poi = bool(request.proof is not None
                       and str(request.proof.observed_result or "").strip()
                       and str(request.proof.control_result or "").strip()
                       and not bounty_report.proof_is_non_differential(
                           {"observed_result": request.proof.observed_result,
                            "control_result": request.proof.control_result}))
        # 3) Runnable POC artifacts from the captured evidence (empty when nothing reconstructable).
        item = {"finding": {"ref": "R1", "title": str(request.title or ""), "location": location,
                            "proof_evidence": pe},
                "source_url": location, "proof_status": proof_status,
                "proof_of_impact": (request.proof.model_dump() if request.proof is not None else {})}
        # confirmed_only=False: unlike the download bundle (whose replay.sh header and INDEX announce
        # these as the requests that CONFIRMED each finding), this is a PREVIEW of one finding the
        # operator is still assembling a report for. A runnable crafted request is useful to them
        # whether or not the differential has been captured yet, and the readiness panel reports POC
        # separately from POE/POI rather than implying confirmation.
        replay, replay_n = bounty_build_replay([item], confirmed_only=False)
        har, har_n = bounty_build_har([item], version=VERSION, confirmed_only=False)
        # POC readiness = a REAL runnable reproduction is present: a replay.sh/findings.har rebuilt
        # from a captured crafted request line, or an operator/brain-supplied runnable PoC
        # (request.poc). The assembled report ALWAYS carries deterministic reproduction steps, but
        # those are auto-generated guidance — not proof the finding reproduces — so gating the flag
        # on a captured or supplied artifact keeps POC honest and consistent with POI/POE (which
        # likewise mean "real proof captured"), instead of reading true for every finding.
        has_poc = bool(replay_n or har_n or str(request.poc or "").strip())

        # 4) Persist the ready state durably (orthogonal to the pipeline stage).
        finding_for_key = {"class_id": str(request.class_id or ""), "rule_id": str(request.rule_id or ""),
                           "location": location}
        key = str(request.dedup_key or "").strip() or bounty_ledger.dedup_key(finding_for_key)
        report_index = {"platform": platform, "filename": f"report-{key}.md", "proof_status": proof_status,
                        "screenshot_path": str(request.screenshot_path or "")}
        proof_flags = {"poc": has_poc, "poi": has_poi, "poe": has_poe}
        marked = bounty_ledger.mark_report_ready(RUNTIME_DIR, request.program, request.target, key,
                                                 report_index=report_index, proof_flags=proof_flags)
        if not marked:
            # Not in the durable ledger yet (readied straight from a fresh board run): record it, then
            # mark. upsert keys into program_key(program, target) — a NEW bucket, so no duplicate risk.
            try:
                bounty_ledger.upsert_findings(RUNTIME_DIR, request.program, request.target, [{
                    "finding": {"class_id": str(request.class_id or ""), "rule_id": str(request.rule_id or ""),
                                "title": str(request.title or ""), "severity": str(request.severity or "info"),
                                "location": location, "proof_evidence": pe,
                                "screenshot_path": str(request.screenshot_path or "")},
                    "source_url": location, "proof_status": proof_status,
                    "proof_of_impact": (request.proof.model_dump() if request.proof is not None else {}),
                }])
                marked = bounty_ledger.mark_report_ready(RUNTIME_DIR, request.program, request.target, key,
                                                         report_index=report_index, proof_flags=proof_flags)
            except Exception:  # noqa: BLE001 - persistence must never 500 the assembly
                marked = False

        # 5) Notify the app-wide stream (best-effort) so any open Report Center refreshes live --
        #    but ONLY when the ready state was durably persisted. Firing report_ready (or returning
        #    ok:True) on a failed write badges the finding "Report ready" in the UI, then silently
        #    drops it on the next reload/restart when the ledger has no flag. Be honest: no persist,
        #    no "ready" signal, and surface ok=False so the client doesn't badge a non-persisted row.
        if marked:
            bounty_progress.global_log("report_ready", {
                "dedup_key": key, "program": str(request.program or ""), "title": str(request.title or ""),
                "severity": str(request.severity or ""), "proof_status": proof_status,
                "poc": has_poc, "poi": has_poi, "poe": has_poe,
            })
        result = {"ok": bool(marked), "package": package, "platform": platform, "proof_status": proof_status,
                  "ready": {"poc": has_poc, "poi": has_poi, "poe": has_poe}, "persisted": bool(marked),
                  "dedup_key": key, "replay": (replay if replay_n else ""), "har": (har if har_n else None)}
        if not marked:
            result["error"] = "Could not persist the report-ready state to the durable ledger — not marked ready."
        return result

    def aggregate_report(self, request: "AggregateReportRequest") -> dict[str, Any]:
        """The special report: one engagement document across many findings — from a cached
        run (rich: proof + attack plans, via per-finding render) or a saved program (its
        durable ledger history)."""
        platform = bounty_formats.normalize_platform(request.platform)
        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        if request.run_id:
            with self.lock:
                run = self.bounty_runs.get(request.run_id)
            if not run:
                return {"ok": False, "error": "That run is no longer cached — re-run the hunt, or generate a program report from the history instead."}
            ctx = run["ctx"]
            findings = list((run.get("findings") or {}).values())
            md = _build_engagement_markdown_from_run(ctx, findings, platform, VERSION)
            label = ctx.get("target") or run.get("program") or "report"
            return {"ok": True, "markdown": md, "filename": f"engagement-{safe(label)}.md"}
        if request.program:
            records = [r for r in bounty_ledger.list_all(RUNTIME_DIR) if r.get("program") == request.program]
            if not records:
                return {"ok": False, "error": "No findings recorded for that program yet."}
            md = _build_engagement_markdown_from_ledger(str(request.program), records, VERSION)
            return {"ok": True, "markdown": md, "filename": f"engagement-{safe(request.program)}.md"}
        return {"ok": False, "error": "Provide a run_id or a program to build an engagement report."}

    def run_campaign(self, request: "CampaignRequest") -> dict[str, Any]:
        # authorized passes straight through — campaign.run_campaign fails closed when
        # it is False, exactly like the CLI. No default-True anywhere.
        run_id = str(request.run_id or "").strip()
        if run_id:
            bounty_progress.start_run(run_id)
        if request.program_id:
            return self._run_program_campaign(request)
        if not request.target.strip():
            return {"ok": False, "error": "No target provided."}
        # Best-effort: request.program is free text for an ad-hoc/cockpit campaign, but
        # for the autonomous operator's own per-cycle calls it IS the saved program's
        # real id (operator.py passes program=pid). When it resolves, apply that
        # program's disclose_automation + out_of_scope_hosts -- previously this plain
        # (non-span) path NEVER looked the program up at all, so the operator's every
        # unattended cycle silently ignored both settings.
        # active_program_id is the RELIABLE binding: the cockpit sends the picked program's real id here
        # for a single-target run so its VDP policy / creds / scope always apply, even when `program`
        # holds only the free-text handle (or is empty, e.g. a preset program with no HackerOne handle).
        # Look it up by id FIRST; fall back to the free-text `program` for the operator's pid path.
        program_obj = (bounty_portfolio.get_program(RUNTIME_DIR, request.active_program_id)
                       if request.active_program_id else None)
        if program_obj is None and request.program:
            program_obj = bounty_portfolio.get_program(RUNTIME_DIR, request.program)
        if program_obj:
            scope_error = bounty_portfolio.manual_web_scope_error(program_obj)
            if scope_error:
                return {"ok": False, "error": scope_error}
        disclose_automation = bool(program_obj.get("disclose_automation")) if program_obj else False
        excluded_hosts = tuple(str(h) for h in (program_obj.get("out_of_scope_hosts") or [])) if program_obj else ()
        account_access = program_obj.get("account_access") if program_obj else None
        admin_account_access = program_obj.get("admin_account_access") if program_obj else None
        idor_pairs = program_obj.get("idor_pairs") if program_obj else None
        policy_profile = str(program_obj.get("policy_profile") or "") if program_obj else ""
        # The saved program's destination platform SHAPES every submission package written to disk
        # (report_formats picks the per-platform field set + severity vocabulary). Without it the
        # engine default stood, so a Bugcrowd/Intigriti/YesWeHack program's on-disk packages came
        # out HackerOne-shaped — wrong severity vocabulary and missing the required VRT/CVSS field.
        # normalize_platform here so the engine is always handed a real platform id: a program's
        # 'manual' (the portfolio default) is not a report format, and normalizing maps it to the
        # same default the engine already used, leaving those programs exactly as they were.
        platform = bounty_formats.normalize_platform(program_obj.get("platform") if program_obj else "")
        # An explicit per-run tag wins over the saved program's (the operator typed it for THIS run);
        # otherwise the program's stored requirement stands, exactly as before. The value is carried
        # VERBATIM (only the emptiness test is trimmed) — a program dictates its own spacing, which is
        # why portfolio._clean_ua_suffix keeps spaces too.
        run_ua_suffix = str(request.user_agent_suffix or "")
        user_agent_suffix = (run_ua_suffix if run_ua_suffix.strip()
                             else (str(program_obj.get("user_agent_suffix") or "") if program_obj else ""))
        # An explicit cookie/header in the request wins; otherwise pass auth=None so the program's
        # stored research-account credentials (account_access) drive an auto-login in run_campaign.
        req_auth = ({"cookie": request.auth_cookie, "headers": request.auth_headers}
                    if (request.auth_cookie or request.auth_headers) else None)
        brain_config = self._coder_config()
        if bounty_operator_guard.current() is not None:
            brain_config = coder.unattended_config(brain_config)
        result = bounty_campaign.run_campaign(
            request.target,
            scope=request.scope,
            authorized=request.authorized,
            coder_cfg=brain_config,
            default_reports_dir=RUNTIME_DIR / "reports",
            seed_dir=SEED_DIR,
            runtime_dir=RUNTIME_DIR,
            version=VERSION,
            active=request.active,
            external_mcp_hunt=request.external_mcp_hunt,
            mcp_manager=getattr(self, "mcp_servers", None),
            time_based=request.time_based,
            auth=req_auth,
            account_access=account_access,
            admin_account_access=admin_account_access,
            idor_pairs=idor_pairs,
            policy_profile=policy_profile,
            platform=platform,
            user_agent_suffix=user_agent_suffix,
            live=request.live,
            program=request.program,
            max_pages=request.max_pages,
            deep=request.deep,
            include_attack_map=request.attack_map,
            disclose_automation=disclose_automation,
            excluded_hosts=excluded_hosts,
            on_progress=bounty_progress.sink(run_id) if run_id else None,
            progress_run_id=run_id or None,
            # The OOB collaborator, same source as the single-hunt route. Without it every
            # autonomous path had the four out-of-band provers (blind SSRF/XXE/RCE, JWT
            # key-URL injection) permanently disabled -- see campaign._run_campaign_body.
            oob_base=self._oob_config()[0], oob_secret=self._oob_config()[1],
        )
        self._cache_bounty_run(result, target=request.target, scope=request.scope, program=request.program,
                                program_id=str(program_obj.get("id")) if program_obj else None,
                                disclose_automation=disclose_automation)
        return result

    def _run_program_campaign(self, request: "CampaignRequest") -> dict[str, Any]:
        """"Span the whole program's scope" mode: resolve the saved program, derive its
        huntable target list (bughunter.campaign.program_campaign_targets — seed_targets,
        else eligible structured_scope entries), and run one full campaign per target,
        merged into a single combined result. The program's OWN scope_text is
        authoritative (not whatever free text happens to be in the request) so the span
        can never drift from the scope the operator actually saved for this program."""
        program = bounty_portfolio.get_program(RUNTIME_DIR, request.program_id)
        if not program:
            return {"ok": False, "error": "Program not found — it may have been deleted."}
        scope_error = bounty_portfolio.manual_web_scope_error(program)
        if scope_error:
            return {"ok": False, "error": scope_error}
        targets = bounty_campaign.program_campaign_targets(program)
        if not targets:
            return {"ok": False, "error": "This program has no huntable targets — add seed targets, opt in a source repository, or import/build its structured scope in the Program tab."}
        scope = str(program.get("scope_text") or "").strip() or request.scope
        program_label = str(program.get("name") or program.get("id") or request.program_id)
        disclose_automation = bool(program.get("disclose_automation"))
        excluded_hosts = tuple(str(h) for h in (program.get("out_of_scope_hosts") or []))
        req_auth = ({"cookie": request.auth_cookie, "headers": request.auth_headers}
                    if (request.auth_cookie or request.auth_headers) else None)
        run_id = str(request.run_id or "").strip()
        result = bounty_campaign.run_campaign_over_targets(
            targets,
            scope=scope,
            authorized=request.authorized,
            coder_cfg=self._coder_config(),
            default_reports_dir=RUNTIME_DIR / "reports",
            seed_dir=SEED_DIR,
            runtime_dir=RUNTIME_DIR,
            version=VERSION,
            active=request.active,
            external_mcp_hunt=request.external_mcp_hunt,
            mcp_manager=getattr(self, "mcp_servers", None),
            time_based=request.time_based,
            auth=req_auth,
            account_access=program.get("account_access"),
            admin_account_access=program.get("admin_account_access"),
            idor_pairs=program.get("idor_pairs"),
            policy_profile=str(program.get("policy_profile") or ""),
            # The program's destination platform shapes every submission package this span writes
            # (see the same line in the single-target path for why it must be forwarded).
            platform=bounty_formats.normalize_platform(program.get("platform")),
            # Same precedence as the single-target path: a per-run tag the operator typed for THIS
            # span wins; otherwise the program's saved requirement. Carried verbatim.
            user_agent_suffix=(str(request.user_agent_suffix or "")
                               if str(request.user_agent_suffix or "").strip()
                               else str(program.get("user_agent_suffix") or "")),
            live=request.live,
            program=program_label,
            max_pages=request.max_pages,
            deep=request.deep,
            include_attack_map=request.attack_map,
            disclose_automation=disclose_automation,
            excluded_hosts=excluded_hosts,
            on_progress=bounty_progress.sink(run_id) if run_id else None,
            progress_run_id=run_id or None,
            # The OOB collaborator, same source as the single-hunt route. Without it every
            # autonomous path had the four out-of-band provers (blind SSRF/XXE/RCE, JWT
            # key-URL injection) permanently disabled -- see campaign._run_campaign_body.
            oob_base=self._oob_config()[0], oob_secret=self._oob_config()[1],
        )
        target_label = f"{program_label} — {len(targets)} in-scope target(s)"
        # program_id is the REAL portfolio id (program_label above is the display name,
        # used for the target label / learning-bucket key) -- capture_screenshot's
        # scope-refresh lookup needs the id specifically, see program_id's docstring.
        self._cache_bounty_run(result, target=target_label, scope=scope, program=program_label,
                                program_id=str(program.get("id") or request.program_id),
                                disclose_automation=disclose_automation)
        return result

    def run_portfolio(self, request: "PortfolioRequest") -> dict[str, Any]:
        """Portfolio Hunt: resolve the selected (or all) saved programs, derive each one's
        huntable targets + authoritative scope, and run their campaigns CONCURRENTLY (bounded)
        merged into a single campaign-shaped result. Each program's own scope_text governs it;
        fail-closed on authorization. deep=True routes the AI-heavy write-ups through the
        (GPU-accelerated) local brain."""
        run_id = str(request.run_id or "").strip()
        if run_id:
            bounty_progress.start_run(run_id)
        all_progs = bounty_portfolio.list_programs(RUNTIME_DIR)
        if request.all_programs:
            chosen = all_progs
        else:
            wanted = {str(pid) for pid in (request.program_ids or [])}
            chosen = [p for p in all_progs if str(p.get("id")) in wanted]
        if not chosen:
            return {"ok": False, "error": "No programs selected — pick at least one saved program (or none exist yet; add one in the Program tab)."}
        for program in chosen:
            scope_error = bounty_portfolio.manual_web_scope_error(program)
            if scope_error:
                label = str(program.get("name") or program.get("id") or "selected program")[:200]
                return {"ok": False, "error": f"{label}: {scope_error}"}
        specs: list[dict[str, Any]] = []
        skipped: list[str] = []
        for program in chosen:
            targets = bounty_campaign.program_campaign_targets(program)
            label = str(program.get("name") or program.get("id"))
            if not targets:
                skipped.append(label)
                continue
            specs.append({
                "label": label,
                "scope": str(program.get("scope_text") or "").strip(),
                "targets": targets,
                "excluded_hosts": [str(h) for h in (program.get("out_of_scope_hosts") or [])],
                "disclose_automation": bool(program.get("disclose_automation")),
                "account_access": program.get("account_access"),
                "admin_account_access": program.get("admin_account_access"),
                "idor_pairs": program.get("idor_pairs"),
                "policy_profile": str(program.get("policy_profile") or ""),
                # Per-program, like policy_profile: a portfolio spans programs on different
                # platforms, so each one's packages must be shaped for ITS destination.
                "platform": bounty_formats.normalize_platform(program.get("platform")),
                "user_agent_suffix": str(program.get("user_agent_suffix") or ""),
            })
        if not specs:
            return {"ok": False, "error": "None of the selected programs have huntable targets — add seed targets, opt in a source repository, or import/build a structured scope in the Program tab."
                                          + (f" (skipped: {', '.join(skipped[:8])})" if skipped else "")}
        result = bounty_campaign.run_portfolio_campaign(
            specs,
            authorized=request.authorized,
            coder_cfg=self._coder_config(),
            default_reports_dir=RUNTIME_DIR / "reports",
            seed_dir=SEED_DIR,
            runtime_dir=RUNTIME_DIR,
            version=VERSION,
            active=request.active,
            external_mcp_hunt=request.external_mcp_hunt,
            mcp_manager=getattr(self, "mcp_servers", None),
            time_based=request.time_based,
            # An explicit request-level cookie/header wins; otherwise pass auth=None (NOT an empty dict)
            # so each program's own stored account_access drives a per-program auto-login. A non-None
            # empty dict here would suppress that login (run_campaign_over_targets only logs in when
            # `auth is None`), silently disabling ALL authenticated hunting — single-account AND the
            # dual-account BFLA / cross-tenant IDOR confirmation passes — for every portfolio run.
            auth=({"cookie": request.auth_cookie, "headers": request.auth_headers}
                  if (request.auth_cookie or request.auth_headers) else None),
            live=request.live,
            max_pages=request.max_pages,
            deep=request.deep,
            include_attack_map=request.attack_map,
            on_progress=bounty_progress.sink(run_id) if run_id else None,
            progress_run_id=run_id or None,
            # The OOB collaborator, same source as the single-hunt route. Without it every
            # autonomous path had the four out-of-band provers (blind SSRF/XXE/RCE, JWT
            # key-URL injection) permanently disabled -- see campaign._run_campaign_body.
            oob_base=self._oob_config()[0], oob_secret=self._oob_config()[1],
        )
        if result.get("ok") and skipped:
            result.setdefault("errors", []).insert(0, f"Skipped {len(skipped)} program(s) with no huntable targets: {', '.join(skipped[:8])}.")
        self._cache_bounty_run(result, target=f"Portfolio — {len(specs)} program(s)", scope="", program="portfolio",
                                program_id="portfolio")
        return result

    # ---- After-testing / submission workflow -------------------------------------
    def _cache_bounty_run(self, result: dict[str, Any], *, target: str, scope: str, program: str | None,
                          program_id: str | None = None, disclose_automation: bool = False) -> None:
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
            # The investigation (bounded: top hypotheses + up to 8 chains) has to ride in the cached
            # ctx, not just in `result`: every per-finding submission body is rendered from THIS ctx,
            # and report._append_chain_role reads ctx["investigation"] — without it the file the
            # operator pastes into the platform silently loses the chain the finding is a step of.
            "investigation": result.get("investigation") or {},
            "disclose_automation": disclose_automation,
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
            # Separate redacted "sensitive data captured" .txt artifacts, bundled under evidence/.
            "sensitive_data_paths": list(result.get("sensitive_data_paths") or []),
        }
        with self.lock:
            self.bounty_runs[run_id] = {
                "ctx": ctx, "findings": findings_by_ref, "program": program, "target": target,
                # "program" above is a DISPLAY label (name, for the target label / learning
                # bucket key) -- program_id is the real portfolio id for an exact-key
                # lookup (capture_screenshot's scope refresh), falling back to "program"
                # only when no real id is known (an ad-hoc, non-portfolio campaign).
                "program_id": program_id or program,
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

    def test_source_credential(self, request: "CredentialTestRequest") -> dict[str, Any]:
        """Explicit source API-key test for one cached finding.

        Sends exactly one benign read-only request to the key's own allowlisted issuer,
        records the issuer response and derived access scope, then attaches the artifact
        to the cached run so both the PoC zip and engagement bundle can carry it. The raw
        key is never returned to the browser and is redacted from the artifact."""
        if not request.authorized:
            return {"ok": False, "error": "Confirm this source API key is in scope and you are authorized to test it."}
        ctx, finding, run = self._resolve_run_finding(request.run_id, request.ref)
        if ctx is None or run is None:
            return {"ok": False, "error": "This run is no longer cached - re-run the hunt to test this source API key."}
        if finding is None:
            return {"ok": False, "error": "Unknown finding for this run."}
        if str(finding.get("class_id") or "").lower() != "secrets":
            return {"ok": False, "error": "This option is only available for API-key/credential findings in source."}
        key = str(finding.get("secret_value") or "").strip()
        if not key:
            return {"ok": False, "error": "This cached finding does not include the raw API key needed for a live issuer check."}
        # Strict secret classification redacts the raw key from the finding so it can't leak into any
        # report/JSON surface — which means it is no longer available for an on-demand re-test here. The
        # engine already validates credentials automatically DURING an authorized hunt (populating the
        # credential's live/not-live proof), so re-testing from a redacted cache isn't needed; be honest
        # rather than silently validating the redacted placeholder and reporting a false "not live".
        if "[REDACTED_SECRET" in key or "…" in key or "..." in key:
            return {"ok": False, "error": "The raw key is redacted for safety, so it can't be re-tested here. "
                    "Run the hunt with authorization ticked — the engine validates the credential live "
                    "automatically and shows whether it's live in the finding's report."}
        rule_id = str(finding.get("rule_id") or "")
        validators = {
            "secret.github-pat": bounty_credential_validation.validate_github_token,
            "secret.slack-bot-token": bounty_credential_validation.validate_slack_token,
            "secret.openai-key": bounty_credential_validation.validate_openai_key,
            "secret.anthropic-key": bounty_credential_validation.validate_anthropic_key,
            "secret.stripe-key": bounty_credential_validation.validate_stripe_key,
        }
        validator = validators.get(rule_id)
        if rule_id == "secret.google-api-key" and bounty_credential_validation.is_google_api_key(key):
            validator = bounty_credential_validation.validate_firebase_key
        if validator is None:
            return {"ok": False, "error": "No safe read-only issuer test is available for this key type yet."}

        proof = validator(key)
        proof["checked"] = True
        redacted_poc = redact_text(str(proof.get("poc") or ""))[0]
        redacted_response = redact_text(str(proof.get("response_excerpt") or proof.get("detail") or ""))[0]
        access_bits = [
            str(proof.get("principal") or "").strip(),
            str(proof.get("project_id") or "").strip(),
            str(proof.get("scopes") or "").strip(),
            ", ".join(str(d) for d in (proof.get("authorized_domains") or []) if str(d).strip()),
        ]
        access_summary = "; ".join(bit for bit in access_bits if bit)
        live = proof.get("live")
        status = "confirmed" if live is True else "not_live" if live is False else "inconclusive"
        artifact = {
            "finding_ref": request.ref,
            "title": str(finding.get("title") or ""),
            "location": str(finding.get("location") or finding.get("file_path") or ""),
            "rule_id": rule_id,
            "status": status,
            "live": live,
            "http_status": proof.get("http_status"),
            "endpoint": str(proof.get("endpoint") or ""),
            "access_summary": access_summary,
            "detail": redact_text(str(proof.get("detail") or ""))[0],
            "request_sent": redacted_poc,
            "api_response": redacted_response,
            "no_data_read": bool(proof.get("no_data_read")),
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        }

        # A LIVE Firebase key: also probe the open RTDB / Storage exposure (the actual DATA-STORE
        # exposure, not just liveness) — mirroring the inline hunt so re-testing a key from the UI
        # records the Firebase project/DB exposure too. Best-effort; never breaks the credential test.
        firebase_exposure: list[dict[str, Any]] = []
        if live is True and str(proof.get("project_id") or "").strip():
            try:
                for exp in bounty_credential_validation.probe_firebase_exposure(str(proof["project_id"]), key):
                    if isinstance(exp, dict) and exp.get("evidence"):
                        exp["evidence"] = redact_text(str(exp["evidence"]))[0]
                    firebase_exposure.append(exp)
            except Exception:  # noqa: BLE001 - exposure probe is enrichment; never fail the test
                pass
        artifact["firebase_exposure"] = firebase_exposure

        lines = [
            f"API KEY ACCESS TEST - {artifact['title'] or request.ref}",
            "=" * 72,
            "",
            f"Finding: {request.ref}",
            f"Location: {artifact['location']}",
            f"Rule: {rule_id}",
            f"Status: {status}",
            f"Endpoint: {artifact['endpoint']}",
            f"HTTP status: {artifact['http_status']}",
        ]
        if access_summary:
            lines.append(f"Accessible with key: {access_summary}")
        if artifact["detail"]:
            lines.extend(["", "Access detail", "-" * 72, artifact["detail"]])
        if redacted_poc:
            lines.extend(["", "Request sent (secret redacted)", "-" * 72, redacted_poc])
        if redacted_response:
            lines.extend(["", "API response returned by issuer", "-" * 72, redacted_response])
        lines.extend([
            "",
            "Safety note",
            "-" * 72,
            "This artifact was created by one read-only request to the key's own allowlisted issuer. The API key is redacted.",
        ])
        artifact_text = "\n".join(lines) + "\n"

        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        out_dir = RUNTIME_DIR / "credential-proofs"
        stem = f"{safe(request.run_id)}-{safe(request.ref)}-api-key-access"
        txt_path = out_dir / f"{stem}.txt"
        json_path = out_dir / f"{stem}.json"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            txt_path.write_text(artifact_text, encoding="utf-8")
            json_path.write_text(json.dumps(artifact, indent=2, default=str), encoding="utf-8")
        except OSError as exc:
            return {"ok": False, "error": f"Could not write API-key proof artifact: {exc}"}

        with self.lock:
            finding["_credential_proof"] = proof
            finding["credential_artifact_path"] = str(txt_path)
            finding["credential_artifact_json_path"] = str(json_path)
            finding["credential_access_artifact"] = artifact
            plans = run["ctx"].setdefault("attack_plans", {})
            plans[request.ref] = _deterministic_attack_plan(finding, str(finding.get("class_id") or "secrets"))
            run.setdefault("credential_artifacts", {})[request.ref] = [str(txt_path), str(json_path)]
        return {
            "ok": True,
            "status": status,
            "live": live,
            "proof": artifact,
            "artifact_text": artifact_text,
            "path": str(txt_path),
            "json_path": str(json_path),
        }

    def capture_screenshot(self, request: "ScreenshotRequest") -> dict[str, Any]:
        """Capture a proof screenshot of a finding's PoC URL in a headless browser and
        record it on the cached run so the report/submission embed it. OPT-IN, scope-bound
        and SSRF-guarded (in screenshot_service); Playwright-lazy (degrades cleanly). The
        image is NOT auto-redacted — the response carries a warning and the screenshot is
        NEVER auto-attached to the HackerOne API submit."""
        import base64

        ctx, finding, run = self._resolve_run_finding(request.run_id, request.ref)
        # Source the PoC URL + annotation from the cached finding when we have one (richest:
        # the exact crafted request URL, and the shot auto-embeds on the report). Otherwise fall
        # back to the request's own url/title/location/matched_value — so a finding opened from
        # HISTORY or an evicted run still screenshots from its OWN page with NO re-hunt.
        if finding is not None:
            url = bounty_screenshot.poc_url_for_finding(finding, ctx)
            title = str(finding.get("title") or "")
            location = str(finding.get("location") or finding.get("file_path") or "")
            pe = finding.get("proof_evidence")
            matched = str((pe.get("matched_value") if isinstance(pe, dict) else "") or finding.get("snippet") or "").strip()
            request_line = str((pe.get("request_line") if isinstance(pe, dict) else "") or "").strip()
        else:
            url = str(request.url or "").strip()
            if not url.startswith(("http://", "https://")):
                url = ""
            title, location, matched = str(request.title or ""), str(request.location or ""), str(request.matched_value or "")
            request_line = ""
        if not url:
            return {"ok": False, "error": "No proof-of-concept URL to screenshot — open this finding from a run or history entry that carries a URL."}
        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        stem = f"{safe(request.run_id or 'adhoc')}-{safe(request.ref or title or 'finding')}"
        out_path = RUNTIME_DIR / "screenshots" / f"{stem}.png"
        # Resolve the FRESHEST scope at capture time: union (1) the run's own scope, (2) the live
        # program's current scope_text (so editing a saved program's scope takes effect WITHOUT a
        # re-run), and (3) an optional scope the caller passes (the cockpit's Scope box). All three
        # are operator-supplied authorizations; the fail-closed host_in_active_scope gate still runs
        # against the union, so this only ever WIDENS to hosts the operator has explicitly named.
        scope_sources = [str((ctx or {}).get("scope") or "")]
        program_id = str((run or {}).get("program_id") or "")
        if program_id:
            prog = bounty_portfolio.get_program(RUNTIME_DIR, program_id)
            if prog:
                scope_error = bounty_portfolio.manual_web_scope_error(prog)
                if scope_error:
                    return {"ok": False, "error": scope_error}
                scope_sources.append(str(prog.get("scope_text") or ""))
        if request.scope.strip():
            scope_sources.append(request.scope)
        scope = " ".join(s for s in scope_sources if s.strip())
        # Annotate + highlight so the shot proves the finding (a rendered page often shows nothing
        # about a source/header bug), and grab a whole-page shot alongside the focused evidence one.
        annotate = {"title": title, "location": location or url, "matched": matched, "request_line": request_line}
        result = bounty_screenshot.capture_screenshot(
            url, out_path, scope=scope, authorized=True, full_page=request.full_page,
            annotate=annotate, highlight=matched, extra_full_page=True,
        )
        if not result.get("ok"):
            return result
        shots = result.get("shots") or [{"path": result.get("path", ""), "kind": "evidence"}]
        source_text = str(result.get("source_text") or "")
        source_text_path = str(result.get("source_text_path") or "")
        # Record on the cached finding so build_submission/report embed the shot(s) by basename.
        # Each /api/* call runs in its own asyncio.to_thread worker, so concurrent requests on the
        # same run_id+ref must not race on this read-modify-write of the shared cached dicts.
        with self.lock:
            if finding is not None:
                paths = [s["path"] for s in shots if s.get("path")]
                if paths:
                    finding["screenshot_path"] = paths[0]
                    finding["screenshot_paths"] = paths
                    if run is not None and request.ref:
                        run.setdefault("screenshots", {})[request.ref] = paths
                if source_text_path:  # the plain-text request/response/source proof, for the bundle
                    finding["source_text_path"] = source_text_path
                    if run is not None and request.ref:
                        run.setdefault("source_texts", {})[request.ref] = source_text_path
        out_shots: list[dict[str, Any]] = []
        for s in shots:
            data_url = ""
            try:
                raw = Path(s["path"]).read_bytes()
                if len(raw) <= 4_000_000:  # inline preview for the cockpit; skip if huge
                    data_url = "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
            except OSError:
                pass
            out_shots.append({"path": s.get("path", ""), "kind": s.get("kind", ""), "data_url": data_url})
        return {
            "ok": True, "shots": out_shots,
            "data_url": out_shots[0]["data_url"] if out_shots else "",  # back-compat single-image field
            "path": shots[0].get("path", "") if shots else "",
            "url": result.get("url"), "final_url": result.get("final_url"),
            "title": result.get("title"), "warning": result.get("warning"),
            "highlighted": result.get("highlighted", False),
            "source_text": source_text,  # copy-pasteable request/response/source, for the POC zip / report
        }

    def render_attack_plan_map(self, request: "AttackMapRequest") -> dict[str, Any]:
        """Render the GRAPHICAL attack-plan map (.png) for a finding ON DEMAND and return it as an
        inline data_url for the 'View full report' page (and record its path on the cached finding so
        the report/submission embed it). Built entirely from already-captured data — NO network.
        Playwright-lazy; degrades cleanly (ok:False) if Chromium is unavailable."""
        import base64

        ctx, finding, run = self._resolve_run_finding(request.run_id, request.ref)
        # Richest source: the cached finding + its attack plan. Fallback: the fields the caller passed
        # (a finding opened from history / an evicted run) so a map still renders with no re-hunt.
        if finding is not None:
            fnd = finding
            plans = (ctx or {}).get("attack_plans")
            plan = plans.get(request.ref) if isinstance(plans, dict) else None
            plan = dict(plan) if isinstance(plan, dict) else {}
            if not isinstance(plan.get("proof_of_impact"), dict) and isinstance(fnd.get("_active_proof"), dict):
                plan["proof_of_impact"] = fnd["_active_proof"]   # active-pass findings carry the differential here
        else:
            if not (str(request.title or "").strip() or str(request.location or "").strip()):
                return {"ok": False, "error": "Open this finding from a run or history entry so its attack plan can be mapped."}
            fnd = {
                "title": request.title, "severity": request.severity, "class_name": request.class_name,
                "location": request.location,
                "proof_evidence": {"request_line": request.request_line, "request_header": request.request_header,
                                   "matched_value": request.matched_value},
            }
            plan = {"impact": request.impact, "proof_of_impact": {
                "actor": request.actor, "observed_result": request.observed_result,
                "control_result": request.control_result}}
        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        stem = f"{safe(request.run_id or 'adhoc')}-{safe(request.ref or fnd.get('title') or 'finding')}"
        out_path = RUNTIME_DIR / "screenshots" / f"{stem}-attack-map.png"
        res = bounty_attack_map.render_attack_map(fnd, plan, out_path)
        if not res.get("ok"):
            return {"ok": False, "error": res.get("error") or "Could not render the attack-plan map (Playwright/Chromium may be unavailable)."}
        data_url = ""
        try:
            raw = Path(res["path"]).read_bytes()
            if len(raw) <= 4_000_000:  # inline preview; skip if huge
                data_url = "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
        except OSError:
            pass
        # Record on the cached finding so build_submission / the report embed the map by basename.
        with self.lock:
            if finding is not None:
                finding["attack_map_path"] = res["path"]
                if run is not None and request.ref:
                    run.setdefault("attack_maps", {})[request.ref] = res["path"]
        return {"ok": True, "path": res["path"], "data_url": data_url}

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
            # See capture_screenshot: concurrent /api/* calls against the same run_id+ref
            # mutate these shared cached dicts from different worker threads.
            with self.lock:
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
                             json_extra: dict[str, Any] | None = None,
                             disclose_automation: bool = False) -> dict[str, Any]:
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
               "target": target, "scope": scope, "attack_plans": plans,
               "disclose_automation": disclose_automation}
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
        self._cache_bounty_run(result, target=target, scope=scope, program=None,
                                disclose_automation=disclose_automation)
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
    def check_mass_assignment(self, request: "MassAssignRequest") -> dict[str, Any]:
        """Confirm MASS ASSIGNMENT -> privilege escalation on an object the account OWNS: the session
        sets a boolean privilege flag (is_admin / is_verified / ...) the server should never accept from
        a client, proven by a before/after re-read plus an empty-write control. Benign + reversible (the
        flag is restored). On a CONFIRMED escalation, cache it as a run so every per-finding action works."""
        res = bounty_access.run_mass_assignment_check(
            request.object_url,
            account={"cookie": request.cookie, "headers": request.headers},
            scope=request.scope,
        )
        if not res.get("ok"):
            return res
        status = res["status"]
        if status != "confirmed":
            return {"ok": True, "status": status, "reason": res.get("reason", ""), "detail": res.get("detail")}
        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.object_url).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.object_url, scope=request.scope,
            platform=request.platform, slug="mass-assignment", host=host, json_extra={"detail": res.get("detail")})
        return {
            "ok": True, "status": "confirmed", "run_id": persisted["run_id"], "ref": "F1",
            "platform": persisted["platform"], "report": persisted["report"], "detail": res.get("detail"),
            "title": finding["title"], "severity": finding["severity"],
        }

    @_confirm_route
    def check_session_invalidation(self, request: "SessionInvalRequest") -> dict[str, Any]:
        """Confirm a SESSION STAYS VALID AFTER LOGOUT: log in, verify an authenticated endpoint, log out,
        then replay the SAME session and confirm it still authenticates (while an anonymous request is
        denied). Only the operator's OWN session is used. On CONFIRMED, cache it as a run."""
        res = bounty_access.run_session_invalidation_check(
            request.authed_url, request.logout_url,
            account={"cookie": request.cookie, "headers": request.headers},
            scope=request.scope,
        )
        if not res.get("ok"):
            return res
        status = res["status"]
        if status != "confirmed":
            return {"ok": True, "status": status, "reason": res.get("reason", ""), "detail": res.get("detail")}
        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.authed_url).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.authed_url, scope=request.scope,
            platform=request.platform, slug="session-invalidation", host=host, json_extra={"detail": res.get("detail")})
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

    def _run_replay_items(self, run: dict[str, Any]) -> list[dict[str, Any]]:
        """Rebuild the replay/HAR item list ({finding, proof_status, proof_of_impact}) from a
        cached run's findings + attack plans — the shape bounty_build_replay/har consume."""
        ctx = run.get("ctx") or {}
        plans = ctx.get("attack_plans") or {}
        items: list[dict[str, Any]] = []
        for ref, finding in (run.get("findings") or {}).items():
            if not isinstance(finding, dict):
                continue
            plan = plans.get(ref) if isinstance(plans.get(ref), dict) else {}
            poi = plan.get("proof_of_impact") if isinstance(plan.get("proof_of_impact"), dict) else {}
            status = str(poi.get("status") or finding.get("proof_status") or "")
            items.append({"finding": finding, "source_url": finding.get("location", ""),
                          "proof_status": status, "proof_of_impact": poi, "plan": plan})
        return items

    def _run_findings_summary(self, run: dict[str, Any]) -> list[dict[str, Any]]:
        """A compact per-finding summary (ref/title/severity/proof_status) for the bundle INDEX."""
        summary: list[dict[str, Any]] = []
        for item in self._run_replay_items(run):
            f = item["finding"]
            summary.append({"ref": str(f.get("ref") or ""), "title": str(f.get("title") or ""),
                            "severity": str(f.get("severity") or ""),
                            "proof_status": item["proof_status"] or "candidate"})
        return summary

    def export_leads(self, request: "LeadsRequest") -> dict[str, Any]:
        """The finished hunt's investigation queue — as a Markdown brief AND as structured rows.

        This is the in-app face of ``gn leads``: the operator gets the ranked leads, their evidence
        state, the contradictions against each, and the exact proof obligation that would confirm
        it — either as one file to hand to an analyst, or rendered in the cockpit.

        ``report`` carries the SAME projection the brief is rendered from. It was already being
        built here and thrown away, which left the in-app operator with a file download and no way
        to actually READ the queue — the CLI had ``--json`` and the cockpit had nothing. Returning
        it costs one key and no extra work, and it cannot widen what crosses the boundary because
        the brief is rendered from this very object: anything reachable in ``report`` was already
        reachable in ``markdown``.

        The sidecar is located from the CACHED RUN (never a client-supplied path), so this route
        cannot be walked into an arbitrary file read. Both shapes are built by ``leads``, which
        projects through a strict allowlist and scrubs every field, so no raw credential, response
        body, page source, or screenshot path can ride along.
        """
        from bughunter import leads as leads_lib

        with self.lock:
            run = self.bounty_runs.get(request.run_id)
        if not run:
            return {"ok": False, "error": "This run is no longer cached — re-run the hunt to rebuild its leads."}
        art = run.get("artifacts") or {}
        # A campaign writes per-target sidecars under its own folder; a single hunt writes one JSON.
        # Point the bridge at the folder for a campaign so it sweeps every target's leads.
        source = str(art.get("output_dir") or "") if art.get("is_campaign") else str(art.get("json_path") or "")
        if not source or not Path(source).exists():
            return {"ok": False, "error": "This run's report file is no longer on disk — re-run the hunt."}
        try:
            report = leads_lib.build_lead_report(source)
            markdown = leads_lib.render_lead_brief(report, wrap=True)
        except Exception as exc:  # noqa: BLE001 - a download must fail with a message, not a 500
            return {"ok": False, "error": f"Could not build the lead brief: {exc}"}
        lead_count = sum(len(h.get("leads") or []) for h in report.get("hunts") or [])
        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "-" for c in str(s))[:48]  # noqa: E731
        # The filename is derived from the target, and a target is not always a URL — a source hunt
        # names a local folder. `safe` only rewrites punctuation, so an opaque target carrying a
        # credential (`/tmp/token-ghp_...`) would survive into the download filename even though the
        # brief's own metadata is scrubbed. Redact before slugging: a hostname is unaffected, and a
        # path keeps enough shape to stay recognisable.
        _target = str(run.get("target") or "")
        host = urlparse(_target).hostname or (leads_lib._redacted(_target, 120) or "hunt")
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return {
            "ok": True,
            "markdown": markdown,
            "report": report,
            "filename": f"greyiq-leads-{safe(host)}-{stamp}.md",
            "lead_count": lead_count,
            "hunts": len(report.get("hunts") or []),
        }

    def export_bundle(self, request: "BundleRequest") -> dict[str, Any]:
        """Zip the whole engagement (reports, per-platform packages, evidence,
        screenshots, research dossiers, JSON, replay.sh/findings.har, and a triager-facing
        INDEX.md) for download. A campaign's self-contained folder is zipped whole; a single
        hunt's artifacts are gathered by file list. V2: a single hunt now also gets the
        machine-replayable replay.sh + findings.har (previously campaign-only) and every
        bundle carries an INDEX.md "start here" map. The .zip is returned inline (base64)
        under a size cap, else by path. Local only."""
        import base64

        with self.lock:
            run = self.bounty_runs.get(request.run_id)
        if not run:
            return {"ok": False, "error": "This run is no longer cached — re-run the hunt to rebuild the bundle."}
        art = run.get("artifacts") or {}
        ctx = run.get("ctx") or {}
        safe = lambda s: "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(s))[:60]  # noqa: E731
        out_zip = RUNTIME_DIR / "bundles" / f"engagement-{safe(request.run_id)}.zip"
        # Stamp the run's identity + generation time into the evidence-integrity manifest so
        # the chain of custody names the exact tool/version and when the evidence was bundled.
        # The findings summary + target/scope feed the INDEX.md the triager reads first.
        bundle_meta: dict[str, Any] = {
            "tool": "GreyIQ BugHunter", "version": VERSION,
            "generated_at": str(run.get("generated_at") or art.get("generated_at") or ""),
            "target": str(run.get("target") or ctx.get("target") or ""),
            "scope": str(ctx.get("scope") or ""),
            "findings": self._run_findings_summary(run),
        }
        if art.get("is_campaign") and art.get("output_dir") and Path(art["output_dir"]).is_dir():
            out_dir = Path(art["output_dir"])
            # Write the INDEX into the campaign folder (idempotent) so the folder is self-
            # documenting whether opened directly or via the .zip. present = what's actually
            # there + the manifest files bundle_directory will add.
            try:
                present = {p.name for p in out_dir.iterdir()}
                present |= {"INDEX.md", "EVIDENCE-MANIFEST.json", "MANIFEST.sha256"}
                bounty_fsutil.write_text_safe(out_dir / "INDEX.md", bounty_bundle.build_index(bundle_meta, present))
            except OSError:
                pass
            res = bounty_bundle.bundle_directory(out_dir, out_zip, meta=bundle_meta)
        else:
            specs: list[tuple[str, str]] = []
            for key in ("report_path", "json_path"):
                if art.get(key):
                    specs.append((Path(art[key]).name, art[key]))
            for p in art.get("per_finding_paths") or []:
                specs.append((f"findings/{Path(p).name}", p))
            for p in art.get("submission_paths") or []:
                specs.append((f"submissions/{Path(p).name}", p))
            # The separate redacted sensitive-data captures (one .txt per finding that disclosed
            # sensitive data), so a triager sees exactly what was returned alongside the report.
            for p in art.get("sensitive_data_paths") or []:
                specs.append((f"evidence/sensitive-data/{Path(p).name}", p))
            for ref, entry in (run.get("screenshots") or {}).items():
                for index, p in enumerate((entry if isinstance(entry, list) else [entry]), 1):
                    if p:
                        specs.append((f"screenshots/{safe(ref)}-{index:02d}-{Path(p).name}", p))
            for ref, entry in (run.get("research_paths") or {}).items():
                for index, p in enumerate((entry if isinstance(entry, list) else [entry]), 1):
                    if p:
                        specs.append((f"research/{safe(ref)}-{index:02d}-{Path(p).name}", p))
            # The plain-text request/response/source proof (.txt) captured per finding.
            for ref, entry in (run.get("source_texts") or {}).items():
                for index, p in enumerate((entry if isinstance(entry, list) else [entry]), 1):
                    if p:
                        specs.append((f"evidence/{safe(ref)}-source-{index:02d}-{Path(p).name}", p))
            for ref, entry in (run.get("credential_artifacts") or {}).items():
                for index, p in enumerate((entry if isinstance(entry, list) else [entry]), 1):
                    if p:
                        specs.append((f"evidence/{safe(ref)}-credential-{index:02d}-{Path(p).name}", p))
            # V2 parity: a single hunt now also ships the machine-replayable reproduction
            # artifacts + the INDEX, staged to disk (bundle_files reads from disk).
            stage = RUNTIME_DIR / "bundles" / f"stage-{safe(request.run_id)}"
            try:
                stage.mkdir(parents=True, exist_ok=True)
                items = self._run_replay_items(run)
                replay, replay_n = bounty_build_replay(items)
                if replay_n:
                    bounty_fsutil.write_text_safe(stage / "replay.sh", replay)
                    specs.append(("replay.sh", str(stage / "replay.sh")))
                har, har_n = bounty_build_har(items, version=VERSION, generated_at=bundle_meta["generated_at"])
                if har_n:
                    bounty_fsutil.write_text_safe(stage / "findings.har", json.dumps(har, indent=2))
                    specs.append(("findings.har", str(stage / "findings.har")))
                present = {arc.split("/", 1)[0] for arc, _ in specs}
                present |= {"INDEX.md", "EVIDENCE-MANIFEST.json", "MANIFEST.sha256"}
                bounty_fsutil.write_text_safe(stage / "INDEX.md", bounty_bundle.build_index(bundle_meta, present))
                specs.append(("INDEX.md", str(stage / "INDEX.md")))
            except OSError:
                pass
            res = bounty_bundle.bundle_files(specs, out_zip, meta=bundle_meta)
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
            "manifest": res.get("manifest") or [],  # evidence-integrity files bundled (chain of custody)
            "download_b64": download_b64, "inline": bool(download_b64),
        }

    def _hackerone_weakness_id(self, handle: str, cwe: Any) -> int | None:
        """Match a finding's CWE against the program's enabled HackerOne weakness list so a
        filed report lands weakness-set (routable) rather than untriaged. The list is fetched
        once per handle per process and cached. Fail-closed: any failure -> None (the report
        still files, just without a structured weakness — the pre-v2 behavior)."""
        number = bounty_taxonomy.cwe_number(cwe)
        if not (handle and number):
            return None
        cache = getattr(self, "_h1_weakness_cache", None)
        if cache is None:
            cache = {}
            self._h1_weakness_cache = cache
        if handle not in cache:
            _, username, token = self._hackerone_creds()
            res = bounty_h1_import.fetch_weaknesses(handle, username, token)
            cache[handle] = res.get("weaknesses") if res.get("ok") else []
        return bounty_taxonomy.match_weakness_id(cache.get(handle) or [], cwe)

    @staticmethod
    def _run_program_id(run: dict[str, Any] | None) -> str:
        """The portfolio id of the program a cached run is bound to, for a portfolio lookup.

        A cached run carries BOTH keys and they are not interchangeable: "program" is the
        DISPLAY label (a span caches the program's name, the plain path the operator's free
        text) while "program_id" is the real key portfolio.get_program indexes on. The id is
        derived from the name (learning.program_key slugifies it), so reading "program" here
        hands get_program "Acme Corp" where the store is keyed "acme-corp" and the lookup
        silently misses. Fall back to "program" only for a run cached before program_id
        existed — _cache_bounty_run itself defaults program_id to program, so the fallback
        is the same value on every run this build writes."""
        return str((run or {}).get("program_id") or (run or {}).get("program") or "").strip()

    def _match_structured_scope_id(self, run: dict[str, Any] | None, finding: dict[str, Any],
                                   override: str = "") -> str:
        """Resolve the HackerOne structured_scope_id for a finding's host so a filed report is
        routed to the exact in-scope asset (the H1 form's required Asset field). An explicit
        operator override (asset picker) wins; otherwise match the finding's host against the
        program's imported structured scope (exact host, then registrable-domain/wildcard).
        Returns '' when nothing matches (report files un-routed, as before)."""
        if str(override or "").strip():
            return str(override).strip()
        program_id = self._run_program_id(run)
        if not program_id:
            return ""
        program = bounty_portfolio.get_program(RUNTIME_DIR, program_id)
        if not program:
            return ""
        host = (urlparse(str(finding.get("location") or (run or {}).get("target") or "")).hostname or "").lower()
        if not host:
            return ""
        best = ""
        for entry in program.get("structured_scope") or []:
            sid = str(entry.get("id") or "").strip()
            if not sid or not entry.get("eligible_for_submission", True):
                continue
            ident = str(entry.get("identifier") or "").strip().lower().lstrip("*.")
            if not ident:
                continue
            if ident == host:
                return sid  # exact host match wins outright
            if not best and (host == ident or host.endswith("." + ident)):
                best = sid  # wildcard / parent-domain match, kept only if no exact match appears
        return best

    def _submission_attachment_paths(self, run: dict[str, Any], finding: dict[str, Any]) -> list[str]:
        """Gather the captured evidence files for a finding to upload as report attachments:
        proof screenshots + attack-plan map (they render inline), the plain-text request/
        response + credential + sensitive-data transcripts, and the machine-replayable
        replay.sh / findings.har. Deduped by basename, existing files only, bounded."""
        candidates: list[str] = []
        for key in ("screenshot_path", "attack_map_path"):
            if finding.get(key):
                candidates.append(str(finding[key]))
        for coll in ("screenshots", "source_texts", "credential_artifacts"):
            for entry in (run.get(coll) or {}).values():
                for p in (entry if isinstance(entry, list) else [entry]):
                    if p:
                        candidates.append(str(p))
        art = (run or {}).get("artifacts") or {}
        for p in art.get("sensitive_data_paths") or []:
            candidates.append(str(p))
        out_dir = art.get("output_dir")
        if out_dir:
            for name in ("replay.sh", "findings.har", "INDEX.md"):
                fp = Path(out_dir) / name
                if fp.is_file():
                    candidates.append(str(fp))
        seen: set[str] = set()
        resolved: list[str] = []
        for p in candidates:
            pp = Path(p)
            if pp.name in seen or not pp.is_file():
                continue
            seen.add(pp.name)
            resolved.append(str(pp))
        return resolved[:12]

    def submit_finding(self, request: "SubmitRequest") -> dict[str, Any]:
        """File one CONFIRMED finding to HackerOne via the hard-gated submit. The gate
        lives in submission.submit_to_hackerone and is unbypassable: proof_status is
        recomputed server-side from the cached ctx, so a forged confirm can't push a
        non-confirmed finding. Creds come from the perms-restricted secrets store, never
        the request body. The ONLY path here that touches the network.

        V2: the report is routed (weakness_id from the CWE, structured_scope_id from the
        finding's host) and the captured evidence rides along as attachments — attachment
        upload is best-effort and cannot fail the submit."""
        if bounty_formats.normalize_platform(request.platform) != "hackerone":
            return {"ok": False, "error": "Only the HackerOne API submit is wired. Export the package (Copy report / Download .md) and file it on the other platforms."}
        # Resolve the finding + run BEFORE the network call and hold a LOCAL reference. The 16-entry
        # run cache is drop-oldest, so the network round-trip below can evict this run; recording must
        # NOT depend on it still being cached afterward — a re-resolve that returned None would file
        # the report with no ledger dedup record, and a later cycle would re-file the identical report.
        _, finding, run = self._resolve_run_finding(request.run_id, request.ref)
        pkg_result = self.build_submission_package(SubmissionPackageRequest(run_id=request.run_id, ref=request.ref, platform="hackerone"))
        if not pkg_result.get("ok"):
            return pkg_result
        package = pkg_result["package"]
        handle, username, token = self._hackerone_creds()
        weakness_id = self._hackerone_weakness_id(handle, package.get("cwe"))
        scope_id = self._match_structured_scope_id(run, finding or {}, request.structured_scope_id)
        attachments = (self._submission_attachment_paths(run or {}, finding or {})
                       if request.include_attachments and finding is not None else None)
        try:
            outcome = bounty_submission.submit_to_hackerone(
                package, team_handle=handle, api_username=username, api_token=token, confirm=request.confirm,
                weakness_id=weakness_id, structured_scope_id=scope_id, attachments=attachments,
            )
        except bounty_submission.SubmissionError as exc:
            return {"ok": False, "error": str(exc)}
        # Record the submission to the learning store + ledger from the PRE-resolved finding/run.
        if finding is not None:
            program, target = (run or {}).get("program"), (run or {}).get("target", "")
            dedup_key = bounty_ledger.dedup_key(finding)
            try:
                bounty_learning.record_outcome(
                    RUNTIME_DIR, program=program, target=target,
                    class_id=str(finding.get("class_id") or "other"), title=str(finding.get("title") or ""),
                    status="submitted", severity=str(finding.get("severity") or ""),
                    notes=f"HackerOne report {outcome.get('report_id', '')}",
                    finding_id=f"ledger:{dedup_key}",
                )
            except ValueError:
                pass
            # Track the H1 report id in the ledger too — not just the learning store —
            # so the report-status sync feature has something to poll. upsert_findings
            # lazily creates the ledger record if this finding was never registered there
            # (e.g. a single-hunt or confirm-route finding, which unlike a campaign run
            # never goes through ledger.upsert_findings at discovery time); it's a no-op
            # merge if the record already exists.
            bounty_ledger.upsert_findings(RUNTIME_DIR, program, target, [
                {"finding": finding, "source_url": finding.get("location", ""), "proof_status": "confirmed"}
            ])
            bounty_ledger.record_submission(RUNTIME_DIR, program, target, dedup_key,
                                            str(outcome.get("report_id", "")), str(outcome.get("url", "")))
        return {"ok": True, **outcome}

    def preflight_submission(self, request: "PreflightRequest") -> dict[str, Any]:
        """Per-platform submission readiness — the paste-and-submit gate the cockpit shows
        before a submit. Returns: the required-field checklist for THIS platform, the
        program's in-scope assets (for the picker) + the auto-matched structured_scope_id,
        a probable-duplicate check against the program's disclosed HackerOne reports, and
        how many evidence files would be attached. Read-only — no submit happens here."""
        ctx, finding, run = self._resolve_run_finding(request.run_id, request.ref)
        if ctx is None:
            return {"ok": False, "error": "This run is no longer cached — re-run the hunt to rebuild it."}
        if finding is None:
            return {"ok": False, "error": "Unknown finding for this run."}
        platform = bounty_formats.normalize_platform(request.platform)
        package = bounty_submission.build_submission(ctx, finding, platform)
        if package is None:
            return {"ok": False, "error": "This finding is not reportable (the report rules drop it, e.g. an unconfirmed credential lead)."}
        pf = bounty_submission.preflight(package, platform)

        assets: list[dict[str, str]] = []
        program_id = self._run_program_id(run)
        if program_id:
            program = bounty_portfolio.get_program(RUNTIME_DIR, program_id)
            for entry in (program or {}).get("structured_scope") or []:
                if entry.get("eligible_for_submission", True) and str(entry.get("id") or "").strip():
                    assets.append({"id": str(entry.get("id")), "identifier": str(entry.get("identifier") or ""),
                                   "asset_type": str(entry.get("asset_type") or "")})
        matched_scope_id = self._match_structured_scope_id(run, finding, "")

        duplicates: list[dict[str, Any]] = []
        if request.check_duplicates and platform == "hackerone":
            handle, uname, token = self._hackerone_creds()
            if handle and token:
                try:
                    hz = bounty_h1_activity.fetch_hacktivity(handle, uname, token, limit=50)
                    if hz.get("ok"):
                        duplicates = bounty_h1_activity.find_probable_duplicates(
                            str(finding.get("title") or ""), package.get("cwe", ""), hz.get("items") or [])
                except Exception:  # noqa: BLE001 - duplicate check is advisory; never break preflight
                    duplicates = []
        return {
            "ok": True, "platform": platform, "preflight": pf, "assets": assets,
            "matched_scope_id": matched_scope_id, "duplicates": duplicates,
            "attachment_count": len(self._submission_attachment_paths(run or {}, finding or {})),
        }

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
        cred = (request.api_credential or "").strip()
        if cred:
            # Token-first single paste. Split on the FIRST ":" only — HackerOne's
            # userinfo is identifier:token and a token may itself contain no colon, but
            # partition-on-first is the exact Basic-auth parse either way. A bare value
            # (no colon) is treated as just the token, leaving any stored identifier
            # untouched so a token rotation doesn't wipe a known-good username.
            if ":" in cred:
                username, _, token = cred.partition(":")
                _store_secret("hackerone.api_username", username.strip())
                _store_secret("hackerone.api_token", token.strip())
            else:
                _store_secret("hackerone.api_token", cred)
        else:
            _store_secret("hackerone.api_username", request.api_username.strip())
            if request.api_token:  # never clear the token on an empty submit of the form
                _store_secret("hackerone.api_token", request.api_token.strip())
        return self.hackerone_creds_status()

    def test_hackerone_creds(self) -> dict[str, Any]:
        """Probe the stored HackerOne creds against a real authenticated endpoint so the
        operator gets a server-authoritative yes/no (and, on 401, the reason) instead of
        guessing which username to use. Read-only — never mutates the secrets store."""
        _, username, token = self._hackerone_creds()
        return bounty_h1_import.verify_credentials(username, token)

    def _hackerone_creds(self) -> tuple[str, str, str]:
        stored = _load_secrets()
        return (stored.get("hackerone.team_handle", ""), stored.get("hackerone.api_username", ""), stored.get("hackerone.api_token", ""))

    # ---- YesWeHack --------------------------------------------------------------
    # Same generic secrets store as HackerOne/OOB/the coder providers — no new machinery.
    # Unlike HackerOne, a credential is OPTIONAL here: YesWeHack serves public programs'
    # scope, rules and markers anonymously, so an operator can import without signing in.

    def yeswehack_creds_status(self) -> dict[str, Any]:
        """Creds presence for the UI — NEVER returns the token."""
        stored = _load_secrets()
        return {
            "ok": True,
            "email": stored.get("yeswehack.email", ""),
            "token_kind": stored.get("yeswehack.token_kind", "") or "jwt",
            "has_token": bool(stored.get("yeswehack.api_token")),
        }

    def save_yeswehack_creds(self, request: "YesWeHackCredsRequest") -> dict[str, Any]:
        # Only write a field the caller actually SENT. _store_secret treats "" as a delete,
        # so writing every field unconditionally would make a partial save (the PAT box, or
        # sign-out, which posts only clear_token) silently wipe the other stored values.
        # Same exclude_unset reasoning as upsert_program.
        if "email" in request.model_fields_set:
            _store_secret("yeswehack.email", request.email.strip())
        if request.clear_token:
            # Explicit sign-out. Kept separate from "empty field" so saving the slug
            # alone can't silently drop a working session token.
            _store_secret("yeswehack.api_token", "")
            _store_secret("yeswehack.token_kind", "")
        elif request.api_token.strip():
            kind = "pat" if request.token_kind.strip().lower() == "pat" else "jwt"
            _store_secret("yeswehack.api_token", request.api_token.strip())
            _store_secret("yeswehack.token_kind", kind)
        return self.yeswehack_creds_status()

    def yeswehack_login(self, request: "YesWeHackLoginRequest") -> dict[str, Any]:
        """Exchange a YesWeHack email+password (+TOTP) for a JWT and store only the JWT.

        The password reaches this process for exactly one POST to api.yeswehack.com and is
        never written to the secrets file, the logs, or the response."""
        result = bounty_ywh_import.login(request.email, request.password, totp_code=request.totp_code)
        if not result.get("ok"):
            # totp_required is carried through so the UI can ask for the 6-digit code.
            return {"ok": False, "error": result.get("error", "Sign-in failed."),
                    "totp_required": bool(result.get("totp_required"))}
        _store_secret("yeswehack.api_token", str(result.get("token") or ""))
        _store_secret("yeswehack.token_kind", "jwt")
        _store_secret("yeswehack.email", request.email.strip())
        status = self.yeswehack_creds_status()
        status["message"] = result.get("message", "Signed in to YesWeHack.")
        return status

    def test_yeswehack_creds(self) -> dict[str, Any]:
        """Probe the stored credential (or the anonymous path, when none is stored)
        against a real endpoint. Read-only — never mutates the secrets store."""
        token, kind = self._yeswehack_creds()
        return bounty_ywh_import.verify_credentials(token, kind)

    def yeswehack_programs(self, request: "YesWeHackProgramsRequest") -> dict[str, Any]:
        """Search the programs this credential can see (anonymous = the public catalogue),
        so the operator can find a program without already knowing its slug."""
        token, kind = self._yeswehack_creds()
        return bounty_ywh_import.list_programs(token=token, token_kind=kind, query=request.query)

    def import_yeswehack_scope(self, request: "YesWeHackImportRequest") -> dict[str, Any]:
        """Preview a YesWeHack program's scope, rules of engagement and required
        user-agent marker — a documented read to a fixed non-target host, only on this
        explicit, operator-clicked call (never automatic/background). Returns a PREVIEW;
        nothing is saved until the operator submits the Program form."""
        token, kind = self._yeswehack_creds()
        return bounty_ywh_import.fetch_program_scope(request.slug, token=token, token_kind=kind)

    def _yeswehack_creds(self) -> tuple[str, str]:
        """(token, token_kind). An empty token is the supported anonymous mode."""
        stored = _load_secrets()
        return (stored.get("yeswehack.api_token", ""),
                stored.get("yeswehack.token_kind", "") or "jwt")

    # ---- Read-only platform program intake --------------------------------------

    def platform_credentials_status(self) -> dict[str, Any]:
        """Only credential presence is returned; API secrets stay in the owner-only store."""
        stored = _load_secrets()
        return {"ok": True, "platforms": {
            "hackerone": self.hackerone_creds_status(),
            "yeswehack": self.yeswehack_creds_status(),
            "intigriti": {"has_token": bool(stored.get("platform.intigriti.credential"))},
        }}

    def save_platform_credential(self, request: "PlatformCredentialRequest") -> dict[str, Any]:
        platform = request.platform.strip().lower()
        if platform == "bugcrowd":
            # Older builds stored Bugcrowd platform tokens. Permit explicit removal,
            # but do not offer the customer API as researcher program discovery.
            if request.clear_token:
                _store_secret("platform.bugcrowd.credential", "")
                return {"ok": True, "platform": platform, "has_token": False}
            return {"ok": False, "error": "Bugcrowd researcher API discovery is unavailable; use manual or CSV intake."}
        if platform != "intigriti":
            return {"ok": False, "error": "This credential form supports Intigriti only."}
        if request.clear_token:
            _store_secret(f"platform.{platform}.credential", "")
        elif request.credential:
            if not bounty_platform_programs._valid_credential(platform, request.credential):
                return {"ok": False, "error": "Enter a valid API credential without whitespace or control characters."}
            _store_secret(f"platform.{platform}.credential", request.credential)
        else:
            return {"ok": False, "error": "Paste an API credential or choose Clear saved credential."}
        return {"ok": True, "platform": platform,
                "has_token": bool(_load_secrets().get(f"platform.{platform}.credential"))}

    def discover_platform_programs(self, request: "PlatformProgramsRequest") -> dict[str, Any]:
        """Explicit, bounded GET of programs visible to an API identity; no persistence."""
        platform = request.platform.strip().lower()
        stored = _load_secrets()
        if platform == "hackerone":
            _, username, token = self._hackerone_creds()
            result = bounty_h1_import.list_programs(username, token, max_entries=request.limit)
            rows = [{"id": p["handle"], "handle": p["handle"], "name": p["name"],
                     "status": p.get("submission_state") or p.get("state") or "unknown",
                     "source_url": p.get("source_url", "")} for p in result.get("programs", [])]
        elif platform == "yeswehack":
            token, kind = self._yeswehack_creds()
            result = bounty_ywh_import.list_programs(token=token, token_kind=kind,
                                                      query=request.query, max_entries=request.limit)
            rows = [{"id": p["slug"], "handle": p["slug"], "name": p["title"],
                     "status": "disabled" if p.get("disabled") else "visible",
                     "source_url": f"https://api.yeswehack.com/programs/{p['slug']}"}
                    for p in result.get("programs", [])]
        elif platform == "intigriti":
            credential = stored.get(f"platform.{platform}.credential", "")
            result = bounty_platform_programs.list_programs(platform, credential, limit=request.limit)
            rows = list(result.get("programs", []))
        elif platform == "bugcrowd":
            return {"ok": False, "platform": platform, "programs": [],
                    "error": "Bugcrowd researcher API discovery is unavailable; use manual or CSV intake."}
        else:
            return {"ok": False, "programs": [], "error": "Unsupported platform."}
        if not result.get("ok"):
            return {"ok": False, "platform": platform, "programs": [],
                    "error": result.get("error", "Program discovery failed."),
                    "warnings": result.get("warnings", [])}
        query = request.query.strip().lower()
        if query and platform != "yeswehack":
            rows = [p for p in rows if query in p.get("name", "").lower()
                    or query in p.get("handle", "").lower()]
        return {"ok": True, "platform": platform, "programs": rows, "count": len(rows),
                "warnings": result.get("warnings", [])}

    def preview_platform_program(self, request: "PlatformPreviewRequest") -> dict[str, Any]:
        """Read one current API record for review. A preview never authorizes a hunt."""
        platform = request.platform.strip().lower()
        identifier = request.program_id.strip()
        if platform == "hackerone":
            result = self.import_hackerone_scope(HackerOneImportRequest(handle=identifier))
        elif platform == "yeswehack":
            result = self.import_yeswehack_scope(YesWeHackImportRequest(slug=identifier))
        elif platform == "intigriti":
            credential = _load_secrets().get(f"platform.{platform}.credential", "")
            result = bounty_platform_programs.preview_program(platform, identifier, credential)
        elif platform == "bugcrowd":
            return {"ok": False, "error": "Bugcrowd researcher API preview is unavailable; review the current program brief and use manual or CSV intake."}
        else:
            return {"ok": False, "error": "Unsupported platform."}
        if not result.get("ok"):
            return result
        # Explicit response contract: provider data can never carry an `authorized`,
        # `enabled`, or other execution flag into the Program form.
        allowed = ("program_name", "structured_scope", "policy_excerpt", "offers_bounty",
                   "program_stats", "notes_digest", "user_agent_suffix", "warnings",
                   "status", "source_url", "out_of_scope", "fetched_at")
        preview = {key: result[key] for key in allowed if key in result}
        preview["ok"] = True
        preview["platform"] = platform
        preview["program_id"] = identifier
        preview["handle"] = result.get("handle") or result.get("slug") or identifier
        preview["fetched_at"] = result.get("fetched_at") or datetime.now(UTC).isoformat()
        if not preview.get("source_url") and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", str(preview["handle"])):
            if platform == "hackerone":
                preview["source_url"] = f"https://api.hackerone.com/v1/hackers/programs/{preview['handle']}"
            elif platform == "yeswehack":
                preview["source_url"] = f"https://api.yeswehack.com/programs/{preview['handle']}"
        # An API response alone cannot prove the program's full exclusions and current
        # testing terms. Even a structurally complete row set remains review-only.
        preview["scope_complete"] = False
        preview["warnings"] = list(result.get("warnings") or []) + [
            "Review the current program policy, exclusions, and your authorization before enabling tests."]
        return preview

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

    @_confirm_route
    def check_stored_xss_beacon(self, request: "StoredXssBeaconRequest") -> dict[str, Any]:
        """Confirm stored XSS via an OOB collaborator beacon rendered in a browser — proves the injected
        markup EXECUTES on render (catches DOM/JS-rendered stored XSS a source fetch misses). Assisted by
        default (mint a token + beacon payloads, hand back to submit, then re-render/poll); ``send=True``
        opts in to GreyIQ POSTing the beacon, rendering the view headlessly, and polling the collaborator.

        The collaborator base + secret come from the SAVED OOB config, never from the request — the
        secret is write-only (oob_config_status reports only its presence), so a client could not
        supply it even if asked."""
        base, secret = self._oob_config()
        res = bounty_stored_xss.confirm_stored_xss_beacon(
            view_url=request.view_url, inject_url=request.inject_url, field=request.field,
            base=base, secret=secret, scope=request.scope, send=bool(request.send),
            token=(request.token or None), cookie=request.cookie, headers=request.headers)
        if not res.get("ok"):
            return res
        if res.get("status") != "confirmed":
            return {"ok": True, "status": res.get("status"), "token": res.get("token"),
                    "payloads": res.get("payloads"), "callback_url": res.get("callback_url", ""),
                    "reason": res.get("reason", ""), "error": res.get("error", "")}
        finding = dict(res["finding"]); finding["ref"] = "F1"
        plan = res["attack_plan"]
        host = urlparse(request.view_url).hostname or "target"
        persisted = self._persist_finding_run(
            findings=[finding], plans={"F1": plan}, target=request.view_url, scope=request.scope,
            platform=request.platform, slug="stored-xss-beacon", host=host, json_extra={"detail": res.get("detail")})
        return {"ok": True, "status": "confirmed", "run_id": persisted["run_id"], "ref": "F1",
                "platform": persisted["platform"], "report": persisted["report"], "token": res.get("token"),
                "title": finding["title"], "severity": finding["severity"]}

    # ---- Autonomous operator ------------------------------------------------------
    def _operator_run_campaign(self, target: str, *, scope: str, program: str, active: bool, live: bool,
                               deep: bool = False, max_pages: int = 12,
                               run_id: str = "") -> dict[str, Any]:
        """The operator's run_campaign_fn — goes through runtime.run_campaign so the
        run is cached (run_id) and the submit path can resolve it. authorized=True
        because the operator only runs after the user explicitly armed it (the start
        endpoint requires authorized); scope stays the fail-closed gate. ``deep`` carries
        the program's deep-mode flag (time-based SQLi + screenshot/research per confirmed
        lead) through unchanged."""
        return self.run_campaign(CampaignRequest(
            target=target, scope=scope, authorized=True, program=program,
            active=active, live=live, deep=deep, max_pages=max_pages, run_id=run_id,
        ))

    def _get_operator(self) -> "OperatorLoop":
        with self.lock:
            if self._operator is None:
                self._operator = OperatorLoop(
                    str(RUNTIME_DIR),
                    run_campaign_fn=self._operator_run_campaign,
                )
            return self._operator

    def list_programs(self) -> dict[str, Any]:
        return {"ok": True, "programs": [_program_for_read(p) for p in bounty_portfolio.list_programs(RUNTIME_DIR)]}

    def upsert_program(self, request: "ProgramUpsertRequest") -> dict[str, Any]:
        # exclude_unset: a caller that doesn't know about a field (e.g. the Operator tab's
        # compact edit form predates structured_scope/oob_allowed/disclose_automation/
        # h1_program_stats/notes) must never reset
        # it to that field's bare default just by omitting it from the request body -- the
        # existing stored value is preserved instead. A caller that DOES send a field
        # (even a falsy one, like active=false) still gets it applied, since Pydantic marks
        # any key present in the request JSON as "set" regardless of its value.
        record = request.model_dump(exclude_unset=True, exclude_none=True)
        # Merge-preserve the research-account secrets: the UI reads them REDACTED (password_set/
        # cookie_set markers, no plaintext), so a normal edit round-trip carries no password/cookie —
        # keep the stored ones rather than wiping them. A caller that DOES send a new secret overwrites.
        # Identical treatment for the low-priv `account_access` and the high-priv `admin_account_access`.
        existing = None
        for field in ("account_access", "admin_account_access"):
            if field not in record:
                continue
            acc = {k: v for k, v in dict(record.get(field) or {}).items()
                   if k not in ("password_set", "cookie_set")}  # drop the read-only markers
            if existing is None:
                existing = bounty_portfolio.get_program(RUNTIME_DIR, str(record.get("id") or "")) or {}
            ex_acc = existing.get(field) if isinstance(existing.get(field), dict) else {}
            for secret in ("password", "cookie"):
                if not str(acc.get(secret) or "").strip() and ex_acc.get(secret):
                    acc[secret] = ex_acc[secret]  # preserve the saved secret the redacted edit didn't resend
            record[field] = acc
        return {"ok": True, "program": _program_for_read(bounty_portfolio.upsert_program(RUNTIME_DIR, record))}

    def list_vdp_profiles(self) -> dict[str, Any]:
        """The built-in VDP policy profiles offered as one-click program presets (id, name, scope, channel)."""
        from bughunter import vdp_policy
        return {"ok": True, "profiles": [
            {"id": p["id"], "name": p["name"], "scope_hosts": list(p.get("scope_hosts") or ()),
             "report_channel": p.get("report_channel", ""), "notes": p.get("notes", "")}
            for p in vdp_policy.PROFILES.values()
        ]}

    def create_program_from_preset(self, request: "VdpPresetRequest") -> dict[str, Any]:
        """Create-or-update a saved program from a built-in VDP policy preset (e.g. "nasa") in one click.
        The preset carries the program's in-scope hosts + policy binding (scope narrowing + excluded
        endpoints/classes + confirmed-only + no-DoS). It AUTHORIZES nothing the engine's own scope/SSRF
        gates don't already — it only constrains the hunt to that program's published rules of engagement.

        IDEMPOTENT + NON-DESTRUCTIVE: if a program is already bound to this VDP profile, re-running the
        preset must NEVER widen a scope the operator narrowed (e.g. down to a NASA test host per NASA's
        own "prefer a test environment" guidance). We reuse that program's id and PRESERVE its existing
        scope/targets/creds; only the policy binding, disclosure flag, and notes are (re)asserted. A
        profile can only ever narrow — never widen scope."""
        from bughunter import vdp_policy
        preset = vdp_policy.program_preset(request.profile)
        if not preset:
            return {"ok": False, "error": f"unknown VDP profile: {request.profile!r}"}
        existing = None
        for prog in bounty_portfolio.list_programs(RUNTIME_DIR):
            if str(prog.get("policy_profile") or "").strip().lower() == preset["policy_profile"]:
                existing = prog
                break
        created = existing is None
        if existing:
            preset["id"] = existing.get("id")
            # For an EXISTING program the preset must not touch scope/targets AT ALL — re-clicking it
            # can't restore hosts the operator removed. upsert merges {**existing, **record}, so dropping
            # these keys from the record preserves exactly what the operator saved (narrowed scope, even
            # an emptied span list). Creds live only in `existing` and are preserved by the merge too.
            # The preset then only (re)asserts the policy binding + disclosure flag + notes.
            for scope_key in ("scope_text", "in_scope_hosts", "out_of_scope_hosts", "structured_scope", "seed_targets"):
                preset.pop(scope_key, None)
        saved = bounty_portfolio.upsert_program(RUNTIME_DIR, preset)
        return {"ok": True, "created": created, "program": _program_for_read(saved)}

    def program_from_repo(self, request: "ProgramFromRepoRequest") -> dict[str, Any]:
        """Create a passive review draft from public forge repository roots.

        Tier 1 is entirely local. Tier 2 runs only for ``enrich=True`` and delegates
        to the fixed-host, one-GET-per-repository forge metadata reader. Metadata may
        add bounded description text to notes, but candidate web hosts are returned
        separately and never written into any scope field.

        Repeating the action is idempotent and non-destructive: repository roots are
        unioned into the same owner-derived program, while established scope, runtime
        flags, credentials, and operator choices remain untouched.
        """
        repository_urls = bounty_portfolio._clean_repository_urls(request.repository_urls)
        if not repository_urls:
            return {
                "ok": False,
                "error": (
                    "Add at least one public HTTPS repository-root URL from a supported forge "
                    "(GitHub, GitLab, Bitbucket, Codeberg, or SourceHut). Forge pages such as "
                    "issues, blobs, trees, and pull requests, non-allowlisted hosts, and "
                    "credential-bearing URLs are not accepted."
                ),
            }

        name = _program_name_from_repositories(repository_urls)
        # Idempotency key: a repeat click for the same owner resolves to the same program id
        # (bounty_learning.program_key(name, "") matches how upsert_program derives the id for
        # this empty-scope/empty-seed record). In the rare case a differently-created program
        # already occupies that id (same owner-derived name, id also seeded from name alone),
        # the merge branch below only ADDS validated repositories, sets clone_repositories, and
        # appends provenance notes — it never rewrites that program's scope, flags, or secrets,
        # so the collision stays non-destructive.
        expected_id = bounty_learning.program_key(name, "")
        existing = next(
            (program for program in bounty_portfolio.list_programs(RUNTIME_DIR)
             if str(program.get("id") or "") == expected_id),
            None,
        )

        enrichment: dict[str, Any] = {"descriptions": [], "candidate_hosts": []}
        if request.enrich:
            # No background path calls this method; this branch is reached only from
            # the explicit opt-in payload sent by the repo onboarding button.
            try:
                fetched_enrichment = bounty_forge_metadata.enrich_repositories(repository_urls, timeout=10.0)
                if isinstance(fetched_enrichment, dict):
                    enrichment = fetched_enrichment
            except Exception:  # noqa: BLE001 - optional enrichment must never block the local draft
                pass
        description_notes = [
            _repo_description_note(item.get("repository_url", ""), item.get("description", ""))
            for item in (enrichment.get("descriptions") or [])
            if isinstance(item, dict) and item.get("repository_url") and item.get("description")
        ]

        if existing:
            # Omit every unrelated field so portfolio.upsert_program's merge preserves
            # the operator's established settings and secrets. The explicit repo-link
            # action only adds validated repositories, enables their clone selection,
            # and appends provenance/description notes once.
            record: dict[str, Any] = {
                "id": existing["id"],
                "name": existing.get("name") or name,
                "repository_urls": bounty_portfolio._clean_repository_urls(
                    list(existing.get("repository_urls") or []) + repository_urls
                ),
                "clone_repositories": True,
                "notes": _merge_note_lines(
                    str(existing.get("notes") or ""),
                    [_REPO_DRAFT_PROVENANCE, *description_notes],
                ),
            }
        else:
            record = {
                "name": name,
                "platform": "manual",
                "platform_handle": "",
                "repository_urls": repository_urls,
                "clone_repositories": True,
                # Persisted internal marker: prevents the normal repository-only scope
                # derivation until the operator reviews and Saves the existing form.
                "repo_draft_pending": True,
                "active": False,
                "live": False,
                "deep": False,
                "auto_submit": False,
                "enabled": False,
                "structured_scope": [],
                "in_scope_hosts": [],
                "out_of_scope_hosts": [],
                "seed_targets": [],
                "notes": _merge_note_lines("", [_REPO_DRAFT_PROVENANCE, *description_notes]),
            }
        saved = bounty_portfolio.upsert_program(RUNTIME_DIR, record)
        return {
            "ok": True,
            "program": _program_for_read(saved),
            "candidate_hosts": list(enrichment.get("candidate_hosts") or []),
        }

    def preflight_repository(self, request: "RepoPreflightRequest") -> dict[str, Any]:
        """Check a repository root is reachable + cloneable BEFORE a hunt commits to it.

        Delegates to git_remote.preflight (a single `git ls-remote` against the already
        forge-allowlisted host — the same transport a clone uses, but without downloading a
        tree). This is the read that catches a typo'd/private/non-existent repo up front with
        an actionable message, instead of letting the clone fail deep in the scan with raw git
        plumbing. Read-only, on this explicit operator call — never background."""
        return bounty_git_remote.preflight(str(request.url or "").strip())

    def import_hackerone_scope(self, request: "HackerOneImportRequest") -> dict[str, Any]:
        """Preview a program's scope pulled from the HackerOne API — a documented read
        to a fixed non-target host, only on this explicit, operator-clicked call
        (never automatic/background). Returns a PREVIEW; nothing is saved until the
        operator submits the Program form. Reuses the same creds already stored for
        submission — no new secret."""
        _, username, token = self._hackerone_creds()
        return bounty_h1_import.fetch_structured_scope(request.handle, username, token)

    def hackerone_hacktivity(self, request: "HackerOneHacktivityRequest") -> dict[str, Any]:
        """Recent disclosed reports for one program — reconnaissance only (what's
        actually getting paid there), never fed into ranking automatically."""
        _, username, token = self._hackerone_creds()
        return bounty_h1_activity.fetch_hacktivity(request.team_handle, username, token)

    def hackerone_my_reports(self, request: "HackerOnePageRequest") -> dict[str, Any]:
        """The operator's own submitted HackerOne reports, across every program."""
        _, username, token = self._hackerone_creds()
        return bounty_h1_activity.fetch_my_reports(username, token, page=request.page)

    def hackerone_report_status(self, request: "HackerOneReportStatusRequest") -> dict[str, Any]:
        """Live status of one HackerOne report — usable standalone (paste any report id)
        or right after a submit (the report id is already in hand)."""
        _, username, token = self._hackerone_creds()
        return bounty_h1_activity.fetch_report_status(request.report_id, username, token)

    def hackerone_earnings(self, request: "HackerOnePageRequest") -> dict[str, Any]:
        """The operator's own bounty/reward history + current balance, one round trip."""
        _, username, token = self._hackerone_creds()
        earnings = bounty_h1_activity.fetch_earnings(username, token, page=request.page)
        if not earnings.get("ok"):
            return earnings
        balance = bounty_h1_activity.fetch_balance(username, token)
        earnings["balance"] = balance.get("balance") if balance.get("ok") else None
        return earnings

    def sync_hackerone_reports(self, request: "HackerOneSyncRequest") -> dict[str, Any]:
        """Poll HackerOne for the current status of every locally-'submitted' finding
        (bounded, never automatic) and reflect real outcomes back onto the ledger + the
        learning store, closing the loop that today requires manually running `gn learn`.
        A bare state change (e.g. new -> triaged) only updates the ledger's h1_state; a
        transition to a REWARDED terminal state also flips the ledger stage to 'paid'; any
        terminal state (rewarded or not) is also recorded once to the learning store so
        future EV ranking uses the real HackerOne outcome instead of the placeholder
        'submitted' status recorded at submit time."""
        _, username, token = self._hackerone_creds()
        if not (username and token):
            return {"ok": False, "error": "Save your HackerOne API username + token in the Submissions tab first."}
        records = bounty_ledger.submitted_records(RUNTIME_DIR, limit=request.limit)
        checked, updated, errors = 0, 0, []
        for rec in records:
            checked += 1
            status = bounty_h1_activity.fetch_report_status(rec.get("h1_report_id", ""), username, token)
            if not status.get("ok"):
                errors.append(f"#{rec.get('h1_report_id')}: {status.get('error', 'unknown error')}")
                continue
            state = str(status.get("state") or "")
            resolved_with_reward = bool(status.get("bounty_awarded_at") or status.get("swag_awarded_at"))
            # A reward can appear on the live report before (or without) a state change —
            # e.g. still 'triaged' but bounty_awarded_at just got set — so skip only when
            # NEITHER signal moved. submitted_records() only ever returns stage=='submitted'
            # records (never already 'paid'), so resolved_with_reward alone is always new
            # information worth recording here, regardless of the state comparison.
            if state == str(rec.get("h1_state") or "") and not resolved_with_reward:
                continue  # nothing new to reflect since the last sync
            try:
                reward_amount = float(status.get("total_awarded_amount") or 0.0)
            except (TypeError, ValueError):
                reward_amount = 0.0
            bounty_ledger.record_h1_sync(RUNTIME_DIR, rec["pid"], rec["key"], state=state,
                                         resolved_with_reward=resolved_with_reward, bounty=reward_amount)
            updated += 1
            learning_status = _H1_STATE_TO_LEARNING_OUTCOME.get(state)
            # HackerOne may award a bounty while the report is still triaged. The ledger
            # then advances to paid and leaves submitted_records(), so there will be no
            # later sync opportunity to teach the learning store about that real award.
            # "accepted" records the reward without claiming the report was resolved.
            if learning_status is None and resolved_with_reward:
                learning_status = "accepted"
            if learning_status:
                try:
                    # rec["program"] is the ledger's already-slugified pid; passing it as
                    # `program=` is safe — learning.program_key() treats a non-empty
                    # `program` as authoritative and slugifies it again, which is a no-op
                    # on an already-slug string, so this resolves to the SAME learning
                    # bucket the ledger used, regardless of `target`.
                    bounty_learning.record_outcome(
                        RUNTIME_DIR, program=rec.get("program"), target=rec.get("source_url", ""),
                        class_id=str(rec.get("class_id") or "other"), title=str(rec.get("title") or ""),
                        status=learning_status, severity=str(rec.get("severity") or ""),
                        # The freshly-fetched amount (rec['bounty'] is the pre-sync copy, still 0.0).
                        bounty=reward_amount if resolved_with_reward else 0.0,
                        notes=f"HackerOne report {rec.get('h1_report_id')} synced to '{state}'",
                        finding_id=f"ledger:{rec['key']}",
                    )
                except ValueError:
                    pass
        return {"ok": True, "checked": checked, "updated": updated, "errors": errors}

    def remove_program(self, program_id: str) -> dict[str, Any]:
        """Delete a program AND cascade to its findings: the program is removed from the
        portfolio, and its ledger findings are deleted — HIGH/CRITICAL findings are archived
        into the 'history subcategory' (kept, read-only) while the rest are purged. Returns the
        cascade counts so the UI can confirm what was kept vs removed."""
        # Capture the program's scope-domain bucket keys BEFORE deleting it: a cockpit/ad-hoc run
        # with program=None keyed its findings by the target's registrable domain, not the program
        # id, so the cascade must sweep those too or HIGH/CRITICAL findings orphan (and keep being
        # counted for a program that no longer exists).
        domain_aliases: list[str] = []
        try:
            prog = bounty_portfolio.get_program(RUNTIME_DIR, program_id) or {}
            for host in list(prog.get("in_scope_hosts") or []) + list(prog.get("seed_targets") or []):
                dom = bounty_ledger.program_key(None, str(host or "").strip())
                if dom:
                    domain_aliases.append(dom)
        except Exception:  # noqa: BLE001 - best-effort alias gathering; the pid bucket is swept regardless
            pass
        removed = bounty_portfolio.remove_program(RUNTIME_DIR, program_id)
        cascade = {"archived": 0, "purged": 0}
        try:
            cascade = bounty_ledger.archive_and_purge_program(RUNTIME_DIR, program_id, also_bucket_ids=domain_aliases)
        except Exception:  # noqa: BLE001 - a portfolio delete must still succeed if the ledger read hiccups
            pass
        return {"ok": bool(removed), "archived": cascade.get("archived", 0), "purged": cascade.get("purged", 0)}

    def operator_start(self, request: "OperatorStartRequest") -> dict[str, Any]:
        if not request.authorized:
            return {"ok": False, "error": "Confirm you are authorized to run the portfolio's programs (set authorized)."}
        if request.allow_submit:
            return {"ok": False, "started": False, "allow_submit": False,
                    "error": "Automatic submission is disabled. Review findings and submit manually."}
        try:
            started = self._get_operator().start(grants=request.grants)
        except (ValueError, OSError) as exc:
            return {"ok": False, "started": False, "allow_submit": False, "error": str(exc)}
        return {"ok": True, "started": started, "allow_submit": False,
                "note": "Review-only — findings are hunted and queued; nothing is auto-filed."}

    def operator_stop(self) -> dict[str, Any]:
        if self._operator is not None:
            self._operator.stop()
        return {"ok": True}

    def operator_events(self, after: int = 0) -> dict[str, Any]:
        if self._operator is None:
            return {"ok": True, "running": False, "events": [], "count": 0}
        return {"ok": True, **self._operator.event_tail(after=after)}

    def operator_pipeline(self) -> dict[str, Any]:
        operator_status = self._operator.event_tail(after=0) if self._operator else {}
        return {
            "ok": True,
            "funnel": bounty_ledger.funnel(RUNTIME_DIR),
            "programs": bounty_portfolio.list_programs(RUNTIME_DIR),
            "learning": bounty_learning.program_summary(RUNTIME_DIR),
            "running": bool(self._operator and self._operator.running),
            "grants": operator_status.get("grants", []),
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
                finding_id=request.finding_id,
            )
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "program": bounty_learning.program_key(request.program, request.target), "stats": prog}

    def bounty_stats(self, program: str | None, target: str) -> dict[str, Any]:
        return {
            "ok": True,
            "summary": bounty_learning.program_summary(RUNTIME_DIR, program, target or ""),
            "intelligence": bounty_learning.program_intelligence(RUNTIME_DIR, program, target or ""),
            # The pipeline funnel (discovered -> confirmed -> reported -> submitted ->
            # paid) is already computed for the Operator tab (operator_pipeline above) --
            # surface it here too so the Learn tab (literally "what the engine has
            # learned") can show where findings are actually getting stuck, not just the
            # flat submitted/rewarded/$ aggregate.
            "funnel": bounty_ledger.funnel(RUNTIME_DIR, program, target or ""),
        }

    def export_ledger_csv(self, program: str | None, target: str) -> dict[str, Any]:
        """Flatten the persistent finding ledger (one program, or the whole
        portfolio) into a CSV for spreadsheet tracking / income reporting. Pure
        reshaping of already-computed data — read-only, no network."""
        import csv
        import io

        rows = bounty_ledger.to_csv_rows(RUNTIME_DIR, program, target or "")
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(bounty_ledger.CSV_COLUMNS))
        writer.writeheader()
        writer.writerows(rows)
        return {"ok": True, "csv": buf.getvalue(), "row_count": len(rows)}

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
        # Chat needs a free-form reasoning provider. The deterministic providers are valid
        # Workbench engines, but ``generate`` intentionally rejects them; treating them as a
        # chat brain would turn every ordinary message into an error instead of allowing the
        # offline domain/TinyGPT fallbacks below to answer it.
        if not coder.reasoning_brain_enabled(raw):
            return None
        cfg = coder.coder_config(raw)
        messages = self._build_coder_messages(request, int(cfg.get("history_turns") or 12))
        student = ""
        try:
            # TinyGPT speaks first. The stronger brain sees this only as an
            # untrusted draft to critique, never as authoritative code.
            student = coding_learning_bridge.student_draft(self.get_engine(), request.message)
        except Exception as exc:  # noqa: BLE001 - teacher remains usable without TinyGPT
            self.log(f"TinyGPT coding dialogue unavailable: {exc}")
        # The coding brain runs with a coding-focused system prompt; bot persona,
        # style, and stored preferences are layered on top.
        cfg = dict(cfg)
        cfg["system_prompt"] = self._coder_system_prompt(request, cfg)
        # The bundled expert cards also inform a configured reasoning brain. Keep
        # operator-editable runtime overrides out of this higher-priority prompt;
        # the excerpts are short, source-labelled reference data, never proof or
        # permission to act on a target.
        try:
            knowledge_context = solin_domain.build_reasoning_context(
                request.message, solin_domain.load_pack(SEED_DIR, None)
            )
        except Exception:  # noqa: BLE001 - retrieval must never break configured chat
            knowledge_context = ""
        if knowledge_context:
            cfg["system_prompt"] += "\n\n" + knowledge_context
        bridge_block = coding_learning_bridge.teacher_prompt_block(student)
        if bridge_block:
            cfg["system_prompt"] += "\n\n" + bridge_block
        # Chat is interactive: responsiveness matters as much as depth, so it gets its own reasoning
        # profile instead of inheriting whatever the deepest brain needed. Only fills values the
        # operator left at the shipped defaults — an explicit setting still wins.
        brain_profiles.apply(cfg, "chat")
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
        lesson = coding_learning_bridge.record_teacher_exchange(
            RUNTIME_DIR,
            prompt=request.message,
            student=student,
            teacher=str(result.get("text") or ""),
            model_version=f"{result['provider']}:{result['model']}",
        )
        return {
            "request_id": uuid4().hex,
            "message": friendly_branding(result["text"]),
            "used_fallback": False,
            "captured_for_training": False,
            "brain_dialogue": {
                "tinygpt_draft_used": bool(student),
                "knowledge_context_used": bool(knowledge_context),
                "lesson_status": lesson.get("outcome"),
                "verification_reason": lesson.get("verification_reason"),
            },
            "model_name": f"{result['provider']}:{result['model']}",
            "device": "remote" if result["provider"] == "anthropic" else "local-model",
            "citations": [],
            "ai_core": self.store.load(),
        }

    def _start_active_chat_scan(self, target: str, scope_host: str) -> dict[str, Any]:
        """Start one bounded active verification without holding the chat HTTP reply open."""
        with self.lock:
            if self._active_chat_running_id:
                return {"ok": False, "error": "An active chat assessment is already running. Wait for its result before starting another."}
            run_id = "active-" + uuid4().hex
            self._active_chat_runs[run_id] = {"status": "running", "message": "Active assessment is running."}
            while len(self._active_chat_runs) > 8:
                self._active_chat_runs.popitem(last=False)
            self._active_chat_running_id = run_id
            worker = threading.Thread(
                target=self._run_active_chat_scan,
                args=(run_id, target, scope_host),
                name="greyiq-active-chat",
                daemon=True,
            )
            try:
                worker.start()
            except RuntimeError:
                self._active_chat_runs.pop(run_id, None)
                self._active_chat_running_id = ""
                return {"ok": False, "error": "Could not start the active assessment worker."}
        return {
            "ok": True, "run_id": run_id, "status": "running",
            "message": (
                f"Active assessment started for {scope_host}. I will use up to 16 bounded "
                "GET/HEAD/OPTIONS requests and report observed results with controls. "
                "Keep this chat open to see the result."
            ),
        }

    def _run_active_chat_scan(self, run_id: str, target: str, scope_host: str) -> None:
        """One-host active proof pass; only a short, redacted summary reaches chat."""
        status = "error"
        message = "Active assessment failed before producing a result."
        try:
            results, meta = bounty_active_verify.verify_active(
                target, [], scope=scope_host, settings=_bounty_get_settings(),
                requests_budget=16, time_based=False, scope_host=scope_host,
            )
            if not meta.get("in_scope") or meta.get("skipped_reason"):
                reason = redact_text(str(meta.get("skipped_reason") or "Target was outside the permitted scope."))[0]
                message = f"Active assessment stopped before proof: {reason[:400]}"
            else:
                compact = [self._compact_active(item) for item in results]
                confirmed = sum(item.get("status") == "confirmed" for item in compact)
                candidate = len(compact) - confirmed
                used = max(0, min(16, int(meta.get("requests_used") or 0)))
                lines = [
                    f"Active assessment of {scope_host}: {used}/16 requests used; "
                    f"{confirmed} confirmed, {candidate} candidate findings."
                ]
                if meta.get("halt_reason"):
                    lines.append(str(meta["halt_reason"])[:200])
                elif meta.get("rate_limited"):
                    lines.append("The request budget or host rate limit ended this pass early.")
                for item in compact[:5]:
                    title = redact_text(str(item.get("title") or "Finding"))[0][:150]
                    severity = str(item.get("severity") or "info").lower()
                    if severity not in {"critical", "high", "medium", "low", "info"}:
                        severity = "info"
                    state = "confirmed" if item.get("status") == "confirmed" else "candidate"
                    lines.append(f"- {title} [{severity}; {state}]")
                    for label, key in (("Observed", "observed"), ("Control", "control"), ("Limit", "limitations")):
                        value = redact_text(str(item.get(key) or ""))[0].replace("\r", " ").replace("\n", " ").strip()
                        if value:
                            lines.append(f"  {label}: {value[:240]}")
                if len(compact) > 5:
                    lines.append(f"{len(compact) - 5} additional findings omitted from this chat summary.")
                lines.append("This bounded sample does not prove the host is free of other vulnerabilities.")
                status = "done"
                message = "\n".join(lines)[:3500]
        except Exception as exc:  # noqa: BLE001 - background worker must release the single-flight gate
            self.log(f"Active chat assessment failed ({exc.__class__.__name__}).")
            message = f"Active assessment failed ({exc.__class__.__name__}); no finding was confirmed."
        finally:
            with self.lock:
                if run_id in self._active_chat_runs:
                    self._active_chat_runs[run_id] = {"status": status, "message": message}
                if self._active_chat_running_id == run_id:
                    self._active_chat_running_id = ""

    def active_chat_status(self, run_id: str) -> dict[str, Any]:
        with self.lock:
            current = self._active_chat_runs.get(run_id)
            if current is None:
                return {"ok": False, "status": "unavailable", "error": "That active run is no longer available in this session."}
            return {"ok": True, "run_id": run_id, **current}

    def _maybe_scan_reply(self, request: ChatRequest) -> dict[str, Any] | None:
        active_command = parse_active_chat_command(request.message)
        if active_command is not None:
            if active_command.get("ok"):
                result = self._start_active_chat_scan(
                    str(active_command["target"]), str(active_command["scope_host"])
                )
            else:
                result = active_command
            return {
                "request_id": uuid4().hex,
                "message": result.get("message") or result.get("error") or "Active assessment could not start.",
                "used_fallback": not bool(result.get("ok")),
                "captured_for_training": False,
                "model_name": "bughunter:active",
                "device": "scanner",
                "citations": [],
                "ai_core": self.store.load(),
                "active_scan": {"run_id": result.get("run_id", ""), "status": result.get("status", "error")},
            }
        result = dispatch_authorized_scan_command(request.message)
        if result is None:
            return None
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

    def _maybe_wardrive_reply(self, request: ChatRequest) -> dict[str, Any] | None:
        """``wardrive -y <path>`` typed in chat — read-only RF survey analysis.

        Sits beside ``_maybe_scan_reply`` so the offline surface covers hunt / code /
        knowledge / RF from one place. ``detect_wardrive_command`` returns None for anything
        ambiguous, so a message that merely says the word "wardrive" is ordinary chat.

        The unauthorized case is answered, not silently dropped: ``run_wardrive`` reads
        nothing without the explicit ``-y`` flag and returns a refusal that says what the
        flag asserts and how to re-send. Treating the chat message itself as authorization
        would make the flag meaningless."""
        command = detect_wardrive_command(request.message)
        if command is None:
            return None
        target, authorized = command
        result = run_wardrive(target, authorized)
        ok = bool(result.get("ok"))
        if ok:
            message = result.get("summary") or "The survey parsed but produced no assessment text."
        else:
            message = f"**Wardrive — {result.get('target') or 'survey'}**\n\n{result.get('error') or 'failed'}"
        return {
            "request_id": uuid4().hex,
            "message": message,
            "used_fallback": not ok,
            "captured_for_training": False,
            "model_name": "bughunter:wardrive",
            "device": "scanner",
            "citations": [],
            "ai_core": self.store.load(),
            "scan": {
                key: result.get(key)
                for key in (
                    "ok", "scan_type", "risk", "finding_count", "undetermined_count",
                    "target", "authorized",
                )
            },
        }

    def _maybe_mcp_reply(self, request: ChatRequest) -> dict[str, Any] | None:
        """Dispatch only a complete, operator-typed MCP command.

        MCP descriptions and results are untrusted server data. They are displayed as
        bounded text, never passed to a model or interpreted as a new instruction.
        Connecting and calling tools require the explicit ``-y`` marker; registration
        and ordinary chat can never start a server on their own.
        """
        raw = request.message.strip()
        if not re.match(r"^/?mcp(?:\s|$)", raw, re.IGNORECASE):
            return None

        def reply(message: str, *, ok: bool = True) -> dict[str, Any]:
            return {
                "request_id": uuid4().hex,
                "message": message,
                "used_fallback": not ok,
                "captured_for_training": False,
                "model_name": "mcp:manual",
                "device": "mcp",
                "diagnostics": {"strategy": "mcp_manual", "used_fallback": not ok},
                "citations": [],
                "ai_core": self.store.load(),
                "mcp_result": {"ok": ok},
            }

        command = re.sub(r"^/?mcp\b", "", raw, count=1, flags=re.IGNORECASE).strip()
        if command.lower() == "list":
            result = self.mcp_servers.list_servers()
            if not result.get("ok"):
                return reply(str(result.get("error") or "Could not load MCP servers."), ok=False)
            servers = result.get("servers") or []
            if not servers:
                return reply("No MCP servers are saved. Add one in Brain settings, then use Test to connect.")
            lines = ["Saved MCP servers (saving does not connect):"]
            for server in servers:
                lines.append(
                    f"- {server['name']} — {server['transport']}, "
                    f"{'enabled' if server.get('enabled') else 'disabled'}, "
                    f"{server.get('status') or 'untested'}"
                )
            return reply("\n".join(lines))

        tools_match = re.fullmatch(r"tools\s+-y\s+([A-Za-z0-9_-]+)", command, re.IGNORECASE)
        if tools_match:
            server_name = tools_match.group(1)
            result = self.mcp_servers.list_tools(server_name)
            if not result.get("ok"):
                return reply(str(result.get("error") or "Could not list MCP tools."), ok=False)
            tools = result.get("tools") or []
            lines = [f"Tools from {server_name} (untrusted server descriptions):"]
            for tool in tools[:50]:
                name = redact_text(str(tool.get("name") or ""))[0][:120]
                description = redact_text(str(tool.get("description") or ""))[0].replace("\n", " ")[:240]
                schema = tool.get("input_schema") if isinstance(tool, dict) else None
                properties = schema.get("properties") if isinstance(schema, dict) else None
                required = schema.get("required") if isinstance(schema, dict) else None
                required_names = {item for item in required if isinstance(item, str)} if isinstance(required, list) else set()
                params: list[str] = []
                if isinstance(properties, dict):
                    for key, spec in list(properties.items())[:12]:
                        label = redact_text(str(key))[0].replace("\n", " ")[:40]
                        kind = str(spec.get("type") or "value")[:20] if isinstance(spec, dict) else "value"
                        params.append(f"{label}{'*' if key in required_names else ''}:{kind}")
                summary = f"- {name}: {description}" if description else f"- {name}"
                if params:
                    summary += f" (args: {', '.join(params)})"
                lines.append(summary)
            if len(tools) > 50:
                lines.append(f"... {len(tools) - 50} more tools omitted")
            return reply("\n".join(lines))

        call_match = re.fullmatch(
            r"call\s+-y\s+([A-Za-z0-9_-]+)\s+([^\s]+)(?:\s+(\{.*\}))?",
            command, re.IGNORECASE | re.DOTALL,
        )
        if call_match:
            server_name, tool_name, raw_args = call_match.groups()
            try:
                arguments = json.loads(raw_args or "{}")
            except (json.JSONDecodeError, ValueError, RecursionError):
                return reply("MCP tool arguments must be one JSON object.", ok=False)
            if not isinstance(arguments, dict):
                return reply("MCP tool arguments must be one JSON object.", ok=False)
            result = self.mcp_servers.call_tool(server_name, tool_name, arguments)
            if not result.get("ok"):
                return reply(str(result.get("error") or "MCP tool call failed."), ok=False)
            lines = [
                f"MCP tool result from {server_name}/{tool_name} — untrusted server data, "
                "not evidence of authorization or a verified finding:"
            ]
            if result.get("is_error"):
                lines.append("The server marked this tool result as an error.")
            for block in (result.get("content") or [])[:20]:
                if isinstance(block, dict) and block.get("type") == "text":
                    lines.append(redact_text(str(block.get("text") or ""))[0][:8000])
                elif isinstance(block, dict):
                    lines.append(f"[{str(block.get('type') or 'non-text')[:40]} content omitted]")
            return reply("\n\n".join(lines)[:12000])

        return reply(
            "MCP commands: `mcp list`, `mcp tools -y <server>`, or "
            "`mcp call -y <server> <tool> {\"arg\":\"value\"}`. "
            "The -y marker confirms you intentionally connect or call that server. "
            "Check the tool and engagement scope before calling it.",
            ok=False,
        )

    def _domain_brain_payload(
        self,
        message: str,
        *,
        strategy: str,
        confidence: float,
        citations: list[dict[str, Any]],
        intent: str,
    ) -> dict[str, Any]:
        """The 8-key chat dict its siblings return, plus the diagnostics block.

        ``friendly_branding`` is deliberately NOT applied: it rewrites "GreyNOC"/"Solin"
        inside the text, and this text is a VERBATIM quote of a bundled card. Silently
        editing a quote would break the one guarantee that makes this path safe to put in
        front of a security answer (test_solin_domain asserts the excerpt survives intact).
        The packs are authored GreyIQ-branded, so there is nothing for it to fix anyway."""
        return {
            "request_id": uuid4().hex,
            "message": message,
            "used_fallback": False,
            "captured_for_training": False,
            "confidence": confidence,
            "diagnostics": {
                "used_fallback": False,
                "captured_for_training": False,
                "intent": intent,
                "mode": "offline",
                "strategy": strategy,
                "confidence": confidence,
                "retrieval_count": len(citations),
                "memory_count": 0,
                "note_count": 0,
                "citation_count": len(citations),
                "engine_ready": False,
                "device": "cpu",
            },
            "model_name": "offline:domain-brain",
            "device": "cpu",
            "citations": citations,
            "ai_core": self.store.load(),
        }

    def _domain_brain_reply(
        self,
        request: ChatRequest,
        min_score: float = solin_domain.MIN_SCORE,
    ) -> dict[str, Any] | None:
        """Answer from the bundled playbooks / vuln-class table, or return None.

        This runs BEFORE ``get_engine()`` because it is torch-free and the engine is not:
        in the shipped build torch is excluded, ``get_engine()`` raises, and chat degrades
        to ``fallback_reply()``'s single content-free sentence. Returning None is a total
        no-op — the caller proceeds down exactly the path it took before this existed.

        Nothing here generates text. Every branch either quotes a card verbatim, renders
        ``VULN_CLASSES`` fields, or lists tool names from the catalog — see
        ``solin_domain``'s module docstring for why that is the whole safety argument."""
        message = str(request.message or "")
        try:
            body = ""
            strategy = ""
            domain = ""
            confidence = 0.0
            citations: list[dict[str, Any]] = []
            wants_tools = solin_domain.looks_like_tool_request(message)
            class_id = solin_domain.detect_class_query(message)

            if class_id:
                # "what is SSRF" — answer straight out of the class table so chat and the
                # report writer can never disagree about a CWE or a checklist step.
                body = solin_domain.explain_class(class_id)
                if body:
                    strategy = "class_explainer"
                    domain = "webapp"
                    confidence = 0.72
                    citations = [{
                        "source": f"bughunter.bounty.VULN_CLASSES['{class_id}']",
                        "source_id": "src_vuln_classes",
                        "score": 1.0,
                        "excerpt": body[:400],
                    }]
            if not body and wants_tools:
                classes = solin_domain.classes_mentioned(message)
                tools = solin_domain.format_tools(
                    solin_domain.recommend_tools(classes, SEED_DIR, RUNTIME_DIR)
                )
                if tools:
                    body = (
                        "Tools in GreyIQ's bundled reference catalog that help TEST "
                        f"{', '.join(classes)} (names and links only — no payloads, and "
                        "every one of them is for authorized testing inside scope):\n\n"
                        f"{tools}"
                    )
                    strategy = "toolkit_recommend"
                    domain = "bounty"
                    confidence = 0.6
                    citations = [{
                        "source": "toolkit/catalog.json",
                        "source_id": "src_toolkit",
                        "score": 1.0,
                        "excerpt": tools[:400],
                    }]
            if not body:
                pack = solin_domain.load_pack(SEED_DIR, RUNTIME_DIR)
                scored = solin_domain.match_cards_scored(
                    message, pack, limit=3, min_score=min_score
                )
                if scored:
                    cards = [card for card, _score in scored]
                    domain = cards[0].domain
                    body = solin_domain.compose_answer(message, cards, domain)
                    if body:
                        strategy = "domain_pack"
                        confidence = round(min(max(scored[0][1], 0.2), 0.75), 3)
                        citations = [
                            {
                                "source": card.source_path,
                                "source_id": "src_domain_pack",
                                "score": round(float(score), 3),
                                "excerpt": solin_domain.verbatim_excerpt(card, message)[:400],
                            }
                            for card, score in scored
                        ]
            if not body or not strategy:
                return None

            # The honest capability gate: the operator named a host/path, and the offline
            # brain has never seen it. Say so BEFORE the playbook, not after.
            if _names_concrete_target(message):
                body = f"{solin_domain.capability_statement(domain)}\n\n{body}"
                strategy = "offline_capability"
                confidence = min(confidence, 0.5)

            return self._domain_brain_payload(
                body,
                strategy=strategy,
                confidence=confidence,
                citations=citations,
                intent=domain or "offline_domain",
            )
        except Exception:  # noqa: BLE001 - additive feature: any failure here must fall through to the unchanged pipeline, never break a chat turn
            self.log(f"Domain brain skipped: {traceback.format_exc(limit=3)}")
            return None

    def chat(self, request: ChatRequest) -> dict[str, Any]:
        mcp_reply = self._maybe_mcp_reply(request)
        if mcp_reply is not None:
            return mcp_reply
        # Read-only RF survey analysis of an export the operator already captured. Runs
        # beside the scanners (and before every brain) so the offline surface reaches the
        # wardrive engine too; returns None for anything that is not the command.
        #
        # STRICTLY BEFORE _maybe_scan_reply, because the wardrive trigger is the more
        # specific one: "scan wardrive -y ./capture" also satisfies detect_scan_command
        # (unknown subtype -> the rest looks like a path -> CODE scan), so the opposite order
        # silently hands an RF survey to the source-code scanner.
        wardrive_reply = self._maybe_wardrive_reply(request)
        if wardrive_reply is not None:
            return wardrive_reply
        scan_reply = self._maybe_scan_reply(request)
        if scan_reply is not None:
            return scan_reply
        # A configured coding brain (local model or Claude) answers instead of the
        # tiny offline model. TinyGPT is the last-resort fallback below.
        coder_reply = self._coder_reply(request)
        if coder_reply is not None:
            return coder_reply
        # No coding brain configured AND this is a code-WRITING request: the tiny offline model
        # cannot write code (a narrow char-level context, ~0% code in its corpus; its own quality gate
        # discards code-shaped output). Be honest and point at the real path instead of generating a
        # reply that gets thrown away — this also avoids the wasted CPU forward passes. See
        # docs/offline-coder-strategy.md.
        if _looks_like_codegen_request(request.message):
            return {
                "request_id": uuid4().hex,
                "message": (
                    "The offline model can't write or edit code. Configure a **Local model (Ollama)** or "
                    "a **Claude brain** in Settings, then use the Workbench agent — it edits files in your "
                    "workspace, runs verify, and can undo its changes. (The offline model is for chat and "
                    "explanations, not code generation.)"
                ),
                "used_fallback": True,
                "captured_for_training": False,
                "model_name": "offline:no-codegen",
                "device": "cpu",
                "citations": [],
                "ai_core": self.store.load(),
            }
        # The curated offline domain brain answers from bundled playbooks/knowledge packs with
        # real citations. It runs BEFORE the TinyGPT engine because it is torch-free: the shipped
        # build excludes torch, so get_engine() raises there and chat would otherwise degrade to
        # fallback_reply()'s content-free placeholder. Returns None (and changes nothing) when no
        # curated card matches above threshold. See solin_domain's module docstring.
        domain_reply = self._domain_brain_reply(request)
        if domain_reply is not None:
            return domain_reply
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
            # Last resort before the canned platitude. On a torch-less machine (every shipped
            # install) get_engine() raises EVERY turn, so this handler is the normal path, not
            # an edge case — try the curated pack once more with a RELAXED threshold. The
            # pre-router's bar exists to protect a working engine's answer; there is no
            # engine answer here, so a weaker-but-real card beats the canned platitude.
            #
            # The threshold is solin_domain's own evidence-tuned constant, NOT a multiplier
            # applied here: `MIN_SCORE * 0.75` used to land BELOW the scorer's off-domain
            # noise floor, which made this handler answer "what is the capital of France"
            # with a bug-bounty playbook. The bar and the evidence that sets it now live in
            # one place, and test_solin_domain asserts the off-domain fixture stays out AT
            # THIS THRESHOLD.
            domain_reply = self._domain_brain_reply(
                request, min_score=solin_domain.MIN_SCORE_RELAXED
            )
            if domain_reply is not None:
                return domain_reply
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
            resolved_size = normalize_model_size(request.model_size)
            self.training = TrainingState(
                active=True,
                job_id=f"job_{uuid4().hex[:12]}",
                started_at=datetime.now(UTC).isoformat(),
                runtime={"status": "queued", "stage": "queued", "detail": "Training is queued."},
                # Echoed so the panel can show what this run is actually doing (and so a stale form
                # cannot misreport it). A fresh TrainingState also resets the loss history.
                settings={
                    "model_size": resolved_size,
                    "max_iters": request.max_iters,
                    "eval_interval": request.eval_interval,
                    "learning_rate": request.learning_rate,
                    "batch_size_override": request.batch_size_override,
                    "dataset_char_cap": request.dataset_char_cap,
                    "fresh_start": bool(request.fresh_start),
                    "device_preference": normalize_device(request.device_preference),
                    "source_ids": normalize_source_ids(request.source_ids),
                    "patience": request.patience,
                    "min_delta": request.min_delta,
                    "auto_stop": bool(request.auto_stop),
                    "save_best_only": bool(request.save_best_only),
                    "restore_best": bool(request.restore_best),
                },
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
            # Architecture + step size. An unknown model_size falls back to the default preset inside
            # model_config_for rather than failing the run.
            model_size=normalize_model_size(request.model_size),
            batch_size_override=request.batch_size_override,
            # The early-stopping / best-model monitor. This was previously left at its dataclass
            # defaults, so the whole ValidationMonitorSettings surface was implemented but unreachable.
            validation=ValidationMonitorSettings(
                patience=request.patience,
                min_delta=request.min_delta,
                auto_stop=request.auto_stop,
                save_best_only=request.save_best_only,
                restore_best=request.restore_best,
            ),
        )

        def should_stop() -> bool:
            return self.training.stop_requested

        def should_pause() -> bool:
            return self.training.paused

        _MAX_HISTORY_POINTS = 400

        def on_status(status: dict[str, Any]) -> None:
            with self.lock:
                # MERGE, don't replace. The trainer emits two shapes: rich ValidationStatus dicts
                # (losses, device, batch size, dataset size) and coarse lifecycle events from
                # _emit_runtime_status that carry only status/stage/detail plus zeroed numeric fields.
                # Replacing wholesale meant the run's achieved losses, device, batch size and
                # stop_reason vanished at exactly the moment the operator wanted them — when the run
                # stopped or errored. Zero/empty incoming values no longer erase a known one.
                merged = dict(self.training.runtime)
                for key, value in (status or {}).items():
                    if value in (None, "", 0) and merged.get(key) not in (None, "", 0):
                        continue  # a coarse event has no opinion on this field; keep what we know
                    merged[key] = value
                self.training.runtime = merged
                # Record a loss point per eval so the panel can draw a curve.
                if status.get("val_loss") is not None:
                    point = {
                        "step": status.get("current_step") or status.get("epoch") or 0,
                        "train_loss": status.get("train_loss"),
                        "val_loss": status.get("val_loss"),
                        "best_val_loss": status.get("best_val_loss"),
                    }
                    if len(self.training.history) < _MAX_HISTORY_POINTS:
                        self.training.history.append(point)

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


def normalize_model_size(value: str | None) -> str:
    """A known MODEL_PRESETS key, or the shipped default. Never raises, so a stale client cannot
    fail a run — an unrecognised size trains the compact (resume-in-place) architecture."""
    normalized = str(value or "").strip().lower()
    known = set(MODEL_PRESETS) or {"compact", "standard", "large"}
    return normalized if normalized in known else "compact"


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
    if clean == "src_verified_replay":
        raise HTTPError(422, "Verified Lessons is generated from verified experiences and cannot be edited as a preference.")
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
    _migrate_code_router_secret()
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
    # Offline domain packs: same never-clobber .md copy as the bounty playbooks (NOT
    # SEED_DATA_FILES, which is a flat tuple of data/*.txt names). solin_domain.load_pack
    # reads the runtime copy first so a user's edits win, and falls back to the bundled
    # seed copy when a file is missing — so a failed copy costs nothing.
    seed_domain = SEED_DIR / "domain"
    if seed_domain.is_dir():
        dst_domain = RUNTIME_DIR / "domain"
        dst_domain.mkdir(parents=True, exist_ok=True)
        for pack_file in seed_domain.glob("*.md"):
            dst_pack = dst_domain / pack_file.name
            if not dst_pack.exists():
                shutil.copy2(pack_file, dst_pack)
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
    """/api/health is the one /api/* path exempt from the session-token gate (it's
    the liveness check Electron polls before a session even exists). When Electron
    supplies a per-launch ID, echo it so the shell can distinguish this backend
    from another process on the port. Standalone servers keep the bare liveness
    signal; neither mode exposes the app name or version."""
    launch_id = os.getenv("GREYIQ_LAUNCH_ID", "")
    if launch_id:
        return {"status": "ok", "launchId": launch_id}
    return {"status": "ok"}


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


_ENGAGEMENT_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": 0, "": 0}


def _build_engagement_markdown_from_run(ctx: dict[str, Any], findings: list[dict[str, Any]], platform: str, version: str) -> str:
    """One aggregate engagement report from a cached run: executive summary + severity/risk
    overview + each finding rendered IN FULL (reusing the per-finding report formatter, so
    the proof-of-impact / screenshots / reproduction match the single-finding reports)."""
    plans = ctx.get("attack_plans") or {}

    def _sev(f: dict[str, Any]) -> str:
        return bounty_report.resolve_severity(f, plans.get(f.get("ref")) or {})

    ranked = sorted(findings, key=lambda f: _ENGAGEMENT_SEV_ORDER.get(_sev(f), 0), reverse=True)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confirmed = 0
    for f in ranked:
        s = _sev(f)
        if s in counts:
            counts[s] += 1
        if bounty_report._proof_of_impact_detail(f, plans.get(f.get("ref")) or {}).get("status") == "confirmed":
            confirmed += 1
    target = ctx.get("target", "")
    out: list[str] = []
    out.append(f"# Engagement report — {target or 'findings'}\n")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| **Target** | {target or '(various)'} |")
    out.append(f"| **Findings** | {len(ranked)} total · **{confirmed} actively confirmed** |")
    out.append(f"| **Severity** | {counts['critical']} critical · {counts['high']} high · {counts['medium']} medium · {counts['low']} low · {counts['info']} info |")
    out.append(f"| **Generated** | {ctx.get('generated_at') or datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} · GreyIQ v{version} |")
    out.append("")
    out.append("## Authorization & scope\n")
    out.append("> Authorized testing only. " + (str(ctx.get("scope") or "") or "(scope not provided)"))
    out.append("")
    out.append("## Findings overview\n")
    out.append("| # | Severity | Class | Proof | Finding | Location |")
    out.append("|---|---|---|---|---|---|")
    for i, f in enumerate(ranked, 1):
        proof = bounty_report._proof_of_impact_detail(f, plans.get(f.get("ref")) or {}).get("status", "missing")
        out.append(f"| {i} | {_sev(f).title()} | {str(f.get('class_name') or f.get('class_id') or '')} | {proof} "
                   f"| {str(f.get('title', '')).replace('|', '/')} | `{f.get('location') or f.get('source_url') or ''}` |")
    out.append("")
    out.append("## Detailed findings\n")
    for f in ranked:
        body = bounty_formats.render_finding(ctx, f, platform)
        if body.strip():
            out.append(body.strip())
            out.append("\n---\n")
    return "\n".join(out)


def _build_engagement_markdown_from_ledger(program: str, records: list[dict[str, Any]], version: str) -> str:
    """Aggregate report from durable ledger history (no full attack plans): executive summary
    + a findings table with proof/stage/bounty — for a program whose rich run cache has aged
    out of memory but whose finding history persists."""
    ranked = sorted(records, key=lambda r: _ENGAGEMENT_SEV_ORDER.get(str(r.get("severity") or "").lower(), 0), reverse=True)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    bounty = 0.0
    for r in ranked:
        s = str(r.get("severity") or "").lower()
        if s in counts:
            counts[s] += 1
        bounty += float(r.get("bounty") or 0.0)
    out: list[str] = []
    out.append(f"# Engagement report — {program}\n")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| **Findings** | {len(ranked)} recorded |")
    out.append(f"| **Severity** | {counts['critical']} critical · {counts['high']} high · {counts['medium']} medium · {counts['low']} low · {counts['info']} info |")
    out.append(f"| **Bounty to date** | ${round(bounty, 2)} |")
    out.append(f"| **Generated** | {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} · GreyIQ v{version} |")
    out.append("")
    out.append("## Findings\n")
    out.append("| Severity | Class | Title | Proof | Stage | Bounty | Location |")
    out.append("|---|---|---|---|---|---|---|")
    for r in ranked:
        out.append(f"| {str(r.get('severity') or '').title()} | {r.get('class_id') or ''} | {str(r.get('title', '')).replace('|', '/')} "
                   f"| {r.get('proof_status') or ''} | {r.get('stage') or ''} | {r.get('bounty') or 0} | `{r.get('source_url') or ''}` |")
    out.append("")
    out.append("---")
    out.append("_GreyIQ engagement report — durable ledger history. Re-run a hunt for full per-finding evidence + reproduction steps._")
    return "\n".join(out)


def _safe_validation_summary(exc: Exception, max_errors: int = 10) -> str:
    """A 422 detail message naming WHICH fields failed and why, without ever reflecting
    the submitted values: pydantic's str(exc) embeds 'input_value=<the actual payload>',
    which would echo arbitrary client-submitted content (and pydantic's own internal
    error-code URLs) straight back to the caller — exactly what the deliberate
    'never reflect raw exception text to the client' design (see route_http's generic
    Exception handler) exists to prevent. err['msg']/err['loc'] are pydantic's own static,
    value-free descriptions ("Field required", "Input should be a valid integer")."""
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return "invalid request payload"
    try:
        parsed = errors()
    except Exception:  # noqa: BLE001 - errors() itself is best-effort here
        return "invalid request payload"
    parts = []
    for err in parsed[:max_errors]:
        loc = ".".join(str(p) for p in (err.get("loc") or ())) or "(body)"
        parts.append(f"{loc}: {err.get('msg') or 'invalid value'}")
    if not parts:
        return "invalid request payload"
    suffix = f" (+{len(parsed) - max_errors} more)" if len(parsed) > max_errors else ""
    return "invalid request payload — " + "; ".join(parts) + suffix


def validate_payload(model: type[BaseModel], payload: dict[str, Any]) -> BaseModel:
    try:
        validator = getattr(model, "model_validate", None)
        if validator is not None:
            return validator(payload)
        return model.parse_obj(payload)
    except Exception as exc:
        raise HTTPError(422, _safe_validation_summary(exc)) from exc


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
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        # A body containing invalid UTF-8 bytes raises UnicodeDecodeError here, which is
        # a ValueError but NOT a json.JSONDecodeError -- it must be caught too, or it
        # escapes as an unhandled exception and the client sees a generic 500 instead of
        # the intended 400 "bad request". A deeply-nested body (e.g. b'['*60000) makes
        # json.loads raise RecursionError, which is NOT a ValueError subclass -- catch it
        # too so malformed-but-nested JSON also maps to the deliberate 400 rather than a
        # 500 + server-log traceback spam.
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


def _internal_model_store_authorized(scope: dict[str, Any]) -> bool:
    """The Electron main process alone may identify its own Ollama store."""
    client = scope.get("client")
    return (bool(INTERNAL_MODEL_STORE_TOKEN)
            and isinstance(client, (tuple, list)) and bool(client)
            and _is_loopback_bind(str(client[0]))
            and hmac.compare_digest(
                _header(scope, "x-greyiq-internal-model-store-token"),
                INTERNAL_MODEL_STORE_TOKEN,
            ))


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
    # Behind the documented Nginx TLS-terminating proxy the raw scope scheme is 'http' while the
    # browser's Origin is 'https://host'; honor a trusted X-Forwarded-Proto so a legitimate
    # same-site request isn't 403'd. Trusted only because the operator's own proxy sets it.
    fwd = _header(scope, "x-forwarded-proto").split(",")[0].strip().lower()
    scheme = fwd if fwd in ("http", "https") else str((scope or {}).get("scheme") or "http").lower()
    return f"{scheme}://{host}"


def _host_header_allowed(scope: dict[str, Any] | None) -> bool:
    """Reject a request whose Host header names a host that is neither loopback nor an
    operator-configured origin. This closes DNS rebinding against the loopback deployment:
    _same_origin() derives the trusted same-origin string verbatim from the client-controlled
    Host header, so an attacker who rebinds evil.com -> 127.0.0.1 would otherwise have the
    rebound page pass the same-origin check, read the SESSION_TOKEN-bearing index, and drive
    /api/*. A configured GREYIQ_ACCESS_KEY already authenticates EVERY request via Basic Auth,
    so beyond-loopback proxy/domain deployments (which may not set GREYIQ_ALLOWED_ORIGINS) are
    left untouched -- the rebinding hole only exists for the keyless loopback default."""
    host = _header(scope, "host").strip().lower()
    if not host:
        # A missing Host header cannot come from the rebinding browser attack (browsers always
        # send one); don't reject legitimate non-browser local callers that omit it.
        return True
    try:
        # urlparse handles host:port and bracketed IPv6 ([::1]:8766) uniformly.
        hostname = (urlparse(f"//{host}").hostname or "").lower()
    except ValueError:
        return False
    if not hostname or hostname in _LOOPBACK_HOSTS:
        return True
    if GREYIQ_ACCESS_KEY:
        return True
    allowed_hosts = {h for h in (urlparse(o).hostname for o in _configured_origins()) if h}
    return hostname in allowed_hosts


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
        # `authorization` is required: the GREYIQ_ACCESS_KEY beyond-loopback deployment carries the
        # key via HTTP Basic Auth, which is not CORS-safelisted, so a credentialed cross-origin
        # request preflights on it — omitting it makes that deployment unauthenticatable.
        (b"access-control-allow-headers", b"content-type,accept,x-greyiq-token,authorization"),
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
    # API/JSON responses carry finding/proof/credential-status data — never let a proxy or
    # the webview disk-cache them.
    if content_type.startswith("application/json"):
        headers.append((b"cache-control", b"no-store"))
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


def _static_target(relative_path: str) -> Path | None:
    """The file under ``PUBLIC_DIR`` a request path names, or ``None`` if it names none.

    ``None`` is the single "refuse this, 404" answer for every reason a request path is not a
    servable name: a traversal out of ``PUBLIC_DIR``, an OS that will not even parse the string,
    and a NUL byte.

    The NUL is checked here rather than left to the OS because the two platforms disagree about
    who notices it, and the disagreement was silent. On POSIX ``.resolve()`` raises
    ``ValueError('embedded null byte')``, which the guard below catches -- so ``GET /%00``
    answered 404 and the test pinning that passed. On Windows ``.resolve()`` returns the path
    with the NUL still in it, ``relative_to`` is happy because it really is under ``PUBLIC_DIR``,
    and then ``Path.exists()`` swallows the same ValueError and answers False -- so the request
    fell through to the SPA fallback and a NUL probe was served index.html with a 200. Rejecting
    the byte in Python gives one answer on both.

    ``.resolve()`` stays INSIDE the try for everything else it raises on: a path this OS will not
    parse must become the 404 below, not an escape into the generic 500 handler with a logged
    traceback. Doing the whole decision here is what lets a test assert the rule itself rather
    than whichever half of it the test machine's OS happens to implement.
    """
    if "\x00" in relative_path:
        return None
    try:
        file_path = (PUBLIC_DIR / relative_path).resolve()
        file_path.relative_to(PUBLIC_DIR.resolve())
    except (ValueError, OSError):
        return None
    return file_path


async def send_file(send: Any, path: Path, status_code: int = 200) -> None:
    try:
        body = await asyncio.to_thread(path.read_bytes)
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
        html = await asyncio.to_thread((PUBLIC_DIR / "index.html").read_text, encoding="utf-8")
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


async def send_unauthorized(send: Any) -> None:
    """401 challenge for the GREYIQ_ACCESS_KEY gate — a browser hitting this shows its
    native Basic Auth prompt, same UX as the reverse-proxy auth_basic pattern operators
    already know from DEPLOY.md."""
    body = json.dumps({"error": "authentication required"}).encode("utf-8")
    headers = response_headers("application/json; charset=utf-8", len(body))
    headers.append((b"www-authenticate", b'Basic realm="GreyIQ"'))
    await send({"type": "http.response.start", "status": 401, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def route_http(scope: dict[str, Any], receive: Any, send: Any) -> None:
    _CURRENT_SCOPE.set(scope)
    method = str(scope.get("method") or "GET").upper()
    path = str(scope.get("path") or "/")

    # Host-header allowlist runs before ANYTHING is served (index/token/static/API), closing
    # DNS rebinding for the loopback deployment: a rebound Host: evil.com is neither loopback
    # nor a configured origin, so it is refused before _same_origin can trust it verbatim.
    if not _host_header_allowed(scope):
        await send_json(send, {"error": "host not allowed"}, 403)
        return

    # A CORS preflight (OPTIONS) NEVER carries credentials per the Fetch spec, so it must be answered
    # BEFORE the access-key gate. Otherwise a configured GREYIQ_ACCESS_KEY 401s every preflight and no
    # preflighted cross-origin /api/* call from an allowlisted frontend can ever succeed. The actual
    # credentialed request that the browser sends AFTER a successful preflight is still access-key gated
    # below. The origin is still validated here, and OPTIONS returns only an empty CORS response.
    if method == "OPTIONS":
        if not _request_origin_allowed(scope):
            await send_json(send, {"error": "origin not allowed"}, 403)
            return
        await send_empty(send)
        return

    # Access-key gate runs before EVERYTHING else, including the unauthenticated index
    # page and static-file fallback that embed/precede SESSION_TOKEN — a no-op when
    # GREYIQ_ACCESS_KEY isn't set (the default local/Electron case).
    if not _access_key_authorized(scope):
        await send_unauthorized(send)
        return

    if not _request_origin_allowed(scope):
        await send_json(send, {"error": "origin not allowed"}, 403)
        return

    # Session-token gate: /api/* (except liveness) requires the per-session token,
    # so other local processes can't drive the API over 127.0.0.1.
    if (path.startswith("/api/")
            and path not in {"/api/health", "/api/internal/ollama-model-store"}
            and not _session_authorized(scope)):
        await send_json(send, {"error": "missing or invalid session token"}, 403)
        return

    try:
        if path == "/api/internal/ollama-model-store":
            if method != "POST":
                await send_json(send, {"error": "method not allowed"}, 405)
                return
            if not _internal_model_store_authorized(scope):
                await send_json(send, {"error": "internal model-store authentication required"}, 403)
                return
            body = await read_json_body(receive)
            if set(body) != {"models_dir"}:
                raise HTTPError(422, "models_dir is required.")
            runtime.set_managed_ollama_models_dir(body["models_dir"])
            await send_json(send, {"ok": True})
            return
        if method == "GET" and path in {"/", "/app"}:
            await send_index(send)
            return
        if method == "GET" and path == "/api/health":
            await send_json(send, health())
            return
        if method == "GET" and path == "/api/status":
            await send_json(send, await asyncio.to_thread(runtime.status))
            return
        if method == "GET" and path == "/api/brain/status":
            await send_json(send, await asyncio.to_thread(runtime.brain_status))
            return
        if method == "POST" and path == "/api/chat":
            request = validate_payload(ChatRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.chat, request))
            return
        if method == "POST" and path == "/api/chat/active-status":
            request = validate_payload(ActiveChatStatusRequest, await read_json_body(receive))
            await send_json(send, runtime.active_chat_status(request.run_id))
            return
        if method == "POST" and path == "/api/scan/code":
            request = validate_payload(ScanCodeRequest, await read_json_body(receive))
            if request.target_type.strip().lower() == "git_remote":
                grant = validate_scoped_network_target("code", request.target, request.scope_repository, request.authorized)
                if not grant["ok"]:
                    await send_json(send, grant)
                    return

            def _scan_and_classify() -> dict[str, Any]:
                res = run_code_scan(request.target, request.target_type, request.max_files,
                                    tuple(request.include_globs), tuple(request.exclude_globs))
                # Strict secret classification + raw-value scrub before the result leaves for the browser:
                # this standalone route returns finding secret_value un-redacted otherwise (run_code_scan is
                # also used INTERNALLY by run_bounty_hunt, which classifies later and needs the raw value for
                # AWS key pairing — so the scrub is applied HERE, at the API edge, not inside run_code_scan).
                if isinstance(res, dict) and isinstance(res.get("findings"), list):
                    bounty_secret_class.apply_secret_classification(res["findings"])
                return res

            await send_json(send, await asyncio.to_thread(_scan_and_classify))
            return
        if method == "POST" and path == "/api/scan/web":
            request = validate_payload(WebScanRequest, await read_json_body(receive))
            grant = validate_scoped_network_target("web", request.url, request.scope_host, request.authorized)
            if not grant["ok"]:
                await send_json(send, grant)
                return
            await send_json(send, await asyncio.to_thread(run_web_scan, request.url, scope_host=grant["scope_host"]))
            return
        if method == "POST" and path == "/api/scan/live":
            request = validate_payload(LiveScanRequest, await read_json_body(receive))
            grant = validate_scoped_network_target("live", request.url, request.scope_host, request.authorized)
            if not grant["ok"]:
                await send_json(send, grant)
                return
            await send_json(
                send,
                await asyncio.to_thread(run_live_scan, request.url, request.wait_seconds, scope_host=grant["scope_host"]),
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
        if method == "POST" and path == "/api/bounty/portfolio":
            request = validate_payload(PortfolioRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.run_portfolio, request))
            return
        if method == "POST" and path == "/api/bounty/progress":
            request = validate_payload(BountyProgressRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.bounty_progress, request.run_id, request.after))
            return
        if method == "POST" and path == "/api/bounty/runs":
            validate_payload(BountyRunsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.list_bounty_runs))
            return
        if method == "POST" and path == "/api/bounty/events":
            request = validate_payload(BountyEventsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.bounty_events, request.after))
            return
        if method == "POST" and path == "/api/bounty/campaign/stop":
            request = validate_payload(CampaignStopRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.stop_campaign, request.run_id))
            return
        if method == "POST" and path == "/api/bounty/finding/reverify":
            request = validate_payload(ReverifyRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.reverify_finding, request))
            return
        if method == "POST" and path == "/api/bounty/finding/prove":
            request = validate_payload(ProveRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.prove_finding, request))
            return
        if method == "POST" and path == "/api/bounty/finding/report":
            request = validate_payload(FindingReportRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.build_finding_report, request))
            return
        if method == "POST" and path == "/api/bounty/finding/report-ready":
            request = validate_payload(ReportReadyRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.get_report_ready, request))
            return
        if method == "POST" and path == "/api/bounty/finding/dismiss":
            request = validate_payload(FindingDismissRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.dismiss_finding, request))
            return
        if method == "POST" and path == "/api/bounty/finding/restore":
            request = validate_payload(FindingRestoreRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.restore_finding, request))
            return
        if method == "POST" and path == "/api/bounty/report/aggregate":
            request = validate_payload(AggregateReportRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.aggregate_report, request))
            return
        if method == "GET" and path == "/api/bounty/findings":
            await send_json(send, await asyncio.to_thread(runtime.list_all_findings))
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
        if method == "GET" and path == "/api/bounty/ledger-csv":
            params = parse_qs(scope.get("query_string", b"").decode("utf-8", "replace"))
            program = (params.get("program") or [None])[0]
            target = (params.get("target") or [""])[0]
            await send_json(send, await asyncio.to_thread(runtime.export_ledger_csv, program, target))
            return
        if method == "POST" and path == "/api/bounty/submission":
            request = validate_payload(SubmissionPackageRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.build_submission_package, request))
            return
        if method == "POST" and path == "/api/bounty/screenshot":
            request = validate_payload(ScreenshotRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.capture_screenshot, request))
            return
        if method == "POST" and path == "/api/bounty/attack-map":
            request = validate_payload(AttackMapRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.render_attack_plan_map, request))
            return
        if method == "POST" and path == "/api/bounty/credential-test":
            request = validate_payload(CredentialTestRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.test_source_credential, request))
            return
        if method == "POST" and path == "/api/bounty/ingest-targets":
            request = validate_payload(IngestTargetsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.ingest_targets, request))
            return
        if method == "POST" and path == "/api/bounty/bundle":
            request = validate_payload(BundleRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.export_bundle, request))
            return
        if method == "POST" and path == "/api/bounty/leads":
            request = validate_payload(LeadsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.export_leads, request))
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
        if method == "POST" and path == "/api/bounty/mass-assignment":
            request = validate_payload(MassAssignRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_mass_assignment, request))
            return
        if method == "POST" and path == "/api/bounty/session-invalidation":
            request = validate_payload(SessionInvalRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_session_invalidation, request))
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
        if method == "POST" and path == "/api/bounty/stored-xss-beacon":
            request = validate_payload(StoredXssBeaconRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.check_stored_xss_beacon, request))
            return
        if method == "POST" and path == "/api/bounty/submit":
            request = validate_payload(SubmitRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.submit_finding, request))
            return
        if method == "POST" and path == "/api/bounty/finding/preflight":
            request = validate_payload(PreflightRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.preflight_submission, request))
            return
        if method == "GET" and path == "/api/bounty/hackerone/creds":
            await send_json(send, await asyncio.to_thread(runtime.hackerone_creds_status))
            return
        if method == "POST" and path == "/api/bounty/hackerone/creds":
            request = validate_payload(HackerOneCredsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.save_hackerone_creds, request))
            return
        if method == "POST" and path == "/api/bounty/hackerone/test":
            await send_json(send, await asyncio.to_thread(runtime.test_hackerone_creds))
            return
        if method == "GET" and path == "/api/bounty/yeswehack/creds":
            await send_json(send, await asyncio.to_thread(runtime.yeswehack_creds_status))
            return
        if method == "POST" and path == "/api/bounty/yeswehack/creds":
            request = validate_payload(YesWeHackCredsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.save_yeswehack_creds, request))
            return
        if method == "POST" and path == "/api/bounty/yeswehack/login":
            request = validate_payload(YesWeHackLoginRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.yeswehack_login, request))
            return
        if method == "POST" and path == "/api/bounty/yeswehack/test":
            await send_json(send, await asyncio.to_thread(runtime.test_yeswehack_creds))
            return
        if method == "GET" and path == "/api/platforms/credentials":
            await send_json(send, await asyncio.to_thread(runtime.platform_credentials_status))
            return
        if method == "POST" and path == "/api/platforms/credentials":
            request = validate_payload(PlatformCredentialRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.save_platform_credential, request))
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
        if method == "GET" and path == "/api/operator/vdp-profiles":
            await send_json(send, await asyncio.to_thread(runtime.list_vdp_profiles))
            return
        if method == "POST" and path == "/api/operator/programs/preset":
            request = validate_payload(VdpPresetRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.create_program_from_preset, request))
            return
        if method == "POST" and path == "/api/programs/from-repo":
            request = validate_payload(ProgramFromRepoRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.program_from_repo, request))
            return
        if method == "POST" and path == "/api/repos/preflight":
            request = validate_payload(RepoPreflightRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.preflight_repository, request))
            return
        if method == "POST" and path == "/api/hackerone/import-scope":
            request = validate_payload(HackerOneImportRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.import_hackerone_scope, request))
            return
        if method == "POST" and path == "/api/yeswehack/import-scope":
            request = validate_payload(YesWeHackImportRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.import_yeswehack_scope, request))
            return
        if method == "POST" and path == "/api/yeswehack/programs":
            request = validate_payload(YesWeHackProgramsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.yeswehack_programs, request))
            return
        if method == "POST" and path == "/api/platforms/programs":
            request = validate_payload(PlatformProgramsRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.discover_platform_programs, request))
            return
        if method == "POST" and path == "/api/platforms/preview":
            request = validate_payload(PlatformPreviewRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.preview_platform_program, request))
            return
        if method == "POST" and path == "/api/hackerone/hacktivity":
            request = validate_payload(HackerOneHacktivityRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.hackerone_hacktivity, request))
            return
        if method == "POST" and path == "/api/hackerone/my-reports":
            request = validate_payload(HackerOnePageRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.hackerone_my_reports, request))
            return
        if method == "POST" and path == "/api/hackerone/report-status":
            request = validate_payload(HackerOneReportStatusRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.hackerone_report_status, request))
            return
        if method == "POST" and path == "/api/hackerone/earnings":
            request = validate_payload(HackerOnePageRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.hackerone_earnings, request))
            return
        if method == "POST" and path == "/api/hackerone/sync-submitted":
            request = validate_payload(HackerOneSyncRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.sync_hackerone_reports, request))
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
        if method == "GET" and path == "/api/hunt/model":
            await send_json(send, await asyncio.to_thread(runtime.hunt_model_status))
            return
        if method == "POST" and path == "/api/hunt/train":
            request = validate_payload(HuntBrainTrainRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.train_hunt_brain, request))
            return
        if method == "GET" and path == "/api/train/dataset":
            # What the trainer would actually read, BEFORE committing to a run: per-source character
            # counts, the total, whether the cap will bite, and each model size's parameter count and
            # minimum corpus. collect_dataset_stats existed for this and had no route, so the Train
            # panel could only show what happened after the fact.
            await send_json(send, await asyncio.to_thread(runtime.training_dataset_preview))
            return
        # pause/resume/stop mutate shared run state, so they take the lock and refuse when no run is
        # active — POSTing pause to an idle runtime used to report paused:true and mean nothing.
        if method == "POST" and path == "/api/train/pause":
            await send_json(send, runtime.set_training_paused(True))
            return
        if method == "POST" and path == "/api/train/resume":
            await send_json(send, runtime.set_training_paused(False))
            return
        if method == "POST" and path == "/api/train/stop":
            await send_json(send, runtime.request_training_stop())
            return
        if method == "POST" and path == "/api/runtime/device":
            request = validate_payload(DeviceRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.set_device, request.preference))
            return
        if path == "/api/mcp/hunt-approvals":
            if method == "GET":
                await send_json(send, await asyncio.to_thread(runtime.mcp_servers.list_hunt_approvals))
                return
            if method == "POST":
                body = await read_json_body(receive)
                if not isinstance(body, dict) or set(body) != {"server", "tool", "evidence_only"}:
                    await send_json(send, {"ok": False, "error": "Server, tool, and evidence_only are required."}, 400)
                    return
                await send_json(send, await asyncio.to_thread(
                    runtime.mcp_servers.approve_hunt_tool, body["server"], body["tool"],
                    evidence_only=body["evidence_only"]))
                return
            await send_json(send, {"error": "method not allowed"}, 405)
            return
        if path.startswith("/api/mcp/hunt-approvals/"):
            tail = unquote(path[len("/api/mcp/hunt-approvals/"):])
            parts = tail.split("/", 1)
            if len(parts) != 2 or not all(parts):
                await send_json(send, {"error": "not found"}, 404)
                return
            if method == "DELETE":
                await send_json(send, await asyncio.to_thread(
                    runtime.mcp_servers.revoke_hunt_tool, parts[0], parts[1]))
                return
            await send_json(send, {"error": "method not allowed"}, 405)
            return
        if path == "/api/mcp/servers":
            if method == "GET":
                await send_json(send, await asyncio.to_thread(runtime.mcp_servers.list_servers))
                return
            if method == "POST":
                body = await read_json_body(receive)
                await send_json(send, await asyncio.to_thread(runtime.mcp_servers.add_server, body))
                return
            await send_json(send, {"error": "method not allowed"}, 405)
            return
        if path.startswith("/api/mcp/servers/"):
            tail = unquote(path[len("/api/mcp/servers/"):])
            if tail.endswith("/test") and method == "POST":
                name = tail[:-len("/test")]
                if not name or "/" in name:
                    await send_json(send, {"error": "not found"}, 404)
                    return
                await send_json(send, await asyncio.to_thread(runtime.mcp_servers.test_server, name))
                return
            if not tail or "/" in tail:
                await send_json(send, {"error": "not found"}, 404)
                return
            if method == "PUT":
                body = await read_json_body(receive)
                await send_json(send, await asyncio.to_thread(runtime.mcp_servers.update_server, tail, body))
                return
            if method == "DELETE":
                await send_json(send, await asyncio.to_thread(runtime.mcp_servers.delete_server, tail))
                return
            await send_json(send, {"error": "method not allowed"}, 405)
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
            params = parse_qs(scope.get("query_string", b"").decode("utf-8", "replace"), keep_blank_values=True)
            urls = params.get("base_url", [])
            if len(urls) > 1:
                raise HTTPError(422, "Supply one Ollama server URL.")
            await send_json(send, await asyncio.to_thread(runtime.list_local_models, urls[0] if urls else None))
            return
        if method == "GET" and path == "/api/coder/catalog":
            await send_json(send, await asyncio.to_thread(runtime.list_public_ollama_models))
            return
        if method == "POST" and path == "/api/coder/pull":
            body = await read_json_body(receive)
            model = str((body or {}).get("model") or "")
            await send_json(send, await asyncio.to_thread(runtime.start_model_pull, model))
            return
        if method == "POST" and path == "/api/coder/setup":
            request = validate_payload(ModelSetupRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.start_model_setup, request.model, request.base_url))
            return
        if method == "POST" and path == "/api/coder/huggingface/import":
            request = validate_payload(HuggingFaceImportRequest, await read_json_body(receive))
            await send_json(send, await asyncio.to_thread(runtime.start_huggingface_import, request.reference))
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

        file_path = _static_target(unquote(path.lstrip("/")) or "index.html")
        if file_path is None:
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
    if not _is_loopback_bind(host) and not GREYIQ_ACCESS_KEY and os.getenv("GREYIQ_ALLOW_INSECURE_PUBLIC_BIND", "").strip() != "1":
        print(
            f"Refusing to start: GREYIQ_HOST={host!r} is not loopback-only, but no GREYIQ_ACCESS_KEY is set.\n"
            "Binding this API beyond 127.0.0.1/localhost without a real access credential lets anyone who can "
            "reach it read the per-session token from the unauthenticated home page and replay it against every "
            "/api/* route (including workspace file read/write and outbound scan requests) -- the token was only "
            "ever designed to stop other local processes, not a remote client.\n"
            "Set GREYIQ_ACCESS_KEY to a strong secret before exposing this server, or set "
            "GREYIQ_ALLOW_INSECURE_PUBLIC_BIND=1 if you already have an equivalent auth layer in front of it "
            "(e.g. a reverse proxy doing its own authentication) and accept the risk.",
            file=sys.stderr,
        )
        raise SystemExit(1)
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
