from __future__ import annotations

import json
import re
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import torch

from document_ingest import ingest_pdf_folder, resolve_default_pdf_folder
from solin_core import TinyGPT, detect_best_device, find_model_path, save_config, save_vocab

ROOT_TRAIN_FILE = "train.txt"
DATA_FOLDER = "data"
COMBINED_FILE = "combined_train.txt"
SOURCE_TEXT_FILES = {
    "src_starter_knowledge": ["greyiq_starter_knowledge.txt"],
    "src_personal_choices": ["greyiq_personal_choices.txt", "greyiq_profile.txt"],
    "src_preferred_examples": ["greyiq_preferred_examples.txt"],
    "src_local_notes": ["greyiq_local_notes.txt"],
    "src_imported_docs": ["greyiq_imported_docs.txt"],
}
GENERATED_TEXT_FILES = {
    "combined_train.txt",
    "greyiq_selected_sources.txt",
}
CHECKPOINT_FILE = "solin_checkpoint.pt"
BEST_MODEL_FILE = "best_model.pt"
STABLE_MODELS_DIR = "StableModels"
MAX_DAILY_STABLE_MODELS = 50
# Minimum seconds between timestamped archive snapshots. The "latest" alias
# (best_model.pt) is always updated; this only throttles the dated history so
# OneDrive isn't flooded with hundreds of large .pt files per session.
MIN_ARCHIVE_INTERVAL_SECONDS = 60.0
MANIFEST_FILE = "pdf_manifest.json"

# Cap dataset loaded into RAM; 275 MB encodes to ~2.2 GB of long tensors and OOMs on CPU.
MAX_TRAINING_CHARS = 8_000_000  # 8 MB is plenty for block_size=64 training
MAX_GRAD_NORM = 1.0

MODEL_CONFIG = {
    "block_size": 64,
    "n_embd": 128,
    "n_head": 4,
    "n_layer": 4,
    "dropout": 0.1,
}

DEFAULT_MAX_ITERS = 1000
DEFAULT_EVAL_INTERVAL = 100
DEFAULT_LEARNING_RATE = 3e-4
DEFAULT_IDLE_SLEEP_SECONDS = 5.0
DEFAULT_POST_CYCLE_SLEEP_SECONDS = 1.0

Logger = Callable[[str], None]
Predicate = Callable[[], bool]
CycleCallback = Callable[[int], None]
StatusCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class ValidationMonitorSettings:
    patience: int = 3
    min_delta: float = 0.0001
    auto_stop: bool = True
    save_best_only: bool = True
    restore_best: bool = True


@dataclass(slots=True)
class ValidationStatus:
    epoch: int = 0
    train_loss: float | None = None
    val_loss: float | None = None
    best_val_loss: float | None = None
    no_improve_count: int = 0
    patience: int = 3
    status: str = "idle"
    last_checkpoint: str = ""
    stop_reason: str = ""
    stage: str = ""
    detail: str = ""
    current_step: int = 0
    total_steps: int = 0
    device: str = ""
    batch_size: int = 0
    dataset_chars: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "epoch": self.epoch,
            "train_loss": self.train_loss,
            "val_loss": self.val_loss,
            "best_val_loss": self.best_val_loss,
            "no_improve_count": self.no_improve_count,
            "patience": self.patience,
            "status": self.status,
            "last_checkpoint": self.last_checkpoint,
            "stop_reason": self.stop_reason,
            "stage": self.stage,
            "detail": self.detail,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "device": self.device,
            "batch_size": self.batch_size,
            "dataset_chars": self.dataset_chars,
        }


@dataclass(slots=True)
class TrainingSettings:
    pdf_folder: str | Path | None = None
    method: str = "auto"
    continuous: bool = False
    trigger_mode: str = "changes"
    idle_sleep_seconds: float = DEFAULT_IDLE_SLEEP_SECONDS
    post_cycle_sleep_seconds: float = DEFAULT_POST_CYCLE_SLEEP_SECONDS
    max_iters: int = DEFAULT_MAX_ITERS
    eval_interval: int = DEFAULT_EVAL_INTERVAL
    learning_rate: float = DEFAULT_LEARNING_RATE
    skip_pdf_ingest: bool = False
    max_cycles: int = 0
    device_preference: str = "auto"
    batch_size_override: int = 0
    dataset_char_cap: int = MAX_TRAINING_CHARS
    source_ids: list[str] = field(default_factory=list)
    fresh_start: bool = False
    validation: ValidationMonitorSettings = field(default_factory=ValidationMonitorSettings)


def _log(logger: Logger | None, message: str) -> None:
    if logger:
        try:
            logger(message)
        except UnicodeEncodeError:
            try:
                logger(message.encode("ascii", errors="replace").decode("ascii"))
            except Exception:
                pass
        except Exception:
            pass


def _is_retryable_cuda_failure(exc: BaseException) -> bool:
    message = str(exc).lower()
    retry_markers = (
        "no kernel image is available",
        "kernel image",
        "sm_",
        "not compatible with the current pytorch installation",
        "acceleratorerror",
        "cuda error",
        "device kernel image is invalid",
    )
    return any(marker in message for marker in retry_markers)


def collect_dataset_stats(base_dir: str | Path) -> dict[str, int | str]:
    root = Path(base_dir)
    data_dir = root / DATA_FOLDER
    data_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(data_dir.glob("*.txt"))
    extracted_characters = 0
    for path in files:
        try:
            extracted_characters += path.stat().st_size
        except Exception:
            continue

    root_chars = 0
    root_train = root / ROOT_TRAIN_FILE
    if root_train.exists():
        try:
            root_chars = root_train.stat().st_size
        except Exception:
            root_chars = 0

    model_path = find_model_path(root)

    return {
        "extracted_files": len(files),
        "extracted_characters": extracted_characters,
        "root_train_characters": root_chars,
        "model_name": model_path.name if model_path else "none",
    }


def safe_torch_save(obj, path: Path) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    torch.save(obj, temp_path)
    try:
        temp_path.replace(path)
    except PermissionError:
        torch.save(obj, path)
        try:
            temp_path.unlink()
        except OSError:
            pass


def _sample_text(text: str, max_chars: int) -> str:
    """Return up to max_chars by pulling evenly-spaced windows across the full text."""
    if len(text) <= max_chars:
        return text
    window = 2000
    n_windows = max_chars // window
    step = max(1, (len(text) - window) // max(n_windows, 1))
    parts = [text[i : i + window] for i in range(0, len(text) - window, step)][:n_windows]
    return "\n".join(parts)


def _write_text_if_changed(path: Path, contents: str) -> None:
    try:
        existing = path.read_text(encoding="utf-8")
    except OSError:
        existing = None
    if existing != contents:
        path.write_text(contents, encoding="utf-8")


def _normalize_root_chat_text(text: str) -> str:
    """
    Convert simple `User:` / `Assistant:` pairs into isolated conversation blocks.
    This gives the model a more consistent "one user turn -> one assistant turn" pattern.
    """
    pattern = re.compile(r"(?ims)^\s*user:\s*(.*?)\s*^\s*assistant:\s*(.*?)(?=^\s*user:\s*|\Z)")
    conversations: list[str] = []

    for match in pattern.finditer(text):
        user_text = match.group(1).strip()
        assistant_text = match.group(2).strip()
        if not user_text or not assistant_text:
            continue

        conversations.append(
            "\n".join(
                [
                    "<START_CONVO>",
                    "<USER>",
                    user_text,
                    "<ASSISTANT>",
                    assistant_text,
                    "<END_CONVO>",
                ]
            )
        )

    return "\n\n".join(conversations) if conversations else text


def _selected_text_paths(data_dir: Path, source_ids: list[str] | None) -> list[Path]:
    if not source_ids:
        return [
            path
            for path in sorted(data_dir.glob("*.txt"))
            if path.name not in GENERATED_TEXT_FILES
        ]

    selected = set(source_ids)
    names: set[str] = set()
    for source_id in selected:
        names.update(SOURCE_TEXT_FILES.get(source_id, []))

    paths = {data_dir / name for name in names}
    if "src_imported_docs" in selected:
        known_names = {name for names_for_source in SOURCE_TEXT_FILES.values() for name in names_for_source}
        paths.update(
            path
            for path in data_dir.glob("*.txt")
            if path.name not in known_names and path.name not in GENERATED_TEXT_FILES
        )
    return sorted(path for path in paths if path.exists())


def load_all_text(
    base_dir: Path,
    logger: Logger | None = None,
    max_training_chars: int = MAX_TRAINING_CHARS,
    source_ids: list[str] | None = None,
) -> str:
    chunks = []
    loaded_chars = 0
    raw_chars_seen = 0
    capped = False
    root_train = base_dir / ROOT_TRAIN_FILE

    def append_training_chunk(label: str, text: str) -> None:
        nonlocal loaded_chars, raw_chars_seen, capped
        if not text:
            return

        chunk = f"{label}\n{text}"
        raw_chars_seen += len(chunk)
        if max_training_chars > 0:
            remaining = max_training_chars - loaded_chars
            if remaining <= 0:
                capped = True
                return
            if len(chunk) > remaining:
                chunk = _sample_text(chunk, remaining)
                capped = True

        chunks.append(chunk)
        loaded_chars += len(chunk)

    selected = set(source_ids or [])
    include_root_train = not selected or "src_starter_knowledge" in selected

    if include_root_train and root_train.exists():
        text = root_train.read_text(encoding="utf-8").strip()
        if text:
            text = _normalize_root_chat_text(text)
            append_training_chunk("### ROOT TRAIN FILE ###", text)
            _log(logger, f"Loaded {root_train.name}")

    data_dir = base_dir / DATA_FOLDER
    data_dir.mkdir(parents=True, exist_ok=True)
    txt_paths = [] if max_training_chars > 0 and loaded_chars >= max_training_chars else _selected_text_paths(
        data_dir,
        source_ids,
    )
    if selected:
        _log(logger, f"Selected training sources: {', '.join(sorted(selected))}")
    for txt_path in txt_paths:
        try:
            text = txt_path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            _log(logger, f"Skipping TXT {txt_path.name}: {exc}")
            continue

        if text:
            append_training_chunk(f"\n\n### FILE: {txt_path.name} ###", text)
            _log(logger, f"Loaded TXT: {txt_path.name}")
            if max_training_chars > 0 and loaded_chars >= max_training_chars:
                break

    combined = "\n\n".join(chunks)
    if not combined.strip():
        raise ValueError("No training data found.")

    if max_training_chars > 0 and len(combined) > max_training_chars:
        combined = _sample_text(combined, max_training_chars)
        if len(combined) > max_training_chars:
            combined = combined[:max_training_chars]
        capped = True

    if capped:
        _log(
            logger,
            f"Dataset capped while loading: {raw_chars_seen:,}+ -> {len(combined):,} chars "
            f"(full text preserved on disk, sampled for RAM).",
        )

    _write_text_if_changed(base_dir / COMBINED_FILE, combined)
    _log(logger, f"Training dataset: {len(combined):,} characters")
    return combined


def build_dataset(text: str, base_dir: Path | None = None):
    """Encode the training corpus and split into train/val tensors.

    If ``solin_vocab.json`` already exists on disk and is a BPE vocab
    (``tokenizer_kind: "bpe"``), this uses the saved BPE encoder so the
    model trains over BPE tokens. Otherwise it falls back to the original
    character-level vocab built from the corpus itself.

    Returns ``(vocab_size, stoi, itos, train_data, val_data, tok_meta)``
    where ``tok_meta`` is ``{"kind": "char"}`` or
    ``{"kind": "bpe", "merges": [...]}``."""
    base = base_dir if base_dir is not None else Path.cwd()
    vocab_path = base / "solin_vocab.json"

    if vocab_path.exists():
        try:
            payload = json.loads(vocab_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict) and payload.get("tokenizer_kind") == "bpe":
            from solin_bpe import BPETokenizer

            merges = [tuple(p) for p in payload.get("merges") or []]
            tok = BPETokenizer(stoi=payload["stoi"], merges=merges)
            ids = tok.encode(text)
            data = torch.tensor(ids, dtype=torch.long)
            split_at = int(0.9 * len(data))
            train_data = data[:split_at]
            val_data = data[split_at:]
            if len(train_data) <= MODEL_CONFIG["block_size"] or len(val_data) <= MODEL_CONFIG["block_size"]:
                raise ValueError("Dataset too small after BPE encoding. Add more text " "or lower block_size.")
            tok_meta = {"kind": "bpe", "merges": [list(p) for p in tok.merges]}
            return tok.vocab_size, tok.stoi, tok.itos, train_data, val_data, tok_meta

    # Fallback: character-level vocab built from the corpus.
    chars = sorted(set(text))
    stoi = {char: index for index, char in enumerate(chars)}
    itos = {index: char for char, index in stoi.items()}

    def encode(value: str) -> list[int]:
        return [stoi[char] for char in value]

    data = torch.tensor(encode(text), dtype=torch.long)
    split_at = int(0.9 * len(data))
    train_data = data[:split_at]
    val_data = data[split_at:]

    if len(train_data) <= MODEL_CONFIG["block_size"] or len(val_data) <= MODEL_CONFIG["block_size"]:
        raise ValueError("Dataset too small. Add more text or lower block_size.")

    return len(chars), stoi, itos, train_data, val_data, {"kind": "char"}


def batch_size_for(device_name: str, override: int = 0) -> int:
    if override and override > 0:
        return override
    return 32 if device_name == "cpu" else 64


def get_batch(source, block_size: int, batch_size: int, device_name: str):
    positions = torch.randint(len(source) - block_size, (batch_size,))
    x = torch.stack([source[pos : pos + block_size] for pos in positions])
    y = torch.stack([source[pos + 1 : pos + block_size + 1] for pos in positions])
    return x.to(device_name), y.to(device_name)


def save_checkpoint(base_dir: Path, model, optimizer, best_loss, stoi, itos, tok_meta: dict | None = None) -> None:
    payload = {
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": optimizer.state_dict(),
        "best_loss": best_loss,
        "config": MODEL_CONFIG,
        "stoi": stoi,
        "itos": {str(index): value for index, value in itos.items()},
    }
    if tok_meta and tok_meta.get("kind") == "bpe":
        # Embed BPE state in the checkpoint so the engine can load it
        # without depending on solin_vocab.json being present.
        payload["tokenizer_kind"] = "bpe"
        payload["merges"] = tok_meta.get("merges") or []
    safe_torch_save(payload, base_dir / CHECKPOINT_FILE)


def save_best_model(
    base_dir: Path,
    model,
    last_archive_time: float = 0.0,
    min_archive_interval: float = MIN_ARCHIVE_INTERVAL_SECONDS,
) -> tuple[Path, float]:
    """Persist the best weights.

    The latest alias (`best_model.pt`) is always overwritten so the chat engine
    can pick it up via `find_model_path`. A timestamped archive is only written
    when at least `min_archive_interval` seconds have passed since the previous
    archive — this prevents the StableModels folder from growing into hundreds
    of redundant snapshots during a single training cycle (which causes the UI
    to feel like it's frozen while OneDrive sync churns through the writes).

    Returns the path of the most-recently-written file (latest alias when no
    archive snapshot was taken this call) and the updated archive timestamp.
    """
    latest_path = base_dir / BEST_MODEL_FILE
    state_dict = model.state_dict()
    safe_torch_save(state_dict, latest_path)

    now = time.monotonic()
    if last_archive_time and (now - last_archive_time) < min_archive_interval:
        return latest_path, last_archive_time

    today_folder = base_dir / STABLE_MODELS_DIR / datetime.now().strftime("%Y-%m-%d")
    today_folder.mkdir(parents=True, exist_ok=True)
    timestamped_path = today_folder / f"best_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pt"
    safe_torch_save(state_dict, timestamped_path)

    archived_models = sorted(
        today_folder.glob("best_model_*.pt"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for stale_path in archived_models[MAX_DAILY_STABLE_MODELS:]:
        try:
            stale_path.unlink()
        except OSError:
            pass
    return timestamped_path, now


def load_checkpoint_if_possible(
    base_dir: Path,
    model,
    optimizer,
    stoi,
    device_name: str,
    logger: Logger | None = None,
    fresh_start: bool = False,
    requested_learning_rate: float | None = None,
):
    checkpoint_path = base_dir / CHECKPOINT_FILE

    if fresh_start:
        _log(logger, "Fresh start enabled. Existing checkpoint will be ignored.")
        return float("inf")

    if not checkpoint_path.exists():
        _log(logger, "No checkpoint found. Starting fresh.")
        return float("inf")

    try:
        checkpoint = torch.load(checkpoint_path, map_location=device_name)
        if checkpoint.get("config") != MODEL_CONFIG:
            _log(logger, "Checkpoint config mismatch. Starting fresh.")
            return float("inf")
        if checkpoint.get("stoi") != stoi:
            _log(logger, "Checkpoint vocab mismatch. Starting fresh.")
            return float("inf")

        model.load_state_dict(checkpoint["model_state_dict"])
        optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        if requested_learning_rate is not None:
            restored_lrs = {float(group.get("lr", requested_learning_rate)) for group in optimizer.param_groups}
            for group in optimizer.param_groups:
                group["lr"] = requested_learning_rate
            if restored_lrs != {float(requested_learning_rate)}:
                restored_summary = ", ".join(f"{lr:.6g}" for lr in sorted(restored_lrs))
                _log(
                    logger,
                    "Checkpoint optimizer learning rate override detected "
                    f"({restored_summary}); using requested lr {requested_learning_rate:.6g}.",
                )
        best_loss = checkpoint.get("best_loss", float("inf"))
        _log(logger, f"Resumed from checkpoint: {checkpoint_path.name}")
        _log(logger, f"Previous best val loss: {best_loss:.4f}")
        return best_loss
    except Exception as exc:
        _log(logger, f"Failed to load checkpoint: {exc}")
        return float("inf")


def input_snapshot(base_dir: Path, pdf_folder: Path, include_pdf_folder: bool = True):
    snapshot = []

    folders = [base_dir / DATA_FOLDER]
    if include_pdf_folder:
        folders.append(pdf_folder)

    for folder in folders:
        folder.mkdir(parents=True, exist_ok=True)
        for path in sorted(folder.glob("*")):
            if path.is_file():
                stat = path.stat()
                snapshot.append((str(path.resolve()), stat.st_mtime, stat.st_size))

    root_train = base_dir / ROOT_TRAIN_FILE
    if root_train.exists():
        stat = root_train.stat()
        snapshot.append((str(root_train.resolve()), stat.st_mtime, stat.st_size))

    manifest = base_dir / MANIFEST_FILE
    if manifest.exists():
        stat = manifest.stat()
        snapshot.append((str(manifest.resolve()), stat.st_mtime, stat.st_size))

    return snapshot


def _raise_if_stopping(should_stop: Predicate | None) -> None:
    if should_stop and should_stop():
        raise InterruptedError("Training stop requested.")


def _emit_runtime_status(
    status_callback: StatusCallback | None,
    *,
    status: str,
    stage: str,
    detail: str = "",
    current_step: int = 0,
    total_steps: int = 0,
    device: str = "",
    batch_size: int = 0,
    dataset_chars: int = 0,
) -> None:
    if not status_callback:
        return
    try:
        status_callback(
            {
                "status": status,
                "stage": stage,
                "detail": detail,
                "current_step": current_step,
                "total_steps": total_steps,
                "device": device,
                "batch_size": batch_size,
                "dataset_chars": dataset_chars,
            }
        )
    except Exception:
        pass


def train_cycle(
    base_dir: Path,
    settings: TrainingSettings,
    logger: Logger | None = None,
    should_stop: Predicate | None = None,
    status_callback: StatusCallback | None = None,
) -> None:
    device_info = detect_best_device(settings.device_preference)
    device_name = device_info.name
    batch_size = batch_size_for(device_name, settings.batch_size_override)

    # If CUDA OOMs mid-cycle, retry transparently on CPU.
    if device_name == "cuda":
        try:
            _train_cycle_inner(base_dir, settings, logger, should_stop, device_name, batch_size, status_callback)
        except torch.cuda.OutOfMemoryError:
            torch.cuda.empty_cache()
            _log(logger, "CUDA out of memory — retrying on CPU.")
            _train_cycle_inner(base_dir, settings, logger, should_stop, "cpu", batch_size_for("cpu"), status_callback)
        except Exception as exc:
            if _is_retryable_cuda_failure(exc):
                try:
                    torch.cuda.empty_cache()
                except Exception:
                    pass
                _log(logger, f"CUDA runtime is not usable on this system ({exc}) — retrying on CPU.")
                _train_cycle_inner(
                    base_dir, settings, logger, should_stop, "cpu", batch_size_for("cpu"), status_callback
                )
            else:
                raise
        return

    _train_cycle_inner(base_dir, settings, logger, should_stop, device_name, batch_size, status_callback)


def _train_cycle_inner(
    base_dir: Path,
    settings: TrainingSettings,
    logger: Logger | None,
    should_stop: Predicate | None,
    device_name: str,
    batch_size: int,
    status_callback: StatusCallback | None = None,
) -> None:
    _log(logger, f"Training device: {device_name}")
    _log(logger, f"Batch size: {batch_size}")
    _emit_runtime_status(
        status_callback,
        status="preparing",
        stage="loading_dataset",
        detail="Reading train.txt and extracted data files.",
        device=device_name,
        batch_size=batch_size,
    )

    _raise_if_stopping(should_stop)
    text = load_all_text(
        base_dir,
        logger=logger,
        max_training_chars=settings.dataset_char_cap,
        source_ids=settings.source_ids,
    )
    _raise_if_stopping(should_stop)
    _emit_runtime_status(
        status_callback,
        status="preparing",
        stage="building_dataset",
        detail="Building vocabulary and train/validation tensors.",
        device=device_name,
        batch_size=batch_size,
        dataset_chars=len(text),
    )
    vocab_size, stoi, itos, train_data, val_data, tok_meta = build_dataset(text, base_dir=base_dir)
    _raise_if_stopping(should_stop)

    # For char vocab we (re)write solin_vocab.json from the corpus. For BPE
    # we leave the user's pre-trained vocab file untouched — overwriting it
    # with char-style stoi/itos would corrupt the BPE merges.
    if tok_meta.get("kind") == "char":
        save_vocab(stoi, itos, base_dir / "solin_vocab.json")
    save_config(MODEL_CONFIG, base_dir / "solin_config.json")

    _emit_runtime_status(
        status_callback,
        status="preparing",
        stage="initializing_model",
        detail="Creating model and optimizer.",
        device=device_name,
        batch_size=batch_size,
        dataset_chars=len(text),
    )
    model = TinyGPT(vocab_size, MODEL_CONFIG).to(device_name)
    optimizer = torch.optim.AdamW(model.parameters(), lr=settings.learning_rate)
    best_loss = load_checkpoint_if_possible(
        base_dir=base_dir,
        model=model,
        optimizer=optimizer,
        stoi=stoi,
        device_name=device_name,
        logger=logger,
        fresh_start=settings.fresh_start,
        requested_learning_rate=settings.learning_rate,
    )

    val_settings = settings.validation or ValidationMonitorSettings()
    # Early-stopping tracks improvement WITHIN this cycle so a pre-existing
    # all-time best (loaded from checkpoint) does not trigger an instant stop.
    cycle_best_val = float("inf")
    status = ValidationStatus(
        patience=val_settings.patience,
        best_val_loss=None if best_loss == float("inf") else best_loss,
        status="running",
        stage="running",
        detail="Running optimization steps.",
        current_step=0,
        total_steps=max(1, settings.max_iters),
        device=device_name,
        batch_size=batch_size,
        dataset_chars=len(text),
    )
    no_improve_count = 0
    # Keep best weights in memory so restore_best works even when save_best_only is off.
    best_state: dict | None = None
    last_archive_time = 0.0

    def emit_status() -> None:
        if status_callback:
            try:
                status_callback(status.as_dict())
            except Exception:
                pass

    emit_status()

    early_stopped = False
    total_steps = max(1, settings.max_iters)
    live_emit_interval = max(1, min(max(1, settings.eval_interval), 10))

    for step in range(total_steps):
        if should_stop and should_stop():
            save_checkpoint(base_dir, model, optimizer, best_loss, stoi, itos, tok_meta)
            status.status = "stopped"
            status.stage = "stopped"
            status.stop_reason = "user_stop"
            status.detail = "Training was stopped by the user."
            emit_status()
            _log(logger, "Stop requested mid-cycle. Saved checkpoint before exiting.")
            raise InterruptedError("Training stop requested.")

        xb, yb = get_batch(
            train_data,
            int(MODEL_CONFIG["block_size"]),
            batch_size,
            device_name,
        )
        _, loss = model(xb, yb)

        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), MAX_GRAD_NORM)
        optimizer.step()

        train_loss_live = float(loss.item())
        status.epoch = step
        status.current_step = step + 1
        status.train_loss = train_loss_live
        if step % live_emit_interval == 0:
            emit_status()

        is_eval_step = step % max(1, settings.eval_interval) == 0 or step == total_steps - 1
        if is_eval_step:
            with torch.no_grad():
                vx, vy = get_batch(
                    val_data,
                    int(MODEL_CONFIG["block_size"]),
                    batch_size,
                    device_name,
                )
                _, vloss = model(vx, vy)

            train_loss_val = train_loss_live
            val_loss_val = float(vloss.item())
            _log(logger, f"step {step}: train {train_loss_val:.4f}, val {val_loss_val:.4f}")

            status.train_loss = train_loss_val
            status.val_loss = val_loss_val

            improved_cycle = val_loss_val < cycle_best_val - val_settings.min_delta
            if improved_cycle:
                cycle_best_val = val_loss_val
                no_improve_count = 0
                # Always capture best weights in memory for potential restore.
                best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
                # Persist to disk only when this beats the all-time best_loss.
                if val_loss_val < best_loss:
                    best_loss = val_loss_val
                    if val_settings.save_best_only:
                        saved_best_path, last_archive_time = save_best_model(
                            base_dir, model, last_archive_time=last_archive_time
                        )
                        save_checkpoint(base_dir, model, optimizer, best_loss, stoi, itos, tok_meta)
                        status.last_checkpoint = saved_best_path.name
                        _log(logger, f"Saved best model -> {saved_best_path.name} (latest alias: {BEST_MODEL_FILE})")
                status.best_val_loss = best_loss if best_loss != float("inf") else val_loss_val
                status.no_improve_count = 0
            else:
                no_improve_count += 1
                status.no_improve_count = no_improve_count

            emit_status()

            if val_settings.auto_stop and no_improve_count >= val_settings.patience:
                status.stop_reason = "early_stopping"
                status.status = "stopped"
                status.stage = "early_stopping"
                status.detail = "Stopped after validation loss stopped improving."
                _log(
                    logger,
                    f"Early stopping: no improvement in {no_improve_count} eval(s) "
                    f"(patience {val_settings.patience}).",
                )
                if val_settings.restore_best and best_state is not None:
                    model.load_state_dict(best_state)
                    _log(logger, "Restored best model weights.")
                emit_status()
                early_stopped = True
                break

    # At clean training end, optionally restore best weights before saving final checkpoint.
    if not early_stopped and val_settings.restore_best and best_state is not None:
        model.load_state_dict(best_state)
        _log(logger, "Restored best model weights at end of cycle.")

    save_checkpoint(base_dir, model, optimizer, best_loss, stoi, itos, tok_meta)
    if not early_stopped:
        status.status = "completed"
        status.stage = "completed"
        status.detail = "Training cycle finished successfully."
        if not status.stop_reason:
            status.stop_reason = "max_iters"
    emit_status()
    _log(logger, "Cycle complete")


def _wait_while_paused(
    should_pause: Predicate | None,
    should_stop: Predicate | None,
    logger: Logger | None = None,
) -> None:
    if not should_pause:
        return

    announced = False
    while should_pause():
        _raise_if_stopping(should_stop)
        if not announced:
            _log(logger, "Training watch paused. Waiting to resume...")
            announced = True
        time.sleep(0.25)

    if announced:
        _log(logger, "Training watch resumed.")


def _sleep_with_controls(
    seconds: float,
    should_stop: Predicate | None = None,
    should_pause: Predicate | None = None,
    logger: Logger | None = None,
    label: str = "Sleeping",
) -> None:
    seconds = max(0.0, float(seconds))
    if seconds <= 0:
        return

    _log(logger, f"{label} {seconds:.1f} second(s)...")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        _raise_if_stopping(should_stop)
        _wait_while_paused(should_pause, should_stop, logger=logger)
        remaining = deadline - time.monotonic()
        time.sleep(min(0.25, max(remaining, 0.0)))


def run_training_loop(
    base_dir: str | Path,
    settings: TrainingSettings,
    logger: Logger | None = None,
    should_stop: Predicate | None = None,
    should_pause: Predicate | None = None,
    on_cycle_complete: CycleCallback | None = None,
    status_callback: StatusCallback | None = None,
) -> None:
    root = Path(base_dir)
    pdf_folder = Path(settings.pdf_folder) if settings.pdf_folder else resolve_default_pdf_folder(root)
    last_snapshot = None
    cycles_completed = 0
    fresh_start_pending = settings.fresh_start

    _log(logger, "GreyIQ trainer started")
    _log(logger, f"Working folder: {root}")
    _log(logger, f"Watching PDFs in: {pdf_folder}")
    _log(logger, f"Watching TXT in: {root / DATA_FOLDER}")
    _log(logger, f"Watching root file: {root / ROOT_TRAIN_FILE}")
    _log(logger, f"Mode: {'continuous' if settings.continuous else 'single cycle'}")
    _log(logger, f"Trigger mode: {settings.trigger_mode}")
    _log(logger, f"Max cycles: {'unlimited' if settings.max_cycles <= 0 else settings.max_cycles}")
    _log(logger, f"Idle sleep: {settings.idle_sleep_seconds:.1f}s")
    _log(logger, f"Post-cycle cooldown: {settings.post_cycle_sleep_seconds:.1f}s")
    _log(logger, f"Skip PDF ingest: {settings.skip_pdf_ingest}")
    _log(
        logger,
        "Dataset cap: " + ("disabled" if settings.dataset_char_cap <= 0 else f"{settings.dataset_char_cap:,} chars"),
    )
    _emit_runtime_status(
        status_callback,
        status="starting",
        stage="initializing",
        detail="Preparing training session.",
        total_steps=max(1, settings.max_iters),
    )

    while True:
        try:
            _wait_while_paused(should_pause, should_stop, logger=logger)
            _raise_if_stopping(should_stop)

            pdf_changes = False
            if not settings.skip_pdf_ingest:

                def on_ingest_progress(data: dict[str, Any]) -> None:
                    current = int(data.get("current") or 0)
                    total = int(data.get("total") or 0)
                    source_name = str(data.get("source_name") or "PDF")
                    status_label = str(data.get("status") or "processing").replace("_", " ")
                    detail = f"{status_label.title()}: {source_name}"
                    _emit_runtime_status(
                        status_callback,
                        status="preparing",
                        stage="checking_sources",
                        detail=detail,
                        current_step=current,
                        total_steps=total,
                    )

                _emit_runtime_status(
                    status_callback,
                    status="preparing",
                    stage="checking_sources",
                    detail="Scanning PDFs and watching for new training data.",
                    total_steps=0,
                )
                ingest_results = ingest_pdf_folder(
                    pdf_folder=pdf_folder,
                    output_folder=root / DATA_FOLDER,
                    manifest_path=root / MANIFEST_FILE,
                    method=settings.method,
                    logger=logger,
                    progress_callback=on_ingest_progress,
                )
                pdf_changes = any(result.status in {"converted", "removed"} for result in ingest_results)

            current_snapshot = input_snapshot(root, pdf_folder, include_pdf_folder=not settings.skip_pdf_ingest)
            should_train = (
                settings.trigger_mode == "always"
                or last_snapshot is None
                or pdf_changes
                or current_snapshot != last_snapshot
            )

            if should_train:
                reason = "Always mode" if settings.trigger_mode == "always" else "Change detected"
                _log(logger, f"\n{reason} -> training cycle starting")
                _emit_runtime_status(
                    status_callback,
                    status="preparing",
                    stage="starting_cycle",
                    detail=reason,
                    total_steps=max(1, settings.max_iters),
                )
                cycle_settings = replace(settings, fresh_start=fresh_start_pending)
                train_cycle(
                    base_dir=root,
                    settings=cycle_settings,
                    logger=logger,
                    should_stop=should_stop,
                    status_callback=status_callback,
                )
                last_snapshot = current_snapshot
                cycles_completed += 1
                fresh_start_pending = False
                if on_cycle_complete:
                    on_cycle_complete(cycles_completed)
            else:
                _log(logger, "No changes detected")
                _emit_runtime_status(
                    status_callback,
                    status="watching",
                    stage="waiting_for_changes",
                    detail="No source changes detected yet.",
                    current_step=cycles_completed,
                    total_steps=max(1, settings.max_cycles) if settings.max_cycles > 0 else 0,
                )

            if not settings.continuous:
                break

            if settings.max_cycles > 0 and cycles_completed >= settings.max_cycles:
                _log(logger, f"Reached max cycles: {settings.max_cycles}")
                _emit_runtime_status(
                    status_callback,
                    status="completed",
                    stage="completed",
                    detail=f"Reached max cycles: {settings.max_cycles}.",
                    current_step=cycles_completed,
                    total_steps=max(1, settings.max_cycles),
                )
                break

            sleep_seconds = settings.post_cycle_sleep_seconds if should_train else settings.idle_sleep_seconds
            label = "Cooling down for" if should_train else "Waiting for next watch check for"
            _sleep_with_controls(
                sleep_seconds,
                should_stop=should_stop,
                should_pause=should_pause,
                logger=logger,
                label=label,
            )

        except InterruptedError:
            _log(logger, "Training stopped.")
            _emit_runtime_status(
                status_callback,
                status="stopped",
                stage="stopped",
                detail="Training session stopped.",
                total_steps=max(1, settings.max_iters),
            )
            break
        except Exception as exc:
            _log(logger, f"Error: {exc}")
            _log(logger, traceback.format_exc())
            _emit_runtime_status(
                status_callback,
                status="error",
                stage="error",
                detail=str(exc),
                total_steps=max(1, settings.max_iters),
            )
            if not settings.continuous:
                raise
            _sleep_with_controls(
                settings.idle_sleep_seconds,
                should_stop=should_stop,
                should_pause=should_pause,
                logger=logger,
                label="Retrying after",
            )
