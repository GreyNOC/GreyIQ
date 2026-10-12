"""``gn train-coder`` — train the local coding brain (TinyGPT) on your own folders, from a terminal.

GreyIQ had two trainable brains and one of them was unreachable outside the desktop app. ``gn
train-brain`` has always trained the HUNT ranker from hunt traces; the coding brain, the TinyGPT that
answers in chat and drafts the offline coder's text, could only be trained by clicking a button in the
Studio. So on a headless box — the CLI tarball ships exactly that, and it is where an operator
actually runs long jobs — the corpus could not be extended and the model could not be trained at all.

This verb closes that, and adds the thing the Studio never had: **arbitrary directories as the
corpus.** Point it at folders of PDFs, Markdown, source, docs or notes and it extracts them into the
training corpus first, then trains on the result:

    gn train-coder ~/research ~/rfcs --steps 4000 --size standard
    gn train-coder --show                     # corpus + active model + presets, no training
    gn train-coder ~/notes --dry-run          # ingest and report, train nothing
    gn train-coder --steps 2000 --fresh --size large --device gpu

Three structural rules, in descending order of how badly breaking them would hurt:

  * **``--show`` and ``--dry-run`` are torch-free.** The whole CLI is torch-free by design (the frozen
    build excludes torch, ``test_boot_no_torch`` proves the app degrades without it), so inspecting the
    corpus and planning a run must work on a machine that can never train. Only the training path
    imports torch, and it says plainly what to install if it is absent.
  * **Registration is import-light.** ``register_cli`` runs on every ``import gn_cli``, including the
    frozen backend's API-server start, so every engine import lives inside the command function — the
    ``_cmd_traces`` convention the CLI's own docstring sets out.
  * **It cannot silently replace a trained model.** The default preset is ``compact``, the shipped
    checkpoint's shape, so a default run RESUMES and improves the existing weights. A different
    ``--size`` starts a new lineage from random weights because a different shape cannot load old
    ones, so that path prints what it is about to do and requires ``--yes`` to proceed unattended.
    ``training_runtime.save_best_model`` archives the outgoing lineage either way.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# Deliberately NOT imported here: training_runtime (imports torch at module scope), document_ingest
# (pulls pypdf/Pillow), gn_fx. All three are imported inside the command body.

_VERB = "train-coder"
_DEFAULT_STEPS = 2000
_DEFAULT_EVAL_INTERVAL = 200


def _resolve_dirs() -> tuple[Path, Path]:
    """(runtime_dir, seed_dir), asking gn_cli so a frozen build and a dev checkout agree."""
    try:
        import gn_cli

        return Path(gn_cli.RUNTIME_DIR), Path(gn_cli.SEED_DIR)
    except Exception:  # noqa: BLE001 - the trainer must still run if the CLI module is unavailable
        backend = Path(__file__).resolve().parent
        runtime = Path(os.getenv("GREYIQ_RUNTIME_DIR", str(backend.parent / "runtime"))).resolve()
        return runtime, backend / "seed"


def _torch_available() -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec("torch") is not None
    except Exception:  # noqa: BLE001 - an unanswerable probe means "not available" (fail closed)
        return False


def _human_bytes(count: int) -> str:
    size = float(max(0, int(count)))
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# --- corpus inspection (torch-free) --------------------------------------------------------------
def corpus_status(runtime_dir: Path, seed_dir: Path | None = None) -> dict[str, Any]:
    """What the coder brain would train on, and which model is active — without importing torch.

    Reads the same layout ``training_runtime`` does (``<runtime>/data/*.txt`` plus ``train.txt``) by
    walking the filesystem rather than calling ``collect_dataset_stats``, because that module imports
    torch at module scope and this has to answer on a machine that cannot train.
    """
    data_dir = runtime_dir / "data"
    text_files: list[dict[str, Any]] = []
    total = 0
    if data_dir.is_dir():
        for path in sorted(data_dir.glob("*.txt")):
            try:
                size = path.stat().st_size
            except OSError:
                continue
            total += size
            text_files.append({"name": path.name, "characters": size})
    root_train = runtime_dir / "train.txt"
    root_chars = 0
    if root_train.is_file():
        try:
            root_chars = root_train.stat().st_size
        except OSError:
            root_chars = 0

    # The active checkpoint, found by name so no torch load is needed to report it.
    active = None
    for candidate in (runtime_dir / "best_model.pt", runtime_dir / "solin_checkpoint.pt"):
        if candidate.is_file():
            active = candidate
            break
    if active is None and seed_dir is not None and (seed_dir / "best_model.pt").is_file():
        active = seed_dir / "best_model.pt"

    published: dict[str, Any] = {}
    config_path = runtime_dir / "solin_config.json"
    if config_path.is_file():
        try:
            published = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            published = {}

    return {
        "runtime_dir": str(runtime_dir),
        "data_dir": str(data_dir),
        "text_files": text_files,
        "extracted_files": len(text_files),
        "extracted_characters": total,
        "root_train_characters": root_chars,
        "total_characters": total + root_chars,
        "active_model": str(active) if active else None,
        "active_model_source": ("runtime" if active and seed_dir and seed_dir not in active.parents
                                else "seed" if active else ""),
        "published_config": published,
        "torch_available": _torch_available(),
    }


def _print_status(status: dict[str, Any], presets: dict[str, dict[str, Any]], default_size: str) -> None:
    active = status["active_model"]
    if active:
        print(f"active model: {active} ({status['active_model_source']})")
        config = status.get("published_config") or {}
        if config:
            shape = "  ".join(f"{key}={config[key]}" for key in
                              ("block_size", "n_embd", "n_head", "n_layer") if key in config)
            if shape:
                print(f"  shape:      {shape}")
    else:
        print("active model: none — GreyIQ ships a compact seed checkpoint; a runtime model appears "
              "only once you train one.")

    print(f"corpus: {status['extracted_files']} text file(s), "
          f"{_human_bytes(status['extracted_characters'])} extracted"
          + (f" + {_human_bytes(status['root_train_characters'])} in train.txt"
             if status["root_train_characters"] else ""))
    if not status["total_characters"]:
        print("  empty — pass one or more directories to ingest, e.g. "
              "`gn train-coder ~/research ~/rfcs`.")
    for entry in status["text_files"][:8]:
        print(f"    {entry['name']:<34} {_human_bytes(entry['characters'])}")
    if len(status["text_files"]) > 8:
        print(f"    … and {len(status['text_files']) - 8} more")

    print("brain sizes:")
    for name, config in presets.items():
        mark = " (default, resumes the shipped checkpoint)" if name == default_size else ""
        print(f"  {name:<10} block={config['block_size']:<4} embd={config['n_embd']:<4} "
              f"head={config['n_head']:<3} layer={config['n_layer']}{mark}")
    if not status["torch_available"]:
        print("torch: NOT installed — `--show` and `--dry-run` work without it, training does not. "
              "Install it with `pip install torch` (CPU-only: "
              "`pip install torch --index-url https://download.pytorch.org/whl/cpu`).")


# --- ingestion ----------------------------------------------------------------------------------
#: Extensions this module reads by itself, with no third-party dependency. Kept in step with
#: document_ingest.TEXT_EXTENSIONS by a test, not by hand.
TEXT_EXTENSIONS = frozenset({
    ".txt", ".md", ".rst", ".csv", ".tsv", ".json", ".yaml", ".yml", ".log", ".ini", ".cfg",
    ".conf", ".toml", ".xml", ".html", ".htm", ".css", ".sql", ".bat", ".ps1", ".py", ".js",
    ".ts", ".jsx", ".tsx",
})
#: Extensions that genuinely need an extractor (pypdf / Pillow+tesseract / python-docx).
BINARY_EXTENSIONS = frozenset({
    ".pdf", ".docx", ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp",
})
_MAX_TEXT_FILE_BYTES = 25 * 1024 * 1024


def _read_text(path: Path) -> str:
    """A source file's text, tolerating whatever encoding it was saved in.

    Survey and note files are written in every encoding there is; a UnicodeDecodeError here would
    lose a whole folder, so this degrades to replacement characters exactly as the rest of the
    codebase does for untrusted text (walker.py, wardrive/parsers.py).
    """
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return path.read_bytes().decode("latin-1", errors="replace")


def _ingest(dirs: list[str], runtime_dir: Path, *, recursive: bool, emit: Any) -> dict[str, Any]:
    """Extract every supported document under each directory into the training corpus.

    Split deliberately in two. TEXT files are read and written here with nothing but the standard
    library, because ``document_ingest`` imports pypdf at MODULE scope — so on a minimal install
    (which is exactly the headless CLI tarball this verb exists for) pointing at a folder of notes or
    source used to die with ``No module named 'pypdf'`` for files that need no PDF library at all.
    Only an actual PDF, DOCX or image reaches ``document_ingest``, and if that import fails those
    files are reported as skipped-with-a-reason while every text file still lands.
    """
    data_dir = runtime_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {"directories": [], "ingested": 0, "skipped": 0, "failed": 0,
                               "text_extensions": sorted(TEXT_EXTENSIONS),
                               "binary_extensions": sorted(BINARY_EXTENSIONS),
                               "extractor_available": None}

    for raw in dirs:
        folder = Path(raw).expanduser()
        entry: dict[str, Any] = {"path": str(folder)}
        if not folder.is_dir():
            entry["error"] = "not a directory"
            summary["directories"].append(entry)
            summary["failed"] += 1
            continue

        walker = folder.rglob("*") if recursive else folder.glob("*")
        text_files: list[Path] = []
        binary_files: list[Path] = []
        for path in sorted(walker):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix in TEXT_EXTENSIONS:
                text_files.append(path)
            elif suffix in BINARY_EXTENSIONS:
                binary_files.append(path)

        emit(f"ingesting {folder} ({len(text_files)} text, {len(binary_files)} document)")
        ok = skipped = failed = 0

        # One .txt per source directory, so re-running replaces rather than duplicating, and the
        # corpus stays inspectable by name in `--show`.
        if text_files:
            chunks: list[str] = []
            for path in text_files:
                try:
                    if path.stat().st_size > _MAX_TEXT_FILE_BYTES:
                        skipped += 1
                        continue
                    body = _read_text(path).strip()
                except OSError:
                    failed += 1
                    continue
                if not body:
                    skipped += 1
                    continue
                # Name each chunk, so the model sees where a passage came from and a human can grep it.
                try:
                    label = path.relative_to(folder).as_posix()
                except ValueError:
                    label = path.name
                chunks.append(f"# {label}\n{body}\n")
                ok += 1
            if chunks:
                out = data_dir / f"gn_corpus_{_slug(folder)}.txt"
                try:
                    out.write_text("\n".join(chunks), encoding="utf-8")
                    entry["text_output"] = str(out)
                except OSError as exc:
                    entry["error"] = f"could not write {out}: {exc}"
                    failed += ok
                    ok = 0

        if binary_files:
            try:
                import document_ingest

                summary["extractor_available"] = True
            except Exception as exc:  # noqa: BLE001 - a missing extractor costs those files, not the run
                summary["extractor_available"] = False
                entry["documents_skipped"] = len(binary_files)
                entry["documents_reason"] = (
                    f"{len(binary_files)} PDF/DOCX/image file(s) need the document extractor, which is "
                    f"not available here ({type(exc).__name__}: {exc}). Every text file was still "
                    "ingested. Install the extras with `pip install -r requirements.txt`."
                )
                emit(entry["documents_reason"])
                skipped += len(binary_files)
                document_ingest = None  # type: ignore[assignment]
            if binary_files and summary["extractor_available"]:
                try:
                    results = document_ingest.ingest_source_files(
                        source_files=binary_files,
                        output_folder=data_dir,
                        manifest_path=runtime_dir / "pdf_manifest.json",
                        logger=emit,
                    )
                except Exception as exc:  # noqa: BLE001 - one bad folder must not lose the others
                    entry["documents_error"] = f"{type(exc).__name__}: {exc}"
                    failed += len(binary_files)
                else:
                    for result in results:
                        status = str(getattr(result, "status", "")).lower()
                        if status in {"ok", "written", "extracted", "processed"}:
                            ok += 1
                        elif status in {"skipped", "reused", "cached", "unchanged"}:
                            skipped += 1
                        else:
                            failed += 1

        entry.update({"files": len(text_files) + len(binary_files),
                      "ingested": ok, "skipped": skipped, "failed": failed})
        summary["directories"].append(entry)
        summary["ingested"] += ok
        summary["skipped"] += skipped
        summary["failed"] += failed
    return summary


def _slug(folder: Path) -> str:
    """A stable, filesystem-safe name for a source directory, so a re-run overwrites its own chunk."""
    import hashlib

    raw = str(folder.resolve())
    stem = "".join(ch if ch.isalnum() else "-" for ch in folder.name).strip("-").lower() or "corpus"
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"{stem[:40]}-{digest}"


# --- the command --------------------------------------------------------------------------------
def _cmd_train_coder(args: argparse.Namespace) -> int:
    runtime_dir, seed_dir = _resolve_dirs()
    as_json = bool(getattr(args, "json", False))
    dirs = [str(d) for d in (getattr(args, "dirs", None) or [])]

    # --- inspect only (torch-free) --------------------------------------------------------------
    if getattr(args, "show", False):
        presets, default_size = _presets()
        status = corpus_status(runtime_dir, seed_dir)
        if as_json:
            print(json.dumps({**status, "presets": presets, "default_size": default_size},
                             indent=2, default=str))
            return 0
        _print_status(status, presets, default_size)
        return 0

    fx = _scanner(args, "train-coder")
    fx.start()
    emit = _emitter(args, fx)

    ingest_summary: dict[str, Any] = {}
    if dirs:
        fx.phase("ingesting documents")
        ingest_summary = _ingest(dirs, runtime_dir, recursive=not getattr(args, "no_recursive", False),
                                 emit=emit)

    status = corpus_status(runtime_dir, seed_dir)
    if not status["total_characters"]:
        fx.stop()
        return _fail("the training corpus is empty. Pass one or more directories to ingest, e.g. "
                     "`gn train-coder ~/research`, or add text under "
                     f"{status['data_dir']}.", as_json)

    presets, default_size = _presets()
    size = str(getattr(args, "size", default_size) or default_size).strip().lower()
    if size not in presets:
        fx.stop()
        return _fail(f"unknown brain size {size!r}. Choose one of: {', '.join(presets)}.", as_json)

    # A different architecture cannot resume the existing weights, so say so before spending an hour.
    changes_lineage = _would_change_lineage(status, presets[size]) or bool(getattr(args, "fresh", False))
    plan = {
        "size": size,
        "config": presets[size],
        "steps": int(getattr(args, "steps", _DEFAULT_STEPS)),
        "eval_interval": int(getattr(args, "eval_interval", _DEFAULT_EVAL_INTERVAL)),
        "learning_rate": float(getattr(args, "lr", 3e-4)),
        "batch_size_override": int(getattr(args, "batch", 0)),
        "device_preference": str(getattr(args, "device", "auto") or "auto"),
        "dataset_char_cap": int(getattr(args, "cap", 0)) or None,
        "fresh_start": bool(getattr(args, "fresh", False)),
        "starts_new_lineage": changes_lineage,
        "corpus_characters": status["total_characters"],
        "ingest": ingest_summary,
    }

    if getattr(args, "dry_run", False):
        fx.stop()
        if as_json:
            print(json.dumps({"dry_run": True, "plan": plan, "corpus": status}, indent=2, default=str))
            return 0
        _print_plan(plan, status)
        print("dry run — nothing was trained.")
        return 0

    if changes_lineage and not getattr(args, "yes", False):
        fx.stop()
        return _fail(
            f"training at size {size!r} starts a NEW lineage from random weights — a different "
            "architecture cannot resume the existing checkpoint, so the model will be untrained until "
            "this run finishes. The outgoing lineage is archived under StableModels/superseded first. "
            "Re-run with --yes to confirm, or use --size compact to resume and improve the current "
            "model.", as_json)

    if not _torch_available():
        fx.stop()
        return _fail("training the coding brain needs torch, which is not installed here. "
                     "`gn train-coder --show` and `--dry-run` work without it. Install with "
                     "`pip install torch --index-url https://download.pytorch.org/whl/cpu`.", as_json)

    # --- train ----------------------------------------------------------------------------------
    import training_runtime

    settings = training_runtime.TrainingSettings(
        method="auto",
        continuous=False,
        max_cycles=1,
        max_iters=plan["steps"],
        eval_interval=plan["eval_interval"],
        learning_rate=plan["learning_rate"],
        skip_pdf_ingest=True,        # this verb ingested already, and did it from the operator's dirs
        device_preference=plan["device_preference"],
        batch_size_override=plan["batch_size_override"],
        dataset_char_cap=plan["dataset_char_cap"] or training_runtime.MAX_TRAINING_CHARS,
        fresh_start=plan["fresh_start"],
        model_size=size,
        validation=training_runtime.ValidationMonitorSettings(
            patience=int(getattr(args, "patience", 3)),
            min_delta=float(getattr(args, "min_delta", 1e-4)),
            auto_stop=not getattr(args, "no_auto_stop", False),
            save_best_only=not getattr(args, "save_every", False),
            restore_best=not getattr(args, "no_restore_best", False),
        ),
    )

    fx.phase(f"training {size} ({plan['steps']} steps)")
    if not as_json:
        _print_plan(plan, status)
    final: dict[str, Any] = {}

    def _status(payload: dict[str, Any]) -> None:
        final.update(payload if isinstance(payload, dict) else {})
        step, total = payload.get("step"), payload.get("total_steps") or plan["steps"]
        loss = payload.get("val_loss") or payload.get("loss")
        bits = [f"step {step}/{total}"] if step else []
        if loss is not None:
            bits.append(f"loss {loss}")
        if payload.get("device"):
            bits.append(str(payload["device"]))
        if bits:
            fx.phase("  ".join(bits))

    try:
        training_runtime.train_cycle(runtime_dir, settings, logger=emit, status_callback=_status)
    except KeyboardInterrupt:
        fx.stop()
        return _fail("interrupted — the best checkpoint so far is kept.", as_json)
    except Exception as exc:  # noqa: BLE001 - report, never traceback-dump
        fx.stop()
        return _fail(f"training failed: {type(exc).__name__}: {exc}", as_json)

    fx.stop()
    after = corpus_status(runtime_dir, seed_dir)
    if as_json:
        print(json.dumps({"ok": True, "plan": plan, "status": final, "model": after}, indent=2, default=str))
        return 0
    print(f"trained: {after['active_model'] or '(no checkpoint written)'}")
    if final.get("stop_reason"):
        print(f"  stopped: {final['stop_reason']}")
    for key, label in (("best_val_loss", "best val loss"), ("device", "device"), ("batch_size", "batch")):
        if final.get(key) is not None:
            print(f"  {label}: {final[key]}")
    return 0


def _presets() -> tuple[dict[str, dict[str, Any]], str]:
    """MODEL_PRESETS without importing torch — training_runtime imports it at module scope.

    Parsed from the module source rather than duplicated here, so a preset added there shows up in
    ``--show`` with no second place to update. Falls back to importing the module (which needs torch)
    only if the parse fails.
    """
    import ast

    source = (Path(__file__).resolve().parent / "training_runtime.py")
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"))
        presets: dict[str, dict[str, Any]] = {}
        default = "compact"
        for node in tree.body:
            targets = getattr(node, "targets", None) or ([node.target] if hasattr(node, "target") else [])
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            if "MODEL_PRESETS" in names and node.value is not None:
                presets = ast.literal_eval(node.value)
            elif "DEFAULT_MODEL_SIZE" in names and node.value is not None:
                default = ast.literal_eval(node.value)
        if presets:
            return presets, default
    except (OSError, SyntaxError, ValueError):
        pass
    import training_runtime

    return dict(training_runtime.MODEL_PRESETS), training_runtime.DEFAULT_MODEL_SIZE


def _would_change_lineage(status: dict[str, Any], config: dict[str, Any]) -> bool:
    """True when the chosen architecture cannot resume the published one."""
    published = status.get("published_config") or {}
    if not published or not status.get("active_model"):
        return False
    for key in ("block_size", "n_embd", "n_head", "n_layer"):
        if key in published and published[key] != config.get(key):
            return True
    return False


def _print_plan(plan: dict[str, Any], status: dict[str, Any]) -> None:
    config = plan["config"]
    print(f"plan: size {plan['size']} (block={config['block_size']} embd={config['n_embd']} "
          f"head={config['n_head']} layer={config['n_layer']})")
    print(f"  steps {plan['steps']}, eval every {plan['eval_interval']}, lr {plan['learning_rate']}, "
          f"device {plan['device_preference']}")
    print(f"  corpus {_human_bytes(plan['corpus_characters'])} across {status['extracted_files']} file(s)")
    ingest = plan.get("ingest") or {}
    if ingest:
        print(f"  ingested {ingest.get('ingested', 0)} file(s), reused {ingest.get('skipped', 0)}, "
              f"failed {ingest.get('failed', 0)}")
        for entry in ingest.get("directories") or []:
            if entry.get("error"):
                print(f"    {entry['path']}: {entry['error']}")
    if plan["starts_new_lineage"]:
        print("  NEW LINEAGE: random weights (the existing checkpoint is archived, not overwritten)")
    else:
        print("  resuming the existing checkpoint")


def _fail(message: str, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"ok": False, "error": message}, indent=2))
    else:
        print(f"gn: {message}", file=sys.stderr)
    return 2


def _scanner(args: argparse.Namespace, title: str) -> Any:
    try:
        import gn_fx

        off = bool(getattr(args, "no_fx", False)) or bool(getattr(args, "json", False))
        return gn_fx.scanner(title, active=False if off else None)
    except Exception:  # noqa: BLE001 - a missing decoration must never stop a training run
        class _Inert:
            active = False

            def start(self) -> "_Inert":
                return self

            def phase(self, _text: str) -> None:
                return None

            def note(self, _text: str) -> None:
                return None

            def hit(self, _severity: str, _text: str = "") -> None:
                return None

            def stop(self, _summary: str = "") -> None:
                return None

        return _Inert()


def _emitter(args: argparse.Namespace, fx: Any) -> Any:
    """The trainer's logger: the live line for a human, the historical stdout for everyone else."""
    if getattr(args, "json", False):
        return lambda _message: None
    if getattr(fx, "active", False):
        def _live(message: str) -> None:
            fx.phase(str(message))
            fx.note(str(message))
        return _live
    return lambda message: print(f"  - {message}")


def register_cli(sub: Any) -> None:
    """gn_cli plugin hook. MUST stay import-light — this runs on every ``import gn_cli``."""
    parser = sub.add_parser(
        _VERB,
        help="train the local coding brain (TinyGPT) on your own folders of documents and code")
    parser.add_argument("dirs", nargs="*", metavar="DIR",
                        help="directories to extract into the training corpus before training "
                             "(PDF, DOCX, Markdown, text, source — see --show for the full list)")
    parser.add_argument("--show", action="store_true",
                        help="print the corpus, the active model and the brain sizes, then exit "
                             "(works without torch)")
    parser.add_argument("--dry-run", action="store_true",
                        help="ingest and print the plan, train nothing (works without torch)")
    parser.add_argument("--size", default=None, metavar="NAME",
                        help="brain size: compact (default, resumes the shipped checkpoint), "
                             "standard, or large")
    parser.add_argument("--steps", type=int, default=_DEFAULT_STEPS,
                        help=f"training steps (default {_DEFAULT_STEPS})")
    parser.add_argument("--eval-interval", type=int, default=_DEFAULT_EVAL_INTERVAL,
                        help=f"validate every N steps (default {_DEFAULT_EVAL_INTERVAL})")
    parser.add_argument("--lr", type=float, default=3e-4, help="learning rate (default 3e-4)")
    parser.add_argument("--batch", type=int, default=0, metavar="N",
                        help="override the token-budgeted batch size (0 = let the trainer choose)")
    parser.add_argument("--device", default="auto", choices=("auto", "cpu", "gpu"),
                        help="device preference (default auto)")
    parser.add_argument("--cap", type=int, default=0, metavar="CHARS",
                        help="cap the corpus at N characters (0 = the trainer's own ceiling)")
    parser.add_argument("--fresh", action="store_true",
                        help="start from random weights instead of resuming (archives the current model)")
    parser.add_argument("--no-recursive", action="store_true",
                        help="do not descend into subdirectories when ingesting")
    parser.add_argument("--patience", type=int, default=3,
                        help="stop after N evaluations with no improvement (default 3)")
    parser.add_argument("--min-delta", type=float, default=1e-4,
                        help="the smallest validation-loss drop that counts as improvement (default 1e-4)")
    parser.add_argument("--no-auto-stop", action="store_true",
                        help="run every step even once validation loss stops improving")
    parser.add_argument("--no-restore-best", action="store_true",
                        help="keep the final weights rather than restoring the best-scoring ones")
    parser.add_argument("--save-every", action="store_true",
                        help="checkpoint every evaluation, not only on an improvement")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="confirm a run that starts a new lineage (a --size or --fresh change)")
    parser.add_argument("--json", action="store_true", help="print the machine-readable result")
    parser.add_argument("--no-fx", action="store_true",
                        help="no live animated status line (also: GN_NO_FX=1, NO_COLOR, or a non-tty)")
    parser.set_defaults(func=_cmd_train_coder)
