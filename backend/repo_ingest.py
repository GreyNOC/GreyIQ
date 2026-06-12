from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


Logger = Callable[[str], None]

REPO_KNOWLEDGE_FILE = "greyiq_repo_knowledge.txt"
DEFAULT_REPO_CACHE_DIR = "repositories"
MAX_FILE_BYTES = 350_000
MAX_TOTAL_CHARS = 4_000_000
MAX_FILES_PER_REPO = 900

TEXT_EXTENSIONS = {
    ".bat",
    ".c",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".csv",
    ".cjs",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".lock",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

IMPORTANT_NAMES = {
    ".env.example",
    ".gitignore",
    "Dockerfile",
    "LICENSE",
    "Makefile",
    "README",
    "README.md",
    "requirements.txt",
}

SKIP_DIRS = {
    ".cache",
    ".git",
    ".hg",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "venv",
}

SECRET_RE = re.compile(
    r"(?i)\b("
    r"api[_-]?key|auth[_-]?token|bearer\s+[a-z0-9._-]{16,}|"
    r"client[_-]?secret|password|private[_-]?key|secret[_-]?key|"
    r"BEGIN\s+(RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE\s+KEY"
    r")\b"
)


@dataclass(slots=True)
class RepoIngestResult:
    source: str
    repo_path: str
    status: str
    files_added: int
    files_skipped: int
    characters_added: int
    message: str

    def as_dict(self) -> dict[str, int | str]:
        return {
            "source": self.source,
            "repo_path": self.repo_path,
            "status": self.status,
            "files_added": self.files_added,
            "files_skipped": self.files_skipped,
            "characters_added": self.characters_added,
            "message": self.message,
        }


def _log(logger: Logger | None, message: str) -> None:
    if logger:
        try:
            logger(message)
        except Exception:
            pass


def _is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https", "ssh", "git"} or value.startswith("git@")


def _safe_repo_name(source: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", source.strip()).strip("._-")
    if len(cleaned) > 72:
        digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:10]
        cleaned = f"{cleaned[:60]}_{digest}"
    return cleaned or "repo"


def _run_git(args: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return proc.stdout.strip()


def _resolve_source(source: str, cache_dir: Path, logger: Logger | None = None) -> tuple[Path, str]:
    clean = source.strip()
    if not clean:
        raise ValueError("Empty repository source.")

    if _is_url(clean):
        cache_dir.mkdir(parents=True, exist_ok=True)
        repo_dir = cache_dir / _safe_repo_name(clean.removesuffix(".git"))
        if repo_dir.exists():
            _log(logger, f"Updating repo cache: {clean}")
            try:
                _run_git(["fetch", "--depth", "1", "origin"], cwd=repo_dir)
                branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_dir) or "main"
                _run_git(["pull", "--ff-only", "--depth", "1", "origin", branch], cwd=repo_dir)
            except Exception as exc:
                _log(logger, f"Repo cache update failed, using existing checkout: {exc}")
        else:
            _log(logger, f"Cloning repo: {clean}")
            _run_git(["clone", "--depth", "1", clean, str(repo_dir)])
        return repo_dir.resolve(), "git-url"

    path = Path(clean).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Repository path not found: {clean}")
    if not path.is_dir():
        raise NotADirectoryError(f"Repository source is not a folder: {clean}")
    return path.resolve(), "local"


def _should_skip_path(path: Path, repo_root: Path) -> bool:
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    parts = set(rel.parts[:-1])
    if parts & SKIP_DIRS:
        return True
    name = path.name
    if name in IMPORTANT_NAMES:
        return False
    suffix = path.suffix.lower()
    return suffix not in TEXT_EXTENSIONS


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        return None
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return None
    if SECRET_RE.search(text):
        return None
    return text


def _iter_repo_files(repo_root: Path) -> Iterable[Path]:
    for path in sorted(repo_root.rglob("*")):
        if path.is_file() and not _should_skip_path(path, repo_root):
            yield path


def _format_repo_block(repo_root: Path, source: str, files: list[tuple[Path, str]]) -> str:
    lines = [
        "<START_REPO>",
        f"Source: {source}",
        f"Repository: {repo_root.name}",
        f"Path: {repo_root}",
    ]
    for file_path, text in files:
        rel = file_path.relative_to(repo_root).as_posix()
        lines.extend(
            [
                "",
                f"--- FILE: {rel} ---",
                text,
            ]
        )
    lines.append("<END_REPO>")
    return "\n".join(lines)


def ingest_repositories(
    sources: Iterable[str],
    *,
    runtime_dir: str | Path,
    output_file: str = REPO_KNOWLEDGE_FILE,
    max_total_chars: int = MAX_TOTAL_CHARS,
    max_files_per_repo: int = MAX_FILES_PER_REPO,
    logger: Logger | None = None,
) -> dict[str, object]:
    runtime_path = Path(runtime_dir)
    data_dir = runtime_path / "data"
    cache_dir = runtime_path / DEFAULT_REPO_CACHE_DIR
    data_dir.mkdir(parents=True, exist_ok=True)

    source_list = [str(source or "").strip() for source in sources if str(source or "").strip()]
    per_repo_char_cap = 0
    if max_total_chars > 0 and source_list:
        per_repo_char_cap = max(20_000, max_total_chars // len(source_list))

    blocks: list[str] = []
    results: list[RepoIngestResult] = []
    total_chars = 0

    for clean_source in source_list:
        try:
            repo_path, source_kind = _resolve_source(clean_source, cache_dir, logger=logger)
            selected_files: list[tuple[Path, str]] = []
            skipped = 0
            for file_path in _iter_repo_files(repo_path):
                if len(selected_files) >= max_files_per_repo:
                    skipped += 1
                    continue
                text = _read_text(file_path)
                if text is None:
                    skipped += 1
                    continue
                selected_files.append((file_path, text))

            block = _format_repo_block(repo_path, clean_source, selected_files)
            truncated = False
            if per_repo_char_cap > 0 and len(block) > per_repo_char_cap:
                block = block[:per_repo_char_cap].rsplit("\n", 1)[0] + "\n<END_REPO>"
                truncated = True

            if max_total_chars > 0 and total_chars + len(block) > max_total_chars:
                remaining = max_total_chars - total_chars
                if remaining <= 0:
                    results.append(
                        RepoIngestResult(
                            clean_source,
                            str(repo_path),
                            "capped",
                            0,
                            len(selected_files) + skipped,
                            0,
                            "Corpus character cap reached before this repo.",
                        )
                    )
                    continue
                block = block[:remaining].rsplit("\n", 1)[0] + "\n<END_REPO>"
                truncated = True

            blocks.append(block)
            total_chars += len(block)
            results.append(
                RepoIngestResult(
                    clean_source,
                    str(repo_path),
                    "ingested",
                    len(selected_files),
                    skipped,
                    len(block),
                    (
                        f"Ingested {len(selected_files)} file(s) from {source_kind} source"
                        + (" with fair-share truncation." if truncated else ".")
                    ),
                )
            )
        except FileNotFoundError as exc:
            results.append(RepoIngestResult(clean_source, "", "failed", 0, 0, 0, str(exc)))
        except (subprocess.SubprocessError, OSError, ValueError, NotADirectoryError) as exc:
            results.append(RepoIngestResult(clean_source, "", "failed", 0, 0, 0, str(exc)))

    output_path = data_dir / output_file
    payload = "\n\n".join(blocks).strip()
    if payload:
        output_path.write_text(payload + "\n", encoding="utf-8")
    elif output_path.exists():
        output_path.unlink()

    converted = sum(1 for result in results if result.status == "ingested")
    failed = sum(1 for result in results if result.status == "failed")
    files_added = sum(result.files_added for result in results)
    _log(logger, f"Repo ingest complete: {converted} ingested, {failed} failed, {files_added} files.")

    return {
        "ok": failed == 0,
        "output_path": str(output_path),
        "summary": {
            "repositories": len(results),
            "ingested": converted,
            "failed": failed,
            "files_added": files_added,
            "characters_added": total_chars,
        },
        "results": [result.as_dict() for result in results],
        "git_available": shutil.which("git") is not None,
    }
