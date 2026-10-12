"""Import a public split GGUF from Hugging Face into a local Ollama server.

Ollama's hf.co registry pull does not support every split GGUF repository. This
fallback uses a pinned Hub revision, verifies every shard against its published
LFS SHA-256, then uses Ollama's blob and create APIs. It is intentionally limited
to complete split GGUF sets; ordinary models stay on the existing pull path.
"""

from __future__ import annotations

import ctypes
import hashlib
import http.client
import json
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import coder


_HEX40 = re.compile(r"[0-9a-f]{40}\Z", re.IGNORECASE)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.IGNORECASE)
_SAFE_FILE_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_SPLIT_NAME = re.compile(r"(?P<stem>.+)-(?P<index>\d{5})-of-(?P<count>\d{5})\.gguf\Z", re.IGNORECASE)
_CHUNK = 1024 * 1024
_MAX_METADATA = 4_000_000
_MAX_SHARDS = 128
_MIN_HEADROOM = 1024**3
_FAT32_MAX_FILE = 2**32 - 1
_MIN_SPLIT_OLLAMA_VERSION = (0, 35, 0)
Progress = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class _Shard:
    path: str
    name: str
    size: int
    sha256: str
    index: int
    count: int


@dataclass(frozen=True)
class _Group:
    key: str
    shards: tuple[_Shard, ...]
    quant: str

    @property
    def size(self) -> int:
        return sum(shard.size for shard in self.shards)


@dataclass(frozen=True)
class _ShardState:
    shard: _Shard
    path: Path
    blob_exists: bool
    cache_verified: bool


def _safe_error(detail: object) -> str:
    """Do not expose signed download links in model status or backend logs."""
    return re.sub(r"https?://[^\s\"']+", "[download URL]", str(detail))[:300]


def _repo_and_tag(ref: str) -> tuple[str, str]:
    normalized = coder.normalize_huggingface_model_ref(ref)
    owner_repo, separator, tag = normalized.removeprefix("hf.co/").partition(":")
    return owner_repo, tag if separator else ""


def _metadata(repo_id: str) -> tuple[str, list[dict[str, Any]]]:
    endpoint = f"https://huggingface.co/api/models/{repo_id}?blobs=true"
    try:
        with urllib.request.urlopen(endpoint, timeout=20) as response:
            raw = response.read(_MAX_METADATA + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise coder.CoderError("This Hugging Face model requires access; public GGUF imports only.") from exc
        if exc.code == 404:
            raise coder.CoderError("Hugging Face model not found or private.") from exc
        raise coder.CoderError(f"Hugging Face model check failed (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise coder.CoderError(f"Could not check the Hugging Face model: {_safe_error(exc)}") from exc
    if len(raw) > _MAX_METADATA:
        raise coder.CoderError("Hugging Face model file list is too large to inspect safely.")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise coder.CoderError("Hugging Face returned invalid model metadata.") from exc
    if not isinstance(data, dict):
        raise coder.CoderError("Hugging Face returned invalid model metadata.")
    if data.get("private") or data.get("gated") not in (None, False):
        raise coder.CoderError("This Hugging Face model is private or gated; public GGUF imports only.")
    revision = str(data.get("sha") or "")
    siblings = data.get("siblings")
    if not _HEX40.fullmatch(revision) or not isinstance(siblings, list):
        raise coder.CoderError("Hugging Face did not provide a pinned revision and file list.")
    return revision.lower(), siblings


def _valid_repo_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 500 or "\\" in value:
        return None
    parts = value.split("/")
    if any(part in (".", "..") or not _SAFE_FILE_PART.fullmatch(part) for part in parts):
        return None
    return value


def _quant_for_group(key: str) -> str:
    directory, _, stem = key.rpartition("/")
    # Prefer the filename's actual quantization. A generic parent like
    # ``models/`` or ``weights/`` must not become the Ollama model tag.
    quant_suffix = r"((?:UD-)?(?:IQ|Q)\d+[A-Za-z0-9_]*|(?:BF|F)\d+|MXFP\d+[A-Za-z0-9_]*)"
    match = re.search(rf"(?:^|[-_.]){quant_suffix}$", stem, re.IGNORECASE)
    if match:
        return match.group(1)
    for part in reversed(directory.split("/")) if directory else ():
        if re.fullmatch(quant_suffix, part, re.IGNORECASE):
            return part
    return "split"


def _select_group(siblings: list[dict[str, Any]], tag: str) -> _Group:
    groups: dict[str, list[_Shard]] = {}
    for item in siblings:
        if not isinstance(item, dict):
            continue
        filename = _valid_repo_path(item.get("rfilename"))
        if not filename:
            continue
        match = _SPLIT_NAME.fullmatch(filename.rsplit("/", 1)[-1])
        if not match:
            continue
        lfs = item.get("lfs")
        digest = str(lfs.get("sha256") or "") if isinstance(lfs, dict) else ""
        size = item.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or not _HEX64.fullmatch(digest):
            # Never download unpinned or size-unknown weights.
            continue
        if isinstance(lfs, dict) and lfs.get("size") != size:
            continue
        count = int(match.group("count"))
        index = int(match.group("index"))
        if count < 2 or count > _MAX_SHARDS or index < 1 or index > count:
            continue
        directory = filename.rpartition("/")[0]
        key = f"{directory}/{match.group('stem')}" if directory else match.group("stem")
        groups.setdefault(key, []).append(_Shard(filename, filename.rsplit("/", 1)[-1], size, digest.lower(), index, count))

    complete: list[_Group] = []
    for key, parts in groups.items():
        expected = parts[0].count
        if (len(parts) != expected or any(part.count != expected for part in parts)
                or {part.index for part in parts} != set(range(1, expected + 1))
                or len({part.name for part in parts}) != expected):
            continue
        complete.append(_Group(key, tuple(sorted(parts, key=lambda shard: shard.index)), _quant_for_group(key)))
    if not complete:
        raise coder.CoderError("No complete, size- and SHA-256-pinned split GGUF set was found in this repository.")

    if tag:
        exact = [group for group in complete if group.quant.casefold() == tag.casefold()]
        if not exact:
            boundary = re.compile(rf"(?:^|[-_.]){re.escape(tag)}(?:$|[-_.])", re.IGNORECASE)
            exact = [group for group in complete if boundary.search(group.key)]
        if not exact:
            available = ", ".join(sorted({group.quant for group in complete}, key=str.casefold)[:12])
            raise coder.CoderError(f"Quantization '{tag}' has no complete split GGUF set. Available: {available}.")
        complete = exact
    # A repository root without a tag takes the smallest complete variant. The
    # disk preflight still prevents an unexpectedly large download on this host.
    return min(complete, key=lambda group: (group.size, group.key.casefold()))


def _alias(repo_id: str, revision: str, group: _Group) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", repo_id.casefold().replace("/", "-"))[:65].strip(".-_")
    fingerprint = hashlib.sha256(f"{repo_id.casefold()}@{revision}:{group.key}".encode()).hexdigest()[:10]
    quant = re.sub(r"[^a-z0-9._-]+", "-", group.quant.casefold())[:30].strip(".-_") or "split"
    return f"greyiq-hf/{slug}-{fingerprint}:{quant}"


def _nearest_existing(path: Path) -> Path:
    current = path.resolve()
    while not current.exists() and current.parent != current:
        current = current.parent
    return current


def _windows_filesystem_type(path: Path) -> str | None:
    """Find the mounted volume's filesystem, including folder mount points."""
    if sys.platform != "win32":
        return None
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    volume_path_name = kernel32.GetVolumePathNameW
    volume_path_name.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    volume_path_name.restype = wintypes.BOOL
    volume = ctypes.create_unicode_buffer(32768)
    if not volume_path_name(str(path), volume, len(volume)):
        raise OSError(ctypes.get_last_error(), "Could not locate the Windows storage volume")

    volume_info = kernel32.GetVolumeInformationW
    volume_info.argtypes = (
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD,
    )
    volume_info.restype = wintypes.BOOL
    filesystem = ctypes.create_unicode_buffer(256)
    if not volume_info(volume.value, None, 0, None, None, None, filesystem, len(filesystem)):
        raise OSError(ctypes.get_last_error(), "Could not inspect the Windows storage volume")
    return filesystem.value.upper()


def _preflight(
    cache_root: Path,
    models_root: Path | None,
    group: _Group,
    states: tuple[_ShardState, ...] | None = None,
) -> None:
    if models_root is None:
        raise coder.CoderError(
            "GreyIQ cannot verify free space in Ollama's model store for this split GGUF import. "
            "Stop the pre-existing Ollama server, set GREYIQ_RUNTIME_DIR and OLLAMA_MODELS "
            "to folders on a volume with enough free space, then let GreyIQ launch Ollama and retry."
        )
    cache_device = _nearest_existing(cache_root)
    model_device = _nearest_existing(models_root)
    largest_shard = max(shard.size for shard in group.shards)
    if largest_shard > _FAT32_MAX_FILE:
        try:
            filesystems = (
                ("GreyIQ cache", _windows_filesystem_type(cache_device)),
                ("Ollama model store", _windows_filesystem_type(model_device)),
            )
        except OSError as exc:
            raise coder.CoderError(
                "Could not verify the Windows storage filesystem for this large split GGUF model. "
                "Use NTFS or exFAT volumes for GREYIQ_RUNTIME_DIR and OLLAMA_MODELS, then retry."
            ) from exc
        incompatible = [f"{label} ({filesystem})" for label, filesystem in filesystems
                        if filesystem in {"FAT", "FAT32"}]
        if incompatible:
            raise coder.CoderError(
                f"The {group.quant} split GGUF has a {largest_shard / 1024**3:.1f} GiB shard, "
                f"but {', '.join(incompatible)} cannot hold a file over 4 GiB. "
                "Set GREYIQ_RUNTIME_DIR and OLLAMA_MODELS to NTFS or exFAT volumes "
                "with enough free space, restart GreyIQ and Ollama, then retry."
            )
    cache_free = shutil.disk_usage(cache_device).free
    total = group.size
    headroom = max(_MIN_HEADROOM, total // 20)
    if states is None:
        states = tuple(_ShardState(shard, Path(shard.path), False, False)
                       for shard in sorted(group.shards, key=lambda item: -item.size))
    # Free space already excludes cached files and existing Ollama blobs. Track
    # only allocations made after this measurement. Uploading a cached shard
    # replaces its cache copy with an Ollama blob, so the net use is zero.
    net_same_volume = 0
    peak_same_volume = 0
    net_cache = 0
    peak_cache = 0
    net_models = 0
    peak_models = 0
    for state in states:
        if state.blob_exists:
            continue
        size = state.shard.size
        peak_same_volume = max(peak_same_volume, net_same_volume + (size if state.cache_verified else 2 * size))
        if not state.cache_verified:
            net_same_volume += size
            peak_cache = max(peak_cache, net_cache + size)
            # Download adds ``size`` to the cache, then successful upload
            # deletes that same file. The cache's net use stays unchanged.
        else:
            # This verified file was already counted against current free
            # space; its deletion frees capacity for later shard downloads.
            net_cache -= size
        peak_models = max(peak_models, net_models + size)
        net_models += size
    required = peak_same_volume + headroom
    model_free = shutil.disk_usage(model_device).free
    if cache_device.stat().st_dev == model_device.stat().st_dev:
        available = min(cache_free, model_free)
        if available < required:
            raise coder.CoderError(
                f"The {group.quant} model ({total / 1024**3:.1f} GiB) needs about "
                f"{required / 1024**3:.1f} GiB free for sequential download and Ollama import; "
                f"only {available / 1024**3:.1f} GiB is available. Set GREYIQ_RUNTIME_DIR and "
                "OLLAMA_MODELS to folders on a larger disk before starting GreyIQ and Ollama, then retry."
            )
    else:
        cache_required = peak_cache + (headroom if peak_cache else 0)
        model_required = peak_models + (headroom if peak_models else 0)
        if cache_free < cache_required or model_free < model_required:
            raise coder.CoderError(
                f"The {group.quant} model ({total / 1024**3:.1f} GiB) needs about "
                f"{cache_required / 1024**3:.1f} GiB free in GreyIQ's cache "
                f"(available {cache_free / 1024**3:.1f} GiB) and "
                f"{model_required / 1024**3:.1f} GiB in Ollama's model store "
                f"(available {model_free / 1024**3:.1f} GiB). Set GREYIQ_RUNTIME_DIR and "
                "OLLAMA_MODELS to folders with enough space before starting GreyIQ and Ollama, then retry."
            )


def _verified_file(path: Path, shard: _Shard) -> bool:
    if not path.is_file() or path.is_symlink() or path.stat().st_size != shard.size:
        return False
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            hasher.update(chunk)
    return hasher.hexdigest() == shard.sha256


def _download(repo_id: str, revision: str, shard: _Shard, target: Path, progress: Progress) -> None:
    if _verified_file(target, shard):
        progress({"status": f"Reusing verified {shard.name}", "completed": shard.size})
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or target.is_dir():
        raise coder.CoderError("Model cache path is not a regular file.")
    partial = target.with_name(target.name + ".part")
    if partial.is_symlink() or partial.is_dir():
        raise coder.CoderError("Model cache path is not a regular file.")
    url = f"https://huggingface.co/{repo_id}/resolve/{revision}/{urllib.parse.quote(shard.path, safe='/')}"
    hasher = hashlib.sha256()
    received = 0
    try:
        with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as output:
            final_url = urllib.parse.urlsplit(response.geturl())
            if final_url.scheme != "https" or not final_url.hostname or final_url.username or final_url.password:
                raise coder.CoderError("Hugging Face returned an unsafe download redirect.")
            while True:
                block = response.read(_CHUNK)
                if not block:
                    break
                received += len(block)
                if received > shard.size:
                    raise coder.CoderError(f"Hugging Face sent more data than expected for {shard.name}.")
                output.write(block)
                hasher.update(block)
                progress({"status": f"Downloading {shard.name}", "completed": len(block)})
        if received != shard.size or hasher.hexdigest() != shard.sha256:
            raise coder.CoderError(f"Downloaded {shard.name} did not match Hugging Face size and SHA-256; retry the import.")
        partial.replace(target)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise coder.CoderError(f"Hugging Face download failed for {shard.name}: {_safe_error(exc)}") from exc
    finally:
        partial.unlink(missing_ok=True)


def _blob_exists(host: str, digest: str) -> bool:
    request = urllib.request.Request(f"{host.rstrip('/')}/api/blobs/sha256:{digest}", method="HEAD")
    try:
        with coder._ollama_open(request, timeout=30):
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise coder.CoderError(f"Ollama blob check failed (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise coder.CoderError(f"Could not reach local Ollama during blob check: {_safe_error(exc)}") from exc


def _check_ollama_version(host: str) -> None:
    """Split GGUF manifests require Ollama 0.35.0 to run, even on servers that can create them."""
    try:
        with coder._ollama_open(f"{host.rstrip('/')}/api/version", timeout=15) as response:
            raw = response.read(4096)
        version = json.loads(raw).get("version")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, AttributeError) as exc:
        raise coder.CoderError(
            "Could not confirm Ollama version. Update Ollama to 0.35.0 or newer, restart GreyIQ and Ollama, then retry."
        ) from exc
    match = re.fullmatch(r"v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:\+[A-Za-z0-9._-]+)?", str(version or ""))
    if not match:
        raise coder.CoderError(
            "Ollama returned an unknown version. Update Ollama to 0.35.0 or newer, restart GreyIQ and Ollama, then retry."
        )
    current = tuple(int(part) for part in match.groups())
    if current < _MIN_SPLIT_OLLAMA_VERSION:
        raise coder.CoderError(
            f"Ollama {version} cannot run split GGUF models. Update Ollama to 0.35.0 or newer, "
            "restart GreyIQ and Ollama, then retry."
        )


def _upload_blob(host: str, shard: _Shard, path: Path, progress: Progress) -> None:
    if _blob_exists(host, shard.sha256):
        progress({"status": f"Reusing Ollama blob for {shard.name}", "completed": shard.size})
        return
    parsed = urllib.parse.urlsplit(host)
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(parsed.hostname, parsed.port, timeout=120)
    try:
        connection.putrequest("POST", f"/api/blobs/sha256:{shard.sha256}")
        connection.putheader("Content-Length", str(shard.size))
        connection.putheader("Content-Type", "application/octet-stream")
        connection.endheaders()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(_CHUNK), b""):
                connection.send(block)
                progress({"status": f"Adding {shard.name} to Ollama", "completed": len(block)})
        response = connection.getresponse()
        detail = response.read(4096).decode("utf-8", "ignore")
        if response.status != 201:
            raise coder.CoderError(f"Ollama blob upload failed (HTTP {response.status}): {_safe_error(detail)}")
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise coder.CoderError(f"Could not upload {shard.name} to local Ollama: {_safe_error(exc)}") from exc
    finally:
        connection.close()


def _create(host: str, alias: str, group: _Group, progress: Progress) -> None:
    files = {shard.name: f"sha256:{shard.sha256}" for shard in group.shards}
    request = urllib.request.Request(
        f"{host.rstrip('/')}/api/create",
        data=json.dumps({"model": alias, "files": files, "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    succeeded = False
    try:
        with coder._ollama_open(request, timeout=3600) as response:
            for raw in response:
                if not raw.strip():
                    continue
                try:
                    event = json.loads(raw)
                except ValueError as exc:
                    raise coder.CoderError("Ollama returned an invalid model-create response.") from exc
                if not isinstance(event, dict):
                    continue
                if event.get("error"):
                    raise coder.CoderError(f"Ollama could not create this GGUF model: {_safe_error(event['error'])}")
                if event.get("status"):
                    progress({"status": str(event["status"])[:160]})
                if event.get("status") == "success":
                    succeeded = True
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "ignore")
        raise coder.CoderError(f"Ollama model creation failed (HTTP {exc.code}): {_safe_error(detail)}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise coder.CoderError(f"Could not reach local Ollama during model creation: {_safe_error(exc)}") from exc
    if not succeeded:
        raise coder.CoderError("Ollama ended model creation without confirming success.")


def import_sharded_hf_model(
    host: str,
    ref: str,
    cache_root: Path,
    progress_cb: Progress,
    models_root: Path | None = None,
) -> str:
    """Return a local Ollama alias after verified split-GGUF import.

    Progress events use the existing model-setup shape: ``status`` plus optional
    cumulative ``completed`` and ``total`` bytes. The caller must still run chat
    and structured-tool readiness probes before selecting the returned alias.
    """
    if not coder.ollama_host_is_loopback(host):
        raise coder.CoderError("Sharded Hugging Face import requires local Ollama on a loopback address.")
    repo_id, tag = _repo_and_tag(ref)
    progress_cb({"status": "checking Hugging Face shard details"})
    revision, siblings = _metadata(repo_id)
    group = _select_group(siblings, tag)
    _check_ollama_version(host)
    alias = _alias(repo_id, revision, group)
    # A repeat request for an already created, pinned model needs no staging.
    if coder.model_installed(coder.ollama_list_models(host), alias):
        progress_cb({"status": "reusing installed Hugging Face model", "completed": 1, "total": 1})
        return alias
    cache_root = Path(cache_root).resolve()
    models_root = Path(models_root).resolve() if models_root is not None else None
    progress_cb({"status": f"Selected {group.quant} ({group.size / 1024**3:.1f} GiB); checking free space",
                 "completed": 0, "total": group.size * 2})
    base = cache_root / repo_id.replace("/", "--") / revision
    if not base.resolve().is_relative_to(cache_root):
        raise coder.CoderError("Model cache path is invalid.")
    states: list[_ShardState] = []
    for shard in sorted(group.shards, key=lambda item: -item.size):
        target = base / shard.path
        if not target.resolve().is_relative_to(base.resolve()):
            raise coder.CoderError("Model shard path is invalid.")
        blob_exists = _blob_exists(host, shard.sha256)
        cached = _verified_file(target, shard)
        if blob_exists and cached:
            # A previous create attempt already stored the verified blob; its
            # temporary cache copy is now redundant and can be reclaimed.
            target.unlink()
            cached = False
        states.append(_ShardState(shard, target, blob_exists, cached))
    state_list = tuple(states)
    if any(not state.blob_exists for state in state_list):
        _preflight(cache_root, models_root, group, state_list)
    completed = 0

    def phase(event: dict[str, Any]) -> None:
        nonlocal completed
        completed += int(event.get("completed") or 0)
        progress_cb({"status": str(event.get("status") or "importing model"),
                     "completed": completed, "total": group.size * 2})

    # Largest first minimizes the momentary total of already stored Ollama
    # blobs plus the current shard in both the cache and Ollama's blob store.
    for state in state_list:
        shard, target = state.shard, state.path
        if state.blob_exists:
            phase({"status": f"Reusing Ollama blob for {shard.name}", "completed": shard.size * 2})
            continue
        if state.cache_verified:
            phase({"status": f"Reusing verified {shard.name}", "completed": shard.size})
        else:
            _download(repo_id, revision, shard, target, phase)
        _upload_blob(host, shard, target, phase)
        # Keep the verified file if upload fails, so a retry need not fetch it.
        # Ollama's blob is verified by its SHA-256 endpoint on successful upload.
        target.unlink()
    progress_cb({"status": "creating local Ollama model", "completed": completed, "total": group.size * 2})
    _create(host, alias, group, progress_cb)
    return alias
