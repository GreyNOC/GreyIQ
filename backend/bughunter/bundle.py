"""GreyIQ BugHunter — engagement bundle (downloadable .zip).

Packages everything an engagement produced — the reports, per-platform submission
packages, captured evidence, screenshots, research dossiers, and JSON sidecars — into a
single .zip the operator can download and submit from. A campaign already writes a self-
contained folder, so that whole tree is zipped; a single hunt's artifacts are gathered by
explicit file list (its report + sidecar + per-finding files + any screenshots/research).

Every bundle also carries an **evidence-integrity manifest** — a chain of custody. As each
artifact is admitted, its SHA-256 is computed over the exact bytes bundled and recorded in
two files written into the archive: ``EVIDENCE-MANIFEST.json`` (machine-readable, with the
tool/version/time and per-artifact digest + size) and ``MANIFEST.sha256`` (the standard
``sha256sum -c`` format). After unzipping, a triager runs ``sha256sum -c MANIFEST.sha256``
(macOS: ``shasum -a 256 -c``) and a matching digest proves every proof artifact — request/
response transcripts, JSON sidecar, and the un-redactable screenshots — is byte-for-byte
unaltered. This is what turns a pile of captured files into solid, verifiable evidence.

Pure / frozen-safe (stdlib ``zipfile`` / ``hashlib`` / ``json`` only). Bounded: each file and
the total archive are size-capped so a runaway artifact can't produce a multi-gigabyte
download, and unreadable files are skipped (recorded in ``skipped``) rather than aborting the
bundle.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_MAX_FILE_BYTES = 50 * 1024 * 1024      # skip any single file larger than 50 MB
_MAX_TOTAL_BYTES = 200 * 1024 * 1024    # stop adding once the (uncompressed) total hits 200 MB
# Never bundle these (caches / VCS / OS noise) when walking a directory tree.
_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}

# The evidence-integrity manifest files, written at the archive root so a single
# ``sha256sum -c MANIFEST.sha256`` from the unzip root verifies every artifact.
_MANIFEST_JSON = "EVIDENCE-MANIFEST.json"
_MANIFEST_SHA256 = "MANIFEST.sha256"
_MANIFEST_NAMES = (_MANIFEST_JSON, _MANIFEST_SHA256)
_HASH_CHUNK = 1024 * 1024  # stream files in 1 MB chunks so a 50 MB artifact never loads whole


def _sha256_of(path: Path) -> str:
    """SHA-256 hex digest of a file, streamed in chunks (never loads it whole). Raises
    OSError if the file can't be read — the caller then skips it rather than bundling an
    artifact it cannot fingerprint."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _add(
    zf: zipfile.ZipFile,
    arcname: str,
    path: Path,
    state: dict[str, int],
    skipped: list[str],
    manifest: list[dict[str, Any]] | None = None,
) -> None:
    # zipfile normalizes stored names to forward slashes; record the SAME normalized name in
    # the manifest so the digest lines match the extracted paths (and `sha256sum -c` verifies)
    # on Windows, where Path builds backslash arcnames.
    arcname = str(arcname).replace("\\", "/")
    try:
        size = path.stat().st_size
    except OSError:
        skipped.append(arcname)
        return
    if size > _MAX_FILE_BYTES:
        skipped.append(f"{arcname} (too large: {size} bytes)")
        return
    if state["total"] + size > _MAX_TOTAL_BYTES:
        skipped.append(f"{arcname} (archive size cap reached)")
        return
    # Fingerprint the artifact BEFORE writing it, so an artifact that lands in the archive
    # always has a manifest entry (and an unreadable file is skipped, not silently bundled
    # without a digest). Only when a manifest is being collected — the direct-_add unit
    # tests pass none and keep the original zip-only path.
    digest = ""
    if manifest is not None:
        try:
            digest = _sha256_of(path)
        except OSError:
            skipped.append(arcname)
            return
    try:
        zf.write(path, arcname)
    except OSError:
        skipped.append(arcname)
        return
    if manifest is not None:
        manifest.append({"path": arcname, "sha256": digest, "bytes": size})
    state["total"] += size
    state["count"] += 1


def _write_manifest(
    zf: zipfile.ZipFile,
    manifest: list[dict[str, Any]],
    skipped: list[str],
    meta: dict[str, Any] | None,
) -> None:
    """Write the evidence-integrity manifest into the open archive: a machine-readable JSON
    and the standard ``sha256sum -c`` checksum file. Deterministic ordering (by path) so two
    runs over the same inputs produce identical manifests."""
    meta = meta or {}
    generated_at = str(meta.get("generated_at") or "").strip() or datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    ordered = sorted(manifest, key=lambda entry: str(entry.get("path") or ""))
    total_bytes = sum(int(entry.get("bytes") or 0) for entry in ordered)
    doc = {
        "manifest_version": 1,
        "tool": str(meta.get("tool") or "GreyIQ BugHunter"),
        "version": str(meta.get("version") or ""),
        "generated_at": generated_at,
        "algorithm": "sha256",
        "artifact_count": len(ordered),
        "total_bytes": total_bytes,
        "note": (
            "Chain-of-custody manifest. Each entry is the SHA-256 of the artifact exactly as bundled. "
            f"After unzipping, verify integrity from the unzip root with: sha256sum -c {_MANIFEST_SHA256} "
            f"(macOS: shasum -a 256 -c {_MANIFEST_SHA256}). A matching digest proves the evidence file is "
            "byte-for-byte unaltered. Screenshots are image evidence and are NOT auto-redacted — the "
            "fingerprint proves the image is unaltered, not that it is safe to share."
        ),
        "artifacts": ordered,
        "skipped": list(skipped),
    }
    zf.writestr(_MANIFEST_JSON, json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    # Pure "<hex>  <path>" lines (two spaces) — the exact format `sha256sum -c` expects. No
    # comment header: some coreutils builds reject non-checksum lines, so keep it clean.
    checksum_lines = [f"{entry['sha256']}  {entry['path']}" for entry in ordered]
    zf.writestr(_MANIFEST_SHA256, "\n".join(checksum_lines) + ("\n" if checksum_lines else ""))


def _finish(out_zip: Path, state: dict[str, int], skipped: list[str]) -> dict[str, Any]:
    if state["count"] == 0:
        try:
            out_zip.unlink()
        except OSError:
            pass
        return {"ok": False, "error": "Nothing to bundle — no readable artifacts were found for this run."}
    try:
        zip_bytes = out_zip.stat().st_size
    except OSError:
        zip_bytes = 0
    return {"ok": True, "path": str(out_zip), "file_count": state["count"],
            "uncompressed_bytes": state["total"], "zip_bytes": zip_bytes, "skipped": skipped,
            "manifest": list(_MANIFEST_NAMES)}


def bundle_directory(
    src_dir: str | Path, out_zip: str | Path, *, meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Zip an entire self-contained engagement folder (e.g. a campaign output dir).
    Arcnames are relative to ``src_dir`` so the archive unpacks into one clean folder.
    ``meta`` (tool/version/generated_at) is stamped into the evidence-integrity manifest."""
    src = Path(src_dir)
    out = Path(out_zip)
    if not src.is_dir():
        return {"ok": False, "error": f"Not a folder: {src}"}
    state = {"total": 0, "count": 0}
    skipped: list[str] = []
    manifest: list[dict[str, Any]] = []
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(src.rglob("*")):
                if not path.is_file():
                    continue
                rel = path.relative_to(src)
                if any(part in _SKIP_DIRS for part in rel.parts):
                    continue
                _add(zf, str(Path(src.name) / rel), path, state, skipped, manifest)
            if state["count"] > 0:
                _write_manifest(zf, manifest, skipped, meta)
    except OSError as exc:
        return {"ok": False, "error": f"Could not write the bundle: {exc}"}
    return _finish(out, state, skipped)


def bundle_files(
    file_specs: list[tuple[str, str | Path]], out_zip: str | Path, *, meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Zip an explicit list of ``(arcname, path)`` files (a single hunt's artifacts).
    Missing/unreadable entries are skipped, deduped by arcname. ``meta`` (tool/version/
    generated_at) is stamped into the evidence-integrity manifest."""
    out = Path(out_zip)
    state = {"total": 0, "count": 0}
    skipped: list[str] = []
    manifest: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, path in file_specs:
                arc = str(arcname).strip()
                # The manifest files are reserved names GreyIQ writes itself; an artifact
                # can't masquerade as one and shadow the real integrity record.
                if not arc or arc in seen or arc in _MANIFEST_NAMES:
                    if arc and arc in _MANIFEST_NAMES:
                        skipped.append(f"{arc} (reserved manifest name)")
                    continue
                p = Path(path)
                if not p.is_file():
                    skipped.append(arc)
                    continue
                seen.add(arc)
                _add(zf, arc, p, state, skipped, manifest)
            if state["count"] > 0:
                _write_manifest(zf, manifest, skipped, meta)
    except OSError as exc:
        return {"ok": False, "error": f"Could not write the bundle: {exc}"}
    return _finish(out, state, skipped)
