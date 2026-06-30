"""GreyIQ BugHunter — engagement bundle (downloadable .zip).

Packages everything an engagement produced — the reports, per-platform submission
packages, captured evidence, screenshots, research dossiers, and JSON sidecars — into a
single .zip the operator can download and submit from. A campaign already writes a self-
contained folder, so that whole tree is zipped; a single hunt's artifacts are gathered by
explicit file list (its report + sidecar + per-finding files + any screenshots/research).

Pure / frozen-safe (stdlib ``zipfile`` only). Bounded: each file and the total archive are
size-capped so a runaway artifact can't produce a multi-gigabyte download, and unreadable
files are skipped (recorded in ``skipped``) rather than aborting the bundle.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

_MAX_FILE_BYTES = 50 * 1024 * 1024      # skip any single file larger than 50 MB
_MAX_TOTAL_BYTES = 200 * 1024 * 1024    # stop adding once the (uncompressed) total hits 200 MB
# Never bundle these (caches / VCS / OS noise) when walking a directory tree.
_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}


def _add(zf: zipfile.ZipFile, arcname: str, path: Path, state: dict[str, int], skipped: list[str]) -> None:
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
    try:
        zf.write(path, arcname)
    except OSError:
        skipped.append(arcname)
        return
    state["total"] += size
    state["count"] += 1


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
            "uncompressed_bytes": state["total"], "zip_bytes": zip_bytes, "skipped": skipped}


def bundle_directory(src_dir: str | Path, out_zip: str | Path) -> dict[str, Any]:
    """Zip an entire self-contained engagement folder (e.g. a campaign output dir).
    Arcnames are relative to ``src_dir`` so the archive unpacks into one clean folder."""
    src = Path(src_dir)
    out = Path(out_zip)
    if not src.is_dir():
        return {"ok": False, "error": f"Not a folder: {src}"}
    state = {"total": 0, "count": 0}
    skipped: list[str] = []
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(src.rglob("*")):
                if not path.is_file():
                    continue
                rel = path.relative_to(src)
                if any(part in _SKIP_DIRS for part in rel.parts):
                    continue
                _add(zf, str(Path(src.name) / rel), path, state, skipped)
    except OSError as exc:
        return {"ok": False, "error": f"Could not write the bundle: {exc}"}
    return _finish(out, state, skipped)


def bundle_files(file_specs: list[tuple[str, str | Path]], out_zip: str | Path) -> dict[str, Any]:
    """Zip an explicit list of ``(arcname, path)`` files (a single hunt's artifacts).
    Missing/unreadable entries are skipped, deduped by arcname."""
    out = Path(out_zip)
    state = {"total": 0, "count": 0}
    skipped: list[str] = []
    seen: set[str] = set()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, path in file_specs:
                arc = str(arcname).strip()
                if not arc or arc in seen:
                    continue
                p = Path(path)
                if not p.is_file():
                    skipped.append(arc)
                    continue
                seen.add(arc)
                _add(zf, arc, p, state, skipped)
    except OSError as exc:
        return {"ok": False, "error": f"Could not write the bundle: {exc}"}
    return _finish(out, state, skipped)
