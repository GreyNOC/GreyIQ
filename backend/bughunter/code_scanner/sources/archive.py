"""Archive source — extract an uploaded .zip / .tar.gz under a byte cap and scan.

The ``target`` is a local filesystem path to the archive. The API
endpoint accepts the upload, writes it to a tempfile, and constructs
an ArchiveSource pointing at that path. The source handles extraction
with strict path-traversal protection: any entry that resolves outside
the destination directory aborts the extraction.
"""

from __future__ import annotations

import tarfile
import tempfile
import zipfile
from pathlib import Path

from bughunter.code_scanner.sources.base import ScanSource
from bughunter.code_scanner.sources.local_guard import resolve_local_scan_path

# Hard cap on extracted bytes. Independent of the per-file cap because
# an archive could expand to many GB even with small per-file files.
_MAX_EXTRACTED_BYTES = 512 * 1024 * 1024


class ArchiveSource(ScanSource):
    def __init__(self, target: str) -> None:
        super().__init__(target)
        self._tempdir: tempfile.TemporaryDirectory[str] | None = None

    def _safe_join(self, dest: Path, member: str) -> Path:
        # Resolve the target without following symlinks the archive
        # provides. Anything that escapes the destination root is a
        # traversal attempt; the extractor aborts in that case.
        if not member or "\x00" in member:
            raise ValueError(f"Archive entry has an invalid name: {member!r}")
        # Reject absolute member names and obvious traversal up-front so
        # we don't rely solely on the resolved-path check below.
        if member.startswith(("/", "\\")) or ":" in Path(member).drive:
            raise ValueError(f"Archive entry uses an absolute name: {member}")
        target = (dest / member).resolve()
        # Use is_relative_to so a destination at /tmp/x and a target at
        # /tmp/x-evil cannot fool a startswith() prefix check.
        if not target.is_relative_to(dest.resolve()):
            raise ValueError(f"Archive entry escapes destination: {member}")
        return target

    def _stream_to(self, source, target: Path, byte_budget: int) -> int:
        """Copy a stream into ``target`` honoring a remaining-byte budget.

        Returns the number of bytes written. Raises if the source would
        exceed ``byte_budget`` — guards against archive metadata that
        lies about uncompressed size.
        """
        written = 0
        # We never write into a pre-existing symlink: open the file in
        # exclusive-create mode so an attacker-controlled symlink at the
        # destination can't redirect us.
        flags = "xb"
        with target.open(flags) as out:
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > byte_budget:
                    raise ValueError("Archive entry exceeded the byte budget during extraction.")
                out.write(chunk)
        return written

    def _extract_zip(self, archive: Path, dest: Path) -> None:
        with zipfile.ZipFile(archive) as zf:
            total = 0
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.file_size > _MAX_EXTRACTED_BYTES:
                    raise ValueError("Archive entry too large.")
                remaining = _MAX_EXTRACTED_BYTES - total
                if remaining <= 0:
                    raise ValueError("Total extracted size exceeds cap.")
                target = self._safe_join(dest, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src:
                    total += self._stream_to(src, target, remaining)

    def _extract_tar(self, archive: Path, dest: Path) -> None:
        with tarfile.open(archive, "r:*") as tf:
            total = 0
            for member in tf.getmembers():
                # Drop symlinks, hardlinks, devices, fifos — never extract
                # anything that could escape the tempdir or affect the
                # host. Even isdir() entries are recreated as plain dirs
                # by `mkdir(parents=True, exist_ok=True)` later, so we
                # don't honor archive-supplied directory metadata.
                if not member.isfile():
                    continue
                if member.size > _MAX_EXTRACTED_BYTES:
                    raise ValueError("Archive entry too large.")
                remaining = _MAX_EXTRACTED_BYTES - total
                if remaining <= 0:
                    raise ValueError("Total extracted size exceeds cap.")
                target = self._safe_join(dest, member.name)
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                total += self._stream_to(extracted, target, remaining)

    def _prepare(self) -> Path:
        archive = resolve_local_scan_path(self.target)
        if not archive.exists():
            raise FileNotFoundError(f"Archive not found: {self.target}")
        self._tempdir = tempfile.TemporaryDirectory(prefix="gn-archive-")
        dest = Path(self._tempdir.name) / "extracted"
        dest.mkdir(parents=True, exist_ok=True)
        suffix = archive.suffix.lower()
        try:
            if suffix == ".zip":
                self._extract_zip(archive, dest)
            else:
                # tarfile auto-detects .tar / .tar.gz / .tar.bz2 / .tar.xz.
                self._extract_tar(archive, dest)
        except Exception:
            if self._tempdir is not None:
                self._tempdir.cleanup()
                self._tempdir = None
            raise
        return dest

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None
