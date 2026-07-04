"""Tests for the engagement .zip bundle (download-everything)."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bundle  # noqa: E402


class BundleFilesTests(unittest.TestCase):
    def test_bundles_explicit_files_with_arcnames(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "a.md").write_text("report", encoding="utf-8")
            (tdp / "b.json").write_text("{}", encoding="utf-8")
            (tdp / "shot.png").write_bytes(b"PNG")
            out = tdp / "out.zip"
            res = bundle.bundle_files(
                [("a.md", tdp / "a.md"), ("b.json", tdp / "b.json"), ("screenshots/shot.png", tdp / "shot.png")], out)
            self.assertTrue(res["ok"])
            self.assertEqual(res["file_count"], 3)  # the manifest is metadata, not counted as an artifact
            with zipfile.ZipFile(out) as zf:
                names = set(zf.namelist())
            # The three artifacts, plus the evidence-integrity manifest every bundle now carries.
            self.assertEqual(names - {"EVIDENCE-MANIFEST.json", "MANIFEST.sha256"},
                             {"a.md", "b.json", "screenshots/shot.png"})
            self.assertIn("EVIDENCE-MANIFEST.json", names)
            self.assertIn("MANIFEST.sha256", names)

    def test_missing_files_are_skipped_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "a.md").write_text("x", encoding="utf-8")
            out = tdp / "out.zip"
            res = bundle.bundle_files([("a.md", tdp / "a.md"), ("gone.md", tdp / "nope.md")], out)
            self.assertTrue(res["ok"])
            self.assertEqual(res["file_count"], 1)
            self.assertIn("gone.md", res["skipped"])

    def test_empty_bundle_is_not_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.zip"
            res = bundle.bundle_files([("gone", Path(td) / "nope")], out)
            self.assertFalse(res["ok"])
            self.assertFalse(out.exists())  # no empty zip left behind


class BundleDirectoryTests(unittest.TestCase):
    def test_bundles_a_tree_relative_to_folder_and_skips_caches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "campaign-acme"
            (src / "targets").mkdir(parents=True)
            (src / "CAMPAIGN.md").write_text("index", encoding="utf-8")
            (src / "targets" / "t1.md").write_text("t1", encoding="utf-8")
            (src / "__pycache__").mkdir()
            (src / "__pycache__" / "junk.pyc").write_bytes(b"junk")
            out = Path(td) / "camp.zip"
            res = bundle.bundle_directory(src, out)
            self.assertTrue(res["ok"])
            with zipfile.ZipFile(out) as zf:
                names = set(zf.namelist())
            self.assertIn("campaign-acme/CAMPAIGN.md", names)        # arcname rooted at the folder
            self.assertIn("campaign-acme/targets/t1.md", names)
            self.assertFalse(any("__pycache__" in n for n in names))  # cache dir excluded

    def test_not_a_directory_errors(self) -> None:
        res = bundle.bundle_directory("/definitely/not/here", "/tmp/x.zip")
        self.assertFalse(res["ok"])


class AddSizeCapTests(unittest.TestCase):
    """Direct unit tests of bundle._add's two size-cap branches and the per-file
    OSError swallow -- previously only reachable by writing real 50MB/200MB files,
    so never exercised. Patches the module-level caps down to a few bytes instead."""

    def test_file_larger_than_max_file_bytes_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "big.bin"
            big.write_bytes(b"x" * 20)
            out = Path(td) / "out.zip"
            state = {"total": 0, "count": 0}
            skipped: list[str] = []
            with mock.patch.object(bundle, "_MAX_FILE_BYTES", 10):
                with zipfile.ZipFile(out, "w") as zf:
                    bundle._add(zf, "big.bin", big, state, skipped)
            self.assertEqual(state, {"total": 0, "count": 0})
            self.assertEqual(len(skipped), 1)
            self.assertIn("too large", skipped[0])
            self.assertIn("20 bytes", skipped[0])
            with zipfile.ZipFile(out) as zf:
                self.assertEqual(zf.namelist(), [])

    def test_total_cap_stops_admitting_further_files_but_keeps_earlier_ones(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f1 = Path(td) / "f1.bin"
            f1.write_bytes(b"a" * 8)
            f2 = Path(td) / "f2.bin"
            f2.write_bytes(b"b" * 5)
            out = Path(td) / "out.zip"
            state = {"total": 0, "count": 0}
            skipped: list[str] = []
            with mock.patch.object(bundle, "_MAX_TOTAL_BYTES", 10):
                with zipfile.ZipFile(out, "w") as zf:
                    bundle._add(zf, "f1.bin", f1, state, skipped)  # 0 + 8 <= 10 -> admitted
                    bundle._add(zf, "f2.bin", f2, state, skipped)  # 8 + 5 > 10 -> capped
            self.assertEqual(state, {"total": 8, "count": 1})
            self.assertEqual(len(skipped), 1)
            self.assertIn("archive size cap reached", skipped[0])
            with zipfile.ZipFile(out) as zf:
                self.assertEqual(zf.namelist(), ["f1.bin"])

    def test_stat_oserror_is_skipped_not_raised(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.zip"
            state = {"total": 0, "count": 0}
            skipped: list[str] = []
            ghost = Path(td) / "ghost.bin"  # never created -> .stat() raises OSError
            with zipfile.ZipFile(out, "w") as zf:
                bundle._add(zf, "ghost.bin", ghost, state, skipped)
            self.assertEqual(state, {"total": 0, "count": 0})
            self.assertEqual(skipped, ["ghost.bin"])

    def test_zf_write_oserror_is_skipped_state_not_advanced(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f1 = Path(td) / "f1.bin"
            f1.write_bytes(b"data")
            out = Path(td) / "out.zip"
            state = {"total": 0, "count": 0}
            skipped: list[str] = []
            with zipfile.ZipFile(out, "w") as zf:
                with mock.patch.object(zf, "write", side_effect=OSError("locked")):
                    bundle._add(zf, "f1.bin", f1, state, skipped)
            self.assertEqual(state, {"total": 0, "count": 0})
            self.assertEqual(skipped, ["f1.bin"])

    def test_bundle_files_end_to_end_respects_patched_total_cap(self) -> None:
        # Integration check: the cap genuinely plumbs through bundle_files, not just
        # the isolated _add unit tests above.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            f1 = tdp / "f1.bin"
            f1.write_bytes(b"a" * 8)
            f2 = tdp / "f2.bin"
            f2.write_bytes(b"b" * 5)
            out = tdp / "out.zip"
            with mock.patch.object(bundle, "_MAX_TOTAL_BYTES", 10):
                res = bundle.bundle_files([("f1.bin", f1), ("f2.bin", f2)], out)
            self.assertTrue(res["ok"])
            self.assertEqual(res["file_count"], 1)
            self.assertTrue(any("archive size cap reached" in s for s in res["skipped"]))


class EvidenceManifestTests(unittest.TestCase):
    """The evidence-integrity manifest is the chain of custody: every bundled artifact must
    carry a verifiable SHA-256 so a triager can prove the proof files are unaltered."""

    @staticmethod
    def _read(zf: zipfile.ZipFile, name: str) -> str:
        return zf.read(name).decode("utf-8")

    def test_manifest_fingerprints_every_artifact_with_correct_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            payloads = {
                "report.md": b"# report body",
                "sidecar.json": b'{"finding": 1}',
                "screenshots/poc.png": b"\x89PNG\r\n\x1a\n not-really-a-png but bytes",
            }
            for name, data in payloads.items():
                p = tdp / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
            out = tdp / "bundle.zip"
            res = bundle.bundle_files([(n, tdp / n) for n in payloads], out,
                                      meta={"tool": "GreyIQ BugHunter", "version": "9.9.9", "generated_at": "2026-07-04 00:00 UTC"})
            self.assertTrue(res["ok"])
            self.assertEqual(res["manifest"], ["EVIDENCE-MANIFEST.json", "MANIFEST.sha256"])
            with zipfile.ZipFile(out) as zf:
                doc = json.loads(self._read(zf, "EVIDENCE-MANIFEST.json"))
                checksums = self._read(zf, "MANIFEST.sha256")
            # Header carries the injected provenance.
            self.assertEqual(doc["algorithm"], "sha256")
            self.assertEqual(doc["version"], "9.9.9")
            self.assertEqual(doc["generated_at"], "2026-07-04 00:00 UTC")
            self.assertEqual(doc["artifact_count"], 3)
            self.assertEqual(doc["total_bytes"], sum(len(d) for d in payloads.values()))
            # Every artifact's recorded digest matches a fresh hash of the ORIGINAL bytes.
            by_path = {e["path"]: e for e in doc["artifacts"]}
            self.assertEqual(set(by_path), set(payloads))
            for name, data in payloads.items():
                expected = hashlib.sha256(data).hexdigest()
                self.assertEqual(by_path[name]["sha256"], expected, f"{name}: manifest digest wrong")
                self.assertEqual(by_path[name]["bytes"], len(data))
                # ...and the same digest appears in the sha256sum -c file, in "<hex>  <path>" form.
                self.assertIn(f"{expected}  {name}", checksums)

    def test_checksum_file_is_valid_sha256sum_c_format(self) -> None:
        # Every non-empty line must be exactly "<64-hex>  <path>" (two spaces) with no comment
        # or stray lines, so `sha256sum -c` accepts it on any coreutils build.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "a.txt").write_bytes(b"alpha")
            (tdp / "b.txt").write_bytes(b"beta")
            out = tdp / "bundle.zip"
            bundle.bundle_files([("a.txt", tdp / "a.txt"), ("b.txt", tdp / "b.txt")], out)
            with zipfile.ZipFile(out) as zf:
                lines = [ln for ln in self._read(zf, "MANIFEST.sha256").splitlines() if ln]
            self.assertEqual(len(lines), 2)
            for ln in lines:
                digest, sep, path = ln.partition("  ")
                self.assertEqual(sep, "  ", f"not two-space separated: {ln!r}")
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                self.assertTrue(path)

    def test_manifest_does_not_fingerprint_itself(self) -> None:
        # The manifest can't hash itself (it's written last); it must never list its own files.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "only.md").write_text("x", encoding="utf-8")
            out = tdp / "bundle.zip"
            bundle.bundle_files([("only.md", tdp / "only.md")], out)
            with zipfile.ZipFile(out) as zf:
                doc = json.loads(self._read(zf, "EVIDENCE-MANIFEST.json"))
            listed = {e["path"] for e in doc["artifacts"]}
            self.assertEqual(listed, {"only.md"})
            self.assertNotIn("EVIDENCE-MANIFEST.json", listed)
            self.assertNotIn("MANIFEST.sha256", listed)

    def test_tampering_is_detectable_via_the_manifest(self) -> None:
        # The whole point: after a file is altered, its real hash no longer matches the manifest.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            evidence = tdp / "evidence.txt"
            evidence.write_bytes(b"the captured HTTP 200 proof")
            out = tdp / "bundle.zip"
            bundle.bundle_files([("evidence.txt", evidence)], out)
            with zipfile.ZipFile(out) as zf:
                recorded = next(e for e in json.loads(self._read(zf, "EVIDENCE-MANIFEST.json"))["artifacts"])["sha256"]
            tampered = hashlib.sha256(b"the captured HTTP 500 proof").hexdigest()
            self.assertNotEqual(recorded, tampered)  # a single byte flip breaks the digest
            self.assertEqual(recorded, hashlib.sha256(b"the captured HTTP 200 proof").hexdigest())

    def test_directory_bundle_manifest_lists_folder_rooted_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "campaign-acme"
            (src / "targets").mkdir(parents=True)
            (src / "CAMPAIGN.md").write_text("index", encoding="utf-8")
            (src / "targets" / "t1.md").write_text("t1", encoding="utf-8")
            out = Path(td) / "camp.zip"
            res = bundle.bundle_directory(src, out, meta={"version": "1.2.3"})
            self.assertTrue(res["ok"])
            with zipfile.ZipFile(out) as zf:
                names = set(zf.namelist())
                doc = json.loads(self._read(zf, "EVIDENCE-MANIFEST.json"))
            # Manifest sits at the archive root (so one `sha256sum -c` covers the whole tree)...
            self.assertIn("EVIDENCE-MANIFEST.json", names)
            self.assertIn("MANIFEST.sha256", names)
            # ...and lists the folder-rooted arcnames that unzip alongside it.
            listed = {e["path"] for e in doc["artifacts"]}
            self.assertEqual(listed, {"campaign-acme/CAMPAIGN.md", "campaign-acme/targets/t1.md"})

    def test_skipped_files_are_recorded_in_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "here.md").write_text("x", encoding="utf-8")
            out = tdp / "bundle.zip"
            bundle.bundle_files([("here.md", tdp / "here.md"), ("gone.md", tdp / "nope.md")], out)
            with zipfile.ZipFile(out) as zf:
                doc = json.loads(self._read(zf, "EVIDENCE-MANIFEST.json"))
            self.assertIn("gone.md", doc["skipped"])
            self.assertEqual({e["path"] for e in doc["artifacts"]}, {"here.md"})

    def test_a_spec_cannot_masquerade_as_the_manifest(self) -> None:
        # A finding artifact named like a manifest file must not shadow the real integrity record.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "evil.sha256").write_text("deadbeef  report.md", encoding="utf-8")
            (tdp / "real.md").write_text("body", encoding="utf-8")
            out = tdp / "bundle.zip"
            res = bundle.bundle_files(
                [("MANIFEST.sha256", tdp / "evil.sha256"), ("real.md", tdp / "real.md")], out)
            self.assertTrue(res["ok"])
            self.assertEqual(res["file_count"], 1)  # the impostor was rejected, only real.md bundled
            self.assertTrue(any("reserved manifest name" in s for s in res["skipped"]))
            with zipfile.ZipFile(out) as zf:
                # The MANIFEST.sha256 in the zip is GreyIQ's, listing real.md — not the impostor's line.
                checksums = self._read(zf, "MANIFEST.sha256")
            self.assertIn("real.md", checksums)
            self.assertNotIn("deadbeef  report.md", checksums)


if __name__ == "__main__":
    unittest.main()
