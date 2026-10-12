"""Small, local-only fixtures for the sharded Hugging Face GGUF fallback."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import hf_gguf_import as hf_import  # noqa: E402


REVISION = "a" * 40
HOST = "http://127.0.0.1:11434"
REF = "hf.co/acme/Sample-GGUF"


def sibling(folder: str, stem: str, index: int, count: int, payload: bytes) -> dict:
    name = f"{stem}-{index:05d}-of-{count:05d}.gguf"
    path = f"{folder}/{name}" if folder else name
    size = len(payload)
    return {"rfilename": path, "size": size,
            "lfs": {"sha256": hashlib.sha256(payload).hexdigest(), "size": size}}


class _Response(io.BytesIO):
    def __init__(self, payload: bytes, url: str = "https://cdn-lfs.hf.co/file"):
        super().__init__(payload)
        self.url = url

    def geturl(self) -> str:
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class GroupSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.files = [
            sibling("IQ2_XS", "model-IQ2_XS", 1, 2, b"small-one"),
            sibling("IQ2_XS", "model-IQ2_XS", 2, 2, b"small-two"),
            sibling("IQ3_S", "model-IQ3_S", 1, 2, b"bigger-one" * 2),
            sibling("IQ3_S", "model-IQ3_S", 2, 2, b"bigger-two" * 2),
        ]

    def test_untagged_reference_selects_smallest_complete_variant(self) -> None:
        group = hf_import._select_group(self.files, "")
        self.assertEqual(group.quant, "IQ2_XS")
        self.assertEqual([part.index for part in group.shards], [1, 2])

    def test_explicit_tag_selects_matching_variant(self) -> None:
        group = hf_import._select_group(self.files, "iq3_s")
        self.assertEqual(group.quant, "IQ3_S")
        self.assertEqual(group.size, len(b"bigger-one" * 2) + len(b"bigger-two" * 2))

    def test_incomplete_or_unverified_shards_are_never_selected(self) -> None:
        with self.assertRaisesRegex(coder.CoderError, "No complete"):
            hf_import._select_group(self.files[:1], "")
        corrupted = [dict(item) for item in self.files[:2]]
        corrupted[1] = {**corrupted[1], "lfs": {"size": corrupted[1]["size"]}}
        with self.assertRaisesRegex(coder.CoderError, "No complete"):
            hf_import._select_group(corrupted, "")

    def test_tag_mismatch_lists_available_variants(self) -> None:
        with self.assertRaisesRegex(coder.CoderError, "Available: IQ2_XS, IQ3_S"):
            hf_import._select_group(self.files, "Q4_K_M")

    def test_unsafe_repo_path_is_ignored(self) -> None:
        unsafe = [
            {**self.files[0], "rfilename": "../model-00001-of-00002.gguf"},
            self.files[1],
        ]
        with self.assertRaisesRegex(coder.CoderError, "No complete"):
            hf_import._select_group(unsafe, "")

    def test_generic_parent_does_not_become_quantization_tag(self) -> None:
        files = [sibling("models", "model-Q4_K_M", 1, 2, b"abc"),
                 sibling("models", "model-Q4_K_M", 2, 2, b"def")]
        self.assertEqual(hf_import._select_group(files, "").quant, "Q4_K_M")
        self.assertEqual(hf_import._select_group(files, "Q4_K_M").quant, "Q4_K_M")


class MetadataAndPreflightTests(unittest.TestCase):
    def test_metadata_requires_public_pinned_file_list(self) -> None:
        payload = {"sha": REVISION, "gated": False, "siblings": []}
        with patch.object(hf_import.urllib.request, "urlopen", return_value=_Response(json.dumps(payload).encode())):
            self.assertEqual(hf_import._metadata("acme/Sample-GGUF"), (REVISION, []))
        for invalid in ({"sha": "main", "siblings": []},
                        {"sha": REVISION, "gated": "manual", "siblings": []}):
            with self.subTest(invalid=invalid), \
                    patch.object(hf_import.urllib.request, "urlopen", return_value=_Response(json.dumps(invalid).encode())):
                with self.assertRaises(coder.CoderError):
                    hf_import._metadata("acme/Sample-GGUF")

    def test_disk_preflight_fails_before_any_weight_get(self) -> None:
        files = [sibling("Q4", "model-Q4", 1, 2, b"abc"), sibling("Q4", "model-Q4", 2, 2, b"def")]
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_metadata", return_value=(REVISION, files)), \
                    patch.object(hf_import, "_check_ollama_version"), \
                    patch.object(coder, "ollama_list_models", return_value=[]), \
                    patch.object(hf_import, "_blob_exists", return_value=False), \
                    patch.object(hf_import.shutil, "disk_usage", return_value=SimpleNamespace(free=0)), \
                    patch.object(hf_import.urllib.request, "urlopen") as open_url:
                with self.assertRaisesRegex(coder.CoderError, "needs about.*only 0.0 GiB"):
                    hf_import.import_sharded_hf_model(
                        HOST, REF, Path(tmp) / "cache", lambda _event: None,
                        models_root=Path(tmp) / "models",
                    )
                open_url.assert_not_called()

    def test_unknown_ollama_store_blocks_split_upload_before_weight_get(self) -> None:
        files = [sibling("Q4", "model-Q4", 1, 2, b"abc"), sibling("Q4", "model-Q4", 2, 2, b"def")]
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_metadata", return_value=(REVISION, files)), \
                    patch.object(hf_import, "_check_ollama_version"), \
                    patch.object(coder, "ollama_list_models", return_value=[]), \
                    patch.object(hf_import, "_blob_exists", return_value=False), \
                    patch.object(hf_import.shutil, "disk_usage") as disk_usage, \
                    patch.object(hf_import.urllib.request, "urlopen") as weight_get, \
                    patch.object(hf_import, "_upload_blob") as upload, \
                    patch.object(hf_import, "_create") as create:
                with self.assertRaises(coder.CoderError) as raised:
                    hf_import.import_sharded_hf_model(HOST, REF, Path(tmp) / "cache", lambda _event: None)
                message = str(raised.exception)
                self.assertIn("Stop the pre-existing Ollama server", message)
                self.assertIn("GREYIQ_RUNTIME_DIR", message)
                self.assertIn("OLLAMA_MODELS", message)
                disk_usage.assert_not_called()
                weight_get.assert_not_called()
                upload.assert_not_called()
                create.assert_not_called()

    def test_fat32_preflight_rejects_oversized_shards_before_download(self) -> None:
        large = sibling("Q4", "model-Q4", 1, 2, b"stub")
        large["size"] = hf_import._FAT32_MAX_FILE + 1
        large["lfs"]["size"] = large["size"]
        files = [large, sibling("Q4", "model-Q4", 2, 2, b"small")]
        group = hf_import._select_group(files, "")
        with tempfile.TemporaryDirectory() as tmp:
            for filesystems, location in (
                (("FAT32", "NTFS"), "GreyIQ cache"),
                (("NTFS", "FAT32"), "Ollama model store"),
            ):
                with self.subTest(location=location), \
                        patch.object(hf_import, "_windows_filesystem_type", side_effect=filesystems), \
                        patch.object(hf_import.shutil, "disk_usage") as disk_usage:
                    with self.assertRaisesRegex(coder.CoderError, location) as raised:
                        hf_import._preflight(Path(tmp), Path(tmp) / "models", group)
                    self.assertIn("NTFS or exFAT", str(raised.exception))
                    disk_usage.assert_not_called()

    def test_large_shard_on_ntfs_and_exfat_passes_file_limit_check(self) -> None:
        large = sibling("Q4", "model-Q4", 1, 2, b"stub")
        large["size"] = hf_import._FAT32_MAX_FILE + 1
        large["lfs"]["size"] = large["size"]
        group = hf_import._select_group([large, sibling("Q4", "model-Q4", 2, 2, b"small")], "")
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_windows_filesystem_type", side_effect=("NTFS", "EXFAT")), \
                    patch.object(hf_import.shutil, "disk_usage", return_value=SimpleNamespace(free=10**13)):
                hf_import._preflight(Path(tmp), Path(tmp) / "models", group)

    def test_small_shards_do_not_require_windows_filesystem_lookup(self) -> None:
        files = [sibling("Q4", "model-Q4", 1, 2, b"abc"), sibling("Q4", "model-Q4", 2, 2, b"def")]
        group = hf_import._select_group(files, "")
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_windows_filesystem_type") as filesystem, \
                    patch.object(hf_import.shutil, "disk_usage", return_value=SimpleNamespace(free=10**13)):
                hf_import._preflight(Path(tmp), Path(tmp) / "models", group)
                filesystem.assert_not_called()

    def test_same_volume_preflight_uses_sequential_peak(self) -> None:
        files = [sibling("Q4", "model-Q4", 1, 2, b"abc"), sibling("Q4", "model-Q4", 2, 2, b"defg")]
        group = hf_import._select_group(files, "")
        # Largest-first peak is max(2*4, 4+2*3) = 10, not 2*total = 14.
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_MIN_HEADROOM", 0), \
                    patch.object(hf_import.shutil, "disk_usage", return_value=SimpleNamespace(free=10)):
                hf_import._preflight(Path(tmp), Path(tmp) / "models", group)
            with patch.object(hf_import, "_MIN_HEADROOM", 0), \
                    patch.object(hf_import.shutil, "disk_usage", return_value=SimpleNamespace(free=9)):
                with self.assertRaisesRegex(coder.CoderError, "needs about"):
                    hf_import._preflight(Path(tmp), Path(tmp) / "models", group)

    def test_separate_volume_preflight_budgets_cache_and_models_independently(self) -> None:
        files = [sibling("Q4", "model-Q4", 1, 2, b"abc"), sibling("Q4", "model-Q4", 2, 2, b"defg")]
        group = hf_import._select_group(files, "")
        drives = [SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=1)),
                  SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=2))]
        with patch.object(hf_import, "_MIN_HEADROOM", 0), \
                patch.object(hf_import, "_nearest_existing", side_effect=drives), \
                patch.object(hf_import.shutil, "disk_usage", side_effect=[SimpleNamespace(free=4),
                                                                          SimpleNamespace(free=7)]):
            # Cache needs only the largest shard (4), not both shards (7).
            hf_import._preflight(Path("cache"), Path("models"), group)

    def test_separate_volume_retry_uses_cached_shard_space_for_next_download(self) -> None:
        files = [sibling("Q4", "model-Q4", 1, 2, b"abc"), sibling("Q4", "model-Q4", 2, 2, b"defg")]
        group = hf_import._select_group(files, "")
        largest, next_shard = sorted(group.shards, key=lambda shard: -shard.size)
        states = (
            hf_import._ShardState(largest, Path("cache/big.gguf"), False, True),
            hf_import._ShardState(next_shard, Path("cache/small.gguf"), False, False),
        )
        drives = [SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=1)),
                  SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=2))]
        with patch.object(hf_import, "_MIN_HEADROOM", 0), \
                patch.object(hf_import, "_nearest_existing", side_effect=drives), \
                patch.object(hf_import.shutil, "disk_usage", side_effect=[SimpleNamespace(free=0),
                                                                          SimpleNamespace(free=7)]):
            # The cached 4-byte shard is freed after upload, so the next
            # 3-byte download needs no additional cache capacity from here.
            hf_import._preflight(Path("cache"), Path("models"), group, states)

    def test_remote_ollama_is_rejected_before_hf_request(self) -> None:
        with patch.object(hf_import, "_metadata") as metadata:
            with self.assertRaisesRegex(coder.CoderError, "local Ollama"):
                hf_import.import_sharded_hf_model("https://server.example", REF, Path("."), lambda _event: None)
            metadata.assert_not_called()

    def test_split_gguf_requires_ollama_035_before_weight_get(self) -> None:
        files = [sibling("Q4", "model-Q4", 1, 2, b"abc"), sibling("Q4", "model-Q4", 2, 2, b"def")]
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_metadata", return_value=(REVISION, files)), \
                    patch.object(coder, "_ollama_open", return_value=_Response(b'{"version":"0.34.2"}')), \
                    patch.object(hf_import.urllib.request, "urlopen") as weight_get, \
                    patch.object(hf_import, "_blob_exists") as blob_check:
                with self.assertRaisesRegex(coder.CoderError, "0.35.0 or newer"):
                    hf_import.import_sharded_hf_model(HOST, REF, Path(tmp), lambda _event: None)
                weight_get.assert_not_called()
                blob_check.assert_not_called()

    def test_split_version_gate_accepts_newer_and_rejects_malformed(self) -> None:
        for version in ("0.35.0", "0.35.1", "0.36.0", "v0.35.0"):
            with self.subTest(version=version), \
                    patch.object(coder, "_ollama_open", return_value=_Response(json.dumps({"version": version}).encode())):
                hf_import._check_ollama_version(HOST)
        for version in ("0.34.4", "0.35.0-rc1", "unknown", ""):
            with self.subTest(version=version), \
                    patch.object(coder, "_ollama_open", return_value=_Response(json.dumps({"version": version}).encode())):
                with self.assertRaises(coder.CoderError):
                    hf_import._check_ollama_version(HOST)


class ImportWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.weights = {"Q4/model-Q4-00001-of-00002.gguf": b"abc", "Q4/model-Q4-00002-of-00002.gguf": b"defg"}
        self.files = [sibling("Q4", "model-Q4", i, 2, payload)
                      for i, payload in enumerate(self.weights.values(), 1)]

    def _open_weight(self, url: str, timeout: int) -> _Response:
        self.assertIn(f"/resolve/{REVISION}/", url)
        filename = url.split(f"/resolve/{REVISION}/", 1)[1]
        return _Response(self.weights[filename])

    def test_verified_shards_upload_and_create_using_original_names(self) -> None:
        uploads: list[tuple[str, bytes]] = []
        creates: list[dict] = []
        events: list[dict] = []

        class FakeConnection:
            def __init__(self, hostname, port, timeout):
                self.path = ""
                self.body = bytearray()

            def putrequest(self, method, path):
                self.path = path
                self.method = method

            def putheader(self, *_):
                pass

            def endheaders(self):
                pass

            def send(self, chunk):
                self.body.extend(chunk)

            def getresponse(self):
                uploads.append((self.path, bytes(self.body)))
                return SimpleNamespace(status=201, read=lambda _size: b"")

            def close(self):
                pass

        def ollama_open(request, timeout):
            creates.append(json.loads(request.data))
            return _Response(b'{"status":"parsing GGUF"}\n{"status":"success"}\n')

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_metadata", return_value=(REVISION, self.files)), \
                    patch.object(hf_import, "_check_ollama_version"), \
                    patch.object(hf_import, "_preflight"), \
                    patch.object(coder, "ollama_list_models", return_value=[]), \
                    patch.object(hf_import.urllib.request, "urlopen", side_effect=self._open_weight), \
                    patch.object(hf_import, "_blob_exists", return_value=False), \
                    patch.object(hf_import.http.client, "HTTPConnection", FakeConnection), \
                    patch.object(coder, "_ollama_open", side_effect=ollama_open):
                alias = hf_import.import_sharded_hf_model(HOST, REF, Path(tmp), events.append)
                self.assertEqual(list(Path(tmp).rglob("*.gguf")), [])
        self.assertTrue(alias.startswith("greyiq-hf/acme-sample-gguf-"))
        self.assertTrue(alias.endswith(":q4"))
        self.assertEqual([body for _path, body in uploads], [b"defg", b"abc"])
        self.assertEqual([path for path, _body in uploads],
                         [f"/api/blobs/sha256:{item['lfs']['sha256']}" for item in reversed(self.files)])
        self.assertEqual(creates[0]["model"], alias)
        self.assertEqual(creates[0]["files"],
                         {Path(item["rfilename"]).name: f"sha256:{item['lfs']['sha256']}" for item in self.files})
        self.assertEqual(events[-1]["status"], "success")
        self.assertEqual(events[-3]["completed"], 14)

    def test_corrupt_download_never_uploads(self) -> None:
        bad = [dict(item) for item in self.files]
        bad[1] = {**bad[1], "lfs": {"sha256": "0" * 64, "size": bad[1]["size"]}}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_metadata", return_value=(REVISION, bad)), \
                    patch.object(hf_import, "_check_ollama_version"), \
                    patch.object(hf_import, "_preflight"), \
                    patch.object(coder, "ollama_list_models", return_value=[]), \
                    patch.object(hf_import, "_blob_exists", return_value=False), \
                    patch.object(hf_import.urllib.request, "urlopen", side_effect=self._open_weight), \
                    patch.object(hf_import, "_upload_blob") as upload:
                with self.assertRaisesRegex(coder.CoderError, "did not match"):
                    hf_import.import_sharded_hf_model(HOST, REF, Path(tmp), lambda _event: None)
                upload.assert_not_called()

    def test_upload_failure_keeps_verified_shard_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_metadata", return_value=(REVISION, self.files)), \
                    patch.object(hf_import, "_check_ollama_version"), \
                    patch.object(hf_import, "_preflight"), \
                    patch.object(coder, "ollama_list_models", return_value=[]), \
                    patch.object(hf_import, "_blob_exists", return_value=False), \
                    patch.object(hf_import.urllib.request, "urlopen", side_effect=self._open_weight), \
                    patch.object(hf_import, "_upload_blob", side_effect=coder.CoderError("upload interrupted")):
                with self.assertRaisesRegex(coder.CoderError, "upload interrupted"):
                    hf_import.import_sharded_hf_model(HOST, REF, Path(tmp), lambda _event: None)
            saved = list(Path(tmp).rglob("*.gguf"))
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0].read_bytes(), b"defg")

            def accepted(_host, shard, _path, progress_cb):
                progress_cb({"status": "uploaded", "completed": shard.size})

            # The first shard is already in the cache and free space has fallen
            # below the cold-start peak of 10 bytes. The retry only needs 6.
            with patch.object(hf_import, "_metadata", return_value=(REVISION, self.files)), \
                    patch.object(hf_import, "_check_ollama_version"), \
                    patch.object(coder, "ollama_list_models", return_value=[]), \
                    patch.object(hf_import, "_blob_exists", return_value=False), \
                    patch.object(hf_import, "_MIN_HEADROOM", 0), \
                    patch.object(hf_import.shutil, "disk_usage", return_value=SimpleNamespace(free=9)), \
                    patch.object(hf_import.urllib.request, "urlopen", side_effect=self._open_weight) as weights, \
                    patch.object(hf_import, "_upload_blob", side_effect=accepted), \
                    patch.object(hf_import, "_create"):
                hf_import.import_sharded_hf_model(
                    HOST, REF, Path(tmp), lambda _event: None, models_root=Path(tmp) / "models"
                )
                self.assertEqual(weights.call_count, 1)
                self.assertIn("00001-of-00002.gguf", weights.call_args.args[0])
            self.assertEqual(list(Path(tmp).rglob("*.gguf")), [])

    def test_create_failure_retry_reuses_ollama_blobs_without_weight_get(self) -> None:
        blobs: set[str] = set()

        def accepted(_host, shard, _path, progress_cb):
            blobs.add(shard.sha256)
            progress_cb({"status": "uploaded", "completed": shard.size})

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_metadata", return_value=(REVISION, self.files)), \
                    patch.object(hf_import, "_check_ollama_version"), \
                    patch.object(coder, "ollama_list_models", return_value=[]), \
                    patch.object(hf_import, "_blob_exists", side_effect=lambda _host, digest: digest in blobs), \
                    patch.object(hf_import, "_preflight") as preflight, \
                    patch.object(hf_import.urllib.request, "urlopen", side_effect=self._open_weight) as weights, \
                    patch.object(hf_import, "_upload_blob", side_effect=accepted) as upload, \
                    patch.object(hf_import, "_create", side_effect=[coder.CoderError("create failed"), None]) as create:
                with self.assertRaisesRegex(coder.CoderError, "create failed"):
                    hf_import.import_sharded_hf_model(HOST, REF, Path(tmp), lambda _event: None)
                self.assertEqual(weights.call_count, 2)
                self.assertEqual(upload.call_count, 2)
                alias = hf_import.import_sharded_hf_model(HOST, REF, Path(tmp), lambda _event: None)
                self.assertEqual(weights.call_count, 2)
                self.assertEqual(upload.call_count, 2)
                self.assertEqual(preflight.call_count, 1)
                self.assertEqual(create.call_count, 2)
                self.assertTrue(alias.startswith("greyiq-hf/"))

    def test_unknown_store_can_create_when_every_blob_already_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hf_import, "_metadata", return_value=(REVISION, self.files)), \
                    patch.object(hf_import, "_check_ollama_version"), \
                    patch.object(coder, "ollama_list_models", return_value=[]), \
                    patch.object(hf_import, "_blob_exists", return_value=True), \
                    patch.object(hf_import, "_preflight") as preflight, \
                    patch.object(hf_import.urllib.request, "urlopen") as weight_get, \
                    patch.object(hf_import, "_upload_blob") as upload, \
                    patch.object(hf_import, "_create") as create:
                alias = hf_import.import_sharded_hf_model(HOST, REF, Path(tmp), lambda _event: None)
                self.assertTrue(alias.startswith("greyiq-hf/"))
                preflight.assert_not_called()
                weight_get.assert_not_called()
                upload.assert_not_called()
                create.assert_called_once()

    def test_ollama_create_error_is_explained_without_success(self) -> None:
        group = hf_import._select_group(self.files, "Q4")
        with patch.object(coder, "_ollama_open", return_value=_Response(b'{"error":"unsupported GGUF architecture"}\n')):
            with self.assertRaisesRegex(coder.CoderError, "unsupported GGUF architecture"):
                hf_import._create(HOST, "greyiq-hf/test:q4", group, lambda _event: None)


if __name__ == "__main__":
    unittest.main()
