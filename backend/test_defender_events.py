"""Integrity and privacy tests for the append-only defender event journal."""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from defender.events import (  # noqa: E402
    EventLogIntegrityError, append_event, read_events, verify_artifacts, verify_events,
)


class DefenderEventTests(unittest.TestCase):
    def test_append_read_verify_chain_and_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = append_event(directory, {
                "type": "scan_started", "message": "token=hidden Bearer secretvalue scan started",
                "evidence": {"pid": 12, "remote_address": "203.0.113.7",
                             "command_line": "curl -H Authorization:secret", "packet_payload": "password=oops",
                             "url": "https://user:pass@example.test/path?api_key=hidden"},
            })
            second = append_event(directory, {"type": "scan_completed", "severity": "info",
                                              "evidence": {"finding_count": 2, "artifact_sha256": "a" * 64}})
            self.assertEqual((first["sequence"], second["sequence"]), (1, 2))
            self.assertEqual(second["prev_hash"], first["hash"])
            self.assertEqual(verify_events(directory)["event_count"], 2)
            recent = read_events(directory, limit=1)
            self.assertEqual([record["type"] for record in recent], ["scan_completed"])
            on_disk = (Path(directory) / "defender" / "events.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("hidden", on_disk)
            self.assertNotIn("secretvalue", on_disk)
            self.assertNotIn("packet_payload", on_disk)
            self.assertNotIn("command_line", on_disk)
            self.assertEqual(first["evidence"]["url"], "https://example.test/path")
            self.assertIn("token=<redacted>", first["message"])
            self.assertIn("Bearer <redacted>", first["message"])
            if os.name != "nt":
                self.assertEqual((Path(directory) / "defender" / "events.jsonl").stat().st_mode & 0o777, 0o600)

    def test_modified_record_breaks_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            append_event(directory, {"type": "scan_started"})
            append_event(directory, {"type": "scan_completed"})
            path = Path(directory) / "defender" / "events.jsonl"
            lines = path.read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[0])
            record["type"] = "tampered"
            lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = verify_events(directory)
            self.assertFalse(result["ok"])
            self.assertIn("hash", result["error"])

    def test_tail_truncation_detected_against_head_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            append_event(directory, {"type": "first"})
            append_event(directory, {"type": "second"})
            path = Path(directory) / "defender" / "events.jsonl"
            first_line = path.read_bytes().splitlines(keepends=True)[0]
            path.write_bytes(first_line)
            result = verify_events(directory)
            self.assertFalse(result["ok"])
            self.assertIn("checkpoint", result["error"])
            with self.assertRaises(EventLogIntegrityError):
                append_event(directory, {"type": "third"})

    def test_rejects_bad_event_type_and_negative_read_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                append_event(directory, {"type": "scan started"})
            with self.assertRaises(ValueError):
                read_events(directory, -1)

    def test_artifact_verification_detects_change_and_rejects_external_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory) / "defender" / "runs"
            runs.mkdir(parents=True)
            artifact = runs / "one.json.gz"
            original = b"compressed evidence fixture"
            artifact.write_bytes(original)
            append_event(directory, {"type": "scan", "evidence": {
                "artifact_path": str(artifact),
                "artifact_sha256": hashlib.sha256(original).hexdigest(),
            }})
            self.assertEqual(verify_artifacts(directory)["verified"], 1)
            artifact.write_bytes(b"changed")
            result = verify_artifacts(directory)
            self.assertFalse(result["ok"])
            self.assertIn("digest mismatch", result["error"])

        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "outside.json.gz"
            outside.write_bytes(b"outside")
            append_event(directory, {"type": "scan", "evidence": {
                "artifact_path": str(outside),
                "artifact_sha256": hashlib.sha256(b"outside").hexdigest(),
            }})
            self.assertIn("outside this runtime", verify_artifacts(directory)["error"])

    def test_relative_artifact_reference_survives_runtime_relocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            archive = Path(directory) / "archive"
            runs = source / "defender" / "runs"
            runs.mkdir(parents=True)
            artifact = runs / "one.json.gz"
            artifact.write_bytes(b"saved observation")
            append_event(source, {"type": "scan", "evidence": {
                "artifact_path": str(artifact), "artifact_relpath": "runs/one.json.gz",
                "artifact_sha256": hashlib.sha256(b"saved observation").hexdigest(),
            }})
            shutil.copytree(source / "defender", archive / "defender")
            self.assertTrue(verify_artifacts(archive)["ok"])


if __name__ == "__main__":
    unittest.main()
