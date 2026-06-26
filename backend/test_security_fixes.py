"""Regression tests for the QA/QC security fixes: redaction of truncated PEM keys
and whitespace-collapsed dotenv values, the argv-aware recursive-delete denylist,
the net_probe cloud-metadata guard (ops loopback/private still allowed), and the
redacted web proof-evidence carrier."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402
from bughunter.code_scanner.redaction import redact_text  # noqa: E402


class RedactionTests(unittest.TestCase):
    def test_truncated_pem_key_body_does_not_leak(self) -> None:
        body = "MIIBOgIBAAJBAKj34GkxFhD9secretkeymaterial"
        out, redacted = redact_text(f"cfg: -----BEGIN RSA PRIVATE KEY-----  {body} (truncated")
        self.assertTrue(redacted)
        self.assertNotIn(body, out)
        self.assertIn("[REDACTED_PRIVATE_KEY_BLOCK]", out)

    def test_full_pem_still_redacted(self) -> None:
        out, redacted = redact_text("-----BEGIN PRIVATE KEY-----\nMIIBSECRETBODY\n-----END PRIVATE KEY-----")
        self.assertTrue(redacted)
        self.assertNotIn("MIIBSECRETBODY", out)

    def test_collapsed_dotenv_values_all_redacted(self) -> None:
        out, redacted = redact_text("API_TOKEN=abcd1234efgh5678 DB_PASSWORD=supersecretvalue99 PORT=8080")
        self.assertTrue(redacted)
        self.assertNotIn("abcd1234efgh5678", out)
        self.assertNotIn("supersecretvalue99", out)


class DenylistTests(unittest.TestCase):
    def test_separated_recursive_force_flags_blocked(self) -> None:
        self.assertIsNotNone(agent._blocked_command("rm -r -f /tmp/x"))
        self.assertIsNotNone(agent._blocked_command("echo a && rm --recursive --force d"))
        self.assertIsNotNone(agent._blocked_command("rm -rf x"))  # original bundled form still caught

    def test_safe_commands_not_blocked(self) -> None:
        self.assertIsNone(agent._blocked_command("rm file.txt"))
        self.assertIsNone(agent._blocked_command("git status"))
        # force WITHOUT recursive is not the catastrophic case, so it isn't blocked.
        self.assertIsNone(agent._blocked_command("rm -f single.txt"))


class NetProbeGuardTests(unittest.TestCase):
    def _box(self) -> agent.ToolBox:
        return agent.ToolBox(Path(tempfile.gettempdir()), dict(agent.AGENT_DEFAULTS))

    def test_cloud_metadata_blocked(self) -> None:
        box = self._box()
        self.assertIn("Refused", box._metadata_guard("169.254.169.254") or "")
        # The guard is enforced by the probe actions.
        out, is_error = box.run("net_probe", {"action": "http", "target": "http://169.254.169.254/latest/meta-data/"})
        self.assertFalse(is_error)
        self.assertIn("Refused", out)

    def test_ops_targets_still_allowed(self) -> None:
        box = self._box()
        # net_probe is an ops/NOC tool — loopback and RFC1918 private hosts must stay reachable.
        self.assertIsNone(box._metadata_guard("127.0.0.1"))
        self.assertIsNone(box._metadata_guard("10.0.0.5"))
        self.assertIsNone(box._metadata_guard("192.168.1.1"))

    def test_http_redirect_to_metadata_is_blocked(self) -> None:
        # A 30x bounce to a metadata IP must not be auto-followed past the guard.
        handler = agent._MetadataGuardRedirect(self._box()._metadata_guard)
        with self.assertRaises(agent._MetadataBlocked):
            handler.redirect_request(None, None, 302, "Found", {}, "http://169.254.169.254/latest/meta-data/")


class RangedReadTests(unittest.TestCase):
    def test_pages_past_the_size_cap(self) -> None:
        # Ranged read exists to page through a large file — offset beyond max_file_bytes
        # must still reach the right line (the first rewrite regressed this).
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "big.txt").write_text("".join(f"line{i}\n" for i in range(1, 60000)), encoding="utf-8")
            box = agent.ToolBox(Path(tmp), dict(agent.AGENT_DEFAULTS))
            out = box.run("read_file", {"path": "big.txt", "offset": 50000, "limit": 3})[0]
            self.assertIn("line50000", out)
            self.assertIn("line50002", out)

    def test_no_newline_file_is_clipped_not_loaded_whole(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "huge.txt").write_text("A" * 2_000_000, encoding="utf-8")
            box = agent.ToolBox(Path(tmp), dict(agent.AGENT_DEFAULTS))
            out = box.run("read_file", {"path": "huge.txt", "offset": 1, "limit": 5})[0]
            self.assertLess(len(out), 50_000)  # clipped, not the full 2 MB


if __name__ == "__main__":
    unittest.main()
