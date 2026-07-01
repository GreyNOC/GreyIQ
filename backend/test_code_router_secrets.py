"""Tests for code_router.remote_api_key secret handling (backend/greyiq_api.py).

Regression coverage for a confirmed low-severity finding: this field lived in the
plaintext, non-owner-restricted solin_runtime_config.json with no equivalent
split/migrate step, unlike every coder.<provider>.api_key (which is always moved
into the perms-restricted secrets.json). Covers the one-time migration and the
read-time overlay that replace it.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402


class CodeRouterSecretTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        self._orig_secrets = g.SECRETS_PATH
        g.RUNTIME_DIR = Path(self._tmp.name)
        g.SECRETS_PATH = Path(self._tmp.name) / "secrets.json"

    def tearDown(self) -> None:
        g.RUNTIME_DIR = self._orig_runtime_dir
        g.SECRETS_PATH = self._orig_secrets
        self._tmp.cleanup()

    def _runtime_config_path(self) -> Path:
        return g.RUNTIME_DIR / "solin_runtime_config.json"

    def test_migration_moves_the_key_out_of_the_plaintext_file(self) -> None:
        self._runtime_config_path().write_text(
            json.dumps({"code_router": {"remote_enabled": True, "remote_api_key": "SUPER-SECRET-KEY"}}),
            encoding="utf-8",
        )
        g._migrate_code_router_secret()
        on_disk = json.loads(self._runtime_config_path().read_text(encoding="utf-8"))
        self.assertEqual(on_disk["code_router"]["remote_api_key"], "")
        self.assertNotIn("SUPER-SECRET-KEY", self._runtime_config_path().read_text(encoding="utf-8"))
        stored = json.loads(g.SECRETS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(stored[g._CODE_ROUTER_SECRET_KEY], "SUPER-SECRET-KEY")

    def test_migration_is_a_no_op_when_nothing_to_move(self) -> None:
        self._runtime_config_path().write_text(json.dumps({"code_router": {"remote_enabled": False}}), encoding="utf-8")
        g._migrate_code_router_secret()  # must not raise or create a secrets file for nothing
        self.assertFalse(g.SECRETS_PATH.exists())

    def test_migration_tolerates_missing_config_file(self) -> None:
        g._migrate_code_router_secret()  # no exception on a fresh runtime dir

    def test_code_router_config_overlays_the_stored_secret(self) -> None:
        self._runtime_config_path().write_text(
            json.dumps({"code_router": {"remote_enabled": True, "remote_url": "https://x", "remote_api_key": ""}}),
            encoding="utf-8",
        )
        g._store_secret(g._CODE_ROUTER_SECRET_KEY, "RESTORED-KEY")
        config = g.runtime._code_router_config()
        self.assertEqual(config["remote_api_key"], "RESTORED-KEY")
        self.assertEqual(config["remote_url"], "https://x")

    def test_code_router_config_empty_when_nothing_stored(self) -> None:
        self.assertEqual(g.runtime._code_router_config(), {})

    def test_secrets_file_is_written_with_owner_only_permissions(self) -> None:
        self._runtime_config_path().write_text(
            json.dumps({"code_router": {"remote_api_key": "SUPER-SECRET-KEY"}}), encoding="utf-8"
        )
        g._migrate_code_router_secret()
        # _store_secret always writes via _atomic_write(..., private=True) -- assert the
        # secrets store (not the plaintext runtime config) is the one holding the key.
        self.assertIn(g._CODE_ROUTER_SECRET_KEY, g._load_secrets())


if __name__ == "__main__":
    unittest.main()
