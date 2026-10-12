"""Electron-only model-store handoff and split-import preflight selection."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import greyiq_api as api  # noqa: E402
import hf_gguf_import  # noqa: E402


def post_store(value: object, *, token: str = "private-secret", peer: str = "127.0.0.1",
               access_key: str = "") -> tuple[int, dict]:
    payload = json.dumps({"models_dir": value}).encode("utf-8")
    sent = False
    messages = []

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message):
        messages.append(message)

    headers = [
        (b"host", b"127.0.0.1:8766"),
        (b"x-greyiq-internal-model-store-token", token.encode("ascii")),
        (b"content-type", b"application/json"),
    ]
    if access_key:
        headers.append((b"authorization", b"Basic " + base64.b64encode(f":{access_key}".encode())))
    scope = {
        "method": "POST", "path": "/api/internal/ollama-model-store",
        "scheme": "http", "query_string": b"", "client": (peer, 55123),
        "headers": headers,
    }
    asyncio.run(api.route_http(scope, receive, send))
    return messages[0]["status"], json.loads(messages[-1]["body"])


class InternalStoreRouteTests(unittest.TestCase):
    def test_only_private_loopback_request_updates_store(self) -> None:
        updates: list[object] = []
        fake_runtime = SimpleNamespace(set_managed_ollama_models_dir=updates.append)
        with patch.object(api, "INTERNAL_MODEL_STORE_TOKEN", "private-secret"), \
                patch.object(api, "runtime", fake_runtime):
            self.assertEqual(post_store("/var/lib/greyiq-models", token="wrong")[0], 403)
            self.assertEqual(post_store("/var/lib/greyiq-models", peer="192.0.2.1")[0], 403)
            self.assertEqual(updates, [])
            self.assertEqual(post_store("/var/lib/greyiq-models")[0], 200)
            self.assertEqual(post_store(None)[0], 200)
        self.assertEqual(updates, ["/var/lib/greyiq-models", None])

    def test_internal_route_is_disabled_without_electron_secret(self) -> None:
        with patch.object(api, "INTERNAL_MODEL_STORE_TOKEN", ""):
            self.assertEqual(post_store(None, token="")[0], 403)

    def test_access_key_gate_accepts_electron_basic_header(self) -> None:
        updates: list[object] = []
        fake_runtime = SimpleNamespace(set_managed_ollama_models_dir=updates.append)
        with patch.object(api, "INTERNAL_MODEL_STORE_TOKEN", "private-secret"), \
                patch.object(api, "GREYIQ_ACCESS_KEY", "operator-key"), \
                patch.object(api, "runtime", fake_runtime):
            self.assertEqual(post_store(None)[0], 401)
            self.assertEqual(post_store(None, access_key="operator-key")[0], 200)
        self.assertEqual(updates, [None])

    def test_store_requires_absolute_path(self) -> None:
        instance = object.__new__(api.GreyIQRuntime)
        instance.lock = threading.RLock()
        instance.managed_ollama_models_dir = None
        with self.assertRaises(api.HTTPError):
            instance.set_managed_ollama_models_dir("relative/models")
        absolute = Path.cwd() / "models"
        instance.set_managed_ollama_models_dir(str(absolute))
        self.assertEqual(instance.managed_ollama_models_dir, absolute.resolve())
        instance.set_managed_ollama_models_dir(None)
        self.assertIsNone(instance.managed_ollama_models_dir)


class SetupStoreSelectionTests(unittest.TestCase):
    def test_only_default_local_host_receives_managed_store(self) -> None:
        managed = Path.cwd() / "ollama-models"
        operator = Path.cwd() / "operator-ollama-models"
        cases = (
            ("", managed, "ignored", managed),
            ("http://localhost:11434", managed, "ignored", None),
            ("", None, str(operator), None),
        )
        for base_url, managed_store, configured_store, expected in cases:
            with self.subTest(base_url=base_url):
                instance = object.__new__(api.GreyIQRuntime)
                instance.lock = threading.RLock()
                instance.model_pull = {"active": False}
                instance.managed_ollama_models_dir = managed_store
                instance._coder_config = lambda: {"enabled": False, "provider": "off", "local": {}}
                instance.save_coder_config = lambda _update: None
                instance.log = lambda *_args: None
                installed: list[str] = []
                received: list[Path | None] = []
                alias = "greyiq-hf/test:split"

                def import_shards(_host, _ref, _cache, _progress, models_root=None):
                    received.append(models_root)
                    installed.append(alias)
                    return alias

                with patch.dict(os.environ, {"OLLAMA_MODELS": configured_store}), \
                        patch.object(api, "INTERNAL_MODEL_STORE_TOKEN", "private-secret"), \
                        patch.object(coder, "ollama_list_models", side_effect=lambda _host: list(installed)), \
                        patch.object(coder, "check_public_hf_gguf"), \
                        patch.object(coder, "ollama_pull", side_effect=coder.CoderError("sharded GGUF")), \
                        patch.object(hf_gguf_import, "import_sharded_hf_model", side_effect=import_shards), \
                        patch.object(coder, "ollama_probe_readiness", return_value={"chat_ready": True, "tool_ready": True}):
                    instance.start_model_setup("hf.co/acme/Test-GGUF", base_url=base_url)
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline and not instance.model_pull_status().get("done"):
                        time.sleep(0.01)
                self.assertEqual(received, [expected])
                self.assertTrue(instance.model_pull_status().get("selected"))


if __name__ == "__main__":
    unittest.main()
