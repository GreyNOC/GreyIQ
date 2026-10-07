"""One-click local model setup without real downloads or model execution."""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import greyiq_api as api  # noqa: E402


class ReferenceTests(unittest.TestCase):
    def test_normalizes_hf_page_name_and_ollama_snippet(self) -> None:
        for raw in (
            "hf.co/acme/Code-GGUF:Q4_K_M",
            "https://huggingface.co/acme/Code-GGUF:Q4_K_M",
            "ollama run hf.co/acme/Code-GGUF:Q4_K_M",
            "ollama pull huggingface.co/acme/Code-GGUF:Q4_K_M",
        ):
            with self.subTest(raw=raw):
                self.assertEqual(
                    coder.normalize_local_model_reference(raw),
                    ("hf.co/acme/Code-GGUF:Q4_K_M", True),
                )

    def test_accepts_ordinary_ollama_name(self) -> None:
        self.assertEqual(coder.normalize_local_model_reference("qwen2.5-coder:14b"), ("qwen2.5-coder:14b", False))
        self.assertTrue(coder.model_installed(["HF.CO/acme/Code-GGUF:q4_k_m"], "hf.co/acme/Code-GGUF:Q4_K_M"))

    def test_validates_ollama_server_origin(self) -> None:
        self.assertEqual(coder.ollama_setup_host("http://127.0.0.1:11434/v1"), "http://127.0.0.1:11434")
        for raw in ("file:///tmp/ollama", "http://localhost:bad/v1", "http://localhost:11434/other"):
            with self.subTest(raw=raw), self.assertRaises(coder.CoderError):
                coder.ollama_setup_host(raw)

    def test_rejects_unsafe_or_ambiguous_references(self) -> None:
        for raw in (
            "http://huggingface.co/acme/Code-GGUF",
            "https://example.com/acme/Code-GGUF",
            "https://huggingface.co/acme/Code-GGUF/tree/main",
            "https://huggingface.co/acme/Code-GGUF?download=true",
            "https://huggingface.co:abc/acme/Code-GGUF",
            "hf.co/acme/../Code-GGUF",
            "hf.co/acme/Code-GGUF:bad/tag",
            "ollama run hf.co/acme/Code-GGUF && echo oops",
        ):
            with self.subTest(raw=raw), self.assertRaises(coder.CoderError):
                coder.normalize_local_model_reference(raw)


class _Response:
    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, *_):
        return self.payload


class HuggingFacePreflightTests(unittest.TestCase):
    def test_public_gguf_is_accepted(self) -> None:
        with patch.object(coder.urllib.request, "urlopen", return_value=_Response({
            "private": False, "gated": False, "siblings": [{"rfilename": "model.Q4_K_M.gguf"}],
        })) as open_url:
            coder.check_public_hf_gguf("hf.co/acme/Code-GGUF:Q4_K_M")
        self.assertEqual(open_url.call_args.args[0], "https://huggingface.co/api/models/acme/Code-GGUF")

    def test_gated_and_non_gguf_are_rejected_before_pull(self) -> None:
        for metadata, expected in (
            ({"gated": "manual", "siblings": [{"rfilename": "model.gguf"}]}, "gated"),
            ({"gated": False, "siblings": [{"rfilename": "model.safetensors"}]}, "GGUF"),
        ):
            with self.subTest(metadata=metadata):
                with patch.object(coder.urllib.request, "urlopen", return_value=_Response(metadata)):
                    with self.assertRaisesRegex(coder.CoderError, expected):
                        coder.check_public_hf_gguf("hf.co/acme/Code-GGUF")


class ReadinessTests(unittest.TestCase):
    def test_chat_without_structured_tool_call_is_chat_only(self) -> None:
        with patch.object(coder, "ollama_chat", side_effect=[
            {"content": "Hello."}, {"content": "I would call the tool."},
        ]):
            status = coder.ollama_probe_readiness("http://127.0.0.1:11434", "hf.co/acme/Code-GGUF")
        self.assertTrue(status["chat_ready"])
        self.assertFalse(status["tool_ready"])

    def test_chat_and_structured_tool_call_are_ready(self) -> None:
        with patch.object(coder, "ollama_chat", side_effect=[
            {"content": "Hello."},
            {"tool_calls": [{"function": {"name": "greyiq_readiness", "arguments": {"marker": "READY"}}}]},
        ]):
            status = coder.ollama_probe_readiness("http://127.0.0.1:11434", "hf.co/acme/Code-GGUF")
        self.assertEqual(status, {"chat_ready": True, "tool_ready": True, "reason": ""})


class SetupJobTests(unittest.TestCase):
    def _runtime(self):
        instance = object.__new__(api.GreyIQRuntime)
        instance.lock = threading.RLock()
        instance.model_pull = {"active": False}
        instance._local_brain = lambda: ("http://127.0.0.1:11434", "previous-model")
        instance._coder_config = lambda: {
            "enabled": True, "provider": "anthropic",
            "local": {"model": "previous-model", "base_url": "http://127.0.0.1:11434/v1"},
        }
        instance.log = lambda *_: None
        saved = []
        instance.save_coder_config = lambda update: saved.append(update)
        return instance, saved

    def _wait_done(self, instance):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = instance.model_pull_status()
            if status.get("done"):
                return status
            time.sleep(0.01)
        self.fail("model setup worker did not finish")

    def test_success_selects_model_only_after_pull_and_probes(self) -> None:
        instance, saved = self._runtime()
        installed = []
        order = []

        def pull(_host, model, timeout, progress_cb):
            order.append("pull")
            installed.append(model)
            progress_cb({"status": "success", "completed": 100, "total": 100})

        def probe(_host, _model):
            order.append("probe")
            self.assertEqual(saved, [])
            return {"chat_ready": True, "tool_ready": True}

        def save(update):
            order.append("save")
            saved.append(update)

        instance.save_coder_config = save
        with patch.object(coder, "ollama_list_models", side_effect=lambda _host: list(installed)), \
                patch.object(coder, "check_public_hf_gguf"), \
                patch.object(coder, "ollama_pull", side_effect=pull), \
                patch.object(coder, "ollama_probe_readiness", side_effect=probe):
            result = instance.start_model_setup("https://huggingface.co/acme/Code-GGUF")
            status = self._wait_done(instance)
        self.assertTrue(result["ok"])
        self.assertEqual(order, ["pull", "probe", "save"])
        self.assertTrue(status["selected"])
        self.assertEqual(saved[0]["local"]["model"], "hf.co/acme/Code-GGUF")

    def test_blank_server_switches_remote_brain_to_local_ollama(self) -> None:
        instance, saved = self._runtime()
        instance._coder_config = lambda: {
            "enabled": True, "provider": "local",
            "local": {"model": "previous-model", "base_url": "https://remote.example/v1"},
        }
        hosts = []

        def list_models(host):
            hosts.append(host)
            return ["hf.co/acme/Code-GGUF:latest"]

        def probe(host, _model):
            hosts.append(host)
            return {"chat_ready": True, "tool_ready": True}

        with patch.object(coder, "ollama_list_models", side_effect=list_models), \
                patch.object(coder, "ollama_probe_readiness", side_effect=probe):
            instance.start_model_setup("hf.co/acme/Code-GGUF", base_url="")
            status = self._wait_done(instance)
        self.assertTrue(status["selected"])
        self.assertEqual(hosts, ["http://127.0.0.1:11434"] * 2)
        self.assertEqual(saved[0]["local"]["base_url"], "")

    def test_chat_only_model_keeps_existing_brain(self) -> None:
        instance, saved = self._runtime()
        with patch.object(coder, "ollama_list_models", return_value=["hf.co/acme/Code-GGUF:latest"]), \
                patch.object(coder, "ollama_probe_readiness", return_value={
                    "chat_ready": True, "tool_ready": False, "reason": "No structured tool call.",
                }):
            instance.start_model_setup("hf.co/acme/Code-GGUF")
            status = self._wait_done(instance)
        self.assertTrue(status["chat_only"])
        self.assertFalse(status["selected"])
        self.assertEqual(saved, [])

    def test_invalid_hf_repo_does_not_pull_or_select(self) -> None:
        instance, saved = self._runtime()
        with patch.object(coder, "ollama_list_models", return_value=[]), \
                patch.object(coder, "check_public_hf_gguf", side_effect=coder.CoderError("No GGUF file")), \
                patch.object(coder, "ollama_pull") as pull:
            instance.start_model_setup("hf.co/acme/Code-GGUF")
            status = self._wait_done(instance)
        self.assertIn("No GGUF", status["error"])
        self.assertFalse(status["selected"])
        self.assertEqual(saved, [])
        pull.assert_not_called()

    def test_changing_brain_during_download_does_not_get_overwritten(self) -> None:
        instance, saved = self._runtime()
        selections = [
            {"enabled": True, "provider": "anthropic", "local": {"model": "previous-model"}},
            {"enabled": True, "provider": "openai", "local": {"model": "previous-model"}},
        ]
        instance._coder_config = lambda: selections.pop(0) if len(selections) > 1 else selections[0]
        with patch.object(coder, "ollama_list_models", return_value=["hf.co/acme/Code-GGUF:latest"]), \
                patch.object(coder, "ollama_probe_readiness", return_value={
                    "chat_ready": True, "tool_ready": True,
                }):
            instance.start_model_setup("hf.co/acme/Code-GGUF")
            status = self._wait_done(instance)
        self.assertFalse(status["selected"])
        self.assertIn("changed during setup", status["error"])
        self.assertEqual(saved, [])


class SetupRouteTests(unittest.TestCase):
    def test_setup_route_passes_model_and_server_url(self) -> None:
        body = json.dumps({
            "model": "https://huggingface.co/acme/Code-GGUF",
            "base_url": "http://127.0.0.1:11434/v1",
        }).encode("utf-8")

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        messages = []

        async def send(message):
            messages.append(message)

        scope = {
            "method": "POST", "path": "/api/coder/setup", "scheme": "http", "query_string": b"",
            "headers": [
                (b"host", b"127.0.0.1:8791"),
                (b"x-greyiq-token", api.SESSION_TOKEN.encode("ascii")),
                (b"content-type", b"application/json"),
            ],
        }
        with patch.object(api.runtime, "start_model_setup", return_value={"ok": True, "active": True}) as start:
            asyncio.run(api.route_http(scope, receive, send))
        self.assertEqual(messages[0]["status"], 200)
        start.assert_called_once_with(
            "https://huggingface.co/acme/Code-GGUF", "http://127.0.0.1:11434/v1"
        )


if __name__ == "__main__":
    unittest.main()
