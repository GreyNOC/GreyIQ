"""Hugging Face GGUF import and the existing Ollama inference wiring."""
from __future__ import annotations

import asyncio
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import greyiq_api as api  # noqa: E402


def post_route(path: str, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    sent = False
    status = 0
    response = b""

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        nonlocal status, response
        if message["type"] == "http.response.start":
            status = message["status"]
        elif message["type"] == "http.response.body":
            response += message.get("body", b"")

    scope = {
        "method": "POST", "path": path, "scheme": "http", "query_string": b"",
        "headers": [
            (b"host", b"127.0.0.1:8791"),
            (b"x-greyiq-token", api.SESSION_TOKEN.encode("ascii")),
            (b"content-type", b"application/json"),
        ],
    }
    asyncio.run(api.route_http(scope, receive, send))
    return status, json.loads(response)


class HuggingFaceReferenceTests(unittest.TestCase):
    def test_repository_url_and_quantization_become_ollama_reference(self):
        cases = {
            "https://huggingface.co/Example/Code-Model-GGUF": "hf.co/Example/Code-Model-GGUF",
            "https://hf.co/Example/Code-Model-GGUF/": "hf.co/Example/Code-Model-GGUF",
            "hf.co/Example/Code-Model-GGUF:Q4_K_M": "hf.co/Example/Code-Model-GGUF:Q4_K_M",
            "https://huggingface.co/Example/Code-Model-GGUF:Q8_0": "hf.co/Example/Code-Model-GGUF:Q8_0",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(coder.normalize_huggingface_model_ref(raw), expected)

    def test_other_hosts_file_paths_and_url_modifiers_are_rejected(self):
        invalid = (
            "https://evil.example/Example/Code-Model-GGUF",
            "http://huggingface.co/Example/Code-Model-GGUF",
            "https://huggingface.co.evil.example/Example/Code-Model-GGUF",
            "https://user@huggingface.co/Example/Code-Model-GGUF",
            "https://huggingface.co:8443/Example/Code-Model-GGUF",
            "https://huggingface.co/Example/Code-Model-GGUF?token=secret",
            "https://huggingface.co/Example/Code-Model-GGUF#x",
            "https://huggingface.co/Example/Code-Model-GGUF/blob/main/model.gguf",
            "hf.co/Example/../Code-Model-GGUF",
            "hf.co/Example/Code-Model-GGUF;echo",
            "hf.co/Example/Code-Model-GGUF:Q4_K_M:extra",
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(coder.CoderError):
                coder.normalize_huggingface_model_ref(raw)


class OllamaWiringTests(unittest.TestCase):
    def test_import_route_pulls_the_normalized_model(self):
        model = "hf.co/Example/Code-Model-GGUF:Q4_K_M"
        with (patch.object(api.runtime, "_local_brain", return_value=("http://127.0.0.1:11434", "")),
              patch.object(api.runtime, "start_model_pull", return_value={"ok": True, "active": True, "model": model}) as pull):
            status, response = post_route(
                "/api/coder/huggingface/import",
                {"reference": "https://huggingface.co/Example/Code-Model-GGUF:Q4_K_M"},
            )
        self.assertEqual(status, 200)
        self.assertEqual(response["model"], model)
        pull.assert_called_once_with(model)

    def test_import_route_rejects_non_huggingface_url_without_pull(self):
        with patch.object(api.runtime, "start_model_pull") as pull:
            status, response = post_route(
                "/api/coder/huggingface/import",
                {"reference": "https://evil.example/Example/Code-Model-GGUF"},
            )
        self.assertEqual(status, 200)
        self.assertFalse(response["ok"])
        pull.assert_not_called()

    def test_import_route_refuses_remote_ollama(self):
        with (patch.object(api.runtime, "_local_brain", return_value=("https://models.example.com", "")),
              patch.object(api.runtime, "start_model_pull") as pull):
            status, response = post_route(
                "/api/coder/huggingface/import",
                {"reference": "hf.co/Example/Code-Model-GGUF"},
            )
        self.assertEqual(status, 200)
        self.assertFalse(response["ok"])
        self.assertIn("local Ollama", response["error"])
        pull.assert_not_called()

    def test_loopback_check_covers_ipv4_ipv6_and_rejects_remote_hosts(self):
        self.assertTrue(coder.ollama_host_is_loopback("http://127.0.0.1:11434"))
        self.assertTrue(coder.ollama_host_is_loopback("http://[::1]:11434"))
        self.assertTrue(coder.ollama_host_is_loopback("http://localhost:11434"))
        self.assertFalse(coder.ollama_host_is_loopback("https://models.example.com"))
        self.assertFalse(coder.ollama_host_is_loopback("http://127.0.0.1.evil.example"))

    def test_pull_sends_hf_reference_and_requires_success_event(self):
        model = "hf.co/Example/Code-Model-GGUF:Q4_K_M"
        sent = []
        events = []

        def open_success(request, timeout):
            sent.append(json.loads(request.data))
            return io.BytesIO(b'{"status":"pulling manifest"}\n{"status":"success"}\n')

        with patch.object(coder, "_ollama_open", side_effect=open_success):
            coder.ollama_pull("http://127.0.0.1:11434", model, 30, events.append)
        self.assertEqual(sent, [{"model": model, "stream": True}])
        self.assertEqual(events[-1]["status"], "success")

        with patch.object(coder, "_ollama_open", return_value=io.BytesIO(b'{"status":"pulling manifest"}\n')):
            with self.assertRaisesRegex(coder.CoderError, "without confirming success"):
                coder.ollama_pull("http://127.0.0.1:11434", model, 30, lambda _event: None)

    def test_pull_error_hides_signed_cdn_url_and_explains_old_ollama_bug(self):
        error = ('Head "https://us.aws.cdn.hf.co/file?Signature=secret": '
                 'blocked redirect to a different host')
        response = io.BytesIO((json.dumps({"error": error}) + "\n").encode())
        with patch.object(coder, "_ollama_open", return_value=response):
            with self.assertRaises(coder.CoderError) as caught:
                coder.ollama_pull("http://127.0.0.1:11434", "hf.co/Example/Repo:Q4_0", 30, lambda _: None)
        self.assertIn("0.34.3", str(caught.exception))
        self.assertNotIn("Signature", str(caught.exception))

    def test_installed_status_and_chat_use_imported_reference(self):
        model = "hf.co/Example/Code-Model-GGUF:Q4_K_M"
        self.assertTrue(coder.model_installed(["hf.co/example/code-model-gguf:q4_k_m"], model))
        cfg = coder.merge_update(None, {"enabled": True, "provider": "local", "local": {"model": model}})
        with patch.object(coder, "ollama_chat", return_value={"content": "OK"}) as chat:
            result = coder.generate([{"role": "user", "content": "ping"}], cfg)
        self.assertEqual(result, {"text": "OK", "model": model, "provider": "local"})
        self.assertEqual(chat.call_args.args[1], model)


if __name__ == "__main__":
    unittest.main()
