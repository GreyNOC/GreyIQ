"""Unattended hunts must not send target-derived evidence to a cloud brain."""

from __future__ import annotations

import sys
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
import coder  # noqa: E402


class OperatorBrainPrivacyTests(unittest.TestCase):
    def test_loopback_ollama_chat_bypasses_environment_proxy(self) -> None:
        received: list[bytes] = []

        class LocalOllama(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - HTTP handler convention
                received.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"message":{"content":"local response"}}')

            def log_message(self, *_args) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), LocalOllama)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            proxy_env = {"HTTP_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1",
                         "HTTPS_PROXY": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1",
                         "NO_PROXY": "", "no_proxy": ""}
            with patch.dict(os.environ, proxy_env):
                message = coder.ollama_chat(
                    f"http://127.0.0.1:{server.server_port}", "test-model",
                    [{"role": "user", "content": "target-derived test"}], timeout=2.0,
                )
            self.assertEqual(message, {"content": "local response"})
            self.assertEqual(len(received), 1)
            self.assertIn(b"target-derived test", received[0])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_only_loopback_ollama_is_eligible_for_auto_mode(self) -> None:
        for provider, base_url in (
            ("anthropic", "http://127.0.0.1:11434/v1"),
            ("openai", "http://127.0.0.1:11434/v1"),
            ("local", "https://models.example.com/v1"),
            ("local", "http://192.0.2.1:11434/v1"),
            ("local", "http://localhost:bad/v1"),
        ):
            with self.subTest(provider=provider, base_url=base_url):
                config = {"enabled": True, "provider": provider, "local": {"base_url": base_url}}
                self.assertEqual(coder.unattended_config(config),
                                 {"enabled": False, "provider": "off"})
        local = {"enabled": True, "provider": "local",
                 "local": {"base_url": "http://127.0.0.1:11434/v1", "model": "test"}}
        self.assertIs(coder.unattended_config(local), local)

    def test_operator_campaign_routes_cloud_config_to_offline_fallback(self) -> None:
        request = api.CampaignRequest(target="https://example.com/", scope="example.com",
                                      authorized=True)
        cloud = {"enabled": True, "provider": "anthropic", "anthropic": {"api_key": "secret"}}
        with patch.object(api.bounty_operator_guard, "current", return_value=object()), \
                patch.object(api.runtime, "_coder_config", return_value=cloud), \
                patch.object(api.bounty_campaign, "run_campaign", return_value={"ok": False, "error": "stub"}) as run, \
                patch.object(api.runtime, "_cache_bounty_run"):
            api.runtime.run_campaign(request)
        self.assertEqual(run.call_args.kwargs["coder_cfg"], {"enabled": False, "provider": "off"})


if __name__ == "__main__":
    unittest.main()
