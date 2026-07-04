"""OpenAI chat-completions token-limit compatibility.

OpenAI-hosted newer models reject the legacy ``max_tokens`` request field and
expect ``max_completion_tokens`` instead. Local OpenAI-compatible servers often
still expect ``max_tokens``. These tests pin both sides of that split.
"""
from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return b'{"choices":[{"message":{"content":"ok"}}]}'


class OpenAiTokenParamTests(unittest.TestCase):
    def _call_coder(self, block: dict[str, str], captured: list[dict]) -> dict:
        def fake_urlopen(request, timeout=0):  # noqa: ANN001
            captured.append(json.loads(request.data.decode("utf-8")))
            return _Response()

        with mock.patch("coder.urllib.request.urlopen", side_effect=fake_urlopen):
            return coder._generate_openai_compatible(
                [{"role": "user", "content": "hi"}],
                "system",
                block,
                321,
                0.2,
                5.0,
                "openai",
            )

    def test_openai_hosted_endpoint_uses_max_completion_tokens(self) -> None:
        captured: list[dict] = []
        out = self._call_coder(
            {"base_url": "https://api.openai.com/v1", "model": "gpt-5", "api_key": "sk-test"},
            captured,
        )
        self.assertEqual(out["text"], "ok")
        self.assertEqual(captured[0]["max_completion_tokens"], 321)
        self.assertNotIn("max_tokens", captured[0])

    def test_local_openai_compatible_endpoint_keeps_max_tokens(self) -> None:
        captured: list[dict] = []
        self._call_coder(
            {"base_url": "http://127.0.0.1:11434/v1", "model": "qwen2.5-coder:14b", "api_key": ""},
            captured,
        )
        self.assertEqual(captured[0]["max_tokens"], 321)
        self.assertNotIn("max_completion_tokens", captured[0])

    def test_gateway_retry_swaps_unsupported_max_tokens(self) -> None:
        captured: list[dict] = []

        def fake_urlopen(request, timeout=0):  # noqa: ANN001
            captured.append(json.loads(request.data.decode("utf-8")))
            if len(captured) == 1:
                detail = b'{"error":{"message":"Unsupported parameter: \\"max_tokens\\" is not supported with this model."}}'
                raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", {}, io.BytesIO(detail))
            return _Response()

        with mock.patch("coder.urllib.request.urlopen", side_effect=fake_urlopen):
            out = coder._generate_openai_compatible(
                [{"role": "user", "content": "hi"}],
                "system",
                {"base_url": "https://gateway.example/v1", "model": "custom-chat", "api_key": "sk-test"},
                222,
                0.2,
                5.0,
                "openai",
            )

        self.assertEqual(out["text"], "ok")
        self.assertIn("max_tokens", captured[0])
        self.assertEqual(captured[1]["max_completion_tokens"], 222)
        self.assertNotIn("max_tokens", captured[1])


if __name__ == "__main__":
    unittest.main()
