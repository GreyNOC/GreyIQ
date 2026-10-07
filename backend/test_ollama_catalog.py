"""Live Ollama catalog and selected-server listing, with no external test traffic."""

from __future__ import annotations

import asyncio
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import greyiq_api as api  # noqa: E402


def _card(name: str, *, local: bool = True, tools: bool = True, cloud_badge: bool = False) -> str:
    local_label = '<span role="tooltip">Runs on your computer</span>' if local else '<span role="tooltip">Runs on Ollama’s cloud</span>'
    tool_label = '<span class="inline-flex items-center">Tools</span>' if tools else ''
    cloud_label = (
        '<span class="group/tip relative inline-flex items-center font-medium text-black">'
        '<span role="tooltip">Runs on Ollama’s cloud</span>Cloud</span>'
    ) if cloud_badge else ''
    return (
        f'<li><a href="/library/{name}">'
        f'<h2 title="{name}">{name}</h2><p title="Model &amp; tools">Model &amp; tools</p>'
        f'<span class="group/tip relative inline-flex items-center">{local_label}'
        '<span class="font-medium text-black">7b</span></span>'
        f'{cloud_label}'
        f'{tool_label}<span class="inline-flex items-center">Thinking</span>'
        '<span title="1,234 downloads">1K</span></a></li>'
    )


class _HtmlResponse:
    def __init__(self, html: str) -> None:
        self.raw = html.encode("utf-8")
        self.headers = {"Content-Type": "text/html; charset=utf-8"}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit: int):
        return self.raw[:limit]


class _Opener:
    def __init__(self, pages: list[str | Exception]) -> None:
        self.pages = pages
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        page = self.pages[len(self.requests) - 1]
        if isinstance(page, Exception):
            raise page
        return _HtmlResponse(page)


class CatalogTests(unittest.TestCase):
    def test_dual_local_cloud_card_does_not_treat_cloud_badge_as_size(self) -> None:
        parser = coder._OllamaCatalogParser()
        parser.feed(_card("gemma4", cloud_badge=True))
        parser.close()
        self.assertEqual([model["name"] for model in parser.models], ["gemma4"])
        self.assertEqual(parser.models[0]["sizes"], ["7b"])

    def test_fetches_all_distinct_pages_from_official_local_tool_search(self) -> None:
        first = _card("qwen2.5-coder") + _card("cloud-only", local=False) + _card("no-tools", tools=False)
        first += '<li hx-get="/search?page=2"></li>'
        second = _card("devstral")
        opener = _Opener([first, second])
        with patch.object(coder.urllib.request, "build_opener", return_value=opener):
            result = coder.ollama_public_catalog()
        self.assertFalse(result["partial"])
        self.assertEqual([m["name"] for m in result["models"]], ["qwen2.5-coder", "devstral"])
        self.assertEqual(result["models"][0]["description"], "Model & tools")
        self.assertEqual(result["models"][0]["sizes"], ["7b"])
        self.assertEqual(result["models"][0]["downloads"], 1234)
        self.assertTrue(result["models"][0]["thinking"])
        self.assertEqual(len(opener.requests), 2)
        for request, timeout in opener.requests:
            self.assertEqual(request.get_header("Hx-request"), "true")
            self.assertTrue(request.full_url.startswith("https://ollama.com/search?"))
            self.assertLessEqual(timeout, 5)
        self.assertIn("page=2", opener.requests[1][0].full_url)

    def test_repeated_page_returns_explicit_partial_result(self) -> None:
        page = _card("qwen2.5-coder") + '<li hx-get="/search?page=2"></li>'
        opener = _Opener([page, page])
        with patch.object(coder.urllib.request, "build_opener", return_value=opener):
            result = coder.ollama_public_catalog()
        self.assertTrue(result["partial"])
        self.assertEqual(len(result["models"]), 1)
        self.assertIn("pagination", result["warning"])

    def test_official_catalog_failure_has_no_fake_or_cached_models(self) -> None:
        opener = _Opener([urllib.error.URLError("offline")])
        with patch.object(coder.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(coder.CoderError, "Could not load Ollama"):
                coder.ollama_public_catalog()

    def test_rejects_redirect_to_another_host(self) -> None:
        redirect = coder._OllamaCatalogRedirects()
        with self.assertRaisesRegex(coder.CoderError, "official server"):
            redirect.redirect_request(None, None, 302, "", {}, "https://example.com/search")

    def test_installed_list_excludes_cloud_stubs(self) -> None:
        payload = {"models": [
            {"name": "kimi-k3:cloud", "size": 0},
            {"name": "cloud-alias", "size": 0},
            {"name": "qwen2.5-coder:7b", "size": 4_000_000_000},
        ]}
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self):
                return json.dumps(payload).encode("utf-8")

        with patch.object(coder, "_ollama_open", return_value=Response()):
            self.assertEqual(coder.ollama_list_models("http://127.0.0.1:11434"), ["qwen2.5-coder:7b"])


def _get(path: str, query: bytes = b"") -> tuple[int, dict]:
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "method": "GET", "path": path, "query_string": query, "scheme": "http",
        "client": ("127.0.0.1", 54321),
        "headers": [(b"host", b"127.0.0.1:8766"), (b"x-greyiq-token", api.SESSION_TOKEN.encode())],
    }
    asyncio.run(api.route_http(scope, receive, send))
    return messages[0]["status"], json.loads(messages[-1]["body"])


class CatalogRouteTests(unittest.TestCase):
    def test_catalog_route_returns_live_result_shape(self) -> None:
        instance = object.__new__(api.GreyIQRuntime)
        with patch.object(coder, "ollama_public_catalog", return_value={"models": [{"name": "devstral"}], "partial": False, "warning": ""}), \
                patch.object(api, "runtime", instance), patch.object(api, "GREYIQ_ACCESS_KEY", ""):
            status, body = _get("/api/coder/catalog")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["models"], [{"name": "devstral"}])
        self.assertEqual(body["source"], coder.OLLAMA_CATALOG_URL)
        self.assertIn("fetched_at", body)

    def test_models_query_uses_validated_unsaved_server(self) -> None:
        instance = object.__new__(api.GreyIQRuntime)
        instance._local_brain = lambda: ("http://127.0.0.1:11434", "qwen2.5-coder:7b")
        with patch.object(coder, "ollama_list_models", return_value=["devstral:24b"]) as listed, \
                patch.object(api, "runtime", instance), patch.object(api, "GREYIQ_ACCESS_KEY", ""):
            status, body = _get("/api/coder/models", b"base_url=http%3A%2F%2Flocalhost%3A11434%2Fv1")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["installed"], ["devstral:24b"])
        listed.assert_called_once_with("http://localhost:11434")

    def test_models_query_rejects_malformed_or_duplicate_server(self) -> None:
        instance = object.__new__(api.GreyIQRuntime)
        instance._local_brain = lambda: ("http://127.0.0.1:11434", "")
        with patch.object(coder, "ollama_list_models") as listed, \
                patch.object(api, "runtime", instance), patch.object(api, "GREYIQ_ACCESS_KEY", ""):
            status, body = _get("/api/coder/models", b"base_url=file%3A%2F%2F%2Ftmp%2Ffake")
            self.assertEqual(status, 200)
            self.assertFalse(body["ok"])
            duplicate_status, _ = _get("/api/coder/models", b"base_url=&base_url=http%3A%2F%2Flocalhost%3A11434")
        self.assertEqual(duplicate_status, 422)
        listed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
