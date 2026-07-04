"""GreyIQ coding brain — routes chat to a capable model when one is configured.

This is what makes GreyIQ able to actually code. The tiny local TinyGPT model
(0.8M params, char-level) stays only as the offline last-resort fallback; when a
"brain" is configured here, coding/serious chat is answered by it instead.

Providers (OpenAI-compatible ones share a client; Claude uses its official SDK):
  - "local"     : OpenAI-compatible endpoint, defaults to a local Ollama server
                  (offline, free, private — runs a code model on your own GPU).
  - "anthropic" : Claude via the official `anthropic` SDK (closest to Claude Code).
  - "openai"    : OpenAI / ChatGPT (api.openai.com) or any OpenAI-compatible endpoint.
  - "off"/"none": disabled — the caller falls back to the local TinyGPT engine.

Secrets (API keys) live in the runtime config and are never echoed back to the UI
(see `public_config`).
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# Transient HTTP statuses worth retrying: rate limiting and server-side errors.
# 4xx client errors (auth, bad request) are NOT retried — they won't fix themselves.
_RETRY_STATUSES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
_MAX_RETRIES = 3
_BASE_RETRY_DELAY = 1.0  # seconds; doubles each attempt (1s, 2s, 4s)


def with_retries(call, *, max_retries: int = _MAX_RETRIES, sleep=time.sleep):
    """Call a zero-arg function, retrying transient network failures with bounded
    exponential backoff. Retries on retryable HTTP statuses (429/5xx/…) and read
    timeouts; everything else (auth errors, connection-refused, bad request)
    propagates immediately so the caller's specific error message still surfaces."""
    attempt = 0
    while True:
        try:
            return call()
        except urllib.error.HTTPError as exc:
            if exc.code in _RETRY_STATUSES and attempt < max_retries:
                sleep(_BASE_RETRY_DELAY * (2 ** attempt))
                attempt += 1
                continue
            raise
        except (TimeoutError, socket.timeout):
            if attempt < max_retries:
                sleep(_BASE_RETRY_DELAY * (2 ** attempt))
                attempt += 1
                continue
            raise

DEFAULT_SYSTEM_PROMPT = (
    "You are GreyIQ, a coding assistant. "
    "Give correct, runnable code with short, clear explanations. "
    "State assumptions, call out failure modes, and prefer the simplest correct "
    "solution. Put code in fenced code blocks tagged with the language. "
    "If you are unsure, say so instead of guessing."
)

# Default Claude model for the coding brain. Opus 4.8 is the most capable model;
# adaptive thinking + high effort is the recommended setup for coding/agentic work.
DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"

CODER_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "provider": "local",
    "system_prompt": DEFAULT_SYSTEM_PROMPT,
    "max_tokens": 8192,
    "temperature": 0.2,
    "timeout_s": 120.0,
    "history_turns": 12,
    "local": {
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "qwen2.5-coder:14b",
        "api_key": "",
        "num_ctx": 16384,
    },
    "anthropic": {
        "model": DEFAULT_ANTHROPIC_MODEL,
        "api_key": "",
        "effort": "high",
        "thinking": True,
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o",
        "api_key": "",
    },
    "agent": {
        "allow_commands": False,
        "allow_network": True,
        "max_steps": 25,
        "command_timeout_s": 60.0,
        "net_timeout_s": 10.0,
        "verify_command": "",
        "skills_enabled": True,
        "repo_map": True,
    },
}

_PROVIDERS_OFF = {"", "off", "none", "disabled"}


class CoderError(RuntimeError):
    """A coding-brain request failed in a way worth showing the user."""


def chat_completion_token_limit_field(base_url: str, model: str) -> str:
    """Return the chat-completions output-token field this endpoint/model expects.

    OpenAI's newer hosted models reject the legacy ``max_tokens`` field and require
    ``max_completion_tokens``. Most local OpenAI-compatible servers still expect the
    legacy field, so keep that default unless the request is clearly headed to OpenAI
    or the selected model name is from the newer OpenAI families.
    """
    host = (urllib.parse.urlparse(str(base_url or "")).hostname or "").lower()
    name = str(model or "").strip().lower()
    if host == "api.openai.com" or name.startswith(("gpt-5", "gpt-4.1", "o1", "o3", "o4", "chatgpt-")):
        return "max_completion_tokens"
    return "max_tokens"


def apply_chat_completion_token_limit(payload: dict[str, Any], base_url: str, model: str, max_tokens: int) -> str:
    field = chat_completion_token_limit_field(base_url, model)
    payload.pop("max_tokens" if field == "max_completion_tokens" else "max_completion_tokens", None)
    payload[field] = int(max_tokens)
    return field


def retry_payload_with_alternate_token_limit(payload: dict[str, Any], detail: str) -> dict[str, Any] | None:
    """If a chat endpoint rejects one token-limit field, build a one-shot retry payload
    with the other spelling. Returns None when the error is unrelated."""
    lower = str(detail or "").lower()
    if "unsupported parameter" not in lower:
        return None
    if "max_tokens" in payload and "max_tokens" in lower:
        retry = dict(payload)
        retry["max_completion_tokens"] = retry.pop("max_tokens")
        return retry
    if "max_completion_tokens" in payload and "max_completion_tokens" in lower:
        retry = dict(payload)
        retry["max_tokens"] = retry.pop("max_completion_tokens")
        return retry
    return None


def coder_config(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Merge stored config over the defaults (provider sub-dicts merged one level deep)."""
    merged = json.loads(json.dumps(CODER_DEFAULTS))  # deep copy of defaults
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
    return merged


def coder_enabled(raw: dict[str, Any] | None) -> bool:
    cfg = coder_config(raw)
    provider = str(cfg.get("provider", "off")).strip().lower()
    return bool(cfg.get("enabled")) and provider not in _PROVIDERS_OFF


def public_config(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Config safe to send to the UI: API keys stripped, replaced by has_* flags."""
    cfg = coder_config(raw)
    safe = json.loads(json.dumps(cfg))
    for name in ("local", "anthropic", "openai"):
        block = safe.get(name) or {}
        block["has_api_key"] = bool((cfg.get(name) or {}).get("api_key"))
        block.pop("api_key", None)
        safe[name] = block
    safe["available"] = coder_enabled(raw)
    return safe


def merge_update(existing: dict[str, Any] | None, update: dict[str, Any]) -> dict[str, Any]:
    """Apply a partial update from the UI onto the stored config.

    An empty-string api_key in the update is treated as "leave unchanged" so the
    UI (which never receives keys) can save other fields without wiping the key.
    """
    cfg = coder_config(existing)
    for key, value in (update or {}).items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            for sub_key, sub_value in value.items():
                if sub_key == "api_key" and not str(sub_value or "").strip():
                    continue  # don't overwrite a stored key with a blank
                cfg[key][sub_key] = sub_value
        else:
            cfg[key] = value
    return cfg


def generate(messages: list[dict[str, str]], raw_config: dict[str, Any] | None) -> dict[str, Any]:
    """Generate a reply from the configured brain.

    `messages` is a list of {"role": "user"|"assistant", "content": str}; the
    system prompt is supplied separately per provider. Returns
    {"text", "model", "provider"}. Raises CoderError on any failure.
    """
    cfg = coder_config(raw_config)
    provider = str(cfg.get("provider", "off")).strip().lower()
    system_prompt = str(cfg.get("system_prompt") or DEFAULT_SYSTEM_PROMPT)
    max_tokens = int(cfg.get("max_tokens") or 8192)
    temperature = float(cfg.get("temperature", 0.2))
    timeout = float(cfg.get("timeout_s") or 120.0)

    if provider in _PROVIDERS_OFF:
        raise CoderError("The coding brain is turned off.")
    if provider == "anthropic":
        return _generate_anthropic(messages, system_prompt, cfg["anthropic"], max_tokens, timeout)
    if provider == "local":
        return _generate_ollama(messages, system_prompt, cfg["local"], max_tokens, temperature, timeout)
    if provider == "openai":
        return _generate_openai_compatible(
            messages, system_prompt, cfg["openai"], max_tokens, temperature, timeout, provider
        )
    raise CoderError(f"Unknown coding-brain provider: {provider}")


def ollama_host(base_url: str | None) -> str:
    """Native Ollama host from a base URL (strip the OpenAI-compat /v1 suffix)."""
    host = str(base_url or "").strip().rstrip("/")
    if host.endswith("/v1"):
        host = host[:-3]
    return host or "http://127.0.0.1:11434"


def ollama_chat(
    host: str,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    options: dict[str, Any] | None = None,
    timeout: float = 120.0,
    api_key: str = "",
) -> dict[str, Any]:
    """Call Ollama's native /api/chat — the only endpoint that lets us set the
    context window (options.num_ctx). Returns the response 'message' dict. Raises
    CoderError with actionable guidance (model not pulled, server down)."""
    payload: dict[str, Any] = {"model": model, "messages": messages, "stream": False}
    if options:
        payload["options"] = options
    if tools:
        payload["tools"] = tools
    endpoint = host.rstrip("/") + "/api/chat"
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if api_key:
        request.add_header("Authorization", f"Bearer {api_key}")

    def _open() -> bytes:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()

    try:
        body = json.loads(with_retries(_open).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore") if hasattr(exc, "read") else ""
        low = (detail or "").lower()
        # Ollama's model-not-found body names the model ("model 'x' not found, try
        # pulling it"); a bare "404 page not found" is a missing endpoint, not a
        # missing model — keep those distinct so we don't tell the user to re-pull.
        if "pull" in low or "no such model" in low or ("model" in low and "not found" in low):
            # Ollama explicitly reports the model is missing.
            raise CoderError(
                f"Ollama model '{model}' isn't available. Pull it with `ollama pull {model}`. "
                "If it IS already pulled (shows under 'Model installed'), your Ollama is likely outdated "
                "or the model failed to load — update Ollama, or switch the coding brain to OpenAI/Claude."
            ) from exc
        if exc.code == 404:
            # A bare 404 on /api/chat usually means an outdated Ollama that lacks the
            # endpoint — NOT a missing model (don't tell the user to re-pull it).
            raise CoderError(
                f"Ollama returned 404 for /api/chat (model '{model}'). Your Ollama is likely outdated and "
                "missing the /api/chat endpoint — update Ollama, or switch the coding brain to OpenAI/Claude."
            ) from exc
        raise CoderError(f"Ollama HTTP {exc.code}: {detail[:400] or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise CoderError(
            f"Could not reach Ollama at {host} ({exc.reason}). "
            "Start it with `ollama serve` and make sure the model is pulled."
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise CoderError(f"Ollama request failed: {exc}") from exc
    if isinstance(body, dict) and body.get("error"):
        raise CoderError(f"Ollama error: {body['error']}")
    return (body or {}).get("message") or {}


def ollama_list_models(host: str, timeout: float = 10.0) -> list[str]:
    """Names of models already pulled into the local Ollama store (/api/tags)."""
    endpoint = host.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(endpoint, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise CoderError(
            f"Could not reach Ollama at {host} ({exc.reason}). Start it with `ollama serve`."
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise CoderError(f"Ollama request failed: {exc}") from exc
    return [str(m.get("name") or m.get("model") or "") for m in (body.get("models") or []) if isinstance(m, dict)]


def ollama_delete(host: str, model: str, timeout: float = 20.0) -> None:
    """Delete a pulled model from the local Ollama store (DELETE /api/delete).
    Raises CoderError on failure."""
    endpoint = host.rstrip("/") + "/api/delete"
    request = urllib.request.Request(
        endpoint,
        data=json.dumps({"name": model}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="DELETE",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore") if hasattr(exc, "read") else ""
        if exc.code == 404:
            raise CoderError(f"Model '{model}' is not installed.") from exc
        raise CoderError(f"Ollama delete HTTP {exc.code}: {detail[:300] or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise CoderError(
            f"Could not reach Ollama at {host} ({exc.reason}). Start it with `ollama serve`."
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise CoderError(f"Ollama delete failed: {exc}") from exc


def model_installed(installed: list[str], model: str) -> bool:
    """Match a configured model name against installed names, tolerating the
    implicit ':latest' tag Ollama adds to untagged names."""
    wanted = {model, f"{model}:latest"} if ":" not in model else {model}
    have = set(installed) | {n.split(":")[0] for n in installed if n.endswith(":latest")}
    return bool(wanted & set(installed)) or model in have


def ollama_pull(host: str, model: str, timeout: float, progress_cb) -> None:
    """Stream `ollama pull <model>` via /api/pull, calling progress_cb(event) for
    each status line. Blocks until done; raises CoderError on failure."""
    endpoint = host.rstrip("/") + "/api/pull"
    request = urllib.request.Request(
        endpoint,
        data=json.dumps({"model": model, "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            for raw in response:
                line = raw.decode("utf-8", "ignore").strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict) and event.get("error"):
                    raise CoderError(f"Ollama pull failed: {event['error']}")
                progress_cb(event)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore") if hasattr(exc, "read") else ""
        raise CoderError(f"Ollama pull HTTP {exc.code}: {detail[:300] or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise CoderError(
            f"Could not reach Ollama at {host} ({exc.reason}). Start it with `ollama serve`."
        ) from exc


def _generate_ollama(
    messages: list[dict[str, str]],
    system_prompt: str,
    block: dict[str, Any],
    max_tokens: int,
    temperature: float,
    timeout: float,
) -> dict[str, Any]:
    model = str(block.get("model") or "").strip()
    if not model:
        raise CoderError("Ollama model is not set.")
    options = {
        "temperature": temperature,
        "num_ctx": int(block.get("num_ctx") or 16384),
        "num_predict": max_tokens,
    }
    message = ollama_chat(
        ollama_host(block.get("base_url")),
        model,
        [{"role": "system", "content": system_prompt}, *messages],
        options=options,
        timeout=timeout,
        api_key=str(block.get("api_key") or ""),
    )
    text = str(message.get("content") or "").strip()
    if not text:
        raise CoderError("Ollama returned an empty response.")
    return {"text": text, "model": model, "provider": "local"}


def _generate_anthropic(
    messages: list[dict[str, str]],
    system_prompt: str,
    block: dict[str, Any],
    max_tokens: int,
    timeout: float,
) -> dict[str, Any]:
    model = str(block.get("model") or DEFAULT_ANTHROPIC_MODEL)
    api_key = str(block.get("api_key") or "").strip()
    if not api_key:
        raise CoderError("Claude API key is not set. Add it in the coding-brain settings.")
    try:
        import anthropic  # lazy: only required when the Claude provider is used
    except ImportError as exc:
        raise CoderError("The 'anthropic' package is not installed in this backend.") from exc

    # max_retries lets the SDK back off and retry transient 429/5xx/connection
    # errors itself, so a single blip doesn't kill the request.
    client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=_MAX_RETRIES)
    base_kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
    }
    # Adaptive thinking + effort is the recommended coding setup on Opus 4.8 / 4.7
    # / Sonnet 4.6. Passed via extra_body so it works regardless of installed SDK
    # version; older models reject these, so retry without them on a 400.
    use_thinking = bool(block.get("thinking", True))
    extra_body: dict[str, Any] = {}
    if use_thinking:
        extra_body = {
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": str(block.get("effort") or "high")},
        }

    try:
        response = client.messages.create(**base_kwargs, extra_body=extra_body or None)
    except anthropic.BadRequestError as exc:
        message = str(getattr(exc, "message", exc)).lower()
        if use_thinking and ("effort" in message or "thinking" in message or "output_config" in message):
            try:
                response = client.messages.create(**base_kwargs)
            except Exception as retry_exc:  # noqa: BLE001 - surfaced to user
                raise CoderError(f"Claude request failed: {retry_exc}") from retry_exc
        else:
            raise CoderError(f"Claude rejected the request: {getattr(exc, 'message', exc)}") from exc
    except anthropic.AuthenticationError as exc:
        raise CoderError("Claude rejected the API key (authentication failed).") from exc
    except anthropic.APIStatusError as exc:
        raise CoderError(f"Claude API error {exc.status_code}: {getattr(exc, 'message', exc)}") from exc
    except Exception as exc:  # noqa: BLE001 - network/SDK errors surfaced to user
        raise CoderError(f"Claude request failed: {exc}") from exc

    text = "".join(
        getattr(block_, "text", "") for block_ in response.content if getattr(block_, "type", "") == "text"
    ).strip()
    if not text:
        raise CoderError("Claude returned an empty response.")
    return {"text": text, "model": getattr(response, "model", model), "provider": "anthropic"}


def _generate_openai_compatible(
    messages: list[dict[str, str]],
    system_prompt: str,
    block: dict[str, Any],
    max_tokens: int,
    temperature: float,
    timeout: float,
    provider: str,
) -> dict[str, Any]:
    base_url = str(block.get("base_url") or "").strip().rstrip("/")
    model = str(block.get("model") or "").strip()
    api_key = str(block.get("api_key") or "").strip()
    label = "Ollama" if provider == "local" else provider
    if not base_url:
        raise CoderError(f"{label} base URL is not set.")
    if not model:
        raise CoderError(f"{label} model is not set.")

    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system_prompt}, *messages],
        "temperature": temperature,
        "stream": False,
    }
    apply_chat_completion_token_limit(payload, base_url, model, max_tokens)

    def _open(body_payload: dict[str, Any]) -> bytes:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(body_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if api_key:
            request.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()

    try:
        body = json.loads(with_retries(lambda: _open(payload)).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore")[:400] if hasattr(exc, "read") else ""
        retry_payload = retry_payload_with_alternate_token_limit(payload, detail)
        if retry_payload:
            try:
                body = json.loads(with_retries(lambda: _open(retry_payload)).decode("utf-8"))
            except urllib.error.HTTPError as retry_exc:
                retry_detail = retry_exc.read().decode("utf-8", "ignore")[:400] if hasattr(retry_exc, "read") else ""
                raise CoderError(f"{label} HTTP {retry_exc.code}: {retry_detail or retry_exc.reason}") from retry_exc
            except Exception as retry_exc:  # noqa: BLE001
                raise CoderError(f"{label} request failed: {retry_exc}") from retry_exc
        else:
            raise CoderError(f"{label} HTTP {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise CoderError(
            f"Could not reach {label} at {base_url} ({exc.reason}). "
            "Is the server running? For Ollama: `ollama serve` and pull the model first."
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise CoderError(f"{label} request failed: {exc}") from exc

    try:
        text = str(body["choices"][0]["message"]["content"]).strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise CoderError(f"{label} returned an unexpected response shape.") from exc
    if not text:
        raise CoderError(f"{label} returned an empty response.")
    return {"text": text, "model": model, "provider": provider}
