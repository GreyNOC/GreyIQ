"""GreyIQ coding brain — routes chat to a capable model when one is configured.

This is what makes GreyIQ able to actually code. The tiny local TinyGPT model
(well under 10M params, char-level) stays only as the offline last-resort fallback; when a
"brain" is configured here, coding/serious chat is answered by it instead.

Providers (OpenAI-compatible ones share a client; Claude uses its official SDK):
  - "local"     : OpenAI-compatible endpoint, defaults to a local Ollama server
                  (offline, free, private — runs a code model on your own GPU).
  - "anthropic" : Claude via the official `anthropic` SDK (closest to Claude Code).
  - "openai"    : OpenAI / ChatGPT (api.openai.com) or any OpenAI-compatible endpoint.
  - "off"/"none": disabled — the caller falls back to the local TinyGPT engine.

Secrets (API keys) live in the runtime config and are never echoed back to the UI
(see `public_config`). Because the UI never receives a key back, a blank api_key in
an update means "keep the stored one"; deleting a key needs the explicit
`clear_api_key` sentinel (see `merge_update` / `api_key_clear_requests`).
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

# Default Claude model for the coding brain. Opus 5 is the current Opus tier and a drop-in for the
# request shape we send (adaptive thinking + output_config.effort, no sampling params) at the same
# price as 4.8. Adaptive thinking + a per-brain effort (see brain_profiles) is the recommended setup.
# NOTE: on Opus 5 thinking is ON by default, and max_tokens is a shared ceiling over thinking AND the
# response — which is why _generate_anthropic now inspects stop_reason instead of trusting the text.
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5"

CODER_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "provider": "local",
    "system_prompt": DEFAULT_SYSTEM_PROMPT,
    # On current models this ceiling covers THINKING as well as the reply, and Opus 5 thinks by
    # default — 8192 (the pre-v2.7.0 value) was small enough that a deep turn could spend the budget
    # reasoning and return a clipped answer. 16000 is the largest value that stays comfortably inside
    # the SDK's non-streaming timeout guard. Per-brain overrides live in brain_profiles.
    "max_tokens": 16000,
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

# Providers served by the DETERMINISTIC offline coder (agent._run_offline) rather than by an LLM:
# a template + AST-edit engine gated by `verify`, no model and no network. They are deliberately
# NOT in _PROVIDERS_OFF — "off" means the caller falls back to TinyGPT chat, whereas these are a
# real, selectable coding capability with a real ceiling (scaffolds and mechanical edits).
# `generate()` still refuses them: there is no chat completion here, only edits through the agent.
PROVIDERS_DETERMINISTIC = frozenset({"offline", "deterministic"})


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


def chat_completion_requires_default_temperature(base_url: str, model: str) -> bool:
    """True for OpenAI chat models that reject non-default temperature values."""
    name = str(model or "").strip().lower()
    return name.startswith(("gpt-5", "o1", "o3", "o4", "chatgpt-"))


def apply_chat_completion_temperature(payload: dict[str, Any], base_url: str, model: str, temperature: float) -> bool:
    """Apply temperature only when the model accepts custom sampling.

    Newer OpenAI reasoning/chat models reject ``temperature`` values other than the
    default. Omitting the field uses the provider default and avoids a hard 400, while
    local OpenAI-compatible servers still receive the configured value.
    """
    if chat_completion_requires_default_temperature(base_url, model):
        payload.pop("temperature", None)
        return False
    payload["temperature"] = float(temperature)
    return True


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


def retry_payload_without_unsupported_temperature(payload: dict[str, Any], detail: str) -> dict[str, Any] | None:
    """If a chat endpoint rejects custom temperature, retry once with provider default."""
    lower = str(detail or "").lower()
    if "temperature" not in lower or "temperature" not in payload:
        return None
    if "unsupported value" not in lower and "unsupported parameter" not in lower:
        return None
    retry = dict(payload)
    retry.pop("temperature", None)
    return retry


def retry_payload_for_chat_completion_compat(payload: dict[str, Any], detail: str) -> dict[str, Any] | None:
    return (
        retry_payload_with_alternate_token_limit(payload, detail)
        or retry_payload_without_unsupported_temperature(payload, detail)
    )


def chat_completion_error_detail(exc: urllib.error.HTTPError, limit: int = 400) -> str:
    """Return a bounded HTTP error body, including one already consumed by the
    compatibility adapter.

    ``HTTPError.read()`` is destructive. The adapter must inspect a 400 response
    to decide whether to change the request, so preserve that detail on the
    exception before re-raising it for the provider-specific error message.
    """
    saved = getattr(exc, "greyiq_detail", None)
    if saved is not None:
        return str(saved)[:limit]
    try:
        detail = exc.read().decode("utf-8", "ignore") if hasattr(exc, "read") else ""
    except Exception:  # noqa: BLE001 - error reporting must not mask the HTTP failure
        detail = ""
    return detail[:limit]


def request_chat_completion_with_compat(
    open_payload,
    payload: dict[str, Any],
    *,
    max_adjustments: int = 2,
) -> bytes:
    """Send one chat-completions request with bounded parameter adaptation.

    Gateways frequently proxy several model families behind one URL. A request
    can therefore be rejected first for ``max_tokens`` and then, after that is
    corrected, for ``temperature``. Adapt one incompatibility at a time while
    preventing field-swap loops; transient retry/backoff remains the job of
    :func:`with_retries` for each concrete payload.
    """
    current = dict(payload)
    seen = {json.dumps(current, sort_keys=True, default=str)}
    adjustments = 0
    while True:
        try:
            return with_retries(lambda: open_payload(current))
        except urllib.error.HTTPError as exc:
            detail = chat_completion_error_detail(exc)
            retry = retry_payload_for_chat_completion_compat(current, detail)
            fingerprint = json.dumps(retry, sort_keys=True, default=str) if retry is not None else ""
            if retry is None or adjustments >= max_adjustments or fingerprint in seen:
                try:
                    exc.greyiq_detail = detail
                except Exception:  # noqa: BLE001 - preserve the original HTTPError
                    pass
                raise
            seen.add(fingerprint)
            current = retry
            adjustments += 1


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
    """True when SOME coding capability is selected — including the deterministic (offline) one.

    This answers "can the Workbench agent do work?", NOT "is there a brain that can answer a
    question?". Callers that need the latter must use ``reasoning_brain_enabled`` instead.
    """
    cfg = coder_config(raw)
    provider = str(cfg.get("provider", "off")).strip().lower()
    return bool(cfg.get("enabled")) and provider not in _PROVIDERS_OFF


def reasoning_brain_enabled(raw: dict[str, Any] | None) -> bool:
    """True only when a brain that can answer a FREE-FORM PROMPT is configured.

    WHY THIS IS SEPARATE FROM ``coder_enabled``: the deterministic providers are a real, selectable
    coding capability (template + AST edits through the agent), so they are deliberately NOT in
    ``_PROVIDERS_OFF`` and ``coder_enabled`` answers True for them. But they have no chat completion
    at all — ``generate()`` raises CoderError for them BY DESIGN. Any feature that gates an LLM
    prompt on ``coder_enabled`` therefore breaks the moment the operator selects the deterministic
    coder: it takes the LLM branch, ``generate`` raises, and the feature fails closed — silently
    losing whatever offline fallback the ``coder_enabled == False`` branch would have run. That is
    strictly WORSE than provider "off". The hunt planner (``hunt_brain.plan_hunt``) hit exactly
    this: selecting the deterministic coder replaced its full offline knowledge-rule plan with an
    empty one, so the hunt flew blind.

    Semantics: reasoning is available iff a coder is enabled AND it is not a deterministic
    scaffolder. Delegating to ``coder_enabled`` keeps the "off" vocabulary defined in exactly one
    place, so a future provider added to ``_PROVIDERS_OFF`` is honoured here for free.
    """
    if not coder_enabled(raw):
        return False
    provider = str(coder_config(raw).get("provider", "off")).strip().lower()
    return provider not in PROVIDERS_DETERMINISTIC


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
    # Tell the UI the truth about WHICH engine is answering. Without this flag the deterministic
    # coder (no API key, no model name, no endpoint) reads as a half-finished configuration, when
    # it is in fact the working offline path — scaffolds and mechanical edits, verify-gated.
    provider = str(cfg.get("provider", "off")).strip().lower()
    safe["deterministic"] = provider in PROVIDERS_DETERMINISTIC
    safe["deterministic_providers"] = sorted(PROVIDERS_DETERMINISTIC)
    return safe


# Sentinel a client sends inside a provider block to delete the stored API key.
# A blank api_key deliberately means "keep what's stored" (the UI never receives the
# key back, so re-saving any other field would otherwise wipe it) -- which leaves no
# way to express deletion. This flag is that explicit, unambiguous path.
CLEAR_API_KEY_FIELD = "clear_api_key"

# Strings a JSON client may send for "no". Without this, `bool("false")` is True and a
# stringified flag would silently delete a key.
_FALSE_FLAGS = frozenset({"", "0", "false", "no", "off", "null", "none"})


def _flag(value: Any) -> bool:
    """Truthiness for a JSON flag, with the usual false-ish strings read as False."""
    if isinstance(value, str):
        return value.strip().lower() not in _FALSE_FLAGS
    return bool(value)


def api_key_clear_requests(update: dict[str, Any] | None) -> set[str]:
    """Provider names in a UI update that explicitly ask for the stored API key to be
    deleted. A blank api_key is NOT a clear request — it means "keep what's stored".

    The secrets store lives outside this module (backend/greyiq_api.py), so the caller
    pairs this with :func:`merge_update` to delete the key there as well.
    """
    return {
        str(key)
        for key, value in (update or {}).items()
        if isinstance(value, dict) and _flag(value.get(CLEAR_API_KEY_FIELD))
    }


def merge_update(existing: dict[str, Any] | None, update: dict[str, Any]) -> dict[str, Any]:
    """Apply a partial update from the UI onto the stored config.

    An empty-string api_key in the update is treated as "leave unchanged" so the
    UI (which never receives keys) can save other fields without wiping the key.
    To actually remove a key the update sets ``clear_api_key: true`` in the provider
    block; that wins over any api_key sent alongside it, so a contradictory update
    fails safe (visibly no key) rather than silently keeping a key the operator
    asked to delete. The flag is a command, not a setting — it is never stored.
    """
    cfg = coder_config(existing)
    for key, value in (update or {}).items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            clearing = _flag(value.get(CLEAR_API_KEY_FIELD))
            for sub_key, sub_value in value.items():
                if sub_key == CLEAR_API_KEY_FIELD:
                    continue  # a command, not a stored field
                if sub_key == "api_key" and (clearing or not str(sub_value or "").strip()):
                    continue  # blank = keep the stored key; an explicit clear outranks it
                cfg[key][sub_key] = sub_value
            if clearing:
                cfg[key]["api_key"] = ""
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
    if provider in PROVIDERS_DETERMINISTIC:
        # The deterministic coder has no chat completion — it only makes verify-gated EDITS through
        # the agent. Say that plainly instead of "Unknown provider", which reads as a bad setting.
        raise CoderError(
            "The offline (deterministic) coder does not chat — it edits files. Use the Workbench "
            "agent, or configure a Local model (Ollama) or Claude brain for conversation."
        )
    if provider == "anthropic":
        # response_schema is Anthropic-only: it constrains the reply to valid JSON. Other providers
        # keep the prose-scraping path, so a caller can always fall back to _parse_json_object.
        schema = cfg.get("response_schema") if isinstance(cfg.get("response_schema"), dict) else None
        return _generate_anthropic(messages, system_prompt, cfg["anthropic"], max_tokens, timeout, schema)
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
    schema: dict[str, Any] | None = None,
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
    # Prompt caching: the system prompt is a large, stable prefix re-sent on every call of a given
    # brain (the hunt planner alone appends up to 56k chars of technique playbooks per run). Marking
    # it as an ephemeral cache breakpoint makes repeat calls read that prefix at ~0.1x input price
    # instead of re-paying it. agent.py has done this since v0.9; the chat/hunt/report path had not.
    base_kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": [{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
    }
    # Adaptive thinking + effort is the recommended setup on Opus 5 / 4.8 / 4.7 / Sonnet.
    # Passed via extra_body so the request shape does not depend on the installed SDK version;
    # older models reject these, so we degrade progressively on a 400 rather than all-at-once.
    # effort is sent INDEPENDENTLY of thinking. They are separate controls, and bundling them meant
    # a brain with thinking off also silently lost its effort level — landing on the API default
    # rather than the cheap setting that was chosen deliberately.
    use_thinking = bool(block.get("thinking", True))
    extra_body: dict[str, Any] = {"output_config": {"effort": str(block.get("effort") or "high")}}
    if use_thinking:
        extra_body["thinking"] = {"type": "adaptive"}
    # Structured output: when a caller supplies a JSON schema the model is CONSTRAINED to emit
    # matching JSON, instead of us scraping the first {...} out of prose. Shape only — the content is
    # still untrusted and still passes the caller's validator and brain_safety sanitizer.
    if isinstance(schema, dict) and schema:
        extra_body.setdefault("output_config", {})
        extra_body["output_config"]["format"] = {"type": "json_schema", "schema": schema}

    # Capability ladder: drop ONE unsupported capability per 400 and try again, rather than throwing
    # everything away at the first rejection. An older model can reject caching, then the schema, then
    # adaptive thinking — a single-shot retry would surface the second rejection as a hard failure and
    # a bundled retry would discard capabilities the model actually supports. Each rung is
    # independent, so a cache rejection never costs us thinking and vice versa.
    attempt_system: Any = base_kwargs["system"]
    attempt_extra: dict[str, Any] = {k: (dict(v) if isinstance(v, dict) else v) for k, v in extra_body.items()}
    response = None
    for _ in range(len(("cache", "schema", "thinking")) + 1):
        try:
            response = client.messages.create(
                **{**base_kwargs, "system": attempt_system}, extra_body=attempt_extra or None
            )
            break
        except anthropic.BadRequestError as exc:
            message = str(getattr(exc, "message", exc)).lower()
            output_config = attempt_extra.get("output_config") or {}
            if "cache" in message and isinstance(attempt_system, list):
                attempt_system = system_prompt          # rung 1: plain system prompt, keep the rest
                continue
            if "format" in output_config and ("schema" in message or "format" in message):
                output_config.pop("format", None)       # rung 2: unconstrained output, keep thinking
                continue
            if attempt_extra and ("effort" in message or "thinking" in message or "output_config" in message):
                attempt_extra = {}                      # rung 3: bare request
                continue
            raise CoderError(f"Claude rejected the request: {getattr(exc, 'message', exc)}") from exc
        except anthropic.AuthenticationError as exc:
            raise CoderError("Claude rejected the API key (authentication failed).") from exc
        except anthropic.APIStatusError as exc:
            raise CoderError(f"Claude API error {exc.status_code}: {getattr(exc, 'message', exc)}") from exc
        except Exception as exc:  # noqa: BLE001 - network/SDK errors surfaced to user
            raise CoderError(f"Claude request failed: {exc}") from exc
    if response is None:  # every rung rejected: report it rather than dereference None
        raise CoderError("Claude rejected the request even without thinking, caching, or a schema.")

    # Why stop_reason is checked BEFORE the text: on current models max_tokens is a shared ceiling
    # over thinking AND the response, so a deep-reasoning turn can spend the budget thinking and come
    # back with a truncated answer. Returning that as a success is the worst outcome — a half-written
    # attack plan or a clipped JSON object reads as real output. Fail loudly and name the fix instead.
    stop_reason = str(getattr(response, "stop_reason", "") or "")
    if stop_reason == "refusal":
        raise CoderError("Claude declined this request (safety refusal); nothing was returned.")

    text = "".join(
        getattr(block_, "text", "") for block_ in response.content if getattr(block_, "type", "") == "text"
    ).strip()

    if stop_reason == "max_tokens":
        raise CoderError(
            f"Claude hit the {max_tokens}-token output ceiling before finishing "
            "(on current models that budget covers thinking as well as the reply), so the answer was "
            "cut off. Raise max_tokens in the coding-brain settings, or lower the effort level."
        )
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
        "stream": False,
    }
    apply_chat_completion_temperature(payload, base_url, model, temperature)
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
        body = json.loads(request_chat_completion_with_compat(_open, payload).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = chat_completion_error_detail(exc)
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
