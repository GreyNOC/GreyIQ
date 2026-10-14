"""Bounded, read-only Elasticsearch source for the Defense log monitor.

The configured cursor field must be unique and increasing. Elasticsearch has no
unique-field constraint, so operators should use an ingest-generated sequence or
another field with that property. A timestamp alone is usually not sufficient.
"""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit


_MAX_ROWS = 100
_MAX_MESSAGE = 2048
_MAX_SEVERITY = 64
_REQUEST_TIMEOUT = 5
_INDEX = re.compile(r"^[a-z0-9][a-z0-9._-]{0,254}$")
_FIELD = re.compile(r"^[A-Za-z_@][A-Za-z0-9_@-]*(?:\.[A-Za-z_@][A-Za-z0-9_@-]*)*$")
_MISSING = object()


def _field_name(value: Any, *, required: bool) -> str:
    name = str(value or "").strip()
    if (required and not name) or (name and (len(name) > 255 or not _FIELD.fullmatch(name))):
        raise ValueError("Elasticsearch fields must be simple dotted names.")
    return name


def _source_fields(source: dict[str, Any]) -> tuple[str, str, str, str]:
    index = str(source.get("table") or "").strip()
    # Reject wildcard, multi-index, cross-cluster, and date-math expressions.
    if not _INDEX.fullmatch(index) or index in {".", ".."} or ".." in index:
        raise ValueError("Elasticsearch index must be a single exact name or alias.")
    cursor = _field_name(source.get("cursor_column"), required=True)
    message = _field_name(source.get("message_column"), required=True)
    severity = _field_name(source.get("severity_column"), required=False)
    if cursor == "_id":
        raise ValueError("Elasticsearch _id cannot be used as a sort cursor.")
    return index, cursor, message, severity


def _connection(source: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    raw = str(source.get("url") or "").strip()
    if not raw or len(raw) > 4096 or any(ord(char) < 33 or ord(char) == 127 for char in raw):
        raise ValueError("A valid HTTP(S) Elasticsearch URL is required.")
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError as exc:
        raise ValueError("A valid HTTP(S) Elasticsearch URL is required.") from None
    if parsed.scheme not in {"http", "https"} or not host or parsed.query or parsed.fragment:
        raise ValueError("A valid HTTP(S) Elasticsearch URL is required.")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("A valid HTTP(S) Elasticsearch URL is required.")
    endpoint = urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", ""))
    api_key = str(source.get("api_key") or "").strip()
    if len(api_key) > 4096 or (api_key and username is not None):
        raise ValueError("Choose either API key or Basic authentication.")
    auth: dict[str, Any] = {}
    if api_key:
        auth["api_key"] = api_key
    elif username is not None:
        auth["basic_auth"] = (unquote(username), unquote(password or ""))
    return endpoint, auth


def _client(source: dict[str, Any]) -> Any:
    endpoint, auth = _connection(source)
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        raise RuntimeError("Elasticsearch driver is not installed.") from None
    try:
        return Elasticsearch(
            endpoint, request_timeout=_REQUEST_TIMEOUT, max_retries=0,
            retry_on_timeout=False, sniff_on_start=False,
            sniff_before_requests=False, sniff_on_node_failure=False, **auth,
        )
    except Exception:
        # Client-constructor errors can also include the original URL.
        raise RuntimeError("Elasticsearch source unavailable.") from None


def _encode_cursor(value: Any) -> dict[str, str]:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("Elasticsearch cursor must be a sortable number or string.")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Elasticsearch cursor must be finite.")
    kind = "integer" if isinstance(value, int) else "float" if isinstance(value, float) else "string"
    encoded = str(value) if kind != "float" else repr(value)
    if len(encoded) > 512:
        raise ValueError("Elasticsearch cursor is too large.")
    return {"type": kind, "value": encoded}


def _decode_cursor(saved: Any) -> int | float | str | None:
    if saved is None:
        return None
    if not isinstance(saved, dict) or not isinstance(saved.get("value"), str):
        raise ValueError("Saved Elasticsearch cursor is invalid.")
    kind, value = saved.get("type"), saved["value"]
    if len(value) > 512:
        raise ValueError("Saved Elasticsearch cursor is invalid.")
    try:
        decoded: int | float | str
        if kind == "integer":
            decoded = int(value)
        elif kind == "float":
            decoded = float(value)
            if not math.isfinite(decoded):
                raise ValueError
        elif kind == "string":
            decoded = value
        else:
            raise ValueError
    except ValueError:
        raise ValueError("Saved Elasticsearch cursor is invalid.") from None
    return decoded


def _sort_value(hit: Any) -> int | float | str:
    if not isinstance(hit, dict) or not isinstance(hit.get("sort"), list) or len(hit["sort"]) != 1:
        raise ValueError("Elasticsearch cursor sort value is unavailable.")
    value = hit["sort"][0]
    _encode_cursor(value)
    return value


def _value(document: dict[str, Any], field: str) -> Any:
    if field in document:
        return document[field]
    current: Any = document
    for part in field.split("."):
        if not isinstance(current, dict):
            return _MISSING
        current = current.get(part, _MISSING)
        if current is _MISSING:
            return _MISSING
    return current


def _bounded(value: Any, limit: int) -> str:
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (int, float, bool)):
        return str(value)[:limit]
    return ""


def _hits(response: Any) -> list[dict[str, Any]]:
    try:
        rows = response["hits"]["hits"]
    except (KeyError, TypeError, IndexError):
        raise ValueError("Elasticsearch returned an invalid search response.") from None
    if not isinstance(rows, list):
        raise ValueError("Elasticsearch returned an invalid search response.")
    return rows


def read_elasticsearch(
    source: dict[str, Any], checkpoint: dict[str, Any], limit: int = _MAX_ROWS,
) -> tuple[list[tuple[str, str, str]], dict[str, Any]]:
    """Read the next ordered page, or baseline an uninitialized source.

    ``source`` contains URL, index (``table``), field names, and optional API key.
    The returned checkpoint is JSON-safe and matches DefenseLogMonitor's shape.
    """
    index, cursor_field, message_field, severity_field = _source_fields(source)
    _connection(source)
    if not isinstance(checkpoint, dict):
        raise ValueError("Elasticsearch checkpoint is invalid.")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("Elasticsearch read limit must be positive.")
    limit = min(limit, _MAX_ROWS)
    saved = _decode_cursor(checkpoint.get("cursor"))
    initialized = bool(checkpoint.get("initialized"))
    # Construct the entire query here. No user-provided JSON/DSL reaches search().
    query: dict[str, Any] = {"match_all": {}} if saved is None or not initialized else {
        "range": {cursor_field: {"gt": saved}}
    }
    order = "asc" if initialized else "desc"
    fields = [message_field] + ([severity_field] if severity_field else [])
    try:
        client = _client(source)
        try:
            response = client.search(
                index=index, query=query, sort=[{cursor_field: {"order": order}}],
                size=limit if initialized else 1,
                **({"source_includes": fields} if initialized else {"source": False}),
                track_total_hits=False, allow_partial_search_results=False,
            )
            rows = _hits(response)
            # A cleared or replaced index may start its sequence again. Persist
            # the reset before reading its new rows on the next poll.
            latest: int | float | str | None = None
            if initialized and saved is not None and not rows:
                top = _hits(client.search(
                    index=index, query={"match_all": {}},
                    sort=[{cursor_field: {"order": "desc"}}], size=1,
                    source=False, track_total_hits=False,
                    allow_partial_search_results=False,
                ))
                latest = _sort_value(top[0]) if top else None
        finally:
            client.close()
    except Exception:
        # Transport errors often contain a credential-bearing URL or request.
        raise RuntimeError("Elasticsearch source unavailable.") from None
    if len(rows) > (limit if initialized else 1):
        raise ValueError("Elasticsearch returned an oversized search response.")
    new_checkpoint = dict(checkpoint)
    new_checkpoint["initialized"] = True
    if not initialized:
        new_checkpoint["cursor"] = _encode_cursor(_sort_value(rows[0])) if rows else None
        return [], new_checkpoint
    if saved is not None and not rows:
        try:
            reset = latest is None or latest < saved
        except TypeError:
            reset = False
        if reset:
            new_checkpoint["cursor"] = None
            new_checkpoint["reset_at"] = datetime.now(timezone.utc).isoformat()
        return [], new_checkpoint
    events: list[tuple[str, str, str]] = []
    previous = saved
    for hit in rows:
        cursor = _sort_value(hit)
        if previous is not None:
            try:
                monotonic = cursor > previous
            except TypeError:
                monotonic = False
            if not monotonic:
                raise ValueError("Elasticsearch cursor must be unique and increasing.")
        previous = cursor
        if not isinstance(hit.get("_source"), dict):
            raise ValueError("Elasticsearch message source is unavailable.")
        document = hit["_source"]
        raw_message = _value(document, message_field)
        if raw_message is _MISSING:
            raise ValueError("Elasticsearch message field is unavailable.")
        message = _bounded(raw_message, _MAX_MESSAGE)
        severity = _bounded(_value(document, severity_field), _MAX_SEVERITY) if severity_field else ""
        locator = json.dumps(_encode_cursor(cursor), sort_keys=True)
        events.append((locator, message, severity))
    if rows:
        new_checkpoint["cursor"] = _encode_cursor(previous)
    return events, new_checkpoint
