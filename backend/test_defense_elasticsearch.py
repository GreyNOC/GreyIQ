"""Elasticsearch collector contracts without a live cluster."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from backend import defense_elasticsearch as es


def _source(**overrides: object) -> dict[str, object]:
    return {
        "url": "https://user:pass@logs.example:9200",
        "table": "security-logs",
        "cursor_column": "event.sequence",
        "message_column": "message",
        "severity_column": "log.level",
        **overrides,
    }


def _hit(cursor: int, message: str = "failed login", level: str = "warning") -> dict[str, object]:
    return {
        "sort": [cursor],
        "_source": {"message": message, "log": {"level": level}},
    }


class FakeClient:
    def __init__(self, *hits: list[dict[str, object]]) -> None:
        self.responses = list(hits)
        self.calls: list[dict[str, object]] = []
        self.closed = 0

    def search(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return {"hits": {"hits": self.responses.pop(0)}}

    def close(self) -> None:
        self.closed += 1


def test_new_source_baselines_then_reads_only_new_events(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient([_hit(10)], [_hit(11, "access denied")])
    monkeypatch.setattr(es, "_client", lambda _source: fake)
    events, checkpoint = es.read_elasticsearch(_source(), {"initialized": False, "cursor": None})
    assert events == []
    assert checkpoint == {"initialized": True, "cursor": {"type": "integer", "value": "10"}}
    assert fake.calls[0]["size"] == 1
    assert fake.calls[0]["sort"] == [{"event.sequence": {"order": "desc"}}]

    events, checkpoint = es.read_elasticsearch(_source(), checkpoint)
    assert events[0][1:] == ("access denied", "warning")
    assert checkpoint["cursor"] == {"type": "integer", "value": "11"}
    assert fake.calls[1]["query"] == {"range": {"event.sequence": {"gt": 10}}}
    assert fake.calls[1]["source_includes"] == ["message", "log.level"]
    assert fake.calls[1]["allow_partial_search_results"] is False
    assert fake.closed == 2


def test_backfill_is_oldest_first_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient([_hit(1), _hit(2)])
    monkeypatch.setattr(es, "_client", lambda _source: fake)
    events, checkpoint = es.read_elasticsearch(_source(), {"initialized": True, "cursor": None}, limit=500)
    assert len(events) == 2
    assert checkpoint["cursor"] == {"type": "integer", "value": "2"}
    assert fake.calls[0]["size"] == 100
    assert fake.calls[0]["query"] == {"match_all": {}}
    assert fake.calls[0]["sort"] == [{"event.sequence": {"order": "asc"}}]


def test_duplicate_or_backward_cursor_does_not_advance_checkpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient([_hit(3), _hit(3)])
    monkeypatch.setattr(es, "_client", lambda _source: fake)
    checkpoint = {"initialized": True, "cursor": {"type": "integer", "value": "2"}}
    with pytest.raises(ValueError, match="unique and increasing"):
        es.read_elasticsearch(_source(), checkpoint)
    assert checkpoint["cursor"]["value"] == "2"


def test_cleared_index_resets_cursor_before_replaying_new_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient([], [_hit(1)], [_hit(1)])
    monkeypatch.setattr(es, "_client", lambda _source: fake)
    checkpoint = {"initialized": True, "cursor": {"type": "integer", "value": "10"}}
    events, reset = es.read_elasticsearch(_source(), checkpoint)
    assert events == []
    assert reset["cursor"] is None
    assert reset["reset_at"]
    assert fake.calls[1]["size"] == 1
    assert fake.calls[1]["source"] is False
    events, resumed = es.read_elasticsearch(_source(), reset)
    assert len(events) == 1
    assert resumed["cursor"]["value"] == "1"


def test_equal_latest_cursor_does_not_trigger_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient([], [_hit(10)])
    monkeypatch.setattr(es, "_client", lambda _source: fake)
    checkpoint = {"initialized": True, "cursor": {"type": "integer", "value": "10"}}
    events, next_checkpoint = es.read_elasticsearch(_source(), checkpoint)
    assert events == []
    assert next_checkpoint == checkpoint


def test_message_and_severity_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient([_hit(1, "x" * 10000, "y" * 1000)])
    monkeypatch.setattr(es, "_client", lambda _source: fake)
    events, _ = es.read_elasticsearch(_source(), {"initialized": True, "cursor": None})
    assert len(events[0][1]) == 2048
    assert len(events[0][2]) == 64


@pytest.mark.parametrize("index", ["logs-*", "logs,other", "remote:logs", "<logs-{now/d}>", ".security"])
def test_index_expressions_and_internal_indices_are_rejected(index: str) -> None:
    with pytest.raises(ValueError, match="single exact"):
        es.read_elasticsearch(_source(table=index), {"initialized": True, "cursor": None})


def test_basic_auth_is_removed_from_endpoint_and_timeout_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    received: dict[str, object] = {}

    def constructor(endpoint: str, **kwargs: object) -> SimpleNamespace:
        received.update(endpoint=endpoint, **kwargs)
        return SimpleNamespace()

    monkeypatch.setitem(sys.modules, "elasticsearch", SimpleNamespace(Elasticsearch=constructor))
    es._client(_source(url="https://user:p%40ss@logs.example:9200"))
    assert received["endpoint"] == "https://logs.example:9200"
    assert received["basic_auth"] == ("user", "p@ss")
    assert received["request_timeout"] == 5
    assert received["max_retries"] == 0
    assert received["retry_on_timeout"] is False


def test_api_key_auth_and_credentials_never_surface_in_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "secret-api-key"
    received: dict[str, object] = {}

    def constructor(endpoint: str, **kwargs: object) -> SimpleNamespace:
        received.update(endpoint=endpoint, **kwargs)
        return SimpleNamespace()

    monkeypatch.setitem(sys.modules, "elasticsearch", SimpleNamespace(Elasticsearch=constructor))
    es._client(_source(url="https://logs.example:9200", api_key=secret))
    assert received["api_key"] == secret
    assert "basic_auth" not in received

    with pytest.raises(ValueError) as exc:
        es.read_elasticsearch(_source(api_key=secret), {"initialized": True, "cursor": None})
    assert secret not in str(exc.value)

    class FailingClient:
        def search(self, **_kwargs: object) -> None:
            raise OSError(f"URL https://user:pass@logs.example:9200 key={secret}")

        def close(self) -> None:
            pass

    monkeypatch.setattr(es, "_client", lambda _source: FailingClient())
    with pytest.raises(RuntimeError) as exc:
        es.read_elasticsearch(_source(url="https://logs.example:9200", api_key=secret),
                              {"initialized": True, "cursor": None})
    assert secret not in str(exc.value)
    assert "pass" not in str(exc.value)


def test_client_constructor_error_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    def constructor(_endpoint: str, **_kwargs: object) -> None:
        raise ValueError("https://user:pass@logs.example:9200")

    monkeypatch.setitem(sys.modules, "elasticsearch", SimpleNamespace(Elasticsearch=constructor))
    with pytest.raises(RuntimeError) as exc:
        es.read_elasticsearch(_source(), {"initialized": True, "cursor": None})
    assert "pass" not in str(exc.value)
    assert "logs.example" not in str(exc.value)


def test_missing_message_source_fails_without_advancing_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient([{"sort": [4]}])
    monkeypatch.setattr(es, "_client", lambda _source: fake)
    checkpoint = {"initialized": True, "cursor": {"type": "integer", "value": "3"}}
    with pytest.raises(ValueError, match="message source"):
        es.read_elasticsearch(_source(), checkpoint)
    assert checkpoint["cursor"]["value"] == "3"


def test_missing_message_field_fails_without_advancing_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient([{"sort": [4], "_source": {"other": "failed login"}}])
    monkeypatch.setattr(es, "_client", lambda _source: fake)
    checkpoint = {"initialized": True, "cursor": {"type": "integer", "value": "3"}}
    with pytest.raises(ValueError, match="message field"):
        es.read_elasticsearch(_source(), checkpoint)
    assert checkpoint["cursor"]["value"] == "3"
