"""Offline contract and safety checks for researcher program previews."""

from __future__ import annotations

import io
import sys
import urllib.error
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import platform_programs as pp

PROGRAM = "11111111-1111-1111-1111-111111111111"


def _intigriti_detail() -> dict:
    return {"id": PROGRAM, "handle": "acme", "name": "Acme", "status": {"id": 1, "value": "Open"},
            "domains": {"content": [
                {"type": {"value": "Website"}, "endpoint": "https://app.example.test",
                 "tier": {"value": "Tier 1"}, "description": "Only test your own account"}]},
            "rulesOfEngagement": {"content": {
                "description": "No service disruption", "testingRequirements": {
                    "automatedTooling": 1, "userAgent": "Researcher", "requestHeader": None,
                    "intigritiMe": True}}}}


def test_intigriti_listing_uses_researcher_api_and_bearer_auth():
    calls = []

    def fetch(url, *, headers, timeout):
        calls.append((url, headers))
        return {"maxCount": 1, "records": [{"id": PROGRAM, "handle": "acme",
                                            "name": "Acme", "status": {"value": "Open"}}]}

    result = pp.list_programs("intigriti", "abc.def", fetch=fetch)
    assert result["ok"] is True
    assert result["programs"][0] == {
        "id": PROGRAM, "handle": "acme", "name": "Acme", "status": "Open",
        "source_url": f"https://api.intigriti.com/external/researcher/v1/programs/{PROGRAM}"}
    assert calls[0][0].startswith("https://api.intigriti.com/external/researcher/v1/programs?")
    assert calls[0][1]["Authorization"] == "Bearer abc.def"


def test_intigriti_listing_is_bounded_and_ignores_remote_next_url():
    calls = []

    def fetch(url, *, headers, timeout):
        calls.append(url)
        start = len(calls) * 25 - 24
        return {"records": [{"id": f"{i:08x}-1111-1111-1111-111111111111",
                             "handle": f"program-{i}", "name": f"Program {i}"}
                            for i in range(start, start + 25)],
                "maxCount": 1000, "next": "https://attacker.example/steal"}

    result = pp.list_programs("intigriti", "token", fetch=fetch, limit=10000)
    assert result["ok"] is True
    assert len(calls) == 4
    assert len(result["programs"]) == 100
    assert all(url.startswith("https://api.intigriti.com/external/researcher/v1/programs?") for url in calls)
    assert any("capped" in warning for warning in result["warnings"])


def test_bugcrowd_researcher_discovery_and_preview_make_no_request():
    calls = []
    fetch = lambda url, **kwargs: calls.append((url, kwargs))
    assert pp.list_programs("bugcrowd", "id:secret", fetch=fetch)["ok"] is False
    assert pp.preview_program("bugcrowd", PROGRAM, "id:secret", fetch=fetch)["ok"] is False
    assert pp._safe_api_url("bugcrowd", "https://api.bugcrowd.com/programs") is False
    assert calls == []


def test_intigriti_preview_is_explicitly_incomplete_because_exclusions_are_not_exposed():
    result = pp.preview_program("intigriti", PROGRAM, "my-token", fetch=lambda url, **kw: _intigriti_detail())
    assert result["ok"] is True
    assert result["scope_complete"] is False
    assert result["structured_scope"][0]["identifier"] == "https://app.example.test"
    assert result["structured_scope"][0]["eligible_for_bounty"] is False
    assert "Automated tooling setting: 1" in result["policy_excerpt"]
    assert any("out-of-scope" in warning for warning in result["warnings"])


def test_intigriti_explicit_out_of_scope_tier_and_missing_tier_are_not_eligible():
    detail = _intigriti_detail()
    detail["domains"]["content"].extend([
        {"type": {"value": "Website"}, "endpoint": "excluded.example.test",
         "tier": {"value": "Out of scope"}, "description": "Do not test"},
        {"type": {"value": "Website"}, "endpoint": "unknown.example.test",
         "tier": None, "description": "Unclear"},
    ])
    result = pp.preview_program("intigriti", PROGRAM, "my-token", fetch=lambda url, **kw: detail)
    assert [row["eligible_for_submission"] for row in result["structured_scope"]] == [True, False, False]
    assert any("no scope tier" in warning for warning in result["warnings"])


def test_strict_uuid_and_api_host_pinning_prevent_credential_leaks():
    calls = []
    fetch = lambda url, **kwargs: calls.append((url, kwargs))
    assert pp.preview_program("intigriti", "../other", "secret", fetch=fetch)["ok"] is False
    for bad in ("http://api.intigriti.com/external/researcher/v1/programs",
                "https://api.intigriti.com.evil.test/external/researcher/v1/programs",
                "https://evil.test@api.intigriti.com:444/external/researcher/v1/programs",
                "https://api.intigriti.com/external/researcher/v1/programs/../payouts"):
        assert pp._safe_api_url("intigriti", bad) is False
        try:
            pp._request("intigriti", bad, "secret", fetch)
        except ValueError:
            pass
        else:
            assert False, "unsafe URL was accepted"
    assert calls == []


def test_redirect_is_refused_and_never_follows_to_location():
    assert pp._NoRedirect().redirect_request(None, None, 302, "Moved", {},
                                             "https://attacker.example/steal") is None

    def fetch(url, *, headers, timeout):
        raise urllib.error.HTTPError(url, 302, "Moved", {"Location": "https://attacker.example/steal"}, io.BytesIO())

    result = pp.list_programs("intigriti", "token", fetch=fetch)
    assert result["ok"] is False
    assert result["status"] == 302
    assert "redirect refused" in result["error"]
    assert "attacker.example" not in str(result)


def test_malformed_schemas_and_credentials_fail_closed():
    assert pp.list_programs("intigriti", "token", fetch=lambda url, **kw: {"records": {}})["ok"] is False
    assert pp.preview_program("intigriti", PROGRAM, "token", fetch=lambda url, **kw: [1])["ok"] is False
    assert pp.list_programs("intigriti", "contains\nnewline")["ok"] is False
    assert pp.list_programs("unknown", "token")["ok"] is False
