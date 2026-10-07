"""Offline contract and safety checks for third-party program previews."""

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
ENGAGEMENT = "22222222-2222-2222-2222-222222222222"
BRIEF = "33333333-3333-3333-3333-333333333333"
IN_GROUP = "44444444-4444-4444-4444-444444444444"
OUT_GROUP = "55555555-5555-5555-5555-555555555555"
IN_TARGET = "66666666-6666-6666-6666-666666666666"
OUT_TARGET = "77777777-7777-7777-7777-777777777777"


def _bc_program(index: int = 1) -> dict:
    program_id = f"{index:08x}-1111-1111-1111-111111111111"
    return {"type": "program", "id": program_id,
            "attributes": {"code": f"program-{index}", "name": f"Program {index}"}}


def _bc_detail() -> dict:
    return {"data": {"type": "program", "id": PROGRAM,
                     "attributes": {"code": "acme", "name": "Acme"},
                     "relationships": {"engagements": {"data": [
                         {"type": "engagement", "id": ENGAGEMENT}]}}}}


def _bc_engagement() -> dict:
    return {
        "data": {"type": "engagement", "id": ENGAGEMENT,
                 "attributes": {"state": "live"},
                 "relationships": {"engagement_brief": {"data": {
                     "type": "engagement_brief", "id": BRIEF}}}},
        "included": [
            {"type": "engagement_brief", "id": BRIEF,
             "attributes": {"description": "No denial of service", "targets_overview": "Use test accounts"},
             "relationships": {"engagement_brief_target_groups": {"data": [
                 {"type": "target_group", "id": IN_GROUP},
                 {"type": "target_group", "id": OUT_GROUP}]}}},
            {"type": "target_group", "id": IN_GROUP,
             "attributes": {"in_scope": True, "description": "Web application"},
             "relationships": {"targets": {"data": [{"type": "target", "id": IN_TARGET}]}}},
            {"type": "target_group", "id": OUT_GROUP,
             "attributes": {"in_scope": False, "description": "Never test"},
             "relationships": {"targets": {"data": [{"type": "target", "id": OUT_TARGET}]}}},
            {"type": "target", "id": IN_TARGET,
             "attributes": {"name": "https://app.example.test", "category": "website"}},
            {"type": "target", "id": OUT_TARGET,
             "attributes": {"name": "admin.example.test", "category": "website"}},
        ],
    }


def _intigriti_detail() -> dict:
    return {"id": PROGRAM, "handle": "acme", "name": "Acme", "status": {"id": 1, "value": "Open"},
            "domains": {"id": BRIEF, "content": [
                {"id": IN_TARGET, "type": {"id": 1, "value": "Website"},
                 "endpoint": "https://app.example.test", "tier": {"id": 1, "value": "Tier 1"},
                 "description": "Only test your own account"}]},
            "rulesOfEngagement": {"id": ENGAGEMENT, "content": {
                "description": "No service disruption", "testingRequirements": {
                    "automatedTooling": 1, "userAgent": "Researcher", "requestHeader": None,
                    "intigritiMe": True}, "safeHarbour": True}}}


def test_bugcrowd_listing_uses_official_json_api_shape_and_fixed_pagination():
    calls = []

    def fetch(url, *, headers, timeout):
        calls.append((url, headers, timeout))
        if len(calls) == 1:
            return {"data": [_bc_program(i) for i in range(1, 26)], "meta": {"total_hits": 26},
                    "links": {"next": "https://attacker.example/steal"}}
        return {"data": [_bc_program(26)], "meta": {"total_hits": 26}}

    result = pp.list_programs("bugcrowd", "id:secret", fetch=fetch)
    assert result["ok"] is True
    assert len(result["programs"]) == 26
    assert result["programs"][0] == {
        "id": "00000001-1111-1111-1111-111111111111", "handle": "program-1",
        "name": "Program 1", "status": "unknown",
        "source_url": "https://api.bugcrowd.com/programs/00000001-1111-1111-1111-111111111111"}
    assert all(url.startswith("https://api.bugcrowd.com/programs?") for url, _, _ in calls)
    assert "page%5Boffset%5D=25" in calls[1][0]
    assert all(headers["Authorization"] == "Token id:secret" for _, headers, _ in calls)
    assert all(headers["Accept"] == "application/vnd.bugcrowd+json" for _, headers, _ in calls)


def test_intigriti_listing_uses_records_and_bearer_auth():
    calls = []

    def fetch(url, *, headers, timeout):
        calls.append((url, headers))
        return {"maxCount": 1, "records": [{"id": PROGRAM, "handle": "acme",
                                            "name": "Acme", "status": {"id": 1, "value": "Open"}}]}

    result = pp.list_programs("intigriti", "abc.def", fetch=fetch)
    assert result["ok"] is True
    assert result["programs"][0]["status"] == "Open"
    assert calls[0][0].startswith("https://api.intigriti.com/external/researcher/v1/programs?")
    assert calls[0][1]["Authorization"] == "Bearer abc.def"


def test_list_caps_request_count_even_when_remote_claims_more():
    calls = []

    def fetch(url, *, headers, timeout):
        calls.append(url)
        start = len(calls) * 25 - 24
        return {"data": [_bc_program(i) for i in range(start, start + 25)],
                "meta": {"total_hits": 1000}}

    result = pp.list_programs("bugcrowd", "id:secret", fetch=fetch, limit=10000)
    assert result["ok"] is True
    assert len(calls) == 4
    assert len(result["programs"]) == 100
    assert any("capped" in warning for warning in result["warnings"])


def test_preview_bugcrowd_joins_included_targets_and_preserves_exclusions():
    calls = []

    def fetch(url, *, headers, timeout):
        calls.append(url)
        return _bc_detail() if "/programs/" in url else _bc_engagement()

    result = pp.preview_program("bugcrowd", PROGRAM, "id:secret", fetch=fetch)
    assert result["ok"] is True
    assert result["scope_complete"] is True
    assert result["program_name"] == "Acme"
    assert result["status"] == "live"
    assert result["fetched_at"]
    assert len(result["structured_scope"]) == 2
    assert result["structured_scope"][0]["eligible_for_submission"] is True
    assert result["structured_scope"][1]["eligible_for_submission"] is False
    assert result["structured_scope"][1]["identifier"] == "admin.example.test"
    assert "No denial of service" in result["policy_excerpt"]
    assert calls == [
        f"https://api.bugcrowd.com/programs/{PROGRAM}?include=engagements",
        (f"https://api.bugcrowd.com/engagements/{ENGAGEMENT}"
         "?include=engagement_brief.engagement_brief_target_groups.targets")]


def test_preview_missing_bugcrowd_target_relation_is_incomplete_and_does_not_infer():
    engagement = _bc_engagement()
    engagement["included"][1]["relationships"]["targets"] = {
        "data": [{"type": "target", "id": IN_TARGET}],
        "links": {"related": {"meta": {"total_hits": 10}}}}

    def fetch(url, *, headers, timeout):
        return _bc_detail() if "/programs/" in url else engagement

    result = pp.preview_program("bugcrowd", PROGRAM, "id:secret", fetch=fetch)
    assert result["ok"] is True
    assert result["scope_complete"] is False
    assert not any(row["identifier"] == "https://app.example.test" for row in result["structured_scope"])
    assert any("relation is incomplete" in warning for warning in result["warnings"])


def test_preview_missing_explicit_in_scope_flag_ignores_group():
    engagement = _bc_engagement()
    engagement["included"][1]["attributes"].pop("in_scope")

    def fetch(url, *, headers, timeout):
        return _bc_detail() if "/programs/" in url else engagement

    result = pp.preview_program("bugcrowd", PROGRAM, "id:secret", fetch=fetch)
    assert result["scope_complete"] is False
    assert all(row["eligible_for_submission"] is False for row in result["structured_scope"])


def test_intigriti_preview_is_explicitly_incomplete_because_exclusions_are_not_exposed():
    result = pp.preview_program("intigriti", PROGRAM, "my-token", fetch=lambda url, **kw: _intigriti_detail())
    assert result["ok"] is True
    assert result["scope_complete"] is False
    assert result["structured_scope"][0]["identifier"] == "https://app.example.test"
    assert result["structured_scope"][0]["eligible_for_bounty"] is False
    assert "Automated tooling setting: 1" in result["policy_excerpt"]
    assert any("out-of-scope" in warning for warning in result["warnings"])


def test_strict_uuid_and_api_host_pinning_prevent_credential_leaks():
    calls = []
    fetch = lambda url, **kwargs: calls.append((url, kwargs))
    assert pp.preview_program("intigriti", "../other", "secret", fetch=fetch)["ok"] is False
    assert calls == []
    for bad in ("http://api.bugcrowd.com/programs", "https://api.bugcrowd.com.evil.test/programs",
                "https://evil.test@api.bugcrowd.com:444/programs",
                "https://api.intigriti.com/external/researcher/v1/programs/../payouts"):
        platform = "intigriti" if "intigriti" in bad else "bugcrowd"
        assert pp._safe_api_url(platform, bad) is False
        try:
            pp._request(platform, bad, "secret", fetch)
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

    result = pp.list_programs("bugcrowd", "id:secret", fetch=fetch)
    assert result["ok"] is False
    assert result["status"] == 302
    assert "redirect refused" in result["error"]
    assert "attacker.example" not in str(result)


def test_malformed_schemas_and_credentials_fail_closed():
    assert pp.list_programs("intigriti", "token", fetch=lambda url, **kw: {"records": {}})["ok"] is False
    assert pp.preview_program("intigriti", PROGRAM, "token", fetch=lambda url, **kw: [1])["ok"] is False
    assert pp.preview_program("bugcrowd", PROGRAM, "id:secret", fetch=lambda url, **kw: {"data": []})["ok"] is False
    assert pp.list_programs("bugcrowd", "contains\nnewline")["ok"] is False
    assert pp.list_programs("unknown", "token")["ok"] is False
