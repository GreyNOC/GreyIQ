"""A manual (non-span) cockpit campaign against a policy-bound program must STILL apply that program's
VDP policy. The cockpit sends the program's real id in `active_program_id` (its free-text `program`
field holds only a HackerOne handle, or is empty for a preset program with no handle), so the plain
path must resolve the program by that id and thread its policy_profile into the engine. Regression."""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


def _run_capturing_policy(monkeypatch, **req_kwargs):
    captured = {}

    def _fake_engine(target, **kwargs):
        captured.update(kwargs)
        return {"ok": True, "findings": [], "confirmed": 0}

    monkeypatch.setattr(api.bounty_campaign, "run_campaign", _fake_engine)
    rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
    monkeypatch.setattr(rt, "_coder_config", lambda: {}, raising=False)
    monkeypatch.setattr(rt, "_cache_bounty_run", lambda *a, **k: None, raising=False)
    api.GreyIQRuntime.run_campaign(rt, api.CampaignRequest(**req_kwargs))
    return captured


def test_plain_path_applies_policy_via_active_program_id(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "RUNTIME_DIR", tmp_path)   # BEFORE saving the program
    rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
    prog = api.GreyIQRuntime.create_program_from_preset(rt, api.VdpPresetRequest(profile="nasa"))["program"]
    captured = _run_capturing_policy(
        monkeypatch,
        target="https://nasa.gov/app", authorized=True, active_program_id=prog["id"],
    )
    # The engine received the NASA policy even though `program` (the handle) was empty and this was
    # a single-target run (no program_id / span).
    assert captured.get("policy_profile") == "nasa"


def test_plain_path_without_a_bound_program_has_no_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "RUNTIME_DIR", tmp_path)
    captured = _run_capturing_policy(
        monkeypatch, target="https://example.com/", authorized=True,
    )
    assert captured.get("policy_profile") == ""
