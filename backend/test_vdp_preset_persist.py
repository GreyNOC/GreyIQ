"""The one-click VDP preset (create_program_from_preset) must be IDEMPOTENT and NON-DESTRUCTIVE:
re-running it can never re-widen a scope the operator narrowed (NASA's own rules say to prefer a test
host). A profile only ever narrows — never widens scope. Regression for that."""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
from bughunter import portfolio  # noqa: E402


def _create(rt):
    return api.GreyIQRuntime.create_program_from_preset(rt, api.VdpPresetRequest(profile="nasa"))


def test_preset_creates_then_never_rewidens_a_narrowed_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "RUNTIME_DIR", tmp_path)
    rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)

    res1 = _create(rt)
    assert res1["ok"] and res1["created"] is True
    prog = res1["program"]
    assert "nasa.gov" in prog["scope_text"]
    pid = prog["id"]

    # Operator narrows the saved NASA program down to a single test host, and clears the span list.
    portfolio.upsert_program(tmp_path, {
        "id": pid, "name": prog["name"], "policy_profile": "nasa",
        "scope_text": "test.gcn.nasa.gov", "in_scope_hosts": ["test.gcn.nasa.gov"],
        "structured_scope": [], "seed_targets": [],
    })

    # Re-clicking the preset must update the SAME program and leave the narrowed scope intact.
    res2 = _create(rt)
    assert res2["ok"] and res2["created"] is False
    prog2 = res2["program"]
    assert prog2["id"] == pid
    assert prog2["scope_text"] == "test.gcn.nasa.gov"      # not re-widened
    assert "nasa.gov" not in " ".join(prog2.get("in_scope_hosts") or ["x"]).replace("test.gcn.nasa.gov", "")
    assert not prog2.get("structured_scope")               # emptied span list stays empty
    # ...but the policy binding is (re)asserted.
    assert prog2["policy_profile"] == "nasa"


def test_fresh_preset_carries_full_scope_and_span_targets(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "RUNTIME_DIR", tmp_path)
    rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
    prog = _create(rt)["program"]
    # A brand-new preset program is huntable via span too (structured_scope seeded from in-scope hosts).
    ids = {e["identifier"] for e in prog.get("structured_scope") or []}
    assert "nasa.gov" in ids and len(ids) >= 5
