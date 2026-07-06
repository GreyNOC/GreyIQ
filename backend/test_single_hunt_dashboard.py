"""A single hunt drives the SAME live dashboard the campaign uses: it must register its target as a
work unit and stream its findings into the progress snapshot (per-target status + findings + tiles),
so the operator can watch a single hunt work exactly like a campaign. Regression for that wiring."""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
from bughunter import progress as bounty_progress  # noqa: E402


def _run_stubbed(monkeypatch, canned, *, run_id):
    monkeypatch.setattr(api, "run_bounty_hunt", lambda *a, **k: canned)
    rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
    monkeypatch.setattr(rt, "_coder_config", lambda: {}, raising=False)
    monkeypatch.setattr(rt, "_oob_config", lambda: ("", ""), raising=False)
    monkeypatch.setattr(rt, "_cache_bounty_run", lambda *a, **k: None, raising=False)
    req = api.BountyScanRequest(target="https://ex.com/", profile="full-sweep", authorized=True, run_id=run_id)
    api.GreyIQRuntime.run_bounty(rt, req)
    return bounty_progress.snapshot(run_id)


def test_single_hunt_streams_target_and_findings_to_dashboard(monkeypatch):
    canned = {
        "ok": True,
        "findings": [
            {"ref": "R1", "title": "Reflected XSS", "severity": "high", "class_id": "xss",
             "class_name": "XSS", "location": "https://ex.com/s", "cwe": "CWE-79", "rule_id": "active.xss"},
        ],
        "proof_of_impact": {"R1": {"status": "confirmed",
                                   "observed_result": "reflected", "control_result": "encoded"}},
    }
    snap = _run_stubbed(monkeypatch, canned, run_id="single-hunt-ok")
    # target registered + marked done
    tgt = [t for t in snap["targets"] if t["target"] == "https://ex.com/"]
    assert tgt and tgt[0]["status"] == "done"
    # finding streamed with its proof status (so the dashboard + drawer show it as a campaign target would)
    fnd = [f for f in snap["findings"] if f["title"] == "Reflected XSS"]
    assert fnd and fnd[0]["proof"] == "confirmed"
    # the drawer's "View full report" needs the captured differential — it must ride along
    assert fnd[0]["proof_detail"] and fnd[0]["proof_detail"].get("control_result")


def test_single_hunt_failure_marks_target_error(monkeypatch):
    snap = _run_stubbed(monkeypatch, {"ok": False, "error": "scope blocked"}, run_id="single-hunt-err")
    tgt = [t for t in snap["targets"] if t["target"] == "https://ex.com/"]
    assert tgt and tgt[0]["status"] == "error" and "scope blocked" in tgt[0]["error"]
    assert not snap["findings"]
