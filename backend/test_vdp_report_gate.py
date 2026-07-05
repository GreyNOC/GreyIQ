"""The on-demand report builder (/api/bounty/finding/report -> build_finding_report) is the single
choke point every hand-filed report flows through. Because the live dashboard streams findings BEFORE
the VDP filter runs, the report builder must RE-APPLY the bound program's policy — otherwise a finding
the campaign withheld could be reconstituted into a submittable report. These tests lock that gate in."""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402

# A real observed-vs-control differential — the same signal the engine's active provers capture, and
# what report._has_captured_artifact treats as a genuine confirmed proof of impact.
CONFIRMED_PROOF = {"status": "confirmed", "method": "GET",
                   "observed_result": "HTTP/1.1 200 OK\n{\"role\":\"admin\"}",
                   "control_result": "HTTP/1.1 403 Forbidden"}


def _report(**kw):
    rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
    return api.GreyIQRuntime.build_finding_report(rt, api.FindingReportRequest(**kw))


def test_gate_withholds_excluded_endpoint_even_when_confirmed():
    # NASA excludes /wp-json/wp/v2/users — withhold regardless of proof.
    res = _report(title="User enumeration", class_id="info", rule_id="info.users",
                  location="https://nasa.gov/wp-json/wp/v2/users",
                  policy_profile="nasa", proof=CONFIRMED_PROOF)
    assert res["ok"] is False and res.get("withheld") is True


def test_gate_withholds_rejected_class_even_when_confirmed():
    res = _report(title="Clickjacking", class_id="clickjacking", rule_id="active.clickjacking",
                  location="https://nasa.gov/", policy_profile="nasa", proof=CONFIRMED_PROOF)
    assert res["ok"] is False and res.get("withheld") is True


def test_gate_withholds_unconfirmed_under_confirmed_only():
    # In-scope, allowed class, but NO proof differential -> not confirmed -> NASA withholds it.
    res = _report(title="Possible CORS", class_id="cors", location="https://api.nasa.gov/user",
                  policy_profile="nasa")
    assert res["ok"] is False and res.get("withheld") is True


def test_gate_allows_confirmed_in_scope_finding():
    res = _report(title="IDOR on orders", class_id="cors", location="https://api.nasa.gov/orders/2",
                  policy_profile="nasa", proof=CONFIRMED_PROOF)
    assert res["ok"] is True and res.get("package")


def test_same_unconfirmed_finding_builds_normally_without_policy():
    # A/B against test_gate_withholds_unconfirmed_under_confirmed_only: the ONLY thing withholding it
    # is the NASA policy — with no policy bound, the on-demand builder authors it as before.
    res = _report(title="Possible CORS", class_id="cors", location="https://api.nasa.gov/user")
    assert res["ok"] is True and res.get("package")
