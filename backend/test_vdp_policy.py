"""Tests for VDP policy profiles ("NASA mode") — bughunter.vdp_policy + the portfolio/campaign wiring
that binds a saved program to a program's published rules of engagement (scope + excluded endpoints/
classes + confirmed-only + no-DoS)."""

from __future__ import annotations

from bughunter import portfolio, vdp_policy


# --- profile lookup + preset ----------------------------------------------------------------------

def test_get_profile_is_case_insensitive_and_none_for_unknown():
    assert vdp_policy.get_profile("nasa") is vdp_policy.get_profile("NASA")
    assert vdp_policy.get_profile("nasa") is not None
    assert vdp_policy.get_profile("") is None
    assert vdp_policy.get_profile(None) is None
    assert vdp_policy.get_profile("does-not-exist") is None
    # Restrictions are explicit U.S.-federal profiles; a hostname never auto-selects one.
    assert vdp_policy.get_profile("nasa.gov") is None
    assert {p.get("entity_class") for p in vdp_policy.PROFILES.values()} == {"us-federal"}


def test_nasa_program_preset_carries_scope_and_binding():
    preset = vdp_policy.program_preset("nasa")
    assert preset is not None
    assert preset["policy_profile"] == "nasa"
    # in-scope registered domains are pre-filled as both scope_text and structured host list
    assert "nasa.gov" in preset["scope_text"]
    assert "nasa.gov" in preset["in_scope_hosts"]
    # a VDP submission should note automated-tool assistance
    assert preset["disclose_automation"] is True
    assert vdp_policy.program_preset("nope") is None


# --- portfolio._normalize validates the profile id ------------------------------------------------

def test_normalize_keeps_known_profile_and_drops_unknown():
    assert portfolio._normalize({"name": "x", "policy_profile": "NASA"})["policy_profile"] == "nasa"
    assert portfolio._normalize({"name": "x", "policy_profile": "bogus"})["policy_profile"] == ""
    assert portfolio._normalize({"name": "x"})["policy_profile"] == ""


# --- filter_findings: the core report-narrowing rules ---------------------------------------------

def _item(ref, rule, status, location):
    return {"proof_status": status, "finding": {"ref": ref, "rule_id": rule, "title": ref, "location": location}}


def test_filter_keeps_confirmed_in_scope_finding():
    p = vdp_policy.get_profile("nasa")
    items = [_item("a", "active.jwt-alg-none", "confirmed", "https://api.nasa.gov/token")]
    kept, dropped = vdp_policy.filter_findings(items, p)
    assert [k["finding"]["ref"] for k in kept] == ["a"]
    assert dropped == []


def test_filter_drops_excluded_endpoint():
    p = vdp_policy.get_profile("nasa")
    items = [_item("u", "info.users", "confirmed", "https://nasa.gov/wp-json/wp/v2/users")]
    kept, dropped = vdp_policy.filter_findings(items, p)
    assert kept == []
    assert len(dropped) == 1 and "excluded endpoint" in dropped[0]["reason"]


def test_filter_drops_always_rejected_class():
    p = vdp_policy.get_profile("nasa")
    items = [_item("c", "active.clickjacking", "confirmed", "https://nasa.gov/")]
    kept, dropped = vdp_policy.filter_findings(items, p)
    assert kept == []
    assert "not accepted" in dropped[0]["reason"]


def test_filter_drops_unconfirmed_when_confirmed_only():
    p = vdp_policy.get_profile("nasa")
    items = [_item("d", "active.idor", "candidate", "https://nasa.gov/obj/2")]
    kept, dropped = vdp_policy.filter_findings(items, p)
    assert kept == []
    assert "not confirmed" in dropped[0]["reason"]


def test_filter_never_raises_and_fails_safe_under_confirmed_only():
    p = vdp_policy.get_profile("nasa")  # confirmed_only=True
    # Under a confirmed-only program, an item we CANNOT evaluate must be WITHHELD, never kept — we
    # can't vouch it carries a proof of exploit, and NASA rejects unconfirmed findings. Non-dict junk
    # (None, 42) raises inside the try; the empty dict is unconfirmed. All three must be dropped.
    kept, dropped = vdp_policy.filter_findings([None, 42, {"garbage": True}], p)
    assert kept == []                            # never over-report to a confirmed-only VDP program
    assert len(dropped) == 3


def test_filter_fails_open_when_not_confirmed_only():
    # A profile WITHOUT confirmed_only keeps unparseable items (fail-open) — the engine's own
    # scope/SSRF gates still apply; the policy only narrows, so a filter error must not lose a finding.
    open_profile = {"id": "x", "name": "X", "excluded_path_substrings": (), "always_rejected_rule_ids": (),
                    "confirmed_only": False}
    kept, dropped = vdp_policy.filter_findings([None, 42], open_profile)
    assert None in kept and 42 in kept and dropped == []


def test_no_profile_is_a_passthrough():
    items = [_item("a", "active.clickjacking", "candidate", "https://example.com/wp-json/wp/v2/users")]
    kept, dropped = vdp_policy.filter_findings(items, {})
    assert kept == items and dropped == []
