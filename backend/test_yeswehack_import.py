"""Tests for yeswehack_import (YesWeHack program scope / rules / marker read-only fetch).

All network is injected via ``fetch`` — never a real socket, matching
test_hackerone_import.py's pattern. The fixtures mirror real api.yeswehack.com response
shapes (captured from live public programs): ``scopes[].{scope,scope_type,
scope_type_name,asset_value}``, string ``out_of_scope``, ``reward_grid_*`` tiers, and the
per-program ``user_agent`` marker.
"""
from __future__ import annotations

import sys
import unittest
import urllib.error
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import yeswehack_import as ywh  # noqa: E402


def _http_error(code: int, reason: str = "error") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url="https://api.yeswehack.com/programs/x", code=code, msg=reason, hdrs=None, fp=None)


def _program(**overrides) -> dict:
    """A realistic /programs/{slug} body; override any field per test."""
    base = {
        "title": "Acme Bug Bounty",
        "slug": "acme-bug-bounty",
        "public": True,
        "vdp": False,
        "type": "bug-bounty",
        "status": "V",
        "disabled": False,
        "bounty": True,
        "gift": False,
        "hall_of_fame": True,
        "bounty_reward_min": 100,
        "bounty_reward_max": 5000,
        "reports_count": 381,
        "user_agent": "-ywh-bugbounty-acme",
        "vpn_active": False,
        "vpn_ips": None,
        "restricted_ips": None,
        "account_access": "Self-register at https://acme.example/signup",
        "rules": "## Rules\nBe nice. Rate-limit yourself.",
        "business_unit": {"name": "Acme Corp", "currency": "EUR"},
        "stats": {"max_reward": 5000, "average_reward": 500, "average_first_time_response": 2},
        "scopes": [
            {"scope": "*.acme.example", "scope_type": "web-application",
             "scope_type_name": "Web application", "asset_value": "HIGH"},
            {"scope": "203.0.113.0/24", "scope_type": "ip-address",
             "scope_type_name": "IP address", "asset_value": "LOW"},
        ],
        "out_of_scope": [
            "blog.acme.example",
            "Anything not listed under Scopes, especially customer production systems",
        ],
        "qualifying_vulnerability": ["RCE", "SQLi"],
        "non_qualifying_vulnerability": ["Self-XSS", "Missing security headers"],
        "reward_grid_default": {"bounty_low": 100, "bounty_medium": 500, "bounty_high": 2000, "bounty_critical": 5000},
        "reward_grid_high": {"bounty_low": 300, "bounty_medium": 1000, "bounty_high": 3000, "bounty_critical": 9000},
        "reward_grid_low": {"bounty_low": None, "bounty_medium": None, "bounty_high": None, "bounty_critical": None},
    }
    base.update(overrides)
    return base


class SlugTests(unittest.TestCase):
    def test_empty_slug_refused(self) -> None:
        r = ywh.fetch_program_scope("")
        self.assertFalse(r["ok"])
        self.assertIn("slug", r["error"].lower())

    def test_pasted_program_url_is_reduced_to_its_slug(self) -> None:
        seen: dict[str, str] = {}

        def fake(url, **kw):
            seen["url"] = url
            return _program()

        r = ywh.fetch_program_scope("https://yeswehack.com/programs/acme-bug-bounty", fetch=fake)
        self.assertTrue(r["ok"])
        self.assertEqual(r["slug"], "acme-bug-bounty")
        self.assertEqual(seen["url"], "https://api.yeswehack.com/programs/acme-bug-bounty")

    def test_trailing_slash_url_refused_rather_than_fetching_empty(self) -> None:
        r = ywh.fetch_program_scope("https://yeswehack.com/programs/")
        self.assertFalse(r["ok"])


class FetchSuccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = ywh.fetch_program_scope("acme-bug-bounty", fetch=lambda url, **kw: _program())

    def test_ok_and_identity(self) -> None:
        self.assertTrue(self.result["ok"])
        self.assertEqual(self.result["program_name"], "Acme Bug Bounty")
        # "handle" is an alias so a caller written against the HackerOne import works unchanged.
        self.assertEqual(self.result["handle"], self.result["slug"])

    def test_in_scope_entries_carry_type_value_and_bounty(self) -> None:
        ins = [e for e in self.result["structured_scope"] if e["eligible_for_submission"]]
        self.assertEqual([e["identifier"] for e in ins], ["*.acme.example", "203.0.113.0/24"])
        web, ip = ins
        self.assertEqual(web["asset_type"], "URL")
        self.assertEqual(web["max_severity"], "high")
        self.assertTrue(web["eligible_for_bounty"])
        self.assertIn("Web application", web["instruction"])
        # HIGH selects reward_grid_high (300..9000), not the default grid.
        self.assertIn("300–9000 EUR", web["instruction"])
        self.assertEqual(ip["asset_type"], "CIDR")

    def test_low_tier_with_an_all_null_grid_falls_back_to_the_default_grid(self) -> None:
        ins = [e for e in self.result["structured_scope"] if e["eligible_for_submission"]]
        self.assertIn("100–5000 EUR", ins[1]["instruction"])

    def test_scope_rows_have_no_invented_asset_id(self) -> None:
        # YesWeHack publishes no per-asset id, so nothing may be fabricated into it.
        self.assertTrue(all(e["id"] == "" for e in self.result["structured_scope"]))

    def test_marker_is_extracted_and_shaped_for_verbatim_append(self) -> None:
        self.assertEqual(self.result["user_agent_marker"], "-ywh-bugbounty-acme")
        self.assertEqual(self.result["user_agent_suffix"], " -ywh-bugbounty-acme")

    def test_program_stats_are_coerced_to_known_keys(self) -> None:
        stats = self.result["program_stats"]
        self.assertTrue(stats["offers_bounty"])
        self.assertEqual(stats["currency"], "EUR")
        self.assertEqual(stats["bounty_reward_max"], 5000)
        self.assertEqual(stats["business_unit"], "Acme Corp")
        self.assertEqual(stats["average_first_response_days"], 2)
        self.assertFalse(stats["vpn_required"])
        self.assertFalse(stats["ip_restricted"])

    def test_notes_digest_leads_with_the_binding_constraints(self) -> None:
        notes = self.result["notes_digest"]
        self.assertIn("REQUIRED user-agent marker", notes)
        self.assertIn("-ywh-bugbounty-acme", notes)
        self.assertIn("Self-register at https://acme.example/signup", notes)
        self.assertIn("Qualifying vulnerabilities", notes)
        self.assertIn("Self-XSS", notes)
        self.assertIn("Be nice.", notes)          # the rules text itself
        self.assertLessEqual(len(notes), 4000)    # portfolio.notes' bound

    def test_policy_excerpt_is_the_raw_rules_text(self) -> None:
        self.assertIn("Rate-limit yourself", self.result["policy_excerpt"])


class NotesDigestTruncationTests(unittest.TestCase):
    """The digest must never end mid-sentence without saying it was cut, and must never
    silently omit the rules section."""

    def _digest(self, **overrides) -> str:
        return ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(**overrides))["notes_digest"]

    def test_long_newline_free_rules_keep_their_truncation_marker(self) -> None:
        # The marker used to be appended AFTER the budget was spent, so the final clamp
        # chopped it off -- but only for rules with no newline in the clip window.
        digest = self._digest(rules="A" * 20000)
        self.assertLessEqual(len(digest), 4000)
        self.assertIn("(truncated", digest)

    def test_long_multiline_rules_keep_their_truncation_marker(self) -> None:
        digest = self._digest(rules="\n".join("line " + "B" * 80 for _ in range(400)))
        self.assertLessEqual(len(digest), 4000)
        self.assertIn("(truncated", digest)

    def test_short_rules_are_not_marked_as_truncated(self) -> None:
        digest = self._digest(rules="## Rules\nShort and complete.")
        self.assertIn("Short and complete.", digest)
        self.assertNotIn("(truncated", digest)

    def test_when_the_constraints_fill_the_digest_the_rules_omission_is_stated(self) -> None:
        # Otherwise the operator assumes Notes is the whole story.
        digest = self._digest(
            out_of_scope=["prose rule " + "x" * 180 for _ in range(21)],
            qualifying_vulnerability=["q" * 190 for _ in range(21)],
            rules="These rules never fit.",
        )
        self.assertLessEqual(len(digest), 4000)
        self.assertIn("the rules did not fit", digest)
        self.assertIn("## Program rules", digest)


class OutOfScopeSplitTests(unittest.TestCase):
    """Host-shaped exclusions become enforceable out-of-scope rows; prose stays readable
    instead of being pushed into the host matcher as a fake hostname."""

    def setUp(self) -> None:
        self.result = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program())

    def test_host_shaped_line_becomes_an_ineligible_scope_row(self) -> None:
        outs = [e for e in self.result["structured_scope"] if not e["eligible_for_submission"]]
        self.assertEqual([e["identifier"] for e in outs], ["blog.acme.example"])
        self.assertFalse(outs[0]["eligible_for_bounty"])

    def test_prose_line_is_kept_as_notes_not_as_a_host(self) -> None:
        self.assertEqual(self.result["out_of_scope"],
                         ["Anything not listed under Scopes, especially customer production systems"])
        idents = [e["identifier"] for e in self.result["structured_scope"]]
        self.assertNotIn("Anything not listed under Scopes, especially customer production systems", idents)

    def test_prose_exclusions_are_warned_about_not_dropped_silently(self) -> None:
        # They bind the operator but the host matcher cannot enforce them, so the fetch
        # result has to say so — otherwise the UI implies every exclusion was captured.
        joined = " ".join(self.result["warnings"])
        self.assertIn("prose, not host patterns", joined)
        self.assertIn("read them before hunting", joined)


class HostTokenNormalizationTests(unittest.TestCase):
    """The load-bearing one. Both scope matchers compare an exclusion token VERBATIM
    against a bare hostname (campaign._target_host_excluded, and the same check in
    active_verify_service), so a URL- or port-shaped exclusion stored as-is is INERT —
    the host stays huntable while the UI claims it was excluded."""

    def test_url_and_port_forms_reduce_to_the_bare_host(self) -> None:
        self.assertEqual(ywh._host_token("https://shop.acme.example/checkout"), "shop.acme.example")
        self.assertEqual(ywh._host_token("http://a.b.example"), "a.b.example")
        self.assertEqual(ywh._host_token("api.acme.example:8443"), "api.acme.example")
        self.assertEqual(ywh._host_token("acme.example/admin"), "acme.example")

    def test_annotated_lines_keep_their_host(self) -> None:
        self.assertEqual(ywh._host_token("staging.acme.example (do not test)"), "staging.acme.example")

    def test_plain_hosts_wildcards_and_ips_pass_through(self) -> None:
        self.assertEqual(ywh._host_token("acme.example"), "acme.example")
        self.assertEqual(ywh._host_token("*.acme.example"), "*.acme.example")
        self.assertEqual(ywh._host_token("203.0.113.4"), "203.0.113.4")
        # A CIDR is kept verbatim: the positive side can't put a CIDR host in scope
        # either, so nothing is exposed by it not matching, and it stays readable.
        self.assertEqual(ywh._host_token("203.0.113.0/24"), "203.0.113.0/24")

    def test_prose_yields_no_token(self) -> None:
        for prose in ("Anything not listed under Scopes", "All production systems", "",
                      "physical attacks", "Denial of service of any kind", "x" * 400):
            self.assertEqual(ywh._host_token(prose), "", prose)

    def test_the_normalized_token_actually_binds_in_the_real_scope_matcher(self) -> None:
        # The regression that matters: end-to-end through portfolio into the matcher the
        # hunt uses at target-selection time.
        from bughunter import campaign, portfolio

        program = _program(
            scopes=[{"scope": "*.acme.example", "scope_type": "web-application", "asset_value": "HIGH"}],
            out_of_scope=["https://shop.acme.example/checkout", "api.acme.example:8443",
                          "staging.acme.example (do not test)", "blocked.acme.example"],
        )
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: program)
        record = portfolio._normalize({"name": "Acme", "structured_scope": r["structured_scope"]})
        excluded = record["out_of_scope_hosts"]
        for host in ("shop.acme.example", "api.acme.example", "staging.acme.example", "blocked.acme.example"):
            self.assertTrue(campaign._target_host_excluded(host, excluded),
                            f"{host} must be excluded, got {excluded}")

    def test_non_web_assets_never_become_campaign_targets(self) -> None:
        # A YesWeHack Android asset is published as its STORE URL, so deriving a target
        # from it schedules a scan of play.google.com / apps.apple.com — third parties who
        # authorized nothing — and a bare package id resolves to an unrelated host.
        from bughunter import campaign, portfolio

        program = _program(scopes=[
            {"scope": "*.acme.example", "scope_type": "web-application", "asset_value": "HIGH"},
            {"scope": "https://play.google.com/store/apps/details?id=com.acme.app",
             "scope_type": "mobile-application-android", "asset_value": "MEDIUM"},
            {"scope": "https://apps.apple.com/fr/app/acme/id972602800",
             "scope_type": "mobile-application-ios", "asset_value": "MEDIUM"},
            {"scope": "com.acme.mobile", "scope_type": "mobile-application-android", "asset_value": "LOW"},
            {"scope": "acme-cli.exe", "scope_type": "executable", "asset_value": "LOW"},
        ], out_of_scope=[])
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: program)
        record = portfolio._normalize({"name": "Acme", "structured_scope": r["structured_scope"]})
        targets = campaign.program_campaign_targets(record)
        self.assertEqual(targets, ["https://acme.example"])
        joined = " ".join(targets)
        for third_party in ("play.google.com", "apps.apple.com", "com.acme.mobile"):
            self.assertNotIn(third_party, joined)

    def test_web_and_api_assets_still_become_targets(self) -> None:
        from bughunter import campaign, portfolio

        program = _program(scopes=[
            {"scope": "api.acme.example", "scope_type": "api", "asset_value": "HIGH"},
            {"scope": "https://app.acme.example/", "scope_type": "web-application", "asset_value": "HIGH"},
        ], out_of_scope=[])
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: program)
        record = portfolio._normalize({"name": "Acme", "structured_scope": r["structured_scope"]})
        self.assertEqual(sorted(campaign.program_campaign_targets(record)),
                         ["https://api.acme.example", "https://app.acme.example/"])

    def test_duplicate_exclusions_collapse(self) -> None:
        program = _program(out_of_scope=["https://a.acme.example/x", "a.acme.example", "a.acme.example:443"])
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: program)
        outs = [e["identifier"] for e in r["structured_scope"] if not e["eligible_for_submission"]]
        self.assertEqual(outs, ["a.acme.example"])


class MarkerShapeTests(unittest.TestCase):
    def test_leading_space_is_added_when_absent(self) -> None:
        # GreyIQ appends the suffix with NO separator, while YesWeHack's own tooling puts a
        # space before the marker — so one is added here.
        self.assertEqual(ywh._marker_suffix("CS_YWH/BB"), " CS_YWH/BB")

    def test_existing_leading_whitespace_is_preserved_verbatim(self) -> None:
        self.assertEqual(ywh._marker_suffix("  -tag "), "  -tag ")

    def test_empty_marker_yields_empty_suffix(self) -> None:
        self.assertEqual(ywh._marker_suffix(""), "")
        self.assertEqual(ywh._marker_suffix("   "), "")


class ConstraintWarningTests(unittest.TestCase):
    def test_vpn_ip_and_disabled_programs_warn_and_reach_the_notes(self) -> None:
        program = _program(vpn_active=True, vpn_ips=["198.51.100.7"],
                           restricted_ips=["203.0.113.9"], disabled=True,
                           disable_message="Paused for maintenance")
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: program)
        joined = " ".join(r["warnings"])
        self.assertIn("REQUIRES the YesWeHack VPN", joined)
        self.assertIn("restricts testing to specific source IPs", joined)
        self.assertIn("DISABLED", joined)
        self.assertTrue(r["program_stats"]["vpn_required"])
        self.assertTrue(r["program_stats"]["ip_restricted"])
        self.assertIn("198.51.100.7", r["notes_digest"])
        self.assertIn("Paused for maintenance", r["notes_digest"])

    def test_program_without_a_marker_says_so(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(user_agent=None))
        self.assertEqual(r["user_agent_suffix"], "")
        self.assertIn("publishes no user-agent marker", " ".join(r["warnings"]))

    def test_empty_scope_warns_and_points_at_sign_in(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(scopes=[], out_of_scope=[]))
        self.assertTrue(r["ok"])
        self.assertEqual(r["structured_scope"], [])
        self.assertIn("No scope entries", " ".join(r["warnings"]))

    def test_scope_entries_are_capped(self) -> None:
        many = [{"scope": f"h{i}.acme.example", "scope_type": "web-application", "asset_value": "LOW"}
                for i in range(20)]
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(scopes=many, out_of_scope=[]),
                                    max_entries=5)
        self.assertEqual(len(r["structured_scope"]), 5)
        self.assertIn("Capped at 5 scope entries", " ".join(r["warnings"]))

    def test_an_exactly_full_scope_list_is_not_reported_as_capped(self) -> None:
        # Nothing was dropped, so claiming a cap would be a fabricated warning.
        five = [{"scope": f"h{i}.acme.example", "scope_type": "web-application", "asset_value": "LOW"}
                for i in range(5)]
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(scopes=five, out_of_scope=[]),
                                    max_entries=5)
        self.assertEqual(len(r["structured_scope"]), 5)
        self.assertNotIn("Capped", " ".join(r["warnings"]))

    def test_the_cap_drops_in_scope_rows_before_exclusions(self) -> None:
        # The safe direction: losing an in-scope row costs an opportunity, losing an
        # exclusion would leave a forbidden host looking merely un-listed.
        many = [{"scope": f"h{i}.acme.example", "scope_type": "web-application", "asset_value": "LOW"}
                for i in range(20)]
        r = ywh.fetch_program_scope(
            "acme",
            fetch=lambda url, **kw: _program(scopes=many, out_of_scope=["blocked.acme.example", "also.acme.example"]),
            max_entries=3,
        )
        outs = [e["identifier"] for e in r["structured_scope"] if not e["eligible_for_submission"]]
        self.assertEqual(sorted(outs), ["also.acme.example", "blocked.acme.example"])
        self.assertEqual(len(r["structured_scope"]), 3)
        self.assertIn("in-scope entries did not fit", " ".join(r["warnings"]))

    def test_a_long_exclusion_list_is_read_past_the_display_limit(self) -> None:
        # _iter_strings' 200 default used to truncate out_of_scope BEFORE the entry budget
        # ran, so exclusion 201+ vanished with no warning and stayed huntable.
        oos = [f"h{i}.acme.example" for i in range(260)]
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(scopes=[], out_of_scope=oos))
        outs = [e["identifier"] for e in r["structured_scope"] if not e["eligible_for_submission"]]
        self.assertEqual(len(outs), 260)
        self.assertIn("h259.acme.example", outs)
        self.assertNotIn("were not read at all", " ".join(r["warnings"]))

    def test_exclusions_beyond_the_read_cap_are_reported_not_dropped_silently(self) -> None:
        oos = [f"h{i}.acme.example" for i in range(ywh._MAX_ENTRIES + 7)]
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(scopes=[], out_of_scope=oos))
        self.assertIn("7 out-of-scope line(s) past the first 500 were not read at all",
                      " ".join(r["warnings"]))

    def test_exclusions_that_themselves_overflow_are_reported(self) -> None:
        r = ywh.fetch_program_scope(
            "acme",
            fetch=lambda url, **kw: _program(scopes=[], out_of_scope=["a.acme.example", "b.acme.example"]),
            max_entries=1,
        )
        self.assertIn("Only the first 1 of 2 out-of-scope entries fit", " ".join(r["warnings"]))


class DegradeTests(unittest.TestCase):
    """Every failure path returns {"ok": False, "error": ...} — never raises."""

    def _raise(self, exc):
        def fake(url, **kw):
            raise exc
        return fake

    def test_401_names_the_expired_jwt_and_the_anonymous_fallback(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=self._raise(_http_error(401)))
        self.assertFalse(r["ok"])
        self.assertIn("401", r["error"])
        self.assertIn("anonymously", r["error"])

    def test_403_is_explained_as_a_private_program(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=self._raise(_http_error(403)))
        self.assertFalse(r["ok"])
        self.assertIn("private program", r["error"])

    def test_404_explains_where_the_slug_comes_from(self) -> None:
        r = ywh.fetch_program_scope("nope", fetch=self._raise(_http_error(404)))
        self.assertFalse(r["ok"])
        self.assertIn("yeswehack.com/programs/", r["error"])

    def test_network_failure_degrades(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=self._raise(urllib.error.URLError("dns")))
        self.assertFalse(r["ok"])
        self.assertIn("Could not reach YesWeHack", r["error"])

    def test_non_dict_response_shape_degrades_instead_of_raising(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: ["not", "a", "program"])
        self.assertFalse(r["ok"])
        self.assertIn("unexpected response", r["error"])

    def test_missing_optional_fields_do_not_raise(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: {"title": "Bare", "slug": "bare"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["structured_scope"], [])
        self.assertEqual(r["user_agent_suffix"], "")

    def test_business_unit_of_the_wrong_type_does_not_raise(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(business_unit="Acme"))
        self.assertTrue(r["ok"])
        self.assertEqual(r["program_stats"]["currency"], "")
        self.assertEqual(r["program_stats"]["business_unit"], "")

    def test_every_list_field_coming_back_non_iterable_does_not_raise(self) -> None:
        # A third-party response is not a contract. An escaped TypeError here would reach
        # the API's generic handler and become an opaque 500 instead of the documented
        # {"ok": False, "error": ...} the UI renders.
        for field in ("scopes", "out_of_scope", "qualifying_vulnerability",
                      "non_qualifying_vulnerability", "restricted_ips", "vpn_ips"):
            for bad in (7, "a string", {"k": "v"}, True):
                with self.subTest(field=field, bad=bad):
                    prog = _program(**{field: bad}, vpn_active=True)
                    r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: prog)
                    self.assertTrue(r["ok"])
                    self.assertIsInstance(r["structured_scope"], list)

    def test_list_and_verify_survive_a_non_iterable_items_field(self) -> None:
        page = {"pagination": {"nb_pages": 1, "nb_results": 0}, "items": 7}
        self.assertTrue(ywh.list_programs(fetch=lambda url, **kw: page)["ok"])
        self.assertTrue(ywh.verify_credentials("", fetch=lambda url, **kw: page)["ok"])

    def test_a_scope_row_that_is_not_a_dict_is_skipped(self) -> None:
        r = ywh.fetch_program_scope(
            "acme", fetch=lambda url, **kw: _program(scopes=["bare string", None, 7,
                                                            {"scope": "ok.acme.example"}], out_of_scope=[]))
        self.assertEqual([e["identifier"] for e in r["structured_scope"]], ["ok.acme.example"])


class BoundsTests(unittest.TestCase):
    """Nothing unbounded from a third-party API reaches the preview or the save. An
    oversized field must not 422 the whole program save."""

    def test_an_oversized_marker_is_capped_to_what_the_save_endpoint_accepts(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(user_agent="M" * 400))
        self.assertLessEqual(len(r["user_agent_suffix"]), 120)   # ProgramUpsertRequest's bound
        self.assertLessEqual(len(r["program_stats"]["user_agent_marker"]), 120)

    def test_an_oversized_title_is_capped(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(title="T" * 900))
        self.assertLessEqual(len(r["program_name"]), 200)        # ProgramUpsertRequest.name

    def test_oversized_scope_and_prose_fields_are_capped(self) -> None:
        prog = _program(scopes=[{"scope": "s" * 3000, "scope_type": "t" * 300,
                                 "scope_type_name": "n" * 300, "asset_value": "v" * 300}],
                        out_of_scope=["p" * 3000],
                        qualifying_vulnerability=["q" * 3000])
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: prog)
        row = r["structured_scope"][0]
        self.assertLessEqual(len(row["identifier"]), 500)
        self.assertLessEqual(len(row["asset_type"]), 60)
        self.assertLessEqual(len(row["max_severity"]), 20)
        self.assertLessEqual(len(row["instruction"]), 2000)
        self.assertLessEqual(len(r["out_of_scope"][0]), 500)
        self.assertLessEqual(len(r["qualifying_vulnerability"][0]), 300)
        self.assertLessEqual(len(r["policy_excerpt"]), 4000)

    def test_control_characters_never_survive_into_the_marker(self) -> None:
        r = ywh.fetch_program_scope("acme", fetch=lambda url, **kw: _program(user_agent="ywh-acme\r\nX-Injected: 1"))
        for value in (r["user_agent_marker"], r["user_agent_suffix"], r["program_stats"]["user_agent_marker"]):
            self.assertNotIn("\r", value)
            self.assertNotIn("\n", value)


class VerifyCredentialsTests(unittest.TestCase):
    def test_no_credential_reports_the_anonymous_path_as_working(self) -> None:
        page = {"pagination": {"nb_pages": 2, "nb_results": 58}, "items": []}
        r = ywh.verify_credentials("", fetch=lambda url, **kw: page)
        self.assertTrue(r["ok"])
        self.assertTrue(r["anonymous"])
        self.assertEqual(r["program_count"], 58)
        self.assertIn("anonymously", r["message"])

    def test_credential_accepted(self) -> None:
        page = {"pagination": {"nb_pages": 1, "nb_results": 3}, "items": []}
        r = ywh.verify_credentials("jwt-token", "jwt", fetch=lambda url, **kw: page)
        self.assertTrue(r["ok"])
        self.assertFalse(r["anonymous"])

    def test_401_suggests_signing_in_again(self) -> None:
        def fake(url, **kw):
            raise _http_error(401)
        r = ywh.verify_credentials("stale", "jwt", fetch=fake)
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], 401)
        self.assertIn("short-lived", r["error"])

    def test_unreachable_degrades(self) -> None:
        def fake(url, **kw):
            raise urllib.error.URLError("offline")
        r = ywh.verify_credentials("", fetch=fake)
        self.assertFalse(r["ok"])
        self.assertIn("Could not reach YesWeHack", r["error"])

    def test_non_401_http_errors_degrade_with_their_status(self) -> None:
        for code in (403, 404, 500):
            with self.subTest(code=code):
                def fake(url, _c=code, **kw):
                    raise _http_error(_c)
                r = ywh.verify_credentials("tok", "jwt", fetch=fake)
                self.assertFalse(r["ok"])
                self.assertEqual(r["status"], code)

    def test_an_off_host_url_guard_degrades_rather_than_raising(self) -> None:
        # _fetch_json raises ValueError rather than send a credential off-host; every
        # entry point must turn that into an {"ok": False} answer, not an exception.
        def fake(url, **kw):
            raise ValueError("refusing to send YesWeHack API credentials to a non-YesWeHack URL")

        self.assertFalse(ywh.verify_credentials("t", "jwt", fetch=fake)["ok"])
        self.assertFalse(ywh.list_programs(fetch=fake)["ok"])
        self.assertFalse(ywh.fetch_program_scope("acme", fetch=fake)["ok"])
        self.assertFalse(ywh.login("a@b.example", "pw", fetch=fake)["ok"])

    def test_login_totp_leg_off_host_guard_degrades(self) -> None:
        def fake(url, **kw):
            if url.endswith("/login"):
                return {"totp_token": "exchange"}
            raise ValueError("refusing to send YesWeHack API credentials to a non-YesWeHack URL")

        r = ywh.login("a@b.example", "pw", totp_code="123456", fetch=fake)
        self.assertFalse(r["ok"])
        self.assertIn("Could not reach YesWeHack", r["error"])


class ListProgramsTests(unittest.TestCase):
    @staticmethod
    def _paged(url, **kw):
        page = 2 if url.endswith("page=2") else 1
        return {
            "pagination": {"page": page, "nb_pages": 2, "nb_results": 4},
            "items": [
                {"slug": f"prog-{page}a", "title": f"Alpha {page}", "scopes_count": 3, "bounty": True,
                 "bounty_reward_max": 1000, "public": True, "type": "bug-bounty"},
                {"slug": f"prog-{page}b", "title": f"Beta {page}", "scopes_count": 1, "vdp": True},
            ],
        }

    def test_walks_every_page(self) -> None:
        r = ywh.list_programs(fetch=self._paged)
        self.assertTrue(r["ok"])
        self.assertEqual([p["slug"] for p in r["programs"]],
                         ["prog-1a", "prog-1b", "prog-2a", "prog-2b"])

    def test_query_filters_on_title_and_slug_case_insensitively(self) -> None:
        r = ywh.list_programs(query="BETA", fetch=self._paged)
        self.assertEqual([p["slug"] for p in r["programs"]], ["prog-1b", "prog-2b"])

    def test_rows_without_a_slug_are_dropped(self) -> None:
        page = {"pagination": {"nb_pages": 1}, "items": [{"title": "No slug"}, {"slug": "ok", "title": "OK"}]}
        r = ywh.list_programs(fetch=lambda url, **kw: page)
        self.assertEqual([p["slug"] for p in r["programs"]], ["ok"])

    def test_cap_is_enforced_and_warned(self) -> None:
        r = ywh.list_programs(fetch=self._paged, max_entries=3)
        self.assertEqual(len(r["programs"]), 3)
        self.assertIn("Capped to the first 3", " ".join(r["warnings"]))

    def test_http_error_with_no_rows_yet_is_an_error(self) -> None:
        def fake(url, **kw):
            raise _http_error(403)
        r = ywh.list_programs(fetch=fake)
        self.assertFalse(r["ok"])

    def test_hitting_the_page_cap_warns_instead_of_implying_a_definitive_no_match(self) -> None:
        # A truncated catalogue walk that returns nothing must not read as "this program
        # does not exist" in the wizard.
        def huge(url, **kw):
            return {"pagination": {"nb_pages": 100, "nb_results": 200},
                    "items": [{"slug": "other", "title": "Other"}]}

        r = ywh.list_programs(query="needle", fetch=huge)
        self.assertTrue(r["ok"])
        self.assertEqual(r["programs"], [])
        joined = " ".join(r["warnings"])
        self.assertIn(f"Stopped after {ywh._MAX_PAGES} of 100 pages", joined)
        self.assertIn("paste the program slug directly", joined)

    def test_a_complete_walk_adds_no_page_cap_warning(self) -> None:
        r = ywh.list_programs(fetch=self._paged)
        self.assertNotIn("Stopped after", " ".join(r["warnings"]))

    def test_odd_pagination_shapes_terminate_on_one_page(self) -> None:
        for pagination in ({"nb_pages": 0}, {"nb_pages": "x"}, {"nb_pages": None}, {}, None):
            with self.subTest(pagination=pagination):
                calls = {"n": 0}

                def fake(url, _p=pagination, **kw):
                    calls["n"] += 1
                    return {"pagination": _p, "items": [{"slug": "a", "title": "A"}]}

                r = ywh.list_programs(fetch=fake)
                self.assertTrue(r["ok"])
                self.assertEqual(calls["n"], 1)

    def test_pagination_urls_are_built_locally_on_the_pinned_host(self) -> None:
        # Never from a server-supplied link -- a hostile response cannot redirect the next
        # credentialed request off-host.
        seen: list[str] = []

        def fake(url, **kw):
            seen.append(url)
            return self._paged(url, **kw)

        ywh.list_programs(fetch=fake)
        self.assertEqual(seen, ["https://api.yeswehack.com/programs?page=1",
                                "https://api.yeswehack.com/programs?page=2"])


class LoginTests(unittest.TestCase):
    def test_missing_fields_refused_without_a_call(self) -> None:
        calls: list[str] = []

        def fake(url, **kw):
            calls.append(url)
            return {}

        self.assertFalse(ywh.login("", "pw", fetch=fake)["ok"])
        self.assertFalse(ywh.login("a@b.example", "", fetch=fake)["ok"])
        self.assertEqual(calls, [])

    def test_password_is_exchanged_for_a_jwt(self) -> None:
        seen: dict = {}

        def fake(url, **kw):
            seen["url"] = url
            seen["payload"] = kw.get("payload")
            return {"token": "jwt-abc"}

        r = ywh.login("a@b.example", "pw", fetch=fake)
        self.assertTrue(r["ok"])
        self.assertEqual(r["token"], "jwt-abc")
        self.assertEqual(r["token_kind"], "jwt")
        self.assertEqual(seen["url"], "https://api.yeswehack.com/login")
        self.assertEqual(seen["payload"], {"email": "a@b.example", "password": "pw"})

    def test_totp_required_does_not_leak_the_exchange_token(self) -> None:
        r = ywh.login("a@b.example", "pw", fetch=lambda url, **kw: {"totp_token": "exchange-secret"})
        self.assertFalse(r["ok"])
        self.assertTrue(r["totp_required"])
        self.assertNotIn("exchange-secret", repr(r))

    def test_totp_second_leg_returns_the_jwt(self) -> None:
        def fake(url, **kw):
            if url.endswith("/login"):
                return {"totp_token": "exchange"}
            self.assertTrue(url.endswith("/account/totp"))
            self.assertEqual(kw.get("payload"), {"token": "exchange", "code": "123456"})
            return {"token": "jwt-2fa"}

        r = ywh.login("a@b.example", "pw", totp_code="123456", fetch=fake)
        self.assertTrue(r["ok"])
        self.assertEqual(r["token"], "jwt-2fa")

    def test_rejected_totp_code_asks_again(self) -> None:
        def fake(url, **kw):
            if url.endswith("/login"):
                return {"totp_token": "exchange"}
            raise _http_error(401)

        r = ywh.login("a@b.example", "pw", totp_code="000000", fetch=fake)
        self.assertFalse(r["ok"])
        self.assertTrue(r["totp_required"])

    def test_bad_credentials(self) -> None:
        def fake(url, **kw):
            raise _http_error(401)

        r = ywh.login("a@b.example", "pw", fetch=fake)
        self.assertFalse(r["ok"])
        self.assertIn("rejected that email/password", r["error"])

    def test_unexpected_shape_degrades(self) -> None:
        r = ywh.login("a@b.example", "pw", fetch=lambda url, **kw: {"unexpected": True})
        self.assertFalse(r["ok"])
        self.assertIn("did not return a session token", r["error"])


class AuthHeaderAndHostPinningTests(unittest.TestCase):
    def test_is_yeswehack_url(self) -> None:
        self.assertTrue(ywh._is_yeswehack_url("https://api.yeswehack.com/programs/x"))
        self.assertFalse(ywh._is_yeswehack_url("http://api.yeswehack.com/programs/x"))   # plaintext
        self.assertFalse(ywh._is_yeswehack_url("https://api.yeswehack.com.evil.test/x"))  # suffix trick
        self.assertFalse(ywh._is_yeswehack_url("https://yeswehack.com/programs/x"))       # not the API host
        self.assertFalse(ywh._is_yeswehack_url("https://evil.test/programs/x"))

    def test_fetch_refuses_to_send_a_credential_off_host(self) -> None:
        with self.assertRaises(ValueError):
            ywh._fetch_json("https://evil.test/programs/x", token="secret", timeout=1.0)

    def test_anonymous_sends_no_auth_header(self) -> None:
        self.assertEqual(ywh._auth_headers("", "jwt"), {})
        self.assertEqual(ywh._auth_headers("   ", "pat"), {})

    def test_jwt_uses_bearer_and_pat_uses_x_auth_token(self) -> None:
        self.assertEqual(ywh._auth_headers("t", "jwt"), {"Authorization": "Bearer t"})
        self.assertEqual(ywh._auth_headers("t", ""), {"Authorization": "Bearer t"})
        self.assertEqual(ywh._auth_headers("t", "PAT"), {"X-AUTH-TOKEN": "t"})


class FetchJsonRetryTests(unittest.TestCase):
    """_fetch_json() (the real, non-injected network call) retries a connection-level
    failure and a transient/rate-limit HTTP status (429/5xx), but never a deterministic
    401/403/404 -- and every retry reuses the SAME already-host-pinned request."""

    URL = "https://api.yeswehack.com/programs/x"

    def setUp(self) -> None:
        self._orig_open = ywh._OPENER.open

    def tearDown(self) -> None:
        ywh._OPENER.open = self._orig_open

    class _FakeResponse:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self, n: int) -> bytes:
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_connection_error_is_retried_and_succeeds(self) -> None:
        calls = {"n": 0}

        def fake_open(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.URLError("simulated connection reset")
            return self._FakeResponse(b'{"ok": true}')

        ywh._OPENER.open = fake_open
        self.assertEqual(ywh._fetch_json(self.URL, timeout=5.0), {"ok": True})
        self.assertEqual(calls["n"], 2)

    def test_503_is_retried_and_succeeds(self) -> None:
        calls = {"n": 0}

        def fake_open(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(503)
            return self._FakeResponse(b'{"ok": true}')

        ywh._OPENER.open = fake_open
        self.assertEqual(ywh._fetch_json(self.URL, timeout=5.0), {"ok": True})
        self.assertEqual(calls["n"], 2)

    def test_401_and_404_are_never_retried(self) -> None:
        for code in (401, 403, 404):
            calls = {"n": 0}

            def fake_open(req, timeout=None, _code=code):
                calls["n"] += 1
                raise _http_error(_code)

            ywh._OPENER.open = fake_open
            with self.assertRaises(urllib.error.HTTPError):
                ywh._fetch_json(self.URL, timeout=5.0)
            self.assertEqual(calls["n"], 1, code)

    def test_post_sets_a_json_body_and_content_type(self) -> None:
        seen: dict = {}

        def fake_open(req, timeout=None):
            seen["method"] = req.get_method()
            seen["body"] = req.data
            seen["ctype"] = req.get_header("Content-type")
            seen["auth"] = req.get_header("Authorization")
            return self._FakeResponse(b'{"token": "x"}')

        ywh._OPENER.open = fake_open
        ywh._fetch_json(self.URL, timeout=5.0, method="POST", payload={"email": "a@b.example"})
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["body"], b'{"email": "a@b.example"}')
        self.assertEqual(seen["ctype"], "application/json")
        self.assertIsNone(seen["auth"])  # anonymous: no credential attached

    def test_no_redirect_handler_never_follows(self) -> None:
        handler = ywh._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://evil.test/"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
