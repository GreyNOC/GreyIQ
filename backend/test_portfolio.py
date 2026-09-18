"""Tests for portfolio.py — the program store, focused on the new structured_scope /
oob_allowed / notes fields: backward compatibility with pre-existing records, the
structured_scope -> scope_text/in_scope_hosts derivation, and that the fail-closed
empty-scope coupling still holds through the new code path.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import portfolio as pf  # noqa: E402


class TempRuntimeMixin:
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.runtime_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()


class BackwardCompatTests(TempRuntimeMixin, unittest.TestCase):
    def test_pre_existing_record_without_new_fields_still_loads(self) -> None:
        # Simulate an old portfolio.json written before structured_scope/oob_allowed/notes
        # existed -- write the store file directly, bypassing upsert_program.
        store = self.runtime_dir / "portfolio.json"
        store.write_text(json.dumps({"programs": {"acme": {
            "id": "acme", "name": "Acme", "scope_text": "acme.com", "active": True,
        }}}), encoding="utf-8")
        programs = pf.list_programs(self.runtime_dir)
        self.assertEqual(len(programs), 1)
        self.assertEqual(programs[0]["structured_scope"], [])
        self.assertFalse(programs[0]["oob_allowed"])
        self.assertFalse(programs[0]["disclose_automation"])
        self.assertEqual(programs[0]["h1_program_stats"], {})
        self.assertEqual(programs[0]["notes"], "")
        self.assertEqual(programs[0]["repository_urls"], [])
        self.assertFalse(programs[0]["clone_repositories"])
        self.assertTrue(programs[0]["active"])   # untouched by the new derivation path

    def test_upsert_without_new_fields_unchanged_behavior(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {"name": "Beta", "scope_text": "beta.com", "active": True})
        self.assertTrue(prog["active"])
        self.assertEqual(prog["structured_scope"], [])


class StructuredScopeDerivationTests(TempRuntimeMixin, unittest.TestCase):
    def test_repository_clone_opt_in_extracts_supported_structured_scope_links(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Source Program",
            "clone_repositories": True,
            "structured_scope": [
                {"identifier": "https://github.com/acme/widget", "eligible_for_submission": True},
                {"identifier": "https://github.com/acme/widget/issues/1", "eligible_for_submission": True},
            ],
        })
        self.assertEqual(prog["repository_urls"], ["https://github.com/acme/widget"])
        self.assertIn("https://github.com/acme/widget", prog["scope_text"])

    def test_repository_urls_are_bounded_deduped_and_root_validated(self) -> None:
        urls = ["https://github.com/acme/widget", "https://github.com/acme/widget/"]
        urls += ["https://github.com/acme/widget/blob/main/app.py", "https://evil.example/acme/widget"]
        urls += [f"https://github.com/acme/repo-{i}" for i in range(pf._MAX_REPOSITORIES + 5)]
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Source Program", "clone_repositories": True, "repository_urls": urls,
        })
        self.assertEqual(prog["repository_urls"][0], "https://github.com/acme/widget")
        self.assertEqual(len(prog["repository_urls"]), pf._MAX_REPOSITORIES)
        self.assertNotIn("https://github.com/acme/widget/blob/main/app.py", prog["repository_urls"])

    def test_derives_scope_text_and_hosts_when_scope_text_empty(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme",
            "structured_scope": [
                {"identifier": "*.acme.com", "eligible_for_submission": True},
                {"identifier": "legacy.acme.com", "eligible_for_submission": False},
            ],
        })
        self.assertIn("*.acme.com", prog["scope_text"])
        self.assertEqual(prog["in_scope_hosts"], ["*.acme.com"])
        self.assertEqual(prog["out_of_scope_hosts"], ["legacy.acme.com"])

    def test_hand_typed_scope_text_never_overridden(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme",
            "scope_text": "hand-typed.acme.com",
            "structured_scope": [{"identifier": "*.acme.com", "eligible_for_submission": True}],
        })
        self.assertEqual(prog["scope_text"], "hand-typed.acme.com")

    def test_entries_without_identifier_are_dropped(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "structured_scope": [{"asset_type": "URL"}, {"identifier": "ok.acme.com"}],
        })
        self.assertEqual(len(prog["structured_scope"]), 1)
        self.assertEqual(prog["structured_scope"][0]["identifier"], "ok.acme.com")

    def test_non_dict_entries_ignored(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {"name": "Acme", "structured_scope": ["not-a-dict", 5, None]})
        self.assertEqual(prog["structured_scope"], [])

    def test_capped_at_max_scope_entries(self) -> None:
        entries = [{"identifier": f"h{i}.acme.com"} for i in range(pf._MAX_SCOPE_ENTRIES + 20)]
        prog = pf.upsert_program(self.runtime_dir, {"name": "Acme", "structured_scope": entries})
        self.assertEqual(len(prog["structured_scope"]), pf._MAX_SCOPE_ENTRIES)


class EditPathDerivationTests(TempRuntimeMixin, unittest.TestCase):
    """Editing an existing program's structured_scope must not leave a stale, previously-
    derived scope_text/in_scope_hosts/out_of_scope_hosts behind -- a real bug caught by
    live adversarial review: the Program-setup UI has no scope_text field of its own, so
    the ONLY way it ever gets a fresh derivation on a second save is resync_scope."""

    def test_without_resync_scope_a_changed_structured_scope_is_silently_stale(self) -> None:
        # Documents the OLD/default behavior other callers (e.g. a hand-typed-scope editor)
        # rely on: once scope_text is non-empty, structured_scope changes don't touch it.
        first = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "structured_scope": [{"identifier": "a.acme.com", "eligible_for_submission": True}],
        })
        self.assertEqual(first["scope_text"], "a.acme.com")
        second = pf.upsert_program(self.runtime_dir, {
            "id": first["id"], "name": "Acme",
            "structured_scope": [{"identifier": "b.acme.com", "eligible_for_submission": True}],
        })
        self.assertEqual(second["scope_text"], "a.acme.com")   # stale -- b.acme.com never enters scope
        self.assertEqual(second["in_scope_hosts"], ["a.acme.com"])

    def test_resync_scope_re_derives_from_the_new_structured_scope(self) -> None:
        first = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "structured_scope": [{"identifier": "a.acme.com", "eligible_for_submission": True}],
        })
        second = pf.upsert_program(self.runtime_dir, {
            "id": first["id"], "name": "Acme", "resync_scope": True,
            "structured_scope": [{"identifier": "b.acme.com", "eligible_for_submission": True}],
        })
        self.assertEqual(second["scope_text"], "b.acme.com")
        self.assertEqual(second["in_scope_hosts"], ["b.acme.com"])

    def test_resync_scope_can_shrink_scope_to_empty_and_forces_active_off(self) -> None:
        first = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "active": True,
            "structured_scope": [{"identifier": "a.acme.com", "eligible_for_submission": True}],
        })
        self.assertTrue(first["active"])
        second = pf.upsert_program(self.runtime_dir, {
            "id": first["id"], "name": "Acme", "resync_scope": True, "active": True,
            "structured_scope": [{"identifier": "a.acme.com", "eligible_for_submission": False}],
        })
        self.assertEqual(second["scope_text"], "")
        self.assertFalse(second["active"])   # fail-closed coupling still holds on the edit path

    def test_resync_scope_is_a_no_op_when_structured_scope_is_empty(self) -> None:
        # Must never use resync_scope to accidentally blank out a scope set some OTHER way
        # (e.g. hand-typed via the Operator tab) just because this save's structured_scope
        # happens to be empty.
        first = pf.upsert_program(self.runtime_dir, {"name": "Acme", "scope_text": "hand-typed.acme.com"})
        second = pf.upsert_program(self.runtime_dir, {"id": first["id"], "name": "Acme", "resync_scope": True})
        self.assertEqual(second["scope_text"], "hand-typed.acme.com")

    def test_resync_can_replace_and_remove_auto_derived_repository_scope(self) -> None:
        first = pf.upsert_program(self.runtime_dir, {
            "name": "Source", "clone_repositories": True,
            "repository_urls": ["https://github.com/acme/one"], "resync_scope": True,
        })
        second = pf.upsert_program(self.runtime_dir, {
            "id": first["id"], "name": "Source", "clone_repositories": True,
            "repository_urls": ["https://github.com/acme/two"], "resync_scope": True,
        })
        self.assertEqual(second["scope_text"], "https://github.com/acme/two")
        third = pf.upsert_program(self.runtime_dir, {
            "id": first["id"], "name": "Source", "clone_repositories": False,
            "repository_urls": [], "resync_scope": True,
        })
        self.assertEqual(third["scope_text"], "")

    def test_repository_resync_preserves_a_hand_typed_scope(self) -> None:
        first = pf.upsert_program(self.runtime_dir, {
            "name": "Mixed", "scope_text": "app.acme.test",
            "clone_repositories": True, "repository_urls": ["https://github.com/acme/one"],
        })
        second = pf.upsert_program(self.runtime_dir, {
            "id": first["id"], "name": "Mixed", "clone_repositories": False,
            "repository_urls": [], "resync_scope": True,
        })
        self.assertEqual(second["scope_text"], "app.acme.test")

    def test_omitted_fields_preserve_existing_value_not_reset_to_default(self) -> None:
        # Mirrors what greyiq_api.RuntimeApi.upsert_program's exclude_unset now guarantees:
        # a caller that doesn't send a key at all must never look like it explicitly reset
        # that field to its bare default. (Here we call upsert_program directly with a
        # record dict that simply omits the keys, same effect as exclude_unset producing one.)
        first = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "oob_allowed": True, "disclose_automation": True, "notes": "policy allows OOB",
            "structured_scope": [{"identifier": "a.acme.com"}],
        })
        # Simulate an edit from a caller that only knows about a subset of fields (like the
        # Operator tab's compact form) -- it never mentions structured_scope/oob_allowed/
        # disclose_automation/notes.
        second = pf.upsert_program(self.runtime_dir, {"id": first["id"], "name": "Acme", "interval_minutes": 60})
        self.assertTrue(second["oob_allowed"])
        self.assertTrue(second["disclose_automation"])
        self.assertEqual(second["notes"], "policy allows OOB")
        self.assertEqual(len(second["structured_scope"]), 1)
        self.assertEqual(second["interval_minutes"], 60)


class FailClosedCouplingStillHoldsTests(TempRuntimeMixin, unittest.TestCase):
    def test_all_out_of_scope_structured_entries_cannot_go_active(self) -> None:
        # Every entry is eligible_for_submission=False -> derived scope_text is "" ->
        # the existing fail-closed coupling must still force active/live/deep/auto_submit off.
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "active": True, "deep": True,
            "structured_scope": [{"identifier": "out.acme.com", "eligible_for_submission": False}],
        })
        self.assertEqual(prog["scope_text"], "")
        self.assertFalse(prog["active"])
        self.assertFalse(prog["deep"])

    def test_oob_allowed_and_notes_round_trip(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "scope_text": "acme.com", "oob_allowed": True,
            "disclose_automation": True, "notes": "Policy allows OOB.",
        })
        self.assertTrue(prog["oob_allowed"])
        self.assertTrue(prog["disclose_automation"])
        self.assertEqual(prog["notes"], "Policy allows OOB.")
        reloaded = pf.get_program(self.runtime_dir, prog["id"])
        self.assertTrue(reloaded["oob_allowed"])
        self.assertTrue(reloaded["disclose_automation"])

    def test_h1_program_stats_round_trip_and_unknown_keys_dropped(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "scope_text": "acme.com",
            "h1_program_stats": {
                "offers_bounties": True, "fast_payments": True, "currency": "usd",
                "number_of_valid_reports_for_user": 2, "bounty_earned_for_user": "1500.5",
                "totally_unexpected_field": "should be dropped",
            },
        })
        stats = prog["h1_program_stats"]
        self.assertTrue(stats["offers_bounties"])
        self.assertTrue(stats["fast_payments"])
        self.assertEqual(stats["currency"], "usd")
        self.assertEqual(stats["number_of_valid_reports_for_user"], 2)
        self.assertEqual(stats["bounty_earned_for_user"], 1500.5)
        self.assertNotIn("totally_unexpected_field", stats)
        reloaded = pf.get_program(self.runtime_dir, prog["id"])
        self.assertEqual(reloaded["h1_program_stats"]["currency"], "usd")

    def test_h1_program_stats_non_dict_is_ignored(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {"name": "Acme", "h1_program_stats": "not-a-dict"})
        self.assertEqual(prog["h1_program_stats"], {})

    def test_ywh_program_stats_round_trip_and_unknown_keys_dropped(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "scope_text": "acme.com",
            "ywh_program_stats": {
                "public": True, "vpn_required": True, "offers_bounty": 1,
                "currency": "EUR", "business_unit": "Acme Corp",
                "user_agent_marker": "-ywh-bugbounty-acme",
                "bounty_reward_max": "7000", "reports_count": 12,
                "totally_unexpected_field": "should be dropped",
            },
        })
        stats = prog["ywh_program_stats"]
        self.assertTrue(stats["public"])
        self.assertTrue(stats["vpn_required"])
        self.assertTrue(stats["offers_bounty"])          # coerced to bool
        self.assertEqual(stats["currency"], "EUR")
        self.assertEqual(stats["business_unit"], "Acme Corp")
        self.assertEqual(stats["user_agent_marker"], "-ywh-bugbounty-acme")
        self.assertEqual(stats["bounty_reward_max"], 7000)   # coerced to int
        self.assertNotIn("totally_unexpected_field", stats)
        reloaded = pf.get_program(self.runtime_dir, prog["id"])
        self.assertEqual(reloaded["ywh_program_stats"]["currency"], "EUR")

    def test_ywh_program_stats_non_dict_is_ignored(self) -> None:
        prog = pf.upsert_program(self.runtime_dir, {"name": "Acme", "ywh_program_stats": "not-a-dict"})
        self.assertEqual(prog["ywh_program_stats"], {})

    def test_ywh_marker_copy_is_sanitized_like_the_ua_suffix(self) -> None:
        # user_agent_marker is a COPY of the value that drives the outbound User-Agent, so
        # a CR/LF from a compromised API response must not be persisted here either.
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme",
            "ywh_program_stats": {"user_agent_marker": "-ywh-acme\r\nX-Injected: 1"},
        })
        marker = prog["ywh_program_stats"]["user_agent_marker"]
        self.assertNotIn("\r", marker)
        self.assertNotIn("\n", marker)

    def test_ywh_marker_keeps_the_leading_space_the_importer_adds(self) -> None:
        # The suffix is appended VERBATIM with no separator, so the space is load-bearing.
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "user_agent_suffix": " -ywh-bugbounty-acme",
        })
        self.assertEqual(prog["user_agent_suffix"], " -ywh-bugbounty-acme")

    def test_oob_allowed_is_not_coupled_to_the_scope_fail_closed_gate(self) -> None:
        # oob_allowed is a policy-confirmation flag surfaced in the UI (a confirm-dialog
        # skip before jumping to the OOB panel), NOT a scope/authorization gate itself --
        # actual OOB egress is independently scope-checked by oob_service's own
        # host_in_active_scope call, regardless of this flag. Documented here (rather than
        # forced off) so a future reader doesn't assume it needs the same coupling as
        # active/live/deep/auto_submit.
        prog = pf.upsert_program(self.runtime_dir, {
            "name": "Acme", "oob_allowed": True,
            "structured_scope": [{"identifier": "out.acme.com", "eligible_for_submission": False}],
        })
        self.assertEqual(prog["scope_text"], "")
        self.assertTrue(prog["oob_allowed"])


if __name__ == "__main__":
    unittest.main()
