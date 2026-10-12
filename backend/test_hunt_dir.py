"""Resolving a DIRECTORY into a hunt plan (`gn auto`).

The three properties these tests exist to hold, in order of how much damage getting them
wrong does:

  1. **Authorization never comes from the directory.** A file on disk cannot assert that a
     human is authorized to test a target. If a hunt file tries, the key is stripped AND
     reported — silently ignoring it is worse, because the operator who wrote it believed
     it worked.
  2. **No scope means active probing stays off, and the plan says why.** An empty scope
     makes `host_in_active_scope` refuse every host, so `--active` becomes a no-op that
     sends zero probes and looks like a clean hunt. `portfolio._normalize` already couples
     these fail-closed; the plan must surface the reason rather than quietly downgrade.
  3. **Fail-soft.** A malformed hunt file, an unreadable directory, a bare public suffix —
     each degrades to refusals in the plan, never an exception, because this runs before a
     hunt the operator is waiting on.
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

from bughunter import hunt_dir  # noqa: E402


class _Dir(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, rel: str, body: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path


class AuthorizationTests(_Dir):
    def test_a_hunt_file_cannot_grant_authorization(self) -> None:
        for key in ("authorized", "authorize", "consent", "yes"):
            with self.subTest(key=key):
                self.write(".greyiq/hunt.json", json.dumps(
                    {key: True, "scope": "example.com", "targets": ["https://app.example.com"]}))
                plan = hunt_dir.resolve(self.root)
                self.assertTrue(plan.ok)
                self.assertTrue(
                    any(key in r and "ignored" in r for r in plan.refusals),
                    f"{key} must be refused OUT LOUD, not silently dropped",
                )

    def test_the_plan_carries_no_authorization_field_at_all(self) -> None:
        """There is nowhere for a directory to put consent, by construction."""
        self.write(".greyiq/targets.txt", "https://app.example.com\n")
        plan = hunt_dir.resolve(self.root)
        for banned in ("authorized", "authorize", "consent"):
            self.assertFalse(hasattr(plan, banned))


class ScopeTests(_Dir):
    def test_explicit_scope_file_wins(self) -> None:
        self.write(".greyiq/targets.txt", "https://app.example.com\n")
        self.write(".greyiq/scope.txt", "example.com\n*.example.com\n")
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(plan.scope_source, ".greyiq/scope.txt")
        self.assertIn("*.example.com", plan.scope_text)

    def test_scope_derived_from_targets_is_reported_as_derived(self) -> None:
        self.write(".greyiq/targets.txt", "https://app.example.com\nhttps://api.example.com\n")
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(plan.scope_text, "example.com")
        self.assertEqual(plan.scope_source, "derived from targets")
        self.assertTrue(any("DERIVED" in n for n in plan.notes))

    def test_an_ip_target_scopes_to_the_exact_address(self) -> None:
        """registrable_domain would fold 127.0.0.1 to '0.1' and authorize every x.x.0.1."""
        self.write(".greyiq/targets.txt", "http://127.0.0.1:8000/\n")
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(plan.scope_text, "127.0.0.1")

    def test_a_bare_public_suffix_is_refused_as_scope(self) -> None:
        """A target that IS the shared suffix yields no scope token at all — scoping to
        'herokuapp.com' would authorize every unrelated tenant on that platform."""
        self.write(".greyiq/targets.txt", "https://herokuapp.com\n")
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(plan.scope_text, "")
        self.assertFalse(plan.active, "no scope must mean no active probing")
        self.assertTrue(any("public suffix" in n for n in plan.notes))

    def test_no_scope_refuses_active_and_says_why(self) -> None:
        self.write(".greyiq/hunt.json", json.dumps(
            {"targets": ["https://herokuapp.com"], "active": True, "scope": ""}))
        plan = hunt_dir.resolve(self.root)
        self.assertFalse(plan.active)
        self.assertFalse(plan.iterate)
        self.assertTrue(any("sends zero probes" in r for r in plan.refusals))


class TargetResolutionTests(_Dir):
    def test_hunt_json_beats_targets_txt(self) -> None:
        self.write(".greyiq/hunt.json", json.dumps(
            {"scope": "example.com", "targets": ["https://from-json.example.com"]}))
        self.write(".greyiq/targets.txt", "https://from-txt.example.com\n")
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(plan.targets, ["https://from-json.example.com"])
        self.assertEqual(plan.source, ".greyiq/hunt.json")

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        self.write(".greyiq/targets.txt",
                   "# the engagement\n\nhttps://a.example.com  # inline\n\nhttps://b.example.com\n")
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(plan.targets, ["https://a.example.com", "https://b.example.com"])

    def test_duplicates_collapse(self) -> None:
        self.write(".greyiq/targets.txt", "https://a.example.com\nhttps://a.example.com\n")
        self.assertEqual(hunt_dir.resolve(self.root).targets, ["https://a.example.com"])

    def test_target_count_is_capped(self) -> None:
        """This feeds a real active prober, never an unbounded fan-out."""
        self.write(".greyiq/targets.txt",
                   "\n".join(f"https://h{i}.example.com" for i in range(60)))
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(len(plan.targets), hunt_dir._MAX_TARGETS)
        self.assertTrue(any("capped" in r for r in plan.refusals))

    def test_a_git_repo_with_no_targets_hunts_itself(self) -> None:
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_text(
            '[remote "origin"]\n\turl = https://github.com/example/widget.git\n', encoding="utf-8")
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(plan.source, "git repository")
        self.assertEqual(plan.targets, [str(self.root)])
        self.assertEqual(plan.repository_urls, ["https://github.com/example/widget.git"])
        # portfolio's own precedent: a source repository IS the saved scope.
        self.assertEqual(plan.scope_source, "git remote")

    def test_a_listed_target_beats_the_repo_heuristic(self) -> None:
        (self.root / ".git").mkdir()
        self.write(".greyiq/targets.txt", "https://app.example.com\n")
        plan = hunt_dir.resolve(self.root)
        self.assertEqual(plan.targets, ["https://app.example.com"])


class FailSoftTests(_Dir):
    def test_empty_directory_is_refused_with_an_actionable_message(self) -> None:
        plan = hunt_dir.resolve(self.root)
        self.assertFalse(plan.ok)
        self.assertTrue(any("targets.txt" in r for r in plan.refusals))

    def test_malformed_hunt_json_does_not_raise(self) -> None:
        self.write(".greyiq/hunt.json", "{not json")
        self.write(".greyiq/targets.txt", "https://app.example.com\n")
        plan = hunt_dir.resolve(self.root)
        self.assertTrue(plan.ok, "a broken hunt file must not block a valid targets file")
        self.assertTrue(any("not valid JSON" in r for r in plan.refusals))

    def test_hunt_json_that_is_not_an_object(self) -> None:
        self.write(".greyiq/hunt.json", "[1,2,3]")
        plan = hunt_dir.resolve(self.root)
        self.assertFalse(plan.ok)
        self.assertTrue(any("not a JSON object" in r for r in plan.refusals))

    def test_missing_and_junk_paths_never_raise(self) -> None:
        for value in ("", "   ", str(self.root / "nope"), "\x00bad"):
            with self.subTest(value=value[:12]):
                plan = hunt_dir.resolve(value)
                self.assertFalse(plan.ok)
                self.assertTrue(plan.refusals)

    def test_a_file_is_not_a_hunt_directory(self) -> None:
        path = self.write("a.txt", "x")
        self.assertFalse(hunt_dir.resolve(path).ok)


class PortfolioHandoffTests(_Dir):
    def test_a_plan_survives_portfolio_normalization_intact(self) -> None:
        """The plan is only useful if the program it produces keeps its posture."""
        from bughunter import portfolio

        self.write(".greyiq/hunt.json", json.dumps(
            {"program": "acme", "scope": "example.com",
             "targets": ["https://app.example.com"], "active": True, "iterate": True}))
        plan = hunt_dir.resolve(self.root)
        program = portfolio._normalize({
            "id": "acme", "name": plan.name, "scope_text": plan.scope_text,
            "seed_targets": plan.targets, "active": plan.active, "iterate": plan.iterate,
        })
        self.assertTrue(program["active"])
        self.assertTrue(program["iterate"])
        self.assertEqual(program["seed_targets"], ["https://app.example.com"])

    def test_a_scopeless_plan_is_forced_passive_on_both_sides(self) -> None:
        from bughunter import portfolio

        self.write(".greyiq/targets.txt", "https://herokuapp.com\n")
        plan = hunt_dir.resolve(self.root)
        self.assertFalse(plan.active)
        program = portfolio._normalize({
            "id": "x", "name": "x", "scope_text": plan.scope_text,
            "seed_targets": plan.targets, "active": True, "iterate": True,
        })
        self.assertFalse(program["active"], "portfolio must refuse it too")
        self.assertFalse(program["iterate"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
