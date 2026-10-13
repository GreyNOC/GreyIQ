"""The operator profile decides what a hunt does when the command line does not. So:

  * **It cannot authorize anything.** There is no ``authorize`` setting, ``set`` refuses every key
    it does not know, and a profile file that carries one has no effect. A file on disk may not
    assert that a human is authorized to test a target — the same rule ``hunt_dir`` states, in the
    one other place a config could have tried to.
  * **A broken profile cannot stop a hunt.** Missing, unreadable, not JSON, not an object, holding
    the wrong types: every one of those is the defaults plus a sentence, never an exception.
  * **It knows what it chose.** ``chosen``/``source`` separate "the operator picked tinygpt" from
    "nobody has said", because the first run depends on that difference and ``gn settings`` prints
    it.
  * **It fills only the unset half.** A flag the operator typed always wins, and nothing in here
    can turn an armed flag off.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_profile  # noqa: E402


class DefaultsTests(unittest.TestCase):
    def test_the_defaults_are_the_local_first_ones(self) -> None:
        values = gn_profile.defaults()
        self.assertEqual(values["bot"], "tinygpt", "the built-in local model, no key, nothing sent")
        self.assertIs(values["learning"], True)
        self.assertIs(values["hunt.active"], False, "live probing is never a default")
        self.assertIs(values["hunt.prompt"], True)
        self.assertEqual(values["hunt.profile"], "full-sweep")
        self.assertEqual(values["output.dir"], "")

    def test_no_setting_can_assert_authorization(self) -> None:
        for forbidden in ("authorize", "authorized", "always_authorize", "hunt.authorize", "-y"):
            with self.subTest(key=forbidden):
                self.assertIsNone(gn_profile.setting(forbidden))
        for item in gn_profile.SETTINGS:
            self.assertNotIn("authoriz", item.key.lower(),
                             "a file on disk cannot assert that a human is authorized")

    def test_every_setting_says_what_it_does(self) -> None:
        for item in gn_profile.SETTINGS:
            with self.subTest(key=item.key):
                self.assertTrue(item.help.strip())
                self.assertIn(item.kind, ("bool", "str", "path", "choice"))
                if item.kind == "choice":
                    self.assertIn(item.default, item.choices)


class LoadTests(unittest.TestCase):
    def test_no_profile_is_the_defaults_and_says_so(self) -> None:
        with TemporaryDirectory() as tmp:
            profile = gn_profile.load(tmp)
        self.assertFalse(profile.exists)
        self.assertEqual(profile.get("bot"), "tinygpt")
        self.assertFalse(profile.chosen("bot"))
        self.assertEqual(profile.source("bot"), "default")
        self.assertIn("gn setup", gn_profile.first_run_hint(profile))

    def test_a_broken_profile_is_the_defaults_plus_a_sentence(self) -> None:
        cases = ("not json at all", "[1, 2, 3]", '"a string"', "")
        for raw in cases:
            with self.subTest(raw=raw[:20]), TemporaryDirectory() as tmp:
                gn_profile.profile_path(tmp).write_text(raw, encoding="utf-8")
                profile = gn_profile.load(tmp)
                self.assertEqual(profile.get("bot"), "tinygpt")
                self.assertTrue(profile.error, "a corrupt settings file must be reported")
                self.assertEqual(gn_profile.first_run_hint(profile), profile.error)

    def test_a_value_of_the_wrong_type_is_dropped_not_honoured(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_profile.profile_path(tmp).write_text(json.dumps({
                "settings": {"learning": "banana", "bot": "skynet", "hunt.active": True},
            }), encoding="utf-8")
            profile = gn_profile.load(tmp)
        self.assertIs(profile.get("learning"), True, "back to the default, not 'banana'")
        self.assertEqual(profile.get("bot"), "tinygpt")
        self.assertIs(profile.get("hunt.active"), True, "the valid one still applies")

    def test_a_key_this_build_does_not_know_is_ignored_entirely(self) -> None:
        with TemporaryDirectory() as tmp:
            gn_profile.profile_path(tmp).write_text(json.dumps({
                "settings": {"authorize": True, "always_hunt": True, "bot": "off"},
            }), encoding="utf-8")
            profile = gn_profile.load(tmp)
        self.assertNotIn("authorize", profile.values)
        self.assertNotIn("always_hunt", profile.values)
        self.assertEqual(profile.get("bot"), "off")


class SetAndSaveTests(unittest.TestCase):
    def test_set_get_unset_round_trips_through_the_file(self) -> None:
        with TemporaryDirectory() as tmp:
            profile = gn_profile.load(tmp)
            profile, error = gn_profile.set_value(profile, "bot", "anthropic")
            self.assertEqual(error, "")
            profile, error = gn_profile.save(tmp, profile)
            self.assertEqual(error, "")
            reloaded = gn_profile.load(tmp)
            self.assertEqual(reloaded.get("bot"), "anthropic")
            self.assertTrue(reloaded.chosen("bot"))
            self.assertEqual(reloaded.source("bot"), "profile")
            dropped, error = gn_profile.unset(reloaded, "bot")
            self.assertEqual(error, "")
            dropped, _error = gn_profile.save(tmp, dropped)
            self.assertEqual(gn_profile.load(tmp).get("bot"), "tinygpt")

    def test_only_the_chosen_half_is_written(self) -> None:
        # So a default that moves in a later version reaches an existing profile, instead of being
        # frozen into it by whatever the defaults were on the day of the first run.
        with TemporaryDirectory() as tmp:
            profile, _error = gn_profile.set_value(gn_profile.load(tmp), "bot", "off")
            gn_profile.save(tmp, profile)
            doc = json.loads(gn_profile.profile_path(tmp).read_text(encoding="utf-8"))
        self.assertEqual(doc["settings"], {"bot": "off"})
        self.assertEqual(doc["version"], gn_profile.VERSION)
        self.assertTrue(doc["created_at"])

    def test_the_booleans_an_operator_will_actually_type(self) -> None:
        profile = gn_profile.Profile()
        for typed, expected in (("on", True), ("ON", True), ("true", True), ("yes", True),
                                ("1", True), ("enable", True), ("off", False), ("no", False),
                                ("0", False), ("false", False), ("disabled", False)):
            with self.subTest(typed=typed):
                updated, error = gn_profile.set_value(profile, "learning", typed)
                self.assertEqual(error, "")
                self.assertIs(updated.get("learning"), expected)
        _profile, error = gn_profile.set_value(profile, "learning", "sometimes")
        self.assertIn("on or off", error)

    def test_a_bad_value_is_refused_with_the_choices_named(self) -> None:
        profile = gn_profile.Profile()
        _p, error = gn_profile.set_value(profile, "bot", "gpt5")
        self.assertIn("tinygpt", error)
        _p, error = gn_profile.set_value(profile, "hunt.profile", "everything")
        self.assertIn("full-sweep", error)
        _p, error = gn_profile.set_value(profile, "nope", "x")
        self.assertIn("gn settings", error)

    def test_a_string_cannot_smuggle_line_breaks_into_the_file(self) -> None:
        _p, error = gn_profile.set_value(gn_profile.Profile(), "operator.handle", "a\nb")
        self.assertIn("line breaks", error)

    def test_an_unwritable_directory_is_reported_not_raised(self) -> None:
        profile, _error = gn_profile.set_value(gn_profile.Profile(), "bot", "off")
        _saved, error = gn_profile.save(Path(__file__), profile)   # a FILE, not a directory
        self.assertTrue(error.startswith("could not write"))

    @unittest.skipIf(os.name == "nt", "POSIX modes only")
    def test_the_file_is_written_private(self) -> None:
        with TemporaryDirectory() as tmp:
            profile, _error = gn_profile.set_value(gn_profile.load(tmp), "operator.handle", "greynoc")
            gn_profile.save(tmp, profile)
            self.assertEqual(gn_profile.profile_path(tmp).stat().st_mode & 0o777, 0o600)

    def test_a_killed_write_leaves_no_half_written_settings_file(self) -> None:
        with TemporaryDirectory() as tmp:
            profile, _error = gn_profile.set_value(gn_profile.load(tmp), "bot", "off")
            gn_profile.save(tmp, profile)
            self.assertEqual([p.name for p in Path(tmp).iterdir()], [gn_profile.PROFILE_FILE],
                             "the temporary file must not be left behind")


class OutputFolderTests(unittest.TestCase):
    def test_a_target_url_and_its_host_name_the_same_folder(self) -> None:
        for typed in ("https://acme.example/app?q=1", "acme.example", "ACME.example/",
                      "http://acme.example"):
            with self.subTest(typed=typed):
                self.assertEqual(gn_profile.output_label(typed), "acme.example")

    def test_the_narrowest_entry_wins_then_the_domain_then_the_default(self) -> None:
        profile = gn_profile.Profile()
        profile, _e = gn_profile.set_value(profile, "output.dir", "/reports/all")
        profile, _e = gn_profile.set_output(profile, "acme.example", "/reports/acme")
        profile, _e = gn_profile.set_output(profile, "api.acme.example", "/reports/api")
        self.assertEqual(gn_profile.output_dir_for(profile, "https://api.acme.example/v2"),
                         str(Path("/reports/api")))
        self.assertEqual(gn_profile.output_dir_for(profile, "https://app.acme.example/"),
                         str(Path("/reports/acme")), "a subdomain falls back to its domain")
        self.assertEqual(gn_profile.output_dir_for(profile, "https://other.example/"),
                         str(Path("/reports/all")))
        self.assertEqual(gn_profile.output_dir_for(gn_profile.Profile(), "https://other.example/"),
                         "", "nothing set means nothing invented")

    def test_the_first_label_given_is_the_most_specific_one_asked_about(self) -> None:
        profile, _e = gn_profile.set_output(gn_profile.Profile(), "acme-program", "/reports/program")
        self.assertEqual(gn_profile.output_dir_for(profile, "https://acme.example/", "acme-program"),
                         str(Path("/reports/program")))

    def test_a_folder_is_recorded_not_created(self) -> None:
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "not" / "there" / "yet"
            profile, error = gn_profile.set_output(gn_profile.Profile(), "acme.example", str(target))
            self.assertEqual(error, "")
            self.assertFalse(target.exists(), "a typo must not leave an empty tree behind")

    def test_no_label_means_the_default_folder(self) -> None:
        # `gn output --path <folder>` with no -s. It is the same thing as output.dir, which is why
        # it sets exactly that rather than inventing an entry keyed on "".
        profile, error = gn_profile.set_output(gn_profile.Profile(), "", "/reports/all")
        self.assertEqual(error, "")
        self.assertEqual(profile.output_paths, {})
        self.assertEqual(profile.get("output.dir"), str(Path("/reports/all")))

    def test_a_label_that_is_not_a_name_is_refused(self) -> None:
        for label in ("../../etc", "a label with spaces", "/", "..", "*"):
            with self.subTest(label=label):
                _p, error = gn_profile.set_output(gn_profile.Profile(), label, "/reports/x")
                self.assertTrue(error)

    def test_clearing_one_leaves_the_others(self) -> None:
        profile, _e = gn_profile.set_output(gn_profile.Profile(), "acme.example", "/reports/acme")
        profile, _e = gn_profile.set_output(profile, "other.example", "/reports/other")
        profile, error = gn_profile.clear_output(profile, "https://acme.example/")
        self.assertEqual(error, "")
        self.assertEqual(list(profile.output_paths), ["other.example"])
        _p, error = gn_profile.clear_output(profile, "acme.example")
        self.assertIn("nothing was set", error)

    def test_a_blank_path_is_a_refusal_not_an_erasure(self) -> None:
        profile, _e = gn_profile.set_output(gn_profile.Profile(), "acme.example", "/reports/acme")
        _p, error = gn_profile.set_output(profile, "acme.example", "   ")
        self.assertIn("give a folder", error)


class RenderingTests(unittest.TestCase):
    def test_the_listing_marks_what_the_operator_chose(self) -> None:
        profile, _e = gn_profile.set_value(gn_profile.Profile(exists=True), "bot", "off")
        lines = gn_profile.settings_lines(profile)
        text = "\n".join(lines)
        for item in gn_profile.SETTINGS:
            self.assertIn(item.key, text, "every setting is listed, not just the set ones")
            self.assertIn(item.help, text)
        keys = {item.key for item in gn_profile.SETTINGS}
        chosen = [line for line in lines
                  if line.startswith(" * ") and line.split()[1] in keys]
        self.assertEqual(len(chosen), 1, f"only the set one is marked: {chosen}")
        self.assertEqual(chosen[0].split()[1], "bot")

    def test_the_listing_says_when_there_is_no_profile(self) -> None:
        self.assertIn("gn setup", "\n".join(gn_profile.settings_lines(gn_profile.Profile())))

    def test_every_command_that_changes_a_setting_is_listed(self) -> None:
        text = "\n".join(gn_profile.command_lines())
        for expected in ("gn setup", "gn settings set", "gn settings unset", "gn settings path",
                         "gn output"):
            self.assertIn(expected, text)

    def test_booleans_read_as_on_and_off_not_true_and_false(self) -> None:
        self.assertEqual(gn_profile.show(True), "on")
        self.assertEqual(gn_profile.show(False), "off")
        self.assertEqual(gn_profile.show(""), "(blank)")
        self.assertEqual(gn_profile.show("tinygpt"), "tinygpt")


if __name__ == "__main__":
    unittest.main()
