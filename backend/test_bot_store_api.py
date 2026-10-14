"""One store, two doors: the /api/bots routes against the registry the `gn bot` verbs write.

The Studio's AI Studio used to keep its bots in the browser's localStorage. A bot made in the app
was invisible to `gn bot ls`, a bot made in the shell was invisible to the app, and "which bot is
live" had two answers that nothing ever compared. These routes make the app a second DOOR onto
``gn_bots``' store rather than a second store, so what is pinned here is that the door cannot
acquire rules of its own:

  * a bot created through a route is in ``runtime/bots.json`` and in ``gn bot ls``
  * a bot created by the CLI is served by the route
  * selecting a bot in the app goes through ``gn_bots.set_active``, so the app's selection and the
    ``*`` in ``gn bot ls`` are the same bot -- and the hunt's resolved config follows it
  * every invariant ``gn_bots``' docstring promises still holds THROUGH the route: no key in the
    store, no field that implies authorization, an inert clone that cannot become a brain, a
    refused entry written back verbatim, a store that cannot be parsed never overwritten
  * the one-time handover of a browser's own bots loses nothing and cannot run twice

``test_gn_bots`` and ``test_bot_review_fixes`` pin the same invariants at the module. These drive
the HTTP handlers, because an invariant that holds in ``gn_bots`` and not in the route that wraps it
is not an invariant.
"""

from __future__ import annotations

import ast
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_bots  # noqa: E402
import gn_profile  # noqa: E402
import greyiq_api as api  # noqa: E402


class BotRouteCase(unittest.TestCase):
    """Each test gets its own runtime directory, pointed at by the module global the handlers read."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.runtime = Path(self._tmp.name)
        self._previous = api.RUNTIME_DIR
        api.RUNTIME_DIR = self.runtime

    def tearDown(self) -> None:
        api.RUNTIME_DIR = self._previous
        self._tmp.cleanup()

    # --- helpers ---------------------------------------------------------------------------------
    def create(self, name: str, **values: object) -> dict:
        return api.create_bot(api.BotCreateRequest(name=name, **values))

    def row(self, payload: dict, bot_id: str) -> dict:
        found = [item for item in payload["bots"] if item["id"] == bot_id]
        self.assertTrue(found, f"{bot_id} is not in the payload: {[i['id'] for i in payload['bots']]}")
        return found[0]

    def cli_listing(self) -> list[str]:
        """``gn bot ls``'s own lines, from the same store the routes just wrote."""
        registry = gn_bots.load(self.runtime)
        live, _note = gn_bots.active(self.runtime)
        return gn_bots.list_lines(registry, live.id, self.runtime)

    def live_marked_in_cli(self) -> str:
        for line in self.cli_listing():
            if line.startswith(" *"):
                return line.split()[1]
        return ""


class OneStoreTests(BotRouteCase):
    def test_the_route_serves_the_stores_own_bots(self) -> None:
        payload = api.list_bots()
        self.assertEqual([bot["id"] for bot in payload["bots"]],
                         [bot.id for bot in gn_bots.load(self.runtime).bots])
        self.assertEqual(payload["active_id"], gn_bots.DEFAULT_ID)
        self.assertEqual(payload["path"], str(gn_bots.store_path(self.runtime)))
        self.assertEqual(payload["error"], "")

    def test_a_bot_made_through_the_route_is_in_gn_bot_ls(self) -> None:
        made = self.create("Recon Scout", provider="local", model="qwen2.5-coder:14b",
                           persona="terse recon analyst")
        self.assertEqual(made["bot"], "recon-scout")
        # The store on disk, which is what every other surface reads.
        stored = gn_bots.load(self.runtime).get("recon-scout")
        self.assertIsNotNone(stored)
        self.assertEqual((stored.provider, stored.model), ("local", "qwen2.5-coder:14b"))
        self.assertIn("recon-scout", "\n".join(self.cli_listing()))

    def test_a_bot_made_by_the_cli_is_served_by_the_route(self) -> None:
        registry, bot, error = gn_bots.create(gn_bots.load(self.runtime), "shell-made",
                                              provider="anthropic", model="claude-opus-5")
        self.assertEqual(error, "")
        _registry, error = gn_bots.save(self.runtime, registry)
        self.assertEqual(error, "")
        row = self.row(api.list_bots(), "shell-made")
        self.assertEqual(row["provider"], "anthropic")
        self.assertEqual(row["describe"], bot.describe())

    def test_the_store_reports_its_own_problems_through_the_route(self) -> None:
        # A refused entry is reported, not swallowed: the app showing the built-ins as the
        # operator's own bots is what gn_bots.load exists to prevent.
        gn_bots.store_path(self.runtime).write_text(
            json.dumps({"version": 1, "bots": [{"id": "ghost", "provider": "ollama"}]}),
            encoding="utf-8")
        payload = api.list_bots()
        self.assertIn("ghost", payload["error"])
        self.assertNotIn("ghost", [bot["id"] for bot in payload["bots"]])


class LiveBotAgreesEverywhereTests(BotRouteCase):
    def test_the_apps_selection_is_the_star_in_gn_bot_ls(self) -> None:
        self.create("Recon", provider="local", model="qwen2.5-coder:14b")
        payload = api.set_active_bot(api.BotSelectRequest(bot="recon"))
        self.assertEqual(payload["active_id"], "recon")
        # The CLI's own listing, from the profile setting set_active wrote.
        self.assertEqual(self.live_marked_in_cli(), "recon")
        self.assertEqual(gn_profile.load(self.runtime).get("bot"), "recon")

    def test_selecting_goes_through_set_active_so_a_missing_bot_is_refused(self) -> None:
        with self.assertRaises(api.HTTPError) as caught:
            api.set_active_bot(api.BotSelectRequest(bot="nope"))
        self.assertEqual(caught.exception.status_code, 422)
        # Nothing was parked in the profile: the setting never names a bot that is not there.
        self.assertEqual(gn_profile.load(self.runtime).get("bot"), gn_bots.DEFAULT_ID)

    def test_a_prefix_is_stored_as_the_bot_it_resolves_to(self) -> None:
        self.create("Recon", provider="local", model="qwen2.5-coder:14b")
        api.set_active_bot(api.BotSelectRequest(bot="rec"))
        self.assertEqual(gn_profile.load(self.runtime).get("bot"), "recon")

    def test_the_hunts_resolved_config_follows_the_apps_selection(self) -> None:
        """What the app picked is what `gn hunt --brain` plans with -- the whole point of one store."""
        self.create("Recon", provider="anthropic", model="claude-opus-5", temperature=0.2)
        api.set_active_bot(api.BotSelectRequest(bot="recon"))
        import gn_cli

        previous = gn_cli.RUNTIME_DIR
        gn_cli.RUNTIME_DIR = self.runtime
        try:
            resolved = gn_cli._load_coder_config(True)
        finally:
            gn_cli.RUNTIME_DIR = previous
        self.assertEqual(resolved.get("provider"), "anthropic")
        self.assertTrue(resolved.get("enabled"))
        self.assertEqual(resolved.get("anthropic", {}).get("model"), "claude-opus-5")
        self.assertEqual(resolved.get("temperature"), 0.2)

    def test_deleting_the_live_bot_re_points_the_profile(self) -> None:
        self.create("Recon", provider="local", model="qwen2.5-coder:14b")
        api.set_active_bot(api.BotSelectRequest(bot="recon"))
        payload = api.delete_bot(api.BotSelectRequest(bot="recon"))
        self.assertEqual(payload["active_id"], gn_bots.DEFAULT_ID)
        self.assertIn("was live", payload["note"])
        # And the profile itself, not just the answer: `gn settings` must not advertise a bot that
        # is gone.
        self.assertEqual(gn_profile.load(self.runtime).get("bot"), gn_bots.DEFAULT_ID)
        self.assertEqual(self.live_marked_in_cli(), gn_bots.DEFAULT_ID)

    def test_deleting_another_bot_leaves_the_live_one_alone(self) -> None:
        self.create("Recon", provider="local", model="qwen2.5-coder:14b")
        self.create("Spare")
        api.set_active_bot(api.BotSelectRequest(bot="recon"))
        api.delete_bot(api.BotSelectRequest(bot="spare"))
        self.assertEqual(gn_profile.load(self.runtime).get("bot"), "recon")


class EditingThroughTheRouteTests(BotRouteCase):
    def test_several_fields_land_together(self) -> None:
        self.create("Recon")
        payload = api.update_bot(api.BotUpdateRequest(
            bot="recon", fields={"name": "Recon II", "persona": "names the endpoint it probed",
                                 "style": "direct", "temperature": 0.65}))
        row = self.row(payload, "recon")
        self.assertEqual((row["name"], row["style"], row["temperature"]), ("Recon II", "direct", 0.65))
        self.assertEqual(row["persona"], "names the endpoint it probed")

    def test_a_refused_field_leaves_the_whole_edit_undone(self) -> None:
        """The editor carries four fields at once; half of them landing is the defect to avoid."""
        self.create("Recon")
        with self.assertRaises(api.HTTPError) as caught:
            api.update_bot(api.BotUpdateRequest(
                bot="recon", fields={"name": "Renamed", "temperature": 99}))
        self.assertEqual(caught.exception.status_code, 422)
        self.assertEqual(self.row(api.list_bots(), "recon")["name"], "Recon")

    def test_an_unknown_field_is_named_rather_than_ignored(self) -> None:
        self.create("Recon")
        with self.assertRaises(api.HTTPError) as caught:
            api.update_bot(api.BotUpdateRequest(bot="recon", fields={"authorized": "yes"}))
        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("authorized", caught.exception.detail)

    def test_renaming_mid_edit_still_finds_the_same_bot(self) -> None:
        # Found by prefix, then renamed: the rest of the fields must keep going to the same bot
        # rather than to whatever a display-name lookup now matches.
        self.create("Recon")
        payload = api.update_bot(api.BotUpdateRequest(
            bot="rec", fields={"name": "Something Else", "style": "teaching"}))
        self.assertEqual(payload["bot"], "recon")
        self.assertEqual(self.row(payload, "recon")["style"], "teaching")

    def test_teach_puts_the_browsers_corpus_where_lessons_live(self) -> None:
        self.create("Recon")
        payload = api.teach_bot(api.BotTeachRequest(bot="recon", lesson="prefer read-only probes"))
        self.assertEqual(self.row(payload, "recon")["lessons"], ["prefer read-only probes"])
        # And it reaches a chat prompt the way a `gn bot teach` lesson does.
        self.assertIn("prefer read-only probes",
                      gn_bots.system_extra(gn_bots.load(self.runtime).get("recon")))

    def test_teaching_the_same_lesson_twice_is_a_note_not_a_failure(self) -> None:
        self.create("Recon")
        api.teach_bot(api.BotTeachRequest(bot="recon", lesson="one"))
        payload = api.teach_bot(api.BotTeachRequest(bot="recon", lesson="one"))
        self.assertIn("already knows", payload["note"])
        self.assertEqual(self.row(payload, "recon")["lessons"], ["one"])

    def test_a_clone_carries_the_lessons_and_not_the_trained_stamp(self) -> None:
        self.create("Recon", provider="local", model="qwen2.5-coder:14b")
        api.teach_bot(api.BotTeachRequest(bot="recon", lesson="cite the endpoint"))
        registry, _bot, error = gn_bots.mark_trained(gn_bots.load(self.runtime), "recon", "ranker run")
        self.assertEqual(error, "")
        gn_bots.save(self.runtime, registry)
        payload = api.clone_bot(api.BotCloneRequest(bot="recon", name="recon-hot"))
        copy = self.row(payload, "recon-hot")
        self.assertEqual(copy["lessons"], ["cite the endpoint"])
        self.assertEqual(copy["trained_at"], "")
        self.assertEqual(self.row(payload, "recon")["trained_at"] != "", True)

    def test_a_builtin_cannot_be_deleted_through_the_route_either(self) -> None:
        with self.assertRaises(api.HTTPError) as caught:
            api.delete_bot(api.BotSelectRequest(bot=gn_bots.DEFAULT_ID))
        self.assertEqual(caught.exception.status_code, 422)
        self.assertIsNotNone(gn_bots.load(self.runtime).get(gn_bots.DEFAULT_ID))


class InvariantsSurviveThisDoorTests(BotRouteCase):
    def test_no_payload_can_carry_a_key(self) -> None:
        (self.runtime / "secrets.json").write_text(json.dumps({"anthropic": "sk-ant-secret-xyz"}),
                                                   encoding="utf-8")
        self.create("Recon", provider="anthropic", model="claude-opus-5")
        payloads = [api.list_bots(),
                    api.update_bot(api.BotUpdateRequest(bot="recon", fields={"notes": "hi"})),
                    api.teach_bot(api.BotTeachRequest(bot="recon", lesson="x")),
                    api.set_active_bot(api.BotSelectRequest(bot="recon"))]
        for payload in payloads:
            text = json.dumps(payload)
            self.assertNotIn("sk-ant-secret-xyz", text)
        # PRESENCE is reported, which is what lets a listing say "ready" without holding one.
        self.assertEqual(self.row(api.list_bots(), "recon")["key_state"], "configured")

    def test_an_endpoint_carrying_a_credential_is_refused_through_the_route(self) -> None:
        self.create("Recon", provider="local")
        for value in ("https://api.example.com/v1?api_key=sk-live-1", "https://u:p@example.com/v1"):
            with self.subTest(base_url=value):
                with self.assertRaises(api.HTTPError) as caught:
                    api.update_bot(api.BotUpdateRequest(bot="recon", fields={"base_url": value}))
                self.assertEqual(caught.exception.status_code, 422)
                # The refusal does not quote what it rejected: it is printed to footers.
                self.assertNotIn("sk-live-1", caught.exception.detail)
        self.assertEqual(self.row(api.list_bots(), "recon")["base_url"], "")

    def test_creating_a_bot_with_a_credential_endpoint_is_refused(self) -> None:
        with self.assertRaises(api.HTTPError):
            self.create("Leaky", provider="local", base_url="https://h/v1?api_key=sk-live-2")
        self.assertIsNone(gn_bots.load(self.runtime).get("leaky"))

    def test_no_route_can_write_a_field_that_implies_authorization(self) -> None:
        self.create("Recon")
        for key in ("authorized", "authorization", "scope", "in_scope"):
            with self.subTest(field=key):
                with self.assertRaises(api.HTTPError):
                    api.update_bot(api.BotUpdateRequest(bot="recon", fields={key: True}))
        self.assertNotIn("authoriz", json.dumps(api.list_bots()["fields"]).lower())

    def test_an_inert_clone_cannot_become_a_brain_through_the_route(self) -> None:
        inert = gn_bots.Bot(id="stranger-agent", name="Stranger", provider="off", inert=True,
                            source="clone", origin={"repo": "someone/agent", "revision": "abc123"})
        registry, placed, error = gn_bots.register(gn_bots.load(self.runtime), inert)
        self.assertEqual(error, "")
        gn_bots.save(self.runtime, registry)
        with self.assertRaises(api.HTTPError) as caught:
            api.update_bot(api.BotUpdateRequest(bot="stranger-agent", fields={"provider": "local"}))
        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("inert", caught.exception.detail)
        row = self.row(api.list_bots(), "stranger-agent")
        self.assertTrue(row["inert"])
        self.assertFalse(row["runnable"])
        self.assertEqual(row["readiness"], "inert")
        # And it still builds no config for the hunt.
        self.assertEqual(gn_bots.coder_overlay(placed), {})

    def test_a_store_that_cannot_be_parsed_is_never_replaced_through_the_route(self) -> None:
        path = gn_bots.store_path(self.runtime)
        broken = '{"version": 1, "bots": [{"id": "keeper", "provider": "local"},]}'
        path.write_text(broken, encoding="utf-8")
        listing = api.list_bots()
        self.assertIn("not valid JSON", listing["error"])
        self.assertFalse(listing["readable"])
        for call in (lambda: self.create("New One"),
                     lambda: api.teach_bot(api.BotTeachRequest(bot="local", lesson="x")),
                     lambda: api.migrate_bots(api.BotMigrateRequest(
                         bots=[{"id": "astra", "name": "Astra"}]))):
            with self.assertRaises(api.HTTPError) as caught:
                call()
            self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(path.read_text(encoding="utf-8"), broken)

    def test_an_entry_this_build_refused_survives_a_route_driven_mutation(self) -> None:
        path = gn_bots.store_path(self.runtime)
        path.write_text(json.dumps({"version": 1, "bots": [
            {"id": "ghost", "provider": "ollama", "persona": "a persona worth keeping"},
            {"id": "keeper", "provider": "local", "model": "qwen2.5-coder:14b"},
        ]}), encoding="utf-8")
        api.teach_bot(api.BotTeachRequest(bot="keeper", lesson="still here"))
        stored = json.loads(path.read_text(encoding="utf-8"))
        ghost = [entry for entry in stored["bots"] if entry.get("id") == "ghost"]
        self.assertEqual(ghost, [{"id": "ghost", "provider": "ollama",
                                  "persona": "a persona worth keeping"}])

    def test_creating_over_a_refused_entrys_id_is_refused(self) -> None:
        gn_bots.store_path(self.runtime).write_text(json.dumps({"version": 1, "bots": [
            {"id": "ghost", "provider": "ollama"}]}), encoding="utf-8")
        with self.assertRaises(api.HTTPError):
            self.create("ghost")

    def test_off_machine_is_resolved_rather_than_read_off_the_bot(self) -> None:
        """A `local` bot with no endpoint of its own inherits the app's -- which may be elsewhere."""
        (self.runtime / "solin_runtime_config.json").write_text(
            json.dumps({"coder": {"local": {"base_url": "http://10.0.0.9:11434/v1"}}}),
            encoding="utf-8")
        self.create("Remote", provider="local", model="qwen2.5-coder:14b")
        row = self.row(api.list_bots(), "remote")
        self.assertEqual(row["base_url"], "")          # the bot itself says nothing
        self.assertTrue(row["off_machine"])            # and the payload still tells the truth
        self.assertEqual(row["endpoint"], "http://10.0.0.9:11434/v1")

    def test_a_credential_in_the_apps_own_config_never_reaches_a_payload(self) -> None:
        """The leak chain: POST /api/coder writes coder.local.base_url unvalidated, endpoint_for
        read it back through _text with no validation either, and /api/bots echoed it verbatim --
        one field, two rules, depending only on which file it was read from."""
        (self.runtime / "solin_runtime_config.json").write_text(json.dumps({"coder": {"local": {
            "base_url": "http://u:sk-live-SECRET@10.0.0.9:11434/v1?api_key=sk-live-SECRET#f"}}}),
            encoding="utf-8")
        self.create("Remote", provider="local", model="qwen2.5-coder:14b")
        payload = api.list_bots()
        self.assertNotIn("sk-live-SECRET", json.dumps(payload))
        row = self.row(payload, "remote")
        # NOT blanked: the request really goes to that host, so the marker must still say so.
        self.assertTrue(row["off_machine"])
        self.assertEqual(row["endpoint"], "http://10.0.0.9:11434/v1")
        # And gn_bots' own surfaces get the same redaction, from the same function.
        self.assertEqual(gn_bots.endpoint_for(self.runtime, gn_bots.load(self.runtime).get("remote")),
                         "http://10.0.0.9:11434/v1")

    def test_an_over_long_endpoint_is_refused_on_the_update_door_too(self) -> None:
        # The create model was bounded to 200; the update door carries base_url inside
        # `fields: dict[str, Any]`, which nothing bounded -- so 326 characters were accepted, the
        # first 200 kept, and the truncated string echoed back as the endpoint.
        self.create("Long", provider="local")
        with self.assertRaises(api.HTTPError) as caught:
            api.update_bot(api.BotUpdateRequest(bot="long",
                fields={"base_url": "http://h/" + "a" * 320}))
        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("at most 200", caught.exception.detail)
        self.assertEqual(self.row(api.list_bots(), "long")["base_url"], "")

    def test_a_note_within_its_declared_limit_is_stored_whole(self) -> None:
        """FIELDS, the API model and `gn bot fields` all advertise 300 characters for notes.

        ``coerce`` truncated every non-text field to 200 before the per-field limit was checked, so
        the 300 check could never fire and a 250-character note was stored as two thirds of itself
        with nothing said.
        """
        note = "n" * 250
        payload = self.create("Noted", notes=note)
        self.assertEqual(self.row(payload, "noted")["notes"], note)
        # And over the real limit is refused rather than quietly cut.
        with self.assertRaises(api.HTTPError) as caught:
            api.update_bot(api.BotUpdateRequest(bot="noted", fields={"notes": "x" * 400}))
        self.assertIn("at most 300", caught.exception.detail)

    def test_show_lines_names_the_endpoint_a_local_bot_will_actually_use(self) -> None:
        """`gn bot show` asked the bot's own fields, which is the one thing no surface may do.

        A `local` bot with no ``base_url`` inherits the app's, so this row omitted both the
        destination and the off-machine warning while the prompt went to another host.
        """
        (self.runtime / "solin_runtime_config.json").write_text(
            json.dumps({"coder": {"local": {"base_url": "http://10.0.0.9:11434/v1"}}}),
            encoding="utf-8")
        self.create("Remote", provider="local", model="qwen2.5-coder:14b")
        bot = gn_bots.load(self.runtime).get("remote")
        self.assertEqual(bot.base_url, "", "the bot itself must carry nothing for this to bite")
        shown = chr(10).join(gn_bots.show_lines(bot, self.runtime))
        self.assertIn("http://10.0.0.9:11434/v1", shown)
        self.assertIn("off this machine", shown)
        self.assertIn("from the app's coder config", shown)
        # A loopback inheritance is shown but not warned about.
        (self.runtime / "solin_runtime_config.json").write_text(
            json.dumps({"coder": {"local": {"base_url": "http://127.0.0.1:11434/v1"}}}),
            encoding="utf-8")
        nearby = chr(10).join(
            gn_bots.show_lines(gn_bots.load(self.runtime).get("remote"), self.runtime))
        self.assertIn("http://127.0.0.1:11434/v1", nearby)
        self.assertNotIn("off this machine", nearby)

    def test_the_listing_footer_describes_the_bot_that_is_actually_live(self) -> None:
        """It said "it answers chat and plans the hunt" whatever was marked `*`.

        False of `off`, `offline`, `tinygpt` and an inert clone — the sentence ``what_it_does``
        exists to keep honest, printed from the one place that had not been using it.
        """
        self.create("Remote", provider="local", model="qwen2.5-coder:14b")
        registry = gn_bots.load(self.runtime)
        for bot_id, expected in (("off", "nothing answers"),
                                 ("offline", "it does not chat"),
                                 ("tinygpt", "bundled offline pack"),
                                 ("remote", "answers chat and plans the hunt")):
            with self.subTest(live=bot_id):
                footer = [line for line in gn_bots.list_lines(registry, bot_id, self.runtime)
                          if line.startswith(" * = live")]
                self.assertEqual(len(footer), 1)
                self.assertIn(expected, footer[0])
                self.assertEqual(footer[0].count("answers chat and plans the hunt"),
                                 1 if bot_id == "remote" else 0)

    def test_whether_a_readiness_is_a_fault_is_the_stores_judgement(self) -> None:
        """``is_blocked`` is the single answer; the app kept its own copy of the same list.

        `off`, `edits only` and `inert` are postures — bots working exactly as designed — and the
        CLI had this wrong in its own words at the same time (`gn bot use off` printed "off: `gn
        bot show off` says what is missing"). Two copies of one judgement is how they drift.
        """
        self.create("Hosted", provider="anthropic", model="claude-opus-5")
        payload = api.list_bots()
        for bot_id, blocked in (("hosted", True),      # needs a key
                                ("off", False),        # nothing answers, by design
                                ("offline", False),    # edits only, by design
                                ("tinygpt", False)):   # ready
            with self.subTest(bot=bot_id):
                row = self.row(payload, bot_id)
                self.assertEqual(row["blocked"], blocked)
                self.assertEqual(row["blocked"], gn_bots.is_blocked(row["readiness"]))

    def test_a_loopback_bot_is_not_marked(self) -> None:
        (self.runtime / "solin_runtime_config.json").write_text(
            json.dumps({"coder": {"local": {"base_url": "http://127.0.0.1:11434/v1"}}}),
            encoding="utf-8")
        self.create("Nearby", provider="local", model="qwen2.5-coder:14b")
        self.assertFalse(self.row(api.list_bots(), "nearby")["off_machine"])


class MigrationTests(BotRouteCase):
    BROWSER = [
        {"id": "astra", "name": "Astra", "style": "direct", "temperature": 46,
         "persona": "Astra is a generalist.", "color": "#ff6633",
         "corpus": ["start with the strongest signal", "say what is inferred"]},
        {"id": "Forge", "name": "Forge", "style": "technical", "temperature": 34,
         "persona": "Forge is skeptical.", "corpus": ["inspect the boundary first"]},
    ]

    def test_every_bot_and_every_field_arrives(self) -> None:
        payload = api.migrate_bots(api.BotMigrateRequest(bots=self.BROWSER))
        self.assertEqual(payload["created"], 2)
        astra = self.row(payload, "astra")
        self.assertEqual(astra["name"], "Astra")
        self.assertEqual(astra["persona"], "Astra is a generalist.")
        self.assertEqual(astra["style"], "direct")
        # The browser's 0-100 slider was a sampling temperature x100 on its only consumer, so this
        # is a conversion rather than a new number.
        self.assertEqual(astra["temperature"], 0.46)
        # corpus -> lessons, which is the field that already means "operator prose for this bot".
        self.assertEqual(astra["lessons"], ["start with the strongest signal", "say what is inferred"])
        # Never a hosted provider: a browser-only bot named none, and inventing one would point it
        # at a key.
        self.assertEqual(astra["provider"], gn_bots.DEFAULT_ID)

    def test_an_id_the_registry_cannot_hold_is_reported_with_the_one_it_got(self) -> None:
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": "Forge", "name": "Forge"},
            {"id": "bot-6f1c0b7e-6b0a-4d6c-9a1a-2f2b6c7d8e9f", "name": "New Bot"},
        ]))
        got = {row["from"]: row["id"] for row in payload["migrated"]}
        self.assertEqual(got["Forge"], "forge")
        assigned = got["bot-6f1c0b7e-6b0a-4d6c-9a1a-2f2b6c7d8e9f"]
        self.assertLessEqual(len(assigned), 32)
        self.assertTrue(gn_bots._ID.fullmatch(assigned), assigned)
        self.assertIsNotNone(gn_bots.load(self.runtime).get(assigned))

    def test_two_bots_that_slug_the_same_are_both_kept(self) -> None:
        """Ids that really DO collide. The first version of this test used ``bot-aaaa``/``bot-bbbb``,
        which are already valid ids, so ``bot_id`` short-circuited and no collision was ever
        exercised -- it passed while the behaviour it is named for silently dropped a bot.
        """
        for label, payload_bots in (
            ("different case", [{"id": "Forge", "name": "Forge", "persona": "the first"},
                                {"id": "FORGE", "name": "Forge", "persona": "the second"}]),
            ("no id at all", [{"name": "New Bot", "persona": "the first"},
                              {"name": "New Bot", "persona": "the second"}]),
        ):
            with self.subTest(collision=label):
                self.setUp()
                payload = api.migrate_bots(api.BotMigrateRequest(bots=payload_bots))
                rows = payload["migrated"]
                self.assertEqual([row["status"] for row in rows], ["created", "created"],
                                 f"a bot was dropped: {rows}")
                ids = [row["id"] for row in rows]
                self.assertEqual(len(set(ids)), 2, f"both bots got one id: {rows}")
                personas = sorted(self.row(payload, bot_id)["persona"] for bot_id in ids)
                self.assertEqual(personas, ["the first", "the second"])
                # And the second one's row says what actually happened, rather than claiming it
                # was already in the store and left alone -- which was false twice over.
                self.assertIn("taken by another bot in this handover", rows[1]["note"])
                self.assertNotIn("already in the store", rows[1]["note"])

    def test_already_in_the_store_means_before_this_handover(self) -> None:
        # The one case that IS "exists": the operator made it in the shell first.
        self.create("Forge", persona="the one I made in the shell")
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": "Forge", "name": "Forge", "persona": "the browser's"}]))
        row = payload["migrated"][0]
        self.assertEqual(row["status"], "exists")
        self.assertEqual(self.row(payload, "forge")["persona"], "the one I made in the shell")

    def test_one_tampered_entry_cannot_take_the_whole_handover_down(self) -> None:
        """A 400-digit integer: ``float(10**400)`` raises OverflowError, not ValueError.

        It 500'd the route, so every other bot in the body was lost -- and because the app leaves
        the handover pending and retries it on each load, it failed identically forever.
        """
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": "good", "name": "Good"},
            {"id": "evil", "name": "Evil", "temperature": int("1" + "0" * 400)},
            {"id": "also-good", "name": "Also Good"},
        ]))
        self.assertEqual([row["status"] for row in payload["migrated"]],
                         ["created", "created", "created"])
        # The unusable temperature is simply unset -- the provider's default, not a derived number.
        self.assertIsNone(self.row(payload, "evil")["temperature"])
        for bot_id in ("good", "also-good"):
            self.assertIsNotNone(gn_bots.load(self.runtime).get(bot_id))

    def test_a_boolean_is_not_a_temperature(self) -> None:
        # float(True) is 1.0, so `"temperature": true` became a stored 0.01 -- a number nobody
        # chose, which is the fabrication this program forbids.
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": "yes", "name": "Yes", "temperature": True},
            {"id": "no", "name": "No", "temperature": False},
            {"id": "sneaky", "name": "Sneaky", "temperature": "1_0"},
        ]))
        for bot_id in ("yes", "no", "sneaky"):
            with self.subTest(bot=bot_id):
                self.assertIsNone(self.row(payload, bot_id)["temperature"])

    def test_more_bots_than_one_handover_reads_is_reported(self) -> None:
        extra = api.MIGRATE_LIMIT + 5
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": f"b{index:04d}", "name": f"Bot {index}"} for index in range(extra)]))
        self.assertEqual(payload["created"], api.MIGRATE_LIMIT)
        overflow = [row for row in payload["migrated"] if row["status"] == "deferred"]
        self.assertEqual(len(overflow), 1, "the bots that fell off the end must be reported")
        self.assertIn("5 more bot(s) were not read", overflow[0]["note"])
        # And the app is told how many were consumed, so it can keep the unread tail pending and
        # send it next time -- which is what makes "the rest will be added" a true sentence.
        self.assertEqual(payload["read"], api.MIGRATE_LIMIT)
        self.assertIn("next load", overflow[0]["note"])
        self.assertNotIn("run it again", overflow[0]["note"])

    def test_a_field_too_long_shortens_the_field_and_says_so(self) -> None:
        # Losing text silently and losing the whole bot are both wrong inside a route that
        # promises to lose nothing. It is cut to fit, and the row says it was cut.
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": "wordy", "name": "N" * 300, "persona": "P" * 2000, "style": "S" * 300}]))
        row = payload["migrated"][0]
        self.assertEqual(row["status"], "created")
        for field in ("name", "persona", "style"):
            self.assertIn(f"{field} was shortened", row["note"])
        stored = self.row(payload, "wordy")
        self.assertEqual((len(stored["name"]), len(stored["persona"]), len(stored["style"])),
                         (60, 600, 80))

    def test_it_cannot_run_twice(self) -> None:
        first = api.migrate_bots(api.BotMigrateRequest(bots=self.BROWSER))
        before = gn_bots.store_path(self.runtime).read_text(encoding="utf-8")
        second = api.migrate_bots(api.BotMigrateRequest(bots=self.BROWSER))
        self.assertEqual(second["created"], 0)
        self.assertEqual([row["status"] for row in second["migrated"]], ["exists", "exists"])
        self.assertEqual([bot["id"] for bot in second["bots"]], [bot["id"] for bot in first["bots"]])
        # And it did not even rewrite the file, so a repeat cannot churn the store either.
        self.assertEqual(gn_bots.store_path(self.runtime).read_text(encoding="utf-8"), before)

    def test_it_never_overwrites_a_bot_the_operator_already_had(self) -> None:
        self.create("Astra", provider="anthropic", model="claude-opus-5",
                    persona="the one I made in the shell")
        payload = api.migrate_bots(api.BotMigrateRequest(bots=self.BROWSER))
        astra = self.row(payload, "astra")
        self.assertEqual(astra["persona"], "the one I made in the shell")
        self.assertEqual(astra["provider"], "anthropic")
        self.assertEqual([row["status"] for row in payload["migrated"] if row["from"] == "astra"],
                         ["exists"])

    def test_a_built_in_id_is_left_exactly_as_it_is(self) -> None:
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": "local", "name": "Local", "persona": "a browser persona", "temperature": 99}]))
        self.assertEqual(payload["created"], 0)
        self.assertEqual(self.row(payload, "local")["persona"], "")

    def test_a_tampered_entry_is_refused_by_name_and_the_rest_still_land(self) -> None:
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": "!!!", "name": "???"},
            "not an object",
            {"id": "good", "name": "Good", "temperature": 50},
        ]))
        statuses = {row["from"]: row["status"] for row in payload["migrated"]}
        self.assertEqual(statuses.get("!!!"), "refused")
        self.assertEqual(statuses.get("good"), "created")
        self.assertEqual(self.row(payload, "good")["temperature"], 0.5)

    def test_an_out_of_range_temperature_becomes_the_provider_default(self) -> None:
        # Not clamped to a number nobody chose: unset means "whatever the provider defaults to".
        payload = api.migrate_bots(api.BotMigrateRequest(bots=[
            {"id": "weird", "name": "Weird", "temperature": 9999}]))
        self.assertIsNone(self.row(payload, "weird")["temperature"])

    def test_a_migrated_bot_is_a_bot_in_gn_bot_ls(self) -> None:
        api.migrate_bots(api.BotMigrateRequest(bots=self.BROWSER))
        listing = "\n".join(self.cli_listing())
        self.assertIn("astra", listing)
        self.assertIn("forge", listing)


class StudioControlsAreBoundTests(unittest.TestCase):
    """Static contracts over the three files that have to agree about this panel.

    Same reason ``test_studio_training_wiring`` is static: a control that posts nothing looks
    exactly like one that works, and a route with no caller looks exactly like a route nobody
    needs. A browser is not needed for either.
    """

    HTML = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
    JS = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
    CSS = (ROOT / "public" / "styles.css").read_text(encoding="utf-8")
    API = (BACKEND_DIR / "greyiq_api.py").read_text(encoding="utf-8")

    def test_every_new_control_exists_and_is_looked_up(self) -> None:
        for element_id in ("botProvider", "botModel", "botTemperatureValue", "botReadiness",
                           "botStoreNote", "cloneBotButton"):
            with self.subTest(element=element_id):
                self.assertIn(f'id="{element_id}"', self.HTML,
                              f"#{element_id} is missing from the markup")
                self.assertIn(f'document.querySelector("#{element_id}")', self.JS,
                              f"#{element_id} is never looked up, so nothing can bind to it")

    def test_every_bot_route_exists_and_is_called(self) -> None:
        for route in ("/api/bots", "/api/bots/update", "/api/bots/delete", "/api/bots/clone",
                      "/api/bots/teach", "/api/bots/active", "/api/bots/migrate"):
            with self.subTest(route=route):
                self.assertIn(f'path == "{route}"', self.API, f"{route} has no handler")
                self.assertIn(f'"{route}"', self.JS, f"{route} is not called from the app")

    def test_the_apps_classes_are_styled(self) -> None:
        for class_name in ("bot-store-note", "bot-readiness", "field-readout"):
            with self.subTest(css_class=class_name):
                self.assertIn(f".{class_name}", self.CSS, f".{class_name} is used but never styled")

    def test_the_temperature_slider_speaks_the_registrys_units(self) -> None:
        # 0-100 here and 0.0-2.0 in the store would mean the two surfaces print different numbers
        # for one bot's one field.
        match = re.search(r'id="botTemperature"[^>]*', self.HTML)
        self.assertIsNotNone(match)
        self.assertIn('min="0"', match.group(0))
        self.assertIn('max="2"', match.group(0))
        self.assertNotIn('max="100"', match.group(0))
        # A step the store's own values do not land on means the slider re-quantizes a temperature
        # set from the CLI the moment the panel is touched.
        self.assertIn('step="0.01"', match.group(0))
        # And nothing divides a temperature by 100 any more.
        self.assertNotIn("temperature / 100", self.JS)

    def test_the_app_does_not_write_the_bot_setting_itself(self) -> None:
        """``set_active`` is the only writer, so the app must reach it through its own route.

        Two halves, because either alone would pass while the rule was broken: the app has to USE
        the route, and the API must have no other way to write the setting.
        """
        self.assertIn('"/api/bots/active"', self.JS)
        # Only the two handlers with a reason to call it: making a bot live, and re-pointing the
        # profile after the live bot is deleted.
        callers = sorted(node.name for node in ast.walk(ast.parse(self.API))
                         if isinstance(node, ast.FunctionDef)
                         and "gn_bots.set_active(" in (ast.get_source_segment(self.API, node) or ""))
        self.assertEqual(callers, ["delete_bot", "set_active_bot"],
                         "set_active is called from somewhere new -- it is the single writer")
        # And nothing in the API reaches the profile's own writers, which is the second door
        # set_active exists to prevent.
        for writer in ("gn_profile.set_value(", "gn_profile.save("):
            self.assertNotIn(writer, self.API,
                             f"{writer} in the API is a second door into the operator profile")

    def test_the_payload_carries_the_stores_own_sentence_rather_than_a_third_copy(self) -> None:
        """``what_it_does`` is one sentence for both doors; the app must print it, not rewrite it."""
        self.assertIn("gn_bots.what_it_does(bot)", self.API)
        self.assertIn("bot.what_it_does", self.JS)
        # The app may frame it ("Live:" / "When live:") but must not carry its own version of the
        # claim. These are the clauses gn_bots owns.
        for clause in ("answers chat and plans the hunt", "the hunt stays deterministic",
                       "bundled offline pack"):
            with self.subTest(clause=clause):
                self.assertNotIn(clause, self.JS,
                                 "the app is restating what_it_does instead of printing it")

    def test_the_app_keeps_no_second_copy_of_what_counts_as_a_fault(self) -> None:
        """``gn_bots.is_blocked`` is the single answer, carried as ``blocked`` in the payload."""
        self.assertIn("gn_bots.is_blocked(", self.API)
        self.assertIn("bot.blocked", self.JS)
        self.assertNotIn("BLOCKING_READINESS", self.JS)
        for answer in ("needs a key", "needs a model"):
            self.assertNotIn(f'"{answer}"', self.JS,
                             "the app is deciding what counts as a fault again")

    def test_the_app_reads_the_facts_it_must_not_compute(self) -> None:
        # readiness/key_state/off_machine/endpoint depend on files the browser cannot see.
        for field in ("readiness", "key_state", "off_machine", "endpoint", "blocked"):
            with self.subTest(field=field):
                self.assertIn(f'"{field}"', self.API, f"the payload no longer carries {field}")
                self.assertIn(f"bot.{field}", self.JS, f"the app never reads {field}")


if __name__ == "__main__":
    unittest.main()
