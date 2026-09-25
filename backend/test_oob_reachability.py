"""The four out-of-band provers must be reachable from every path that can hunt.

``run_bounty_hunt`` gates blind SSRF, blind XXE, blind RCE and JWT key-URL injection on a configured
collaborator: each one mints a fresh unguessable callback token, probes, and confirms only on a hit
whose matched control stayed silent. Three of the four are Critical classes, and they are the only way
this engine can prove a vulnerability whose effect is *not* visible in the response.

Every one of them was dead outside a single manual hunt. Only the one-URL API route passed
``oob_base``/``oob_secret``; ``campaign.py`` did not mention the parameters at all, and neither did the
CLI. So a campaign, a program span, the unattended operator loop, ``gn hunt`` and ``gn campaign`` — the
entire autonomous surface — had four confirmable classes permanently switched off, silently, with no
message anywhere saying so.

These are wiring contracts over the whole chain, because the failure is invisible: a hunt with the
provers disabled looks exactly like a hunt where nothing blind was present.

Forwarding the config weakens no gate. The provers stay behind active + authorized + in-scope inside
``run_bounty_hunt``, and a collaborator exists only because the operator pasted one into Settings —
that *is* the opt-in.
"""
from __future__ import annotations

import inspect
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import campaign  # noqa: E402

API_SOURCE = (BACKEND_DIR / "greyiq_api.py").read_text(encoding="utf-8")
CAMPAIGN_SOURCE = (BACKEND_DIR / "bughunter" / "campaign.py").read_text(encoding="utf-8")
CLI_SOURCE = (BACKEND_DIR / "gn_cli.py").read_text(encoding="utf-8")

#: The provers that are gated on a collaborator, and the oob_service call each one makes.
PROVERS = {
    "blind SSRF": "confirm_blind_ssrf",
    "blind XXE": "confirm_blind_xxe",
    "blind RCE": "confirm_blind_rce",
    "JWT key-URL injection": "confirm_jwt_key_injection",
}


class TheGateIsWhatWeThinkItIsTests(unittest.TestCase):
    """Anti-vacuity: establish that these provers really are collaborator-gated before asserting it."""

    def test_all_four_provers_exist_and_are_gated_on_a_collaborator(self) -> None:
        from bughunter import bounty

        source = inspect.getsource(bounty._run_bounty_hunt_body)
        for label, call in PROVERS.items():
            with self.subTest(prover=label):
                self.assertIn(call, source, f"{label} is no longer run from the hunt body")
        # Each call site sits behind a truthiness check on BOTH values.
        gates = re.findall(r'if str\(oob_base or ""\)\.strip\(\) and str\(oob_secret or ""\)\.strip\(\)',
                           source)
        self.assertEqual(len(gates), len(PROVERS),
                         f"expected {len(PROVERS)} collaborator gates, found {len(gates)} — the "
                         "prover set changed, so re-check what this test is protecting")

    def test_the_hunt_body_takes_the_collaborator_as_a_parameter(self) -> None:
        from bughunter import bounty

        params = inspect.signature(bounty._run_bounty_hunt_body).parameters
        for name in ("oob_base", "oob_secret"):
            self.assertIn(name, params)


class EveryHopAcceptsAndForwardsTests(unittest.TestCase):
    """Accepting is not enough — a hop that accepts and drops is exactly the bug that was here."""

    def test_each_campaign_entry_point_accepts_the_collaborator(self) -> None:
        for fn in (campaign._run_campaign_body, campaign.run_campaign_over_targets,
                   campaign.run_portfolio_campaign):
            params = inspect.signature(fn).parameters
            for name in ("oob_base", "oob_secret"):
                with self.subTest(function=fn.__name__, parameter=name):
                    self.assertIn(name, params, f"{fn.__name__} cannot be told the collaborator")
                    self.assertEqual(params[name].default, "",
                                     "the default must be empty, so an unconfigured operator keeps "
                                     "the provers off rather than getting a broken callback")

    def test_run_campaign_forwards_unknown_kwargs_to_the_body(self) -> None:
        # It is a thin wrapper over _run_campaign_body via **kwargs; if that stops being true the
        # forward above silently breaks.
        params = inspect.signature(campaign.run_campaign).parameters
        self.assertTrue(any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()),
                        "run_campaign no longer forwards **kwargs, so oob_* would be dropped")

    def test_there_is_a_forward_at_each_of_the_three_hops(self) -> None:
        # body -> per-URL hunt, over_targets -> per-target campaign, portfolio -> per-program span.
        self.assertEqual(CAMPAIGN_SOURCE.count("oob_base=oob_base"), 3,
                         "a hop accepts the collaborator and drops it")


class TheCollaboratorReachesThePerUrlHuntTests(unittest.TestCase):
    """The one that matters: drive a real campaign and see what the per-URL hunt is handed."""

    def test_a_campaign_hands_the_collaborator_to_every_per_url_hunt(self) -> None:
        captured: list[dict] = []
        original = campaign.run_bounty_hunt

        def _spy(*args: object, **kwargs: object) -> dict:
            captured.append({"oob_base": kwargs.get("oob_base"), "oob_secret": kwargs.get("oob_secret")})
            return {"ok": False, "error": "stubbed after capture"}

        campaign.run_bounty_hunt = _spy
        self.addCleanup(lambda: setattr(campaign, "run_bounty_hunt", original))
        with tempfile.TemporaryDirectory() as tmp:
            campaign.run_campaign(
                "https://t.invalid/page",
                scope="t.invalid", authorized=True, coder_cfg={},
                default_reports_dir=Path(tmp), seed_dir=None, runtime_dir=Path(tmp),
                version="test", active=False, live=False, program="p", max_pages=1,
                oob_base="https://collab.example", oob_secret="s3cret",
            )
        self.assertTrue(captured, "no per-URL hunt ran, so this test proved nothing")
        for call in captured:
            self.assertEqual(call["oob_base"], "https://collab.example")
            self.assertEqual(call["oob_secret"], "s3cret")

    def test_an_unconfigured_campaign_still_hands_over_nothing(self) -> None:
        # The provers must stay off by default: no collaborator, no callback, no probe.
        captured: list[dict] = []
        original = campaign.run_bounty_hunt

        def _spy(*args: object, **kwargs: object) -> dict:
            captured.append({"oob_base": kwargs.get("oob_base"), "oob_secret": kwargs.get("oob_secret")})
            return {"ok": False, "error": "stubbed after capture"}

        campaign.run_bounty_hunt = _spy
        self.addCleanup(lambda: setattr(campaign, "run_bounty_hunt", original))
        with tempfile.TemporaryDirectory() as tmp:
            campaign.run_campaign(
                "https://t.invalid/page",
                scope="t.invalid", authorized=True, coder_cfg={},
                default_reports_dir=Path(tmp), seed_dir=None, runtime_dir=Path(tmp),
                version="test", active=False, live=False, program="p", max_pages=1,
            )
        self.assertTrue(captured)
        for call in captured:
            self.assertEqual(call["oob_base"], "")
            self.assertEqual(call["oob_secret"], "")


class EveryCallerSuppliesItTests(unittest.TestCase):
    def test_all_four_api_hunt_routes_pass_the_configured_collaborator(self) -> None:
        # The single hunt plus the three campaign shapes: single-target, program span, portfolio.
        self.assertEqual(API_SOURCE.count("oob_base=self._oob_config()"), 4,
                         "an API hunt route does not supply the collaborator, so its provers are dead")

    def test_the_cli_reads_the_same_secrets_store_as_the_app(self) -> None:
        import gn_cli

        self.assertTrue(callable(getattr(gn_cli, "_oob_config", None)),
                        "the CLI cannot read a configured collaborator")
        self.assertIn("oob.collaborator_url", CLI_SOURCE)
        self.assertIn("oob.secret", CLI_SOURCE)
        # The same keys greyiq_api reads, or a collaborator set in the app is invisible to the CLI.
        for key in ("oob.collaborator_url", "oob.secret"):
            with self.subTest(key=key):
                self.assertIn(key, API_SOURCE)

    def test_both_cli_hunt_verbs_supply_it(self) -> None:
        self.assertEqual(CLI_SOURCE.count("oob_base=_oob_config()[0]"), 2,
                         "gn hunt and gn campaign must both honour a configured collaborator")


class TheCliReaderIsTotalTests(unittest.TestCase):
    """A malformed secrets store must disable the provers, never half-configure them."""

    def _read(self, payload: object | None, *, raw: str | None = None) -> tuple[str, str]:
        import gn_cli

        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp)
            if raw is not None:
                (runtime / "secrets.json").write_text(raw, encoding="utf-8")
            elif payload is not None:
                (runtime / "secrets.json").write_text(json.dumps(payload), encoding="utf-8")
            original = gn_cli.RUNTIME_DIR
            gn_cli.RUNTIME_DIR = runtime
            try:
                return gn_cli._oob_config()
            finally:
                gn_cli.RUNTIME_DIR = original

    def test_a_complete_config_is_read(self) -> None:
        self.assertEqual(
            self._read({"oob.collaborator_url": "https://c.example", "oob.secret": "s"}),
            ("https://c.example", "s"))

    def test_a_missing_file_disables_the_provers(self) -> None:
        self.assertEqual(self._read(None), ("", ""))

    def test_malformed_json_disables_the_provers(self) -> None:
        self.assertEqual(self._read(None, raw="{not json"), ("", ""))

    def test_a_non_object_store_disables_the_provers(self) -> None:
        self.assertEqual(self._read(None, raw='["a", "list"]'), ("", ""))

    def test_a_url_with_no_secret_is_refused_as_a_pair(self) -> None:
        # A base with no secret cannot mint a token; handing it over would start probes that can
        # never confirm, spending request budget against the target for nothing.
        self.assertEqual(self._read({"oob.collaborator_url": "https://c.example"}), ("", ""))
        self.assertEqual(self._read({"oob.secret": "s"}), ("", ""))

    def test_whitespace_only_values_are_not_a_config(self) -> None:
        self.assertEqual(self._read({"oob.collaborator_url": "   ", "oob.secret": "\\t"}), ("", ""))


if __name__ == "__main__":
    unittest.main()
