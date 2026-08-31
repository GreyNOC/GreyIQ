"""Contract tests for the surface-drift engine.

The engine's whole value is that a change feed stays worth reading, so most of these are about
what it must NOT say: it must not call a first run clean, must not diff against a baseline too
thin to mean anything, must not report a redeploy as a hundred separate discoveries, must not
let a fingerprint move because of a timestamp, and must never claim a delta is a finding.
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

from bughunter import surface_drift  # noqa: E402


def _response(body: str = "{}", status: int = 200, headers: dict | None = None,
              cookies: list | None = None, url: str = "https://a.test/") -> dict:
    return {"status": status, "body": body, "final_url": url,
            "headers": headers if headers is not None else {"content-type": "application/json"},
            "cookies": cookies or []}


def _obs(url: str, **kwargs) -> dict:
    return surface_drift.observe(url, _response(url=url, **kwargs))


def row_values(row: dict) -> set:
    """Every scalar an observation stores, for asserting what is NOT in it."""
    out = set()
    for value in row.values():
        if isinstance(value, list):
            out.update(v for v in value if isinstance(v, (str, int)))
        elif isinstance(value, (str, int, bool)):
            out.add(value)
    return out


class ObservationTests(unittest.TestCase):
    def test_the_fingerprint_ignores_content_churn(self) -> None:
        """Hashing the body is the naive failure mode: it moves on every request on any real
        site, so every run would report that everything changed."""
        first = _obs("https://a.test/api", body=json.dumps(
            {"id": 1, "name": "Ada", "price": 19.99, "updated_at": "2026-01-01T00:00:00Z"}))
        second = _obs("https://a.test/api", body=json.dumps(
            {"id": 7712, "name": "Grace", "price": 24.50, "updated_at": "2026-08-30T11:02:44Z"}))
        self.assertTrue(first["bt"])
        self.assertEqual(first["bt"], second["bt"])

    def test_the_fingerprint_moves_when_a_field_appears(self) -> None:
        before = _obs("https://a.test/api", body=json.dumps({"id": 1, "name": "Ada"}))
        after = _obs("https://a.test/api", body=json.dumps({"id": 1, "name": "Ada", "is_admin": False}))
        self.assertNotEqual(before["bt"], after["bt"])

    def test_a_url_identity_drops_the_query(self) -> None:
        """A session id or cache-buster in the query would make the same page look new every run."""
        self.assertEqual(_obs("https://a.test/p?sid=aaa")["u"], _obs("https://a.test/p?sid=bbb")["u"])

    def test_only_a_magnitude_of_the_body_length_is_stored(self) -> None:
        """A page's exact byte count moves on every request (timestamps, nonces, ad ids), so
        storing it would make everything look changed."""
        small = _obs("https://a.test/x", body="a" * 5000)
        wobbled = _obs("https://a.test/x", body="a" * 5400)
        bigger = _obs("https://a.test/x", body="a" * 500000)
        self.assertEqual(small["cl"], wobbled["cl"])
        self.assertNotEqual(small["cl"], bigger["cl"])
        self.assertNotIn(5000, row_values(small), "the exact length must not be stored")

    def test_cookies_are_stored_as_names_and_flags_never_values(self) -> None:
        row = _obs("https://a.test/", cookies=["sessionid=SUPERSECRETVALUE; Path=/; HttpOnly; Secure"])
        blob = json.dumps(row)
        self.assertNotIn("SUPERSECRETVALUE", blob)
        self.assertIn("sessionid:hs", row["ck"])

    def test_only_a_surface_that_exists_is_observed(self) -> None:
        """Recon spends most of its request budget on a constant list of well-known paths, and
        on a real target nearly all of them 404. Recording those was not just wasted space: they
        inflated the observation count the baseline-confidence gate divides by, so a run whose
        real surface had collapsed could still look well-covered. Measured on a live target:
        17 of 18 observations were not-found rows.
        """
        for status in (404, 410, 500, 502):
            with self.subTest(status=status):
                self.assertEqual(_obs("https://a.test/nope", status=status), {})
        for status in (200, 204, 301, 401, 403):
            with self.subTest(status=status):
                self.assertTrue(_obs("https://a.test/real", status=status).get("u"),
                                "a gated endpoint is real, and its gate coming off is the signal")

    def test_the_port_is_part_of_a_url_identity(self) -> None:
        """Two services on one host are two surfaces; collapsing them diffed an app on :8080
        against an admin panel on :8443."""
        self.assertNotEqual(_obs("https://a.test:8080/x")["u"], _obs("https://a.test:8443/x")["u"])
        self.assertIn(":8080", _obs("https://a.test:8080/x")["u"])

    def test_a_malformed_response_never_raises(self) -> None:
        """An observation is optional; a hunt is not. Anything unusable yields nothing."""
        for junk in (None, {"status": "not-a-number"}, [], "nope", 3):
            with self.subTest(junk=junk):
                self.assertEqual(surface_drift.observe("https://a.test/", junk).get("u", ""), "")
        # A URL that is not a URL yields nothing even from a well-formed response.
        self.assertEqual(surface_drift.observe("not a url", _response(url="not a url")), {})
        # A response with no status at all is not evidence that a surface exists.
        self.assertEqual(surface_drift.observe("https://a.test/", {"headers": 5, "cookies": 7}), {})
        # ...but a real response whose optional fields are the wrong type still observes cleanly.
        sparse = surface_drift.observe("https://a.test/", {"status": 200, "headers": 5, "cookies": 7})
        self.assertEqual((sparse["sh"], sparse["ck"], sparse["st"]), ([], [], 200))


class BaselineHonestyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.runtime = self._dir.name

    def tearDown(self) -> None:
        self._dir.cleanup()

    def _record(self, obs: dict, surface: dict | None = None, **kwargs) -> None:
        self.assertTrue(surface_drift.record_snapshot(
            self.runtime, program="acme", target="https://a.test/", host="a.test",
            observations=obs, surface=surface or {}, **kwargs))

    def _drift(self, obs: dict, surface: dict | None = None) -> dict:
        return surface_drift.build_drift(
            self.runtime, program="acme", target="https://a.test/", host="a.test",
            observations=obs, surface=surface or {})

    def test_a_missing_baseline_is_not_a_clean_baseline(self) -> None:
        """Saying "no changes detected" on a first run is a claim about a comparison that never
        happened — the operator cannot tell "stable" from "never looked"."""
        result = self._drift({"https://a.test/": _obs("https://a.test/")})
        self.assertEqual(result["status"], "first-observation")
        self.assertEqual(result["deltas"], [])
        prose = " ".join(surface_drift.summary_lines(result)).lower()
        self.assertIn("baseline", prose)
        self.assertNotIn("no changes detected", prose)
        self.assertNotIn("surface stable", prose)

    def test_a_degraded_baseline_is_refused_not_diffed(self) -> None:
        """A prior run cut short by a WAF or an exhausted budget would otherwise make every URL
        it missed look new — a flood of phantom signal that burns the whole active budget."""
        self._record({"https://a.test/": _obs("https://a.test/")})
        current = {f"https://a.test/p{i}": _obs(f"https://a.test/p{i}") for i in range(30)}
        result = self._drift(current)
        self.assertEqual(result["status"], "low-confidence-baseline")
        self.assertEqual(result["deltas"], [])
        prose = " ".join(surface_drift.summary_lines(result)).lower()
        self.assertIn("too little", prose)
        self.assertIn("refusing", prose)

    def test_a_site_wide_control_loss_is_one_row_not_a_hundred(self) -> None:
        """Dropping one CSP header from a shared middleware produced eighteen identical rows on a
        live target, which crowded the real changes out of the top of the feed."""
        secure = {"content-type": "text/html", "content-security-policy": "default-src 'self'"}
        self._record({f"https://a.test/p{i}": _obs(f"https://a.test/p{i}", headers=secure)
                      for i in range(10)})
        result = self._drift({f"https://a.test/p{i}": _obs(f"https://a.test/p{i}",
                                                           headers={"content-type": "text/html"})
                              for i in range(10)})
        lost = [d for d in result["deltas"] if d["kind"] == "header.security-removed"]
        self.assertEqual(len(lost), 1, "one middleware change is one fact about the site")
        self.assertIn("content-security-policy", lost[0]["names"])

    def test_a_redeploy_is_one_row_not_a_hundred(self) -> None:
        before = {f"https://a.test/p{i}": _obs(f"https://a.test/p{i}", body=json.dumps({"a": 1}))
                  for i in range(10)}
        self._record(before)
        after = {f"https://a.test/p{i}": _obs(f"https://a.test/p{i}", body=json.dumps({"a": 1, "b": 2}))
                 for i in range(10)}
        result = self._drift(after)
        shape = [d for d in result["deltas"] if d["kind"] == "shape.changed"]
        self.assertEqual(len(shape), 1, "a whole-site rebuild is one observation, not ten")
        self.assertIn("redeploy", shape[0]["why"])

    def test_a_truncated_fingerprint_is_never_compared(self) -> None:
        """The digest fills its key cap in encounter order, so two runs over the SAME unchanged
        response can legitimately keep different keys. Comparing them invents a change."""
        wide = json.dumps({f"field_{i}": i for i in range(120)})
        row = _obs("https://a.test/wide", body=wide)
        self.assertTrue(row["cap"], "the fixture must actually hit the digest cap")
        self._record({"https://a.test/wide": row})
        moved = dict(row, bt="0000000000000000")
        result = self._drift({"https://a.test/wide": moved})
        self.assertEqual([d for d in result["deltas"] if d["kind"] == "shape.changed"], [])

    def test_absence_is_never_reported_as_a_fix(self) -> None:
        self._record({"https://a.test/admin": _obs("https://a.test/admin", status=200)})
        result = self._drift({"https://a.test/admin": _obs("https://a.test/admin", status=401)})
        gated = next(d for d in result["deltas"] if d["kind"] == "auth.added")
        self.assertIn("not a verified remediation", gated["why"].lower())

    def test_an_auth_gate_coming_off_is_the_top_signal(self) -> None:
        self._record({"https://a.test/admin": _obs("https://a.test/admin", status=403)})
        result = self._drift({"https://a.test/admin": _obs("https://a.test/admin", status=200)})
        top = result["deltas"][0]
        self.assertEqual(top["kind"], "auth.removed")
        self.assertEqual(surface_drift.delta_targets(result, limit=2), ["https://a.test/admin"])

    def test_decay_is_monotone(self) -> None:
        """A change that has sat there for six runs has already been looked at; re-shouting at
        full volume is how a change feed stops being read."""
        base = {"https://a.test/": _obs("https://a.test/")}
        scores: list[int] = []
        for _ in range(5):
            self._record(base, surface={"endpoints": []},
                         deltas=[{"kind": "endpoint.new", "subject": "https://a.test/new"}])
            result = self._drift(base, surface={"endpoints": ["https://a.test/new"]})
            row = next((d for d in result["deltas"] if d["kind"] == "endpoint.new"), None)
            if row:
                scores.append(row["score"])
        self.assertTrue(scores)
        self.assertEqual(scores, sorted(scores, reverse=True), f"scores rose: {scores}")
        # Ordering alone does NOT pin decay: a constant series is also non-increasing, so
        # deleting the decay factor entirely left this green. Pin the drop and the floor.
        self.assertLess(scores[1], scores[0],
                        "a delta seen a second time must score below its first run")
        self.assertLessEqual(
            scores[-1],
            int(surface_drift._DELTA_WEIGHT["endpoint.new"] * surface_drift._DECAY_FLOOR) + 1,
            "a long-standing delta must decay to the floor, not hold its opening score")

    def test_identity_is_scope_bound(self) -> None:
        surface_drift.record_snapshot(
            self.runtime, program="acme", target="https://a.test/", host="a.test",
            observations={"https://a.test/": _obs("https://a.test/")}, surface={})
        other = surface_drift.build_drift(
            self.runtime, program="zenith", target="https://b.test/", host="b.test",
            observations={"https://b.test/": _obs("https://b.test/")}, surface={})
        self.assertEqual(other["status"], "first-observation",
                         "one program's baseline must never be diffed against another's")

    def test_a_hostile_store_never_raises(self) -> None:
        path = Path(self.runtime) / "surface_snapshots.jsonl"
        path.write_text('{"v":1,"program":"acme","host":"a.test","obs":"not-a-dict"}\n'
                        '{ torn json without a newline', encoding="utf-8")
        result = self._drift({"https://a.test/": _obs("https://a.test/")})
        self.assertIn(result["status"], {"compared", "first-observation", "low-confidence-baseline"})
        self.assertIsInstance(result["deltas"], list)

    def test_a_delta_is_never_a_finding(self) -> None:
        """The engine emits no finding shape at all — no severity, no class, no ref — so nothing
        it produces can be mistaken for something that was observed to be broken."""
        self._record({"https://a.test/admin": _obs("https://a.test/admin", status=403)})
        result = self._drift({"https://a.test/admin": _obs("https://a.test/admin", status=200)})
        self.assertTrue(result["deltas"])
        for delta in result["deltas"]:
            self.assertEqual({"severity", "class_id", "ref", "proof_of_impact"} & set(delta), set())


class ChainReopenTests(unittest.TestCase):
    """The temporal half of the chain engine: a chain blocked for several runs becomes worth
    retrying the moment the surface changes in a way that may supply what it was waiting for."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.runtime = self._dir.name
        self.blocked = {
            "id": "AC1", "title": "Unauthenticated attacker → read another tenant's data",
            "projected_impact": "Unauthorized read of another tenant's data",
            "status": "candidate", "blocking_step": 2, "refs": ["F1"],
            "steps": [
                {"n": 1, "technique_id": "disclosure-yields-identifiers", "proven": True,
                 "title": "Disclosure leaks real object identifiers",
                 "grants_ids": ["disclose.identifier"]},
                {"n": 2, "technique_id": "identifier-to-object-read", "proven": False,
                 "title": "Replay a disclosed identifier across the authorization boundary",
                 "grants_ids": ["read.other-object"]},
            ],
        }

    def tearDown(self) -> None:
        self._dir.cleanup()

    def _record(self, **kwargs) -> None:
        surface_drift.record_snapshot(
            self.runtime, program="acme", target="https://a.test/", host="a.test",
            observations={"https://a.test/": _obs("https://a.test/")},
            surface={"endpoints": []}, chains=[self.blocked], **kwargs)

    def test_a_chain_identity_survives_renumbering(self) -> None:
        """Chain ids are a position in one report's sorted list and are reassigned at every
        render, so keying the matcher on them would match whichever chain ranked first."""
        renumbered = {**self.blocked, "id": "AC7"}
        self.assertEqual(surface_drift.chain_shape(self.blocked),
                         surface_drift.chain_shape(renumbered))
        different = {**self.blocked, "projected_impact": "Remote code execution"}
        self.assertNotEqual(surface_drift.chain_shape(self.blocked),
                            surface_drift.chain_shape(different))

    def test_a_matching_delta_reopens_the_blocked_chain_as_a_probe(self) -> None:
        self._record()
        self._record()
        drift = {"deltas": [{"kind": "endpoint.new", "subject": "https://a.test/api/orders/1",
                             "label": "an endpoint that did not exist in the previous run",
                             "score": 50}]}
        rows = surface_drift.reopened_chains(drift, self.runtime, program="acme",
                                             target="https://a.test/", host="a.test")
        self.assertTrue(rows, "read.other-object is unblockable by a new endpoint")
        row = rows[0]
        self.assertEqual(row["status"], "untested")
        self.assertGreaterEqual(row["blocked_runs"], 2)
        self.assertIn("blocked at step 2", row["hypothesis"])
        # It must read as a thing to TEST, never as a thing that happened.
        self.assertIn("not evidence", row["next_action"].lower())
        self.assertEqual({"confidence_score", "proven", "severity"} & set(row), set())

    def test_an_unrelated_delta_does_not_reopen_anything(self) -> None:
        self._record()
        drift = {"deltas": [{"kind": "auth.added", "subject": "https://a.test/x",
                             "label": "gate appeared", "score": 20}]}
        self.assertEqual(surface_drift.reopened_chains(
            drift, self.runtime, program="acme", target="https://a.test/", host="a.test"), [])

    def test_no_baseline_means_nothing_is_reopened(self) -> None:
        drift = {"deltas": [{"kind": "endpoint.new", "subject": "https://a.test/n",
                             "label": "new", "score": 50}]}
        self.assertEqual(surface_drift.reopened_chains(
            drift, self.runtime, program="acme", target="https://a.test/", host="a.test"), [])


class ReportIntegrationTests(unittest.TestCase):
    """Drift reaches the operator without ever reading as a finding."""

    DRIFT = {
        "algorithm": surface_drift.ALGORITHM_VERSION, "status": "compared",
        "baseline_ts": "2026-08-29T10:00:00+00:00",
        "summary": {"urls_before": 6, "urls_now": 7, "by_kind": {"auth.removed": 1}},
        "deltas": [{
            "kind": "auth.removed", "subject": "https://a.test/admin", "score": 95, "age_runs": 0,
            "label": "an endpoint that required authentication now answers without it",
            "why": "this endpoint required authentication in the previous run and now answers without it",
            "names": [], "from": "403", "to": "200", "base_score": 95,
        }],
    }

    def _ctx(self, **extra) -> dict:
        return {"profile": {"name": "Test"}, "findings": [], "attack_plans": {},
                "scanners_run": [], "brain": {}, "next_steps": [], "coverage": {}, **extra}

    def test_the_report_carries_the_drift_section(self) -> None:
        from bughunter import report

        markdown = report.build_markdown(self._ctx(drift=self.DRIFT))
        self.assertIn("## Surface drift", markdown)
        self.assertIn("https://a.test/admin", markdown)
        # It must say what it is, so a skim cannot read it as a finding.
        self.assertIn("not findings", markdown)

    def test_drift_never_changes_the_reported_findings(self) -> None:
        """The load-bearing separation: the findings a hunt reports are byte-identical whether
        or not the target's history was compared."""
        from bughunter import report

        finding = {"ref": "F1", "class_id": "xss", "title": "Reflected XSS", "severity": "medium",
                   "location": "https://a.test/s"}
        without = report.build_json(self._ctx(findings=[finding]))
        with_drift = report.build_json(self._ctx(findings=[finding], drift=self.DRIFT))
        self.assertEqual(without["findings"], with_drift["findings"])
        self.assertEqual(without["severity_counts"], with_drift["severity_counts"])
        self.assertEqual(with_drift["drift"], self.DRIFT)

    def test_a_first_run_report_never_claims_the_surface_is_stable(self) -> None:
        from bughunter import report

        markdown = report.build_markdown(self._ctx(drift={
            "algorithm": surface_drift.ALGORITHM_VERSION, "status": "first-observation",
            "deltas": [], "summary": {}, "baseline_ts": ""}))
        self.assertIn("## Surface drift", markdown)
        self.assertIn("baseline", markdown.lower())
        for forbidden in ("no changes detected", "surface stable", "unchanged since"):
            self.assertNotIn(forbidden, markdown.lower())

    def test_the_action_plan_leads_with_what_changed(self) -> None:
        from bughunter import next_steps

        steps = next_steps.build_next_steps(self._ctx(
            drift=self.DRIFT, kind="url",
            investigation={"chain_probes": [{
                "id": "CR1", "blocked_runs": 3,
                "hypothesis": "blocked at step 2 waiting on read.other-object",
                "next_action": "Re-probe https://a.test/admin."}]}))
        self.assertTrue(steps)
        self.assertEqual(steps[0]["phase"], "What changed")
        detail = " ".join(s["detail"] for s in steps if s["phase"] == "What changed")
        self.assertIn("not evidence that anything is exploitable", detail)
        self.assertTrue(any("CR1" in s["action"] for s in steps))


class StaleProofTests(unittest.TestCase):
    """A proof is a statement about a response that existed when it was captured."""

    CHAIN = {
        "id": "AC1", "title": "Unauthenticated attacker -> disclosure", "status": "confirmed",
        "steps": [{"n": 1, "technique_id": "sql-injection-read", "proven": True,
                   # An ORDINARY title: matching a URL against this prose is what could never fire.
                   "title": "SQL injection returns database content",
                   "evidence_title": "SQL injection in the q parameter",
                   "evidence_location": "https://a.test/report?q=1"}],
    }

    def _drift(self, subject: str, kind: str = "shape.changed") -> dict:
        return {"deltas": [{"kind": kind, "subject": subject, "score": 70, "label": "changed"}]}

    def test_a_moved_endpoint_flags_the_proof_that_rests_on_it(self) -> None:
        rows = surface_drift.stale_proof_probes(self._drift("https://a.test/report"), [self.CHAIN])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["chain"], "AC1")
        self.assertIn("https://a.test/report", rows[0]["why"])

    def test_an_unrelated_endpoint_flags_nothing(self) -> None:
        self.assertEqual(
            surface_drift.stale_proof_probes(self._drift("https://a.test/other"), [self.CHAIN]), [])

    def test_only_a_confirmed_chain_can_have_a_stale_proof(self) -> None:
        candidate = {**self.CHAIN, "status": "candidate"}
        self.assertEqual(
            surface_drift.stale_proof_probes(self._drift("https://a.test/report"), [candidate]), [])

    def test_the_engine_emits_the_location_the_matcher_needs(self) -> None:
        """Pins the contract between the two modules: without evidence_location on the step the
        matcher has nothing but prose to compare, which is how the feature shipped inert."""
        from bughunter import attack_chain

        result = attack_chain.build_attack_chains([{
            "ref": "F1", "class_id": "sqli", "title": "SQL injection", "severity": "high",
            "location": "https://a.test/report",
            "proof_of_impact": {"status": "confirmed",
                                "observed_result": "the boolean differential held",
                                "control_result": "the control returned the unmodified page"},
        }], {})
        steps = [s for c in result["chains"] for s in c["steps"] if s["evidence_ref"]]
        self.assertTrue(steps)
        for step in steps:
            self.assertEqual(step["evidence_location"], "https://a.test/report")


class DegradedRunTests(unittest.TestCase):
    """"We could not look" must never render as "nothing changed"."""

    def setUp(self) -> None:
        import tempfile
        self._dir = tempfile.TemporaryDirectory()
        self.runtime = self._dir.name

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_a_thin_current_run_is_not_an_all_clear(self) -> None:
        full = {f"https://a.test/p{i}": _obs(f"https://a.test/p{i}") for i in range(20)}
        surface_drift.record_snapshot(self.runtime, program="acme", target="https://a.test/",
                                      host="a.test", observations=full, surface={})
        blocked = surface_drift.build_drift(
            self.runtime, program="acme", target="https://a.test/", host="a.test",
            observations={}, surface={})
        self.assertEqual(blocked["status"], "degraded-run")
        self.assertEqual(blocked["deltas"], [])
        prose = " ".join(surface_drift.summary_lines(blocked)).lower()
        self.assertIn("nothing has been compared", prose)
        for forbidden in ("no change worth chasing", "no changes detected"):
            self.assertNotIn(forbidden, prose)


class NoEgressTests(unittest.TestCase):
    def test_the_module_makes_no_network_call(self) -> None:
        """Zero new requests is this engine's primary safety property, and it is meant to be
        structural rather than enforced — so pin it structurally."""
        source = (BACKEND_DIR / "bughunter" / "surface_drift.py").read_text(encoding="utf-8")
        for forbidden in ("urlopen", "requests.", "http.client", "socket.", "_Http",
                          "web_ingest", "fetch(", "_safe_fetch"):
            self.assertNotIn(forbidden, source,
                             f"the drift engine must never reach the network ({forbidden})")


if __name__ == "__main__":
    unittest.main()
