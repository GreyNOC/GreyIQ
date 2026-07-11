"""Replayable proof-of-exploit artifacts: every confirmed finding's benign crafted request is exported
as a copy-paste replay.sh (curl) and a Burp/devtools-importable findings.har, so a report ships a
machine-replayable reproduction. Requests only — no response bodies embedded (differential-only proof)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty  # noqa: E402


def _item(ref: str, title: str, req_line: str, req_hdr: str = "", status: str = "HTTP 200",
          observed: str = "", plan_poi: bool = False) -> dict:
    finding = {"ref": ref, "title": title, "location": req_line.split(" ", 1)[-1],
               "proof_evidence": {"request_line": req_line, "request_header": req_hdr, "response_status": status}}
    poi = {"observed_result": observed, "control_result": "control differed"} if observed else {}
    item = {"finding": finding, "source_url": finding["location"]}
    if poi:
        item["plan" if plan_poi else "proof_of_impact"] = ({"proof_of_impact": poi} if plan_poi else poi)
    return item


class ReplayScriptTests(unittest.TestCase):
    def test_confirmed_requests_become_runnable_curls(self) -> None:
        items = [
            _item("F1", "Reflected XSS", "GET https://t/q?x=<svg/onload=1>", "Origin: https://evil.example",
                  observed="the payload reflected UNENCODED"),
            _item("B1", "BFLA", "GET https://t/admin/users", "Cookie: <low-priv session>",
                  observed="low-priv reached admin response", plan_poi=True),
            _item("C1", "no request line", ""),   # nothing to replay -> skipped
        ]
        sh, n = bounty.build_replay_script(items)
        self.assertEqual(n, 2)                                    # C1 skipped (no crafted request)
        self.assertTrue(sh.startswith("#!/usr/bin/env bash"))
        self.assertIn("curl -i -H 'Origin: https://evil.example' 'https://t/q?x=<svg/onload=1>'", sh)
        self.assertIn("curl -i https://t/admin/users", sh)
        self.assertIn("observed: the payload reflected UNENCODED", sh)  # the differential rides as a comment
        self.assertNotIn("<low-priv session>", sh)               # placeholder auth header is NOT emitted as -H

    def test_no_confirmed_requests_is_empty(self) -> None:
        sh, n = bounty.build_replay_script([_item("C1", "x", "")])
        self.assertEqual((sh, n), ("", 0))

    def test_multi_step_and_placeholder_request_lines_are_not_runnable(self) -> None:
        # Several engine producers emit request_line as a multi-step / placeholder DESCRIPTION, not a
        # single runnable request: mass-assignment/BFLA, broken-session, blind-XXE, stored-XSS, and
        # GraphQL introspection. Each has a target with internal whitespace or a '...' placeholder, so
        # it must NOT become a (malformed) curl — otherwise replay.sh ships a line curl rejects.
        items = [
            _item("A1", "mass-assign", 'PATCH https://h/x  (body: {"admin": true})  then  GET https://h/x'),
            _item("A2", "broken-session", "GET https://h/x (session)  ->  logout  ->  GET https://h/x (SAME session)"),
            _item("A3", "blind-xxe", "POST https://h/x  (Content-Type: application/xml)"),
            _item("A4", "stored-xss", "POST https://h/inject (c=<payload>)  then  GET https://h/view"),
            _item("A5", "graphql-introspection", "GET https://h/graphql?query={__schema...}"),
        ]
        sh, n = bounty.build_replay_script(items)
        self.assertEqual((sh, n), ("", 0))                       # none is a single runnable request
        # Genuinely runnable single-URL lines still replay: an inline XSS payload, AND a path-traversal
        # payload whose '....' dot runs must NOT be mistaken for an ellipsis placeholder.
        ok = _item("F1", "reflected-xss", "GET https://h/q?x=<svg/onload=1>")
        lfi = _item("F2", "path-traversal", "GET https://h/f?p=....//....//....//etc/passwd")
        sh2, n2 = bounty.build_replay_script([ok, lfi] + items)
        self.assertEqual(n2, 2)                                  # F1 + F2, the multi-step ones stay excluded
        self.assertIn("curl -i 'https://h/q?x=<svg/onload=1>'", sh2)
        self.assertIn("curl -i 'https://h/f?p=....//....//....//etc/passwd'", sh2)

    def test_single_url_target_predicate(self) -> None:
        # The shared gate _curl_from_evidence and build_findings_har both use.
        self.assertEqual(bounty._single_url_target("GET https://h/a?x=1"), "https://h/a?x=1")
        self.assertEqual(bounty._single_url_target("GET https://h/q?x=<svg/onload=1>"), "https://h/q?x=<svg/onload=1>")
        self.assertEqual(bounty._single_url_target("PATCH https://h/x  then  GET https://h/x"), "")   # whitespace
        self.assertEqual(bounty._single_url_target("GET https://h/g?query={__schema...}"), "")        # ellipsis placeholder
        self.assertEqual(bounty._single_url_target("GET HTTP://h/x"), "")                              # scheme case-sensitive
        self.assertEqual(bounty._single_url_target("GET /relative"), "")                              # not absolute
        self.assertEqual(bounty._single_url_target(""), "")
        # A path-traversal payload uses LONGER dot runs ('....'), not a truncation ellipsis — it is a
        # genuine single runnable URL and must NOT be rejected as a placeholder.
        self.assertEqual(bounty._single_url_target("GET https://h/f?p=....//....//....//etc/passwd"),
                         "https://h/f?p=....//....//....//etc/passwd")
        self.assertEqual(bounty._single_url_target("GET https://h/f?p=../../../../etc/passwd"),
                         "https://h/f?p=../../../../etc/passwd")

    def test_a_detected_secret_in_a_request_is_redacted(self) -> None:
        # belt-and-suspenders: if a crafted request line somehow carries a real token, redact it
        items = [_item("F1", "leak", "GET https://t/cb?token=ghp_" + "A" * 36)]
        sh, n = bounty.build_replay_script(items)
        self.assertEqual(n, 1)
        self.assertNotIn("ghp_" + "A" * 36, sh)                  # the token does not survive into replay.sh


class FindingsHarTests(unittest.TestCase):
    def test_valid_har_of_crafted_requests_only(self) -> None:
        items = [
            _item("F1", "Reflected XSS", "GET https://t/q?x=1", "Origin: https://evil.example",
                  status="HTTP 200", observed="payload reflected"),
            _item("B1", "BFLA", "GET https://t/admin", "Cookie: <session>", status="403"),
            _item("C1", "no line", ""),   # skipped
        ]
        har, n = bounty.build_findings_har(items, version="9.9.9", generated_at="2026-07-04T12:00:00Z")
        self.assertEqual(n, 2)
        json.dumps(har)                                          # serializable / valid shape
        self.assertEqual(har["log"]["version"], "1.2")
        e0 = har["log"]["entries"][0]
        self.assertEqual(e0["request"]["url"], "https://t/q?x=1")
        self.assertEqual(e0["request"]["method"], "GET")
        self.assertEqual(e0["request"]["headers"][0], {"name": "Origin", "value": "https://evil.example"})
        self.assertEqual([{"name": "x", "value": "1"}], e0["request"]["queryString"])
        self.assertEqual(e0["response"]["status"], 200)
        self.assertEqual(har["log"]["entries"][1]["response"]["status"], 403)   # status parsed from "403"
        # placeholder auth header is not embedded, and no response BODY is embedded (only the differential)
        self.assertEqual(har["log"]["entries"][1]["request"]["headers"], [])
        self.assertEqual(e0["response"]["content"]["text"], "payload reflected")

    def test_empty_input_is_a_valid_empty_har(self) -> None:
        har, n = bounty.build_findings_har([])
        self.assertEqual(n, 0)
        self.assertEqual(har["log"]["entries"], [])
        json.dumps(har)

    def test_multi_step_and_placeholder_lines_produce_no_har_entries(self) -> None:
        # Parity with build_replay_script: a multi-step / placeholder request_line is a description,
        # not a request, so it must not become a (malformed) HAR entry either.
        items = [
            _item("A1", "mass-assign", 'PATCH https://h/x  (body: {"admin": true})  then  GET https://h/x'),
            _item("A2", "graphql", "GET https://h/graphql?query={__schema...}"),
        ]
        har, n = bounty.build_findings_har(items)
        self.assertEqual(n, 0)
        self.assertEqual(har["log"]["entries"], [])

    def test_a_secret_in_the_request_url_or_header_is_redacted_in_the_har(self) -> None:
        # QAQC: a secret riding in a crafted request's URL/header must NOT leak into findings.har (the
        # same guarantee replay.sh gives) — parity with build_replay_script's redaction.
        tok = "ghp_" + "A" * 36
        items = [_item("F1", "leak", f"GET https://t/cb?access_token={tok}&q=x", f"Authorization: Bearer {tok}")]
        har, n = bounty.build_findings_har(items)
        self.assertEqual(n, 1)
        blob = json.dumps(har)
        self.assertNotIn(tok, blob)                              # not in url, queryString, or header value
        e = har["log"]["entries"][0]
        self.assertNotIn(tok, e["request"]["url"])
        self.assertNotIn(tok, e["request"]["headers"][0]["value"])
        self.assertTrue(all(tok not in q["value"] for q in e["request"]["queryString"]))


if __name__ == "__main__":
    unittest.main()
