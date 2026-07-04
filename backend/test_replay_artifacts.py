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
