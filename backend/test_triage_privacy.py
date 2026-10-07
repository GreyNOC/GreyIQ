"""Remote triage must receive coarse metadata, never raw scan evidence."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import triage  # noqa: E402


class RemoteTriagePrivacyTests(unittest.TestCase):
    def test_outgoing_json_contains_only_allowlisted_finding_metadata(self) -> None:
        secret = "raw-private-credential-7e5ad6"
        token = "target-url-token-8bdfe1"
        result = {
            "ok": True,
            "scan_type": "web",
            "target": f"https://user:{secret}@example.test/private/{secret}?token={token}#{secret}",
            "risk": "high",
            "findings": [{
                "rule_id": f"secret.{secret}",
                "severity": "high",
                "confidence": "medium",
                "category": "secret",
                "secret_classification": "candidate_unverified",
                "secret_value": secret,
                "title": f"Token {secret} at https://example.test/?token={token}",
                "description": f"Response included {secret}",
                "snippet": f"Authorization: Bearer {secret}",
                "remediation": f"Rotate {secret}",
                "file_path": f"https://example.test/private/{secret}?token={token}",
                "location": f"https://example.test/?token={token}",
                "proof_evidence": {"response_header": f"Set-Cookie: session={secret}"},
                "_credential_proof": {"response_excerpt": f"key={secret}"},
            }],
        }
        request_bodies: list[dict[str, object]] = []

        def fake_urlopen(request: object, timeout: float) -> io.BytesIO:
            del timeout
            request_bodies.append(json.loads(request.data.decode("utf-8")))  # type: ignore[attr-defined]
            return io.BytesIO(b'{"choices":[{"message":{"content":"Review candidate"}}]}')

        config = {"remote_enabled": True, "remote_url": "http://model.test", "remote_model": "local-model"}
        with mock.patch.object(triage.urllib.request, "urlopen", side_effect=fake_urlopen):
            self.assertEqual(triage.remote_triage(result, config), "Review candidate")

        self.assertEqual(len(request_bodies), 1)
        outgoing = json.dumps(request_bodies[0])
        self.assertNotIn(secret, outgoing)
        self.assertNotIn(token, outgoing)
        self.assertNotIn("example.test", outgoing)
        self.assertNotIn("Authorization: Bearer", outgoing)
        self.assertNotIn("Set-Cookie", outgoing)

        prompt = request_bodies[0]["messages"][0]["content"]  # type: ignore[index]
        metadata = json.loads(prompt.split("Findings JSON:\n", 1)[1])
        self.assertEqual(metadata, {
            "scan_type": "web",
            "risk": "high",
            "findings": [{
                "index": 1,
                "severity": "low",
                "confidence": "medium",
                "category": "secret",
                "rule_family": "secret",
                "secret_classification": "candidate_unverified",
            }],
        })

    def test_arbitrary_labels_are_replaced_and_local_evidence_is_unchanged(self) -> None:
        sentinel = "untrusted-raw-secret-3b2f7e"
        finding = {
            "rule_id": sentinel,
            "severity": sentinel,
            "confidence": sentinel,
            "category": sentinel,
            "title": sentinel,
            "snippet": sentinel,
            "file_path": sentinel,
        }
        result = {"ok": True, "scan_type": sentinel, "risk": sentinel, "target": sentinel,
                  "findings": [finding]}
        local_before = triage.summarize_findings(result)
        citations_before = triage._citations(result)
        view = triage._remote_triage_view(result)
        self.assertNotIn(sentinel, json.dumps(view))
        self.assertEqual(view["findings"][0]["severity"], "unknown")
        self.assertEqual(view["findings"][0]["category"], "unknown")
        self.assertEqual(triage.summarize_findings(result), local_before)
        self.assertEqual(triage._citations(result), citations_before)

    def test_known_scanner_category_is_preserved_as_fixed_label(self) -> None:
        view = triage._remote_triage_view({"findings": [
            {"rule_id": "py.sql-execute-format", "severity": "high", "category": "sqli"},
        ]})
        self.assertEqual(view["findings"][0]["category"], "sqli")


if __name__ == "__main__":
    unittest.main()
