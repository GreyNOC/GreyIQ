"""Tests for the brain-only per-lead research dossier.

No brain is configured in the test, so these exercise the deterministic offline path
(which must always produce a usable dossier) plus the JSON extraction + rendering. The
brain path reuses coder.generate, covered elsewhere.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import research  # noqa: E402


def _ctx_finding():
    ctx = {
        "target": "https://app.example.com/",
        "scope": "app.example.com",
        "attack_plans": {"F1": {
            "steps": ["Visit the endpoint.", "Inject the marker."],
            "proof_of_impact": {"proof_obligation": "Capture the unescaped reflection in the response."},
        }},
    }
    finding = {
        "ref": "F1", "title": "Reflected XSS via 'q'", "severity": "high",
        "class_id": "xss", "class_name": "Cross-site scripting (XSS)", "cwe": "CWE-79",
        "owasp": "A03:2021 Injection", "location": "https://app.example.com/?q=",
        "description": "The 'q' parameter reflects without encoding.",
    }
    return ctx, finding


class DeterministicDossierTests(unittest.TestCase):
    def test_dossier_without_brain_is_complete(self) -> None:
        ctx, finding = _ctx_finding()
        d = research.build_dossier(finding, ctx, None)   # no brain configured
        self.assertFalse(d["used_brain"])
        s = d["structured"]
        self.assertTrue(s["summary"])
        self.assertTrue(s["why_it_matters"])
        self.assertTrue(s["how_to_confirm"])                       # always has steps
        self.assertTrue(s["references"])                           # impact-model floor
        # The plan's proof obligation is folded into the confirm steps.
        self.assertTrue(any("proof obligation" in step.lower() for step in s["how_to_confirm"]))

    def test_markdown_has_the_sections(self) -> None:
        ctx, finding = _ctx_finding()
        md = research.build_dossier(finding, ctx, {})["markdown"]   # {} == brain off
        for heading in ("Research dossier", "Summary", "Why it matters", "Plan to confirm", "Residual risk"):
            self.assertIn(heading, md)
        self.assertIn("CWE-79", md)
        self.assertIn("Deterministic", md)   # labels that no brain was used

    def test_handles_finding_with_no_class(self) -> None:
        d = research.build_dossier({"ref": "F1", "title": "Mystery", "severity": "low"},
                                   {"target": "https://h/", "attack_plans": {}}, None)
        self.assertTrue(d["structured"]["summary"])
        self.assertTrue(d["markdown"].strip())


class JsonExtractionTests(unittest.TestCase):
    def test_parses_object_amid_prose_and_fences(self) -> None:
        text = 'Sure!\n```json\n{"summary": "x", "references": ["https://a"]}\n```\nhope that helps'
        obj = research._parse_json_object(text)
        self.assertEqual(obj["summary"], "x")

    def test_returns_none_on_garbage(self) -> None:
        self.assertIsNone(research._parse_json_object("no json here"))
        self.assertIsNone(research._parse_json_object(""))


if __name__ == "__main__":
    unittest.main()
