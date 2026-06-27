"""Tests for the static SQLi + SSRF sink rule packs (zero egress, source-only)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.code_scanner.rules.sqli import RULES as SQLI_RULES  # noqa: E402
from bughunter.code_scanner.rules.ssrf import RULES as SSRF_RULES  # noqa: E402


def _hits(rules, text: str, lang: str, path: str = "f.src") -> list[str]:
    out: list[str] = []
    for rule in rules:
        if rule.applies_to(lang, path):
            out.extend(f.rule_id for f in rule.scan(path=path, text=text))
    return out


class SqliRuleTests(unittest.TestCase):
    def test_fstring_execute_is_flagged(self) -> None:
        self.assertIn("py.sql-execute-format", _hits(SQLI_RULES, 'cursor.execute(f"SELECT * FROM u WHERE n = {name}")', "python"))

    def test_concatenated_execute_is_flagged(self) -> None:
        self.assertIn("py.sql-execute-format", _hits(SQLI_RULES, 'db.execute("SELECT * FROM u WHERE n = " + name)', "python"))

    def test_parameterized_execute_is_safe(self) -> None:
        # The canonical safe form must NOT be flagged.
        self.assertEqual(_hits(SQLI_RULES, 'cursor.execute("SELECT * FROM u WHERE n = %s", (name,))', "python"), [])

    def test_constant_sql_is_safe(self) -> None:
        self.assertEqual(_hits(SQLI_RULES, 'cursor.execute("SELECT 1")', "python"), [])

    def test_django_raw_interpolation_flagged(self) -> None:
        self.assertIn("py.django-raw-extra", _hits(SQLI_RULES, 'User.objects.raw(f"SELECT * FROM u WHERE id = {uid}")', "python"))

    def test_node_template_literal_query_flagged(self) -> None:
        self.assertIn("js.sql-query-template", _hits(SQLI_RULES, "db.query(`SELECT * FROM u WHERE id=${id}`)", "javascript", "f.js"))

    def test_go_sprintf_query_flagged(self) -> None:
        self.assertIn("go.sql-sprintf", _hits(SQLI_RULES, 'db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", id))', "go", "f.go"))


class SsrfRuleTests(unittest.TestCase):
    def test_requests_variable_url_flagged(self) -> None:
        self.assertIn("py.requests-variable-url", _hits(SSRF_RULES, "r = requests.get(user_url)", "python"))

    def test_requests_fstring_url_flagged(self) -> None:
        self.assertIn("py.requests-variable-url", _hits(SSRF_RULES, 'requests.get(f"https://{host}/x")', "python"))

    def test_requests_literal_url_is_safe(self) -> None:
        self.assertEqual(_hits(SSRF_RULES, 'requests.get("https://api.example.com/x")', "python"), [])

    def test_urlopen_variable_flagged(self) -> None:
        self.assertIn("py.urlopen-variable-url", _hits(SSRF_RULES, "urllib.request.urlopen(target)", "python"))

    def test_node_fetch_and_axios_variable_flagged(self) -> None:
        hits = _hits(SSRF_RULES, "const r = await fetch(req.query.url); axios.get(targetUrl);", "javascript", "f.js")
        self.assertIn("js.fetch-variable-url", hits)
        self.assertIn("js.axios-variable-url", hits)

    def test_ssrf_findings_are_low_confidence_leads(self) -> None:
        # SSRF sinks are HIGH severity but LOW confidence (the first arg is often a
        # benign constant) — honest leads, not confirmed bugs.
        for rule in SSRF_RULES:
            self.assertEqual(rule.confidence.value, "low", rule.rule_id)
            self.assertEqual(rule.severity.value, "high", rule.rule_id)


if __name__ == "__main__":
    unittest.main()
