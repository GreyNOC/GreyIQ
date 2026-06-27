"""Raw-SQL / SQL-injection sink primitives.

These flag a query built by string-formatting (f-string, %, +, .format, template
literal) handed to a database execute call — the canonical SQL-injection sink the
moment any attacker-influenced value reaches the formatted string. Like the
command-injection pack, we flag the SINK, not a proven data flow: a fast static
check that catches real bugs, with reachability left for the operator to confirm
(severity high, confidence medium). Parameterized calls — execute(sql, (x,)) — and
constant SQL do not match.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_RULES_RAW = [
    # ---------- Python (DB-API: cursor/conn/db.execute(many)) ----------
    (
        "py.sql-execute-format",
        "Python DB execute() with a formatted SQL string",
        "cursor/conn/db.execute(...) given an f-string, %-format, concatenation, or .format() builds the query from untrusted text — a SQL-injection sink. Parameterized execute(sql, params) is safe and does not match.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "sqli",
        "Use parameter substitution: cursor.execute('... WHERE id = %s', (value,)). Never build SQL with f-strings/%/+/.format.",
        ("python",),
        r"(?:cursor|conn|connection|db|session)\s*\.\s*execute(?:many)?\s*\(\s*[fF]?[\"'].*(?:\{|%s.*%|%\s*\(|\"\s*\+|'\s*\+|\.format\s*\()",
    ),
    (
        "py.django-raw-extra",
        "Django .raw() / .extra() with interpolation",
        "QuerySet.raw() and .extra() take raw SQL; building them with f-strings/%/+ exposes SQL injection.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "sqli",
        "Pass params=[...] to .raw()/.extra() and use %s placeholders, or use the ORM.",
        ("python",),
        r"\.\s*(?:raw|extra)\s*\(\s*[fF]?[\"'].*(?:\{|%s.*%|\"\s*\+|'\s*\+|\.format\s*\()",
    ),
    # ---------- JavaScript / TypeScript ----------
    (
        "js.sql-query-template",
        "Node DB query() with a template literal / concatenation",
        "db.query(`SELECT ... ${x}`) or query('SELECT ...' + x) interpolates untrusted text straight into SQL.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "sqli",
        "Use parameterized queries: db.query('SELECT ... WHERE id = ?', [x]) (or $1 placeholders for pg).",
        ("javascript", "typescript"),
        r"\.\s*(?:query|execute)\s*\(\s*`[^`]*\$\{",
    ),
    (
        "js.sequelize-raw-concat",
        "Sequelize query() with concatenated SQL",
        "sequelize.query('SELECT ...' + input) bypasses the ORM's escaping.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "sqli",
        "Use replacements/bind: sequelize.query('... :id', { replacements: { id } }).",
        ("javascript", "typescript"),
        r"\.\s*query\s*\(\s*[\"'][^\"']*[\"']\s*\+",
    ),
    # ---------- Go ----------
    (
        "go.sql-sprintf",
        "Go db.Query/Exec built with fmt.Sprintf",
        "db.Query(fmt.Sprintf(\"... %s\", x)) formats untrusted input into SQL; use placeholders.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "sqli",
        "Use db.Query(\"... WHERE id = $1\", x) with driver placeholders, never fmt.Sprintf.",
        ("go",),
        r"\.\s*(?:Query|QueryRow|Exec)(?:Context)?\s*\(\s*fmt\.Sprintf\s*\(",
    ),
    # ---------- PHP ----------
    (
        "php.mysqli-superglobal",
        "PHP SQL query interpolating a request superglobal",
        "mysqli_query/->query with $_GET/$_POST/$_REQUEST concatenated into the SQL is classic SQL injection.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "sqli",
        "Use prepared statements (mysqli/PDO) with bound parameters.",
        ("php",),
        r"(?:mysqli_query|->\s*query)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)\b",
    ),
]


RULES = tuple(
    RegexRule(
        rule_id=rid,
        title=title,
        description=desc,
        severity=sev,
        confidence=conf,
        category=cat,
        remediation=remed,
        languages=langs,
        pattern=pat,
        flags=re.MULTILINE,
    )
    for rid, title, desc, sev, conf, cat, remed, langs, pat in _RULES_RAW
)
