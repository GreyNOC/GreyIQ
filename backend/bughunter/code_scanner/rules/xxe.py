"""XML external entity (XXE) source sinks.

Parsing untrusted XML with a parser that resolves external entities (or a DTD) lets
an attacker read local files, SSRF, or DoS. We flag the unsafe parser construction
where a safe-config token is NOT on the same line; HIGH severity, LOW/MEDIUM
confidence (XXE is config-dependent, so these are leads to verify the parser setup).
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

# (rule_id, title, desc, severity, confidence, languages, remediation, pattern, must_not_contain)
_RAW = [
    (
        "py.lxml-etree-parse",
        "Python lxml etree.parse/fromstring without a hardened parser",
        "lxml.etree.parse/fromstring resolves entities/DTDs by default; on untrusted XML this is XXE.",
        Severity.HIGH, Confidence.LOW, ("python",),
        "Parse with an etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False).",
        r"\betree\s*\.\s*(?:parse|fromstring)\s*\(",
        ("resolve_entities", "no_network", "load_dtd", "defusedxml"),
    ),
    (
        "py.xml-sax-parse",
        "Python xml.sax / minidom / pulldom parse of untrusted XML",
        "The stdlib xml.* parsers resolve external entities unless explicitly disabled — XXE on untrusted input.",
        Severity.HIGH, Confidence.LOW, ("python",),
        "Use defusedxml, or disable external entities / DTDs on the parser before parsing untrusted XML.",
        r"\b(?:xml\.sax\.parse|xml\.dom\.minidom\.parse(?:String)?|parseString)\s*\(",
        ("defusedxml", "forbid_dtd", "feature_external_ges"),
    ),
    (
        "php.simplexml-load",
        "PHP simplexml_load_string / DOMDocument->loadXML on untrusted XML",
        "Loading XML without LIBXML_NONET / disabled entity loading exposes XXE (file read, SSRF).",
        Severity.HIGH, Confidence.LOW, ("php",),
        "Pass LIBXML_NONET and disable external entity loading (libxml_disable_entity_loader on old PHP).",
        r"\b(?:simplexml_load_string|->\s*loadXML)\s*\(",
        ("libxml_nonet", "disable_entity"),
    ),
    (
        "java.documentbuilderfactory",
        "Java DocumentBuilderFactory / SAXParserFactory without DTD hardening",
        "An XML factory that doesn't disallow doctype declarations / external entities is an XXE sink.",
        Severity.HIGH, Confidence.LOW, ("java",),
        "Set factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) (and disable external entities).",
        r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s*\.\s*newInstance\s*\(",
        ("disallow-doctype-decl", "is_supporting_external_entities", "xxe"),
    ),
]


RULES = tuple(
    RegexRule(
        rule_id=rid, title=title, description=desc, severity=sev, confidence=conf,
        category="xxe", remediation=remed, languages=langs, pattern=pat,
        flags=re.MULTILINE, line_must_not_contain=mnc,
    )
    for rid, title, desc, sev, conf, langs, remed, pat, mnc in _RAW
)
