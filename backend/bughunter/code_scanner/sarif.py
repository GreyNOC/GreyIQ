"""SARIF v2.1.0 export.

Converts a ``ScanResult`` into a Static Analysis Results Interchange
Format document so findings can be loaded into GitHub Code Scanning,
VS Code's Problems pane, Azure DevOps, and most security workflows.
Schema reference:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html
"""

from __future__ import annotations

from typing import Any

from bughunter.code_scanner.model import ScanResult, Severity
from bughunter.code_scanner.rules import ALL_RULES

_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules_payload: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rule in ALL_RULES:
        if rule.rule_id in seen:
            continue
        seen.add(rule.rule_id)
        rules_payload.append(
            {
                "id": rule.rule_id,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "helpUri": "",
                "properties": {
                    "category": rule.category,
                    "severity": rule.severity.value,
                    "remediation": rule.remediation,
                },
            }
        )

    results_payload: list[dict[str, Any]] = []
    for finding in result.findings:
        results_payload.append(
            {
                "ruleId": finding.rule_id,
                "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {
                                "startLine": finding.line_start,
                                "endLine": finding.line_end,
                                "snippet": {"text": finding.snippet},
                            },
                        }
                    }
                ],
                "properties": {
                    "category": finding.category,
                    "confidence": finding.confidence.value,
                    "remediation": finding.remediation,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GreyNOC Slop Detection",
                        "version": result.algorithm,
                        "informationUri": "https://github.com/GreyNOC/GN-SLOP-DETECTION",
                        "rules": rules_payload,
                    }
                },
                "results": results_payload,
                "properties": {
                    "target": result.target,
                    "targetType": result.target_type.value,
                    "filesScanned": result.files_scanned,
                    "bytesScanned": result.bytes_scanned,
                    "score": result.score,
                    "risk": result.risk,
                },
            }
        ],
    }
