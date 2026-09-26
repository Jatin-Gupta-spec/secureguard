"""SARIF 2.1.0 reporting for SecureGuard - the format GitHub Code Scanning
and similar CI tools consume."""
from __future__ import annotations

import json

from secureguard.models import Finding, ScanSummary
from secureguard.rules.catalog import ALL_RULES

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SEVERITY_TO_LEVEL = {"High": "error", "Medium": "warning", "Low": "note"}


def _sort_key(finding: Finding) -> tuple[str, int, str, str]:
    return (finding.file_path, finding.line_number, finding.rule_id, finding.evidence_key)


def _rule_descriptor(rule_id: str) -> dict:
    meta = ALL_RULES.get(rule_id)
    if meta is None:
        return {"id": rule_id, "name": rule_id}
    return {
        "id": meta.rule_id,
        "name": meta.rule_id,
        "shortDescription": {"text": meta.explanation},
        "fullDescription": {"text": meta.rationale},
        "help": {"text": f"{meta.fix} Safe example: {meta.safe_example}"},
        "properties": {"cwe": meta.cwe},
    }


def _result(finding: Finding) -> dict:
    return {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
        "message": {
            "text": f"{finding.explanation} Evidence: {finding.evidence} {finding.remediation}"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line_number},
                }
            }
        ],
        "partialFingerprints": {"secureguardFingerprint": finding.fingerprint},
    }


def to_dict(summary: ScanSummary) -> dict:
    findings = sorted(summary.findings, key=_sort_key)
    used_rule_ids = sorted({f.rule_id for f in findings})

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureGuard",
                        "informationUri": "https://github.com/Jatin-Gupta-spec/secureguard",
                        "rules": [_rule_descriptor(rid) for rid in used_rule_ids],
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }


def format_sarif(summary: ScanSummary) -> str:
    return json.dumps(to_dict(summary), indent=2)