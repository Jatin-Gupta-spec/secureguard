"""Deterministic JSON reporting for SecureGuard."""
from __future__ import annotations

import json

from secureguard.models import Finding, ScanSummary


def _sort_key(finding: Finding) -> tuple[str, int, str, str]:
    return (finding.file_path, finding.line_number, finding.rule_id, finding.evidence_key)


def _public_dict(finding: Finding) -> dict:
    return {
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "cwe": finding.cwe,
        "evidence": finding.evidence,
        "explanation": finding.explanation,
        "remediation": finding.remediation,
        "fingerprint": finding.fingerprint,
    }


def to_dict(summary: ScanSummary) -> dict:
    findings = [_public_dict(f) for f in sorted(summary.findings, key=_sort_key)]
    return {
        "files_scanned": summary.files_scanned,
        "skip_counts": dict(sorted(summary.skip_counts.items())),
        "findings": findings,
    }


def format_json(summary: ScanSummary) -> str:
    return json.dumps(to_dict(summary), indent=2, sort_keys=False)