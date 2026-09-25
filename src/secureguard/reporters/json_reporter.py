"""Deterministic JSON reporting for SecureGuard."""
from __future__ import annotations

import json
from dataclasses import asdict

from secureguard.models import Finding, ScanSummary


def _sort_key(finding: Finding) -> tuple[str, int, str, str]:
    return (finding.file_path, finding.line_number, finding.rule_id, finding.evidence_key)


def to_dict(summary: ScanSummary) -> dict:
    findings = [asdict(f) for f in sorted(summary.findings, key=_sort_key)]
    return {
        "files_scanned": summary.files_scanned,
        "skip_counts": dict(sorted(summary.skip_counts.items())),
        "findings": findings,
    }


def format_json(summary: ScanSummary) -> str:
    return json.dumps(to_dict(summary), indent=2, sort_keys=False)