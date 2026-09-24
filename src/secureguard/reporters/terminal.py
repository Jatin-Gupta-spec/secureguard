"""Deterministic terminal reporting for SecureGuard."""
from __future__ import annotations

from secureguard.models import Finding, ScanSummary


def _sort_key(finding: Finding) -> tuple[str, int, str, str]:
    return (finding.file_path, finding.line_number, finding.rule_id, finding.evidence_key)


def format_finding(finding: Finding) -> str:
    lines = [
        f"{finding.file_path}:{finding.line_number}: {finding.rule_id} "
        f"[{finding.severity}/{finding.confidence}] {finding.cwe}",
        f"  Evidence: {finding.evidence}",
        f"  {finding.explanation}",
        f"  Fix: {finding.remediation}",
    ]
    return "\n".join(lines)


def format_summary(summary: ScanSummary) -> str:
    lines: list[str] = []

    for finding in sorted(summary.findings, key=_sort_key):
        lines.append(format_finding(finding))

    lines.append(f"Scanned {summary.files_scanned} file(s).")
    for reason, count in sorted(summary.skip_counts.items()):
        lines.append(f"Skipped {count} file(s): {reason}")

    return "\n".join(lines)