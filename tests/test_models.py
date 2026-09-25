import dataclasses

import pytest

from secureguard.models import Finding, ScanSummary


def make_finding(**overrides):
    defaults = dict(
        file_path="src/app.py",
        line_number=10,
        rule_id="PY-SEC-001",
        severity="Medium",
        confidence="Low",
        cwe="CWE-798",
        evidence="***redacted***",
        explanation="Possible hardcoded credential.",
        remediation="Load credentials from environment variables instead.",
        evidence_key="abc123",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_finding_is_frozen():
    finding = make_finding()

    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.severity = "High"


def test_scan_summary_defaults_are_independent():
    a = ScanSummary()
    b = ScanSummary()

    a.skip_counts["binary"] = 1
    a.findings.append(make_finding())

    assert b.skip_counts == {}
    assert b.findings == []


def test_scan_summary_accumulates():
    summary = ScanSummary()
    summary.files_scanned = 3
    summary.findings.append(make_finding())

    assert summary.files_scanned == 3
    assert len(summary.findings) == 1

def test_fingerprint_is_deterministic():
    a = make_finding()
    b = make_finding()
    assert a.fingerprint == b.fingerprint


def test_fingerprint_ignores_line_number():
    a = make_finding(line_number=10)
    b = make_finding(line_number=999)
    assert a.fingerprint == b.fingerprint


def test_fingerprint_differs_for_different_rule():
    a = make_finding(rule_id="PY-SEC-001")
    b = make_finding(rule_id="PY-SQL-001")
    assert a.fingerprint != b.fingerprint


def test_fingerprint_differs_for_different_file():
    a = make_finding(file_path="src/app.py")
    b = make_finding(file_path="src/other.py")
    assert a.fingerprint != b.fingerprint