import json

from secureguard.models import Finding, ScanSummary
from secureguard.reporters.json_reporter import format_json


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
        evidence_key="k1",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_output_is_valid_json():
    summary = ScanSummary()
    summary.files_scanned = 2
    summary.findings.append(make_finding())

    parsed = json.loads(format_json(summary))

    assert parsed["files_scanned"] == 2
    assert len(parsed["findings"]) == 1


def test_findings_sorted_by_path_then_line():
    summary = ScanSummary()
    summary.findings.append(make_finding(file_path="b.py", line_number=1))
    summary.findings.append(make_finding(file_path="a.py", line_number=5))
    summary.findings.append(make_finding(file_path="a.py", line_number=2))

    parsed = json.loads(format_json(summary))
    paths_and_lines = [(f["file_path"], f["line_number"]) for f in parsed["findings"]]

    assert paths_and_lines == sorted(paths_and_lines)


def test_evidence_stays_redacted_in_json():
    summary = ScanSummary()
    summary.findings.append(make_finding(evidence="***redacted***"))

    parsed = json.loads(format_json(summary))

    assert parsed["findings"][0]["evidence"] == "***redacted***"


def test_output_is_deterministic_across_runs():
    summary = ScanSummary()
    summary.files_scanned = 1
    summary.findings.append(make_finding())

    assert format_json(summary) == format_json(summary)


def test_fingerprint_is_included():
    summary = ScanSummary()
    summary.findings.append(make_finding())

    parsed = json.loads(format_json(summary))

    assert "fingerprint" in parsed["findings"][0]
    assert len(parsed["findings"][0]["fingerprint"]) == 16