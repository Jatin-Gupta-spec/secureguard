from secureguard.models import Finding, ScanSummary
from secureguard.reporters.terminal import format_summary


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


def test_findings_sorted_by_path_then_line():
    summary = ScanSummary()
    summary.findings.append(make_finding(file_path="b.py", line_number=1))
    summary.findings.append(make_finding(file_path="a.py", line_number=5))
    summary.findings.append(make_finding(file_path="a.py", line_number=2))

    output = format_summary(summary)
    positions = [output.index("a.py:2"), output.index("a.py:5"), output.index("b.py:1")]

    assert positions == sorted(positions)


def test_summary_includes_scan_and_skip_counts():
    summary = ScanSummary()
    summary.files_scanned = 4
    summary.skip_counts["binary"] = 2

    output = format_summary(summary)

    assert "Scanned 4 file(s)." in output
    assert "Skipped 2 file(s): binary" in output


def test_finding_shows_masked_evidence():
    summary = ScanSummary()
    summary.findings.append(make_finding(evidence="***redacted***"))

    output = format_summary(summary)

    assert "***redacted***" in output