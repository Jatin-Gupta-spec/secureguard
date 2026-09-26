from secureguard.models import Finding, ScanSummary
from secureguard.reporters.html_reporter import format_html


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


def test_output_contains_doctype_and_title():
    html = format_html(ScanSummary())
    assert html.startswith("<!DOCTYPE html>")
    assert "<title>SecureGuard Report</title>" in html


def test_finding_fields_appear_in_output():
    summary = ScanSummary()
    summary.findings.append(make_finding())
    html = format_html(summary)

    assert "PY-SEC-001" in html
    assert "CWE-798" in html
    assert "***redacted***" in html


def test_html_special_characters_are_escaped():
    summary = ScanSummary()
    summary.findings.append(make_finding(explanation='<script>alert("xss")</script>'))
    html = format_html(summary)

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_findings_sorted_by_path_then_line():
    summary = ScanSummary()
    summary.findings.append(make_finding(file_path="b.py", line_number=1))
    summary.findings.append(make_finding(file_path="a.py", line_number=5))
    summary.findings.append(make_finding(file_path="a.py", line_number=2))

    html = format_html(summary)
    positions = [html.index("a.py:2"), html.index("a.py:5"), html.index("b.py:1")]

    assert positions == sorted(positions)


def test_skip_counts_appear_in_output():
    summary = ScanSummary()
    summary.skip_counts["binary"] = 3
    html = format_html(summary)

    assert "binary" in html
    assert "3" in html