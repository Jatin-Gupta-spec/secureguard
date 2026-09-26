from secureguard.models import Finding
from secureguard.suppressions import filter_suppressed, find_suppressed_lines


def make_finding(**overrides):
    defaults = dict(
        file_path="src/app.py",
        line_number=1,
        rule_id="PY-SEC-001",
        severity="Medium",
        confidence="Low",
        cwe="CWE-798",
        evidence="***redacted***",
        explanation="x",
        remediation="x",
        evidence_key="k1",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_no_markers_returns_empty_dict():
    assert find_suppressed_lines("password = 'x'\nother = 'y'") == {}


def test_bare_marker_suppresses_all_rules_on_that_line():
    content = 'password = "hunter2"  # secureguard: ignore'
    assert find_suppressed_lines(content) == {1: None}


def test_rule_specific_marker_parsed():
    content = 'password = "hunter2"  # secureguard: ignore[PY-SEC-001]'
    assert find_suppressed_lines(content) == {1: {"PY-SEC-001"}}


def test_multiple_rules_in_marker():
    content = 'x = "y"  # secureguard: ignore[PY-SEC-001, PY-SQL-001]'
    assert find_suppressed_lines(content) == {1: {"PY-SEC-001", "PY-SQL-001"}}


def test_filter_removes_bare_suppressed_finding():
    finding = make_finding(line_number=1)
    assert filter_suppressed([finding], {1: None}) == []


def test_filter_removes_matching_rule_specific_finding():
    finding = make_finding(line_number=1, rule_id="PY-SEC-001")
    assert filter_suppressed([finding], {1: {"PY-SEC-001"}}) == []


def test_filter_keeps_non_matching_rule_specific_finding():
    finding = make_finding(line_number=1, rule_id="PY-SQL-001")
    assert filter_suppressed([finding], {1: {"PY-SEC-001"}}) == [finding]


def test_filter_keeps_finding_on_unsuppressed_line():
    finding = make_finding(line_number=5)
    assert filter_suppressed([finding], {1: None}) == [finding]