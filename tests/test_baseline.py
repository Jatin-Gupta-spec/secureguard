from secureguard.baseline import apply_baseline, load_baseline_fingerprints, write_baseline
from secureguard.models import Finding, ScanSummary
from secureguard.engine import run_scan


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


def test_load_missing_baseline_returns_empty_set(tmp_path):
    missing = tmp_path / "does_not_exist.json"
    assert load_baseline_fingerprints(missing) == set()


def test_load_malformed_json_returns_empty_set(tmp_path):
    bad = tmp_path / "baseline.json"
    bad.write_text("{not valid json", encoding="utf-8")
    assert load_baseline_fingerprints(bad) == set()


def test_load_non_dict_json_returns_empty_set(tmp_path):
    bad = tmp_path / "baseline.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    assert load_baseline_fingerprints(bad) == set()


def test_write_then_load_round_trip(tmp_path):
    summary = ScanSummary()
    finding = make_finding()
    summary.findings.append(finding)
    out = tmp_path / "baseline.json"

    write_baseline(summary, out)
    loaded = load_baseline_fingerprints(out)

    assert loaded == {finding.fingerprint}


def test_apply_baseline_removes_known_finding():
    summary = ScanSummary()
    finding = make_finding()
    summary.findings.append(finding)

    filtered = apply_baseline(summary, {finding.fingerprint})

    assert filtered.findings == []
    assert filtered.files_scanned == summary.files_scanned


def test_apply_baseline_keeps_unknown_finding():
    summary = ScanSummary()
    finding = make_finding()
    summary.findings.append(finding)

    filtered = apply_baseline(summary, {"some-other-fingerprint"})

    assert filtered.findings == [finding]


def test_baseline_file_never_contains_raw_secret(tmp_path):
    summary = ScanSummary()
    summary.findings.append(make_finding())
    out = tmp_path / "baseline.json"

    write_baseline(summary, out)

    assert "hunter2" not in out.read_text(encoding="utf-8")

def test_baseline_does_not_collide_for_same_structural_evidence_different_lines(tmp_path):
    """The exact scenario audit item 4 is about: two SQL findings in the
    same file, on different lines, sharing the same STRUCTURAL
    evidence_key (both "sql-select", since audit item 2 made SQL/CMD
    evidence non-literal). Baselining one must never silently suppress
    the other."""
    php_file = tmp_path / "app.php"
    php_file.write_text(
        '<?php\n'
        '$sql1 = "SELECT * FROM users WHERE id = " . $id;\n'
        '$sql2 = "SELECT * FROM orders WHERE id = " . $oid;\n',
        encoding="utf-8",
    )

    first_scan = run_scan(tmp_path)
    assert len(first_scan.findings) == 2

    baseline_path = tmp_path / "baseline.json"
    single_finding_summary = ScanSummary(findings=[first_scan.findings[0]])
    write_baseline(single_finding_summary, baseline_path)

    known = load_baseline_fingerprints(baseline_path)
    filtered = apply_baseline(first_scan, known)

    assert len(filtered.findings) == 1
    assert filtered.findings[0].line_number == first_scan.findings[1].line_number