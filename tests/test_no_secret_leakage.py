"""Adversarial tests for audit item 2: prove that no raw secret value from
scanned source ever appears in any SecureGuard output, across all four
affected rules and every reporter format."""
from __future__ import annotations

import json

from secureguard.baseline import write_baseline
from secureguard.engine import run_scan
from secureguard.reporters.html_reporter import format_html
from secureguard.reporters.json_reporter import format_json
from secureguard.reporters.sarif_reporter import format_sarif
from secureguard.reporters.terminal import format_summary

FAKE_SECRET = "sk-UNIQUE-FAKE-9f8e7d6c5b4a"

_SCENARIOS = {
    "py_sql.py": f'cursor.execute("SELECT * FROM users WHERE token = \'{FAKE_SECRET}\'" + suffix)',
    "py_cmd.py": f'os.system("curl -H \'Authorization: {FAKE_SECRET}\' " + url)',
    "php_sql.php": f'<?php\n$sql = "SELECT * FROM users WHERE token = \'{FAKE_SECRET}\'" . $suffix;\n',
    "php_cmd.php": f'<?php\nsystem("curl -H \'Authorization: {FAKE_SECRET}\' " . $url);\n',
}


def _scan_all(tmp_path):
    for name, content in _SCENARIOS.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    return run_scan(tmp_path)


def test_findings_produced_for_every_scenario(tmp_path):
    summary = _scan_all(tmp_path)
    assert len(summary.findings) == 4


def test_secret_absent_from_every_finding_field(tmp_path):
    summary = _scan_all(tmp_path)
    for finding in summary.findings:
        assert FAKE_SECRET not in finding.evidence
        assert FAKE_SECRET not in finding.explanation
        assert FAKE_SECRET not in finding.remediation
        assert FAKE_SECRET not in finding.evidence_key
        assert FAKE_SECRET not in finding.fingerprint
        assert FAKE_SECRET not in finding.file_path


def test_secret_absent_from_terminal_output(tmp_path):
    assert FAKE_SECRET not in format_summary(_scan_all(tmp_path))


def test_secret_absent_from_json_output(tmp_path):
    output = format_json(_scan_all(tmp_path))
    assert FAKE_SECRET not in output
    json.loads(output)  # still valid JSON


def test_secret_absent_from_html_output(tmp_path):
    assert FAKE_SECRET not in format_html(_scan_all(tmp_path))


def test_secret_absent_from_sarif_output(tmp_path):
    output = format_sarif(_scan_all(tmp_path))
    assert FAKE_SECRET not in output
    json.loads(output)


def test_secret_absent_from_baseline_file(tmp_path):
    summary = _scan_all(tmp_path)
    baseline_path = tmp_path / "baseline.json"
    write_baseline(summary, baseline_path)
    assert FAKE_SECRET not in baseline_path.read_text(encoding="utf-8")