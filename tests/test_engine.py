from secureguard.engine import run_scan


def test_engine_detects_php_sec_001(tmp_path):
    php_file = tmp_path / "config.php"
    php_file.write_text('$password = "hunter2";', encoding="utf-8")

    summary = run_scan(tmp_path)

    assert summary.files_scanned == 1
    assert len(summary.findings) == 1
    finding = summary.findings[0]
    assert finding.rule_id == "PHP-SEC-001"
    assert finding.file_path == "config.php"
    assert "hunter2" not in finding.evidence


def test_engine_ignores_py_files_for_php_rules(tmp_path):
    py_file = tmp_path / "app.py"
    py_file.write_text('password = "hunter2"', encoding="utf-8")

    summary = run_scan(tmp_path)

    assert summary.files_scanned == 1
    assert summary.findings == []


def test_engine_relative_path_for_nested_file(tmp_path):
    sub = tmp_path / "app" / "config"
    sub.mkdir(parents=True)
    php_file = sub / "db.php"
    php_file.write_text('$secret = "topsecret";', encoding="utf-8")

    summary = run_scan(tmp_path)

    assert summary.findings[0].file_path == "app/config/db.php"