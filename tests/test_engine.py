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
    py_file.write_text("'api_key' => 'sk-real-looking-value';", encoding="utf-8")

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

def test_suppression_comment_hides_finding(tmp_path):
    py_file = tmp_path / "app.py"
    py_file.write_text('password = "hunter2"  # secureguard: ignore\n', encoding="utf-8")

    summary = run_scan(tmp_path)

    assert summary.files_scanned == 1
    assert summary.findings == []


def test_rule_specific_suppression_only_hides_that_rule(tmp_path):
    php_file = tmp_path / "app.php"
    php_file.write_text(
        '<?php\n'
        'system("SELECT * FROM users WHERE id = " . $id); // secureguard: ignore[PHP-SQL-001]\n',
        encoding="utf-8",
    )

    summary = run_scan(tmp_path)
    rule_ids = {f.rule_id for f in summary.findings}

    assert "PHP-SQL-001" not in rule_ids
    assert "PHP-CMD-001" in rule_ids