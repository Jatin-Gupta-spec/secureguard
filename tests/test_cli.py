from secureguard.cli import main
import json


def test_scan_existing_file_returns_zero(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')", encoding="utf-8")

    assert main(["scan", str(sample)]) == 0


def test_missing_argv_returns_usage_error():
    assert main([]) == 3


def test_missing_file_returns_input_error(tmp_path):
    missing = tmp_path / "does_not_exist.py"

    assert main(["scan", str(missing)]) == 2


def test_scan_directory_counts_files(tmp_path, capsys):
    (tmp_path / "a.py").write_text("print(1)", encoding="utf-8")
    (tmp_path / "b.py").write_text("print(2)", encoding="utf-8")

    exit_code = main(["scan", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Scanned 2 file(s)." in output


def test_scan_reports_skipped_binary_file(tmp_path, capsys):
    (tmp_path / "bad.py").write_bytes(b"\x00\x01")

    exit_code = main(["scan", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 2
    assert "Skipped 1 file(s): binary" in output


def test_scan_empty_directory_returns_two(tmp_path):
    assert main(["scan", str(tmp_path)]) == 2

def test_scan_json_format_returns_valid_json(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text('password = "hunter2"', encoding="utf-8")

    exit_code = main(["scan", str(tmp_path), "--format", "json"])
    output = capsys.readouterr().out
    parsed = json.loads(output)

    assert exit_code == 0
    assert parsed["files_scanned"] == 1
    assert len(parsed["findings"]) == 1


def test_unknown_format_returns_usage_error(tmp_path):
    assert main(["scan", str(tmp_path), "--format", "xml"]) == 3

def test_explain_known_rule_returns_zero(capsys):
    exit_code = main(["explain", "PHP-SEC-001"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "PHP-SEC-001" in output


def test_explain_lowercase_rule_id_works():
    assert main(["explain", "php-sec-001"]) == 0


def test_explain_unknown_rule_returns_two(capsys):
    exit_code = main(["explain", "NOT-A-REAL-RULE"])
    output = capsys.readouterr().out

    assert exit_code == 2
    assert "Unknown rule" in output


def test_explain_missing_argument_returns_usage_error():
    assert main(["explain"]) == 3

def test_baseline_command_writes_file(tmp_path):
    sample = tmp_path / "config.php"
    sample.write_text('$password = "hunter2";', encoding="utf-8")
    out = tmp_path / "baseline.json"

    exit_code = main(["baseline", str(tmp_path), str(out)])

    assert exit_code == 0
    assert out.is_file()


def test_scan_with_baseline_suppresses_known_finding(tmp_path, capsys):
    sample = tmp_path / "config.php"
    sample.write_text('$password = "hunter2";', encoding="utf-8")
    baseline_file = tmp_path / "baseline.json"

    main(["baseline", str(tmp_path), str(baseline_file)])
    exit_code = main(["scan", str(tmp_path), "--baseline", str(baseline_file)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "PHP-SEC-001" not in output
    assert "Scanned 1 file(s)." in output


def test_baseline_command_missing_args_returns_usage_error():
    assert main(["baseline", "somepath"]) == 3

def test_scan_html_format_returns_html(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text('password = "hunter2"', encoding="utf-8")

    exit_code = main(["scan", str(tmp_path), "--format", "html"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert output.startswith("<!DOCTYPE html>")
    assert "PY-SEC-001" in output