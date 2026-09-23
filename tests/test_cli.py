from secureguard.cli import main


def test_scan_existing_file_returns_zero(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')", encoding="utf-8")

    assert main(["scan", str(sample)]) == 0


def test_missing_argv_returns_usage_error():
    assert main([]) == 3


def test_missing_file_returns_input_error(tmp_path):
    missing = tmp_path / "does_not_exist.py"

    assert main(["scan", str(missing)]) == 2