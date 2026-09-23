from secureguard.reader import read_file_safely


def test_reads_existing_utf8_file(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')", encoding="utf-8")

    assert read_file_safely(sample) == "print('hello')"


def test_missing_file_returns_none(tmp_path):
    missing = tmp_path / "does_not_exist.py"

    assert read_file_safely(missing) is None


def test_directory_returns_none(tmp_path):
    assert read_file_safely(tmp_path) is None