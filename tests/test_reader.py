from secureguard.reader import read_file_safely


def test_reads_existing_utf8_file(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')", encoding="utf-8")

    result = read_file_safely(sample)

    assert result.content == "print('hello')"
    assert result.skip_reason is None


def test_missing_file_returns_unreadable(tmp_path):
    missing = tmp_path / "does_not_exist.py"

    result = read_file_safely(missing)

    assert result.content is None
    assert result.skip_reason == "unreadable"


def test_directory_returns_unreadable(tmp_path):
    result = read_file_safely(tmp_path)

    assert result.content is None
    assert result.skip_reason == "unreadable"