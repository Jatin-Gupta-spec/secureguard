from pathlib import Path

from secureguard.reader import MAX_FILE_SIZE_BYTES, read_file_safely


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


def test_exactly_max_size_succeeds(tmp_path):
    exact = tmp_path / "exact.py"
    exact.write_bytes(b"x" * MAX_FILE_SIZE_BYTES)

    result = read_file_safely(exact)

    assert result.content is not None
    assert result.skip_reason is None


def test_one_byte_over_max_size_is_skipped(tmp_path):
    over = tmp_path / "over.py"
    over.write_bytes(b"x" * (MAX_FILE_SIZE_BYTES + 1))

    result = read_file_safely(over)

    assert result.content is None
    assert result.skip_reason == "too_large"


def test_file_growing_after_stat_check_is_still_caught(tmp_path, monkeypatch):
    """Simulates the exact TOCTOU scenario the audit calls out: stat()
    reports a small size, but the file has actually grown past the limit
    by the time it's opened and read. The bounded read must catch this
    even though the earlier stat()-based check was fooled.
    """
    import secureguard.reader as reader_module

    grown = tmp_path / "grown.py"
    grown.write_bytes(b"x" * 10)  # tiny, so the stat() check passes

    real_stat = Path.stat

    def fake_stat(self, *args, **kwargs):
        result = real_stat(self, *args, **kwargs)
        if self == grown:
            grown.write_bytes(b"x" * (reader_module.MAX_FILE_SIZE_BYTES + 1))
        return result

    monkeypatch.setattr(Path, "stat", fake_stat)

    result = read_file_safely(grown)

    assert result.content is None
    assert result.skip_reason == "too_large"


def test_empty_file_succeeds_with_empty_content(tmp_path):
    empty = tmp_path / "empty.py"
    empty.write_bytes(b"")

    result = read_file_safely(empty)

    assert result.content == ""
    assert result.skip_reason is None


def test_utf8_bom_file_decodes_correctly(tmp_path):
    bom_file = tmp_path / "bom.py"
    bom_file.write_bytes(b"\xef\xbb\xbfprint('hi')")

    result = read_file_safely(bom_file)

    assert result.content == "print('hi')"
    assert result.skip_reason is None


def test_utf16_bom_file_decodes_correctly(tmp_path):
    utf16_file = tmp_path / "utf16.py"
    utf16_file.write_text("x = 1", encoding="utf-16")

    result = read_file_safely(utf16_file)

    assert result.content == "x = 1"
    assert result.skip_reason is None


def test_cp1252_file_decodes_correctly(tmp_path):
    cp_file = tmp_path / "cp1252.py"
    cp_file.write_bytes("café".encode("cp1252"))

    result = read_file_safely(cp_file)

    assert result.content == "café"
    assert result.skip_reason is None


def test_binary_file_is_skipped(tmp_path):
    bin_file = tmp_path / "bin.py"
    bin_file.write_bytes(b"\x00\x01\x02")

    result = read_file_safely(bin_file)

    assert result.content is None
    assert result.skip_reason == "binary"