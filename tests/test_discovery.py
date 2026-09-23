from secureguard.discovery import discover_files


def test_finds_eligible_files_recursively(tmp_path):
    (tmp_path / "a.py").write_text("print(1)", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.php").write_text("<?php echo 1; ?>", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")

    found = discover_files(tmp_path)
    names = sorted(p.name for p in found)

    assert names == ["a.py", "b.php"]


def test_skips_excluded_directories(tmp_path):
    (tmp_path / "real.py").write_text("print(1)", encoding="utf-8")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "should_be_ignored.py").write_text("print(2)", encoding="utf-8")

    found = discover_files(tmp_path)

    assert [p.name for p in found] == ["real.py"]


def test_single_file_input(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print(1)", encoding="utf-8")

    assert discover_files(sample) == [sample]


def test_case_insensitive_extension(tmp_path):
    (tmp_path / "Upper.PHP").write_text("<?php ?>", encoding="utf-8")

    found = discover_files(tmp_path)

    assert [p.name for p in found] == ["Upper.PHP"]