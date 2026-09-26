"""Regression tests: run every fixture through the real engine and verify
the expected result, as a corpus-wide precision/recall check.

Precision/recall here are internal, fixture-corpus measurements only -
not a claim about accuracy on real-world code, per the locked spec.
"""
from __future__ import annotations

from pathlib import Path

from secureguard.engine import run_scan

FIXTURES = Path(__file__).parent / "fixtures"


def _scan_dir(language: str, category: str):
    target = FIXTURES / language / category
    return run_scan(target)


def test_php_vulnerable_fixtures_all_produce_findings():
    summary = _scan_dir("php", "vulnerable")
    fixture_count = len(list((FIXTURES / "php" / "vulnerable").glob("*.php")))
    flagged_files = {f.file_path for f in summary.findings}

    assert summary.files_scanned == fixture_count
    assert len(flagged_files) == fixture_count


def test_php_safe_fixtures_produce_zero_findings():
    assert _scan_dir("php", "safe").findings == []


def test_python_vulnerable_fixtures_all_produce_findings():
    summary = _scan_dir("python", "vulnerable")
    fixture_count = len(list((FIXTURES / "python" / "vulnerable").glob("*.py")))
    flagged_files = {f.file_path for f in summary.findings}

    assert summary.files_scanned == fixture_count
    assert len(flagged_files) == fixture_count


def test_python_safe_fixtures_produce_zero_findings():
    assert _scan_dir("python", "safe").findings == []


def test_corpus_wide_precision_and_recall_are_perfect():
    true_positive_files = 0
    false_negative_files = 0
    false_positive_findings = 0

    for language, ext in (("php", "*.php"), ("python", "*.py")):
        vuln_summary = _scan_dir(language, "vulnerable")
        vuln_count = len(list((FIXTURES / language / "vulnerable").glob(ext)))
        flagged = {f.file_path for f in vuln_summary.findings}
        true_positive_files += len(flagged)
        false_negative_files += vuln_count - len(flagged)

        false_positive_findings += len(_scan_dir(language, "safe").findings)

    precision = true_positive_files / (true_positive_files + false_positive_findings)
    recall = true_positive_files / (true_positive_files + false_negative_files)

    assert precision == 1.0
    assert recall == 1.0

def test_own_source_has_no_unsuppressed_findings():
    """SecureGuard's own shipped code (src/) should be clean. If a future
    change ever reintroduces a self-referential false positive, this test
    fails immediately - the fix is a suppression comment, not silence."""
    src_dir = Path(__file__).parent.parent / "src"
    summary = run_scan(src_dir)

    assert summary.findings == []