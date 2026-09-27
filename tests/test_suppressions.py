from secureguard.models import Finding
from secureguard.suppressions import filter_suppressed, find_python_suppressed_lines


def make_finding(**overrides):
    defaults = dict(
        file_path="src/app.py",
        line_number=1,
        rule_id="PY-SEC-001",
        severity="Medium",
        confidence="Low",
        cwe="CWE-798",
        evidence="***redacted***",
        explanation="x",
        remediation="x",
        evidence_key="k1",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_no_markers_returns_empty_dict():
    assert find_python_suppressed_lines("password = 'x'\nother = 'y'") == {}


def test_bare_marker_suppresses_all_rules_on_that_line():
    content = 'password = "hunter2"  # secureguard: ignore'
    assert find_python_suppressed_lines(content) == {1: None}


def test_rule_specific_marker_parsed():
    content = 'password = "hunter2"  # secureguard: ignore[PY-SEC-001]'
    assert find_python_suppressed_lines(content) == {1: {"PY-SEC-001"}}


def test_multiple_rules_in_marker():
    content = 'x = "y"  # secureguard: ignore[PY-SEC-001, PY-SQL-001]'
    assert find_python_suppressed_lines(content) == {1: {"PY-SEC-001", "PY-SQL-001"}}


def test_filter_removes_bare_suppressed_finding():
    finding = make_finding(line_number=1)
    assert filter_suppressed([finding], {1: None}) == []


def test_filter_removes_matching_rule_specific_finding():
    finding = make_finding(line_number=1, rule_id="PY-SEC-001")
    assert filter_suppressed([finding], {1: {"PY-SEC-001"}}) == []


def test_filter_keeps_non_matching_rule_specific_finding():
    finding = make_finding(line_number=1, rule_id="PY-SQL-001")
    assert filter_suppressed([finding], {1: {"PY-SEC-001"}}) == [finding]


def test_filter_keeps_finding_on_unsuppressed_line():
    finding = make_finding(line_number=5)
    assert filter_suppressed([finding], {1: None}) == [finding]

def test_marker_inside_string_literal_does_not_suppress():
    content = 'password = "SECRET"; text = "secureguard: ignore"'
    assert find_python_suppressed_lines(content) == {}


def test_marker_inside_docstring_does_not_suppress():
    content = '"""\nsecureguard: ignore\n"""\npassword = "hunter2"'
    assert find_python_suppressed_lines(content) == {}


def test_marker_inside_fstring_does_not_suppress():
    content = 'x = f"secureguard: ignore {name}"'
    assert find_python_suppressed_lines(content) == {}

from secureguard.suppressions import find_php_suppressed_lines


def test_bare_marker_in_double_slash_comment_suppresses():
    content = '<?php\nsystem($cmd); // secureguard: ignore\n'
    assert find_php_suppressed_lines(content) == {2: None}


def test_rule_specific_marker_in_hash_comment_suppresses():
    content = '<?php\nsystem($cmd); # secureguard: ignore[PHP-CMD-001]\n'
    assert find_php_suppressed_lines(content) == {2: {"PHP-CMD-001"}}


def test_marker_in_single_line_block_comment_suppresses():
    content = '<?php\nsystem($cmd); /* secureguard: ignore */\n'
    assert find_php_suppressed_lines(content) == {2: None}


def test_marker_inside_double_quoted_string_does_not_suppress():
    content = '<?php\n$x = "secureguard: ignore";\n'
    assert find_php_suppressed_lines(content) == {}


def test_marker_inside_single_quoted_string_does_not_suppress():
    content = "<?php\n$x = 'secureguard: ignore';\n"
    assert find_php_suppressed_lines(content) == {}


def test_marker_after_escaped_quote_in_string_does_not_suppress():
    """The dangerous case: an escaped quote inside a string must not be
    mistaken for the string's end - otherwise text after it could be
    wrongly treated as a real comment, suppressing a genuine finding."""
    content = '<?php\n$x = "a \\" // secureguard: ignore";\n'
    assert find_php_suppressed_lines(content) == {}


def test_real_comment_after_string_with_escaped_quote_still_works():
    """The other direction: a genuine comment must still be recognized
    even when it comes right after a string containing an escaped quote -
    proving we didn't overcorrect and break the normal case."""
    content = '<?php\n$x = "a \\" b"; // secureguard: ignore\n'
    assert find_php_suppressed_lines(content) == {2: None}


def test_heredoc_anywhere_disables_suppression_for_whole_file():
    """Fail-safe by design: if the file contains a heredoc/nowdoc at all,
    we can't safely tell what's inside it, so suppression is disabled for
    the ENTIRE file - even a real, valid comment marker elsewhere gets
    ignored, because under-suppressing is safe and over-suppressing isn't."""
    content = (
        "<?php\n"
        "$sql = <<<SQL\n"
        "SELECT * FROM users\n"
        "SQL;\n"
        'system($cmd); // secureguard: ignore[PHP-CMD-001]\n'
    )
    assert find_php_suppressed_lines(content) == {}