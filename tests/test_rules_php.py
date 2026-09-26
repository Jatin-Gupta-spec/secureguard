from pathlib import Path

from secureguard.rules.php_rules import find_php_cmd_001, find_php_sec_001, find_php_sql_001

FIXTURES = Path(__file__).parent / "fixtures" / "php"


def _findings_for(fixture_name: str, subfolder: str, rule_func=find_php_sec_001):
    path = FIXTURES / subfolder / fixture_name
    content = path.read_text(encoding="utf-8")
    return rule_func(content, fixture_name)


def test_hardcoded_password_flagged():
    findings = _findings_for("hardcoded_password.php", "vulnerable")
    assert len(findings) == 1
    assert findings[0].rule_id == "PHP-SEC-001"


def test_hardcoded_api_key_flagged():
    findings = _findings_for("hardcoded_api_key.php", "vulnerable")
    assert len(findings) == 1


def test_hardcoded_secret_underscore_flagged():
    findings = _findings_for("hardcoded_secret_underscore.php", "vulnerable")
    assert len(findings) == 1


def test_getenv_not_flagged():
    assert _findings_for("uses_getenv.php", "safe") == []


def test_commented_out_not_flagged():
    assert _findings_for("commented_out.php", "safe") == []


def test_placeholder_value_not_flagged():
    assert _findings_for("placeholder_value.php", "safe") == []


def test_realistic_safe_file_has_no_findings():
    assert _findings_for("realistic_safe_file.php", "safe") == []


def test_sql_concat_variable_flagged():
    findings = _findings_for("sql_concat_variable.php", "vulnerable", find_php_sql_001)
    assert len(findings) == 1
    assert findings[0].rule_id == "PHP-SQL-001"


def test_sql_concat_request_flagged():
    findings = _findings_for("sql_concat_request.php", "vulnerable", find_php_sql_001)
    assert len(findings) == 1


def test_sql_literal_only_not_flagged():
    assert _findings_for("sql_literal_only.php", "safe", find_php_sql_001) == []


def test_sql_prepared_statement_not_flagged():
    assert _findings_for("sql_prepared_statement.php", "safe", find_php_sql_001) == []


def test_sql_constant_concat_not_flagged():
    assert _findings_for("sql_constant_concat.php", "safe", find_php_sql_001) == []


def test_cmd_variable_flagged():
    findings = _findings_for("cmd_variable.php", "vulnerable", find_php_cmd_001)
    assert len(findings) == 1
    assert findings[0].rule_id == "PHP-CMD-001"


def test_cmd_concat_flagged():
    findings = _findings_for("cmd_concat.php", "vulnerable", find_php_cmd_001)
    assert len(findings) == 1


def test_cmd_literal_only_not_flagged():
    assert _findings_for("cmd_literal_only.php", "safe", find_php_cmd_001) == []


def test_cmd_commented_out_not_flagged():
    assert _findings_for("cmd_commented_out.php", "safe", find_php_cmd_001) == []

def test_line_number_correct_after_multiline_comment():
    content = (
        "<?php\n"
        "/* A multi-line\n"
        "   block comment\n"
        "   spanning lines */\n"
        "system($cmd);\n"
    )
    findings = find_php_cmd_001(content, "example.php")

    assert len(findings) == 1
    assert findings[0].line_number == 5