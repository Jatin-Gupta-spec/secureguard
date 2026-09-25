from pathlib import Path

from secureguard.rules.python_rules import find_py_cmd_001, find_py_sec_001, find_py_sql_001

FIXTURES = Path(__file__).parent / "fixtures" / "python"


def _findings_for(fixture_name: str, subfolder: str, rule_func=find_py_sec_001):
    path = FIXTURES / subfolder / fixture_name
    content = path.read_text(encoding="utf-8")
    return rule_func(content, fixture_name)


def test_hardcoded_password_flagged():
    findings = _findings_for("hardcoded_password.py", "vulnerable")
    assert len(findings) == 1
    assert findings[0].rule_id == "PY-SEC-001"


def test_hardcoded_api_key_flagged():
    findings = _findings_for("hardcoded_api_key.py", "vulnerable")
    assert len(findings) == 1


def test_hardcoded_secret_underscore_flagged():
    findings = _findings_for("hardcoded_secret_underscore.py", "vulnerable")
    assert len(findings) == 1


def test_getenv_not_flagged():
    assert _findings_for("uses_getenv.py", "safe") == []


def test_commented_out_not_flagged():
    assert _findings_for("commented_out.py", "safe") == []


def test_placeholder_value_not_flagged():
    assert _findings_for("placeholder_value.py", "safe") == []


def test_docstring_not_flagged():
    assert _findings_for("docstring_example.py", "safe") == []


def test_realistic_safe_file_has_no_findings():
    assert _findings_for("realistic_safe_file.py", "safe") == []


def test_sql_fstring_flagged():
    findings = _findings_for("sql_fstring.py", "vulnerable", find_py_sql_001)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY-SQL-001"


def test_sql_concat_flagged():
    findings = _findings_for("sql_concat.py", "vulnerable", find_py_sql_001)
    assert len(findings) == 1


def test_sql_parameterized_not_flagged():
    assert _findings_for("sql_parameterized.py", "safe", find_py_sql_001) == []


def test_sql_literal_only_not_flagged():
    assert _findings_for("sql_literal_only.py", "safe", find_py_sql_001) == []


def test_cmd_os_system_variable_flagged():
    findings = _findings_for("cmd_os_system_variable.py", "vulnerable", find_py_cmd_001)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY-CMD-001"


def test_cmd_shell_true_flagged():
    findings = _findings_for("cmd_shell_true.py", "vulnerable", find_py_cmd_001)
    assert len(findings) == 1


def test_cmd_list_form_not_flagged():
    assert _findings_for("cmd_list_form.py", "safe", find_py_cmd_001) == []


def test_cmd_os_system_literal_not_flagged():
    assert _findings_for("cmd_os_system_literal.py", "safe", find_py_cmd_001) == []