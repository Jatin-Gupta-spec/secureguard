from pathlib import Path

from secureguard.rules.python_rules import find_py_sec_001

FIXTURES = Path(__file__).parent / "fixtures" / "python"


def _findings_for(fixture_name: str, subfolder: str):
    path = FIXTURES / subfolder / fixture_name
    content = path.read_text(encoding="utf-8")
    return find_py_sec_001(content, fixture_name)


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