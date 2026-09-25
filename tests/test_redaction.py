from pathlib import Path

from secureguard.redaction import REDACTED_PLACEHOLDER, redact
from secureguard.rules.php_rules import find_php_sec_001
from secureguard.rules.python_rules import find_py_sec_001

PHP_FIXTURES = Path(__file__).parent / "fixtures" / "php" / "vulnerable"
PY_FIXTURES = Path(__file__).parent / "fixtures" / "python" / "vulnerable"

_KNOWN_SECRETS = ("hunter2", "s3cr3t!", "sk-real-looking-value-123")


def test_redact_never_includes_the_raw_value():
    result = redact("password")
    assert REDACTED_PLACEHOLDER in result
    for secret in _KNOWN_SECRETS:
        assert secret not in result


def test_php_sec_001_findings_never_contain_known_secrets():
    for fixture in PHP_FIXTURES.glob("*.php"):
        content = fixture.read_text(encoding="utf-8")
        for finding in find_php_sec_001(content, fixture.name):
            for secret in _KNOWN_SECRETS:
                assert secret not in finding.evidence


def test_py_sec_001_findings_never_contain_known_secrets():
    for fixture in PY_FIXTURES.glob("*.py"):
        content = fixture.read_text(encoding="utf-8")
        for finding in find_py_sec_001(content, fixture.name):
            for secret in _KNOWN_SECRETS:
                assert secret not in finding.evidence