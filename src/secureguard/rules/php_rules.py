"""PHP-specific detection rules."""
from __future__ import annotations

import re

from secureguard.models import Finding
from secureguard.rules.catalog import PHP_SEC_001

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"(?://|#).*$")

_ASSIGNMENT_RE = re.compile(
    r"[$]?(?P<name>[A-Za-z_][A-Za-z0-9_]*)['\"]?\s*(?:=>|=)\s*"
    r"(?P<quote>['\"])(?P<value>.+?)(?P=quote)"
)

_CREDENTIAL_KEYWORDS = (
    "password", "passwd", "pwd", "secret", "apikey", "api_key",
    "token", "credential",
)

_PLACEHOLDER_VALUES = {
    "changeme", "change_me", "xxx", "your_password_here", "yourpassword",
    "placeholder", "example", "todo", "test", "demo", "password", "secret",
}


def _strip_comments(content: str) -> str:
    without_blocks = _BLOCK_COMMENT_RE.sub("", content)
    lines = [_LINE_COMMENT_RE.sub("", line) for line in without_blocks.splitlines()]
    return "\n".join(lines)


def find_php_sec_001(content: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    cleaned = _strip_comments(content)

    for line_number, line in enumerate(cleaned.splitlines(), start=1):
        for match in _ASSIGNMENT_RE.finditer(line):
            name = match.group("name")
            if not any(keyword in name.lower() for keyword in _CREDENTIAL_KEYWORDS):
                continue

            value = match.group("value").strip()
            if not value or value.lower() in _PLACEHOLDER_VALUES:
                continue

            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_number,
                    rule_id=PHP_SEC_001.rule_id,
                    severity=PHP_SEC_001.default_severity,
                    confidence=PHP_SEC_001.default_confidence,
                    cwe=PHP_SEC_001.cwe,
                    evidence=f"{name} = ***redacted***",
                    explanation="Possible hardcoded credential assigned as a literal value.",
                    remediation="Load this value from an environment variable or secret store instead.",
                    evidence_key=name.lower(),
                )
            )

    return findings


PHP_RULES = [find_php_sec_001]