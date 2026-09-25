"""Python-specific detection rules."""
from __future__ import annotations

import ast
import re

from secureguard.models import Finding
from secureguard.redaction import redact
from secureguard.rules.catalog import PY_CMD_001, PY_SEC_001, PY_SQL_001

_TRIPLE_QUOTE_RE = re.compile(r"('''|\"\"\").*?\1", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"#.*$")

_CREDENTIAL_KEYWORDS = (
    "password", "passwd", "pwd", "secret", "apikey", "api_key",
    "token", "credential",
)

_PLACEHOLDER_VALUES = {
    "changeme", "change_me", "xxx", "your_password_here", "yourpassword",
    "placeholder", "example", "todo", "test", "demo", "password", "secret",
}

_EXECUTE_CALL_RE = re.compile(r"\.(execute|executemany|executescript)\s*\(")
_SQL_KEYWORD_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
_FSTRING_RE = re.compile(r"[fF]['\"].*?\{.*?\}.*?['\"]")
_CONCAT_WITH_VAR_RE = re.compile(r"['\"][^'\"]*['\"]\s*\+\s*\w")

_OS_SYSTEM_RE = re.compile(r"\bos\.system\s*\((?P<args>[^)]*)\)")
_SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True")
_STRING_LITERAL_RE = re.compile(r"(['\"]).*?\1")


def _strip_comments(content: str) -> str:
    without_triple_quotes = _TRIPLE_QUOTE_RE.sub("", content)
    lines = [_LINE_COMMENT_RE.sub("", line) for line in without_triple_quotes.splitlines()]
    return "\n".join(lines)


def find_py_sec_001(content: str, file_path: str) -> list[Finding]:
    """AST-based: only flags real assignment/dict-key shapes, so comments,
    docstrings, and string literals used as data (e.g. as a function call's
    argument) are structurally excluded - not just pattern-avoided.
    """
    findings: list[Finding] = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    candidates: list[tuple[str, ast.expr, int]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                candidates.append((node.targets[0].id, node.value, node.lineno))
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value is not None:
                candidates.append((node.target.id, node.value, node.lineno))
        elif isinstance(node, ast.Dict):
            for key_node, val_node in zip(node.keys, node.values):
                if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                    candidates.append((key_node.value, val_node, val_node.lineno))

    for name, value_node, line_number in candidates:
        if not any(keyword in name.lower() for keyword in _CREDENTIAL_KEYWORDS):
            continue
        if not (isinstance(value_node, ast.Constant) and isinstance(value_node.value, str)):
            continue

        value = value_node.value.strip()
        if not value or value.lower() in _PLACEHOLDER_VALUES:
            continue

        findings.append(
            Finding(
                file_path=file_path,
                line_number=line_number,
                rule_id=PY_SEC_001.rule_id,
                severity=PY_SEC_001.default_severity,
                confidence=PY_SEC_001.default_confidence,
                cwe=PY_SEC_001.cwe,
                evidence=redact(name),
                explanation="Possible hardcoded credential assigned as a literal value.",
                remediation="Load this value from an environment variable or secret store instead.",
                evidence_key=name.lower(),
            )
        )

    return findings


def find_py_sql_001(content: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    cleaned = _strip_comments(content)

    for line_number, line in enumerate(cleaned.splitlines(), start=1):
        if not _EXECUTE_CALL_RE.search(line):
            continue
        if not _SQL_KEYWORD_RE.search(line):
            continue
        if not (_FSTRING_RE.search(line) or _CONCAT_WITH_VAR_RE.search(line)):
            continue

        findings.append(
            Finding(
                file_path=file_path,
                line_number=line_number,
                rule_id=PY_SQL_001.rule_id,
                severity=PY_SQL_001.default_severity,
                confidence=PY_SQL_001.default_confidence,
                cwe=PY_SQL_001.cwe,
                evidence=line.strip(),
                explanation="Dynamically built SQL string passed to an execute-like call.",
                remediation=(
                    "Use parameterized queries (pass values separately, e.g. "
                    "cursor.execute(sql, params)) instead of building SQL "
                    "with f-strings or concatenation."
                ),
                evidence_key=line.strip().lower()[:50],
            )
        )

    return findings


def find_py_cmd_001(content: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    cleaned = _strip_comments(content)

    for line_number, line in enumerate(cleaned.splitlines(), start=1):
        evidence = None
        explanation = None

        os_match = _OS_SYSTEM_RE.search(line)
        if os_match:
            without_strings = _STRING_LITERAL_RE.sub("", os_match.group("args"))
            if without_strings.strip():
                evidence = os_match.group(0)
                explanation = "os.system() called with a non-literal argument."

        if evidence is None and _SHELL_TRUE_RE.search(line):
            evidence = line.strip()
            explanation = "subprocess call uses shell=True, which enables shell interpretation."

        if evidence is not None:
            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_number,
                    rule_id=PY_CMD_001.rule_id,
                    severity=PY_CMD_001.default_severity,
                    confidence=PY_CMD_001.default_confidence,
                    cwe=PY_CMD_001.cwe,
                    evidence=evidence,
                    explanation=explanation,
                    remediation="Use subprocess with a list of arguments and shell=False (the default) instead of a shell string.",
                    evidence_key=evidence.lower()[:50],
                )
            )

    return findings


PY_RULES = [find_py_sec_001, find_py_sql_001, find_py_cmd_001]

def test_string_literal_in_function_call_not_flagged():
    """Regression test for the Stage 14 self-scan false positive: a string
    that merely looks like an assignment, sitting as a function call's
    argument, must never be treated as a real one."""
    content = 'some_file.write_text(\'password = "hunter2"\', encoding="utf-8")'
    assert find_py_sec_001(content, "example.py") == []