"""Rule catalogue: metadata and rationale for every SecureGuard rule."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    cwe: str
    default_severity: str
    default_confidence: str
    rationale: str


PHP_SEC_001 = RuleMeta(
    rule_id="PHP-SEC-001",
    cwe="CWE-798",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "A credential-like variable or array key assigned a non-empty string "
        "literal is suspicious, but this pattern is also common in test "
        "fixtures, examples, and local-only config - so severity stays at "
        "Medium and confidence at Low rather than High, matching the locked "
        "spec's rule that a keyword match alone never justifies High severity."
    ),
)

PY_SEC_001 = RuleMeta(
    rule_id="PY-SEC-001",
    cwe="CWE-798",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "Same reasoning as PHP-SEC-001: a credential-like name assigned a "
        "literal string is suspicious but common in fixtures and local-only "
        "config, so severity stays Medium and confidence Low rather than "
        "High on a keyword match alone."
    ),
)

PHP_SQL_001 = RuleMeta(
    rule_id="PHP-SQL-001",
    cwe="CWE-89",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "A SQL-looking string concatenated with a non-literal expression is "
        "a classic injection shape, but this pattern-matcher cannot prove "
        "the concatenated value is attacker-controlled, reaches the "
        "database, or is unsanitized elsewhere - so it stays Medium/Low "
        "rather than High."
    ),
)

PY_SQL_001 = RuleMeta(
    rule_id="PY-SQL-001",
    cwe="CWE-89",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "Same shape as PHP-SQL-001: a dynamically built SQL string passed "
        "to an execute-like call. Heuristic only - v0.1 does not parse the "
        "AST, so it can't fully confirm complete data flow, hence "
        "Medium/Low rather than High."
    ),
)

PHP_CMD_001 = RuleMeta(
    rule_id="PHP-CMD-001",
    cwe="CWE-78",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "A shell-execution function receiving a non-literal argument is a "
        "classic command-injection shape, but a keyword match alone can't "
        "prove the value is attacker-controlled - so it stays Medium/Low, "
        "not High."
    ),
)

PY_CMD_001 = RuleMeta(
    rule_id="PY-CMD-001",
    cwe="CWE-78",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "os.system() always shells out, and shell=True explicitly opts "
        "into shell interpretation - both are risky regardless of the "
        "specific input, but neither proves the value is attacker-"
        "controlled, so severity/confidence stay Medium/Low. Safe list-form "
        "subprocess calls (no shell=True) must never be flagged."
    ),
)