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