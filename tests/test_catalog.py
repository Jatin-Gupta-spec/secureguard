from secureguard.rules.catalog import ALL_RULES

EXPECTED_RULE_IDS = {
    "PHP-SEC-001",
    "PY-SEC-001",
    "PHP-SQL-001",
    "PY-SQL-001",
    "PHP-CMD-001",
    "PY-CMD-001",
}


def test_all_rules_present():
    assert set(ALL_RULES.keys()) == EXPECTED_RULE_IDS


def test_every_rule_has_complete_documentation():
    for rule_id, rule in ALL_RULES.items():
        assert rule.rule_id == rule_id
        assert rule.cwe
        assert rule.explanation
        assert rule.impact
        assert rule.fix
        assert rule.safe_example
        assert rule.rationale