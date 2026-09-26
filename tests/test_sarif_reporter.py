import json

from secureguard.models import Finding, ScanSummary
from secureguard.reporters.sarif_reporter import format_sarif


def make_finding(**overrides):
    defaults = dict(
        file_path="src/app.php",
        line_number=10,
        rule_id="PHP-SEC-001",
        severity="Medium",
        confidence="Low",
        cwe="CWE-798",
        evidence="***redacted***",
        explanation="Possible hardcoded credential.",
        remediation="Load credentials from environment variables instead.",
        evidence_key="k1",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_output_is_valid_json_with_sarif_shape():
    summary = ScanSummary()
    summary.findings.append(make_finding())

    parsed = json.loads(format_sarif(summary))

    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"]) == 1
    assert len(parsed["runs"][0]["results"]) == 1


def test_result_has_rule_id_and_location():
    summary = ScanSummary()
    summary.findings.append(make_finding())

    parsed = json.loads(format_sarif(summary))
    result = parsed["runs"][0]["results"][0]

    assert result["ruleId"] == "PHP-SEC-001"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.php"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10


def test_fingerprint_included_as_partial_fingerprint():
    summary = ScanSummary()
    finding = make_finding()
    summary.findings.append(finding)

    parsed = json.loads(format_sarif(summary))
    result = parsed["runs"][0]["results"][0]

    assert result["partialFingerprints"]["secureguardFingerprint"] == finding.fingerprint


def test_rules_section_uses_real_catalog_descriptions():
    summary = ScanSummary()
    summary.findings.append(make_finding(rule_id="PHP-SEC-001"))

    parsed = json.loads(format_sarif(summary))
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 1
    assert rules[0]["id"] == "PHP-SEC-001"
    assert "help" in rules[0]


def test_redacted_evidence_appears_in_message():
    summary = ScanSummary()
    summary.findings.append(make_finding(evidence="***redacted***"))

    parsed = json.loads(format_sarif(summary))
    result = parsed["runs"][0]["results"][0]

    assert "***redacted***" in result["message"]["text"]