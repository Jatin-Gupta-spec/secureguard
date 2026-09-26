"""Inline suppression comments: `secureguard: ignore` or
`secureguard: ignore[RULE-ID, RULE-ID]` anywhere on a line suppresses
findings on that line - either all of them, or just the named rule(s).

Runs against the file's original, unmodified content - not any rule's
internally comment-stripped copy - so the marker is never accidentally
removed before it's read.
"""
from __future__ import annotations

import re

from secureguard.models import Finding

_SUPPRESSION_RE = re.compile(
    r"secureguard:\s*ignore(?:\[(?P<rules>[\w,\s-]+)\])?", re.IGNORECASE
)


def find_suppressed_lines(content: str) -> dict[int, set[str] | None]:
    """Map line number -> None (suppress everything on that line) or a set
    of specific rule IDs to suppress. Lines with no marker are absent."""
    suppressed: dict[int, set[str] | None] = {}

    for line_number, line in enumerate(content.splitlines(), start=1):
        match = _SUPPRESSION_RE.search(line)
        if not match:
            continue

        rules_text = match.group("rules")
        if rules_text is None:
            suppressed[line_number] = None
        else:
            rule_ids = {r.strip().upper() for r in rules_text.split(",") if r.strip()}
            suppressed[line_number] = rule_ids

    return suppressed


def filter_suppressed(findings: list[Finding], suppressed: dict[int, set[str] | None]) -> list[Finding]:
    kept: list[Finding] = []
    for finding in findings:
        if finding.line_number in suppressed:
            marker = suppressed[finding.line_number]
            if marker is None or finding.rule_id in marker:
                continue  # suppressed
        kept.append(finding)
    return kept