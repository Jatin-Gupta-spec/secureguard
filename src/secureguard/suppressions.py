"""Inline suppression comments: `secureguard: ignore` or
`secureguard: ignore[RULE-ID, RULE-ID]` anywhere on a line suppresses
findings on that line - either all of them, or just the named rule(s).

Runs against the file's original, unmodified content - not any rule's
internally comment-stripped copy - so the marker is never accidentally
removed before it's read.
"""
from __future__ import annotations

import re

import io
import tokenize

from secureguard.models import Finding

_SUPPRESSION_RE = re.compile(
    r"secureguard:\s*ignore(?:\[(?P<rules>[\w,\s-]+)\])?", re.IGNORECASE
)
_HEREDOC_START_RE = re.compile(r"<<<\s*['\"]?\w+['\"]?")
_COMMENT_START_RE = re.compile(r"//|#|/\*")
_PHP_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"' + r"|" + r"'(?:\\.|[^'\\])*'")

def _blank_strings(line: str) -> str:
    """Replace quoted string contents with spaces of the same length
    (never removed entirely - that would shift character positions), so
    a later search for a comment-start symbol never mistakes // or #
    sitting inside a string for a real comment."""
    return _PHP_STRING_RE.sub(lambda m: " " * len(m.group(0)), line)


def _parse_marker(comment_text: str) -> tuple[bool, set[str] | None]:
    """Returns (found, rule_ids_or_None). rule_ids_or_None is None for a
    bare 'ignore everything on this line' marker."""
    match = _SUPPRESSION_RE.search(comment_text)
    if not match:
        return False, None

    rules_text = match.group("rules")
    if rules_text is None:
        return True, None
    return True, {r.strip().upper() for r in rules_text.split(",") if r.strip()}


def find_python_suppressed_lines(content: str) -> dict[int, set[str] | None]:
    """Map line number -> suppression marker, recognized ONLY inside a
    genuine Python # comment token - never inside a string literal, an
    f-string, a docstring, or anywhere else text merely resembles one.
    Uses the tokenize module, so this is exactly as accurate as Python's
    own lexer at telling a comment from a string.
    """
    suppressed: dict[int, set[str] | None] = {}

    try:
        for tok in tokenize.generate_tokens(io.StringIO(content).readline):
            if tok.type != tokenize.COMMENT:
                continue
            found, rule_ids = _parse_marker(tok.string)
            if found:
                suppressed[tok.start[0]] = rule_ids
    except (tokenize.TokenizeError, IndentationError, SyntaxError):
        pass  # unparseable Python - recognize no suppressions; this can
              # only mean MORE findings show up, never fewer

    return suppressed


def find_php_suppressed_lines(content: str) -> dict[int, set[str] | None]:
    """Map line number -> suppression marker, recognized ONLY inside a
    genuine PHP //, #, or /* */ comment - never inside a string literal.

    Known limitation, deliberately fail-safe: a marker inside a
    MULTI-LINE /* ... */ comment is not recognized (under-suppression is
    safe - it only means an extra finding shows up). If the file contains
    a PHP heredoc or nowdoc (<<<NAME ... NAME) anywhere, suppression
    recognition is disabled for the WHOLE file - a heredoc body can
    contain arbitrary text, and wrongly suppressing a real finding is the
    one outcome this feature must never produce.
    """
    if _HEREDOC_START_RE.search(content):
        return {}

    suppressed: dict[int, set[str] | None] = {}

    for line_number, line in enumerate(content.splitlines(), start=1):
        blanked = _blank_strings(line)
        match = _COMMENT_START_RE.search(blanked)
        if not match:
            continue

        comment_text = line[match.start():]
        found, rule_ids = _parse_marker(comment_text)
        if found:
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