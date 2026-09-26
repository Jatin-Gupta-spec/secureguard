"""Command-line interface for SecureGuard."""
from __future__ import annotations

from pathlib import Path

from secureguard.discovery import TooManyFilesError
from secureguard.engine import run_scan
from secureguard.reporters.json_reporter import format_json
from secureguard.reporters.terminal import format_rule_explanation, format_summary
from secureguard.rules.catalog import ALL_RULES

USAGE = (
    "Usage: python -m secureguard scan <path> [--format text|json]\n"
    "       python -m secureguard explain <rule-id>"
)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = []

    if not argv:
        print(USAGE)
        return 3

    command = argv[0]

    if command == "explain":
        if len(argv) != 2:
            print(USAGE)
            return 3
        rule = ALL_RULES.get(argv[1].upper())
        if rule is None:
            print(f"Unknown rule: {argv[1]}")
            return 2
        print(format_rule_explanation(rule))
        return 0

    if command != "scan" or len(argv) < 2:
        print(USAGE)
        return 3

    target = Path(argv[1])
    output_format = "text"

    if len(argv) == 4 and argv[2] == "--format":
        output_format = argv[3]
    elif len(argv) not in (2, 4):
        print(USAGE)
        return 3

    if output_format not in ("text", "json"):
        print(f"Unknown format: {output_format}")
        return 3

    if not target.exists():
        print(f"Could not read: {target}")
        return 2

    try:
        summary = run_scan(target)
    except TooManyFilesError as exc:
        print(str(exc))
        return 2

    if output_format == "json":
        print(format_json(summary))
    else:
        print(format_summary(summary))

    if summary.files_scanned == 0:
        return 2

    return 0