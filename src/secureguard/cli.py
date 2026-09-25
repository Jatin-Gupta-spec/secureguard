"""Command-line interface for SecureGuard."""
from __future__ import annotations

from pathlib import Path

from secureguard.discovery import TooManyFilesError
from secureguard.engine import run_scan
from secureguard.reporters.json_reporter import format_json
from secureguard.reporters.terminal import format_summary


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = []

    if len(argv) < 2 or argv[0] != "scan":
        print("Usage: python -m secureguard scan <path> [--format text|json]")
        return 3

    target = Path(argv[1])
    output_format = "text"

    if len(argv) == 4 and argv[2] == "--format":
        output_format = argv[3]
    elif len(argv) not in (2, 4):
        print("Usage: python -m secureguard scan <path> [--format text|json]")
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