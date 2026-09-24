"""Command-line interface for SecureGuard."""
from __future__ import annotations

from pathlib import Path

from secureguard.discovery import TooManyFilesError, discover_files
from secureguard.models import ScanSummary
from secureguard.reader import read_file_safely
from secureguard.reporters.terminal import format_summary


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = []

    if len(argv) < 2 or argv[0] != "scan":
        print("Usage: python -m secureguard scan <path>")
        return 3

    target = Path(argv[1])

    if not target.exists():
        print(f"Could not read: {target}")
        return 2

    try:
        files = discover_files(target)
    except TooManyFilesError as exc:
        print(str(exc))
        return 2

    summary = ScanSummary()

    for path in files:
        result = read_file_safely(path)
        if result.content is not None:
            summary.files_scanned += 1
        else:
            summary.skip_counts[result.skip_reason] = (
                summary.skip_counts.get(result.skip_reason, 0) + 1
            )

    print(format_summary(summary))

    if summary.files_scanned == 0:
        return 2

    return 0