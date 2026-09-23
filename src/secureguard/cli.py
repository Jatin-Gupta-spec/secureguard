"""Command-line interface for SecureGuard."""
from __future__ import annotations

from pathlib import Path

from secureguard.discovery import TooManyFilesError, discover_files
from secureguard.reader import read_file_safely


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

    read_count = 0
    skip_counts: dict[str, int] = {}

    for path in files:
        result = read_file_safely(path)
        if result.content is not None:
            read_count += 1
        else:
            skip_counts[result.skip_reason] = skip_counts.get(result.skip_reason, 0) + 1

    print(f"Scanned {read_count} file(s).")
    for reason, count in sorted(skip_counts.items()):
        print(f"Skipped {count} file(s): {reason}")

    if read_count == 0:
        return 2

    return 0