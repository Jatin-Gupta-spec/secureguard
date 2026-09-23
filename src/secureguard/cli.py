"""Command-line interface for SecureGuard."""
from __future__ import annotations

from pathlib import Path

from secureguard.reader import read_file_safely


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code:
    0 = read succeeded, 2 = path could not be read, 3 = usage error.
    """
    if argv is None:
        argv = []

    if len(argv) < 2 or argv[0] != "scan":
        print("Usage: python -m secureguard scan <path>")
        return 3

    target = Path(argv[1])
    content = read_file_safely(target)

    if content is None:
        print(f"Could not read: {target}")
        return 2

    print(f"Read {len(content)} characters from {target}")
    return 0