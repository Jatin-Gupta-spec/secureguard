"""Safe file reading for SecureGuard.

Reads a file as text only. Never executes, imports, or otherwise runs the
file's contents - it is treated purely as bytes to decode and hand off for
pattern matching later.
"""
from __future__ import annotations

from pathlib import Path


def read_file_safely(path: Path) -> str | None:
    """Attempt to read `path` as UTF-8 text.

    Returns the file's text content, or None if it could not be read
    (missing, not a file, a permissions error, or not valid UTF-8).
    Stage 4 adds the full encoding fallback chain and size/binary checks
    the locked spec requires - this is the minimal safe version.
    """
    if not path.is_file():
        return None

    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None