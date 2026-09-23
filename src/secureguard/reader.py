"""Safe file reading for SecureGuard.

Reads a file as text only, applying the locked size limit, binary guard,
and encoding fallback chain. Never executes, imports, or otherwise runs
the file's contents.
"""
from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MiB, per the locked spec
BINARY_SAMPLE_SIZE = 8192
UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


class ReadResult(NamedTuple):
    content: str | None
    skip_reason: str | None  # None on success


def read_file_safely(path: Path) -> ReadResult:
    if not path.is_file():
        return ReadResult(None, "unreadable")

    try:
        size = path.stat().st_size
    except OSError:
        return ReadResult(None, "unreadable")

    if size > MAX_FILE_SIZE_BYTES:
        return ReadResult(None, "too_large")

    try:
        raw = path.read_bytes()
    except OSError:
        return ReadResult(None, "unreadable")

    if raw.startswith(UTF16_BOMS):
        try:
            return ReadResult(raw.decode("utf-16"), None)
        except UnicodeDecodeError:
            return ReadResult(None, "decode_failed")

    if b"\x00" in raw[:BINARY_SAMPLE_SIZE]:
        return ReadResult(None, "binary")

    content = _decode_non_utf16(raw)
    if content is None:
        return ReadResult(None, "decode_failed")
    return ReadResult(content, None)


def _decode_non_utf16(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError:
        return None

