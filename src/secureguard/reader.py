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


def _read_bounded(path: Path, limit: int) -> tuple[bytes | None, str | None]:
    """Read at most `limit` + 1 bytes directly from disk - never the whole
    file. Returns (data, None) on success, or (None, reason) on failure:
    "too_large" if the extra byte was present (the file exceeds the
    limit, even if it grew after an earlier size check), "unreadable" for
    any OS-level error. Oversized content is never fully read into memory
    or retained.
    """
    try:
        with path.open("rb") as f:
            data = f.read(limit + 1)
    except OSError:
        return None, "unreadable"

    if len(data) > limit:
        return None, "too_large"

    return data, None


def read_file_safely(path: Path) -> ReadResult:
    if not path.is_file():
        return ReadResult(None, "unreadable")

    try:
        size = path.stat().st_size
    except OSError:
        return ReadResult(None, "unreadable")

    if size > MAX_FILE_SIZE_BYTES:
        return ReadResult(None, "too_large")

    raw, error = _read_bounded(path, MAX_FILE_SIZE_BYTES)
    if error is not None:
        return ReadResult(None, error)

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