"""Recursive file discovery for SecureGuard.

Walks a root path (a single file or a directory), returns every eligible
.py/.php file it finds, while skipping excluded folders entirely and
never following symlinks or Windows junctions.
"""
from __future__ import annotations

from pathlib import Path

ELIGIBLE_SUFFIXES = {".py", ".php"}

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "vendor",
    "node_modules",
    "build",
    "dist",
    "__pycache__",
    ".pytest_cache",
}

MAX_ELIGIBLE_FILES = 10_000


class TooManyFilesError(Exception):
    """Raised when discovery would exceed MAX_ELIGIBLE_FILES."""


def discover_files(root: Path) -> list[Path]:
    """Return every eligible .py/.php file under `root`.

    `root` may be a single file (returned directly, if eligible) or a
    directory (walked recursively).
    """
    if root.is_file():
        return [root] if _is_eligible(root) else []

    found: list[Path] = []
    _walk(root, found)
    return found


def _walk(directory: Path, found: list[Path]) -> None:
    for entry in sorted(directory.iterdir()):
        if entry.is_symlink():
            continue

        if entry.is_dir():
            if entry.name in EXCLUDED_DIRS:
                continue
            _walk(entry, found)  # recursion: _walk calling itself
            continue

        if _is_eligible(entry):
            found.append(entry)
            if len(found) > MAX_ELIGIBLE_FILES:
                raise TooManyFilesError(
                    f"Scan exceeds the {MAX_ELIGIBLE_FILES}-file limit"
                )


def _is_eligible(path: Path) -> bool:
    return path.suffix.lower() in ELIGIBLE_SUFFIXES