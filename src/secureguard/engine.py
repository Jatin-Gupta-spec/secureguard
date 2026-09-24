"""Scan orchestration: runs the right rules against each file's content."""
from __future__ import annotations

from pathlib import Path

from secureguard.discovery import discover_files
from secureguard.models import ScanSummary
from secureguard.reader import read_file_safely
from secureguard.rules.php_rules import PHP_RULES
from secureguard.rules.python_rules import PY_RULES

_PHP_SUFFIXES = {".php"}
_PY_SUFFIXES = {".py"}


def _rules_for(path: Path) -> list:
    suffix = path.suffix.lower()
    if suffix in _PHP_SUFFIXES:
        return PHP_RULES
    if suffix in _PY_SUFFIXES:
        return PY_RULES
    return []


def _relative_posix(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    return rel.as_posix()


def run_scan(target: Path) -> ScanSummary:
    """Discover, read, and scan every eligible file under `target`.

    May raise TooManyFilesError (from discover_files) - the caller is
    responsible for turning that into exit code 2.
    """
    summary = ScanSummary()
    files = discover_files(target)
    root = target if target.is_dir() else target.parent

    for path in files:
        result = read_file_safely(path)
        if result.content is None:
            summary.skip_counts[result.skip_reason] = (
                summary.skip_counts.get(result.skip_reason, 0) + 1
            )
            continue

        summary.files_scanned += 1
        rel_path = _relative_posix(path, root)

        for rule in _rules_for(path):
            summary.findings.extend(rule(result.content, rel_path))

    return summary