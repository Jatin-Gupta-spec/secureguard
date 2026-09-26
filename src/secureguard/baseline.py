"""Baseline support: suppress previously-accepted findings by fingerprint.

A corrupted, missing, or malformed baseline file always fails toward
reporting MORE findings, never fewer - it is treated as "nothing was
previously accepted" rather than an error. Nothing in this file executes
or evaluates baseline content; it is only ever read as plain JSON data.
"""
from __future__ import annotations

import json
from pathlib import Path

from secureguard.models import ScanSummary


def load_baseline_fingerprints(path: Path) -> set[str]:
    if not path.is_file():
        return set()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()

    if not isinstance(data, dict):
        return set()

    fingerprints = data.get("fingerprints", [])
    if not isinstance(fingerprints, list):
        return set()

    return {fp for fp in fingerprints if isinstance(fp, str)}


def apply_baseline(summary: ScanSummary, baseline_fingerprints: set[str]) -> ScanSummary:
    return ScanSummary(
        files_scanned=summary.files_scanned,
        skip_counts=dict(summary.skip_counts),
        findings=[f for f in summary.findings if f.fingerprint not in baseline_fingerprints],
    )


def write_baseline(summary: ScanSummary, path: Path) -> None:
    fingerprints = sorted({f.fingerprint for f in summary.findings})
    data = {"fingerprints": fingerprints}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")