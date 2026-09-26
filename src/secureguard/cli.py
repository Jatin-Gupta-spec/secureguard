"""Command-line interface for SecureGuard."""
from __future__ import annotations

from pathlib import Path

from secureguard.baseline import apply_baseline, load_baseline_fingerprints, write_baseline
from secureguard.discovery import TooManyFilesError
from secureguard.engine import run_scan
from secureguard.reporters.json_reporter import format_json
from secureguard.reporters.terminal import format_rule_explanation, format_summary
from secureguard.rules.catalog import ALL_RULES
from secureguard.reporters.html_reporter import format_html
from secureguard.reporters.sarif_reporter import format_sarif

USAGE = (
    "Usage: python -m secureguard scan <path> [--format text|json] [--baseline <file>]\n"
    "       python -m secureguard baseline <path> <output-file>\n"
    "       python -m secureguard explain <rule-id>"
)


def _parse_scan_args(args: list[str]):
    if not args:
        return None

    target = Path(args[0])
    output_format = "text"
    baseline_path = None

    i = 1
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            output_format = args[i + 1]
            i += 2
        elif args[i] == "--baseline" and i + 1 < len(args):
            baseline_path = Path(args[i + 1])
            i += 2
        else:
            return None

    if output_format not in ("text", "json", "html", "sarif"):
        return None

    if output_format not in ("text", "json", "html", "sarif"):
        return None

    return target, output_format, baseline_path


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = []

    if not argv:
        print(USAGE)
        return 3

    command = argv[0]

    if command == "explain":
        if len(argv) != 2:
            print(USAGE)
            return 3
        rule = ALL_RULES.get(argv[1].upper())
        if rule is None:
            print(f"Unknown rule: {argv[1]}")
            return 2
        print(format_rule_explanation(rule))
        return 0

    if command == "baseline":
        if len(argv) != 3:
            print(USAGE)
            return 3
        target = Path(argv[1])
        output_path = Path(argv[2])
        if not target.exists():
            print(f"Could not read: {target}")
            return 2
        try:
            summary = run_scan(target)
        except TooManyFilesError as exc:
            print(str(exc))
            return 2
        write_baseline(summary, output_path)
        print(f"Wrote {len(summary.findings)} fingerprint(s) to {output_path}")
        return 0

    if command != "scan":
        print(USAGE)
        return 3

    parsed = _parse_scan_args(argv[1:])
    if parsed is None:
        print(USAGE)
        return 3
    target, output_format, baseline_path = parsed

    if not target.exists():
        print(f"Could not read: {target}")
        return 2

    try:
        summary = run_scan(target)
    except TooManyFilesError as exc:
        print(str(exc))
        return 2

    if baseline_path is not None:
        known = load_baseline_fingerprints(baseline_path)
        summary = apply_baseline(summary, known)

    if output_format == "json":
        print(format_json(summary))
    elif output_format == "html":
        print(format_html(summary))
    elif output_format == "sarif":
        print(format_sarif(summary))
    else:
        print(format_summary(summary))

    if summary.files_scanned == 0:
        return 2

    return 0