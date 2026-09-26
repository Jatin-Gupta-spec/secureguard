"""HTML reporting for SecureGuard.

All finding/text content is HTML-escaped before embedding, since it
originates from scanned source files - untrusted input. Without escaping,
a crafted file could inject markup or script into the generated report (a
classic stored-XSS shape), even though the report is only ever opened
locally by the person who ran the scan.
"""
from __future__ import annotations

from html import escape

from secureguard.models import Finding, ScanSummary


def _sort_key(finding: Finding) -> tuple[str, int, str, str]:
    return (finding.file_path, finding.line_number, finding.rule_id, finding.evidence_key)


def _finding_row(finding: Finding) -> str:
    return f"""
    <tr>
      <td>{escape(finding.file_path)}:{finding.line_number}</td>
      <td>{escape(finding.rule_id)}</td>
      <td>{escape(finding.severity)}/{escape(finding.confidence)}</td>
      <td>{escape(finding.cwe)}</td>
      <td><code>{escape(finding.evidence)}</code></td>
      <td>{escape(finding.explanation)}</td>
      <td>{escape(finding.remediation)}</td>
    </tr>"""


def format_html(summary: ScanSummary) -> str:
    findings = sorted(summary.findings, key=_sort_key)
    rows = "".join(_finding_row(f) for f in findings)
    skip_rows = "".join(
        f"<tr><td>{escape(reason)}</td><td>{count}</td></tr>"
        for reason, count in sorted(summary.skip_counts.items())
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecureGuard Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
  th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; vertical-align: top; }}
  th {{ background: #f2f2f2; }}
  code {{ font-family: monospace; }}
</style>
</head>
<body>
  <h1>SecureGuard Report</h1>
  <p>Scanned {summary.files_scanned} file(s). {len(findings)} finding(s).</p>

  <h2>Findings</h2>
  <table>
    <tr><th>Location</th><th>Rule</th><th>Severity/Confidence</th><th>CWE</th><th>Evidence</th><th>Explanation</th><th>Fix</th></tr>
    {rows}
  </table>

  <h2>Skipped files</h2>
  <table>
    <tr><th>Reason</th><th>Count</th></tr>
    {skip_rows}
  </table>
</body>
</html>
"""