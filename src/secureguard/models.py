"""Data models for SecureGuard's findings and scan results."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    """A single possible security finding. Immutable once created - a
    finding shouldn't change after a rule reports it."""

    file_path: str        # root-relative, POSIX-style (e.g. "src/app.py")
    line_number: int
    rule_id: str           # e.g. "PY-SEC-001"
    severity: str          # e.g. "Low", "Medium", "High"
    confidence: str        # independent of severity - a keyword match alone
                            # is never enough to justify High severity
    cwe: str                # e.g. "CWE-798"
    evidence: str            # already redacted - never the raw secret/line
    explanation: str
    remediation: str
    evidence_key: str        # internal stable key, used for ordering
    fingerprint: str = field(init=False)  # computed - never passed in

    def __post_init__(self) -> None:
        raw = f"{self.rule_id}|{self.file_path}|{self.evidence_key}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        object.__setattr__(self, "fingerprint", digest)


@dataclass
class ScanSummary:
    """Aggregate result of one scan run."""

    files_scanned: int = 0
    skip_counts: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)