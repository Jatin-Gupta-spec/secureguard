"""Redaction helpers - ensures secret values never appear in output."""
from __future__ import annotations

REDACTED_PLACEHOLDER = "***redacted***"


def redact(name: str) -> str:
    """Return a safe, non-reversible stand-in for a credential's evidence.

    The actual secret value is never passed in and never appears in the
    result - only the variable/key name (itself not a secret) is shown,
    paired with a fixed placeholder.
    """
    return f"{name} = {REDACTED_PLACEHOLDER}"