"""Command-line interface for SecureGuard."""
from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    """Entry point. argv is the list of command-line args (excluding the
    program name); returning an int gives the process its exit code —
    0 means success, matching the locked spec's exit-code contract.
    """
    print("SecureGuard v0.1 - CLI scaffold. Scanning not implemented yet.")
    return 0