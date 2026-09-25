# Security Policy

## What SecureGuard does and does not do
SecureGuard is a local, offline, read-only static-analysis tool.

- It never makes network or DNS requests.
- It never executes, imports, or evaluates any code it scans.
- It never modifies the files it scans.
- It never stores or logs raw secret values - credential evidence is always
  replaced with `***redacted***` before being printed.
- It does not read Git history, and it does not require any authentication
  or credentials of its own to run.

## Reporting a vulnerability in SecureGuard itself
This is a student learning project (v0.1), not a maintained public tool. If you
find a security issue in SecureGuard's own code (for example, something that
would let it execute untrusted input despite the guarantees above), please open
an issue in this repository describing the problem and, if possible, a minimal
reproduction. Please do not include real credentials or sensitive data in any
report or reproduction case.

## Out of scope for v0.1
The following are explicitly not implemented and should not be assumed to work:
- Dependency/CVE vulnerability scanning
- Runtime or localhost probing of any kind
- Exploit generation or proof-of-concept payloads
- Automatic source rewriting or "auto-fix"
- JSON, HTML, or SARIF report output
- A release gate (all scans exit 0 regardless of findings, per the locked v0.1 spec)