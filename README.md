# SecureGuard

Offline, local-first command-line static-analysis tool for authorized Python and PHP
source projects. Scans for possible hardcoded credentials, unsafe SQL construction,
and unsafe command execution using six pattern-based rules.

**Status:** v0.1 complete.

## Safety
SecureGuard never executes scanned code, imports scanned modules, starts processes,
opens network connections, reads Git history, modifies source files, or uploads data.
A clean scan means no configured pattern matched the files that were successfully read.

## Installation
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Usage
```powershell
python -m secureguard scan <path>
```
`<path>` may be a single file or a directory (scanned recursively). `.git`, `.venv`,
`venv`, `vendor`, `node_modules`, `build`, `dist`, `__pycache__`, and `.pytest_cache`
are excluded by default.

## Exit codes
| Code | Meaning |
|------|---------|
| 0 | Scan completed (including when findings were printed - v0.1 has no release gate) |
| 2 | Invalid path, or zero eligible files could be read |
| 3 | Usage error (missing path or bad arguments) |

## Rules

| Rule | CWE | What it looks for |
|------|-----|--------------------|
| PHP-SEC-001 | CWE-798 | Hardcoded credential assigned to a credential-like PHP variable/key |
| PY-SEC-001 | CWE-798 | Same, for Python |
| PHP-SQL-001 | CWE-89 | SQL string concatenated with a non-literal PHP expression |
| PY-SQL-001 | CWE-89 | Dynamically built SQL string passed to an execute-like call |
| PHP-CMD-001 | CWE-78 | Shell-execution function called with a non-literal argument |
| PY-CMD-001 | CWE-78 | os.system() with a non-literal argument, or subprocess with shell=True |

## Example output
tests/fixtures/php/vulnerable/hardcoded_password.php:2: PHP-SEC-001 [Medium/Low] CWE-798
Evidence: password = redacted
Possible hardcoded credential assigned as a literal value.
Fix: Load this value from an environment variable or secret store instead.
Scanned 1 file(s).


## Known limitations
SecureGuard is a regex/pattern-based scanner, not a parser - it has no understanding
of Python or PHP syntax beyond simple text patterns. This is a deliberate v0.1 scope
decision (AST-based analysis is planned for v0.2+), with real, observable consequences:

- **It can flag its own test code.** `python -m secureguard scan .` against this repo
  flags lines in `tests/test_engine.py` where test setup code builds a temporary
  fixture using a string like `'$password = "hunter2";'` - PY-SEC-001 can't
  distinguish that from a real assignment, because both are just matching text.
- **It can even flag its own rule descriptions.** PY-CMD-001's explanation text
  contains the phrase `shell=True` (because it's *describing* that pattern), which
  the rule then matches against its own source code.
- For an accurate view of what SecureGuard reports about itself as a *shipped tool*
  (rather than its own tests and documentation), scan `src/` alone:
  `python -m secureguard scan src`
- A finding means "this pattern is worth a human look," never a confirmed
  vulnerability - SecureGuard proves nothing about taint, reachability, or
  sanitization.