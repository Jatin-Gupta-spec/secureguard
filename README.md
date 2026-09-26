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

- **v0.2 update:** PY-SEC-001 now uses Python's `ast` module instead of regex, so
  it correctly ignores string literals that merely look like assignments (e.g. test
  setup code) - this eliminates the `tests/test_engine.py` false positive noted in
  the original v0.1 self-scan. PY-SQL-001 and PY-CMD-001, and all three PHP rules,
  remain regex-based for now.
- **v0.5 update:** the self-referential PY-CMD-001 findings in `catalog.py` and
  `python_rules.py` (documentation text describing `shell=True`) are now silenced
  with explicit `# secureguard: ignore[PY-CMD-001]` comments - a deliberate,
  visible acknowledgment that these specific matches are known false positives,
  not a hidden fix. `python -m secureguard scan src` now shows zero findings.
- For an accurate view of what SecureGuard reports about itself as a *shipped tool*
  (rather than its own tests and documentation), scan `src/` alone:
  `python -m secureguard scan src`
- A finding means "this pattern is worth a human look," never a confirmed
  vulnerability - SecureGuard proves nothing about taint, reachability, or
  sanitization.