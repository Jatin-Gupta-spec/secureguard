# SecureGuard

Offline, local-first command-line static-analysis tool for authorized Python and PHP
source projects. Scans for possible hardcoded credentials, unsafe SQL construction,
and unsafe command execution using six pattern-based rules (one AST-based, five
regex-based).

**Status:** v0.1 complete, plus the full v0.2/0.4/0.5+ feature set (fingerprints,
JSON/HTML/SARIF output, rule catalogue `explain` command, baseline comparison,
inline suppressions, and a pre-commit hook).

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
python -m secureguard scan <path> [--format text|json|html|sarif] [--baseline <file>]
python -m secureguard baseline <path> <output-file>
python -m secureguard explain <rule-id>
```
`<path>` may be a single file or a directory (scanned recursively). `.git`, `.venv`,
`venv`, `vendor`, `node_modules`, `build`, `dist`, `__pycache__`, and `.pytest_cache`
are excluded by default.

- `--format` selects the output: `text` (default, human-readable), `json`
  (machine-readable, includes each finding's stable `fingerprint`), `html`
  (a browsable report - all content is HTML-escaped), or `sarif` (for GitHub
  Code Scanning / CI integration).
- `--baseline <file>` suppresses any finding whose fingerprint already appears in
  that file - use `baseline <path> <output-file>` to create one from the current
  results. A missing or corrupted baseline file always fails toward showing *more*
  findings, never fewer.
- `explain <rule-id>` prints a rule's full CWE, rationale, impact, fix, and a safe
  code example, independent of actually finding an instance of it.

### Inline suppressions
A comment containing `secureguard: ignore` anywhere on a line suppresses every
finding on that line; `secureguard: ignore[RULE-ID]` (or a comma-separated list)
suppresses only the named rule(s), leaving any other finding on that same line
intact.

## Exit codes
| Code | Meaning |
|------|---------|
| 0 | Scan completed (including when findings were printed - no release gate) |
| 2 | Invalid path, zero eligible files could be read, or an unknown rule name given to `explain` |
| 3 | Usage error (missing path/rule-id, or bad arguments) |

## Rules

| Rule | CWE | What it looks for |
|------|-----|--------------------|
| PHP-SEC-001 | CWE-798 | Hardcoded credential assigned to a credential-like PHP variable/key |
| PY-SEC-001 | CWE-798 | Same, for Python - AST-based (not regex) since v0.2 |
| PHP-SQL-001 | CWE-89 | SQL string concatenated with a non-literal PHP expression |
| PY-SQL-001 | CWE-89 | Dynamically built SQL string passed to an execute-like call |
| PHP-CMD-001 | CWE-78 | Shell-execution function called with a non-literal argument |
| PY-CMD-001 | CWE-78 | os.system() with a non-literal argument, or subprocess with shell=True |

Run `python -m secureguard explain <rule-id>` for full detail on any rule above.

## Example output
tests/fixtures/php/vulnerable/hardcoded_password.php:2: PHP-SEC-001 [Medium/Low] CWE-798
Evidence: password = redacted
Possible hardcoded credential assigned as a literal value.
Fix: Load this value from an environment variable or secret store instead.
Scanned 1 file(s).


## Optional: pre-commit hook
To block commits containing new possible security issues in `src/`:
```powershell
git config core.hooksPath hooks
```
Run once per clone. The hook only scans `src/` (never `tests/fixtures/*/vulnerable/`,
which is intentionally vulnerable by design). Bypass in an emergency with
`git commit --no-verify`.

## Known limitations
SecureGuard's PHP rules and two of its three Python rules (PY-SQL-001, PY-CMD-001)
are regex/pattern-based, not real parsers - they have no understanding of PHP or
Python syntax beyond text patterns. This is a deliberate scope decision, with real,
observable consequences:

- **PY-SEC-001 is AST-based** (since v0.2) and correctly ignores comments,
  docstrings, and string literals that merely look like assignments (e.g. test
  setup code) - it understands Python's actual syntax tree rather than guessing
  from text.
- **PHP-SEC-001, PHP-SQL-001, PHP-CMD-001, PY-SQL-001, and PY-CMD-001 remain
  regex-based** and can still be fooled by a string that merely looks like the
  pattern they check for, without actually being that code.
- **Self-referential matches in this repo's own documentation** (PY-CMD-001 matching
  the phrase `shell=True` inside its own rule descriptions) are explicitly
  acknowledged and silenced with `# secureguard: ignore[PY-CMD-001]` comments,
  visible directly in `catalog.py` and `python_rules.py` - not hidden.
- A finding means "this pattern is worth a human look," never a confirmed
  vulnerability - SecureGuard proves nothing about taint, reachability, or
  sanitization.