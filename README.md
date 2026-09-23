# SecureGuard

Offline, local-first command-line static-analysis tool for authorized Python and PHP
source projects. Scans for possible hardcoded credentials, unsafe SQL construction,
and unsafe command execution using six pattern-based rules.

**Status:** v0.1 in progress — not yet functional.

## Safety
SecureGuard never executes scanned code, imports scanned modules, starts processes,
opens network connections, reads Git history, modifies source files, or uploads data.
A clean scan means no configured pattern matched the files that were successfully read.

## Installation, usage, exit codes, examples
To be filled in as each part is built.