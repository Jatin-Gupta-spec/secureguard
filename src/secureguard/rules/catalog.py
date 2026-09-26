"""Rule catalogue: metadata and rationale for every SecureGuard rule."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    cwe: str
    default_severity: str
    default_confidence: str
    rationale: str
    explanation: str
    impact: str
    fix: str
    safe_example: str


PHP_SEC_001 = RuleMeta(
    rule_id="PHP-SEC-001",
    cwe="CWE-798",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "A credential-like variable or array key assigned a non-empty string "
        "literal is suspicious, but this pattern is also common in test "
        "fixtures, examples, and local-only config - so severity stays at "
        "Medium and confidence at Low rather than High, matching the locked "
        "spec's rule that a keyword match alone never justifies High severity."
    ),
    explanation=(
        "A variable or array key whose name looks like a credential "
        "(password, secret, api key, token, etc.) is assigned a non-empty, "
        "non-placeholder string literal directly in source code."
    ),
    impact=(
        "Anyone with read access to the source - including version control "
        "history - can read the credential in plain text. If the repository "
        "is ever made public, shared, or leaked, the credential is "
        "immediately compromised."
    ),
    fix=(
        "Load the value from an environment variable, a secrets manager, or "
        "a local, gitignored configuration file instead of hardcoding it."
    ),
    safe_example="$password = getenv('DB_PASSWORD');",
)

PY_SEC_001 = RuleMeta(
    rule_id="PY-SEC-001",
    cwe="CWE-798",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "Same reasoning as PHP-SEC-001: a credential-like name assigned a "
        "literal string is suspicious but common in fixtures and local-only "
        "config, so severity stays Medium and confidence Low rather than "
        "High on a keyword match alone."
    ),
    explanation=(
        "Same shape as PHP-SEC-001: a credential-like Python variable or "
        "dict key is assigned a non-empty, non-placeholder string literal "
        "directly in source code."
    ),
    impact=(
        "The credential is readable by anyone with source or git-history "
        "access, and is trivially exposed if the code is shared or made "
        "public."
    ),
    fix=(
        "Load the value from an environment variable (os.getenv) or a "
        "secrets manager instead of hardcoding it."
    ),
    safe_example='password = os.getenv("DB_PASSWORD")',
)

PHP_SQL_001 = RuleMeta(
    rule_id="PHP-SQL-001",
    cwe="CWE-89",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "A SQL-looking string concatenated with a non-literal expression is "
        "a classic injection shape, but this pattern-matcher cannot prove "
        "the concatenated value is attacker-controlled, reaches the "
        "database, or is unsanitized elsewhere - so it stays Medium/Low "
        "rather than High."
    ),
    explanation=(
        "A SQL-looking string literal is concatenated with a non-literal "
        "PHP expression (a variable, superglobal, or function result) "
        "rather than being fully hardcoded."
    ),
    impact=(
        "If the concatenated value ever originates from user input, an "
        "attacker can inject additional SQL, potentially reading, "
        "modifying, or deleting data beyond what the query was intended to "
        "access."
    ),
    fix=(
        "Use a parameterized query / prepared statement (e.g. PDO with "
        "bound parameters) instead of building the SQL string by "
        "concatenation."
    ),
    safe_example=(
        '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); '
        "$stmt->execute([$id]);"
    ),
)

PY_SQL_001 = RuleMeta(
    rule_id="PY-SQL-001",
    cwe="CWE-89",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "Same shape as PHP-SQL-001: a dynamically built SQL string passed "
        "to an execute-like call. Heuristic only - v0.1 does not parse the "
        "AST, so it can't fully confirm complete data flow, hence "
        "Medium/Low rather than High."
    ),
    explanation=(
        "A SQL-looking string is built with an f-string or + concatenation "
        "and passed directly to an execute-like database call (execute, "
        "executemany, executescript)."
    ),
    impact=(
        "Same risk as PHP-SQL-001: if any concatenated/interpolated value "
        "comes from user input, an attacker can inject SQL and access or "
        "alter data beyond the intended query."
    ),
    fix=(
        "Pass parameters separately from the SQL string, e.g. "
        "cursor.execute(sql, params), and let the database driver handle "
        "escaping."
    ),
    safe_example='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
)

PHP_CMD_001 = RuleMeta(
    rule_id="PHP-CMD-001",
    cwe="CWE-78",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "A shell-execution function receiving a non-literal argument is a "
        "classic command-injection shape, but a keyword match alone can't "
        "prove the value is attacker-controlled - so it stays Medium/Low, "
        "not High."
    ),
    explanation=(
        "A shell-executing function (system, exec, shell_exec, passthru, "
        "popen) is called with an argument that is not a fully hardcoded "
        "string literal."
    ),
    impact=(
        "If the non-literal portion of the command is influenced by user "
        "input, an attacker can inject additional shell commands, "
        "potentially gaining arbitrary code execution on the server."
    ),
    fix=(
        "Avoid shell execution of dynamic input entirely where possible; if "
        "unavoidable, validate the input against a strict allow-list and "
        "use escapeshellarg() on every argument."
    ),
    safe_example=(
        "$safeArg = escapeshellarg($userInput); "
        "shell_exec('ls ' . $safeArg);"
    ),
)

PY_CMD_001 = RuleMeta(
    rule_id="PY-CMD-001",
    cwe="CWE-78",
    default_severity="Medium",
    default_confidence="Low",
    rationale=(
        "os.system() always shells out, and shell=True explicitly opts "
        "into shell interpretation - both are risky regardless of the "
        "specific input, but neither proves the value is attacker-"
        "controlled, so severity/confidence stay Medium/Low. Safe list-form "
        "subprocess calls (no shell=True) must never be flagged."
    ),
    explanation=(
        "os.system() is called with a non-literal argument, or a "
        "subprocess call uses shell=True (which enables shell "
        "interpretation of the command string)."
    ),
    impact=(
        "If the command or its shell=True string is influenced by user "
        "input, an attacker can inject additional shell commands, "
        "potentially gaining arbitrary code execution."
    ),
    fix=(
        "Use subprocess with a list of arguments and shell=False (the "
        "default) - this passes arguments directly to the program without "
        "shell interpretation, so shell metacharacters in user input can't "
        "be abused."
    ),
    safe_example='subprocess.run(["ls", user_supplied_dir], shell=False)',
)

ALL_RULES: dict[str, RuleMeta] = {
    rule.rule_id: rule
    for rule in (
        PHP_SEC_001,
        PY_SEC_001,
        PHP_SQL_001,
        PY_SQL_001,
        PHP_CMD_001,
        PY_CMD_001,
    )
}