from secureguard.rules.python_rules import find_py_sql_001

samples = [
    'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    'cursor.execute("SELECT * FROM users")',
]

for sample in samples:
    findings = find_py_sql_001(sample, "sample.py")
    print(repr(sample), "->", findings)