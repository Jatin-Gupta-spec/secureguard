from secureguard.rules.python_rules import find_py_sec_001

samples = [
    'password = "hunter2"',
    '"api_key": "sk-real-looking-value",',
    'DB_PASSWORD = "s3cr3t!"',
    'password = os.getenv("APP_PASSWORD")',
    '# password = "test123"  example only',
    'password = "changeme"',
]

for sample in samples:
    findings = find_py_sec_001(sample, "sample.py")
    print(repr(sample), "->", findings)