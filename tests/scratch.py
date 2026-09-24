from secureguard.rules.php_rules import find_php_sec_001

samples = [
    '$password = "hunter2";',
    "'api_key' => 'sk-real-looking-value',",
    '$DB_PASSWORD = "s3cr3t!";',
    "$password = getenv('APP_PASSWORD');",
    '// $password = "test123"; example only',
    '$password = "changeme";',
]

for sample in samples:
    findings = find_php_sec_001(sample, "sample.php")
    print(repr(sample), "->", findings)