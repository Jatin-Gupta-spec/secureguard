import tempfile
from pathlib import Path

from secureguard.engine import run_scan

with tempfile.TemporaryDirectory() as tmpdir:
    tmp = Path(tmpdir)

    (tmp / "app.py").write_text(
        'password = "hunter2"  # secureguard: ignore\n', encoding="utf-8"
    )
    (tmp / "app.php").write_text(
        '<?php\n'
        'system("SELECT * FROM users WHERE id = " . $id); // secureguard: ignore[PHP-SQL-001]\n',
        encoding="utf-8",
    )

    summary = run_scan(tmp)
    for f in summary.findings:
        print(f.rule_id, f.file_path)