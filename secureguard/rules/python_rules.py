import re

RULES = [
    {
        "id": "PY-SECRET001",
        "pattern": re.compile(
            r"(password|passwd|api_key|secret|token)\s*=\s*[\"'][^\"']{4,}[\"']",
            re.IGNORECASE,
        ),
        "severity": "High",
        "why": "A password, API key, or token appears to be hardcoded directly in source code.",
        "fix": "Move secrets to environment variables or a secret manager.",
    },
]