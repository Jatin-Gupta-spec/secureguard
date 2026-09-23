import re
from secureguard.rules.python_rules import RULES

pattern = RULES[0]["pattern"]
print(pattern.search('API_KEY = "sk_live_51Hxxxx"') is not None)  # expect True
print(pattern.search("x = 5") is not None)                        # expect False