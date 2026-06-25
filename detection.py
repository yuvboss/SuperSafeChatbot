import re
import math
from collections import Counter

PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS Secret Key", re.compile(r'(?i)aws.{0,20}secret.{0,20}["\'][A-Za-z0-9/+=]{40}["\']')),
    ("GitHub Token", re.compile(r'ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}')),
    ("Generic Password", re.compile(r'(?i)password\s*=\s*["\'][^"\']{1,}["\']')),
    ("Generic API Key", re.compile(r'(?i)api[_-]?key\s*=\s*["\'][^"\']{8,}["\']')),
    ("Generic Secret", re.compile(r'(?i)secret\s*=\s*["\'][^"\']{8,}["\']')),
    ("Bearer Token", re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*')),
]

ENTROPY_THRESHOLD = 4.5
MIN_TOKEN_LENGTH = 8


def _shannon_entropy(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect(code: str) -> list:
    findings = []
    seen_values = set()
    lines = code.splitlines()

    # Regex scan
    for cred_type, pattern in PATTERNS:
        for i, line in enumerate(lines, 1):
            for match in pattern.finditer(line):
                value = match.group()
                if value not in seen_values:
                    seen_values.add(value)
                    findings.append({
                        "type": cred_type,
                        "line_number": i,
                        "matched_value": value,
                        "method": "regex",
                    })

    # Shannon entropy scan — flag high-randomness strings
    for i, line in enumerate(lines, 1):
        tokens = re.split(r'[\s\'"=,;:(){}\[\]]+', line)
        for token in tokens:
            if len(token) >= MIN_TOKEN_LENGTH and token not in seen_values:
                e = _shannon_entropy(token)
                if e > ENTROPY_THRESHOLD:
                    seen_values.add(token)
                    findings.append({
                        "type": "High-entropy string",
                        "line_number": i,
                        "matched_value": token,
                        "method": "entropy",
                        "entropy": round(e, 2),
                    })

    return findings
