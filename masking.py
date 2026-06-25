def mask(code: str, findings: list) -> str:
    masked = code
    for finding in findings:
        masked = masked.replace(finding["matched_value"], "[REDACTED]")
    return masked
