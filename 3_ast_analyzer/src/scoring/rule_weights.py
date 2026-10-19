"""Default static-analysis rule weights on a 0-10 risk scale."""

RULE_WEIGHTS: dict[str, float] = {
    "SQLI_RAW_CONCAT": 9.0,
    "AF-VULN-001": 9.0,
    "AF-TAINT-001": 9.0,
    "CMD_INJ_EXEC": 8.5,
    "XSS_UNSANITIZED_WRITE": 6.1,
    "LOG_INJECTION": 3.8,
}

DEFAULT_RULE_WEIGHT = 5.0


def get_rule_weight(rule_id: str) -> float:
    return RULE_WEIGHTS.get(rule_id, DEFAULT_RULE_WEIGHT)
