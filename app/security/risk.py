SEVERITY_SCORES = {
    "info": 0,
    "low": 2,
    "medium": 5,
    "high": 8,
    "critical": 10
}


def calculate_risk(severity: str):
    severity = severity.lower()

    score = SEVERITY_SCORES.get(severity, 0)

    return {
        "severity": severity,
        "score": score
    }

