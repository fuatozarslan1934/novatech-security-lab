"""Calculate finding severity and risk summaries."""


SEVERITY_SCORES = {
    "Critical": 40,
    "High": 25,
    "Medium": 10,
    "Low": 5,
}
INCIDENT_BASE_SCORES = {
    "Easy": 10,
    "Medium": 20,
    "Hard": 40,
}
def score_investigation(investigation):
    incident = investigation.get(
        "incident",
        {},
    )

    correlation = investigation.get(
        "correlation",
        {},
    ) or {}

    difficulty = incident.get(
        "difficulty",
        "Easy",
    )

    base_score = INCIDENT_BASE_SCORES.get(
        difficulty,
        10,
    )

    summary = build_incident_risk_summary(
        base_score,
        correlation,
    )

    summary["incident_id"] = incident.get("id")
    summary["difficulty"] = difficulty

    return summary

def score_finding(finding):
    severity = finding.get(
        "severity",
        "Low",
    )

    return SEVERITY_SCORES.get(
        severity,
        0,
    )


def calculate_risk_score(findings):
    total_score = sum(
        score_finding(finding)
        for finding in findings
    )

    return min(total_score, 100)


def get_risk_level(score):
    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


def build_risk_summary(findings):
    score = calculate_risk_score(
        findings
    )

    return {
        "score": score,
        "level": get_risk_level(score),
        "finding_count": len(findings),
    }

    def calculate_incident_bonus(correlation):
        bonus = 0
    reasons = []

    sources = correlation.get(
        "sources",
        [],
    )

    events = correlation.get(
        "events",
        [],
    )

    if len(sources) >= 3:
        bonus += 15
        reasons.append(
            "Multi-source correlation"
        )

    actions = [
        event.get(
            "action",
            "",
        ).lower()
        for event in events
    ]

    if any(
        "success" in action
        for action in actions
    ):
        bonus += 15
        reasons.append(
            "Successful access detected"
        )

    if any(
        "sudo" in action
        or "privileged" in action
        for action in actions
    ):
        bonus += 15
        reasons.append(
            "Privileged activity detected"
        )

    if any(
        "configuration change" in action
        or "securityrules/write" in action
        for action in actions
    ):
        bonus += 10
        reasons.append(
            "Configuration change detected"
        )

    return {
        "bonus": bonus,
        "reasons": reasons,
    }

def calculate_incident_bonus(correlation):
    bonus = 0
    reasons = []

    sources = correlation.get(
        "sources",
        [],
    )

    events = correlation.get(
        "events",
        [],
    )

    if len(sources) >= 3:
        bonus += 15
        reasons.append(
            "Multi-source correlation"
        )

    actions = [
        event.get(
            "action",
            "",
        ).lower()
        for event in events
    ]

    if any(
        "success" in action
        for action in actions
    ):
        bonus += 15
        reasons.append(
            "Successful access detected"
        )

    if any(
        "sudo" in action
        or "privileged" in action
        for action in actions
    ):
        bonus += 15
        reasons.append(
            "Privileged activity detected"
        )

    if any(
        "configuration change" in action
        or "securityrules/write" in action
        for action in actions
    ):
        bonus += 10
        reasons.append(
            "Configuration change detected"
        )

    return {
        "bonus": bonus,
        "reasons": reasons,
    }
def build_incident_risk_summary(
    base_score,
    correlation,
):
    incident_bonus = (
        calculate_incident_bonus(
            correlation
        )
    )

    final_score = min(
        base_score
        + incident_bonus["bonus"],
        100,
    )

    return {
        "base_score": base_score,
        "bonus": incident_bonus["bonus"],
        "bonus_reasons": incident_bonus["reasons"],
        "final_score": final_score,
        "level": get_risk_level(
            final_score
        ),
    }