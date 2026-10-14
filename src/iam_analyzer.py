"""Analyze identities, RBAC, and sign-in events."""

import json
from pathlib import Path
from datetime import datetime, timezone

from rule_engine import get_rule_value


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

PRIVILEGED_ROLES = {"Owner", "Contributor"}


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def create_finding(
    finding_id,
    severity,
    identity,
    reason,
    evidence,
    recommendation,
):
    return {
        "finding_id": finding_id,
        "severity": severity,
        "identity": identity,
        "reason": reason,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def get_privileged_users():
    role_data = load_json(
        DATA_DIR / "identity" / "entra_roles.json"
    )

    privileged_users = set()

    for assignment in role_data.get("assignments", []):
        if assignment.get("role") in PRIVILEGED_ROLES:
            privileged_users.add(
                assignment.get("identity")
            )

    return privileged_users


def analyze_privileged_roles():
    findings = []

    role_data = load_json(
        DATA_DIR / "identity" / "entra_roles.json"
    )

    for assignment in role_data.get("assignments", []):
        role = assignment.get("role")
        identity = assignment.get("identity")
        scope = assignment.get("scope")

        if role == "Owner":
            findings.append(
                create_finding(
                    "IAM-RBAC-001",
                    "High",
                    identity,
                    "Identity has the Owner role.",
                    f"role={role}, scope={scope}",
                    "Review whether Owner access is required and apply least privilege.",
                )
            )

        elif role == "Contributor":
            findings.append(
                create_finding(
                    "IAM-RBAC-002",
                    "Medium",
                    identity,
                    "Identity has the Contributor role.",
                    f"role={role}, scope={scope}",
                    "Review Contributor access and reduce scope where possible.",
                )
            )

    return findings


def analyze_stale_privileged_accounts():
    findings = []

    users_data = load_json(
        DATA_DIR / "identity" / "entra_users.json"
    )

    privileged_users = get_privileged_users()

    stale_threshold = get_rule_value(
        "ID-STALE-001",
        "inactive_days_threshold",
        90,
    )

    now = datetime.now(timezone.utc)

    for user in users_data.get("users", []):
        username = user.get("username")

        if username not in privileged_users:
            continue

        last_signin = user.get("last_signin")

        if not last_signin:
            continue

        last_signin_dt = datetime.fromisoformat(
            last_signin.replace("Z", "+00:00")
        )

        days_since_signin = (
            now - last_signin_dt
        ).days

        if days_since_signin > stale_threshold:
            findings.append(
                create_finding(
                    "IAM-STALE-001",
                    "High",
                    username,
                    "Privileged account has been inactive for more than the configured threshold.",
                    (
                        f"last_signin={last_signin}, "
                        f"inactive_days={days_since_signin}, "
                        f"threshold={stale_threshold}"
                    ),
                    "Review the account and remove or disable unnecessary privileged access.",
                )
            )

    return findings


def analyze_failed_logins(signins):
    findings = []

    failed_threshold = get_rule_value(
        "ID-AUTH-001",
        "failed_threshold",
        3,
    )

    failure_map = {}

    for event in signins:
        if event.get("result") != "Failure":
            continue

        key = (
            event.get("user"),
            event.get("source_ip"),
        )

        failure_map.setdefault(key, [])
        failure_map[key].append(event)

    for key, failures in failure_map.items():
        user, source_ip = key

        if len(failures) >= failed_threshold:
            findings.append(
                create_finding(
                    "IAM-AUTH-001",
                    "High",
                    user,
                    "Multiple failed sign-in attempts detected.",
                    (
                        f"source_ip={source_ip}, "
                        f"failures={len(failures)}, "
                        f"threshold={failed_threshold}"
                    ),
                    "Investigate the source IP and verify whether the activity was legitimate.",
                )
            )

    return findings


def analyze_success_after_failures(signins):
    findings = []

    failed_threshold = get_rule_value(
        "ID-AUTH-001",
        "failed_threshold",
        3,
    )

    sorted_signins = sorted(
        signins,
        key=lambda event: event.get("timestamp", ""),
    )

    failures = {}

    for event in sorted_signins:
        user = event.get("user")
        source_ip = event.get("source_ip")
        result = event.get("result")

        key = (user, source_ip)

        if result == "Failure":
            failures.setdefault(key, [])
            failures[key].append(event)

        elif result == "Success":
            previous_failures = failures.get(key, [])

            if len(previous_failures) >= failed_threshold:
                findings.append(
                    create_finding(
                        "IAM-AUTH-002",
                        "Critical",
                        user,
                        "Successful sign-in occurred after repeated failures from the same source.",
                        (
                            f"source_ip={source_ip}, "
                            f"previous_failures={len(previous_failures)}, "
                            f"threshold={failed_threshold}, "
                            f"success_time={event.get('timestamp')}"
                        ),
                        "Investigate for possible credential compromise and review subsequent activity.",
                    )
                )

                failures[key] = []

    return findings


def analyze_privileged_unusual_sources(signins):
    findings = []

    privileged_users = get_privileged_users()

    for event in signins:
        if event.get("result") != "Success":
            continue

        user = event.get("user")
        source_ip = event.get("source_ip")

        if user not in privileged_users:
            continue

        if source_ip and not source_ip.startswith("10."):
            findings.append(
                create_finding(
                    "IAM-AUTH-003",
                    "High",
                    user,
                    "Privileged identity successfully signed in from an unusual external source.",
                    (
                        f"source_ip={source_ip}, "
                        f"application={event.get('application')}, "
                        f"timestamp={event.get('timestamp')}"
                    ),
                    "Validate the sign-in, review MFA and conditional access, and investigate related activity.",
                )
            )

    return findings


def scan_identity():
    findings = []

    signins = load_json(
        DATA_DIR / "identity" / "entra_signins.json"
    )

    findings.extend(analyze_privileged_roles())
    findings.extend(analyze_stale_privileged_accounts())
    findings.extend(analyze_failed_logins(signins))
    findings.extend(analyze_success_after_failures(signins))
    findings.extend(analyze_privileged_unusual_sources(signins))

    return findings


def print_identity_findings():
    findings = scan_identity()

    print("\nNOVATECH IDENTITY SECURITY FINDINGS\n")

    if not findings:
        print("No identity security findings.")
        return

    for finding in findings:
        print(f"[{finding['severity']}] {finding['finding_id']}")
        print(f"Identity: {finding['identity']}")
        print(f"Reason: {finding['reason']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Recommendation: {finding['recommendation']}")
        print("-" * 60)
