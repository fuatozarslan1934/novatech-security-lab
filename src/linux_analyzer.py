"""Parse and analyze Linux authentication logs."""

import re
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "endpoint" / "linux_auth.log"


FAILED_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]: Failed password for "
    r"(?P<user>\S+) from "
    r"(?P<source_ip>\S+) port "
    r"(?P<port>\d+)"
)

SUCCESS_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]: Accepted "
    r"(?P<auth_method>\S+) for "
    r"(?P<user>\S+) from "
    r"(?P<source_ip>\S+) port "
    r"(?P<port>\d+)"
)

SUDO_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sudo:\s+"
    r"(?P<user>\S+)\s+:.*"
    r"USER=(?P<target_user>\S+)\s+;\s+"
    r"COMMAND=(?P<command>.+)$"
)


def parse_timestamp(month, day, time_value):
    return datetime.strptime(
        f"2026 {month} {day} {time_value}",
        "%Y %b %d %H:%M:%S",
    )


def create_finding(
    finding_id,
    severity,
    host,
    identity,
    reason,
    evidence,
    recommendation,
):
    return {
        "finding_id": finding_id,
        "severity": severity,
        "host": host,
        "identity": identity,
        "reason": reason,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def parse_linux_log():
    events = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            failed_match = FAILED_RE.match(line)

            if failed_match:
                data = failed_match.groupdict()

                events.append(
                    {
                        "event_type": "ssh_failure",
                        "timestamp": parse_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "host": data["host"],
                        "user": data["user"],
                        "source_ip": data["source_ip"],
                        "raw": line,
                    }
                )
                continue

            success_match = SUCCESS_RE.match(line)

            if success_match:
                data = success_match.groupdict()

                events.append(
                    {
                        "event_type": "ssh_success",
                        "timestamp": parse_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "host": data["host"],
                        "user": data["user"],
                        "source_ip": data["source_ip"],
                        "auth_method": data["auth_method"],
                        "raw": line,
                    }
                )
                continue

            sudo_match = SUDO_RE.match(line)

            if sudo_match:
                data = sudo_match.groupdict()

                events.append(
                    {
                        "event_type": "sudo",
                        "timestamp": parse_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "host": data["host"],
                        "user": data["user"],
                        "target_user": data["target_user"],
                        "command": data["command"],
                        "source_ip": None,
                        "raw": line,
                    }
                )

    return events


def analyze_brute_force(events):
    findings = []
    grouped = {}

    for event in events:
        if event["event_type"] != "ssh_failure":
            continue

        key = (
            event["host"],
            event["source_ip"],
        )

        grouped.setdefault(key, [])
        grouped[key].append(event)

    for key, failures in grouped.items():
        host, source_ip = key

        if len(failures) >= 3:
            findings.append(
                create_finding(
                    "LINUX-AUTH-001",
                    "High",
                    host,
                    "Multiple users",
                    "Possible SSH brute-force activity detected.",
                    (
                        f"source_ip={source_ip}, "
                        f"failures={len(failures)}"
                    ),
                    "Investigate the source IP and consider blocking repeated unauthorized SSH attempts.",
                )
            )

    return findings


def analyze_username_enumeration(events):
    findings = []
    grouped = {}

    for event in events:
        if event["event_type"] != "ssh_failure":
            continue

        source_ip = event["source_ip"]

        grouped.setdefault(source_ip, [])
        grouped[source_ip].append(event)

    for source_ip, failures in grouped.items():
        usernames = {
            event["user"]
            for event in failures
        }

        if len(usernames) >= 3:
            findings.append(
                create_finding(
                    "LINUX-AUTH-002",
                    "High",
                    failures[0]["host"],
                    ",".join(sorted(usernames)),
                    "Possible username enumeration detected.",
                    (
                        f"source_ip={source_ip}, "
                        f"usernames={','.join(sorted(usernames))}"
                    ),
                    "Investigate the source and review SSH exposure and authentication controls.",
                )
            )

    return findings


def analyze_success_after_failures(events):
    findings = []

    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"],
    )

    failure_history = {}

    for event in sorted_events:
        source_ip = event.get("source_ip")

        if event["event_type"] == "ssh_failure":
            failure_history.setdefault(source_ip, [])
            failure_history[source_ip].append(event)

        elif event["event_type"] == "ssh_success":
            failures = failure_history.get(
                source_ip,
                [],
            )

            if len(failures) >= 3:
                findings.append(
                    create_finding(
                        "LINUX-AUTH-003",
                        "Critical",
                        event["host"],
                        event["user"],
                        "Successful SSH login occurred after repeated failures.",
                        (
                            f"source_ip={source_ip}, "
                            f"previous_failures={len(failures)}, "
                            f"success_time={event['timestamp']}"
                        ),
                        "Treat as possible credential compromise and investigate post-login activity.",
                    )
                )

    return findings


def analyze_privileged_activity(events):
    findings = []

    for event in events:
        if event["event_type"] == "ssh_success":
            if event["user"] == "root":
                findings.append(
                    create_finding(
                        "LINUX-PRIV-001",
                        "High",
                        event["host"],
                        event["user"],
                        "Direct root SSH login detected.",
                        (
                            f"source_ip={event['source_ip']}, "
                            f"auth_method={event['auth_method']}"
                        ),
                        "Review whether direct root SSH login is required and disable it where possible.",
                    )
                )

        elif event["event_type"] == "sudo":
            if event["target_user"] == "root":
                severity = "High"

                if "/etc/shadow" in event["command"]:
                    severity = "Critical"

                findings.append(
                    create_finding(
                        "LINUX-PRIV-002",
                        severity,
                        event["host"],
                        event["user"],
                        "Privileged sudo activity detected.",
                        (
                            f"target_user={event['target_user']}, "
                            f"command={event['command']}"
                        ),
                        "Verify that the privilege escalation and executed command were authorized.",
                    )
                )

    return findings


def analyze_linux():
    events = parse_linux_log()

    findings = []

    findings.extend(
        analyze_brute_force(events)
    )

    findings.extend(
        analyze_username_enumeration(events)
    )

    findings.extend(
        analyze_success_after_failures(events)
    )

    findings.extend(
        analyze_privileged_activity(events)
    )

    return findings


def print_linux_findings():
    findings = analyze_linux()

    print(
        "\nNOVATECH LINUX SECURITY FINDINGS\n"
    )

    if not findings:
        print("No Linux security findings.")
        return

    for finding in findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['finding_id']}"
        )
        print(f"Host: {finding['host']}")
        print(
            f"Identity: {finding['identity']}"
        )
        print(
            f"Reason: {finding['reason']}"
        )
        print(
            f"Evidence: {finding['evidence']}"
        )
        print(
            f"Recommendation: "
            f"{finding['recommendation']}"
        )
        print("-" * 60)
        