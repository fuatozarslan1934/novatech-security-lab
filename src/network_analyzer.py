"""Parse and analyze Cisco network device logs."""

import re
from pathlib import Path
from datetime import datetime
from rule_engine import get_rule_value


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "network" / "cisco-core.log"


FAILED_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<device>\S+)\s+"
    r"%SEC_LOGIN-4-LOGIN_FAILED:.*"
    r"\[user:\s*(?P<user>[^\]]+)\]\s+"
    r"\[Source:\s*(?P<source_ip>[^\]]+)\]"
)

SUCCESS_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<device>\S+)\s+"
    r"%SEC_LOGIN-5-LOGIN_SUCCESS:.*"
    r"\[user:\s*(?P<user>[^\]]+)\]\s+"
    r"\[Source:\s*(?P<source_ip>[^\]]+)\]"
)

CONFIG_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<device>\S+)\s+"
    r"%SYS-5-CONFIG_I: Configured from console by (?P<user>\S+)"
)


def create_finding(
    finding_id,
    severity,
    category,
    device,
    reason,
    evidence,
    recommendation,
):
    return {
        "finding_id": finding_id,
        "severity": severity,
        "category": category,
        "device": device,
        "reason": reason,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def parse_timestamp(month, day, time_value):
    timestamp_text = f"2026 {month} {day} {time_value}"

    return datetime.strptime(
        timestamp_text,
        "%Y %b %d %H:%M:%S",
    )


def parse_cisco_log():
    events = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            failed_match = FAILED_RE.match(line)

            if failed_match:
                data = failed_match.groupdict()

                events.append(
                    {
                        "event_type": "login_failure",
                        "timestamp": parse_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "device": data["device"],
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
                        "event_type": "login_success",
                        "timestamp": parse_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "device": data["device"],
                        "user": data["user"],
                        "source_ip": data["source_ip"],
                        "raw": line,
                    }
                )

                continue

            config_match = CONFIG_RE.match(line)

            if config_match:
                data = config_match.groupdict()

                events.append(
                    {
                        "event_type": "config_change",
                        "timestamp": parse_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "device": data["device"],
                        "user": data["user"],
                        "source_ip": None,
                        "raw": line,
                    }
                )

    return events


def analyze_failed_logins(events):
    findings = []

    grouped = {}

    for event in events:
        if event["event_type"] != "login_failure":
            continue

        key = (
            event["device"],
            event["source_ip"],
        )

        grouped.setdefault(key, [])
        grouped[key].append(event)

    for key, failures in grouped.items():
        device, source_ip = key

        if len(failures) >= get_rule_value(
    "NET-AUTH-001",
    "threshold",
    3,
):
            users = sorted(
                {
                    event["user"]
                    for event in failures
                }
            )

            findings.append(
                create_finding(
                    "NET-AUTH-001",
                    "High",
                    "Cisco Authentication",
                    device,
                    "Repeated failed administrative login attempts detected.",
                    (
                        f"source_ip={source_ip}, "
                        f"failures={len(failures)}, "
                        f"users={','.join(users)}"
                    ),
                    "Investigate the source IP and validate whether the login attempts were authorized.",
                )
            )

    return findings


def analyze_success_after_failures(events):
    findings = []

    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"],
    )

    failures_by_source = {}

    for event in sorted_events:
        source_ip = event.get("source_ip")

        if event["event_type"] == "login_failure":
            failures_by_source.setdefault(source_ip, [])
            failures_by_source[source_ip].append(event)

        elif event["event_type"] == "login_success":
            previous_failures = failures_by_source.get(
                source_ip,
                [],
            )

            if len(previous_failures) >= get_rule_value(
    "NET-AUTH-002",
    "threshold",
    3,
):
                findings.append(
                    create_finding(
                        "NET-AUTH-002",
                        "Critical",
                        "Cisco Authentication",
                        event["device"],
                        "Successful administrative login occurred after repeated failures.",
                        (
                            f"source_ip={source_ip}, "
                            f"user={event['user']}, "
                            f"previous_failures={len(previous_failures)}, "
                            f"success_time={event['timestamp']}"
                        ),
                        "Treat as possible credential compromise and review subsequent administrative activity.",
                    )
                )

                failures_by_source[source_ip] = []

    return findings


def analyze_config_after_suspicious_auth(events):
    findings = []

    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"],
    )

    failure_count = {}
    suspicious_successes = []

    for event in sorted_events:
        source_ip = event.get("source_ip")

        if event["event_type"] == "login_failure":
            failure_count[source_ip] = (
                failure_count.get(source_ip, 0) + 1
            )

        elif event["event_type"] == "login_success":
            if failure_count.get(source_ip, 0) >= get_rule_value(
    "NET-AUTH-002",
    "threshold",
    3,
):                suspicious_successes.append(event)

        elif event["event_type"] == "config_change":
            for success in suspicious_successes:
                same_user = (
                    success["user"] == event["user"]
                )

                time_difference = (
                    event["timestamp"]
                    - success["timestamp"]
                ).total_seconds()

                if (
                    same_user
                    and 0 <= time_difference <= 600
                ):
                    findings.append(
                        create_finding(
                            "NET-CONFIG-001",
                            "Critical",
                            "Cisco Configuration",
                            event["device"],
                            "Configuration change occurred shortly after suspicious authentication.",
                            (
                                f"user={event['user']}, "
                                f"login_time={success['timestamp']}, "
                                f"config_time={event['timestamp']}, "
                                f"source_ip={success['source_ip']}"
                            ),
                            "Review the configuration change and compare the device configuration with the approved baseline.",
                        )
                    )

    return findings


def analyze_repeated_source_activity(events):
    findings = []

    grouped = {}

    for event in events:
        source_ip = event.get("source_ip")

        if not source_ip:
            continue

        grouped.setdefault(source_ip, [])
        grouped[source_ip].append(event)

    for source_ip, source_events in grouped.items():
        if len(source_events) >= 4:
            devices = sorted(
                {
                    event["device"]
                    for event in source_events
                }
            )

            findings.append(
                create_finding(
                    "NET-SOURCE-001",
                    "Medium",
                    "Network Activity",
                    ",".join(devices),
                    "Repeated activity from the same source IP detected.",
                    (
                        f"source_ip={source_ip}, "
                        f"events={len(source_events)}"
                    ),
                    "Review the source IP activity and determine whether the behavior is expected.",
                )
            )

    return findings


def analyze_cisco():
    events = parse_cisco_log()

    findings = []

    findings.extend(
        analyze_failed_logins(events)
    )

    findings.extend(
        analyze_success_after_failures(events)
    )

    findings.extend(
        analyze_config_after_suspicious_auth(events)
    )

    findings.extend(
        analyze_repeated_source_activity(events)
    )

    return findings


def hunt_indicator(indicator):
    events = parse_cisco_log()

    matching_events = []

    for event in events:
        if indicator in event["raw"]:
            matching_events.append(event)

    return matching_events


def print_hunt_results(indicator):
    events = hunt_indicator(indicator)

    print(
        f"\nNOVATECH CISCO HUNT: {indicator}\n"
    )

    if not events:
        print("No matching Cisco events found.")
        return

    for event in events:
        print(event["raw"])


def print_network_findings():
    findings = analyze_cisco()

    print(
        "\nNOVATECH CISCO SECURITY FINDINGS\n"
    )

    if not findings:
        print("No Cisco security findings.")
        return

    for finding in findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['finding_id']}"
        )
        print(
            f"Device: {finding['device']}"
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