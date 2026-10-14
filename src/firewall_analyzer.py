"""Parse and analyze firewall logs."""

from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "firewall" / "cisco_firewall.log"


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
    return datetime.strptime(
        f"2026 {month} {day} {time_value}",
        "%Y %b %d %H:%M:%S",
    )


def parse_firewall_log():
    events = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 10:
                continue

            month = parts[0]
            day = parts[1]
            time_value = parts[2]
            device = parts[3]
            action = parts[4]
            protocol = parts[5]

            fields = {}

            for item in parts[6:]:
                if "=" in item:
                    key, value = item.split("=", 1)
                    fields[key] = value

            event = {
                "timestamp": parse_timestamp(
                    month,
                    day,
                    time_value,
                ),
                "device": device,
                "action": action,
                "protocol": protocol,
                "src": fields.get("src"),
                "dst": fields.get("dst"),
                "sport": fields.get("sport"),
                "dport": fields.get("dport"),
                "raw": line,
            }

            events.append(event)

    return events


def is_private_ip(ip_address):
    if not ip_address:
        return False

    return (
        ip_address.startswith("10.")
        or ip_address.startswith("192.168.")
        or ip_address.startswith("172.16.")
        or ip_address.startswith("172.17.")
        or ip_address.startswith("172.18.")
        or ip_address.startswith("172.19.")
        or ip_address.startswith("172.2")
        or ip_address.startswith("172.30.")
        or ip_address.startswith("172.31.")
    )


def analyze_repeated_denies(events):
    findings = []

    grouped = {}

    for event in events:
        if event["action"] != "DENY":
            continue

        key = (
            event["src"],
            event["dst"],
        )

        grouped.setdefault(key, [])
        grouped[key].append(event)

    for key, denied_events in grouped.items():
        src, dst = key

        if len(denied_events) >= 3:
            ports = sorted(
                {
                    event["dport"]
                    for event in denied_events
                }
            )

            findings.append(
                create_finding(
                    "FW-DENY-001",
                    "High",
                    "Firewall",
                    denied_events[0]["device"],
                    "Repeated denied connections detected.",
                    (
                        f"src={src}, "
                        f"dst={dst}, "
                        f"denies={len(denied_events)}, "
                        f"ports={','.join(ports)}"
                    ),
                    "Investigate the source and determine whether the denied traffic is expected.",
                )
            )

    return findings


def analyze_port_scanning(events):
    findings = []

    grouped = {}

    for event in events:
        if event["action"] != "DENY":
            continue

        key = (
            event["src"],
            event["dst"],
        )

        grouped.setdefault(key, [])
        grouped[key].append(event)

    for key, scan_events in grouped.items():
        src, dst = key

        unique_ports = {
            event["dport"]
            for event in scan_events
        }

        if len(unique_ports) >= 4:
            findings.append(
                create_finding(
                    "FW-SCAN-001",
                    "High",
                    "Firewall",
                    scan_events[0]["device"],
                    "Possible port scanning behavior detected.",
                    (
                        f"src={src}, "
                        f"dst={dst}, "
                        f"unique_ports={','.join(sorted(unique_ports))}"
                    ),
                    "Block or investigate the source IP and review whether the target was subsequently accessed.",
                )
            )

    return findings


def analyze_success_after_scan(events):
    findings = []

    deny_history = {}

    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"],
    )

    for event in sorted_events:
        key = (
            event["src"],
            event["dst"],
        )

        if event["action"] == "DENY":
            deny_history.setdefault(key, [])
            deny_history[key].append(event)

        elif event["action"] == "ALLOW":
            prior_denies = deny_history.get(key, [])

            unique_ports = {
                denied["dport"]
                for denied in prior_denies
            }

            if len(unique_ports) >= 3:
                findings.append(
                    create_finding(
                        "FW-SCAN-002",
                        "Critical",
                        "Firewall",
                        event["device"],
                        "Successful connection occurred after scanning activity.",
                        (
                            f"src={event['src']}, "
                            f"dst={event['dst']}, "
                            f"allowed_port={event['dport']}, "
                            f"prior_scanned_ports={','.join(sorted(unique_ports))}"
                        ),
                        "Investigate the successful connection as possible follow-on exploitation.",
                    )
                )

    return findings


def analyze_lateral_movement(events):
    findings = []

    suspicious_ports = {"22", "3389", "445", "1433"}

    for event in events:
        if event["action"] != "ALLOW":
            continue

        if not (
            is_private_ip(event["src"])
            and is_private_ip(event["dst"])
        ):
            continue

        if event["dport"] not in suspicious_ports:
            continue

        findings.append(
            create_finding(
                "FW-LATERAL-001",
                "High",
                "Firewall",
                event["device"],
                "Potential lateral movement detected between internal systems.",
                (
                    f"src={event['src']}, "
                    f"dst={event['dst']}, "
                    f"port={event['dport']}"
                ),
                "Validate whether this internal administrative or database connection is expected.",
            )
        )

    return findings


def analyze_unusual_outbound(events):
    findings = []

    common_ports = {
        "53",
        "80",
        "123",
        "443",
    }

    for event in events:
        if event["action"] != "ALLOW":
            continue

        if not is_private_ip(event["src"]):
            continue

        if is_private_ip(event["dst"]):
            continue

        if event["dport"] not in common_ports:
            findings.append(
                create_finding(
                    "FW-OUTBOUND-001",
                    "High",
                    "Firewall",
                    event["device"],
                    "Unusual outbound connection detected.",
                    (
                        f"src={event['src']}, "
                        f"dst={event['dst']}, "
                        f"port={event['dport']}"
                    ),
                    "Investigate the destination and validate whether the outbound connection is authorized.",
                )
            )

    return findings


def analyze_vpn_activity(events):
    findings = []

    vpn_ports = {
        "500",
        "4500",
        "1194",
        "1723",
    }

    for event in events:
        if event["dport"] not in vpn_ports:
            continue

        findings.append(
            create_finding(
                "FW-VPN-001",
                "Medium",
                "Firewall",
                event["device"],
                "Potential VPN-related traffic detected.",
                (
                    f"action={event['action']}, "
                    f"src={event['src']}, "
                    f"dst={event['dst']}, "
                    f"port={event['dport']}"
                ),
                "Validate whether the VPN activity is expected and associated with an approved service.",
            )
        )

    return findings


def analyze_firewall():
    events = parse_firewall_log()

    findings = []

    findings.extend(
        analyze_repeated_denies(events)
    )

    findings.extend(
        analyze_port_scanning(events)
    )

    findings.extend(
        analyze_success_after_scan(events)
    )

    findings.extend(
        analyze_lateral_movement(events)
    )

    findings.extend(
        analyze_unusual_outbound(events)
    )

    findings.extend(
        analyze_vpn_activity(events)
    )

    return findings


def print_firewall_findings():
    findings = analyze_firewall()

    print(
        "\nNOVATECH FIREWALL SECURITY FINDINGS\n"
    )

    if not findings:
        print("No firewall security findings.")
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