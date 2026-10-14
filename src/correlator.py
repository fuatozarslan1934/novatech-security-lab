"""Correlate events across datasets."""

import json
import re
from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

SUSPICIOUS_IP = "198.51.100.77"


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def parse_iso_timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_syslog_timestamp(month, day, time_value):
    timestamp = datetime.strptime(
        f"2026 {month} {day} {time_value}",
        "%Y %b %d %H:%M:%S",
    )

    return timestamp.replace(tzinfo=timezone.utc)

def get_incident(incident_id):
    data = load_json(
        DATA_DIR / "incidents" / "incident_queue.json"
    )

    for incident in data.get("incidents", []):
        if incident.get("id") == incident_id:
            return incident

    return None


def collect_entra_events(source_ip):
    events = []

    signins = load_json(
        DATA_DIR / "identity" / "entra_signins.json"
    )

    for event in signins:
        if event.get("source_ip") != source_ip:
            continue

        events.append(
            {
                "timestamp": parse_iso_timestamp(
                    event["timestamp"]
                ),
                "source": "Entra ID",
                "system": event.get("application"),
                "identity": event.get("user"),
                "action": f"Sign-in {event.get('result')}",
                "resource": event.get("application"),
                "source_ip": event.get("source_ip"),
                "raw": event,
            }
        )

    return events


def collect_azure_events(source_ip):
    events = []

    activity = load_json(
        DATA_DIR / "cloud" / "azure_activity.json"
    )

    for event in activity:
        if event.get("source_ip") != source_ip:
            continue

        events.append(
            {
                "timestamp": parse_iso_timestamp(
                    event["timestamp"]
                ),
                "source": "Azure Activity",
                "system": "Azure",
                "identity": event.get("caller"),
                "action": event.get("operation"),
                "resource": event.get("resource"),
                "source_ip": event.get("source_ip"),
                "raw": event,
            }
        )

    return events


def collect_cisco_events(source_ip):
    events = []

    log_path = (
        DATA_DIR / "network" / "cisco-core.log"
    )

    login_pattern = re.compile(
        r"^(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<device>\S+).*"
        r"\[user:\s*(?P<user>[^\]]+)\].*"
        r"\[Source:\s*(?P<source_ip>[^\]]+)\]"
    )

    config_pattern = re.compile(
        r"^(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<device>\S+)\s+"
        r"%SYS-5-CONFIG_I: Configured from console by "
        r"(?P<user>\S+)"
    )

    suspicious_users = set()

    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            login_match = login_pattern.match(line)

            if login_match:
                data = login_match.groupdict()

                if data["source_ip"] != source_ip:
                    continue

                action = "Cisco login activity"

                if "LOGIN_FAILED" in line:
                    action = "Cisco login failure"

                elif "LOGIN_SUCCESS" in line:
                    action = "Cisco login success"
                    suspicious_users.add(data["user"])

                events.append(
                    {
                        "timestamp": parse_syslog_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "source": "Cisco",
                        "system": data["device"],
                        "identity": data["user"],
                        "action": action,
                        "resource": data["device"],
                        "source_ip": data["source_ip"],
                        "raw": line,
                    }
                )

                continue

            config_match = config_pattern.match(line)

            if config_match:
                data = config_match.groupdict()

                if data["user"] not in suspicious_users:
                    continue

                events.append(
                    {
                        "timestamp": parse_syslog_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "source": "Cisco",
                        "system": data["device"],
                        "identity": data["user"],
                        "action": "Cisco configuration change",
                        "resource": data["device"],
                        "source_ip": source_ip,
                        "raw": line,
                    }
                )

    return events


def collect_linux_events(source_ip):
    events = []

    log_path = (
        DATA_DIR / "endpoint" / "linux_auth.log"
    )

    failed_pattern = re.compile(
        r"^(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+).*"
        r"Failed password for (?P<user>\S+) from "
        r"(?P<source_ip>\S+)"
    )

    success_pattern = re.compile(
        r"^(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+).*"
        r"Accepted \S+ for (?P<user>\S+) from "
        r"(?P<source_ip>\S+)"
    )

    sudo_pattern = re.compile(
        r"^(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sudo:\s+"
        r"(?P<user>\S+).*"
        r"USER=(?P<target_user>\S+).*"
        r"COMMAND=(?P<command>.+)$"
    )

    compromised_users = set()

    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            failed_match = failed_pattern.match(line)

            if failed_match:
                data = failed_match.groupdict()

                if data["source_ip"] != source_ip:
                    continue

                events.append(
                    {
                        "timestamp": parse_syslog_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "source": "Linux",
                        "system": data["host"],
                        "identity": data["user"],
                        "action": "SSH login failure",
                        "resource": data["host"],
                        "source_ip": data["source_ip"],
                        "raw": line,
                    }
                )

                continue

            success_match = success_pattern.match(line)

            if success_match:
                data = success_match.groupdict()

                if data["source_ip"] != source_ip:
                    continue

                compromised_users.add(data["user"])

                events.append(
                    {
                        "timestamp": parse_syslog_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "source": "Linux",
                        "system": data["host"],
                        "identity": data["user"],
                        "action": "SSH login success",
                        "resource": data["host"],
                        "source_ip": data["source_ip"],
                        "raw": line,
                    }
                )

                continue

            sudo_match = sudo_pattern.match(line)

            if sudo_match:
                data = sudo_match.groupdict()

                if data["user"] not in compromised_users:
                    continue

                events.append(
                    {
                        "timestamp": parse_syslog_timestamp(
                            data["month"],
                            data["day"],
                            data["time"],
                        ),
                        "source": "Linux",
                        "system": data["host"],
                        "identity": data["user"],
                        "action": (
                            "Privileged sudo command: "
                            f"{data['command']}"
                        ),
                        "resource": data["host"],
                        "source_ip": source_ip,
                        "raw": line,
                    }
                )

    return events


def collect_firewall_events(source_ip):
    events = []

    log_path = (
        DATA_DIR / "firewall" / "cisco_firewall.log"
    )

    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            parts = line.split()

            if len(parts) < 10:
                continue

            fields = {}

            for item in parts[6:]:
                if "=" in item:
                    key, value = item.split("=", 1)
                    fields[key] = value

            if fields.get("src") != source_ip:
                continue

            events.append(
                {
                    "timestamp": parse_syslog_timestamp(
                        parts[0],
                        parts[1],
                        parts[2],
                    ),
                    "source": "Firewall",
                    "system": parts[3],
                    "identity": None,
                    "action": (
                        f"{parts[4]} {parts[5]} "
                        f"to port {fields.get('dport')}"
                    ),
                    "resource": fields.get("dst"),
                    "source_ip": fields.get("src"),
                    "raw": line,
                }
            )

    return events


def correlate_source_ip(source_ip):
    events = []

    events.extend(
        collect_entra_events(source_ip)
    )
    events.extend(
        collect_cisco_events(source_ip)
    )
    events.extend(
        collect_azure_events(source_ip)
    )
    events.extend(
        collect_linux_events(source_ip)
    )
    events.extend(
        collect_firewall_events(source_ip)
    )

    return sorted(
        events,
        key=lambda event: event["timestamp"],
    )


def build_incident_summary(source_ip):
    events = correlate_source_ip(source_ip)

    systems = sorted(
        {
            event["system"]
            for event in events
            if event.get("system")
        }
    )

    identities = sorted(
        {
            event["identity"]
            for event in events
            if event.get("identity")
        }
    )

    sources = sorted(
        {
            event["source"]
            for event in events
        }
    )

    return {
        "source_ip": source_ip,
        "event_count": len(events),
        "sources": sources,
        "systems": systems,
        "identities": identities,
        "events": events,
    }


def investigate_incident(incident_id):
    incident = get_incident(incident_id)

    if not incident:
        return None

    result = {
        "incident": incident,
        "correlation": None,
    }

    if incident_id == "INC-004":
        result["correlation"] = build_incident_summary(
            SUSPICIOUS_IP
        )

    return result


def print_incident_investigation(incident_id):
    result = investigate_incident(incident_id)

    if not result:
        print(
            f"\nIncident not found: {incident_id}\n"
        )
        return

    incident = result["incident"]

    print(
        f"\nNOVATECH INCIDENT INVESTIGATION: "
        f"{incident_id}\n"
    )

    print(f"Title: {incident['title']}")
    print(f"Difficulty: {incident['difficulty']}")
    print(f"Status: {incident['status']}")

    correlation = result.get("correlation")

    if not correlation:
        print(
            "\nDetailed correlation is currently "
            "implemented for INC-004."
        )
        return

    print(
        f"\nPrimary Indicator: "
        f"{correlation['source_ip']}"
    )

    print(
        f"Correlated Events: "
        f"{correlation['event_count']}"
    )

    print(
        "Sources: "
        + ", ".join(correlation["sources"])
    )

    print(
        "Systems: "
        + ", ".join(correlation["systems"])
    )

    print(
        "Identities: "
        + ", ".join(correlation["identities"])
    )

    print("\nTIMELINE\n")

    for event in correlation["events"]:
        print(
            event["timestamp"].isoformat()
        )
        print(
            f"  Source: {event['source']}"
        )
        print(
            f"  System: {event['system']}"
        )

        if event.get("identity"):
            print(
                f"  Identity: {event['identity']}"
            )

        print(
            f"  Action: {event['action']}"
        )
        print(
            f"  Resource: {event['resource']}"
        )
        print(
            f"  Source IP: {event['source_ip']}"
        )
        print("-" * 60)

    print(
        "\nCORRELATION ASSESSMENT\n"
    )

    print(
        "The same source IP appears across Entra ID, "
        "Cisco, Azure, Linux, and firewall telemetry. "
        "The sequence includes repeated authentication "
        "failures, successful privileged access, "
        "configuration changes, cloud activity, SSH "
        "access, and privileged Linux activity. These "
        "events may represent one multi-system security "
        "incident rather than unrelated alerts."
    )