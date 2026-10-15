"""Search indicators across multiple security telemetry sources."""

import json
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


TEXT_SOURCES = {
    "Cisco": DATA_DIR / "network" / "cisco-core.log",
    "Firewall": DATA_DIR / "firewall" / "cisco_firewall.log",
    "Linux": DATA_DIR / "endpoint" / "linux_auth.log",
}


JSON_SOURCES = {
    "Entra ID": DATA_DIR / "identity" / "entra_signins.json",
    "Azure Activity": DATA_DIR / "cloud" / "azure_activity.json",
}


def contains_indicator(value, indicator):
    return indicator.lower() in str(value).lower()


def search_text_file(source, path, indicator):
    matches = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if contains_indicator(line, indicator):
                matches.append(
                    {
                        "source": source,
                        "record": line,
                    }
                )

    return matches


def walk_json(data, source, indicator, matches):
    if isinstance(data, list):
        for item in data:
            walk_json(
                item,
                source,
                indicator,
                matches,
            )

    elif isinstance(data, dict):
        immediate_match = any(
            contains_indicator(value, indicator)
            for value in data.values()
            if not isinstance(
                value,
                (dict, list),
            )
        )

        if immediate_match:
            matches.append(
                {
                    "source": source,
                    "record": json.dumps(
                        data,
                        default=str,
                    ),
                }
            )

        for value in data.values():
            if isinstance(
                value,
                (dict, list),
            ):
                walk_json(
                    value,
                    source,
                    indicator,
                    matches,
                )


def search_json_file(source, path, indicator):
    matches = []

    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    walk_json(
        data,
        source,
        indicator,
        matches,
    )

    return matches


def hunt_all_sources(indicator):
    matches = []

    for source, path in TEXT_SOURCES.items():
        matches.extend(
            search_text_file(
                source,
                path,
                indicator,
            )
        )

    for source, path in JSON_SOURCES.items():
        matches.extend(
            search_json_file(
                source,
                path,
                indicator,
            )
        )

    return matches


def print_hunt_results(indicator):
    matches = hunt_all_sources(indicator)

    print(
        f"\nNOVATECH MULTI-SOURCE THREAT HUNT: "
        f"{indicator}\n"
    )

    if not matches:
        print("No matching events found.")
        return

    source_counts = {}

    for match in matches:
        source = match["source"]

        source_counts[source] = (
            source_counts.get(source, 0) + 1
        )

    print("MATCH SUMMARY\n")

    for source in sorted(source_counts):
        print(
            f"{source}: "
            f"{source_counts[source]}"
        )

    print(
        f"\nTotal Matches: {len(matches)}"
    )

    print("\nMATCHES\n")

    for match in matches:
        print(
            f"[{match['source']}] "
            f"{match['record']}"
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python3 src/hunter.py <indicator>"
        )
        raise SystemExit(1)

    print_hunt_results(
        sys.argv[1]
    )