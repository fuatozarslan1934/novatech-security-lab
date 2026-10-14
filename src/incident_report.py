"""Generate Markdown incident investigation reports."""

from pathlib import Path

from correlator import investigate_incident


BASE_DIR = Path(__file__).resolve().parent.parent
INVESTIGATIONS_DIR = BASE_DIR / "investigations"


def format_timestamp(timestamp):
    if hasattr(timestamp, "isoformat"):
        return timestamp.isoformat()

    return str(timestamp)


def generate_incident_report(incident_id):
    investigation = investigate_incident(
        incident_id
    )

    if not investigation:
        return None

    incident = investigation["incident"]
    correlation = investigation.get(
        "correlation"
    )

    INVESTIGATIONS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path = (
        INVESTIGATIONS_DIR
        / f"{incident_id}.md"
    )

    lines = [
        f"# NovaTech Incident Investigation — {incident_id}",
        "",
        "## Incident Overview",
        "",
        f"- **Title:** {incident.get('title')}",
        f"- **Difficulty:** {incident.get('difficulty')}",
        f"- **Status:** {incident.get('status')}",
        "",
    ]

    if correlation:
        lines.extend(
            [
                "## Correlation Summary",
                "",
                (
                    f"- **Primary Indicator:** "
                    f"{correlation.get('source_ip')}"
                ),
                (
                    f"- **Correlated Events:** "
                    f"{correlation.get('event_count')}"
                ),
                (
                    "- **Telemetry Sources:** "
                    + ", ".join(
                        correlation.get(
                            "sources",
                            [],
                        )
                    )
                ),
                (
                    "- **Systems:** "
                    + ", ".join(
                        correlation.get(
                            "systems",
                            [],
                        )
                    )
                ),
                (
                    "- **Identities:** "
                    + ", ".join(
                        correlation.get(
                            "identities",
                            [],
                        )
                    )
                ),
                "",
                "## Timeline",
                "",
            ]
        )

        for event in correlation.get(
            "events",
            [],
        ):
            lines.extend(
                [
                    (
                        "### "
                        + format_timestamp(
                            event.get(
                                "timestamp"
                            )
                        )
                    ),
                    "",
                    (
                        f"- **Source:** "
                        f"{event.get('source')}"
                    ),
                    (
                        f"- **System:** "
                        f"{event.get('system')}"
                    ),
                ]
            )

            if event.get("identity"):
                lines.append(
                    (
                        f"- **Identity:** "
                        f"{event.get('identity')}"
                    )
                )

            lines.extend(
                [
                    (
                        f"- **Action:** "
                        f"{event.get('action')}"
                    ),
                    (
                        f"- **Resource:** "
                        f"{event.get('resource')}"
                    ),
                    (
                        f"- **Source IP:** "
                        f"{event.get('source_ip')}"
                    ),
                    "",
                ]
            )

        lines.extend(
            [
                "## Assessment",
                "",
                (
                    "The same source IP was observed across "
                    "multiple telemetry sources. The sequence "
                    "includes scanning or connection attempts, "
                    "authentication failures, successful access, "
                    "configuration changes, cloud activity, and "
                    "privileged Linux activity."
                ),
                "",
                (
                    "The correlated evidence supports treating "
                    "these events as a possible multi-system "
                    "security incident rather than isolated alerts."
                ),
                "",
                "## Recommended Actions",
                "",
                "1. Validate the affected identities and reset potentially compromised credentials.",
                "2. Review MFA and conditional access enforcement.",
                "3. Review Cisco configuration changes and compare them with the approved baseline.",
                "4. Review the Azure NSG rule change and remove unauthorized administrative access.",
                "5. Investigate activity on web-prod-01, including the privileged `/etc/shadow` access.",
                "6. Block or investigate the suspicious source IP where appropriate.",
                "7. Preserve relevant logs and evidence for further investigation.",
                "",
                "## Analyst Notes",
                "",
                (
                    "This report was generated from structured "
                    "NovaTech lab telemetry and deterministic "
                    "correlation logic."
                ),
                "",
            ]
        )

    else:
        lines.extend(
            [
                "## Investigation Notes",
                "",
                (
                    "Detailed correlation is not currently "
                    "implemented for this incident."
                ),
                "",
            ]
        )

    report_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return report_path