

import csv
import json
from html import escape
from pathlib import Path
from datetime import datetime, timezone

from cloud_analyzer import scan_cloud
from iam_analyzer import scan_identity
from network_analyzer import analyze_cisco
from firewall_analyzer import analyze_firewall
from linux_analyzer import analyze_linux


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"


def get_asset(finding):
    return (
        finding.get("resource")
        or finding.get("identity")
        or finding.get("device")
        or finding.get("host")
        or finding.get("source_ip")
        or "Unknown"
    )


def normalize_finding(finding, source):
    return {
        "source": source,
        "severity": finding.get("severity", "Unknown"),
        "finding_id": finding.get(
            "finding_id",
            "Unknown",
        ),
        "asset": get_asset(finding),
        "reason": finding.get("reason", ""),
        "evidence": finding.get("evidence", ""),
        "recommendation": finding.get(
            "recommendation",
            "",
        ),
    }


def collect_findings():
    findings = []

    for finding in scan_cloud():
        findings.append(
            normalize_finding(
                finding,
                "Cloud",
            )
        )

    for finding in scan_identity():
        findings.append(
            normalize_finding(
                finding,
                "Identity",
            )
        )

    for finding in analyze_cisco():
        findings.append(
            normalize_finding(
                finding,
                "Cisco",
            )
        )

    for finding in analyze_firewall():
        findings.append(
            normalize_finding(
                finding,
                "Firewall",
            )
        )

    for finding in analyze_linux():
        findings.append(
            normalize_finding(
                finding,
                "Linux",
            )
        )

    return findings


def write_json_report(findings, path):
    report = {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
        )


def write_csv_report(findings, path):
    fieldnames = [
        "source",
        "severity",
        "finding_id",
        "asset",
        "reason",
        "evidence",
        "recommendation",
    ]

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(findings)


def write_html_report(findings, path):
    rows = []

    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(str(finding['source']))}</td>"
            f"<td>{escape(str(finding['severity']))}</td>"
            f"<td>{escape(str(finding['finding_id']))}</td>"
            f"<td>{escape(str(finding['asset']))}</td>"
            f"<td>{escape(str(finding['reason']))}</td>"
            f"<td>{escape(str(finding['evidence']))}</td>"
            f"<td>{escape(str(finding['recommendation']))}</td>"
            "</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NovaTech Security Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
        }}

        th, td {{
            border: 1px solid #cccccc;
            padding: 8px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background-color: #eeeeee;
        }}
    </style>
</head>
<body>
    <h1>NovaTech Security Report</h1>

    <p>
        Total findings:
        <strong>{len(findings)}</strong>
    </p>

    <table>
        <thead>
            <tr>
                <th>Source</th>
                <th>Severity</th>
                <th>Finding ID</th>
                <th>Asset</th>
                <th>Reason</th>
                <th>Evidence</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
</body>
</html>
"""

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(html)


def generate_reports():
    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    findings = collect_findings()

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    json_path = (
        REPORTS_DIR
        / f"novatech_security_report_{timestamp}.json"
    )

    csv_path = (
        REPORTS_DIR
        / f"novatech_security_report_{timestamp}.csv"
    )

    html_path = (
        REPORTS_DIR
        / f"novatech_security_report_{timestamp}.html"
    )

    write_json_report(
        findings,
        json_path,
    )

    write_csv_report(
        findings,
        csv_path,
    )

    write_html_report(
        findings,
        html_path,
    )

    return {
        "total_findings": len(findings),
        "json": json_path,
        "csv": csv_path,
        "html": html_path,
    }


def print_report_results():
    result = generate_reports()

    print("\nNOVATECH SECURITY REPORT GENERATED\n")

    print(
        f"Total findings: "
        f"{result['total_findings']}"
    )

    print(
        f"JSON: {result['json']}"
    )

    print(
        f"CSV:  {result['csv']}"
    )

    print(
        f"HTML: {result['html']}"
    )
