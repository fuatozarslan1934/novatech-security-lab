#!/usr/bin/env python3
"""
NovaTech Security Lab CLI.

Implements inventory, scan, hunt, investigate,
report, and supporting analysis commands.
"""

import argparse

from inventory import print_inventory
from cloud_analyzer import print_cloud_findings
from iam_analyzer import print_identity_findings
from firewall_analyzer import print_firewall_findings
from linux_analyzer import print_linux_findings
from report_generator import print_report_results
from incident_report import generate_incident_report
from ai_assistant import print_ai_analysis

from correlator import (
    investigate_incident,
    print_incident_investigation,
)

from hunter import print_hunt_results
from network_analyzer import print_network_findings
from risk_engine import score_investigation


def main():
    parser = argparse.ArgumentParser(
        description="NovaTech Security Analysis CLI"
    )

    sub = parser.add_subparsers(
        dest="command"
    )

    sub.add_parser("inventory")
    sub.add_parser("scan")
    sub.add_parser("identity")
    sub.add_parser("network")
    sub.add_parser("firewall")
    sub.add_parser("linux")

    hunt = sub.add_parser("hunt")
    hunt.add_argument("indicator")

    investigate = sub.add_parser(
        "investigate"
    )

    investigate.add_argument(
        "incident_id"
    )

    investigate.add_argument(
        "--ai",
        action="store_true",
    )

    investigate.add_argument(
        "--report",
        action="store_true",
    )

    sub.add_parser("report")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "inventory":
        print_inventory()

    elif args.command == "scan":
        print_cloud_findings()

    elif args.command == "identity":
        print_identity_findings()

    elif args.command == "network":
        print_network_findings()

    elif args.command == "firewall":
        print_firewall_findings()

    elif args.command == "linux":
        print_linux_findings()

    elif args.command == "hunt":
        print_hunt_results(
            args.indicator
        )
    elif args.command == "investigate":
        print_incident_investigation(
            args.incident_id
        )

        investigation = investigate_incident(
            args.incident_id
        )

        if investigation:
            risk = score_investigation(
                investigation
            )

            print("\nRISK ASSESSMENT\n")
            print(
                f"Risk Score: "
                f"{risk['final_score']}/100"
            )
            print(
                f"Risk Level: "
                f"{risk['level']}"
            )
            print(
                f"Base Score: "
                f"{risk['base_score']}"
            )
            print(
                f"Context Bonus: "
                f"+{risk['bonus']}"
            )

            if risk["bonus_reasons"]:
                print("Risk Factors:")

                for reason in risk["bonus_reasons"]:
                    print(
                        f"  - {reason}"
                    )

        if args.report:
            report_path = generate_incident_report(
                args.incident_id
            )

            if report_path:
                print(
                    "\nIncident Markdown Report:"
                )
                print(report_path)

        if args.ai and investigation:
            print_ai_analysis(
                investigation
            )

    

    elif args.command == "report":
        print_report_results()

    else:
        print(
            f"Unknown command: "
            f"{args.command}"
        )


if __name__ == "__main__":
    main()