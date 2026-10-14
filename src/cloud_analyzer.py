"""Analyze Azure configuration exports for security issues."""

import json
from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def create_finding(
    finding_id,
    severity,
    category,
    resource,
    reason,
    evidence,
    recommendation,
):
    return {
        "finding_id": finding_id,
        "severity": severity,
        "category": category,
        "resource": resource,
        "reason": reason,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def analyze_virtual_machine(resource):
    findings = []

    if resource.get("public_ip"):
        findings.append(
            create_finding(
                "CLOUD-VM-001",
                "High",
                "Virtual Machine",
                resource.get("name"),
                "Virtual machine has a public IP address.",
                f"public_ip={resource.get('public_ip')}",
                "Remove the public IP if it is not required and use private access methods.",
            )
        )

    if not resource.get("managed_identity"):
        findings.append(
            create_finding(
                "CLOUD-VM-002",
                "Medium",
                "Virtual Machine",
                resource.get("name"),
                "Managed identity is not enabled.",
                "managed_identity=false",
                "Enable managed identity where possible to reduce credential usage.",
            )
        )

    if resource.get("password_authentication"):
        findings.append(
            create_finding(
                "CLOUD-VM-003",
                "High",
                "Virtual Machine",
                resource.get("name"),
                "Password authentication is enabled.",
                "password_authentication=true",
                "Disable password authentication and prefer SSH keys.",
            )
        )

    if not resource.get("disk_encryption"):
        findings.append(
            create_finding(
                "CLOUD-VM-004",
                "High",
                "Virtual Machine",
                resource.get("name"),
                "Disk encryption indication is missing.",
                "disk_encryption is missing or empty",
                "Enable and verify disk encryption.",
            )
        )

    return findings


def analyze_storage_account(resource):
    findings = []

    if resource.get("allow_blob_public_access"):
        findings.append(
            create_finding(
                "CLOUD-STG-001",
                "High",
                "Storage Account",
                resource.get("name"),
                "Public blob access is enabled.",
                "allow_blob_public_access=true",
                "Disable public blob access unless explicitly required.",
            )
        )

    if resource.get("public_network_access"):
        findings.append(
            create_finding(
                "CLOUD-STG-002",
                "Medium",
                "Storage Account",
                resource.get("name"),
                "Public network access is enabled.",
                "public_network_access=true",
                "Restrict storage access to approved networks or private endpoints.",
            )
        )

    if resource.get("minimum_tls") in {"TLS1_0", "TLS1_1"}:
        findings.append(
            create_finding(
                "CLOUD-STG-003",
                "High",
                "Storage Account",
                resource.get("name"),
                "Storage account allows an old TLS version.",
                f"minimum_tls={resource.get('minimum_tls')}",
                "Require TLS 1.2 or newer.",
            )
        )

    if resource.get("network_default_action") == "Allow":
        findings.append(
            create_finding(
                "CLOUD-STG-004",
                "High",
                "Storage Account",
                resource.get("name"),
                "Storage network restrictions are overly permissive.",
                "network_default_action=Allow",
                "Set the default network action to Deny.",
            )
        )

    return findings


def analyze_sql_database(resource):
    findings = []

    if resource.get("public_network_access"):
        findings.append(
            create_finding(
                "CLOUD-SQL-001",
                "High",
                "SQL Database",
                resource.get("name"),
                "SQL database is publicly accessible.",
                "public_network_access=true",
                "Disable public network access where possible.",
            )
        )

    if not resource.get("auditing_enabled"):
        findings.append(
            create_finding(
                "CLOUD-SQL-002",
                "Medium",
                "SQL Database",
                resource.get("name"),
                "SQL auditing is disabled.",
                "auditing_enabled=false",
                "Enable auditing.",
            )
        )

    for rule in resource.get("firewall_rules", []):
        if (
            rule.get("start_ip") == "0.0.0.0"
            and rule.get("end_ip") == "255.255.255.255"
        ):
            findings.append(
                create_finding(
                    "CLOUD-SQL-003",
                    "Critical",
                    "SQL Database",
                    resource.get("name"),
                    "SQL firewall rule allows an excessively broad IP range.",
                    f"{rule.get('start_ip')} - {rule.get('end_ip')}",
                    "Restrict SQL firewall rules to trusted ranges.",
                )
            )

    return findings


def analyze_key_vault(resource):
    findings = []

    if resource.get("public_network_access"):
        findings.append(
            create_finding(
                "CLOUD-KV-001",
                "High",
                "Key Vault",
                resource.get("name"),
                "Key Vault allows public network access.",
                "public_network_access=true",
                "Restrict Key Vault access.",
            )
        )

    now = datetime.now(timezone.utc)

    for secret in resource.get("secrets", []):
        expires = secret.get("expires")

        if expires is None:
            findings.append(
                create_finding(
                    "CLOUD-KV-002",
                    "High",
                    "Key Vault Secret",
                    secret.get("name"),
                    "Secret does not have an expiration date.",
                    "expires=null",
                    "Configure an expiration date and rotation process.",
                )
            )
            continue

        expiration_date = datetime.fromisoformat(expires).replace(
            tzinfo=timezone.utc
        )

        days_remaining = (expiration_date - now).days

        if 0 <= days_remaining <= 30:
            findings.append(
                create_finding(
                    "CLOUD-KV-003",
                    "Medium",
                    "Key Vault Secret",
                    secret.get("name"),
                    "Secret expires within 30 days.",
                    f"expires={expires}, days_remaining={days_remaining}",
                    "Rotate or renew the secret before expiration.",
                )
            )

    return findings


def analyze_nsg(nsg):
    findings = []

    for rule in nsg.get("rules", []):
        source = rule.get("source")
        port = rule.get("destination_port")
        action = rule.get("action")

        if action != "Allow":
            continue

        if source in {"0.0.0.0/0", "*"} and port == 22:
            findings.append(
                create_finding(
                    "CLOUD-NSG-001",
                    "Critical",
                    "Network Security Group",
                    nsg.get("name"),
                    "SSH is exposed to the Internet.",
                    f"rule={rule.get('name')}, source={source}, port={port}",
                    "Restrict SSH access to trusted administrative IP ranges.",
                )
            )

        if source in {"0.0.0.0/0", "*"} and port == 3389:
            findings.append(
                create_finding(
                    "CLOUD-NSG-002",
                    "Critical",
                    "Network Security Group",
                    nsg.get("name"),
                    "RDP is exposed to the Internet.",
                    f"rule={rule.get('name')}, source={source}, port={port}",
                    "Restrict RDP access to trusted administrative IP ranges.",
                )
            )

        if source in {"0.0.0.0/0", "*"} and port in {22, 23, 3389}:
            findings.append(
                create_finding(
                    "CLOUD-NSG-003",
                    "High",
                    "Network Security Group",
                    nsg.get("name"),
                    "Administrative access is overly broad.",
                    f"rule={rule.get('name')}, source={source}, port={port}",
                    "Limit administrative access to trusted networks.",
                )
            )

    return findings


def scan_cloud():
    findings = []

    resources_data = load_json(
        DATA_DIR / "cloud" / "azure_resources.json"
    )

    for resource in resources_data.get("resources", []):
        resource_type = resource.get("type")

        if resource_type == "virtual_machine":
            findings.extend(analyze_virtual_machine(resource))

        elif resource_type == "storage_account":
            findings.extend(analyze_storage_account(resource))

        elif resource_type == "sql_database":
            findings.extend(analyze_sql_database(resource))

        elif resource_type == "key_vault":
            findings.extend(analyze_key_vault(resource))

    nsg_data = load_json(
        DATA_DIR / "cloud" / "network_security_groups.json"
    )

    for nsg in nsg_data.get("network_security_groups", []):
        findings.extend(analyze_nsg(nsg))

    return findings


def print_cloud_findings():
    findings = scan_cloud()

    print("\nNOVATECH CLOUD SECURITY FINDINGS\n")

    if not findings:
        print("No cloud security findings.")
        return

    for finding in findings:
        print(f"[{finding['severity']}] {finding['finding_id']}")
        print(f"Category: {finding['category']}")
        print(f"Resource: {finding['resource']}")
        print(f"Reason: {finding['reason']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Recommendation: {finding['recommendation']}")
        print("-" * 60)