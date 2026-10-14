"""Inventory cloud, identity, and network resources."""

# TODO: Implement resource inventory.
"""Inventory cloud, identity, and network resources."""

import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def count_cloud_resources():
    data = load_json(DATA_DIR / "cloud" / "azure_resources.json")
    resources = data["resources"]

    counts = {
        "Virtual Machines": 0,
        "Storage Accounts": 0,
        "SQL Databases": 0,
        "Key Vaults": 0,
        "VNets": 0,
        "NSGs": 0,
    }

    type_map = {
        "virtual_machine": "Virtual Machines",
        "storage_account": "Storage Accounts",
        "sql_database": "SQL Databases",
        "key_vault": "Key Vaults",
        "virtual_network": "VNets",
        "network_security_group": "NSGs",
    }

    for resource in resources:
        resource_type = resource.get("type")

        if resource_type in type_map:
            counts[type_map[resource_type]] += 1

    return counts


def count_users():
    data = load_json(DATA_DIR / "identity" / "entra_users.json")
    return len(data["users"])


def count_privileged_users():
    data = load_json(DATA_DIR / "identity" / "entra_roles.json")

    privileged_roles = {"Owner", "Contributor"}
    privileged_users = set()

    for assignment in data["assignments"]:
        if assignment.get("role") in privileged_roles:
            privileged_users.add(assignment.get("identity"))

    return len(privileged_users)


def get_devices_from_log(path):
    devices = set()

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            parts = line.split()

            if len(parts) >= 4:
                devices.add(parts[3])

    return devices


def count_network_devices():
    devices = set()

    devices.update(
        get_devices_from_log(DATA_DIR / "network" / "cisco-core.log")
    )

    devices.update(
        get_devices_from_log(DATA_DIR / "firewall" / "cisco_firewall.log")
    )

    return len(devices)


def build_inventory():
    inventory = count_cloud_resources()

    inventory["Users"] = count_users()
    inventory["Privileged Users"] = count_privileged_users()
    inventory["Network Devices"] = count_network_devices()

    return inventory


def print_inventory():
    inventory = build_inventory()

    print("\nNOVATECH ENVIRONMENT\n")

    for name, count in inventory.items():
        print(f"{name:<22} {count}")