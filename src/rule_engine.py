"""Load and manage security detection rules."""

import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = BASE_DIR / "rules"


RULE_FILES = {
    "cloud": "cloud_rules.json",
    "identity": "identity_rules.json",
    "network": "network_rules.json",
}


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_rules(category):
    filename = RULE_FILES.get(category)

    if not filename:
        raise ValueError(
            f"Unknown rule category: {category}"
        )

    data = load_json(
        RULES_DIR / filename
    )

    return data.get("rules", [])


def load_all_rules():
    all_rules = []

    for category in RULE_FILES:
        rules = load_rules(category)

        for rule in rules:
            rule_copy = rule.copy()
            rule_copy["category"] = category
            all_rules.append(rule_copy)

    return all_rules


def get_rule(rule_id):
    for rule in load_all_rules():
        if rule.get("id") == rule_id:
            return rule

    return None


def get_rule_value(
    rule_id,
    field,
    default=None,
):
    rule = get_rule(rule_id)

    if not rule:
        return default

    return rule.get(field, default)


def print_rules():
    rules = load_all_rules()

    print("\nNOVATECH SECURITY RULES\n")

    for rule in rules:
        print(
            f"[{rule.get('severity')}] "
            f"{rule.get('id')} - "
            f"{rule.get('title')}"
        )

    print(
        f"\nTotal Rules: {len(rules)}"
    )