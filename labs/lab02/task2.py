import argparse
import csv
import json
import logging
import re
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


IP_PATTERN = re.compile(
    r"^(?:"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:/(?:[0-9]|[12][0-9]|3[0-2]))?"
    r"$"
)


def load_rules(file_path: str) -> list[dict]:
    path = Path(file_path)

    if path.suffix.lower() == ".json":
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        if isinstance(data, dict) and "rules" in data:
            return data["rules"]

        raise ValueError("Некоректна структура JSON")

    if path.suffix.lower() == ".csv":
        with open(path, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            return list(reader)

    raise ValueError("Підтримуються тільки CSV та JSON файли")


def validate_ip(value: str) -> bool:
    if value.upper() == "ANY":
        return True

    return bool(IP_PATTERN.fullmatch(value))


def validate_rule(rule: dict) -> bool:
    source = str(rule.get("source", ""))
    destination = str(rule.get("destination", ""))
    action = str(rule.get("action", "")).upper()

    if not validate_ip(source):
        return False

    if not validate_ip(destination):
        return False

    return action in {"ALLOW", "DENY"}


def find_duplicates(rules: list[dict]) -> list[list[dict]]:
    groups = defaultdict(list)

    for rule in rules:
        key = (
            str(rule.get("source")),
            str(rule.get("destination")),
            str(rule.get("port")),
            str(rule.get("action")).upper(),
        )
        groups[key].append(rule)

    return [
        group
        for group in groups.values()
        if len(group) > 1
    ]


def find_conflicts(rules: list[dict]) -> list[tuple[dict, dict]]:
    groups = defaultdict(list)

    for rule in rules:
        key = (
            str(rule.get("source")),
            str(rule.get("destination")),
            str(rule.get("port")),
        )
        groups[key].append(rule)

    conflicts = []

    for group in groups.values():
        allow_rules = [
            rule
            for rule in group
            if str(rule.get("action")).upper() == "ALLOW"
        ]

        deny_rules = [
            rule
            for rule in group
            if str(rule.get("action")).upper() == "DENY"
        ]

        for allow_rule in allow_rules:
            for deny_rule in deny_rules:
                conflicts.append(
                    (allow_rule, deny_rule)
                )

    return conflicts


def find_high_risk_rules(rules: list[dict]) -> list[dict]:
    dangerous = []

    for rule in rules:
        action = str(rule.get("action", "")).upper()
        source = str(rule.get("source", ""))
        port = str(rule.get("port", "")).upper()

        if action == "ALLOW" and (
            port == "ANY"
            or source == "0.0.0.0/0"
        ):
            dangerous.append(rule)

    return dangerous


def save_rules(rules: list[dict], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(
            rules,
            file,
            ensure_ascii=False,
            indent=4,
        )


def analyze_rules(
    rules_file: str,
    output: str,
    check_conflicts: bool = False,
) -> None:
    logger.info(
        "Parsing firewall rules from %s...",
        rules_file,
    )

    rules = load_rules(rules_file)

    logger.info(
        "Total rules parsed: %d. "
        "Validating IP syntax and rule logic...",
        len(rules),
    )

    invalid_rules = [
        rule
        for rule in rules
        if not validate_rule(rule)
    ]

    valid_rules = [
        rule
        for rule in rules
        if validate_rule(rule)
    ]

    duplicates = find_duplicates(valid_rules)

    conflicts = []
    if check_conflicts:
        conflicts = find_conflicts(valid_rules)

    high_risk = find_high_risk_rules(valid_rules)

    print("\n=== Firewall Configuration Audit Report ===")
    print(f"Invalid IP Formats : {len(invalid_rules)}")
    print(
        f"Conflicting Rules  : "
        f"{len(conflicts)} conflicts found"
    )
    print(
        f"Duplicate Rules    : "
        f"{len(duplicates)} duplicates found"
    )
    print(
        f"High-Risk Rules    : "
        f"{len(high_risk)} dangerous ALLOW rules"
    )

    print("\n=== Critical Findings ===")

    for allow_rule, deny_rule in conflicts:
        print(
            f"[CONFLICT] Rule #{allow_rule.get('id')} "
            f"(ALLOW {allow_rule.get('source')} -> "
            f"{allow_rule.get('destination')}:"
            f"{allow_rule.get('port')}) "
            f"conflicts with Rule #{deny_rule.get('id')} "
            f"(DENY {deny_rule.get('source')} -> "
            f"{deny_rule.get('destination')}:"
            f"{deny_rule.get('port')})"
        )

    for rule in high_risk:
        print(
            f"[HIGH-RISK] Rule #{rule.get('id')}: "
            f"ALLOW {rule.get('source')} -> "
            f"{rule.get('destination')}:"
            f"{rule.get('port')}"
        )

    save_rules(valid_rules, output)

    logger.info(
        "Security report successfully exported to %s",
        output,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Firewall rules validator and analyzer"
    )

    parser.add_argument(
        "--rules-file",
        required=True,
        help="Шлях до CSV або JSON файлу з правилами",
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Шлях до вихідного JSON файлу",
    )

    parser.add_argument(
        "--check-conflicts",
        action="store_true",
        help="Перевірити суперечливі правила",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=[
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
        ],
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="[%(levelname)s] %(message)s",
    )

    analyze_rules(
        rules_file=args.rules_file,
        output=args.output,
        check_conflicts=args.check_conflicts,
    )


if __name__ == "__main__":
    main()