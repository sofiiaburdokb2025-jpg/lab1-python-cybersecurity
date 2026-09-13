import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
print(f"Студент: {STUDENT_NAME}")
print(f"Група: {GROUP_NAME}")
print(f"Варіант: {VARIANT_NUMBER}")


users = {
    "security_chief": {
        "role": "security_officer",
        "clearance": 4,
        "department": "Security",
        "active": True
    },
    "network_admin": {
        "role": "network_admin",
        "clearance": 3,
        "department": "Network",
        "active": True
    },
    "help_desk": {
        "role": "support",
        "clearance": 1,
        "department": "Support",
        "active": True
    },
    "auditor_ext": {
        "role": "auditor",
        "clearance": 3,
        "department": "Audit",
        "active": True
    },
    "temp_worker": {
        "role": "temporary",
        "clearance": 1,
        "department": "Temp",
        "active": False
    }
}


resources = [
    ("incident_reports", 4),
    ("network_topology", 3),
    ("user_manual", 1),
    ("vulnerability_scans", 3),
    ("root_access", 4),
    ("help_tickets", 1),
    ("penetration_tests", 4),
    ("firewall_rules", 3),
    ("software_licenses", 2),
    ("faq_docs", 1)
]


security_levels = (
    "Unrestricted",
    "Limited",
    "Sensitive",
    "Classified"
)


blocked_users = {
    "temp_worker",
    "fired_employee",
    "compromised_acc"
}


print("Список ресурсів")
print()

for resource_name, security_level in resources:
    level_name = security_levels[security_level - 1]
    print(f"{resource_name:<25} {level_name}")


def check_access(username, resource_level):
    if username not in users:
        return "DENY (User not found)"

    if username in blocked_users:
        return "DENY (User is blocked)"

    if not users[username]["active"]:
        return "DENY (Account inactive)"

    user_clearance = users[username]["clearance"]

    if user_clearance >= resource_level:
        return "ALLOW"

    return "DENY (Insufficient clearance)"


print("\nРезультати перевірки")
print()

for username in users:
    for resource_name, resource_level in resources:
        result = check_access(username, resource_level)
        print(
            f"user={username:<15} "
            f"resource={resource_name:<25} -> {result}"
        )