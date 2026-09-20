import sys
import os
import random

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


def main():
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")

    passwords = [
        "UserPass1!",
        "temp",
        "Cyber$ecur1ty",
        "guest",
        "P0w3rful@Pass",
        "login",
        "Defens3#2023",
        "abc123",
        "Elit3@Secur",
        "demo"
    ]

    criteria = {
        "min_length": 9,
        "require_digits": True,
        "require_upper": True,
        "require_special": True
    }

    forbidden_passwords = {"temp", "guest", "login", "demo", "abc123", "user"}

    random_indices = random.sample(range(len(passwords)), 3)
    duplicate_passwords = [passwords[i] for i in random_indices]
    passwords.extend(duplicate_passwords)

    def analyze_password(password):
        is_forbidden = password in forbidden_passwords
        is_too_short = len(password) < criteria["min_length"]
        has_digit = any(char.isdigit() for char in password)
        has_upper = any(char.isupper() for char in password)
        has_special = any(not char.isalnum() for char in password)
        has_lower = any(char.islower() for char in password)
        if is_forbidden or is_too_short:
            return "Заборонений"
        criteria_count = sum([
            has_digit,
            has_upper,
            has_special,
            has_lower
        ])
        if criteria_count == 1:
            return "Слабкий"
        if criteria_count < 4:
            return "Середній"
        if len(password) < criteria["min_length"] + 4:
            return "Сильний"
        is_unique = passwords.count(password) == 1

        if is_unique:
            return "Дуже сильний"

        return "Сильний"

    print(f"{'Пароль':<20} {'Результат':<20}")

    for password in passwords:
        result = analyze_password(password)
        print(f"{password:<20} {result:<20}")


if __name__ == "__main__":
    main()