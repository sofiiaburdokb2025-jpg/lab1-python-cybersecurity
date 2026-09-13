import sys
import os
import csv
import hashlib
import json
from datetime import datetime
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import VARIANT_NUMBER


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 8
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"


class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or password == "":
        raise ValueError("Password cannot be empty")

    if salt is None or salt == "":
        raise ValueError("Salt cannot be empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must contain at least {MIN_PASSWORD_LENGTH} characters"
        )

    data = password + salt

    hash_object = hashlib.sha1(data.encode("utf-8"))

    return hash_object.hexdigest()


users_to_register = (
    ("admin", "AdminPass1!"),
    ("security_user", "Security1!"),
    ("network_admin", "Network1!"),
    ("help_desk", "HelpDesk1!"),
    ("auditor", "Auditor1!"),
    ("analyst", "Analyst1!"),
    ("operator", "Operator1!"),
    ("manager", "Manager1!"),
    ("developer", "Developer1!"),
    ("guest_user", "GuestUser1!"),
)


def create_user(username: str, password: str):
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)

    with open(USERS_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        for username, password in users_list:
            user_data = create_user(username, password)
            writer.writerow(user_data)


def read_users():
    users_db = []

    with open(USERS_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.reader(file)

        for row in reader:
            if len(row) == 2:
                username, password_hash = row
                users_db.append((username, password_hash))

    return users_db


def print_users_table(users_db):
    print("\nБАЗА КОРИСТУВАЧІВ")
    print("-" * 75)
    print(f"{'Логін':<20} {'SHA-1 хеш':<45}")
    print("-" * 75)

    for username, password_hash in users_db:
        print(f"{username:<20} {password_hash:<45}")


def log_event(function):
    @wraps(function)
    def wrapper(username, password):
        result = "failure"

        try:
            success = function(username, password)

            if success:
                result = "success"

            return success

        finally:
            log_data = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {}
            }

            os.makedirs(DATA_DIR, exist_ok=True)

            try:
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r", encoding="utf-8") as file:
                        logs = json.load(file)
                else:
                    logs = []
            except (FileNotFoundError, json.JSONDecodeError):
                logs = []

            logs.append(log_data)

            with open(LOG_FILE, "w", encoding="utf-8") as file:
                json.dump(logs, file, indent=4, ensure_ascii=False)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    if username is None or username == "":
        raise ValueError("Username cannot be empty")

    if password is None or password == "":
        raise ValueError("Password cannot be empty")

    users_db = read_users()

    for saved_username, saved_hash in users_db:
        if saved_username == username:
            entered_hash = generate_hash(password, PERSONAL_SALT)

            if entered_hash == saved_hash:
                return True

            return False

    return False


def main():
    try:
        create_users(users_to_register)

        users_db = read_users()

        print_users_table(users_db)

        print("\nПЕРЕВІРКА ВХОДУ")
        print("-" * 50)

        test_logins = [
            ("admin", "AdminPass1!"),
            ("security_user", "WrongPassword"),
            ("unknown_user", "SomePassword1!")
        ]

        for username, password in test_logins:
            try:
                result = login(username, password)

                if result:
                    print(f"{username}: Успішний вхід")
                else:
                    print(f"{username}: Невдалий вхід")

            except (ValidationError, ValueError) as error:
                print(f"{username}: Помилка — {error}")

    except FileNotFoundError as error:
        print(f"Помилка: файл не знайдено — {error}")

    except PermissionError as error:
        print(f"Помилка: немає дозволу — {error}")

    except IOError as error:
        print(f"Помилка введення/виведення — {error}")

    except ValidationError as error:
        print(f"Помилка валідації — {error}")

    except ValueError as error:
        print(f"Помилка значення — {error}")


if __name__ == "__main__":
    main()