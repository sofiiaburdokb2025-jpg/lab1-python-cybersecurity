import sys
import os
import csv
import hashlib
import json
from datetime import datetime, timezone
from functools import wraps


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 8
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"


users = {
    "admin": "AdminPass1!",
    "security_user": "Security1!",
    "network_admin": "Network1!",
    "help_desk": "HelpDesk1!",
    "auditor": "Auditor1!",
    "analyst": "Analyst1!",
    "operator": "Operator1!",
    "manager": "Manager1!",
    "developer": "Developer1!",
    "guest_user": "GuestUser1!"
}


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


def create_users():

    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        with open(USERS_FILE, "w", newline="", encoding="utf-8") as file:

            writer = csv.writer(file)

            for username, password in users.items():

                password_hash = generate_hash(password, PERSONAL_SALT)

                writer.writerow([username, password_hash])

    except (OSError, csv.Error) as error:
        print(f"Помилка роботи з файлом: {error}")


def read_users():

    users_db = []

    try:
        with open(USERS_FILE, "r", newline="", encoding="utf-8") as file:

            reader = csv.reader(file)

            for row in reader:

                if len(row) == 2:
                    username, password_hash = row
                    users_db.append((username, password_hash))

    except (OSError, csv.Error) as error:
        print(f"Помилка читання файлу: {error}")

    return users_db


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
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
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

            except (OSError, json.JSONDecodeError) as error:

                print(f"Помилка читання журналу: {error}")
                logs = []

            logs.append(log_data)

            try:

                with open(LOG_FILE, "w", encoding="utf-8") as file:
                    json.dump(logs, file, indent=4, ensure_ascii=False)

            except OSError as error:

                print(f"Помилка запису журналу: {error}")

    return wrapper


def check(username: str, password: str) -> tuple[bool, str]:

    if username is None or username == "":
        raise ValueError("Username cannot be empty")

    if password is None or password == "":
        raise ValueError("Password cannot be empty")

    users_db = read_users()

    for saved_username, saved_hash in users_db:

        if saved_username == username:

            entered_hash = generate_hash(password, PERSONAL_SALT)

            if entered_hash == saved_hash:
                return True, "ALLOW"

            return False, "Wrong password"

    return False, "User not found"


@log_event
def login(username: str, password: str) -> bool:

    allowed, reason = check(username, password)

    if allowed:
        return True

    return False


def main():

    print(
        f"\nСтудент: {STUDENT_NAME} | "
        f"Група: {GROUP_NAME} | "
        f"Варіант: {VARIANT_NUMBER}\n"
    )

    create_users()

    users_db = read_users()

    print("\nБаза користувачів")
    print(f"{'Логін':<20} | {'SHA-1 хеш'}")

    for username, password_hash in users_db:

        print(f"{username:<20} | {password_hash}")

    test_users = [
        ("admin", "AdminPass1!"),
        ("security_user", "WrongPassword"),
        ("unknown_user", "SomePassword1!")
    ]

    print("\nКористувач | Статус | Причина")

    for username, password in test_users:

        try:

            allowed, reason = check(username, password)

            status = "ALLOW" if allowed else "DENY"

            print(f"{username} | {status} | {reason}")

            login(username, password)

        except (ValidationError, ValueError) as error:

            print(f"{username} | DENY | Помилка — {error}")


if __name__ == "__main__":
    main()