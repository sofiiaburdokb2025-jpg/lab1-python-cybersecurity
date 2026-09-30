import argparse
import logging
from datetime import timedelta

from .task1 import (
    SESSION_TIMEOUT_SEC,
    Admin,
    AuditLog,
    User,
    UserAccount,
)
from .task2 import analyze_rules


def demo():
    print("=== Створення користувача ===")

    user = User(
        username="sofia",
        email="sofia123@example.com",
        role="user",
    )
    user.set_password("SecurePass123!")

    audit_log = AuditLog()
    account = UserAccount(
        user=user,
        audit_log=audit_log,
    )

    print(user)

    print("\n=== Невдалий вхід ===")

    result = account.login(
        username="sofia",
        password="wrong_password",
        ip="192.168.1.10",
    )

    print("Результат входу:", result)

    print("\n=== Успішний вхід ===")

    result = account.login(
        username="sofia",
        password="SecurePass123!",
        ip="192.168.1.10",
    )

    print("Результат входу:", result)
    print(
        "Автентифікований:",
        account.is_authenticated(),
    )

    print("\n=== Перевірка email ===")

    try:
        user.email = "wrong-email"
    except ValueError as error:
        print("Помилка:", error)

    user.email = "sofia_new@example.com"
    print("Новий email:", user.email)

    print("\n=== Адміністратор ===")

    admin = Admin(
        username="admin",
        email="admin123@example.com",
    )

    admin.grant_permission("read")
    admin.grant_permission("write")
    admin.grant_permission("delete")

    print(admin)

    print(
        "Має право delete:",
        admin.has_permission("delete"),
    )

    admin.revoke_permission("delete")

    print(
        "Має право delete після видалення:",
        admin.has_permission("delete"),
    )

    print("\n=== Завершення сеансу за таймаутом ===")

    if account.session is not None:
        account.session.last_activity -= timedelta(
            seconds=SESSION_TIMEOUT_SEC + 1
        )

    print(
        "Автентифікований після таймауту:",
        account.is_authenticated(),
    )

    print("\n=== Вихід із системи ===")

    account.logout()

    print(
        "Автентифікований після logout:",
        account.is_authenticated(),
    )

    print("\n=== AuditLog ===")

    audit_log.show_all()


def main():
    parser = argparse.ArgumentParser(
        description="Лабораторна робота №2"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "demo",
        help="Демонстрація Завдання 1",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Аналіз правил фаєрвола",
    )

    analyze_parser.add_argument(
        "--rules-file",
        required=True,
        help="Шлях до файлу правил",
    )

    analyze_parser.add_argument(
        "--output",
        required=True,
        help="Шлях до вихідного JSON-файлу",
    )

    analyze_parser.add_argument(
        "--check-conflicts",
        action="store_true",
        help="Перевірка конфліктів",
    )

    analyze_parser.add_argument(
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

    if args.command == "demo":
        demo()

    elif args.command == "analyze":
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