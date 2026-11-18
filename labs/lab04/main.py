import argparse
import json
import re
import sys
from pathlib import Path

import requests

from labs.lab04 import api_client
from labs.lab04.analysis import build_report, extract_record
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> dict:
    """Читає JSON-відповідь NVD з локального UTF-8 файла."""
    with Path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def main(argv=None) -> int:
    """Обробляє аргументи CLI та формує JSON-звіт."""
    parser = argparse.ArgumentParser(description="Перегляд інформації про CVE з NVD")
    parser.add_argument(
        "--cve",
        required=True,
        help="Ідентифікатор CVE",
    )
    parser.add_argument(
        "--input",
        help="Шлях до локального JSON-файла",
    )

    args = parser.parse_args(argv)

    if (
        not isinstance(VARIANT_NUMBER, int)
        or isinstance(VARIANT_NUMBER, bool)
        or not 1 <= VARIANT_NUMBER <= 15
    ):
        print(
            "Помилка: номер варіанта має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2

    if not CVE_PATTERN.fullmatch(args.cve):
        parser.error("Неправильний формат CVE. Приклад: CVE-2099-10001")

    try:
        if args.input:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(args.cve)

        record = extract_record(payload, args.cve)
        report = build_report(record, args.cve, VARIANT_NUMBER)

    except requests.HTTPError as error:
        status = (
            error.response.status_code if error.response is not None else "невідомий"
        )
        print(f"Помилка HTTP: статус {status}.", file=sys.stderr)
        return 1

    except requests.RequestException:
        print("Помилка мережевого запиту до NVD.", file=sys.stderr)
        return 1

    except (OSError, UnicodeError):
        print("Помилка читання локального файла.", file=sys.stderr)
        return 1

    except (json.JSONDecodeError, ValueError):
        print("Помилка: некоректний JSON або структура даних.", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
