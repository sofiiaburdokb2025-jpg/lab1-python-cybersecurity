# Лабораторна робота №2

## Запуск Завдання 1

```bash
python -m labs.lab02.main demo
```

## Запуск Завдання 2

```bash
python -m labs.lab02.main analyze \
--rules-file labs/lab02/data/firewall_rules.json \
--output labs/lab02/data/fw_audit_report.json \
--check-conflicts \
--log-level INFO
```

## Перевірка коду

```bash
ruff check labs/lab02
```