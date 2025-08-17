import json
import sqlite3

from rich.console import Console

console = Console()


def load_versions(conn, file_name):
    try:
        with open(file_name, 'r') as f:
            versions_data = json.load(f)

        cursor = conn.cursor()
        for item in versions_data:
            cursor.execute(
                "INSERT OR IGNORE INTO products (vendor, product, version) VALUES (?, ?, ?)",
                (item['vendor'], item['product'], item['version'])
            )
        conn.commit()
        return len(versions_data)
    except FileNotFoundError:
        console.print(f"[bold red]Ошибка: файл {file_name} не найден.[/]")
        return 0
    except Exception as e:
        console.print(f"[bold red]Ошибка при чтении {file_name}: {e}[/]")
        return 0


def load_vulnerabilities(conn, file_name):
    # Загружает уязвимости из JSON-файла.
    try:
        with open(file_name, 'r') as f:
            vulns_data = json.load(f)

        cursor = conn.cursor()
        for item in vulns_data:
            cursor.execute(
                "INSERT OR IGNORE INTO vulnerabilities "
                "(vendor, product, KLA_id, description, publish_date, start_vuln_version, fixed_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    item['vendor'],
                    item['product'],
                    item['KLA_id'],
                    item['description'],
                    item['publish_date'],
                    item['start_vuln_version'],
                    item['fixed_version']
                )
            )
        conn.commit()
        return len(vulns_data)
    except FileNotFoundError:
        console.print(f"[bold red]Ошибка: файл {file_name} не найден.[/]")
        return 0
    except Exception as e:
        console.print(f"[bold red]Ошибка при чтении {file_name}: {e}[/]")
        return 0
