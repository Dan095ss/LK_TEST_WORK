import os

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from db_init import init_database
from data_load import load_versions, load_vulnerabilities
from secure import compress_file, decompress_file
from vuln_check import get_safe_version, check_vulnerabilities

import re

from packaging import version

import pygame

DB_NAME = 'test.sqlite'
VERSIONS_FILE = 'json/versions.json'
VULNERABILITIES_FILE = 'json/vulnerabilities.json'

pygame.mixer.init()

console = Console()


def validate_product_name(conn, product_name):
    os.system("clear")

    # Проверка на пустое значение
    if not product_name:
        raise ValueError("Название продукта не может быть пустым.")

    # Проверка на допустимые символы
    if not re.match(r"^[a-zA-Z0-9\s\-\(\)]+$", product_name):
        raise ValueError("Недопустимое название продукта. Используйте только буквы, цифры, пробелы, дефисы и скобки.")

    # Проверка существования продукта в базе данных
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM products WHERE product = ?
    """, (product_name,))
    product_exists = cursor.fetchone()[0]

    if not product_exists:
        raise ValueError(f"Продукт '{product_name}' не найден в базе данных.")


def validate_version(conn, product_name, version_str):
    """
    Проверяет, что версия:
    1. Соответствует формату X.Y.Z.
    2. Существует в базе данных для указанного продукта.
    """
    os.system("clear")

    # Проверка формата версии
    try:
        version.parse(version_str)
    except Exception:
        raise ValueError(f"Недопустимый формат версии: {version_str}. Ожидается формат X.Y.Z.")

    # Проверка существования версии в базе данных
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM products WHERE product = ? AND version = ?
    """, (product_name, version_str))
    version_exists = cursor.fetchone()[0]

    if not version_exists:
        raise ValueError(f"Версия '{version_str}' для продукта '{product_name}' не найдена в базе данных.")


def print_vulnerabilities_table(results, terminal_supports_links):
    os.system("clear")
    if not results:
        console.print("[bold green]Уязвимостей не найдено! ✅[/]")
        return

    play_alert_sound()

    # Повторяем предупреждение, если терминал не поддерживает гиперссылки
    if not terminal_supports_links:
        console.print("[bold yellow]Внимание:[/] Ваш терминал может не поддерживать кликабельные ссылки. "
                      "Используйте текстовые ссылки ниже.")
        console.print()

    table = Table(title="⚠️ Найденные уязвимости ⚠️", show_lines=True)
    table.add_column("KLA ID", style="cyan", justify="center")  # Ссылка на KLA ID
    table.add_column("Описание", style="magenta", justify="left")
    table.add_column("Дата публикации", style="yellow", justify="center")
    table.add_column("Уязвимо с мажора", style="red", justify="center")
    table.add_column("Исправлено в версии", style="green", justify="center")

    for row in results:
        kla_id, description, publish_date, start_ver, fixed_ver = row

        major_version = start_ver.split('.')[0] + '.'

        # Создаем кликабельную ссылку или текстовый вариант
        if terminal_supports_links:
            kla_id_link = f"[link=https://threats.kaspersky.com/en/vulnerability/{kla_id}]{kla_id}[/link]"
        else:
            kla_id_link = f"{kla_id} (https://threats.kaspersky.com/en/vulnerability/{kla_id})"

        table.add_row(
            kla_id_link,
            description,
            publish_date,
            f"[bold red]{major_version}[/]",
            f"[bold green]{fixed_ver}[/]"
        )

    console.print(table)


def check_terminal_support():
    # Проверяет поддержку гиперссылок терминалом.
    if not console.is_terminal:
        console.print("[bold yellow]Внимание:[/] Ваш терминал может не поддерживать кликабельные ссылки. "
                      "Для полного функционала используйте современный терминал (например, Windows Terminal, iTerm2).")
        console.print()
        return False
    return True


def play_main_theme():
    try:
        pygame.mixer.music.load("sounds/main_theme.mp3")
        pygame.mixer.music.play(-1)
    except Exception as e:
        console.print(f"[bold red]Ошибка воспроизведения основной мелодии: {e}[/]")


def play_alert_sound():
    try:
        pygame.mixer.music.stop()
        pygame.mixer.music.load("sounds/alert_sound.mp3")
        pygame.mixer.music.play()
        while pygame.mixer.music.get_busy():
            pygame.time.Clock().tick(10)
        play_main_theme()
    except Exception as e:
        console.print(f"[bold red]Ошибка воспроизведения уведомления: {e}[/]")


def exit_sound():
    try:
        pygame.mixer.music.stop()
        pygame.mixer.music.load("sounds/exit_sound.mp3")
        pygame.mixer.music.play()
        while pygame.mixer.music.get_busy():
            pygame.time.Clock().tick(10)
    except Exception as e:
        console.print(f"[bold red]Ошибка воспроизведения уведомления: {e}[/]")


def print_easter_egg():
    os.system("clear")
    console.print(Panel(
        "[bold magenta]Вы нашли секретную пасхалку! 🎉\n\n"
        "Спасибо за внимание к моей программе:)!\n"
        "Ставьте лайки, подписывайтесь на канал.. ой, я что-то перепутал😊[/]",
        title="🎉 Секретная пасхалка! 🎉",
        style="on black"
    ))


def handle_database_initialization():
    """
    Обрабатывает инициализацию базы данных:
    - Если база данных не существует, создает новую.
    - Если существует зашифрованный файл (.zlib), расшифровывает его.
    - В случае ошибки удаляет базу данных и формирует её заново.

    Я тут изначально использовал цикл While True без отдельной функции инициализации запуска, но потом понял, что это ребячество и решил взяться за ум)
    """
    try:
        # Проверяем существование файлов
        if not os.path.exists(DB_NAME) and not os.path.exists(DB_NAME + ".zlib"):
            # Первый запуск: база данных не найдена
            console.print("[bold yellow]Первый запуск: база данных не найдена. Создаём новую...[/]")
            conn = init_database(DB_NAME)
            return conn

        elif os.path.exists(DB_NAME + ".zlib"):
            # Если существует зашифрованный файл, расшифровываем его
            decompress_file(DB_NAME + ".zlib")
            conn = init_database(DB_NAME)
            return conn

        else:
            # База данных существует, пытаемся подключиться
            conn = init_database(DB_NAME)
            return conn

    except Exception as e:
        # В случае ошибки удаляем старую базу данных и создаём новую
        console.print(f"[bold red]Ошибка работы с базой данных: {e}[/]")
        console.print("[bold yellow]Попытка восстановления: удаляем старую базу данных и создаём новую...[/]")

        # Удаляем существующие файлы базы данных
        if os.path.exists(DB_NAME):
            os.remove(DB_NAME)
            console.print(f"[bold yellow]Удалён файл базы данных: {DB_NAME}[/]")
        if os.path.exists(DB_NAME + ".zlib"):
            os.remove(DB_NAME + ".zlib")
            console.print(f"[bold yellow]Удалён зашифрованный файл базы данных: {DB_NAME}.zlib[/]")

        # Пытаемся создать новую базу данных
        console.print("[bold yellow]Создаём новую базу данных...[/]")
        conn = init_database(DB_NAME)
        return conn


def main():
    # Проверка поддержки терминала
    terminal_supports_links = check_terminal_support()

    play_main_theme()

    console.print(Panel("[bold green]SUPER PUPER DUPER ULTRA [bold cyan]Vulnerability Checker[/] v1.0[/]",
                        title="Добро пожаловать!", subtitle="Защитите свои системы!"))

    try:
        conn = handle_database_initialization()
    except Exception as e:
        console.print(f"[bold red]Критическая ошибка при работе с базой данных: {e}[/]")
        return


    # Загрузка данных
    loaded_versions = load_versions(conn, VERSIONS_FILE)
    loaded_vulns = load_vulnerabilities(conn, VULNERABILITIES_FILE)

    if loaded_versions == 0 or loaded_vulns == 0:
        console.print("[bold red]Ошибка: данные не загружены. Проверьте файлы JSON.[/]")
        return

    console.print(f"[green]Загружено {loaded_versions} версий и {loaded_vulns} уязвимостей.[/]")

    while True:
        console.print("\n[bold cyan]Главное меню:[/]")
        console.print("1. 🔍 Найти безопасную версию продукта")
        console.print("2. 🕵️‍♂️ Проверить уязвимости по продукту и версии")
        console.print("3. 🚪 Выйти")

        choice = input("Выберите действие: ").strip()

        if choice.lower() == "kaspersky":
            print_easter_egg()
            continue

        # Проверяем, что введённое значение соответствует меню
        if choice not in ["1", "2", "3"]:
            os.system("clear")
            console.print("[bold red]Неверный выбор. Попробуйте снова.[/]")
            continue

        if choice == "1":
            product = Prompt.ask("[bold yellow]Введите название продукта[/]").strip()
            try:
                validate_product_name(conn, product)
            except ValueError as e:
                console.print(f"[bold red]{e}[/]")
                continue

            os.system("clear")
            first_safe_version, last_version = get_safe_version(conn, product)
            if first_safe_version:
                console.print(Panel(
                    f"✅ Первая безопасная версия: [bold green]{first_safe_version}[/]\n"
                    f"Все более новые версии также безопасны (последняя доступная версия: [bold green]{last_version}[/]).",
                    title="Безопасная версия найдена!"
                ))
            else:
                console.print("[bold red]❌ Не удалось найти безопасную версию.[/]")

        elif choice == "2":
            product = Prompt.ask("[bold yellow]Введите название продукта[/]").strip()
            version = Prompt.ask("[bold yellow]Введите версию[/]").strip()

            os.system("clear")
            try:
                validate_product_name(conn, product)
                validate_version(conn, product, version)
            except ValueError as e:
                console.print(f"[bold red]{e}[/]")
                continue

            results = check_vulnerabilities(conn, product, version)

            if not results:
                console.print(Panel(f"✅ У продукта '{product}' в версии '{version}' уязвимостей не найдено.",
                                    title="Анализ завершен"))
            else:
                print_vulnerabilities_table(results, terminal_supports_links)

        elif choice == "3":
            os.system("clear")
            console.print("[bold magenta]Вы покинули матрицу... 🚪[/]")
            exit_sound()
            pygame.mixer.music.stop()

            compress_file(DB_NAME)

            break

    conn.close()


if __name__ == "__main__":
    main()
