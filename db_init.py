import sqlite3

def init_database(db_name):
    try:
        conn = sqlite3.connect(db_name)

        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT NOT NULL,
                UNIQUE(vendor, product, version)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                KLA_id TEXT NOT NULL,
                description TEXT NOT NULL,
                publish_date TEXT NOT NULL,
                start_vuln_version TEXT NOT NULL,
                fixed_version TEXT NOT NULL,
                UNIQUE(vendor, product, KLA_id)
            )
        ''')

        conn.commit()
        return conn
    except Exception as e:
        print(f"[bold red]Ошибка инициализации базы данных: {e}[/]")
        sys.exit(1)