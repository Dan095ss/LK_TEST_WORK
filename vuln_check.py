from packaging import version

def get_safe_version(conn, product_name):
    """Возвращает первую безопасную версию и последнюю доступную версию продукта."""
    cursor = conn.cursor()

    # Получаем все версии продукта
    cursor.execute("""
        SELECT DISTINCT version FROM products WHERE product = ?
    """, (product_name,))
    versions = [row[0] for row in cursor.fetchall()]

    if not versions:
        return None, None

    versions.sort(key=lambda v: version.parse(v))

    first_safe_version = None
    for ver in versions:
        parsed_ver = version.parse(ver)

        cursor.execute("""
            SELECT KLA_id, start_vuln_version, fixed_version FROM vulnerabilities
            WHERE product = ?
        """, (product_name,))
        all_vulns = cursor.fetchall()

        is_vulnerable = False
        for vuln in all_vulns:
            kla_id = vuln[0]
            start_vuln = version.parse(vuln[1])
            fixed_vuln = version.parse(vuln[2])

            if parsed_ver >= start_vuln and parsed_ver < fixed_vuln:
                is_vulnerable = True
                break

        if not is_vulnerable:
            first_safe_version = ver
            break

    last_version = versions[-1] if versions else None
    return first_safe_version, last_version


def check_vulnerabilities(conn, product_name, version_str):
    """Проверяет, есть ли уязвимости для указанного продукта и версии."""
    cursor = conn.cursor()

    cursor.execute("""
        SELECT KLA_id, description, publish_date, start_vuln_version, fixed_version
        FROM vulnerabilities
        WHERE product = ?
    """, (product_name,))
    all_vulns = cursor.fetchall()

    results = []
    parsed_version = version.parse(version_str)
    for row in all_vulns:
        kla_id = row[0]
        start_ver = version.parse(row[3])  # start_vuln_version
        fixed_ver = version.parse(row[4])  # fixed_version

        if parsed_version >= start_ver and parsed_version < fixed_ver:
            results.append(row)

    return results