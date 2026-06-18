import time

import config

_db_type = config.DB_TYPE
_ph = '?' if _db_type == 'sqlite' else '%s'  # placeholder 符号


def _conn():
    """返回数据库连接 (兼容 SQLite / MySQL)"""
    if _db_type == 'mysql':
        import pymysql
        conn = pymysql.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USER,
            password=config.MYSQL_PASSWORD,
            database=config.MYSQL_DATABASE,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
        )
        return conn
    else:
        import sqlite3
        conn = sqlite3.connect(config.DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn


def _row_to_dict(row):
    """将数据库行转为普通 dict"""
    if row is None:
        return None
    if _db_type == 'mysql':
        return dict(row)
    # sqlite3.Row
    return dict(row)


def init_db():
    conn = _conn()
    cur = conn.cursor()

    if _db_type == 'mysql':
        cur.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                target VARCHAR(500) NOT NULL,
                scan_type VARCHAR(50) NOT NULL DEFAULT 'full',
                status VARCHAR(50) NOT NULL DEFAULT 'pending',
                nmap_output MEDIUMTEXT,
                nuclei_output MEDIUMTEXT,
                open_ports VARCHAR(500) DEFAULT '',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INT AUTO_INCREMENT PRIMARY KEY,
                scan_id INT NOT NULL,
                template_name VARCHAR(500),
                template_id VARCHAR(200),
                severity VARCHAR(20),
                matched_at VARCHAR(1000),
                ip VARCHAR(100),
                host VARCHAR(500),
                request_headers MEDIUMTEXT,
                request_body MEDIUMTEXT,
                response_headers MEDIUMTEXT,
                response_body MEDIUMTEXT,
                info_json MEDIUMTEXT,
                curl_command MEDIUMTEXT,
                created_at DATETIME NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS nuclei_plugins (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(200) NOT NULL UNIQUE,
                content MEDIUMTEXT NOT NULL,
                description VARCHAR(500) DEFAULT '',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')
    else:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL DEFAULT 'full',
                status TEXT NOT NULL DEFAULT 'pending',
                nmap_output TEXT,
                nuclei_output TEXT,
                open_ports TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                template_name TEXT,
                template_id TEXT,
                severity TEXT,
                matched_at TEXT,
                ip TEXT,
                host TEXT,
                request_headers TEXT,
                request_body TEXT,
                response_headers TEXT,
                response_body TEXT,
                info_json TEXT,
                curl_command TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS nuclei_plugins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                content TEXT NOT NULL,
                description TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

    # 为已有数据库添加 open_ports 列（迁移）
    try:
        cur.execute(f'ALTER TABLE scans ADD COLUMN open_ports VARCHAR(500) DEFAULT \'\'')
    except Exception:
        pass

    conn.commit()
    conn.close()


def create_scan(target, scan_type='full'):
    conn = _conn()
    cur = conn.cursor()
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    cur.execute(
        f'INSERT INTO scans (target, scan_type, status, created_at, updated_at) VALUES ({_ph}, {_ph}, {_ph}, {_ph}, {_ph})',
        (target, scan_type, 'pending', now, now)
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_scan_status(scan_id, status, nmap_output=None, nuclei_output=None, open_ports=None):
    conn = _conn()
    cur = conn.cursor()
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    fields = ['status = ' + _ph, 'updated_at = ' + _ph]
    values = [status, now]
    if nmap_output is not None:
        fields.append('nmap_output = ' + _ph)
        values.append(nmap_output)
    if nuclei_output is not None:
        fields.append('nuclei_output = ' + _ph)
        values.append(nuclei_output)
    if open_ports is not None:
        fields.append('open_ports = ' + _ph)
        values.append(open_ports)
    values.append(scan_id)
    cur.execute(f'UPDATE scans SET {", ".join(fields)} WHERE id = {_ph}', values)
    conn.commit()
    conn.close()


def get_scan(scan_id):
    conn = _conn()
    cur = conn.cursor()
    cur.execute(f'SELECT * FROM scans WHERE id = {_ph}', (scan_id,))
    row = cur.fetchone()
    conn.close()
    return _row_to_dict(row)


def get_all_scans():
    conn = _conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM scans ORDER BY created_at DESC')
    rows = cur.fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def insert_vulnerability(scan_id, template_name, template_id, severity,
                         matched_at, ip, host, request_headers, request_body,
                         response_headers, response_body, info_json, curl_command):
    conn = _conn()
    cur = conn.cursor()
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    cur.execute(f'''
        INSERT INTO vulnerabilities
        (scan_id, template_name, template_id, severity, matched_at, ip, host,
         request_headers, request_body, response_headers, response_body, info_json, curl_command, created_at)
        VALUES ({_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph})
    ''', (scan_id, template_name, template_id, severity, matched_at, ip, host,
          request_headers, request_body, response_headers, response_body, info_json, curl_command, now))
    conn.commit()
    conn.close()


def get_vulnerabilities_by_scan(scan_id):
    conn = _conn()
    cur = conn.cursor()
    cur.execute(f'SELECT * FROM vulnerabilities WHERE scan_id = {_ph} ORDER BY severity DESC, created_at DESC', (scan_id,))
    rows = cur.fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_vulnerability(vuln_id):
    conn = _conn()
    cur = conn.cursor()
    cur.execute(f'SELECT * FROM vulnerabilities WHERE id = {_ph}', (vuln_id,))
    row = cur.fetchone()
    conn.close()
    return _row_to_dict(row)


def get_all_vulnerabilities():
    conn = _conn()
    cur = conn.cursor()
    cur.execute('''
        SELECT v.*, s.target FROM vulnerabilities v
        JOIN scans s ON v.scan_id = s.id
        ORDER BY v.created_at DESC
    ''')
    rows = cur.fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def save_plugin(name, content, description=''):
    conn = _conn()
    cur = conn.cursor()
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    cur.execute(f'SELECT id FROM nuclei_plugins WHERE name = {_ph}', (name,))
    existing = cur.fetchone()
    if existing:
        cur.execute(
            f'UPDATE nuclei_plugins SET content = {_ph}, description = {_ph}, updated_at = {_ph} WHERE name = {_ph}',
            (content, description, now, name)
        )
    else:
        cur.execute(
            f'INSERT INTO nuclei_plugins (name, content, description, created_at, updated_at) VALUES ({_ph},{_ph},{_ph},{_ph},{_ph})',
            (name, content, description, now, now)
        )
    conn.commit()
    conn.close()


def delete_plugin(plugin_id):
    conn = _conn()
    cur = conn.cursor()
    cur.execute(f'DELETE FROM nuclei_plugins WHERE id = {_ph}', (plugin_id,))
    conn.commit()
    conn.close()


def delete_scan(scan_id):
    """删除扫描任务及其关联漏洞"""
    conn = _conn()
    cur = conn.cursor()
    cur.execute(f'DELETE FROM vulnerabilities WHERE scan_id = {_ph}', (scan_id,))
    cur.execute(f'DELETE FROM scans WHERE id = {_ph}', (scan_id,))
    conn.commit()
    conn.close()


def get_all_plugins():
    conn = _conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM nuclei_plugins ORDER BY updated_at DESC')
    rows = cur.fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_plugin(plugin_id):
    conn = _conn()
    cur = conn.cursor()
    cur.execute(f'SELECT * FROM nuclei_plugins WHERE id = {_ph}', (plugin_id,))
    row = cur.fetchone()
    conn.close()
    return _row_to_dict(row)
