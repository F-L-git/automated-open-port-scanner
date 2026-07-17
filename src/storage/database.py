import sqlite3
from datetime import datetime
from typing import List, Dict


class Database:
    def __init__(self, db_path: str = "scans.db"):
        self.conn = sqlite3.connect(db_path)
        self._init_tables()

    def _init_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT,
                open_ports INTEGER,
                status TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS open_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                ip TEXT,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                version TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS port_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                port INTEGER,
                first_seen DATETIME,
                last_seen DATETIME,
                status TEXT
            )
        """)
        self.conn.commit()

    def save_scan_results(self, target: str, results: Dict) -> int:
        """Сохраняет результаты сканирования и отслеживает изменения.[reference:7]"""
        cursor = self.conn.cursor()

        # Сохраняем информацию о сканировании
        cursor.execute(
            "INSERT INTO scans (target, open_ports, status) VALUES (?, ?, ?)",
            (target, results.get("total_open_ports", 0), "completed")
        )
        scan_id = cursor.lastrowid

        # Сохраняем открытые порты
        for port_info in results.get("detailed_results", []):
            cursor.execute(
                """INSERT INTO open_ports (scan_id, ip, port, protocol, service, version)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan_id, port_info["ip"], port_info["port"],
                 port_info.get("protocol", "tcp"),
                 port_info.get("service", ""),
                 port_info.get("version", ""))
            )

            # Обновляем историю портов
            self._update_port_history(
                port_info["ip"], port_info["port"], "open")

        self.conn.commit()
        return scan_id

    def _update_port_history(self, ip: str, port: int, status: str):
        """Обновляет историю изменения состояния порта.[reference:8]"""
        cursor = self.conn.cursor()
        cursor.execute(
            """SELECT id, status FROM port_history 
               WHERE ip = ? AND port = ? ORDER BY last_seen DESC LIMIT 1""",
            (ip, port)
        )
        row = cursor.fetchone()

        now = datetime.now().isoformat()
        if row and row[1] != status:
            # Состояние изменилось — добавляем запись
            cursor.execute(
                """INSERT INTO port_history (ip, port, first_seen, last_seen, status)
                   VALUES (?, ?, ?, ?, ?)""",
                (ip, port, now, now, status)
            )
        elif row:
            # Состояние не изменилось — обновляем last_seen
            cursor.execute(
                "UPDATE port_history SET last_seen = ? WHERE id = ?",
                (now, row[0])
            )
        else:
            # Новая запись
            cursor.execute(
                """INSERT INTO port_history (ip, port, first_seen, last_seen, status)
                   VALUES (?, ?, ?, ?, ?)""",
                (ip, port, now, now, status)
            )
        self.conn.commit()
