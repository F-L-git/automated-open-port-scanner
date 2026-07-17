from typing import Dict
import requests
from typing import List, Dict


class AlertRules:
    HIGH_RISK_SERVICES = {
        22: "SSH",
        23: "Telnet",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
        9000: "Portainer",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }

    @staticmethod
    def check_high_risk(ip: str, port: int, service: str) -> bool:
        """Проверяет, является ли сервис высокорисковым.[reference:10]"""
        return port in AlertRules.HIGH_RISK_SERVICES or service.lower() in ["docker", "redis", "mongodb"]

    @staticmethod
    def generate_alert(ip: str, port: int, service: str, version: str = "") -> str:
        """Генерирует текст оповещения."""
        service_name = AlertRules.HIGH_RISK_SERVICES.get(port, service)
        msg = f"🚨 <b>ОБНАРУЖЕН ВЫСОКОРИСКОВЫЙ СЕРВИС</b>\n"
        msg += f"📍 IP: <code>{ip}</code>\n"
        msg += f"🔌 Порт: <b>{port}</b>\n"
        msg += f"📦 Сервис: <b>{service_name}</b>\n"
        if version:
            msg += f"📌 Версия: <code>{version}</code>\n"
        msg += f"⚠️ Рекомендуется немедленная проверка!"
        return msg
