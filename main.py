#!/usr/bin/env python3
import argparse
import logging
from src.scanner.engine import ScanEngine
from src.storage.database import Database
from src.notifier.telegram import TelegramNotifier
from src.notifier.webhook import WebhookNotifier
from src.notifier.email import EmailNotifier
from src.notifier.alert_rules import AlertRules
from src.analyzer.service_detector import ServiceAnalyzer
from src.utils.config import load_config
from src.utils.logger import setup_logging


def main():
    parser = argparse.ArgumentParser(
        description="Автоматизированный сканер портов")
    parser.add_argument("--targets", "-t", help="Файл со списком целей")
    parser.add_argument("--ports", "-p", default="1-65535",
                        help="Диапазон портов")
    parser.add_argument("--rate", "-r", type=int,
                        default=1000, help="Скорость сканирования")
    parser.add_argument(
        "--config", "-c", default="config/config.yaml", help="Путь к конфигу")
    parser.add_argument("--force-nmap", action="store_true",
                        help="Использовать только Nmap")
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger(__name__)

    config = load_config(args.config)
    targets_file = args.targets or config.get(
        "targets_file", "targets/targets.txt")

    try:
        with open(targets_file, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()
                       and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[!] Файл целей не найден: {targets_file}")
        exit(1)

    logger.info(f"Запуск сканирования для {len(targets)} целей:")
    for t in targets:
        logger.info(f"  - {t}")

    # Передаём путь к Masscan из конфига (если указан)
    masscan_binary = config.get("scan", {}).get("masscan_binary", "masscan")
    engine = ScanEngine(masscan_rate=args.rate, force_nmap=args.force_nmap,
                        masscan_binary=masscan_binary)
    results = engine.run_scan(targets, args.ports)

    db = Database(config.get("db_path", "scans.db"))
    scan_id = db.save_scan_results(", ".join(targets), results)
    logger.info(f"Результаты сохранены в БД (ID: {scan_id})")

    # Обогащение веб-сервисов – только для открытых портов
    for port_info in results.get("detailed_results", []):
        if port_info.get('state') == 'open' and port_info.get("port") in [80, 443, 8080, 8443]:
            web_info = ServiceAnalyzer.analyze_web_service(
                port_info["ip"], port_info["port"])
            port_info["web_analysis"] = web_info

    # Настройка уведомлений
    notifiers = []
    if config.get("telegram", {}).get("enabled"):
        tg = config["telegram"]
        notifiers.append(TelegramNotifier(tg["bot_token"], tg["chat_id"]))
    if config.get("webhook", {}).get("enabled"):
        notifiers.append(WebhookNotifier(config["webhook"]["url"]))
    if config.get("email", {}).get("enabled"):
        email_cfg = config["email"]
        notifiers.append(EmailNotifier(
            email_cfg["smtp_server"],
            email_cfg["smtp_port"],
            email_cfg["username"],
            email_cfg["password"],
            email_cfg["from_addr"],
            email_cfg["to_addrs"]
        ))

    # Проверка высокорисковых сервисов – только для открытых портов
    for port_info in results.get("detailed_results", []):
        if port_info.get('state') != 'open':
            continue
        if AlertRules.check_high_risk(port_info["ip"], port_info["port"], port_info.get("service", "")):
            alert_msg = AlertRules.generate_alert(
                port_info["ip"],
                port_info["port"],
                port_info.get("service", ""),
                port_info.get("version", "")
            )
            for notifier in notifiers:
                notifier.send_alert(alert_msg)
            logger.warning(f"Высокорисковый сервис: {port_info}")

    logger.info("=== СВОДКА ===")
    logger.info(f"Всего открытых портов: {results['total_open_ports']}")
    logger.info(
        f"Детально просканировано (только open): {len(results['detailed_results'])}")


if __name__ == "__main__":
    main()
