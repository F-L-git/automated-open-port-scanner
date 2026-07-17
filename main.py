#!/usr/bin/env python3
import argparse
import yaml
import logging
from src.scanner.engine import ScanEngine
from src.storage.database import Database
from src.notifier.telegram import TelegramNotifier
from src.notifier.webhook import WebhookNotifier
from src.notifier.alert_rules import AlertRules
from src.analyzer.service_detector import ServiceAnalyzer


def load_config(config_path: str = "config/config.yaml") -> dict:
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scanner.log'),
            logging.StreamHandler()
        ]
    )


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
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger(__name__)

    # Загрузка конфигурации
    config = load_config(args.config)
    targets_file = args.targets or config.get(
        "targets_file", "targets/targets.txt")

    # Чтение целей
    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    logger.info(f"Запуск сканирования для {len(targets)} целей")

    # Запуск движка сканирования
    engine = ScanEngine(masscan_rate=args.rate)
    results = engine.run_scan(targets, args.ports)

    # Сохранение в БД
    db = Database(config.get("db_path", "scans.db"))
    scan_id = db.save_scan_results(", ".join(targets), results)
    logger.info(f"Результаты сохранены в БД (ID: {scan_id})")

    # Анализ и оповещения
    notifiers = []
    if config.get("telegram", {}).get("enabled"):
        tg = config["telegram"]
        notifiers.append(TelegramNotifier(tg["bot_token"], tg["chat_id"]))
    if config.get("webhook", {}).get("enabled"):
        notifiers.append(WebhookNotifier(config["webhook"]["url"]))

    # Проверка высокорисковых сервисов
    for port_info in results.get("detailed_results", []):
        if AlertRules.check_high_risk(
            port_info["ip"],
            port_info["port"],
            port_info.get("service", "")
        ):
            alert_msg = AlertRules.generate_alert(
                port_info["ip"],
                port_info["port"],
                port_info.get("service", ""),
                port_info.get("version", "")
            )
            for notifier in notifiers:
                notifier.send_alert(alert_msg)
            logger.warning(f"Высокорисковый сервис: {port_info}")

    # Вывод сводки
    logger.info(f"=== СВОДКА ===")
    logger.info(f"Всего открытых портов: {results['total_open_ports']}")
    logger.info(f"Детально просканировано: {len(results['detailed_results'])}")


if __name__ == "__main__":
    main()
