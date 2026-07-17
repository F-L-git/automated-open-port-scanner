import json
import subprocess
from typing import List, Dict, Optional
from nmass import Masscan


class MasscanWrapper:
    def __init__(self, binary_path: str = "masscan", rate: int = 1000):
        self.binary_path = binary_path
        self.rate = rate
        self.scanner = Masscan(binary_path=binary_path)

    def scan_targets(self, targets: List[str], ports: str = "1-65535") -> List[Dict]:
        """
        Выполняет сканирование с помощью Masscan.

        Args:
            targets: Список IP-адресов или CIDR-блоков
            ports: Диапазон портов (например, "1-65535" или "80,443,8080")

        Returns:
            Список открытых портов в формате:
            [{"ip": "192.168.1.1", "port": 80, "protocol": "tcp"}, ...]
        """
        results = []

        for target in targets:
            self.scanner.set_targets(target)
            self.scanner.set_ports(ports)
            self.scanner.set_rate(self.rate)
            self.scanner.set_output_format("json")

            # Запуск сканирования
            output = self.scanner.run()

            # Парсинг JSON-вывода
            parsed = self._parse_output(output)
            results.extend(parsed)

        return results

    def _parse_output(self, output: str) -> List[Dict]:
        """Парсит JSON-вывод Masscan."""
        try:
            data = json.loads(output)
            results = []
            for host in data.get("hosts", []):
                ip = host.get("ip", "")
                for port in host.get("ports", []):
                    results.append({
                        "ip": ip,
                        "port": port.get("port"),
                        "protocol": port.get("proto", "tcp")
                    })
            return results
        except json.JSONDecodeError:
            # Если вывод в другом формате, используем альтернативный парсинг
            return self._parse_grepable(output)
