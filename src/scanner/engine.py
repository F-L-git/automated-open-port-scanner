import concurrent.futures
from typing import List, Dict
from .masscan_wrapper import MasscanWrapper
from .nmap_wrapper import NmapWrapper


class ScanEngine:
    def __init__(self, masscan_rate: int = 1000, nmap_threads: int = 10):
        self.masscan = MasscanWrapper(rate=masscan_rate)
        self.nmap = NmapWrapper()
        self.nmap_threads = nmap_threads

    def run_scan(self, targets: List[str], ports: str = "1-65535") -> Dict:
        """
        Запускает двухуровневое сканирование.

        Уровень 1: Masscan быстро находит открытые порты.
        Уровень 2: Nmap детально сканирует только открытые порты.
        """
        # Уровень 1: быстрое сканирование
        print(f"[*] Запуск Masscan для {len(targets)} целей...")
        open_ports = self.masscan.scan_targets(targets, ports)
        print(f"[+] Masscan обнаружил {len(open_ports)} открытых портов")

        # Группировка результатов по IP
        targets_to_scan = self._group_by_ip(open_ports)

        # Уровень 2: детальное сканирование Nmap (параллельно)
        print(f"[*] Запуск детального сканирования Nmap...")
        detailed_results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_threads) as executor:
            futures = {
                executor.submit(self._nmap_scan_ip, ip, ports_list): ip
                for ip, ports_list in targets_to_scan.items()
            }
            for future in concurrent.futures.as_completed(futures):
                detailed_results.extend(future.result())

        return {
            "masscan_results": open_ports,
            "detailed_results": detailed_results,
            "total_open_ports": len(open_ports)
        }

    def _group_by_ip(self, results: List[Dict]) -> Dict:
        """Группирует порты по IP-адресам."""
        grouped = {}
        for item in results:
            ip = item["ip"]
            if ip not in grouped:
                grouped[ip] = []
            grouped[ip].append(item["port"])
        return grouped

    def _nmap_scan_ip(self, ip: str, ports: List[int]) -> List[Dict]:
        """Запускает Nmap для одного IP с указанными портами."""
        return self.nmap.scan(ip, ports)
