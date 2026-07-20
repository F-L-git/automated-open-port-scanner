import concurrent.futures
from typing import List, Dict
from .masscan_wrapper import MasscanWrapper
from .nmap_wrapper import NmapWrapper


class ScanEngine:
    def __init__(self, masscan_rate: int = 1000, nmap_threads: int = 10, force_nmap: bool = False):
        self.masscan = MasscanWrapper(rate=masscan_rate)
        self.nmap = NmapWrapper()
        self.nmap_threads = nmap_threads
        self.force_nmap = force_nmap

    def run_scan(self, targets: List[str], ports: str = "1-65535") -> Dict:
        # Уровень 1: Masscan (если не принудительно Nmap)
        open_ports = []
        if not self.force_nmap:
            print(f"[*] Запуск Masscan для {len(targets)} целей...")
            open_ports = self.masscan.scan_targets(targets, ports)
            print(f"[+] Masscan обнаружил {len(open_ports)} открытых портов")
        else:
            print("[*] Используется только Nmap (force_nmap=True)")

        # Если Masscan не дал результатов или force_nmap, запускаем Nmap для всех целей
        if not open_ports or self.force_nmap:
            print(
                "[*] Masscan не дал результатов или пропущен. Запускаем Nmap для всех указанных IP...")
            port_list = self._parse_ports(ports)
            detailed_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_threads) as executor:
                futures = {
                    executor.submit(self._nmap_scan_ip, ip, port_list): ip
                    for ip in targets
                }
                for future in concurrent.futures.as_completed(futures):
                    detailed_results.extend(future.result())
            return {
                "masscan_results": open_ports,
                "detailed_results": detailed_results,
                "total_open_ports": len(detailed_results)
            }
        else:
            # Если Masscan сработал, выполняем детальное сканирование только открытых портов
            targets_to_scan = self._group_by_ip(open_ports)
            print(
                f"[*] Запуск детального сканирования Nmap для {len(targets_to_scan)} хостов...")
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
        grouped = {}
        for item in results:
            ip = item["ip"]
            if ip not in grouped:
                grouped[ip] = []
            grouped[ip].append(item["port"])
        return grouped

    def _nmap_scan_ip(self, ip: str, ports: List[int]) -> List[Dict]:
        return self.nmap.scan(ip, ports)

    def _parse_ports(self, ports_str: str) -> List[int]:
        port_list = []
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                if part.isdigit():
                    port_list.append(int(part))
        return sorted(set(port_list))
