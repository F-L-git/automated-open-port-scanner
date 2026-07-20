import concurrent.futures
import shutil
from typing import List, Dict
from .masscan_wrapper import MasscanWrapper
from .nmap_wrapper import NmapWrapper

class ScanEngine:
    def __init__(self, masscan_rate: int = 1000, nmap_threads: int = 10, force_nmap: bool = False,
                 masscan_binary: str = "masscan"):
        self.masscan = MasscanWrapper(binary_path=masscan_binary, rate=masscan_rate)
        self.nmap = NmapWrapper()
        self.nmap_threads = nmap_threads
        self.force_nmap = force_nmap
        self.masscan_available = self._check_masscan(masscan_binary)

    def _check_masscan(self, binary: str) -> bool:
        """Проверяет, доступен ли Masscan в системе."""
        return shutil.which(binary) is not None

    def run_scan(self, targets: List[str], ports: str = "1-65535") -> Dict:
        open_ports = []

        # Если force_nmap или Masscan недоступен – пропускаем Masscan
        if self.force_nmap or not self.masscan_available:
            if not self.masscan_available:
                print("[!] Masscan не найден в системе. Используем только Nmap.")
            else:
                print("[*] Используется только Nmap (force_nmap=True)")
        else:
            print(f"[*] Запуск Masscan для {len(targets)} целей...")
            open_ports = self.masscan.scan_targets(targets, ports)
            print(f"[+] Masscan обнаружил {len(open_ports)} открытых портов")

        # Если Masscan не дал результатов или force_nmap / недоступен – запускаем Nmap для всех целей
        if not open_ports or self.force_nmap or not self.masscan_available:
            print("[*] Запускаем Nmap для всех указанных IP...")
            port_list = self._parse_ports(ports)
            detailed_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_threads) as executor:
                futures = {
                    executor.submit(self._nmap_scan_ip, ip, port_list): ip
                    for ip in targets
                }
                for future in concurrent.futures.as_completed(futures):
                    for result in future.result():
                        if result.get('state') == 'open':      # Только действительно открытые
                            detailed_results.append(result)
            return {
                "masscan_results": open_ports,
                "detailed_results": detailed_results,
                "total_open_ports": len(detailed_results)
            }
        else:
            # Если Masscan сработал – сканируем только найденные порты
            targets_to_scan = self._group_by_ip(open_ports)
            print(f"[*] Запуск детального сканирования Nmap для {len(targets_to_scan)} хостов...")
            detailed_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_threads) as executor:
                futures = {
                    executor.submit(self._nmap_scan_ip, ip, ports_list): ip
                    for ip, ports_list in targets_to_scan.items()
                }
                for future in concurrent.futures.as_completed(futures):
                    for result in future.result():
                        if result.get('state') == 'open':
                            detailed_results.append(result)
            return {
                "masscan_results": open_ports,
                "detailed_results": detailed_results,
                "total_open_ports": len(detailed_results)
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