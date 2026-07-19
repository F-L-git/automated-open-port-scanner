import nmap
from typing import List, Dict

class NmapWrapper:
    def __init__(self, binary_path: str = "nmap"):
        self.nm = nmap.PortScanner()

    def scan(self, ip: str, ports: List[int]) -> List[Dict]:
        """
        Выполняет детальное сканирование указанных портов на одном IP.
        Возвращает список словарей с информацией о каждом порте.
        """
        if not ports:
            return []

        port_str = ",".join(str(p) for p in ports)
        # Запускаем сканирование с определением версий (-sV) и ОС (-O) – можно настроить
        self.nm.scan(hosts=ip, ports=port_str, arguments="-sV -sT -Pn")

        results = []
        if ip in self.nm.all_hosts():
            for proto in self.nm[ip].all_protocols():
                for port in self.nm[ip][proto].keys():
                    if port in ports:  # Проверка на случай, если Nmap вернул больше
                        info = self.nm[ip][proto][port]
                        results.append({
                            "ip": ip,
                            "port": port,
                            "protocol": proto,
                            "service": info.get("name", ""),
                            "version": info.get("version", ""),
                            "product": info.get("product", ""),
                            "extrainfo": info.get("extrainfo", ""),
                            "state": info.get("state", ""),
                        })
        return results