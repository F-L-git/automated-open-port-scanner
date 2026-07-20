import nmap
from typing import List, Dict


class NmapWrapper:
    def __init__(self, binary_path: str = "nmap"):
        self.nm = nmap.PortScanner()

    def scan(self, ip: str, ports: List[int]) -> List[Dict]:
        if not ports:
            return []
        port_str = ",".join(str(p) for p in ports)
        print(f"[DEBUG] Сканирование {ip} на порты: {port_str}")
        try:
            self.nm.scan(hosts=ip, ports=port_str, arguments="-sT -Pn")
        except Exception as e:
            print(f"[ERROR] Ошибка Nmap: {e}")
            return []

        results = []
        if ip in self.nm.all_hosts():
            print(
                f"[DEBUG] Nmap нашёл хост {ip}, протоколы: {self.nm[ip].all_protocols()}")
            for proto in self.nm[ip].all_protocols():
                for port in self.nm[ip][proto].keys():
                    if port in ports:
                        info = self.nm[ip][proto][port]
                        print(
                            f"[DEBUG] Порт {port} состояние: {info.get('state')}")
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
        else:
            print(f"[DEBUG] Хост {ip} не найден в результатах Nmap")
        return results
