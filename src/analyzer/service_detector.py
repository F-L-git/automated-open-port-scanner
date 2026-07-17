import requests
import ssl
import socket
from typing import Dict, Optional


class ServiceAnalyzer:
    @staticmethod
    def analyze_web_service(ip: str, port: int) -> Dict:
        """Анализирует веб-сервис (HTTP/HTTPS)."""
        result = {"port": port, "type": "web"}
        try:
            # HTTP
            url = f"http://{ip}:{port}"
            resp = requests.get(url, timeout=5, headers={
                                "User-Agent": "PortScanner/1.0"})
            result["http"] = {
                "status_code": resp.status_code,
                "server": resp.headers.get("Server", "unknown"),
                "title": self._extract_title(resp.text)
            }
        except requests.exceptions.RequestException:
            # HTTPS
            try:
                url = f"https://{ip}:{port}"
                resp = requests.get(url, timeout=5, verify=False)
                result["https"] = {
                    "status_code": resp.status_code,
                    "server": resp.headers.get("Server", "unknown")
                }
                # SSL-информация
                result["ssl"] = self._get_ssl_info(ip, port)
            except:
                pass
        return result

    @staticmethod
    def _get_ssl_info(ip: str, port: int) -> Dict:
        """Извлекает информацию из SSL-сертификата.[reference:6]"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "expired": self._check_expired(cert.get("notAfter"))
                    }
        except:
            return {"error": "SSL info unavailable"}
