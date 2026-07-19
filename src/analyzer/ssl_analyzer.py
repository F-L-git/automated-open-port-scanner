from typing import Dict
from .service_detector import ServiceAnalyzer


class SSLAnalyzer:
    @staticmethod
    def analyze(ip: str, port: int) -> Dict:
        """Получение SSL-информации."""
        return ServiceAnalyzer._get_ssl_info(ip, port)
