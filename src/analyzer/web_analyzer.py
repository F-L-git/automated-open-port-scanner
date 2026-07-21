from typing import Dict
from .service_detector import ServiceAnalyzer


class WebAnalyzer:
    @staticmethod
    def analyze(ip: str, port: int) -> Dict:
        return ServiceAnalyzer.analyze_web_service(ip, port)
