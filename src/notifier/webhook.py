from typing import Dict
import requests
from typing import List, Dict


class WebhookNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_alert(self, data: Dict):
        """Отправляет уведомление через Webhook (например, в корпоративный мессенджер)."""
        try:
            requests.post(self.webhook_url, json=data, timeout=10)
        except Exception as e:
            print(f"[!] Ошибка отправки Webhook: {e}")
