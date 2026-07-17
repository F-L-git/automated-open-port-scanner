from typing import Dict
import requests
from typing import List, Dict


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    def send_alert(self, message: str):
        """Отправляет сообщение в Telegram.[reference:9]"""
        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        try:
            requests.post(self.api_url, json=payload, timeout=10)
        except Exception as e:
            print(f"[!] Ошибка отправки в Telegram: {e}")
