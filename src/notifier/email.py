import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict


class EmailNotifier:
    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str, from_addr: str, to_addrs: list):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs

    def send_alert(self, message: str, subject: str = "Port Scanner Alert"):
        """Отправляет письмо с уведомлением."""
        msg = MIMEMultipart()
        msg['From'] = self.from_addr
        msg['To'] = ", ".join(self.to_addrs)
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
        except Exception as e:
            print(f"[!] Ошибка отправки email: {e}")
