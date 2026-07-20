import json
import subprocess
import tempfile
import os
from typing import List, Dict


class MasscanWrapper:
    def __init__(self, binary_path: str = "masscan", rate: int = 1000):
        self.binary_path = binary_path
        self.rate = rate

    def scan_targets(self, targets: List[str], ports: str = "1-65535") -> List[Dict]:
        """
        Выполняет сканирование с помощью Masscan через subprocess.
        """
        if not targets:
            return []

        # Создаём временный файл со списком целей
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        output_file = tempfile.NamedTemporaryFile(
            delete=False, suffix='.json').name

        cmd = [
            self.binary_path,
            '-iL', targets_file,
            '-p', ports,
            '--rate', str(self.rate),
            '-oJ', output_file,
            '--quiet'
        ]

        try:
            result = subprocess.run(
                cmd, check=False, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[!] Masscan завершился с кодом {result.returncode}")
                print(f"STDERR: {result.stderr}")
                print(f"STDOUT: {result.stdout}")
                return []

            # Проверяем, что файл существует и не пустой
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                print("[!] Masscan не создал выходной файл или он пуст.")
                print(f"Проверьте права администратора и наличие Npcap.")
                return []

            # Читаем JSON-вывод
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    print("[!] Файл с результатами Masscan пуст.")
                    return []
                data = json.loads(content)

            return self._parse_output(data)

        except FileNotFoundError:
            print(
                f"[!] Исполняемый файл Masscan не найден по пути: {self.binary_path}")
            print(
                "Убедитесь, что masscan.exe установлен и добавлен в PATH, либо укажите полный путь.")
            return []
        except json.JSONDecodeError as e:
            print(f"[!] Ошибка парсинга JSON из вывода Masscan: {e}")
            # Попытаемся показать начало содержимого файла для диагностики
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()[:500]
                print(f"Содержимое файла (первые 500 символов):\n{content}")
            except:
                pass
            return []
        finally:
            # Удаляем временные файлы
            if os.path.exists(targets_file):
                os.remove(targets_file)
            if os.path.exists(output_file):
                os.remove(output_file)

    def _parse_output(self, data: dict) -> List[Dict]:
        """Парсит JSON-вывод Masscan."""
        results = []
        for host in data.get("hosts", []):
            ip = host.get("ip", "")
            for port in host.get("ports", []):
                results.append({
                    "ip": ip,
                    "port": port.get("port"),
                    "protocol": port.get("proto", "tcp")
                })
        return results
