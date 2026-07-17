1. Установка зависимостей
```bash
# Установка Masscan
sudo apt-get update
sudo apt-get install masscan   # Ubuntu/Debian[reference:11]
# или
brew install masscan            # macOS

# Установка Nmap
sudo apt-get install nmap

# Установка Python-зависимостей
pip install -r requirements.txt
```

2. Файл requirements.txt
```text
nmass>=0.2.0
requests>=2.28.0
pyyaml>=6.0
python-nmap>=0.7.0
paramiko>=3.0.0
```

3. Запуск
```bash
# Базовый запуск
python main.py --targets targets/targets.txt

# С настройкой скорости
python main.py --targets targets/targets.txt --rate 5000 --ports "1-1000"

# С указанием конфига
python main.py -c config/production.yaml -t targets/prod.txt
```