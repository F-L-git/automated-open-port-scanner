FROM python:3.11-slim

# Установка системных зависимостей (masscan, nmap, и прочее)
RUN apt-get update && apt-get install -y \
    masscan \
    nmap \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Установка рабочей директории
WORKDIR /app

# Копирование requirements.txt и установка Python-пакетов
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование всего остального кода
COPY . .

# Точка входа – запуск main.py
ENTRYPOINT ["python", "main.py"]