```text

automated-open-port-scanner/
├── src/
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py             # (приведён выше)
│   │   ├── masscan_wrapper.py    # (приведён выше)
│   │   └── nmap_wrapper.py       # (приведён выше)
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── service_detector.py   # (приведён выше)
│   │   ├── web_analyzer.py
│   │   └── ssl_analyzer.py       # (приведён выше)
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py           # (приведён ниже)
│   │   └── models.py             # (приведён ниже)
│   ├── notifier/
│   │   ├── __init__.py
│   │   ├── telegram.py           # (приведён выше)
│   │   ├── webhook.py            # (приведён выше)
│   │   ├── email.py              # (приведён выше)
│   │   └── alert_rules.py        # (приведён выше)
│   └── utils/
│       ├── __init__.py
│       ├── config.py             # (приведён ниже)
│       └── logger.py             # (приведён ниже)
├── config/
│   └── config.yaml               # (приведён выше)
├── targets/
│   └── targets.txt               # (пример)
├── main.py                       # (приведён выше)
├── requirements.txt              # (приведён ниже)
├── Dockerfile                    # (приведён ниже)
├── docker-compose.yml            # (приведён ниже)
├── .dockerignore                 # (приведён ниже)
├── .gitignore                    # (приведён ниже)
├── README.md                     # (полный текст – приведён ниже)
├── LICENSE                       # (MIT – приведён ниже)
└── .github/
    └── workflows/
        └── docker-publish.yml    # (приведён ниже)
```
