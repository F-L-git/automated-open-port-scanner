from dataclasses import dataclass
from datetime import datetime


@dataclass
class Scan:
    id: int
    timestamp: datetime
    target: str
    open_ports: int
    status: str


@dataclass
class OpenPort:
    id: int
    scan_id: int
    ip: str
    port: int
    protocol: str
    service: str
    version: str


@dataclass
class PortHistory:
    id: int
    ip: str
    port: int
    first_seen: datetime
    last_seen: datetime
    status: str
