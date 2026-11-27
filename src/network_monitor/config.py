from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
EXPORT_DIR = PROJECT_ROOT / "exports"
PCAP_DIR = PROJECT_ROOT / "pcaps"
CONFIG_DIR = PROJECT_ROOT / "config"
CONFIG_FILE = CONFIG_DIR / "settings.json"
DATABASE_FILE = DATA_DIR / "network_monitor.db"

_INVALID = object()


@dataclass
class Settings:
    monitor_interval: float = 2.0
    packet_capture_duration: int = 30
    port_scan_threshold: int = 15
    repeated_attempt_threshold: int = 10
    dos_packet_threshold: int = 100
    dos_byte_threshold: int = 1_048_576
    detection_window_seconds: int = 10
    connection_window_seconds: int = 60
    unusual_remote_connection_threshold: int = 15
    high_bandwidth_threshold_bps: int = 10_485_760
    alert_cooldown_seconds: int = 60
    suspicious_ports: list[int] = field(default_factory=lambda: [
        23, 2323, 4444, 5555, 6667, 31337
    ])
    allowed_listening_ports: list[int] = field(default_factory=lambda: [
        22, 53, 80, 443, 631, 5432
    ])

    @classmethod
    def load(cls) -> "Settings":
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if not CONFIG_FILE.exists():
            settings = cls()
            settings.save()
            return settings
        try:
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return cls()
        if not isinstance(raw, dict):
            return cls()

        values: dict[str, Any] = {}
        for key in cls.__dataclass_fields__:
            if key not in raw:
                continue
            cleaned = _clean_value(key, raw[key])
            if cleaned is not _INVALID:
                values[key] = cleaned
        return cls(**values)

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(
            json.dumps(self.__dict__, indent=4), encoding="utf-8"
        )


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _clean_int(value: Any, low: int, high: int) -> Any:
    number = _as_number(value)
    if number is None:
        return _INVALID
    integer = int(round(number))
    if not low <= integer <= high:
        return _INVALID
    return integer


def _clean_float(value: Any, low: float, high: float) -> Any:
    number = _as_number(value)
    if number is None or not low <= number <= high:
        return _INVALID
    return float(number)


def _clean_port_list(value: Any) -> Any:
    if not isinstance(value, list):
        return _INVALID
    ports: list[int] = []
    for item in value:
        number = _as_number(item)
        if number is None:
            return _INVALID
        port = int(round(number))
        if not 0 <= port <= 65535:
            return _INVALID
        if port not in ports:
            ports.append(port)
    return ports


def _clean_value(key: str, value: Any) -> Any:
    """Validate one setting; return _INVALID to fall back to the default."""
    if key in ("suspicious_ports", "allowed_listening_ports"):
        return _clean_port_list(value)
    if key == "monitor_interval":
        return _clean_float(value, 0.1, 3600.0)
    if key == "packet_capture_duration":
        return _clean_int(value, 1, 3600)
    if key in ("detection_window_seconds", "connection_window_seconds"):
        return _clean_int(value, 1, 86_400)
    if key == "alert_cooldown_seconds":
        return _clean_int(value, 0, 86_400)
    if key in (
        "port_scan_threshold",
        "repeated_attempt_threshold",
        "dos_packet_threshold",
        "dos_byte_threshold",
        "unusual_remote_connection_threshold",
        "high_bandwidth_threshold_bps",
    ):
        return _clean_int(value, 1, 2**63 - 1)
    return _INVALID


def prepare_directories() -> None:
    for directory in (DATA_DIR, EXPORT_DIR, PCAP_DIR, CONFIG_DIR):
        directory.mkdir(parents=True, exist_ok=True)
