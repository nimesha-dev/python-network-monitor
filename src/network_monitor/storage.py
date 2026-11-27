from __future__ import annotations

import csv
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from network_monitor.config import DATABASE_FILE, EXPORT_DIR, prepare_directories

EVENT_FIELDS = [
    "id", "timestamp", "severity", "category", "source_ip",
    "destination_ip", "description", "details",
]


class Storage:
    """SQLite persistence for security events and monitoring snapshots.

    Every operation opens its own connection and guarantees it is closed,
    committed on success and rolled back on failure.
    """

    def __init__(self, database_path: Path = DATABASE_FILE):
        prepare_directories()
        self.database_path = Path(database_path)
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    description TEXT NOT NULL,
                    details TEXT
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    interface_count INTEGER NOT NULL,
                    active_interfaces INTEGER NOT NULL,
                    connection_count INTEGER NOT NULL,
                    listening_port_count INTEGER NOT NULL,
                    upload_bytes INTEGER NOT NULL,
                    download_bytes INTEGER NOT NULL,
                    snapshot_json TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON security_events (timestamp)
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_severity
                ON security_events (severity)
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_category
                ON security_events (category)
            """)

    def save_event(self, event: dict[str, Any]) -> None:
        with self._connection() as db:
            db.execute("""
                INSERT INTO security_events
                (timestamp, severity, category, source_ip, destination_ip,
                 description, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                event.get("severity", "INFO"),
                event.get("category", "General"),
                event.get("source_ip"),
                event.get("destination_ip"),
                event.get("description", ""),
                json.dumps(event.get("details", {}), default=str),
            ))

    def save_snapshot(self, snapshot: dict[str, Any]) -> None:
        interfaces = snapshot.get("interfaces", [])
        active = sum(1 for item in interfaces if item.get("status") == "UP")
        stats = snapshot.get("statistics", [])
        upload = sum(item.get("bytes_sent", 0) for item in stats)
        download = sum(item.get("bytes_recv", 0) for item in stats)
        with self._connection() as db:
            db.execute("""
                INSERT INTO monitoring_snapshots
                (timestamp, interface_count, active_interfaces, connection_count,
                 listening_port_count, upload_bytes, download_bytes, snapshot_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                snapshot.get("timestamp", datetime.now(timezone.utc).isoformat()),
                len(interfaces), active, len(snapshot.get("connections", [])),
                len(snapshot.get("listening_ports", [])), upload, download,
                json.dumps(snapshot, default=str),
            ))

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, int(limit))
        with self._connection() as db:
            rows = db.execute(
                "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_snapshots(self, limit: int = 20) -> list[dict[str, Any]]:
        limit = max(1, int(limit))
        with self._connection() as db:
            rows = db.execute(
                "SELECT * FROM monitoring_snapshots ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT * FROM security_events WHERE id = ?", (event_id,)
            ).fetchone()
        return dict(row) if row else None

    def event_categories(self) -> list[str]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT DISTINCT category FROM security_events ORDER BY category"
            ).fetchall()
        return [row["category"] for row in rows]

    def search_events(
        self,
        ip: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 100,
        ascending: bool = False,
    ) -> list[dict[str, Any]]:
        """Return events matching any combination of IP, severity and category."""
        clauses: list[str] = []
        params: list[Any] = []
        if ip:
            clauses.append("(source_ip = ? OR destination_ip = ?)")
            params.extend([ip, ip])
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if category:
            clauses.append("category = ?")
            params.append(category)
        limit = max(1, int(limit))
        params.append(limit)
        order = "ASC" if ascending else "DESC"
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connection() as db:
            rows = db.execute(
                f"SELECT * FROM security_events {where} "
                f"ORDER BY id {order} LIMIT ?",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def export_events(
        self, file_format: str, rows: list[dict[str, Any]] | None = None
    ) -> Path:
        if rows is None:
            rows = self.recent_events(limit=100000)
        fmt = (file_format or "").strip().lower()
        if fmt not in ("json", "csv"):
            raise ValueError("Export format must be csv or json.")
        EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "json":
            path = EXPORT_DIR / f"security_events_{stamp}.json"
            path.write_text(
                json.dumps(rows, indent=2, default=str), encoding="utf-8"
            )
            return path
        path = EXPORT_DIR / f"security_events_{stamp}.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=EVENT_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        return path
