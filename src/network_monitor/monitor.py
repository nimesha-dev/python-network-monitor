from __future__ import annotations

import time
from typing import Any, Callable

import psutil

from network_monitor.collector import collect_snapshot
from network_monitor.config import Settings
from network_monitor.detector import SecurityDetector
from network_monitor.storage import Storage

UpdateCallback = Callable[[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]], None]


def calculate_speeds(previous: dict[str, Any], current: dict[str, Any],
                     elapsed: float) -> list[dict[str, Any]]:
    """Convert cumulative counter deltas into per-second rates.

    ``elapsed`` must be the real time elapsed between the two snapshots.
    """
    if elapsed <= 0:
        raise ValueError("elapsed time must be greater than zero")
    old = {item["name"]: item for item in previous.get("statistics", [])}
    result = []
    for item in current.get("statistics", []):
        before = old.get(item["name"])
        if before is None:
            continue
        result.append({
            "name": item["name"],
            "upload_bps": max(0, item["bytes_sent"] - before["bytes_sent"]) / elapsed,
            "download_bps": max(0, item["bytes_recv"] - before["bytes_recv"]) / elapsed,
        })
    return result


def run_monitoring(duration: int | None, settings: Settings,
                   storage: Storage, on_update: UpdateCallback) -> None:
    detector = SecurityDetector(settings)
    previous = collect_snapshot()
    # Treat the first snapshot as the baseline, not as newly observed activity.
    detector.inspect_interfaces(previous["interfaces"])
    detector.inspect_connections(previous["connections"])
    detector.inspect_listeners(previous["listening_ports"])
    storage.save_snapshot(previous)
    start = time.monotonic()
    last_sample = start

    while True:
        time.sleep(settings.monitor_interval)
        try:
            current = collect_snapshot()
        except (psutil.Error, OSError):
            # Skip a failed sample instead of crashing the monitoring loop.
            continue

        now = time.monotonic()
        elapsed = max(0.001, now - last_sample)
        last_sample = now
        speeds = calculate_speeds(previous, current, elapsed)

        events = detector.inspect_interfaces(current["interfaces"])
        events.extend(detector.inspect_connections(current["connections"]))
        events.extend(detector.inspect_speeds(speeds))
        events.extend(detector.inspect_listeners(current["listening_ports"]))
        for event in events:
            storage.save_event(event)

        storage.save_snapshot(current)
        on_update(current, speeds, events)
        previous = current

        if duration is not None and now - start >= duration:
            break
