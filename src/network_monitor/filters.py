from __future__ import annotations

from typing import Any


def filter_connections(
    connections: list[dict[str, Any]] | None,
    protocol: str | None = None,
    status: str | None = None,
    process_name: str | None = None,
    port: int | None = None,
) -> list[dict[str, Any]]:
    """Filter connection dictionaries by protocol, status, process and port.

    Missing keys, ``None`` input and ``ALL`` sentinel values are handled
    safely; a filter never raises on incomplete records.
    """
    if not connections:
        return []

    result = []
    for item in connections:
        if not isinstance(item, dict):
            continue
        if protocol and protocol.upper() != "ALL":
            if str(item.get("protocol", "")).upper() != protocol.upper():
                continue
        if status and status.upper() != "ALL":
            if str(item.get("status", "")).upper() != status.upper():
                continue
        if process_name and process_name.upper() != "ALL":
            if process_name.casefold() not in str(item.get("process_name", "")).casefold():
                continue
        if port is not None:
            if port not in (item.get("local_port"), item.get("remote_port")):
                continue
        result.append(item)
    return result
