from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

import psutil


def _process_name(pid: int | None, cache: dict[int, str]) -> str:
    if pid is None:
        return "Unknown"
    if pid in cache:
        return cache[pid]
    try:
        name = psutil.Process(pid).name()
    except psutil.ZombieProcess:
        name = "Zombie Process"
    except psutil.NoSuchProcess:
        name = "Process Not Found"
    except psutil.AccessDenied:
        name = "Access Denied"
    cache[pid] = name
    return name


def format_bytes(value: float) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024:
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{amount:.2f} PB"


def identify_interface_type(name: str) -> str:
    if name == "lo":
        return "Loopback"
    if name.startswith(("wl", "wifi")):
        return "Wi-Fi"
    if name.startswith(("en", "eth")):
        return "Ethernet"
    if name.startswith(("br-", "virbr", "docker", "veth")):
        return "Virtual"
    if name.startswith(("tun", "tap", "wg")):
        return "VPN / Tunnel"
    return "Other"


def get_interfaces() -> list[dict[str, Any]]:
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    result = []
    for name in sorted(addresses):
        state = stats.get(name)
        ipv4, ipv6 = [], []
        for address in addresses[name]:
            if address.family == socket.AF_INET:
                ipv4.append(address.address)
            elif address.family == socket.AF_INET6:
                ipv6.append(address.address.split("%")[0])
        result.append({
            "name": name,
            "type": identify_interface_type(name),
            "status": "UP" if state and state.isup else "DOWN",
            "speed_mbps": state.speed if state else 0,
            "mtu": state.mtu if state else 0,
            "ipv4": ipv4,
            "ipv6": ipv6,
        })
    return result


def get_network_statistics() -> list[dict[str, Any]]:
    counters = psutil.net_io_counters(pernic=True) or {}
    result = []
    for name, item in sorted(counters.items()):
        result.append({
            "name": name,
            "bytes_sent": item.bytes_sent,
            "bytes_recv": item.bytes_recv,
            "packets_sent": item.packets_sent,
            "packets_recv": item.packets_recv,
            "errors_in": item.errin,
            "errors_out": item.errout,
            "drops_in": item.dropin,
            "drops_out": item.dropout,
        })
    return result


def get_connections() -> list[dict[str, Any]]:
    try:
        raw_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        raw_connections = []

    cache: dict[int, str] = {}
    result = []
    seen: set[tuple] = set()
    for item in raw_connections:
        if item.type == socket.SOCK_STREAM:
            protocol = "TCP"
        elif item.type == socket.SOCK_DGRAM:
            protocol = "UDP"
        else:
            protocol = "OTHER"

        local_ip = item.laddr.ip if item.laddr else "N/A"
        local_port = item.laddr.port if item.laddr else 0
        remote_ip = item.raddr.ip if item.raddr else "N/A"
        remote_port = item.raddr.port if item.raddr else 0
        status = item.status or "NONE"
        key = (protocol, local_ip, local_port, remote_ip, remote_port,
               status, item.pid)
        if key in seen:
            continue
        seen.add(key)
        result.append({
            "protocol": protocol,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": status,
            "pid": item.pid,
            "process_name": _process_name(item.pid, cache),
        })
    return result


def get_listening_ports(
    connections: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if connections is None:
        connections = get_connections()
    return [
        {
            "protocol": "TCP",
            "local_ip": item["local_ip"],
            "port": item["local_port"],
            "status": item["status"],
            "pid": item["pid"],
            "process_name": item["process_name"],
        }
        for item in connections
        if item["protocol"] == "TCP" and item["status"] == "LISTEN"
    ]


def get_udp_endpoints(
    connections: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if connections is None:
        connections = get_connections()
    return [
        {
            "protocol": "UDP",
            "local_ip": item["local_ip"],
            "port": item["local_port"],
            "pid": item["pid"],
            "process_name": item["process_name"],
        }
        for item in connections
        if item["protocol"] == "UDP"
    ]


def collect_snapshot() -> dict[str, Any]:
    connections = get_connections()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "interfaces": get_interfaces(),
        "statistics": get_network_statistics(),
        "connections": connections,
        "listening_ports": get_listening_ports(connections),
        "udp_endpoints": get_udp_endpoints(connections),
    }


def get_ip_information() -> list[dict[str, str]]:
    return [
        {
            "name": item["name"],
            "ipv4": ", ".join(item["ipv4"]) or "Not assigned",
            "ipv6": ", ".join(item["ipv6"]) or "Not assigned",
        }
        for item in get_interfaces()
    ]
