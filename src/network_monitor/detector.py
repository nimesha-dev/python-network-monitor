from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from network_monitor.config import Settings

SAMPLE_LIMIT = 10
ALERT_CACHE_LIMIT = 2048


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class SecurityDetector:
    """Transparent threshold/rule-based detection; not ML.

    Alerts indicate suspicious patterns worth investigating; they do not
    confirm that an attack occurred. Every alert carries evidence (observed
    values, thresholds, windows and sample data) in its ``details`` field.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        # Per-source packet history: (time, dst_port, length, protocol, is_syn)
        self.packet_windows: dict[str, deque[tuple]] = defaultdict(deque)
        # Time-stamped connection observations for connection-based rules.
        self.connection_history: deque[tuple[float, dict[str, Any]]] = deque()
        self.connection_seen: set[tuple] = set()
        self.listening_seen: set[tuple] = set()
        self.interface_state: dict[str, str] | None = None
        self.high_bandwidth_alerted: set[str] = set()
        # Cooldown bookkeeping: alert key -> monotonic time of last alert.
        self._last_alert: dict[tuple, float] = {}

    # ------------------------------------------------------------------ #
    # Shared helpers
    # ------------------------------------------------------------------ #
    def _event(self, severity: str, category: str, description: str,
               source_ip: str | None = None,
               destination_ip: str | None = None,
               details: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "timestamp": _now().isoformat(),
            "severity": severity,
            "category": category,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "description": description,
            "details": details or {},
        }

    def _should_alert(self, key: tuple) -> bool:
        """Rate-limit alerts per key using the configured cooldown."""
        cooldown = max(0, int(self.settings.alert_cooldown_seconds))
        now = time.monotonic()
        if len(self._last_alert) > ALERT_CACHE_LIMIT:
            self._last_alert = {
                k: t for k, t in self._last_alert.items()
                if now - t <= max(cooldown, 60)
            }
        last = self._last_alert.get(key)
        if last is not None and (now - last) < cooldown:
            return False
        self._last_alert[key] = now
        return True

    def _emit(self, events: list[dict[str, Any]], batch: set[tuple],
              key: tuple, event: dict[str, Any]) -> None:
        """Append an event once per batch and once per cooldown window."""
        if key in batch:
            return
        if not self._should_alert(key):
            return
        batch.add(key)
        events.append(event)

    @staticmethod
    def _sample(values: set[int] | list[int], limit: int = SAMPLE_LIMIT) -> list[int]:
        return sorted(values)[:limit]

    # ------------------------------------------------------------------ #
    # Interface rules
    # ------------------------------------------------------------------ #
    def inspect_interfaces(self, interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Report interfaces that appear or change operational state after the baseline."""
        current = {item["name"]: item["status"] for item in interfaces}
        if self.interface_state is None:
            self.interface_state = current
            return []

        events: list[dict[str, Any]] = []
        batch: set[tuple] = set()
        for name, status in current.items():
            previous = self.interface_state.get(name)
            if previous is None:
                self._emit(events, batch, ("interface_new", name), self._event(
                    "INFO", "New Network Interface",
                    f"Network interface {name} appeared with status {status}.",
                    details={
                        "rule": "new_interface",
                        "interface": name,
                        "status": status,
                        "threshold": None,
                        "observed": {"status": status},
                    },
                ))
            elif previous != status:
                severity = "MEDIUM" if status == "UP" else "INFO"
                self._emit(events, batch, ("interface_state", name), self._event(
                    severity, "Interface State Change",
                    f"Network interface {name} changed from {previous} to {status}.",
                    details={
                        "rule": "interface_state_change",
                        "interface": name,
                        "threshold": None,
                        "observed": {"previous_status": previous,
                                     "current_status": status},
                    },
                ))
        for name in self.interface_state:
            if name not in current:
                self._emit(events, batch, ("interface_gone", name), self._event(
                    "INFO", "Network Interface Removed",
                    f"Network interface {name} is no longer present.",
                    details={"rule": "interface_removed", "interface": name,
                             "observed": {"status": "absent"}},
                ))
        self.interface_state = current
        return events

    # ------------------------------------------------------------------ #
    # Bandwidth rule
    # ------------------------------------------------------------------ #
    def inspect_speeds(self, speeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Flag per-sample interface rates above a configurable threshold."""
        events = []
        threshold = self.settings.high_bandwidth_threshold_bps
        for item in speeds:
            name = item["name"]
            total_rate = item["upload_bps"] + item["download_bps"]
            if total_rate >= threshold:
                if name not in self.high_bandwidth_alerted:
                    events.append(self._event(
                        "MEDIUM", "High Bandwidth Usage",
                        f"Interface {name} reached {total_rate:,.0f} bytes/second "
                        f"(configured threshold: {threshold:,}).",
                        details={
                            "rule": "high_bandwidth",
                            "interface": name,
                            "threshold": threshold,
                            "observed": {
                                "upload_bytes_per_second": round(item["upload_bps"], 2),
                                "download_bytes_per_second": round(item["download_bps"], 2),
                                "total_bytes_per_second": round(total_rate, 2),
                            },
                        },
                    ))
                    self.high_bandwidth_alerted.add(name)
            else:
                self.high_bandwidth_alerted.discard(name)
        return events

    # ------------------------------------------------------------------ #
    # Connection rules
    # ------------------------------------------------------------------ #
    def inspect_connections(
        self,
        connections: list[dict[str, Any]],
        timestamp: float | None = None,
    ) -> list[dict[str, Any]]:
        connections = connections or []
        events: list[dict[str, Any]] = []
        batch: set[tuple] = set()
        ts = float(timestamp) if timestamp is not None else _now().timestamp()
        scan_window = max(1, int(self.settings.connection_window_seconds))
        attempt_window = max(1, int(self.settings.detection_window_seconds))
        scan_threshold = self.settings.port_scan_threshold
        attempt_threshold = self.settings.repeated_attempt_threshold

        for item in connections:
            self.connection_history.append((ts, item))
        while self.connection_history and ts - self.connection_history[0][0] > scan_window:
            self.connection_history.popleft()

        current: set[tuple] = set()
        remote_counts: dict[str, int] = defaultdict(int)
        inbound_ports: dict[str, set[int]] = defaultdict(set)
        outbound_ports: dict[Any, set[int]] = defaultdict(set)
        outbound_owner: dict[Any, str] = {}
        recent_attempts: dict[str, set[tuple]] = defaultdict(set)
        suspicious_seen: set[tuple] = set()

        for item in connections:
            remote_ip = item["remote_ip"]
            has_remote = remote_ip not in ("N/A", "", None)
            key = (
                item["protocol"], item["local_ip"], item["local_port"],
                remote_ip, item["remote_port"], item["pid"],
            )
            current.add(key)
            if has_remote:
                remote_counts[remote_ip] += 1
            if key not in self.connection_seen and item["status"] == "ESTABLISHED":
                self._emit(events, batch, ("new_connection", key), self._event(
                    "INFO", "New Connection",
                    f"New established {item['protocol']} connection to "
                    f"{remote_ip}:{item['remote_port']} "
                    f"({item['process_name']}).",
                    item["local_ip"], remote_ip if has_remote else None,
                    details={
                        "rule": "new_connection",
                        "protocol": item["protocol"],
                        "local_endpoint": f"{item['local_ip']}:{item['local_port']}",
                        "remote_endpoint": f"{remote_ip}:{item['remote_port']}",
                        "process": item["process_name"],
                        "pid": item["pid"],
                        "observed": {"status": item["status"]},
                    },
                ))
            remote_port = _as_int(item.get("remote_port"))
            if (remote_port in self.settings.suspicious_ports
                    and item["status"] != "LISTEN" and has_remote
                    and remote_port > 0):
                suspicious_seen.add((remote_port, item["pid"]))

        # ---- history-derived rules (port scan / repeated attempts) ---- #
        for hts, item in self.connection_history:
            remote_ip = item["remote_ip"]
            has_remote = remote_ip not in ("N/A", "", None)
            local_port = _as_int(item.get("local_port"))
            remote_port = _as_int(item.get("remote_port"))
            if has_remote and local_port > 0:
                inbound_ports[remote_ip].add(local_port)
            if remote_port > 0 and item.get("status") != "LISTEN":
                owner = item.get("pid") or item.get("process_name") or "unknown"
                outbound_ports[owner].add(remote_port)
                outbound_owner[owner] = item.get("process_name") or str(owner)
            if has_remote and hts >= ts - attempt_window:
                recent_attempts[remote_ip].add(
                    (local_port, remote_port, item.get("pid"))
                )

        alerted_remotes: set[str] = set()
        for remote_ip, ports in inbound_ports.items():
            if len(ports) >= scan_threshold:
                key = ("inbound_port_scan", remote_ip)
                if key in batch or not self._should_alert(key):
                    alerted_remotes.add(remote_ip)
                    continue
                batch.add(key)
                alerted_remotes.add(remote_ip)
                events.append(self._event(
                    "HIGH", "Possible Port Scan",
                    f"Source {remote_ip} targeted {len(ports)} distinct local "
                    f"ports within {scan_window} seconds "
                    f"(threshold: {scan_threshold}).",
                    source_ip=remote_ip,
                    details={
                        "rule": "inbound_port_scan",
                        "variant": "connection-based inbound",
                        "threshold": scan_threshold,
                        "window_seconds": scan_window,
                        "observed": {"distinct_local_ports": len(ports)},
                        "sample_local_ports": self._sample(ports),
                    },
                ))

        for owner, ports in outbound_ports.items():
            if len(ports) >= scan_threshold:
                key = ("outbound_port_scan", owner)
                self._emit(events, batch, key, self._event(
                    "HIGH", "Possible Port Scan",
                    f"Process {outbound_owner.get(owner, owner)} targeted "
                    f"{len(ports)} distinct remote ports within {scan_window} "
                    f"seconds (threshold: {scan_threshold}).",
                    details={
                        "rule": "outbound_port_scan",
                        "variant": "connection-based outbound",
                        "process": outbound_owner.get(owner, str(owner)),
                        "pid": owner if isinstance(owner, int) else None,
                        "threshold": scan_threshold,
                        "window_seconds": scan_window,
                        "observed": {"distinct_remote_ports": len(ports)},
                        "sample_remote_ports": self._sample(ports),
                    },
                ))

        for remote_ip, attempts in recent_attempts.items():
            if remote_ip in alerted_remotes:
                continue
            if len(attempts) >= attempt_threshold:
                self._emit(events, batch, ("repeated_connection", remote_ip),
                           self._event(
                    "MEDIUM", "Repeated Connection Attempts",
                    f"Remote {remote_ip} opened {len(attempts)} distinct "
                    f"connections within {attempt_window} seconds "
                    f"(threshold: {attempt_threshold}).",
                    destination_ip=remote_ip,
                    details={
                        "rule": "repeated_connection_attempts",
                        "threshold": attempt_threshold,
                        "window_seconds": attempt_window,
                        "observed": {"distinct_connections": len(attempts)},
                        "sample_local_ports": self._sample(
                            {a[0] for a in attempts}
                        ),
                    },
                ))

        for remote_ip, count in remote_counts.items():
            threshold = self.settings.unusual_remote_connection_threshold
            if count >= threshold:
                self._emit(events, batch, ("remote_frequency", remote_ip),
                           self._event(
                    "MEDIUM", "Connection Frequency",
                    f"{count} simultaneous connections were observed to remote "
                    f"IP {remote_ip} (threshold: {threshold}).",
                    destination_ip=remote_ip,
                    details={
                        "rule": "connection_frequency",
                        "threshold": threshold,
                        "observed": {"simultaneous_connections": count},
                    },
                ))

        for remote_port, pid in sorted(suspicious_seen):
            self._emit(events, batch, ("suspicious_connection", remote_port, pid),
                       self._event(
                "MEDIUM", "Suspicious Outbound Connection",
                f"Outbound connection to configured suspicious port "
                f"{remote_port} was observed.",
                destination_ip=None,
                details={
                    "rule": "suspicious_outbound_connection",
                    "threshold": None,
                    "observed": {"remote_port": remote_port, "pid": pid},
                },
            ))

        self.connection_seen = current
        return events

    # ------------------------------------------------------------------ #
    # Listener rule
    # ------------------------------------------------------------------ #
    def inspect_listeners(self, listening_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        batch: set[tuple] = set()
        current = set()
        allowed = set(self.settings.allowed_listening_ports)
        listening_ports = listening_ports or []
        for item in listening_ports:
            key = (item["local_ip"], item["port"], item.get("pid"))
            current.add(key)
            if key not in self.listening_seen and item["port"] not in allowed:
                suspicious = item["port"] in self.settings.suspicious_ports
                severity = "HIGH" if suspicious else "MEDIUM"
                self._emit(events, batch, ("listener", item["local_ip"], item["port"]),
                           self._event(
                    severity, "Unexpected Listening Port",
                    f"TCP port {item['port']} on {item['local_ip']} is not in "
                    f"the configured allowlist"
                    + (" and is a configured suspicious port" if suspicious else "")
                    + f" (process: {item['process_name']}).",
                    details={
                        "rule": "unexpected_listener",
                        "threshold": None,
                        "observed": {
                            "ip": item["local_ip"],
                            "port": item["port"],
                            "process": item["process_name"],
                            "pid": item["pid"],
                            "suspicious_port": suspicious,
                            "allowed_ports": sorted(allowed),
                        },
                    },
                ))
        self.listening_seen = current
        return events

    # ------------------------------------------------------------------ #
    # Packet rules
    # ------------------------------------------------------------------ #
    def inspect_packets(self, packet_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        batch: set[tuple] = set()
        window = max(1, int(self.settings.detection_window_seconds))
        scan_threshold = self.settings.port_scan_threshold
        attempt_threshold = self.settings.repeated_attempt_threshold
        dos_packets = self.settings.dos_packet_threshold
        dos_bytes = self.settings.dos_byte_threshold

        for packet in packet_rows or []:
            source = packet.get("src_ip") or "unknown"
            destination = packet.get("dst_ip") or "unknown"
            destination_port = packet.get("dst_port")
            protocol = packet.get("protocol", "OTHER")
            is_syn = bool(packet.get("tcp_syn")) and not bool(packet.get("tcp_ack"))
            length = _as_int(packet.get("length"))

            try:
                packet_time = datetime.fromisoformat(
                    str(packet["timestamp"]).replace("Z", "+00:00")
                ).timestamp()
            except (KeyError, TypeError, ValueError):
                packet_time = _now().timestamp()

            bucket = self.packet_windows[source]
            bucket.append((packet_time, _as_int(destination_port),
                           length, protocol, is_syn))
            while bucket and packet_time - bucket[0][0] > window:
                bucket.popleft()

            syn_ports = {e[1] for e in bucket if e[4] and e[1]}
            syn_count = sum(1 for e in bucket if e[4])
            byte_count = sum(e[2] for e in bucket)

            if is_syn and len(syn_ports) >= scan_threshold:
                self._emit(events, batch, ("packet_port_scan", source), self._event(
                    "HIGH", "Possible Port Scan",
                    f"Source {source} sent TCP SYN packets to {len(syn_ports)} "
                    f"distinct destination ports within {window} seconds "
                    f"(threshold: {scan_threshold}).",
                    source, destination,
                    details={
                        "rule": "packet_port_scan",
                        "variant": "packet-based",
                        "threshold": scan_threshold,
                        "window_seconds": window,
                        "observed": {"distinct_destination_ports": len(syn_ports)},
                        "sample_destination_ports": self._sample(syn_ports),
                    },
                ))

            if is_syn and syn_count >= attempt_threshold:
                self._emit(events, batch, ("packet_repeated_syn", source),
                           self._event(
                    "MEDIUM", "Repeated SYN Attempts",
                    f"Source {source} sent {syn_count} TCP SYN packets within "
                    f"{window} seconds (threshold: {attempt_threshold}).",
                    source, destination,
                    details={
                        "rule": "repeated_syn_attempts",
                        "threshold": attempt_threshold,
                        "window_seconds": window,
                        "observed": {"syn_packets": syn_count},
                    },
                ))

            if len(bucket) >= dos_packets or byte_count >= dos_bytes:
                self._emit(events, batch, ("packet_dos", source), self._event(
                    "HIGH", "Possible DoS Pattern",
                    f"Source {source} sent {len(bucket)} packets "
                    f"({byte_count:,} bytes) within {window} seconds "
                    f"(thresholds: {dos_packets} packets / {dos_bytes:,} bytes).",
                    source, destination,
                    details={
                        "rule": "possible_dos",
                        "threshold": {"packets": dos_packets, "bytes": dos_bytes},
                        "window_seconds": window,
                        "observed": {"packets": len(bucket), "bytes": byte_count},
                    },
                ))

            if destination_port in self.settings.suspicious_ports:
                self._emit(events, batch,
                           ("suspicious_port", source, destination_port),
                           self._event(
                    "MEDIUM", "Suspicious Destination Port",
                    f"Traffic from {source} to {destination} used configured "
                    f"suspicious port {destination_port} ({protocol}).",
                    source, destination,
                    details={
                        "rule": "suspicious_destination_port",
                        "threshold": None,
                        "observed": {
                            "destination_port": destination_port,
                            "protocol": protocol,
                            "length": length,
                        },
                    },
                ))

        return events
