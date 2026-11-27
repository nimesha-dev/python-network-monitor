from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader, PcapWriter, sniff
from scapy.packet import Packet

from network_monitor.config import PCAP_DIR, prepare_directories

TOP_TALKERS = 10
DEFAULT_BATCH_SIZE = 500


class PcapError(Exception):
    """Raised when a PCAP file cannot be read (empty, corrupt, invalid)."""


class _CaptureLimitReached(Exception):
    """Internal signal used to stop a capture once max_packets is hit."""


def _packet_timestamp(packet: Any) -> str:
    try:
        stamp = float(packet.time)
    except (AttributeError, TypeError, ValueError):
        stamp = time.time()
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def _safe_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _tcp_flags(packet: Any) -> str:
    try:
        flags = _safe_int(packet[TCP].flags, 0) or 0
    except (IndexError, TypeError, ValueError, KeyError):
        return ""
    names = ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
             (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C"))
    return "".join(char for bit, char in names if flags & bit)


def packet_to_row(packet: Any) -> dict[str, Any]:
    """Extract a lightweight, JSON-friendly metadata row from a packet.

    Raises ``ValueError`` when ``packet`` is not a Scapy packet. Missing or
    unreadable header fields degrade to ``None`` instead of raising.
    """
    if not isinstance(packet, Packet):
        raise ValueError("packet_to_row expects a Scapy packet")

    src_ip = dst_ip = None
    ip_version = None
    ttl = None

    try:
        if IP in packet:
            layer = packet[IP]
            src_ip, dst_ip = layer.src, layer.dst
            ip_version = 4
            ttl = _safe_int(layer.ttl)
        elif IPv6 in packet:
            layer = packet[IPv6]
            src_ip, dst_ip = layer.src, layer.dst
            ip_version = 6
            ttl = _safe_int(layer.hlim)
    except (IndexError, TypeError, ValueError, AttributeError):
        src_ip = dst_ip = None
        ip_version = None
        ttl = None

    protocol = "OTHER"
    src_port = dst_port = None
    tcp_syn = tcp_ack = False
    tcp_flags = ""

    try:
        if TCP in packet:
            protocol = "TCP"
            src_port = _safe_int(packet[TCP].sport)
            dst_port = _safe_int(packet[TCP].dport)
            flags = _safe_int(packet[TCP].flags, 0) or 0
            tcp_syn = bool(flags & 0x02)
            tcp_ack = bool(flags & 0x10)
            tcp_flags = _tcp_flags(packet)
        elif UDP in packet:
            protocol = "UDP"
            src_port = _safe_int(packet[UDP].sport)
            dst_port = _safe_int(packet[UDP].dport)
        elif ICMP in packet:
            protocol = "ICMP"
    except (IndexError, TypeError, ValueError, AttributeError):
        protocol = "OTHER"
        src_port = dst_port = None
        tcp_syn = tcp_ack = False
        tcp_flags = ""

    return {
        "timestamp": _packet_timestamp(packet),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": len(packet),
        "ip_version": ip_version,
        "ttl": ttl,
        "tcp_flags": tcp_flags,
        "tcp_syn": tcp_syn,
        "tcp_ack": tcp_ack,
    }


def capture_packets(interface: str | None, duration: int,
                    output_path: Path | None = None,
                    bpf_filter: str | None = None,
                    max_packets: int | None = None) -> tuple[list[dict[str, Any]], Path]:
    """Capture live packets to a PCAP file.

    Packets are streamed to disk as they arrive instead of being buffered in
    memory first; only lightweight metadata rows are kept for analysis.
    ``bpf_filter`` applies a capture filter (e.g. ``"tcp port 80"``) and
    ``max_packets`` caps the number of captured packets.
    """
    prepare_directories()
    if duration <= 0:
        raise ValueError("Capture duration must be greater than zero.")
    if max_packets is not None and max_packets <= 0:
        raise ValueError("max_packets must be greater than zero.")
    if bpf_filter is not None and not str(bpf_filter).strip():
        bpf_filter = None

    if output_path is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = PCAP_DIR / f"capture_{stamp}.pcap"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    writer = PcapWriter(str(output_path), sync=True)
    try:
        def handle(packet: Any) -> None:
            writer.write(packet)
            rows.append(packet_to_row(packet))
            if max_packets is not None and len(rows) >= max_packets:
                raise _CaptureLimitReached

        sniff_kwargs: dict[str, Any] = {
            "iface": interface or None,
            "timeout": duration,
            "store": False,
            "prn": handle,
        }
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter
        try:
            sniff(**sniff_kwargs)
        except _CaptureLimitReached:
            pass
    finally:
        writer.close()
    return rows, output_path


def _validate_pcap(path: Path) -> Path:
    path = Path(path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")
    if not path.is_file():
        raise PcapError(f"Not a file: {path}")
    if path.stat().st_size == 0:
        raise PcapError(f"PCAP file is empty: {path}")
    return path


def iter_pcap(path: Path, max_packets: int | None = None) -> Iterator[Any]:
    """Yield packets from a PCAP file one at a time (low memory usage).

    Raises ``FileNotFoundError`` for missing files and ``PcapError`` for
    empty, corrupt or unsupported files.
    """
    path = _validate_pcap(path)
    if max_packets is not None and max_packets <= 0:
        raise ValueError("max_packets must be greater than zero.")
    return _read_packets(path, max_packets)


def _read_packets(path: Path, max_packets: int | None) -> Iterator[Any]:
    try:
        reader = PcapReader(str(path))
    except Exception as error:
        raise PcapError(f"Cannot read PCAP file {path}: {error}") from error
    count = 0
    try:
        for packet in reader:
            yield packet
            count += 1
            if max_packets is not None and count >= max_packets:
                return
    except PcapError:
        raise
    except Exception as error:
        raise PcapError(
            f"PCAP file {path} is corrupt after {count} packets: {error}"
        ) from error
    finally:
        reader.close()


def _empty_summary() -> dict[str, Any]:
    return {
        "packet_count": 0,
        "total_bytes": 0,
        "protocol_counts": {},
        "protocol_bytes": {},
        "top_sources": [],
        "top_destinations": [],
        "top_destination_ports": [],
        "first_timestamp": None,
        "last_timestamp": None,
        "truncated": False,
    }


def _update_summary(summary: dict[str, Any], row: dict[str, Any]) -> None:
    protocol = row.get("protocol", "OTHER")
    length = int(row.get("length") or 0)
    summary["packet_count"] += 1
    summary["total_bytes"] += length
    summary["protocol_counts"][protocol] = summary["protocol_counts"].get(protocol, 0) + 1
    summary["protocol_bytes"][protocol] = summary["protocol_bytes"].get(protocol, 0) + length

    timestamp = row.get("timestamp")
    if timestamp:
        if summary["first_timestamp"] is None:
            summary["first_timestamp"] = timestamp
        summary["last_timestamp"] = timestamp


def _finalise_summary(summary: dict[str, Any],
                      sources: dict[str, int],
                      destinations: dict[str, int],
                      ports: dict[int, int]) -> dict[str, Any]:
    summary["top_sources"] = sorted(sources.items(), key=lambda x: x[1],
                                    reverse=True)[:TOP_TALKERS]
    summary["top_destinations"] = sorted(destinations.items(), key=lambda x: x[1],
                                         reverse=True)[:TOP_TALKERS]
    summary["top_destination_ports"] = sorted(ports.items(), key=lambda x: x[1],
                                              reverse=True)[:TOP_TALKERS]
    return summary


def analyse_pcap(path: Path, detector: Any = None,
                 max_packets: int | None = None,
                 keep_rows: bool = False,
                 batch_size: int = DEFAULT_BATCH_SIZE
                 ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Stream a PCAP file and return ``(summary, events, rows)``.

    Packets are read one at a time so large capture files do not need to fit
    in memory. When ``detector`` is provided, packets are fed to it in small
    batches and any triggered events are returned. ``rows`` is only populated
    when ``keep_rows`` is true.
    """
    if batch_size <= 0:
        raise ValueError("batch_size must be greater than zero.")

    summary = _empty_summary()
    events: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    sources: dict[str, int] = {}
    destinations: dict[str, int] = {}
    ports: dict[int, int] = {}
    batch: list[dict[str, Any]] = []
    truncated = False

    for packet in iter_pcap(path, max_packets=max_packets):
        row = packet_to_row(packet)
        _update_summary(summary, row)
        if row.get("src_ip"):
            sources[row["src_ip"]] = sources.get(row["src_ip"], 0) + 1
        if row.get("dst_ip"):
            destinations[row["dst_ip"]] = destinations.get(row["dst_ip"], 0) + 1
        if row.get("dst_port"):
            ports[row["dst_port"]] = ports.get(row["dst_port"], 0) + 1
        if keep_rows:
            rows.append(row)
        if detector is not None:
            batch.append(row)
            if len(batch) >= batch_size:
                events.extend(detector.inspect_packets(batch))
                batch.clear()

    if detector is not None and batch:
        events.extend(detector.inspect_packets(batch))

    if max_packets is not None and summary["packet_count"] >= max_packets:
        truncated = True
    summary["truncated"] = truncated
    return _finalise_summary(summary, sources, destinations, ports), events, rows
