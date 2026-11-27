#!/usr/bin/env python3
"""Capture SVG screenshots of the terminal UI for the README.

Each screen is rendered by the application's own display functions using a
rich recording console, so the screenshots show the real interface.

Usage:  python scripts/capture_screenshots.py
"""

from __future__ import annotations

import io
import logging
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from scapy.all import Ether, IP, TCP, UDP, wrpcap  # noqa: E402

from network_monitor import dashboard  # noqa: E402
from network_monitor import main as app  # noqa: E402
from network_monitor import storage as storage_module  # noqa: E402
from network_monitor.config import Settings  # noqa: E402
from network_monitor.detector import SecurityDetector  # noqa: E402
from network_monitor.filters import filter_connections  # noqa: E402
from network_monitor.monitor import calculate_speeds  # noqa: E402
from network_monitor.packet_tools import iter_pcap, packet_to_row  # noqa: E402
from network_monitor.storage import Storage  # noqa: E402

SCREEN_DIR = PROJECT_ROOT / "screenshots"
WIDTH = 110

logging.getLogger("scapy").setLevel(logging.ERROR)


def _conn(protocol, local_ip, local_port, remote_ip, remote_port,
          status, pid, process):
    return {"protocol": protocol, "local_ip": local_ip,
            "local_port": local_port, "remote_ip": remote_ip,
            "remote_port": remote_port, "status": status, "pid": pid,
            "process_name": process}


def demo_snapshot(sent_delta: int = 0, recv_delta: int = 0) -> dict:
    """Synthetic snapshot using documentation IP ranges only.

    Screenshots must never expose the real machine's network activity, so
    every screen renders from this fixture instead of live psutil data.
    RFC 5737/3849 addresses (192.0.2.x, 198.51.100.x, 203.0.113.x, fd00::/8)
    are reserved for documentation.
    """
    connections = [
        _conn("TCP", "192.0.2.10", 51234, "203.0.113.25", 443,
              "ESTABLISHED", 4242, "firefox"),
        _conn("TCP", "192.0.2.10", 51235, "198.51.100.7", 443,
              "ESTABLISHED", 4242, "firefox"),
        _conn("TCP", "192.0.2.10", 51236, "203.0.113.80", 22,
              "ESTABLISHED", 1101, "ssh"),
        _conn("TCP", "192.0.2.10", 51237, "198.51.100.40", 443,
              "ESTABLISHED", 2202, "python3"),
        _conn("UDP", "192.0.2.10", 5353, "N/A", 0, "NONE", 888,
              "avahi-daemon"),
        _conn("UDP", "192.0.2.10", 46135, "N/A", 0, "NONE", 2202,
              "python3"),
        _conn("TCP", "0.0.0.0", 22, "N/A", 0, "LISTEN", 700, "sshd"),
        _conn("TCP", "127.0.0.1", 5432, "N/A", 0, "LISTEN", 950,
              "postgres"),
        _conn("TCP", "127.0.0.1", 631, "N/A", 0, "LISTEN", 600, "cupsd"),
        _conn("TCP", "192.0.2.10", 445, "N/A", 0, "LISTEN", 901,
              "smbd"),
    ]
    return {
        "timestamp": "2026-01-15T10:30:00+00:00",
        "interfaces": [
            {"name": "lo", "type": "Loopback", "status": "UP",
             "speed_mbps": 0, "mtu": 65536,
             "ipv4": ["127.0.0.1"], "ipv6": ["::1"]},
            {"name": "eth0", "type": "Ethernet", "status": "UP",
             "speed_mbps": 1000, "mtu": 1500,
             "ipv4": ["192.0.2.10"], "ipv6": []},
            {"name": "wlan0", "type": "Wi-Fi", "status": "UP",
             "speed_mbps": 144, "mtu": 1500,
             "ipv4": ["192.0.2.11"], "ipv6": ["fd00::11"]},
            {"name": "docker0", "type": "Virtual", "status": "DOWN",
             "speed_mbps": 0, "mtu": 1500,
             "ipv4": ["172.17.0.1"], "ipv6": []},
        ],
        "statistics": [
            {"name": "lo", "bytes_sent": 204800, "bytes_recv": 204800,
             "packets_sent": 1500, "packets_recv": 1500,
             "errors_in": 0, "errors_out": 0, "drops_in": 0, "drops_out": 0},
            {"name": "eth0", "bytes_sent": 15728640 + sent_delta,
             "bytes_recv": 22020096 + recv_delta,
             "packets_sent": 24400, "packets_recv": 30100,
             "errors_in": 0, "errors_out": 0, "drops_in": 0, "drops_out": 0},
            {"name": "wlan0", "bytes_sent": 5242880,
             "bytes_recv": 9437184, "packets_sent": 8200,
             "packets_recv": 11400,
             "errors_in": 0, "errors_out": 0, "drops_in": 2, "drops_out": 0},
        ],
        "connections": connections,
        "listening_ports": [
            {"protocol": "TCP", "local_ip": item["local_ip"],
             "port": item["local_port"], "status": item["status"],
             "pid": item["pid"], "process_name": item["process_name"]}
            for item in connections
            if item["protocol"] == "TCP" and item["status"] == "LISTEN"
        ],
        "udp_endpoints": [
            {"protocol": "UDP", "local_ip": item["local_ip"],
             "port": item["local_port"], "pid": item["pid"],
             "process_name": item["process_name"]}
            for item in connections if item["protocol"] == "UDP"
        ],
    }


@contextmanager
def screen(name: str, answers: tuple[str, ...] = ()):
    """Render a screen into a recording console and export it as SVG."""
    from rich.console import Console

    console = Console(record=True, width=WIDTH, force_terminal=True,
                      color_system="truecolor", file=io.StringIO())
    remaining = iter(answers)

    def fake_input(prompt="", **kwargs):
        console.print(str(prompt), end="")
        try:
            return next(remaining)
        except StopIteration:
            raise KeyboardInterrupt from None

    console.input = fake_input  # type: ignore[method-assign]

    old_app, old_dash = app.console, dashboard.console
    app.console = console
    dashboard.console = console
    try:
        yield console
    finally:
        app.console = old_app
        dashboard.console = old_dash
        SCREEN_DIR.mkdir(parents=True, exist_ok=True)
        path = SCREEN_DIR / f"{name}.svg"
        svg = console.export_svg(title=f"network-monitor: {name}")
        path.write_text(svg, encoding="utf-8")
        print(f"  captured {path.relative_to(PROJECT_ROOT)}")


def seeded_storage(tmp: Path) -> Storage:
    """Create a storage instance populated with genuine detector output."""
    storage = Storage(tmp / "screenshots.db")
    settings = Settings(
        port_scan_threshold=5, repeated_attempt_threshold=4,
        dos_packet_threshold=100, alert_cooldown_seconds=0,
    )
    detector = SecurityDetector(settings)

    events = []
    events += detector.inspect_connections(
        [{"protocol": "TCP", "local_ip": "192.0.2.20", "local_port": 445,
          "remote_ip": "203.0.113.7", "remote_port": 49321,
          "status": "SYN_SENT", "pid": 4242, "process_name": "python3"}],
        timestamp=time.time(),
    )
    events += detector.inspect_listeners(
        [{"local_ip": "0.0.0.0", "port": 31337, "pid": 9001,
          "process_name": "backdoor"}]
    )
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    scan_rows = [
        {"timestamp": now, "src_ip": "203.0.113.7", "dst_ip": "192.0.2.20",
         "dst_port": port, "protocol": "TCP", "length": 60,
         "tcp_syn": True, "tcp_ack": False}
        for port in (21, 23, 25, 80, 443, 4444, 3389)
    ]
    events += detector.inspect_packets(scan_rows)
    for event in events:
        storage.save_event(event)
    return storage


def demo_pcap(tmp: Path) -> Path:
    """Build a small demo capture used by the capture/analysis screens."""
    path = tmp / "demo_capture.pcap"
    packets = [
        Ether() / IP(src="192.0.2.20", dst="193.182.14.51") / TCP(sport=51000, dport=443, flags="PA"),
        Ether() / IP(src="193.182.14.51", dst="192.0.2.20") / TCP(sport=443, dport=51000, flags="A"),
        Ether() / IP(src="192.0.2.20", dst="192.0.2.1") / UDP(sport=5353, dport=5353),
        Ether() / IP(src="203.0.113.7", dst="192.0.2.20") / TCP(sport=49321, dport=445, flags="S"),
        Ether() / IP(src="192.0.2.20", dst="8.8.8.8") / TCP(sport=51100, dport=53, flags="S"),
        Ether() / IP(src="8.8.8.8", dst="192.0.2.20") / TCP(sport=53, dport=51100, flags="SA"),
    ]
    for index in range(12):
        packets.append(
            Ether() / IP(src="192.0.2.20", dst="193.182.14.51")
            / TCP(sport=52000 + index, dport=443, flags="PA")
        )
    wrpcap(str(path), packets)
    return path


def capture_rows(path: Path) -> list[dict]:
    return [packet_to_row(packet) for packet in iter_pcap(path)]


def main() -> None:
    settings = Settings.load()
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        storage = seeded_storage(tmp)
        pcap_path = demo_pcap(tmp)
        snapshot = demo_snapshot()
        # packet_capture_menu calls collect_snapshot() for its interface
        # list — patch it so no real interface names leak into the screen.
        original_collect = app.collect_snapshot
        app.collect_snapshot = demo_snapshot  # type: ignore[assignment]
        # Render prompts/paths as repository-relative so screenshots never
        # expose the local home directory.
        original_pcap_dir = app.PCAP_DIR
        app.PCAP_DIR = Path("pcaps")
        original_export_dir = storage_module.EXPORT_DIR
        storage_module.EXPORT_DIR = Path("exports")

        print("Capturing screenshots...")
        original_capture = app.capture_packets

        def fake_capture(interface, duration, output_path=None,
                         bpf_filter=None, max_packets=None):
            rows = capture_rows(pcap_path)
            if max_packets:
                rows = rows[:max_packets]
            # Display a repository-relative path instead of the temp file.
            return rows, Path("pcaps/demo_capture.pcap")

        try:
            with screen("main_menu"):
                dashboard.display_header()
                app.display_main_menu()

            with screen("network_overview"):
                dashboard.display_report(snapshot)

            with screen("active_connections"):
                established = filter_connections(snapshot["connections"],
                                                status="ESTABLISHED")
                app.show_connections(established)

            first = demo_snapshot()
            time.sleep(1.0)
            second = demo_snapshot(sent_delta=2_000_000, recv_delta=3_500_000)
            speeds = calculate_speeds(first, second, 1.0)
            live_events = storage.recent_events(4)
            with screen("live_monitoring"):
                app.render_live(second, speeds, live_events)

            with screen("security_alerts"):
                app.show_events(storage)

            # Packet capture screen: show the real menu prompts, then feed
            # rows from the demo capture so the summary output is genuine.
            app.capture_packets = fake_capture  # type: ignore[assignment]
            with screen("packet_capture",
                        answers=("", "10", "tcp or udp", "50")):
                app.packet_capture_menu(settings, storage)

            with screen("pcap_analysis", answers=(str(pcap_path), "")):
                app.pcap_analysis_menu(settings, storage)

            for _ in range(3):
                storage.save_snapshot(demo_snapshot())
            with screen("event_history"):
                app.show_history(storage)

            with screen("filtering",
                        answers=("6", "TCP", "ESTABLISHED", "", "", "0")):
                app.filter_menu(snapshot)

            with screen("export_results", answers=("csv",)):
                app.export_events_menu(storage)
        finally:
            app.capture_packets = original_capture
            app.collect_snapshot = original_collect
            app.PCAP_DIR = original_pcap_dir
            storage_module.EXPORT_DIR = original_export_dir

    print("Done.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
