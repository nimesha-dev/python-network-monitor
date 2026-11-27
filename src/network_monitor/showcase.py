"""One-command showcase of every implemented project feature.

Usage:

    python -m network_monitor.showcase

Runs a read-mostly guided tour through configuration, live network
collection, filtering, the detection engine, monitoring, PCAP analysis,
storage, investigation, exports and the automated test suite — without
needing elevated privileges.
"""

from __future__ import annotations

import io
import json
import platform
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from network_monitor.collector import collect_snapshot
from network_monitor.config import PROJECT_ROOT, PCAP_DIR, Settings, prepare_directories
from network_monitor.dashboard import (
    display_events,
    display_header,
    display_packet_summary,
    display_report,
    display_speeds,
)
from network_monitor.detector import SecurityDetector
from network_monitor.filters import filter_connections
from network_monitor.monitor import calculate_speeds
from network_monitor.packet_tools import PcapError, analyse_pcap
from network_monitor.storage import Storage

console = Console()

RULES = [
    ("Port scan (packet)", "TCP SYN packets to distinct destination ports",
     "port_scan_threshold", "detection_window_seconds"),
    ("Port scan (inbound)", "One remote IP targeting distinct local ports",
     "port_scan_threshold", "connection_window_seconds"),
    ("Port scan (outbound)", "One process targeting distinct remote ports",
     "port_scan_threshold", "connection_window_seconds"),
    ("Repeated SYN attempts", "Many SYN packets from one source",
     "repeated_attempt_threshold", "detection_window_seconds"),
    ("Repeated connections", "Many distinct connections from one remote IP",
     "repeated_attempt_threshold", "detection_window_seconds"),
    ("Possible DoS pattern", "High packet count or byte volume from one source",
     "dos_packet_threshold", "detection_window_seconds"),
    ("Suspicious destination port", "Traffic to a configured suspicious port",
     "suspicious_ports", None),
    ("Unexpected listener", "TCP service outside the allowlist",
     "allowed_listening_ports", None),
    ("Connection frequency", "Many simultaneous connections to one remote IP",
     "unusual_remote_connection_threshold", None),
    ("High bandwidth usage", "Interface rate above the configured threshold",
     "high_bandwidth_threshold_bps", None),
    ("Interface changes", "New, removed or state-changed interfaces",
     None, None),
]


def rule(n: int, title: str) -> None:
    console.print()
    console.rule(f"[bold cyan]{n}. {title}[/bold cyan]")


def threshold_text(settings: Settings, key: str | None, window: str | None) -> str:
    if key is None:
        return "baseline comparison"
    value = getattr(settings, key)
    if key == "suspicious_ports":
        value = ", ".join(str(p) for p in value)
    elif key == "allowed_listening_ports":
        value = f"allowlist: {', '.join(str(p) for p in value)}"
    elif key == "high_bandwidth_threshold_bps":
        value = f"{value:,} bytes/s"
    else:
        value = f"{value:,}"
    if window:
        seconds = getattr(settings, window)
        return f"{value} within {seconds}s"
    return str(value)


def section_project_summary() -> None:
    rule(1, "Project summary")
    display_header()
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("Project", "Python Network Monitor v1.0.0")
    info.add_row("Purpose", "Network visibility, packet analysis and "
                            "rule-based security detection")
    info.add_row("Platform", f"{platform.system()} {platform.release()} "
                             f"({platform.machine()})")
    info.add_row("Python", sys.version.split()[0])
    info.add_row("Stack", "psutil · Scapy · Rich · SQLite · unittest")
    info.add_row("Detection", "Transparent threshold rules — no machine learning")
    info.add_row("Showcase", "python -m network_monitor.showcase")
    console.print(Panel(info, title="ABOUT", border_style="cyan", expand=False))


def section_configuration(settings: Settings) -> None:
    rule(2, "Configuration (config/settings.json + config.py validation)")
    table = Table(title="ACTIVE SETTINGS", box=box.ROUNDED,
                  header_style="bold magenta")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    for key, value in sorted(settings.__dict__.items()):
        table.add_row(key, str(value))
    console.print(table)
    console.print("[dim]Invalid or missing values fall back to validated "
                  "defaults (see test_config.py).[/dim]")


def section_network_overview() -> dict:
    rule(3, "Live network overview (collector.py + dashboard.py)")
    snapshot = collect_snapshot()
    display_report(snapshot)
    return snapshot


def section_filtering(snapshot: dict) -> None:
    rule(4, "Connection filtering (filters.py)")
    tcp_established = filter_connections(snapshot["connections"],
                                         protocol="TCP", status="ESTABLISHED")
    table = Table(title=f"FILTER: TCP + ESTABLISHED ({len(tcp_established)})",
                  box=box.ROUNDED, header_style="bold magenta")
    for heading in ("Local", "Remote", "PID", "Process"):
        table.add_column(heading)
    for item in tcp_established[:12]:
        table.add_row(f'{item["local_ip"]}:{item["local_port"]}',
                      f'{item["remote_ip"]}:{item["remote_port"]}',
                      str(item["pid"] or "-"), item["process_name"])
    if not tcp_established:
        table.add_row("-", "-", "-", "No matching connections")
    console.print(table)
    console.print("[dim]Filters are pure functions: protocol, status, "
                  "process, port and combined conditions (test_filters.py).[/dim]")


def section_rules_catalog(settings: Settings) -> None:
    rule(5, "Detection rules catalogue (detector.py — all 11 rules)")
    table = Table(title="RULE-BASED DETECTION MECHANISMS", box=box.ROUNDED,
                  header_style="bold magenta")
    table.add_column("#", justify="right")
    table.add_column("Rule", style="cyan")
    table.add_column("What it detects")
    table.add_column("Threshold")
    for index, (name, detects, key, window) in enumerate(RULES, 1):
        table.add_row(str(index), name, detects,
                      threshold_text(settings, key, window))
    console.print(table)
    console.print("[dim]Every alert carries evidence: rule, observed values, "
                  "threshold and window (see section 7).[/dim]")


def section_detection_live(snapshot: dict) -> None:
    rule(6, "Detection engine on live data (this machine, right now)")
    detector = SecurityDetector(Settings.load())
    events: list[dict] = []
    events += detector.inspect_interfaces(snapshot["interfaces"])
    events += detector.inspect_connections(snapshot["connections"])
    events += detector.inspect_listeners(snapshot["listening_ports"])
    display_events(events)
    if not events:
        console.print("[dim]No rule currently matches this machine's state — "
                      "that is correct behaviour for a quiet network.[/dim]")


def section_example_alert() -> None:
    rule(7, "Example alert with full evidence (synthetic demonstration)")
    settings = Settings(port_scan_threshold=5, alert_cooldown_seconds=0,
                        dos_packet_threshold=1000, repeated_attempt_threshold=100)
    detector = SecurityDetector(settings)
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        {"timestamp": now, "src_ip": "203.0.113.7", "dst_ip": "192.0.2.20",
         "dst_port": port, "protocol": "TCP", "length": 60,
         "tcp_syn": True, "tcp_ack": False}
        for port in (21, 23, 25, 80, 443)
    ]
    events = detector.inspect_packets(rows)
    display_events(events)
    if events:
        evidence = json.dumps(events[0]["details"], indent=2)
        console.print(Panel(evidence, title="EVIDENCE / details",
                            border_style="yellow", expand=False))
    console.print("[dim]Synthetic addresses only (RFC 5737 documentation "
                  "range). An alert is an investigation lead, not proof of "
                  "an attack.[/dim]")


def section_monitoring(settings: Settings) -> None:
    rule(8, "Continuous monitoring & traffic rates (monitor.py)")
    console.print(f"[dim]Sampling interfaces for ~{settings.monitor_interval}s "
                  "to calculate real upload/download rates...[/dim]")
    first = collect_snapshot()
    time.sleep(max(1.0, float(settings.monitor_interval)))
    second = collect_snapshot()
    speeds = calculate_speeds(first, second,
                              max(0.001, settings.monitor_interval))
    console.print(display_speeds(speeds))
    console.print("[dim]Rates use actual elapsed time between samples, not "
                  "the configured interval. Monitoring history is stored in "
                  "SQLite (menu 8 in the main app).[/dim]")


def section_pcap_analysis(settings: Settings) -> None:
    rule(9, "Offline PCAP analysis (packet_tools.py)")
    captures = sorted(PCAP_DIR.glob("*.pcap"))
    if not captures:
        console.print("[yellow]No captures in pcaps/ yet.[/yellow] Record one "
                      "from the main app (menu 4) — live capture may need "
                      "elevated privileges — then re-run this showcase.")
        return
    target = captures[-1]
    console.print(f"[dim]Analysing {target} "
                  f"({target.stat().st_size:,} bytes), streamed packet by "
                  "packet...[/dim]")
    try:
        summary, events, _rows = analyse_pcap(
            target, detector=SecurityDetector(settings))
    except PcapError as error:
        console.print(f"[red]{error}[/red]")
        return
    display_packet_summary(summary)
    display_events(events)


def section_storage_investigation(storage: Storage) -> None:
    rule(10, "Event storage & investigation (storage.py + investigation menu)")
    events = storage.recent_events(8)
    categories = storage.event_categories()
    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="bold cyan")
    meta.add_column()
    meta.add_row("Database", str(storage.database_path))
    meta.add_row("Recent events shown", str(len(events)))
    meta.add_row("Categories present", ", ".join(categories) or "none yet")
    console.print(meta)
    if events:
        table = Table(title="RECENT SECURITY EVENTS", box=box.ROUNDED,
                      header_style="bold magenta")
        for heading in ("ID", "Severity", "Category", "Source", "Description"):
            table.add_column(heading)
        for event in events:
            severity = event["severity"]
            style = ("red" if severity == "HIGH"
                     else "yellow" if severity == "MEDIUM" else "cyan")
            table.add_row(str(event["id"]),
                          f"[{style}]{severity}[/{style}]",
                          event["category"],
                          event["source_ip"] or "-",
                          event["description"])
        console.print(table)
        console.print("[dim]Investigate further in the main app: search by "
                      "IP, filter by severity/category, view evidence JSON, "
                      "timeline (menu 7).[/dim]")
    else:
        console.print("[dim]Database is empty — start monitoring (menu 3) or "
                      "analyse a PCAP (menu 5) to generate events.[/dim]")


def section_export(storage: Storage) -> None:
    rule(11, "CSV / JSON export (storage.export_events)")
    events = storage.recent_events(1000)
    if not events:
        console.print("[dim]No events to export yet. After events exist, "
                      "export from menu 9 or investigation option 7.[/dim]")
        return
    json_path = storage.export_events("json")
    csv_path = storage.export_events("csv")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    table = Table(box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Format")
    table.add_column("File")
    table.add_column("Contents")
    table.add_row("JSON", str(json_path), f"{len(data)} events · "
                  f"{'valid JSON ✓' if isinstance(data, list) else 'invalid'}")
    table.add_row("CSV", str(csv_path), f"{len(events)} events · "
                  "header + rows")
    console.print(table)
    console.print("[dim]Generated files live in exports/ (gitignored).[/dim]")


def section_tests() -> None:
    rule(12, "Automated test suite (tests/)")
    console.print("[dim]Running unittest discovery...[/dim]")
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(PROJECT_ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=0, stream=stream).run(suite)
    total = result.testsRun
    skipped = len(result.skipped)
    failed = len(result.failures) + len(result.errors)
    passed = total - skipped - failed
    table = Table(box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Result", style="cyan")
    table.add_column("Count", justify="right")
    table.add_row("Total tests", str(total))
    table.add_row("Passed", f"[green]{passed}[/green]")
    table.add_row("Skipped", str(skipped))
    table.add_row("Failed", f"[red]{failed}[/red]" if failed
                  else f"[green]{failed}[/green]")
    console.print(table)
    console.print("[dim]Modules: test_config · test_detector · test_filters · "
                  "test_packet_tools · test_storage. The single skip is the "
                  "loopback capture test (needs capture privileges).[/dim]")


def section_next_steps() -> None:
    rule(13, "What was implemented — where to look next")
    table = Table(title="FEATURE INDEX", box=box.ROUNDED,
                  header_style="bold magenta")
    table.add_column("Feature", style="cyan")
    table.add_column("Module")
    table.add_column("Also see")
    rows = [
        ("Network overview & dashboard", "collector.py · dashboard.py",
         "README §5.1, screenshots"),
        ("Connection filtering", "filters.py", "README §5.2, test_filters"),
        ("Continuous monitoring & rates", "monitor.py", "README §5.3"),
        ("Rule-based detection (11 rules)", "detector.py",
         "README §12, test_detector"),
        ("Live capture & PCAP analysis", "packet_tools.py",
         "README §13, test_packet_tools"),
        ("SQLite storage & search", "storage.py", "README §14, test_storage"),
        ("Investigation & export", "main.py · storage.py",
         "README §14.3–14.4"),
        ("Validated configuration", "config.py", "README §17, test_config"),
        ("Documentation", "README · docs/",
         "architecture.md · demo.md"),
    ]
    for feature, module, see in rows:
        table.add_row(feature, module, see)
    console.print(table)
    console.print(Panel(
        "[bold]Run the full application:[/bold]\n"
        "    python -m network_monitor.main\n\n"
        "[bold]Live web dashboard (browser, auto-updating graphs):[/bold]\n"
        "    python -m network_monitor.web\n\n"
        "[bold]Regenerate README screenshots:[/bold]\n"
        "    python scripts/capture_screenshots.py\n\n"
        "[bold]This showcase:[/bold]\n"
        "    python -m network_monitor.showcase",
        title="NEXT STEPS", border_style="green", expand=False))


def main() -> None:
    prepare_directories()
    settings = Settings.load()
    storage = Storage()

    console.print()
    console.print(Panel(
        "[bold cyan]PYTHON NETWORK MONITOR — PROJECT SHOWCASE[/bold cyan]\n"
        "One command · every implemented feature · no elevated privileges "
        "required",
        border_style="cyan", padding=(1, 2), expand=False))

    section_project_summary()
    section_configuration(settings)
    snapshot = section_network_overview()
    section_filtering(snapshot)
    section_rules_catalog(settings)
    section_detection_live(snapshot)
    section_example_alert()
    section_monitoring(settings)
    section_pcap_analysis(settings)
    section_storage_investigation(storage)
    section_export(storage)
    section_tests()
    section_next_steps()

    console.print()
    console.print("[bold green]Showcase complete.[/bold green] "
                  "Start the interactive app with: "
                  "[bold]python -m network_monitor.main[/bold]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Showcase stopped by user.[/yellow]")
        sys.exit(0)
    except Exception as error:
        console.print(f"[red]Showcase error: {error}[/red]")
        sys.exit(1)
