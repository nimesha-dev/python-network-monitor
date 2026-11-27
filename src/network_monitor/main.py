from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from network_monitor.collector import collect_snapshot
from network_monitor.config import Settings, prepare_directories, PCAP_DIR
from network_monitor.dashboard import (
    display_header, display_report, display_speeds, display_events,
    display_packet_summary,
)
from network_monitor.detector import SecurityDetector
from network_monitor.filters import filter_connections
from network_monitor.monitor import run_monitoring
from network_monitor.packet_tools import capture_packets, analyse_pcap, PcapError
from network_monitor.storage import Storage

console = Console()


def show_connections(connections):
    table = Table(title=f"FILTERED CONNECTIONS ({len(connections)})")
    for heading in ("Protocol", "Local", "Remote", "Status", "PID", "Process"):
        table.add_column(heading)
    for item in connections:
        table.add_row(
            item["protocol"], f'{item["local_ip"]}:{item["local_port"]}',
            f'{item["remote_ip"]}:{item["remote_port"]}', item["status"],
            str(item["pid"] or "-"), item["process_name"],
        )
    if not connections:
        table.add_row("-", "-", "-", "-", "-", "No matching connections")
    console.print(table)


def filter_menu(snapshot):
    connections = snapshot["connections"]
    while True:
        console.print("\n[bold cyan]CONNECTION FILTERING[/bold cyan]")
        console.print("1. Show all  2. Protocol  3. Status  4. Process  5. Port  6. Combined  0. Back")
        choice = console.input("Select option: ").strip()
        if choice == "0":
            return
        protocol = status = process = None
        port = None
        if choice in ("2", "6"):
            protocol = console.input("Protocol (TCP/UDP/ALL): ").strip().upper() or None
            if protocol and protocol not in ("TCP", "UDP", "ALL"):
                console.print("[red]Enter TCP, UDP, or ALL.[/red]")
                continue
        if choice in ("3", "6"):
            status = console.input("Status (e.g. ESTABLISHED/LISTEN/ALL): ").strip().upper() or None
        if choice in ("4", "6"):
            process = console.input("Process name (or ALL): ").strip() or None
        if choice in ("5", "6"):
            raw = console.input("Port (0-65535, blank for all): ").strip()
            if raw:
                try:
                    port = int(raw)
                    if not 0 <= port <= 65535:
                        raise ValueError
                except ValueError:
                    console.print("[red]Port must be an integer from 0 to 65535.[/red]")
                    continue
        if choice == "1":
            result = filter_connections(connections)
        elif choice in ("2", "3", "4", "5", "6"):
            result = filter_connections(connections, protocol, status, process, port)
        else:
            console.print("[red]Invalid menu option.[/red]")
            continue
        show_connections(result)


def render_live(snapshot, speeds, events):
    """Render one frame of the live monitoring view."""
    console.print("[bold cyan]PYTHON NETWORK MONITOR — LIVE[/bold cyan]")
    console.print(f"Connections: {len(snapshot['connections'])} | "
                  f"Interfaces UP: {sum(x['status'] == 'UP' for x in snapshot['interfaces'])} | "
                  f"Listening TCP ports: {len(snapshot['listening_ports'])}")
    console.print(display_speeds(speeds))
    display_events(events)


def live_monitor(settings, storage):
    console.print("[yellow]Live monitoring. Press Ctrl+C to stop.[/yellow]")
    def update(snapshot, speeds, events):
        console.clear()
        render_live(snapshot, speeds, events)
    try:
        run_monitoring(None, settings, storage, update)
    except KeyboardInterrupt:
        console.print("\n[yellow]Live monitoring stopped.[/yellow]")


def packet_capture_menu(settings, storage):
    interfaces = collect_snapshot()["interfaces"]
    console.print("Available interfaces: " + ", ".join(x["name"] for x in interfaces))
    interface = console.input("Interface (blank for default): ").strip() or None
    raw_duration = console.input(
        f"Capture duration in seconds [{settings.packet_capture_duration}]: "
    ).strip()
    try:
        duration = int(raw_duration) if raw_duration else settings.packet_capture_duration
        if duration < 1 or duration > 3600:
            raise ValueError
    except ValueError:
        console.print("[red]Duration must be between 1 and 3600 seconds.[/red]")
        return
    bpf_filter = console.input(
        "Capture filter (BPF syntax, e.g. 'tcp port 80', blank for none): "
    ).strip() or None
    raw_max = console.input("Max packets (blank for unlimited): ").strip()
    max_packets = None
    if raw_max:
        try:
            max_packets = int(raw_max)
            if max_packets < 1:
                raise ValueError
        except ValueError:
            console.print("[red]Max packets must be a positive integer.[/red]")
            return

    console.print("[yellow]Starting packet capture. Packet capture may require sudo/root privileges.[/yellow]")
    try:
        rows, path = capture_packets(interface, duration,
                                     bpf_filter=bpf_filter,
                                     max_packets=max_packets)
    except PermissionError:
        console.print("[red]Permission denied. On Linux, run the application with appropriate capture permissions.[/red]")
        return
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        return
    except Exception as error:
        console.print(f"[red]Capture failed: {error}[/red]")
        return

    detector = SecurityDetector(settings)
    events = detector.inspect_packets(rows)
    for event in events:
        storage.save_event(event)
    console.print(f"[green]Captured {len(rows)} packets.[/green]")
    console.print(f"PCAP saved to: {path}")
    console.print(f"Packet-level security events: {len(events)}")
    display_events(events)


def pcap_analysis_menu(settings, storage):
    raw_path = console.input(f"PCAP path (default folder: {PCAP_DIR}): ").strip()
    if not raw_path:
        console.print("[yellow]No path entered.[/yellow]")
        return
    path = Path(raw_path).expanduser()
    raw_max = console.input("Max packets to analyse (blank for all): ").strip()
    max_packets = None
    if raw_max:
        try:
            max_packets = int(raw_max)
            if max_packets < 1:
                raise ValueError
        except ValueError:
            console.print("[red]Max packets must be a positive integer.[/red]")
            return
    try:
        summary, events, _rows = analyse_pcap(
            path, detector=SecurityDetector(settings), max_packets=max_packets
        )
    except FileNotFoundError as error:
        console.print(f"[red]{error}[/red]")
        return
    except (PcapError, ValueError) as error:
        console.print(f"[red]{error}[/red]")
        return
    except Exception as error:
        console.print(f"[red]PCAP analysis failed: {error}[/red]")
        return
    display_packet_summary(summary)
    for event in events:
        storage.save_event(event)
    console.print(f"[green]Rule-based events found: {len(events)}[/green]")
    display_events(events)


def _severity_style(severity: str) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "INFO": "cyan"}.get(severity, "white")


def _print_event_table(events, title: str, show_id: bool = True) -> None:
    headings = (["ID"] if show_id else []) + [
        "Time", "Severity", "Category", "Source", "Destination", "Description",
    ]
    table = Table(title=f"{title} ({len(events)})")
    for heading in headings:
        table.add_column(heading)
    for event in events:
        severity = event["severity"]
        row = (([str(event["id"])] if show_id else []) + [
            event["timestamp"],
            f"[{_severity_style(severity)}]{severity}[/{_severity_style(severity)}]",
            event["category"],
            event["source_ip"] or "-",
            event["destination_ip"] or "-",
            event["description"],
        ])
        table.add_row(*row)
    if not events:
        table.add_row(*( ["-"] * (len(headings) - 1) + ["No matching events"] ))
    console.print(table)


def show_events(storage):
    _print_event_table(storage.recent_events(100), "RECENT SECURITY EVENTS")


def show_event_details(storage, event_id=None):
    """Display the full evidence/details of a single stored event."""
    if event_id is None:
        raw = console.input("Event ID: ").strip()
        try:
            event_id = int(raw)
        except ValueError:
            console.print("[red]Event ID must be an integer.[/red]")
            return
    event = storage.get_event(event_id)
    if event is None:
        console.print(f"[red]No event with ID {event_id}.[/red]")
        return
    try:
        details = json.dumps(json.loads(event["details"] or "{}"), indent=2)
    except (json.JSONDecodeError, TypeError):
        details = str(event["details"])
    severity = event["severity"]
    style = _severity_style(severity)
    console.print(Panel(
        f"ID: [bold]{event['id']}[/bold]\n"
        f"Time: {event['timestamp']}\n"
        f"Severity: [{style}]{severity}[/{style}]\n"
        f"Category: {event['category']}\n"
        f"Source: {event['source_ip'] or '-'}\n"
        f"Destination: {event['destination_ip'] or '-'}\n"
        f"Description: {event['description']}\n\n"
        f"[bold]Evidence / details:[/bold]\n{details}",
        title=f"EVENT #{event['id']} DETAILS", border_style="blue",
    ))


def show_timeline(storage, events=None):
    """View events in chronological (oldest first) order."""
    if events is None:
        events = storage.search_events(limit=200, ascending=True)
    _print_event_table(events, "EVENT TIMELINE (oldest first)")


def _prompt_severity() -> str | None:
    raw = console.input(
        "Severity (INFO/MEDIUM/HIGH, blank to cancel): "
    ).strip().upper()
    if not raw:
        return None
    if raw not in ("INFO", "MEDIUM", "HIGH"):
        console.print("[red]Severity must be INFO, MEDIUM or HIGH.[/red]")
        return ""
    return raw


def investigation_menu(storage):
    """Investigate stored events: search, filter, inspect, export."""
    last_rows = storage.recent_events(100)
    while True:
        console.print(f"\n[bold cyan]EVENT INVESTIGATION[/bold cyan] "
                      f"[dim](last result: {len(last_rows)} events)[/dim]")
        console.print(
            "1. Search by IP\n"
            "2. Filter by severity\n"
            "3. Filter by category\n"
            "4. Combined filter (IP + severity + category)\n"
            "5. View event details\n"
            "6. Event timeline\n"
            "7. Export last results\n"
            "0. Back"
        )
        choice = console.input("Select option: ").strip()
        try:
            if choice == "0":
                return
            elif choice == "1":
                ip = console.input("IP address: ").strip()
                if not ip:
                    console.print("[yellow]No IP entered.[/yellow]")
                    continue
                last_rows = storage.search_events(ip=ip, limit=200)
                _print_event_table(last_rows, f"EVENTS FOR IP {ip}")
            elif choice == "2":
                severity = _prompt_severity()
                if severity is None:
                    continue
                if severity == "":
                    continue
                last_rows = storage.search_events(severity=severity, limit=200)
                _print_event_table(last_rows, f"{severity} EVENTS")
            elif choice == "3":
                known = storage.event_categories()
                if known:
                    console.print("[dim]Known categories: "
                                  + ", ".join(known) + "[/dim]")
                category = console.input("Category: ").strip()
                if not category:
                    console.print("[yellow]No category entered.[/yellow]")
                    continue
                last_rows = storage.search_events(category=category, limit=200)
                _print_event_table(last_rows, f"CATEGORY: {category}")
            elif choice == "4":
                ip = console.input("IP (blank for any): ").strip() or None
                severity = _prompt_severity()
                if severity == "":
                    continue
                severity = severity or None
                category = console.input("Category (blank for any): ").strip() or None
                last_rows = storage.search_events(
                    ip=ip, severity=severity, category=category, limit=200
                )
                _print_event_table(last_rows, "COMBINED FILTER RESULTS")
            elif choice == "5":
                show_event_details(storage)
            elif choice == "6":
                show_timeline(storage)
            elif choice == "7":
                if not last_rows:
                    console.print("[yellow]No events to export.[/yellow]")
                    continue
                fmt = console.input("Export format (csv/json): ").strip().lower()
                path = storage.export_events(fmt, rows=last_rows)
                console.print(f"[green]Export created: {path} "
                              f"({len(last_rows)} events)[/green]")
            else:
                console.print("[red]Invalid option. Choose 0-7.[/red]")
        except ValueError as error:
            console.print(f"[red]{error}[/red]")
        except KeyboardInterrupt:
            raise
        except Exception as error:
            console.print(f"[red]Investigation failed: {error}[/red]")


def show_history(storage):
    rows = storage.recent_snapshots(20)
    table = Table(title="RECENT MONITORING HISTORY")
    for heading in ("Time", "Interfaces", "UP", "Connections", "TCP Listeners"):
        table.add_column(heading)
    for row in rows:
        table.add_row(row["timestamp"], str(row["interface_count"]),
                      str(row["active_interfaces"]), str(row["connection_count"]),
                      str(row["listening_port_count"]))
    if not rows:
        table.add_row("-", "-", "-", "-", "No snapshots stored yet")
    console.print(table)


def display_main_menu() -> None:
    console.print("\n[bold cyan]MAIN MENU[/bold cyan]")
    console.print(
        "1. Refresh network report\n"
        "2. Filter network connections\n"
        "3. Start continuous monitoring\n"
        "4. Capture live packets and save PCAP\n"
        "5. Analyse an existing PCAP file\n"
        "6. View security events\n"
        "7. Investigate events (search/filter/details/export)\n"
        "8. View monitoring history\n"
        "9. Export security events (CSV/JSON)\n"
        "0. Exit"
    )


def export_events_menu(storage):
    fmt = console.input("Export format (csv/json): ").strip().lower()
    path = storage.export_events(fmt)
    console.print(f"[green]Export created: {path}[/green]")


def main():
    prepare_directories()
    settings = Settings.load()
    storage = Storage()
    display_header()
    snapshot = collect_snapshot()
    display_report(snapshot)

    while True:
        display_main_menu()
        choice = console.input("Select option: ").strip()
        try:
            if choice == "1":
                snapshot = collect_snapshot()
                display_report(snapshot)
            elif choice == "2":
                filter_menu(snapshot)
            elif choice == "3":
                live_monitor(settings, storage)
            elif choice == "4":
                packet_capture_menu(settings, storage)
            elif choice == "5":
                pcap_analysis_menu(settings, storage)
            elif choice == "6":
                show_events(storage)
            elif choice == "7":
                investigation_menu(storage)
            elif choice == "8":
                show_history(storage)
            elif choice == "9":
                export_events_menu(storage)
            elif choice == "0":
                console.print("[green]Goodbye.[/green]")
                break
            else:
                console.print("[red]Invalid option. Choose 0-9.[/red]")
        except ValueError as error:
            console.print(f"[red]{error}[/red]")
        except KeyboardInterrupt:
            raise
        except Exception as error:
            console.print(f"[red]Operation failed: {error}[/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Application stopped by user.[/yellow]")
    except Exception as error:
        console.print(f"[red]Fatal error: {error}[/red]")
