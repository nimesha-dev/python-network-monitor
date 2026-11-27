from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from network_monitor.collector import format_bytes

console = Console()


def _status(value: str) -> str:
    value = str(value).upper()
    if value == "ESTABLISHED":
        return "[bold green]ESTABLISHED[/bold green]"
    if value == "LISTEN":
        return "[bold yellow]LISTEN[/bold yellow]"
    if value in ("CLOSE_WAIT", "CLOSING"):
        return f"[bold red]{value}[/bold red]"
    if value == "NONE":
        return "[dim blue]NONE[/dim blue]"
    return value


def _protocol(value: str) -> str:
    return "[cyan]TCP[/cyan]" if value == "TCP" else "[magenta]UDP[/magenta]" if value == "UDP" else value


def display_header() -> None:
    console.print(Panel(
        "[bold cyan]PYTHON NETWORK MONITOR[/bold cyan]\n"
        "Network Visibility | Traffic Monitoring | Packet Analysis | Security Events\n"
        "[dim]Rule-based detection only — machine learning is not enabled.[/dim]",
        border_style="cyan", padding=(1, 2), expand=False,
    ))


def display_report(snapshot: dict[str, Any]) -> None:
    interfaces = snapshot["interfaces"]
    connections = snapshot["connections"]
    listeners = snapshot["listening_ports"]
    udp = snapshot["udp_endpoints"]
    stats = snapshot["statistics"]

    active = sum(1 for item in interfaces if item["status"] == "UP")
    tcp = sum(1 for item in connections if item["protocol"] == "TCP")
    udp_connections = sum(1 for item in connections if item["protocol"] == "UDP")
    established = sum(1 for item in connections if item["status"] == "ESTABLISHED")
    sent = sum(item["bytes_sent"] for item in stats)
    received = sum(item["bytes_recv"] for item in stats)

    summary = Table.grid(expand=False)
    summary.add_column()
    summary.add_column()
    summary.add_column()
    summary.add_row(
        f"[bold cyan]Interfaces[/bold cyan]\n{len(interfaces)} total | [green]{active} UP[/green]",
        f"[bold cyan]Connections[/bold cyan]\n{len(connections)} total | TCP {tcp} | UDP {udp_connections}",
        f"[bold cyan]TCP[/bold cyan]\n{established} established | {len(listeners)} listening",
    )
    summary.add_row(
        f"[bold green]Total sent[/bold green]\n{format_bytes(sent)}",
        f"[bold blue]Total received[/bold blue]\n{format_bytes(received)}",
        f"[bold magenta]UDP endpoints[/bold magenta]\n{len(udp)}",
    )
    console.print(Panel(summary, title="NETWORK SUMMARY", border_style="blue", expand=False))

    table = Table(title="NETWORK INTERFACES", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Interface", style="cyan")
    table.add_column("Type")
    table.add_column("Status", justify="center")
    table.add_column("IPv4")
    table.add_column("IPv6")
    table.add_column("Speed Mbps", justify="right")
    for item in interfaces:
        status = "[green]● UP[/green]" if item["status"] == "UP" else "[red]● DOWN[/red]"
        table.add_row(item["name"], item["type"], status,
                      ", ".join(item["ipv4"]) or "-",
                      ", ".join(item["ipv6"]) or "-",
                      str(item["speed_mbps"] or "-"))
    console.print(table)

    traffic = Table(title="CUMULATIVE NETWORK TRAFFIC", box=box.ROUNDED, header_style="bold magenta")
    traffic.add_column("Interface", style="cyan")
    for heading in ("Sent", "Received", "Packets Out", "Packets In", "Errors In/Out", "Drops In/Out"):
        traffic.add_column(heading, justify="right")
    for item in stats:
        errors = item["errors_in"] + item["errors_out"]
        drops = item["drops_in"] + item["drops_out"]
        traffic.add_row(
            item["name"], format_bytes(item["bytes_sent"]), format_bytes(item["bytes_recv"]),
            str(item["packets_sent"]), str(item["packets_recv"]),
            f"[red]{errors}[/red]" if errors else "[green]0[/green]",
            f"[red]{drops}[/red]" if drops else "[green]0[/green]",
        )
    console.print(traffic)
    console.print("[dim]Traffic counters are cumulative. Non-zero drops/errors are not automatically security incidents.[/dim]")

    conn_table = Table(title=f"NETWORK CONNECTIONS ({len(connections)})",
                       box=box.ROUNDED, header_style="bold magenta")
    for heading in ("Protocol", "Local", "Remote", "Status", "PID", "Process"):
        conn_table.add_column(heading)
    for item in connections:
        conn_table.add_row(
            _protocol(item["protocol"]),
            f'{item["local_ip"]}:{item["local_port"]}',
            f'{item["remote_ip"]}:{item["remote_port"]}',
            _status(item["status"]),
            str(item["pid"] or "-"),
            item["process_name"],
        )
    if not connections:
        conn_table.add_row("-", "-", "-", "-", "-", "No connections found")
    console.print(conn_table)

    listen_table = Table(title=f"TCP LISTENING PORTS ({len(listeners)})",
                         box=box.ROUNDED, header_style="bold magenta")
    for heading in ("Local IP", "Port", "PID", "Process"):
        listen_table.add_column(heading)
    for item in listeners:
        listen_table.add_row(item["local_ip"], str(item["port"]),
                             str(item["pid"] or "-"), item["process_name"])
    if not listeners:
        listen_table.add_row("-", "-", "-", "No TCP listeners")
    console.print(listen_table)

    udp_table = Table(title=f"UDP BOUND ENDPOINTS ({len(udp)})",
                      box=box.ROUNDED, header_style="bold magenta")
    for heading in ("Local IP", "Port", "PID", "Process"):
        udp_table.add_column(heading)
    for item in udp:
        udp_table.add_row(item["local_ip"], str(item["port"]),
                          str(item["pid"] or "-"), item["process_name"])
    if not udp:
        udp_table.add_row("-", "-", "-", "No UDP endpoints")
    console.print(udp_table)


def display_speeds(speeds: list[dict[str, Any]]) -> Table:
    table = Table(title="LIVE NETWORK SPEED", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Interface", style="cyan")
    table.add_column("Upload", justify="right", style="green")
    table.add_column("Download", justify="right", style="blue")
    for item in speeds:
        table.add_row(item["name"], format_bytes(item["upload_bps"]) + "/s",
                      format_bytes(item["download_bps"]) + "/s")
    return table


def display_events(events: list[dict[str, Any]]) -> None:
    if not events:
        console.print("[dim]No new rule-based security events in this interval.[/dim]")
        return
    table = Table(title="NEW SECURITY EVENTS", box=box.ROUNDED)
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Description")
    for event in events:
        severity = event["severity"]
        style = "red" if severity == "HIGH" else "yellow" if severity == "MEDIUM" else "cyan"
        table.add_row(f"[{style}]{severity}[/{style}]",
                      event["category"], event["description"])
    console.print(table)


def display_packet_summary(summary: dict[str, Any]) -> None:
    protocols = ", ".join(
        f"{name}: {count} ({format_bytes(summary.get('protocol_bytes', {}).get(name, 0))})"
        for name, count in summary.get("protocol_counts", {}).items()
    ) or "none"
    sources = ", ".join(f"{ip} ({count})" for ip, count in summary.get("top_sources", [])) or "none"
    destinations = ", ".join(f"{ip} ({count})" for ip, count in summary.get("top_destinations", [])) or "none"
    ports = ", ".join(f"{port} ({count})" for port, count in summary.get("top_destination_ports", [])) or "none"
    window = ""
    if summary.get("first_timestamp"):
        window = (f"\nTime range: {summary['first_timestamp']} -> "
                  f"{summary.get('last_timestamp')}")
    truncated = "\nTruncated by packet limit: yes" if summary.get("truncated") else ""
    console.print(Panel(
        f"Packets analysed: [bold]{summary.get('packet_count', 0)}[/bold] "
        f"({format_bytes(summary.get('total_bytes', 0))})\n"
        f"Protocols: {protocols}\n"
        f"Top sources: {sources}\n"
        f"Top destinations: {destinations}\n"
        f"Top destination ports: {ports}"
        f"{window}{truncated}",
        title="PCAP ANALYSIS SUMMARY", border_style="blue", expand=False,
    ))
