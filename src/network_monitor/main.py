from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich import box

from network_monitor.interfaces import (
    get_network_interfaces,
    get_ip_addresses,
    get_network_statistics,
    get_network_connections,
    get_listening_ports,
    format_bytes
)

from network_monitor.traffic import get_network_speed


# Create Rich Console
console = Console()


def display_header():
    """Display the application header."""

    console.print(
        Panel(
            "[bold cyan]PYTHON NETWORK MONITOR[/bold cyan]\n"
            "[white]Network Information and Monitoring System[/white]",
            border_style="cyan",
            padding=(1, 2),
            expand=True
        )
    )


def display_network_summary(interfaces, connections, listening_ports):
    """Display a summary of the current network status."""

    total_interfaces = len(interfaces)

    active_interfaces = sum(
        1 for interface in interfaces
        if interface["status"] == "UP"
    )

    inactive_interfaces = total_interfaces - active_interfaces

    summary = (
        f"[bold cyan]Total Interfaces:[/bold cyan] {total_interfaces}    "
        f"[bold green]Active:[/bold green] {active_interfaces}    "
        f"[bold red]Inactive:[/bold red] {inactive_interfaces}\n\n"
        f"[bold cyan]Active Connections:[/bold cyan] {len(connections)}    "
        f"[bold yellow]Listening Ports:[/bold yellow] "
        f"{len(listening_ports)}"
    )

    console.print(
        Panel(
            summary,
            title="[bold white]NETWORK SUMMARY[/bold white]",
            border_style="blue",
            padding=(1, 2),
            expand=True
        )
    )


def display_network_interfaces(interfaces):
    """Display available network interfaces."""

    console.print("\n[bold cyan]1. NETWORK INTERFACES[/bold cyan]")

    table = Table(
        title="Available Network Interfaces",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        expand=True
    )

    table.add_column("Interface Name", style="cyan")
    table.add_column("Interface Type")
    table.add_column("Status", justify="center")

    for interface in interfaces:

        status = (
            "[bold green]UP[/bold green]"
            if interface["status"] == "UP"
            else "[bold red]DOWN[/bold red]"
        )

        table.add_row(
            interface["name"],
            interface["type"],
            status
        )

    console.print(table)


def display_ip_information(ip_information):
    """Display IPv4 and IPv6 address information."""

    console.print("\n[bold cyan]2. IP ADDRESS INFORMATION[/bold cyan]")

    table = Table(
        title="Network IP Address Information",
        box=box.ROUNDED,
        header_style="bold magenta",
        expand=True
    )

    table.add_column("Interface", style="cyan")
    table.add_column("IPv4 Address")
    table.add_column("IPv6 Address")

    for interface in ip_information:

        table.add_row(
            interface["name"],
            interface["ipv4"],
            interface["ipv6"]
        )

    console.print(table)


def display_network_statistics(statistics):
    """Display cumulative network traffic statistics."""

    console.print("\n[bold cyan]3. NETWORK TRAFFIC STATISTICS[/bold cyan]")

    table = Table(
        title="Network Traffic Statistics",
        box=box.ROUNDED,
        header_style="bold magenta",
        expand=True
    )

    table.add_column("Interface", style="cyan")
    table.add_column("Data Sent", justify="right")
    table.add_column("Data Received", justify="right")
    table.add_column("Packets Sent", justify="right")
    table.add_column("Packets Received", justify="right")
    table.add_column("Errors In", justify="right")
    table.add_column("Errors Out", justify="right")
    table.add_column("Drops In", justify="right")
    table.add_column("Drops Out", justify="right")

    for interface in statistics:

        table.add_row(
            interface["name"],
            format_bytes(interface["bytes_sent"]),
            format_bytes(interface["bytes_recv"]),
            str(interface["packets_sent"]),
            str(interface["packets_recv"]),
            str(interface["errors_in"]),
            str(interface["errors_out"]),
            str(interface["drops_in"]),
            str(interface["drops_out"])
        )

    console.print(table)

    console.print(
        "[dim]Note: Traffic values are cumulative counters since the "
        "system or interface statistics were reset.[/dim]"
    )


def display_network_connections(connections):
    """Display active network connections."""

    console.print("\n[bold cyan]4. ACTIVE NETWORK CONNECTIONS[/bold cyan]")

    table = Table(
        title=f"Network Connections - Total: {len(connections)}",
        box=box.ROUNDED,
        header_style="bold magenta",
        expand=True
    )

    table.add_column("Protocol", style="cyan")
    table.add_column("Local Address")
    table.add_column("Remote Address")
    table.add_column("Status", justify="center")
    table.add_column("Process ID", justify="right")

    for connection in connections:

        local_address = (
            f"{connection['local_ip']}:{connection['local_port']}"
        )

        remote_address = (
            f"{connection['remote_ip']}:{connection['remote_port']}"
        )

        table.add_row(
            str(connection["protocol"]),
            local_address,
            remote_address,
            str(connection["status"]),
            str(connection["pid"])
        )

    console.print(table)


def display_listening_ports(listening_ports):
    """Display TCP listening ports."""

    console.print("\n[bold cyan]5. LISTENING PORTS[/bold cyan]")

    table = Table(
        title=f"Listening Ports - Total: {len(listening_ports)}",
        box=box.ROUNDED,
        header_style="bold magenta",
        expand=True
    )

    table.add_column("Protocol", style="cyan")
    table.add_column("Local IP Address")
    table.add_column("Port Number", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Process ID", justify="right")

    for port_info in listening_ports:

        table.add_row(
            str(port_info["protocol"]),
            str(port_info["local_ip"]),
            str(port_info["port"]),
            str(port_info["status"]),
            str(port_info["pid"])
        )

    console.print(table)

    console.print(
        "[dim]Note: This section currently displays TCP listening "
        "sockets detected by the monitoring functions.[/dim]"
    )


def create_network_speed_table(speeds):
    """Create a table showing current upload and download speeds."""

    table = Table(
        title="Live Network Traffic Speed",
        box=box.ROUNDED,
        header_style="bold magenta",
        expand=True
    )

    table.add_column("Network Interface", style="cyan")
    table.add_column("Upload Speed", justify="right", style="green")
    table.add_column("Download Speed", justify="right", style="blue")

    for interface in speeds:

        upload_speed = (
            format_bytes(int(interface["upload_speed"])) + "/s"
        )

        download_speed = (
            format_bytes(int(interface["download_speed"])) + "/s"
        )

        table.add_row(
            interface["name"],
            upload_speed,
            download_speed
        )

    if not speeds:
        table.add_row("No interfaces available", "-", "-")

    return table


def display_live_network_speed():
    """Display continuously updating network upload and download speeds."""

    console.print("\n[bold cyan]6. LIVE NETWORK SPEED MONITORING[/bold cyan]")

    console.print(
        "[dim]Press Ctrl+C to stop live monitoring.[/dim]\n"
    )

    with Live(
        console=console,
        refresh_per_second=1
    ) as live:

        while True:

            # Collect current network speeds
            speeds = get_network_speed(interval=1.0)

            # Update the dashboard
            live.update(create_network_speed_table(speeds))


def display_report():
    """Collect and display the complete network monitoring report."""

    # Collect network information
    interfaces = get_network_interfaces()

    ip_information = get_ip_addresses()

    statistics = get_network_statistics()

    connections = get_network_connections()

    listening_ports = get_listening_ports()

    # Display application header
    display_header()

    # Display network summary
    display_network_summary(
        interfaces,
        connections,
        listening_ports
    )

    # Display all existing monitoring sections
    display_network_interfaces(interfaces)

    display_ip_information(ip_information)

    display_network_statistics(statistics)

    display_network_connections(connections)

    display_listening_ports(listening_ports)

    # Application footer
    console.print(
        Panel(
            "[bold green]Network monitoring report generated "
            "successfully![/bold green]",
            border_style="green",
            expand=True
        )
    )


def main():
    """Main entry point of the network monitoring application."""

    try:

        # Display the initial network report
        display_report()

        # Start live network speed monitoring
        display_live_network_speed()

    except KeyboardInterrupt:

        console.print(
            "\n[bold yellow]Network monitoring stopped by user.[/bold yellow]"
        )

    except Exception as error:

        console.print(
            f"\n[bold red]An error occurred: {error}[/bold red]"
        )


if __name__ == "__main__":
    main()
