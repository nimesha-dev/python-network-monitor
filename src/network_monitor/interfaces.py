import psutil
import socket


def format_bytes(size: int) -> str:
    """Convert bytes into a human-readable format."""

    units = ["B", "KB", "MB", "GB", "TB"]

    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"

        size = size / 1024

    return f"{size:.2f} PB"



def identify_interface_type(interface_name: str) -> str:
    """Identify the type of a network interface."""

    if interface_name == "lo":
        return "Loopback"

    elif interface_name.startswith("wl"):
        return "Wi-Fi"

    elif interface_name.startswith(("en", "eth")):
        return "Ethernet"

    elif interface_name.startswith(("br-", "virbr", "docker")):
        return "Virtual Bridge"

    else:
        return "Other"


def get_network_interfaces() -> list[dict[str, str]]:
    """Collect network interface names, types, and statuses."""

    interface_addresses = psutil.net_if_addrs()
    interface_stats = psutil.net_if_stats()

    interfaces = []

    for interface_name in sorted(interface_addresses):

        stats = interface_stats.get(interface_name)

        if stats and stats.isup:
            status = "UP"
        else:
            status = "DOWN"

        interface_type = identify_interface_type(interface_name)

        interface_info = {
            "name": interface_name,
            "type": interface_type,
            "status": status
        }

        interfaces.append(interface_info)

    return interfaces


def get_ip_addresses() -> list[dict[str, str]]:
    """Collect IPv4 and IPv6 addresses of network interfaces."""

    interface_addresses = psutil.net_if_addrs()

    ip_information = []

    for interface_name, addresses in interface_addresses.items():

        ipv4_addresses = []
        ipv6_addresses = []

        for address in addresses:

            if address.family == socket.AF_INET:
                ipv4_addresses.append(address.address)

            elif address.family == socket.AF_INET6:
                ipv6_addresses.append(address.address)

        interface_info = {
            "name": interface_name,
            "ipv4": ", ".join(ipv4_addresses) if ipv4_addresses else "Not assigned",
            "ipv6": ", ".join(ipv6_addresses) if ipv6_addresses else "Not assigned"
        }

        ip_information.append(interface_info)

    return ip_information


def get_network_statistics() -> list[dict[str, int | str]]:
    """Collect network traffic statistics for each interface."""

    network_statistics = psutil.net_io_counters(pernic=True)

    statistics = []

    for interface_name, stats in network_statistics.items():

        interface_info = {
            "name": interface_name,
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "errors_in": stats.errin,
            "errors_out": stats.errout,
            "drops_in": stats.dropin,
            "drops_out": stats.dropout
        }

        statistics.append(interface_info)

    return statistics


def get_network_connections() -> list[dict[str, str | int | None]]:
    """Collect active network connection information."""

    connections = psutil.net_connections(kind="inet")

    connection_information = []

    for connection in connections:

        if connection.type == socket.SOCK_STREAM:
            protocol = "TCP"

        elif connection.type == socket.SOCK_DGRAM:
            protocol = "UDP"

        else:
            protocol = "Other"

        local_ip = connection.laddr.ip if connection.laddr else "N/A"
        local_port = connection.laddr.port if connection.laddr else 0

        remote_ip = connection.raddr.ip if connection.raddr else "N/A"
        remote_port = connection.raddr.port if connection.raddr else 0

        connection_info = {
            "protocol": protocol,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": connection.status,
            "pid": connection.pid
        }

        connection_information.append(connection_info)

    return connection_information


def get_listening_ports() -> list[dict[str, str | int | None]]:
    """Collect information about listening network ports."""

    connections = psutil.net_connections(kind="inet")

    listening_ports = []

    for connection in connections:

        if connection.status == psutil.CONN_LISTEN:

            if connection.type == socket.SOCK_STREAM:
                protocol = "TCP"

            elif connection.type == socket.SOCK_DGRAM:
                protocol = "UDP"

            else:
                protocol = "Other"

            port_information = {
                "protocol": protocol,
                "local_ip": connection.laddr.ip,
                "port": connection.laddr.port,
                "status": connection.status,
                "pid": connection.pid
            }

            listening_ports.append(port_information)

    return listening_ports
