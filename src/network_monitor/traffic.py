import time
import psutil


def get_network_speed(interval: float = 1.0) -> list[dict[str, str | float]]:
    """
    Calculate upload and download speeds for each network interface.

    Args:
        interval: Time in seconds between two traffic measurements.

    Returns:
        A list containing upload and download speeds in bytes per second.
    """

    if interval <= 0:
        raise ValueError("The measurement interval must be greater than zero.")

    # First measurement
    previous_stats = psutil.net_io_counters(pernic=True)

    # Record the starting time
    start_time = time.monotonic()

    # Wait before taking the second measurement
    time.sleep(interval)

    # Second measurement
    current_stats = psutil.net_io_counters(pernic=True)

    # Calculate the actual time between measurements
    elapsed_time = time.monotonic() - start_time

    network_speeds = []

    # Compare interfaces available in both measurements
    for interface_name in sorted(
        set(previous_stats) & set(current_stats)
    ):

        previous = previous_stats[interface_name]
        current = current_stats[interface_name]

        # Calculate the difference in transferred data
        uploaded_bytes = max(
            0,
            current.bytes_sent - previous.bytes_sent
        )

        downloaded_bytes = max(
            0,
            current.bytes_recv - previous.bytes_recv
        )

        # Calculate speeds in bytes per second
        upload_speed = uploaded_bytes / elapsed_time
        download_speed = downloaded_bytes / elapsed_time

        network_speeds.append({
            "name": interface_name,
            "upload_speed": upload_speed,
            "download_speed": download_speed
        })

    return network_speeds
