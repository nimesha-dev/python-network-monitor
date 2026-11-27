import unittest
from datetime import datetime, timezone

from network_monitor.config import Settings
from network_monitor.detector import SecurityDetector


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def packet(src="1.2.3.4", dst="10.0.0.5", port=443, protocol="TCP",
           syn=False, ack=True, length=60, timestamp=None):
    return {
        "timestamp": timestamp or now_iso(),
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "protocol": protocol,
        "length": length,
        "tcp_syn": syn,
        "tcp_ack": ack,
    }


def connection(remote_ip="8.8.8.8", remote_port=443, local_port=50000,
               status="ESTABLISHED", pid=100, process="python",
               local_ip="10.0.0.5", protocol="TCP"):
    return {
        "protocol": protocol,
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "status": status,
        "pid": pid,
        "process_name": process,
    }


def detector(**overrides):
    defaults = {
        "alert_cooldown_seconds": 60,
        "port_scan_threshold": 5,
        "repeated_attempt_threshold": 4,
        "dos_packet_threshold": 10,
        "dos_byte_threshold": 100000,
        "detection_window_seconds": 10,
        "connection_window_seconds": 60,
        "unusual_remote_connection_threshold": 5,
        "suspicious_ports": [4444, 23],
        "allowed_listening_ports": [22],
    }
    defaults.update(overrides)
    return SecurityDetector(Settings(**defaults))


def categories(events):
    return [event["category"] for event in events]


class PacketRuleTests(unittest.TestCase):
    def test_normal_traffic_produces_no_alerts(self):
        d = detector()
        rows = [packet(port=443), packet(port=443), packet(port=53, protocol="UDP")]
        self.assertEqual(d.inspect_packets(rows), [])

    def test_empty_input(self):
        self.assertEqual(detector().inspect_packets([]), [])
        self.assertEqual(detector().inspect_packets(None), [])

    def test_port_scan_at_threshold(self):
        d = detector(port_scan_threshold=5)
        rows = [packet(port=p, syn=True, ack=False)
                for p in (21, 22, 23, 25, 80)]
        events = d.inspect_packets(rows)
        scans = [e for e in events if e["category"] == "Possible Port Scan"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["severity"], "HIGH")

    def test_port_scan_below_threshold(self):
        d = detector(port_scan_threshold=5)
        rows = [packet(port=p, syn=True, ack=False) for p in (135, 139, 445)]
        self.assertEqual(categories(d.inspect_packets(rows)), [])

    def test_port_scan_requires_syn_packets(self):
        d = detector(port_scan_threshold=5)
        rows = [packet(port=p, syn=False, ack=True)
                for p in (135, 139, 445, 3389, 5900)]
        self.assertEqual(categories(d.inspect_packets(rows)), [])

    def test_port_scan_evidence_includes_ports_and_threshold(self):
        d = detector(port_scan_threshold=5)
        rows = [packet(port=p, syn=True, ack=False)
                for p in (21, 22, 23, 25, 80)]
        event = next(e for e in d.inspect_packets(rows)
                     if e["category"] == "Possible Port Scan")
        details = event["details"]
        self.assertEqual(details["threshold"], 5)
        self.assertEqual(details["observed"]["distinct_destination_ports"], 5)
        self.assertEqual(details["sample_destination_ports"], [21, 22, 23, 25, 80])
        self.assertIn("window_seconds", details)

    def test_repeated_syn_at_threshold(self):
        d = detector(repeated_attempt_threshold=4, port_scan_threshold=50)
        rows = [packet(port=443, syn=True, ack=False) for _ in range(4)]
        events = d.inspect_packets(rows)
        self.assertIn("Repeated SYN Attempts", categories(events))

    def test_repeated_syn_requires_syn(self):
        d = detector(repeated_attempt_threshold=4, port_scan_threshold=50)
        rows = [packet(port=443, syn=False, ack=True) for _ in range(4)]
        self.assertEqual(categories(d.inspect_packets(rows)), [])  # ack-only SYNs ignored

    def test_dos_packet_threshold(self):
        d = detector(dos_packet_threshold=10, dos_byte_threshold=10**9)
        rows = [packet(length=10) for _ in range(10)]
        events = d.inspect_packets(rows)
        dos = [e for e in events if e["category"] == "Possible DoS Pattern"]
        self.assertEqual(len(dos), 1)
        self.assertEqual(dos[0]["severity"], "HIGH")
        self.assertEqual(dos[0]["details"]["observed"]["packets"], 10)

    def test_dos_byte_threshold(self):
        d = detector(dos_packet_threshold=10**6, dos_byte_threshold=1000)
        rows = [packet(length=100) for _ in range(10)]
        events = d.inspect_packets(rows)
        self.assertIn("Possible DoS Pattern", categories(events))

    def test_dos_below_threshold(self):
        d = detector(dos_packet_threshold=50, dos_byte_threshold=10**9)
        rows = [packet(length=10) for _ in range(10)]
        self.assertNotIn("Possible DoS Pattern", categories(d.inspect_packets(rows)))

    def test_suspicious_port_detected(self):
        d = detector()
        events = d.inspect_packets([packet(port=4444, ack=True)])
        self.assertIn("Suspicious Destination Port", categories(events))

    def test_suspicious_port_normal_port_ignored(self):
        d = detector()
        self.assertEqual(d.inspect_packets([packet(port=443)]), [])

    def test_duplicate_alerts_suppressed_within_cooldown(self):
        d = detector(alert_cooldown_seconds=60)
        rows = [packet(port=4444, ack=True)]
        self.assertEqual(len(d.inspect_packets(rows)), 1)
        self.assertEqual(d.inspect_packets(rows), [])
        self.assertEqual(d.inspect_packets(rows), [])

    def test_alerts_resume_after_cooldown(self):
        d = detector(alert_cooldown_seconds=0)
        rows = [packet(port=4444, ack=True)]
        self.assertEqual(len(d.inspect_packets(rows)), 1)
        self.assertEqual(len(d.inspect_packets(rows)), 1)

    def test_malformed_packets_do_not_crash(self):
        d = detector()
        events = d.inspect_packets([
            {},
            {"timestamp": "not-a-date", "src_ip": None, "dst_port": "abc"},
            {"timestamp": None, "src_ip": "1.1.1.1", "dst_port": None,
             "length": None},
        ])
        self.assertIsInstance(events, list)


class ConnectionRuleTests(unittest.TestCase):
    def test_baseline_connections_are_not_alerted(self):
        d = detector()
        d.inspect_connections([connection()])
        # Same connection observed again: no repeated "New Connection" event.
        events = d.inspect_connections([connection()])
        self.assertEqual(categories(events), [])

    def test_new_connection_event(self):
        d = detector()
        events = d.inspect_connections([connection()])
        self.assertIn("New Connection", categories(events))
        event = events[0]
        self.assertEqual(event["details"]["process"], "python")
        self.assertEqual(event["destination_ip"], "8.8.8.8")

    def test_inbound_port_scan_from_history(self):
        d = detector(port_scan_threshold=5, connection_window_seconds=60)
        ts = datetime.now(timezone.utc).timestamp()
        conns = [
            connection(remote_ip="9.9.9.9", local_port=1000 + i,
                       remote_port=40000 + i, pid=i)
            for i in range(5)
        ]
        events = d.inspect_connections(conns, timestamp=ts)
        scans = [e for e in events if e["category"] == "Possible Port Scan"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["source_ip"], "9.9.9.9")
        self.assertEqual(scans[0]["severity"], "HIGH")
        self.assertEqual(scans[0]["details"]["observed"]["distinct_local_ports"], 5)

    def test_inbound_port_scan_below_threshold(self):
        d = detector(port_scan_threshold=5)
        ts = datetime.now(timezone.utc).timestamp()
        conns = [connection(remote_ip="9.9.9.9", local_port=1000 + i, pid=i)
                 for i in range(3)]
        events = d.inspect_connections(conns, timestamp=ts)
        self.assertNotIn("Possible Port Scan", categories(events))

    def test_outbound_port_scan_from_history(self):
        d = detector(port_scan_threshold=5)
        ts = datetime.now(timezone.utc).timestamp()
        conns = [
            connection(remote_ip="1.1.1.1", remote_port=2000 + i,
                       local_port=50000 + i, pid=77, process="scanner")
            for i in range(5)
        ]
        events = d.inspect_connections(conns, timestamp=ts)
        scans = [e for e in events
                 if e["category"] == "Possible Port Scan"
                 and e["details"].get("rule") == "outbound_port_scan"]
        self.assertEqual(len(scans), 1)
        self.assertIn("scanner", scans[0]["description"])

    def test_repeated_connection_attempts(self):
        d = detector(repeated_attempt_threshold=4, port_scan_threshold=50)
        ts = datetime.now(timezone.utc).timestamp()
        conns = [
            connection(remote_ip="5.5.5.5", local_port=50000 + i,
                       remote_port=80, pid=i)
            for i in range(4)
        ]
        events = d.inspect_connections(conns, timestamp=ts)
        self.assertIn("Repeated Connection Attempts", categories(events))

    def test_persistent_connection_is_not_repeated_attempts(self):
        d = detector(repeated_attempt_threshold=4, port_scan_threshold=50)
        ts = datetime.now(timezone.utc).timestamp()
        conns = [connection(remote_ip="5.5.5.5", local_port=50000)]
        for _ in range(5):
            events = d.inspect_connections(conns, timestamp=ts)
            ts += 2
        self.assertNotIn("Repeated Connection Attempts", categories(events))

    def test_old_history_expires_out_of_scan_window(self):
        d = detector(port_scan_threshold=5, connection_window_seconds=10,
                     repeated_attempt_threshold=100)
        ts = datetime.now(timezone.utc).timestamp()
        d.inspect_connections(
            [connection(remote_ip="9.9.9.9", local_port=1000 + i, pid=i)
             for i in range(5)],
            timestamp=ts,
        )
        # Much later: history is pruned, no scan alert.
        events = d.inspect_connections(
            [connection(remote_ip="7.7.7.7", local_port=1)],
            timestamp=ts + 120,
        )
        self.assertNotIn("Possible Port Scan", categories(events))

    def test_unusual_remote_connection_frequency(self):
        d = detector(unusual_remote_connection_threshold=5,
                     port_scan_threshold=100, repeated_attempt_threshold=100)
        ts = datetime.now(timezone.utc).timestamp()
        conns = [
            connection(remote_ip="3.3.3.3", local_port=50000 + i,
                       remote_port=443, pid=i)
            for i in range(5)
        ]
        events = d.inspect_connections(conns, timestamp=ts)
        freq = [e for e in events if e["category"] == "Connection Frequency"]
        self.assertEqual(len(freq), 1)
        self.assertEqual(freq[0]["details"]["observed"]["simultaneous_connections"], 5)

    def test_suspicious_outbound_connection(self):
        d = detector()
        ts = datetime.now(timezone.utc).timestamp()
        events = d.inspect_connections(
            [connection(remote_port=4444)], timestamp=ts)
        self.assertIn("Suspicious Outbound Connection", categories(events))

    def test_listening_socket_is_not_outbound_alert(self):
        d = detector()
        ts = datetime.now(timezone.utc).timestamp()
        # LISTEN sockets have no remote endpoint and must not trigger the rule.
        events = d.inspect_connections(
            [connection(remote_ip="N/A", remote_port=0, status="LISTEN")],
            timestamp=ts,
        )
        self.assertNotIn("Suspicious Outbound Connection", categories(events))

    def test_empty_and_none_connections(self):
        d = detector()
        self.assertEqual(d.inspect_connections([]), [])
        self.assertEqual(d.inspect_connections(None), [])

    def test_duplicate_alerts_suppressed_across_calls(self):
        d = detector(alert_cooldown_seconds=60, unusual_remote_connection_threshold=3)
        ts = datetime.now(timezone.utc).timestamp()
        conns = [connection(remote_ip="3.3.3.3", local_port=50000 + i, pid=i)
                 for i in range(3)]
        first = [e for e in d.inspect_connections(conns, timestamp=ts)
                 if e["category"] == "Connection Frequency"]
        second = [e for e in d.inspect_connections(conns, timestamp=ts + 2)
                  if e["category"] == "Connection Frequency"]
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 0)


class ListenerRuleTests(unittest.TestCase):
    def test_unexpected_listener(self):
        d = detector()
        events = d.inspect_listeners(
            [{"local_ip": "0.0.0.0", "port": 9999, "pid": 1, "process_name": "x"}])
        self.assertEqual(categories(events), ["Unexpected Listening Port"])
        self.assertEqual(events[0]["severity"], "MEDIUM")

    def test_allowed_listener_is_silent(self):
        d = detector()
        self.assertEqual(
            d.inspect_listeners(
                [{"local_ip": "0.0.0.0", "port": 22, "pid": 1, "process_name": "sshd"}]),
            [])

    def test_suspicious_listening_port_is_high(self):
        d = detector()  # 23 is both suspicious and not allowlisted
        events = d.inspect_listeners(
            [{"local_ip": "0.0.0.0", "port": 23, "pid": 1, "process_name": "telnet"}])
        self.assertEqual(events[0]["severity"], "HIGH")

    def test_stable_listener_alerts_once(self):
        d = detector()
        item = {"local_ip": "0.0.0.0", "port": 9999, "pid": 1, "process_name": "x"}
        self.assertEqual(len(d.inspect_listeners([item])), 1)
        self.assertEqual(d.inspect_listeners([item]), [])

    def test_empty_listeners(self):
        self.assertEqual(detector().inspect_listeners([]), [])


class InterfaceAndSpeedTests(unittest.TestCase):
    def test_baseline_interface_state_is_silent(self):
        d = detector()
        interfaces = [{"name": "eth0", "status": "UP"}]
        self.assertEqual(d.inspect_interfaces(interfaces), [])

    def test_interface_state_change(self):
        d = detector()
        d.inspect_interfaces([{"name": "eth0", "status": "UP"}])
        events = d.inspect_interfaces([{"name": "eth0", "status": "DOWN"}])
        self.assertEqual(categories(events), ["Interface State Change"])

    def test_new_interface_detected(self):
        d = detector()
        d.inspect_interfaces([{"name": "eth0", "status": "UP"}])
        events = d.inspect_interfaces(
            [{"name": "eth0", "status": "UP"}, {"name": "tun0", "status": "UP"}])
        self.assertIn("New Network Interface", categories(events))

    def test_interface_flap_is_cooldown_limited(self):
        d = detector(alert_cooldown_seconds=60)
        d.inspect_interfaces([{"name": "eth0", "status": "UP"}])
        d.inspect_interfaces([{"name": "eth0", "status": "DOWN"}])
        events = d.inspect_interfaces([{"name": "eth0", "status": "UP"}])
        self.assertEqual(events, [])

    def test_high_bandwidth_alert_and_rearm(self):
        d = detector(high_bandwidth_threshold_bps=1000)
        speeds = [{"name": "eth0", "upload_bps": 500.0, "download_bps": 1000.0}]
        events = d.inspect_speeds(speeds)
        self.assertEqual(categories(events), ["High Bandwidth Usage"])
        # Still above threshold: no duplicate.
        self.assertEqual(d.inspect_speeds(speeds), [])
        # Drop below then rise again: re-arms and alerts once more.
        d.inspect_speeds([{"name": "eth0", "upload_bps": 0.0, "download_bps": 0.0}])
        self.assertEqual(len(d.inspect_speeds(speeds)), 1)

    def test_bandwidth_below_threshold_is_silent(self):
        d = detector(high_bandwidth_threshold_bps=10_000_000)
        speeds = [{"name": "eth0", "upload_bps": 10.0, "download_bps": 10.0}]
        self.assertEqual(d.inspect_speeds(speeds), [])

    def test_empty_speeds(self):
        self.assertEqual(detector().inspect_speeds([]), [])


class EvidenceTests(unittest.TestCase):
    def test_every_event_carries_evidence(self):
        d = detector(port_scan_threshold=3, dos_packet_threshold=5,
                     dos_byte_threshold=10**9, repeated_attempt_threshold=3,
                     unusual_remote_connection_threshold=3)
        ts = datetime.now(timezone.utc).timestamp()
        events = []
        events += d.inspect_packets(
            [packet(port=p, syn=True, ack=False) for p in (1, 2, 3)])
        events += d.inspect_connections(
            [connection(remote_ip="9.9.9.9", local_port=1000 + i, pid=i)
             for i in range(3)], timestamp=ts)
        events += d.inspect_listeners(
            [{"local_ip": "0.0.0.0", "port": 7777, "pid": 1, "process_name": "x"}])
        self.assertTrue(events)
        for event in events:
            self.assertIn("rule", event["details"])
            self.assertTrue(event["description"])
            self.assertIn("observed", event["details"])


if __name__ == "__main__":
    unittest.main()
