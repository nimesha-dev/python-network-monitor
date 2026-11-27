import tempfile
import unittest
from pathlib import Path

from scapy.all import ARP, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, wrpcap

from network_monitor.config import Settings
from network_monitor.detector import SecurityDetector
from network_monitor.packet_tools import (
    PcapError,
    analyse_pcap,
    capture_packets,
    iter_pcap,
    packet_to_row,
)


def sample_packets():
    return [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1235, dport=443, flags="A"),
        Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=53, dport=5353),
        Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / ICMP(),
        Ether() / IPv6(src="::1", dst="::1") / TCP(sport=1, dport=2, flags="PA"),
        Ether() / ARP(),
    ]


class PacketToRowTests(unittest.TestCase):
    def test_tcp_ipv4(self):
        row = packet_to_row(
            Ether() / IP(src="192.168.1.10", dst="192.168.1.1",
                         ttl=64) / TCP(sport=50000, dport=443, flags="SA")
        )
        self.assertEqual(row["protocol"], "TCP")
        self.assertEqual(row["src_ip"], "192.168.1.10")
        self.assertEqual(row["dst_ip"], "192.168.1.1")
        self.assertEqual(row["src_port"], 50000)
        self.assertEqual(row["dst_port"], 443)
        self.assertEqual(row["ip_version"], 4)
        self.assertEqual(row["ttl"], 64)
        self.assertEqual(row["tcp_flags"], "SA")
        self.assertTrue(row["tcp_syn"])
        self.assertTrue(row["tcp_ack"])
        self.assertGreater(row["length"], 0)
        self.assertTrue(row["timestamp"])

    def test_udp(self):
        row = packet_to_row(Ether() / IP() / UDP(sport=68, dport=67))
        self.assertEqual(row["protocol"], "UDP")
        self.assertEqual(row["src_port"], 68)
        self.assertEqual(row["dst_port"], 67)
        self.assertFalse(row["tcp_syn"])
        self.assertEqual(row["tcp_flags"], "")

    def test_icmp(self):
        row = packet_to_row(Ether() / IP() / ICMP())
        self.assertEqual(row["protocol"], "ICMP")
        self.assertIsNone(row["dst_port"])

    def test_ipv6(self):
        row = packet_to_row(
            Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=42)
            / TCP(sport=10, dport=20, flags="A")
        )
        self.assertEqual(row["ip_version"], 6)
        self.assertEqual(row["src_ip"], "2001:db8::1")
        self.assertEqual(row["dst_ip"], "2001:db8::2")
        self.assertEqual(row["ttl"], 42)
        self.assertEqual(row["protocol"], "TCP")
        self.assertTrue(row["tcp_ack"])
        self.assertFalse(row["tcp_syn"])

    def test_non_ip_packet_is_other(self):
        row = packet_to_row(Ether() / ARP())
        self.assertEqual(row["protocol"], "OTHER")
        self.assertIsNone(row["src_ip"])
        self.assertIsNone(row["ip_version"])

    def test_raw_payload_is_other(self):
        row = packet_to_row(Raw(b"\x00\x01\x02garbage"))
        self.assertEqual(row["protocol"], "OTHER")
        self.assertIsNone(row["src_ip"])

    def test_truncated_payload_does_not_crash(self):
        row = packet_to_row(
            Ether() / IP() / TCP(flags="S") / Raw(b"\x00\x01")
        )
        self.assertEqual(row["protocol"], "TCP")

    def test_syn_only_flags(self):
        row = packet_to_row(Ether() / IP() / TCP(flags="S"))
        self.assertTrue(row["tcp_syn"])
        self.assertFalse(row["tcp_ack"])

    def test_none_field_values_degrade_safely(self):
        packet = Ether() / IP() / TCP()
        packet[IP].ttl = None
        row = packet_to_row(packet)
        self.assertIsNone(row["ttl"])

    def test_non_packet_inputs_raise_value_error(self):
        for bad in (None, b"raw-bytes", "string", 42, {"packet": 1}):
            with self.assertRaises(ValueError):
                packet_to_row(bad)


class AnalysePcapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _write(self, name, packets):
        path = self.dir / name
        wrpcap(str(path), packets)
        return path

    def test_summary_counts_and_stats(self):
        path = self._write("ok.pcap", sample_packets())
        summary, events, rows = analyse_pcap(path, keep_rows=True)
        self.assertEqual(summary["packet_count"], 6)
        self.assertEqual(summary["protocol_counts"]["TCP"], 3)
        self.assertEqual(summary["protocol_counts"]["UDP"], 1)
        self.assertEqual(summary["protocol_counts"]["ICMP"], 1)
        self.assertEqual(summary["protocol_counts"]["OTHER"], 1)
        self.assertGreater(summary["total_bytes"], 0)
        self.assertEqual(summary["protocol_bytes"]["TCP"],
                         sum(r["length"] for r in rows if r["protocol"] == "TCP"))
        self.assertEqual(len(summary["top_sources"]), 4)
        self.assertEqual(summary["top_sources"][0][0], "10.0.0.1")
        self.assertTrue(summary["first_timestamp"])
        self.assertTrue(summary["last_timestamp"])
        self.assertFalse(summary["truncated"])
        self.assertEqual(events, [])

    def test_rows_not_kept_by_default(self):
        path = self._write("ok.pcap", sample_packets())
        summary, _events, rows = analyse_pcap(path)
        self.assertEqual(rows, [])
        self.assertEqual(summary["packet_count"], 6)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            analyse_pcap(self.dir / "missing.pcap")

    def test_empty_file_raises_pcap_error(self):
        path = self.dir / "empty.pcap"
        path.write_bytes(b"")
        with self.assertRaises(PcapError):
            analyse_pcap(path)

    def test_invalid_file_raises_pcap_error(self):
        path = self.dir / "garbage.pcap"
        path.write_bytes(b"this is definitely not a capture file")
        with self.assertRaises(PcapError):
            analyse_pcap(path)

    def test_header_only_file_returns_zero_packets(self):
        path = self.dir / "header.pcap"
        path.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
        summary, events, rows = analyse_pcap(path)
        self.assertEqual(summary["packet_count"], 0)
        self.assertEqual(events, [])
        self.assertEqual(rows, [])

    def test_max_packets_truncates(self):
        path = self._write("ok.pcap", sample_packets())
        summary, _events, rows = analyse_pcap(path, max_packets=2, keep_rows=True)
        self.assertEqual(summary["packet_count"], 2)
        self.assertEqual(len(rows), 2)
        self.assertTrue(summary["truncated"])

    def test_max_packets_equal_to_file_size(self):
        path = self._write("ok.pcap", sample_packets())
        summary, _events, _rows = analyse_pcap(path, max_packets=6)
        self.assertEqual(summary["packet_count"], 6)
        self.assertTrue(summary["truncated"])

    def test_invalid_max_packets_raises(self):
        path = self._write("ok.pcap", sample_packets())
        with self.assertRaises(ValueError):
            analyse_pcap(path, max_packets=0)

    def test_invalid_batch_size_raises(self):
        path = self._write("ok.pcap", sample_packets())
        with self.assertRaises(ValueError):
            analyse_pcap(path, batch_size=0)

    def test_detector_integration_finds_events(self):
        settings = Settings(alert_cooldown_seconds=60, port_scan_threshold=3,
                            suspicious_ports=[4444])
        detector = SecurityDetector(settings)
        packets = [
            Ether() / IP(src="7.7.7.7", dst="8.8.8.8") / TCP(sport=1, dport=4444, flags="S"),
            Ether() / IP(src="7.7.7.7", dst="8.8.8.8") / TCP(sport=2, dport=4444, flags="S"),
            Ether() / IP(src="7.7.7.7", dst="8.8.8.8") / TCP(sport=3, dport=4444, flags="S"),
        ]
        path = self._write("scan.pcap", packets)
        summary, events, _rows = analyse_pcap(path, detector=detector)
        categories = [e["category"] for e in events]
        self.assertIn("Suspicious Destination Port", categories)
        self.assertEqual(summary["packet_count"], 3)

    def test_detector_batching_across_batches(self):
        # batch_size=1 forces multiple inspect_packets calls; cooldown state
        # must still suppress duplicate suspicious-port alerts.
        settings = Settings(alert_cooldown_seconds=60, suspicious_ports=[4444],
                            port_scan_threshold=100, repeated_attempt_threshold=100,
                            dos_packet_threshold=1000)
        detector = SecurityDetector(settings)
        packets = [
            Ether() / IP(src="7.7.7.7", dst="8.8.8.8") / TCP(sport=1, dport=4444, flags="A")
            for _ in range(3)
        ]
        path = self._write("dup.pcap", packets)
        _summary, events, _rows = analyse_pcap(path, detector=detector, batch_size=1)
        self.assertEqual(len(events), 1)


class IterPcapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_iterates_all_packets(self):
        path = self.dir / "ok.pcap"
        wrpcap(str(path), sample_packets())
        packets = list(iter_pcap(path))
        self.assertEqual(len(packets), 6)

    def test_max_packets_limit(self):
        path = self.dir / "ok.pcap"
        wrpcap(str(path), sample_packets())
        packets = list(iter_pcap(path, max_packets=3))
        self.assertEqual(len(packets), 3)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            list(iter_pcap(self.dir / "nope.pcap"))

    def test_empty_file(self):
        path = self.dir / "empty.pcap"
        path.write_bytes(b"")
        with self.assertRaises(PcapError):
            list(iter_pcap(path))

    def test_invalid_max_packets(self):
        path = self.dir / "ok.pcap"
        wrpcap(str(path), sample_packets())
        with self.assertRaises(ValueError):
            list(iter_pcap(path, max_packets=-1))

    def test_directory_input_raises(self):
        with self.assertRaises(PcapError):
            list(iter_pcap(self.dir))


class CaptureValidationTests(unittest.TestCase):
    def test_invalid_duration_raises(self):
        with self.assertRaises(ValueError):
            capture_packets(None, 0)

    def test_invalid_max_packets_raises(self):
        with self.assertRaises(ValueError):
            capture_packets(None, 1, max_packets=0)

    def test_loopback_capture_if_permitted(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name) / "cap.pcap"
        try:
            rows, path = capture_packets("lo", 1, output_path=out,
                                         max_packets=5, bpf_filter="icmp or tcp")
        except (PermissionError, OSError):
            self.skipTest("packet capture requires elevated privileges")
        self.assertEqual(path, out)
        self.assertTrue(path.exists())
        summary, _events, _rows = analyse_pcap(path)
        self.assertEqual(summary["packet_count"], len(rows))


if __name__ == "__main__":
    unittest.main()
