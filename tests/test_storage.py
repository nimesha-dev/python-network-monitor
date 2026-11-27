import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from network_monitor import storage as storage_module
from network_monitor.storage import Storage


def make_event(**overrides):
    event = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "severity": "HIGH",
        "category": "Possible Port Scan",
        "source_ip": "10.0.0.9",
        "destination_ip": "10.0.0.1",
        "description": "test event",
        "details": {"threshold": 5, "observed": {"ports": 7}},
    }
    event.update(overrides)
    return event


def make_snapshot():
    return {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "interfaces": [{"name": "eth0", "status": "UP"},
                       {"name": "lo", "status": "UP"}],
        "statistics": [{"name": "eth0", "bytes_sent": 100, "bytes_recv": 200}],
        "connections": [{"protocol": "TCP"} for _ in range(3)],
        "listening_ports": [{"port": 22}, {"port": 80}],
        "udp_endpoints": [],
    }


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "test.db"
        patcher = mock.patch.object(storage_module, "EXPORT_DIR",
                                    Path(self.tmp.name) / "exports")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.storage = Storage(self.db_path)

    # ---- lifecycle ---------------------------------------------------- #
    def test_database_file_created(self):
        self.assertTrue(self.db_path.exists())

    def test_reinitialize_is_idempotent(self):
        Storage(self.db_path)
        self.storage.save_event(make_event())
        self.assertEqual(len(Storage(self.db_path).recent_events()), 1)

    def test_connections_are_closed_after_use(self):
        self.storage.save_event(make_event())
        # A second writer must not be blocked by a leaked connection lock.
        other = Storage(self.db_path)
        other.save_event(make_event())
        self.assertEqual(len(self.storage.recent_events()), 2)
        with sqlite3.connect(self.db_path) as db:
            count = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        self.assertEqual(count, 2)

    # ---- events -------------------------------------------------------- #
    def test_save_and_retrieve_event(self):
        self.storage.save_event(make_event(description="port scan"))
        events = self.storage.recent_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["description"], "port scan")
        self.assertEqual(events[0]["severity"], "HIGH")

    def test_event_details_roundtrip_as_json(self):
        self.storage.save_event(make_event())
        stored = self.storage.recent_events()[0]
        details = json.loads(stored["details"])
        self.assertEqual(details["threshold"], 5)

    def test_event_defaults_for_missing_fields(self):
        self.storage.save_event({})
        event = self.storage.recent_events()[0]
        self.assertEqual(event["severity"], "INFO")
        self.assertEqual(event["category"], "General")
        self.assertEqual(event["description"], "")

    def test_recent_events_limit(self):
        for i in range(10):
            self.storage.save_event(make_event(description=f"e{i}"))
        events = self.storage.recent_events(limit=3)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["description"], "e9")

    def test_recent_events_limit_clamped_to_positive(self):
        self.storage.save_event(make_event())
        self.assertEqual(len(self.storage.recent_events(limit=0)), 1)

    def test_empty_database_returns_no_events(self):
        self.assertEqual(self.storage.recent_events(), [])

    # ---- snapshots ------------------------------------------------------ #
    def test_save_and_retrieve_snapshot(self):
        self.storage.save_snapshot(make_snapshot())
        rows = self.storage.recent_snapshots()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["interface_count"], 2)
        self.assertEqual(rows[0]["active_interfaces"], 2)
        self.assertEqual(rows[0]["connection_count"], 3)
        self.assertEqual(rows[0]["listening_port_count"], 2)
        self.assertEqual(rows[0]["upload_bytes"], 100)
        self.assertEqual(rows[0]["download_bytes"], 200)

    def test_snapshot_json_content(self):
        self.storage.save_snapshot(make_snapshot())
        stored = json.loads(self.storage.recent_snapshots()[0]["snapshot_json"])
        self.assertEqual(stored["interfaces"][0]["name"], "eth0")

    def test_empty_snapshot_does_not_crash(self):
        self.storage.save_snapshot({})
        self.assertEqual(len(self.storage.recent_snapshots()), 1)

    def test_empty_history_returns_no_snapshots(self):
        self.assertEqual(self.storage.recent_snapshots(), [])

    # ---- get_event ------------------------------------------------------ #
    def test_get_event_by_id(self):
        self.storage.save_event(make_event(description="first"))
        event = self.storage.get_event(1)
        self.assertIsNotNone(event)
        self.assertEqual(event["description"], "first")

    def test_get_event_missing_id_returns_none(self):
        self.assertIsNone(self.storage.get_event(999))

    # ---- categories ------------------------------------------------------ #
    def test_event_categories(self):
        self.storage.save_event(make_event(category="Possible Port Scan"))
        self.storage.save_event(make_event(category="Connection Frequency"))
        self.storage.save_event(make_event(category="Possible Port Scan"))
        self.assertEqual(self.storage.event_categories(),
                         ["Connection Frequency", "Possible Port Scan"])

    # ---- export ---------------------------------------------------------- #
    def test_export_json(self):
        self.storage.save_event(make_event())
        path = self.storage.export_events("json")
        self.assertTrue(path.exists())
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["severity"], "HIGH")

    def test_export_csv(self):
        self.storage.save_event(make_event())
        path = self.storage.export_events("csv")
        self.assertTrue(path.exists())
        with path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["category"], "Possible Port Scan")

    def test_export_invalid_format_raises(self):
        with self.assertRaises(ValueError):
            self.storage.export_events("xml")

    def test_export_empty_events_still_writes_file(self):
        path = self.storage.export_events("csv")
        self.assertTrue(path.exists())
        self.assertEqual(path.read_text(encoding="utf-8").strip(),
                         "id,timestamp,severity,category,source_ip,"
                         "destination_ip,description,details")

    def test_export_accepts_explicit_rows(self):
        rows = [make_event(description="filtered")]
        path = self.storage.export_events("json", rows=rows)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data[0]["description"], "filtered")


class SearchEventTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "test.db"
        patcher = mock.patch.object(storage_module, "EXPORT_DIR",
                                    Path(self.tmp.name) / "exports")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.storage = Storage(self.db_path)
        self.storage.save_event(make_event(
            timestamp="2026-01-01T00:00:00+00:00", severity="HIGH",
            category="Possible Port Scan", source_ip="10.0.0.9",
            destination_ip="10.0.0.1", description="scan"))
        self.storage.save_event(make_event(
            timestamp="2026-01-02T00:00:00+00:00", severity="INFO",
            category="New Connection", source_ip="10.0.0.2",
            destination_ip="8.8.8.8", description="conn"))
        self.storage.save_event(make_event(
            timestamp="2026-01-03T00:00:00+00:00", severity="MEDIUM",
            category="Connection Frequency", source_ip=None,
            destination_ip="8.8.8.8", description="freq"))

    def test_search_by_source_ip(self):
        rows = self.storage.search_events(ip="10.0.0.9")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "scan")

    def test_search_by_destination_ip(self):
        rows = self.storage.search_events(ip="8.8.8.8")
        self.assertEqual(len(rows), 2)

    def test_search_by_ip_no_match(self):
        self.assertEqual(self.storage.search_events(ip="1.2.3.4"), [])

    def test_search_by_severity(self):
        rows = self.storage.search_events(severity="HIGH")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "HIGH")

    def test_search_by_severity_case_insensitive(self):
        rows = self.storage.search_events(severity="high")
        self.assertEqual(len(rows), 1)

    def test_search_by_severity_no_match(self):
        self.assertEqual(self.storage.search_events(severity="CRITICAL"), [])

    def test_search_by_category(self):
        rows = self.storage.search_events(category="New Connection")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "conn")

    def test_search_by_category_no_match(self):
        self.assertEqual(self.storage.search_events(category="Nope"), [])

    def test_combined_filters(self):
        rows = self.storage.search_events(ip="8.8.8.8", severity="MEDIUM",
                                          category="Connection Frequency")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "freq")

    def test_combined_filters_no_match(self):
        rows = self.storage.search_events(ip="8.8.8.8", severity="HIGH")
        self.assertEqual(rows, [])

    def test_search_without_filters_returns_all(self):
        self.assertEqual(len(self.storage.search_events()), 3)

    def test_search_default_order_is_newest_first(self):
        rows = self.storage.search_events()
        descriptions = [r["description"] for r in rows]
        self.assertEqual(descriptions, ["freq", "conn", "scan"])

    def test_search_ascending_order(self):
        rows = self.storage.search_events(ascending=True)
        descriptions = [r["description"] for r in rows]
        self.assertEqual(descriptions, ["scan", "conn", "freq"])

    def test_search_limit(self):
        rows = self.storage.search_events(limit=2)
        self.assertEqual(len(rows), 2)

    def test_search_limit_clamped(self):
        self.assertEqual(len(self.storage.search_events(limit=0)), 1)

    def test_search_empty_database(self):
        empty = Storage(Path(self.tmp.name) / "empty.db")
        self.assertEqual(empty.search_events(ip="10.0.0.9"), [])


if __name__ == "__main__":
    unittest.main()
