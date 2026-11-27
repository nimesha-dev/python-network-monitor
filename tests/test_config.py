import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from network_monitor import config as config_module
from network_monitor.config import Settings


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_dir = Path(self.tmp.name)
        self.config_file = self.config_dir / "settings.json"
        for name, value in (("CONFIG_DIR", self.config_dir),
                            ("CONFIG_FILE", self.config_file)):
            patcher = mock.patch.object(config_module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _write(self, data) -> None:
        if isinstance(data, str):
            self.config_file.write_text(data, encoding="utf-8")
        else:
            self.config_file.write_text(json.dumps(data), encoding="utf-8")

    # ---- defaults ---------------------------------------------------- #
    def test_defaults_when_file_missing(self):
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 2.0)
        self.assertEqual(settings.packet_capture_duration, 30)
        self.assertEqual(settings.port_scan_threshold, 15)
        self.assertIn(4444, settings.suspicious_ports)
        self.assertTrue(self.config_file.exists())

    def test_defaults_when_file_is_empty_json(self):
        self._write("")
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, Settings().monitor_interval)

    def test_defaults_when_file_is_not_json(self):
        self._write("this is not json {{")
        settings = Settings.load()
        self.assertEqual(settings.dos_packet_threshold, Settings().dos_packet_threshold)

    def test_defaults_when_file_is_json_array(self):
        self._write("[1, 2, 3]")
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 2.0)

    def test_defaults_when_file_is_unreadable(self):
        self.config_file.write_text(json.dumps({"monitor_interval": 5.0}))
        with mock.patch.object(Path, "read_text", side_effect=OSError("nope")):
            settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 2.0)

    # ---- valid configuration ----------------------------------------- #
    def test_valid_configuration(self):
        self._write({
            "monitor_interval": 5,
            "port_scan_threshold": 20,
            "suspicious_ports": [1234, 4321],
            "allowed_listening_ports": [22],
        })
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 5.0)
        self.assertEqual(settings.port_scan_threshold, 20)
        self.assertEqual(settings.suspicious_ports, [1234, 4321])
        self.assertEqual(settings.allowed_listening_ports, [22])

    def test_partial_configuration_uses_defaults_for_missing(self):
        self._write({"monitor_interval": 7.5})
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 7.5)
        self.assertEqual(settings.packet_capture_duration, 30)
        self.assertEqual(settings.repeated_attempt_threshold, 10)

    def test_numeric_string_is_coerced(self):
        self._write({"monitor_interval": "3.5", "port_scan_threshold": "12"})
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 3.5)
        self.assertEqual(settings.port_scan_threshold, 12)

    # ---- invalid configuration --------------------------------------- #
    def test_unknown_keys_are_ignored(self):
        self._write({"monitor_interval": 4.0, "totally_unknown": "x"})
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 4.0)

    def test_invalid_field_falls_back_to_default(self):
        self._write({"monitor_interval": "not-a-number", "port_scan_threshold": 20})
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 2.0)
        self.assertEqual(settings.port_scan_threshold, 20)

    def test_out_of_range_values_fall_back(self):
        self._write({
            "monitor_interval": -1,
            "packet_capture_duration": 0,
            "port_scan_threshold": -5,
            "detection_window_seconds": 0,
        })
        settings = Settings.load()
        defaults = Settings()
        self.assertEqual(settings.monitor_interval, defaults.monitor_interval)
        self.assertEqual(settings.packet_capture_duration,
                         defaults.packet_capture_duration)
        self.assertEqual(settings.port_scan_threshold, defaults.port_scan_threshold)
        self.assertEqual(settings.detection_window_seconds,
                         defaults.detection_window_seconds)

    def test_boolean_is_not_accepted_as_number(self):
        self._write({"monitor_interval": True})
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 2.0)

    def test_port_list_with_invalid_entries_uses_default(self):
        self._write({"suspicious_ports": "not-a-list"})
        settings = Settings.load()
        self.assertEqual(settings.suspicious_ports, Settings().suspicious_ports)

    def test_port_list_with_out_of_range_port_uses_default(self):
        self._write({"allowed_listening_ports": [22, 70000]})
        settings = Settings.load()
        self.assertEqual(settings.allowed_listening_ports,
                         Settings().allowed_listening_ports)

    def test_port_list_deduplicates_and_accepts_numeric_strings(self):
        self._write({"suspicious_ports": [4444, "4444", 5555]})
        settings = Settings.load()
        self.assertEqual(settings.suspicious_ports, [4444, 5555])

    def test_wrong_type_for_list_field_uses_default(self):
        self._write({"suspicious_ports": {"a": 1}})
        settings = Settings.load()
        self.assertEqual(settings.suspicious_ports, Settings().suspicious_ports)

    # ---- round trip ---------------------------------------------------- #
    def test_save_then_load_roundtrip(self):
        settings = Settings(monitor_interval=9.0, port_scan_threshold=33,
                            suspicious_ports=[1111])
        settings.save()
        loaded = Settings.load()
        self.assertEqual(loaded.monitor_interval, 9.0)
        self.assertEqual(loaded.port_scan_threshold, 33)
        self.assertEqual(loaded.suspicious_ports, [1111])

    def test_load_does_not_crash_on_binary_garbage(self):
        self.config_file.write_bytes(b"\xff\xfe\x00\x01not json")
        settings = Settings.load()
        self.assertEqual(settings.monitor_interval, 2.0)


if __name__ == "__main__":
    unittest.main()
