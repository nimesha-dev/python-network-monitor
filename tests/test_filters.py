import unittest

from network_monitor.filters import filter_connections


SAMPLE = [
    {"protocol": "TCP", "status": "ESTABLISHED", "process_name": "firefox",
     "local_port": 50000, "remote_port": 443},
    {"protocol": "UDP", "status": "NONE", "process_name": "python",
     "local_port": 5353, "remote_port": 0},
    {"protocol": "TCP", "status": "LISTEN", "process_name": "postgres",
     "local_port": 5432, "remote_port": 0},
]


class FilterTests(unittest.TestCase):
    def test_protocol(self):
        self.assertEqual(len(filter_connections(SAMPLE, protocol="TCP")), 2)

    def test_protocol_case_insensitive(self):
        self.assertEqual(len(filter_connections(SAMPLE, protocol="udp")), 1)

    def test_status(self):
        self.assertEqual(len(filter_connections(SAMPLE, status="ESTABLISHED")), 1)

    def test_status_case_insensitive(self):
        self.assertEqual(len(filter_connections(SAMPLE, status="listen")), 1)

    def test_process_case_insensitive(self):
        self.assertEqual(len(filter_connections(SAMPLE, process_name="FIRE")), 1)

    def test_port_local_or_remote(self):
        self.assertEqual(len(filter_connections(SAMPLE, port=443)), 1)
        self.assertEqual(len(filter_connections(SAMPLE, port=5432)), 1)

    def test_combined(self):
        self.assertEqual(
            len(filter_connections(SAMPLE, protocol="TCP",
                                   status="ESTABLISHED", process_name="firefox",
                                   port=443)),
            1,
        )

    def test_no_criteria_returns_all(self):
        self.assertEqual(len(filter_connections(SAMPLE)), 3)

    def test_all_sentinels_return_all(self):
        self.assertEqual(
            len(filter_connections(SAMPLE, protocol="ALL", status="ALL",
                                   process_name="ALL")),
            3,
        )

    def test_no_match_returns_empty(self):
        self.assertEqual(filter_connections(SAMPLE, protocol="ICMP"), [])
        self.assertEqual(filter_connections(SAMPLE, status="SYN_SENT"), [])
        self.assertEqual(filter_connections(SAMPLE, process_name="chromium"), [])
        self.assertEqual(filter_connections(SAMPLE, port=9999), [])

    def test_empty_input(self):
        self.assertEqual(filter_connections([], protocol="TCP"), [])

    def test_missing_keys_are_tolerated(self):
        broken = [{"protocol": "TCP"}]
        # Missing fields simply do not match a specific filter.
        self.assertEqual(filter_connections(broken, status="LISTEN"), [])
        self.assertEqual(filter_connections(broken), broken)

    def test_none_criteria_match_everything(self):
        self.assertEqual(
            len(filter_connections(SAMPLE, protocol=None, status=None,
                                   process_name=None, port=None)),
            3,
        )

    def test_port_zero_filter(self):
        self.assertEqual(len(filter_connections(SAMPLE, port=0)), 2)


if __name__ == "__main__":
    unittest.main()
