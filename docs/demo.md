# Project demonstration guide

A short, repeatable walkthrough for demonstrating the Python Network Monitor
in an internship interview or code review. Total time: about 5 minutes.

For a one-command tour of every feature first, run:

```bash
python -m network_monitor.showcase
```

It prints a guided report covering configuration, live network data,
filtering, all 11 detection rules, monitoring, PCAP analysis, storage,
exports and the test suite — no elevated privileges needed.

For a live browser view with graphs that update themselves every 2 seconds
(no menus, no terminal input after startup), run:

```bash
python -m network_monitor.web
```

and open `http://127.0.0.1:8765/` (opened automatically unless
`--no-browser` is given).

## Before the demo

```bash
cd python-network-monitor
source .venv/bin/activate
python -m network_monitor.main
```

No elevated privileges are needed except for live packet capture
(step 5). If capture fails with a permission error, either re-run with
`sudo .venv/bin/python -m network_monitor.main` or demonstrate PCAP analysis
(step 6) with an existing capture file instead.

## 1. Start the application

Show the banner and the automatic startup network report: interfaces with
addresses, cumulative traffic counters, active connections with process
names, TCP listeners and UDP endpoints.

**Talk track:** *"This collects data from the OS with psutil — one pass per
snapshot — and renders it as tables."*

## 2. View network information

Menu `1` refreshes the report. Point out:

- interface status/type (UP/DOWN, Ethernet/Wi-Fi/VPN)
- which process owns each connection (PID + name)
- listening ports — these feed the "unexpected listener" rule

## 3. Monitor live traffic

Menu `3`. Show the live view refreshing every `monitor_interval` seconds:
upload/download rates per interface and any new security events.

**Talk track:** *"Rates are computed from the actual elapsed time between
samples, not the configured interval — so they stay accurate even when a
sample is delayed. Press Ctrl+C to stop."*

Stop with `Ctrl+C`.

## 4. View security alerts

Menu `6` shows recent events from SQLite. If the database is fresh, generate
evidence first by running PCAP analysis (step 6) or by demoing a scan against
your own machine:

```bash
# terminal 2 — harmless local scan against a closed port range on localhost
python - <<'PY'
import socket
for port in range(20, 60):
    s = socket.socket(); s.settimeout(0.05)
    s.connect(("127.0.0.1", port)); s.close()
PY
```

Then show alerts in the app: severity, category, source, destination,
description.

**Talk track:** *"These are rule-based alerts with evidence — not machine
learning, and not proof of an attack. Each one explains the observed value
and the threshold it crossed."*

## 5. Capture packets

Menu `4`:

- interface: `lo` (or leave blank for default)
- duration: `5`
- capture filter: `tcp` (BPF — optional)
- max packets: `100` (optional)

Show the resulting PCAP path and any packet-level events. Requires capture
privileges — mention the `setcap` option from the README if asked.

## 6. Analyse a PCAP file

Menu `5`, enter a capture path (e.g. `pcaps/capture_....pcap` from step 5,
or any existing file). Show:

- packet count and total bytes
- protocol breakdown with byte counts
- top sources / destinations / destination ports
- rule-based events found (e.g. suspicious destination port)

**Talk track:** *"Analysis streams the file packet-by-packet, so even large
captures don't have to fit in memory. Corrupt or empty files are reported
cleanly instead of crashing."*

## 7. Investigate events

Menu `7`:

1. Search by IP — enter a source or destination IP from the alerts
2. Filter by severity — `HIGH`
3. Filter by category — `Possible Port Scan`
4. Combined filter — e.g. IP + severity together
5. View event details — enter an event ID to see the full evidence JSON
6. Event timeline — events in chronological order

**Talk track:** *"This is the investigation workflow: find related events,
open the evidence, and see the sequence of what happened."*

## 8. Filter results

Menu `2` (connection filtering): try `6` (combined) with protocol `TCP`,
status `ESTABLISHED`, process blank, port `443`.

**Talk track:** *"Filters are pure functions with their own unit tests —
protocol, status, process and port can be combined."*

## 9. Export reports

- Menu `7` → `7` exports the *current filtered result set*
- Menu `9` exports all events

Choose `csv` or `json` and open the file from `exports/`:

```bash
head exports/security_events_*.csv
```

**Talk track:** *"Exported results carry the evidence field, so findings can
be shared or archived without the tool."*

## Closing points

- Transparent rules, thresholds in `config/settings.json`, per-field
  validation — no black box.
- 142 automated tests across filters, detector, packet tools, storage and
  configuration (141 passed, 1 skipped — the skip needs capture privileges).
- Streaming packet/PCAP handling, closed SQLite connections, real elapsed
  time for rates — the reliability work behind the features.
- Machine learning, web dashboard and SIEM integration are intentionally out
  of scope for this project.
