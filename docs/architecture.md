# Architecture and module responsibilities

## Modules

| Module | Responsibility |
|---|---|
| `collector.py` | Operating-system network interfaces, counters, sockets and process names. Connections are collected in **one** psutil pass per snapshot and reused for listener/endpoint views. |
| `filters.py` | Pure connection-filtering logic (protocol, status, process, port). Tolerates missing keys and empty input. |
| `monitor.py` | Periodic snapshots; upload/download rates computed from the **actual elapsed time** between samples. Failed samples are skipped instead of crashing the loop. |
| `packet_tools.py` | Scapy live capture (streamed to disk with optional BPF filter and packet limit), streaming PCAP reading, packet metadata extraction, statistics, `PcapError` handling for empty/corrupt/invalid files. |
| `detector.py` | Explainable threshold/rule-based checks with per-key alert cooldowns and evidence-rich alert details. No ML model is used. |
| `storage.py` | SQLite persistence. Every operation opens its own connection, commits on success, rolls back on failure and **always closes** the connection. Search/filter/export helpers for investigation. |
| `dashboard.py` | Rich terminal presentation (tables, panels). |
| `main.py` | Menus and orchestration: overview, filtering, live monitoring, capture, analysis, events, investigation, history, export. |
| `web.py` | Local HTTP server (standard library only) serving an auto-refreshing HTML dashboard: KPIs, live charts, filters, search, sorting, event evidence modal and CSV/JSON downloads. A background thread runs collection and detection. |
| `showcase.py` | One-command guided tour printing every implemented feature (config, overview, filtering, rules, monitoring, PCAP, storage, exports, tests). |
| `config.py` | Defaults, validated configuration loading (per-field type/range checks with fallback to defaults) and output directories. |
| `filters.py` / investigation | `storage.search_events(ip=…, severity=…, category=…)` powers the investigation menu (search, combined filters, timeline, filtered export). |

## Data flow

```text
psutil ──► collector ──► dashboard (display)
                 │
                 └──► monitor ──► detector ──► storage ──► investigation / export

Scapy ──► packet_tools ──► rows ──► detector ──► storage
                │
                └──► summary (streaming statistics)
```

## Detection logic

Detection is transparent: every alert carries a `details` object containing
`rule`, `threshold`, `observed` values and `window_seconds` where applicable.
A per-key cooldown (`alert_cooldown_seconds`, default 60 s) suppresses
duplicate alerts while a condition persists.

1. **Packet port scan** — one source sends TCP SYN packets to at least
   `port_scan_threshold` distinct destination ports within
   `detection_window_seconds`.
2. **Inbound connection scan** — one remote IP targets at least
   `port_scan_threshold` distinct local ports within
   `connection_window_seconds` (derived from connection history).
3. **Outbound connection scan** — one process targets at least
   `port_scan_threshold` distinct remote ports within
   `connection_window_seconds`.
4. **Repeated SYN attempts** — SYN packet count from one source reaches
   `repeated_attempt_threshold` within `detection_window_seconds`.
5. **Repeated connection attempts** — one remote IP opens at least
   `repeated_attempt_threshold` *distinct* connections within
   `detection_window_seconds` (long-lived connections count once).
6. **Possible DoS pattern** — packet count from one source reaches
   `dos_packet_threshold` **or** byte volume reaches `dos_byte_threshold`
   within `detection_window_seconds`.
7. **Suspicious destination port** — packet destination port (or an outbound
   connection's remote port) matches the configured `suspicious_ports` list.
8. **Unexpected listener** — a TCP listening port is not in
   `allowed_listening_ports`; severity is HIGH when the port is also in
   `suspicious_ports`.
9. **Connection frequency** — a remote IP has at least
   `unusual_remote_connection_threshold` simultaneous observed connections.
10. **High bandwidth** — an interface's per-sample rate reaches
    `high_bandwidth_threshold_bps` (re-arms after dropping below threshold).
11. **Interface changes** — new, removed or state-changed interfaces after
    the baseline snapshot.

In addition, an **informational** `New Connection` event (severity INFO) is
emitted the first time each established connection is observed, so the event
history shows when connections appeared.

These are simple heuristics. They can generate false positives and should be
treated as investigation leads, not definitive incident findings.

## Reliability notes

- SQLite connections are closed after every operation (no leaked file
  handles or write locks).
- Traffic rates use real wall-clock deltas, not the configured interval.
- Configuration is validated per field: wrong types and out-of-range values
  fall back to defaults instead of crashing.
- PCAP reading is streaming (`PcapReader`) so large captures do not need to
  fit in memory; empty, corrupt and unsupported files raise `PcapError`.
- Menu operations catch and display errors instead of terminating the app.
