# Project presentation kit

Materials for presenting the Python Network Monitor to internship
recruiters: a five-minute live demo script, CV bullet points and a
LinkedIn post draft.

**Key talking point:** the detection system identifies suspicious activity
for investigation; its alerts do not independently prove an attack.

---

## Five-minute live demo script

Start everything from the project directory with the virtual environment
active (`source .venv/bin/activate`).

### 1. Launch the web dashboard (10 seconds)

```bash
python -m network_monitor.web
```

The browser opens `http://127.0.0.1:8765/` automatically.

**Say:** "One command starts a live dashboard — no menus, no terminal
input. A background thread collects network data every two seconds."

### 2. Show the live upload/download graphs (30 seconds)

Point at the traffic rate chart filling in real time and the KPI cards.

**Say:** "These rates come from real interface counters divided by the
actual elapsed time between samples — not assumed intervals."

### 3. Demonstrate active network connections (40 seconds)

Open the **Connections** section: filter chips (TCP/UDP/Established),
search box, sortable columns.

**Say:** "Every connection is mapped to its owning process with psutil in
a single pass. I can filter and search without touching the terminal."

### 4. Display a rule-based security alert (60 seconds)

Open the **Events** section. Filter with the HIGH chip. Live alerts
appear as rules match; stored history shows severity totals.

**Say:** "All eleven detection rules are transparent thresholds — port
scans, repeated SYN attempts, DoS patterns, unexpected listeners. No
machine learning, no black box. This alert is an investigation lead, not
proof of an attack."

Optional deterministic demo (synthetic documentation IPs):

```bash
python -m network_monitor.showcase   # section 7 prints a full alert
```

### 5. Open the event evidence (40 seconds)

Click any event row in the dashboard.

**Say:** "Every alert carries structured evidence — the rule that fired,
the observed values, the threshold and the time window — so an analyst
can verify it in seconds. The JSON is copyable."

### 6. Demonstrate PCAP capture and analysis (60 seconds)

```bash
sudo .venv/bin/python -m network_monitor.main   # menu 4: capture 30s
python -m network_monitor.main                  # menu 5: analyse capture
```

Or analyse an existing capture without privileges:

```bash
python -m network_monitor.showcase              # section 9
```

**Say:** "Captures are streamed to disk packet by packet, then analysed
offline with Scapy. The sample capture shows 523 packets — 505 UDP, 12
TCP — and the rules correctly raised DoS-pattern alerts against the
busiest sources."

### 7. Explain SQLite storage (40 seconds)

Show menu 7 (investigation) in the terminal app, or the event totals on
the dashboard.

**Say:** "Events and monitoring snapshots persist in SQLite — currently
hundreds of security events and thousands of snapshots. Every database
operation opens its own connection, commits on success, rolls back on
failure and always closes. History survives restarts and powers the
search, timeline and CSV/JSON export."

### Closing line

"The whole system is one install, three commands — dashboard, guided
tour, interactive app — with 142 automated tests and CI on every push."

---

## CV bullet points

Choose two or three depending on space:

- Designed and built a Python network monitoring tool with live
  interface/connection visibility, packet capture and offline PCAP
  analysis using psutil, Scapy and Rich on Linux.
- Implemented 11 transparent rule-based detection rules (port scans,
  repeated SYN attempts, DoS patterns, unexpected listeners) with
  structured evidence JSON and per-rule cooldowns — no machine learning.
- Delivered an interactive web dashboard (standard-library HTTP server)
  with auto-refreshing traffic charts, filters, search, sortable tables
  and CSV/JSON export; zero additional web dependencies.
- Wrote 142 unit tests across configuration, detection, filtering,
  packet tooling and storage with GitHub Actions CI on Python 3.10 and
  3.12; MIT licensed, fully documented.

## LinkedIn post draft

> I just completed my cybersecurity portfolio project: a **Python
> Network Monitor** — network visibility, packet analysis and
> rule-based security detection, built on Linux with psutil, Scapy and
> Rich.
>
> What it does:
> · Live dashboard with auto-updating traffic graphs and connection views
> · 11 transparent detection rules (port scans, DoS patterns, unexpected
>   listeners) — every alert ships with structured evidence, not a black
>   box score
> · Live packet capture + offline PCAP analysis with Scapy
> · SQLite-backed event investigation with search, timeline and
>   CSV/JSON export
> · 142 automated tests and GitHub Actions CI
>
> One command tours the whole system, another opens the browser
> dashboard. Alerts are investigation leads — not proof of attack —
> which is exactly how real detection engineering works.
>
> #CyberSecurity #Python #NetworkSecurity #DetectionEngineering
> #Portfolio

Repository: https://github.com/nimesha-dev/python-network-monitor
